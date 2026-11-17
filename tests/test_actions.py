"""Actions: wake / shutdown / reboot / graceful Proxmox, all with fakes.

No real sleeping, no network, no SSH server: runner, prober, clock and sleep
are fakes. These code paths power off real machines, so the tests pin the exact
commands issued and their order.
"""
import asyncio
import functools

import asyncssh
import pytest

from wakeboard.actions import (ActionResult, Actions, StageResult, parse_pct_list,
                               parse_qm_list)
from wakeboard.config import Settings
from wakeboard.devices import Device
from wakeboard.ssh import HostKeyChanged, RunResult, SudoRequired
from wakeboard.wol import send_magic

QM_LIST = """\
      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID
       100 debian-12            running    2048              32.00 1734
       101 win11                stopped    8192             128.00 0
       102 reminder-vm          running    1024              10.00 2210
       103 paused-box           paused     512                8.00 3001
"""

PCT_LIST = """\
VMID       Status     Lock         Name
105        running                 scrapemcp
120        stopped                 monitoring
121        running    backup       grafana
"""


# ---- fakes -------------------------------------------------------------------

class FakeClock:
    def __init__(self):
        self.t = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.t

    async def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.t += s


class FakeProber:
    """is_up driven by a callable (so it can depend on commands already issued)."""

    def __init__(self, up):
        self.up = up if callable(up) else (lambda: up)
        self.calls = 0

    async def is_up(self, device) -> bool:
        self.calls += 1
        return self.up()


class FakeRunner:
    def __init__(self, handler=None):
        self.cmds: list[str] = []
        self.handler = handler or (lambda cmd: RunResult("", "", 0))

    async def run(self, device, cmd, timeout=30):
        self.cmds.append(cmd)
        r = self.handler(cmd)
        if isinstance(r, BaseException):
            raise r
        return r


def ok(out=""):
    return RunResult(out, "", 0)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def cfg(tmp_path):
    return Settings(data_dir=tmp_path, wake_timeout=300, guest_timeout=120)


def mk(runner, prober, cfg, clock, **kw):
    return Actions(runner, prober, cfg, sleep=clock.sleep, clock=clock, **kw)


def linux(**kw):
    return Device(name="box", host="10.0.0.5", mac="aa:bb:cc:dd:ee:ff", **kw)


def pve(**kw):
    return Device(name="pve1", host="10.0.0.9", mac="aa:bb:cc:dd:ee:01", type="proxmox", **kw)


class ProxmoxSim:
    """Stateful fake Proxmox host: guests stop when told; host goes down on shutdown."""

    def __init__(self, qm_running, pct_running, ignore_shutdown=(), host_up=True):
        self.qm = set(qm_running)
        self.pct = set(pct_running)
        self.ignore = set(ignore_shutdown)
        self.host_up = host_up

    def handler(self, cmd):
        parts = cmd.split()
        if parts[:2] == ["sudo", "-n"]:
            parts = parts[2:]
        if parts == ["qm", "list"]:
            return ok(self._qm_text())
        if parts == ["pct", "list"]:
            return ok(self._pct_text())
        if len(parts) == 3 and parts[0] in ("qm", "pct") and parts[1] in ("shutdown", "stop"):
            gid = int(parts[2])
            pool = self.qm if parts[0] == "qm" else self.pct
            if parts[1] == "stop" or gid not in self.ignore:
                pool.discard(gid)
            return ok()
        if parts == ["shutdown", "-h", "now"]:
            self.host_up = False
            return ok()
        return RunResult("", f"unknown command {cmd}", 127)

    def _qm_text(self):
        rows = ["      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID"]
        for gid in (100, 101, 102):
            st = "running" if gid in self.qm else "stopped"
            rows.append(f"       {gid} vm{gid}                {st}    2048              32.00 0")
        return "\n".join(rows) + "\n"

    def _pct_text(self):
        rows = ["VMID       Status     Lock         Name"]
        for gid in (105, 106):
            st = "running" if gid in self.pct else "stopped"
            rows.append(f"{gid}        {st}                 ct{gid}")
        return "\n".join(rows) + "\n"


# ---- parsers -----------------------------------------------------------------

def test_parse_qm_list_running_only():
    assert parse_qm_list(QM_LIST) == [100, 102]


def test_parse_pct_list_running_only():
    assert parse_pct_list(PCT_LIST) == [105, 121]


def test_parsers_empty_and_header_only():
    assert parse_qm_list("") == []
    assert parse_pct_list("VMID       Status     Lock         Name\n") == []


def test_parsers_ignore_non_integer_ids():
    # Anything that is not a plain integer VMID must never reach a command line.
    evil = "VMID Status Lock Name\n105;reboot running  x\n-1 running  y\n$(id) running z\n"
    assert parse_pct_list(evil) == []
    assert parse_qm_list("VMID NAME STATUS\n 1x vm running\n") == []


# ---- wake --------------------------------------------------------------------

async def test_wake_all_stages_ok(cfg, clock):
    sent = []
    prober = FakeProber(lambda: bool(sent))
    runner = FakeRunner()
    a = mk(runner, prober, cfg, clock, wol=lambda mac, broadcast, repeat: sent.append(mac))
    seen = []
    res = await a.wake(pve(), progress=seen.append)
    assert res.ok is True
    assert [s.stage for s in res.stages] == ["magic_packet", "ping", "ssh", "pvesh"]
    assert all(s.ok for s in res.stages)
    assert seen == res.stages
    assert runner.cmds == ["true", "pvesh get /version"]


async def test_wake_linux_has_no_pvesh_stage(cfg, clock):
    a = mk(FakeRunner(), FakeProber(True), cfg, clock, wol=lambda *a, **k: None)
    res = await a.wake(linux())
    assert res.ok
    assert [s.stage for s in res.stages] == ["magic_packet", "ping", "ssh"]


async def test_wake_stops_at_ping_timeout_reports_failure(cfg, clock):
    runner = FakeRunner()
    a = mk(runner, FakeProber(False), cfg, clock, wol=lambda *a, **k: None)
    res = await a.wake(pve())
    assert res.ok is False
    assert [(s.stage, s.ok) for s in res.stages] == [("magic_packet", True), ("ping", False)]
    assert runner.cmds == []  # later stages never attempted
    assert clock.t >= cfg.wake_timeout  # polled until the timeout, not forever
    assert clock.t < cfg.wake_timeout + 60


async def test_wake_sends_three_packets(cfg, clock):
    class Sock:
        sent = []

        def __init__(self, *a):
            pass

        def setsockopt(self, *a):
            pass

        def sendto(self, data, addr):
            Sock.sent.append((data, addr))

        def close(self):
            pass

    wol = functools.partial(send_magic, sock_factory=Sock)
    a = mk(FakeRunner(), FakeProber(True), cfg, clock, wol=wol)
    res = await a.wake(linux(broadcast="10.0.0.255"))
    assert res.ok
    assert len(Sock.sent) == 3
    assert all(addr == ("10.0.0.255", 9) for _, addr in Sock.sent)
    assert Sock.sent[0][0] == b"\xff" * 6 + bytes.fromhex("aabbccddeeff") * 16


async def test_wake_without_mac_fails_first_stage(cfg, clock):
    a = mk(FakeRunner(), FakeProber(True), cfg, clock, wol=lambda *a, **k: None)
    res = await a.wake(Device(name="nomac", host="10.0.0.7"))
    assert res.ok is False
    assert [(s.stage, s.ok) for s in res.stages] == [("magic_packet", False)]


async def test_wake_ssh_retries_until_up_then_ok(cfg, clock):
    n = {"i": 0}

    def handler(cmd):
        n["i"] += 1
        return ConnectionRefusedError() if n["i"] < 3 else ok()

    a = mk(FakeRunner(handler), FakeProber(True), cfg, clock, wol=lambda *a, **k: None)
    res = await a.wake(linux())
    assert res.ok
    assert n["i"] == 3


async def test_wake_ssh_host_key_changed_fails_immediately(cfg, clock):
    runner = FakeRunner(lambda cmd: HostKeyChanged("changed"))
    a = mk(runner, FakeProber(True), cfg, clock, wol=lambda *a, **k: None)
    res = await a.wake(pve())
    assert res.ok is False
    assert res.stages[-1].stage == "ssh" and not res.stages[-1].ok
    assert len(runner.cmds) == 1  # not retried
    assert [s.stage for s in res.stages] == ["magic_packet", "ping", "ssh"]


async def test_wake_ssh_timeout_fails_and_skips_pvesh(cfg, clock):
    runner = FakeRunner(lambda cmd: OSError("unreachable"))
    a = mk(runner, FakeProber(True), cfg, clock, wol=lambda *a, **k: None)
    res = await a.wake(pve())
    assert res.ok is False
    assert [(s.stage, s.ok) for s in res.stages][-1] == ("ssh", False)
    assert "pvesh get /version" not in runner.cmds


# ---- shutdown: plain ---------------------------------------------------------

async def test_shutdown_plain_issues_shutdown_command(cfg, clock):
    state = {"up": True}

    def handler(cmd):
        if cmd == "shutdown -h now":
            state["up"] = False
        return ok()

    runner = FakeRunner(handler)
    a = mk(runner, FakeProber(lambda: state["up"]), cfg, clock)
    res = await a.shutdown(linux())
    assert res.ok is True
    assert runner.cmds == ["shutdown -h now"]
    assert [s.stage for s in res.stages] == ["precheck", "shutdown", "down"]


async def test_shutdown_down_device_reports_already_down(cfg, clock):
    runner = FakeRunner()
    a = mk(runner, FakeProber(False), cfg, clock)
    res = await a.shutdown(pve())
    assert res == ActionResult(ok=False, stages=[StageResult("precheck", False, "already down")])
    assert runner.cmds == []


async def test_shutdown_reports_failure_if_host_still_up_after_timeout(cfg, clock):
    runner = FakeRunner()
    a = mk(runner, FakeProber(True), cfg, clock)
    res = await a.shutdown(linux())
    assert res.ok is False
    assert res.stages[-1].stage == "down" and res.stages[-1].ok is False
    assert clock.t >= cfg.wake_timeout


async def test_shutdown_connection_drop_is_expected(cfg, clock):
    state = {"up": True}

    def handler(cmd):
        state["up"] = False
        return asyncssh.ConnectionLost("connection lost")

    a = mk(FakeRunner(handler), FakeProber(lambda: state["up"]), cfg, clock)
    res = await a.shutdown(linux())
    assert res.ok is True
    assert [(s.stage, s.ok) for s in res.stages] == [
        ("precheck", True), ("shutdown", True), ("down", True)]


async def test_shutdown_no_exit_status_is_expected_drop(cfg, clock):
    state = {"up": True}

    def handler(cmd):
        state["up"] = False
        return RunResult("", "", -1)

    a = mk(FakeRunner(handler), FakeProber(lambda: state["up"]), cfg, clock)
    assert (await a.shutdown(linux())).ok is True


async def test_shutdown_real_command_failure_fails_action(cfg, clock):
    prober = FakeProber(True)
    a = mk(FakeRunner(lambda cmd: RunResult("", "Failed to set wall message: Access denied\n"
                                                  "Failed to power off system: Access denied", 1)),
           prober, cfg, clock)
    res = await a.shutdown(linux())
    assert res.ok is False
    assert res.stages[-1].stage == "shutdown" and not res.stages[-1].ok
    assert "Access denied" in res.stages[-1].detail
    assert "down" not in [s.stage for s in res.stages]


async def test_shutdown_auth_failure_is_not_treated_as_drop(cfg, clock):
    a = mk(FakeRunner(lambda cmd: asyncssh.PermissionDenied("auth failed")),
           FakeProber(True), cfg, clock)
    res = await a.shutdown(linux())
    assert res.ok is False
    assert res.stages[-1].stage == "shutdown" and not res.stages[-1].ok


async def test_shutdown_connection_refused_is_not_treated_as_drop(cfg, clock):
    a = mk(FakeRunner(lambda cmd: ConnectionRefusedError()), FakeProber(True), cfg, clock)
    res = await a.shutdown(linux())
    assert res.ok is False
    assert res.stages[-1].stage == "shutdown" and not res.stages[-1].ok


async def test_shutdown_unknown_mode_rejected(cfg, clock):
    a = mk(FakeRunner(), FakeProber(True), cfg, clock)
    with pytest.raises(ValueError):
        await a.shutdown(linux(), mode="yolo")


# ---- sudo --------------------------------------------------------------------

async def test_non_root_uses_sudo_n(cfg, clock):
    state = {"up": True}

    def handler(cmd):
        if cmd == "sudo -n shutdown -h now":
            state["up"] = False
        return ok()

    runner = FakeRunner(handler)
    a = mk(runner, FakeProber(lambda: state["up"]), cfg, clock)
    res = await a.shutdown(linux(ssh_user="ahmad"))
    assert res.ok
    assert runner.cmds == ["sudo -n shutdown -h now"]


async def test_non_root_graceful_prefixes_every_privileged_command(cfg, clock):
    sim = ProxmoxSim({100}, {105})
    runner = FakeRunner(sim.handler)
    a = mk(runner, FakeProber(lambda: sim.host_up), cfg, clock)
    res = await a.shutdown(pve(ssh_user="ops"))
    assert res.ok
    assert all(c.startswith("sudo -n ") for c in runner.cmds), runner.cmds


async def test_sudo_password_required_raises(cfg, clock):
    runner = FakeRunner(lambda cmd: RunResult("", "sudo: a password is required\n", 1))
    a = mk(runner, FakeProber(True), cfg, clock)
    with pytest.raises(SudoRequired, match="password"):
        await a.shutdown(linux(ssh_user="ahmad"))
    assert runner.cmds == ["sudo -n shutdown -h now"]


async def test_sudo_generic_error_with_nonzero_exit_raises(cfg, clock):
    runner = FakeRunner(lambda cmd: RunResult("", "sudo: sorry, you must have a tty\n", 1))
    a = mk(runner, FakeProber(True), cfg, clock)
    with pytest.raises(SudoRequired):
        await a.shutdown(linux(ssh_user="ahmad"))


async def test_sudo_required_releases_lock(cfg, clock):
    runner = FakeRunner(lambda cmd: RunResult("", "sudo: a password is required\n", 1))
    a = mk(runner, FakeProber(True), cfg, clock)
    d = linux(ssh_user="ahmad")
    with pytest.raises(SudoRequired):
        await a.shutdown(d)
    with pytest.raises(SudoRequired):  # not "action in progress"
        await a.shutdown(d)


async def test_graceful_sudo_required_aborts_before_host_shutdown(cfg, clock):
    def handler(cmd):
        if "qm shutdown" in cmd:
            return RunResult("", "sudo: a password is required\n", 1)
        return ProxmoxSim({100}, set()).handler(cmd)

    runner = FakeRunner(handler)
    a = mk(runner, FakeProber(True), cfg, clock)
    with pytest.raises(SudoRequired):
        await a.shutdown(pve(ssh_user="ops"))
    assert not any("shutdown -h now" in c for c in runner.cmds)


async def test_wake_pvesh_sudo_required_fails_stage(cfg, clock):
    def handler(cmd):
        if "pvesh" in cmd:
            return RunResult("", "sudo: a password is required\n", 1)
        return ok()

    runner = FakeRunner(handler)
    a = mk(runner, FakeProber(True), cfg, clock, wol=lambda *a, **k: None)
    res = await a.wake(pve(ssh_user="ops"))
    assert res.ok is False
    assert res.stages[-1].stage == "pvesh" and "password" in res.stages[-1].detail
    assert runner.cmds.count("sudo -n pvesh get /version") == 1  # not retried


# ---- shutdown: graceful proxmox ----------------------------------------------

async def test_graceful_stops_guests_then_shutdown_in_order(cfg, clock):
    sim = ProxmoxSim({100, 102}, {105})
    runner = FakeRunner(sim.handler)
    a = mk(runner, FakeProber(lambda: sim.host_up), cfg, clock)
    res = await a.shutdown(pve())
    assert res.ok is True, res
    assert runner.cmds == [
        "qm list", "pct list",
        "qm shutdown 100", "qm shutdown 102", "pct shutdown 105",
        "qm list", "pct list",            # wait: all stopped
        "shutdown -h now",
    ]
    assert [s.stage for s in res.stages] == [
        "precheck", "guests", "guest_shutdown", "guest_wait", "shutdown", "down"]


async def test_graceful_zero_guests_goes_straight_to_shutdown(cfg, clock):
    sim = ProxmoxSim(set(), set())
    runner = FakeRunner(sim.handler)
    a = mk(runner, FakeProber(lambda: sim.host_up), cfg, clock)
    res = await a.shutdown(pve())
    assert res.ok is True
    assert runner.cmds == ["qm list", "pct list", "shutdown -h now"]
    assert [s.stage for s in res.stages] == ["precheck", "guests", "shutdown", "down"]


async def test_graceful_force_stops_guest_after_timeout(cfg, clock):
    sim = ProxmoxSim({100, 102}, {105}, ignore_shutdown={102})
    runner = FakeRunner(sim.handler)
    a = mk(runner, FakeProber(lambda: sim.host_up), cfg, clock)
    res = await a.shutdown(pve())
    assert res.ok is True, res
    stops = [c for c in runner.cmds if " stop " in c]
    assert stops == ["qm stop 102"]
    # forced only after waiting the full guest timeout, and before host shutdown
    i_stop = runner.cmds.index("qm stop 102")
    assert runner.cmds.index("shutdown -h now") > i_stop
    assert runner.cmds[:5] == ["qm list", "pct list", "qm shutdown 100", "qm shutdown 102",
                               "pct shutdown 105"]
    assert clock.t >= cfg.guest_timeout
    assert "force_stop" in [s.stage for s in res.stages]


async def test_graceful_force_stop_failure_aborts_host_shutdown(cfg, clock):
    sim = ProxmoxSim({100}, set(), ignore_shutdown={100})

    def handler(cmd):
        if cmd == "qm stop 100":
            return RunResult("", "can't lock file '/var/lock/qemu-server/lock-100.conf'", 255)
        return sim.handler(cmd)

    runner = FakeRunner(handler)
    a = mk(runner, FakeProber(lambda: sim.host_up), cfg, clock)
    res = await a.shutdown(pve())
    assert res.ok is False
    assert res.stages[-1].stage == "force_stop" and not res.stages[-1].ok
    assert "shutdown -h now" not in runner.cmds


async def test_graceful_guest_list_failure_aborts(cfg, clock):
    runner = FakeRunner(lambda cmd: RunResult("", "ipcc_send_rec failed", 2))
    a = mk(runner, FakeProber(True), cfg, clock)
    res = await a.shutdown(pve())
    assert res.ok is False
    assert res.stages[-1].stage == "guests" and not res.stages[-1].ok
    assert "shutdown -h now" not in runner.cmds


async def test_graceful_guest_shutdown_timeout_is_not_fatal(cfg, clock):
    """`qm shutdown` blocks until the guest stops; a runner timeout just means 'still stopping'."""
    sim = ProxmoxSim({100}, set())

    def handler(cmd):
        if cmd == "qm shutdown 100":
            sim.qm.discard(100)
            return asyncio.TimeoutError()
        return sim.handler(cmd)

    runner = FakeRunner(handler)
    a = mk(runner, FakeProber(lambda: sim.host_up), cfg, clock)
    res = await a.shutdown(pve())
    assert res.ok is True, res
    assert "qm stop 100" not in runner.cmds


async def test_plain_mode_override_on_proxmox_skips_guests(cfg, clock):
    sim = ProxmoxSim({100}, set())
    runner = FakeRunner(sim.handler)
    a = mk(runner, FakeProber(lambda: sim.host_up), cfg, clock)
    res = await a.shutdown(pve(), mode="plain")
    assert res.ok
    assert runner.cmds == ["shutdown -h now"]


# ---- reboot ------------------------------------------------------------------

async def test_reboot_waits_down_then_up(cfg, clock):
    state = {"phase": "up"}

    def handler(cmd):
        if cmd == "reboot":
            state["phase"] = "rebooting"
            state["at"] = clock.t
        return ok()

    def up():
        if state["phase"] == "rebooting":
            if clock.t - state["at"] >= 20:
                state["phase"] = "booting"
                state["at"] = clock.t
            return False
        if state["phase"] == "booting":
            return clock.t - state["at"] >= 40
        return True

    runner = FakeRunner(handler)
    a = mk(runner, FakeProber(up), cfg, clock)
    res = await a.reboot(linux())
    assert res.ok is True, res
    assert runner.cmds == ["reboot"]
    assert [s.stage for s in res.stages] == ["precheck", "reboot", "down", "up"]


async def test_reboot_never_comes_back_fails(cfg, clock):
    state = {"up": True}

    def handler(cmd):
        state["up"] = False
        return ok()

    a = mk(FakeRunner(handler), FakeProber(lambda: state["up"]), cfg, clock)
    res = await a.reboot(linux())
    assert res.ok is False
    assert [(s.stage, s.ok) for s in res.stages][-1] == ("up", False)


async def test_reboot_down_device_reports_already_down(cfg, clock):
    runner = FakeRunner()
    a = mk(runner, FakeProber(False), cfg, clock)
    res = await a.reboot(linux())
    assert res.ok is False and res.stages[0].detail == "already down"
    assert runner.cmds == []


# ---- lock --------------------------------------------------------------------

async def test_concurrent_action_rejected_by_lock(cfg):
    gate = asyncio.Event()
    state = {"up": True}

    async def sleep(s):
        await gate.wait()
        state["up"] = False

    class Prober:
        async def is_up(self, device):
            return state["up"] if device.name == "box" else False

    t = {"v": 0.0}
    runner = FakeRunner()
    a = Actions(runner, Prober(), cfg, sleep=sleep, clock=lambda: t["v"])
    d = linux()
    first = asyncio.create_task(a.shutdown(d))
    for _ in range(5):
        await asyncio.sleep(0)  # let the first action reach its (blocked) sleep
    second = await asyncio.wait_for(a.reboot(d), 1)  # must not wait for the first
    assert second == ActionResult(ok=False, stages=[StageResult("lock", False, "action in progress")])
    # a different device is not blocked
    other = await asyncio.wait_for(a.shutdown(Device(name="other", host="10.0.0.6")), 1)
    assert other.stages[0].stage != "lock"
    gate.set()
    assert (await first).ok is True
    # lock released afterwards
    state["up"] = True
    third = await a.shutdown(d)
    assert third.stages[0].stage != "lock"


async def test_progress_callback_errors_do_not_abort(cfg, clock):
    state = {"up": True}

    def handler(cmd):
        state["up"] = False
        return ok()

    def bad(_):
        raise RuntimeError("ui went away")

    a = mk(FakeRunner(handler), FakeProber(lambda: state["up"]), cfg, clock)
    assert (await a.shutdown(linux(), progress=bad)).ok is True
