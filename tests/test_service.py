"""Service facade: confirm / self rules, auditing, error degradation. All fakes."""
import pytest

from wakeboard.actions import ActionResult, StageResult
from wakeboard.audit import AuditLog
from wakeboard.devices import Device, DeviceRepo
from wakeboard.service import (MAX_OUTPUT, ConfirmationRequired,
                               InvalidRequest, RunCommandDisabled, SelfTargetRefused, Service,
                               detect_self, host_key_ack_clearer)
from wakeboard.ssh import ConnectFailed, HostKeyChanged, RunResult, SudoRequired
from wakeboard.status import Info
from wakeboard.targets import NoDevices, UnknownTarget
from wakeboard.wolcheck import WolReport


class FakeActions:
    def __init__(self):
        self.calls: list[tuple] = []
        self.raise_for: dict[str, Exception] = {}

    async def _go(self, action, device, **kw):
        self.calls.append((action, device.name, kw))
        if device.name in self.raise_for:
            raise self.raise_for[device.name]
        return ActionResult(ok=True, stages=[StageResult(action, True, f"{action} done")])

    async def wake(self, device, progress=None):
        return await self._go("wake", device)

    async def shutdown(self, device, mode=None, progress=None):
        return await self._go("shutdown", device, mode=mode)

    async def reboot(self, device, progress=None):
        return await self._go("reboot", device)


class FakeRunner:
    def __init__(self):
        self.calls: list[tuple[str, str]] = []
        self.result = RunResult("hello\n", "", 0)
        self.exc: Exception | None = None
        self.acked: list[str] = []

    async def run(self, device, cmd, timeout=30):
        self.calls.append((device.name, cmd))
        if self.exc:
            raise self.exc
        return self.result

    def acknowledge_host_key(self, device):
        self.acked.append(device.name)


class FakeProber:
    def __init__(self, up=True):
        self.up = up

    async def is_up(self, device):
        return self.up


@pytest.fixture
def repo(conn):
    r = DeviceRepo(conn)
    r.add(Device(name="pve1", host="10.0.0.1", type="proxmox", groups=["lab"], mac="aa:bb:cc:00:00:01"))
    r.add(Device(name="pve2", host="10.0.0.2", type="proxmox", groups=["lab"], mac="aa:bb:cc:00:00:02"))
    r.add(Device(name="pi", host="10.0.0.9", groups=["lab"], is_self=True, mac="aa:bb:cc:00:00:09"))
    return r


@pytest.fixture
def audit(conn):
    return AuditLog(conn)


@pytest.fixture
def actions():
    return FakeActions()


@pytest.fixture
def runner():
    return FakeRunner()


def make_service(repo, audit, actions, runner, local=("127.0.0.1",), prober=None, state=None,
                 **kw):
    return Service(repo, audit, actions, runner, prober or FakeProber(),
                   state if state is not None else {},
                   local_ips=lambda: set(local), resolve=lambda host: set(), **kw)


@pytest.fixture
def svc(repo, audit, actions, runner):
    return make_service(repo, audit, actions, runner)


# ---- confirmation / self rules ----------------------------------------------

async def test_shutdown_all_without_confirm_raises(svc, actions, audit):
    with pytest.raises(ConfirmationRequired) as ei:
        await svc.shutdown("all", caller="api")
    msg = str(ei.value)
    assert "pve1" in msg and "pve2" in msg
    assert actions.calls == []
    rows = audit.list()
    assert rows[0]["caller"] == "api" and rows[0]["action"] == "shutdown"
    assert "refused" in rows[0]["result"]


async def test_shutdown_group_without_confirm_raises(svc, actions):
    with pytest.raises(ConfirmationRequired):
        await svc.shutdown("lab", caller="ui")
    with pytest.raises(ConfirmationRequired):
        await svc.reboot("LAB", caller="ui")
    assert actions.calls == []


async def test_shutdown_all_skips_self_device(svc, actions):
    res = await svc.shutdown("all", caller="ui", confirm=True)
    assert set(res) == {"pve1", "pve2"}
    assert all(v["ok"] for v in res.values())
    assert sorted(c[1] for c in actions.calls) == ["pve1", "pve2"]


async def test_group_shutdown_and_reboot_skip_self_device(svc, actions):
    res = await svc.shutdown("lab", caller="ui", confirm=True)
    assert set(res) == {"pve1", "pve2"}
    res = await svc.reboot("lab", caller="ui", confirm=True)
    assert set(res) == {"pve1", "pve2"}
    assert "pi" not in {c[1] for c in actions.calls}


async def test_shutdown_self_requires_confirm_with_warning(svc, actions):
    with pytest.raises(SelfTargetRefused) as ei:
        await svc.shutdown("pi", caller="ui")
    assert "WARNING" in str(ei.value) and "pi" in str(ei.value)
    assert isinstance(ei.value, ConfirmationRequired)
    with pytest.raises(SelfTargetRefused):
        await svc.reboot("pi", caller="ui")
    assert actions.calls == []
    res = await svc.shutdown("pi", caller="ui", confirm=True)
    assert res["pi"]["ok"] and actions.calls == [("shutdown", "pi", {"mode": None})]


async def test_single_non_self_shutdown_needs_no_confirm(svc, actions):
    res = await svc.shutdown("pve1", caller="ui", mode="plain")
    assert res["pve1"]["ok"]
    assert res["pve1"]["stages"] == [{"stage": "shutdown", "ok": True, "detail": "shutdown done"}]
    assert actions.calls == [("shutdown", "pve1", {"mode": "plain"})]


async def test_invalid_shutdown_mode_rejected(svc, actions):
    with pytest.raises(InvalidRequest):
        await svc.shutdown("pve1", caller="ui", mode="yank-the-cord")
    assert actions.calls == []


async def test_detected_self_host_requires_confirm_and_is_excluded_from_bulk(repo, audit, actions, runner):
    repo.add(Device(name="hv", host="192.168.1.50", groups=["lab"], mac="aa:bb:cc:00:00:50"))
    svc = make_service(repo, audit, actions, runner, local=("127.0.0.1", "192.168.1.50"))
    with pytest.raises(SelfTargetRefused) as ei:
        await svc.reboot("hv", caller="ui")
    assert "WARNING" in str(ei.value)
    res = await svc.shutdown("all", caller="ui", confirm=True)
    assert set(res) == {"pve1", "pve2"}
    with pytest.raises(ConfirmationRequired) as ei:
        await svc.shutdown("lab", caller="ui")
    assert "hv" in str(ei.value)  # named as excluded
    assert not repo.get("hv").is_self  # never persisted
    listed = {d["name"]: d for d in await svc.list_devices()}
    assert listed["hv"]["is_self"] is True


async def test_unknown_target_and_no_devices(repo, audit, actions, runner, svc):
    with pytest.raises(UnknownTarget):
        await svc.shutdown("nope", caller="ui")
    with pytest.raises(UnknownTarget):
        await svc.wake("nope", caller="ui")
    for name in ("pve1", "pve2"):
        repo.remove(name)
    with pytest.raises(NoDevices):
        await svc.shutdown("all", caller="ui", confirm=True)
    assert actions.calls == []


def test_detect_self_matches_local_ips_and_names():
    devs = [Device(name="a", host="10.0.0.1"), Device(name="b", host="LOCALHOST"),
            Device(name="c", host="myhv.lan"), Device(name="d", host="10.0.0.2"),
            Device(name="e", host="::1")]
    resolve = {"localhost": {"127.0.0.1"}, "myhv.lan": {"10.0.0.7"}}
    got = detect_self(devs, local_ips=lambda: {"10.0.0.7", "127.0.0.1", "::1"},
                      resolve=lambda h: resolve.get(h.lower(), set()))
    assert got == {"b", "c", "e"}


def test_detect_self_default_local_ips_include_loopback():
    got = detect_self([Device(name="lo", host="127.0.0.1")], resolve=lambda h: set())
    assert got == {"lo"}


# ---- wake --------------------------------------------------------------------

async def test_wake_without_mac_fails_clearly(repo, svc, actions):
    repo.add(Device(name="nomac", host="10.0.0.3"))
    res = await svc.wake("nomac", caller="ui")
    assert res["nomac"]["ok"] is False
    assert "no MAC configured; run wake_check to discover one" in res["nomac"]["error"]
    assert actions.calls == []


async def test_wake_group_runs_without_confirm(svc, actions):
    res = await svc.wake("lab", caller="ui")
    assert set(res) == {"pve1", "pve2"}


# ---- run_command -------------------------------------------------------------

async def test_run_command_disabled_by_default(svc, runner, audit):
    with pytest.raises(RunCommandDisabled):
        await svc.run_command("pve1", "uptime", caller="mcp")
    assert runner.calls == []
    row = audit.list()[0]
    assert row["caller"] == "mcp" and row["action"] == "run_command" and "refused" in row["result"]


async def test_run_command_rejects_bulk_target(svc, repo, runner):
    for t in ("all", "lab"):
        with pytest.raises(InvalidRequest):
            await svc.run_command(t, "uptime", caller="api")
    with pytest.raises(UnknownTarget):
        await svc.run_command("nope", "uptime", caller="api")
    assert runner.calls == []


async def test_run_command_returns_truncated_output(svc, repo, runner):
    d = repo.get("pve1")
    d.allow_run_command = True
    repo.update(d)
    runner.result = RunResult("x" * (MAX_OUTPUT + 10), "e" * 5, 3)
    res = await svc.run_command("pve1", "cat big", caller="api")
    assert runner.calls == [("pve1", "cat big")]
    assert len(res["stdout"]) == MAX_OUTPUT and res["stderr"] == "eeeee"
    assert res["exit"] == 3 and res["truncated"] is True and res["ok"] is False


async def test_run_command_connect_failure_is_a_result(svc, repo, runner):
    d = repo.get("pve1")
    d.allow_run_command = True
    repo.update(d)
    runner.exc = ConnectFailed("connect to root@10.0.0.1:22 timed out after 30s")
    res = await svc.run_command("pve1", "uptime", caller="api")
    assert res["ok"] is False and "timed out" in res["error"]


# ---- auditing ----------------------------------------------------------------

async def test_every_action_audited_with_caller(svc, repo, audit, monkeypatch):
    d = repo.get("pve1")
    d.allow_run_command = True
    repo.update(d)

    async def fake_wol_check(runner, device):
        return WolReport(nic="eno1", mac=device.mac, supported=True, current_flags="g",
                         persistent=True, notes=[])
    svc._wol_check = fake_wol_check

    await svc.wake("pve1", caller="mcp")
    await svc.shutdown("pve1", caller="mcp")
    await svc.reboot("pve1", caller="mcp")
    await svc.wake_check("pve1", caller="mcp")
    await svc.run_command("pve1", "uptime", caller="mcp")
    with pytest.raises(ConfirmationRequired):
        await svc.reboot("all", caller="mcp")
    rows = list(reversed(audit.list()))
    assert [r["action"].split()[0] for r in rows] == [
        "wake", "shutdown", "shutdown", "reboot", "reboot", "wake_check", "run_command",
        "run_command", "reboot"]
    assert rows[1]["result"].startswith("attempt") and rows[3]["result"].startswith("attempt")
    assert rows[6]["result"].startswith("attempt") and rows[7]["result"].startswith("ok")
    assert all(r["caller"] == "mcp" for r in rows)
    assert rows[0]["target"] == "pve1" and rows[0]["result"].startswith("ok")
    assert rows[-1]["target"] == "all" and "refused" in rows[-1]["result"]
    assert "uptime" in rows[6]["action"] + rows[6]["result"]


async def test_failed_action_audited_as_fail(svc, actions, audit):
    actions.raise_for["pve2"] = HostKeyChanged("host key for [10.0.0.2]:22 changed")
    res = await svc.shutdown("lab", caller="ui", confirm=True)
    assert res["pve1"]["ok"] is True
    assert res["pve2"]["ok"] is False and "host key" in res["pve2"]["error"]
    rows = {r["target"]: r["result"] for r in audit.list()}
    assert rows["pve2"].startswith("fail") and "host key" in rows["pve2"]
    assert rows["pve1"].startswith("ok")


async def test_unexpected_exception_becomes_failed_result(svc, actions):
    actions.raise_for["pve1"] = SudoRequired("sudo needs a password")
    res = await svc.reboot("pve1", caller="ui")
    assert res["pve1"]["ok"] is False and "sudo" in res["pve1"]["error"]
    actions.raise_for["pve1"] = RuntimeError("boom")
    res = await svc.reboot("pve1", caller="ui")
    assert res["pve1"]["ok"] is False and "boom" in res["pve1"]["error"]


# ---- status / wake_check degrade ----------------------------------------------

INFO = Info(uptime_s=100, load1=0.5, mem_used_pct=10.0, disk_root_pct=20.0, cpu_temp_c=None,
            kernel="6.8", pve_version=None, vms_running=None, cts_running=None, fetched_at=1.0)


async def test_device_status_up_with_info_and_caches(repo, audit, actions, runner):
    calls = []

    async def collect(r, d):
        calls.append(d.name)
        return INFO
    state = {}
    svc = make_service(repo, audit, actions, runner, state=state, collect_info=collect)
    res = await svc.device_status("pve1")
    assert res["pve1"]["status"] == "up" and res["pve1"]["info"]["uptime_s"] == 100
    await svc.device_status("pve1")
    assert calls == ["pve1"]  # second call served from cache
    assert state["pve1"] is True
    listed = {d["name"]: d for d in await svc.list_devices()}
    assert listed["pve1"]["up"] is True and listed["pve1"]["info"]["kernel"] == "6.8"


async def test_device_status_degrades_to_unreachable(repo, audit, actions, runner):
    async def collect(r, d):
        raise ConnectFailed("connect to root@10.0.0.1:22 failed: refused")
    svc = make_service(repo, audit, actions, runner, collect_info=collect)
    res = await svc.device_status("pve1")
    assert res["pve1"]["status"] == "unreachable" and "refused" in res["pve1"]["error"]


async def test_device_status_down(repo, audit, actions, runner):
    svc = make_service(repo, audit, actions, runner, prober=FakeProber(up=False))
    res = await svc.device_status("pve1")
    assert res["pve1"]["status"] == "down" and res["pve1"]["info"] is None


async def test_wake_check_degrades_and_adopts_mac(repo, audit, actions, runner):
    repo.add(Device(name="nomac", host="10.0.0.3"))

    async def wol(r, d):
        if d.name == "pve1":
            raise ConnectFailed("connect to root@10.0.0.1:22 failed: no route")
        return WolReport(nic="eno1", mac="aa:bb:cc:dd:ee:ff", supported=True, current_flags="g",
                         persistent=False, notes=["not persistent"])
    svc = make_service(repo, audit, actions, runner)
    svc._wol_check = wol
    res = await svc.wake_check("pve1", caller="ui")
    assert res["pve1"]["ok"] is False and res["pve1"]["status"] == "unreachable"
    res = await svc.wake_check("nomac", caller="ui")
    assert res["nomac"]["ok"] is True and res["nomac"]["mac_adopted"] is True
    assert res["nomac"]["report"]["nic"] == "eno1" and res["nomac"]["ready"] is False
    assert repo.get("nomac").mac == "aa:bb:cc:dd:ee:ff"


# ---- list_devices ----------------------------------------------------------------

async def test_list_devices_has_state_and_no_secrets(repo, audit, actions, runner):
    d = repo.get("pve1")
    d.key_id = "pve1key"
    repo.update(d)
    svc = make_service(repo, audit, actions, runner, state={"pve1": True, "pve2": False})
    out = {d["name"]: d for d in await svc.list_devices()}
    assert out["pve1"]["up"] is True and out["pve2"]["up"] is False and out["pi"]["up"] is None
    assert out["pi"]["is_self"] is True
    assert out["pve1"]["info"] is None
    for d in out.values():
        assert "key_id" not in d and "id" not in d
        assert "password" not in str(d).lower()


# ---- host key acknowledge ------------------------------------------------------

async def test_acknowledge_sets_flag(repo, audit, actions, runner):
    svc = make_service(repo, audit, actions, runner)
    await svc.acknowledge_host_key("pve1", caller="ui")
    assert runner.acked == ["pve1"] and repo.get("pve1").host_key_ack is True
    assert audit.list()[0]["action"] == "acknowledge_host_key"
    with pytest.raises(UnknownTarget):
        await svc.acknowledge_host_key("nope", caller="ui")


def test_host_key_ack_clearer_persists_cleared_flag(repo):
    d = repo.get("pve1")
    d.host_key_ack = True
    repo.update(d)
    clear = host_key_ack_clearer(repo)
    clear(Device(name="pve1", host="x"))
    assert repo.get("pve1").host_key_ack is False
    clear(Device(name="gone", host="x"))  # unknown device: no-op


# ---- wake_test --------------------------------------------------------------------

async def test_wake_test_refuses_self_and_bulk(svc, actions, audit):
    res = await svc.wake_test("pi", caller="ui")
    assert res["pi"]["ok"] is False and "host Wakeboard runs on" in res["pi"]["stages"][0]["detail"]
    assert audit.list()[0]["action"] == "wake_test"
    with pytest.raises(InvalidRequest):
        await svc.wake_test("lab", caller="ui")
    assert actions.calls == []


async def test_detected_self_never_persisted_via_wake_check(repo, audit, actions, runner):
    repo.add(Device(name="hv", host="192.168.1.50"))

    async def wol(r, d):
        return WolReport(nic="eno1", mac="aa:bb:cc:dd:ee:50", supported=True, current_flags="g",
                         persistent=True, notes=[])
    svc = make_service(repo, audit, actions, runner, local=("192.168.1.50",))
    svc._wol_check = wol
    res = await svc.wake_check("hv", caller="ui")
    assert res["hv"]["mac_adopted"] is True
    saved = repo.get("hv")
    assert saved.mac == "aa:bb:cc:dd:ee:50" and saved.is_self is False


# ---- review fixes -----------------------------------------------------------------

import asyncio as _asyncio
import threading as _threading

from wakeboard.actions import Actions as _RealActions
from wakeboard.config import Settings as _Settings
from wakeboard.service import redact_cmd
from wakeboard.ssh import AuthFailed


@pytest.mark.parametrize("bad", ["false", "0", 1, "true", "yes"])
async def test_confirm_must_be_exactly_true(svc, actions, bad):
    with pytest.raises(ConfirmationRequired):
        await svc.shutdown("all", caller="mcp", confirm=bad)
    with pytest.raises(SelfTargetRefused):
        await svc.reboot("pi", caller="mcp", confirm=bad)
    with pytest.raises(ConfirmationRequired):
        await svc.reboot("lab", caller="mcp", confirm=bad)
    assert actions.calls == []


async def test_attempt_row_written_before_destructive_action(svc, actions, audit):
    await svc.shutdown("pve1", caller="ui")
    rows = list(reversed(audit.list()))
    assert rows[0]["result"] == "attempt: confirm=False targets=pve1"
    assert rows[1]["result"].startswith("ok")
    await svc.reboot("lab", caller="api", confirm=True)
    att = [r for r in audit.list() if r["action"] == "reboot" and r["result"].startswith("attempt")]
    assert att[0]["result"] == "attempt: confirm=True targets=pve1,pve2" and att[0]["target"] == "lab"


async def test_attempt_row_survives_process_dying_mid_action(svc, actions, audit):
    actions.raise_for["pi"] = _asyncio.CancelledError()
    with pytest.raises(_asyncio.CancelledError):
        await svc.shutdown("pi", caller="ui", confirm=True)
    rows = audit.list()
    assert any(r["target"] == "pi" and r["result"] == "attempt: confirm=True targets=pi" for r in rows)


async def test_adopt_mac_keeps_concurrent_edits(repo, audit, actions, runner):
    repo.add(Device(name="nomac", host="10.0.0.3"))

    async def wol(r, d):
        fresh = repo.get("nomac")         # someone edits the device mid-check
        fresh.allow_run_command = True
        fresh.notes = "edited"
        repo.update(fresh)
        return WolReport(nic="eno1", mac="aa:bb:cc:dd:ee:03", supported=True, current_flags="g",
                         persistent=True, notes=[])
    svc = make_service(repo, audit, actions, runner)
    svc._wol_check = wol
    res = await svc.wake_check("nomac", caller="ui")
    assert res["nomac"]["mac_adopted"] is True
    saved = repo.get("nomac")
    assert saved.mac == "aa:bb:cc:dd:ee:03"
    assert saved.allow_run_command is True and saved.notes == "edited"


def test_redact_cmd():
    assert redact_cmd("uptime") == "uptime"
    out = redact_cmd("mysql -psecret -u root --password=hunter2 x token=abc PASSWORD: zz")
    for secret in ("secret", "hunter2", "abc", "zz"):
        assert secret not in out
    assert "-p***" in out and "--password=***" in out and "token=***" in out
    out = redact_cmd("curl -H 'Authorization: Bearer abc.def' http://x")
    assert "abc.def" not in out and "Authorization: Bearer ***" in out
    out = redact_cmd("ssh -p 22 host")  # not a glued -p<word>
    assert out == "ssh -p 22 host"
    long = "echo " + "a" * 300
    out = redact_cmd(long)
    assert out.startswith(long[:120]) and len(out) < 200
    assert f"…(+{len(long) - 120} chars, sha256:" in out


async def test_run_command_audit_is_redacted(svc, repo, audit):
    d = repo.get("pve1")
    d.allow_run_command = True
    repo.update(d)
    await svc.run_command("pve1", "mysql -psecret -e 'select 1'", caller="api")
    row = audit.list()[0]
    assert "secret" not in row["result"] + row["action"] and "-p***" in row["result"]


@pytest.mark.parametrize("exc", [AuthFailed("authentication to root@10.0.0.1:22 failed"),
                                 SudoRequired("sudo needs a password"),
                                 HostKeyChanged("host key changed"),
                                 RuntimeError("weird")])
async def test_wake_check_failure_shape_is_uniform(repo, audit, actions, runner, exc, caplog):
    async def wol(r, d):
        raise exc
    svc = make_service(repo, audit, actions, runner)
    svc._wol_check = wol
    res = (await svc.wake_check("pve1", caller="ui"))["pve1"]
    assert set(res) == {"ok", "status", "report", "ready", "mac_adopted", "stages", "error"}
    assert res["ok"] is False and res["status"] in ("unreachable", "error") and str(exc) in res["error"]
    expected = not isinstance(exc, RuntimeError)
    recs = [r for r in caplog.records if r.name == "wakeboard.service"]
    assert recs and all((r.exc_info is None) == expected for r in recs)
    assert all(r.levelname == ("WARNING" if expected else "ERROR") for r in recs)


async def test_expected_action_errors_logged_without_traceback(svc, actions, caplog):
    actions.raise_for["pve1"] = ConnectFailed("connect timed out")
    await svc.reboot("pve1", caller="ui")
    recs = [r for r in caplog.records if r.name == "wakeboard.service"]
    assert recs and all(r.levelname == "WARNING" and r.exc_info is None for r in recs)


async def test_run_command_refuses_self(repo, audit, actions, runner):
    repo.add(Device(name="hv", host="192.168.1.50", allow_run_command=True))
    pi = repo.get("pi")
    pi.allow_run_command = True
    repo.update(pi)
    svc = make_service(repo, audit, actions, runner, local=("192.168.1.50",))
    for name in ("pi", "hv"):
        with pytest.raises(RunCommandDisabled) as ei:
            await svc.run_command(name, "uptime", caller="mcp")
        assert "Wakeboard runs on" in str(ei.value)
        assert "refused" in audit.list()[0]["result"]
    assert runner.calls == []


async def test_run_command_takes_the_actions_device_lock(repo, audit, runner, tmp_path):
    real = _RealActions(runner, FakeProber(), _Settings(data_dir=tmp_path))
    d = repo.get("pve1")
    d.allow_run_command = True
    repo.update(d)
    svc = make_service(repo, audit, real, runner)
    lock = real._lock(repo.get("pve1"))
    await lock.acquire()
    try:
        res = await svc.run_command("pve1", "uptime", caller="api")
    finally:
        lock.release()
    assert res["ok"] is False and "in progress" in res["error"] and runner.calls == []
    res = await svc.run_command("pve1", "uptime", caller="api")
    assert res["ok"] is True and not lock.locked()


# ---- re-review: fail-closed attempt row, harder redaction ----------------------------

from wakeboard.service import AuditUnavailable


class BrokenAudit:
    def __init__(self, inner):
        self.inner = inner

    def record(self, *a):
        raise RuntimeError("database is locked")

    def __getattr__(self, n):
        return getattr(self.inner, n)


@pytest.mark.parametrize("call", [
    lambda s: s.shutdown("pve1", caller="ui"),
    lambda s: s.shutdown("all", caller="ui", confirm=True),
    lambda s: s.reboot("pi", caller="ui", confirm=True),
])
async def test_attempt_audit_fails_closed(repo, audit, actions, runner, call):
    svc = make_service(repo, BrokenAudit(audit), actions, runner)
    with pytest.raises(AuditUnavailable):
        await call(svc)
    assert actions.calls == []


async def test_result_row_failure_still_swallowed(repo, audit, actions, runner):
    class FailAfterAttempt(BrokenAudit):
        def record(self, caller, target, action, result):
            if result.startswith("attempt"):
                return self.inner.record(caller, target, action, result)
            raise RuntimeError("disk full")
    svc = make_service(repo, FailAfterAttempt(audit), actions, runner)
    res = await svc.shutdown("pve1", caller="ui")
    assert res["pve1"]["ok"] is True


@pytest.mark.parametrize("cmd,secret,keep", [
    ("sshpass -p secret ssh root@h", "secret", "sshpass -p *** ssh"),
    ("mysql -u root -p hunter2 db", "hunter2", "-p ***"),
    ("mysql -p'my secret' db", "my secret", "-p***"),
    ('mysql -p"my secret" db', "my secret", "-p***"),
    ("tool -p'quoted' x", "quoted", "-p***"),
    ("app --password 'two words'", "two words", "--password ***"),
    ('app --token "a b c"', "a b c", "--token ***"),
    ("env password='x y z' run", "x y z", "password=***"),
    ('env secret="s p" run', "s p", "secret=***"),
    ("env passwd='q' token='w w'", "w w", "token=***"),
    ("git clone https://bob:pa55@github.com/x.git", "pa55", "https://bob:***@github.com"),
    ("curl -u admin:letmein http://h", "letmein", "-u admin:***"),
    ("curl --user admin:letmein http://h", "letmein", "--user admin:***"),
    ('curl -u "admin:let me in" http://h', "me in", '-u "admin:***"'),
    ("curl -H 'X: Bearer tok123' http://h", "tok123", "Bearer ***"),
    ("echo Bearer abc.def", "abc.def", "Bearer ***"),
])
def test_redact_cmd_cases(cmd, secret, keep):
    out = redact_cmd(cmd)
    assert secret not in out, out
    assert keep in out, out


@pytest.mark.parametrize("cmd", [
    "find / -name x -print", "ssh -p 22 host", "ls -u x:y", "mkdir -p /tmp/a",
    "psql-less -print", "uptime",
])
def test_redact_cmd_leaves_harmless_commands(cmd):
    assert redact_cmd(cmd) == cmd


# ---- audit-first for run_command and wake_test --------------------------------------

async def test_run_command_attempt_audit_fails_closed(repo, audit, actions, runner):
    d = repo.get("pve1")
    d.allow_run_command = True
    repo.update(d)
    svc = make_service(repo, BrokenAudit(audit), actions, runner)
    with pytest.raises(AuditUnavailable):
        await svc.run_command("pve1", "uptime", caller="api")
    assert runner.calls == []


async def test_run_command_writes_attempt_row_first(repo, audit, actions, runner):
    d = repo.get("pve1")
    d.allow_run_command = True
    repo.update(d)
    svc = make_service(repo, audit, actions, runner)
    await svc.run_command("pve1", "echo password=hunter2", caller="api")
    rows = [r for r in audit.list() if r["action"] == "run_command"]
    results = [r["result"] for r in rows]
    assert any(x.startswith("attempt: targets=pve1 | ") for x in results), results
    assert all("hunter2" not in x for x in results)


async def test_wake_test_attempt_audit_fails_closed(repo, audit, actions, runner):
    svc = make_service(repo, BrokenAudit(audit), actions, runner)
    with pytest.raises(AuditUnavailable):
        await svc.wake_test("pve1", caller="ui")
    assert actions.calls == []


# ---- self detection: every local interface address ------------------------------------

from wakeboard.service import default_local_ips, interface_ips

FIB_TRIE = """Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 100.64.0.0/10 2 0 2
        |-- 100.101.102.103
           /32 host LOCAL
        |-- 100.90.1.1
           /32 universe UNICAST
     +-- 172.17.0.0/16 2 0 2
        |-- 172.17.0.0
           /32 link BROADCAST
        |-- 172.17.0.1
           /32 host LOCAL
     |-- 192.168.1.50
        /32 host LOCAL
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 192.168.1.50
        /32 host LOCAL
"""
IF_INET6 = """fd7a115ca1e0000000000000b93a370d 03 80 00 80 tailscale0
fe800000000000002fa4cd3f3e0ae9ec 03 40 20 80 tailscale0
00000000000000000000000000000001 01 80 10 80       lo
"""


def test_interface_ips_parses_proc_files(tmp_path):
    (tmp_path / "fib_trie").write_text(FIB_TRIE)
    (tmp_path / "if_inet6").write_text(IF_INET6)
    got = interface_ips(tmp_path / "fib_trie", tmp_path / "if_inet6")
    assert got == {"100.101.102.103", "172.17.0.1", "192.168.1.50",
                   "fd7a:115c:a1e0::b93a:370d", "fe80::2fa4:cd3f:3e0a:e9ec", "::1"}
    # peers routed via tailscale (UNICAST) and broadcast entries are not local
    assert "100.90.1.1" not in got and "172.17.0.0" not in got


def test_interface_ips_missing_files_is_empty(tmp_path):
    assert interface_ips(tmp_path / "nope", tmp_path / "nope6") == set()


def test_default_local_ips_includes_interfaces(monkeypatch):
    import wakeboard.service as s
    monkeypatch.setattr(s, "interface_ips", lambda *a, **k: {"100.101.102.103", "172.17.0.1"})
    got = default_local_ips()
    assert {"100.101.102.103", "172.17.0.1", "127.0.0.1", "::1"} <= got


def test_detect_self_matches_tailscale_and_docker_bridge_addresses():
    devs = [Device(name="ts", host="100.101.102.103"), Device(name="br", host="172.17.0.1"),
            Device(name="v6", host="fd7a:115c:a1e0::b93a:370d"), Device(name="other", host="10.0.0.9")]
    local = {"192.168.1.50", "100.101.102.103", "172.17.0.1", "fd7a:115c:a1e0::b93a:370d"}
    assert detect_self(devs, local_ips=lambda: local, resolve=lambda h: set()) == {"ts", "br", "v6"}
