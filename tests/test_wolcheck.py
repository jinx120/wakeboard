"""WoL readiness check and wake test, with fake runner / actions (no SSH, no sleeping)."""
import pytest

from wakeboard.actions import ActionResult, StageResult
from wakeboard.audit import AuditLog
from wakeboard.devices import Device, DeviceRepo
from wakeboard.ssh import ConnectFailed, RunResult
from wakeboard.wolcheck import WolReport, adopt_mac, parse_ethtool_wol, wake_test, wol_check

IP_LINK = (
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
    "2: eno1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\\    link/ether aa:bb:cc:dd:ee:01 brd ff:ff:ff:ff:ff:ff\n"
    "3: wlan0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\\    link/ether aa:bb:cc:dd:ee:02 brd ff:ff:ff:ff:ff:ff\n"
)
ROUTE = "1.1.1.1 via 192.168.1.1 dev eno1 src 192.168.1.50 uid 0 \\    cache\n"


def ethtool(supports="pumbg", current="g"):
    return (f"Settings for eno1:\n\tSupports Wake-on: {supports}\n\tWake-on: {current}\n"
            "\tLink detected: yes\n")


class FakeRunner:
    def __init__(self, canned):
        self.canned = canned  # substring -> RunResult | Exception
        self.cmds = []

    async def run(self, device, cmd, timeout=30):
        self.cmds.append(cmd)
        for key, val in self.canned.items():
            if key in cmd:
                if isinstance(val, Exception):
                    raise val
                return val
        return RunResult("", "command not found", 127)


def ok(out=""):
    return RunResult(out, "", 0)


def dev(**kw):
    kw.setdefault("name", "box")
    kw.setdefault("host", "10.0.0.5")
    return Device(**kw)


def test_parse_ethtool_wol_g():
    assert parse_ethtool_wol(ethtool("pumbg", "g")) == ("pumbg", "g")


def test_parse_ethtool_wol_d_flags_not_ready():
    assert parse_ethtool_wol(ethtool("pumbg", "d")) == ("pumbg", "d")
    assert parse_ethtool_wol("nothing here") == ("", "")


async def test_wol_check_ready_by_mac_case_insensitive():
    r = FakeRunner({"ip -o link": ok(IP_LINK), "ethtool": ok(ethtool()),
                    "grep": ok("/etc/systemd/network/10-eno1.link:WakeOnLan=magic")})
    rep = await wol_check(r, dev(mac="AA:BB:CC:DD:EE:01"))
    assert rep.nic == "eno1" and rep.supported and rep.current_flags == "g"
    assert rep.persistent is True
    assert rep.notes == ["persistence is a config-file heuristic, not verified at boot"]


async def test_wol_check_captures_mac_when_missing():
    r = FakeRunner({"ip -o link": ok(IP_LINK), "route get": ok(ROUTE),
                    "ethtool": ok(ethtool()), "grep": ok("x")})
    rep = await wol_check(r, dev())
    assert rep.nic == "eno1" and rep.mac == "aa:bb:cc:dd:ee:01"


async def test_adopt_mac_only_when_missing(conn):
    repo = DeviceRepo(conn)
    d = repo.add(dev())
    rep = WolReport("eno1", "aa:bb:cc:dd:ee:01", True, "g", True, [])
    assert adopt_mac(repo, d, rep) is True
    assert repo.get("box").mac == "aa:bb:cc:dd:ee:01"
    rep2 = WolReport("eno1", "aa:bb:cc:dd:ee:09", True, "g", True, [])
    assert adopt_mac(repo, repo.get("box"), rep2) is False
    assert repo.get("box").mac == "aa:bb:cc:dd:ee:01"


async def test_wol_check_flags_non_persistent():
    r = FakeRunner({"ip -o link": ok(IP_LINK), "ethtool": ok(ethtool()),
                    "grep": RunResult("", "", 1)})
    rep = await wol_check(r, dev(mac="aa:bb:cc:dd:ee:01"))
    assert rep.persistent is False
    assert any("persist" in n for n in rep.notes)


async def test_wol_check_supported_but_current_d():
    r = FakeRunner({"ip -o link": ok(IP_LINK), "ethtool": ok(ethtool("pumbg", "d")),
                    "grep": ok("x")})
    rep = await wol_check(r, dev(mac="aa:bb:cc:dd:ee:01"))
    assert rep.supported is True and rep.current_flags == "d"
    assert any("not enabled" in n for n in rep.notes)


async def test_wol_check_missing_ethtool_is_a_note():
    r = FakeRunner({"ip -o link": ok(IP_LINK)})  # ethtool -> exit 127
    rep = await wol_check(r, dev(mac="aa:bb:cc:dd:ee:01"))
    assert rep.supported is False and rep.nic == "eno1"
    assert any("ethtool" in n for n in rep.notes)


async def test_wol_check_no_matching_nic():
    r = FakeRunner({"ip -o link": ok(IP_LINK)})
    rep = await wol_check(r, dev(mac="11:22:33:44:55:66"))
    assert rep.nic is None and rep.supported is False and rep.notes


async def test_wol_check_ip_failure_is_a_note():
    rep = await wol_check(FakeRunner({}), dev(mac="aa:bb:cc:dd:ee:01"))
    assert rep.nic is None and rep.notes


async def test_wol_check_rejects_hostile_nic_name():
    link = "2: x;reboot: <UP> mtu 1\\    link/ether aa:bb:cc:dd:ee:01 brd ff:ff:ff:ff:ff:ff\n"
    r = FakeRunner({"ip -o link": ok(link)})
    rep = await wol_check(r, dev(mac="aa:bb:cc:dd:ee:01"))
    assert rep.nic is None and rep.notes
    assert not any("reboot" in c for c in r.cmds)


async def test_wol_check_connect_failure_propagates():
    with pytest.raises(ConnectFailed):
        await wol_check(FakeRunner({"ip": ConnectFailed("down")}), dev(mac="aa:bb:cc:dd:ee:01"))


# ---- wake_test ------------------------------------------------------------

class FakeActions:
    def __init__(self, shutdown_res, wake_res=None):
        self.shutdown_res, self.wake_res, self.calls = shutdown_res, wake_res, []

    async def shutdown(self, device, mode=None, progress=None):
        self.calls.append("shutdown")
        return self.shutdown_res

    async def wake(self, device, progress=None):
        self.calls.append("wake")
        return self.wake_res


GOOD = ActionResult(True, [StageResult("down", True)])
WAKE_OK = ActionResult(True, [StageResult("magic_packet", True), StageResult("ping", True)])


async def test_wake_test_stamps_pass_result(conn):
    repo, audit = DeviceRepo(conn), AuditLog(conn)
    d = repo.add(dev(mac="aa:bb:cc:dd:ee:01"))
    a = FakeActions(GOOD, WAKE_OK)
    res = await wake_test(a, repo, audit, d, now=lambda: 1234.5)
    assert res.ok and a.calls == ["shutdown", "wake"]
    got = repo.get("box")
    assert got.wake_test_result == "pass" and got.wake_test_at == 1234.5
    assert audit.list()[0]["action"] == "wake_test" and audit.list()[0]["caller"] == "ui"


async def _seed(conn):
    repo = DeviceRepo(conn)
    d = repo.add(dev(mac="aa:bb:cc:dd:ee:01"))
    d.wake_test_result, d.wake_test_at = "pass", 7.0
    repo.update(d)
    return repo, AuditLog(conn), d


async def test_wake_test_lock_rejection_not_stamped(conn):
    repo, audit, d = await _seed(conn)
    a = FakeActions(ActionResult(False, [StageResult("lock", False, "action in progress")]))
    res = await wake_test(a, repo, audit, d, now=lambda: 99.0)
    assert not res.ok and a.calls == ["shutdown"]
    got = repo.get("box")
    assert (got.wake_test_result, got.wake_test_at) == ("pass", 7.0)
    assert audit.list()[0]["result"] == "not run: action in progress"


async def test_wake_test_already_down_not_stamped(conn):
    repo, audit, d = await _seed(conn)
    a = FakeActions(ActionResult(False, [StageResult("precheck", False, "already down")]))
    await wake_test(a, repo, audit, d, now=lambda: 99.0)
    assert repo.get("box").wake_test_result == "pass"
    assert audit.list()[0]["result"] == "not run: already down"


async def test_wake_test_real_shutdown_failure_stamps_detail(conn):
    repo, audit, d = await _seed(conn)
    a = FakeActions(ActionResult(False, [StageResult("precheck", True),
                                         StageResult("down", False, "host still up after 120s")]))
    await wake_test(a, repo, audit, d, now=lambda: 99.0)
    assert a.calls == ["shutdown"]
    assert repo.get("box").wake_test_result == "fail: shutdown: host still up after 120s"


class RaisingActions(FakeActions):
    def __init__(self, on, exc, shutdown_res=GOOD):
        super().__init__(shutdown_res)
        self.on, self.exc = on, exc

    async def shutdown(self, device, mode=None, progress=None):
        if self.on == "shutdown":
            raise self.exc
        return await super().shutdown(device, mode, progress)

    async def wake(self, device, progress=None):
        raise self.exc


async def test_wake_test_shutdown_exception_stamps_and_reraises(conn):
    repo, audit, d = await _seed(conn)
    with pytest.raises(ConnectFailed):
        await wake_test(RaisingActions("shutdown", ConnectFailed("no route")), repo, audit, d,
                        now=lambda: 3.0)
    assert repo.get("box").wake_test_result == "error: no route"
    assert audit.list()[0]["result"] == "error: no route"


async def test_wake_test_wake_exception_stamps_and_reraises(conn):
    repo, audit, d = await _seed(conn)
    with pytest.raises(ConnectFailed):
        await wake_test(RaisingActions("wake", ConnectFailed("boom")), repo, audit, d,
                        now=lambda: 3.0)
    assert repo.get("box").wake_test_result == "error: boom"


async def test_wake_test_cancelled_after_shutdown_stamps(conn):
    import asyncio
    repo, audit, d = await _seed(conn)
    with pytest.raises(asyncio.CancelledError):
        await wake_test(RaisingActions("wake", asyncio.CancelledError()), repo, audit, d,
                        now=lambda: 3.0)
    assert repo.get("box").wake_test_result == "error: cancelled"


async def test_wake_test_wake_lock_is_error_not_fail(conn):
    repo, audit, d = await _seed(conn)
    lock = ActionResult(False, [StageResult("lock", False, "action in progress")])
    await wake_test(FakeActions(GOOD, lock), repo, audit, d, now=lambda: 3.0)
    assert repo.get("box").wake_test_result == "error: wake not run: action in progress"


async def test_wake_test_device_deleted_midway_skips_update(conn):
    repo, audit, d = await _seed(conn)

    class Deleting(FakeActions):
        async def wake(self, device, progress=None):
            repo.remove("box")
            return await super().wake(device, progress)

    await wake_test(Deleting(GOOD, WAKE_OK), repo, audit, d)
    assert repo.get("box") is None
    assert "not stamped" in audit.list()[0]["result"]


async def test_wol_check_persistence_false_positive_unrelated_wol():
    r = FakeRunner({"ip -o link": ok(IP_LINK), "ethtool": ok(ethtool()),
                    "grep": ok("/etc/network/interfaces:post-up ethtool -s eth9 wol g\n"
                               "/etc/systemd/network/a.link:Name=eth9")})
    rep = await wol_check(r, dev(mac="aa:bb:cc:dd:ee:01"))
    assert rep.persistent is False


async def test_wol_check_persistence_true_adds_heuristic_note():
    r = FakeRunner({"ip -o link": ok(IP_LINK), "ethtool": ok(ethtool()),
                    "grep": ok("/etc/network/interfaces:post-up ethtool -s eno1 wol g")})
    rep = await wol_check(r, dev(mac="aa:bb:cc:dd:ee:01"))
    assert rep.persistent is True
    assert "persistence is a config-file heuristic, not verified at boot" in rep.notes


async def test_wol_check_grep_uses_sudo_and_nic_for_non_root():
    r = FakeRunner({"ip -o link": ok(IP_LINK), "ethtool": ok(ethtool()), "grep": RunResult("", "", 1)})
    await wol_check(r, dev(mac="aa:bb:cc:dd:ee:01", ssh_user="bob"))
    g = next(c for c in r.cmds if "grep" in c)
    assert g.startswith("sudo -n grep") and "eno1" in g


async def test_wol_check_sys_class_net_mac_fallback():
    link = "1: lo: <LOOPBACK> mtu 1\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
    r = FakeRunner({"ip -o link": ok(link), "route get": ok(ROUTE),
                    "/sys/class/net/eno1/address": ok("AA:BB:CC:DD:EE:01\n"),
                    "ethtool": ok(ethtool()), "grep": RunResult("", "", 1)})
    rep = await wol_check(r, dev())
    assert rep.nic == "eno1" and rep.mac == "aa:bb:cc:dd:ee:01"


async def test_wake_test_stamps_fail_when_never_wakes(conn):
    repo, audit = DeviceRepo(conn), AuditLog(conn)
    d = repo.add(dev(mac="aa:bb:cc:dd:ee:01"))
    bad = ActionResult(False, [StageResult("magic_packet", True),
                               StageResult("ping", False, "timed out after 300s")])
    res = await wake_test(FakeActions(GOOD, bad), repo, audit, d, now=lambda: 5.0)
    assert not res.ok
    assert repo.get("box").wake_test_result == "fail: timed out after 300s"


async def test_wake_test_shutdown_failure_skips_wake(conn):
    repo, audit = DeviceRepo(conn), AuditLog(conn)
    d = repo.add(dev())
    a = FakeActions(ActionResult(False, [StageResult("down", False, "host still up")]))
    res = await wake_test(a, repo, audit, d, now=lambda: 1.0)
    assert not res.ok and a.calls == ["shutdown"]
    assert repo.get("box").wake_test_result == "fail: shutdown: host still up"


async def test_wake_test_refuses_self(conn):
    repo, audit = DeviceRepo(conn), AuditLog(conn)
    d = repo.add(dev(is_self=True))
    a = FakeActions(GOOD, WAKE_OK)
    res = await wake_test(a, repo, audit, d)
    assert not res.ok and a.calls == []
    assert res.stages == [StageResult("precheck", False,
                                      "refusing to wake-test the host Wakeboard runs on")]
    assert repo.get("box").wake_test_result is None


class BrokenRepo:
    def __init__(self, repo):
        self.repo = repo

    def get(self, name):
        return self.repo.get(name)

    def update(self, d):
        raise RuntimeError("db locked")


async def test_wake_test_bookkeeping_failure_keeps_original_exception(conn):
    repo, audit, d = await _seed(conn)
    with pytest.raises(ConnectFailed, match="no route"):
        await wake_test(RaisingActions("shutdown", ConnectFailed("no route")),
                        BrokenRepo(repo), audit, d)


async def test_wake_test_bookkeeping_failure_keeps_cancellation(conn):
    import asyncio
    repo, audit, d = await _seed(conn)
    with pytest.raises(asyncio.CancelledError):
        await wake_test(RaisingActions("wake", asyncio.CancelledError()),
                        BrokenRepo(repo), audit, d)


async def test_wol_check_persistence_nic_whole_word_only():
    r = FakeRunner({"ip -o link": ok(IP_LINK), "ethtool": ok(ethtool()),
                    "grep": ok("/etc/network/interfaces:post-up ethtool -s eno10 wol g")})
    rep = await wol_check(r, dev(mac="aa:bb:cc:dd:ee:01"))
    assert rep.persistent is False
