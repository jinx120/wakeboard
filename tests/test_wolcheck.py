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
                    "grep": ok("/etc/systemd/network/10-eno1.link")})
    rep = await wol_check(r, dev(mac="AA:BB:CC:DD:EE:01"))
    assert rep.nic == "eno1" and rep.supported and rep.current_flags == "g"
    assert rep.persistent is True and rep.notes == []


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
    a = FakeActions(ActionResult(False, [StageResult("precheck", False, "already down")]))
    res = await wake_test(a, repo, audit, d, now=lambda: 1.0)
    assert not res.ok and a.calls == ["shutdown"]
    assert repo.get("box").wake_test_result == "fail: shutdown failed"


async def test_wake_test_refuses_self(conn):
    repo, audit = DeviceRepo(conn), AuditLog(conn)
    d = repo.add(dev(is_self=True))
    a = FakeActions(GOOD, WAKE_OK)
    res = await wake_test(a, repo, audit, d)
    assert not res.ok and a.calls == []
    assert res.stages == [StageResult("precheck", False,
                                      "refusing to wake-test the host Wakeboard runs on")]
    assert repo.get("box").wake_test_result is None
