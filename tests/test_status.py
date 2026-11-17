import asyncio

import pytest

from wakeboard.devices import Device
from wakeboard.ssh import RunResult
from wakeboard.status import (Info, InfoCache, InfoError, Poller, Prober,
                              collect_info, info_command, parse_info)

LINUX = "uptime=12345.67\nload1=0.42\nmem=37.5\ndisk=61\ntemp=48000\nkernel=6.8.0-1\n"
PVE = LINUX + "pve=8.2.4\nvms=3\ncts=5\n"


def dev(name="a", type="linux"):
    return Device(name=name, host="127.0.0.1", type=type)


async def _true(d):
    return True


async def _false(d):
    return False


async def test_is_up_true_when_tcp_connects():
    assert await Prober(ping=_false, tcp=_true).is_up(dev())


async def test_is_up_true_when_only_ping_works():
    assert await Prober(ping=_true, tcp=_false).is_up(dev())


async def test_is_up_false_on_timeout():
    async def slow(d):
        raise asyncio.TimeoutError
    assert not await Prober(ping=_false, tcp=slow).is_up(dev())


async def test_default_tcp_check():
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        d = Device(name="x", host="127.0.0.1", ssh_port=port)
        assert await Prober(ping=_false).is_up(d)
    finally:
        server.close()
    assert not await Prober(ping=_false).is_up(d)


def test_collect_info_parses_linux_output():
    i = parse_info(LINUX, False)
    assert i.uptime_s == 12345 and i.load1 == 0.42 and i.mem_used_pct == 37.5
    assert i.disk_root_pct == 61 and i.cpu_temp_c == 48.0 and i.kernel == "6.8.0-1"
    assert i.pve_version is None and i.vms_running is None and i.cts_running is None


def test_collect_info_parses_proxmox_counts():
    i = parse_info(PVE, True)
    assert (i.pve_version, i.vms_running, i.cts_running) == ("8.2.4", 3, 5)
    assert parse_info(PVE, False).pve_version is None


def test_missing_temp_is_none():
    assert parse_info(LINUX.replace("temp=48000\n", ""), False).cpu_temp_c is None
    assert parse_info(LINUX.replace("temp=48000", "temp="), False).cpu_temp_c is None


def test_unparseable_raises():
    with pytest.raises(InfoError):
        parse_info("garbage", False)
    with pytest.raises(InfoError):
        parse_info(LINUX.replace("load1=0.42", "load1=abc"), False)


class FakeRunner:
    def __init__(self, result):
        self.result, self.cmds = result, []

    async def run(self, device, cmd, timeout=30):
        self.cmds.append(cmd)
        return self.result


async def test_collect_info_runs_one_command():
    r = FakeRunner(RunResult(PVE, "", 0))
    i = await collect_info(r, dev(type="proxmox"))
    assert len(r.cmds) == 1 and "pveversion" in r.cmds[0] and i.vms_running == 3
    r = FakeRunner(RunResult(LINUX, "", 0))
    await collect_info(r, dev())
    assert "pveversion" not in r.cmds[0]


async def test_collect_info_nonzero_raises():
    with pytest.raises(InfoError):
        await collect_info(FakeRunner(RunResult("", "boom", 3)), dev())


def test_info_cache_expires():
    now = [100.0]
    c = InfoCache(ttl=60, clock=lambda: now[0])
    i = parse_info(LINUX, False)
    assert c.get("a") is None
    c.put("a", i)
    assert c.get("a") is i
    now[0] = 161
    assert c.get("a") is None


class ByName:
    def __init__(self, up, boom=()):
        self.up, self.boom = up, boom

    async def is_up(self, d):
        if d.name in self.boom:
            raise RuntimeError("x")
        return d.name in self.up


async def test_poller_updates_state_for_all_devices(conn):
    from wakeboard.devices import DeviceRepo
    repo = DeviceRepo(conn)
    for n in "abc":
        repo.add(Device(name=n, host="h"))
    state = {"gone": True}
    calls = []

    async def sleep(s):
        calls.append(s)
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await Poller(sleep=sleep).run(repo, ByName({"a"}, boom={"c"}), state, 7)
    assert state == {"a": True, "b": False, "c": False}
    assert calls == [7]
