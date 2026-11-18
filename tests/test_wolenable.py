"""enable_wol presets and autodetect with a fake runner (nothing touches a real host)."""
import base64
import shlex

import pytest

from wakeboard.devices import Device
from wakeboard.ssh import ConnectFailed, RunResult
from wakeboard.wolenable import PRESETS, SUDO_MSG, build_script, enable_wol
from tests.test_wolcheck import FakeRunner, IP_LINK, ROUTE, dev, ethtool, ok

MAC = "aa:bb:cc:dd:ee:01"


class SeqEthRunner(FakeRunner):
    """ethtool reports 'd' until a script that sets wol has run, then 'g'."""
    def __init__(self, canned):
        super().__init__(canned)
        self.applied = False

    async def run(self, device, cmd, timeout=30):
        if "sh -c" in cmd:
            self.applied = True
        if cmd.endswith("ethtool eno1") or cmd == "ethtool eno1":
            self.cmds.append(cmd)
            return ok(ethtool("pumbg", "g" if self.applied else "d"))
        return await super().run(device, cmd, timeout)


def base(**extra):
    c = {"sudo -n true": ok(), "ip -o link": ok(IP_LINK), "grep -rIsiE": RunResult("", "", 1),
         "sh -c": ok("done")}
    c.update(extra)
    return c


def script_of(r):
    cmd = next(c for c in r.cmds if "sh -c" in c)
    toks = shlex.split(cmd)
    return toks[toks.index("-c") + 1]


async def run(preset, canned, device=None):
    r = SeqEthRunner(canned)
    res, mac = await enable_wol(r, device or dev(ssh_user="u", mac=MAC), preset)
    return r, res, mac


async def test_systemd_unit_explicit():
    r, res, _ = await run("systemd-unit", base())
    assert res.ok and [s.stage for s in res.stages] == ["detect", "apply", "verify"]
    s = script_of(r)
    assert "wakeboard-wol@.service" in s and "daemon-reload" in s
    assert "enable --now wakeboard-wol@eno1.service" in s
    assert "command -v ethtool" in s and "@ETHTOOL@" in s and '-s eno1 wol g' in s
    assert r.cmds[-2].startswith("sudo -n sh -c")


async def test_root_has_no_sudo():
    r, res, _ = await run("systemd-unit", base(), dev(ssh_user="root", mac=MAC))
    assert res.ok and not any("sudo" in c for c in r.cmds)


async def test_networkmanager_explicit():
    r, res, _ = await run("networkmanager", base(**{"nmcli -g": ok("Wired connection 1\n")}))
    assert res.ok
    s = script_of(r)
    assert "nmcli connection modify 'Wired connection 1' 802-3-ethernet.wake-on-lan magic" in s
    assert "-s eno1 wol g" in s


async def test_networkmanager_no_connection_fails():
    r, res, _ = await run("networkmanager", base(**{"nmcli -g": ok("\n")}))
    assert not res.ok and res.stages[-1].stage == "detect"
    assert not any("sh -c" in c for c in r.cmds)


async def test_networkd_link_file():
    r, res, _ = await run("systemd-networkd", base())
    s = script_of(r)
    assert res.ok and "/etc/systemd/network/50-wakeboard-wol-eno1.link" in s
    assert f"MACAddress={MAC}" in s and "WakeOnLan=magic" in s


def test_networkd_needs_mac():
    with pytest.raises(ValueError, match="MAC"):
        build_script("systemd-networkd", "eno1", None)


async def test_ifupdown():
    r, res, _ = await run("ifupdown", base())
    s = script_of(r)
    assert res.ok and "/etc/network/interfaces.d/wakeboard-wol-eno1" in s
    assert "post-up @ETHTOOL@ -s eno1 wol g" in s


async def test_auto_prefers_networkmanager():
    r, res, _ = await run("auto", base(**{"cmd /c ver": RunResult("", "", 127),
        "is-active NetworkManager": ok("active\n"), "nmcli -g": ok("lan\n")}))
    assert res.ok and "networkmanager" in res.stages[0].detail
    assert "nmcli connection modify lan" in script_of(r)


async def test_auto_nm_inactive_goes_systemd_unit():
    r, res, _ = await run("auto", base(**{"is-active NetworkManager": RunResult("inactive\n", "", 3),
                                          "command -v systemctl": ok("/bin/systemctl")}))
    assert res.ok and "systemd-unit" in res.stages[0].detail


async def test_auto_nm_active_but_no_conn_falls_back():
    r, res, _ = await run("auto", base(**{"is-active NetworkManager": ok("active\n"),
                                          "nmcli -g": ok("--\n"), "command -v systemctl": ok("x")}))
    assert "systemd-unit" in res.stages[0].detail


async def test_auto_ifupdown_when_no_systemctl():
    r, res, _ = await run("auto", base(**{"test -e /etc/network/interfaces": ok()}))
    assert res.ok and "ifupdown" in res.stages[0].detail


async def test_auto_nothing_fails_clearly():
    r, res, _ = await run("auto", base())
    assert not res.ok and "choose a preset" in res.stages[-1].detail


async def test_sudo_required():
    r, res, _ = await run("auto", base(**{"sudo -n true": RunResult("", "sudo: a password is required", 1)}))
    assert not res.ok and res.stages[-1].detail == SUDO_MSG and "sudo -n required" in SUDO_MSG
    assert not any("sh -c" in c for c in r.cmds)


async def test_verify_failure_reported():
    r = FakeRunner(base(**{"ethtool eno1": ok(ethtool("pumbg", "d")), "command -v systemctl": ok("x")}))
    res, _ = await enable_wol(r, dev(ssh_user="u", mac=MAC), "systemd-unit")
    assert not res.ok and res.stages[-1].stage == "verify"


async def test_unsupported_nic_fails_at_detect():
    r = FakeRunner(base(**{"ethtool eno1": ok(ethtool("d", "d"))}))
    res, _ = await enable_wol(r, dev(ssh_user="u", mac=MAC), "systemd-unit")
    assert not res.ok and res.stages[-1].stage == "detect"


async def test_connect_failure_propagates():
    r = FakeRunner({"cmd /c ver": ConnectFailed("down")})
    with pytest.raises(ConnectFailed):
        await enable_wol(r, dev(), "auto")


async def test_adopts_discovered_mac():
    r = SeqEthRunner(base(**{"ip -o route get": ok(ROUTE), "systemctl": ok("x")}))
    res, mac = await enable_wol(r, dev(ssh_user="u"), "systemd-unit")
    assert res.ok and mac == MAC


async def test_unknown_preset_rejected():
    r = FakeRunner({})
    res, _ = await enable_wol(r, dev(), "rm -rf /")
    assert not res.ok and r.cmds == []


# ---- windows

def decode_ps(cmd):
    assert cmd.startswith("powershell -NoProfile -NonInteractive -EncodedCommand ")
    return base64.b64decode(cmd.rsplit(" ", 1)[1]).decode("utf-16-le")


class WinRunner(FakeRunner):
    def __init__(self, verify="adapter=Ethernet WakeOnMagicPacket=Enabled"):
        super().__init__({"cmd /c ver": ok("Microsoft Windows [Version 10.0.19045]")})
        self.verify = verify

    async def run(self, device, cmd, timeout=30):
        if cmd.startswith("powershell"):
            self.cmds.append(cmd)
            return ok(self.verify if "Get-NetAdapterPowerManagement" in decode_ps(cmd) else "adapter=Ethernet")
        return await super().run(device, cmd, timeout)


async def test_windows_autodetect_and_commands():
    r = WinRunner()
    res, _ = await enable_wol(r, dev(mac="AA:BB:CC:DD:EE:01"), "auto")
    assert res.ok and [s.stage for s in res.stages] == ["detect", "apply", "verify"]
    ps = decode_ps(r.cmds[1])
    assert "Set-NetAdapterPowerManagement -Name $n -WakeOnMagicPacket Enabled" in ps
    assert "'Wake on Magic Packet'" in ps and "AA-BB-CC-DD-EE-01" in ps
    assert "Fast Startup" in res.stages[-1].detail
    assert not any("sudo" in c for c in r.cmds)


async def test_windows_verify_failure():
    r = WinRunner(verify="adapter=Ethernet WakeOnMagicPacket=Disabled")
    res, _ = await enable_wol(r, dev(mac=MAC), "windows")
    assert not res.ok and res.stages[-1].stage == "verify"


# ---- injection

async def test_nic_with_metacharacters_never_reaches_a_command():
    evil = "eth0;rm -rf /"
    link = IP_LINK.replace("eno1", evil)
    r = FakeRunner(base(**{"ip -o link": ok(link)}))
    res, _ = await enable_wol(r, dev(ssh_user="u", mac=MAC), "systemd-unit")
    assert not res.ok
    assert not any("rm -rf" in c for c in r.cmds)
    with pytest.raises(ValueError):
        build_script("systemd-unit", evil, MAC)


async def test_connection_name_is_quoted():
    evil = "x'; touch /tmp/pwn; echo '"
    r, res, _ = await run("networkmanager", base(**{"nmcli -g": ok(evil + "\n")}))
    assert res.ok
    assert shlex.quote(evil) in script_of(r)
    inner = shlex.split(script_of(r).split("nmcli connection modify ", 1)[1].split(" 802-3", 1)[0])
    assert inner == [evil]


def test_presets_whitelist_shape():
    assert PRESETS["auto"] and {"systemd-unit", "networkmanager", "systemd-networkd",
                                "ifupdown", "windows"} <= set(PRESETS)


@pytest.mark.parametrize("preset", ["systemd-unit", "networkmanager", "systemd-networkd", "ifupdown"])
def test_generated_scripts_are_valid_posix_sh(preset):
    """Regression: a stray ';;' once made the systemd-unit script a sh syntax error."""
    import subprocess
    script = build_script(preset, "nic0", "aa:bb:cc:dd:ee:ff", conn="Wired connection 1")
    assert ";;" not in script and "; ;" not in script
    r = subprocess.run(["sh", "-n", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
