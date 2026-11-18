"""Persistently enable Wake-on-LAN on a managed device over SSH.

Remote-derived strings (NIC names, connection names) are validated (_NIC_OK) or
shlex-quoted before they reach a command line, and file contents are written
with printf from quoted literals - never interpolated raw.
"""
import base64
import re
import shlex

from wakeboard.actions import ActionResult, StageResult
from wakeboard.devices import Device
from wakeboard.ssh import RunResult
from wakeboard.wol import normalize_mac
from wakeboard.wolcheck import _NIC_OK, _priv, _short, parse_ethtool_wol, wol_check

PRESETS: dict[str, str] = {
    "auto": "Autodetect",
    "systemd-unit": "systemd unit (any systemd Linux)",
    "networkmanager": "NetworkManager (nmcli)",
    "systemd-networkd": "systemd-networkd (.link file)",
    "ifupdown": "ifupdown (Debian / Proxmox)",
    "windows": "Windows (PowerShell over OpenSSH)",
}

SUDO_MSG = "sudo -n required: passwordless sudo (or an SSH login as root) is needed on the device"
FAST_STARTUP = ("Windows Fast Startup can defeat WoL after a normal shutdown: disable it "
                "(powercfg /h off, or Control Panel > Power Options) and enable WoL in BIOS/UEFI")

_ETH_FIND = ("ETH=$(command -v ethtool 2>/dev/null || ls /usr/sbin/ethtool /sbin/ethtool 2>/dev/null | head -n1); "
             "[ -n \"$ETH\" ] || { echo 'ethtool is not installed' >&2; exit 3; }; ")
_UNIT = ("[Unit]\nDescription=Wakeboard: enable Wake-on-LAN on %i\nAfter=network-pre.target\n"
         "Wants=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n"
         "ExecStart=@ETHTOOL@ -s %i wol g\n\n[Install]\nWantedBy=multi-user.target\n")


def _write(content: str, path: str, subst_eth: bool = False) -> str:
    sed = ' | sed "s#@ETHTOOL@#$ETH#g"' if subst_eth else ""
    return f"printf %s {shlex.quote(content)}{sed} | tee {shlex.quote(path)} >/dev/null"


def _live(nic: str) -> str:
    return f"\"$ETH\" -s {shlex.quote(nic)} wol g"


def build_script(preset: str, nic: str, mac: str | None, conn: str | None = None) -> str:
    """The shell script (run as root via sh -c) that applies one Linux preset."""
    if not _NIC_OK.match(nic):
        raise ValueError("unsafe interface name")
    parts = [_ETH_FIND]
    if preset == "systemd-unit":
        parts += [_write(_UNIT, "/etc/systemd/system/wakeboard-wol@.service", True),
                  "systemctl daemon-reload",
                  f"systemctl enable --now {shlex.quote(f'wakeboard-wol@{nic}.service')}",
                  _live(nic)]
    elif preset == "networkmanager":
        if not conn:
            raise ValueError("no connection")
        parts += [f"nmcli connection modify {shlex.quote(conn)} 802-3-ethernet.wake-on-lan magic",
                  _live(nic)]
    elif preset == "systemd-networkd":
        if not mac:
            raise ValueError("MAC required")
        content = f"[Match]\nMACAddress={normalize_mac(mac)}\n\n[Link]\nWakeOnLan=magic\n"
        parts += [_write(content, f"/etc/systemd/network/50-wakeboard-wol-{nic}.link"), _live(nic)]
    elif preset == "ifupdown":
        content = f"# managed by Wakeboard\nallow-hotplug {nic}\npost-up @ETHTOOL@ -s {nic} wol g\n"
        parts += [_write(content, f"/etc/network/interfaces.d/wakeboard-wol-{nic}", True),
                  "grep -qsE '^[[:space:]]*source(-directory)?[[:space:]].*interfaces.d' "
                  "/etc/network/interfaces || echo 'NOTE: /etc/network/interfaces does not source "
                  "interfaces.d; add: source /etc/network/interfaces.d/*'",
                  _live(nic)]
    else:
        raise ValueError(f"not a Linux preset: {preset}")
    return "; ".join(p.strip().rstrip(";").strip() for p in parts)


def _ps(script: str) -> str:
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    return f"powershell -NoProfile -NonInteractive -EncodedCommand {enc}"


def _win_script(mac: str | None, verify: bool = False) -> str:
    if mac:
        sel = f"$m='{normalize_mac(mac).upper().replace(':', '-')}'; " \
              "$a=Get-NetAdapter -Physical | Where-Object { $_.MacAddress -eq $m } | Select-Object -First 1; "
    else:
        sel = "$a=Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1; "
    sel += "if(-not $a){ Write-Error 'no matching network adapter'; exit 2 }; $n=$a.Name; "
    if verify:
        return sel + "$v=(Get-NetAdapterPowerManagement -Name $n).WakeOnMagicPacket; Write-Output \"adapter=$n WakeOnMagicPacket=$v\""
    return (sel + "$ErrorActionPreference='Stop'; "
            "Set-NetAdapterPowerManagement -Name $n -WakeOnMagicPacket Enabled; "
            "if(Get-NetAdapterAdvancedProperty -Name $n -DisplayName 'Wake on Magic Packet' -ErrorAction SilentlyContinue)"
            "{ Set-NetAdapterAdvancedProperty -Name $n -DisplayName 'Wake on Magic Packet' -DisplayValue 'Enabled' }; "
            "Write-Output \"adapter=$n\"")


def _fail(stages: list[StageResult], stage: str, detail: str):
    stages.append(StageResult(stage, False, detail))
    return ActionResult(ok=False, stages=stages)


async def _is_windows(runner, device: Device) -> bool:
    r = await runner.run(device, "cmd /c ver")
    return r.exit == 0 and "windows" in r.stdout.lower()


async def _nm_conn(runner, device: Device, nic: str) -> str | None:
    r = await runner.run(device, f"nmcli -g GENERAL.CONNECTION device show {shlex.quote(nic)}")
    if r.exit != 0:
        return None
    conn = r.stdout.strip()
    if not conn or conn == "--" or "\n" in conn or "\x00" in conn:
        return None
    return conn


async def _enable_windows(runner, device: Device, stages: list[StageResult]):
    mac = device.mac
    r = await runner.run(device, _ps(_win_script(mac)), timeout=60)
    if r.exit != 0:
        return _fail(stages, "apply", f"PowerShell failed ({_short(r)})"), mac
    stages.append(StageResult("apply", True, r.stdout.strip()[:120] or "applied"))
    v = await runner.run(device, _ps(_win_script(mac, verify=True)), timeout=60)
    if v.exit == 0 and "enabled" in v.stdout.lower():
        stages.append(StageResult("verify", True, f"{v.stdout.strip()[:120]}. {FAST_STARTUP}"))
        return ActionResult(ok=True, stages=stages), mac
    return _fail(stages, "verify", f"Wake on magic packet not enabled ({_short(v)})"), mac


async def enable_wol(runner, device: Device, preset: str = "auto") -> tuple[ActionResult, str | None]:
    """Enable WoL persistently. Returns (result, discovered MAC or None).
    ConnectFailed / AuthFailed from the runner propagate."""
    stages: list[StageResult] = []
    if preset not in PRESETS:
        return _fail(stages, "detect", f"unknown preset {preset[:30]!r}"), None

    if preset in ("auto", "windows"):
        win = preset == "windows" or await _is_windows(runner, device)
        if win:
            stages.append(StageResult("detect", True, f"preset windows"
                                      + (" (autodetected)" if preset == "auto" else "")))
            return await _enable_windows(runner, device, stages)

    if device.ssh_user != "root":
        s = await runner.run(device, "sudo -n true")
        if s.exit != 0:
            return _fail(stages, "detect", SUDO_MSG), None

    rep = await wol_check(runner, device)
    mac = rep.mac
    if rep.nic is None:
        return _fail(stages, "detect", "; ".join(rep.notes) or "no network interface found"), mac
    nic = rep.nic
    if not rep.supported:
        return _fail(stages, "detect", "; ".join(rep.notes) or f"{nic} does not support magic-packet wake"), mac

    chosen, conn = preset, None
    if preset in ("auto", "networkmanager"):
        if preset == "networkmanager" or (await runner.run(
                device, "systemctl is-active NetworkManager")).stdout.strip() == "active":
            conn = await _nm_conn(runner, device, nic)
        if conn:
            chosen = "networkmanager"
        elif preset == "networkmanager":
            return _fail(stages, "detect", f"NetworkManager has no active connection for {nic}"), mac
    if preset == "auto" and chosen == "auto":
        if (await runner.run(device, "command -v systemctl")).exit == 0:
            chosen = "systemd-unit"
        elif (await runner.run(device, "test -e /etc/network/interfaces")).exit == 0:
            chosen = "ifupdown"
        else:
            return _fail(stages, "detect", "could not pick a method: no systemd and no "
                         "/etc/network/interfaces; choose a preset manually"), mac
    stages.append(StageResult("detect", True, f"preset {chosen} on {nic}"
                              + (" (autodetected)" if preset == "auto" else "")))

    try:
        script = build_script(chosen, nic, mac, conn)
    except ValueError as e:
        return _fail(stages, "apply", str(e)), mac
    r = await runner.run(device, _priv(device, f"sh -c {shlex.quote(script)}"), timeout=60)
    if r.exit != 0:
        return _fail(stages, "apply", _short(r)), mac
    note = r.stdout.strip().splitlines()[-1][:200] if r.stdout.strip() else ""
    stages.append(StageResult("apply", True, note or "applied"))

    et = await runner.run(device, _priv(device, f"ethtool {shlex.quote(nic)}"))
    _, cur = parse_ethtool_wol(et.stdout) if et.exit == 0 else ("", "")
    if "g" in cur:
        stages.append(StageResult("verify", True, f"{nic} Wake-on: {cur}"))
        return ActionResult(ok=True, stages=stages), mac
    return _fail(stages, "verify", f"{nic} Wake-on is still {cur or '?'} after applying"), mac
