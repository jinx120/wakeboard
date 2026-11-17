"""Wake-on-LAN readiness check (over SSH) and an end-to-end wake test.

NIC names come from remote output, so they are validated before they reach a
command line and quoted with shlex.quote.
"""
import re
import shlex
import time
from dataclasses import dataclass, field

from wakeboard.actions import ActionResult, StageResult
from wakeboard.devices import Device
from wakeboard.ssh import RunResult
from wakeboard.wol import normalize_mac

_NIC_OK = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
_LINK_LINE = re.compile(r"^\d+:\s+([^:\s]+?)(?:@\S+)?:\s.*?link/ether\s+([0-9a-fA-F:]{17})\b")
_PERSIST_PATHS = ("/etc/systemd/network /etc/network/interfaces /etc/network/interfaces.d "
                  "/etc/udev/rules.d /etc/systemd/system /etc/NetworkManager")


@dataclass
class WolReport:
    nic: str | None
    mac: str | None
    supported: bool
    current_flags: str
    persistent: bool | None
    notes: list[str] = field(default_factory=list)


def parse_ethtool_wol(text: str) -> tuple[str, str]:
    """(supported_flags, current_flags) from ethtool output; ("", "") if absent."""
    supported = current = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Supports Wake-on:"):
            supported = line.split(":", 1)[1].strip()
        elif line.startswith("Wake-on:"):
            current = line.split(":", 1)[1].strip()
    return supported, current


def _parse_links(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        m = _LINK_LINE.match(line.replace("\\", " "))
        if m:
            out.append((m.group(1), m.group(2).lower()))
    return out


def _short(r: RunResult) -> str:
    text = (r.stderr.strip() or r.stdout.strip())[:200]
    return f"exit {r.exit}: {text}" if text else f"exit {r.exit}"


def _priv(device: Device, cmd: str) -> str:
    return cmd if device.ssh_user == "root" else f"sudo -n {cmd}"


async def wol_check(runner, device: Device) -> WolReport:
    """Inspect the device's NIC for Wake-on-LAN. Normal failures become notes;
    ConnectFailed / AuthFailed from the runner propagate."""
    rep = WolReport(nic=None, mac=device.mac, supported=False, current_flags="",
                    persistent=None, notes=[])
    link = await runner.run(device, "ip -o link")
    if link.exit != 0:
        rep.notes.append(f"could not list network interfaces ({_short(link)})")
        return rep
    links = _parse_links(link.stdout)

    nic: str | None = None
    if device.mac:
        want = device.mac.lower()
        nic = next((n for n, m in links if m == want), None)
        if nic is None:
            rep.notes.append(f"no network interface has MAC {device.mac}")
            return rep
    else:
        route = await runner.run(device, "ip -o route get 1.1.1.1")
        m = re.search(r"\bdev\s+(\S+)", route.stdout) if route.exit == 0 else None
        if not m:
            rep.notes.append("could not determine the default-route interface")
            return rep
        nic = m.group(1)
        if not _NIC_OK.match(nic):
            rep.notes.append(f"unexpected interface name {nic[:30]!r}; not using it")
            return rep
        mac = next((mc for n, mc in links if n == nic), None)
        if mac is None:
            r = await runner.run(device, f"cat /sys/class/net/{shlex.quote(nic)}/address")
            if r.exit == 0:
                try:
                    mac = normalize_mac(r.stdout.strip())
                except ValueError:
                    mac = None
        if mac is None:
            rep.notes.append(f"could not read the MAC address of {nic}")
        rep.mac = mac

    if not _NIC_OK.match(nic):
        rep.notes.append(f"unexpected interface name {nic[:30]!r}; not using it")
        return rep
    rep.nic = nic

    et = await runner.run(device, _priv(device, f"ethtool {shlex.quote(nic)}"))
    if et.exit != 0:
        rep.notes.append(f"ethtool failed or is not installed ({_short(et)})")
        return rep
    sup, cur = parse_ethtool_wol(et.stdout)
    rep.current_flags = cur
    rep.supported = "g" in sup
    if not sup:
        rep.notes.append("ethtool reported no Wake-on information for this interface")
    elif not rep.supported:
        rep.notes.append(f"{nic} does not support magic-packet wake (supports: {sup})")
    elif "g" not in cur:
        rep.notes.append(f"{nic} supports WoL but it is not enabled (current: {cur or '?'}); "
                         f"run: ethtool -s {nic} wol g")

    g = await runner.run(
        device, f"grep -rIsilE 'wol|wake-on' {_PERSIST_PATHS}")
    if g.exit == 0:
        rep.persistent = True
    elif g.exit == 1:
        rep.persistent = False
        if rep.supported:
            rep.notes.append("WoL setting does not appear to persist across reboots "
                             "(no wol config found in systemd/networkd/ifupdown)")
    else:
        rep.notes.append(f"could not check WoL persistence ({_short(g)})")
    return rep


def adopt_mac(repo, device: Device, report: WolReport) -> bool:
    """Save a discovered MAC onto the device, only if it has none. True if saved."""
    if device.mac or not report.mac:
        return False
    device.mac = normalize_mac(report.mac)
    repo.update(device)
    return True


async def wake_test(actions, repo, audit, device: Device, caller: str = "ui",
                    now=time.time) -> ActionResult:
    """Shut the device down, wake it, and stamp the outcome on the device."""
    if device.is_self:
        return ActionResult(ok=False, stages=[StageResult(
            "precheck", False, "refusing to wake-test the host Wakeboard runs on")])

    stages: list[StageResult] = []
    down = await actions.shutdown(device)
    stages.extend(down.stages)
    if not down.ok:
        result = "fail: shutdown failed"
        res = ActionResult(ok=False, stages=stages)
    else:
        up = await actions.wake(device)
        stages.extend(up.stages)
        res = ActionResult(ok=up.ok, stages=stages)
        if up.ok:
            result = "pass"
        else:
            failed = next((s for s in up.stages if not s.ok), None)
            result = f"fail: {failed.detail or failed.stage}" if failed else "fail: wake failed"

    fresh = repo.get(device.name) or device
    fresh.wake_test_result = result
    fresh.wake_test_at = now()
    repo.update(fresh)
    audit.record(caller, device.name, "wake_test", result)
    return res
