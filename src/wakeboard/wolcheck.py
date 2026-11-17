"""Wake-on-LAN readiness check (over SSH) and an end-to-end wake test.

NIC names come from remote output, so they are validated before they reach a
command line and quoted with shlex.quote.
"""
import asyncio
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

    ident = [re.escape(nic)] + ([re.escape(rep.mac)] if rep.mac else [])
    pattern = "|".join(["wol", "wake-on", "wakeonlan", *ident])
    g = await runner.run(
        device, _priv(device, f"grep -rIsiE {shlex.quote(pattern)} {_PERSIST_PATHS}"))
    if g.exit == 0:
        rep.persistent = _persists(g.stdout, ident)
        if rep.persistent:
            rep.notes.append("persistence is a config-file heuristic, not verified at boot")
    elif g.exit == 1:
        rep.persistent = False
    else:
        rep.notes.append(f"could not check WoL persistence ({_short(g)})")
    if rep.persistent is False and rep.supported:
        rep.notes.append("WoL setting does not appear to persist across reboots "
                         "(no wol config mentioning this NIC found in systemd/networkd/ifupdown)")
    return rep


def _persists(grep_out: str, ident: list[str]) -> bool:
    """True if some single file mentions both wol/wake-on and this NIC or MAC."""
    wol: set[str] = set()
    nic: set[str] = set()
    ident_re = re.compile("|".join(ident), re.I)
    for line in grep_out.splitlines():
        path, _, text = line.partition(":")
        if re.search(r"wol|wake-on|wakeonlan", text, re.I):
            wol.add(path)
        if ident_re.search(text) or ident_re.search(path):
            nic.add(path)
    return bool(wol & nic)


def adopt_mac(repo, device: Device, report: WolReport) -> bool:
    """Save a discovered MAC onto the device, only if it has none. True if saved."""
    if device.mac or not report.mac:
        return False
    device.mac = normalize_mac(report.mac)
    repo.update(device)
    return True


_NOT_RUN = ("lock", "precheck")


def _failed(res: ActionResult) -> StageResult | None:
    return next((st for st in res.stages if not st.ok), None)


async def wake_test(actions, repo, audit, device: Device, caller: str = "ui",
                    now=time.time) -> ActionResult:
    """Shut the device down, wake it, and stamp the outcome on the device.

    A shutdown rejected by lock/precheck means the test never ran: nothing is
    stamped. Exceptions stamp "error: ..." and re-raise.
    """
    if device.is_self:
        return ActionResult(ok=False, stages=[StageResult(
            "precheck", False, "refusing to wake-test the host Wakeboard runs on")])

    def stamp(result: str) -> None:
        fresh = repo.get(device.name)
        if fresh is None:
            audit.record(caller, device.name, "wake_test",
                         f"{result} (not stamped: device no longer exists)")
            return
        fresh.wake_test_result = result
        fresh.wake_test_at = now()
        repo.update(fresh)
        audit.record(caller, device.name, "wake_test", result)

    stages: list[StageResult] = []
    shut_down = False
    try:
        down = await actions.shutdown(device)
        stages.extend(down.stages)
        if not down.ok:
            bad = _failed(down)
            if bad is not None and bad.stage in _NOT_RUN:
                audit.record(caller, device.name, "wake_test",
                             f"not run: {bad.detail or bad.stage}")
                return down
            stamp(f"fail: shutdown: {(bad.detail or bad.stage) if bad else 'unknown'}")
            return ActionResult(ok=False, stages=stages)
        shut_down = True
        up = await actions.wake(device)
        stages.extend(up.stages)
        bad = _failed(up)
        if up.ok:
            stamp("pass")
        elif bad is not None and bad.stage == "lock":
            stamp(f"error: wake not run: {bad.detail or bad.stage}")
        else:
            stamp(f"fail: {(bad.detail or bad.stage) if bad else 'wake failed'}")
        return ActionResult(ok=up.ok, stages=stages)
    except asyncio.CancelledError:
        if shut_down:
            stamp("error: cancelled")
        raise
    except Exception as e:
        stamp(f"error: {e or type(e).__name__}")
        raise
