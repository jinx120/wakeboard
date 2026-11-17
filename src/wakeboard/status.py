"""Up/down probing, rich host info over SSH, and the background poller."""
import asyncio
import logging
import time
from dataclasses import dataclass

from wakeboard.devices import Device

log = logging.getLogger(__name__)


class InfoError(Exception):
    pass


@dataclass
class Info:
    uptime_s: int
    load1: float
    mem_used_pct: float
    disk_root_pct: float
    cpu_temp_c: float | None
    kernel: str
    pve_version: str | None
    vms_running: int | None
    cts_running: int | None
    fetched_at: float


# ---- probing ---------------------------------------------------------------

async def _tcp(device: Device) -> bool:
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(device.host, device.ssh_port), 2)
    except (OSError, asyncio.TimeoutError):
        return False
    w.close()
    try:
        await w.wait_closed()
    except OSError:
        pass
    return True


async def _ping(device: Device) -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c1", "-W2", device.host,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    except (FileNotFoundError, PermissionError, OSError):
        return False
    try:
        return await asyncio.wait_for(proc.wait(), 5) == 0
    except asyncio.TimeoutError:
        proc.kill()
        return False


class Prober:
    def __init__(self, ping=_ping, tcp=_tcp):
        self.ping, self.tcp = ping, tcp

    async def _safe(self, fn, device) -> bool:
        try:
            return bool(await fn(device))
        except Exception:
            return False

    async def is_up(self, device: Device) -> bool:
        if await self._safe(self.tcp, device):
            return True
        return await self._safe(self.ping, device)


# ---- rich info ---------------------------------------------------------------

_BASE_CMD = (
    'echo "uptime=$(cut -d" " -f1 /proc/uptime)"; '
    'echo "load1=$(cut -d" " -f1 /proc/loadavg)"; '
    "free | awk '/^Mem:/{printf \"mem=%.1f\\n\", $3*100/$2}'; "
    "df -P / | awk 'NR==2{gsub(\"%\",\"\",$5); print \"disk=\"$5}'; "
    'echo "temp=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null)"; '
)
_PVE_CMD = (
    'echo "pve=$(pveversion 2>/dev/null | sed -n \'s#^pve-manager/\\([^/]*\\)/.*#\\1#p\')"; '
    'echo "vms=$(qm list 2>/dev/null | awk \'NR>1 && $3==\\"running\\"\' | wc -l)"; '
    'echo "cts=$(pct list 2>/dev/null | awk \'NR>1 && $2==\\"running\\"\' | wc -l)"; '
)
_TAIL_CMD = 'echo "kernel=$(uname -r)"'


def info_command(is_proxmox: bool) -> str:
    return _BASE_CMD + (_PVE_CMD if is_proxmox else "") + _TAIL_CMD


def parse_info(text: str, is_proxmox: bool) -> Info:
    kv = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            kv[k.strip()] = v.strip()
    try:
        temp = kv.get("temp", "")
        info = Info(
            uptime_s=int(float(kv["uptime"])),
            load1=float(kv["load1"]),
            mem_used_pct=float(kv["mem"]),
            disk_root_pct=float(kv["disk"]),
            cpu_temp_c=float(temp) / 1000 if temp else None,
            kernel=kv["kernel"],
            pve_version=None, vms_running=None, cts_running=None,
            fetched_at=time.time(),
        )
        if not info.kernel:
            raise ValueError("empty kernel")
        if is_proxmox:
            info.pve_version = kv["pve"] or None
            info.vms_running = int(kv["vms"])
            info.cts_running = int(kv["cts"])
    except (KeyError, ValueError) as e:
        raise InfoError(f"unparseable info output: {e!r}") from None
    return info


async def collect_info(runner, device: Device) -> Info:
    is_pve = device.type == "proxmox"
    r = await runner.run(device, info_command(is_pve))
    if r.exit != 0:
        raise InfoError(f"info command failed (exit {r.exit}): {r.stderr.strip()[:200]}")
    return parse_info(r.stdout, is_pve)


class InfoCache:
    def __init__(self, ttl: float = 60, clock=time.monotonic):
        self.ttl, self.clock = ttl, clock
        self._d: dict[str, tuple[float, Info]] = {}

    def get(self, name: str) -> Info | None:
        e = self._d.get(name)
        if e is None:
            return None
        if self.clock() - e[0] >= self.ttl:
            del self._d[name]
            return None
        return e[1]

    def put(self, name: str, info: Info) -> None:
        self._d[name] = (self.clock(), info)


# ---- poller --------------------------------------------------------------------

class Poller:
    def __init__(self, sleep=asyncio.sleep):
        self.sleep = sleep

    async def run(self, repo, prober, state: dict[str, bool], interval: float) -> None:
        while True:
            try:
                devices = repo.list()
            except Exception:
                log.exception("poller: listing devices failed")
                devices = None
            if devices is not None:
                for d in devices:
                    try:
                        state[d.name] = bool(await prober.is_up(d))
                    except Exception:
                        log.exception("poller: probe of %s failed", d.name)
                        state[d.name] = False
                names = {d.name for d in devices}
                for k in [k for k in state if k not in names]:
                    del state[k]
            await self.sleep(interval)
