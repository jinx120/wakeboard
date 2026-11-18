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
    uptime_s: int | None
    load1: float | None
    mem_used_pct: float | None
    disk_root_pct: float | None
    cpu_temp_c: float | None
    kernel: str | None
    pve_version: str | None
    vms_running: int | None
    cts_running: int | None
    fetched_at: float
    hostname: str | None = None  # only the minimal (Windows) info sets this


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


def _safe_host(host: str) -> bool:
    return bool(host) and not host.startswith("-")


async def _ping(device: Device) -> bool:
    if not _safe_host(device.host):
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c1", "-W2", "--", device.host,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    except (FileNotFoundError, PermissionError, OSError):
        return False
    try:
        return await asyncio.wait_for(proc.wait(), 5) == 0
    except asyncio.TimeoutError:
        return False
    finally:
        if proc.returncode is None:
            proc.kill()
            await asyncio.shield(proc.wait())


class Prober:
    def __init__(self, ping=_ping, tcp=_tcp):
        self.ping, self.tcp = ping, tcp

    async def _safe(self, fn, device) -> bool:
        try:
            return bool(await fn(device))
        except Exception:
            return False

    async def is_up(self, device: Device) -> bool:
        if not _safe_host(device.host):
            return False
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
    if device.type == "windows":  # the POSIX script cannot run there: reachable + hostname only
        r = await runner.run(device, "hostname")
        name = r.stdout.strip()
        if r.exit != 0 or not name:
            raise InfoError(f"info command failed (exit {r.exit}): {r.stderr.strip()[:200]}")
        return Info(None, None, None, None, None, None, None, None, None,
                    fetched_at=time.time(), hostname=name[:253])
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
    def __init__(self, sleep=asyncio.sleep, probe_timeout: float = 10, concurrency: int = 8):
        self.sleep = sleep
        self.probe_timeout = probe_timeout
        self.concurrency = concurrency

    async def _probe(self, sem, prober, d: Device) -> bool:
        async with sem:
            try:
                return bool(await asyncio.wait_for(prober.is_up(d), self.probe_timeout))
            except asyncio.TimeoutError:
                log.warning("poller: probe of %s timed out", d.name)
            except Exception:
                log.exception("poller: probe of %s failed", d.name)
            return False

    async def run(self, repo, prober, state: dict[str, bool], interval: float) -> None:
        sem = asyncio.Semaphore(self.concurrency)
        while True:
            try:
                devices = repo.list()
            except Exception:
                log.exception("poller: listing devices failed")
                devices = None
            if devices is not None:
                results = await asyncio.gather(*(self._probe(sem, prober, d) for d in devices))
                new = {d.name: r for d, r in zip(devices, results)}
                state.clear()
                state.update(new)
            await self.sleep(interval)
