"""Power actions: wake, shutdown (plain / graceful Proxmox), reboot.

Every action is a sequence of stages. A failed stage stops the later stages and
the overall result is ok only if every stage was ok, so an action never reports
success for a host that did not actually reach the requested state.

Guest IDs used in commands only ever come from parse_qm_list / parse_pct_list,
which return ints; raw remote text never reaches a command line.
"""
import asyncio
import logging
import re
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

import asyncssh

from wakeboard.devices import VALID_SHUTDOWN_MODES, Device
from wakeboard.ssh import HostKeyChanged, RunResult, SudoRequired
from wakeboard.wol import send_magic

log = logging.getLogger(__name__)

Progress = Callable[["StageResult"], None]


@dataclass
class StageResult:
    stage: str
    ok: bool
    detail: str = ""


@dataclass
class ActionResult:
    ok: bool
    stages: list[StageResult]


LOCKED = "action in progress"

# Errors that mean "the host is not reachable (yet) / the connection went away".
_TRANSIENT = (OSError, asyncio.TimeoutError, asyncssh.Error)
# Errors that will not fix themselves by retrying.
_PERMANENT = (HostKeyChanged, SudoRequired, asyncssh.PermissionDenied)
# Errors that must never be read as a shutdown-induced connection drop: a refused
# connection means the command was never delivered (it is transient while booting).
_NOT_A_DROP = (*_PERMANENT, ConnectionRefusedError)

_VMID = re.compile(r"[1-9][0-9]{0,8}")


def _parse_running(text: str, status_col: int) -> list[int]:
    ids: list[int] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) <= status_col:
            continue
        if not _VMID.fullmatch(parts[0]):  # header line or anything unexpected
            continue
        if parts[status_col] == "running":
            ids.append(int(parts[0]))
    return ids


def parse_qm_list(text: str) -> list[int]:
    """Running VM IDs from `qm list` (columns: VMID NAME STATUS ...)."""
    return _parse_running(text, 2)


def parse_pct_list(text: str) -> list[int]:
    """Running container IDs from `pct list` (columns: VMID Status [Lock] Name)."""
    return _parse_running(text, 1)


def _short(r: RunResult) -> str:
    text = (r.stderr.strip() or r.stdout.strip())[:300]
    return f"exit {r.exit}: {text}" if text else f"exit {r.exit}"


def _err(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}" if str(e) else type(e).__name__


class _Abort(Exception):
    """Stop polling a stage now with this detail (permanent failure)."""


class Actions:
    poll_interval: float = 5.0
    down_interval: float = 2.0  # short, so a fast reboot's down window is not missed
    force_stop_timeout: float = 60.0

    def __init__(self, runner, prober, settings, sleep=asyncio.sleep, clock=time.monotonic,
                 wol=None):
        self.runner = runner
        self.prober = prober
        self.settings = settings
        self.sleep = sleep
        self.clock = clock
        self._wol = wol
        self._locks: dict[str, asyncio.Lock] = {}

    # ---- plumbing --------------------------------------------------------

    def _lock(self, device: Device) -> asyncio.Lock:
        key = device.id or device.name
        return self._locks.setdefault(key, asyncio.Lock())

    async def _locked(self, device: Device, fn) -> ActionResult:
        lock = self._lock(device)
        if lock.locked():
            return ActionResult(ok=False, stages=[StageResult("lock", False, LOCKED)])
        # An unlocked asyncio.Lock with no waiters is acquired without yielding,
        # so the check above and this acquire cannot interleave with another task.
        async with lock:
            return await fn()

    @staticmethod
    def _emit(stages: list[StageResult], progress: Progress | None, s: StageResult) -> bool:
        stages.append(s)
        if progress is not None:
            try:
                progress(s)
            except Exception:
                log.exception("progress callback failed for stage %s", s.stage)
        return s.ok

    @staticmethod
    def _priv(device: Device, cmd: str) -> str:
        return cmd if device.ssh_user == "root" else f"sudo -n {cmd}"

    async def _run_priv(self, device: Device, cmd: str, timeout: float = 30) -> RunResult:
        full = self._priv(device, cmd)
        r = await self.runner.run(device, full, timeout=timeout)
        if device.ssh_user != "root":
            out = f"{r.stdout}\n{r.stderr}".lower()
            if "a password is required" in out or (r.exit != 0 and "sudo:" in out):
                raise SudoRequired(
                    f"sudo on {device.name} needs a password for user {device.ssh_user!r} "
                    f"(running {cmd!r}); grant passwordless sudo (NOPASSWD) for it or use root")
        return r

    async def _poll(self, check: Callable[[], Awaitable[bool]], timeout: float,
                    interval: float) -> tuple[bool, str]:
        """Run check() until it returns True or `timeout` elapses. Never waits past the deadline."""
        deadline = self.clock() + timeout
        last = ""
        while True:
            try:
                if await check():
                    return True, ""
            except _Abort as e:
                return False, str(e)
            except _TRANSIENT as e:
                last = _err(e)
            if self.clock() >= deadline:
                return False, f"timed out after {timeout:g}s" + (f" ({last})" if last else "")
            await self.sleep(min(interval, max(deadline - self.clock(), 0)) or interval)

    async def _is_up(self, device: Device) -> bool:
        try:
            return bool(await self.prober.is_up(device))
        except Exception:
            log.exception("probe failed for %s", device.name)
            return False

    async def _wait_up(self, device: Device) -> tuple[bool, str]:
        return await self._poll(lambda: self._is_up(device), self.settings.wake_timeout,
                                self.poll_interval)

    async def _wait_down(self, device: Device) -> tuple[bool, str]:
        async def down() -> bool:
            return not await self._is_up(device)
        ok, detail = await self._poll(down, self.settings.wake_timeout, self.down_interval)
        return ok, "" if ok else f"host still up: {detail}"

    async def _precheck(self, device, stages, progress) -> bool:
        if not await self._is_up(device):
            self._emit(stages, progress, StageResult("precheck", False, "already down"))
            return False
        return self._emit(stages, progress, StageResult("precheck", True))

    async def _power_cmd(self, device: Device, cmd: str) -> tuple[bool, str]:
        """Issue a command that is expected to kill our own SSH connection.

        A dropped connection (transient error, or no exit status) is the expected
        outcome; a real nonzero exit or an auth / host-key / sudo problem is not.
        """
        try:
            r = await self._run_priv(device, cmd)
        except SudoRequired:
            raise
        except _NOT_A_DROP as e:
            return False, _err(e)
        except _TRANSIENT as e:
            return True, f"connection dropped ({_err(e)})"
        if r.exit == 0:
            return True, ""
        if r.exit == -1:
            return True, "connection dropped (no exit status)"
        return False, _short(r)

    # ---- wake ------------------------------------------------------------

    async def wake(self, device: Device, progress: Progress | None = None) -> ActionResult:
        return await self._locked(device, lambda: self._wake(device, progress))

    async def _wake(self, device: Device, progress) -> ActionResult:
        stages: list[StageResult] = []

        def done() -> ActionResult:
            return ActionResult(ok=all(s.ok for s in stages), stages=stages)

        if not device.mac:
            self._emit(stages, progress, StageResult("magic_packet", False, "no MAC address configured"))
            return done()
        try:
            (self._wol or send_magic)(device.mac, broadcast=device.broadcast, repeat=3)
        except (OSError, ValueError) as e:
            self._emit(stages, progress, StageResult("magic_packet", False, _err(e)))
            return done()
        if not self._emit(stages, progress, StageResult("magic_packet", True,
                                                        f"3 packets to {device.broadcast or '255.255.255.255'}")):
            return done()

        ok, detail = await self._wait_up(device)
        if not self._emit(stages, progress, StageResult("ping", ok, detail)):
            return done()

        async def ssh_ok() -> bool:
            try:
                r = await self.runner.run(device, "true")
            except _PERMANENT as e:
                raise _Abort(_err(e)) from None
            return r.exit == 0

        ok, detail = await self._poll(ssh_ok, self.settings.wake_timeout, self.poll_interval)
        if not self._emit(stages, progress, StageResult("ssh", ok, detail)):
            return done()

        if device.type == "proxmox":
            async def pvesh_ok() -> bool:
                try:
                    r = await self._run_priv(device, "pvesh get /version")
                except _PERMANENT as e:
                    raise _Abort(_err(e)) from None
                return r.exit == 0

            ok, detail = await self._poll(pvesh_ok, self.settings.wake_timeout, self.poll_interval)
            self._emit(stages, progress, StageResult("pvesh", ok, detail))
        return done()

    # ---- shutdown --------------------------------------------------------

    async def shutdown(self, device: Device, mode: str | None = None,
                       progress: Progress | None = None) -> ActionResult:
        mode = mode or device.shutdown_mode
        if mode not in VALID_SHUTDOWN_MODES:
            raise ValueError(f"invalid shutdown mode: {mode!r}")
        return await self._locked(device, lambda: self._shutdown(device, mode, progress))

    async def _shutdown(self, device: Device, mode: str, progress) -> ActionResult:
        stages: list[StageResult] = []

        def done() -> ActionResult:
            return ActionResult(ok=all(s.ok for s in stages), stages=stages)

        if not await self._precheck(device, stages, progress):
            return done()
        if mode == "graceful-proxmox" and not await self._stop_guests(device, stages, progress):
            return done()

        ok, detail = await self._power_cmd(device, "shutdown -h now")
        if not self._emit(stages, progress, StageResult("shutdown", ok, detail)):
            return done()
        ok, detail = await self._wait_down(device)
        self._emit(stages, progress, StageResult("down", ok, detail))
        return done()

    async def _list_guests(self, device: Device) -> tuple[list[int], list[int]]:
        """(running VM ids, running CT ids). Raises RuntimeError if either listing fails."""
        qm = await self._run_priv(device, "qm list")
        if qm.exit != 0:
            raise RuntimeError(f"qm list failed: {_short(qm)}")
        pct = await self._run_priv(device, "pct list")
        if pct.exit != 0:
            raise RuntimeError(f"pct list failed: {_short(pct)}")
        return parse_qm_list(qm.stdout), parse_pct_list(pct.stdout)

    async def _stop_guests(self, device: Device, stages, progress) -> bool:
        try:
            vms, cts = await self._list_guests(device)
        except SudoRequired:
            raise
        except (RuntimeError, *_TRANSIENT, *_PERMANENT) as e:
            return self._emit(stages, progress, StageResult("guests", False, str(e) or _err(e)))
        targets = [("qm", i) for i in vms] + [("pct", i) for i in cts]
        if not targets:
            return self._emit(stages, progress, StageResult("guests", True, "no running guests"))
        self._emit(stages, progress, StageResult(
            "guests", True, f"running: qm {vms or '-'}, pct {cts or '-'}"))

        timeout = self.settings.guest_timeout
        deadline = self.clock() + timeout
        sem = asyncio.Semaphore(4)  # stay well under sshd MaxStartups

        async def ask(tool: str, gid: int) -> str | None:
            async with sem:
                try:
                    # `qm/pct shutdown` blocks until the guest is off; a timeout
                    # here only means it is still stopping (handled below).
                    r = await self._run_priv(device, f"{tool} shutdown {int(gid)}",
                                             timeout=max(deadline - self.clock(), 1.0))
                except SudoRequired:
                    raise
                except (*_TRANSIENT, *_PERMANENT) as e:
                    return f"{tool} {gid}: {_err(e)}"
                return None if r.exit == 0 else f"{tool} {gid}: {_short(r)}"

        notes = [n for n in await asyncio.gather(*(ask(t, g) for t, g in targets)) if n]
        self._emit(stages, progress, StageResult(
            "guest_shutdown", True, f"requested {len(targets)}" + (f"; {'; '.join(notes)}" if notes else "")))

        remaining = list(targets)
        while True:
            try:
                vms_now, cts_now = await self._list_guests(device)
            except SudoRequired:
                raise
            except (RuntimeError, *_TRANSIENT, *_PERMANENT):
                pass  # unknown this round; keep the last known set
            else:
                running = {("qm", i) for i in vms_now} | {("pct", i) for i in cts_now}
                remaining = [t for t in targets if t in running]
            if not remaining or self.clock() >= deadline:
                break
            await self.sleep(min(self.poll_interval, max(deadline - self.clock(), 0)) or self.poll_interval)

        if not remaining:
            self._emit(stages, progress, StageResult("guest_wait", True, "all guests stopped"))
            return True
        names = ", ".join(f"{t} {g}" for t, g in remaining)
        self._emit(stages, progress, StageResult(
            "guest_wait", True, f"{len(remaining)} still running after {timeout:g}s: {names}"))

        failures = []
        for tool, gid in remaining:
            try:
                r = await self._run_priv(device, f"{tool} stop {int(gid)}",
                                         timeout=self.force_stop_timeout)
            except SudoRequired:
                raise
            except (*_TRANSIENT, *_PERMANENT) as e:
                failures.append(f"{tool} {gid}: {_err(e)}")
                continue
            if r.exit != 0:
                failures.append(f"{tool} {gid}: {_short(r)}")
        if failures:
            return self._emit(stages, progress, StageResult(
                "force_stop", False, "not shutting down host; " + "; ".join(failures)))
        return self._emit(stages, progress, StageResult("force_stop", True, f"force-stopped {names}"))

    # ---- reboot ----------------------------------------------------------

    async def reboot(self, device: Device, progress: Progress | None = None) -> ActionResult:
        return await self._locked(device, lambda: self._reboot(device, progress))

    async def _reboot(self, device: Device, progress) -> ActionResult:
        stages: list[StageResult] = []

        def done() -> ActionResult:
            return ActionResult(ok=all(s.ok for s in stages), stages=stages)

        if not await self._precheck(device, stages, progress):
            return done()
        ok, detail = await self._power_cmd(device, "reboot")
        if not self._emit(stages, progress, StageResult("reboot", ok, detail)):
            return done()
        ok, detail = await self._wait_down(device)
        if not self._emit(stages, progress, StageResult("down", ok, detail)):
            return done()
        ok, detail = await self._wait_up(device)
        self._emit(stages, progress, StageResult("up", ok, detail))
        return done()
