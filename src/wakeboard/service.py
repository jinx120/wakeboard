"""Service facade: the one place that decides what is safe to run.

The REST API, MCP server and web UI are thin adapters over Service. Service
owns the safety rules (bulk confirmation, self-device protection, run_command
gating), audits every action and refusal, and turns SSH/connect errors into
per-device failed results instead of exceptions.
"""
import asyncio
import contextlib
import hashlib
import ipaddress
import logging
import re
import socket
import threading
import time
from dataclasses import asdict, replace
from typing import Callable, Iterable

from wakeboard.actions import ActionResult, StageResult
from wakeboard.devices import VALID_SHUTDOWN_MODES, Device
from wakeboard.actions import LOCKED
from wakeboard.ssh import ConnectFailed, HostKeyChanged, SudoRequired
from wakeboard.status import InfoCache, collect_info as _collect_info
from wakeboard.targets import NoDevices, UnknownTarget, is_bulk, resolve_targets
from wakeboard.wolcheck import adopt_mac, wake_test as _wake_test, wol_check as _wol_check

log = logging.getLogger(__name__)

MAX_OUTPUT = 64 * 1024        # per stream, characters
MAX_CMD = 4096
RUN_COMMAND_TIMEOUT = 120
SELF_CACHE_TTL = 60.0
_AUDIT_MAX = 500
_AUDIT_CMD = 120

# Failures that are part of normal operation: logged at WARNING, no traceback.
EXPECTED_ERRORS = (ConnectFailed, HostKeyChanged, SudoRequired)


class ConfirmationRequired(Exception):
    """A destructive bulk action was requested without confirm=True."""


class SelfTargetRefused(ConfirmationRequired):
    """The target is the machine Wakeboard runs on (or hosts it); needs confirm=True."""


class RunCommandDisabled(Exception):
    pass


class InvalidRequest(ValueError):
    pass


class AuditUnavailable(Exception):
    """The pre-action audit row could not be written; nothing destructive was run."""


# ---- sqlite write serialization ------------------------------------------------

class LockedRepo:
    """DeviceRepo proxy that serializes writes on the shared connection.

    The connection is shared by the event loop and the threadpool; without a lock
    one thread's rollback could discard another thread's uncommitted write.
    """

    def __init__(self, repo, lock):
        self._inner, self.lock = repo, lock

    def add(self, d):
        with self.lock:
            return self._inner.add(d)

    def update(self, d):
        with self.lock:
            return self._inner.update(d)

    def remove(self, name):
        with self.lock:
            return self._inner.remove(name)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LockedAudit:
    def __init__(self, audit, lock):
        self._inner, self.lock = audit, lock

    def record(self, caller, target, action, result):
        with self.lock:
            return self._inner.record(caller, target, action, result)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class HostKeyAckRunner:
    """Runner wrapper: the first successful run on a device whose changed host key
    was acknowledged clears its host_key_ack flag, so a later key change is
    refused again instead of being silently re-pinned."""

    def __init__(self, inner, repo):
        self._inner, self._repo = inner, repo

    async def run(self, device: Device, cmd: str, timeout: float = 30):
        r = await self._inner.run(device, cmd, timeout)
        if device.host_key_ack:
            device.host_key_ack = False
            try:
                fresh = self._repo.get(device.name)
                if fresh is not None and fresh.host_key_ack:
                    fresh.host_key_ack = False
                    self._repo.update(fresh)
            except Exception:
                log.exception("clearing host_key_ack for %s failed", device.name)
        return r

    def __getattr__(self, name):
        return getattr(self._inner, name)


# ---- self detection -------------------------------------------------------------

def _norm_ip(s: str) -> str | None:
    try:
        ip = ipaddress.ip_address(s.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def default_local_ips() -> set[str]:
    """IPs of this machine, via the socket module only (no extra dependency)."""
    ips = {"127.0.0.1", "::1"}
    name = socket.gethostname()
    try:
        for info in socket.getaddrinfo(name, None):
            ips.add(info[4][0])
    except OSError:
        pass
    # Primary outbound address for each family (connect() on UDP sends nothing).
    for fam, probe in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.connect((probe, 9))
                ips.add(s.getsockname()[0])
        except OSError:
            pass
    return ips


def default_resolve(host: str) -> set[str]:
    try:
        return {info[4][0] for info in socket.getaddrinfo(host, None)}
    except (OSError, UnicodeError):
        return set()


def detect_self(devices: Iterable[Device], local_ips: Callable[[], Iterable[str]] = default_local_ips,
                resolve: Callable[[str], Iterable[str]] = default_resolve) -> set[str]:
    """Names of devices whose host is an address of this machine. Never persisted."""
    local = {n for n in (_norm_ip(i) for i in local_ips()) if n}
    found: set[str] = set()
    for d in devices:
        lit = _norm_ip(d.host)
        addrs = {lit} if lit else {n for n in (_norm_ip(a) for a in resolve(d.host)) if n}
        for a in addrs:
            if a in local or ipaddress.ip_address(a).is_loopback:
                found.add(d.name)
                break
    return found


# ---- result helpers ----------------------------------------------------------------

def _log_failure(what: str, name: str, e: BaseException) -> None:
    if isinstance(e, EXPECTED_ERRORS):
        log.warning("%s on %s failed: %s", what, name, _err(e))
    else:
        log.error("%s on %s failed unexpectedly", what, name, exc_info=e)


_Q = r"""(?:'[^']*'|"[^"]*"|[^\s'"]+)"""          # a quoted string or a bare word
_KEYS = r"(?:password|passwd|pwd|token|secret|api[_-]?key)"
_PW_TOOLS = re.compile(r"(?<![\w-])(?:sshpass|mysql|mysqladmin|mysqldump|psql)(?![\w-])")
_CURL = re.compile(r"(?<![\w-])curl(?![\w-])")

# Always applied, in order (quoted values before bare words, inside each regex).
_REDACT = [
    (re.compile(r"(?i)(authorization:\s*)((?:bearer|basic|token)\s+)?" + _Q), r"\1\2***"),
    (re.compile(r"(?i)\b(bearer\s+)(?!\*\*\*)[^\s'\"]+"), r"\1***"),
    (re.compile(r"(?i)((?<!\S)--?" + _KEYS + r"\s+)(?!-)" + _Q), r"\1***"),
    (re.compile(r"(?i)\b(" + _KEYS + r")(\s*[=:]\s*)" + _Q), r"\1\2***"),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^\s/:@]+:)[^\s@/]+@"), r"\1***@"),
    (re.compile(r"""(?<!\S)-p(?:'[^']*'|"[^"]*")"""), "-p***"),       # -p'secret' anywhere
]
# Only when a password-taking tool is in the command: -psecret and -p secret.
_REDACT_PW_TOOL = [
    (re.compile(r"(?<!\S)-p(?=[^\s*])" + _Q), "-p***"),
    (re.compile(r"(?<!\S)(-p\s+)(?!-)" + _Q), r"\1***"),
]
# Only for curl: -u/--user user:pass keeps the user.
_REDACT_CURL = [
    (re.compile(r"""(?<!\S)(-u|--user)(\s+|=)(['"])([^:'"]*):[^'"]*\3"""), r"\1\2\3\4:***\3"),
    (re.compile(r"""(?<!\S)(-u|--user)(\s+|=)([^\s:'"]*):[^\s'"]+"""), r"\1\2\3:***"),
]


def redact_cmd(cmd: str) -> str:
    """Audit form of a command: obvious secrets masked, cut to 120 chars plus
    '…(+N chars, sha256:<8 hex>)' (hash of the redacted text, so it leaks nothing).

    Redaction is best-effort: audit text masks common secret patterns only; do not
    rely on it for commands that carry credentials."""
    out = cmd or ""
    rules = list(_REDACT)
    if _PW_TOOLS.search(out):
        rules += _REDACT_PW_TOOL
    if _CURL.search(out):
        rules += _REDACT_CURL
    for rx, sub in rules:
        out = rx.sub(sub, out)
    if len(out) > _AUDIT_CMD:
        digest = hashlib.sha256(out.encode()).hexdigest()[:8]
        out = f"{out[:_AUDIT_CMD]}…(+{len(out) - _AUDIT_CMD} chars, sha256:{digest})"
    return out


def _err(e: BaseException) -> str:
    if isinstance(e, EXPECTED_ERRORS) and str(e):
        return str(e)[:_AUDIT_MAX]
    return (f"{type(e).__name__}: {e}" if str(e) else type(e).__name__)[:_AUDIT_MAX]


def _result_dict(res: ActionResult) -> dict:
    return {"ok": res.ok, "stages": [asdict(s) for s in res.stages], "error": None}


def _fail_dict(error: str) -> dict:
    return {"ok": False, "stages": [], "error": error}


def _summary(r: dict) -> str:
    if r.get("error"):
        return f"fail: {r['error']}"
    stages = r.get("stages") or []
    if r.get("ok"):
        detail = stages[-1]["detail"] if stages else ""
        return f"ok: {detail}" if detail else "ok"
    bad = next((s for s in stages if not s["ok"]), None)
    if bad is None:
        return "fail"
    return f"fail: {bad['stage']}: {bad['detail']}" if bad["detail"] else f"fail: {bad['stage']}"


def _truncate(s: str) -> tuple[str, bool]:
    return (s[:MAX_OUTPUT], True) if len(s) > MAX_OUTPUT else (s, False)


def _self_warning(name: str) -> str:
    return (f"WARNING: '{name}' is the machine Wakeboard runs on (or hosts it). "
            f"Powering it off or rebooting it takes Wakeboard offline, and Wakeboard "
            f"cannot wake its own host. Re-send with confirm=true only if you mean it.")


# ---- the facade ------------------------------------------------------------------------

class Service:
    def __init__(self, repo, audit, actions, runner, prober, state: dict, *,
                 lock=None, info_cache: InfoCache | None = None,
                 local_ips: Callable[[], Iterable[str]] = default_local_ips,
                 resolve: Callable[[str], Iterable[str]] = default_resolve,
                 collect_info=_collect_info, clock=time.monotonic):
        self.lock = lock if lock is not None else threading.RLock()
        self.repo = repo if isinstance(repo, LockedRepo) else LockedRepo(repo, self.lock)
        self.audit = audit if isinstance(audit, LockedAudit) else LockedAudit(audit, self.lock)
        self.actions = actions   # the ONE shared Actions instance (per-device locks)
        self.runner = runner
        self.prober = prober
        self.state = state       # shared with the Poller, mutated in place
        self.info_cache = info_cache or InfoCache()
        self._local_ips, self._resolve = local_ips, resolve
        self._collect_info = collect_info
        self._wol_check = _wol_check
        self._wake_test = _wake_test
        self._clock = clock
        self._self_cache: tuple[float, frozenset, frozenset] | None = None

    # -- self detection

    def detect_self(self, devices: Iterable[Device]) -> set[str]:
        return detect_self(devices, self._local_ips, self._resolve)

    async def _self_names(self, devices: list[Device]) -> set[str]:
        """Stored is_self flags plus runtime-detected self hosts (cached briefly)."""
        key = frozenset((d.name, d.host) for d in devices)
        now = self._clock()
        c = self._self_cache
        if c is None or c[1] != key or now - c[0] >= SELF_CACHE_TTL:
            detected = await asyncio.to_thread(self.detect_self, devices)
            c = self._self_cache = (now, key, frozenset(detected))
        return {d.name for d in devices if d.is_self} | set(c[2])

    # -- helpers

    def _audit(self, caller: str, target: str, action: str, result: str) -> None:
        try:
            self.audit.record(caller, str(target)[:200], action[:300], result[:_AUDIT_MAX])
        except Exception:
            log.exception("audit write failed (%s %s %s)", caller, target, action)

    def _audit_attempt(self, caller, target, action, confirm, devices) -> None:
        # Written BEFORE the action: if it takes Wakeboard's own host down, the
        # intent is still on record even though no result row will follow.
        # Fails CLOSED: no record, no action.
        names = ",".join(d.name for d in devices)
        try:
            self.audit.record(caller, str(target)[:200], action,
                              f"attempt: confirm={confirm} targets={names}"[:_AUDIT_MAX])
        except Exception as e:
            log.error("pre-action audit write failed; refusing %s of %s: %s", action, target, _err(e))
            raise AuditUnavailable(
                f"audit log unavailable; refusing to {action} '{target}' without a record") from e

    def _resolve_target(self, target: str, caller: str, action: str) -> list[Device]:
        try:
            return resolve_targets(self.repo, target)
        except (UnknownTarget, NoDevices) as e:
            self._audit(caller, target, action, f"refused: {type(e).__name__}")
            raise

    async def _targets(self, target: str, caller: str, action: str,
                       destructive: bool, confirm: bool) -> list[Device]:
        bulk = is_bulk(target, self.repo)
        devices = self._resolve_target(target, caller, action)
        selfs = await self._self_names(self.repo.list())
        if bulk:
            excluded = sorted(d.name for d in devices if d.name in selfs)
            devices = [d for d in devices if d.name not in selfs]
            if not devices:
                self._audit(caller, target, action, "refused: no eligible devices")
                raise NoDevices(f"no eligible devices in '{target}'"
                                + (f" (excluded: {', '.join(excluded)})" if excluded else ""))
            if destructive and not confirm:
                names = ", ".join(d.name for d in devices)
                msg = (f"{action} of '{target}' affects {len(devices)} device(s): {names}. "
                       f"Re-send with confirm=true to proceed.")
                if excluded:
                    msg += (f" Excluded because they run or host Wakeboard: "
                            f"{', '.join(excluded)} (name one explicitly to target it).")
                self._audit(caller, target, action, "refused: confirmation required")
                raise ConfirmationRequired(msg)
        else:
            d = devices[0]
            # Never set d.is_self here: d may be saved later (adopt_mac), and the
            # detected flag must not be persisted.
            if d.name in selfs:
                if destructive and not confirm:
                    self._audit(caller, target, action, "refused: self target needs confirm")
                    raise SelfTargetRefused(_self_warning(d.name))
        return devices

    def _single(self, target: str, caller: str, action: str) -> Device:
        d = self.repo.get(target)
        if d is None:
            if is_bulk(target, self.repo) or target.lower() == "all":
                self._audit(caller, target, action, "refused: single device required")
                raise InvalidRequest(f"{action} takes a single device name, not '{target}'")
            self._audit(caller, target, action, "refused: UnknownTarget")
            raise UnknownTarget(target)
        return d

    async def _run_each(self, devices: list[Device], caller: str, action: str, fn) -> dict:
        async def one(d: Device) -> dict:
            try:
                out = await fn(d)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                _log_failure(action, d.name, e)
                out = _fail_dict(_err(e))
            self._audit(caller, d.name, action, _summary(out))
            return out

        results = await asyncio.gather(*(one(d) for d in devices), return_exceptions=True)
        out: dict[str, dict] = {}
        for d, r in zip(devices, results):
            if isinstance(r, asyncio.CancelledError):
                raise r
            out[d.name] = r if isinstance(r, dict) else _fail_dict(_err(r))
        return out

    # -- read-only

    def _device_dict(self, d: Device, selfs: set[str]) -> dict:
        info = self.info_cache.get(d.name)
        return {
            "name": d.name, "host": d.host, "ssh_user": d.ssh_user, "ssh_port": d.ssh_port,
            "mac": d.mac, "broadcast": d.broadcast, "type": d.type, "groups": list(d.groups),
            "allow_run_command": d.allow_run_command, "shutdown_mode": d.shutdown_mode,
            "notes": d.notes, "bios_verified": d.bios_verified,
            "is_self": d.name in selfs, "host_key_ack": d.host_key_ack,
            "wake_test_result": d.wake_test_result, "wake_test_at": d.wake_test_at,
            "up": self.state.get(d.name),
            "info": asdict(info) if info else None,
        }

    async def list_devices(self) -> list[dict]:
        devices = self.repo.list()
        selfs = await self._self_names(devices)
        return [self._device_dict(d, selfs) for d in devices]

    async def device_status(self, target: str) -> dict:
        devices = resolve_targets(self.repo, target)

        async def one(d: Device) -> dict:
            try:
                up = bool(await self.prober.is_up(d))
            except asyncio.CancelledError:
                raise
            except Exception as e:
                _log_failure("probe", d.name, e)
                return {"status": "unreachable", "up": None, "info": None, "error": _err(e)}
            self.state[d.name] = up
            if not up:
                return {"status": "down", "up": False, "info": None, "error": None}
            info = self.info_cache.get(d.name)
            if info is None:
                try:
                    info = await self._collect_info(self.runner, d)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    _log_failure("collect_info", d.name, e)
                    return {"status": "unreachable", "up": True, "info": None, "error": _err(e)}
                self.info_cache.put(d.name, info)
            return {"status": "up", "up": True, "info": asdict(info), "error": None}

        results = await asyncio.gather(*(one(d) for d in devices), return_exceptions=True)
        out = {}
        for d, r in zip(devices, results):
            if isinstance(r, asyncio.CancelledError):
                raise r
            out[d.name] = r if isinstance(r, dict) else {
                "status": "unreachable", "up": None, "info": None, "error": _err(r)}
        return out

    # -- power actions

    async def wake(self, target: str, caller: str) -> dict:
        devices = await self._targets(target, caller, "wake", destructive=False, confirm=False)

        async def fn(d: Device) -> dict:
            if not d.mac:
                return _fail_dict("no MAC configured; run wake_check to discover one")
            return _result_dict(await self.actions.wake(d))
        return await self._run_each(devices, caller, "wake", fn)

    async def shutdown(self, target: str, caller: str, mode: str | None = None,
                       confirm: bool = False) -> dict:
        confirm = confirm is True  # JSON-ish "false", "0", 1 are NOT confirmation
        if mode is not None and mode not in VALID_SHUTDOWN_MODES:
            self._audit(caller, target, "shutdown", f"refused: invalid mode {mode!r}")
            raise InvalidRequest(f"invalid shutdown mode: {mode!r}")
        devices = await self._targets(target, caller, "shutdown", destructive=True, confirm=confirm)
        label = f"shutdown {mode}" if mode else "shutdown"
        self._audit_attempt(caller, target, label, confirm, devices)

        async def fn(d: Device) -> dict:
            return _result_dict(await self.actions.shutdown(d, mode=mode))
        return await self._run_each(devices, caller, label, fn)

    async def reboot(self, target: str, caller: str, confirm: bool = False) -> dict:
        confirm = confirm is True  # JSON-ish "false", "0", 1 are NOT confirmation
        devices = await self._targets(target, caller, "reboot", destructive=True, confirm=confirm)
        self._audit_attempt(caller, target, "reboot", confirm, devices)

        async def fn(d: Device) -> dict:
            return _result_dict(await self.actions.reboot(d))
        return await self._run_each(devices, caller, "reboot", fn)

    async def wake_check(self, target: str, caller: str) -> dict:
        devices = await self._targets(target, caller, "wake_check", destructive=False, confirm=False)

        async def fn(d: Device) -> dict:
            try:
                rep = await self._wol_check(self.runner, d)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                _log_failure("wake_check", d.name, e)
                reach = isinstance(e, (ConnectFailed, HostKeyChanged, OSError, asyncio.TimeoutError))
                return {"ok": False, "status": "unreachable" if reach else "error", "report": None,
                        "ready": False, "mac_adopted": False, "stages": [], "error": _err(e)}
            with self.lock:  # re-read + set only mac, atomically w.r.t. other writers
                adopted = adopt_mac(self.repo, d, rep)
            ready = bool(rep.supported and "g" in rep.current_flags and rep.persistent)
            notes = "; ".join(rep.notes)
            detail = ("ready" if ready else "not ready") + (f" ({notes})" if notes else "")
            if adopted:
                detail += f"; adopted MAC {rep.mac}"
            return {"ok": True, "status": "checked", "report": asdict(rep), "ready": ready,
                    "mac_adopted": adopted, "stages": [asdict(StageResult("wol_check", True, detail))],
                    "error": None}
        return await self._run_each(devices, caller, "wake_check", fn)

    async def wake_test(self, target: str, caller: str) -> dict:
        """Shut down + wake one device and stamp the result (wolcheck audits outcomes)."""
        d = self._single(target, caller, "wake_test")
        selfs = await self._self_names(self.repo.list())
        dev = replace(d, is_self=d.is_self or d.name in selfs)
        try:
            res = await self._wake_test(self.actions, self.repo, self.audit, dev, caller=caller)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # wolcheck already stamped + audited "error: ..."
            return {d.name: _fail_dict(_err(e))}
        out = _result_dict(res)
        if dev.is_self:
            self._audit(caller, d.name, "wake_test", f"refused: {_summary(out)}")
        return {d.name: out}

    async def run_command(self, target: str, cmd: str, caller: str) -> dict:
        d = self._single(target, caller, "run_command")
        shown = redact_cmd(cmd)
        selfs = await self._self_names(self.repo.list())
        if d.name in selfs:
            self._audit(caller, d.name, "run_command", f"refused: self device: {shown}")
            raise RunCommandDisabled(
                f"run_command is refused on '{d.name}': it is the machine Wakeboard runs on "
                f"(or hosts it)")
        if not d.allow_run_command:
            self._audit(caller, d.name, "run_command", f"refused: run_command disabled: {shown}")
            raise RunCommandDisabled(f"run_command is disabled for '{d.name}'")
        if not cmd or not cmd.strip() or len(cmd) > MAX_CMD:
            self._audit(caller, d.name, "run_command", "refused: invalid command")
            raise InvalidRequest(f"cmd must be 1..{MAX_CMD} characters")
        # Share Actions' per-device lock so a command never races a power action.
        get_lock = getattr(self.actions, "_lock", None)
        lock = get_lock(d) if callable(get_lock) else None
        if lock is not None and lock.locked():
            out = {"ok": False, "stdout": "", "stderr": "", "exit": None, "truncated": False,
                   "error": LOCKED}
            self._audit(caller, d.name, "run_command", f"fail: {LOCKED} | {shown}")
            return out
        try:
            async with (lock if lock is not None else contextlib.nullcontext()):
                r = await self.runner.run(d, cmd, timeout=RUN_COMMAND_TIMEOUT)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            _log_failure("run_command", d.name, e)
            out = {"ok": False, "stdout": "", "stderr": "", "exit": None, "truncated": False,
                   "error": _err(e)}
            self._audit(caller, d.name, "run_command", f"fail: {out['error']} | {shown}")
            return out
        stdout, t1 = _truncate(r.stdout)
        stderr, t2 = _truncate(r.stderr)
        out = {"ok": r.exit == 0, "stdout": stdout, "stderr": stderr, "exit": r.exit,
               "truncated": t1 or t2, "error": None}
        self._audit(caller, d.name, "run_command",
                    f"{'ok' if r.exit == 0 else 'fail'}: exit {r.exit} | {shown}")
        return out

    # -- host keys

    async def acknowledge_host_key(self, name: str, caller: str = "ui") -> None:
        """Accept a changed host key: forget the pin; the next successful connect
        re-pins it and clears host_key_ack (see HostKeyAckRunner)."""
        d = self.repo.get(name)
        if d is None:
            raise UnknownTarget(name)
        self.runner.acknowledge_host_key(d)
        d.host_key_ack = True
        self.repo.update(d)
        self._audit(caller, d.name, "acknowledge_host_key", "ok")
