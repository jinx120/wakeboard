"""Web UI: cookie-session pages over Service.

Safety rules live in Service; this module only adds the browser concerns:
session cookies, CSRF on every POST (checked once, in the router dependency),
security headers, and turning every Service error into a readable page.
"""
import hmac
import ipaddress
import logging
import re
import secrets
from pathlib import Path
from urllib.parse import quote

import asyncssh
from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader

from wakeboard.api import client_ip
from wakeboard.auth import MIN_PASSWORD, SESSION_MAX_AGE, LockedOut
from wakeboard.devices import (NAME_RE, RESERVED_NAMES, VALID_SHUTDOWN_MODES, VALID_TYPES, Device,
                               DuplicateDevice, UnknownDevice, valid_name)
from wakeboard.service import (AuditUnavailable, ConfirmationRequired, InvalidRequest,
                               RunCommandDisabled, SelfTargetRefused)
from wakeboard.ssh import ConnectFailed, EnrollmentFailed, HostKeyChanged
from wakeboard.targets import NoDevices, UnknownTarget, is_bulk, resolve_targets
from wakeboard.wol import normalize_mac
from wakeboard.wolenable import PRESETS

log = logging.getLogger(__name__)

CALLER = "ui"
SESSION_COOKIE = "wakeboard_session"
ANON_COOKIE = "wakeboard_csrf"          # pre-login CSRF nonce (login / setup forms)
PUBLIC_PATHS = {"/login", "/setup"}
AUDIT_LIMIT = 200
HISTORY_LIMIT = 50

CSP = ("default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
       "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'")
SECURITY_HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
]

_HERE = Path(__file__).parent
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")
DEVICE_ACTIONS = {"wake", "shutdown", "reboot", "wol-check", "wake-test", "enable-wol", "enroll",
                  "ack-host-key", "delete", "edit"}
BULK_ACTIONS = {"wake", "shutdown", "reboot"}
# actions that must be confirmed: bulk ones via the confirm page, device ones via hx-confirm
# (HTMX) or, without JavaScript, the confirm page (a plain POST without confirm=1 is sent there)
BULK_CONFIRM_ACTIONS = {"shutdown", "reboot"}
DEVICE_CONFIRM_ACTIONS = {"shutdown", "reboot", "wake-test", "enable-wol", "delete", "ack-host-key"}
CONFIRM_VERBS = {"shutdown": "Shut down", "reboot": "Reboot", "wake-test": "Run the wake test on", "enable-wol": "Enable Wake-on-LAN on",
                 "delete": "Remove", "ack-host-key": "Accept the new host key of"}


# ---- plumbing --------------------------------------------------------------------

class SecurityHeaders:
    """Pure ASGI middleware: adds the security headers to every HTTP response
    (pure ASGI so streaming responses such as MCP are untouched)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def _send(msg):
            if msg["type"] == "http.response.start":
                names = {k.lower() for k, _ in msg.get("headers", [])}
                msg["headers"] = list(msg.get("headers", [])) + [
                    (k, v) for k, v in SECURITY_HEADERS if k not in names]
            await send(msg)
        await self.app(scope, receive, _send)


class WebError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class LoginRequired(Exception):
    pass


def _is_https(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return request.url.scheme == "https" or proto == "https"


def _is_hx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"


def _cookie(response: Response, request: Request, name: str, value: str, max_age: int | None) -> None:
    response.set_cookie(name, value, max_age=max_age, path="/", httponly=True,
                        samesite="strict", secure=_is_https(request))


def _fmt_uptime(s) -> str:
    if s is None:
        return "-"
    s = int(s)
    d, h, m = s // 86400, s % 86400 // 3600, s % 3600 // 60
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def _q(v) -> str:
    return quote(str(v), safe="")


def _env() -> Environment:
    env = Environment(loader=FileSystemLoader(str(_HERE / "templates")), autoescape=True)
    env.filters["uptime"] = _fmt_uptime
    env.filters["q"] = _q
    return env


class FormError(ValueError):
    pass


def _parse_device(form, existing: Device | None) -> Device:
    """Form -> Device. Blank optional fields become None. Raises FormError."""
    def f(k, default=""):
        return str(form.get(k, default) or "").strip()

    name = f("name")
    if not valid_name(name):
        raise FormError("Invalid name: use 1-64 letters, digits, '.', '_' or '-' "
                        "(not 'all' or 'new').")
    host = f("host")
    if not host or len(host) > 253 or any(c.isspace() for c in host) or host.startswith("-"):
        raise FormError("Invalid host: give an IP address or hostname.")
    user = f("ssh_user") or "root"
    if not _USER_RE.fullmatch(user):
        raise FormError("Invalid SSH user name.")
    try:
        port = int(f("ssh_port") or "22")
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        raise FormError("Invalid SSH port: must be 1-65535.")
    broadcast = f("broadcast") or None
    if broadcast is not None:
        try:
            ipaddress.IPv4Address(broadcast)
        except ValueError:
            raise FormError("Invalid broadcast address: must be an IPv4 address.") from None
    dtype = f("type") or "linux"
    if dtype not in VALID_TYPES:
        raise FormError(f"Invalid type: choose one of {', '.join(sorted(VALID_TYPES))}.")
    mode = f("shutdown_mode") or None
    if mode is not None and mode not in VALID_SHUTDOWN_MODES:
        raise FormError("Invalid shutdown mode.")
    groups = [g.strip() for g in f("groups").split(",") if g.strip()]
    for g in groups:
        if not NAME_RE.fullmatch(g) or g.lower() in RESERVED_NAMES:
            raise FormError(f"Invalid group name {g!r}: use letters, digits, '.', '_' or '-'.")
    notes = str(form.get("notes", "") or "")
    if len(notes) > 2000:
        raise FormError("Notes are too long (max 2000 characters).")
    mac = f("mac") or None
    if mac is not None:
        try:
            mac = normalize_mac(mac)
        except ValueError:
            raise FormError("Invalid MAC address: use the form aa:bb:cc:dd:ee:ff.") from None
    keep = {}
    if existing is not None:
        keep = {"id": existing.id, "key_id": existing.key_id, "host_key_ack": existing.host_key_ack,
                "wake_test_result": existing.wake_test_result, "wake_test_at": existing.wake_test_at}
    try:
        return Device(name=name, host=host, ssh_user=user, ssh_port=port, mac=mac, broadcast=broadcast,
                      type=dtype, groups=groups, shutdown_mode=mode, notes=notes,
                      allow_run_command=form.get("allow_run_command") == "1",
                      bios_verified=form.get("bios_verified") == "1",
                      is_self=form.get("is_self") == "1", **keep)
    except ValueError as e:
        raise FormError(f"Invalid device: {str(e)[:200]}") from None


def _enroll_reason(e: BaseException) -> str:
    """Generic failure reason: never the exception text, which could echo input."""
    if isinstance(e, EnrollmentFailed):
        return ("password authentication failed" if "password authentication" in str(e)
                else "installing the key failed")
    if isinstance(e, HostKeyChanged):
        return "the host key changed; acknowledge it first"
    if isinstance(e, TimeoutError):
        return "timed out"
    if isinstance(e, (ConnectFailed, OSError, asyncssh.Error)):
        return "could not connect"
    return "enrollment failed"


# ---- the router --------------------------------------------------------------------

def build_web_router(service, auth, *, keystore, runner, settings) -> APIRouter:
    env = _env()
    repo = service.repo

    def session_of(request: Request) -> str | None:
        c = request.cookies.get(SESSION_COOKIE)
        return c if c and auth.valid_session(c) else None

    def expected_csrf(request: Request, public: bool) -> str | None:
        if public:
            base = request.cookies.get(ANON_COOKIE)
            return auth.csrf_token("a:" + base) if base else None
        s = session_of(request)
        return auth.csrf_token("s:" + s) if s else None

    async def guard(request: Request) -> None:
        """The one place that enforces login and CSRF for every web route."""
        public = request.url.path in PUBLIC_PATHS
        if not public and session_of(request) is None:
            raise LoginRequired()
        if request.method in ("GET", "HEAD"):
            return
        if request.url.path == "/setup" and auth.password_set():
            raise WebError(404, "Not found.")     # setup is gone once a password exists
        expected = expected_csrf(request, public)
        sent = request.headers.get("x-csrf-token")
        if not sent:
            try:
                sent = (await request.form()).get("csrf")
            except Exception:
                sent = None
        # compare as bytes: compare_digest raises TypeError on non-ASCII str (would be a 500)
        if (not expected or not isinstance(sent, str)
                or not hmac.compare_digest(sent.encode("utf-8", "replace"), expected.encode())):
            raise WebError(403, "Your form expired or the request was forged (bad CSRF token). "
                                "Reload the page and try again.")

    r = APIRouter(dependencies=[Depends(guard)])

    def render(request: Request, template: str, status: int = 200, *, anon: str | None = None,
               headers: dict | None = None, **ctx) -> HTMLResponse:
        if anon is not None:
            csrf = auth.csrf_token("a:" + anon)
            authed = False
        else:
            s = session_of(request)
            csrf = auth.csrf_token("s:" + s) if s else ""
            authed = s is not None
        html = env.get_template(template).render(csrf=csrf, authed=authed, **ctx)
        resp = HTMLResponse(html, status_code=status, headers=headers)
        resp.headers["cache-control"] = "no-store"
        if anon is not None:
            _cookie(resp, request, ANON_COOKIE, anon, None)
        return resp

    def anon_nonce(request: Request) -> str:
        return request.cookies.get(ANON_COOKIE) or secrets.token_urlsafe(24)

    def login_response(request: Request, location: str = "/") -> Response:
        resp = RedirectResponse(location, status_code=303)
        _cookie(resp, request, SESSION_COOKIE, auth.new_session(), SESSION_MAX_AGE)
        resp.delete_cookie(ANON_COOKIE, path="/")
        return resp

    def get_device(name: str) -> Device:
        d = repo.get(name)
        if d is None:
            raise WebError(404, "No such device.")
        return d

    def result(request: Request, title: str, *, results=None, message=None, ok=True,
               confirm_url=None, status=200) -> HTMLResponse:
        tpl = "_result.html" if _is_hx(request) else "result.html"
        return render(request, tpl, status, title=title, results=results, message=message, ok=ok,
                      confirm_url=confirm_url)

    async def run_action(request: Request, title: str, coro, *, confirm_url=None) -> HTMLResponse:
        """Await a Service call; every error becomes a readable message, never a 500 page."""
        try:
            res = await coro
        except SelfTargetRefused as e:
            return result(request, title, message=str(e), ok=False, confirm_url=confirm_url, status=409)
        except ConfirmationRequired as e:
            return result(request, title, message=str(e), ok=False, confirm_url=confirm_url, status=409)
        except UnknownTarget:
            return result(request, title, message="No such device or group.", ok=False, status=404)
        except NoDevices as e:
            return result(request, title, message=f"Nothing to do: {e}", ok=False, status=404)
        except (RunCommandDisabled, InvalidRequest) as e:
            return result(request, title, message=str(e), ok=False, status=400)
        except AuditUnavailable as e:
            return result(request, title, message=str(e), ok=False, status=503)
        except Exception as e:
            log.error("%s failed unexpectedly: %s", title, type(e).__name__)
            return result(request, title, message="Internal error; nothing more is known. See server logs.",
                          ok=False, status=500)
        return result(request, title, results=res)

    def confirm_url(action: str, target: str) -> str:
        return f"/confirm/{action}?target={_q(target)}"

    # -- login / setup / logout

    @r.get("/login")
    async def login_page(request: Request):
        if not auth.password_set():
            return RedirectResponse("/setup", status_code=303)
        if session_of(request):
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html", anon=anon_nonce(request))

    @r.post("/login")
    async def login_post(request: Request):
        form = await request.form()
        pw = str(form.get("password", "") or "")
        anon = request.cookies[ANON_COOKIE]    # guard checked it exists
        try:
            ok = await auth.check_password_async(pw, client_ip(request))
        except LockedOut as e:
            return render(request, "login.html", 429, anon=anon, headers={"Retry-After": str(e.retry_after)},
                          error=f"Too many failed attempts. Try again in {e.retry_after} seconds.")
        if not ok:
            return render(request, "login.html", 401, anon=anon, error="Incorrect password.")
        return login_response(request)

    @r.get("/setup")
    async def setup_page(request: Request):
        if auth.password_set():
            return RedirectResponse("/login", status_code=303)
        return render(request, "setup.html", anon=anon_nonce(request))

    @r.post("/setup")
    async def setup_post(request: Request):
        if auth.password_set():
            raise WebError(404, "Not found.")
        form = await request.form()
        pw, pw2 = str(form.get("password", "") or ""), str(form.get("confirm", "") or "")
        anon = request.cookies[ANON_COOKIE]
        if len(pw) < MIN_PASSWORD:
            return render(request, "setup.html", 400, anon=anon,
                          error=f"Password must be at least {MIN_PASSWORD} characters.")
        if pw != pw2:
            return render(request, "setup.html", 400, anon=anon, error="Passwords do not match.")
        if not auth.set_initial_password(pw):
            raise WebError(404, "Not found.")
        return login_response(request)

    @r.post("/logout")
    async def logout(request: Request):
        auth.revoke_session(request.cookies.get(SESSION_COOKIE))   # server-side: copies die too
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    # -- dashboard

    async def cards_ctx() -> dict:
        devices = await service.list_devices()
        groups = sorted({g for d in devices for g in d["groups"]}, key=str.lower)
        return {"devices": devices, "groups": groups}

    @r.get("/")
    async def dashboard(request: Request):
        return render(request, "dashboard.html", **(await cards_ctx()))

    @r.get("/partials/cards")
    async def cards(request: Request):
        return render(request, "_cards.html", **(await cards_ctx()))

    # -- confirm + bulk

    @r.get("/confirm/{action}")
    async def confirm_page(request: Request, action: str, target: str = "", preset: str = ""):
        if action not in DEVICE_CONFIRM_ACTIONS:
            raise WebError(404, "Not found.")
        if action == "enable-wol" and preset not in PRESETS:
            if preset:
                raise WebError(400, "Unknown Wake-on-LAN preset.")
            preset = "auto"
        try:
            members = resolve_targets(repo, target)
        except (UnknownTarget, NoDevices):
            raise WebError(404, "No such device or group.") from None
        bulk = is_bulk(target, repo)
        if bulk and action not in BULK_CONFIRM_ACTIONS:
            raise WebError(404, "Not found.")
        selfs = {d["name"] for d in await service.list_devices() if d["is_self"]}
        affected = [d.name for d in members if not (bulk and d.name in selfs)]
        # only devices the target names: a self device outside the group is not "excluded" from it
        # ('all' already drops stored self devices in resolve_targets, so list them from the repo)
        named = repo.list() if target.lower() == "all" else members
        excluded = sorted(d.name for d in named if d.name in selfs) if bulk else []
        post_to = f"/bulk/{action}" if bulk else f"/devices/{_q(target)}/{action}"
        return render(request, "confirm.html", action=action, verb=CONFIRM_VERBS[action],
                      target=target, bulk=bulk,
                      affected=affected, excluded=excluded, is_self=(not bulk and target in selfs),
                      post_to=post_to, preset=preset if action == "enable-wol" else None,
                      preset_label=PRESETS.get(preset))

    @r.post("/bulk/{action}")
    async def bulk(request: Request, action: str):
        if action not in BULK_ACTIONS:
            raise WebError(404, "Not found.")
        form = await request.form()
        target = str(form.get("target", "") or "").strip()
        confirm = form.get("confirm") == "1"
        if not target:
            raise WebError(400, "No target given.")
        title = f"{action} {target}"
        if action in BULK_CONFIRM_ACTIONS and not confirm and not _is_hx(request):
            return RedirectResponse(confirm_url(action, target), status_code=303)
        if action == "wake":
            coro = service.wake(target, caller=CALLER)
        elif action == "shutdown":
            coro = service.shutdown(target, caller=CALLER, confirm=confirm)
        else:
            coro = service.reboot(target, caller=CALLER, confirm=confirm)
        return await run_action(request, title, coro, confirm_url=confirm_url(action, target))

    # -- devices

    @r.get("/devices/new")
    async def new_device(request: Request):
        return render(request, "device_form.html", device=None, form={}, editing=False)

    @r.post("/devices/new")
    async def add_device(request: Request):
        form = await request.form()
        try:
            d = _parse_device(form, None)
            repo.add(d)
        except FormError as e:
            return render(request, "device_form.html", 400, device=None, form=form, editing=False,
                          error=str(e))
        except DuplicateDevice:
            return render(request, "device_form.html", 400, device=None, form=form, editing=False,
                          error="A device with that name already exists.")
        _audit("device_add", d.name, "ok")
        return RedirectResponse(f"/devices/{_q(d.name)}", status_code=303)

    def _audit(action: str, target: str, res: str) -> None:
        try:
            service.audit.record(CALLER, target, action, res)
        except Exception as e:
            log.error("audit write failed (%s %s): %s", action, target, type(e).__name__)

    def _history(name: str) -> list[dict]:
        try:
            rows = service.audit.list(limit=1000)
        except Exception:
            return []
        return [row for row in rows if row["target"] == name][:HISTORY_LIMIT]

    @r.get("/devices/{name}")
    async def device_detail(request: Request, name: str):
        d = get_device(name)
        info, info_error, status = None, None, "unknown"
        try:
            st = (await service.device_status(name)).get(d.name) or {}
            status = st.get("status", "unknown")
            info = st.get("info")
            if info is None:
                info_error = st.get("error") or ("device is down" if status == "down" else "no data")
        except Exception as e:
            log.warning("status for %s failed: %s", d.name, type(e).__name__)
            info_error = "status check failed"
        try:
            enroll_cmd, pubkey = keystore.authorize_command(d.key_id), keystore.public_key(d.key_id)
        except Exception as e:
            log.warning("key for %s unavailable: %s", d.name, type(e).__name__)
            enroll_cmd, pubkey = None, None
        selfs = {x["name"] for x in await service.list_devices() if x["is_self"]}
        return render(request, "device.html", wol_presets=PRESETS, d=d, is_self=d.name in selfs, dev_status=status, info=info,
                      info_error=info_error, enroll_cmd=enroll_cmd, pubkey=pubkey,
                      history=_history(d.name))

    @r.get("/devices/{name}/edit")
    async def edit_page(request: Request, name: str):
        d = get_device(name)
        form = {"name": d.name, "host": d.host, "ssh_user": d.ssh_user, "ssh_port": d.ssh_port,
                "mac": d.mac or "", "broadcast": d.broadcast or "", "type": d.type,
                "groups": ", ".join(d.groups), "shutdown_mode": d.shutdown_mode, "notes": d.notes,
                "allow_run_command": "1" if d.allow_run_command else "",
                "bios_verified": "1" if d.bios_verified else "", "is_self": "1" if d.is_self else ""}
        return render(request, "device_form.html", device=d, form=form, editing=True)

    @r.post("/devices/{name}/{action}")
    async def device_action(request: Request, name: str, action: str):
        if action not in DEVICE_ACTIONS:
            raise WebError(404, "Not found.")
        d = get_device(name)
        form = await request.form()
        confirm = form.get("confirm") == "1"
        preset = str(form.get("preset") or "auto")
        if action == "enable-wol" and preset not in PRESETS:  # whitelist, checked before anything else
            return result(request, f"enable WoL {d.name}", message="Unknown Wake-on-LAN preset.",
                          ok=False, status=400)
        if action == "enable-wol" and not confirm and not _is_hx(request):
            return RedirectResponse(f"{confirm_url(action, d.name)}&preset={_q(preset)}", status_code=303)
        if action in DEVICE_CONFIRM_ACTIONS and not confirm and not _is_hx(request):
            # no JavaScript means no hx-confirm dialog ran: confirm on the server-rendered page
            return RedirectResponse(confirm_url(action, d.name), status_code=303)
        if action == "wake":
            return await run_action(request, f"wake {d.name}", service.wake(d.name, caller=CALLER))
        if action == "shutdown":
            return await run_action(request, f"shutdown {d.name}",
                                    service.shutdown(d.name, caller=CALLER, confirm=confirm),
                                    confirm_url=confirm_url("shutdown", d.name))
        if action == "reboot":
            return await run_action(request, f"reboot {d.name}",
                                    service.reboot(d.name, caller=CALLER, confirm=confirm),
                                    confirm_url=confirm_url("reboot", d.name))
        if action == "wol-check":
            return await run_action(request, f"WoL check {d.name}", service.wake_check(d.name, caller=CALLER))
        if action == "enable-wol":
            return await run_action(request, f"enable WoL {d.name}",
                                    service.enable_wol(d.name, caller=CALLER, preset=preset))
        if action == "wake-test":
            return await run_action(request, f"wake test {d.name}", service.wake_test(d.name, caller=CALLER))
        if action == "ack-host-key":
            async def ack():
                await service.acknowledge_host_key(d.name, caller=CALLER)
                return None
            resp = await run_action(request, f"acknowledge host key {d.name}", ack())
            if resp.status_code == 200:
                return result(request, f"acknowledge host key {d.name}",
                              message="Host key pin cleared; the next connection pins the new key.")
            return resp
        if action == "enroll":
            return await enroll(request, d, form)
        if action == "delete":
            try:
                repo.remove(d.name)
            except UnknownDevice:
                raise WebError(404, "No such device.") from None
            _audit("device_delete", d.name, "ok")
            if _is_hx(request):
                return Response(status_code=200, headers={"HX-Redirect": "/"})
            return RedirectResponse("/", status_code=303)
        # edit
        try:
            new = _parse_device(form, d)
            repo.update(new)
        except FormError as e:
            return render(request, "device_form.html", 400, device=d, form=form, editing=True, error=str(e))
        except DuplicateDevice:
            return render(request, "device_form.html", 400, device=d, form=form, editing=True,
                          error="A device with that name already exists.")
        except UnknownDevice:
            raise WebError(404, "No such device.") from None
        _audit("device_edit", new.name, "ok" if new.name == d.name else f"ok: renamed from {d.name}")
        return RedirectResponse(f"/devices/{_q(new.name)}", status_code=303)

    async def enroll(request: Request, d: Device, form) -> HTMLResponse:
        password = form.get("password")
        if not isinstance(password, str) or not password:
            return result(request, f"enroll {d.name}", message="Enter the device's SSH password.",
                          ok=False, status=400)
        try:
            await runner.enroll_with_password(d, password)
        except Exception as e:
            reason = _enroll_reason(e)
            # log only the exception type: its text could echo the password
            log.warning("enroll %s failed: %s", d.name, type(e).__name__)
            _audit("enroll", d.name, f"fail: {reason}")
            return result(request, f"enroll {d.name}", message=f"Enrollment failed: {reason}.", ok=False)
        finally:
            password = None  # noqa: F841 - used for that one call only
        _audit("enroll", d.name, "ok")
        return result(request, f"enroll {d.name}",
                      message="Enrolled: the Wakeboard key is installed. The password was not stored.")

    # -- audit / settings

    @r.get("/audit")
    async def audit_page(request: Request):
        try:
            rows = service.audit.list(limit=AUDIT_LIMIT)
        except Exception as e:
            log.error("audit read failed: %s", type(e).__name__)
            rows, err = [], "The audit log is unavailable."
        else:
            err = None
        return render(request, "audit.html", rows=rows, error=err, limit=AUDIT_LIMIT)

    def settings_ctx() -> dict:
        try:
            pubkey = keystore.public_key()
        except Exception:
            pubkey = None
        return {"pubkey": pubkey, "settings": {
            "poll_interval": settings.poll_interval, "wake_timeout": settings.wake_timeout,
            "guest_timeout": settings.guest_timeout, "shutdown_timeout": settings.shutdown_timeout}}

    @r.get("/settings")
    async def settings_page(request: Request):
        return render(request, "settings.html", **settings_ctx())

    async def check_current(request: Request, form, err_key: str) -> HTMLResponse | None:
        """Re-check the current password (under lockout); None when it is right."""
        cur = form.get("current")
        cur = cur if isinstance(cur, str) else ""
        try:
            ok = bool(cur) and await auth.check_password_async(cur, client_ip(request))
        except LockedOut as e:
            return render(request, "settings.html", 429, headers={"Retry-After": str(e.retry_after)},
                          **{err_key: f"Too many failed attempts. Try again in {e.retry_after} seconds."},
                          **settings_ctx())
        if not ok:
            return render(request, "settings.html", 400,
                          **{err_key: "Current password is incorrect."}, **settings_ctx())
        return None

    @r.post("/settings")
    async def settings_post(request: Request):
        form = await request.form()
        op = form.get("op")
        if op == "rotate_token":
            denied = await check_current(request, form, "token_error")
            if denied is not None:
                return denied
            token = auth.rotate_token()
            _audit("rotate_token", "mcp", "ok")
            return render(request, "settings.html", new_token=token, **settings_ctx())
        if op == "password":
            new, new2 = str(form.get("new", "") or ""), str(form.get("confirm", "") or "")
            denied = await check_current(request, form, "pw_error")
            if denied is not None:
                return denied
            if len(new) < MIN_PASSWORD:
                return render(request, "settings.html", 400,
                              pw_error=f"New password must be at least {MIN_PASSWORD} characters.",
                              **settings_ctx())
            if new != new2:
                return render(request, "settings.html", 400, pw_error="New passwords do not match.",
                              **settings_ctx())
            auth.set_password(new)   # rotates the session secret: all sessions end
            _audit("change_password", "ui", "ok")
            sess = auth.new_session()
            html = env.get_template("settings.html").render(
                csrf=auth.csrf_token("s:" + sess), authed=True,
                pw_message="Password changed. Other sessions were signed out.", **settings_ctx())
            resp = HTMLResponse(html, headers={"cache-control": "no-store"})
            _cookie(resp, request, SESSION_COOKIE, sess, SESSION_MAX_AGE)
            return resp
        raise WebError(400, "Unknown settings operation.")

    r.render = render  # for the exception handlers
    return r


def mount_web(app: FastAPI, service, auth, *, keystore, runner, settings) -> None:
    """Mount the web UI, its static files, error handlers and security headers."""
    router = build_web_router(service, auth, keystore=keystore, runner=runner, settings=settings)
    app.include_router(router)
    app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")
    render = router.render

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired):
        if _is_hx(request):
            return Response(status_code=401, headers={"HX-Redirect": "/login"})
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(WebError)
    async def _web_error(request: Request, exc: WebError):
        if _is_hx(request):
            return render(request, "_result.html", exc.status, title="Error", results=None,
                          message=exc.message, ok=False, confirm_url=None)
        return render(request, "error.html", exc.status, message=exc.message)

    app.add_middleware(SecurityHeaders)
