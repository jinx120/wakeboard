"""Web UI over a real Service + AuthStore + tmp sqlite, with fake actions/runner/prober."""
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from wakeboard.audit import AuditLog
from wakeboard.auth import AuthStore
from wakeboard.config import Settings
from wakeboard.devices import Device, DeviceRepo
from wakeboard.service import Service
from wakeboard.ssh import EnrollmentFailed
from wakeboard.sshkeys import KeyStore
from wakeboard.status import Info
from wakeboard.web.routes import mount_web

from test_service import FakeActions, FakeProber, FakeRunner

PASSWORD = "correct horse battery"
ENROLL_PW = "s3cret-enroll-PASSWORD-xyz"
INFO = Info(uptime_s=90061, load1=0.1, mem_used_pct=5.0, disk_root_pct=7.0, cpu_temp_c=40.0,
            kernel="6.8", pve_version="8.2", vms_running=1, cts_running=0, fetched_at=1.0)


class EnrollRunner(FakeRunner):
    def __init__(self):
        super().__init__()
        self.enrolled: list[tuple[str, str]] = []
        self.enroll_exc: Exception | None = None

    async def enroll_with_password(self, device, password, timeout=30):
        self.enrolled.append((device.name, password))
        if self.enroll_exc:
            raise self.enroll_exc


def _build(conn, tmp_path, *, password=True):
    repo = DeviceRepo(conn)
    repo.add(Device(name="pve1", host="10.0.0.1", type="proxmox", groups=["lab"], mac="aa:bb:cc:00:00:01"))
    repo.add(Device(name="pve2", host="10.0.0.2", groups=["lab"], mac="aa:bb:cc:00:00:02"))
    repo.add(Device(name="pi", host="10.0.0.9", is_self=True))
    audit = AuditLog(conn)
    auth = AuthStore(conn)
    if password:
        auth.set_password(PASSWORD)
    actions = FakeActions()
    runner = EnrollRunner()
    keystore = KeyStore(tmp_path)
    keystore.ensure_global()

    async def collect(r, d):
        return INFO
    svc = Service(repo, audit, actions, runner, FakeProber(), {},
                  local_ips=lambda: {"127.0.0.1"}, resolve=lambda h: set(), collect_info=collect)
    settings = Settings(data_dir=tmp_path)
    app = FastAPI()
    mount_web(app, svc, auth, keystore=keystore, runner=runner, settings=settings)
    return {"app": app, "client": TestClient(app), "auth": auth, "actions": actions,
            "runner": runner, "audit": audit, "repo": repo, "svc": svc, "keystore": keystore}


@pytest.fixture
def env(conn, tmp_path):
    return _build(conn, tmp_path)


@pytest.fixture
def fresh(tmp_path):
    from wakeboard.db import connect
    (tmp_path / "fresh").mkdir()
    c = connect(tmp_path / "fresh" / "wakeboard.db")
    yield _build(c, tmp_path / "fresh", password=False)
    c.close()


def csrf_of(html: str) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    assert m, "no csrf field in page"
    return m.group(1)


def login(c, pw=PASSWORD):
    page = c.get("/login")
    return c.post("/login", data={"password": pw, "csrf": csrf_of(page.text)}, follow_redirects=False)


@pytest.fixture
def authed(env):
    r = login(env["client"])
    assert r.status_code == 303
    page = env["client"].get("/")
    env["csrf"] = csrf_of(page.text)
    return env


def post(env, path, data=None, **kw):
    d = {"csrf": env["csrf"], **(data or {})}
    return env["client"].post(path, data=d, **kw)


# ---- auth / setup ------------------------------------------------------------------

def test_redirects_to_login_when_unauthenticated(env):
    c = env["client"]
    for path in ("/", "/partials/cards", "/devices/new", "/devices/pve1", "/audit", "/settings"):
        r = c.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login", path
    r = c.post("/devices/pve1/shutdown", data={}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert env["actions"].calls == []
    # htmx polling gets HX-Redirect instead of a swapped login page
    r = c.get("/partials/cards", headers={"HX-Request": "true"}, follow_redirects=False)
    assert r.status_code == 401 and r.headers["hx-redirect"] == "/login"
    # static, login and setup are reachable
    assert c.get("/static/style.css").status_code == 200
    assert c.get("/static/htmx.min.js").status_code == 200
    assert c.get("/login").status_code == 200


def test_setup_only_when_no_password(fresh):
    c, auth = fresh["client"], fresh["auth"]
    r = c.get("/login", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/setup"
    page = c.get("/setup")
    assert page.status_code == 200 and 'type="password"' in page.text
    tok = csrf_of(page.text)
    # no csrf -> refused
    r = c.post("/setup", data={"password": "new-password-1", "confirm": "new-password-1"})
    assert r.status_code == 403 and not auth.password_set()
    r = c.post("/setup", data={"password": "short", "confirm": "short", "csrf": tok})
    assert r.status_code == 400 and not auth.password_set()
    r = c.post("/setup", data={"password": "new-password-1", "confirm": "different-1", "csrf": tok})
    assert r.status_code == 400 and not auth.password_set()
    r = c.post("/setup", data={"password": "new-password-1", "confirm": "new-password-1", "csrf": tok},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert auth.check_password("new-password-1", "x")
    assert c.get("/").status_code == 200          # logged in by setup
    # once set: GET redirects, POST is 404 and cannot overwrite
    r = c.get("/setup", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    tok2 = csrf_of(c.get("/login").text) if c.get("/login", follow_redirects=False).status_code == 200 else tok
    r = c.post("/setup", data={"password": "attacker-pw-1", "confirm": "attacker-pw-1", "csrf": tok2})
    assert r.status_code == 404
    assert auth.check_password("new-password-1", "x")


def test_login_sets_cookie_and_dashboard_renders_devices(env):
    c = env["client"]
    r = login(c)
    assert r.status_code == 303 and r.headers["location"] == "/"
    sc = r.headers["set-cookie"]
    assert "wakeboard_session=" in sc and "httponly" in sc.lower() and "path=/" in sc.lower()
    assert "samesite=strict" in sc.lower() or "samesite=lax" in sc.lower()
    assert "secure" not in sc.lower()           # plain http
    page = c.get("/")
    assert page.status_code == 200
    for name in ("pve1", "pve2", "pi"):
        assert name in page.text
    assert 'name="viewport"' in page.text
    assert 'hx-get="/partials/cards"' in page.text and "every 5s" in page.text
    assert "self" in c.get("/partials/cards").text.lower()   # self badge
    # next/redirect params are ignored: never an open redirect
    c.cookies.clear()
    page = c.get("/login")
    r = c.post("/login?next=https://evil.example/", data={"password": PASSWORD, "csrf": csrf_of(page.text),
                                                           "next": "https://evil.example/"},
               follow_redirects=False)
    assert r.headers["location"] in ("/", "/login")


def test_login_cookie_secure_behind_https_proxy(env):
    c = env["client"]
    page = c.get("/login")
    r = c.post("/login", data={"password": PASSWORD, "csrf": csrf_of(page.text)},
               headers={"X-Forwarded-Proto": "https"}, follow_redirects=False)
    assert "secure" in r.headers["set-cookie"].lower()


def test_login_failure_identical_for_wrong_and_unset(env, fresh):
    r1 = login(env["client"], pw="wrong-password")
    r2 = login(fresh["client"], pw="wrong-password")
    assert r1.status_code == r2.status_code == 401
    strip = lambda t: re.sub(r'value="[^"]*"|\'{"X-CSRF-Token"[^\']*\'', "", t)
    assert strip(r1.text) == strip(r2.text)
    assert "wakeboard_session" not in r1.headers.get("set-cookie", "")


def test_login_lockout_returns_429(env):
    c = env["client"]
    for _ in range(5):
        assert login(c, pw="nope").status_code == 401
    r = login(c)                    # even the right password
    assert r.status_code == 429
    assert "try again" in r.text.lower() and r.headers.get("retry-after")
    assert "wakeboard_session" not in r.headers.get("set-cookie", "")


def test_logout_requires_csrf_and_clears_session(authed):
    c = authed["client"]
    assert c.post("/logout", data={}).status_code == 403
    assert c.get("/", follow_redirects=False).status_code == 200
    stolen = c.cookies.get("wakeboard_session")
    r = post(authed, "/logout", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert c.get("/", follow_redirects=False).status_code == 303
    # a copied cookie is dead too: logout revokes the session server-side
    c.cookies.set("wakeboard_session", stolen)
    assert c.get("/", follow_redirects=False).status_code == 303
    assert c.get("/settings", follow_redirects=False).status_code == 303


# ---- CSRF / headers --------------------------------------------------------------

def test_csrf_missing_or_wrong_is_403_and_does_nothing(authed):
    c = authed["client"]
    r = c.post("/devices/pve1/wake", data={})
    assert r.status_code == 403
    r = c.post("/devices/pve1/wake", data={"csrf": "wrong"})
    assert r.status_code == 403
    r = c.post("/devices/pve1/wake", data={}, headers={"X-CSRF-Token": "wrong"})
    assert r.status_code == 403
    r = c.post("/devices/pve1/delete", data={"csrf": "wrong"})
    assert r.status_code == 403 and authed["repo"].get("pve1") is not None
    r = c.post("/settings", data={"op": "rotate_token"})
    assert r.status_code == 403 and not authed["auth"]._get("auth.token_hash")
    assert authed["actions"].calls == []
    # right token in the HTMX header works
    r = c.post("/devices/pve1/wake", headers={"X-CSRF-Token": authed["csrf"], "HX-Request": "true"})
    assert r.status_code == 200 and authed["actions"].calls == [("wake", "pve1", {})]
    # and as a form field
    r = post(authed, "/devices/pve2/wake")
    assert r.status_code == 200 and authed["actions"].calls[-1][:2] == ("wake", "pve2")


def test_get_requests_never_change_state(authed):
    c = authed["client"]
    for path in ("/devices/pve1/shutdown", "/devices/pve1/reboot", "/devices/pve1/wake",
                 "/devices/pve1/delete", "/bulk/shutdown?target=all", "/logout"):
        assert c.get(path).status_code in (404, 405), path
    c.get("/confirm/shutdown?target=all")
    c.get("/confirm/reboot?target=pi")
    c.get("/settings")
    assert authed["actions"].calls == []
    assert authed["repo"].get("pve1") is not None
    assert not authed["auth"]._get("auth.token_hash")


def test_security_headers_and_no_external_assets(authed):
    c = authed["client"]
    for path in ("/", "/login", "/static/style.css", "/devices/pve1", "/settings", "/audit"):
        r = c.get(path)
        assert r.headers["content-security-policy"] == (
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'"), path
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["referrer-policy"] == "no-referrer"
        if path.startswith("/static"):
            continue
        assert "http://" not in r.text and "https://" not in r.text, path
        assert not re.search(r"\son[a-z]+\s*=", r.text), path     # no inline handlers
        assert "<script>" not in r.text and " style=" not in r.text, path
        assert '<script src="/static/htmx.min.js"' in r.text
        assert "includeIndicatorStyles" in r.text


def test_names_and_notes_are_escaped(authed):
    d = authed["repo"].get("pve2")
    d.notes = "<script>alert(1)</script>"
    authed["repo"].update(d)
    r = authed["client"].get("/devices/pve2")
    assert "<script>alert(1)</script>" not in r.text and "&lt;script&gt;" in r.text


# ---- devices ------------------------------------------------------------------------

def test_add_device_then_visible(authed):
    c = authed["client"]
    page = c.get("/devices/new")
    assert page.status_code == 200
    r = post(authed, "/devices/new", {"name": "nas", "host": "10.0.0.20", "ssh_user": "admin",
                                      "ssh_port": "22", "mac": "", "broadcast": "", "type": "linux",
                                      "groups": "lab, storage", "notes": "<b>x</b>"},
             follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/devices/nas"
    d = authed["repo"].get("nas")
    assert d.mac is None and d.broadcast is None and d.groups == ["lab", "storage"]
    assert "nas" in c.get("/").text
    detail = c.get("/devices/nas")
    assert detail.status_code == 200
    assert authed["keystore"].public_key().split()[1] in detail.text   # enrollment command
    assert 'autocomplete="off"' in detail.text


@pytest.mark.parametrize("field,value,msg", [
    ("mac", "zz:zz", "mac"),
    ("name", "pve1", "already exists"),
    ("name", "bad name/../", "name"),
    ("name", "new", "name"),
    ("groups", "ok, bad group!", "group"),
    ("ssh_port", "99999", "port"),
    ("broadcast", "not-an-ip", "broadcast"),
    ("type", "macos", "type"),
    ("wol_method", "bogus", "wol"),
])
def test_add_device_validation_rerenders_form(authed, field, value, msg):
    data = {"name": "nas", "host": "10.0.0.20", "ssh_user": "root", "ssh_port": "22",
            "type": "linux", field: value}
    r = post(authed, "/devices/new", data)
    assert r.status_code == 400 and msg in r.text.lower()
    assert 'name="host"' in r.text and "10.0.0.20" in r.text     # form re-rendered with values
    if field != "name" or value != "pve1":
        assert authed["repo"].get("nas") is None


def test_edit_and_delete_device(authed):
    c = authed["client"]
    page = c.get("/devices/pve2/edit")
    assert page.status_code == 200 and "10.0.0.2" in page.text
    r = post(authed, "/devices/pve2/edit", {"name": "pve2", "host": "10.0.0.22", "ssh_user": "root",
                                            "ssh_port": "2222", "type": "linux", "groups": "lab",
                                            "mac": "aa-bb-cc-00-00-22"}, follow_redirects=False)
    assert r.status_code == 303
    d = authed["repo"].get("pve2")
    assert d.host == "10.0.0.22" and d.ssh_port == 2222 and d.mac == "aa:bb:cc:00:00:22"
    r = post(authed, "/devices/pve2/edit", {"name": "pve1", "host": "x", "ssh_user": "root",
                                            "ssh_port": "22", "type": "linux"})
    assert r.status_code == 400 and "already exists" in r.text
    r = post(authed, "/devices/pve2/delete", {"confirm": "1"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert authed["repo"].get("pve2") is None


def test_unknown_device_is_404(authed):
    c = authed["client"]
    assert c.get("/devices/nope").status_code == 404
    assert c.get("/devices/nope/edit").status_code == 404
    for a in ("wake", "shutdown", "reboot", "wol-check", "wake-test", "enable-wol", "enroll", "ack-host-key", "delete"):
        r = post(authed, f"/devices/nope/{a}", {"password": "x"})
        assert r.status_code == 404, a
    assert post(authed, "/devices/pve1/bogus").status_code == 404
    assert authed["actions"].calls == []


def test_device_detail_info_and_unavailable(authed):
    c = authed["client"]
    r = c.get("/devices/pve1")
    assert r.status_code == 200 and "8.2" in r.text and "1d 1h" in r.text

    async def broken(runner, d):
        raise RuntimeError("ssh exploded")
    authed["svc"].info_cache = type(authed["svc"].info_cache)()
    authed["svc"]._collect_info = broken
    r = c.get("/devices/pve2")
    assert r.status_code == 200 and "unavailable:" in r.text


# ---- actions -------------------------------------------------------------------------

def test_shutdown_button_has_confirm_attr(authed):
    c = authed["client"]
    for path in ("/", "/devices/pve1", "/confirm/shutdown?target=all", "/confirm/reboot?target=pi"):
        html = c.get(path).text
        buttons = re.findall(r"<button[^>]*>\s*[^<]*(?:Shutdown|Shut down|Reboot|Wake test|Run wake test)",
                             html, re.I)
        assert buttons, path
        for b in buttons:
            assert "hx-confirm=" in b, (path, b)
    # the self device never gets a direct shutdown button: it links to the confirm page
    cards = c.get("/partials/cards").text
    assert "/confirm/shutdown?target=pi" in cards and "/confirm/reboot?target=pi" in cards
    assert 'hx-post="/devices/pi/shutdown"' not in cards


def test_single_shutdown_calls_service_as_ui(authed):
    r = post(authed, "/devices/pve1/shutdown", headers={"HX-Request": "true"})
    assert r.status_code == 200 and "shutdown done" in r.text
    assert authed["actions"].calls == [("shutdown", "pve1", {"mode": None})]
    assert {row["caller"] for row in authed["audit"].list()} == {"ui"}


def test_self_device_goes_through_confirm_page(authed):
    c = authed["client"]
    r = post(authed, "/devices/pi/shutdown", headers={"HX-Request": "true"})
    assert r.status_code == 409 and "WARNING" in r.text and "/confirm/shutdown?target=pi" in r.text
    assert authed["actions"].calls == []
    page = c.get("/confirm/shutdown?target=pi")
    assert page.status_code == 200 and "Wakeboard" in page.text and "pi" in page.text
    assert 'action="/devices/pi/shutdown"' in page.text and 'name="confirm" value="1"' in page.text
    r = post(authed, "/devices/pi/shutdown", {"confirm": "1"})
    assert r.status_code == 200 and authed["actions"].calls == [("shutdown", "pi", {"mode": None})]


def test_bulk_shutdown_requires_confirm_page(authed):
    c = authed["client"]
    dash = c.get("/").text
    assert "/confirm/shutdown?target=all" in dash and "/confirm/shutdown?target=lab" in dash
    page = c.get("/confirm/shutdown?target=all")
    assert page.status_code == 200
    assert "pve1" in page.text and "pve2" in page.text and "excluded" in page.text.lower()
    assert 'action="/bulk/shutdown"' in page.text and 'name="confirm" value="1"' in page.text
    r = post(authed, "/bulk/shutdown", {"target": "all"}, headers={"HX-Request": "true"})
    assert r.status_code == 409 and authed["actions"].calls == []
    assert "/confirm/shutdown?target=all" in r.text
    r = post(authed, "/bulk/shutdown", {"target": "all"}, follow_redirects=False)   # no JS
    assert r.status_code == 303 and r.headers["location"] == "/confirm/shutdown?target=all"
    assert authed["actions"].calls == []
    r = post(authed, "/bulk/shutdown", {"target": "all", "confirm": "1"})
    assert r.status_code == 200
    assert sorted(n for _, n, _ in authed["actions"].calls) == ["pve1", "pve2"]
    assert c.get("/confirm/shutdown?target=nope").status_code == 404
    assert c.get("/confirm/explode?target=all").status_code == 404


def test_bulk_wake_and_group_reboot(authed):
    r = post(authed, "/bulk/wake", {"target": "lab"})
    assert r.status_code == 200 and {n for _, n, _ in authed["actions"].calls} == {"pve1", "pve2"}
    r = post(authed, "/bulk/reboot", {"target": "lab", "confirm": "1"})
    assert r.status_code == 200
    assert sum(1 for a, _, _ in authed["actions"].calls if a == "reboot") == 2
    r = post(authed, "/bulk/wake", {"target": "nogroup"})
    assert r.status_code == 404


def test_service_errors_render_messages_not_500(authed):
    def boom(*a):
        raise RuntimeError("database is locked")
    authed["audit"].record = boom
    r = post(authed, "/devices/pve1/shutdown", {"confirm": "1"})
    assert r.status_code == 503 and "audit" in r.text.lower() and "Traceback" not in r.text
    assert authed["actions"].calls == []

    async def kaboom(*a, **k):
        raise RuntimeError("internal detail")
    authed["svc"].wake = kaboom
    r = post(authed, "/devices/pve1/wake")
    assert r.status_code == 500 and "Traceback" not in r.text and "internal detail" not in r.text


def test_wol_check_wake_test_and_ack(authed):
    r = post(authed, "/devices/pve1/ack-host-key", {"confirm": "1"})
    assert r.status_code == 200 and authed["runner"].acked == ["pve1"]
    assert authed["repo"].get("pve1").host_key_ack is True
    r = post(authed, "/devices/pve1/wol-check")
    assert r.status_code == 200          # fake runner output: rendered, not a 500
    r = post(authed, "/devices/pve1/wake-test", {"confirm": "1"})
    assert r.status_code == 200


def test_enroll_password_not_in_response_or_audit(authed, caplog):
    caplog.set_level("DEBUG")
    r = post(authed, "/devices/pve1/enroll", {"password": ENROLL_PW})
    assert r.status_code == 200 and authed["runner"].enrolled == [("pve1", ENROLL_PW)]
    assert ENROLL_PW not in r.text and "enrolled" in r.text.lower()
    authed["runner"].enroll_exc = EnrollmentFailed(f"installing key failed: echo {ENROLL_PW}")
    r = post(authed, "/devices/pve1/enroll", {"password": ENROLL_PW})
    assert r.status_code == 200 and ENROLL_PW not in r.text and "failed" in r.text.lower()
    authed["runner"].enroll_exc = RuntimeError(ENROLL_PW)
    r = post(authed, "/devices/pve1/enroll", {"password": ENROLL_PW})
    assert ENROLL_PW not in r.text
    rows = authed["audit"].list()
    assert any(row["action"] == "enroll" for row in rows)
    assert all(ENROLL_PW not in str(row) for row in rows)
    assert ENROLL_PW not in caplog.text
    assert ENROLL_PW not in authed["client"].get("/audit").text
    assert ENROLL_PW not in authed["client"].get("/devices/pve1").text
    assert post(authed, "/devices/pve1/enroll", {"password": ""}).status_code == 400


# ---- settings / audit ----------------------------------------------------------------

def test_token_shown_once_on_rotate(authed):
    c = authed["client"]
    r = post(authed, "/settings", {"op": "rotate_token", "current": PASSWORD})
    assert r.status_code == 200
    m = re.search(r'id="new-token"[^>]*>([A-Za-z0-9_\-]{20,})<', r.text)
    assert m, "token not shown"
    token = m.group(1)
    assert authed["auth"].check_token(token)
    assert "copy it now" in r.text.lower()
    assert "no-store" in r.headers.get("cache-control", "")
    assert token not in r.headers.get("set-cookie", "") and token not in str(r.url)
    later = c.get("/settings")
    assert token not in later.text
    assert authed["keystore"].public_key().split()[1] in later.text
    assert "30" in later.text   # poll interval default


def test_change_password(authed):
    c = authed["client"]
    r = post(authed, "/settings", {"op": "password", "current": "wrong-pw", "new": "another-pass-1",
                                    "confirm": "another-pass-1"})
    assert r.status_code == 400 and authed["auth"].check_password(PASSWORD, "y")
    r = post(authed, "/settings", {"op": "password", "current": PASSWORD, "new": "another-pass-1",
                                    "confirm": "another-pass-1"})
    assert r.status_code == 200 and "changed" in r.text.lower()
    assert authed["auth"].check_password("another-pass-1", "y")
    assert c.get("/", follow_redirects=False).status_code == 200   # re-issued session


def test_audit_page_lists_entries(authed):
    post(authed, "/devices/pve1/wake")
    post(authed, "/devices/pve2/wake")
    r = authed["client"].get("/audit")
    assert r.status_code == 200
    assert r.text.index("pve2") < r.text.index("pve1")     # newest first
    assert "ui" in r.text and "wake" in r.text


# ---- wiring through create_app ---------------------------------------------------------

def test_create_app_mounts_web(tmp_path):
    from wakeboard import main
    app = main.create_app(Settings(data_dir=tmp_path))
    c = TestClient(app)
    assert c.get("/", follow_redirects=False).headers["location"] in ("/login", "/setup")
    assert c.get("/static/htmx.min.js").status_code == 200
    assert c.get("/healthz").json() == {"ok": True}
    assert c.get("/healthz").headers["x-content-type-options"] == "nosniff"
    assert c.get("/api/v1/devices").status_code == 401


def test_package_data_includes_templates_and_static():
    import tomllib
    from pathlib import Path
    cfg = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())
    data = cfg["tool"]["setuptools"]["package-data"]["wakeboard"]
    assert any("templates" in p for p in data) and any("static" in p for p in data)


# ---- review fix round ------------------------------------------------------------------

def test_rotate_token_requires_current_password(authed):
    for data in ({}, {"current": ""}, {"current": "wrong-password"}):
        r = post(authed, "/settings", {"op": "rotate_token", **data})
        assert r.status_code == 400, data
        assert "password" in r.text.lower() and 'id="new-token"' not in r.text
    assert not authed["auth"]._get("auth.token_hash")
    page = authed["client"].get("/settings").text
    form = page[page.index('value="rotate_token"'):]
    form = form[:form.index("</form>")]
    assert 'type="password"' in form and 'name="current"' in form
    r = post(authed, "/settings", {"op": "rotate_token", "current": PASSWORD})
    assert r.status_code == 200 and 'id="new-token"' in r.text


def test_rotate_token_honours_lockout(authed):
    for _ in range(5):
        post(authed, "/settings", {"op": "rotate_token", "current": "nope-nope"})
    r = post(authed, "/settings", {"op": "rotate_token", "current": PASSWORD})
    assert r.status_code == 429 and r.headers.get("retry-after")
    assert not authed["auth"]._get("auth.token_hash")


@pytest.mark.parametrize("action", ["shutdown", "reboot", "wake-test", "delete", "ack-host-key"])
def test_no_js_destructive_post_goes_to_confirm_page(authed, action):
    c = authed["client"]
    r = post(authed, f"/devices/pve1/{action}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/confirm/{action}?target=pve1"
    assert authed["actions"].calls == [] and authed["runner"].acked == []
    assert authed["repo"].get("pve1") is not None
    page = c.get(r.headers["location"])
    assert page.status_code == 200
    assert f'action="/devices/pve1/{action}"' in page.text and 'name="confirm" value="1"' in page.text
    r = post(authed, f"/devices/pve1/{action}", {"confirm": "1"}, follow_redirects=False)
    assert r.status_code in (200, 303)
    if action == "delete":
        assert authed["repo"].get("pve1") is None
    elif action == "ack-host-key":
        assert authed["runner"].acked == ["pve1"]
    else:
        assert authed["actions"].calls or authed["runner"].calls


def test_confirm_page_device_only_actions_reject_groups(authed):
    c = authed["client"]
    for action in ("wake-test", "delete", "ack-host-key"):
        assert c.get(f"/confirm/{action}?target=lab").status_code == 404
        assert c.get(f"/confirm/{action}?target=all").status_code == 404
    assert c.get("/confirm/delete?target=nope").status_code == 404


def test_bulk_no_js_reboot_goes_to_confirm_page(authed):
    r = post(authed, "/bulk/reboot", {"target": "lab"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/confirm/reboot?target=lab"
    assert authed["actions"].calls == []


def test_group_confirm_excludes_only_group_members(authed):
    authed["repo"].add(Device(name="labhost", host="10.0.0.50", groups=["lab"], is_self=True))
    page = authed["client"].get("/confirm/shutdown?target=lab").text
    m = re.search(r"Excluded[^<:]*:([^<.]*)\.", page)
    assert m, "no excluded list"
    excluded = [x.strip() for x in m.group(1).split(",")]
    assert excluded == ["labhost"]          # 'pi' is self but not in group lab
    page = authed["client"].get("/confirm/shutdown?target=all").text
    m = re.search(r"Excluded[^<:]*:([^<.]*)\.", page)
    assert sorted(x.strip() for x in m.group(1).split(",")) == ["labhost", "pi"]


def test_destructive_buttons_guard_double_submit(authed):
    c = authed["client"]
    for path in ("/", "/devices/pve1", "/confirm/shutdown?target=all", "/confirm/reboot?target=pi",
                 "/confirm/delete?target=pve1"):
        html = c.get(path).text
        buttons = re.findall(r"<button[^>]*hx-confirm=[^>]*>", html)
        assert buttons, path
        for b in buttons:
            assert 'hx-disabled-elt="this"' in b, (path, b)
            assert 'hx-sync="this:drop"' in b, (path, b)


def test_non_ascii_csrf_token_is_403_not_500(authed):
    c = authed["client"]
    r = c.post("/devices/pve1/wake", data={"csrf": "caf\u00e9-\u2603"})
    assert r.status_code == 403
    r = c.post("/devices/pve1/wake", headers={"X-CSRF-Token": "caf\u00e9".encode("latin-1")})
    assert r.status_code == 403
    assert authed["actions"].calls == []


def test_device_name_rules_apply_to_any_entry_path(authed):
    with pytest.raises(ValueError):
        authed["repo"].add(Device(name="all", host="h"))
    with pytest.raises(ValueError):
        Device(name="a/b", host="h")
    assert authed["repo"].get("all") is None


# ---- enable WoL (persistent) -------------------------------------------------------

def _fake_enable(authed):
    from wakeboard.actions import ActionResult, StageResult
    calls = []

    async def fake(runner, d, preset):
        calls.append((d.name, preset))
        return ActionResult(True, [StageResult("detect", True, "x"), StageResult("verify", True, "g")]), None
    authed["svc"]._enable_wol = fake
    return calls


def test_enable_wol_requires_auth_and_csrf(env):
    r = env["client"].post("/devices/pve1/enable-wol", data={}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_enable_wol_csrf_missing_is_403(authed):
    calls = _fake_enable(authed)
    r = authed["client"].post("/devices/pve1/enable-wol", data={"confirm": "1", "preset": "auto"})
    assert r.status_code == 403 and calls == []


def test_enable_wol_device_page_has_form(authed):
    page = authed["client"].get("/devices/pve1").text
    assert 'action="/devices/pve1/enable-wol"' in page and 'name="preset"' in page
    assert 'value="systemd-unit"' in page and "Enable WoL (persistent)" in page


def test_enable_wol_no_js_goes_through_confirm_page(authed):
    calls = _fake_enable(authed)
    r = post(authed, "/devices/pve1/enable-wol", {"preset": "ifupdown"}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/confirm/enable-wol?target=pve1&preset=ifupdown" and calls == []
    page = authed["client"].get(r.headers["location"])
    assert page.status_code == 200 and 'name="preset" value="ifupdown"' in page.text
    assert 'name="confirm" value="1"' in page.text
    r = post(authed, "/devices/pve1/enable-wol", {"confirm": "1", "preset": "ifupdown"})
    assert r.status_code == 200 and calls == [("pve1", "ifupdown")]
    rows = authed["audit"].list()
    assert any(x["action"] == "enable_wol" and "preset=ifupdown" in x["result"] for x in rows)


def test_enable_wol_invalid_preset_rejected(authed):
    calls = _fake_enable(authed)
    for data in ({"preset": "bogus; reboot", "confirm": "1"}, {"preset": "bogus"}):
        r = post(authed, "/devices/pve1/enable-wol", data, follow_redirects=False)
        assert r.status_code == 400
    assert authed["client"].get("/confirm/enable-wol?target=pve1&preset=bogus").status_code == 400
    assert calls == []


def test_enable_wol_confirm_rejects_groups_and_unknown(authed):
    c = authed["client"]
    assert c.get("/confirm/enable-wol?target=lab").status_code == 404
    assert c.get("/confirm/enable-wol?target=nope").status_code == 404


def test_form_lists_all_types_and_wol_methods(authed):
    from wakeboard.devices import VALID_TYPES
    from wakeboard.wolenable import PRESETS
    for url in ("/devices/new", "/devices/pve1/edit"):
        page = authed["client"].get(url).text
        for t in VALID_TYPES:
            assert f'<option value="{t}"' in page
        assert 'name="wol_method"' in page
        for k in PRESETS:
            assert f'<option value="{k}"' in page


def test_add_windows_device_with_wol_method(authed):
    r = post(authed, "/devices/new", {"name": "winbox", "host": "10.0.0.30", "ssh_user": "admin",
                                      "ssh_port": "22", "type": "windows", "wol_method": "windows"},
             follow_redirects=False)
    assert r.status_code == 303
    d = authed["repo"].get("winbox")
    assert d.type == "windows" and d.wol_method == "windows" and d.shutdown_mode == "plain"
    page = authed["client"].get("/devices/winbox").text
    assert 'value="windows" selected' in page


def test_edit_keeps_and_changes_wol_method(authed):
    r = post(authed, "/devices/pve2/edit", {"name": "pve2", "host": "10.0.0.2", "ssh_user": "root",
                                            "ssh_port": "22", "type": "linux", "wol_method": "ifupdown"},
             follow_redirects=False)
    assert r.status_code == 303 and authed["repo"].get("pve2").wol_method == "ifupdown"
    assert 'value="ifupdown" selected' in authed["client"].get("/devices/pve2/edit").text


def test_enable_wol_defaults_to_saved_method(authed):
    calls = _fake_enable(authed)
    d = authed["repo"].get("pve1"); d.wol_method = "ifupdown"; authed["repo"].update(d)
    r = post(authed, "/devices/pve1/enable-wol", {"confirm": "1"})
    assert r.status_code == 200 and calls == [("pve1", "ifupdown")]
