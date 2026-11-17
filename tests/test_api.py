"""REST API over a real Service + tmp sqlite, with fake actions/runner/prober."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from wakeboard.api import build_api_router, client_ip
from wakeboard.audit import AuditLog
from wakeboard.auth import AuthStore
from wakeboard.config import Settings
from wakeboard.devices import Device, DeviceRepo
from wakeboard.service import Service
from wakeboard.status import Info

from test_service import FakeActions, FakeProber, FakeRunner

INFO = Info(uptime_s=42, load1=0.1, mem_used_pct=5.0, disk_root_pct=7.0, cpu_temp_c=40.0,
            kernel="6.8", pve_version="8.2", vms_running=1, cts_running=0, fetched_at=1.0)


@pytest.fixture
def env(conn):
    repo = DeviceRepo(conn)
    repo.add(Device(name="pve1", host="10.0.0.1", type="proxmox", groups=["lab"], mac="aa:bb:cc:00:00:01"))
    repo.add(Device(name="pve2", host="10.0.0.2", groups=["lab"], mac="aa:bb:cc:00:00:02"))
    repo.add(Device(name="pi", host="10.0.0.9", is_self=True))
    audit = AuditLog(conn)
    auth = AuthStore(conn)
    token = auth.rotate_token()
    actions = FakeActions()

    async def collect(r, d):
        return INFO
    svc = Service(repo, audit, actions, FakeRunner(), FakeProber(), {},
                  local_ips=lambda: {"127.0.0.1"}, resolve=lambda h: set(), collect_info=collect)
    app = FastAPI()
    app.include_router(build_api_router(svc, auth))
    client = TestClient(app)
    return {"client": client, "token": token, "actions": actions, "audit": audit, "repo": repo}


def H(token):
    return {"Authorization": f"Bearer {token}"}


def test_api_requires_token(env):
    c = env["client"]
    missing = c.get("/api/v1/devices")
    wrong = c.get("/api/v1/devices", headers=H("not-the-token"))
    basic = c.get("/api/v1/devices", headers={"Authorization": "Basic Zm9vOmJhcg=="})
    assert missing.status_code == wrong.status_code == basic.status_code == 401
    assert missing.json() == wrong.json() == basic.json()
    assert missing.headers.get("www-authenticate") == wrong.headers.get("www-authenticate")
    r = c.post("/api/v1/shutdown", json={"target": "pve1"})
    assert r.status_code == 401 and env["actions"].calls == []
    assert c.get("/api/v1/devices", headers=H(env["token"])).status_code == 200


def test_api_confirm_required_returns_409(env):
    c, t = env["client"], env["token"]
    r = c.post("/api/v1/shutdown", json={"target": "all"}, headers=H(t))
    assert r.status_code == 409 and "pve1" in r.json()["detail"]
    r = c.post("/api/v1/reboot", json={"target": "pi"}, headers=H(t))
    assert r.status_code == 409 and "WARNING" in r.json()["detail"]
    assert env["actions"].calls == []
    r = c.post("/api/v1/shutdown", json={"target": "all", "confirm": True}, headers=H(t))
    assert r.status_code == 200 and set(r.json()) == {"pve1", "pve2"}
    callers = {row["caller"] for row in env["audit"].list()}
    assert callers == {"api"}


def test_api_unknown_target_404(env):
    c, t = env["client"], env["token"]
    assert c.post("/api/v1/wake", json={"target": "nope"}, headers=H(t)).status_code == 404
    assert c.get("/api/v1/devices/nope/status", headers=H(t)).status_code == 404
    assert c.post("/api/v1/shutdown", json={"target": "nope"}, headers=H(t)).status_code == 404


def test_api_status_ok(env):
    c, t = env["client"], env["token"]
    r = c.get("/api/v1/devices/pve1/status", headers=H(t))
    assert r.status_code == 200
    body = r.json()["pve1"]
    assert body["status"] == "up" and body["info"]["pve_version"] == "8.2"
    devs = c.get("/api/v1/devices", headers=H(t)).json()
    assert {d["name"] for d in devs} == {"pve1", "pve2", "pi"}


def test_api_run_command_disabled_403_and_bad_bodies_422(env):
    c, t = env["client"], env["token"]
    r = c.post("/api/v1/run_command", json={"target": "pve1", "cmd": "uptime"}, headers=H(t))
    assert r.status_code == 403
    assert c.post("/api/v1/run_command", json={"target": "pve1"}, headers=H(t)).status_code == 422
    assert c.post("/api/v1/run_command", json={"target": "lab", "cmd": "x"}, headers=H(t)).status_code == 422
    assert c.post("/api/v1/wake", json={}, headers=H(t)).status_code == 422
    assert c.post("/api/v1/shutdown", json={"target": "pve1", "mode": "bogus"},
                  headers=H(t)).status_code == 422
    assert c.post("/api/v1/shutdown", json={"target": "all", "confirm": "yes"},
                  headers=H(t)).status_code == 422
    assert env["actions"].calls == []


def test_api_wake_and_run_command_ok(env):
    c, t = env["client"], env["token"]
    r = c.post("/api/v1/wake", json={"target": "lab"}, headers=H(t))
    assert r.status_code == 200 and r.json()["pve1"]["ok"] is True
    d = env["repo"].get("pve1")
    d.allow_run_command = True
    env["repo"].update(d)
    r = c.post("/api/v1/run_command", json={"target": "pve1", "cmd": "uptime"}, headers=H(t))
    assert r.status_code == 200 and r.json()["stdout"] == "hello\n" and r.json()["exit"] == 0


def test_client_ip_ignores_forwarded_headers():
    class Req:
        class client:
            host = "192.168.1.20"
        headers = {"x-forwarded-for": "1.2.3.4"}
    assert client_ip(Req()) == "192.168.1.20"

    class NoClient:
        client = None
        headers = {"x-forwarded-for": "1.2.3.4"}
    assert client_ip(NoClient()) == "unknown"


# ---- main.create_app ---------------------------------------------------------------

def test_create_app_wires_everything(tmp_path, monkeypatch):
    from wakeboard import main
    monkeypatch.setenv("WAKEBOARD_PASSWORD", "hunter2-long")
    probes = []

    class P:
        async def is_up(self, d):
            probes.append(d.name)
            return True
    app = main.create_app(Settings(data_dir=tmp_path, poll_interval=3600), prober=P())
    for attr in ("service", "auth", "repo", "audit", "keystore", "runner"):
        assert getattr(app.state, attr) is not None
    assert app.state.auth.check_password("hunter2-long", "127.0.0.1")
    assert (tmp_path / "keys" / "id_ed25519").exists()
    with TestClient(app) as c:
        assert c.get("/healthz").json() == {"ok": True}
        assert c.get("/api/v1/devices").status_code == 401
        task = app.state.poller_task
        assert not task.done()
    assert task.cancelled() or task.done()


def test_create_app_env_password_only_applied_when_unset(tmp_path, monkeypatch):
    from wakeboard import main
    monkeypatch.setenv("WAKEBOARD_PASSWORD", "first-password")
    main.create_app(Settings(data_dir=tmp_path))
    monkeypatch.setenv("WAKEBOARD_PASSWORD", "second-password")
    app = main.create_app(Settings(data_dir=tmp_path))
    assert app.state.auth.check_password("first-password", "127.0.0.1")


def test_docs_and_openapi_disabled(tmp_path):
    from wakeboard import main
    app = main.create_app(Settings(data_dir=tmp_path))
    c = TestClient(app)
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert c.get(path).status_code == 404


def test_api_mode_literal_matches_device_modes():
    import typing
    from wakeboard.api import ShutdownBody
    from wakeboard.devices import VALID_SHUTDOWN_MODES
    ann = ShutdownBody.model_fields["mode"].annotation
    lit = next(a for a in typing.get_args(ann) if a is not type(None))
    assert set(typing.get_args(lit)) == VALID_SHUTDOWN_MODES


def test_auth_store_uses_injected_lock(conn):
    import threading

    class Spy:
        def __init__(self):
            self.inner, self.n = threading.RLock(), 0

        def __enter__(self):
            self.n += 1
            return self.inner.__enter__()

        def __exit__(self, *a):
            return self.inner.__exit__(*a)
    spy = Spy()
    store = AuthStore(conn, lock=spy)
    store.rotate_token()
    assert spy.n == 1
    store.new_session()          # first session-secret write
    assert spy.n == 2
    store.new_session()          # secret exists: no write, no lock
    assert spy.n == 2
    store.set_password("pw-long-enough")
    assert spy.n == 3
    assert isinstance(AuthStore(conn)._lock, type(threading.Lock()))


def test_create_app_shares_db_lock_with_auth(tmp_path):
    from wakeboard import main
    app = main.create_app(Settings(data_dir=tmp_path))
    assert app.state.auth._lock is app.state.service.lock is app.state.repo.lock
