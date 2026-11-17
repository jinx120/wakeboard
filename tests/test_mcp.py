"""MCP server over a real Service + tmp sqlite, driven by the real MCP client
in-process (httpx2 ASGI transport -> FastAPI app -> /mcp). Fake actions/runner/prober."""
import asyncio
import contextlib
import json
import logging

import httpx2
import pytest
from fastapi import FastAPI
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from wakeboard.audit import AuditLog
from wakeboard.auth import AuthStore
from wakeboard.config import Settings
from wakeboard.devices import Device, DeviceRepo
from wakeboard.mcp_server import build_mcp
from wakeboard.service import Service
from wakeboard.status import Info

from test_service import FakeActions, FakeProber, FakeRunner

INFO = Info(uptime_s=42, load1=0.1, mem_used_pct=5.0, disk_root_pct=7.0, cpu_temp_c=40.0,
            kernel="6.8", pve_version="8.2", vms_running=1, cts_running=0, fetched_at=1.0)

TOOLS = {"list_devices", "device_status", "wake", "shutdown", "reboot", "wake_check", "run_command"}
BASE = "http://wakeboard.lan:8080"


@pytest.fixture
async def env(conn):
    repo = DeviceRepo(conn)
    repo.add(Device(name="pve1", host="10.0.0.1", type="proxmox", groups=["lab"], mac="aa:bb:cc:00:00:01"))
    repo.add(Device(name="pve2", host="10.0.0.2", groups=["lab"], mac="aa:bb:cc:00:00:02",
                    allow_run_command=True))
    repo.add(Device(name="pi", host="10.0.0.9", is_self=True))
    audit = AuditLog(conn)
    auth = AuthStore(conn)
    token = auth.rotate_token()
    actions, runner = FakeActions(), FakeRunner()

    async def collect(r, d):
        return INFO
    svc = Service(repo, audit, actions, runner, FakeProber(), {},
                  local_ips=lambda: {"127.0.0.1"}, resolve=lambda h: set(), collect_info=collect)
    app = FastAPI()
    mcp_app = build_mcp(svc, auth)
    from wakeboard.main import mount_mcp
    mount_mcp(app, mcp_app)
    async with running(mcp_app.session_manager.run()):
        yield {"app": app, "token": token, "actions": actions, "runner": runner,
               "audit": audit, "svc": svc}


@contextlib.asynccontextmanager
async def running(cm):
    """Enter an anyio-task-group context manager in ONE dedicated task, so a
    pytest-asyncio fixture's setup and teardown (different tasks) can host it."""
    started, stop = asyncio.Event(), asyncio.Event()

    async def host():
        async with cm:
            started.set()
            await stop.wait()
    task = asyncio.create_task(host())
    await asyncio.wait({task, asyncio.ensure_future(started.wait())},
                       return_when=asyncio.FIRST_COMPLETED)
    if task.done():
        task.result()
    try:
        yield
    finally:
        stop.set()
        await task


def _http(app, headers=None):
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=BASE,
                              headers=headers or {})


@contextlib.asynccontextmanager
async def mcp_client(env, token=None):
    token = env["token"] if token is None else token
    async with _http(env["app"], {"Authorization": f"Bearer {token}"}) as http:
        async with Client(streamable_http_client(f"{BASE}/mcp", http_client=http)) as c:
            yield c


def text(result) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "0"}}}
ACCEPT = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


# ---- tests ---------------------------------------------------------------------

async def test_tools_listed(env):
    async with mcp_client(env) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    assert set(tools) == TOOLS
    sd = tools["shutdown"]
    assert sd.input_schema["properties"]["confirm"]["type"] == "boolean"
    assert set(sd.input_schema["required"]) == {"target"}
    assert set(tools["reboot"].input_schema["required"]) == {"target"}
    assert set(tools["run_command"].input_schema["required"]) == {"target", "cmd"}
    for name in ("shutdown", "reboot"):
        d = tools[name].description.lower()
        assert "confirm=true" in d and "ask" in d and "all" in d and "self" in d
    assert "allow" in tools["run_command"].description.lower()


async def test_mcp_rejects_missing_token(env):
    async with _http(env["app"]) as http:
        missing = await http.post("/mcp", json=INIT, headers=ACCEPT)
        wrong = await http.post("/mcp", json=INIT, headers={**ACCEPT, "Authorization": "Bearer nope"})
        basic = await http.post("/mcp", json=INIT,
                                headers={**ACCEPT, "Authorization": "Basic Zm9vOmJhcg=="})
        empty = await http.post("/mcp", json=INIT, headers={**ACCEPT, "Authorization": "Bearer "})
        get = await http.get("/mcp", headers={"Accept": "text/event-stream"})
        sub = await http.post("/mcp/", json=INIT, headers=ACCEPT)
    for r in (missing, wrong, basic, empty, get, sub):
        assert r.status_code == 401, r
        assert r.headers["www-authenticate"] == "Bearer"
        assert r.headers["content-type"].startswith("application/json")
        assert r.json() == missing.json() == {"detail": "unauthorized"}
        assert "mcp-session-id" not in r.headers
    # The real client with a bad token cannot even initialize.
    with pytest.raises(BaseException):
        async with mcp_client(env, token="wrong-token") as c:
            await c.list_tools()
    assert env["actions"].calls == [] and env["audit"].list() == []


async def test_mcp_valid_token_initializes(env):
    async with _http(env["app"]) as http:
        r = await http.post("/mcp", json=INIT,
                            headers={**ACCEPT, "Authorization": f"Bearer {env['token']}"})
    assert r.status_code == 200


async def test_shutdown_all_without_confirm_is_tool_error(env):
    async with mcp_client(env) as c:
        r = await c.call_tool("shutdown", {"target": "all"})
        assert r.is_error and "confirm=true" in text(r) and "pve1" in text(r)
        r = await c.call_tool("reboot", {"target": "lab", "confirm": False})
        assert r.is_error and "confirm=true" in text(r)
        r = await c.call_tool("reboot", {"target": "pi"})
        assert r.is_error and "WARNING" in text(r)
    assert env["actions"].calls == []


@pytest.mark.parametrize("bad", ["false", "true", "True", 1, "1", "yes"])
async def test_confirm_string_is_never_confirmation(env, bad):
    async with mcp_client(env) as c:
        r = await c.call_tool("shutdown", {"target": "all", "confirm": bad})
        assert r.is_error
        r = await c.call_tool("reboot", {"target": "all", "confirm": bad})
        assert r.is_error
    assert env["actions"].calls == []


async def test_confirm_reaches_service_unmodified(env, monkeypatch):
    seen = []
    real = env["svc"].shutdown

    async def spy(target, caller, mode=None, confirm=False):
        seen.append((target, caller, mode, confirm))
        return await real(target, caller, mode=mode, confirm=confirm)
    monkeypatch.setattr(env["svc"], "shutdown", spy)
    async with mcp_client(env) as c:
        r = await c.call_tool("shutdown", {"target": "all", "confirm": True, "mode": "plain"})
    assert not r.is_error, text(r)
    assert seen == [("all", "mcp", "plain", True)]
    assert seen[0][3] is True
    assert sorted(n for _, n, _ in env["actions"].calls) == ["pve1", "pve2"]  # pi (self) excluded
    body = json.loads(text(r))
    assert set(body) == {"pve1", "pve2"} and body["pve1"]["ok"] is True


async def test_shutdown_all_confirmed_and_caller_is_mcp(env):
    async with mcp_client(env) as c:
        r = await c.call_tool("reboot", {"target": "pve1"})
        assert not r.is_error
        r = await c.call_tool("wake", {"target": "lab"})
        assert not r.is_error
    callers = {row["caller"] for row in env["audit"].list()}
    assert callers == {"mcp"}


async def test_wake_unknown_target_tool_error(env):
    async with mcp_client(env) as c:
        r = await c.call_tool("wake", {"target": "nope"})
        assert r.is_error and "UnknownTarget" in text(r) and "nope" in text(r)
        r = await c.call_tool("device_status", {"target": "nope"})
        assert r.is_error and "UnknownTarget" in text(r)
    assert env["actions"].calls == []


async def test_run_command_disabled_tool_error(env):
    async with mcp_client(env) as c:
        r = await c.call_tool("run_command", {"target": "pve1", "cmd": "uptime"})
        assert r.is_error and "disabled" in text(r)
        r = await c.call_tool("run_command", {"target": "pi", "cmd": "uptime"})
        assert r.is_error and "refused" in text(r)
        r = await c.call_tool("run_command", {"target": "pve2", "cmd": "uptime"})
        assert not r.is_error and json.loads(text(r))["stdout"] == "hello\n"
    assert env["runner"].calls == [("pve2", "uptime")]


async def test_bad_mode_and_no_devices_are_tool_errors(env):
    async with mcp_client(env) as c:
        r = await c.call_tool("shutdown", {"target": "pve1", "mode": "explode"})
        assert r.is_error
        r = await c.call_tool("wake", {"target": "emptygroup"})
        assert r.is_error
    assert env["actions"].calls == []


async def test_audit_unavailable_is_tool_error(env):
    def boom(*a):
        raise RuntimeError("database is locked")
    env["audit"].record = boom
    async with mcp_client(env) as c:
        r = await c.call_tool("shutdown", {"target": "pve1"})
    assert r.is_error and "audit log unavailable" in text(r)
    assert env["actions"].calls == []


async def test_unexpected_error_is_generic(env, monkeypatch, caplog):
    async def boom(*a, **k):
        raise RuntimeError("secret-path /data/keys/id_ed25519 leaked")
    monkeypatch.setattr(env["svc"], "list_devices", boom)
    with caplog.at_level(logging.ERROR, logger="wakeboard.mcp_server"):
        async with mcp_client(env) as c:
            r = await c.call_tool("list_devices", {})
    assert r.is_error and text(r).endswith(": internal error")  # SDK prefixes the tool name
    assert "secret" not in text(r) and "Traceback" not in text(r)
    assert any("secret-path" in (rec.exc_text or str(rec.exc_info)) for rec in caplog.records)


async def test_read_tools_and_wake_check(env):
    async with mcp_client(env) as c:
        devs = json.loads(text(await c.call_tool("list_devices", {})))
        assert {d["name"] for d in devs} == {"pve1", "pve2", "pi"}
        st = json.loads(text(await c.call_tool("device_status", {"target": "pve1"})))
        assert st["pve1"]["status"] == "up"
        r = await c.call_tool("wake_check", {"target": "pve1"})
        assert not r.is_error  # per-device failure is a result, not a tool error


async def test_create_app_mounts_mcp_with_lifespan(tmp_path):
    from wakeboard import main

    class P:
        async def is_up(self, d):
            return False
    app = main.create_app(Settings(data_dir=tmp_path, poll_interval=3600), prober=P())
    token = app.state.auth.rotate_token()
    async with app.router.lifespan_context(app):
        async with _http(app) as http:
            r = await http.post("/mcp", json=INIT, headers=ACCEPT)
            assert r.status_code == 401
        async with _http(app, {"Authorization": f"Bearer {token}"}) as http:
            async with Client(streamable_http_client(f"{BASE}/mcp", http_client=http)) as c:
                assert {t.name for t in (await c.list_tools()).tools} == TOOLS
