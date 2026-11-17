"""Application wiring: create_app(settings) -> FastAPI."""
import asyncio
import contextlib
import logging
import os
import threading

from fastapi import FastAPI
from starlette.routing import Route

from wakeboard.actions import Actions
from wakeboard.api import build_api_router
from wakeboard.audit import AuditLog
from wakeboard.auth import AuthStore
from wakeboard.config import Settings
from wakeboard.db import connect
from wakeboard.mcp_server import build_mcp
from wakeboard.devices import DeviceRepo
from wakeboard.service import HostKeyAckRunner, LockedAudit, LockedRepo, Service
from wakeboard.ssh import SshRunner
from wakeboard.sshkeys import KeyStore
from wakeboard.status import Poller, Prober
from wakeboard.web.routes import mount_web

log = logging.getLogger(__name__)


def mount_mcp(app: FastAPI, mcp_app) -> None:
    """Serve the (already authenticated) MCP ASGI app at exactly /mcp (and /mcp/),
    with no redirect. Its session manager is run by create_app's lifespan."""
    for path in ("/mcp", "/mcp/"):
        app.router.routes.append(Route(path, endpoint=mcp_app))
    app.state.mcp = mcp_app


def mount_extras(app: FastAPI, service: Service, auth: AuthStore) -> None:
    """Plug-in point for the MCP server (/mcp) and the web UI."""
    mount_mcp(app, build_mcp(service, auth))
    mount_web(app, service, auth, keystore=app.state.keystore, runner=app.state.runner,
              settings=app.state.settings)


def create_app(settings: Settings | None = None, *, prober=None, poller: Poller | None = None,
               **service_kw) -> FastAPI:
    settings = settings or Settings.from_env()
    conn = connect(settings.data_dir / "wakeboard.db")

    # One lock serializes every write on the shared connection (repo, audit, auth),
    # so one thread's rollback can never discard another's uncommitted write.
    db_lock = threading.RLock()
    auth = AuthStore(conn, lock=db_lock)
    pw = os.environ.get("WAKEBOARD_PASSWORD")
    if pw and not auth.password_set():
        auth.set_password(pw)

    repo = LockedRepo(DeviceRepo(conn), db_lock)
    audit = LockedAudit(AuditLog(conn), db_lock)
    keystore = KeyStore(settings.data_dir)
    keystore.ensure_global()
    runner = HostKeyAckRunner(SshRunner(keystore, settings.data_dir / "known_hosts"), repo)
    prober = prober or Prober()
    actions = Actions(runner, prober, settings)  # the ONE shared instance (per-device locks)
    state: dict[str, bool] = {}
    service = Service(repo, audit, actions, runner, prober, state, lock=db_lock, **service_kw)
    poller = poller or Poller()

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        task = asyncio.create_task(poller.run(repo, prober, state, settings.poll_interval))
        app.state.poller_task = task
        try:
            mcp_app = getattr(app.state, "mcp", None)
            async with (mcp_app.session_manager.run() if mcp_app is not None
                        else contextlib.nullcontext()):
                yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    # No docs/OpenAPI routes: /healthz is the only unauthenticated endpoint.
    app = FastAPI(title="Wakeboard", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.service = service
    app.state.auth = auth
    app.state.repo = repo
    app.state.audit = audit
    app.state.keystore = keystore
    app.state.runner = runner
    app.state.actions = actions
    app.state.state = state

    @app.get("/healthz")
    async def healthz():
        return {"ok": True}

    app.include_router(build_api_router(service, auth))
    # MCP (/mcp) and web UI routers plug in here.
    mount_extras(app, service, auth)
    return app


_app: FastAPI | None = None


def __getattr__(name: str):
    # `uvicorn wakeboard.main:app` builds the app lazily, so importing this module
    # (e.g. in tests) never touches /data.
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
