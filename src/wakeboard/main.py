"""Application wiring: create_app(settings) -> FastAPI."""
import asyncio
import contextlib
import logging
import os
import threading

from fastapi import FastAPI

from wakeboard.actions import Actions
from wakeboard.api import build_api_router
from wakeboard.audit import AuditLog
from wakeboard.auth import AuthStore
from wakeboard.config import Settings
from wakeboard.db import connect
from wakeboard.devices import DeviceRepo
from wakeboard.service import HostKeyAckRunner, LockedAudit, LockedRepo, Service
from wakeboard.ssh import SshRunner
from wakeboard.sshkeys import KeyStore
from wakeboard.status import Poller, Prober

log = logging.getLogger(__name__)


def mount_extras(app: FastAPI, service: Service, auth: AuthStore) -> None:
    """Hook for the MCP server (Task 10, mounted at /mcp) and the web UI router
    (Task 11). No-op until those exist."""


def create_app(settings: Settings | None = None, *, prober=None, poller: Poller | None = None,
               **service_kw) -> FastAPI:
    settings = settings or Settings.from_env()
    conn = connect(settings.data_dir / "wakeboard.db")

    # One lock serializes every write on the shared connection (repo, audit, auth),
    # so one thread's rollback can never discard another's uncommitted write.
    db_lock = threading.RLock()
    auth = AuthStore(conn)
    auth._lock = db_lock  # share the write lock (RLock: auth methods nest _set under it)
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
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="Wakeboard", lifespan=lifespan)
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
