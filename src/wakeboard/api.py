"""REST API (/api/v1): a thin bearer-token adapter over Service."""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, StrictBool

from wakeboard.devices import VALID_SHUTDOWN_MODES
from wakeboard.service import (AuditUnavailable, ConfirmationRequired, InvalidRequest, RunCommandDisabled,
                               Service)
from wakeboard.targets import NoDevices, UnknownTarget

CALLER = "api"
_UNAUTHORIZED = HTTPException(status_code=401, detail="unauthorized",
                              headers={"WWW-Authenticate": "Bearer"})


def client_ip(request) -> str:
    """The trusted TCP peer address. Never X-Forwarded-For or other headers:
    those are client-controlled and would let a caller dodge the login lockout."""
    client = getattr(request, "client", None)
    return client.host if client and client.host else "unknown"


class TargetBody(BaseModel):
    target: str = Field(min_length=1, max_length=200)


class RebootBody(TargetBody):
    confirm: StrictBool = False


ShutdownMode = Literal[tuple(sorted(VALID_SHUTDOWN_MODES))]  # single source of truth


class ShutdownBody(RebootBody):
    mode: ShutdownMode | None = None


class RunCommandBody(TargetBody):
    cmd: str = Field(min_length=1, max_length=4096)


async def _call(coro):
    try:
        return await coro
    except ConfirmationRequired as e:   # includes SelfTargetRefused
        raise HTTPException(status_code=409, detail=str(e)) from None
    except (UnknownTarget, NoDevices) as e:
        raise HTTPException(status_code=404, detail=f"{type(e).__name__}: {e}") from None
    except RunCommandDisabled as e:
        raise HTTPException(status_code=403, detail=str(e)) from None
    except InvalidRequest as e:
        raise HTTPException(status_code=422, detail=str(e)) from None
    except AuditUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e)) from None


def build_api_router(service: Service, auth) -> APIRouter:
    async def require_token(request: Request) -> None:
        # Same response for a missing, malformed or wrong token.
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not auth.check_token(token.strip() or None):
            raise _UNAUTHORIZED

    r = APIRouter(prefix="/api/v1", dependencies=[Depends(require_token)])

    @r.get("/devices")
    async def devices():
        return await service.list_devices()

    @r.get("/devices/{target}/status")
    async def status(target: str):
        return await _call(service.device_status(target))

    @r.post("/wake")
    async def wake(body: TargetBody):
        return await _call(service.wake(body.target, caller=CALLER))

    @r.post("/shutdown")
    async def shutdown(body: ShutdownBody):
        return await _call(service.shutdown(body.target, caller=CALLER, mode=body.mode,
                                            confirm=body.confirm))

    @r.post("/reboot")
    async def reboot(body: RebootBody):
        return await _call(service.reboot(body.target, caller=CALLER, confirm=body.confirm))

    @r.post("/wake_check")
    async def wake_check(body: TargetBody):
        return await _call(service.wake_check(body.target, caller=CALLER))

    @r.post("/run_command")
    async def run_command(body: RunCommandBody):
        return await _call(service.run_command(body.target, body.cmd, caller=CALLER))

    return r
