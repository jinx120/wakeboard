"""MCP server (/mcp, streamable HTTP): a thin bearer-token adapter over Service.

Every request is authenticated by `BearerAuthApp` BEFORE the MCP SDK sees it
(initialize included). Tools are thin calls into Service, which owns the safety
rules; Service errors become MCP tool errors (is_error) carrying the message so
the model can read why, and anything unexpected becomes a generic
"internal error" (logged server-side with its traceback).
"""
import json
import logging
from typing import Annotated, Literal

from pydantic import Field, StrictBool
from starlette.responses import JSONResponse

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings

from wakeboard.devices import VALID_SHUTDOWN_MODES
from wakeboard.service import (AuditUnavailable, ConfirmationRequired, InvalidRequest,
                               RunCommandDisabled, Service)
from wakeboard.targets import NoDevices, UnknownTarget

log = logging.getLogger(__name__)

CALLER = "mcp"

ShutdownMode = Literal[tuple(sorted(VALID_SHUTDOWN_MODES))]  # single source of truth
Target = Annotated[str, Field(min_length=1, max_length=200,
                              description="A device name, a group name, or 'all'.")]
DeviceName = Annotated[str, Field(min_length=1, max_length=200, description="A single device name.")]
Confirm = Annotated[StrictBool, Field(
    description="Must be the JSON boolean true to act on a group, 'all', or a self device. "
                "Only set it after the human has explicitly agreed.")]

_SAFETY = (
    "Safety rules: when the target is a group or 'all', this refuses unless confirm=true; "
    "the refusal lists the affected devices. Before re-sending with confirm=true, show the "
    "human that list and ask them to confirm; never set confirm=true on your own. "
    "Self devices (the machine Wakeboard runs on, or the host it runs inside) are always "
    "excluded from groups and 'all'; naming a self device directly also needs confirm=true "
    "and will take Wakeboard itself offline, so ask the human first."
)

INSTRUCTIONS = (
    "Wakeboard controls power for homelab machines: list them, check status, wake (Wake-on-LAN), "
    "shut down and reboot them, check Wake-on-LAN readiness, and run commands on devices that "
    "allow it. " + _SAFETY
)

_UNAUTHORIZED_BODY = {"detail": "unauthorized"}


def _dump(obj) -> str:
    return json.dumps(obj, indent=2, default=str)


async def _call(coro) -> str:
    try:
        return _dump(await coro)
    except ConfirmationRequired as e:          # includes SelfTargetRefused
        raise ToolError(str(e)) from None
    except (UnknownTarget, NoDevices) as e:
        raise ToolError(f"{type(e).__name__}: {e}") from None
    except (RunCommandDisabled, InvalidRequest, AuditUnavailable) as e:
        raise ToolError(str(e)) from None
    except Exception:
        log.exception("MCP tool failed unexpectedly")
        raise ToolError("internal error") from None


class BearerAuthApp:
    """ASGI wrapper: identical 401 for a missing, malformed or wrong token, checked
    before any MCP processing. Only then is the request handed to the SDK."""

    def __init__(self, server: MCPServer, auth):
        self.server = server
        self.auth = auth
        # Builds the session manager; we dispatch to it directly (no inner routing),
        # so the mount path is decided solely by the host app.
        server.streamable_http_app(
            # Bearer auth is mandatory, so DNS-rebinding Host/Origin pinning (which
            # would pin to localhost and break LAN clients) adds nothing here.
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
        self.session_manager = server.session_manager

    def _authorized(self, scope) -> bool:
        header = b""
        for k, v in scope.get("headers") or ():
            if k == b"authorization":
                header = v
                break
        try:
            value = header.decode("latin-1")
        except Exception:
            return False
        scheme, _, token = value.partition(" ")
        if scheme.lower() != "bearer":
            return False
        try:
            return bool(self.auth.check_token(token.strip() or None))
        except Exception:
            log.exception("token check failed")
            return False

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return  # websockets/lifespan never reach MCP through this mount
        if not self._authorized(scope):
            resp = JSONResponse(_UNAUTHORIZED_BODY, status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
            await resp(scope, receive, send)
            return
        await self.session_manager.handle_request(scope, receive, send)


def build_server(service: Service) -> MCPServer:
    mcp = MCPServer(name="wakeboard", instructions=INSTRUCTIONS)

    @mcp.tool(structured_output=False, description=(
        "List every configured device with its host, MAC, groups, type, whether it allows "
        "run_command, whether it is a self device, and its last known up/down state."))
    async def list_devices() -> str:
        return await _call(service.list_devices())

    @mcp.tool(structured_output=False, description=(
        "Probe a device, group, or 'all' right now and return up/down/unreachable plus "
        "system info (uptime, load, memory, disk, temperature, Proxmox VMs/CTs) for up devices."))
    async def device_status(target: Target) -> str:
        return await _call(service.device_status(target))

    @mcp.tool(structured_output=False, description=(
        "Send Wake-on-LAN to a device, group, or 'all' and wait for it to come up. Safe and "
        "needs no confirmation; self devices are excluded from groups and 'all'."))
    async def wake(target: Target) -> str:
        return await _call(service.wake(target, caller=CALLER))

    @mcp.tool(structured_output=False, description=(
        "Shut down a device, group, or 'all'. mode is 'plain' (OS shutdown) or "
        "'graceful-proxmox' (stop guests first); omit it to use the device's configured mode. "
        + _SAFETY))
    async def shutdown(target: Target, mode: ShutdownMode | None = None,
                       confirm: Confirm = False) -> str:
        # confirm is passed through untouched: Service accepts only `confirm is True`.
        return await _call(service.shutdown(target, caller=CALLER, mode=mode, confirm=confirm))

    @mcp.tool(structured_output=False, description="Reboot a device, group, or 'all'. " + _SAFETY)
    async def reboot(target: Target, confirm: Confirm = False) -> str:
        return await _call(service.reboot(target, caller=CALLER, confirm=confirm))

    @mcp.tool(structured_output=False, description=(
        "Check over SSH whether Wake-on-LAN is enabled and persistent on a device, group, or "
        "'all'; adopts the NIC's MAC address if none is configured. Read-mostly, no confirmation."))
    async def wake_check(target: Target) -> str:
        return await _call(service.wake_check(target, caller=CALLER))

    @mcp.tool(structured_output=False, description=(
        "Run one shell command over SSH on a single named device and return stdout, stderr "
        "and the exit code. Only works on devices whose allow_run_command setting is true "
        "(see list_devices); it is refused otherwise, and always refused on self devices. "
        "Groups and 'all' are not accepted."))
    async def run_command(target: DeviceName,
                          cmd: Annotated[str, Field(min_length=1, max_length=4096)]) -> str:
        return await _call(service.run_command(target, cmd, caller=CALLER))

    return mcp


def build_mcp(service: Service, auth) -> BearerAuthApp:
    """The authenticated MCP ASGI app. Its `session_manager.run()` must be entered
    for the app's lifetime (main.create_app does this in its lifespan)."""
    return BearerAuthApp(build_server(service), auth)
