"""SSH command runner with trust-on-first-use host keys and password enrollment."""
import asyncio
import os
from dataclasses import dataclass
from pathlib import Path

import asyncssh

from wakeboard.devices import Device
from wakeboard.sshkeys import KeyStore


class HostKeyChanged(Exception):
    pass


class SudoRequired(Exception):
    pass


class EnrollmentFailed(Exception):
    pass


@dataclass
class RunResult:
    stdout: str
    stderr: str
    exit: int


def _entry(host: str, port: int) -> str:
    return f"[{host}]:{port}"


def _decode(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="replace")
    return v


class _TofuClient(asyncssh.SSHClient):
    """Called by asyncssh only when the presented key is not in the trusted set.

    No pin  -> accept and remember the key (first use).
    Pin     -> mismatch: reject (recorded so the caller raises HostKeyChanged),
               unless the device acknowledged the change.
    """

    def __init__(self, pinned: bool, allow_change: bool):
        self.pinned = pinned
        self.allow_change = allow_change
        self.seen_key: asyncssh.SSHKey | None = None
        self.mismatch = False

    def validate_host_public_key(self, host, addr, port, key):
        if not self.pinned or self.allow_change:
            self.seen_key = key
            return True
        self.mismatch = True
        self.seen_key = key
        return False


class SshRunner:
    def __init__(self, keystore: KeyStore, known_hosts: Path):
        self.keystore = keystore
        self.known_hosts = Path(known_hosts)

    # ---- known_hosts file ------------------------------------------------

    def _read_lines(self) -> list[str]:
        if not self.known_hosts.exists():
            return []
        return [ln for ln in self.known_hosts.read_text().splitlines() if ln.strip()]

    def _write_lines(self, lines: list[str]) -> None:
        self.known_hosts.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.known_hosts.with_name(self.known_hosts.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, "".join(ln + "\n" for ln in lines).encode())
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        os.replace(tmp, self.known_hosts)

    def _pinned(self, device: Device) -> list[asyncssh.SSHKey]:
        entry = _entry(device.host, device.ssh_port)
        keys = []
        for ln in self._read_lines():
            parts = ln.split(None, 1)
            if len(parts) == 2 and parts[0] == entry:
                try:
                    keys.append(asyncssh.import_public_key(parts[1]))
                except (asyncssh.KeyImportError, ValueError):
                    continue
        return keys

    def _pin(self, device: Device, key: asyncssh.SSHKey) -> None:
        entry = _entry(device.host, device.ssh_port)
        lines = [ln for ln in self._read_lines() if ln.split(None, 1)[0] != entry]
        lines.append(f"{entry} {key.export_public_key().decode().strip()}")
        self._write_lines(lines)

    def acknowledge_host_key(self, device: Device) -> None:
        """Forget the pinned key for this device so the next connect re-pins."""
        entry = _entry(device.host, device.ssh_port)
        lines = self._read_lines()
        kept = [ln for ln in lines if ln.split(None, 1)[0] != entry]
        if kept != lines:
            self._write_lines(kept)

    # ---- connections -----------------------------------------------------

    async def _connect(self, device: Device, **auth) -> tuple[asyncssh.SSHClientConnection, _TofuClient]:
        pinned = self._pinned(device)
        client = _TofuClient(pinned=bool(pinned), allow_change=device.host_key_ack)
        try:
            conn = await asyncssh.connect(
                device.host, port=device.ssh_port, username=device.ssh_user,
                known_hosts=(pinned, [], []), client_factory=lambda: client,
                agent_path=None, config=None, **auth)
        except asyncssh.HostKeyNotVerifiable as e:
            if client.mismatch:
                raise HostKeyChanged(
                    f"host key for {_entry(device.host, device.ssh_port)} changed "
                    f"(now {client.seen_key.get_fingerprint()}); acknowledge to re-pin") from None
            raise
        if client.seen_key is not None:
            self._pin(device, client.seen_key)
        return conn, client

    def _key_auth(self, device: Device) -> dict:
        return {"client_keys": [self.keystore.load_private(device.key_id)],
                "password": None, "kbdint_auth": False, "preferred_auth": "publickey"}

    async def run(self, device: Device, cmd: str, timeout: float = 30) -> RunResult:
        async def _go() -> RunResult:
            conn, _ = await self._connect(device, **self._key_auth(device))
            async with conn:
                r = await conn.run(cmd, check=False, encoding=None)
            return RunResult(stdout=_decode(r.stdout), stderr=_decode(r.stderr),
                             exit=r.exit_status if r.exit_status is not None else -1)
        return await asyncio.wait_for(_go(), timeout)

    async def enroll_with_password(self, device: Device, password: str, timeout: float = 30) -> None:
        """Connect once with the password and install the public key (idempotent).

        The password is passed straight to asyncssh and is never stored, logged or
        put in an exception message; auth errors are re-raised without context.
        """
        cmd = self.keystore.authorize_command(device.key_id)

        async def _go():
            try:
                conn, _ = await self._connect(
                    device, password=password, client_keys=None,
                    kbdint_auth=False, preferred_auth="password")
            except asyncssh.PermissionDenied:
                raise EnrollmentFailed(
                    f"password authentication failed for {device.ssh_user}@{device.host}") from None
            async with conn:
                r = await conn.run(cmd, check=False, encoding=None)
            if r.exit_status != 0:
                raise EnrollmentFailed(
                    f"installing key failed (exit {r.exit_status}): {_decode(r.stderr).strip()[:200]}")

        try:
            await asyncio.wait_for(_go(), timeout)
        finally:
            password = None  # noqa: F841 - drop our reference promptly

    async def sudo_ok(self, device: Device) -> bool:
        if device.ssh_user == "root":
            return True
        r = await self.run(device, "sudo -n true")
        return r.exit == 0
