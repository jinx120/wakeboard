import pytest

from wakeboard.config import Settings
from wakeboard.db import connect


@pytest.fixture
def settings(tmp_path):
    return Settings(data_dir=tmp_path)


@pytest.fixture
def conn(settings):
    c = connect(settings.data_dir / "wakeboard.db")
    yield c
    c.close()


# ---------------------------------------------------------------------------
# In-process asyncssh server fixture (127.0.0.1, ephemeral port, no real network)
# ---------------------------------------------------------------------------
import asyncio
import os
import subprocess
from dataclasses import dataclass, field as dc_field

import asyncssh


@dataclass
class Canned:
    stdout: bytes | str = b""
    stderr: bytes | str = b""
    exit: int = 0
    delay: float = 0.0


@dataclass
class FakeSshServer:
    """Controls for the in-process SSH server.

    - authorized_keys: set of OpenSSH public-key lines accepted for pubkey auth
      (keys found in ``home/.ssh/authorized_keys`` are also accepted).
    - password: accepted password (None disables password auth).
    - responses: exact command -> Canned.
    - shell_allowlist: exact command strings that are really executed via
      ``bash -c`` with HOME set to ``home`` (a temp dir); tests add only the
      KeyStore.authorize_command() line so enrollment is exercised for real.
    - Any other command is NEVER executed: it returns exit 127 with
      "command not found" (so e.g. ``shutdown -h now`` cannot touch the test host).
    - commands: every command received, in order.
    - auth_log: (method, username) tuples for successful auths.
    """
    host: str
    port: int
    home: object
    host_key: asyncssh.SSHKey
    acceptor: object = None
    authorized_keys: set = dc_field(default_factory=set)
    password: str | None = None
    responses: dict = dc_field(default_factory=dict)
    shell_allowlist: set = dc_field(default_factory=set)
    commands: list = dc_field(default_factory=list)
    auth_log: list = dc_field(default_factory=list)

    @property
    def host_key_line(self) -> str:
        return self.host_key.export_public_key().decode().strip()

    def swap_host_key(self) -> None:
        self.host_key = asyncssh.generate_private_key("ssh-ed25519")
        self.acceptor.update(server_host_keys=[self.host_key])

    def accepted_keys(self) -> set:
        keys = {k.strip() for k in self.authorized_keys}
        ak = self.home / ".ssh" / "authorized_keys"
        if ak.exists():
            keys |= {ln.strip() for ln in ak.read_text().splitlines() if ln.strip()}
        return keys


def _key_body(line: str) -> str:
    parts = line.split()
    return " ".join(parts[:2])


def _make_server_class(ctl: FakeSshServer):
    class _Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

        def public_key_auth_supported(self):
            return True

        def validate_public_key(self, username, key):
            body = _key_body(key.export_public_key().decode())
            ok = body in {_key_body(k) for k in ctl.accepted_keys()}
            if ok:
                ctl.auth_log.append(("publickey", username))
            return ok

        def password_auth_supported(self):
            return ctl.password is not None

        def validate_password(self, username, password):
            ok = ctl.password is not None and password == ctl.password
            if ok:
                ctl.auth_log.append(("password", username))
            return ok

    return _Server


def _b(v):
    return v.encode() if isinstance(v, str) else v


@pytest.fixture
async def ssh_server(tmp_path):
    home = tmp_path / "remote_home"
    home.mkdir()
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    ctl = FakeSshServer(host="127.0.0.1", port=0, home=home, host_key=host_key)

    async def handle(process: asyncssh.SSHServerProcess):
        cmd = process.command or ""
        ctl.commands.append(cmd)
        canned = ctl.responses.get(cmd)
        if canned is None and cmd not in ctl.shell_allowlist:
            canned = Canned(b"", f"bash: {cmd.split()[0] if cmd.split() else cmd}: command not found\n".encode(), 127)
        if canned is None:
            env = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
            proc = await asyncio.create_subprocess_exec(
                "bash", "-c", cmd, env=env, cwd=str(home),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = await proc.communicate()
            canned = Canned(out, err, proc.returncode)
        if canned.delay:
            await asyncio.sleep(canned.delay)
        process.stdout.write(_b(canned.stdout))
        process.stderr.write(_b(canned.stderr))
        process.exit(canned.exit)

    acceptor = await asyncssh.create_server(
        _make_server_class(ctl), "127.0.0.1", 0,
        server_host_keys=[host_key], process_factory=handle, encoding=None)
    ctl.acceptor = acceptor
    ctl.port = acceptor.sockets[0].getsockname()[1]
    yield ctl
    acceptor.close()
    await acceptor.wait_closed()
