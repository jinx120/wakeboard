"""SSH key storage: one global ed25519 key plus optional per-device keys."""
import os
import re
import shlex
from pathlib import Path

import asyncssh

GLOBAL_KEY_NAME = "id_ed25519"
KEY_COMMENT = "wakeboard"
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _write_private(path: Path, data: bytes) -> None:
    """Create a file with mode 0600 from the start (no world-readable window)."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    os.replace(tmp, path)


class KeyStore:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.key_dir = self.data_dir / "keys"

    def _ensure_dir(self) -> None:
        self.key_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.key_dir, 0o700)

    def private_path(self, key_id: str | None = None) -> Path:
        if key_id is None:
            return self.key_dir / GLOBAL_KEY_NAME
        if not _KEY_ID_RE.match(key_id) or key_id == GLOBAL_KEY_NAME:
            raise ValueError(f"invalid key id: {key_id!r}")
        return self.key_dir / key_id

    def ensure_global(self) -> None:
        self._ensure_dir()
        path = self.private_path(None)
        if path.exists():
            os.chmod(path, 0o600)
            return
        key = asyncssh.generate_private_key("ssh-ed25519", comment=KEY_COMMENT)
        _write_private(path, key.export_private_key())

    def load_private(self, key_id: str | None = None) -> asyncssh.SSHKey:
        return asyncssh.read_private_key(self.private_path(key_id))

    def public_key(self, key_id: str | None = None) -> str:
        key = self.load_private(key_id)
        return key.export_public_key().decode().strip()

    def authorize_command(self, key_id: str | None = None) -> str:
        """Shell one-liner installing the public key; idempotent (never appends twice)."""
        pub = shlex.quote(self.public_key(key_id))
        return (
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && "
            f"(grep -qxF {pub} ~/.ssh/authorized_keys || "
            # add a newline first if the file does not end with one
            "{ [ -z \"$(tail -c1 ~/.ssh/authorized_keys)\" ] || echo >> ~/.ssh/authorized_keys; "
            f"echo {pub} >> ~/.ssh/authorized_keys; }}) && "
            "chmod 600 ~/.ssh/authorized_keys"
        )
