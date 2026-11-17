import re
import sqlite3
import uuid
from dataclasses import dataclass, field

from wakeboard.wol import normalize_mac

VALID_TYPES = {"proxmox", "linux"}


class DuplicateDevice(Exception):
    pass


class UnknownDevice(Exception):
    pass


VALID_SHUTDOWN_MODES = {"plain", "graceful-proxmox"}

# Device names appear in URLs and target expressions: no '/', no whitespace, and never a
# word that the UI or the target resolver gives a meaning of its own.
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
RESERVED_NAMES = {"all", "new"}


def valid_name(name) -> bool:
    return isinstance(name, str) and NAME_RE.fullmatch(name) is not None \
        and name.lower() not in RESERVED_NAMES


@dataclass
class Device:
    name: str
    host: str
    ssh_user: str = "root"
    ssh_port: int = 22
    mac: str | None = None
    broadcast: str | None = None
    type: str = "linux"
    groups: list[str] = field(default_factory=list)
    key_id: str | None = None
    allow_run_command: bool = False
    shutdown_mode: str | None = None  # resolved in __post_init__ ("plain" / "graceful-proxmox")
    notes: str = ""
    bios_verified: bool = False
    is_self: bool = False
    host_key_ack: bool = False
    wake_test_result: str | None = None
    wake_test_at: float | None = None
    id: str | None = None

    def __post_init__(self):
        if not valid_name(self.name):
            raise ValueError(f"invalid device name: {str(self.name)[:80]!r} (use 1-64 letters, digits, "
                             "'.', '_' or '-', starting with a letter or digit; not 'all' or 'new')")
        if self.type not in VALID_TYPES:
            raise ValueError(f"invalid device type: {self.type!r}")
        if self.mac is not None:
            self.mac = normalize_mac(self.mac)
        if self.shutdown_mode is None:
            self.shutdown_mode = "graceful-proxmox" if self.type == "proxmox" else "plain"
        if self.shutdown_mode not in VALID_SHUTDOWN_MODES:
            raise ValueError(f"invalid shutdown_mode: {self.shutdown_mode!r}")
        groups = [g.strip() for g in self.groups]
        if any("," in g for g in groups):
            raise ValueError("group names must not contain commas")
        self.groups = [g for g in groups if g]


_COLS = ["name", "host", "ssh_user", "ssh_port", "mac", "broadcast", "type", "groups",
         "key_id", "allow_run_command", "shutdown_mode", "notes", "bios_verified", "is_self", "host_key_ack",
         "wake_test_result", "wake_test_at"]


def _values(d: Device) -> list:
    return [d.name, d.host, d.ssh_user, d.ssh_port, d.mac, d.broadcast, d.type,
            ",".join(d.groups), d.key_id, int(d.allow_run_command), d.shutdown_mode,
            d.notes, int(d.bios_verified), int(d.is_self), int(d.host_key_ack),
            d.wake_test_result, d.wake_test_at]


def _row(r: sqlite3.Row) -> Device:
    return Device(
        name=r["name"], host=r["host"], ssh_user=r["ssh_user"], ssh_port=r["ssh_port"],
        mac=r["mac"], broadcast=r["broadcast"], type=r["type"],
        groups=[g for g in r["groups"].split(",") if g], key_id=r["key_id"],
        allow_run_command=bool(r["allow_run_command"]), shutdown_mode=r["shutdown_mode"],
        notes=r["notes"], bios_verified=bool(r["bios_verified"]),
        is_self=bool(r["is_self"]), host_key_ack=bool(r["host_key_ack"]),
        wake_test_result=r["wake_test_result"], wake_test_at=r["wake_test_at"], id=r["id"],
    )


class DeviceRepo:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def add(self, d: Device) -> Device:
        d.id = d.id or uuid.uuid4().hex
        sql = f"INSERT INTO devices (id, {', '.join(_COLS)}) VALUES ({', '.join('?' * (len(_COLS) + 1))})"
        try:
            self.conn.execute(sql, [d.id, *_values(d)])
        except sqlite3.IntegrityError as e:
            self.conn.rollback()
            raise DuplicateDevice(d.name) from e
        self.conn.commit()
        return d

    def get(self, name: str) -> Device | None:
        r = self.conn.execute("SELECT * FROM devices WHERE name = ?", (name,)).fetchone()
        return _row(r) if r else None

    def update(self, d: Device) -> None:
        sets = ", ".join(f"{c} = ?" for c in _COLS)
        try:
            cur = self.conn.execute(f"UPDATE devices SET {sets} WHERE id = ?", [*_values(d), d.id])
        except sqlite3.IntegrityError as e:
            self.conn.rollback()
            raise DuplicateDevice(d.name) from e
        if cur.rowcount == 0:
            self.conn.rollback()
            raise UnknownDevice(d.name)
        self.conn.commit()

    def remove(self, name: str) -> None:
        cur = self.conn.execute("DELETE FROM devices WHERE name = ?", (name,))
        if cur.rowcount == 0:
            self.conn.rollback()
            raise UnknownDevice(name)
        self.conn.commit()

    def list(self) -> list[Device]:
        return [_row(r) for r in self.conn.execute("SELECT * FROM devices ORDER BY name")]
