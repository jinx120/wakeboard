import sqlite3
import uuid
from dataclasses import dataclass, field

VALID_TYPES = {"proxmox", "linux"}


class DuplicateDevice(Exception):
    pass


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
    id: str | None = None

    def __post_init__(self):
        if self.type not in VALID_TYPES:
            raise ValueError(f"invalid device type: {self.type!r}")
        if self.shutdown_mode is None:
            self.shutdown_mode = "graceful-proxmox" if self.type == "proxmox" else "plain"


_COLS = ["name", "host", "ssh_user", "ssh_port", "mac", "broadcast", "type", "groups",
         "key_id", "allow_run_command", "shutdown_mode", "notes", "bios_verified", "is_self"]


def _values(d: Device) -> list:
    return [d.name, d.host, d.ssh_user, d.ssh_port, d.mac, d.broadcast, d.type,
            ",".join(d.groups), d.key_id, int(d.allow_run_command), d.shutdown_mode,
            d.notes, int(d.bios_verified), int(d.is_self)]


def _row(r: sqlite3.Row) -> Device:
    return Device(
        name=r["name"], host=r["host"], ssh_user=r["ssh_user"], ssh_port=r["ssh_port"],
        mac=r["mac"], broadcast=r["broadcast"], type=r["type"],
        groups=[g for g in r["groups"].split(",") if g], key_id=r["key_id"],
        allow_run_command=bool(r["allow_run_command"]), shutdown_mode=r["shutdown_mode"],
        notes=r["notes"], bios_verified=bool(r["bios_verified"]),
        is_self=bool(r["is_self"]), id=r["id"],
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
            self.conn.execute(f"UPDATE devices SET {sets} WHERE id = ?", [*_values(d), d.id])
        except sqlite3.IntegrityError as e:
            self.conn.rollback()
            raise DuplicateDevice(d.name) from e
        self.conn.commit()

    def remove(self, name: str) -> None:
        self.conn.execute("DELETE FROM devices WHERE name = ?", (name,))
        self.conn.commit()

    def list(self) -> list[Device]:
        return [_row(r) for r in self.conn.execute("SELECT * FROM devices ORDER BY name")]
