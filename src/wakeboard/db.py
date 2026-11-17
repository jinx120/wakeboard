import sqlite3
from pathlib import Path

MIGRATIONS: list[str] = [
    """
    CREATE TABLE devices (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        host TEXT NOT NULL,
        ssh_user TEXT,
        ssh_port INTEGER NOT NULL DEFAULT 22,
        mac TEXT,
        broadcast TEXT,
        type TEXT,
        groups TEXT NOT NULL DEFAULT '',
        key_id TEXT,
        allow_run_command INTEGER NOT NULL DEFAULT 0,
        shutdown_mode TEXT,
        notes TEXT NOT NULL DEFAULT '',
        bios_verified INTEGER NOT NULL DEFAULT 0,
        is_self INTEGER NOT NULL DEFAULT 0,
        host_key_ack INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        caller TEXT NOT NULL,
        target TEXT NOT NULL,
        action TEXT NOT NULL,
        result TEXT NOT NULL
    );
    CREATE TABLE kv (
        key TEXT PRIMARY KEY,
        value TEXT
    );
    """,
]


def connect(path: Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    for i in range(version, len(MIGRATIONS)):
        conn.executescript(MIGRATIONS[i])
        conn.execute(f"PRAGMA user_version = {i + 1}")
    conn.commit()
    return conn
