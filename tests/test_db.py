from pathlib import Path

from wakeboard.config import Settings
from wakeboard.db import MIGRATIONS, connect


def test_connect_creates_schema_and_is_idempotent(tmp_path):
    path = tmp_path / "w.db"
    c1 = connect(path)
    c1.close()
    c2 = connect(path)
    names = {r["name"] for r in c2.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"devices", "audit", "kv"} <= names
    assert c2.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
    assert c2.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    c2.close()


def test_settings_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("WAKEBOARD_DATA", str(tmp_path))
    s = Settings.from_env()
    assert s.data_dir == Path(tmp_path)
    assert (s.poll_interval, s.wake_timeout, s.guest_timeout) == (30, 300, 120)
