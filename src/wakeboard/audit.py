import sqlite3
from datetime import datetime, timezone


class AuditLog:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def record(self, caller: str, target: str, action: str, result: str) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO audit (ts, caller, target, action, result) VALUES (?,?,?,?,?)",
            (ts, caller, target, action, result))
        self.conn.commit()

    def list(self, limit: int = 200) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, ts, caller, target, action, result FROM audit ORDER BY id DESC LIMIT ?",
            (limit,))
        return [dict(r) for r in rows]
