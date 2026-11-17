import hashlib
import hmac
import json
import math
import secrets
import sqlite3
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from itsdangerous import BadSignature, TimestampSigner, URLSafeTimedSerializer

MAX_FAILURES = 5
LOCKOUT_SECONDS = 15 * 60
SESSION_MAX_AGE = 7 * 24 * 3600


class LockedOut(Exception):
    def __init__(self, retry_after: int):
        super().__init__(f"locked out; retry in {retry_after}s")
        self.retry_after = retry_after


class AuthStore:
    def __init__(self, conn: sqlite3.Connection, now=time.time):
        self.conn = conn
        self.now = now
        self._ph = PasswordHasher()

    # -- kv helpers
    def _get(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def _set(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO kv(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    def _delete(self, key: str) -> None:
        self.conn.execute("DELETE FROM kv WHERE key=?", (key,))
        self.conn.commit()

    # -- password
    def password_set(self) -> bool:
        return self._get("auth.password_hash") is not None

    def set_password(self, pw: str) -> None:
        self._set("auth.password_hash", self._ph.hash(pw))

    def _lock_state(self, ip: str) -> dict:
        raw = self._get(f"auth.lock.{ip}")
        if raw:
            try:
                return json.loads(raw)
            except ValueError:
                pass
        return {"fails": 0, "locked_until": 0}

    def check_password(self, pw: str, client_ip: str) -> bool:
        now = self.now()
        state = self._lock_state(client_ip)
        if state["locked_until"] > now:
            raise LockedOut(math.ceil(state["locked_until"] - now))
        if state["locked_until"]:  # lockout elapsed: start fresh
            state = {"fails": 0, "locked_until": 0}
        stored = self._get("auth.password_hash")
        ok = False
        if stored:
            try:
                ok = self._ph.verify(stored, pw)
            except (VerificationError, InvalidHashError):
                ok = False
        key = f"auth.lock.{client_ip}"
        if ok:
            self._delete(key)
            return True
        state["fails"] += 1
        if state["fails"] >= MAX_FAILURES:
            state["locked_until"] = now + LOCKOUT_SECONDS
        self._set(key, json.dumps(state))
        return False

    # -- sessions
    def _secret(self) -> str:
        s = self._get("auth.session_secret")
        if s is None:
            s = secrets.token_hex(32)
            self._set("auth.session_secret", s)
        return s

    def _serializer(self) -> URLSafeTimedSerializer:
        now = self.now

        class _Signer(TimestampSigner):
            def get_timestamp(self) -> int:
                return int(now())

        return URLSafeTimedSerializer(
            self._secret(), salt="wakeboard-session", signer=_Signer
        )

    def new_session(self) -> str:
        return self._serializer().dumps({"s": secrets.token_hex(8)})

    def valid_session(self, cookie: str | None) -> bool:
        if not cookie:
            return False
        try:
            self._serializer().loads(cookie, max_age=SESSION_MAX_AGE)
            return True
        except Exception:
            return False

    # -- bearer token
    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def rotate_token(self) -> str:
        token = secrets.token_urlsafe(32)
        self._set("auth.token_hash", self._hash(token))
        return token

    def check_token(self, token: str | None) -> bool:
        if not token:
            return False
        stored = self._get("auth.token_hash")
        if not stored:
            return False
        return hmac.compare_digest(self._hash(token), stored)
