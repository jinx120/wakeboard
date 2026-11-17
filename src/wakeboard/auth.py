import hashlib
import hmac
import json
import math
import secrets
import sqlite3
import threading
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
    def __init__(self, conn: sqlite3.Connection, now=time.time, lock=None):
        self.conn = conn
        self.now = now
        self._ph = PasswordHasher()
        # Pass the app's shared DB write lock so kv writes never interleave with
        # other writers on the same connection; must not be held when calling in.
        self._lock = lock if lock is not None else threading.Lock()

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
        with self._lock:
            self._set("auth.password_hash", self._ph.hash(pw))
            # rotate the session secret: all existing sessions become invalid
            self._set("auth.session_secret", secrets.token_hex(32))

    def set_initial_password(self, pw: str) -> bool:
        """Set the password only if none is set (first-run setup), atomically.
        Returns False, changing nothing, when a password already exists."""
        with self._lock:
            if self._get("auth.password_hash") is not None:
                return False
            self._set("auth.password_hash", self._ph.hash(pw))
            self._set("auth.session_secret", secrets.token_hex(32))
            return True

    def csrf_token(self, base: str) -> str:
        """CSRF token bound to `base` (a session cookie or a pre-login nonce) under
        the session secret, so it rotates whenever the password changes."""
        return hmac.new(self._secret().encode(), b"wakeboard-csrf:" + base.encode("utf-8", "replace"),
                        hashlib.sha256).hexdigest()

    @staticmethod
    def _lock_key(ip: str) -> str:
        # fixed-length key regardless of input length
        return "auth.lock." + hashlib.sha256(str(ip).encode()).hexdigest()[:32]

    def _lock_state(self, key: str) -> dict:
        raw = self._get(key)
        if raw:
            try:
                return json.loads(raw)
            except ValueError:
                pass
        return {"fails": 0, "locked_until": 0, "last": 0}

    def _prune(self, now: float) -> None:
        """Delete lock rows whose lock expired and with no recent failures."""
        rows = self.conn.execute(
            "SELECT key, value FROM kv WHERE key LIKE 'auth.lock.%'"
        ).fetchall()
        stale = []
        for r in rows:
            try:
                st = json.loads(r["value"])
                dead = (
                    st.get("locked_until", 0) <= now
                    and now - st.get("last", 0) > LOCKOUT_SECONDS
                )
            except (ValueError, AttributeError, TypeError):
                dead = True
            if dead:
                stale.append((r["key"],))
        if stale:
            self.conn.executemany("DELETE FROM kv WHERE key=?", stale)
            self.conn.commit()

    def check_password(self, pw: str, client_ip: str) -> bool:
        """Check the password, enforcing per-IP lockout.

        client_ip must be the trusted TCP peer address, never a value derived
        from request headers (e.g. X-Forwarded-For), which a client can spoof
        to dodge the lockout. Raises LockedOut while locked, even for the
        correct password. The whole check/verify/update is serialized.
        """
        with self._lock:
            now = self.now()
            self._prune(now)
            key = self._lock_key(client_ip)
            state = self._lock_state(key)
            if state["locked_until"] > now:
                raise LockedOut(math.ceil(state["locked_until"] - now))
            if state["locked_until"]:  # lockout elapsed: start fresh
                state = {"fails": 0, "locked_until": 0, "last": 0}
            stored = self._get("auth.password_hash")
            ok = False
            if stored:
                try:
                    ok = self._ph.verify(stored, pw)
                except (VerificationError, InvalidHashError):
                    ok = False
            if ok:
                self._delete(key)
                return True
            state["fails"] += 1
            state["last"] = now
            if state["fails"] >= MAX_FAILURES:
                state["locked_until"] = now + LOCKOUT_SECONDS
            self._set(key, json.dumps(state))
            return False

    # -- sessions
    def _secret(self) -> str:
        s = self._get("auth.session_secret")
        if s is None:
            with self._lock:
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

    def _session_data(self, cookie: str | None):
        """(session id, issued-at) for a valid signed cookie, else None. Ignores revocation."""
        if not cookie:
            return None
        try:
            data, ts = self._serializer().loads(cookie, max_age=SESSION_MAX_AGE, return_timestamp=True)
        except Exception:
            return None
        sid = data.get("s") if isinstance(data, dict) else None
        if not isinstance(sid, str) or not sid:
            return None
        return sid, ts.timestamp()

    @staticmethod
    def _revoked_key(sid: str) -> str:
        return "auth.revoked." + hashlib.sha256(sid.encode()).hexdigest()[:32]

    def valid_session(self, cookie: str | None) -> bool:
        got = self._session_data(cookie)
        if got is None:
            return False
        return self._get(self._revoked_key(got[0])) is None

    def revoke_session(self, cookie: str | None) -> None:
        """Server-side logout: deny this session until it would have expired anyway.
        Invalid or already-expired cookies are ignored. Expired deny rows are pruned."""
        got = self._session_data(cookie)
        with self._lock:
            now = self.now()
            rows = self.conn.execute(
                "SELECT key, value FROM kv WHERE key LIKE 'auth.revoked.%'").fetchall()
            stale = []
            for r in rows:
                try:
                    dead = float(r["value"]) <= now
                except (TypeError, ValueError):
                    dead = True
                if dead:
                    stale.append((r["key"],))
            if stale:
                self.conn.executemany("DELETE FROM kv WHERE key=?", stale)
                self.conn.commit()
            if got is not None:
                sid, issued = got
                self._set(self._revoked_key(sid), str(issued + SESSION_MAX_AGE + 1))

    # -- bearer token
    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def rotate_token(self) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._set("auth.token_hash", self._hash(token))
        return token

    def check_token(self, token: str | None) -> bool:
        if not token:
            return False
        stored = self._get("auth.token_hash")
        if not stored:
            return False
        return hmac.compare_digest(self._hash(token), stored)
