import pytest

from wakeboard.auth import AuthStore, LockedOut


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(conn, clock):
    s = AuthStore(conn, now=clock)
    s.set_password("hunter2")
    return s


def test_password_hash_not_plaintext_in_db(conn, store):
    assert store.password_set()
    rows = [r["value"] for r in conn.execute("SELECT value FROM kv")]
    assert rows and all("hunter2" not in (v or "") for v in rows)
    assert any((v or "").startswith("$argon2") for v in rows)


def test_password_not_set_initially(conn):
    assert not AuthStore(conn).password_set()


def test_check_password_ok_and_bad(store):
    assert store.check_password("hunter2", "1.1.1.1") is True
    assert store.check_password("nope", "1.1.1.1") is False


def test_lockout_after_five_failures_even_with_correct_password(store):
    for _ in range(5):
        assert store.check_password("bad", "2.2.2.2") is False
    with pytest.raises(LockedOut) as e:
        store.check_password("hunter2", "2.2.2.2")
    assert 0 < e.value.retry_after <= 900
    # other IP unaffected
    assert store.check_password("hunter2", "3.3.3.3") is True


def test_lockout_persists_across_store_instances(conn, clock, store):
    for _ in range(5):
        store.check_password("bad", "2.2.2.2")
    with pytest.raises(LockedOut):
        AuthStore(conn, now=clock).check_password("hunter2", "2.2.2.2")


def test_lockout_expires(store, clock):
    for _ in range(5):
        store.check_password("bad", "2.2.2.2")
    clock.t += 901
    assert store.check_password("hunter2", "2.2.2.2") is True


def test_success_resets_failure_counter(store):
    for _ in range(4):
        store.check_password("bad", "4.4.4.4")
    assert store.check_password("hunter2", "4.4.4.4") is True
    for _ in range(4):
        assert store.check_password("bad", "4.4.4.4") is False
    assert store.check_password("hunter2", "4.4.4.4") is True


def test_session_roundtrip_and_tamper_rejected(store):
    c = store.new_session()
    assert store.valid_session(c) is True
    assert store.valid_session(c[:-2] + "xx") is False
    assert store.valid_session("garbage") is False
    assert store.valid_session("") is False
    assert store.valid_session(None) is False


def test_session_expires_after_seven_days(store, clock):
    c = store.new_session()
    clock.t += 7 * 86400 + 5
    assert store.valid_session(c) is False


def test_session_secret_stable_across_instances(conn, clock, store):
    c = store.new_session()
    assert AuthStore(conn, now=clock).valid_session(c) is True


def test_token_rotation_invalidates_old(conn, store):
    t1 = store.rotate_token()
    assert store.check_token(t1) is True
    t2 = store.rotate_token()
    assert t1 != t2
    assert store.check_token(t1) is False
    assert store.check_token(t2) is True
    assert all(t2 not in (r["value"] or "") for r in conn.execute("SELECT value FROM kv"))


def test_check_token_none_false(store):
    assert store.check_token(None) is False
    store.rotate_token()
    assert store.check_token(None) is False
    assert store.check_token("") is False


def test_fifth_failure_locks_sixth_raises_with_correct_password(store):
    for _ in range(4):
        assert store.check_password("bad", "5.5.5.5") is False
    assert store.check_password("bad", "5.5.5.5") is False  # 5th triggers lock
    with pytest.raises(LockedOut):
        store.check_password("hunter2", "5.5.5.5")


def test_concurrent_wrong_guesses_cannot_bypass_lockout(store):
    import threading

    results = []

    def guess():
        try:
            results.append(store.check_password("bad", "6.6.6.6"))
        except LockedOut:
            results.append("locked")

    threads = [threading.Thread(target=guess) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count(False) == 5
    assert results.count("locked") == 3
    with pytest.raises(LockedOut):
        store.check_password("hunter2", "6.6.6.6")


def test_lock_key_length_bounded(conn, store):
    store.check_password("bad", "x" * 10000)
    keys = [r["key"] for r in conn.execute("SELECT key FROM kv WHERE key LIKE 'auth.lock.%'")]
    assert len(keys) == 1 and len(keys[0]) < 64


def test_stale_lock_rows_pruned(conn, store, clock):
    store.check_password("bad", "7.7.7.7")
    for _ in range(5):
        store.check_password("bad", "8.8.8.8")
    n = lambda: conn.execute("SELECT count(*) FROM kv WHERE key LIKE 'auth.lock.%'").fetchone()[0]
    assert n() == 2
    clock.t += 2000
    store.check_password("hunter2", "9.9.9.9")
    assert n() == 0


def test_set_password_invalidates_sessions(store):
    c = store.new_session()
    assert store.valid_session(c)
    store.set_password("newpass")
    assert store.valid_session(c) is False
    assert store.valid_session(store.new_session()) is True
