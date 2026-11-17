from wakeboard.audit import AuditLog


def test_audit_newest_first(conn):
    log = AuditLog(conn)
    log.record("c", "a", "wake", "ok")
    log.record("c", "b", "shutdown", "fail")
    rows = log.list()
    assert [r["target"] for r in rows] == ["b", "a"]
    assert rows[0]["action"] == "shutdown" and rows[0]["result"] == "fail" and rows[0]["ts"]
    assert len(log.list(limit=1)) == 1
