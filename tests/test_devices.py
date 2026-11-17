import pytest

from wakeboard.devices import Device, DeviceRepo, DuplicateDevice


def test_add_get_roundtrip(conn):
    repo = DeviceRepo(conn)
    d = repo.add(Device(name="nas", host="10.0.0.2", mac="aa:bb", groups=["Lab", "x"],
                        allow_run_command=True, bios_verified=True, notes="hi"))
    assert d.id is not None
    got = repo.get("nas")
    assert got == d
    assert got.groups == ["Lab", "x"] and got.allow_run_command is True
    assert repo.get("nope") is None
    assert [x.name for x in repo.list()] == ["nas"]


def test_update_and_remove(conn):
    repo = DeviceRepo(conn)
    d = repo.add(Device(name="a", host="h"))
    d.host = "h2"
    repo.update(d)
    assert repo.get("a").host == "h2"
    repo.remove("a")
    assert repo.get("a") is None


def test_duplicate_name_rejected(conn):
    repo = DeviceRepo(conn)
    repo.add(Device(name="a", host="h"))
    with pytest.raises(DuplicateDevice):
        repo.add(Device(name="a", host="h2"))


def test_proxmox_defaults_to_graceful():
    assert Device(name="p", host="h", type="proxmox").shutdown_mode == "graceful-proxmox"
    assert Device(name="p", host="h", type="proxmox", shutdown_mode="plain").shutdown_mode == "plain"
    assert Device(name="l", host="h").shutdown_mode == "plain"


def test_invalid_type():
    with pytest.raises(ValueError):
        Device(name="x", host="h", type="bsd")


def test_connect_thread_safe(conn):
    import threading
    out = []
    t = threading.Thread(target=lambda: out.append(conn.execute("select 1").fetchone()[0]))
    t.start(); t.join()
    assert out == [1]
