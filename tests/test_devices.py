import pytest

from wakeboard.devices import Device, DeviceRepo, DuplicateDevice, UnknownDevice


def test_add_get_roundtrip(conn):
    repo = DeviceRepo(conn)
    d = repo.add(Device(name="nas", host="10.0.0.2", mac="aa:bb:cc:dd:ee:ff", groups=["Lab", "x"],
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


def test_host_key_ack_roundtrip(conn):
    repo = DeviceRepo(conn)
    d = repo.add(Device(name="a", host="h"))
    assert repo.get("a").host_key_ack is False
    d.host_key_ack = True
    repo.update(d)
    assert repo.get("a").host_key_ack is True
    assert repo.add(Device(name="b", host="h", host_key_ack=True)).host_key_ack is True
    assert repo.get("b").host_key_ack is True


def test_group_with_comma_rejected():
    with pytest.raises(ValueError):
        Device(name="a", host="h", groups=["a,b"])


def test_groups_stripped_and_empties_dropped():
    assert Device(name="a", host="h", groups=[" lab ", "", "  "]).groups == ["lab"]


def test_invalid_shutdown_mode_rejected():
    with pytest.raises(ValueError):
        Device(name="a", host="h", shutdown_mode="nuke")


def test_remove_missing_raises(conn):
    with pytest.raises(UnknownDevice):
        DeviceRepo(conn).remove("ghost")


def test_update_missing_raises(conn):
    with pytest.raises(UnknownDevice):
        DeviceRepo(conn).update(Device(name="ghost", host="h", id="nope"))


def test_update_to_duplicate_name_raises_duplicate(conn):
    repo = DeviceRepo(conn)
    repo.add(Device(name="a", host="h"))
    b = repo.add(Device(name="b", host="h"))
    b.name = "a"
    with pytest.raises(DuplicateDevice):
        repo.update(b)


@pytest.mark.parametrize("bad", ["all", "ALL", "new", "New", "a/b", "/x", "", " a", "a b", "-a",
                                 ".hidden", "x" * 65, "café"])
def test_device_name_rules_enforced_in_model(bad):
    with pytest.raises(ValueError):
        Device(name=bad, host="h")


@pytest.mark.parametrize("good", ["a", "pve-1", "nas.lan", "box_2", "X" * 64, "allx", "newer"])
def test_device_name_rules_accept_valid(good):
    assert Device(name=good, host="h").name == good

