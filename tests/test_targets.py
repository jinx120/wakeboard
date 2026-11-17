import pytest

from wakeboard.devices import Device, DeviceRepo
from wakeboard.targets import NoDevices, UnknownTarget, is_bulk, resolve_targets


@pytest.fixture
def repo(conn):
    r = DeviceRepo(conn)
    r.add(Device(name="a", host="1", groups=["Lab"]))
    r.add(Device(name="b", host="2", groups=["lab"]))
    r.add(Device(name="me", host="3", is_self=True, groups=["lab"]))
    r.add(Device(name="lab", host="4"))
    return r


def test_resolve_by_name(repo):
    assert [d.name for d in resolve_targets(repo, "a")] == ["a"]


def test_name_beats_group(repo):
    assert [d.name for d in resolve_targets(repo, "lab")] == ["lab"]


def test_resolve_group_returns_members(conn):
    r = DeviceRepo(conn)
    r.add(Device(name="a", host="1", groups=["Lab"]))
    r.add(Device(name="b", host="2", groups=["lab"]))
    assert sorted(d.name for d in resolve_targets(r, "LAB")) == ["a", "b"]


def test_all_excludes_self(repo):
    assert sorted(d.name for d in resolve_targets(repo, "all")) == ["a", "b", "lab"]


def test_all_with_only_self_raises_nodevices(conn):
    r = DeviceRepo(conn)
    with pytest.raises(NoDevices):
        resolve_targets(r, "all")
    r.add(Device(name="me", host="3", is_self=True))
    with pytest.raises(NoDevices):
        resolve_targets(r, "all")


def test_unknown_target_raises(repo):
    with pytest.raises(UnknownTarget):
        resolve_targets(repo, "zzz")


def test_is_bulk(repo):
    assert is_bulk("all", repo)
    assert not is_bulk("a", repo)
    assert not is_bulk("lab", repo)  # device name wins
