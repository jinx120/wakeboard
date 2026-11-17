import pytest

from wakeboard.devices import Device
from wakeboard.wol import magic_packet, normalize_mac, send_magic


def test_magic_packet_layout():
    p = magic_packet("aa:bb:cc:dd:ee:ff")
    assert len(p) == 102
    assert p[:6] == b"\xff" * 6
    assert p[6:] == bytes.fromhex("aabbccddeeff") * 16


@pytest.mark.parametrize("s", ["AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "aabbccddeeff", "aa:bb:cc:dd:ee:ff"])
def test_normalize_accepts_dash_colon_dot_formats(s):
    assert normalize_mac(s) == "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize("s", ["", "garbage", "aa:bb:cc:dd:ee", "gg:bb:cc:dd:ee:ff", "aabbccddeeff00"])
def test_normalize_rejects_garbage(s):
    with pytest.raises(ValueError):
        normalize_mac(s)


class FakeSock:
    instances = []

    def __init__(self, *a):
        self.sent, self.opts, self.closed = [], [], False
        FakeSock.instances.append(self)

    def setsockopt(self, *a):
        self.opts.append(a)

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def close(self):
        self.closed = True


def test_send_magic_sends_three_packets_to_broadcast():
    FakeSock.instances.clear()
    send_magic("aa:bb:cc:dd:ee:ff", sock_factory=FakeSock)
    s = FakeSock.instances[0]
    assert len(s.sent) == 3
    assert all(a == ("255.255.255.255", 9) and len(d) == 102 for d, a in s.sent)
    assert s.opts and s.closed


def test_device_rejects_invalid_mac():
    with pytest.raises(ValueError):
        Device(name="x", host="h", mac="nope")


def test_device_normalizes_mac_and_allows_none():
    assert Device(name="x", host="h", mac="AA-BB-CC-DD-EE-FF").mac == "aa:bb:cc:dd:ee:ff"
    assert Device(name="x", host="h").mac is None
