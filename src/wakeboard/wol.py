import re
import socket

WOL_PORT = 9


def normalize_mac(s: str) -> str:
    h = re.sub(r"[-:.]", "", s.strip()).lower() if isinstance(s, str) else ""
    if not re.fullmatch(r"[0-9a-f]{12}", h):
        raise ValueError(f"invalid MAC address: {s!r}")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def magic_packet(mac: str) -> bytes:
    return b"\xff" * 6 + bytes.fromhex(normalize_mac(mac).replace(":", "")) * 16


def send_magic(mac, broadcast: str | None = None, repeat=3, sock_factory=socket.socket) -> None:
    packet = magic_packet(mac)
    addr = (broadcast or "255.255.255.255", WOL_PORT)
    sock = sock_factory(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for _ in range(repeat):
            sock.sendto(packet, addr)
    finally:
        sock.close()
