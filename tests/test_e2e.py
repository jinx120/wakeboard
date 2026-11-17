"""End-to-end smoke: the real create_app (web UI + REST + real SshRunner/KeyStore/
AuthStore/sqlite) against the in-process asyncssh test server.

Nothing here touches the real network or this machine's power state:
- SSH goes to 127.0.0.1 on an ephemeral port served by the ``ssh_server`` fixture,
  which never executes ``shutdown -h now`` (it only returns a canned exit 0);
- the magic packet goes to a fake socket;
- reachability comes from a scripted prober;
- devices use host "localhost" and name resolution for self detection is stubbed:
  a literal loopback address is always treated as Wakeboard's own host (by design),
  which would make every shutdown need confirm=true.
"""
import re

import httpx

from wakeboard.config import Settings
from wakeboard.main import create_app
from wakeboard.wol import magic_packet, send_magic

from conftest import Canned

UI_PASSWORD = "correct horse battery"
SSH_PASSWORD = "device-root-password"


class FakeSocket:
    sent: list = []

    def __init__(self, family, kind):
        self.family, self.kind = family, kind

    def setsockopt(self, *a):
        pass

    def sendto(self, data, addr):
        FakeSocket.sent.append((data, addr))

    def close(self):
        pass


class ScriptedProber:
    """Devices in ``up`` answer up. A device in ``going_down`` answers up once more
    (the shutdown precheck) and is then down."""

    def __init__(self):
        self.up: set[str] = set()
        self.going_down: set[str] = set()

    async def is_up(self, device) -> bool:
        if device.name not in self.up:
            return False
        if device.name in self.going_down:
            self.going_down.discard(device.name)
            self.up.discard(device.name)
        return True


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    async def sleep(self, s: float) -> None:
        self.t += max(s, 0.01)


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    assert m, "no csrf field in page"
    return m.group(1)


async def test_add_device_enroll_wake_shutdown_via_rest(tmp_path, ssh_server, monkeypatch):
    monkeypatch.delenv("WAKEBOARD_PASSWORD", raising=False)
    FakeSocket.sent = []
    prober, clock = ScriptedProber(), FakeClock()
    app = create_app(
        Settings(data_dir=tmp_path / "data", poll_interval=3600),
        prober=prober,
        actions_kw={
            "sleep": clock.sleep, "clock": clock,
            "wol": lambda mac, broadcast=None, repeat=3: send_magic(
                mac, broadcast=broadcast, repeat=repeat, sock_factory=FakeSocket),
        },
        local_ips=lambda: set(), resolve=lambda h: set())

    ssh_server.password = SSH_PASSWORD
    ssh_server.shell_allowlist.add(app.state.keystore.authorize_command())
    ssh_server.responses["true"] = Canned(exit=0)
    ssh_server.responses["shutdown -h now"] = Canned(exit=0)   # never executed

    # The SSH test server lives on this test's event loop, so drive the ASGI app on
    # the same loop (TestClient would run it on a separate thread/loop).
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app), \
            httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        # -- first-run setup: password, then an API token
        page = await c.get("/setup")
        assert page.status_code == 200
        r = await c.post("/setup", data={"password": UI_PASSWORD, "confirm": UI_PASSWORD,
                                   "csrf": _csrf(page.text)}, follow_redirects=False)
        assert r.status_code == 303
        csrf = _csrf((await c.get("/")).text)
        r = await c.post("/settings", data={"op": "rotate_token", "current": UI_PASSWORD, "csrf": csrf})
        m = re.search(r'id="new-token"[^>]*>([A-Za-z0-9_\-]{20,})<', r.text)
        assert r.status_code == 200 and m, "token not shown"
        H = {"Authorization": f"Bearer {m.group(1)}"}

        # -- add two devices (both served by the test SSH server)
        for name, mac in (("node1", "aa:bb:cc:00:00:01"), ("node2", "aa:bb:cc:00:00:02")):
            r = await c.post("/devices/new", follow_redirects=False, data={
                "csrf": csrf, "name": name, "host": "localhost", "ssh_port": str(ssh_server.port),
                "ssh_user": "root", "mac": mac, "type": "linux", "groups": "lab"})
            assert r.status_code == 303, r.text
        assert {d["name"] for d in (await c.get("/api/v1/devices", headers=H)).json()} == {"node1", "node2"}

        # -- enrollment method B: one-time password; installs the Wakeboard key for real
        r = await c.post("/devices/node1/enroll", data={"csrf": csrf, "password": SSH_PASSWORD})
        assert r.status_code == 200 and "enrolled" in r.text.lower()
        assert SSH_PASSWORD not in r.text
        pub = app.state.keystore.public_key().split()[1]
        assert pub in (ssh_server.home / ".ssh" / "authorized_keys").read_text()
        ssh_server.password = None            # from here on only the key works

        # -- wake: magic packets to the fake socket, then ping + SSH (key auth)
        prober.up = {"node1", "node2"}       # simulate the hosts coming up
        r = await c.post("/api/v1/wake", json={"target": "node1"}, headers=H)
        assert r.status_code == 200 and r.json()["node1"]["ok"] is True, r.json()
        assert FakeSocket.sent and FakeSocket.sent[0] == (
            magic_packet("aa:bb:cc:00:00:01"), ("255.255.255.255", 9))
        assert ("publickey", "root") in ssh_server.auth_log

        # -- shutdown one device
        prober.going_down = {"node1"}
        r = await c.post("/api/v1/shutdown", json={"target": "node1"}, headers=H)
        assert r.status_code == 200 and r.json()["node1"]["ok"] is True, r.json()

        # -- shutdown all: refused without confirm, done with it
        prober.up, prober.going_down = {"node1", "node2"}, {"node1", "node2"}
        r = await c.post("/api/v1/shutdown", json={"target": "all"}, headers=H)
        assert r.status_code == 409 and "confirm" in r.json()["detail"]
        r = await c.post("/api/v1/shutdown", json={"target": "all", "confirm": True}, headers=H)
        assert r.status_code == 200, r.text
        assert all(v["ok"] for v in r.json().values()) and set(r.json()) == {"node1", "node2"}
        assert ssh_server.commands.count("shutdown -h now") == 3

        # -- the audit log records all three shutdown requests (and the rest)
        rows = app.state.audit.list(limit=1000)
        shut = [(row["target"], row["result"]) for row in rows if row["action"] == "shutdown"]
        assert any(t == "node1" and res.startswith("attempt") for t, res in shut)
        assert ("all", "refused: confirmation required") in shut
        assert any(t == "all" and res.startswith("attempt: confirm=True") for t, res in shut)
        actions = {row["action"] for row in rows}
        assert {"device_add", "enroll", "wake", "shutdown", "rotate_token"} <= actions
        audit_page = await c.get("/audit")
        assert audit_page.status_code == 200 and "refused: confirmation required" in audit_page.text
