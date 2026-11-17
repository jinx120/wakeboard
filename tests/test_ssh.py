import asyncio
import stat

import pytest

from conftest import Canned
from wakeboard.devices import Device
from wakeboard.ssh import (AuthFailed, ConnectFailed, EnrollmentFailed, HostKeyChanged, RunResult,
                           SshRunner)
from wakeboard.sshkeys import KeyStore

PASSWORD = "s3cret-Enroll-Pw!"


def _mode(p):
    return stat.S_IMODE(p.stat().st_mode)


@pytest.fixture
def keystore(tmp_path):
    ks = KeyStore(tmp_path / "data")
    ks.ensure_global()
    return ks


@pytest.fixture
def known_hosts(tmp_path):
    return tmp_path / "data" / "known_hosts"


@pytest.fixture
def runner(keystore, known_hosts):
    return SshRunner(keystore, known_hosts)


@pytest.fixture
def device(ssh_server):
    return Device(name="box", host=ssh_server.host, ssh_port=ssh_server.port, ssh_user="root")


@pytest.fixture
def authorized(ssh_server, keystore):
    ssh_server.authorized_keys.add(keystore.public_key())
    return ssh_server


def test_global_key_created_0600_and_idempotent(tmp_path):
    ks = KeyStore(tmp_path / "data")
    ks.ensure_global()
    p = ks.private_path(None)
    assert p.exists()
    assert _mode(p) == 0o600
    assert _mode(p.parent) == 0o700
    first = p.read_bytes()
    pub = ks.public_key()
    assert pub.startswith("ssh-ed25519 ")
    ks.ensure_global()
    assert p.read_bytes() == first
    assert ks.public_key() == pub


def test_private_path_rejects_traversal(keystore):
    with pytest.raises(ValueError):
        keystore.private_path("../evil")


def test_private_path_rejects_trailing_newline(keystore):
    with pytest.raises(ValueError):
        keystore.private_path("abc\n")


def test_authorize_command_contains_pubkey(keystore):
    cmd = keystore.authorize_command()
    pub = keystore.public_key()
    assert pub in cmd
    assert "mkdir -p ~/.ssh" in cmd
    assert "chmod 700 ~/.ssh" in cmd
    assert ">> ~/.ssh/authorized_keys" in cmd
    assert "chmod 600 ~/.ssh/authorized_keys" in cmd


async def test_run_returns_stdout_exit(runner, device, authorized):
    authorized.responses["uptime"] = Canned("up 3 days\n", "warn\n", 3)
    r = await runner.run(device, "uptime")
    assert r == RunResult(stdout="up 3 days\n", stderr="warn\n", exit=3)
    assert authorized.commands == ["uptime"]
    assert ("publickey", "root") in authorized.auth_log


async def test_first_connect_pins_host_key(runner, device, authorized, known_hosts):
    assert not known_hosts.exists()
    authorized.responses["true"] = Canned()
    await runner.run(device, "true")
    text = known_hosts.read_text()
    assert f"[{device.host}]:{device.ssh_port}" in text
    assert authorized.host_key_line.split()[1] in text
    assert _mode(known_hosts) == 0o600
    # second connect matches the pin and does not duplicate it
    await runner.run(device, "true")
    assert known_hosts.read_text() == text


async def test_changed_host_key_raises(runner, device, authorized, known_hosts):
    authorized.responses["true"] = Canned()
    await runner.run(device, "true")
    pinned = known_hosts.read_text()
    authorized.swap_host_key()
    with pytest.raises(HostKeyChanged):
        await runner.run(device, "true")
    # hard error: the command never ran and the pin was not replaced
    assert authorized.commands == ["true"]
    assert known_hosts.read_text() == pinned


async def test_changed_host_key_accepted_when_device_acked(runner, device, authorized, known_hosts):
    authorized.responses["true"] = Canned()
    await runner.run(device, "true")
    authorized.swap_host_key()
    device.host_key_ack = True
    await runner.run(device, "true")
    assert authorized.host_key_line.split()[1] in known_hosts.read_text()


async def test_acknowledge_then_repins(runner, device, authorized, known_hosts):
    authorized.responses["true"] = Canned()
    await runner.run(device, "true")
    old = authorized.host_key_line.split()[1]
    authorized.swap_host_key()
    with pytest.raises(HostKeyChanged):
        await runner.run(device, "true")
    runner.acknowledge_host_key(device)
    assert old not in (known_hosts.read_text() if known_hosts.exists() else "")
    await runner.run(device, "true")
    text = known_hosts.read_text()
    assert authorized.host_key_line.split()[1] in text
    assert old not in text


async def test_acknowledge_leaves_other_hosts_pinned(runner, device, authorized, known_hosts):
    authorized.responses["true"] = Canned()
    await runner.run(device, "true")
    known_hosts.write_text(known_hosts.read_text() + "[10.0.0.9]:22 ssh-ed25519 AAAAother\n")
    runner.acknowledge_host_key(device)
    text = known_hosts.read_text()
    assert "[10.0.0.9]:22" in text
    assert f"[{device.host}]:{device.ssh_port}" not in text


async def test_enroll_with_password_installs_key_then_key_login_works(
        runner, device, ssh_server, keystore, tmp_path):
    ssh_server.shell_allowlist.add(keystore.authorize_command())
    ssh_server.password = PASSWORD
    await runner.enroll_with_password(device, PASSWORD)
    assert ("password", "root") in ssh_server.auth_log
    ak = ssh_server.home / ".ssh" / "authorized_keys"
    assert keystore.public_key() in ak.read_text().splitlines()
    # password login no longer needed
    ssh_server.password = None
    ssh_server.responses["hostname"] = Canned("box\n")
    r = await runner.run(device, "hostname")
    assert r.stdout == "box\n"
    assert ("publickey", "root") in ssh_server.auth_log
    # password never persisted anywhere under the data dir, nor kept on the runner
    for f in (tmp_path / "data").rglob("*"):
        if f.is_file():
            assert PASSWORD.encode() not in f.read_bytes()
    assert PASSWORD not in repr(vars(runner))


async def test_enroll_twice_does_not_duplicate_key(runner, device, ssh_server, keystore, caplog):
    caplog.set_level("DEBUG")
    ssh_server.shell_allowlist.add(keystore.authorize_command())
    ssh_server.password = PASSWORD
    await runner.enroll_with_password(device, PASSWORD)
    await runner.enroll_with_password(device, PASSWORD)
    lines = (ssh_server.home / ".ssh" / "authorized_keys").read_text().splitlines()
    assert lines.count(keystore.public_key()) == 1
    assert PASSWORD not in caplog.text


async def test_enroll_wrong_password_error_hides_password(runner, device, ssh_server, caplog):
    caplog.set_level("DEBUG")
    ssh_server.password = "the-right-one"
    with pytest.raises(EnrollmentFailed) as ei:
        await runner.enroll_with_password(device, PASSWORD)
    assert PASSWORD not in str(ei.value)
    assert PASSWORD not in repr(ei.value)
    assert PASSWORD not in caplog.text


async def test_non_utf8_output_decoded_with_replacement(runner, device, authorized):
    authorized.responses["dump"] = Canned(b"ok \xff\xfe end\n", b"\xc3\x28", 0)
    r = await runner.run(device, "dump")
    assert r.stdout == "ok �� end\n"
    assert "�" in r.stderr
    assert r.exit == 0


async def test_run_timeout(runner, device, authorized):
    authorized.responses["slow"] = Canned(delay=5)
    with pytest.raises(asyncio.TimeoutError):
        await runner.run(device, "slow", timeout=0.5)


async def test_sudo_ok_false_when_prompt_required(runner, ssh_server, keystore):
    ssh_server.authorized_keys.add(keystore.public_key())
    dev = Device(name="u", host=ssh_server.host, ssh_port=ssh_server.port, ssh_user="alice")
    ssh_server.responses["sudo -n true"] = Canned("", "sudo: a password is required\n", 1)
    assert await runner.sudo_ok(dev) is False
    ssh_server.responses["sudo -n true"] = Canned("", "", 0)
    assert await runner.sudo_ok(dev) is True


async def test_sudo_ok_true_for_root_without_running_sudo(runner, device, authorized):
    assert await runner.sudo_ok(device) is True
    assert "sudo -n true" not in authorized.commands


async def test_unknown_command_is_not_executed(runner, device, authorized, tmp_path):
    marker = tmp_path / "should_not_exist"
    r = await runner.run(device, f"touch {marker}")
    assert r.exit == 127
    assert "command not found" in r.stderr
    assert not marker.exists()
    r = await runner.run(device, "shutdown -h now")
    assert r.exit == 127
    assert "command not found" in r.stderr
    assert authorized.commands[-1] == "shutdown -h now"


async def test_corrupt_pinned_entry_fails_closed(runner, device, authorized, known_hosts):
    authorized.responses["true"] = Canned()
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    corrupt = f"[{device.host}]:{device.ssh_port} ssh-ed25519 not-base64!!\n"
    known_hosts.write_text(corrupt)
    with pytest.raises(HostKeyChanged):
        await runner.run(device, "true")
    device.host_key_ack = True
    with pytest.raises(HostKeyChanged):
        await runner.run(device, "true")
    assert known_hosts.read_text() == corrupt
    assert authorized.commands == []


@pytest.mark.parametrize("bad", ["evil host", "evil\nhost", "evil\thost", ""])
async def test_host_with_whitespace_rejected(runner, bad, known_hosts):
    dev = Device(name="x", host=bad, ssh_port=22)
    with pytest.raises(ValueError):
        await runner.run(dev, "true")
    with pytest.raises(ValueError):
        runner.acknowledge_host_key(dev)
    assert not known_hosts.exists()


async def test_run_connection_refused_raises_connect_failed(runner, keystore):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here now
    dev = Device(name="gone", host="127.0.0.1", ssh_port=port)
    with pytest.raises(ConnectFailed) as ei:
        await runner.run(dev, "shutdown -h now")
    assert not isinstance(ei.value, AuthFailed)


async def test_run_connect_timeout_raises_connect_failed(runner, keystore):
    async def silent(reader, writer):
        await asyncio.sleep(5)  # accept TCP but never speak SSH

    srv = await asyncio.start_server(silent, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    try:
        with pytest.raises(ConnectFailed, match="timed out"):
            await runner.run(Device(name="mute", host="127.0.0.1", ssh_port=port), "true",
                             timeout=0.5)
    finally:
        srv.close()


async def test_run_auth_rejected_raises_auth_failed(runner, device, ssh_server):
    # key not in authorized_keys
    with pytest.raises(AuthFailed):
        await runner.run(device, "true")
    assert ssh_server.commands == []


# ---- host_key_ack is cleared whenever a key is (re)pinned -----------------------

def _ack_runner(keystore, known_hosts):
    cleared = []
    return SshRunner(keystore, known_hosts, on_repin=lambda d: cleared.append(d.name)), cleared


async def _pin_then_swap_and_ack(r, device, authorized):
    authorized.responses["true"] = Canned()
    await r.run(device, "true")
    authorized.swap_host_key()
    r.acknowledge_host_key(device)
    device.host_key_ack = True


async def test_repin_via_run_clears_ack_and_next_change_is_hard_error(
        keystore, known_hosts, device, authorized):
    r, cleared = _ack_runner(keystore, known_hosts)
    await _pin_then_swap_and_ack(r, device, authorized)
    await r.run(device, "true")
    assert device.host_key_ack is False and cleared == ["box"]
    authorized.swap_host_key()
    with pytest.raises(HostKeyChanged):
        await r.run(device, "true")


async def test_repin_clears_ack_even_when_command_then_fails(keystore, known_hosts, device, authorized):
    r, cleared = _ack_runner(keystore, known_hosts)
    await _pin_then_swap_and_ack(r, device, authorized)
    authorized.responses["slow"] = Canned(delay=5)
    with pytest.raises(asyncio.TimeoutError):
        await r.run(device, "slow", timeout=1.0)
    assert device.host_key_ack is False and cleared == ["box"]


async def test_repin_via_sudo_ok_clears_ack(keystore, known_hosts, ssh_server):
    ssh_server.authorized_keys.add(keystore.public_key())
    dev = Device(name="u", host=ssh_server.host, ssh_port=ssh_server.port, ssh_user="alice")
    ssh_server.responses["sudo -n true"] = Canned("", "", 0)
    r, cleared = _ack_runner(keystore, known_hosts)
    await r.run(dev, "sudo -n true")
    ssh_server.swap_host_key()
    r.acknowledge_host_key(dev)
    dev.host_key_ack = True
    assert await r.sudo_ok(dev) is True
    assert dev.host_key_ack is False and cleared == ["u"]


async def test_repin_via_enroll_clears_ack_and_next_change_is_hard_error(
        keystore, known_hosts, device, ssh_server):
    ssh_server.shell_allowlist.add(keystore.authorize_command())
    ssh_server.password = PASSWORD
    r, cleared = _ack_runner(keystore, known_hosts)
    await r.enroll_with_password(device, PASSWORD)
    assert cleared == []  # first use with no ack: nothing to clear
    ssh_server.swap_host_key()
    r.acknowledge_host_key(device)
    device.host_key_ack = True
    await r.enroll_with_password(device, PASSWORD)
    assert device.host_key_ack is False and cleared == ["box"]
    ssh_server.swap_host_key()
    with pytest.raises(HostKeyChanged):
        await r.enroll_with_password(device, PASSWORD)


async def test_failed_connect_keeps_ack(keystore, known_hosts, device, ssh_server):
    # key auth rejected: no connection, no pin, ack kept for the next attempt
    r, cleared = _ack_runner(keystore, known_hosts)
    device.host_key_ack = True
    with pytest.raises(AuthFailed):
        await r.run(device, "true")
    assert device.host_key_ack is True and cleared == []


async def test_on_repin_error_does_not_break_connection(keystore, known_hosts, device, authorized):
    def boom(d):
        raise RuntimeError("db down")
    r = SshRunner(keystore, known_hosts, on_repin=boom)
    await _pin_then_swap_and_ack(r, device, authorized)
    assert (await r.run(device, "true")).exit == 0
    assert device.host_key_ack is False
