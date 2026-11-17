# Wakeboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Wakeboard: a self-hosted web dashboard + REST + MCP server that wakes (WoL), shuts down, reboots and inspects Linux/Proxmox devices over SSH.

**Architecture:** One FastAPI process. A shared service layer (`service.py`) owns all device logic; the Jinja2/HTMX UI, REST API and MCP server (streamable HTTP at `/mcp`) are thin adapters over it. State is SQLite + SSH keys under `/data`. Everything that touches the network (WoL socket, ping/TCP probe, SSH) sits behind small injectable interfaces so tests run with fakes and an in-process asyncssh server.

**Tech Stack:** Python 3.11+, FastAPI, uvicorn, asyncssh, sqlite3 (stdlib), Jinja2 + HTMX (vendored, no build step), argon2-cffi, itsdangerous (session cookie), official `mcp` Python SDK, pytest + pytest-asyncio, Docker (linux/arm64 + amd64), GitHub Actions → GHCR.

**Spec:** `docs/superpowers/specs/2026-11-17-wakeboard-design.md`

## Global Constraints

- Single container, ~100 MB RAM target on a Raspberry Pi 3B; images built for `linux/arm64` and `linux/amd64`.
- `docker-compose.yml` uses `network_mode: host` (WoL UDP broadcast must reach the LAN).
- All state in one volume `/data`: SQLite DB, SSH keys (mode 0600), `known_hosts`.
- Web UI: ONE shared password (argon2 hash), signed session cookie, login rate-limit/lockout, no usernames.
- MCP + REST: separate bearer token, generated and rotatable in the UI; never unauthenticated.
- MCP served as streamable HTTP at `/mcp`. UI is server-rendered Jinja2 + HTMX, no JS build step, mobile-friendly.
- Never store plaintext passwords (UI password hashed; enrollment password used for one connection and discarded).
- `shutdown`/`reboot` on a group or `all` require `confirm=true` (MCP/REST) or a confirm dialog (UI).
- A device flagged `self` (or detected as hosting the app) is excluded from `all` and needs explicit single-target confirmation.
- `run_command` is allowed only on devices with the per-device flag set (default off).
- Never report "wake sent" as success unless the machine came up: wake reports per-stage results (magic packet → ping → SSH → proxmox `pvesh`), timeout default 5 min; magic packet sent 3x.
- Status poll default 30 s (ICMP/TCP-22). Graceful Proxmox shutdown guest timeout default 120 s, then force-stop, then `shutdown -h now`, then confirm ping fails.
- Host keys pinned trust-on-first-use; a changed key is a hard error requiring UI acknowledgement.
- Device model fields: name (unique), host, ssh user/port, MAC, optional broadcast IP, type (`proxmox`|`linux`), tags/groups, key (global or per-device), `run_command` allowed (default off), shutdown mode (`graceful-proxmox` default for proxmox | `plain`), notes, `bios_verified`.
- Audit log row: time, caller (`ui`|`mcp`|`api`), target, action, result.
- Commits per task; MIT license only if repo made public (private by default).

## Review Focus

1. Unknown target name / empty `all` (zero devices) → clear "no such target" / "no devices" error, never a silent no-op reported as success. (Task 2)
2. MAC address in any common format (`aa:bb:..`, `AA-BB-..`, `aabb.ccdd.eeff`) or invalid → normalized or rejected on save. (Task 3)
3. Shutdown/reboot of a device that is already down, or SSH unreachable → reported as such, not as a successful shutdown. (Task 7)
4. Graceful Proxmox shutdown with zero running guests, and with a guest that ignores the shutdown until timeout → still proceeds; stuck guest is force-stopped. (Task 7)
5. Changed host key, non-UTF8 command output, concurrent actions on the same device → hard error / decoded safely / serialized per device. (Tasks 5, 7)

---

## File Structure

```
pyproject.toml  Dockerfile  docker-compose.yml  README.md  .github/workflows/image.yml
src/wakeboard/
  config.py      Settings (data dir, env vars, default timeouts)
  db.py          sqlite connection + versioned migrations
  devices.py     Device dataclass, DeviceRepo CRUD, validation (MAC normalize)
  targets.py     resolve_targets(): name | tag | all, self-exclusion
  audit.py       AuditLog write/list
  wol.py         magic packet build + send
  auth.py        password hash, session signing, bearer token, lockout
  sshkeys.py     global/per-device ed25519 keys, TOFU known_hosts
  ssh.py         SshRunner: run(), enroll_with_password(), sudo detection
  status.py      Prober (up/down) + collect_info()
  actions.py     wake / shutdown / reboot / graceful proxmox, per-device locks
  wolcheck.py    ethtool WoL readiness + wake test
  service.py     Service facade used by all adapters
  api.py         REST router (bearer token)
  mcp_server.py  MCP tools mounted at /mcp
  web/           routes.py, templates/, static/ (htmx.min.js vendored)
  main.py        create_app(), poller lifespan
tests/           one test module per source module + conftest.py (fakes, asyncssh test server)
```

---

### Task 1: Scaffold, settings, database

**Files:**
- Create: `pyproject.toml`, `src/wakeboard/__init__.py`, `src/wakeboard/config.py`, `src/wakeboard/db.py`, `tests/conftest.py`, `tests/test_db.py`, `.gitignore`

**Interfaces:**
- Produces: `Settings(data_dir: Path, poll_interval: int = 30, wake_timeout: int = 300, guest_timeout: int = 120)` with `Settings.from_env()` (env `WAKEBOARD_DATA`, default `/data`); `connect(path: Path) -> sqlite3.Connection` (row_factory=Row, WAL, foreign keys on) that applies migrations and sets `PRAGMA user_version`; pytest fixture `settings` (tmp data dir) and `conn`.

- [ ] **Step 1: Write failing test** `tests/test_db.py::test_connect_creates_schema_and_is_idempotent`: connect twice on same file; assert tables `devices`, `audit`, `kv` exist and `user_version == len(MIGRATIONS)`; `test_settings_from_env` sets `WAKEBOARD_DATA` and asserts `data_dir`.
- [ ] **Step 2: Run** `pytest tests/test_db.py -v` → FAIL (module missing).
- [ ] **Step 3: Implement** `pyproject.toml` (deps above, `pytest` asyncio_mode=auto, src layout), `Settings`, and `db.connect` with a `MIGRATIONS: list[str]` list. Migration 1 creates `devices` (columns per Device model above; `groups` stored as comma-joined text, `host_key_ack` flag), `audit(id, ts, caller, target, action, result)`, `kv(key PRIMARY KEY, value)` (holds password hash, token hash, session secret, login lockout state).
- [ ] **Step 4: Run** tests → PASS.
- [ ] **Step 5: Commit** `feat: scaffold project, settings, sqlite migrations`

### Task 2: Device repo, target resolution, audit log

**Files:**
- Create: `src/wakeboard/devices.py`, `targets.py`, `audit.py`, `tests/test_devices.py`, `tests/test_targets.py`, `tests/test_audit.py`

**Interfaces:**
- Consumes: `connect()` from Task 1.
- Produces:
  - `@dataclass Device(name, host, ssh_user="root", ssh_port=22, mac=None, broadcast=None, type="linux", groups: list[str]=[], key_id: str|None=None, allow_run_command=False, shutdown_mode="plain", notes="", bios_verified=False, is_self=False, id: int|None=None)`; `type` validated in `{"proxmox","linux"}`; `shutdown_mode` default becomes `"graceful-proxmox"` when type is proxmox and not given.
  - `DeviceRepo(conn)`: `add(Device)->Device`, `get(name)->Device|None`, `update(Device)`, `remove(name)`, `list()->list[Device]`; duplicate name raises `DuplicateDevice`.
  - `resolve_targets(repo, target: str) -> list[Device]` — name, group/tag, or `"all"` (excludes `is_self`); raises `UnknownTarget` (no match) / `NoDevices` (`all` on empty or all-self).
  - `is_bulk(target: str, repo) -> bool` — true for `all` or a group name matching more than one device or a group.
  - `AuditLog(conn)`: `record(caller, target, action, result)`, `list(limit=200)->list[dict]` newest first.

- [ ] **Step 1: Write failing tests:** `test_add_get_roundtrip`, `test_duplicate_name_rejected`, `test_proxmox_defaults_to_graceful`, `test_resolve_by_name`, `test_resolve_group_returns_members`, `test_all_excludes_self`, `test_all_with_only_self_raises_nodevices`, `test_unknown_target_raises` (Review Focus 1), `test_audit_newest_first`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** the three modules; groups matched case-insensitively; a device name takes precedence over a group of the same name.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: device repo, target resolution, audit log`

### Task 3: Wake-on-LAN packet

**Files:**
- Create: `src/wakeboard/wol.py`, `tests/test_wol.py`

**Interfaces:**
- Produces: `normalize_mac(s: str) -> str` (lowercase `aa:bb:cc:dd:ee:ff`; raises `ValueError`); `magic_packet(mac: str) -> bytes` (6×0xFF + 16×MAC, 102 bytes); `send_magic(mac, broadcast: str|None=None, repeat=3, sock_factory=socket.socket) -> None` (UDP port 9, `SO_BROADCAST`, default `255.255.255.255`).
- Update `devices.Device` validation to call `normalize_mac` on save (Review Focus 2).

- [ ] **Step 1: Write failing tests:** `test_magic_packet_layout` (len 102, header, repeated MAC), `test_normalize_accepts_dash_colon_dot_formats` (`AA-BB-CC-DD-EE-FF`, `aabb.ccdd.eeff`, `aabbccddeeff`), `test_normalize_rejects_garbage`, `test_send_magic_sends_three_packets_to_broadcast` using a fake socket recording `sendto`, `test_device_rejects_invalid_mac`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: wake-on-lan magic packet`

### Task 4: Authentication

**Files:**
- Create: `src/wakeboard/auth.py`, `tests/test_auth.py`

**Interfaces:**
- Consumes: `kv` table from Task 1.
- Produces `AuthStore(conn, now=time.time)`:
  - `password_set() -> bool`, `set_password(pw)` (argon2 hash into kv), `check_password(pw, client_ip) -> bool` — after 5 consecutive failures per IP, lockout 15 min raises `LockedOut(retry_after: int)` even for the correct password.
  - `new_session() -> str` / `valid_session(cookie) -> bool` (itsdangerous-signed, secret generated once in kv, max-age 7 days).
  - `rotate_token() -> str` (returns plaintext once; stores sha256 hash); `check_token(token: str|None) -> bool` (constant-time).
  - Initial password from env `WAKEBOARD_PASSWORD` applied by `main` only if unset.

- [ ] **Step 1: Write failing tests:** `test_password_hash_not_plaintext_in_db`, `test_check_password_ok_and_bad`, `test_lockout_after_five_failures_even_with_correct_password`, `test_lockout_expires` (injected clock), `test_session_roundtrip_and_tamper_rejected`, `test_token_rotation_invalidates_old`, `test_check_token_none_false`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: password, session, bearer-token auth with lockout`

### Task 5: SSH keys, TOFU host keys, runner, enrollment

**Files:**
- Create: `src/wakeboard/sshkeys.py`, `src/wakeboard/ssh.py`, `tests/test_ssh.py`; extend `tests/conftest.py` with an in-process `asyncssh` server fixture (`ssh_server`: accepts a given public key or password, records commands, returns canned output per command, exposes its host key, can swap host key).

**Interfaces:**
- Produces:
  - `KeyStore(data_dir)`: `ensure_global() -> None` (ed25519, file mode 0600, idempotent), `public_key(key_id: str|None=None) -> str` (OpenSSH line), `private_path(key_id) -> Path`, `authorize_command(key_id=None) -> str` (the `mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '<pub>' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys` one-liner).
  - `class HostKeyChanged(Exception)`, `class SudoRequired(Exception)`.
  - `@dataclass RunResult(stdout: str, stderr: str, exit: int)`.
  - `SshRunner(keystore, known_hosts: Path)`: `async run(device, cmd, timeout=30) -> RunResult` (decodes with `errors="replace"`; first connect pins host key into `known_hosts`; mismatch raises `HostKeyChanged` unless device `host_key_ack` was set); `async enroll_with_password(device, password) -> None` (connects once with password, appends public key idempotently, closes; password never persisted or logged); `async sudo_ok(device) -> bool` (`sudo -n true` for non-root users).
  - `acknowledge_host_key(device)` clears the pinned entry so the next connect re-pins.

- [ ] **Step 1: Write failing tests:** `test_global_key_created_0600_and_idempotent`, `test_authorize_command_contains_pubkey`, `test_run_returns_stdout_exit`, `test_first_connect_pins_host_key`, `test_changed_host_key_raises` (Review Focus 5), `test_acknowledge_then_repins`, `test_enroll_with_password_installs_key_then_key_login_works`, `test_enroll_twice_does_not_duplicate_key`, `test_non_utf8_output_decoded_with_replacement`, `test_sudo_ok_false_when_prompt_required`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** with `asyncssh.generate_private_key("ssh-ed25519")` and `asyncssh.connect(known_hosts=...)` using a custom TOFU `known_hosts` handling (read file; if host absent, connect with host-key capture and append).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: ssh key store, TOFU host keys, runner, password enrollment`

### Task 6: Status probing and rich info

**Files:**
- Create: `src/wakeboard/status.py`, `tests/test_status.py`

**Interfaces:**
- Consumes: `SshRunner.run`, `Device`.
- Produces: `Prober(ping=…, tcp=…)` with `async is_up(device) -> bool` (TCP connect to ssh port within 2 s OR ICMP; both injectable); `@dataclass Info(uptime_s, load1, mem_used_pct, disk_root_pct, cpu_temp_c|None, kernel, pve_version|None, vms_running|None, cts_running|None, fetched_at)`; `async collect_info(runner, device) -> Info` (one SSH call running a compound command; PVE fields only when `device.type == "proxmox"`; missing temp sensor → `None`, not an error); `InfoCache(ttl=60)` with `get(name)`/`put(name, Info)`; `Poller` coroutine `run(repo, prober, state: dict[str,bool], interval)` updating an in-memory up/down map.

- [ ] **Step 1: Write failing tests:** `test_is_up_true_when_tcp_connects`, `test_is_up_false_on_timeout`, `test_collect_info_parses_linux_output`, `test_collect_info_parses_proxmox_counts`, `test_missing_temp_is_none`, `test_info_cache_expires`, `test_poller_updates_state_for_all_devices`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement**; parsing is a pure function `parse_info(text, is_proxmox) -> Info` tested directly on fixture strings.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: status probing, rich info collection, poller`

### Task 7: Actions — wake, shutdown, reboot, graceful Proxmox

**Files:**
- Create: `src/wakeboard/actions.py`, `tests/test_actions.py`

**Interfaces:**
- Consumes: `send_magic`, `Prober.is_up`, `SshRunner.run`, `Settings`, `AuditLog`.
- Produces:
  - `@dataclass StageResult(stage: str, ok: bool, detail: str = "")` and `@dataclass ActionResult(ok: bool, stages: list[StageResult])`.
  - `Actions(runner, prober, settings, sleep=asyncio.sleep, clock=time.monotonic)`:
    - `async wake(device, progress=None) -> ActionResult` — stages `magic_packet`, `ping`, `ssh`, and for proxmox `pvesh` (`pvesh get /version`); each polled until `settings.wake_timeout`; later stages are not attempted after a failed stage; overall `ok` only if all stages ok.
    - `async shutdown(device, mode: str|None=None, progress=None) -> ActionResult` — if device already down returns `ok=False` stage `precheck` "already down" (Review Focus 3); `plain` → `shutdown -h now` (prefixed `sudo -n` for non-root); `graceful-proxmox` → list running guests (`qm list`/`pct list`), `qm|pct shutdown <id>` each, wait up to `settings.guest_timeout`, force `qm|pct stop` any remaining, then `shutdown -h now`; final stage `down` confirms ping fails within timeout. Zero guests proceeds directly (Review Focus 4).
    - `async reboot(device, progress=None) -> ActionResult` (`reboot`, then waits down→up).
  - Per-device `asyncio.Lock`; a second action on a locked device returns `ActionResult(ok=False, stages=[StageResult("lock", False, "action in progress")])` instead of queuing (Review Focus 5).
  - `progress` is an optional `Callable[[StageResult], None]`.

- [ ] **Step 1: Write failing tests with fake runner/prober/clock:** `test_wake_all_stages_ok`, `test_wake_stops_at_ping_timeout_reports_failure` (never reports success if host never up), `test_wake_sends_three_packets`, `test_shutdown_plain_issues_shutdown_command`, `test_shutdown_down_device_reports_already_down`, `test_graceful_stops_guests_then_shutdown_in_order`, `test_graceful_zero_guests_goes_straight_to_shutdown`, `test_graceful_force_stops_guest_after_timeout`, `test_shutdown_reports_failure_if_host_still_up_after_timeout`, `test_non_root_uses_sudo_n`, `test_concurrent_action_rejected_by_lock`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement**; guest-list parsing as pure helpers `parse_qm_list(text)->list[int]` / `parse_pct_list` (running only), unit-tested with real command output samples.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: wake, shutdown, reboot, graceful proxmox actions`

### Task 8: WoL readiness check and wake test

**Files:**
- Create: `src/wakeboard/wolcheck.py`, `tests/test_wolcheck.py`

**Interfaces:**
- Consumes: `SshRunner.run`, `Actions.shutdown/wake`, `DeviceRepo.update`.
- Produces: `@dataclass WolReport(nic: str|None, mac: str|None, supported: bool, current_flags: str, persistent: bool|None, notes: list[str])`; `async wol_check(runner, device) -> WolReport` (finds NIC by MAC via `ip -o link`; `ethtool <nic>` parse `Supports Wake-on` / `Wake-on` (expects `g`); persistence checked by grepping systemd `.link`/networkd and `/etc/network/interfaces` for `wol`/`ethtool -s … wol g`; captures MAC when device has none); `parse_ethtool_wol(text) -> tuple[str,str]`; `async wake_test(actions, repo, audit, device) -> ActionResult` — shutdown → wait down → wake → verify up, stamps `wake_test_result` and `wake_test_at` on the device (add both columns via migration 2 in `db.py`). Refuses to run on `is_self` devices.

- [ ] **Step 1: Write failing tests:** `test_parse_ethtool_wol_g`, `test_parse_ethtool_wol_d_flags_not_ready`, `test_wol_check_captures_mac_when_missing`, `test_wol_check_flags_non_persistent`, `test_wake_test_stamps_pass_result`, `test_wake_test_stamps_fail_when_never_wakes` (the m2000 case), `test_wake_test_refuses_self`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: WoL readiness check and wake test`

### Task 9: Service facade and REST API

**Files:**
- Create: `src/wakeboard/service.py`, `src/wakeboard/api.py`, `src/wakeboard/main.py`, `tests/test_service.py`, `tests/test_api.py`

**Interfaces:**
- Consumes: everything above.
- Produces `Service` with methods (all return plain dicts/dataclasses, all write an audit row with the given `caller`): `list_devices()`, `device_status(target)`, `wake(target, caller)`, `shutdown(target, caller, mode=None, confirm=False)`, `reboot(target, caller, confirm=False)`, `wake_check(target, caller)`, `run_command(target, cmd, caller)`.
  - Raises `ConfirmationRequired` when `is_bulk(target)` and not `confirm` for shutdown/reboot; raises `SelfTargetRefused` when the target resolves to an `is_self` device and `confirm` is false (explicit single-target confirmation); `RunCommandDisabled` when the device flag is off. Multi-device actions run concurrently and return per-device results.
  - Hypervisor-hosting-self warning: `Device.is_self` also set when `Service.detect_self(devices)` finds a device whose host matches a local interface IP; the warning text is included in the `ConfirmationRequired`/`SelfTargetRefused` message.
- REST (`/api/v1`, `Authorization: Bearer`): `GET /devices`, `GET /devices/{target}/status`, `POST /wake`, `/shutdown`, `/reboot`, `/wake_check`, `/run_command` with JSON bodies `{target, confirm?, mode?, cmd?}`; 401 without valid token, 409 for confirmation required, 404 unknown target.
- `main.create_app(settings) -> FastAPI` wires poller (lifespan), applies `WAKEBOARD_PASSWORD` if unset, mounts API, MCP, web.

- [ ] **Step 1: Write failing tests:** `test_shutdown_all_without_confirm_raises`, `test_shutdown_group_without_confirm_raises`, `test_shutdown_all_skips_self_device`, `test_shutdown_self_requires_confirm_with_warning`, `test_run_command_disabled_by_default`, `test_every_action_audited_with_caller`, API: `test_api_requires_token`, `test_api_confirm_required_returns_409`, `test_api_unknown_target_404`, `test_api_status_ok`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** Service and router; Service takes its collaborators in the constructor so tests inject fakes.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: service layer and REST API`

### Task 10: MCP server

**Files:**
- Create: `src/wakeboard/mcp_server.py`, `tests/test_mcp.py`

**Interfaces:**
- Consumes: `Service`, `AuthStore.check_token`.
- Produces: `build_mcp(service, auth) -> ASGI app` mounted at `/mcp` (streamable HTTP, bearer-token middleware, 401 otherwise). Tools exactly: `list_devices`, `device_status(target)`, `wake(target)`, `shutdown(target, mode?, confirm?)`, `reboot(target, confirm?)`, `wake_check(target)`, `run_command(target, cmd)`; errors (`ConfirmationRequired`, `UnknownTarget`, etc.) returned as tool errors with the message. Caller recorded as `mcp`.

- [ ] **Step 1: Write failing tests** using the MCP SDK client against the ASGI app: `test_tools_listed`, `test_mcp_rejects_missing_token`, `test_shutdown_all_without_confirm_is_tool_error`, `test_wake_unknown_target_tool_error`, `test_run_command_disabled_tool_error`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** with `FastMCP` and its streamable-HTTP ASGI app.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: MCP server`

### Task 11: Web UI

**Files:**
- Create: `src/wakeboard/web/routes.py`, `web/templates/{base,login,setup,dashboard,device,device_form,audit,settings}.html`, `web/static/{htmx.min.js,style.css}`, `tests/test_web.py`

**Interfaces:**
- Consumes: `Service`, `AuthStore`, `KeyStore`, `SshRunner`, `DeviceRepo`, `AuditLog`.
- Produces routes (cookie-session protected except `/login`, `/setup`): `GET /` dashboard (cards: state, uptime, quick Wake/Shutdown, bulk actions; HTMX polls `/partials/cards` every 5 s); `GET|POST /devices/new` (add wizard); `GET /devices/{name}` detail (info, enrollment command, "Enroll with password once", WoL check, "Run wake test", history, host-key acknowledge button); `POST /devices/{name}/{wake|shutdown|reboot|wol-check|wake-test|enroll}`; `GET /audit`; `GET|POST /settings` (change password, rotate/show MCP token once, defaults, show global public key); `GET|POST /setup` first-run password page shown only while `password_set()` is false; `POST /login` handles `LockedOut` with a message and 429.
- Destructive buttons carry `hx-confirm`; bulk and self actions go through a server-rendered confirm page and pass `confirm=true`. Self device shows a warning badge.

- [ ] **Step 1: Write failing tests** (FastAPI TestClient, fake Service): `test_redirects_to_login_when_unauthenticated`, `test_setup_only_when_no_password`, `test_login_sets_cookie_and_dashboard_renders_devices`, `test_login_lockout_returns_429`, `test_add_device_then_visible`, `test_shutdown_button_has_confirm_attr`, `test_bulk_shutdown_requires_confirm_page`, `test_enroll_password_not_in_response_or_audit`, `test_token_shown_once_on_rotate`, `test_audit_page_lists_entries`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** routes/templates; viewport meta + single responsive CSS file; vendored htmx pinned (version noted in README).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: web dashboard UI`

### Task 12: Packaging, CI, docs, end-to-end smoke

**Files:**
- Create: `Dockerfile`, `docker-compose.yml`, `.github/workflows/image.yml`, `README.md`, `tests/test_e2e.py`; optionally `LICENSE` is NOT added (private by default).

**Interfaces:**
- Consumes: `create_app`.
- Produces: image `ghcr.io/<owner>/wakeboard` for `linux/arm64,linux/amd64` (buildx + QEMU, push on tag/main); compose with `network_mode: host`, volume `./data:/data`, env `WAKEBOARD_PASSWORD`; `uvicorn wakeboard.main:app` entry on port 8080 (env `WAKEBOARD_PORT`).
- README sections: what it is, Pi 3B install (64-bit Raspberry Pi OS Lite, Docker, compose), first run/setup, adding a device + both enrollment methods, enabling WoL on a node (ethtool + persistence + BIOS Deep Sleep Control note), `tailscale serve` HTTPS, Funnel warning, MCP connection (`claude mcp add --transport http wakeboard https://<host>/mcp --header "Authorization: Bearer <token>"`), safety model (confirm, self exclusion).

- [ ] **Step 1: Write failing e2e test** `tests/test_e2e.py::test_add_device_enroll_wake_shutdown_via_rest` — real app + asyncssh test server + fake socket: create password/token, add device, enroll with password, `POST /shutdown` for one device (ok), `POST /shutdown` target `all` without confirm → 409, with confirm → 200, audit lists all three.
- [ ] **Step 2: Run** `pytest tests/test_e2e.py -v` → FAIL.
- [ ] **Step 3: Fix wiring gaps** found in `create_app`; write Dockerfile (python:3.12-slim, non-root-free since SSH keys under /data, `iputils-ping` installed) and compose/CI/README as listed.
- [ ] **Step 4: Run** full suite `pytest -q` → all PASS; `docker build .` succeeds locally.
- [ ] **Step 5: Commit** `feat: docker packaging, CI, README, e2e test`

---

## Self-Review Notes

- **Spec coverage:** auth/token/lockout (4), device model (2), SSH+TOFU+enrollment A/B (5), status/info (6), wake stages + graceful shutdown (7), WoL check + wake test (8), MCP tools + confirm/self rules (9, 10), UI pages (11), delivery/Pi/Tailscale docs/GHCR (12). Settings page "defaults" covers poll/timeouts via `kv` overrides read by `Settings` consumers in Task 11.
- **Types:** `Device`, `ActionResult`, `StageResult`, `RunResult`, `Info` names are used identically across tasks.
