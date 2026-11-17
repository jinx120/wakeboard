# Wakeboard — design

Working name (my call; rename freely). Self-hosted power controller for homelab machines:
web dashboard + REST + MCP server, so Claude can wake / shut down / inspect devices.

## Intent
Control WoL wake-up and SSH shutdown of 3–4 Proxmox nodes (ib250mh, m91p, opti3010, m2000/z420)
by telling Claude "power off node X / all", and from a web UI. Generic enough to be a reusable
GitHub app for any number of Linux/Proxmox devices. Runs in a VM first, then on a Raspberry Pi 3B
(the Pi is the real home: always on, same LAN, so it can wake nodes that are fully off).

## Goals
- Web UI: add/edit/remove devices, enroll SSH access, see status/info, trigger wake/shutdown/reboot, audit log, settings.
- Access via Tailscale with ONE shared password, no user accounts.
- MCP tools for Claude: list/status/wake/shutdown/reboot/wake_check/run_command, by name, group, or `all`.
- Passwordless SSH: app owns an ed25519 key; UI shows a one-line command per node to authorize it,
  or "enroll with password once" (password used for that one connection, never stored).
- Graceful Proxmox shutdown (stop guests, then power off) as well as plain shutdown.
- WoL readiness check per node, plus real wake-test verification.
- Runs in ~100 MB RAM on a Pi 3B; one container; multi-arch (arm64 + amd64).

## Non-goals
Multi-user/roles, public-internet exposure by default, BIOS/IPMI/AMT control, Windows targets,
VM-level (guest) management beyond stop-all-guests-before-shutdown, cluster/HA awareness.

## Anti-goals (failure even if it "works")
- Reports "wake sent" when the machine never came up.
- Claude can power off everything in one unconfirmed call.
- Stored plaintext passwords; unauthenticated MCP/API.
- App shuts down the host it runs on (or the hypervisor hosting its own VM) without a loud warning.

## Approaches considered
- **A. Python (FastAPI + asyncssh + SQLite), one Docker container, MCP in-process. — chosen (my call).** Same language as the user's other projects; fine on Pi 3B; one shared device-logic layer for UI/REST/MCP.
- B. Go static binary: smallest footprint, but slower to build and not the user's language.
- C. Node/TS: good MCP tooling but heavier on a Pi 3B, no advantage over A.

## Design

### Stack (my calls)
FastAPI, asyncssh, SQLite, official MCP Python SDK (streamable HTTP at `/mcp`), server-rendered
Jinja2 + HTMX (no JS build step, light on Pi). Docker image built for linux/arm64 + amd64;
compose file uses `network_mode: host` (required so WoL UDP broadcast reaches the LAN; bridge
networking won't). Recommended Pi OS: 64-bit Raspberry Pi OS Lite. Data in one volume (`/data`):
SQLite DB, SSH keys (0600), known_hosts.

### Auth & network
- Web UI: single shared password (argon2 hash; set via env on first run or a first-run setup page).
  Signed session cookie, login rate-limiting/lockout. No usernames.
- MCP + REST API: separate bearer token, generated in the UI, rotatable (Claude can't do cookie login).
- Intended exposure: Tailscale only. Docs recommend `tailscale serve` for HTTPS on the tailnet.
  Tailscale Funnel (needed for claude.ai web connector) documented as optional with a warning.
- Destructive actions: `shutdown`/`reboot` targeting a group or `all` require `confirm=true`
  (MCP) / a confirm dialog (UI). A device flagged `self` (or detected as hosting the app) is
  excluded from `all` and requires explicit single-target confirmation.

### Device model
name (unique), host (IP/DNS/tailscale name), ssh user/port, MAC, optional broadcast IP,
type (`proxmox` | `linux`), tags/groups, key (global or per-device), `run_command` allowed (default off),
shutdown mode (`graceful-proxmox` default for proxmox | `plain`), notes, `bios_verified` checkbox.

### SSH & enrollment
- Global ed25519 keypair generated on first run (per-device override possible).
- Enroll A: UI displays `echo '<pubkey>' >> ~/.ssh/authorized_keys` (and mkdir/chmod) to paste on the node.
- Enroll B: enter password once; app connects, installs the key, discards the password.
- Host keys pinned trust-on-first-use; changed key = hard error needing UI acknowledgement.
- Requires root or passwordless-sudo user on target; the app tells the user if sudo prompts.

### Status & info
- Cheap poll (default 30 s): ICMP/TCP-22 → up/down. Rich info fetched over SSH on demand and on
  page view (cached): uptime, load, memory, root disk, CPU temp, kernel, PVE version, running VM/CT counts.
- Wake flow: send magic packet (repeat 3x) → poll ping → SSH → (proxmox) API/`pvesh` → report
  per-stage result with timeout (default 5 min) instead of fire-and-forget.
- Graceful Proxmox shutdown: `qm list`/`pct list` → `qm shutdown`/`pct shutdown` each running guest
  with timeout (default 120 s, then force-stop) → `shutdown -h now`; reports progress; confirms node went down (ping fails).

### WoL readiness check (per device)
Over SSH: NIC name for MAC, `ethtool` Wake-on-LAN supported/current flags (expect `g`), whether it
persists (checks for systemd/networkd/ifupdown setting), MAC captured automatically. BIOS Deep Sleep
Control cannot be read remotely → manual `bios_verified` checkbox; "Run wake test" does shutdown →
wait → wake → verify and stamps result + timestamp (this is what exposed m2000's failure earlier).

### MCP tools
`list_devices`, `device_status(target)`, `wake(target)`, `shutdown(target, mode?, confirm?)`,
`reboot(target, confirm?)`, `wake_check(target)`, `run_command(target, cmd)` (only on devices that
allow it). `target` = name | tag/group | `all`. All actions written to an audit log
(time, caller [ui/mcp], target, action, result), viewable in the UI.

### UI pages
Dashboard (device cards: state, uptime, quick Wake/Shutdown, bulk actions) · Device detail/edit
(info, enroll, WoL check, wake test, history) · Add device wizard · Audit log · Settings
(password, MCP token, defaults, global key). Mobile-friendly.

### Delivery
Own GitHub repo (private by default, my call; MIT license if made public), README with Pi 3B
install, compose file, GHCR image via GitHub Actions. Phase 1: VM; phase 2: Pi (same image).
Tests: unit tests for target resolution, shutdown ordering, WoL packet, auth; SSH tested against a
mock/containerized sshd.

## Left to the builder
Exact schema/migrations, UI visual styling, polling/timeouts tuning, repo/CI details, name bikeshed.
