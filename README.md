# Wakeboard

Power controller for homelab machines. Wakeboard wakes machines (Wake-on-LAN), shuts
them down (plain, or gracefully for Proxmox VE nodes: guests first, then the host),
reboots them, and shows their status. You can drive it from three places:

- a web UI at `/` (password login),
- a REST API at `/api/v1` (bearer token),
- an MCP server at `/mcp` (streamable HTTP, same bearer token), so an AI agent can use it.

Each action is a sequence of checked stages (magic packet, ping, SSH, `pvesh`, guests
stopped, host down...). An action reports success only when the machine actually reached
the requested state. Every action is written to an audit log.

Vendored front-end: htmx 2.0.4 (`src/wakeboard/web/static/htmx.min.js`,
sha256 `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447`);
see `src/wakeboard/web/static/VENDORED.txt`. The UI loads nothing from external hosts.

## Install on a Raspberry Pi 3B

1. Flash **Raspberry Pi OS Lite (64-bit)** with Raspberry Pi Imager. In the Imager
   settings, turn on SSH and set a user. The 3B needs the 64-bit OS for the
   `linux/arm64` image.
2. Wire the Pi to the same LAN (layer-2 broadcast domain) as the machines you want to
   wake. Magic packets are broadcasts and do not cross routers.
3. Install Docker and the compose plugin:

   ```sh
   curl -fsSL https://get.docker.com | sh
   sudo usermod -aG docker "$USER"   # log out and back in
   ```

4. Create a directory with a `docker-compose.yml`. Copy the one from this repo and
   replace `OWNER` in the image name with the GitHub owner that publishes the image:

   ```sh
   mkdir -p ~/wakeboard && cd ~/wakeboard
   # copy docker-compose.yml here
   echo 'WAKEBOARD_PASSWORD=change-me-to-something-long' > .env
   docker compose up -d
   ```

The compose file uses `network_mode: host`, which lets WoL broadcasts and ping reach the
LAN. It keeps all state in `./data` (mounted at `/data`): the SQLite database, Wakeboard's
SSH keys and its `known_hosts`. Back up that directory and keep it private.

The container runs as root because it needs raw-socket ping and host networking, and its
SSH keys live under `/data`. The image is published as `ghcr.io/<owner>/wakeboard` for
`linux/arm64` and `linux/amd64` (see `.github/workflows/image.yml`). To build it yourself
instead, replace `image:` with `build: .` and run `docker compose up -d --build`.

| Variable | Default | Meaning |
|---|---|---|
| `WAKEBOARD_PASSWORD` | unset | Initial UI password. Used only if no password is set yet. |
| `WAKEBOARD_PORT` | `8080` | HTTP port (uvicorn binds `0.0.0.0`). |
| `WAKEBOARD_DATA` | `/data` | State directory. |

## First run

Open `http://<pi>:8080/`. If you did not set `WAKEBOARD_PASSWORD`, the setup page asks you
to choose a password (at least 8 characters). Five wrong logins from the same IP lock that
IP out for 15 minutes.

For the REST API and MCP, go to **Settings → Rotate token**. The token is shown once.
Rotating it again invalidates the old one.

```sh
curl -H "Authorization: Bearer $TOKEN" http://<pi>:8080/api/v1/devices
curl -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"target":"pve1"}' http://<pi>:8080/api/v1/wake
```

Endpoints: `GET /devices`, `GET /devices/{target}/status`, `POST /wake`, `/shutdown`,
`/reboot`, `/wake_check`, `/run_command`. Bodies are `{"target": ..., "confirm": bool,
"mode": ...}`. A target is a device name, a group name, or `all`.
`GET /healthz` is the only unauthenticated endpoint.

## Adding a device

**Add** a device with its name, host (IP or hostname), SSH user/port, MAC address
(needed for wake), optional broadcast address, type (`linux` or `proxmox`), groups and
shutdown mode (`plain` or `graceful-proxmox`). A user other than `root` needs passwordless
sudo (`NOPASSWD`) for `shutdown`, `reboot`, `qm`, `pct` and `pvesh`.

Then enroll Wakeboard's SSH key on the device. The device page offers two methods:

- **Option A: run a command yourself.** The page shows a one-line command (and the public
  key). Run it on the device as the SSH user. It appends the key to
  `~/.ssh/authorized_keys` and is safe to run twice.
- **Option B: enroll with the password once.** Type the device's SSH password. Wakeboard
  uses it for a single connection that installs the key. The password is never stored or
  logged.

On first contact Wakeboard pins the device's SSH host key. If the key later changes (for
example after a reinstall), every connection is refused until you press **Acknowledge changed
host key** on the device page.

## Enabling Wake-on-LAN on a node

Use **WoL check** on the device page. It reports the NIC, its MAC, its current
`Wake-on` flags and whether the setting persists. To enable WoL on a Linux or Proxmox node:

```sh
ethtool eth0 | grep Wake-on          # "Wake-on: g" means enabled
ethtool -s eth0 wol g                # enable now (lost on reboot)
```

To make it persist, use one of these:

- systemd-networkd / udev link file `/etc/systemd/network/50-wol.link`:
  ```ini
  [Match]
  MACAddress=aa:bb:cc:dd:ee:ff
  [Link]
  WakeOnLan=magic
  ```
- ifupdown (Proxmox default), in `/etc/network/interfaces` under the physical NIC:
  `post-up /usr/sbin/ethtool -s eth0 wol g`
- NetworkManager: `nmcli connection modify <conn> 802-3-ethernet.wake-on-lan magic`

Also enable WoL in the BIOS/UEFI (often "Power On by PCI-E", "Wake on LAN" or "Remote
Wake Up"). On many Dell and HP desktops, **Deep Sleep Control** (or "ErP"/"EuP" low-power
mode) cuts power to the NIC when the machine is off, so WoL silently fails even when the
OS settings are right. Disable it. When the BIOS side is done, tick "Wake-on-LAN enabled in
BIOS" on the device, then use **Run wake test**: it shuts the device down and wakes it again
to prove the whole chain works.

## HTTPS with Tailscale

Serve Wakeboard over HTTPS on your tailnet with `tailscale serve`:

```sh
sudo tailscale serve --bg 8080
# -> https://<pi-name>.<tailnet>.ts.net/
```

Once requests arrive over HTTPS, cookies are marked `Secure`. Use the HTTPS URL for the UI
and MCP clients. Plain HTTP on `:8080` stays open on the LAN (the container binds
`0.0.0.0`), so firewall it if the LAN is not trusted. Behind `tailscale serve`, every client
reaches Wakeboard from `127.0.0.1`, so the per-IP login lockout applies to all of them
together.

> **Do not use `tailscale funnel`.** Funnel publishes the service to the whole internet.
> Wakeboard can power off your machines, and its only protection is a password and a
> token. Keep it on the tailnet (or LAN) only.

## MCP connection

With an API token (Settings → Rotate token):

```sh
claude mcp add --transport http wakeboard https://<host>/mcp --header "Authorization: Bearer <token>"
```

Tools: `list_devices`, `device_status`, `wake`, `shutdown`, `reboot`, `wake_check`,
`run_command` (only on devices with "Allow run_command" enabled).

## Safety model

- **Confirmation for bulk destructive actions.** Shutdown or reboot of a group or `all`
  is refused (REST `409`, MCP error) unless `confirm` is the JSON boolean `true`. The
  refusal lists the affected devices. MCP tool descriptions tell the agent to show that
  list to the human and ask before it re-sends with `confirm=true`. The web UI shows a
  confirmation step.
- **Self exclusion.** A "self" device is the machine Wakeboard runs on, or the host it
  runs inside: one marked "self" by hand, or one whose address is a local or loopback
  address. Self devices are always excluded from groups and `all`. To shut down or reboot
  one, name it explicitly with `confirm=true`. Wakeboard cannot wake its own host, and the
  wake test refuses to run on it.
- **Audit first.** The intent of every action is recorded *before* it runs. If the audit
  log cannot be written, the action is refused (`503`).
- **Graceful Proxmox shutdown** stops running VMs/CTs first (`qm|pct shutdown <id>
  --timeout <s>`, then `qm|pct stop <id> --overrule-shutdown 1` for stragglers). The host
  is shut down only when no guest is still running.
  *Note:* these `--timeout` / `--overrule-shutdown` flags follow the PVE documentation
  but have **not yet been verified against a real Proxmox node**. Try a graceful shutdown
  on a non-critical node first.
- `run_command` is off per device unless you enable it. Secrets in commands are redacted
  in the audit log.

## Development

```sh
python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
docker build .
```

The tests never power anything off. SSH goes to an in-process asyncssh server on
127.0.0.1 that answers `shutdown`/`reboot` with a canned reply and never runs them. WoL
packets go to a fake socket.
