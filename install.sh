#!/usr/bin/env sh
# Wakeboard native installer: any Linux with Python >= 3.12, no Docker needed.
# Creates a venv, installs wakeboard, and (if systemd is present) a per-user
# service that starts at boot. No root required (ping must be installed).
#
#   ./install.sh                      # install / upgrade, port 8080
#   WAKEBOARD_PORT=9000 ./install.sh  # custom port
#   WAKEBOARD_PASSWORD=... ./install.sh   # initial UI password (first start only)
set -eu

SRC="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${WAKEBOARD_PREFIX:-$HOME/.local/share/wakeboard}"
PORT="${WAKEBOARD_PORT:-8080}"
PY="${PYTHON:-python3}"

"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 12))' 2>/dev/null \
  || { echo "need Python >= 3.12 (set PYTHON=/path/to/python3.12)" >&2; exit 1; }
command -v ping >/dev/null || echo "warning: 'ping' not found; install iputils-ping for status checks" >&2

mkdir -p "$PREFIX/data"
"$PY" -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet --upgrade "$SRC"

# Env file keeps config/secret out of the unit; 0600.
ENVF="$PREFIX/wakeboard.env"
if [ ! -f "$ENVF" ]; then
  umask 077
  { echo "WAKEBOARD_DATA=$PREFIX/data"; echo "WAKEBOARD_PORT=$PORT"
    [ -n "${WAKEBOARD_PASSWORD:-}" ] && echo "WAKEBOARD_PASSWORD=$WAKEBOARD_PASSWORD"
    true; } > "$ENVF"
fi

if command -v systemctl >/dev/null && systemctl --user show-environment >/dev/null 2>&1; then
  UD="$HOME/.config/systemd/user"; mkdir -p "$UD"
  cat > "$UD/wakeboard.service" <<UNIT
[Unit]
Description=Wakeboard power controller
After=network-online.target

[Service]
EnvironmentFile=$ENVF
ExecStart=$PREFIX/venv/bin/uvicorn wakeboard.main:app --host 0.0.0.0 --port \${WAKEBOARD_PORT}
Restart=on-failure

[Install]
WantedBy=default.target
UNIT
  systemctl --user daemon-reload
  systemctl --user enable wakeboard.service >/dev/null 2>&1
  systemctl --user restart wakeboard.service
  loginctl enable-linger "$USER" 2>/dev/null \
    || echo "note: run 'sudo loginctl enable-linger $USER' so it starts at boot without a login" >&2
  echo "installed: systemctl --user status wakeboard   (http://localhost:$PORT)"
else
  echo "no user systemd; run manually:"
  echo "  set -a; . $ENVF; set +a; $PREFIX/venv/bin/uvicorn wakeboard.main:app --host 0.0.0.0 --port \$WAKEBOARD_PORT"
fi
