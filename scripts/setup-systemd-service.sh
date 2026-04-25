#!/usr/bin/env bash
set -euo pipefail

SERVICE_USER="inferiot"
SERVICE_GROUP="inferiot"
SERVICE_HOME="/var/lib/infer_iot_raw"
DEFAULTS_FILE="/etc/default/infer_iot_raw"
UNIT_FILE="/etc/systemd/system/infer_iot_raw@.service"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_BINARY="${REPO_ROOT}/bin/infer_iot_raw"
BINARY="${BINARY:-$(command -v infer_iot_raw 2>/dev/null || true)}"
INTERFACE="${1:-enx000ec6bc22b0}"
PACKETS="${PACKETS:-100}"
TIMEOUT="${TIMEOUT:-10}"
ROTATE_SIZE="${ROTATE_SIZE:-10M}"
RETAIN_COUNT="${RETAIN_COUNT:-7}"

if [[ -z "$BINARY" && -x "$REPO_BINARY" ]]; then
  BINARY="$REPO_BINARY"
fi

if [[ ! -x "$BINARY" ]]; then
  echo "Binary not found or not executable: $BINARY" >&2
  echo "Install it first with: sudo make install" >&2
  echo "Or override the path explicitly with: BINARY=/path/to/infer_iot_raw $0 [interface]" >&2
  exit 1
fi

BINARY="$(readlink -f "$BINARY")"

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl is required to install the service" >&2
  exit 1
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  sudo useradd --system --home "$SERVICE_HOME" --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

sudo mkdir -p "$SERVICE_HOME"
sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$SERVICE_HOME"

sudo tee "$DEFAULTS_FILE" >/dev/null <<EOF
PACKETS=$PACKETS
TIMEOUT=$TIMEOUT
ROTATE_SIZE=$ROTATE_SIZE
RETAIN_COUNT=$RETAIN_COUNT
EOF

sudo tee "$UNIT_FILE" >/dev/null <<EOF
[Unit]
Description=Infer IoT device details from raw Ethernet traffic on %I
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=inferiot
Group=inferiot
WorkingDirectory=/var/lib/infer_iot_raw
EnvironmentFile=/etc/default/infer_iot_raw
ExecStart=${BINARY} -l -i %I -n \${PACKETS} -t \${TIMEOUT} -o ${SERVICE_HOME}/infer_iot_raw-%I.log --rotate-size \${ROTATE_SIZE} --retain \${RETAIN_COUNT}
Restart=always
RestartSec=2

AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes

PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/infer_iot_raw
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now "infer_iot_raw@${INTERFACE}.service"

cat <<EOF

Service enabled: infer_iot_raw@${INTERFACE}.service
Status:
  sudo systemctl status infer_iot_raw@${INTERFACE}.service
Journal:
  journalctl -u infer_iot_raw@${INTERFACE}.service -f
Log file:
  sudo tail -f ${SERVICE_HOME}/infer_iot_raw-${INTERFACE}.log
Defaults file:
  sudoedit ${DEFAULTS_FILE}
EOF
