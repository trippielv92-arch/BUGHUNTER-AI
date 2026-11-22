#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"

if [[ ! -x "$PYTHON" ]]; then
  echo "Virtual environment not found: $PYTHON" >&2
  exit 1
fi

mkdir -p "$HOME/.config/systemd/user"

cat > "$HOME/.config/systemd/user/bughunter-hunt-worker.service" <<EOF
[Unit]
Description=BugHunter AI Persistent Authorized Hunt Worker
After=default.target

[Service]
Type=simple
WorkingDirectory=$ROOT
ExecStart=$PYTHON -m app.services.hunt_daemon
Restart=always
RestartSec=3
TimeoutStopSec=90
KillSignal=SIGTERM
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now bughunter-hunt-worker.service
if command -v loginctl >/dev/null 2>&1; then
  loginctl enable-linger "$USER" || true
fi

echo "Persistent worker service installed."
echo "Check: systemctl --user status bughunter-hunt-worker.service"
echo "Logs:  journalctl --user -u bughunter-hunt-worker.service -f"
