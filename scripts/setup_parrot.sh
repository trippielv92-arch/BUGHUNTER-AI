#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip wheel
python -m pip install -r requirements.txt
mkdir -p data/evidence data/reports data/backups
python -c "from app.database.db import init_db; init_db(); print('Database initialized')"
echo "Setup complete. Launch with ./scripts/run_parrot.sh"
