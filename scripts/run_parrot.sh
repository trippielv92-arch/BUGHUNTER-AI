#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -d .venv ]] || { echo "Run ./scripts/setup_parrot.sh first"; exit 1; }
source .venv/bin/activate
export BUGHUNTER_API_URL="${BUGHUNTER_API_URL:-https://bughunter-ai-ebon.vercel.app}"
exec python -u main.py
