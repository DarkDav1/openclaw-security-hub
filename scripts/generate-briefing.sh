#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

if [[ ! -f .env ]]; then
  echo ".env is missing. Copy .env.example to .env first." >&2
  exit 1
fi

set -a
source ./.env
set +a

HUB_URL="${HUB_URL:-http://${TAILSCALE_IP:-127.0.0.1}:${SECURITY_HUB_PORT:-8099}}"

curl -sS -X POST "${HUB_URL}/briefing/daily?send_to_telegram=true" \
  -H "X-Security-Hub-Secret: ${SECURITY_HUB_WEBHOOK_SECRET}"
echo
