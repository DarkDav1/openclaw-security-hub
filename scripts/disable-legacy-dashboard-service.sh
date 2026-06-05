#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${1:-dashboard.service}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run with sudo because ${SERVICE_NAME} is a system service." >&2
  echo "Usage: sudo $0 [service-name]" >&2
  exit 1
fi

if ! systemctl list-unit-files --type=service | awk '{print $1}' | grep -qx "${SERVICE_NAME}"; then
  echo "${SERVICE_NAME} is not installed. Nothing to disable."
  exit 0
fi

echo "Stopping ${SERVICE_NAME}..."
systemctl stop "${SERVICE_NAME}" || true

echo "Disabling ${SERVICE_NAME}..."
systemctl disable "${SERVICE_NAME}" || true

echo "Clearing failed state for ${SERVICE_NAME}..."
systemctl reset-failed "${SERVICE_NAME}" || true

echo
systemctl status "${SERVICE_NAME}" --no-pager || true

echo
echo "Listening sockets on port 8765:"
ss -ltnp | grep -E '(^|:)8765[[:space:]]' || echo "No listener on port 8765."
