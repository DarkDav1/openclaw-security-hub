# Test Plan

This project is tested as a homelab security workflow, not only as a web API.

## Done Criteria

- The Security Hub container starts cleanly and stays healthy.
- `/health` and `/status` respond from the Tailscale address.
- A generic webhook creates an OpenClaw review note, an event record, dashboard data, and a Telegram alert.
- A security posture scan creates:
  - `security-alerts/reports/YYYY-MM-DD-security-posture.md`
  - `security-alerts/queue/queue.json`
  - `security-alerts/latest.md`
  - `dashboard/security-alerts.json`
- A NIST CSF 2.0 scan creates:
  - `security-alerts/reports/YYYY-MM-DD-nist-csf-2.0-profile.md`
  - `security-alerts/queue/nist-csf-profile.json`
  - `security-alerts/queue/nist-csf-gap-backlog.json`
  - NIST status fields in `security-alerts/queue/queue.json`
- The daily briefing includes event counts, open review counts, and posture findings.
- Unit tests pass inside the same Docker image used by the service.
- Secrets stay in `.env` and are not committed.

## Automated Tests

Run:

```bash
scripts/run-tests.sh
```

The tests verify:

- Linux `/proc/net/tcp` address parsing.
- SSH hardening directive matching.
- Risky exposed service detection.
- OpenClaw queue and dashboard JSON generation.
- NIST CSF function coverage across GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, and RECOVER.
- NIST CSF profile JSON generation.
- NIST CSF Current/Target Profile fields and gap backlog priority sorting.

## Manual End-to-End Tests

Run these after deployment:

```bash
curl -sS http://100.77.103.17:8099/health
curl -sS http://100.77.103.17:8099/status
scripts/test-alert.sh
scripts/security-scan.sh
scripts/nist-csf-check.sh
scripts/generate-briefing.sh
```

Then confirm:

- Telegram receives the test alert.
- `~/.openclaw/workspace/security-alerts/inbox` contains a new review note.
- `~/.openclaw/workspace/security-alerts/events/events.jsonl` has the new event.
- `~/.openclaw/workspace/security-alerts/queue/queue.json` is valid JSON.
- `~/.openclaw/workspace/security-alerts/queue/nist-csf-profile.json` is valid JSON.
- `~/.openclaw/workspace/security-alerts/queue/nist-csf-gap-backlog.json` is valid JSON.
- `~/.openclaw/workspace/security-alerts/latest.md` gives OpenClaw a concise current queue.
- Docker logs do not print secrets.

For the NIST CSF check, confirm the report clearly says it is a CSF-aligned self-assessment, not a certification or formal compliance attestation.

## Security Regression Checks

After local hardening, the expected posture is:

- No Samba, XRDP, GNOME Remote Desktop, or Ollama listener.
- SSH is only reachable over Tailscale.
- Security Hub is reachable over Tailscale on port `8099`.
- OpenClaw gateway remains bound to localhost.
- UFW default incoming policy remains deny.
