# OpenClaw Security Hub

OpenClaw Security Hub is a clean homelab security workflow built around OpenClaw as the review workspace.

It receives alerts, watches local SSH failures, checks the OpenClaw gateway, scans local security posture, creates Telegram notifications, and writes structured review notes into the OpenClaw workspace.

## What It Does

- Receives webhook alerts with a request-header secret.
- Monitors `/var/log/auth.log` for repeated SSH login failures.
- Checks whether the OpenClaw gateway is reachable.
- Checks root disk usage.
- Scans local security posture from host `/proc`, SSH configuration, disk usage, and OpenClaw reachability.
- Produces a NIST CSF 2.0-aligned homelab self-assessment with current evidence, gaps, and next actions.
- Sends Telegram alerts.
- Creates OpenClaw review notes in `~/.openclaw/workspace/security-alerts/inbox`.
- Writes event history to `~/.openclaw/workspace/security-alerts/events/events.jsonl`.
- Writes OpenClaw's current work queue to `~/.openclaw/workspace/security-alerts/queue/queue.json`.
- Writes a human-readable queue summary to `~/.openclaw/workspace/security-alerts/latest.md`.
- Writes dashboard data to `~/.openclaw/workspace/dashboard/security-alerts.json`.
- Generates daily security briefings in `~/.openclaw/workspace/security-alerts/briefings`.
- Generates security posture reports in `~/.openclaw/workspace/security-alerts/reports`.
- Generates NIST CSF 2.0 profile reports in `~/.openclaw/workspace/security-alerts/reports`.

## Architecture

```mermaid
flowchart LR
  SSH["auth.log"] --> Hub["OpenClaw Security Hub"]
  Webhook["External webhook"] --> Hub
  Gateway["OpenClaw gateway check"] --> Hub
  Posture["Host security posture scan"] --> Hub
  CSF["NIST CSF 2.0 profile"] --> Hub
  Disk["Disk usage check"] --> Hub
  Hub --> TG["Telegram"]
  Hub --> Inbox["OpenClaw review inbox"]
  Hub --> Events["events.jsonl"]
  Hub --> Queue["OpenClaw queue"]
  Hub --> Reports["Security posture reports"]
  Hub --> CSFReport["CSF profile report"]
  Hub --> Briefing["Daily briefing"]
  Hub --> Dashboard["OpenClaw dashboard JSON"]
```

## Run

```bash
cp .env.example .env
docker compose up -d --build
```

## Test

```bash
scripts/test-alert.sh
scripts/security-scan.sh
scripts/nist-csf-check.sh
scripts/generate-briefing.sh
scripts/run-tests.sh
```

## API

Protected routes require `X-Security-Hub-Secret`.

- `GET /health` - service health and monitor status.
- `GET /status` - event count, open notes, latest event, and posture summary.
- `POST /webhook/generic` - receive a normalized alert.
- `POST /scan/security` - run a security posture scan now.
- `POST /scan/nist-csf` - run a NIST CSF 2.0-aligned self-assessment.
- `GET /queue` - read OpenClaw's current security work queue.
- `POST /briefing/daily` - generate a daily briefing.

## NIST CSF 2.0 Alignment

The CSF scan is a self-assessment for a personal homelab. It is not a certification or formal compliance attestation.

The scan maps available evidence to representative NIST CSF 2.0 outcomes across GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, and RECOVER. Automated evidence is used where possible. Governance, policy, and recovery outcomes are marked for manual review when they require human-owned evidence.

## Current Host Paths

- Project: `~/openclaw-security-hub`
- OpenClaw inbox: `~/.openclaw/workspace/security-alerts/inbox`
- Security queue: `~/.openclaw/workspace/security-alerts/queue/queue.json`
- NIST CSF profile JSON: `~/.openclaw/workspace/security-alerts/queue/nist-csf-profile.json`
- Latest queue summary: `~/.openclaw/workspace/security-alerts/latest.md`
- Security reports: `~/.openclaw/workspace/security-alerts/reports`
- Briefings: `~/.openclaw/workspace/security-alerts/briefings`
- Dashboard JSON: `~/.openclaw/workspace/dashboard/security-alerts.json`

Runtime secrets stay in `.env` and are ignored by Git.

## Scan Tuning

The default posture scan ignores Tailscale IPv6 high ephemeral ports to avoid false positives from `tailscaled` itself. Set `IGNORE_TAILSCALE_EPHEMERAL_TCP_PORTS=false` in `.env` for a stricter review mode.
