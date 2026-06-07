# Codex Handoff

This document is for a new Codex thread taking over the OpenClaw Security Hub project.

## Project

- Local project path: `/Users/chenweic/dev/openclaw-security-hub`
- GitHub repo: `https://github.com/DarkDav1/openclaw-security-hub`
- Runtime host: `ssh kyonccw@100.77.103.17`
- Runtime project path on GPD: `/home/kyonccw/openclaw-security-hub`
- Runtime service: Docker Compose service `security-hub`, container `openclaw-security-hub`
- API base URL on Tailscale: `http://100.77.103.17:8099`

This is now an independent project. Do not work from `/Users/chenweic/dev/my_website` for this repo.

## Security Rules

- Never print, commit, or copy the real `.env`.
- The local Mac clone should only have `.env.example`.
- The real `.env` exists on the GPD runtime host.
- Do not expose Telegram bot tokens, chat IDs, webhook secrets, or other secrets.
- This is a public GitHub repo, so keep runtime credentials and host-specific secrets out of tracked files.

## Current Capabilities

The service currently provides:

- SSH auth failure monitoring.
- OpenClaw gateway health monitoring.
- Disk usage monitoring.
- Host posture scan from `/proc`, SSH config, disk usage, and OpenClaw reachability.
- NIST CSF 2.0 Current Profile, Target Profile, and Gap Backlog generation.
- Telegram outbound alerts.
- Telegram command polling.
- Telegram commands:
  - `/scan`
  - `/harden`
  - `/queue`
  - `/approve <request-id>`
  - `/codex`
  - `/briefing`
- Allowlisted remediation request queue.
- Host remediation runner: `scripts/remediation-runner.py`
- Codex automation task generation: `scripts/codex-automation.sh`
- OpenClaw workspace outputs:
  - `~/.openclaw/workspace/security-alerts/inbox`
  - `~/.openclaw/workspace/security-alerts/events/events.jsonl`
  - `~/.openclaw/workspace/security-alerts/queue/queue.json`
  - `~/.openclaw/workspace/security-alerts/queue/remediation-requests.json`
  - `~/.openclaw/workspace/security-alerts/queue/nist-csf-profile.json`
  - `~/.openclaw/workspace/security-alerts/queue/nist-csf-gap-backlog.json`
  - `~/.openclaw/workspace/security-alerts/codex-automation/pending`
  - `~/.openclaw/workspace/dashboard/security-alerts.json`

## Codex App Automation

Existing Codex automation:

- ID: `openclaw-security-hub-queue-review`
- Schedule: hourly
- Working directory: `/Users/chenweic/dev/openclaw-security-hub`
- Purpose: SSH to the GPD, review Security Hub queue state, report findings, NIST gap count, pending remediation, and `needs_sudo` items.
- Guardrail: it must not execute host-level remediation or sudo actions.

## Current Known State

At the last verified check:

- Service health: OK
- Telegram enabled: true
- Telegram command polling enabled: true
- OpenClaw gateway: reachable
- Security findings: `0`
- NIST CSF gap count: `8`
- Docker service: healthy
- Port `8099`: listening on Tailscale IP
- Port `8765`: not listening

There may be one pending remediation request with status `needs_sudo` for disabling the legacy dashboard service. This is expected until the user refreshes sudo and runs the host runner.

To finish that item on the GPD:

```bash
cd /home/kyonccw/openclaw-security-hub
sudo -v
scripts/remediation-runner.py
```

Then verify:

```bash
scripts/security-scan.sh
scripts/nist-csf-check.sh
curl -sS http://100.77.103.17:8099/status
ss -ltnpe | grep ':8765' || true
```

## Development Workflow

Use the local independent repo for code changes:

```bash
cd /Users/chenweic/dev/openclaw-security-hub
```

Before reporting completion, verify locally:

```bash
bash -n scripts/*.sh
python3 -m py_compile scripts/remediation-runner.py
```

For full service tests, run on the GPD:

```bash
ssh kyonccw@100.77.103.17
cd /home/kyonccw/openclaw-security-hub
./scripts/run-tests.sh
```

Deploy runtime changes on the GPD:

```bash
cd /home/kyonccw/openclaw-security-hub
git pull
docker compose up -d --build
curl -sS http://100.77.103.17:8099/health
curl -sS http://100.77.103.17:8099/status
```

## Done Criteria For Future Work

Before saying a task is done:

- Unit tests pass in Docker on the GPD when service logic changes.
- The running container is healthy.
- `/health` and `/status` respond.
- Security scan and NIST scan are run when security posture changes.
- No real `.env` or secret values are committed.
- GitHub is updated if the change belongs in the public project.
- Any host-level remediation remains allowlisted and approval-based.

## Notes For New Thread

Start by reading:

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/OPERATIONS.md`
- `docs/SECURITY.md`
- `docs/TEST_PLAN.md`
- `docs/CODEX-HANDOFF.md`

Treat the GPD as the source of runtime truth and the local Mac clone as the clean development workspace.
