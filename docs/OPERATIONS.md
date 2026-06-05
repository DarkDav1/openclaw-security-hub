# Operations

## Start

```bash
docker compose up -d --build
```

## Stop

```bash
docker compose down
```

## Status

```bash
docker compose ps
curl -sS http://<tailscale-ip>:8099/health
curl -sS http://<tailscale-ip>:8099/status
```

## Test Alert

```bash
scripts/test-alert.sh
```

## Generate Daily Briefing

```bash
scripts/generate-briefing.sh
```

## Run NIST CSF Self-Assessment

```bash
scripts/nist-csf-check.sh
```

## Logs

```bash
docker compose logs --tail=80 security-hub
```

## OpenClaw Workspace

Generated files are in:

```text
~/.openclaw/workspace/security-alerts/
```
