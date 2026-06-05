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

## Disable Legacy Dashboard Service

If the posture scan reports a globally exposed dashboard listener on port `8765`,
first bind the dashboard to `127.0.0.1`, then disable the old system service that
can restart it from the legacy workspace:

```bash
sudo scripts/disable-legacy-dashboard-service.sh
```

Verify the gap is closed:

```bash
ss -ltnp | grep ':8765' || true
scripts/security-scan.sh
scripts/nist-csf-check.sh
```

Expected result: port `8765` is either absent or bound only to `127.0.0.1`,
`security_findings` is `0`, and the NIST CSF backlog no longer includes the
exposed dashboard listener.

## Logs

```bash
docker compose logs --tail=80 security-hub
```

## OpenClaw Workspace

Generated files are in:

```text
~/.openclaw/workspace/security-alerts/
```
