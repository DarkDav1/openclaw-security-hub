# Security Notes

## Secrets

Do not commit `.env`.

Secrets include:

- Telegram Bot token
- Telegram chat ID
- Security Hub webhook secret

## Webhook Auth

Pass the webhook secret with this header:

```text
X-Security-Hub-Secret: <secret>
```

Do not put secrets in URLs.

## Scope

This project is for a personal homelab. It does not perform automatic containment, blocking, account disabling, or firewall changes.

## Network Exposure

The service binds to the Tailscale IP. Do not expose it directly to the public internet.

Local dashboards and development helpers should bind to `127.0.0.1`. If an
old service exposes a helper dashboard on `0.0.0.0:8765`, disable the legacy
systemd service and rerun the posture scan before accepting the machine as clean.

## Remediation Safety

Telegram, OpenClaw, and Codex do not get arbitrary shell access. Remediation is
limited to named playbooks in the service code and host runner. Host-level
changes require an approved request before execution, and every execution is
followed by security posture and NIST CSF verification scans.
