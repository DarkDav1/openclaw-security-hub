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
