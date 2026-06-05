# Architecture

The previous standalone alert notebook has been replaced by an OpenClaw-centered workflow.

The Security Hub does not try to decide whether an event is safe or malicious. It creates review material for OpenClaw and the human operator.

## Components

| Component | Purpose |
| --- | --- |
| OpenClaw Security Hub | Receives and normalizes alerts |
| OpenClaw gateway monitor | Checks whether OpenClaw is reachable |
| SSH monitor | Detects repeated failed SSH logins |
| Disk monitor | Warns about high disk usage |
| Telegram | Sends short mobile alerts |
| OpenClaw review inbox | Stores structured investigation notes |
| Daily briefing | Summarizes events and open review work |

## Review Note Contract

Each note includes:

- Summary
- Confirmed evidence
- Unknowns
- Suggested checks
- OpenClaw review request
- Human decision
- Final outcome
- Raw alert

This keeps evidence, assumptions, and decisions separate.
