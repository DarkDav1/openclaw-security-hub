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
| Security posture monitor | Checks host listeners, SSH hardening, disk usage, and OpenClaw reachability |
| NIST CSF profile generator | Maps available evidence to a CSF 2.0-aligned Current/Target Profile and gap backlog |
| Telegram | Sends short mobile alerts |
| OpenClaw review inbox | Stores structured investigation notes |
| OpenClaw queue | Stores the current security work list for OpenClaw |
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

## OpenClaw Collaboration Contract

OpenClaw does not need direct control over host services to participate in the workflow. The Security Hub writes a stable set of files that OpenClaw can read:

| File | Purpose |
| --- | --- |
| `security-alerts/inbox/*.md` | Individual review notes |
| `security-alerts/latest.md` | Current summary for fast review |
| `security-alerts/queue/queue.json` | Machine-readable work queue |
| `security-alerts/queue/nist-csf-profile.json` | Machine-readable NIST CSF 2.0 profile |
| `security-alerts/queue/nist-csf-gap-backlog.json` | Prioritized CSF gap backlog |
| `security-alerts/reports/*-security-posture.md` | Host posture reports |
| `security-alerts/reports/*-nist-csf-2.0-profile.md` | NIST CSF aligned self-assessment |
| `security-alerts/briefings/*.md` | Daily summaries |
| `dashboard/security-alerts.json` | Dashboard feed |

The intended flow is:

1. The Security Hub observes alerts and local posture.
2. It writes evidence and open questions into the OpenClaw workspace.
3. OpenClaw reads the queue and helps draft review notes or next checks.
4. A human records the final decision before closing the event.

This keeps automation useful without letting it silently declare an event safe or malicious.

## NIST CSF 2.0 Profile Model

The CSF module follows the framework's outcome-oriented structure:

- Function
- Category
- Subcategory outcome
- Current evidence
- Gap
- Next action

The output is a homelab self-assessment, not a formal compliance report. Technical outcomes such as SSH hardening, service exposure, monitoring, and alert review are checked automatically where possible. Governance, policy, supplier, and recovery outcomes are marked as `manual_review` when they require human-owned evidence.

The profile has three layers:

| Layer | Purpose |
| --- | --- |
| Current Profile | Evidence-supported status for each selected CSF outcome |
| Target Profile | Intended baseline for the homelab security workflow |
| Gap Backlog | Prioritized actions needed to move from current to target |

This design keeps the project close to industry practice: it uses CSF as a shared risk language and profile mechanism, while avoiding the false claim that a small tool can fully certify CSF adoption.

## Port Scan Tuning

The posture scan treats globally exposed listeners more strictly than Tailscale-only listeners.

Default behavior:

- Global listeners are allowed only when listed in `ALLOWED_GLOBAL_TCP_PORTS`.
- Tailscale listeners are allowed when listed in `ALLOWED_TAILSCALE_TCP_PORTS`.
- Tailscale IPv6 high ephemeral ports are ignored by default because `tailscaled` can open dynamic listeners that are visible in `/proc/net/tcp6`, while container permissions may prevent mapping the socket back to the process.

Set `IGNORE_TAILSCALE_EPHEMERAL_TCP_PORTS=false` if strict review of every Tailscale-only high port is preferred.
