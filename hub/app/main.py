from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import urllib.error
import urllib.request
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from stat import S_ISSOCK
from typing import Any

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field


APP_NAME = "openclaw-security-hub"

TAILSCALE_IP = os.getenv("TAILSCALE_IP", "127.0.0.1")
SECURITY_HUB_PORT = int(os.getenv("SECURITY_HUB_PORT", "8099"))
WEBHOOK_SECRET = os.getenv("SECURITY_HUB_WEBHOOK_SECRET", "")

ENABLE_TELEGRAM = os.getenv("ENABLE_TELEGRAM", "false").lower() == "true"
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

HOST_LABEL = os.getenv("HOST_LABEL", "homelab")
OPENCLAW_GATEWAY_URL = os.getenv("OPENCLAW_GATEWAY_URL", "http://127.0.0.1:18789")
OPENCLAW_SECURITY_DIR = Path(os.getenv("OPENCLAW_SECURITY_DIR", "/openclaw/security-alerts"))
OPENCLAW_DASHBOARD_DIR = Path(os.getenv("OPENCLAW_DASHBOARD_DIR", "/openclaw/dashboard"))

ENABLE_AUTH_LOG_MONITOR = os.getenv("ENABLE_AUTH_LOG_MONITOR", "true").lower() == "true"
AUTH_LOG_PATH = Path(os.getenv("AUTH_LOG_PATH", "/host/auth.log"))
AUTH_FAILURE_THRESHOLD = int(os.getenv("AUTH_FAILURE_THRESHOLD", "5"))
AUTH_WINDOW_SECONDS = int(os.getenv("AUTH_WINDOW_SECONDS", "300"))
AUTH_ALERT_COOLDOWN_SECONDS = int(os.getenv("AUTH_ALERT_COOLDOWN_SECONDS", "1800"))

ENABLE_OPENCLAW_MONITOR = os.getenv("ENABLE_OPENCLAW_MONITOR", "true").lower() == "true"
OPENCLAW_CHECK_INTERVAL_SECONDS = int(os.getenv("OPENCLAW_CHECK_INTERVAL_SECONDS", "60"))
OPENCLAW_ALERT_COOLDOWN_SECONDS = int(os.getenv("OPENCLAW_ALERT_COOLDOWN_SECONDS", "1800"))

ENABLE_DISK_MONITOR = os.getenv("ENABLE_DISK_MONITOR", "true").lower() == "true"
DISK_CHECK_INTERVAL_SECONDS = int(os.getenv("DISK_CHECK_INTERVAL_SECONDS", "300"))
DISK_ALERT_THRESHOLD_PERCENT = int(os.getenv("DISK_ALERT_THRESHOLD_PERCENT", "90"))
HOST_ROOT_PATH = Path(os.getenv("HOST_ROOT_PATH", "/host-root"))
HOST_PROC_PATH = Path(os.getenv("HOST_PROC_PATH", "/host-proc"))

ENABLE_SECURITY_POSTURE_MONITOR = os.getenv("ENABLE_SECURITY_POSTURE_MONITOR", "true").lower() == "true"
SECURITY_POSTURE_INTERVAL_SECONDS = int(os.getenv("SECURITY_POSTURE_INTERVAL_SECONDS", "900"))
SECURITY_POSTURE_ALERT_COOLDOWN_SECONDS = int(os.getenv("SECURITY_POSTURE_ALERT_COOLDOWN_SECONDS", "3600"))
ALLOWED_GLOBAL_TCP_PORTS = {
    int(port.strip())
    for port in os.getenv("ALLOWED_GLOBAL_TCP_PORTS", "22").split(",")
    if port.strip().isdigit()
}
ALLOWED_TAILSCALE_TCP_PORTS = {
    int(port.strip())
    for port in os.getenv("ALLOWED_TAILSCALE_TCP_PORTS", "8099").split(",")
    if port.strip().isdigit()
}
IGNORE_TAILSCALE_EPHEMERAL_TCP_PORTS = (
    os.getenv("IGNORE_TAILSCALE_EPHEMERAL_TCP_PORTS", "true").lower() == "true"
)
EXPECTED_SSH_ALLOW_USERS = os.getenv("EXPECTED_SSH_ALLOW_USERS", "kyonccw")

OUTPUT_UID = int(os.getenv("OUTPUT_UID", "1000"))
OUTPUT_GID = int(os.getenv("OUTPUT_GID", "1000"))

auth_failures: dict[str, deque[datetime]] = defaultdict(deque)
auth_last_alert: dict[str, datetime] = {}
auth_last_lines: dict[str, list[str]] = defaultdict(list)
openclaw_last_alert_at: datetime | None = None
disk_last_alert_at: datetime | None = None
security_posture_last_alert_at: datetime | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    ensure_dirs()
    tasks = [
        asyncio.create_task(auth_log_monitor()),
        asyncio.create_task(openclaw_monitor()),
        asyncio.create_task(disk_monitor()),
        asyncio.create_task(security_posture_monitor()),
    ]
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


app = FastAPI(title=APP_NAME, lifespan=lifespan)


class Alert(BaseModel):
    title: str = "Homelab alert"
    source: str = "unknown"
    severity: str = "medium"
    summary: str = ""
    evidence: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    suggested_checks: list[str] = Field(default_factory=list)
    category: str = "homelab"
    status: str = "unreviewed"
    raw: dict[str, Any] = Field(default_factory=dict)


class SecurityFinding(BaseModel):
    id: str
    severity: str
    title: str
    evidence: str
    recommendation: str
    status: str = "open"


class NistCsfControl(BaseModel):
    id: str
    function: str
    category: str
    outcome: str
    status: str
    target: str = ""
    target_status: str = "met"
    gap_priority: str = "none"
    owner: str = "homelab owner"
    due: str = "manual"
    evidence: list[str] = Field(default_factory=list)
    gap: str = ""
    next_action: str = ""


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def today_slug() -> str:
    return now_utc().strftime("%Y-%m-%d")


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug[:90] or "alert"


def normalize_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def ensure_dirs() -> None:
    for subdir in ["inbox", "briefings", "events", "reports", "queue"]:
        (OPENCLAW_SECURITY_DIR / subdir).mkdir(parents=True, exist_ok=True)
    OPENCLAW_DASHBOARD_DIR.mkdir(parents=True, exist_ok=True)


def chown_if_possible(path: Path) -> None:
    try:
        os.chown(path, OUTPUT_UID, OUTPUT_GID)
    except PermissionError:
        pass
    except FileNotFoundError:
        pass


def write_text_owned(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    chown_if_possible(path)


def append_jsonl(path: Path, item: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(item, ensure_ascii=False) + "\n")
    chown_if_possible(path)


def alert_from_payload(payload: dict[str, Any]) -> Alert:
    suggested = normalize_list(payload.get("suggested_checks") or payload.get("suggestedChecks"))
    if not suggested:
        suggested = [
            "Check whether the activity is expected.",
            "Review nearby logs or service status.",
            "Record a human decision in the OpenClaw review note.",
        ]

    unknowns = normalize_list(payload.get("unknowns"))
    if not unknowns:
        unknowns = [
            "Whether related events happened before or after this alert.",
            "Whether this is expected activity or a real issue.",
        ]

    return Alert(
        title=str(payload.get("title") or payload.get("name") or "Homelab alert").strip(),
        source=str(payload.get("source") or payload.get("monitor") or payload.get("monitorName") or HOST_LABEL).strip(),
        severity=str(payload.get("severity") or "medium").strip().lower(),
        summary=str(payload.get("summary") or payload.get("msg") or payload.get("message") or "").strip(),
        evidence=normalize_list(payload.get("evidence")),
        unknowns=unknowns,
        suggested_checks=suggested,
        category=str(payload.get("category") or "homelab").strip().lower(),
        status=str(payload.get("status") or "unreviewed").strip().lower(),
        raw=payload,
    )


def render_review_note(alert: Alert, created_at: datetime) -> str:
    evidence = alert.evidence or ["No confirmed evidence was supplied by the alert source."]

    def bullets(items: list[str]) -> str:
        return "\n".join(f"- {item}" for item in items)

    return f"""# {alert.title}

Created: {created_at.isoformat()}
Source: {alert.source}
Category: {alert.category}
Severity: {alert.severity}
Status: {alert.status}

## Summary

{alert.summary or "No summary was supplied by the alert source."}

## Confirmed Evidence

{bullets(evidence)}

## Unknowns

{bullets(alert.unknowns)}

## Suggested Checks

{bullets(alert.suggested_checks)}

## OpenClaw Review Request

Use this section as the OpenClaw review inbox prompt:

- Separate facts from assumptions.
- Identify what evidence is still missing.
- Suggest the next low-risk checks.
- Do not mark the event safe or malicious without human review.

## Human Decision

- Decision:
- Reason:
- Follow-up:

## Final Outcome

- Outcome:
- Closed at:

## Raw Alert

```json
{json.dumps(alert.raw, indent=2, ensure_ascii=False)}
```
"""


def write_review_note(alert: Alert) -> Path:
    created_at = now_utc()
    filename = f"{created_at.strftime('%Y%m%d-%H%M%S')}-{slugify(alert.source)}-{slugify(alert.title)}.md"
    path = OPENCLAW_SECURITY_DIR / "inbox" / filename
    write_text_owned(path, render_review_note(alert, created_at))
    return path


def event_from_alert(alert: Alert, note_path: Path, telegram_sent: bool) -> dict[str, Any]:
    return {
        "created_at": now_utc().isoformat(),
        "title": alert.title,
        "source": alert.source,
        "category": alert.category,
        "severity": alert.severity,
        "status": alert.status,
        "note": note_path.name,
        "telegram_sent": telegram_sent,
    }


def read_events() -> list[dict[str, Any]]:
    path = OPENCLAW_SECURITY_DIR / "events" / "events.jsonl"
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def write_dashboard(events: list[dict[str, Any]]) -> None:
    recent = events[-25:]
    open_notes = sorted((OPENCLAW_SECURITY_DIR / "inbox").glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    data = {
        "updated_at": now_utc().isoformat(),
        "event_count": len(events),
        "open_review_count": len(open_notes),
        "latest_events": recent,
        "latest_open_reviews": [path.name for path in open_notes[:25]],
    }
    write_text_owned(OPENCLAW_DASHBOARD_DIR / "security-alerts.json", json.dumps(data, indent=2, ensure_ascii=False))


def send_telegram(alert: Alert, note_path: Path) -> bool:
    if not ENABLE_TELEGRAM or not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    text = (
        f"[OPENCLAW SECURITY] {alert.title}\n\n"
        f"Source: {alert.source}\n"
        f"Severity: {alert.severity}\n"
        f"Summary: {alert.summary or 'No summary supplied.'}\n"
        f"Review note: {note_path.name}"
    )
    payload = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": text}).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status == 200
    except urllib.error.URLError:
        return False


def process_alert(alert: Alert) -> dict[str, Any]:
    ensure_dirs()
    note_path = write_review_note(alert)
    telegram_sent = send_telegram(alert, note_path)
    event = event_from_alert(alert, note_path, telegram_sent)
    append_jsonl(OPENCLAW_SECURITY_DIR / "events" / "events.jsonl", event)
    events = read_events()
    write_dashboard(events)
    return {
        "ok": True,
        "note": str(note_path),
        "event": event,
        "telegram_sent": telegram_sent,
    }


def require_secret(secret: str | None) -> None:
    if WEBHOOK_SECRET and secret != WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="Invalid webhook secret")


def openclaw_gateway_ok() -> bool:
    try:
        with urllib.request.urlopen(OPENCLAW_GATEWAY_URL, timeout=5) as response:
            return 200 <= response.status < 500
    except Exception:
        return False


def disk_usage_percent() -> float:
    usage = shutil.disk_usage(HOST_ROOT_PATH)
    return round((usage.used / usage.total) * 100, 2)


def parse_tcp_addr(hex_ip: str, hex_port: str, version: int) -> tuple[str, int]:
    port = int(hex_port, 16)
    if version == 4:
        raw = bytes.fromhex(hex_ip)
        address = str(IPv4Address(raw[::-1]))
    else:
        raw = bytes.fromhex(hex_ip)
        words = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
        address = str(IPv6Address(b"".join(words)))
    return address, port


def read_process_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def read_process_cmdline(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError, OSError):
        return ""
    return " ".join(part for part in text.split("\x00") if part).strip()


def build_socket_process_map() -> dict[str, dict[str, str]]:
    process_by_inode: dict[str, dict[str, str]] = {}
    for proc_dir in HOST_PROC_PATH.glob("[0-9]*"):
        fd_dir = proc_dir / "fd"
        if not fd_dir.exists():
            continue
        comm = read_process_text(proc_dir / "comm")
        cmdline = read_process_cmdline(proc_dir / "cmdline")
        cgroup = read_process_text(proc_dir / "cgroup")
        process = {
            "pid": proc_dir.name,
            "comm": comm,
            "cmdline": cmdline,
            "cgroup": cgroup,
        }
        try:
            fd_paths = list(fd_dir.iterdir())
        except (FileNotFoundError, PermissionError, OSError):
            continue
        for fd_path in fd_paths:
            try:
                stat_result = fd_path.stat()
                if not S_ISSOCK(stat_result.st_mode):
                    continue
                target = os.readlink(fd_path)
            except (FileNotFoundError, PermissionError, OSError):
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", target)
            if match:
                process_by_inode.setdefault(match.group(1), process)
    return process_by_inode


def read_listening_tcp_ports() -> list[dict[str, Any]]:
    listeners: list[dict[str, Any]] = []
    process_by_inode = build_socket_process_map()
    for filename, version in [("tcp", 4), ("tcp6", 6)]:
        path = HOST_PROC_PATH / "net" / filename
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "0A":
                continue
            local_address = fields[1]
            hex_ip, hex_port = local_address.split(":", 1)
            address, port = parse_tcp_addr(hex_ip, hex_port, version)
            inode = fields[9] if len(fields) > 9 else ""
            listener = {
                "address": address,
                "port": port,
                "family": f"tcp{version}",
                "inode": inode,
            }
            if inode in process_by_inode:
                listener["process"] = process_by_inode[inode]
            listeners.append(listener)
    return sorted(listeners, key=lambda item: (item["port"], item["address"]))


def is_global_listener(address: str) -> bool:
    return address in {"0.0.0.0", "::"}


def is_loopback_listener(address: str) -> bool:
    return address.startswith("127.") or address == "::1"


def is_tailscale_listener(address: str) -> bool:
    return address == TAILSCALE_IP or address.startswith("fd7a:115c:a1e0:")


def is_tailscale_daemon_listener(listener: dict[str, Any]) -> bool:
    process = listener.get("process")
    if not isinstance(process, dict):
        return False
    comm = str(process.get("comm", ""))
    cmdline = str(process.get("cmdline", ""))
    cgroup = str(process.get("cgroup", ""))
    return "tailscaled" in {comm, Path(cmdline.split(" ", 1)[0]).name if cmdline else ""} or "tailscaled.service" in cgroup


def is_tailscale_ephemeral_port(port: int) -> bool:
    return 32768 <= port <= 65535


def read_ssh_config_text() -> str:
    parts: list[str] = []
    main = HOST_ROOT_PATH / "etc/ssh/sshd_config"
    if main.exists():
        parts.append(main.read_text(encoding="utf-8", errors="replace"))
    dropin_dir = HOST_ROOT_PATH / "etc/ssh/sshd_config.d"
    if dropin_dir.exists():
        for path in sorted(dropin_dir.glob("*.conf")):
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def config_has(pattern: str, text: str) -> bool:
    return re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE) is not None


def collect_security_findings() -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    listeners = read_listening_tcp_ports()
    risky_ports = {
        139: "Samba NetBIOS is listening.",
        445: "Samba SMB is listening.",
        3389: "XRDP/RDP is listening.",
        3391: "GNOME Remote Desktop is listening.",
        11434: "Ollama local model API is listening.",
    }

    for listener in listeners:
        address = str(listener["address"])
        port = int(listener["port"])
        if port in risky_ports:
            findings.append(
                SecurityFinding(
                    id=f"risky-port-{port}",
                    severity="high" if port in {139, 445, 3389, 3391} else "medium",
                    title=f"Risky service port {port} is listening",
                    evidence=f"{address}:{port} ({risky_ports[port]})",
                    recommendation="Disable the service if not needed, or restrict it to Tailscale only.",
                )
            )
        if is_global_listener(address) and port not in ALLOWED_GLOBAL_TCP_PORTS:
            findings.append(
                SecurityFinding(
                    id=f"global-listener-{port}",
                    severity="medium",
                    title=f"TCP port {port} listens on all interfaces",
                    evidence=f"{address}:{port}",
                    recommendation="Bind the service to localhost or the Tailscale IP, or add a documented allowlist reason.",
                )
            )
        if (
            is_tailscale_listener(address)
            and port not in ALLOWED_TAILSCALE_TCP_PORTS
            and port != 39443
            and not is_tailscale_daemon_listener(listener)
            and not (IGNORE_TAILSCALE_EPHEMERAL_TCP_PORTS and is_tailscale_ephemeral_port(port))
        ):
            findings.append(
                SecurityFinding(
                    id=f"unexpected-tailscale-listener-{port}",
                    severity="low",
                    title=f"Unexpected Tailscale listener on port {port}",
                    evidence=f"{address}:{port}",
                    recommendation="Confirm the service is expected and document it in the allowlist.",
                )
            )

    ssh_config = read_ssh_config_text()
    ssh_expectations = [
        ("ssh-password-auth", r"^\s*PasswordAuthentication\s+no\s*$", "SSH password authentication should be disabled."),
        ("ssh-root-login", r"^\s*PermitRootLogin\s+no\s*$", "SSH root login should be disabled."),
        (
            "ssh-keyboard-interactive",
            r"^\s*KbdInteractiveAuthentication\s+no\s*$",
            "SSH keyboard-interactive authentication should be disabled.",
        ),
        ("ssh-x11-forwarding", r"^\s*X11Forwarding\s+no\s*$", "SSH X11 forwarding should be disabled."),
        (
            "ssh-allow-users",
            rf"^\s*AllowUsers\s+{re.escape(EXPECTED_SSH_ALLOW_USERS)}\s*$",
            "SSH should restrict login users.",
        ),
    ]
    for finding_id, pattern, message in ssh_expectations:
        if not config_has(pattern, ssh_config):
            findings.append(
                SecurityFinding(
                    id=finding_id,
                    severity="medium",
                    title=message,
                    evidence="Expected directive was not found in sshd_config or sshd_config.d.",
                    recommendation="Add the expected directive and validate with sshd -t before restarting SSH.",
                )
            )

    if disk_usage_percent() >= DISK_ALERT_THRESHOLD_PERCENT:
        findings.append(
            SecurityFinding(
                id="disk-threshold",
                severity="medium",
                title="Disk usage exceeds configured threshold",
                evidence=f"Disk usage is {disk_usage_percent()}%.",
                recommendation="Review backups, logs, and unused artifacts before deleting data.",
            )
        )

    if not openclaw_gateway_ok():
        findings.append(
            SecurityFinding(
                id="openclaw-gateway",
                severity="high",
                title="OpenClaw gateway is unreachable",
                evidence=f"GET {OPENCLAW_GATEWAY_URL} failed.",
                recommendation="Check openclaw-gateway systemd user service and logs.",
            )
        )

    deduped: dict[str, SecurityFinding] = {}
    for finding in findings:
        deduped[finding.id] = finding
    return sorted(deduped.values(), key=lambda item: ({"high": 0, "medium": 1, "low": 2}.get(item.severity, 3), item.id))


def severity_counts_from_findings(findings: list[SecurityFinding]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for finding in findings:
        counts[finding.severity] += 1
    return dict(sorted(counts.items()))


def existing_nist_queue_fields() -> dict[str, Any]:
    profile_path = OPENCLAW_SECURITY_DIR / "queue" / "nist-csf-profile.json"
    backlog_path = OPENCLAW_SECURITY_DIR / "queue" / "nist-csf-gap-backlog.json"
    if not profile_path.exists():
        return {}
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    backlog: list[Any] = []
    if backlog_path.exists():
        try:
            parsed_backlog = json.loads(backlog_path.read_text(encoding="utf-8"))
            if isinstance(parsed_backlog, list):
                backlog = parsed_backlog
        except json.JSONDecodeError:
            backlog = []
    return {
        "nist_csf_profile": profile_path.name,
        "nist_csf_report": profile.get("report"),
        "nist_csf_gap_backlog": backlog_path.name if backlog_path.exists() else profile.get("gap_backlog_file"),
        "nist_csf_gap_count": len(backlog) if backlog else len(profile.get("gap_backlog", [])),
        "nist_csf_status_counts": profile.get("status_counts"),
        "nist_csf_tier_note": profile.get("tier_note"),
    }


def has_open_review_notes() -> bool:
    return any((OPENCLAW_SECURITY_DIR / "inbox").glob("*.md"))


def status_counts(items: list[NistCsfControl]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for item in items:
        counts[item.status] += 1
    return dict(sorted(counts.items()))


def control(
    identifier: str,
    function: str,
    category: str,
    outcome: str,
    status: str,
    evidence: list[str],
    gap: str,
    next_action: str,
    target: str = "",
    target_status: str | None = None,
    gap_priority: str | None = None,
    due: str = "manual",
) -> NistCsfControl:
    inferred_target_status = target_status or ("met" if status == "pass" else "gap")
    inferred_priority = gap_priority
    if inferred_priority is None:
        inferred_priority = {
            "fail": "high",
            "warning": "medium",
            "manual_review": "manual",
            "pass": "none",
        }.get(status, "manual")
    return NistCsfControl(
        id=identifier,
        function=function,
        category=category,
        outcome=outcome,
        status=status,
        target=target or f"Target state for {identifier}: evidence supports this outcome or an owner-approved exception is recorded.",
        target_status=inferred_target_status,
        gap_priority=inferred_priority,
        due=due,
        evidence=evidence,
        gap=gap,
        next_action=next_action,
    )


def collect_nist_csf_controls(findings: list[SecurityFinding] | None = None) -> list[NistCsfControl]:
    findings = findings if findings is not None else collect_security_findings()
    finding_ids = {finding.id for finding in findings}
    high_medium_findings = [finding for finding in findings if finding.severity in {"high", "medium"}]
    listeners = read_listening_tcp_ports()
    ssh_config = read_ssh_config_text()
    events = read_events()
    open_notes_exist = has_open_review_notes()
    gateway_ok = openclaw_gateway_ok()
    disk_usage = disk_usage_percent()

    ssh_password_disabled = config_has(r"^\s*PasswordAuthentication\s+no\s*$", ssh_config)
    ssh_root_disabled = config_has(r"^\s*PermitRootLogin\s+no\s*$", ssh_config)
    ssh_kbd_disabled = config_has(r"^\s*KbdInteractiveAuthentication\s+no\s*$", ssh_config)
    ssh_allow_users = config_has(rf"^\s*AllowUsers\s+{re.escape(EXPECTED_SSH_ALLOW_USERS)}\s*$", ssh_config)
    ssh_x11_disabled = config_has(r"^\s*X11Forwarding\s+no\s*$", ssh_config)
    risky_ports = [finding for finding in findings if finding.id.startswith("risky-port-")]
    global_listener_findings = [finding for finding in findings if finding.id.startswith("global-listener-")]

    return [
        control(
            "GV.OC-01",
            "GOVERN",
            "Organizational Context",
            "The organizational mission is understood and informs cybersecurity risk management.",
            "manual_review",
            ["Homelab scope is documented in README and architecture notes."],
            "Mission, assumptions, and risk tolerance still need an explicit owner-approved statement.",
            "Add a short homelab risk statement covering scope, accepted exposure, and review cadence.",
        ),
        control(
            "GV.RM-01",
            "GOVERN",
            "Risk Management Strategy",
            "Risk management objectives are established and agreed to by stakeholders.",
            "manual_review",
            ["The queue separates evidence, unknowns, and human decisions."],
            "Risk acceptance criteria are not yet formalized.",
            "Document severity handling rules for low, medium, and high findings.",
        ),
        control(
            "GV.PO-01",
            "GOVERN",
            "Policy",
            "Cybersecurity policy is established based on context, strategy, and priorities.",
            "manual_review",
            ["Security notes and operational docs exist for the project."],
            "There is no standalone policy document for this homelab service.",
            "Create a lightweight policy covering secrets, Tailscale-only exposure, alert review, and backups.",
        ),
        control(
            "ID.AM-01",
            "IDENTIFY",
            "Asset Management",
            "Inventories of hardware managed by the organization are maintained.",
            "warning",
            [f"Scanner can observe {len(listeners)} listening TCP sockets on the host."],
            "The scanner observes services but does not maintain a full hardware inventory.",
            "Add a small asset inventory file for the GPD host, OpenClaw gateway, and key dependencies.",
        ),
        control(
            "ID.AM-02",
            "IDENTIFY",
            "Asset Management",
            "Inventories of software, services, and systems are maintained.",
            "pass" if listeners else "warning",
            [f"Listening services are recorded during each posture scan: {len(listeners)} observed."],
            "" if listeners else "No service inventory was observed from /proc.",
            "Keep service allowlists in .env and document accepted listeners.",
        ),
        control(
            "ID.RA-01",
            "IDENTIFY",
            "Risk Assessment",
            "Vulnerabilities in assets are identified, validated, and recorded.",
            "pass" if not high_medium_findings else "fail",
            [f"Current medium/high posture findings: {len(high_medium_findings)}."],
            "" if not high_medium_findings else "Medium or high posture findings remain open.",
            "Review every medium/high finding and record a human decision in OpenClaw.",
        ),
        control(
            "ID.IM-01",
            "IDENTIFY",
            "Improvement",
            "Improvements are identified from evaluations.",
            "pass",
            ["Security posture reports and OpenClaw queue are generated for review."],
            "",
            "Use the CSF profile gap list as the next improvement backlog.",
        ),
        control(
            "PR.AA-01",
            "PROTECT",
            "Identity Management, Authentication, and Access Control",
            "Identities and credentials for authorized users are managed.",
            "pass" if ssh_allow_users else "fail",
            ["SSH AllowUsers directive is present." if ssh_allow_users else "SSH AllowUsers directive was not found."],
            "" if ssh_allow_users else "SSH login is not restricted to the expected user in observed config.",
            "Restrict SSH users and validate sshd configuration before restart.",
        ),
        control(
            "PR.AA-03",
            "PROTECT",
            "Identity Management, Authentication, and Access Control",
            "Users, services, and hardware are authenticated.",
            "pass" if ssh_password_disabled and ssh_kbd_disabled and ssh_root_disabled else "fail",
            [
                f"PasswordAuthentication no: {ssh_password_disabled}",
                f"KbdInteractiveAuthentication no: {ssh_kbd_disabled}",
                f"PermitRootLogin no: {ssh_root_disabled}",
            ],
            "" if ssh_password_disabled and ssh_kbd_disabled and ssh_root_disabled else "SSH authentication hardening is incomplete.",
            "Keep SSH key-based access only and disable root/password-based authentication.",
        ),
        control(
            "PR.PS-01",
            "PROTECT",
            "Platform Security",
            "Configuration management practices are established and applied.",
            "pass" if ssh_x11_disabled and not global_listener_findings else "fail",
            [
                f"X11Forwarding disabled: {ssh_x11_disabled}",
                f"Unexpected global listeners: {len(global_listener_findings)}",
            ],
            "" if ssh_x11_disabled and not global_listener_findings else "Observed host configuration does not match the expected secure baseline.",
            "Keep SSH hardening and listener allowlists under versioned configuration.",
        ),
        control(
            "PR.PS-02",
            "PROTECT",
            "Platform Security",
            "Software is maintained, replaced, and removed commensurate with risk.",
            "pass" if not risky_ports else "fail",
            [f"Risky service listeners detected: {len(risky_ports)}."],
            "" if not risky_ports else "High-risk local services are still listening.",
            "Remove or restrict unneeded services such as Samba, XRDP, remote desktop, or local model APIs.",
        ),
        control(
            "PR.IR-03",
            "PROTECT",
            "Technology Infrastructure Resilience",
            "Mechanisms are implemented to achieve resilience requirements.",
            "warning" if disk_usage < DISK_ALERT_THRESHOLD_PERCENT else "fail",
            [f"Disk usage is {disk_usage}% with threshold {DISK_ALERT_THRESHOLD_PERCENT}%."],
            "Backup and restore verification is not yet automated.",
            "Add a backup inventory and periodic restore verification note.",
        ),
        control(
            "DE.CM-01",
            "DETECT",
            "Continuous Monitoring",
            "Networks and network services are monitored to find potentially adverse events.",
            "pass" if ENABLE_SECURITY_POSTURE_MONITOR else "fail",
            [f"Security posture monitor enabled: {ENABLE_SECURITY_POSTURE_MONITOR}."],
            "" if ENABLE_SECURITY_POSTURE_MONITOR else "Network/service posture monitoring is disabled.",
            "Keep posture monitoring enabled and review latest.md regularly.",
        ),
        control(
            "DE.CM-03",
            "DETECT",
            "Continuous Monitoring",
            "Personnel activity and technology usage are monitored to find potentially adverse events.",
            "pass" if ENABLE_AUTH_LOG_MONITOR else "fail",
            [f"Auth log monitor enabled: {ENABLE_AUTH_LOG_MONITOR}.", f"Auth log path: {AUTH_LOG_PATH}."],
            "" if ENABLE_AUTH_LOG_MONITOR else "SSH authentication monitoring is disabled.",
            "Keep SSH auth log monitoring enabled and tune the failure threshold if needed.",
        ),
        control(
            "DE.AE-02",
            "DETECT",
            "Adverse Event Analysis",
            "Potentially adverse events are analyzed to better understand associated activities.",
            "pass" if events or open_notes_exist else "warning",
            [f"Recorded events: {len(events)}.", f"Open review notes exist: {open_notes_exist}."],
            "" if events or open_notes_exist else "No event or review-note evidence exists yet.",
            "Run a test alert and ensure OpenClaw review notes capture evidence and unknowns.",
        ),
        control(
            "RS.MA-01",
            "RESPOND",
            "Incident Management",
            "The incident response plan is executed in coordination with relevant parties.",
            "warning" if open_notes_exist else "manual_review",
            ["Review notes include human decision and final outcome sections."],
            "There is a review workflow, but no tested incident response runbook yet.",
            "Add a small incident runbook for SSH brute force, exposed service, and OpenClaw outage scenarios.",
        ),
        control(
            "RS.AN-03",
            "RESPOND",
            "Incident Analysis",
            "Analysis is performed to establish what has taken place during an incident.",
            "pass" if open_notes_exist else "warning",
            [f"Open review notes exist: {open_notes_exist}."],
            "" if open_notes_exist else "No review note has been created yet.",
            "Use review notes to separate evidence, assumptions, unknowns, and next checks.",
        ),
        control(
            "RS.CO-02",
            "RESPOND",
            "Incident Response Reporting and Communication",
            "Internal and external stakeholders are notified of incidents.",
            "pass" if ENABLE_TELEGRAM and TELEGRAM_CHAT_ID else "warning",
            [f"Telegram enabled: {ENABLE_TELEGRAM}.", f"Telegram chat configured: {bool(TELEGRAM_CHAT_ID)}."],
            "" if ENABLE_TELEGRAM and TELEGRAM_CHAT_ID else "Mobile alerting is not fully configured.",
            "Keep Telegram alerting enabled for medium/high alerts and daily briefing tests.",
        ),
        control(
            "RC.RP-01",
            "RECOVER",
            "Incident Recovery Plan Execution",
            "The recovery portion of the incident response plan is executed once initiated.",
            "manual_review",
            ["No automatic recovery action is intentionally performed by this project."],
            "Recovery runbooks and restore tests are not yet documented in the generated evidence.",
            "Document recovery steps for disabling bad services, restoring OpenClaw workspace files, and returning to normal state.",
        ),
        control(
            "RC.RP-03",
            "RECOVER",
            "Incident Recovery Plan Execution",
            "The integrity of backups and restoration assets is verified before restoration.",
            "manual_review",
            ["The project records reports and queue files, but does not verify backups."],
            "Backup integrity verification is outside the current MVP.",
            "Add a scheduled backup check and record restore-test evidence in OpenClaw reports.",
        ),
    ]


def nist_csf_tier_note(controls: list[NistCsfControl]) -> str:
    counts = status_counts(controls)
    if counts.get("fail", 0):
        return "Tier 1 to Tier 2: some repeatable technical practices exist, but open failures need review."
    if counts.get("manual_review", 0) > counts.get("pass", 0):
        return "Tier 2: risk-informed technical monitoring exists, with governance and recovery evidence still informal."
    return "Tier 2 moving toward Tier 3: repeatable monitoring exists; formal policy, roles, and recovery testing remain the main gaps."


def nist_csf_gap_backlog(controls: list[NistCsfControl]) -> list[dict[str, Any]]:
    priority_order = {"high": 0, "medium": 1, "manual": 2, "low": 3, "none": 4}
    backlog = [
        {
            "id": item.id,
            "function": item.function,
            "category": item.category,
            "current_status": item.status,
            "target_status": item.target_status,
            "gap_priority": item.gap_priority,
            "owner": item.owner,
            "due": item.due,
            "gap": item.gap,
            "next_action": item.next_action,
        }
        for item in controls
        if item.target_status != "met"
    ]
    return sorted(backlog, key=lambda item: (priority_order.get(str(item["gap_priority"]), 9), str(item["id"])))


def nist_function_summary(controls: list[NistCsfControl]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for function in sorted({item.function for item in controls}):
        items = [item for item in controls if item.function == function]
        summary[function] = status_counts(items)
    return summary


def render_nist_csf_report(controls: list[NistCsfControl]) -> str:
    counts = status_counts(controls)
    backlog = nist_csf_gap_backlog(controls)
    lines = [
        f"# NIST CSF 2.0 Aligned Homelab Assessment - {today_slug()}",
        "",
        f"Generated: {now_utc().isoformat()}",
        f"Host: {HOST_LABEL}",
        "Framework: NIST Cybersecurity Framework (CSF) 2.0",
        "Profile model: Current Profile, Target Profile, Gap Backlog",
        "",
        "## Scope and Caveat",
        "",
        "This is a CSF-aligned self-assessment for a personal homelab security workflow. It is not a formal certification or compliance attestation.",
        "The CSF is outcome-oriented, so this report records current evidence, gaps, and next actions rather than treating the framework as a simple checklist.",
        "",
        "## Summary",
        "",
        f"- Controls assessed: {len(controls)}",
        f"- Status counts: {json.dumps(counts, ensure_ascii=False)}",
        f"- Gap backlog items: {len(backlog)}",
        f"- Tier note: {nist_csf_tier_note(controls)}",
        "",
        "## Current and Target Profile",
        "",
        "Current Profile records what the homelab evidence supports today. Target Profile records the intended baseline for a repeatable, reviewable homelab security workflow.",
        "",
        f"- Current function summary: {json.dumps(nist_function_summary(controls), ensure_ascii=False)}",
        "- Target baseline: no high or medium technical findings, documented accepted risks, reviewed governance assumptions, and tested recovery evidence.",
        "",
        "## Gap Backlog",
        "",
    ]
    if backlog:
        for item in backlog:
            lines.extend(
                [
                    f"- [{item['gap_priority']}] {item['id']} ({item['function']}): {item['next_action']}",
                ]
            )
    else:
        lines.append("- No current target-profile gaps.")

    lines.extend(
        [
            "",
            "## Function Coverage",
            "",
        ]
    )

    by_function: dict[str, list[NistCsfControl]] = defaultdict(list)
    for item in controls:
        by_function[item.function].append(item)
    for function, items in sorted(by_function.items()):
        lines.append(f"- {function}: {len(items)} checks")

    lines.extend(["", "## Checks", ""])
    for item in controls:
        lines.extend(
            [
                f"### {item.id} - {item.function} / {item.category}",
                "",
                f"- Status: `{item.status}`",
                f"- Target status: `{item.target_status}`",
                f"- Gap priority: `{item.gap_priority}`",
                f"- Outcome: {item.outcome}",
                f"- Target: {item.target}",
                f"- Gap: {item.gap or 'No current gap from available evidence.'}",
                f"- Next action: {item.next_action}",
                "- Evidence:",
                *(f"  - {evidence}" for evidence in item.evidence),
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def write_nist_csf_outputs(controls: list[NistCsfControl]) -> dict[str, Any]:
    ensure_dirs()
    report_path = OPENCLAW_SECURITY_DIR / "reports" / f"{today_slug()}-nist-csf-2.0-profile.md"
    profile_path = OPENCLAW_SECURITY_DIR / "queue" / "nist-csf-profile.json"
    backlog_path = OPENCLAW_SECURITY_DIR / "queue" / "nist-csf-gap-backlog.json"
    backlog = nist_csf_gap_backlog(controls)
    data = {
        "updated_at": now_utc().isoformat(),
        "framework": "NIST CSF 2.0",
        "profile_model": "current_target_gap",
        "status_counts": status_counts(controls),
        "function_summary": nist_function_summary(controls),
        "tier_note": nist_csf_tier_note(controls),
        "current_profile": [item.model_dump() for item in controls],
        "target_profile": {
            "name": "Homelab CSF target profile",
            "baseline": "No high or medium technical findings, documented accepted risks, reviewed governance assumptions, and tested recovery evidence.",
            "target_status": "met only when evidence supports the outcome or an accepted-risk note is recorded.",
        },
        "gap_backlog": backlog,
        "controls": [item.model_dump() for item in controls],
        "report": report_path.name,
        "gap_backlog_file": backlog_path.name,
    }
    write_text_owned(report_path, render_nist_csf_report(controls))
    write_text_owned(profile_path, json.dumps(data, indent=2, ensure_ascii=False))
    write_text_owned(backlog_path, json.dumps(backlog, indent=2, ensure_ascii=False))
    queue_path = OPENCLAW_SECURITY_DIR / "queue" / "queue.json"
    if queue_path.exists():
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
        queue.update(
            {
                "nist_csf_profile": profile_path.name,
                "nist_csf_report": report_path.name,
                "nist_csf_gap_backlog": backlog_path.name,
                "nist_csf_gap_count": len(backlog),
                "nist_csf_status_counts": data["status_counts"],
                "nist_csf_tier_note": data["tier_note"],
            }
        )
        write_text_owned(queue_path, json.dumps(queue, indent=2, ensure_ascii=False))
    return {
        "report": str(report_path),
        "profile": str(profile_path),
        "gap_backlog": str(backlog_path),
        "gap_count": len(backlog),
        "status_counts": data["status_counts"],
        "tier_note": data["tier_note"],
    }


def process_nist_csf_scan() -> dict[str, Any]:
    findings = collect_security_findings()
    write_security_posture_outputs(findings)
    controls = collect_nist_csf_controls(findings)
    outputs = write_nist_csf_outputs(controls)
    return {
        "ok": True,
        "framework": "NIST CSF 2.0",
        "control_count": len(controls),
        "status_counts": status_counts(controls),
        "gap_count": len(nist_csf_gap_backlog(controls)),
        "tier_note": nist_csf_tier_note(controls),
        "outputs": outputs,
    }


def render_security_report(findings: list[SecurityFinding]) -> str:
    generated = now_utc().isoformat()
    lines = [
        f"# Homelab Security Posture Report - {today_slug()}",
        "",
        f"Generated: {generated}",
        f"Host: {HOST_LABEL}",
        "",
        "## Summary",
        "",
        f"- Findings: {len(findings)}",
        f"- OpenClaw gateway reachable: {openclaw_gateway_ok()}",
        f"- Disk usage: {disk_usage_percent()}%",
        f"- Listening TCP sockets observed: {len(read_listening_tcp_ports())}",
        "",
        "## Findings",
        "",
    ]
    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"### [{finding.severity.upper()}] {finding.title}",
                    "",
                    f"- ID: `{finding.id}`",
                    f"- Evidence: {finding.evidence}",
                    f"- Recommendation: {finding.recommendation}",
                    "",
                ]
            )
    else:
        lines.append("No open findings from the current local security posture check.")

    lines.extend(
        [
            "",
            "## OpenClaw Review Instructions",
            "",
            "- Treat this as a local posture review, not an incident conclusion.",
            "- Confirm any medium/high finding against current service needs.",
            "- If a finding is accepted risk, record the reason in the Human Decision section of the relevant review note.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_security_posture_outputs(findings: list[SecurityFinding]) -> dict[str, Any]:
    ensure_dirs()
    report_path = OPENCLAW_SECURITY_DIR / "reports" / f"{today_slug()}-security-posture.md"
    write_text_owned(report_path, render_security_report(findings))

    open_notes = sorted((OPENCLAW_SECURITY_DIR / "inbox").glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    queue = {
        "updated_at": now_utc().isoformat(),
        "open_review_count": len(open_notes),
        "open_reviews": [path.name for path in open_notes[:50]],
        "finding_count": len(findings),
        "finding_severity_counts": severity_counts_from_findings(findings),
        "findings": [finding.model_dump() for finding in findings],
        "daily_briefing": f"{today_slug()}.md",
        "security_posture_report": report_path.name,
    }
    queue.update({key: value for key, value in existing_nist_queue_fields().items() if value is not None})
    queue_path = OPENCLAW_SECURITY_DIR / "queue" / "queue.json"
    write_text_owned(queue_path, json.dumps(queue, indent=2, ensure_ascii=False))

    latest_lines = [
        "# OpenClaw Security Queue",
        "",
        f"Updated: {queue['updated_at']}",
        "",
        f"- Open review notes: {queue['open_review_count']}",
        f"- Security findings: {queue['finding_count']}",
        f"- Daily briefing: `briefings/{queue['daily_briefing']}`",
        f"- Security posture report: `reports/{queue['security_posture_report']}`",
        "",
        "## Current Findings",
        "",
    ]
    if findings:
        latest_lines.extend(f"- [{finding.severity}] {finding.title} (`{finding.id}`)" for finding in findings)
    else:
        latest_lines.append("- No current posture findings.")
    latest_path = OPENCLAW_SECURITY_DIR / "latest.md"
    write_text_owned(latest_path, "\n".join(latest_lines) + "\n")

    events = read_events()
    write_dashboard(events)
    return {"report": str(report_path), "queue": str(queue_path), "latest": str(latest_path), "findings": queue["findings"]}


def read_openclaw_queue() -> dict[str, Any]:
    path = OPENCLAW_SECURITY_DIR / "queue" / "queue.json"
    if not path.exists():
        findings = collect_security_findings()
        write_security_posture_outputs(findings)
    return json.loads(path.read_text(encoding="utf-8"))


def process_security_posture_scan() -> dict[str, Any]:
    findings = collect_security_findings()
    outputs = write_security_posture_outputs(findings)
    return {
        "ok": True,
        "finding_count": len(findings),
        "severity_counts": severity_counts_from_findings(findings),
        "outputs": outputs,
    }


def generate_daily_briefing(send_to_telegram: bool = False) -> Path:
    ensure_dirs()
    date = today_slug()
    events = [event for event in read_events() if str(event.get("created_at", "")).startswith(date)]
    findings = collect_security_findings()
    posture_outputs = write_security_posture_outputs(findings)
    nist_controls = collect_nist_csf_controls(findings)
    nist_outputs = write_nist_csf_outputs(nist_controls)
    severity_counts: dict[str, int] = defaultdict(int)
    category_counts: dict[str, int] = defaultdict(int)
    for event in events:
        severity_counts[str(event.get("severity", "unknown"))] += 1
        category_counts[str(event.get("category", "unknown"))] += 1

    open_notes = sorted((OPENCLAW_SECURITY_DIR / "inbox").glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    lines = [
        f"# Daily Homelab Security Briefing - {date}",
        "",
        f"Generated: {now_utc().isoformat()}",
        "",
        "## Summary",
        "",
        f"- Events today: {len(events)}",
        f"- Open review notes: {len(open_notes)}",
        f"- Security posture findings: {len(findings)}",
        f"- NIST CSF status counts: {json.dumps(status_counts(nist_controls), ensure_ascii=False)}",
        f"- NIST CSF gap backlog items: {len(nist_csf_gap_backlog(nist_controls))}",
        f"- OpenClaw gateway reachable: {openclaw_gateway_ok()}",
        f"- Disk usage: {disk_usage_percent()}%",
        f"- Security queue: `{Path(str(posture_outputs['queue'])).name}`",
        f"- NIST CSF profile: `{Path(str(nist_outputs['profile'])).name}`",
        "",
        "## Severity Counts",
        "",
    ]
    if severity_counts:
        lines.extend(f"- {severity}: {count}" for severity, count in sorted(severity_counts.items()))
    else:
        lines.append("- No events recorded today.")

    lines.extend(["", "## Category Counts", ""])
    if category_counts:
        lines.extend(f"- {category}: {count}" for category, count in sorted(category_counts.items()))
    else:
        lines.append("- No categories recorded today.")

    lines.extend(["", "## Security Posture Findings", ""])
    if findings:
        for finding in findings:
            lines.append(f"- [{finding.severity}] {finding.title} (`{finding.id}`)")
    else:
        lines.append("- No current posture findings.")

    lines.extend(["", "## NIST CSF 2.0 Review", ""])
    lines.append(f"- Tier note: {nist_csf_tier_note(nist_controls)}")
    lines.append(f"- Gap backlog items: {len(nist_csf_gap_backlog(nist_controls))}")
    lines.append("- Manual review items are expected because governance and recovery outcomes need human evidence.")

    lines.extend(["", "## Latest Events", ""])
    if events:
        for event in events[-10:]:
            lines.append(
                f"- {event.get('created_at')} | {event.get('severity')} | "
                f"{event.get('source')} | {event.get('title')} | {event.get('note')}"
            )
    else:
        lines.append("- No events recorded today.")

    lines.extend(
        [
            "",
            "## Suggested Review",
            "",
            "- Review unclosed notes in `security-alerts/inbox`.",
            "- Mark expected activity clearly in the Human Decision section.",
            "- Tune noisy rules only after confirming the evidence pattern.",
        ]
    )

    path = OPENCLAW_SECURITY_DIR / "briefings" / f"{date}.md"
    write_text_owned(path, "\n".join(lines) + "\n")

    if send_to_telegram and ENABLE_TELEGRAM and TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        alert = Alert(
            title="Daily Homelab Security Briefing",
            source=HOST_LABEL,
            severity="info",
            summary=f"{len(events)} events today, {len(open_notes)} open review notes.",
            category="briefing",
            raw={"briefing": path.name},
        )
        send_telegram(alert, path)

    return path


def parse_failed_ssh_line(line: str) -> tuple[str, str] | None:
    if "sshd" not in line:
        return None
    if "Failed password" not in line and "Invalid user" not in line:
        return None
    match = re.search(r" from ([0-9a-fA-F:.]+) port ", line)
    source_ip = match.group(1) if match else "unknown"
    return source_ip, line.strip()


def prune_window(events: deque[datetime], current_time: datetime) -> None:
    while events and (current_time - events[0]).total_seconds() > AUTH_WINDOW_SECONDS:
        events.popleft()


async def handle_auth_failure(source_ip: str, line: str) -> None:
    current_time = now_utc()
    events = auth_failures[source_ip]
    events.append(current_time)
    prune_window(events, current_time)

    lines = auth_last_lines[source_ip]
    lines.append(line)
    del lines[:-10]

    if len(events) < AUTH_FAILURE_THRESHOLD:
        return

    last_alert = auth_last_alert.get(source_ip)
    if last_alert and (current_time - last_alert).total_seconds() < AUTH_ALERT_COOLDOWN_SECONDS:
        return

    auth_last_alert[source_ip] = current_time
    process_alert(
        Alert(
            title="SSH login failures",
            source=HOST_LABEL,
            severity="medium",
            category="ssh",
            summary=(
                f"{len(events)} failed SSH login attempts from {source_ip} "
                f"within {AUTH_WINDOW_SECONDS // 60} minutes."
            ),
            evidence=lines[-5:],
            unknowns=[
                "Whether any login from this source later succeeded.",
                "Whether this source IP belongs to expected automation.",
            ],
            suggested_checks=[
                "Review nearby auth.log entries for successful logins.",
                "Check whether password login is disabled for SSH.",
                "Record the final human decision in the review note.",
            ],
            raw={"source_ip": source_ip, "recent_failures": lines[-10:]},
        )
    )


async def auth_log_monitor() -> None:
    if not ENABLE_AUTH_LOG_MONITOR:
        return
    offset = AUTH_LOG_PATH.stat().st_size if AUTH_LOG_PATH.exists() else 0
    while True:
        try:
            if AUTH_LOG_PATH.exists():
                size = AUTH_LOG_PATH.stat().st_size
                if size < offset:
                    offset = 0
                with AUTH_LOG_PATH.open("r", encoding="utf-8", errors="replace") as auth_log:
                    auth_log.seek(offset)
                    for line in auth_log:
                        parsed = parse_failed_ssh_line(line)
                        if parsed:
                            await handle_auth_failure(*parsed)
                    offset = auth_log.tell()
        except Exception as exc:
            print(f"auth log monitor error: {exc}", flush=True)
        await asyncio.sleep(10)


async def openclaw_monitor() -> None:
    global openclaw_last_alert_at
    if not ENABLE_OPENCLAW_MONITOR:
        return
    while True:
        ok = openclaw_gateway_ok()
        if not ok:
            current = now_utc()
            if (
                openclaw_last_alert_at is None
                or (current - openclaw_last_alert_at).total_seconds() > OPENCLAW_ALERT_COOLDOWN_SECONDS
            ):
                openclaw_last_alert_at = current
                process_alert(
                    Alert(
                        title="OpenClaw gateway unreachable",
                        source=HOST_LABEL,
                        severity="high",
                        category="openclaw",
                        summary=f"OpenClaw gateway did not respond at {OPENCLAW_GATEWAY_URL}.",
                        evidence=[f"GET {OPENCLAW_GATEWAY_URL} failed from security hub."],
                        unknowns=["Whether the gateway service is stopped or only temporarily slow."],
                        suggested_checks=[
                            "Run systemctl --user status openclaw-gateway.",
                            "Check OpenClaw gateway logs.",
                            "Confirm whether Telegram/OpenClaw commands still work.",
                        ],
                        raw={"gateway_url": OPENCLAW_GATEWAY_URL},
                    )
                )
        await asyncio.sleep(OPENCLAW_CHECK_INTERVAL_SECONDS)


async def disk_monitor() -> None:
    global disk_last_alert_at
    if not ENABLE_DISK_MONITOR:
        return
    while True:
        try:
            percent = disk_usage_percent()
            if percent >= DISK_ALERT_THRESHOLD_PERCENT:
                current = now_utc()
                if disk_last_alert_at is None or (current - disk_last_alert_at).total_seconds() > 3600:
                    disk_last_alert_at = current
                    process_alert(
                        Alert(
                            title="Disk usage threshold exceeded",
                            source=HOST_LABEL,
                            severity="medium",
                            category="system",
                            summary=f"Root disk usage is {percent}%.",
                            evidence=[f"Disk usage from {HOST_ROOT_PATH}: {percent}%"],
                            suggested_checks=[
                                "Check large backup archives and Docker artifacts.",
                                "Review OpenClaw workspace storage usage.",
                                "Remove old logs only after confirming they are not needed.",
                            ],
                            raw={"disk_usage_percent": percent},
                        )
                    )
        except Exception as exc:
            print(f"disk monitor error: {exc}", flush=True)
        await asyncio.sleep(DISK_CHECK_INTERVAL_SECONDS)


async def security_posture_monitor() -> None:
    global security_posture_last_alert_at
    if not ENABLE_SECURITY_POSTURE_MONITOR:
        return
    while True:
        try:
            findings = collect_security_findings()
            write_security_posture_outputs(findings)
            actionable = [finding for finding in findings if finding.severity in {"high", "medium"}]
            if actionable:
                current = now_utc()
                if (
                    security_posture_last_alert_at is None
                    or (current - security_posture_last_alert_at).total_seconds()
                    > SECURITY_POSTURE_ALERT_COOLDOWN_SECONDS
                ):
                    security_posture_last_alert_at = current
                    process_alert(
                        Alert(
                            title="Security posture findings need review",
                            source=HOST_LABEL,
                            severity="high" if any(f.severity == "high" for f in actionable) else "medium",
                            category="posture",
                            summary=f"{len(actionable)} medium/high local security posture findings are open.",
                            evidence=[f"{finding.severity}: {finding.title}" for finding in actionable[:10]],
                            unknowns=[
                                "Whether any open finding is an accepted homelab risk.",
                                "Whether the service exposure is temporary or still needed.",
                            ],
                            suggested_checks=[
                                "Open security-alerts/latest.md in the OpenClaw workspace.",
                                "Review security-alerts/reports for the full posture report.",
                                "Close or document each finding after human review.",
                            ],
                            raw={"findings": [finding.model_dump() for finding in actionable]},
                        )
                    )
        except Exception as exc:
            print(f"security posture monitor error: {exc}", flush=True)
        await asyncio.sleep(SECURITY_POSTURE_INTERVAL_SECONDS)


@app.get("/")
async def index() -> dict[str, Any]:
    return {
        "app": APP_NAME,
        "routes": {
            "health": "/health",
            "status": "/status",
            "generic_webhook": "/webhook/generic",
            "daily_briefing": "/briefing/daily",
            "security_scan": "/scan/security",
            "nist_csf_scan": "/scan/nist-csf",
            "openclaw_queue": "/queue",
        },
        "openclaw_workspace": str(OPENCLAW_SECURITY_DIR),
    }


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "ok": True,
        "app": APP_NAME,
        "telegram_enabled": ENABLE_TELEGRAM,
        "auth_log_monitor_enabled": ENABLE_AUTH_LOG_MONITOR,
        "openclaw_monitor_enabled": ENABLE_OPENCLAW_MONITOR,
        "disk_monitor_enabled": ENABLE_DISK_MONITOR,
        "security_posture_monitor_enabled": ENABLE_SECURITY_POSTURE_MONITOR,
        "openclaw_gateway_ok": openclaw_gateway_ok(),
        "openclaw_security_dir": str(OPENCLAW_SECURITY_DIR),
    }


@app.get("/status")
async def status() -> dict[str, Any]:
    events = read_events()
    open_notes = list((OPENCLAW_SECURITY_DIR / "inbox").glob("*.md"))
    queue_path = OPENCLAW_SECURITY_DIR / "queue" / "queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8")) if queue_path.exists() else None
    nist_profile_path = OPENCLAW_SECURITY_DIR / "queue" / "nist-csf-profile.json"
    nist_profile = json.loads(nist_profile_path.read_text(encoding="utf-8")) if nist_profile_path.exists() else None
    return {
        "events": len(events),
        "open_review_notes": len(open_notes),
        "security_findings": queue.get("finding_count", 0) if queue else None,
        "nist_csf_status_counts": nist_profile.get("status_counts") if nist_profile else None,
        "nist_csf_gap_count": len(nist_profile.get("gap_backlog", [])) if nist_profile else None,
        "nist_csf_tier_note": nist_profile.get("tier_note") if nist_profile else None,
        "openclaw_gateway_ok": openclaw_gateway_ok(),
        "disk_usage_percent": disk_usage_percent(),
        "latest_event": events[-1] if events else None,
    }


@app.post("/webhook/generic")
async def generic_webhook(
    request: Request, x_security_hub_secret: str | None = Header(default=None)
) -> dict[str, Any]:
    require_secret(x_security_hub_secret)
    payload = await request.json()
    return process_alert(alert_from_payload(payload))


@app.post("/briefing/daily")
async def daily_briefing(
    x_security_hub_secret: str | None = Header(default=None),
    send_to_telegram: bool = False,
) -> dict[str, Any]:
    require_secret(x_security_hub_secret)
    path = generate_daily_briefing(send_to_telegram=send_to_telegram)
    return {"ok": True, "briefing": str(path)}


@app.post("/scan/security")
async def security_scan(x_security_hub_secret: str | None = Header(default=None)) -> dict[str, Any]:
    require_secret(x_security_hub_secret)
    return process_security_posture_scan()


@app.post("/scan/nist-csf")
async def nist_csf_scan(x_security_hub_secret: str | None = Header(default=None)) -> dict[str, Any]:
    require_secret(x_security_hub_secret)
    return process_nist_csf_scan()


@app.get("/queue")
async def openclaw_queue(x_security_hub_secret: str | None = Header(default=None)) -> dict[str, Any]:
    require_secret(x_security_hub_secret)
    return read_openclaw_queue()


def main() -> None:
    uvicorn.run("app.main:app", host=TAILSCALE_IP, port=SECURITY_HUB_PORT)


if __name__ == "__main__":
    main()
