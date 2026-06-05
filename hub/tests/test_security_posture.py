from __future__ import annotations

import json
from pathlib import Path

from app import main


def test_parse_tcp_ipv4_address() -> None:
    address, port = main.parse_tcp_addr("0100007F", "1F9F", 4)

    assert address == "127.0.0.1"
    assert port == 8095


def test_config_has_matches_case_insensitive_lines() -> None:
    text = "PasswordAuthentication no\nPermitRootLogin no\n"

    assert main.config_has(r"^\s*passwordauthentication\s+no\s*$", text)
    assert not main.config_has(r"^\s*x11forwarding\s+no\s*$", text)


def test_collect_security_findings_flags_risky_ports(monkeypatch) -> None:
    monkeypatch.setattr(
        main,
        "read_listening_tcp_ports",
        lambda: [
            {"address": "0.0.0.0", "port": 445, "family": "tcp4"},
            {"address": "100.77.103.17", "port": 8099, "family": "tcp4"},
        ],
    )
    monkeypatch.setattr(
        main,
        "read_ssh_config_text",
        lambda: "\n".join(
            [
                "PasswordAuthentication no",
                "PermitRootLogin no",
                "KbdInteractiveAuthentication no",
                "X11Forwarding no",
                "AllowUsers kyonccw",
            ]
        ),
    )
    monkeypatch.setattr(main, "disk_usage_percent", lambda: 20.0)
    monkeypatch.setattr(main, "openclaw_gateway_ok", lambda: True)

    findings = main.collect_security_findings()

    assert any(finding.id == "risky-port-445" for finding in findings)
    assert all(finding.id != "unexpected-tailscale-listener-8099" for finding in findings)


def test_collect_security_findings_ignores_tailscale_daemon_dynamic_port(monkeypatch) -> None:
    monkeypatch.setattr(main, "TAILSCALE_IP", "100.77.103.17")
    monkeypatch.setattr(
        main,
        "read_listening_tcp_ports",
        lambda: [
            {
                "address": "fd7a:115c:a1e0::3301:67a0",
                "port": 60845,
                "family": "tcp6",
                "process": {"comm": "tailscaled", "cmdline": "/usr/sbin/tailscaled", "cgroup": "tailscaled.service"},
            }
        ],
    )
    monkeypatch.setattr(
        main,
        "read_ssh_config_text",
        lambda: "\n".join(
            [
                "PasswordAuthentication no",
                "PermitRootLogin no",
                "KbdInteractiveAuthentication no",
                "X11Forwarding no",
                "AllowUsers kyonccw",
            ]
        ),
    )
    monkeypatch.setattr(main, "disk_usage_percent", lambda: 20.0)
    monkeypatch.setattr(main, "openclaw_gateway_ok", lambda: True)

    findings = main.collect_security_findings()

    assert findings == []


def test_collect_security_findings_ignores_tailscale_ephemeral_port(monkeypatch) -> None:
    monkeypatch.setattr(main, "TAILSCALE_IP", "100.77.103.17")
    monkeypatch.setattr(main, "IGNORE_TAILSCALE_EPHEMERAL_TCP_PORTS", True)
    monkeypatch.setattr(
        main,
        "read_listening_tcp_ports",
        lambda: [{"address": "fd7a:115c:a1e0::3301:67a0", "port": 60845, "family": "tcp6"}],
    )
    monkeypatch.setattr(
        main,
        "read_ssh_config_text",
        lambda: "\n".join(
            [
                "PasswordAuthentication no",
                "PermitRootLogin no",
                "KbdInteractiveAuthentication no",
                "X11Forwarding no",
                "AllowUsers kyonccw",
            ]
        ),
    )
    monkeypatch.setattr(main, "disk_usage_percent", lambda: 20.0)
    monkeypatch.setattr(main, "openclaw_gateway_ok", lambda: True)

    findings = main.collect_security_findings()

    assert findings == []


def test_write_security_posture_outputs_creates_queue(tmp_path, monkeypatch) -> None:
    security_dir = tmp_path / "security-alerts"
    dashboard_dir = tmp_path / "dashboard"
    monkeypatch.setattr(main, "OPENCLAW_SECURITY_DIR", security_dir)
    monkeypatch.setattr(main, "OPENCLAW_DASHBOARD_DIR", dashboard_dir)
    monkeypatch.setattr(main, "openclaw_gateway_ok", lambda: True)
    monkeypatch.setattr(main, "disk_usage_percent", lambda: 10.0)
    monkeypatch.setattr(main, "read_listening_tcp_ports", lambda: [])

    finding = main.SecurityFinding(
        id="example",
        severity="medium",
        title="Example finding",
        evidence="example evidence",
        recommendation="example recommendation",
    )

    outputs = main.write_security_posture_outputs([finding])
    queue = json.loads(Path(outputs["queue"]).read_text(encoding="utf-8"))

    assert queue["finding_count"] == 1
    assert queue["findings"][0]["id"] == "example"
    assert (security_dir / "latest.md").exists()
    assert (dashboard_dir / "security-alerts.json").exists()


def test_collect_nist_csf_controls_covers_all_functions(monkeypatch) -> None:
    monkeypatch.setattr(main, "read_listening_tcp_ports", lambda: [{"address": "100.77.103.17", "port": 8099}])
    monkeypatch.setattr(
        main,
        "read_ssh_config_text",
        lambda: "\n".join(
            [
                "PasswordAuthentication no",
                "PermitRootLogin no",
                "KbdInteractiveAuthentication no",
                "X11Forwarding no",
                "AllowUsers kyonccw",
            ]
        ),
    )
    monkeypatch.setattr(main, "read_events", lambda: [{"title": "example"}])
    monkeypatch.setattr(main, "has_open_review_notes", lambda: True)
    monkeypatch.setattr(main, "disk_usage_percent", lambda: 20.0)
    monkeypatch.setattr(main, "openclaw_gateway_ok", lambda: True)

    controls = main.collect_nist_csf_controls([])
    functions = {control.function for control in controls}

    assert functions == {"GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"}
    assert any(control.id == "DE.CM-01" and control.status == "pass" for control in controls)
    assert any(control.status == "manual_review" for control in controls)
    assert all(control.target for control in controls)
    assert any(control.target_status == "gap" for control in controls)


def test_write_nist_csf_outputs_creates_profile_and_updates_queue(tmp_path, monkeypatch) -> None:
    security_dir = tmp_path / "security-alerts"
    dashboard_dir = tmp_path / "dashboard"
    monkeypatch.setattr(main, "OPENCLAW_SECURITY_DIR", security_dir)
    monkeypatch.setattr(main, "OPENCLAW_DASHBOARD_DIR", dashboard_dir)
    main.ensure_dirs()
    queue_path = security_dir / "queue" / "queue.json"
    queue_path.write_text(json.dumps({"finding_count": 0}), encoding="utf-8")

    controls = [
        main.NistCsfControl(
            id="DE.CM-01",
            function="DETECT",
            category="Continuous Monitoring",
            outcome="Networks and services are monitored.",
            status="pass",
            evidence=["example"],
            next_action="keep monitoring",
        )
    ]

    outputs = main.write_nist_csf_outputs(controls)
    profile = json.loads(Path(outputs["profile"]).read_text(encoding="utf-8"))
    backlog = json.loads(Path(outputs["gap_backlog"]).read_text(encoding="utf-8"))
    queue = json.loads(queue_path.read_text(encoding="utf-8"))

    assert profile["framework"] == "NIST CSF 2.0"
    assert profile["profile_model"] == "current_target_gap"
    assert profile["status_counts"]["pass"] == 1
    assert profile["target_profile"]["name"] == "Homelab CSF target profile"
    assert backlog == []
    assert queue["nist_csf_profile"] == "nist-csf-profile.json"
    assert queue["nist_csf_gap_backlog"] == "nist-csf-gap-backlog.json"


def test_nist_csf_gap_backlog_prioritizes_failures() -> None:
    controls = [
        main.NistCsfControl(
            id="GV.PO-01",
            function="GOVERN",
            category="Policy",
            outcome="Policy is established.",
            status="manual_review",
            target_status="gap",
            gap_priority="manual",
            gap="Policy evidence is missing.",
            next_action="Write policy.",
        ),
        main.NistCsfControl(
            id="PR.PS-01",
            function="PROTECT",
            category="Platform Security",
            outcome="Configuration management is applied.",
            status="fail",
            target_status="gap",
            gap_priority="high",
            gap="Global listener is open.",
            next_action="Bind service to localhost.",
        ),
    ]

    backlog = main.nist_csf_gap_backlog(controls)

    assert [item["id"] for item in backlog] == ["PR.PS-01", "GV.PO-01"]


def test_security_posture_queue_preserves_existing_nist_fields(tmp_path, monkeypatch) -> None:
    security_dir = tmp_path / "security-alerts"
    dashboard_dir = tmp_path / "dashboard"
    monkeypatch.setattr(main, "OPENCLAW_SECURITY_DIR", security_dir)
    monkeypatch.setattr(main, "OPENCLAW_DASHBOARD_DIR", dashboard_dir)
    monkeypatch.setattr(main, "openclaw_gateway_ok", lambda: True)
    monkeypatch.setattr(main, "disk_usage_percent", lambda: 10.0)
    monkeypatch.setattr(main, "read_listening_tcp_ports", lambda: [])
    main.ensure_dirs()
    (security_dir / "queue" / "nist-csf-profile.json").write_text(
        json.dumps(
            {
                "report": "2026-06-05-nist-csf-2.0-profile.md",
                "status_counts": {"pass": 1},
                "tier_note": "example tier",
                "gap_backlog": [{"id": "GV.PO-01"}],
            }
        ),
        encoding="utf-8",
    )
    (security_dir / "queue" / "nist-csf-gap-backlog.json").write_text(
        json.dumps([{"id": "GV.PO-01"}]),
        encoding="utf-8",
    )

    outputs = main.write_security_posture_outputs([])
    queue = json.loads(Path(outputs["queue"]).read_text(encoding="utf-8"))

    assert queue["nist_csf_profile"] == "nist-csf-profile.json"
    assert queue["nist_csf_gap_count"] == 1
    assert queue["nist_csf_tier_note"] == "example tier"
