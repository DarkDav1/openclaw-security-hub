#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_env() -> dict[str, str]:
    env = os.environ.copy()
    env_path = PROJECT_DIR / ".env"
    if not env_path.exists():
        return env
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    return env


def security_dir(env: dict[str, str]) -> Path:
    configured = env.get("OPENCLAW_HOST_SECURITY_DIR") or env.get("OPENCLAW_SECURITY_DIR")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".openclaw" / "workspace" / "security-alerts"


def run(command: list[str], env: dict[str, str]) -> dict[str, object]:
    completed = subprocess.run(
        command,
        cwd=PROJECT_DIR,
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
        "ok": completed.returncode == 0,
    }


def action_commands(action: str) -> list[list[str]]:
    if action == "disable_legacy_dashboard_service":
        return [["sudo", "-n", str(PROJECT_DIR / "scripts" / "disable-legacy-dashboard-service.sh")]]
    if action == "restart_openclaw_gateway":
        return [["systemctl", "--user", "restart", "openclaw-gateway.service"]]
    if action == "stop_ollama_service":
        return [
            ["systemctl", "--user", "stop", "ollama.service"],
            ["sudo", "-n", "systemctl", "stop", "ollama.service"],
        ]
    raise ValueError(f"Unsupported host remediation action: {action}")


def update_queue_summary(queue_dir: Path, requests: list[dict[str, object]]) -> None:
    queue_path = queue_dir / "queue.json"
    if queue_path.exists():
        try:
            queue = json.loads(queue_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            queue = {}
    else:
        queue = {}
    pending = [
        item
        for item in requests
        if item.get("status") in {"pending", "approved", "needs_host_runner", "needs_sudo"}
    ]
    queue.update(
        {
            "remediation_request_count": len(requests),
            "remediation_pending_count": len(pending),
            "remediation_requests": "remediation-requests.json",
            "remediation_pending": [
                {
                    "id": item.get("id"),
                    "action": item.get("action"),
                    "status": item.get("status"),
                    "risk": item.get("risk"),
                    "executor": item.get("executor"),
                    "title": item.get("title"),
                }
                for item in pending[-20:]
            ],
        }
    )
    queue_path.write_text(json.dumps(queue, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    env = load_env()
    queue_dir = security_dir(env) / "queue"
    requests_path = queue_dir / "remediation-requests.json"
    results_path = queue_dir / "remediation-results.jsonl"
    if not requests_path.exists():
        print("No remediation request file exists.")
        return 0

    requests = json.loads(requests_path.read_text(encoding="utf-8"))
    changed = False
    executed_count = 0

    for item in requests:
        if item.get("executor") != "host_runner":
            continue
        if item.get("status") not in {"approved", "needs_host_runner", "needs_sudo"}:
            continue
        action = str(item.get("action", ""))
        result = {"started_at": now(), "action": action, "steps": []}
        try:
            for command in action_commands(action):
                step = run(command, env)
                result["steps"].append(step)
                if not step["ok"]:
                    if command[0] == "sudo":
                        item["status"] = "needs_sudo"
                    else:
                        item["status"] = "failed"
                    break
            else:
                verification = [
                    run([str(PROJECT_DIR / "scripts" / "security-scan.sh")], env),
                    run([str(PROJECT_DIR / "scripts" / "nist-csf-check.sh")], env),
                ]
                result["verification"] = verification
                item["status"] = "executed" if all(step["ok"] for step in verification) else "verification_failed"
                item["executed_at"] = now()
                executed_count += 1
        except Exception as exc:
            result["error"] = str(exc)
            item["status"] = "failed"
        result["finished_at"] = now()
        item["result"] = result
        changed = True
        with results_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(item, ensure_ascii=False) + "\n")

    if changed:
        requests_path.write_text(json.dumps(requests, indent=2, ensure_ascii=False), encoding="utf-8")
        update_queue_summary(queue_dir, requests)

    print(json.dumps({"ok": True, "executed_count": executed_count, "changed": changed}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
