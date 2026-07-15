#!/usr/bin/env python3
"""Audit repositories and workspaces for Miasma/Hades AI Coding Assistant and VS Code task compromise."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CAMPAIGN = "Miasma/Hades/TeamPCP"
SUSPICIOUS_STRINGS = [
    "folderOpen",
    "setup.js",
    "SessionStart",
    "masscan.cloud",
    "getsession.org",
    "git-tanstack.com",
    "EveryBoiWeBuildIsAWormyBoi",
    "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner",
    "OhNoWhatsGoingOnWithGitHub",
    "Hades: The End for the Damned",
]


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except (UnicodeDecodeError, OSError):
        return ""


def audit_tasks_json(path: Path, text: str) -> dict[str, object] | None:
    # Look for runOn: folderOpen
    has_folder_open = False
    has_setup_js = "setup.js" in text

    try:
        data = json.loads(text)
        tasks = data.get("tasks", [])
        if not isinstance(tasks, list):
            tasks = [tasks]
        for task in tasks:
            if not isinstance(task, dict):
                continue
            run_options = task.get("runOptions", {})
            if isinstance(run_options, dict):
                run_on = run_options.get("runOn")
                if run_on == "folderOpen" or (isinstance(run_on, list) and "folderOpen" in run_on):
                    has_folder_open = True
    except Exception:
        # Fallback to regex/string match if JSON parsing fails (e.g., has comments)
        if "folderOpen" in text:
            has_folder_open = True

    if has_folder_open or has_setup_js:
        return {
            "file": str(path),
            "type": "tasks.json",
            "has_runOn_folderOpen": has_folder_open,
            "has_setup_js_ref": has_setup_js,
            "severity": "critical" if (has_folder_open and has_setup_js) else "medium",
            "reason": "VS Code task configured to run automatically on folder open or references setup.js.",
        }
    return None


def audit_ai_settings_json(path: Path, text: str, tool_name: str) -> dict[str, object] | None:
    suspicious_hits = [s for s in SUSPICIOUS_STRINGS if s in text]

    # AI assistant settings files are suspicious if they exist and contain setup.js or other C2 indicators
    if suspicious_hits or "setup.js" in text or "run" in text or "command" in text:
        return {
            "file": str(path),
            "type": f"{tool_name}_settings",
            "matched_indicators": suspicious_hits,
            "severity": "critical" if "setup.js" in text else "high",
            "reason": f"AI coding tool settings file for {tool_name} contains execution hooks or suspicious triggers.",
        }
    return None


def audit_cursor_rule(path: Path, text: str) -> dict[str, object] | None:
    suspicious_hits = [s for s in SUSPICIOUS_STRINGS if s in text]

    # Cursor .mdc files are rules. If they instruct the assistant to execute shell scripts or setup.js
    if "setup.js" in text or "execute" in text.lower() or "run" in text.lower() or suspicious_hits:
        return {
            "file": str(path),
            "type": "cursor_rule",
            "matched_indicators": suspicious_hits,
            "severity": "high",
            "reason": "Cursor rule instructing agent to run setup scripts or contains Miasma indicators.",
        }
    return None


def audit_setup_js(path: Path, text: str) -> dict[str, object] | None:
    suspicious_hits = [s for s in SUSPICIOUS_STRINGS if s in text]
    size_mb = path.stat().st_size / (1024 * 1024)

    # Typically, the malicious setup.js is a large obfuscated file (4MB+)
    is_large = size_mb > 1.0
    if is_large or suspicious_hits or "process.env" in text or "eval" in text:
        return {
            "file": str(path),
            "type": "payload_candidate",
            "file_size_mb": round(size_mb, 2),
            "matched_indicators": suspicious_hits,
            "severity": "critical",
            "reason": "Malicious payload candidate matching Miasma signature or execution characteristics.",
        }
    return None


def iter_files(root: Path):
    exclude_dirs = {".git", "node_modules", "vendor", "dist", "venv", ".venv"}
    for path in root.rglob("*"):
        if path.is_file() and not any(part in path.parts for part in exclude_dirs):
            yield path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, default=[Path(".")], help="Directories or files to scan (defaults to current directory)")
    parser.add_argument("--out", type=Path, default=Path("miasma-findings.json"), help="Output JSON path")
    args = parser.parse_args()

    findings = []

    for input_path in args.paths:
        if not input_path.exists():
            print(f"[-] Path does not exist: {input_path}", file=sys.stderr)
            continue

        paths = iter_files(input_path) if input_path.is_dir() else [input_path]
        for path in paths:
            name = path.name.lower()
            text = read_text(path)

            result = None
            if name == "tasks.json":
                result = audit_tasks_json(path, text)
            elif name == "settings.json":
                if ".claude" in path.parts:
                    result = audit_ai_settings_json(path, text, "claude")
                elif ".gemini" in path.parts:
                    result = audit_ai_settings_json(path, text, "gemini")
            elif path.suffix == ".mdc" and ".cursor" in path.parts:
                result = audit_cursor_rule(path, text)
            elif name == "setup.js" or (path.suffix == ".js" and "setup" in name):
                result = audit_setup_js(path, text)

            if result:
                findings.append(result)

    payload = {
        "campaign": CAMPAIGN,
        "suspicious_strings": SUSPICIOUS_STRINGS,
        "finding_count": len(findings),
        "findings": findings,
    }

    args.out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[+] Wrote {len(findings)} findings to {args.out}")

    # Print findings to stdout for immediate visibility
    if findings:
        print("\n[!] SUSPICIOUS OR MALICIOUS ARTIFACTS FOUNDER:")
        for f in findings:
            print(f"  - [{f['severity'].upper()}] {f['file']}: {f['reason']}")

    return 2 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
