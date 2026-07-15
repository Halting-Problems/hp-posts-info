#!/usr/bin/env python3
"""Audit IronWorm npm supply-chain exposure and eBPF credential-stealer activity."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

EVENT_ID = "ironworm-npm-ebpf-stealer-worm"
DISCLOSED = "2026-06-03"
WINDOW_START = "2026-06-01T00:00:00Z"
WINDOW_END = "2026-06-05T23:59:59Z"

MALICIOUS_PACKAGES = {
    "ai3": ["0.3.5"],
    "aonote": ["0.11.1"],
    "arjson": ["0.1.4"],
    "arnext": ["0.1.5"],
    "arnext-arkb": ["0.0.2"],
    "atomic-notes": ["0.5.3"],
    "create-arnext-app": ["0.0.10"],
    "cwao": ["0.5.6"],
    "cwao-tools": ["0.3.1"],
    "cwao-units": ["0.8.3"],
    "fpjson-lang": ["0.1.7"],
    "hbsig": ["0.3.2"],
    "monade": ["0.0.7"],
    "roidjs": ["0.1.7"],
    "test-ajs": ["0.1.19"],
    "test-weavedb-sdk": ["1.1.1"],
    "testnpmnmp": ["1.0.21"],
    "wao": ["0.41.2"],
    "warp-contracts-plugin-deploy-test": ["3.0.1"],
    "wdb-cli": ["0.1.1"],
    "wdb-core": ["0.1.2"],
    "wdb-sdk": ["0.1.2"],
    "weavedb-base": ["0.45.3"],
    "weavedb-client": ["0.45.3"],
    "weavedb-console": ["0.2.1"],
    "weavedb-contracts": ["0.45.2"],
    "weavedb-exm-sdk": ["0.7.4"],
    "weavedb-exm-sdk-web": ["0.7.4"],
}

SELECTORS = [
    "asteroiddao",
    "ocrybit",
    "ebpf",
    "rootkit",
    "weavedb",
    "asteroid-dao",
    "preinstall",
    "child_process",
    "process.env",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "GITHUB_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "Tor network",
    ".onion",
]

LOCKFILE_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
}


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def find_lockfile_hits(root: Path) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.name not in LOCKFILE_NAMES:
            continue
        try:
            text = load_text(path)
        except OSError:
            continue
        for package, versions in MALICIOUS_PACKAGES.items():
            if package not in text:
                continue
            version_hits = [version for version in versions if version in text]
            hits.append(
                {
                    "file": str(path),
                    "package": package,
                    "matched_versions": version_hits,
                    "confidence": "versioned" if version_hits else "package_name_only",
                }
            )
    return hits


def find_package_json_hits(root: Path) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for path in root.rglob("package.json"):
        if "node_modules" in path.parts:
            continue
        try:
            text = load_text(path)
        except OSError:
            continue
        for package in MALICIOUS_PACKAGES:
            if package in text:
                hits.append({"file": str(path), "package": package})
    return hits


def scan_node_modules(root: Path) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for package, versions in MALICIOUS_PACKAGES.items():
        parts = package.split("/")
        candidate = root / "node_modules" / parts[0] / parts[1] if package.startswith("@") else root / "node_modules" / package
        if not candidate.exists():
            continue
        package_json = candidate / "package.json"
        version = "unknown"
        scripts: dict[str, object] = {}
        if package_json.exists():
            try:
                metadata = json.loads(load_text(package_json))
                version = str(metadata.get("version", "unknown"))
                scripts = metadata.get("scripts", {}) if isinstance(metadata.get("scripts"), dict) else {}
            except (OSError, json.JSONDecodeError):
                pass
        hits.append(
            {
                "package": package,
                "path": str(candidate),
                "installed_version": version,
                "known_malicious_version": version in versions,
                "scripts": scripts,
            }
        )
    return hits


def scan_text_tree(root: Path, selectors: list[str]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    skipped = {".git", "dist", "build", ".next", ".astro"}
    for path in root.rglob("*"):
        if not path.is_file() or any(part in skipped for part in path.parts):
            continue
        try:
            text = load_text(path)
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for selector in selectors:
                if selector in line:
                    findings.append({"file": str(path), "line": line_no, "selector": selector, "evidence": line[:500]})
    return findings


def parse_github_audit(path: Path) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    interesting = re.compile(r"(oidc|workflow|package|npm|secret|token|publish|actions|asteroiddao|ocrybit)", re.I)
    if not path.exists():
        return findings
    files = [path] if path.is_file() else [entry for entry in path.rglob("*") if entry.is_file()]
    for file_path in files:
        try:
            lines = load_text(file_path).splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            if any(package in line for package in MALICIOUS_PACKAGES) or interesting.search(line):
                findings.append({"file": str(file_path), "line": line_no, "evidence": line[:1000]})
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."), help="Repository, monorepo, or exported source tree to scan.")
    parser.add_argument("--node-modules-root", type=Path, help="Directory that contains node_modules, if separate from --repo-root.")
    parser.add_argument("--log-dir", type=Path, help="Exported CI, package-manager, proxy, or endpoint logs.")
    parser.add_argument("--github-audit-dir", type=Path, help="Exported GitHub audit log JSON/CSV/text directory.")
    parser.add_argument("--output", type=Path, default=Path("hp-ironworm-ebpf-audit.json"))
    parser.add_argument("--fail-on-hit", action="store_true", help="Return exit code 2 when exposure evidence is found.")
    args = parser.parse_args()

    for input_path in [args.repo_root, args.node_modules_root, args.log_dir, args.github_audit_dir]:
        if input_path and not input_path.exists():
            print(f"input path not found: {input_path}", file=sys.stderr)
            return 1

    repo_root = args.repo_root.expanduser().resolve()
    module_root = (args.node_modules_root or args.repo_root).expanduser().resolve()
    result = {
        "event_id": EVENT_ID,
        "disclosed": DISCLOSED,
        "exposure_window": {"start": WINDOW_START, "end": WINDOW_END},
        "malicious_packages": MALICIOUS_PACKAGES,
        "repository_dependency_hits": find_package_json_hits(repo_root),
        "lockfile_hits": find_lockfile_hits(repo_root),
        "installed_package_hits": scan_node_modules(module_root),
        "source_selector_hits": scan_text_tree(repo_root, SELECTORS),
        "log_selector_hits": scan_text_tree(args.log_dir.expanduser().resolve(), SELECTORS) if args.log_dir else [],
        "github_audit_hits": parse_github_audit(args.github_audit_dir.expanduser().resolve()) if args.github_audit_dir else [],
    }
    result["positive_signal"] = any(
        result[key]
        for key in [
            "repository_dependency_hits",
            "lockfile_hits",
            "installed_package_hits",
            "source_selector_hits",
            "log_selector_hits",
            "github_audit_hits",
        ]
    )
    result["recommended_escalation"] = (
        "Treat hosts or runners with affected package execution as credential-exposed; rotate npm, GitHub, cloud, and deployment credentials from clean systems."
        if result["positive_signal"]
        else "No local evidence found in supplied inputs; preserve negative results and verify registry/proxy telemetry coverage."
    )

    output = args.output.expanduser().resolve()
    output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"output": str(output), "positive_signal": result["positive_signal"]}, indent=2))
    return 2 if args.fail_on_hit and result["positive_signal"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
