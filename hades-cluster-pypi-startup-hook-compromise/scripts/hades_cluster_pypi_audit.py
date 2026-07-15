#!/usr/bin/env python3
"""Audit Hades Cluster PyPI supply-chain exposure."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

EVENT_ID = "hades-cluster-pypi-startup-hook-compromise"
DISCLOSED = "2026-06-07"
WINDOW_START = "2026-06-06T00:00:00Z"
WINDOW_END = "2026-06-07T23:59:59Z"

MALICIOUS_PACKAGES = {
    "bramin": ["0.0.2", "0.0.3", "0.0.4"],
    "cmd2func": ["0.2.2", "0.2.3"],
    "coolbox": ["0.4.1", "0.4.2"],
    "dynamo-release": ["1.5.4"],
    "executor-engine": ["0.3.4", "0.3.5"],
    "executor-http": ["0.1.3", "0.1.4"],
    "funcdesc": ["0.2.2", "0.2.3"],
    "magique": ["0.6.8", "0.6.9"],
    "magique-ai": ["0.4.4", "0.4.5"],
    "mrbios": ["0.1.1", "0.1.2"],
    "napari-ufish": ["0.0.2", "0.0.3"],
    "nucbox": ["0.1.2", "0.1.3"],
    "okite": ["0.0.7", "0.0.8"],
    "pantheon-agents": ["0.6.1", "0.6.2"],
    "pantheon-toolsets": ["0.5.5", "0.5.6"],
    "spateo-release": ["1.1.2"],
    "synago": ["0.1.1", "0.1.2"],
    "ufish": ["0.1.2", "0.1.3"],
    "uprobe": ["0.1.3", "0.1.4"],
}

SELECTORS = [
    "hades-setup.pth",
    "_index.js",
    "Hades - The End for the Damned",
    "tartarean",
    "cerberus",
    "charon",
    "thanatos",
    "stygian",
    "styx",
    "lethe",
    "persephone",
]

LOCKFILE_NAMES = {
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "pixi.lock",
    "conda-lock.yml",
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


def scan_site_packages(root: Path) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    # Search for site-packages directories under the root
    site_packages_dirs = []
    if (root / "site-packages").exists():
        site_packages_dirs.append(root / "site-packages")
    else:
        for p in root.rglob("site-packages"):
            if p.is_dir():
                site_packages_dirs.append(p)

    for sp in site_packages_dirs:
        for package, versions in MALICIOUS_PACKAGES.items():
            candidate = sp / package
            if not candidate.exists():
                continue
            # Try to find version metadata via dist-info or egg-info
            version = "unknown"
            dist_infos = list(sp.glob(f"{package.replace('-', '_')}-*.dist-info")) + \
                         list(sp.glob(f"{package}-*.dist-info"))
            if dist_infos:
                meta = dist_infos[0] / "METADATA"
                if meta.exists():
                    try:
                        for line in load_text(meta).splitlines():
                            if line.startswith("Version:"):
                                version = line.split(":", 1)[1].strip()
                                break
                    except OSError:
                        pass
            pth_file = sp / f"{package}-setup.pth"
            hits.append(
                {
                    "package": package,
                    "path": str(candidate),
                    "installed_version": version,
                    "known_malicious_version": version in versions,
                    "has_setup_pth": pth_file.exists(),
                }
            )
    return hits


def scan_text_tree(root: Path, selectors: list[str]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    skipped = {".git", "dist", "build", ".next", ".astro", "node_modules"}
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
    interesting = re.compile(r"(oidc|workflow|package|pypi|secret|token|publish|actions)", re.I)
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
    parser.add_argument("--site-packages-root", type=Path, help="Directory that contains Python site-packages, if separate from --repo-root.")
    parser.add_argument("--log-dir", type=Path, help="Exported CI, package-manager, proxy, or endpoint logs.")
    parser.add_argument("--github-audit-dir", type=Path, help="Exported GitHub audit log JSON/CSV/text directory.")
    parser.add_argument("--output", type=Path, default=Path("hp-hades-cluster-pypi-audit.json"))
    parser.add_argument("--fail-on-hit", action="store_true", help="Return exit code 2 when exposure evidence is found.")
    args = parser.parse_args()

    for input_path in [args.repo_root, args.site_packages_root, args.log_dir, args.github_audit_dir]:
        if input_path and not input_path.exists():
            print(f"input path not found: {input_path}", file=sys.stderr)
            return 1

    repo_root = args.repo_root.expanduser().resolve()
    sp_root = (args.site_packages_root or args.repo_root).expanduser().resolve()
    result = {
        "event_id": EVENT_ID,
        "disclosed": DISCLOSED,
        "exposure_window": {"start": WINDOW_START, "end": WINDOW_END},
        "malicious_packages": MALICIOUS_PACKAGES,
        "lockfile_hits": find_lockfile_hits(repo_root),
        "installed_package_hits": scan_site_packages(sp_root),
        "source_selector_hits": scan_text_tree(repo_root, SELECTORS),
        "log_selector_hits": scan_text_tree(args.log_dir.expanduser().resolve(), SELECTORS) if args.log_dir else [],
        "github_audit_hits": parse_github_audit(args.github_audit_dir.expanduser().resolve()) if args.github_audit_dir else [],
    }
    result["positive_signal"] = any(
        result[key]
        for key in [
            "lockfile_hits",
            "installed_package_hits",
            "source_selector_hits",
            "log_selector_hits",
            "github_audit_hits",
        ]
    )
    result["recommended_escalation"] = (
        "Treat hosts or runners with affected package installation as credential-exposed; rotate pypi, npm, GitHub, cloud, and deployment credentials from clean systems."
        if result["positive_signal"]
        else "No local evidence found in supplied inputs; preserve negative results and verify registry/proxy telemetry coverage."
    )

    output = args.output.expanduser().resolve()
    output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"output": str(output), "positive_signal": result["positive_signal"]}, indent=2))
    return 2 if args.fail_on_hit and result["positive_signal"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
