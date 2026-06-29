#!/usr/bin/env python3
"""Audit repositories, lockfiles, CI definitions, and exported logs for exposure to GHSA-5vwr-qchf-q4pf.

Exit codes:
  0: scan completed and no exposure indicators were found
  1: scan completed and one or more exposure indicators were found
  2: scan failed because the supplied evidence root was unavailable
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable

AFFECTED_PACKAGE = "@cyclonedx/cdxgen"
FIXED_VERSION = "12.4.3"
VULNERABLE_RANGE = "@cyclonedx/cdxgen < 12.4.3"
GHSA_ID = "GHSA-5vwr-qchf-q4pf"
ADVISORY_URL = "https://github.com/cdxgen/cdxgen/security/advisories/GHSA-5vwr-qchf-q4pf"
FIX_PULL_REQUEST = "https://github.com/cdxgen/cdxgen/pull/4059"
NPM_FIXED_TARBALL_INTEGRITY = "sha512-1cg3zWCW5J+nU2TDXi3ehM5n2PdznlWQ8KNr/blGIGGu995pZECUJKDB7iOVMRRC+C5GNoDMmN8CYLTX0/vr7A=="
MAVEN_SCAN_TOKENS = ["--type maven", "-t maven", "CDXGEN_TYPE=maven", "cdxgen -t", "cdxgen --type"]
WORKFLOW_DIRECTORY = ".github/workflows"
INTERESTING_FILE_NAMES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "workflow.yml",
    "workflow.yaml",
    "build.yml",
    "build.yaml",
    "ci.yml",
    "ci.yaml",
    "action.yml",
    "action.yaml",
    "Dockerfile",
}
INTERESTING_SUFFIXES = (".yml", ".yaml", ".json", ".lock", ".log", ".txt", ".md", ".toml")
EXCLUDED_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}
VERSION_RE = re.compile(r"@cyclonedx/cdxgen[^0-9]{0,24}(\d+\.\d+\.\d+)", re.IGNORECASE)
JSON_VERSION_RE = re.compile(r'"@cyclonedx/cdxgen"\s*:\s*"[~^<>= ]*(\d+\.\d+\.\d+)"')


def parse_version(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    return tuple(int(part) for part in parts[:3])  # type: ignore[return-value]


def is_vulnerable(version: str) -> bool:
    return parse_version(version) < parse_version(FIXED_VERSION)


def should_scan(path: Path) -> bool:
    if path.name in INTERESTING_FILE_NAMES:
        return True
    if WORKFLOW_DIRECTORY in path.as_posix() and path.suffix.lower() in (".yml", ".yaml"):
        return True
    return path.suffix.lower() in INTERESTING_SUFFIXES


def iter_files(root: Path) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [dirname for dirname in dirs if dirname not in EXCLUDED_DIRS]
        for filename in files:
            candidate = Path(current) / filename
            if should_scan(candidate):
                yield candidate


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"READ_ERROR:{type(exc).__name__}:{exc}"


def scan_file(path: Path, text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if AFFECTED_PACKAGE in text:
        versions = {match.group(1) for match in VERSION_RE.finditer(text)}
        versions.update(match.group(1) for match in JSON_VERSION_RE.finditer(text))
        vulnerable_versions = sorted(version for version in versions if is_vulnerable(version))
        if vulnerable_versions:
            findings.append({
                "file": str(path),
                "indicator": VULNERABLE_RANGE,
                "evidence": ",".join(vulnerable_versions),
                "reason": "dependency version before 12.4.3",
            })
        elif not versions:
            findings.append({
                "file": str(path),
                "indicator": AFFECTED_PACKAGE,
                "evidence": "version_not_extracted",
                "reason": "cdxgen dependency or invocation present; version requires manual review",
            })
    lower_text = text.lower()
    if "cdxgen" in lower_text and any(token.lower() in lower_text for token in MAVEN_SCAN_TOKENS):
        findings.append({
            "file": str(path),
            "indicator": "cdxgen Maven scanner invocation",
            "evidence": "maven_scan_reference",
            "reason": "SBOM job may scan Maven projects and should be paired with fixed cdxgen version",
        })
    return findings


def main() -> int:
    root_arg = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SCAN_ROOT", ".")
    root = Path(root_arg).resolve()
    out_dir = Path(os.environ.get("OUT", "hp-cyclonedx-cdxgen-maven-scanning-command-injection-audit"))
    if not root.exists() or not root.is_dir():
        print(json.dumps({"status": "error", "reason": "scan root is not a directory", "root": str(root)}))
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)
    findings: list[dict[str, str]] = []
    for path in iter_files(root):
        text = read_text(path)
        findings.extend(scan_file(path, text))
    result = {
        "advisory": GHSA_ID,
        "advisory_url": ADVISORY_URL,
        "fix_pull_request": FIX_PULL_REQUEST,
        "affected_package": AFFECTED_PACKAGE,
        "fixed_version": FIXED_VERSION,
        "fixed_tarball_integrity": NPM_FIXED_TARBALL_INTEGRITY,
        "scan_root": str(root),
        "findings": findings,
    }
    result_path = out_dir / "cdxgen-maven-scanner-exposure-findings.json"
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if findings:
        print(json.dumps({"status": "alert", "findings": len(findings), "output": str(result_path)}))
        return 1
    print(json.dumps({"status": "clean", "findings": 0, "output": str(result_path)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
