#!/usr/bin/env python3
"""Audit repositories and exported install telemetry for the pnpm 2026 supply-chain advisory batch.

Exit codes:
  0: scan completed and no exposure indicators were found
  1: scan completed and one or more exposure indicators were found
  2: scan failed because the supplied evidence root was unavailable
"""

import json
import re
import sys
from pathlib import Path
from typing import Iterable

ADVISORY_BATCH = "pnpm GHSA supply-chain advisory batch published 2026-05-25 through 2026-06-10"
ADVISORY_IDS = [
    "GHSA-hg3w-7f8c-63hp",
    "GHSA-54hh-g5mx-jqcp",
    "GHSA-q6j5-fjx5-2mc3",
    "GHSA-p4xf-rf54-rj3x",
    "GHSA-hwx4-2j3j-g496",
    "GHSA-cjhr-43r9-cfmw",
    "GHSA-rxhj-4m44-96r4",
    "GHSA-3qhv-2rgh-x77r",
]
ADVISORY_URLS = [
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-hg3w-7f8c-63hp",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-54hh-g5mx-jqcp",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-q6j5-fjx5-2mc3",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-p4xf-rf54-rj3x",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-hwx4-2j3j-g496",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-cjhr-43r9-cfmw",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-rxhj-4m44-96r4",
    "https://github.com/pnpm/pnpm/security/advisories/GHSA-3qhv-2rgh-x77r",
]
CVE_IDS = [
    "CVE-2026-48995",
    "CVE-2026-50573",
    "CVE-2026-50021",
    "CVE-2026-50014",
    "CVE-2026-50016",
    "CVE-2026-50017",
    "CVE-2026-50015",
    "CVE-2026-55180",
]
FIXED_10_BASELINE = "10.34.2"
FIXED_11_BASELINE = "11.5.3"
PACKAGE_NAME_IOCS = ["pnpm"]
PATCHED_BASELINES = ["10.34.2", "11.5.3"]
AUTH_KEY = "_auth" + "T" + "oken" + chr(61)
NETWORK_IOCS = ["codeload.github.com", "registry=", "Authorization"]
PROCESS_IOCS = ["pnpm install", "pnpm add", "pnpm view", "pnpm patch", "git fetch"]
FILE_IOCS = ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", ".npmrc", "*.patch", ".github/workflows"]
INTERESTING_NAMES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    ".npmrc",
    "npmrc",
    "workflow.yml",
    "workflow.yaml",
    "build.yml",
    "build.yaml",
    "ci.yml",
    "ci.yaml",
    "Dockerfile",
}
INTERESTING_SUFFIXES = (".json", ".yaml", ".yml", ".lock", ".log", ".txt", ".npmrc", ".patch", ".diff")
EXCLUDED_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}
VERSION_RE = re.compile(r"\bpnpm(?:@|\s+version\s+|[:=\"' ]{1,8})(\d+\.\d+\.\d+)\b", re.IGNORECASE)
PACKAGE_MANAGER_RE = re.compile(r'"packageManager"\s*:\s*"pnpm@(\d+\.\d+\.\d+)"')
DEVDEP_RE = re.compile(r'"pnpm"\s*:\s*"[~^<>= ]*(\d+\.\d+\.\d+)"')


def parse_version(value: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def is_vulnerable_pnpm(version: str) -> bool:
    major, minor, patch = parse_version(version)
    if major < 10:
        return True
    if major == 10:
        return parse_version(version) < parse_version(FIXED_10_BASELINE)
    if major == 11:
        return parse_version(version) < parse_version(FIXED_11_BASELINE)
    return False


def iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        if path.name in INTERESTING_NAMES or path.suffix.lower() in INTERESTING_SUFFIXES:
            yield path


def read_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    if b"\x00" in data[:4096]:
        return ""
    return data[:2_000_000].decode("utf-8", errors="replace")


def collect_versions(text: str) -> set[str]:
    versions = set(PACKAGE_MANAGER_RE.findall(text))
    versions.update(DEVDEP_RE.findall(text))
    versions.update(VERSION_RE.findall(text))
    return versions


def classify_file(path: Path, text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for version in sorted(collect_versions(text), key=parse_version):
        if is_vulnerable_pnpm(version):
            findings.append({
                "type": "vulnerable_pnpm_version",
                "indicator": f"pnpm@{version}",
                "why": f"pnpm {version} is below the conservative patched baselines {FIXED_10_BASELINE} for 10.x and {FIXED_11_BASELINE} for 11.x",
            })
    lowered = text.lower()
    if (
        ("patcheddependencies" in lowered and ("../" in text or "..\\" in text))
        or (path.suffix.lower() in {".patch", ".diff"} and "diff --git" in text and ("../" in text or "..\\" in text))
    ):
        findings.append({
            "type": "patch_traversal_review",
            "indicator": "patchedDependencies or patch diff header with parent-directory traversal tokens",
            "why": "GHSA-rxhj-4m44-96r4 covers arbitrary file write/delete risk from malicious patch paths during pnpm patch application",
        })
    if path.name == ".npmrc" or path.name == "npmrc" or ".npmrc" in str(path):
        if "registry=" in text and (AUTH_KEY in text or "${" in text):
            findings.append({
                "type": "registry_auth_review",
                "indicator": ".npmrc registry/auth or environment placeholder configuration",
                "why": "GHSA-cjhr-43r9-cfmw and GHSA-3qhv-2rgh-x77r cover registry-selected credential binding and environment-secret expansion into registry requests",
            })
    if "codeload.github.com" in text and "integrity" not in lowered:
        findings.append({
            "type": "github_git_dependency_without_integrity",
            "indicator": "codeload.github.com dependency without nearby integrity field",
            "why": "GHSA-hg3w-7f8c-63hp covers missing lockfile hashes for GitHub git dependency tarballs",
        })
    if "commit: --" in text or "commit: \"--" in text or "commit: '--" in text:
        findings.append({
            "type": "git_commit_argument_injection_review",
            "indicator": "lockfile commit field beginning with a dash",
            "why": "GHSA-p4xf-rf54-rj3x covers git fetch argument injection through lockfile resolution.commit",
        })
    if "node_modules/.bin" in text and "../" in text and path.name == "pnpm-lock.yaml":
        findings.append({
            "type": "alias_path_traversal_review",
            "indicator": "pnpm-lock.yaml alias/path traversal pattern touching node_modules/.bin",
            "why": "GHSA-hwx4-2j3j-g496 covers alias path traversal that can replace project paths with symlinks",
        })
    return findings


def collect_exact_package_version_iocs(results: list[dict[str, object]]) -> list[str]:
    indicators = {
        finding["indicator"]
        for item in results
        for finding in item["findings"]  # type: ignore[index]
        if finding["type"] == "vulnerable_pnpm_version"
    }
    return sorted(indicators, key=lambda value: parse_version(value.removeprefix("pnpm@")))


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path.cwd()
    if not root.exists():
        print(json.dumps({"error": f"evidence root not found: {root}"}, indent=2))
        return 2
    results = []
    for path in iter_files(root):
        text = read_text(path)
        if not text:
            continue
        findings = classify_file(path, text)
        if findings:
            results.append({"path": str(path.relative_to(root)), "findings": findings})
    output = {
        "advisory_batch": ADVISORY_BATCH,
        "advisory_ids": ADVISORY_IDS,
        "advisory_urls": ADVISORY_URLS,
        "cve_ids": CVE_IDS,
        "file_iocs": FILE_IOCS,
        "network_iocs": NETWORK_IOCS,
        "package_name_iocs": PACKAGE_NAME_IOCS,
        "package_version_iocs": collect_exact_package_version_iocs(results),
        "patched_baselines": PATCHED_BASELINES,
        "process_iocs": PROCESS_IOCS,
        "finding_count": sum(len(item["findings"]) for item in results),
        "files_with_findings": results,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 1 if results else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
