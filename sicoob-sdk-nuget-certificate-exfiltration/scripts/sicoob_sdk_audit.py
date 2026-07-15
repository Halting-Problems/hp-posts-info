#!/usr/bin/env python3
"""Audit repositories, package caches, and exported logs for Sicoob.Sdk exposure."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path


PACKAGE_ID = "Sicoob.Sdk"
MALICIOUS_VERSIONS = {"2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4"}
EXPOSURE_START_UTC = "2026-05-05T15:09:00Z"
SOCKET_PUBLICATION_DATE = "2026-05-28"
SENTRY_HOST = "o4511335034847232.ingest.de.sentry.io"
SENTRY_DSN = "https://d565e3f03d0b1a7c8935d7ff94237316@o4511335034847232.ingest.de.sentry.io/4511337546317904"
SENTRY_PROJECT_ID = "4511337546317904"
SENTRY_PUBLIC_KEY = "d565e3f03d0b1a7c8935d7ff94237316"
RELATED_NUGET_OWNER = "sicoob"
IMPERSONATION_ORG = "Sicoob-Cooperativa"
CONSTRUCTOR_SELECTORS = ("new SicoobClient(", "SicoobClient(")
PACKAGE_SELECTORS = (
    "PackageReference Include=\"Sicoob.Sdk\"",
    "PackageReference Include='Sicoob.Sdk'",
    "dotnet add package Sicoob.Sdk",
    "<id>Sicoob.Sdk</id>",
    "\"Sicoob.Sdk\"",
    "'Sicoob.Sdk'",
)
NETWORK_SELECTORS = (SENTRY_HOST, SENTRY_DSN, SENTRY_PROJECT_ID, SENTRY_PUBLIC_KEY)
DLL_SELECTORS = (
    "cliend_id:",
    "pass:",
    "ReadAllBytes",
    "ToBase64String",
    "CaptureMessage",
    "SentrySdk",
)


@dataclass
class Finding:
    category: str
    path: str
    selector: str
    detail: str
    severity: str


def decode_bytes(data: bytes) -> str:
    parts = []
    for encoding in ("utf-8", "utf-16le", "latin-1"):
        try:
            parts.append(data.decode(encoding, errors="ignore"))
        except Exception:
            pass
    return "\n".join(parts)


def read_text(path: Path, max_bytes: int) -> str:
    try:
        return decode_bytes(path.read_bytes()[:max_bytes])
    except OSError:
        return ""


def is_skipped(path: Path, root: Path, skip_dirs: set[str]) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    return any(part in skip_dirs for part in rel.parts)


def scan_text_file(path: Path, root: Path, args: argparse.Namespace) -> list[Finding]:
    text = read_text(path, args.max_file_bytes)
    findings: list[Finding] = []
    if not text:
        return findings

    selectors = list(PACKAGE_SELECTORS) + list(CONSTRUCTOR_SELECTORS) + list(NETWORK_SELECTORS)
    for selector in selectors:
        if selector in text:
            category = "network_ioc" if selector in NETWORK_SELECTORS else "dependency_or_usage"
            severity = "critical" if selector in NETWORK_SELECTORS else "high"
            findings.append(Finding(category, str(path), selector, "selector present in text file", severity))

    version_patterns = [
        re.compile(r"Sicoob\.Sdk[^0-9]{0,80}" + re.escape(version), re.IGNORECASE)
        for version in MALICIOUS_VERSIONS
    ]
    for pattern in version_patterns:
        if pattern.search(text):
            findings.append(Finding("malicious_version", str(path), pattern.pattern, "affected Sicoob.Sdk version reference", "critical"))

    return findings


def scan_nupkg(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            nuspec_names = [name for name in names if name.lower().endswith(".nuspec")]
            for name in nuspec_names:
                text = decode_bytes(zf.read(name))
                if f"<id>{PACKAGE_ID}</id>" in text:
                    version_match = re.search(r"<version>([^<]+)</version>", text)
                    version = version_match.group(1) if version_match else "unknown"
                    severity = "critical" if version in MALICIOUS_VERSIONS else "medium"
                    findings.append(Finding("nupkg_identity", str(path), f"{PACKAGE_ID}@{version}", f"NuGet package archive contains {PACKAGE_ID}", severity))
            for name in names:
                if not name.lower().endswith(".dll"):
                    continue
                text = decode_bytes(zf.read(name))
                hits = [selector for selector in DLL_SELECTORS + NETWORK_SELECTORS if selector in text]
                if hits:
                    severity = "critical" if SENTRY_HOST in hits or SENTRY_DSN in hits else "high"
                    findings.append(Finding("nupkg_static_indicator", f"{path}!{name}", ",".join(hits), "DLL contains Sicoob exfiltration selectors", severity))
    except (OSError, zipfile.BadZipFile) as exc:
        findings.append(Finding("scan_error", str(path), "zipfile", f"could not inspect nupkg: {exc}", "low"))
    return findings


def walk_roots(roots: list[Path], args: argparse.Namespace) -> list[Finding]:
    skip_dirs = set(args.skip_dir)
    findings: list[Finding] = []
    for root in roots:
        if not root.exists():
            findings.append(Finding("input_error", str(root), "missing_path", "root does not exist", "low"))
            continue
        if root.is_file():
            files = [root]
            base = root.parent
        else:
            files = [p for p in root.rglob("*") if p.is_file() and not is_skipped(p, root, skip_dirs)]
            base = root
        for path in files:
            if path.suffix.lower() == ".nupkg":
                findings.extend(scan_nupkg(path))
            findings.extend(scan_text_file(path, base, args))
    return findings


def write_outputs(findings: list[Finding], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    payload = {
        "incident": "sicoob-sdk-nuget-certificate-exfiltration",
        "package": PACKAGE_ID,
        "malicious_versions": sorted(MALICIOUS_VERSIONS),
        "exposure_start_utc": EXPOSURE_START_UTC,
        "socket_publication_date": SOCKET_PUBLICATION_DATE,
        "sentry_host": SENTRY_HOST,
        "sentry_project_id": SENTRY_PROJECT_ID,
        "sentry_public_key": SENTRY_PUBLIC_KEY,
        "related_nuget_owner": RELATED_NUGET_OWNER,
        "impersonation_org": IMPERSONATION_ORG,
        "findings": [asdict(finding) for finding in findings],
    }
    (output / "sicoob_sdk_audit_findings.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    with (output / "sicoob_sdk_audit_findings.csv").open("w", encoding="utf-8") as fh:
        fh.write("category,path,selector,severity,detail\n")
        for finding in findings:
            row = [finding.category, finding.path, finding.selector, finding.severity, finding.detail]
            fh.write(",".join('"' + value.replace('"', '""') + '"' for value in row) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+", type=Path, help="Repository, package cache, exported telemetry, or .nupkg paths to scan.")
    parser.add_argument("--output", type=Path, default=Path("sicoob-sdk-audit-output"), help="Directory for JSON and CSV findings.")
    parser.add_argument("--max-file-bytes", type=int, default=2_000_000, help="Maximum bytes read from each non-nupkg file.")
    parser.add_argument("--skip-dir", action="append", default=[".git", "node_modules", "bin", "obj", "dist", "build"], help="Directory name to skip; may be repeated.")
    parser.add_argument("--fail-on-hit", action="store_true", help="Exit 2 when any high or critical finding is found.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.max_file_bytes < 1024:
        print("--max-file-bytes must be at least 1024", file=sys.stderr)
        return 1

    findings = walk_roots(args.roots, args)
    write_outputs(findings, args.output)

    critical_or_high = [f for f in findings if f.severity in {"critical", "high"}]
    print(f"scanned_roots={len(args.roots)} findings={len(findings)} high_or_critical={len(critical_or_high)} output={args.output}")
    for finding in critical_or_high[:25]:
        print(f"{finding.severity}: {finding.category}: {finding.path}: {finding.selector}")

    if args.fail_on_hit and critical_or_high:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
