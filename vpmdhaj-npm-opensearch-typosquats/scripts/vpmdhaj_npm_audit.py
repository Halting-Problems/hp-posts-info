#!/usr/bin/env python3
"""Scope exposure to the May 2026 vpmdhaj npm typosquat credential theft set."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


MALICIOUS_PACKAGES = {
    "@vpmdhaj/opensearch-setup": ["1.0.9102", "1.0.9103"],
    "@vpmdhaj/elastic-helper": ["1.0.7267", "1.0.7268", "1.0.7269", "1.0.7270"],
    "@vpmdhaj/aws-compat": [],
    "@vpmdhaj/aws-credential-provider-env": [],
    "@vpmdhaj/aws-credential-provider-http": [],
    "@vpmdhaj/aws-sdk-client-opensearch": [],
    "@vpmdhaj/aws-sdk-client-sts": [],
    "@vpmdhaj/aws-sdk-credential-provider-node": [],
    "@vpmdhaj/aws-sdk-types": [],
    "@vpmdhaj/bun": [],
    "@vpmdhaj/opensearch": [],
    "@vpmdhaj/opensearch-project": [],
    "@vpmdhaj/opensearch-js": [],
    "@vpmdhaj/sts-client": [],
}

SUSPICIOUS_DOMAINS = [
    "aab.sportsontheweb.net",
    "www.sportsontheweb.net",
]

SUSPICIOUS_PATHS = [
    "/api/b",
    "/.aws/config",
    "/.aws/credentials",
    "/.vault-token",
    "/var/run/secrets/kubernetes.io/serviceaccount",
]

SUSPICIOUS_STRINGS = [
    "NPX_ISOLATED_ENVIRONMENT",
    "x-forwarded-host",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "NPM_TOKEN",
    "VAULT_TOKEN",
]

SUSPICIOUS_HASHES = [
    "a39155771e93e65b05195c8a705dfc03aa85c2ec682505f0d557233a8f275145",
    "9d962ed605bb4a39991f8fab9b1d2e423ea4d545f23fd44d9473a6423d94bbf",
]

TEXT_EXTENSIONS = {
    ".cjs",
    ".conf",
    ".env",
    ".js",
    ".json",
    ".lock",
    ".log",
    ".mjs",
    ".out",
    ".txt",
    ".yaml",
    ".yml",
}

PACKAGE_FILES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+", type=Path, help="Repository, workspace, cache, or exported telemetry roots to scan.")
    parser.add_argument("--cloudtrail", type=Path, help="Directory or JSON file with exported CloudTrail records.")
    parser.add_argument("--out", type=Path, default=Path("vpmdhaj-npm-audit-findings.json"), help="JSON findings output path.")
    parser.add_argument("--max-file-bytes", type=int, default=8_000_000, help="Skip larger files to avoid binary/cache blowups.")
    return parser.parse_args()


def iter_files(roots: Iterable[Path]) -> Iterable[Path]:
    for root in roots:
        if root.is_file():
            yield root
            continue
        if not root.exists():
            print(f"[!] Missing root: {root}", file=sys.stderr)
            continue
        for path in root.rglob("*"):
            if path.is_file():
                yield path


def read_text(path: Path, max_file_bytes: int) -> str | None:
    try:
        if path.stat().st_size > max_file_bytes:
            return None
        if path.name not in PACKAGE_FILES and path.suffix.lower() not in TEXT_EXTENSIONS:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def record(findings: list[dict[str, Any]], kind: str, path: Path, value: str, detail: str = "") -> None:
    findings.append({
        "kind": kind,
        "path": str(path),
        "value": value,
        "detail": detail,
    })


def scan_package_json(path: Path, text: str, findings: list[dict[str, Any]]) -> None:
    if path.name != "package.json":
        return
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "bundledDependencies"):
        deps = data.get(field)
        if not isinstance(deps, dict):
            continue
        for package, spec in deps.items():
            if package in MALICIOUS_PACKAGES:
                record(findings, "manifest_dependency", path, package, f"{field}: {spec}")


def scan_text(path: Path, text: str, findings: list[dict[str, Any]]) -> None:
    lowered = text.lower()
    for package, versions in MALICIOUS_PACKAGES.items():
        if package.lower() in lowered:
            version_hits = [version for version in versions if version and version in text]
            detail = "versions: " + ", ".join(version_hits) if version_hits else "package reference"
            record(findings, "package_reference", path, package, detail)
    for domain in SUSPICIOUS_DOMAINS:
        if domain in lowered:
            record(findings, "network_ioc", path, domain)
    for suspicious_path in SUSPICIOUS_PATHS:
        if suspicious_path.lower() in lowered:
            record(findings, "secret_path_reference", path, suspicious_path)
    for marker in SUSPICIOUS_STRINGS:
        if marker.lower() in lowered:
            record(findings, "credential_marker", path, marker)
    for digest in SUSPICIOUS_HASHES:
        if digest in lowered:
            record(findings, "sha256_ioc", path, digest)
    if re.search(r"\bbun\s+run\b|\bbun\s+x\b|\bbunfig\.toml\b", text, flags=re.IGNORECASE):
        record(findings, "bun_execution_context", path, "bun runtime reference")


def normalize_records(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("Records"), list):
        for record_item in payload["Records"]:
            if isinstance(record_item, dict):
                yield record_item
    elif isinstance(payload, list):
        for record_item in payload:
            if isinstance(record_item, dict):
                yield record_item
    elif isinstance(payload, dict):
        yield payload


def scan_cloudtrail(path: Path, findings: list[dict[str, Any]]) -> None:
    targets = [path] if path.is_file() else list(path.rglob("*.json"))
    for target in targets:
        try:
            payload = json.loads(target.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            continue
        for item in normalize_records(payload):
            event_name = str(item.get("eventName", ""))
            source = str(item.get("eventSource", ""))
            request = json.dumps(item.get("requestParameters", {}), sort_keys=True)
            user_agent = str(item.get("userAgent", ""))
            combined = f"{event_name} {source} {request} {user_agent}".lower()
            if "assumerolewithwebidentity" in combined or "getcalleridentity" in combined:
                record(findings, "cloudtrail_aws_identity_check", target, event_name or source, user_agent)
            if any(marker.lower() in combined for marker in ("github", "actions", "npm", "opensearch")):
                record(findings, "cloudtrail_ci_context", target, event_name or source, user_agent)


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(item["kind"] for item in findings)
    package_hits = sorted({item["value"] for item in findings if item["kind"] in {"manifest_dependency", "package_reference"}})
    network_hits = sorted({item["value"] for item in findings if item["kind"] == "network_ioc"})
    return {
        "finding_count": len(findings),
        "counts_by_kind": dict(sorted(counts.items())),
        "packages_observed": package_hits,
        "network_iocs_observed": network_hits,
        "decision_hint": "treat credentials reachable from matching install/execution contexts as exposed" if findings else "no matching indicators observed in supplied inputs",
    }


def main() -> int:
    args = parse_args()
    findings: list[dict[str, Any]] = []
    scanned = 0
    for path in iter_files(args.roots):
        text = read_text(path, args.max_file_bytes)
        if text is None:
            continue
        scanned += 1
        scan_package_json(path, text, findings)
        scan_text(path, text, findings)
    if args.cloudtrail:
        scan_cloudtrail(args.cloudtrail, findings)

    result = {
        "incident": "vpmdhaj-npm-opensearch-typosquats",
        "scanned_text_files": scanned,
        "summary": summarize(findings),
        "findings": findings,
    }
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], indent=2, sort_keys=True))
    return 2 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
