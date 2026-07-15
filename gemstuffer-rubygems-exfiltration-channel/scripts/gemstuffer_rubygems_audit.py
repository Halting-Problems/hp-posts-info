#!/usr/bin/env python3
"""
Audit local telemetry and RubyGems registry metadata for GemStuffer indicators.

The registry mode uses RubyGems' public timeframe_versions API to reproduce a
bounded May 12, 2026 search window and flag gem versions that contain the
ModernGov council domains or related GemStuffer selectors.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

CAMPAIGN_ID = "gemstuffer-rubygems-exfiltration-channel"
REGISTRY_WINDOW_FROM = "2026-05-12T02:20:00Z"
REGISTRY_WINDOW_TO = "2026-05-12T03:30:00Z"
RUBYGEMS_TIMEFRAME_API = "https://rubygems.org/api/v1/timeframe_versions.json"
RUBYGEMS_PUSH_ENDPOINT = "https://rubygems.org/api/v1/gems"

COUNCIL_DOMAINS = [
    "moderngov.lambeth.gov.uk",
    "democracy.wandsworth.gov.uk",
    "moderngov.southwark.gov.uk",
]

COUNCIL_URLS = [
    "https://moderngov.lambeth.gov.uk/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1",
    "https://democracy.wandsworth.gov.uk/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1",
    "https://moderngov.southwark.gov.uk/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1",
    "https://moderngov.lambeth.gov.uk/mgCalendarMonthView.aspx?GL=1&M=1&Y=2026",
    "https://democracy.wandsworth.gov.uk/mgCalendarMonthView.aspx?GL=1&M=1&Y=2026",
    "https://moderngov.southwark.gov.uk/mgCalendarMonthView.aspx?GL=1&M=1&Y=2026",
]

REPRESENTATIVE_PACKAGE_VERSIONS = {
    "agenda-sample-yard": ["0.1.0", "0.1.1"],
    "bot9evil": ["0.1.0"],
    "fetchrootx2": ["0.0.1"],
    "soufetchabc": ["0.0.1", "0.0.2", "0.0.3"],
    "wandcabfetchfix21736": ["0.0.1"],
    "wandscrawlr": ["0.0.1"],
    "slnleaker5": ["0.0.1"],
    "fetchrootx1": ["0.0.1"],
    "lambeth71b": ["0.0.1", "0.0.2"],
    "probeextwand": ["0.0.1"],
    "designfetchdemo": ["0.0.1"],
    "lambethx33zzz": ["0.0.1", "0.0.2"],
    "wandocal1": ["0.1.1"],
    "wandcabm10266dsgn4": ["0.0.1"],
    "sl-yard-probe2": ["0.0.1"],
    "lambexploitabc1": ["0.0.2"],
    "wandscrawlq": ["0.0.1"],
    "lambcrawlxyz": ["0.0.1", "0.0.2"],
    "swmeetfetcha": ["0.0.1"],
    "lbdeepgeta": ["0.0.1"],
    "slfetchrootabc": ["0.1.0"],
    "zzsouthrunnerb": ["1.0.0"],
    "slnleakerext": ["0.0.1"],
    "lambfetchx550961": ["0.0.1"],
    "swcalfetcha": ["0.0.1"],
    "runnerhack1778553910": ["0.0.1", "0.0.2"],
    "yard-slnmultifetch": ["0.0.1"],
    "swkagenttwo": ["0.0.2"],
    "rootfetchproperxyz": ["0.0.1"],
    "yard-controllerlambda": ["0.0.1", "0.0.3"],
    "lambfetchx548811": ["0.0.1"],
    "wandhackmy": ["0.0.2"],
    "wandcabm10266dsgn2": ["0.0.1"],
    "lambtmp35293950": ["0.0.2"],
    "slnmultifetchabc": ["0.0.1"],
    "uuext4c477": ["0.0.1", "0.0.2", "0.0.3"],
    "wandfetchcal021": ["0.0.5"],
    "extssrfabc1778553451": ["0.0.1"],
    "lamhackzzq": ["0.0.5"],
    "southfetchefefd": ["0.0.1", "0.0.2"],
    "qwandfetch1": ["0.0.1", "0.0.2"],
    "ygexpwzqbot": ["0.0.1"],
    "yexpabc58377": ["0.0.1"],
    "dnsfetchabc12": ["0.0.1"],
    "wandzfetch1500929": ["0.0.2"],
    "yard-skyfetch": ["0.0.1"],
    "aaaresultfetchx": ["0.0.1"],
    "southmqsedwjgw": ["0.0.1"],
    "wandsworthprefetch209db": ["0.0.1"],
    "councilprobexyz": ["0.0.1"],
    "anchorx995": ["0.0.2"],
    "wn98122eth": ["9.8.0", "9.9.0"],
    "useful_helper_tools": ["1.2.3"],
    "southyardmine1": ["0.0.1"],
    "zzsouthfetchsimplex": ["0.0.1"],
    "fmtstatdoca": ["0.0.1"],
    "yard-docxrun": ["0.0.1", "0.0.3"],
    "wanfetcherx9": ["0.0.1"],
    "rootfetchcalendarx": ["0.0.1"],
    "yardbreakerxqh1778552850": ["0.0.1"],
    "lambfetchjj2": ["0.0.1"],
    "lambfetchx528211": ["0.0.1"],
    "sf8aea": ["0.0.1"],
    "southfetchprobe42": ["0.0.2", "0.0.3"],
    "southc0ea": ["0.0.1"],
}

KNOWN_PAYLOAD_HASHES = {
    "payload.rb": {
        "sha256": "239440c830e17530dda0a8a06ed2708860998750a1e3ed2239e919465dc59420",
        "sha1": "5f924c0454f1fb6b2299d658c3bb4e75ce3d0b66",
        "md5": "81c34eea9c853c5ec13a3b3cd4a2228b",
    },
    "script.rb": {
        "sha256": "c2d6bcacc88177e0f2c8c262726f86f37e671b1692c8bc135bac4b610ddcf31a",
        "sha1": "db9827ae2c004a4dc6009be2d009477bff5249df",
        "md5": "9211506ae02c9e4e75aeadfebeb4883c",
    },
}

FILE_NAMES = [
    "payload.rb",
    "script.rb",
    "evil.rb",
    "yardload.rb",
    "yard_plugin.rb",
    "exploit.rb",
    "extconf.rb",
    "fetcher.rb",
]

FS_SELECTORS = [
    "/tmp/gemhome/.gem/credentials",
    "/tmp/gemhome",
    "/tmp/rubydocran_",
    "lib/result.txt",
    "x.gemspec",
    "agenda-sample-result-0.1.1.gem",
]

RUBY_CODE_SELECTORS = [
    "ENV['HOME'] = '/tmp/gemhome'",
    'ENV["HOME"] = "/tmp/gemhome"',
    "File.chmod(0600",
    "Net::HTTP::Post.new",
    "Gem::Package.build",
    "gem push",
    "--host https://rubygems.org",
    "Content-Type",
    "application/octet-stream",
    "Authorization",
    "Mozilla/5.0",
    "mgCalendarMonthView.aspx",
    "ieList",
    "mgCommittee",
]

PACKAGE_NAMES = sorted(REPRESENTATIVE_PACKAGE_VERSIONS)
PACKAGE_VERSION_STRINGS = sorted(
    f"{name}-{version}" for name, versions in REPRESENTATIVE_PACKAGE_VERSIONS.items() for version in versions
)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


def read_url_json(url: str, timeout: int) -> Any:
    request = urllib.request.Request(url, headers={"User-Agent": f"{CAMPAIGN_ID}-audit/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_timeframe_versions(start: str, end: str, timeout: int, max_pages: int) -> list[dict[str, Any]]:
    versions: list[dict[str, Any]] = []
    for page in range(1, max_pages + 1):
        url = RUBYGEMS_TIMEFRAME_API + "?" + urllib.parse.urlencode({"from": start, "to": end, "page": page})
        try:
            batch = read_url_json(url, timeout)
        except urllib.error.URLError as exc:
            raise RuntimeError(f"failed to fetch {url}: {exc}") from exc
        if not isinstance(batch, list):
            raise RuntimeError(f"unexpected RubyGems API response for page {page}: {type(batch).__name__}")
        if not batch:
            break
        versions.extend(batch)
    return versions


def normalize_blob(record: dict[str, Any]) -> str:
    fields = [
        "name",
        "version",
        "number",
        "authors",
        "info",
        "description",
        "summary",
        "homepage_uri",
        "source_code_uri",
        "bug_tracker_uri",
    ]
    return "\n".join(str(record.get(field) or "") for field in fields).lower()


def classify_registry_record(record: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    name = str(record.get("name") or "")
    version = str(record.get("version") or record.get("number") or "")
    blob = normalize_blob(record)
    if name in REPRESENTATIVE_PACKAGE_VERSIONS and version in REPRESENTATIVE_PACKAGE_VERSIONS[name]:
        reasons.append("known_representative_package_version")
    for domain in COUNCIL_DOMAINS:
        if domain in blob:
            reasons.append(f"embedded_council_domain:{domain}")
    for term in ["mgcalendarmonthview", "ielist", "mgcommittee", "r.jina.ai"]:
        if term in blob:
            reasons.append(f"embedded_scrape_selector:{term}")
    if record.get("yanked") is True:
        reasons.append("rubygems_yanked_true")
    if record.get("built_at") == "1980-01-02T00:00:00.000Z":
        reasons.append("default_or_synthetic_built_at")
    return bool(reasons), sorted(set(reasons))


def write_registry_outputs(matches: list[dict[str, Any]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "gemstuffer-rubygems-registry-matches.json"
    csv_path = out_dir / "gemstuffer-rubygems-registry-matches.csv"
    json_path.write_text(json.dumps(matches, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    fields = [
        "name",
        "version",
        "version_created_at",
        "yanked",
        "sha",
        "spec_sha",
        "authors",
        "summary",
        "downloads_count",
        "gem_uri",
        "reasons",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in matches:
            writer.writerow({field: item.get(field, "") for field in fields})
    print(f"[+] wrote {json_path}")
    print(f"[+] wrote {csv_path}")


def mode_registry(args: argparse.Namespace) -> int:
    versions = fetch_timeframe_versions(args.from_time, args.to_time, args.timeout, args.max_pages)
    matches: list[dict[str, Any]] = []
    for record in versions:
        matched, reasons = classify_registry_record(record)
        if matched:
            matches.append(
                {
                    "name": record.get("name"),
                    "version": record.get("version") or record.get("number"),
                    "version_created_at": record.get("version_created_at") or record.get("created_at"),
                    "yanked": record.get("yanked"),
                    "sha": record.get("sha"),
                    "spec_sha": record.get("spec_sha"),
                    "authors": record.get("authors"),
                    "summary": record.get("summary"),
                    "downloads_count": record.get("downloads_count"),
                    "gem_uri": record.get("gem_uri"),
                    "reasons": ";".join(reasons),
                }
            )
    matches.sort(key=lambda item: (str(item.get("version_created_at") or ""), str(item.get("name") or "")))
    write_registry_outputs(matches, args.out_dir)
    print(f"[+] fetched_versions={len(versions)} matches={len(matches)}")
    if args.fail_on_match and matches:
        return 2
    return 0


def iter_files(root: Path, max_bytes: int) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        yield path


def hash_file(path: Path) -> dict[str, str]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def safe_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def scan_file(path: Path, root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    relative = str(path.relative_to(root))
    basename = path.name
    if basename in FILE_NAMES:
        hashes = hash_file(path)
        matched_name = None
        for known_name, known_hashes in KNOWN_PAYLOAD_HASHES.items():
            if all(hashes[k] == v for k, v in known_hashes.items()):
                matched_name = known_name
        findings.append(
            {
                "path": relative,
                "type": "suspicious_file_name",
                "selector": basename,
                "sha256": hashes["sha256"],
                "known_payload_hash_match": matched_name or "",
            }
        )
    text = safe_text(path)
    if not text:
        return findings
    haystack = text.lower()
    selectors = (
        PACKAGE_NAMES
        + PACKAGE_VERSION_STRINGS
        + COUNCIL_DOMAINS
        + COUNCIL_URLS
        + FS_SELECTORS
        + RUBY_CODE_SELECTORS
        + [RUBYGEMS_PUSH_ENDPOINT]
    )
    for selector in selectors:
        if selector.lower() in haystack:
            findings.append({"path": relative, "type": "text_selector", "selector": selector})
    for digest in SHA256_RE.findall(text):
        if digest.lower() in {
            hashes["sha256"] for hashes in KNOWN_PAYLOAD_HASHES.values()
        }:
            findings.append({"path": relative, "type": "known_payload_hash", "selector": digest.lower()})
    return findings


def mode_scan(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    if not root.exists() or not root.is_dir():
        eprint(f"[-] scan root is not a directory: {root}")
        return 64
    findings: list[dict[str, Any]] = []
    for path in iter_files(root, args.max_bytes):
        findings.extend(scan_file(path, root))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out_dir / "gemstuffer-local-scan-findings.json"
    out_path.write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[+] scanned {root}")
    print(f"[+] findings={len(findings)} output={out_path}")
    if args.fail_on_match and findings:
        return 2
    return 0


def parse_log_line(path: Path, line_no: int, line: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    raw = line.strip()
    if not raw:
        return findings
    lowered = raw.lower()
    selectors = COUNCIL_DOMAINS + COUNCIL_URLS + [RUBYGEMS_PUSH_ENDPOINT, "rubygems.org/api/v1/gems"]
    for selector in selectors:
        if selector.lower() in lowered:
            findings.append({"path": str(path), "line": line_no, "type": "network_selector", "selector": selector})
    if "post" in lowered and "rubygems.org" in lowered and "/api/v1/gems" in lowered:
        findings.append({"path": str(path), "line": line_no, "type": "rubygems_push_post", "selector": "POST rubygems.org/api/v1/gems"})
    if "mozilla/5.0" in lowered and any(domain in lowered for domain in COUNCIL_DOMAINS):
        findings.append({"path": str(path), "line": line_no, "type": "gemstuffer_user_agent_to_council", "selector": "Mozilla/5.0 council fetch"})
    if "authorization" in lowered and "rubygems_" in lowered:
        findings.append({"path": str(path), "line": line_no, "type": "rubygems_api_key_in_log", "selector": "Authorization rubygems_*"})
    return findings


def mode_logs(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    if not root.exists():
        eprint(f"[-] log path does not exist: {root}")
        return 64
    paths = [root] if root.is_file() else list(iter_files(root, args.max_bytes))
    findings: list[dict[str, Any]] = []
    for path in paths:
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line_no, line in enumerate(handle, 1):
                    findings.extend(parse_log_line(path, line_no, line))
        except OSError as exc:
            eprint(f"[!] skipped {path}: {exc}")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out_dir / "gemstuffer-log-findings.json"
    out_path.write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[+] scanned_logs={len(paths)} findings={len(findings)} output={out_path}")
    if args.fail_on_match and findings:
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GemStuffer RubyGems registry and telemetry audit utility")
    parser.add_argument("--out-dir", type=Path, default=Path("gemstuffer-audit-output"), help="Directory for JSON/CSV results")
    parser.add_argument("--fail-on-match", action="store_true", help="Exit 2 when matching indicators are found")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    registry = subparsers.add_parser("registry", help="Fetch and filter RubyGems timeframe metadata")
    registry.add_argument("--from-time", default=REGISTRY_WINDOW_FROM, help="ISO8601 start time; default is the GemStuffer window")
    registry.add_argument("--to-time", default=REGISTRY_WINDOW_TO, help="ISO8601 end time; default is the GemStuffer window")
    registry.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds")
    registry.add_argument("--max-pages", type=int, default=80, help="Maximum RubyGems API pages to fetch")
    registry.set_defaults(func=mode_registry)

    scan = subparsers.add_parser("scan", help="Scan local source trees, gem caches, or preserved /tmp artifacts")
    scan.add_argument("root", type=Path, help="Directory to scan")
    scan.add_argument("--max-bytes", type=int, default=5_000_000, help="Skip files larger than this size")
    scan.set_defaults(func=mode_scan)

    logs = subparsers.add_parser("logs", help="Scan exported proxy, EDR, CI, or shell logs")
    logs.add_argument("root", type=Path, help="Log file or directory to scan")
    logs.add_argument("--max-bytes", type=int, default=50_000_000, help="Skip log files larger than this size")
    logs.set_defaults(func=mode_logs)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except BrokenPipeError:
        return 1
    except KeyboardInterrupt:
        eprint("[-] interrupted")
        return 130
    except Exception as exc:
        eprint(f"[-] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
