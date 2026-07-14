#!/usr/bin/env python3
"""Read-only Chromium history/service-worker/cache collector for Lucide Proxy.

Exit codes: 0 clean, 1 campaign evidence found, 2 collection failure.
The collector performs no network requests, makes no browser changes, and emits
only matching records rather than unrelated browsing data.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


DOMAINS = [
    "woofbeginner.com",
    "c.vipersfutbol.com",
    "realizationnewestfangs.com",
    "protrafficinspector.com",
    "preferencenail.com",
    "skinnycrawlinglax.com",
    "cdn.conditionfuneral.com",
    "lucideon.top",
    "wisp.breadarchive.dpdns.org",
    "21baseballacademy.com",
    "cdn.21baseballacademy.com",
    "abdct.com",
    "geeked.wtf",
]
CAMPAIGN_IDENTIFIERS = [
    "G-0VL3ZSBXDH",
    "0a913561831bdf2c26dcf18b852b5cc1",
    "c6851a038da578a80eeb201e0588c84c",
]
PAYLOAD_HASHES = [
    "eb4e1394d537d8eba509dd5c57e7aaf4c1df57715c7161330012a11f6202af84",
    "10ddbbae0070267b8d15888b09a3cdb19fa74d861315b71f21c9ace8b9f85c75",
    "4b188d179e50e8208a6efec85e273e88d8fc390c836f299ba12915e0840408fd",
]
SELECTORS = DOMAINS + CAMPAIGN_IDENTIFIERS + PAYLOAD_HASHES
MAX_STATIC_FILE_BYTES = 16 * 1024 * 1024


def chromium_time(value: object) -> str | None:
    try:
        microseconds = int(value)
        if microseconds <= 0:
            return None
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds)).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def history_findings(path: Path) -> tuple[list[dict[str, object]], list[str]]:
    findings: list[dict[str, object]] = []
    errors: list[str] = []
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        try:
            rows = connection.execute("SELECT url, title, last_visit_time FROM urls").fetchall()
        finally:
            connection.close()
    except (sqlite3.Error, OSError) as error:
        return [], [f"{path}:{type(error).__name__}"]
    for url, title, last_visit_time in rows:
        lower_url = str(url).lower()
        matched = sorted(selector for selector in SELECTORS if selector.lower() in lower_url)
        if matched:
            findings.append(
                {
                    "evidence_type": "browser_history",
                    "profile_history": str(path),
                    "url": str(url),
                    "title": str(title),
                    "last_visit_time_raw": last_visit_time,
                    "last_visit_time_utc": chromium_time(last_visit_time),
                    "matched_selectors": matched,
                }
            )
    return findings, errors


def static_findings(profile_root: Path) -> tuple[list[dict[str, object]], list[str]]:
    findings: list[dict[str, object]] = []
    errors: list[str] = []
    candidate_roots = [path for path in profile_root.rglob("*") if path.is_dir() and path.name in {"Service Worker", "Cache", "Cache_Data"}]
    scanned: set[Path] = set()
    for root in candidate_roots:
        for path in root.rglob("*"):
            if not path.is_file() or path in scanned:
                continue
            scanned.add(path)
            try:
                if path.stat().st_size > MAX_STATIC_FILE_BYTES:
                    continue
                content = path.read_bytes().lower()
            except OSError as error:
                errors.append(f"{path}:{type(error).__name__}")
                continue
            matched = sorted(selector for selector in SELECTORS if selector.lower().encode() in content)
            if matched:
                findings.append(
                    {
                        "evidence_type": "service_worker_or_cache",
                        "path": str(path),
                        "matched_selectors": matched,
                    }
                )
    return findings, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("user_data_dir", type=Path, help="Reader-owned Chromium/Chrome user-data directory or forensic copy")
    parser.add_argument("--out", type=Path, help="Optional JSON evidence output")
    args = parser.parse_args()
    root = args.user_data_dir.expanduser().resolve()
    if not root.is_dir():
        print(json.dumps({"status": "collection_failure", "error": "user-data directory is not readable"}))
        return 2

    history_paths = sorted({path for path in [root / "History", *root.glob("*/History")] if path.is_file()})
    findings: list[dict[str, object]] = []
    errors: list[str] = []
    for history_path in history_paths:
        found, failed = history_findings(history_path)
        findings.extend(found)
        errors.extend(failed)
    found, failed = static_findings(root)
    findings.extend(found)
    errors.extend(failed)

    payload = {
        "event_id": "lucide-proxy-npm-browser-ddos-campaign",
        "status": "alert" if findings else "clean",
        "history_databases": [str(path) for path in history_paths],
        "finding_count": len(findings),
        "findings": findings,
        "read_errors": errors,
        "interpretation": "A match establishes browser/profile evidence for the selector; correlate with deployment and network logs before asserting flood participation.",
    }
    encoded = json.dumps(payload, indent=2, sort_keys=True)
    if args.out:
        try:
            args.out.expanduser().resolve().write_text(encoded + "\n", encoding="utf-8")
        except OSError as error:
            print(json.dumps({"status": "collection_failure", "error": type(error).__name__}))
            return 2
    print(encoded)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
