#!/usr/bin/env python3
"""Query npm registry metadata for the JFrog Lucide package list.

No package tarballs are downloaded and no package code is executed. Output is
limited to removal status, version presence, publish timestamps, deprecation,
and maintainer usernames needed for incident research.
"""

from __future__ import annotations

import concurrent.futures
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "jfrog-package-version-table.json"
OUTPUT = ROOT / "npm-registry-status-2026-07-13.json"
USER_AGENT = "HaltingProblems-static-research/1.0"


def fetch(record: dict[str, Any]) -> dict[str, Any]:
    name = str(record["name"])
    url = f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}"
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.npm.install-v1+json", "User-Agent": USER_AGENT},
    )
    result: dict[str, Any] = {
        "ecosystem": "npm",
        "name": name,
        "jfrog_malicious_versions": record["malicious_versions"],
        "xray_id": record["xray_id"],
        "registry_url": url,
    }
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            metadata = json.load(response)
        available_versions = sorted(metadata.get("versions", {}).keys())
        security_placeholder = available_versions == ["0.0.1-security"]
        result.update(
            {
                "http_status": 200,
                "availability": "security_placeholder" if security_placeholder else "available",
                "available_versions": available_versions,
                "malicious_versions_currently_available": [
                    version for version in record["malicious_versions"] if version in available_versions
                ],
                "dist_tags": metadata.get("dist-tags", {}),
                "modified": metadata.get("time", {}).get("modified"),
                "publish_times": {
                    version: metadata.get("time", {}).get(version)
                    for version in record["malicious_versions"]
                    if metadata.get("time", {}).get(version)
                },
                "maintainers": sorted(
                    {
                        maintainer.get("name", "")
                        for maintainer in metadata.get("maintainers", [])
                        if isinstance(maintainer, dict) and maintainer.get("name")
                    }
                ),
                "deprecations": {
                    version: metadata.get("versions", {}).get(version, {}).get("deprecated")
                    for version in available_versions
                    if metadata.get("versions", {}).get(version, {}).get("deprecated")
                },
            }
        )
    except urllib.error.HTTPError as error:
        result.update(
            {
                "http_status": error.code,
                "availability": "removed_or_security_placeholder" if error.code == 404 else "query_error",
                "error": str(error.reason),
            }
        )
    except Exception as error:  # network/parse failures remain explicit
        result.update({"http_status": None, "availability": "query_error", "error": type(error).__name__})
    return result


def main() -> None:
    records = json.loads(SOURCE.read_text(encoding="utf-8"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(fetch, records))
    output = {
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "method": "npm registry abbreviated metadata GET; no tarballs downloaded or code executed",
        "records": results,
    }
    OUTPUT.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    counts: dict[str, int] = {}
    for record in results:
        counts[record["availability"]] = counts.get(record["availability"], 0) + 1
    print(json.dumps({"records": len(results), "availability": counts}))


if __name__ == "__main__":
    main()
