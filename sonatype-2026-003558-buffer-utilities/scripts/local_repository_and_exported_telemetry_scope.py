#!/usr/bin/env python3
"""Audit the buffer-utilities brandjacking campaign for repo, log, and registry evidence.

The script is designed for offline hunts against filesystem exports and for optional
npm packument snapshots. It looks for the package family names Sonatype listed, the
install-time loader markers JFrog described, and the current npm registry state for
buffer-utilities.
"""

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CANDIDATE_ID = "sonatype-2026-003558-buffer-utilities"
CAMPAIGN_ID = "sonatype-2026-003558"
PACKAGE_NAME = "buffer-utilities"
PACKUMENT_URL = "https://registry.npmjs.org/buffer-utilities"
CURRENT_SECURITY_HOLDER_VERSION = "0.0.1-security"
HISTORICAL_VERSIONS = ["1.0.0", "1.1.0", "1.1.1"]
ARCHIVE_URLS = [
    "https://registry.npmjs.org/buffer-utilities",
    "https://registry.npmjs.org/buffer-utilities/-/buffer-utilities-1.0.0.tgz",
    "https://registry.npmjs.org/buffer-utilities/-/buffer-utilities-1.1.0.tgz",
    "https://registry.npmjs.org/buffer-utilities/-/buffer-utilities-1.1.1.tgz",
    "https://registry.npmjs.org/buffer-utilities/-/buffer-utilities-0.0.1-security.tgz",
]
PACKAGE_FAMILY_NAMES = [
    "buffer",
    "buffer-utilities",
    "buffer-util-extend",
    "express-denv",
    "jwt-path",
    "webpack-patch",
    "chai-as-patch",
    "chai-beta",
    "react-next-dom",
]
LOADER_MARKERS = [
    "postinstall",
    "node setup.cjs --no-warnings",
    "setup.cjs",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "fetch(",
    "spawn(process.execPath, ..., detached: true)",
    ".vscode",
    ".pkg_history",
    ".pkg_logs",
]
EXCLUDED_DIR_NAMES = {".git", "node_modules", "dist", "vendor", "__pycache__", ".venv"}
TEXT_SUFFIXES = {
    "",
    ".json",
    ".md",
    ".markdown",
    ".txt",
    ".log",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".conf",
    ".js",
    ".cjs",
    ".mjs",
    ".ts",
    ".py",
    ".lock",
}


def _is_text_candidate(path: Path) -> bool:
    if path.name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def scan_tree(root: Path) -> dict[str, Any]:
    """Scan a directory tree for campaign selectors.

    Returns a JSON-serializable summary with hit counts and matching file paths.
    """

    root = root.expanduser().resolve()
    file_hits: list[dict[str, Any]] = []
    hit_terms: set[str] = set()

    if not root.exists():
        return {
            "root": str(root),
            "exists": False,
            "file_hit_count": 0,
            "hit_terms": [],
            "file_hits": [],
        }

    for path in root.rglob("*"):
        if path.is_dir() or any(part in EXCLUDED_DIR_NAMES for part in path.parts):
            continue
        if not _is_text_candidate(path):
            continue
        text = _read_text(path)
        matches = []
        for term in [*PACKAGE_FAMILY_NAMES, *LOADER_MARKERS]:
            if term.lower() in text.lower():
                matches.append(term)
                hit_terms.add(term)
        if matches:
            file_hits.append({"path": str(path), "terms": sorted(set(matches))})

    return {
        "root": str(root),
        "exists": True,
        "file_hit_count": len(file_hits),
        "hit_terms": sorted(hit_terms),
        "file_hits": file_hits,
    }


def load_packument(source: str) -> dict[str, Any]:
    """Load a packument JSON document from a path or URL."""

    source = source.strip()
    if not source:
        raise ValueError("empty packument source")

    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=30) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))

    path = Path(source).expanduser()
    return json.loads(path.read_text(encoding="utf-8"))


def summarize_packument(packument: dict[str, Any]) -> dict[str, Any]:
    versions = packument.get("versions") or {}
    time_map = packument.get("time") or {}
    historical_versions = [version for version in HISTORICAL_VERSIONS if version in time_map]
    missing_version_objects = [version for version in historical_versions if version not in versions]

    return {
        "name": packument.get("name", PACKAGE_NAME),
        "latest": (packument.get("dist-tags") or {}).get("latest", "unknown"),
        "time_entries": {version: time_map.get(version, "unknown") for version in [*HISTORICAL_VERSIONS, CURRENT_SECURITY_HOLDER_VERSION]},
        "historical_versions": historical_versions,
        "missing_version_objects": missing_version_objects,
        "present_versions": sorted(versions.keys()),
    }


def probe_url(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return {"url": url, "status": response.status, "reason": "reachable"}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status": exc.code, "reason": exc.reason}
    except Exception as exc:  # pragma: no cover - network and resolver failures are environment-specific
        return {"url": url, "status": "error", "reason": str(exc)}


def build_report(scan_root: Path, packument_source: str | None, probe_tarballs: bool) -> dict[str, Any]:
    report: dict[str, Any] = {
        "candidate_id": CANDIDATE_ID,
        "campaign_id": CAMPAIGN_ID,
        "package_name": PACKAGE_NAME,
        "registry": {"packument_url": PACKUMENT_URL, "current_security_holder_version": CURRENT_SECURITY_HOLDER_VERSION},
        "scan": scan_tree(scan_root),
    }

    if packument_source:
        packument = load_packument(packument_source)
        summary = summarize_packument(packument)
        report["packument"] = summary
        report["packument_source"] = packument_source

        if probe_tarballs:
            report["tarball_probes"] = [probe_url(url) for url in ARCHIVE_URLS]
    else:
        report["packument"] = {
            "name": PACKAGE_NAME,
            "latest": "unknown",
            "time_entries": {},
            "historical_versions": [],
            "missing_version_objects": [],
            "present_versions": [],
        }
        if probe_tarballs:
            report["tarball_probes"] = [probe_url(url) for url in ARCHIVE_URLS]

    report["interpretation"] = {
        "campaign_match": bool(report["scan"]["file_hit_count"]),
        "registry_artifact_gap": bool(report.get("packument", {}).get("missing_version_objects")),
        "archive_probe_gap": any(entry.get("status") == 404 for entry in report.get("tarball_probes", [])),
    }
    return report


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="directory tree to scan")
    parser.add_argument("--packument", help="path or URL to a npm packument JSON snapshot")
    parser.add_argument("--probe-tarballs", action="store_true", help="probe known tarball URLs with HEAD requests")
    parser.add_argument("--out", default=f"hp-{CANDIDATE_ID}-scope", help="output directory for JSON artifacts")
    args = parser.parse_args(argv)

    scan_root = Path(args.root).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    report = build_report(scan_root, args.packument, args.probe_tarballs)
    write_text(out_dir / "report.json", json.dumps(report, indent=2, sort_keys=True) + "\n")
    write_text(out_dir / "selectors.txt", "\n".join([*PACKAGE_FAMILY_NAMES, *LOADER_MARKERS]) + "\n")

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
