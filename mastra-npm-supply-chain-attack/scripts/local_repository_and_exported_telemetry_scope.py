#!/usr/bin/env python3

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable

DEFAULT_EXCLUDES = {".git", "__pycache__", "dist", "node_modules", "vendor", "build"}

MASTRA_SEARCH_PACKAGES = [
    "easy-day-js",
    "@mastra/schema-compat",
    "@mastra/core",
    "@mastra/memory",
    "@mastra/server",
    "@mastra/loggers",
    "@mastra/observability",
    "@mastra/deployer",
    "create-mastra",
]
MASTRA_PACKAGE_VERSIONS = [
    "easy-day-js@1.11.22",
    "easy-day-js@1.11.21",
    "@mastra/schema-compat@1.2.12",
    "@mastra/core@1.42.1",
    "@mastra/memory@1.20.4",
    "@mastra/server@2.1.1",
    "@mastra/loggers@1.1.3",
    "@mastra/observability@1.14.2",
    "@mastra/deployer@1.42.1",
    "mastra@1.13.1",
    "create-mastra@1.13.1",
]
MASTRA_FILES = [
    "setup.cjs",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "~/.pkg_history",
    "~/.pkg_logs",
]
MASTRA_HASHES = [
    "221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf",
]
MASTRA_IPS = [
    "23.254.164.92",
    "23.254.164.123",
]
MASTRA_URLS = [
    "https://23.254.164.92:8000/update/49890878",
]
MASTRA_PROCESS_PATTERNS = [
    "npm install executing postinstall from easy-day-js",
    "node process launched from setup.cjs",
    "package manager lifecycle script execution on an affected Mastra package",
]
MASTRA_NETWORK_PATTERNS = [
    "HTTPS fetch to raw IP 23.254.164.92 on port 8000",
    "outbound request to attacker-controlled stage-two endpoint",
]


def load_iocs(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _unique(values: Iterable[str]) -> list[str]:
    return sorted({value for value in values if isinstance(value, str) and value})


def build_indicators(iocs: dict) -> dict:
    section = iocs.get("iocs", {})
    indicators = {
        "package_versions": _unique(section.get("package_versions", [])),
        "files": _unique(section.get("files", [])),
        "hashes": _unique(section.get("hashes", [])),
        "domains": _unique(section.get("domains", [])),
        "urls": _unique(section.get("urls", [])),
        "ips": _unique(section.get("ips", [])),
        "process_patterns": _unique(section.get("process_patterns", [])),
        "network_patterns": _unique(section.get("network_patterns", [])),
    }
    indicators["literal_indicators"] = _unique(
        indicators["package_versions"]
        + indicators["files"]
        + indicators["hashes"]
        + indicators["domains"]
        + indicators["urls"]
        + indicators["ips"]
        + indicators["process_patterns"]
        + indicators["network_patterns"]
        + MASTRA_SEARCH_PACKAGES
        + MASTRA_PACKAGE_VERSIONS
        + MASTRA_FILES
        + MASTRA_HASHES
        + MASTRA_IPS
        + MASTRA_URLS
        + MASTRA_PROCESS_PATTERNS
        + MASTRA_NETWORK_PATTERNS
    )
    return indicators


def scan_text(path: Path, text: str, indicators: dict) -> list[dict]:
    lowered = text.lower()
    hits: list[dict] = []
    for indicator in indicators["literal_indicators"]:
        if indicator.lower() in lowered:
            hits.append({
                "path": str(path),
                "indicator": indicator,
                "kind": "literal",
            })
    return hits


def scan_root(root: Path, indicators: dict) -> list[dict]:
    hits: list[dict] = []
    for current, dirs, filenames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDES]
        for filename in filenames:
            file_path = Path(current) / filename
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            hits.extend(scan_text(file_path, content, indicators))
    return hits


def write_outputs(out_dir: Path, matches: list[dict], indicators: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "indicator_count": len(indicators["literal_indicators"]),
        "match_count": len(matches),
        "matches": matches,
    }
    (out_dir / "scan-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (out_dir / "indicators.txt").write_text("\n".join(indicators["literal_indicators"]) + "\n", encoding="utf-8")
    if matches:
        (out_dir / "repository-indicator-matches.txt").write_text(
            "\n".join(f"{item['path']}: found '{item['indicator']}'" for item in matches) + "\n",
            encoding="utf-8",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mastra npm supply-chain hunt script")
    parser.add_argument("root", nargs="?", default=".", help="Directory to scan")
    parser.add_argument("--iocs", default=str(Path(__file__).resolve().parents[1] / "iocs.json"), help="Path to iocs.json")
    parser.add_argument("--out", default=os.environ.get("OUT", "hp-mastra-npm-supply-chain-attack-scope"), help="Output directory")
    parser.add_argument("--log-root", default=os.environ.get("LOG_ROOT", ""), help="Optional exported log root to scan")
    args = parser.parse_args(argv)

    root = Path(args.root)
    if not root.exists():
        print(f"directory not found: {root}", file=sys.stderr)
        return 2

    iocs = load_iocs(Path(args.iocs))
    indicators = build_indicators(iocs)

    matches = scan_root(root, indicators)
    log_matches: list[dict] = []
    if args.log_root:
        log_root = Path(args.log_root)
        if log_root.exists():
            log_matches = scan_root(log_root, indicators)
            matches.extend(log_matches)

    out_dir = Path(args.out)
    write_outputs(out_dir, matches, indicators)

    print(json.dumps({"match_count": len(matches), "log_match_count": len(log_matches), "out": str(out_dir)}, indent=2))
    return 1 if matches else 0


if __name__ == "__main__":
    raise SystemExit(main())
