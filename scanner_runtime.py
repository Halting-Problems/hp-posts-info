#!/usr/bin/env python3
"""Offline, deterministic runtime used by generated post hunt scanners."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable

MAX_FILE_SIZE = 25_000_000
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}
TEXT_SUFFIXES = {".json", ".yaml", ".yml", ".lock", ".txt", ".log", ".md", ".mdx", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".sh", ".ps1", ".xml", ".csv", ".toml", ""}


def _files(root: Path, excluded: set[Path]) -> Iterable[Path]:
    for current, dirs, names in os.walk(root):
        current_path = Path(current)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            path = current_path / name
            if any(path == item or item in path.parents for item in excluded):
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES and path.stat().st_size > 0:
                continue
            try:
                if path.stat().st_size <= MAX_FILE_SIZE:
                    yield path
            except OSError:
                continue


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _profile(path: Path) -> dict[str, list[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("profile must be an object")
    result = {}
    for key in ("packages", "package_versions", "files", "hashes", "domains", "urls", "ips", "process_patterns", "network_patterns"):
        values = data.get(key, [])
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ValueError(f"profile field {key!r} must be a list of strings")
        result[key] = [v for v in values if v.strip()]
    return result


def _match(matches: list[dict], category: str, selector: str, path: Path, root_kind: str, detail: str = "") -> None:
    matches.append({"category": category, "selector": selector, "source": f"{root_kind}:{path}", "detail": detail})


def scan(scan_root: Path, log_root: Path | None, out: Path, profile: dict[str, list[str]]) -> tuple[int, dict]:
    out.mkdir(parents=True, exist_ok=True)
    excluded = {out.resolve()}
    roots = [("repository", scan_root)] + ([('telemetry', log_root)] if log_root else [])
    matches: list[dict] = []
    files_seen = 0
    for root_kind, root in roots:
        for path in _files(root, excluded):
            files_seen += 1
            rel = path.relative_to(root).as_posix()
            content = _read(path)
            if content is None:
                continue
            for selector in profile["files"]:
                if rel == selector or rel.endswith("/" + selector) or path.name == selector:
                    _match(matches, "path", selector, path, root_kind, rel)
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                for selector in profile["hashes"]:
                    if digest.lower() == selector.lower():
                        _match(matches, "hash", selector, path, root_kind, "sha256")
            except OSError:
                pass
            # Package selectors are deliberately contextual: a bare package name
            # in prose is not evidence of an installed affected version.
            for selector in profile["package_versions"]:
                package, version = selector.rsplit("@", 1)
                pattern = rf"(?<![\w@/-]){re.escape(package)}(?:@|[\"']\s*:\s*[\"']){re.escape(version)}\b"
                if re.search(pattern, content):
                    _match(matches, "package", selector, path, root_kind)
            if root_kind == "telemetry":
                for category, key in (("process", "process_patterns"), ("network", "network_patterns"), ("network", "domains"), ("network", "urls"), ("network", "ips")):
                    for selector in profile[key]:
                        if selector in content:
                            _match(matches, category, selector, path, root_kind)
    inventory = {key: values for key, values in profile.items() if values}
    (out / "selector-inventory.json").write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "indicators.txt").write_text("\n".join(sorted({value for values in inventory.values() for value in values})) + "\n", encoding="utf-8")
    for item in matches:
        item["indicator"] = item["selector"]
    result = {"classification": "actionable_match" if matches else "clean", "files_scanned": files_seen, "match_count": len(matches), "matches": matches, "scan_root": str(scan_root), "telemetry_root": str(log_root) if log_root else None}
    (out / "scope-results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    legacy = [f"{item['source']}: found {item['selector']!r}" for item in matches]
    if legacy:
        (out / "repository-indicator-matches.txt").write_text("\n".join(legacy) + "\n", encoding="utf-8")
        (out / "matches.txt").write_text("\n".join(legacy) + "\n", encoding="utf-8")
        telemetry = [line for line, item in zip(legacy, matches) if item["source"].startswith("telemetry:")]
        if telemetry:
            (out / "exported-telemetry-indicator-matches.txt").write_text("\n".join(telemetry) + "\n", encoding="utf-8")
    (out / "scan-summary.json").write_text(json.dumps({"match_count": len(matches), "matches": matches}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return (1 if matches else 0), result


def main(argv: list[str] | None = None, embedded_profile: dict[str, list[str]] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_root")
    parser.add_argument("log_root", nargs="?")
    parser.add_argument("out_dir", nargs="?")
    parser.add_argument("--profile", required=False)
    parser.add_argument("--log-root", dest="log_flag")
    parser.add_argument("--out", dest="out_flag")
    args = parser.parse_args(argv)
    try:
        scan_root = Path(args.scan_root).resolve()
        log_root = Path(args.log_flag or args.log_root).resolve() if (args.log_flag or args.log_root) else None
        out = Path(args.out_flag or args.out_dir or os.environ.get("OUT", "hp-scope")).resolve()
        if not args.log_flag and not args.log_root and os.environ.get("LOG_ROOT"):
            log_root = Path(os.environ["LOG_ROOT"]).resolve()
        if not scan_root.is_dir() or (log_root and not log_root.is_dir()):
            raise ValueError("scan root and log root must be existing directories")
        keys = ("packages", "package_versions", "files", "hashes", "domains", "urls", "ips", "process_patterns", "network_patterns")
        loaded = embedded_profile or (_profile(Path(args.profile)) if args.profile else {})
        profile = {key: list(loaded.get(key, [])) for key in keys}
        return scan(scan_root, log_root, out, profile)[0]
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"scanner error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
