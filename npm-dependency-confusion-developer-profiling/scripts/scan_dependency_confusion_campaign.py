#!/usr/bin/env python3
"""Scan a checkout or log export for the Microsoft-tracked npm dependency-confusion campaign."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

INDICATORS = (
    {"id": "scope_cloudplatform", "patterns": ("@cloudplatform-single-spa",)},
    {"id": "scope_wb_track", "patterns": ("@wb-track",)},
    {"id": "scope_data_science", "patterns": ("@data-science",)},
    {"id": "scope_ce_rwb", "patterns": ("@ce-rwb",)},
    {"id": "scope_payments_widget", "patterns": ("@payments-widget",)},
    {"id": "scope_travel_autotests", "patterns": ("@travel-autotests",)},
    {"id": "scope_t_in_one", "patterns": ("@t-in-one",)},
    {"id": "scope_capibar_chat", "patterns": ("@capibar.chat",)},
    {"id": "scope_sber_ecom_core", "patterns": ("@sber-ecom-core",)},
    {"id": "rep_logaas", "patterns": ("@cloudplatform-single-spa/logaas", "100.100.100", "99.99.100", "99.99.99")},
    {"id": "rep_capibar_ui", "patterns": ("@capibar.chat/ui-kit", "99.5.7", "99.0.7")},
    {"id": "rep_sber_widget", "patterns": ("@sber-ecom-core/sberpay-widget", "99.5.8", "99.5.7", "99.0.7")},
    {"id": "payload_recon", "patterns": ("_RECON_ONLY", "_PKG", "_VER", "_SECRET", "X-Secret")},
    {"id": "install_hook", "patterns": ("postinstall", "scripts/postinstall.js")},
    {"id": "c2_oob", "patterns": ("oob.moika.tech", "https://oob.moika.tech/payload")},
    {"id": "fake_enterprise_domains", "patterns": ("github.cloudplatform-single-spa.io", "docs.cloudplatform-single-spa.io", "jira.cloudplatform-single-spa.io", "npm.t-in-one.io", "docs.t-in-one.io", "jira.t-in-one.io")},
)

SKIP_DIRS = {".git", ".venv", "__pycache__", "build", "dist", "node_modules", "vendor", "coverage"}
TEXT_SUFFIXES = {".txt", ".log", ".md", ".markdown", ".yml", ".yaml", ".json", ".js", ".ts", ".mjs", ".cjs", ".lock", ".html"}
DEFAULT_OUT = "hp-npm-dependency-confusion-developer-profiling-scope"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", default=["."], help="Checkout or log export paths to scan")
    parser.add_argument("--json-out", type=Path, help="Optional path to write structured findings")
    return parser.parse_args()


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding, errors="ignore")
        except UnicodeDecodeError:
            continue
    return None


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    if not root.exists():
        return
    for child in root.rglob("*"):
        if child.is_dir():
            continue
        if any(part in SKIP_DIRS for part in child.parts):
            continue
        yield child


def scan_paths(paths: list[Path]):
    matches: list[dict[str, str]] = []
    for root in paths:
        for path in iter_files(root):
            if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", ".npmrc"}:
                continue
            text = read_text(path)
            if text is None:
                continue
            for indicator in INDICATORS:
                for pattern in indicator["patterns"]:
                    if pattern in text:
                        matches.append({"path": str(path), "indicator": indicator["id"], "pattern": pattern})
                        break
    return matches


def write_outputs(out_dir: Path, matches: list[dict[str, str]]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    indicators_path = out_dir / "indicators.txt"
    indicators = {entry["indicator"] for entry in matches} or {item["id"] for item in INDICATORS}
    indicators_path.write_text("\n".join(sorted(indicators)) + "\n", encoding="utf-8")
    if matches:
        (out_dir / "matches.json").write_text(json.dumps(matches, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    paths = [Path(p) for p in args.paths]
    matches = scan_paths(paths)
    out_dir = Path(args.json_out).parent if args.json_out else Path(DEFAULT_OUT)
    write_outputs(out_dir, matches)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps({"matches": matches}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"scanned={len(paths)} matches={len(matches)} out={out_dir}")
    return 1 if matches else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
