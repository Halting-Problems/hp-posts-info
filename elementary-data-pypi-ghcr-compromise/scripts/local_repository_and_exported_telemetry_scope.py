#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "elementary-data"
]
PACKAGE_VERSIONS = [
    "0.23.3",
    "elementary-data==0.23.3",
    "ghcr.io/elementary-data/elementary:0.23.3",
    "ghcr.io/elementary-data/elementary:latest"
]
FILES = [
    "elementary.pth",
    "trin.tar.gz",
    "/tmp/.trinny-security-update",
    "%TEMP%\\\\.trinny-security-update"
]
HASHES = [
    "31ecc5939de6d24cf60c50d4ca26cf7a8c322db82a8ce4bd122ebd89cf634255",
    "b3bbfafde1a0db3a4d47e70eb0eb2ca19daef4a19410154a71abee567b35d3d9",
    "fe52712660fef56586d954e50f81ccc7b96ed2809b5e930c7b9d032e7ab03b8d",
    "5cf8f4c3fa0b7e84cb0096c94eb9af941ea632c9acffa002d0db3b3c1d9ef97e"
]
DOMAINS = [
    "igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud",
    "trin.tar.gz"
]
PROCESS_PATTERNS = [
    "Python startup executes `elementary.pth`"
]
NETWORK_PATTERNS = [
    "egress related to elementary-data 0.23.3 package or GHCR image"
]
PROFILE = {
    'packages': PACKAGES,
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
    'hashes': HASHES,
    'domains': DOMAINS,
    'process_patterns': PROCESS_PATTERNS,
    'network_patterns': NETWORK_PATTERNS
}

def main() -> int:
    try:
        runtime_path = Path(__file__).resolve().parents[2] / "scanner_runtime.py"
        spec = importlib.util.spec_from_file_location("hp_scanner_runtime", runtime_path)
        if spec is None or spec.loader is None:
            print(f"scanner runtime not found: {runtime_path}", file=sys.stderr)
            return 2
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        args = list(sys.argv[1:])
        if os.environ.get("LOG_ROOT") and "--log-root" not in args:
            args.extend(["--log-root", os.environ["LOG_ROOT"]])
        if os.environ.get("OUT") and "--out" not in args:
            args.extend(["--out", os.environ["OUT"]])
        return runtime.main(args, PROFILE) if args else 2
    except Exception as exc:
        print(f"scanner execution error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
