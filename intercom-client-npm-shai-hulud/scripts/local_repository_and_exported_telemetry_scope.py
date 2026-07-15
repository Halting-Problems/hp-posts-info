#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "intercom-client"
]
PACKAGE_VERSIONS = [
    "7.0.4",
    "intercom-client@7.0.4"
]
FILES = [
    "setup.mjs",
    "router_runtime.js"
]
HASHES = [
    "5f748fbc89cde66abefa826439c765a0081a027792e9da8d80fbf23571311622",
    "fe64699649591948d6f960705caac86fe99600bf76e3eae29b4517705a58f0e2",
    "5ae8b2343e97cc3b2c945ec34318b63f27fa2db1e3d8fbaa78c298aa63db52ed"
]
DOMAINS = [
    "metadata.google.internal"
]
IPS = [
    "169.254.169.254"
]
PROCESS_PATTERNS = [
    "npm preinstall launches Bun-backed loader files"
]
NETWORK_PATTERNS = [
    "egress related to intercom-client 7.0.4"
]
PROFILE = {
    'packages': PACKAGES,
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
    'hashes': HASHES,
    'domains': DOMAINS,
    'ips': IPS,
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
