#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "github.com/shopsprint/decimal"
]
PACKAGE_VERSIONS = [
    "v1.3.3",
    "github.com/shopsprint/decimal v1.3.3"
]
FILES = [
    "go.mod",
    "go.sum",
    "decimal.go"
]
HASHES = [
    "f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c"
]
DOMAINS = [
    "dnslog-cdn-images.freemyip.com",
    "freemyip.com"
]
PROCESS_PATTERNS = [
    "Go application importing github.com/shopsprint/decimal"
]
NETWORK_PATTERNS = [
    "TXT query to dnslog-cdn-images.freemyip.com every five minutes"
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
