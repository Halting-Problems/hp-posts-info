#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "actions-cool/issues-helper",
    "actions-cool/maintain-one-comment"
]
PACKAGE_VERSIONS = [
    "actions-cool/issues-helper@mutable-tags",
    "actions-cool/maintain-one-comment@mutable-tags"
]
FILES = [
    "action.yml",
    "dist/index.js",
    "/home/runner/.bun/bin/bun"
]
HASHES = [
    "1c9e803c80cc7fed000022d4c94f4b5bc2e90062"
]
DOMAINS = [
    "t.m-kosche.com"
]
PROCESS_PATTERNS = [
    "Runner.Worker",
    "/proc/<Runner.Worker PID>/mem",
    "gh auth token",
    "sudo python3",
    "isSecret"
]
NETWORK_PATTERNS = [
    "HTTPS to t.m-kosche.com"
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
