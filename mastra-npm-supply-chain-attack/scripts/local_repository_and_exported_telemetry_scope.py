#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGE_VERSIONS = [
    "easy-day-js@1.11.22",
    "easy-day-js@1.11.21",
    "@mastra/schema-compat@1.2.12",
    "@mastra/core@1.42.1",
    "@mastra/memory@1.20.4",
    "@mastra/server@2.1.1",
    "@mastra/loggers@1.1.3",
    "@mastra/observability@1.14.2",
    "@mastra/deployer@1.42.1"
]
FILES = [
    "setup.cjs",
    "yarn.lock",
    "bun.lock"
]
HASHES = [
    "221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf"
]
IPS = [
    "23.254.164.92",
    "23.254.164.123"
]
PROFILE = {
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
    'hashes': HASHES,
    'ips': IPS
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
