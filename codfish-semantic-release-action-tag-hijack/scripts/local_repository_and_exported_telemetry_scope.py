#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "codfish/semantic-release-action"
]
PACKAGE_VERSIONS = [
    "codfish/semantic-release-action@v5.0.0",
    "codfish/semantic-release-action@v5",
    "codfish/semantic-release-action@v4.0.1",
    "codfish/semantic-release-action@v4.0.0",
    "codfish/semantic-release-action@v4",
    "codfish/semantic-release-action@v3.5.0",
    "codfish/semantic-release-action@v3.4.1",
    "codfish/semantic-release-action@v3.4.0",
    "codfish/semantic-release-action@v3.3.0",
    "codfish/semantic-release-action@v3.2.0",
    "codfish/semantic-release-action@v3.1.1",
    "codfish/semantic-release-action@v3.1.0",
    "codfish/semantic-release-action@v3.0.0",
    "codfish/semantic-release-action@v3",
    "codfish/semantic-release-action@v2.2.1"
]
FILES = [
    "action.yml",
    "index.js"
]
HASHES = [
    "5792aba0e2180b9b80b77644370a6889d5817456",
    "8f9a58f2acdc190c356f79159b5de2548cdb63cd"
]
PROCESS_PATTERNS = [
    "oven-sh/setup-bun",
    "bun run $GITHUB_ACTION_PATH/index.js",
    "Runner.Worker memory access"
]
PROFILE = {
    'packages': PACKAGES,
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
    'hashes': HASHES,
    'process_patterns': PROCESS_PATTERNS
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
