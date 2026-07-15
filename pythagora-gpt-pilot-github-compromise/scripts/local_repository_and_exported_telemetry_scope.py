#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGE_VERSIONS = [
    "Pythagora-io/gpt-pilot@90f59f5de6819a43ffe9b6272e3ed65aaadca804"
]
FILES = [
    "core/telemetry/_hooks.py",
    "core/telemetry/_runtime.bin",
    "core/telemetry/__init__.py"
]
HASHES = [
    "53154df1c66b42021f230c3fb6ef797c4b7c3e83",
    "90f59f5de6819a43ffe9b6272e3ed65aaadca804"
]
PROFILE = {
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
    'hashes': HASHES
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
