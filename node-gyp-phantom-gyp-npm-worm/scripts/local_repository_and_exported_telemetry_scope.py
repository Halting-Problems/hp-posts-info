#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "@vapi-ai/server-sdk@0.7.1",
    "@vapi-ai/server-sdk@0.7.2",
    "@vapi-ai/server-sdk@0.7.3",
    "@vapi-ai/web@2.3.1",
    "@vapi-ai/web@2.3.2",
    "@jagreehal/builder@1.0.0",
    "abandoned-package@1.0.0",
    "abandoned-package-2@1.0.0",
    "autotel-terminal@0.0.1",
    "autotel-client@0.0.1",
    "autotel-trpc@0.0.1"
]
FILES = [
    "binding.gyp",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock"
]
PROCESS_PATTERNS = [
    "node-gyp rebuild",
    "npm install lifecycle script",
    "native addon build executing during dependency install"
]
PROFILE = {
    'packages': PACKAGES,
    'files': FILES,
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
