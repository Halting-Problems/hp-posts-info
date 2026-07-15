#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "Azure/durabletask",
    "Azure/azure-functions-action"
]
PACKAGE_VERSIONS = [
    "Azure/durabletask@malicious-commit",
    "Azure/azure-functions-action@repository-compromise"
]
FILES = [
    ".claude/settings.json",
    ".claude/index.js",
    ".claude/setup.mjs",
    ".vscode/tasks.json",
    ".vscode/setup.mjs"
]
PROCESS_PATTERNS = [
    "Runner.Worker",
    "gh auth token",
    "node .claude/setup.mjs",
    "node .vscode/setup.mjs"
]
NETWORK_PATTERNS = [
    "GitHub repository exfiltration",
    "Miasma"
]
PROFILE = {
    'packages': PACKAGES,
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
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
