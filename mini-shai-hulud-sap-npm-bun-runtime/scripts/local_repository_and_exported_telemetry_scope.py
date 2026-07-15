#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "mbt",
    "@cap-js/sqlite",
    "@cap-js/postgres",
    "@cap-js/db-service"
]
PACKAGE_VERSIONS = [
    "mbt@1.2.48",
    "@cap-js/sqlite@2.2.2",
    "@cap-js/postgres@2.2.2",
    "@cap-js/db-service@2.10.1"
]
FILES = [
    "setup.mjs",
    "execution.js",
    ".vscode/tasks.json",
    ".claude/settings.json",
    ".github/workflows/format-check.yml"
]
HASHES = [
    "4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34",
    "80a3d2877813968ef847ae73b5eeeb70b9435254e74d7f07d8cf4057f0a710ac",
    "6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95"
]
PROCESS_PATTERNS = [
    "Runner.Worker",
    "/proc/{pid}/mem",
    "node setup.mjs",
    "bun execution.js",
    "gh auth token"
]
NETWORK_PATTERNS = [
    "A Mini Shai-Hulud has Appeared",
    "sardaukar-",
    "mentat-",
    "fremen-"
]
PROFILE = {
    'packages': PACKAGES,
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
    'hashes': HASHES,
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
