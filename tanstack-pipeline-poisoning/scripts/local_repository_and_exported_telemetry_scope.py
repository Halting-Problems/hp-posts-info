#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "@tanstack/zod-adapter",
    "@tanstack/router",
    "@tanstack/react-router",
    "@tanstack/react-query",
    "@tanstack/table-core"
]
PACKAGE_VERSIONS = [
    "@tanstack/zod-adapter@1.166.12",
    "@tanstack/zod-adapter@1.166.15",
    "@tanstack/router@1.166.12",
    "@tanstack/router@1.166.15",
    "@tanstack/react-router@1.166.12",
    "@tanstack/react-router@1.166.15",
    "@tanstack/react-query@1.166.12",
    "@tanstack/react-query@1.166.15",
    "@tanstack/table-core@1.166.12",
    "@tanstack/table-core@1.166.15"
]
FILES = [
    "router_init.js",
    "tanstack_runner.js"
]
HASHES = [
    "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
]
DOMAINS = [
    "git-tanstack.com"
]
PROFILE = {
    'packages': PACKAGES,
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
    'hashes': HASHES,
    'domains': DOMAINS
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
