#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "simonecorsi/mawesome"
]
PACKAGE_VERSIONS = [
    "simonecorsi/mawesome@latest",
    "simonecorsi/mawesome@v1",
    "simonecorsi/mawesome@v2",
    "simonecorsi/mawesome@v2.2.0"
]
FILES = [
    "action.yml",
    "index.js"
]
HASHES = [
    "e339407b8e34dc1540290d1d310bccafbc6028ca",
    "4a665037e0619e2181c7cccc3291d75104175a92",
    "6e26314c306ed5ea744eb90ebc6f3f70298abcb5",
    "7a59a7d02b1fdf6432ea9467b8e31357217288f7"
]
PROCESS_PATTERNS = [
    "oven-sh/setup-bun",
    "bun run $GITHUB_ACTION_PATH/index.js",
    "createCipheriv",
    "createDecipheriv",
    "pbkdf2Sync",
    "VAULT_TOKEN",
    "ARM_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "X-GitHub-Api-Version"
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
