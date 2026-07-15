#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "moritz-sauer-13/silverstripe-cms-theme",
    "crosiersource/crosierlib-base",
    "devdojo/wave",
    "devdojo/genesis",
    "katanaui/katana",
    "elitedevsquad/sidecar-laravel",
    "r2luna/brain",
    "baskarcm/tzi-chat-ui"
]
PACKAGE_VERSIONS = [
    "dev-main",
    "dev-master",
    "3.x-dev",
    "moritz-sauer-13/silverstripe-cms-theme dev-master",
    "crosiersource/crosierlib-base dev-master",
    "devdojo/wave dev-main",
    "devdojo/genesis dev-main",
    "katanaui/katana dev-main",
    "elitedevsquad/sidecar-laravel 3.x-dev",
    "r2luna/brain dev-main",
    "baskarcm/tzi-chat-ui dev-main"
]
FILES = [
    "package.json",
    "/tmp/.sshd"
]
PROCESS_PATTERNS = [
    "curl -skL ... -o /tmp/.sshd",
    "chmod +x /tmp/.sshd",
    "/tmp/.sshd running in background"
]
NETWORK_PATTERNS = [
    "download of gvfsd-network from parikhpreyash4/systemd-network-helper-aa5c751f"
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
