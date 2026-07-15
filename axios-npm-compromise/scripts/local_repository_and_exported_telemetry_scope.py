#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "axios",
    "plain-crypto-js"
]
PACKAGE_VERSIONS = [
    "axios@1.14.1",
    "axios@0.30.4",
    "plain-crypto-js@4.2.1"
]
FILES = [
    "/Library/Caches/com.apple.act.mond",
    "%PROGRAMDATA%\\\\wt.exe",
    "%PROGRAMDATA%\\\\system.bat",
    "/tmp/ld.py"
]
HASHES = [
    "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09",
    "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a",
    "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101",
    "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf",
    "6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7",
    "ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c",
    "e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff"
]
DOMAINS = [
    "sfrclak.com",
    "cloud.google.com",
    "www.elastic.co",
    "com.apple.act.mond"
]
IPS = [
    "142.11.206.73"
]
PROFILE = {
    'packages': PACKAGES,
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
    'hashes': HASHES,
    'domains': DOMAINS,
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
