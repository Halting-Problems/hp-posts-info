#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "Sicoob.Sdk"
]
PACKAGE_VERSIONS = [
    "Sicoob.Sdk@2.0.0",
    "Sicoob.Sdk@2.0.1",
    "Sicoob.Sdk@2.0.2",
    "Sicoob.Sdk@2.0.3",
    "Sicoob.Sdk@2.0.4"
]
FILES = [
    "lib/net8.0/Sicoob.Sdk.dll"
]
HASHES = [
    "7d2332e76c266509cdec8b552ccc839f50c28e6b01070071257bd3f57d1d9da2",
    "f0dff53969080584560b2971411415bdf9064d5a5a50185c4ae018943e7d5cbe",
    "94eb8da6703dd073184015c9e3cb34e9b6153fc499c9cb1a7db6e4361ec349dd",
    "ac9dc55f13d973e05865e9674c8b8e6744e7fbfca3355199b292f614f13ac7bc",
    "190dbcafa776e8cc221106414b8fbd68252d98438c5e46b8449788fbe70316a4",
    "d565e3f03d0b1a7c8935d7ff94237316"
]
DOMAINS = [
    "o4511335034847232.ingest.de.sentry.io",
    "Sicoob.Sdk.dll"
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
