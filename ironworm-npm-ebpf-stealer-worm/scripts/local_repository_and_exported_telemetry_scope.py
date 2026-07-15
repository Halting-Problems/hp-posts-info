#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "ai3@0.3.5",
    "aonote@0.11.1",
    "arjson@0.1.4",
    "arnext@0.1.5",
    "arnext-arkb@0.0.2",
    "atomic-notes@0.5.3",
    "create-arnext-app@0.0.10",
    "cwao@0.5.6",
    "cwao-tools@0.3.1",
    "cwao-units@0.8.3",
    "fpjson-lang@0.1.7",
    "hbsig@0.3.2",
    "monade@0.0.7",
    "roidjs@0.1.7",
    "test-ajs@0.1.19",
    "test-weavedb-sdk@1.1.1",
    "testnpmnmp@1.0.21",
    "wao@0.41.2",
    "warp-contracts-plugin-deploy-test@3.0.1",
    "wdb-cli@0.1.1",
    "wdb-core@0.1.2",
    "wdb-sdk@0.1.2",
    "weavedb-base@0.45.3",
    "weavedb-client@0.45.3",
    "weavedb-console@0.2.1",
    "weavedb-contracts@0.45.2",
    "weavedb-exm-sdk@0.7.4",
    "weavedb-exm-sdk-web@0.7.4",
    "weavedb-lite@0.1.1",
    "weavedb-node-client@0.45.3",
    "weavedb-offchain@0.45.4",
    "weavedb-sdk-base@0.21.1",
    "weavedb-sdk-node@0.45.3",
    "weavedb-tools@0.45.3",
    "weavedb-warp-contracts-plugin-deploy@1.0.11",
    "zkjson@0.8.5"
]
FILES = [
    "tools/setup"
]
HASHES = [
    "7750bab1a6c48831b5a889e6b799d1684d0a4f2a"
]
PROCESS_PATTERNS = [
    "preinstall hook launching custom Rust binary",
    "unusual loading of eBPF programs"
]
PROFILE = {
    'packages': PACKAGES,
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
