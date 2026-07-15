#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "@evolvconsulting/evolv-coder-lite",
    "@jagreehal/workflow",
    "@vapi-ai/server-sdk",
    "ai-sdk-ollama",
    "autotel",
    "autotel-adapters",
    "autotel-audit",
    "autotel-aws",
    "autotel-backends",
    "autotel-cli",
    "autotel-cloudflare",
    "autotel-devtools",
    "autotel-drizzle",
    "autotel-edge",
    "autotel-eventcatalog",
    "autotel-hono",
    "autotel-mcp",
    "awaitly",
    "awaitly-analyze",
    "awaitly-libsql"
]
PACKAGE_VERSIONS = [
    "@vapi-ai/server-sdk@0.11.1",
    "@vapi-ai/server-sdk@0.11.2",
    "@vapi-ai/server-sdk@1.2.1",
    "@vapi-ai/server-sdk@1.2.2",
    "ai-sdk-ollama@0.13.1",
    "ai-sdk-ollama@1.1.1",
    "ai-sdk-ollama@2.2.1",
    "ai-sdk-ollama@3.8.5",
    "@evolvconsulting/evolv-coder-lite@1.2.0",
    "@jagreehal/workflow@1.16.1"
]
FILES = [
    "binding.gyp",
    "index.js",
    "stub.c"
]
HASHES = [
    "288f26c2eadcb1a7923fe376d16f5404216cce15d9fc162a4a78574dc7df399a",
    "ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90",
    "5926b86b642e00672252953eb30d8f75cfb7797fe3118bd6fa2cfbee92905d61",
    "ceff7c51d70832c3ec8dd2744b606a23b3c924ef664ae23439b9b742ea154108",
    "da39146ef451d1b174a24d00b1e2a45cd38d54e849737f8f35333dcb22175707"
]
PROCESS_PATTERNS = [
    "node-gyp rebuild",
    "node index.js",
    "Runner.Worker",
    "/proc/{pid}/mem",
    "gh auth token",
    "sudo python3"
]
NETWORK_PATTERNS = [
    "thebeautifulmarchoftime",
    "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner",
    "Miasma - The Spreading Blight"
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
