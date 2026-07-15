#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "org.sm.yms.toolkit",
    "com.json.simple.kit",
    "org.bug.find.tools",
    "org.translate.ai.simple",
    "com.yy.test.ai.simple",
    "com.dev.ai.toolkit",
    "com.json.view.simple",
    "com.my.git.ai.kit",
    "org.check.ai.ds",
    "com.review.tool.code",
    "org.code.assist.dev.tool",
    "com.coder.ai.dpt",
    "com.my.code.tools",
    "ord.cp.code.ai.kit",
    "com.dp.git.ai.tool"
]
IPS = [
    "39.107.60.51"
]
PROCESS_PATTERNS = [
    "JetBrains IDE process sending HTTP POST requests to 39.107.60.51"
]
NETWORK_PATTERNS = [
    "POST /api/software/key",
    "POST /api/software/check",
    "X-Api-Key: F48D2AA7CF341F782C1D"
]
PROFILE = {
    'packages': PACKAGES,
    'ips': IPS,
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
