#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "leo-logger",
    "leo-sdk",
    "leo-aws",
    "leo-config",
    "leo-streams",
    "serverless-leo",
    "leo-connector-mongo",
    "serverless-convention",
    "rstreams-metrics",
    "leo-connector-elasticsearch",
    "leo-auth",
    "leo-cache",
    "leo-cli",
    "hexo-deployer-wrangler",
    "hexo-shoka-swiper",
    "leo-cron",
    "leo-connector-redshift",
    "leo-connector-oracle",
    "prism-silq",
    "rstreams-shard-util",
    "leo-connector-mysql",
    "leo-cdk-lib",
    "solo-nav"
]
PACKAGE_VERSIONS = [
    "leo-logger@1.0.8",
    "leo-sdk@6.0.19",
    "leo-aws@2.0.4",
    "leo-config@1.1.1",
    "leo-streams@2.0.1",
    "serverless-leo@3.0.14",
    "leo-connector-mongo@3.0.8",
    "serverless-convention@2.0.4",
    "rstreams-metrics@2.0.2",
    "leo-connector-elasticsearch@2.0.6",
    "leo-auth@4.0.6",
    "leo-cache@1.0.2",
    "leo-cli@3.0.3",
    "hexo-deployer-wrangler@1.0.4",
    "hexo-shoka-swiper@0.1.10",
    "leo-cron@2.0.2",
    "leo-connector-redshift@3.0.6",
    "leo-connector-oracle@2.0.1",
    "prism-silq@1.0.1",
    "rstreams-shard-util@1.0.1",
    "leo-connector-mysql@3.0.3",
    "leo-cdk-lib@0.0.2",
    "solo-nav@1.0.1"
]
FILES = [
    "binding.gyp",
    "index.js",
    "stub.c"
]
HASHES = [
    "d45ad3cffbcc7c4b354ebe9d71d002fa585379ec",
    "1dcc0a39e1cd7293a9058cfc41e1afe8b397c943",
    "ef8bf6dd92cbc29ef8d23f3f0fa786ed20a856b1",
    "9be49287057cd6a54ef4a70a8d541a7259efbd2d",
    "c05068f18e7f94304b92a307a030e0038ab61004",
    "cb78d0dca573f99a22b41ca01e99853a6162d5d5",
    "c721c184dbb5c2dc23bacfd28571daef1decfac1"
]
PROCESS_PATTERNS = [
    "Runner.Worker",
    "/proc/{pid}/mem",
    "bypass_2fa",
    "ALL=(ALL) NOPASSWD:ALL",
    "/tmp/p"
]
NETWORK_PATTERNS = [
    "api.github.com/graphql",
    "github.com/oven-sh/bun/releases/download/bun-v1.3.13"
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
