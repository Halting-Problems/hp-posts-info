#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "@tanstack/react-router",
    "@tanstack/vue-router",
    "@tanstack/solid-router",
    "@tanstack/react-start",
    "@tanstack/router-core",
    "@antv/g2",
    "@antv/g6",
    "@antv/x6",
    "@antv/l7",
    "@antv/s2",
    "@antv/f2",
    "echarts-for-react",
    "timeago.js",
    "size-sensor",
    "canvas-nest.js",
    "@sap/cds",
    "@sap/cds-dk",
    "opensearch-py",
    "lite-llm",
    "nx-console"
]
PACKAGE_VERSIONS = [
    "@tanstack/react-router@1.169.5",
    "@tanstack/react-router@1.169.8",
    "@tanstack/vue-router@1.169.5",
    "@tanstack/vue-router@1.169.8",
    "@tanstack/solid-router@1.169.5",
    "@tanstack/solid-router@1.169.8",
    "@tanstack/react-start@1.167.68",
    "@tanstack/react-start@1.167.71",
    "@antv/g2@4.2.8",
    "@antv/g6@4.8.24",
    "nx-console@18.95.0",
    "@antv/* published 2026-05-19T01:39:00",
    "@tanstack/router-core@1.169.5",
    "@antv/x6@2.2.0",
    "@antv/l7@2.19.0",
    "@antv/s2@1.30.0",
    "@antv/f2@4.1.0",
    "echarts-for-react@3.0.0",
    "timeago.js@4.0.2",
    "size-sensor@1.0.1",
    "canvas-nest.js@2.0.4",
    "@sap/cds@7.9.2",
    "@sap/cds-dk@7.9.2",
    "opensearch-py@2.5.0",
    "lite-llm@1.34.0"
]
FILES = [
    "router_init.js",
    "setup_bun.js",
    "bun_environment.js",
    "transformers.pyz",
    "gh-token-monitor"
]
HASHES = [
    "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
]
DOMAINS = [
    "filev2.getsession.org",
    "api.masscan.cloud",
    "git-tanstack.com",
    "t.m-kosche.com",
    "www.endorlabs.com",
    "www.microsoft.com",
    "www.sentinelone.com"
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
