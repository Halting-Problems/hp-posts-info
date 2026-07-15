#!/usr/bin/env python3
"""Generated offline hunt scanner; regenerate with generate_scanners.py."""
import importlib.util
import os
from pathlib import Path
import sys

PACKAGES = [
    "@redhat-cloud-services/patch-client@4.0.4",
    "@redhat-cloud-services/insights-client@3.0.3",
    "@redhat-cloud-services/host-inventory-client@2.0.4",
    "@redhat-cloud-services/vulnerabilities-client@2.0.3",
    "@redhat-cloud-services/vulnerabilities-client@2.0.4",
    "@redhat-cloud-services/remediations-client@4.0.3",
    "@redhat-cloud-services/sources-client@3.0.4",
    "@redhat-cloud-services/compliance-client@3.0.4",
    "@redhat-cloud-services/rbac-client@2.0.3",
    "@redhat-cloud-services/advisor-client@4.0.3",
    "@redhat-cloud-services/notifications-client@3.0.3",
    "@redhat-cloud-services/integrations-client@2.0.4",
    "@redhat-cloud-services/drift-client@3.0.3",
    "@redhat-cloud-services/content-sources-client@4.0.4",
    "@redhat-cloud-services/approval-client@2.0.3",
    "@redhat-cloud-services/topms-client@2.0.4",
    "@redhat-cloud-services/ros-client@2.0.4",
    "@redhat-cloud-services/cost-management-client@3.0.4",
    "@redhat-cloud-services/subscriptions-client@3.0.4",
    "@redhat-cloud-services/swatch-client@2.0.3",
    "@redhat-cloud-services/image-builder-client@3.0.3",
    "@redhat-cloud-services/vulnerability-client@2.0.4",
    "@redhat-cloud-services/provisioning-client@2.0.3",
    "@redhat-cloud-services/patch-advisory-client@2.0.3",
    "@redhat-cloud-services/quickstarts-client@2.0.3",
    "@redhat-cloud-services/notifications-backend-client@2.0.4",
    "@redhat-cloud-services/landing-page-frontend@2.0.3",
    "@redhat-cloud-services/frontend-components@6.0.4",
    "@redhat-cloud-services/frontend-components-utilities@4.0.4",
    "@redhat-cloud-services/frontend-components-notifications@3.0.4"
]
FILES = [
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "index.js",
    ".github/workflows/codeql.yml"
]
PROCESS_PATTERNS = [
    "npm install executing lifecycle script from @redhat-cloud-services package",
    "node or bun process launched from package lifecycle hook",
    "workflow run using id-token: write and npm trusted publishing"
]
NETWORK_PATTERNS = [
    "GitHub API activity from developer or CI host after package install",
    "npm publish or dist-tag activity tied to trusted-publishing workflow"
]
PROFILE = {
    'packages': PACKAGES,
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
