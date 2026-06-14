#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-redhat-cloud-services-npm-miasma-compromise-scope"))

PACKAGES = ["@redhat-cloud-services/patch-client@4.0.4","@redhat-cloud-services/insights-client@3.0.3","@redhat-cloud-services/host-inventory-client@2.0.4","@redhat-cloud-services/vulnerabilities-client@2.0.3","@redhat-cloud-services/vulnerabilities-client@2.0.4","@redhat-cloud-services/remediations-client@4.0.3","@redhat-cloud-services/sources-client@3.0.4","@redhat-cloud-services/compliance-client@3.0.4","@redhat-cloud-services/rbac-client@2.0.3","@redhat-cloud-services/advisor-client@4.0.3","@redhat-cloud-services/notifications-client@3.0.3","@redhat-cloud-services/integrations-client@2.0.4","@redhat-cloud-services/drift-client@3.0.3","@redhat-cloud-services/content-sources-client@4.0.4","@redhat-cloud-services/approval-client@2.0.3","@redhat-cloud-services/topms-client@2.0.4","@redhat-cloud-services/ros-client@2.0.4","@redhat-cloud-services/cost-management-client@3.0.4","@redhat-cloud-services/subscriptions-client@3.0.4","@redhat-cloud-services/swatch-client@2.0.3","@redhat-cloud-services/image-builder-client@3.0.3","@redhat-cloud-services/vulnerability-client@2.0.4","@redhat-cloud-services/provisioning-client@2.0.3","@redhat-cloud-services/patch-advisory-client@2.0.3","@redhat-cloud-services/quickstarts-client@2.0.3","@redhat-cloud-services/notifications-backend-client@2.0.4","@redhat-cloud-services/landing-page-frontend@2.0.3","@redhat-cloud-services/frontend-components@6.0.4","@redhat-cloud-services/frontend-components-utilities@4.0.4","@redhat-cloud-services/frontend-components-notifications@3.0.4"]
FILES = ["package.json","package-lock.json","pnpm-lock.yaml","yarn.lock","bun.lock","index.js",".github/workflows/codeql.yml"]
DOMAINS = ["registry.npmjs.org","api.github.com","github.com"]
URLS = ["https://github.com/RedHatInsights/javascript-clients"]
PROCESS_PATTERNS = ["npm install executing lifecycle script from @redhat-cloud-services package","node or bun process launched from package lifecycle hook","workflow run using id-token: write and npm trusted publishing"]
NETWORK_PATTERNS = ["GitHub API activity from developer or CI host after package install","npm publish or dist-tag activity tied to trusted-publishing workflow"]

# Collect unique indicators
indicators = set()
for group in [PACKAGES, FILES, DOMAINS, URLS, PROCESS_PATTERNS, NETWORK_PATTERNS]:
    for val in group:
        if val:
            indicators.add(val)

with open(indicators_file, "w") as f:
    for ind in sorted(indicators):
        f.write(ind + "\n")

print(f"[+] Written unique selectors to {indicators_file}")

# Walk local directory
print(f"[+] Scanning directory: {ROOT} for selectors...")
matches = []
exclude_dirs = {"node_modules", "vendor", "dist", ".git"}
for root, dirs, filenames in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in exclude_dirs]
    for filename in filenames:
        filepath = Path(root) / filename
        try:
            content = filepath.read_text(errors="ignore")
            for ind in indicators:
                if ind in content:
                    matches.append(f"{filepath}: found '{ind}'")
        except Exception:
            pass  # pass # return or raise not needed here

if matches:
    (OUT / "repository-indicator-matches.txt").write_text("\n".join(matches) + "\n")
    print(f"[!] Found {len(matches)} matches in codebase!")

# Optional Log Scanning
if LOG_ROOT and os.path.exists(LOG_ROOT):
    print(f"[+] Scanning telemetry log directory: {LOG_ROOT}...")
    log_matches = []
    for root, _, filenames in os.walk(LOG_ROOT):
        for filename in filenames:
            filepath = Path(root) / filename
            try:
                content = filepath.read_text(errors="ignore")
                for ind in indicators:
                    if ind in content:
                        log_matches.append(f"{filepath}: found '{ind}'")
            except Exception:
                pass  # pass # return or raise not needed here
    if log_matches:
        (OUT / "exported-telemetry-indicator-matches.txt").write_text("\n".join(log_matches) + "\n")
        print(f"[!] Found {len(log_matches)} matches in logs!")

    if PACKAGES:
        registry_dir = OUT / "registry"
        registry_dir.mkdir(exist_ok=True)
        for package in PACKAGES:
            if not package: continue
            safe_name = package.replace("/", "__")
            print(f"[+] Querying npm view for {package}...")
            res = subprocess.run(["npm", "view", package, "name", "version", "time", "versions", "dist-tags", "maintainers", "dist.tarball", "dist.integrity", "scripts", "--json"], capture_output=True, text=True)
            if res.returncode == 0:
                (registry_dir / f"npm-{safe_name}.json").write_text(res.stdout)

print(f"[+] Wrote scope artifacts under {OUT}")
