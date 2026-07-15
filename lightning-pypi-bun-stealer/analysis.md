---
title: "Lightning PyPI Bun-Based Credential Stealer"
date: 2026-04-30
severity: "critical"
tags:
  - pypi
  - package-compromise
  - supply-chain
  - credential-theft
  - shai-hulud
summary: "On April 30, 2026, malicious `lightning` PyPI releases 2.6.2 and 2.6.3 shipped an import-time loader that bootstrapped Bun and executed a large obfuscated JavaScript credential stealer."
sourceCount: 7
---

## Executive Summary
On April 30, 2026, two malicious releases of the legitimate PyPI package `lightning` were published as versions `2.6.2` and `2.6.3` [Lightning advisory](https://github.com/Lightning-AI/pytorch-lightning/security/advisories/GHSA-w37p-236h-pfx3) [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Socket](https://socket.dev/blog/lightning-pypi-package-compromised). The package is the modern distribution name for the PyTorch Lightning deep learning framework, making the compromise materially different from a lookalike or typosquat.

The malicious wheels added a hidden `_runtime` directory that executed when Python code imported `lightning`, downloaded the Bun JavaScript runtime from GitHub, and used it to run an approximately 11 MB obfuscated JavaScript credential stealer named `router_runtime.js` [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Socket](https://socket.dev/blog/lightning-pypi-package-compromised). The payload targeted GitHub tokens, npm tokens, cloud credentials, metadata services, local environment variables, and developer credential files [Socket](https://socket.dev/blog/lightning-pypi-package-compromised). The project advisory tracks the incident as `GHSA-w37p-236h-pfx3` / `CVE-2026-44484` and states that the malicious releases were quarantined [Lightning advisory](https://github.com/Lightning-AI/pytorch-lightning/security/advisories/GHSA-w37p-236h-pfx3).

## Key Facts
**Threat Type**: legitimate package compromise, import-time credential stealer

**Ecosystem**: pypi, python

**Registry**: PyPI

**Affected Packages**:
- lightning

**Malicious Versions**:
- 2.6.2
- 2.6.3

**Known Good Versions**:
- 2.6.1

**Post Incident Versions Not Listed As Affected**:
- 2.6.4
- 2.6.5

**Execution Trigger**: import lightning

**Primary Impact**: Developer, CI/CD, npm, GitHub, and cloud credential theft

**Campaign Context**: Mini Shai-Hulud-style Bun payload reuse; exact attribution remains vendor-disputed

**Known Iocs**:
- lightning/_runtime/start.py
- lightning/_runtime/router_runtime.js
- github.com/oven-sh/bun/releases/download/bun-v1.3.13
- api.github.com/user
- registry.npmjs.org/-/whoami

**Confidence**: high

**Canonical Source**: hxxps://snyk[.]io/blog/lightning-pypi-compromise-bun-based-credential-stealer/

## Evidence Assessment
* **confirmed:** `lightning` versions `2.6.2` and `2.6.3` were malicious and are covered by the project's `GHSA-w37p-236h-pfx3` / `CVE-2026-44484` advisory [Lightning advisory](https://github.com/Lightning-AI/pytorch-lightning/security/advisories/GHSA-w37p-236h-pfx3).
* **confirmed:** The malicious execution chain runs automatically on module import and launches a background process with suppressed output [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true).
* **confirmed:** The payload uses Bun to execute a large obfuscated JavaScript credential stealer that targets cloud and developer credentials [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true).
* **confirmed:** The project says the attacker captured PyPI credentials; the security advisory says the exact root cause remained under investigation in its May 12 update [Lightning incident review](https://lightning.ai/blog/pytorch-lightning-supply-chain-attack) [Lightning advisory](https://github.com/Lightning-AI/pytorch-lightning/security/advisories/GHSA-w37p-236h-pfx3).
* **confirmed:** PyPI no longer exposes `2.6.2` or `2.6.3`; current registry metadata lists `2.6.4` and `2.6.5`, while the incident advisory still names `2.6.1` as its explicit fallback [PyPI](https://pypi.org/pypi/lightning/json) [Lightning advisory](https://github.com/Lightning-AI/pytorch-lightning/security/advisories/GHSA-w37p-236h-pfx3).
* **unclear:** Vendors differ on whether the operator is the original Shai-Hulud actor, a copycat, or a related cluster reusing the same payload family [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | `lightning==2.6.2` or `lightning==2.6.3` is present and Python import-time loader starts Bun and obfuscated JavaScript or the reported process, file, or network indicators is observed. | Artifact inventory plus runtime telemetry showing Python import-time loader starts Bun and obfuscated JavaScript or listed C2/process/file indicators. | Isolate affected hosts or runners, preserve artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, exposed credentials are replaced, and downstream audit modules show no suspicious follow-on use. |
| Presumed exposed | `lightning==2.6.2` or `lightning==2.6.3` was installed, pulled, imported, built, or executed during the exposure window, but telemetry cannot prove exfiltration. | Lockfile, package cache, workflow, image pull, extension inventory, build log, or deployment record tied to the exposure window. | Rebuild from clean artifacts and rotate credentials available to the affected environment. | Credential owners confirm revocation of old material and clean artifacts are deployed. |
| Potentially exposed | The package, workflow, image, extension, or module appears in dependency or deployment records, but Python install, import, or interpreter-startup execution is not established. | Manifest, lockfile, build, deployment, or endpoint records plus a named telemetry gap. | Collect the missing execution and telemetry evidence before narrowing scope. | Every hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected version, artifact, mutable reference, or indicator appears in source, lockfiles, build outputs, deployments, package caches, or runtime telemetry. | Repository search, dependency inventory, build/deployment export, package cache query, and runtime telemetry query results. | Preserve the negative search output and keep the prevention controls active. | Search evidence covers developer endpoints, CI runners, production deployments, and package or image caches. |
| Unknown | Required inventory, build, endpoint, network, or audit telemetry is unavailable. | A gap statement naming unavailable systems, owners, and time windows. | Keep the asset in scope and make conservative rotation or rebuild decisions for high-value environments. | The missing evidence is recovered or the risk owner accepts residual uncertainty. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Dependency, workflow, extension, image, or module inventory covering developer endpoints, CI runners, and production deployments.
- Positive or negative search results for lightning==2.6.2, lightning==2.6.3.
- Execution evidence for Python import-time loader starts Bun and obfuscated JavaScript.
- Process, file, DNS, proxy, firewall, or package-manager telemetry for listed indicators.
- Inventory of credentials, tokens, deployment paths, and downstream systems reachable from exposed environments.

## Timeline
- **2026-01-30T00:00:00Z** `lightning==2.6.1` is identified by Snyk as the last clean release before the compromise [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).
- **2026-04-30T00:00:00Z** Malicious `lightning==2.6.2` and `lightning==2.6.3` releases are published to PyPI [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true).
- **2026-04-30T00:00:00Z** Snyk publishes advisory coverage for the affected releases [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PYTHON-LIGHTNING-16323121).
- **2026-05-01T00:00:00Z** Sonatype updates its public analysis to include additional packages connected to the wider wave [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true).
- **2026-05-12T00:00:00Z** The project advisory states that the malicious releases were quarantined and release credentials were revoked and rotated [Lightning advisory](https://github.com/Lightning-AI/pytorch-lightning/security/advisories/GHSA-w37p-236h-pfx3).
- **2026-05-20T22:10:01Z** PyPI publishes `lightning==2.6.4`, a post-incident release not listed as affected [PyPI](https://pypi.org/pypi/lightning/json).
- **2026-05-27T14:33:39Z** PyPI publishes `lightning==2.6.5`, the current release as of 2026-06-10 [PyPI](https://pypi.org/pypi/lightning/json).

## What Happened
Attackers published malicious versions of the legitimate `lightning` package, preserving the expected framework code while adding a hidden runtime directory [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/). When an affected environment imported `lightning`, the modified initialization path launched a background thread that invoked `_runtime/start.py` with output redirected away from the console [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).

The Python bootstrapper fetched Bun from GitHub releases and used it to execute `router_runtime.js`, a large obfuscated JavaScript payload [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true). That design let the attackers reuse JavaScript supply-chain malware inside a Python ecosystem package instead of rewriting the stealer in Python [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).

## Technical Analysis
### Initial Access
The available evidence points to a compromised package publishing path for the real `lightning` project rather than a typosquat [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/). Snyk notes that `2.6.3` did not correspond to a normal GitHub release or tag, which supports a registry-side upload using stolen publishing authority [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).

### Execution Trigger
Execution begins when Python imports the package [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true). This is more dangerous than a CLI-only path because notebooks, smoke tests, version checks, and CI import probes can all trigger the background payload.

### Payload Behavior
The payload searches for GitHub tokens, npm tokens, cloud provider credentials, environment variables, local credential files, and cloud metadata service material [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) [Sonatype](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true). Snyk also reports repository poisoning and npm tarball mutation logic consistent with a worm-capable supply-chain payload [Snyk](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/).

## Affected Assets and Blast Radius

**Affected Assets**:
  - **ecosystems**: PyPI,Python
  - **registries**: pypi.org
  - **packages**: lightning
  - **versions**: lightning==2.6.2,lightning==2.6.3
  - **repositories**: Lightning-AI/pytorch-lightning
  - **ci_cd_systems**: GitHub Actions,developer CI runners
  - **container_images**:
  - **developer_tools**: Python notebooks,developer workstations

**Credentials At Risk**:
- GitHub tokens
- cloud credentials
- CI/CD secrets
- SSH keys
- environment variables
- AI provider tokens

**Downstream Systems To Audit**:
- source control
- package registries
- cloud control planes
- deployment platforms
- Kubernetes or containers
- secret managers

**Not Currently Known To Affect**:
- Assets without the affected artifact and without execution evidence.

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Domains
- setup.mjs


## Detection and Hunting

### Hunt Manifest: lightning-pypi-bun-stealer-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Lightning PyPI Bun-Based Credential Stealer?
- **Telemetry Family:** process
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-lightning-pypi-bun-stealer-scope"))

DOMAINS = ["setup.mjs"]

# Collect unique indicators
indicators = set()
for group in [DOMAINS]:
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
            pass  # pass # return or raise not needed here  # pass # return or raise not needed here

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
                pass  # pass # return or raise not needed here  # pass # return or raise not needed here
    if log_matches:
        (OUT / "exported-telemetry-indicator-matches.txt").write_text("\n".join(log_matches) + "\n")
        print(f"[!] Found {len(log_matches)} matches in logs!")

    if PACKAGES:
        registry_dir = OUT / "registry"
        registry_dir.mkdir(exist_ok=True)
        for package in PACKAGES:
            if not package: continue
            safe_name = package.replace("/", "__")
            print(f"[+] Querying pip index for {package}...")
            res = subprocess.run(["python3", "-m", "pip", "index", "versions", package], capture_output=True, text=True)
            if res.returncode == 0:
                (registry_dir / f"pypi-{safe_name}-versions.txt").write_text(res.stdout)
            subprocess.run(["python3", "-m", "pip", "download", "--no-deps", package, "-d", str(registry_dir)], capture_output=True)

print(f"[+] Wrote scope artifacts under {OUT}")
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Sources
1. [Lightning project advisory: GHSA-w37p-236h-pfx3](https://github.com/Lightning-AI/pytorch-lightning/security/advisories/GHSA-w37p-236h-pfx3) - **Role:** VENDOR_DIRECT_SOURCE - **Impact:** Confirmed malicious versions, quarantine, credential rotation, and official remediation.
2. [Lightning: Community Discovery and 42-Minute Response](https://lightning.ai/blog/pytorch-lightning-supply-chain-attack) - **Role:** VENDOR_DIRECT_SOURCE - **Impact:** Incident discovery and project response timeline.
3. [PyPI JSON metadata: lightning](https://pypi.org/pypi/lightning/json) - **Role:** REGISTRY_DIRECT_SOURCE - **Impact:** Current release state and post-incident artifact hashes and timestamps.
4. [Socket: PyTorch Lightning PyPI Package Compromised](https://socket.dev/blog/lightning-pypi-package-compromised) - **Role:** PRIMARY_RESEARCH - **Impact:** Import-time execution chain, file IOCs, credential theft, repository poisoning, and npm propagation.
5. [Snyk: lightning PyPI Compromise](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/) - **Role:** PRIMARY_RESEARCH - **Impact:** Package versions, Bun loader, payload behavior, and publishing-path analysis.
6. [Snyk Vulnerability Database: SNYK-PYTHON-LIGHTNING-16323121](https://security.snyk.io/vuln/SNYK-PYTHON-LIGHTNING-16323121) - **Role:** ENRICHMENT_DATA - **Impact:** Advisory identifier, CVE mapping, affected versions, and severity.
7. [Sonatype: Malicious PyTorch Lightning Packages Found on PyPI](https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi?hs_amp=true) - **Role:** PRIMARY_RESEARCH - **Impact:** Cross-vendor corroboration of the affected versions, credential theft, and propagation behavior.
