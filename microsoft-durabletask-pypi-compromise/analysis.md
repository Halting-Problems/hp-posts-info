---
title: "Microsoft DurableTask Python SDK PyPI Hijacking"
date: 2026-05-19
severity: "critical"
tags:
  - pypi
  - package-compromise
  - supply-chain
  - credential-theft
  - microsoft
  - teampcp
summary: "On May 19, 2026, the official Microsoft durabletask Python SDK was compromised on PyPI. Threat actors used hijacked publishing credentials to directly upload malicious versions containing a cloud credential-harvesting payload."
sourceCount: 3
---
## Executive Summary
On May 19, 2026, the official Microsoft Python SDK **`durabletask`** (widely used for building stateful orchestrations in serverless and distributed environments) was compromised in a severe software supply chain attack [StepSecurity Incident Registry](https://www.stepsecurity.io). Attackers hijacked the PyPI publishing credentials (likely via a leaked API token or account takeover) and bypassed Microsoft's source repository and build pipeline entirely [Snyk Security Blog](https://snyk.io/advisor). They directly uploaded three compromised versions to PyPI: **1.4.1**, **1.4.2**, and **1.4.3** [StepSecurity Incident Registry](https://www.stepsecurity.io). The malicious packages contained a dropper payload designed to download and execute **`rope.pyz`**—a highly sophisticated, multi-stage credential harvesting and exfiltration framework attributed to the cybercrime group **TeamPCP** [JFrog Security Research](https://jfrog.com). The payload scraped developer workspaces, CI/CD runners, and active environment memories to steal AWS, Google Cloud, Azure, and Kubernetes secrets, exfiltrating them to TeamPCP-controlled C2 servers. CISA and Microsoft security teams intervened to yank the compromised releases and revoke the compromised token. Purge affected caches, then use the lockfile, process, and downstream audit recipes below to determine whether `rope.pyz` executed and which identities were reachable.

## Key Facts
**Threat Type**: Registry-Only Malicious Package Upload & Credential Theft

**Ecosystem**: pypi, python

**Registry**: PyPI Registry

**Affected Packages**:
- durabletask

**Malicious Versions**:
- 1.4.1
- 1.4.2
- 1.4.3

**Fixed Versions**:
- 1.4.4

**Safe Versions**:
- 1.4.0
- 1.4.4

**Exposure Window**: 2026-05-19T06:00:00Z to 2026-05-19T17:30:00Z

**Execution Trigger**: Installing the package or executing workflows pulling versions 1.4.1 - 1.4.3 during runtime or testing

**Primary Impact**: Host and runner memory scraping, secret harvesting, and automated C2 exfiltration

**Known Iocs**:
- rope[.]pyz
- filev2.getsession[.]org
- api.masscan[.]cloud

**Confidence**: high

**Canonical Source**: https://www.stepsecurity.io

## Evidence Assessment
*   **confirmed:**
    *   Malicious versions of `durabletask` published on PyPI were 1.4.1, 1.4.2, and 1.4.3. Source: [StepSecurity Incident Registry](https://www.stepsecurity.io)
    *   The attack bypassed Microsoft's repository build pipelines and was uploaded using compromised registry publishing credentials. Source: [Snyk Security Blog](https://snyk.io/advisor)
    *   The injected package acted as a dropper for the `rope.pyz` malicious framework. Source: [JFrog Security Research](https://jfrog.com)
*   **likely:**
    *   The attack is linked to the wider "Mini Shai-Hulud" supply chain campaign orchestrated by TeamPCP. Source: [StepSecurity Incident Registry](https://www.stepsecurity.io)
*   **unclear:**
    *   Whether the credentials were stolen via developer workstation compromise or leaked through a public GitHub Action log. Source: [JFrog Security Research](https://jfrog.com)

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | `durabletask==1.4.1`, `1.4.2`, or `1.4.3` is present and setup/install-time dropper executes `rope.pyz` or the reported process, file, or network indicators is observed. | Artifact inventory plus runtime telemetry showing setup/install-time dropper executes `rope.pyz` or listed C2/process/file indicators. | Isolate affected hosts or runners, preserve artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, exposed credentials are replaced, and downstream audit modules show no suspicious follow-on use. |
| Presumed exposed | `durabletask==1.4.1`, `1.4.2`, or `1.4.3` was installed, pulled, imported, built, or executed during the exposure window, but telemetry cannot prove exfiltration. | Lockfile, package cache, workflow, image pull, extension inventory, build log, or deployment record tied to the exposure window. | Rebuild from clean artifacts and rotate credentials available to the affected environment. | Credential owners confirm revocation of old material and clean artifacts are deployed. |
| Potentially exposed | The package, workflow, image, extension, or module appears in dependency or deployment records, but Python install, import, or interpreter-startup execution is not established. | Manifest, lockfile, build, deployment, or endpoint records plus a named telemetry gap. | Collect the missing execution and telemetry evidence before narrowing scope. | Every hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected version, artifact, mutable reference, or indicator appears in source, lockfiles, build outputs, deployments, package caches, or runtime telemetry. | Repository search, dependency inventory, build/deployment export, package cache query, and runtime telemetry query results. | Preserve the negative search output and keep the prevention controls active. | Search evidence covers developer endpoints, CI runners, production deployments, and package or image caches. |
| Unknown | Required inventory, build, endpoint, network, or audit telemetry is unavailable. | A gap statement naming unavailable systems, owners, and time windows. | Keep the asset in scope and make conservative rotation or rebuild decisions for high-value environments. | The missing evidence is recovered or the risk owner accepts residual uncertainty. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Dependency, workflow, extension, image, or module inventory covering developer endpoints, CI runners, and production deployments.
- Positive or negative search results for durabletask==1.4.1, durabletask==1.4.2, durabletask==1.4.3.
- Execution evidence for setup/install-time dropper executes `rope.pyz`.
- Process, file, DNS, proxy, firewall, or package-manager telemetry for listed indicators.
- Inventory of credentials, tokens, deployment paths, and downstream systems reachable from exposed environments.

## Timeline
- **2026-05-19T06:00:00Z** Attackers exploit a leaked PyPI token associated with the Microsoft package, uploading `1.4.1`, `1.4.2`, and `1.4.3` directly to PyPI. Source: [StepSecurity Incident Registry](https://www.stepsecurity.io)
- **2026-05-19T08:30:00Z** Automated threat intelligence systems at StepSecurity detect abnormal library size expansion and anomalous package structural signatures. Source: [StepSecurity Incident Registry](https://www.stepsecurity.io)
- **2026-05-19T10:15:00Z** Snyk and Microsoft Security teams begin analysis of the dropped file `rope.pyz`. Source: [Snyk Security Blog](https://snyk.io/advisor)
- **2026-05-19T17:30:00Z** PyPI administrators remove the malicious releases and invalidate the compromised publishing tokens. Source: [StepSecurity Incident Registry](https://www.stepsecurity.io)

## What Happened
On May 19, 2026, enterprise security teams running automated dependency scanners flagged an unexpected patch release for Microsoft's `durabletask` library on PyPI [StepSecurity Incident Registry](https://www.stepsecurity.io). Inspection of the underlying PyPI metadata revealed that the releases were uploaded via a legacy API token rather than the standard OpenID Connect (OIDC) Trusted Publishing workflow that Microsoft normally enforces for its SDK builds [Snyk Security Blog](https://snyk.io/advisor). Inside the package archives, analysts discovered a modified setup file that executed dynamically on installation, dropping an executable archive named `rope.pyz` [JFrog Security Research](https://jfrog.com). The dropper bypassed Microsoft's official GitHub repository, leaving the source code completely clean but leaving anyone who pulled the latest version from PyPI vulnerable [StepSecurity Incident Registry](https://www.stepsecurity.io). PyPI administrators quickly deleted the compromised releases and revoked all active publisher tokens for the package [StepSecurity Incident Registry](https://www.stepsecurity.io).

## Technical Analysis

### Initial Access
Initial access was achieved using compromised registry publishing credentials [Snyk Security Blog](https://snyk.io/advisor). Threat actors either obtained a leaked PyPI API token from an exposed workstation or leveraged an active credential harvested during earlier stages of their campaign against other projects [StepSecurity Incident Registry](https://www.stepsecurity.io).

### Package or Artifact Manipulation
The repository `microsoft/durabletask-python` remained completely unaffected. The attackers downloaded the official `1.4.0` package, injected the malicious dropper into `setup.py` and the main module bundle, changed the version metadata to `1.4.1`, `1.4.2`, and `1.4.3`, and uploaded the backdoored wheel and source distribution files directly to PyPI [StepSecurity Incident Registry](https://www.stepsecurity.io).

### Execution Trigger
The malicious script was triggered automatically at install-time [Snyk Security Blog](https://snyk.io/advisor). Because `setup.py` was altered, any system running:
```bash
pip install durabletask
```
or loading the dependency during standard CI/CD workflow provisioning automatically executed the dropper script [JFrog Security Research](https://jfrog.com).

### Payload Behavior
Once triggered, the payload downloaded `rope.pyz`—an obfuscated Python zip application [JFrog Security Research](https://jfrog.com). The script unpacked the framework into the runner's local execution environment, performing memory-scraping operations to harvest active credentials [StepSecurity Incident Registry](https://www.stepsecurity.io). The malware targeted AWS credentials, Azure tokens, Google Cloud secrets, and local environment variables, matching the signature credential-stealing mechanics of TeamPCP [Snyk Security Blog](https://snyk.io/advisor).

### Exfiltration / C2
Exfiltrated data was packaged and shipped via secure outbound web requests to TeamPCP-controlled C2 servers: [1]
- `filev2.getsession[.]org`
- `api.masscan[.]cloud`

These servers were used to store collected secret dumps and coordinate further automated package hijacking tasks [StepSecurity Incident Registry](https://www.stepsecurity.io).

### Propagation
The malware does not feature direct replication code inside `durabletask`, but stolen tokens are routinely recycled by TeamPCP's centralized infrastructure to automate compromises of other packages downstream [StepSecurity Incident Registry](https://www.stepsecurity.io).

### Obfuscation or Evasion
The `rope.pyz` payload utilized zip-application bundling to package multiple obfuscated Python files together, preventing simple directory-based file scanners from flagging individual raw malicious scripts on disk [JFrog Security Research](https://jfrog.com).

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: pypi
  - **packages**: durabletask
  - **versions**: 1.4.1,1.4.2,1.4.3
  - **repositories**: microsoft/durabletask-python
  - **container_images**: 
  - **CI_CD_systems**: GitHub Actions pipelines,Azure DevOps pipelines
  - **developer_tools**: Developer workstations
**Credentials At Risk**:
- AWS access keys
- Azure service principal tokens
- Google Cloud credentials
- PyPI publishing tokens

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Domains
- www[.]stepsecurity[.]io

### Urls
- hxxps://www[.]stepsecurity[.]io


## Detection and Hunting

### Hunt Manifest: microsoft-durabletask-pypi-compromise-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Microsoft DurableTask Python SDK PyPI Hijacking?
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
OUT = Path(os.environ.get("OUT", "hp-microsoft-durabletask-pypi-compromise-scope"))

DOMAINS = ["www.stepsecurity.io"]
URLS = ["https://www.stepsecurity.io`"]

# Collect unique indicators
indicators = set()
for group in [DOMAINS, URLS]:
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
1. [StepSecurity DurableTask Analysis](https://www.stepsecurity.io/blog/durabletask-compromise-analysis) - **Role:** DIRECT_SOURCE - **Impact:** Detailed version numbers, timeline timestamps, and OIDC bypass analysis.
2. [Snyk Security Blog on PyPI Threat Vectors](https://snyk.io/blog/pypi-threat-vectors-durabletask-hijack) - **Role:** PRIMARY_RESEARCH - **Impact:** Explanation of token-hijacking and C2 infrastructure mapping.
3. [JFrog rope.pyz Technical Analysis](https://jfrog.com/blog/rope-pyz-malicious-injection-pypi-compromise) - **Role:** PRIMARY_RESEARCH - **Impact:** Zip-app payload bundling mechanics and credential-scraping behavior details.
