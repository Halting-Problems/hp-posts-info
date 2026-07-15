---
title: "LiteLLM Python SDK PyPI Hijacking & Cascading Trust Failure"
date: 2026-03-24
severity: "critical"
tags:
  - pypi
  - package-compromise
  - supply-chain
  - credential-theft
  - teampcp
  - cascading-trust
summary: "On March 24, 2026, the popular LiteLLM Python package was compromised on PyPI. Attackers harvested PyPI publishing secrets from LiteLLM's CI/CD runner via a previously backdoored dependency, uploading malicious versions containing a python startup hook payload."
sourceCount: 3
---
## Executive Summary
On March 24, 2026, the popular Python library **`litellm`** (used to call 100+ LLM APIs using the OpenAI format) was compromised in a highly sophisticated, cascading software supply chain attack [Snyk Advisory Database](https://snyk.io/advisor). Rather than targeting the maintainers' workstations directly, the attackers executed a "cascading trust" attack [Zscaler ThreatLabz](https://www.zscaler.com). By leveraging their earlier compromise of the widely adopted container scanner **Trivy** inside LiteLLM's GitHub Actions build pipeline, they scraped memory configurations to harvest LiteLLM's long-lived PyPI publishing API token [Datadog Security Research](https://www.datadoghq.com). Using the stolen credentials, they directly published two compromised versions to PyPI: **1.82.7** and **1.82.8** [LiteLLM AI Official Advisory](https://www.litellm.ai). The backdoored wheels contained a malicious **`.pth`** startup hook file designed to execute automatically on Python startup-even if `litellm` was never explicitly imported [Datadog Security Research](https://www.datadoghq.com). The payload acted as a credential harvester, capturing environment variables, database keys, cloud IAM credentials, and AI provider tokens, exfiltrating the data to TeamPCP C2 servers. PyPI administrators intervened to delete the compromised versions. Use the `.pth` artifact, Python startup, and publishing-token audit recipes below to determine whether the compromised wheels executed and whether the stolen PyPI identity was reused.

## Key Facts
**Threat Type**: Cascading CI/CD Compromise & Startup Hook Package Poisoning

**Ecosystem**: pypi, python

**Registry**: PyPI Registry

**Affected Packages**:
- litellm

**Malicious Versions**:
- 1.82.7
- 1.82.8

**Fixed Versions**:
- 1.83.0

**Safe Versions**:
- 1.82.6
- 1.83.0

**Exposure Window**: 2026-03-24T12:00:00Z to 2026-03-24T15:30:00Z

**Execution Trigger**: Python interpreter initialization in environments where the compromised package versions were installed

**Primary Impact**: Host workstation and pipeline memory scraping, secret harvesting, and automated exfiltration

**Known Iocs**:
- litellm_init.pth
- filev2.getsession[.]org
- api.masscan[.]cloud

**Confidence**: high

**Canonical Source**: hxxps://www[.]litellm[.]ai

## Evidence Assessment
*   **confirmed:**
    *   Compromised package releases published on PyPI under `litellm` were versions 1.82.7 and 1.82.8. Source: [LiteLLM AI Official Advisory](https://www.litellm.ai)
    *   The PyPI API key was exfiltrated from the CI/CD pipeline due to a previously compromised execution of the Trivy scanner. Source: [Snyk Advisory Database](https://snyk.io/advisor)
    *   The payload utilized a `.pth` file (`litellm_init.pth`) to hijack Python's site-packages initialization mechanics and auto-run on startup. Source: [Datadog Security Research](https://www.datadoghq.com)
*   **likely:**
    *   The attack was executed by the threat syndicate TeamPCP as part of a wider multi-ecosystem campaign. Source: [Zscaler ThreatLabz](https://www.zscaler.com)
*   **unclear:**
    *   The exact volume of downstream development and production environments that fetched the malicious wheels during the three-hour window. Source: [LiteLLM AI Official Advisory](https://www.litellm.ai)

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | `litellm==1.82.7` or `litellm==1.82.8` is present and Python interpreter startup executes `litellm_init.pth` or the reported process, file, or network indicators is observed. | Artifact inventory plus runtime telemetry showing Python interpreter startup executes `litellm_init.pth` or listed C2/process/file indicators. | Isolate affected hosts or runners, preserve artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, exposed credentials are replaced, and downstream audit modules show no suspicious follow-on use. |
| Presumed exposed | `litellm==1.82.7` or `litellm==1.82.8` was installed, pulled, imported, built, or executed during the exposure window, but telemetry cannot prove exfiltration. | Lockfile, package cache, workflow, image pull, extension inventory, build log, or deployment record tied to the exposure window. | Rebuild from clean artifacts and rotate credentials available to the affected environment. | Credential owners confirm revocation of old material and clean artifacts are deployed. |
| Potentially exposed | The package, workflow, image, extension, or module appears in dependency or deployment records, but Python install, import, or interpreter-startup execution is not established. | Manifest, lockfile, build, deployment, or endpoint records plus a named telemetry gap. | Collect the missing execution and telemetry evidence before narrowing scope. | Every hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected version, artifact, mutable reference, or indicator appears in source, lockfiles, build outputs, deployments, package caches, or runtime telemetry. | Repository search, dependency inventory, build/deployment export, package cache query, and runtime telemetry query results. | Preserve the negative search output and keep the prevention controls active. | Search evidence covers developer endpoints, CI runners, production deployments, and package or image caches. |
| Unknown | Required inventory, build, endpoint, network, or audit telemetry is unavailable. | A gap statement naming unavailable systems, owners, and time windows. | Keep the asset in scope and make conservative rotation or rebuild decisions for high-value environments. | The missing evidence is recovered or the risk owner accepts residual uncertainty. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Dependency, workflow, extension, image, or module inventory covering developer endpoints, CI runners, and production deployments.
- Positive or negative search results for litellm==1.82.7, litellm==1.82.8.
- Execution evidence for Python interpreter startup executes `litellm_init.pth`.
- Process, file, DNS, proxy, firewall, or package-manager telemetry for listed indicators.
- Inventory of credentials, tokens, deployment paths, and downstream systems reachable from exposed environments.

## Timeline
- **2026-03-19T08:00:00Z** TeamPCP compromises Trivy scanner tags in GitHub Actions. Source: [Snyk Advisory Database](https://snyk.io/advisor)
- **2026-03-24T10:30:00Z** LiteLLM's GitHub Actions build pipeline executes a compromised Trivy runner, exfiltrating the repository's PyPI publishing token to TeamPCP servers. Source: [Zscaler ThreatLabz](https://www.zscaler.com)
- **2026-03-24T12:00:00Z** Attackers exploit the stolen token to directly publish `1.82.7` and `1.82.8` to PyPI. Source: [LiteLLM AI Official Advisory](https://www.litellm.ai)
- **2026-03-24T12:40:00Z** Security researchers at Datadog and Snyk flag anomalous `.pth` insertions inside the newly released package wheels. Source: [Datadog Security Research](https://www.datadoghq.com)
- **2026-03-24T15:30:00Z** PyPI administrators remove the malicious versions and ban the compromised API key. Source: [LiteLLM AI Official Advisory](https://www.litellm.ai)

## What Happened
On March 24, 2026, the developers of `litellm` were alerted by security researchers that Snyk had flagged a major structural anomaly in the package's latest minor updates on PyPI [LiteLLM AI Official Advisory](https://www.litellm.ai). Analysts discovered that although the main code in the repository remained unaltered, the published packages contained a newly introduced file named `litellm_init.pth` inside the wheel archive [Datadog Security Research](https://www.datadoghq.com). Retrospective build analysis showed that a previous automated build workflow executed a compromised container scanner (Trivy), which silently harvested the repository's long-lived PyPI token and exfiltrated it [Snyk Advisory Database](https://snyk.io/advisor). Using this out-of-band token, the threat group TeamPCP directly uploaded backdoored releases, bypassing peer review and repository pull request gates entirely [Zscaler ThreatLabz](https://www.zscaler.com).

## Technical Analysis

### Initial Access
Initial access was achieved via a cascading trust failure [Zscaler ThreatLabz](https://www.zscaler.com). The attackers first hijacked mutable version tags in an upstream dependency—the Trivy container scanner Action—which LiteLLM's release pipeline imported for automated security compliance scans [Snyk Advisory Database](https://snyk.io/advisor). When the workflow executed, the poisoned Trivy runner scraped memory directories to extract the repository secrets (including the PyPI publish token) and shipped it to the C2 nameserver [Datadog Security Research](https://www.datadoghq.com). [1]

### Package or Artifact Manipulation
The repository `BerriAI/litellm` was not breached. The attackers packaged the compromised release locally. They injected a malicious payload file `litellm_init.py` and a startup directive `litellm_init.pth` into the site-packages root directory, updating the version metadata to `1.82.7` and `1.82.8` before pushing the wheels to PyPI using the exfiltrated key [LiteLLM AI Official Advisory](https://www.litellm.ai). [1]

### Execution Trigger
The execution trigger exploited Python's path configuration (`.pth`) file processing [Datadog Security Research](https://www.datadoghq.com). Upon interpreter startup, Python automatically processes all `.pth` files in the `site-packages` directory. By formatting the file to import the malicious initialization module, the payload ran automatically whenever Python started up:
```python
import sys; import litellm_init # Triggers setup automatically on Python startup
```
This allowed the malware to run without requiring the user to explicitly call `import litellm` in their code [Datadog Security Research](https://www.datadoghq.com).

### Payload Behavior
The payload enumerates system environments, harvesting cloud IAM access keys, SSH keys, database credentials, and GitHub PATs. The malware was designed to establish persistent footholds on developer machines and attempt lateral movement inside compromised Kubernetes clusters using stolen configuration files [Zscaler ThreatLabz](https://www.zscaler.com).

### Exfiltration / C2
Telemetry data was compressed, encoded in Base64, and shipped to TeamPCP-controlled endpoints:
- `filev2.getsession[.]org`
- `api.masscan[.]cloud`

### Propagation
Stolen cloud and GitHub credentials were automatically analyzed by TeamPCP's backend server to identify further vulnerable repositories, creating a cascading propagation effect [StepSecurity Incident Registry](https://www.stepsecurity.io).

### Obfuscation or Evasion
The use of the `.pth` startup hook was a highly effective evasion technique, as traditional static scanners that only parse import trees inside project source files failed to detect that the backdoored dependency was actively running in the background [Datadog Security Research](https://www.datadoghq.com).

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: pypi
  - **packages**: litellm
  - **versions**: 1.82.7,1.82.8
  - **repositories**: BerriAI/litellm
  - **container_images**:
  - **CI_CD_systems**: GitHub Actions pipelines
  - **developer_tools**: Developer workstations,Python execution runtimes
**Credentials At Risk**:
- PyPI publishing tokens
- AWS IAM credentials
- GCP service account keys
- Azure principal keys
- SSH private keys

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Domains
- www.litellm.ai

### Urls
- hxxps://www[.]litellm[.]ai


## Detection and Hunting

### Hunt Manifest: litellm-pypi-hijacking-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with LiteLLM Python SDK PyPI Hijacking & Cascading Trust Failure?
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
OUT = Path(os.environ.get("OUT", "hp-litellm-pypi-hijacking-scope"))

DOMAINS = ["www.litellm.ai"]
URLS = ["https://www.litellm.ai`"]

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
1. [LiteLLM Official Security Postmortem](https://blog.litellm.ai/security/postmortem-litellm-pypi-hijacking) - **Role:** DIRECT_SOURCE - **Impact:** Advisory notification, version boundaries, and remediation guidelines.
2. [Datadog Security Research on .pth Backdoors](https://www.datadoghq.com/blog/datadog-security-research-pth-backdoors-pypi/) - **Role:** PRIMARY_RESEARCH - **Impact:** Detailed technical analysis of Python `.pth` startup hook hijacking mechanics.
3. [Zscaler ThreatLabz Trivy-LiteLLM Cascade](https://www.zscaler.com/blogs/security-research/trivy-litellm-cascade-malicious-pypi-packages) - **Role:** PRIMARY_RESEARCH - **Impact:** Correlation of the cascading trust attack between Trivy and LiteLLM.
