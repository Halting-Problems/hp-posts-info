---
title: "elementary-data PyPI and GHCR GitHub Actions Compromise"
date: 2026-04-25
severity: "critical"
tags:
  - pypi
  - github-actions
  - ghcr
  - supply-chain
  - credential-theft
summary: "A malicious `elementary-data==0.23.3` release was pushed to PyPI and GHCR after attackers exploited a GitHub Actions script-injection path, adding an interpreter-startup `.pth` infostealer."
sourceCount: 6
---

## Executive Summary
On April 24, 2026 at 22:20:47 UTC, a malicious `elementary-data==0.23.3` release was uploaded to PyPI [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection). The same release workflow also pushed a compromised multi-architecture container image to GitHub Container Registry at `ghcr.io/elementary-data/elementary`, including the `0.23.3` and `latest` tags [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).

The attacker exploited a script-injection vulnerability in an Elementary GitHub Actions workflow, used the workflow's `GITHUB_TOKEN` to forge a release commit, and dispatched the legitimate publishing pipeline without modifying the `master` branch [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection). The malicious wheel and source distribution added a top-level `elementary.pth` file, which Python executes at interpreter startup when installed in `site-packages`; this means the payload could run even if the victim never explicitly imported `elementary` [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).

Elementary's incident report defines the affected window as **2026-04-24 22:10 UTC through 2026-04-25 09:45 UTC** and says users who installed `0.23.3` or ran the affected container should assume credentials available to that environment were exposed [Elementary](https://www.elementary-data.com/post/security-incident-report-malicious-release-of-elementary-oss-python-cli-v0-23-3). Snyk tracks the incident as `SNYK-PYTHON-ELEMENTARYDATA-16316110`, affecting only `elementary-data==0.23.3`; Elementary Cloud, the Elementary dbt package, and other CLI versions were not affected [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PYTHON-ELEMENTARYDATA-16316110). The clean replacement is `0.23.4` [PyPI](https://pypi.org/project/elementary-data/).

## Key Facts
**Threat Type**: GitHub Actions script injection, forged release, PyPI/GHCR credential stealer

**Ecosystem**: pypi, python, container

**Registry**:
- PyPI
- GitHub Container Registry

**Affected Packages**:
- elementary-data

**Malicious Versions**:
- 0.23.3

**Fixed Versions**:
- 0.23.4 and later

**Known Good Versions**:
- 0.23.2

**Execution Trigger**: Python interpreter startup through elementary.pth

**Primary Impact**: dbt, data warehouse, cloud, SSH, API token, environment variable, and developer secret theft

**Known Iocs**:
- elementary.pth
- ghcr.io/elementary-data/elementary:0.23.3
- ghcr.io/elementary-data/elementary:latest
- igotnofriendsonlineorirl-imgonnakmslmao[.]skyhanni[.]cloud
- X-Rise-To-The-Trinny: agree
- trin[.]tar[.]gz
- /tmp/.trinny-security-update
- %TEMP%\.trinny-security-update

**Confidence**: high

**Canonical Source**: https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection

**Affected Window**: 2026-04-24T22:10:00Z/2026-04-25T09:45:00Z

**Last Verified**: 2026-06-10

## Evidence Assessment
* **confirmed:** `elementary-data==0.23.3` was the malicious PyPI release; `0.23.4` is the clean replacement [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection) [PyPI](https://pypi.org/project/elementary-data/).
* **confirmed:** The malicious release added `elementary.pth`, which executes at Python interpreter startup from `site-packages` [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).
* **confirmed:** The incident also affected GHCR images tagged `0.23.3` and `latest`, with the clean `0.23.2` image available by digest for comparison [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).
* **confirmed:** Snyk identifies the payload as an embedded credential stealer targeting dbt profiles, data warehouse credentials, cloud keys, API tokens, SSH keys, `.env` files, and environment variables [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PYTHON-ELEMENTARYDATA-16316110).
* **confirmed:** Elementary states the affected window, exact response timeline, marker paths, credential-rotation scope, and that only CLI version `0.23.3` and the corresponding container were affected [Elementary](https://www.elementary-data.com/post/security-incident-report-malicious-release-of-elementary-oss-python-cli-v0-23-3).
* **confirmed registry state:** PyPI no longer exposes `0.23.3`; clean `0.23.4` artifacts were uploaded at 11:48 UTC on April 25 with SHA-256 values `fe52712660fef56586d954e50f81ccc7b96ed2809b5e930c7b9d032e7ab03b8d` and `5cf8f4c3fa0b7e84cb0096c94eb9af941ea632c9acffa002d0db3b3c1d9ef97e` [PyPI](https://pypi.org/project/elementary-data/).
* **unclear:** The public sources do not identify the threat actor or confirm whether any stolen credentials were used after exfiltration.

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | `elementary-data==0.23.3` or the compromised GHCR image is present and Python startup executes `elementary.pth` or the reported process, file, or network indicators is observed. | Artifact inventory plus runtime telemetry showing Python startup executes `elementary.pth` or listed C2/process/file indicators. | Isolate affected hosts or runners, preserve artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, exposed credentials are replaced, and downstream audit modules show no suspicious follow-on use. |
| Presumed exposed | `elementary-data==0.23.3` or the compromised GHCR image was installed, pulled, imported, built, or executed during the exposure window, but telemetry cannot prove exfiltration. | Lockfile, package cache, workflow, image pull, extension inventory, build log, or deployment record tied to the exposure window. | Rebuild from clean artifacts and rotate credentials available to the affected environment. | Credential owners confirm revocation of old material and clean artifacts are deployed. |
| Potentially exposed | The package, workflow, image, extension, or module appears in dependency or deployment records, but Python install, import, or interpreter-startup execution is not established. | Manifest, lockfile, build, deployment, or endpoint records plus a named telemetry gap. | Collect the missing execution and telemetry evidence before narrowing scope. | Every hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected version, artifact, mutable reference, or indicator appears in source, lockfiles, build outputs, deployments, package caches, or runtime telemetry. | Repository search, dependency inventory, build/deployment export, package cache query, and runtime telemetry query results. | Preserve the negative search output and keep the prevention controls active. | Search evidence covers developer endpoints, CI runners, production deployments, and package or image caches. |
| Unknown | Required inventory, build, endpoint, network, or audit telemetry is unavailable. | A gap statement naming unavailable systems, owners, and time windows. | Keep the asset in scope and make conservative rotation or rebuild decisions for high-value environments. | The missing evidence is recovered or the risk owner accepts residual uncertainty. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Dependency, workflow, extension, image, or module inventory covering developer endpoints, CI runners, and production deployments.
- Positive or negative search results for elementary-data==0.23.3, ghcr.io/elementary-data/elementary:0.23.3, ghcr.io/elementary-data/elementary:latest.
- Execution evidence for Python startup processing `elementary.pth`, or the marker `/tmp/.trinny-security-update` or `%TEMP%\.trinny-security-update`.
- Process, file, DNS, proxy, firewall, or package-manager telemetry for listed indicators.
- Inventory of credentials, tokens, deployment paths, and downstream systems reachable from exposed environments.

## Timeline
- **2026-04-24T22:10:00Z:** A crafted pull-request comment triggers the vulnerable workflow [Elementary](https://www.elementary-data.com/post/security-incident-report-malicious-release-of-elementary-oss-python-cli-v0-23-3).
- **2026-04-24T22:20:47Z:** `elementary-data==0.23.3` is uploaded to PyPI with a malicious top-level `elementary.pth` file [Elementary](https://www.elementary-data.com/post/security-incident-report-malicious-release-of-elementary-oss-python-cli-v0-23-3) [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).
- **2026-04-24T22:24:00Z:** The compromised container image is pushed to GHCR [Elementary](https://www.elementary-data.com/post/security-incident-report-malicious-release-of-elementary-oss-python-cli-v0-23-3).
- **2026-04-25T06:18:26Z:** GitHub issue #2205 reports the malicious release [GitHub](https://github.com/elementary-data/elementary/issues/2205).
- **2026-04-25T08:51:00Z-11:51:00Z:** Elementary removes affected artifacts and workflows, rotates credentials, and publishes clean `0.23.4` [Elementary](https://www.elementary-data.com/post/security-incident-report-malicious-release-of-elementary-oss-python-cli-v0-23-3).
- **2026-04-27:** Elementary publishes its incident report; Snyk publishes its technical analysis and advisory [Elementary](https://www.elementary-data.com/post/security-incident-report-malicious-release-of-elementary-oss-python-cli-v0-23-3) [Snyk](https://snyk.io/blog/malicious-release-of-elementary-data-pypi-package-steals-cloud-credentials-from-data-engineers/).

## What Happened
The attacker did not need to land a conventional malicious pull request on the default branch. Instead, they abused a script-injection weakness in a GitHub Actions workflow and used the workflow's own token to forge a release commit that looked signed by automation [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection). The release tag pointed to an orphaned commit that bumped the version to `0.23.3` and added `elementary.pth`, rather than a normal branch commit reviewed through the project workflow [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).

Because `.pth` files are evaluated by Python at interpreter startup, the malicious code could execute in any environment where the package was installed, independent of application-level imports [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection). The same release run produced a compromised container image, expanding the blast radius to teams pulling `ghcr.io/elementary-data/elementary:latest` in data engineering deployments [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).

## Technical Analysis
### Initial Access
Initial access came through a GitHub Actions script-injection vector, not through a direct commit to `master` [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection). The key failure was allowing attacker-influenced workflow input to execute with a token capable of causing release publication.

### Package or Artifact Manipulation
The malicious delta was narrow: a version bump plus a single top-level `elementary.pth` file containing a large base64-wrapped payload [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection). That small source delta belied a serious runtime impact because `.pth` execution happens automatically at interpreter startup.

### Payload Behavior
Snyk reports that the malware harvested dbt profiles, Snowflake, BigQuery, Redshift, AWS, GCP, Azure, API token, SSH key, `.env`, and active environment variable secrets [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PYTHON-ELEMENTARYDATA-16316110). StepSecurity lists the C2/exfiltration domain as `igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud`, the exfiltration header as `X-Rise-To-The-Trinny: agree`, and the staged archive as `trin.tar.gz` [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection). [1]

## Affected Assets and Blast Radius

**Affected Assets**:
  - **ecosystems**: PyPI,Python
  - **registries**: pypi.org
  - **packages**: elementary-data
  - **versions**: elementary-data==0.23.3,ghcr.io/elementary-data/elementary:0.23.3,ghcr.io/elementary-data/elementary:latest
  - **repositories**: elementary-data/elementary
  - **ci_cd_systems**: GitHub Actions
  - **container_images**: ghcr.io/elementary-data/elementary:0.23.3,ghcr.io/elementary-data/elementary:latest
  - **developer_tools**: dbt,data engineering CLI environments

**Credentials At Risk**:
- dbt profiles
- data warehouse credentials
- cloud credentials
- API tokens
- SSH keys
- CI/CD secrets
- Docker credentials
- Kubernetes credentials

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

### Hashes
- 31ecc5939de6d24cf60c50d4ca26cf7a8c322db82a8ce4bd122ebd89cf634255
- b3bbfafde1a0db3a4d47e70eb0eb2ca19daef4a19410154a71abee567b35d3d9
- fe52712660fef56586d954e50f81ccc7b96ed2809b5e930c7b9d032e7ab03b8d
- 5cf8f4c3fa0b7e84cb0096c94eb9af941ea632c9acffa002d0db3b3c1d9ef97e

### Domains
- elementary.pth
- igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud


## Detection and Hunting

### Hunt Manifest: elementary-data-pypi-ghcr-compromise-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with elementary-data PyPI and GHCR GitHub Actions Compromise?
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
OUT = Path(os.environ.get("OUT", "hp-elementary-data-pypi-ghcr-compromise-scope"))

DOMAINS = ["ghcr.io","elementary.pth","igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud"]
HASHES = ["31ecc5939de6d24cf60c50d4ca26cf7a8c322db82a8ce4bd122ebd89cf634255","b3bbfafde1a0db3a4d47e70eb0eb2ca19daef4a19410154a71abee567b35d3d9","fe52712660fef56586d954e50f81ccc7b96ed2809b5e930c7b9d032e7ab03b8d","5cf8f4c3fa0b7e84cb0096c94eb9af941ea632c9acffa002d0db3b3c1d9ef97e"]

# Collect unique indicators
indicators = set()
for group in [DOMAINS, HASHES]:
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
1. [StepSecurity: elementary-data Compromised on PyPI and GHCR](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection) - **Role:** PRIMARY_RESEARCH - **Impact:** Timeline, attack path, `.pth` execution, GHCR digest, C2 indicators.
2. [Snyk Vulnerability Database: SNYK-PYTHON-ELEMENTARYDATA-16316110](https://security.snyk.io/vuln/SNYK-PYTHON-ELEMENTARYDATA-16316110) - **Role:** ENRICHMENT_DATA - **Impact:** Advisory ID, affected version, severity, credential classes.
3. [Snyk: Malicious Release of elementary-data PyPI Package](https://snyk.io/es/blog/malicious-release-of-elementary-data-pypi-package-steals-cloud-credentials-from-data-engineers/) - **Role:** PRIMARY_RESEARCH - **Impact:** Data engineering target profile and remediation context.
4. [PyPI project page: elementary-data](https://pypi.org/project/elementary-data/) - **Role:** DIRECT_SOURCE - **Impact:** Clean replacement release evidence.
5. [Elementary GitHub issue #2205](https://github.com/elementary-data/elementary/issues/2205) - **Role:** DIRECT_SOURCE - **Impact:** Original community report and discovery timestamp.
6. [Elementary: Security Incident Report for CLI v0.23.3](https://www.elementary-data.com/post/security-incident-report-malicious-release-of-elementary-oss-python-cli-v0-23-3) - **Role:** VENDOR_INCIDENT_REPORT - **Impact:** Authoritative exposure window, response timeline, affected scope, marker paths, and remediation.
