---
title: "TanStack CI/CD Release Pipeline Poisoning"
date: 2026-05-11
severity: "critical"
tags:
  - npm
  - supply-chain
  - compromise
  - github-actions
  - oidc
  - teampcp
summary: "On May 11, 2026, the popular open-source project TanStack fell victim to a CI/CD release pipeline poisoning attack. Threat actors hijacked the release pipeline via a pull request exploitation vector and OIDC token theft to publish 84 backdoored versions across 42 packages."
sourceCount: 4
---
## Executive Summary
On May 11, 2026, the highly popular open-source project TanStack (used widely for state management, routing, and data fetching) fell victim to a highly sophisticated CI/CD pipeline poisoning attack [TanStack Advisory](https://tanstack.com). The threat actor group **TeamPCP** (also tracked as **UNC6780**) bypassed direct registry controls by exploiting a `pull_request_target` "Pwn Request" vulnerability and GitHub Actions cache poisoning [Snyk Research](https://snyk.io/advisor). This allowed them to hijack the automated release pipeline and publish 84 backdoored versions across 42 legitimate `@tanstack/*` npm packages [TanStack Advisory](https://tanstack.com). The malicious versions executed a credential-stealing loader (`router_init.js`) during package installation, which subsequently led to the compromise of downstream development assets—most notably, the theft of an Nx contributor's GitHub CLI credentials [StepSecurity](https://www.stepsecurity.io/blog). Start with the persistence-file, install-time payload, and contributor-token audit recipes below before rotating identities from confirmed runs [TanStack Advisory](https://tanstack.com).

## Key Facts
**Threat Type**: CI/CD compromise, GitHub Actions compromise, poisoned release, artifact tampering, credential theft, token exfiltration

**Ecosystem**: npm

**Registry**: npmjs.com

**Affected Packages**:
- @tanstack/zod-adapter
- @tanstack/router
- @tanstack/react-router
- @tanstack/react-query
- @tanstack/table-core

**Malicious Versions**:
- 1.166.12
- 1.166.15

**Fixed Versions**:
- 1.166.16
- 1.166.17

**Safe Versions**:
- v1.166.16 and later

**Exposure Window**: 2026-05-11T19:20:00Z to 2026-05-11T20:15:00Z (55 minutes)

**Execution Trigger**: install-time execution (npm lifecycle scripts)

**Primary Impact**: Credential theft (AWS/GCP tokens, npm configs, SSH keys, GitHub PATs) and lateral worm propagation

**Known Iocs**:
- router_init.js
- ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c
- git-tanstack[.]com

**Confidence**: high

**Canonical Source**: hxxps://tanstack[.]com

## Evidence Assessment
*   **confirmed:** Hijack of GitHub Actions automated release pipeline via a pull request exploitation vector, resulting in 84 backdoored releases across 42 `@tanstack/*` npm packages. [TanStack Advisory](https://tanstack.com)
*   **likely:** Chaining of `pull_request_target` workflow vulnerabilities and cache poisoning to forge signed OIDC identity tokens, enabling authorized publishing to the npm registry. [Snyk Research](https://snyk.io/advisor)
*   **unclear:** The complete list of developer environments or downstream organizations that downloaded and executed the malicious version during the 55-minute exposure window.
*   **not_observed:** No direct maintainer account passwords or active MFA sessions were bypassed; the threat actor interacted solely with the automated pipeline's credentials.

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | a compromised `@tanstack/*` release is present and npm install executes the injected TanStack loader or the reported process, file, or network indicators is observed. | Artifact inventory plus runtime telemetry showing npm install executes the injected TanStack loader or listed C2/process/file indicators. | Isolate affected hosts or runners, preserve artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, exposed credentials are replaced, and downstream audit modules show no suspicious follow-on use. |
| Presumed exposed | a compromised `@tanstack/*` release was installed, pulled, imported, built, or executed during the exposure window, but telemetry cannot prove exfiltration. | Lockfile, package cache, workflow, image pull, extension inventory, build log, or deployment record tied to the exposure window. | Rebuild from clean artifacts and rotate credentials available to the affected environment. | Credential owners confirm revocation of old material and clean artifacts are deployed. |
| Potentially exposed | The package, workflow, image, extension, or module appears in dependency or deployment records, but workflow, action, release, or runner execution is not established. | Manifest, lockfile, build, deployment, or endpoint records plus a named telemetry gap. | Collect the missing execution and telemetry evidence before narrowing scope. | Every hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected version, artifact, mutable reference, or indicator appears in source, lockfiles, build outputs, deployments, package caches, or runtime telemetry. | Repository search, dependency inventory, build/deployment export, package cache query, and runtime telemetry query results. | Preserve the negative search output and keep the prevention controls active. | Search evidence covers developer endpoints, CI runners, production deployments, and package or image caches. |
| Unknown | Required inventory, build, endpoint, network, or audit telemetry is unavailable. | A gap statement naming unavailable systems, owners, and time windows. | Keep the asset in scope and make conservative rotation or rebuild decisions for high-value environments. | The missing evidence is recovered or the risk owner accepts residual uncertainty. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Dependency, workflow, extension, image, or module inventory covering developer endpoints, CI runners, and production deployments.
- Positive or negative search results for 84 compromised @tanstack versions, @tanstack/zod-adapter@1.166.12, @tanstack/zod-adapter@1.166.15.
- Execution evidence for npm install executes the injected TanStack loader.
- Process, file, DNS, proxy, firewall, or package-manager telemetry for listed indicators.
- Inventory of credentials, tokens, deployment paths, and downstream systems reachable from exposed environments.

## Timeline
- **2026-05-11T19:20:00Z** Attackers submit a malicious pull request, triggering the poisoned GitHub Actions workflow. Source: [Snyk Research](https://snyk.io/advisor)
- **2026-05-11T19:23:00Z** Attackers successfully poison the GitHub Actions runner cache and extract valid OIDC identity tokens. Source: [StepSecurity](https://www.stepsecurity.io/blog)
- **2026-05-11T19:26:00Z** First batch of 84 malicious `@tanstack/*` packages (including `@tanstack/zod-adapter@1.166.12`) are published to npmjs.com. Source: [TanStack Advisory](https://tanstack.com)
- **2026-05-11T19:45:00Z** Maintainers detect anomaly in automated release logs and initiate active incident response. Source: [TanStack Advisory](https://tanstack.com)
- **2026-05-11T20:15:00Z** npm registry removes the 84 backdoored versions and revokes the associated publishing tokens. Source: [TanStack Advisory](https://tanstack.com)
- **2026-05-11T20:30:00Z** TanStack releases clean, official patches (e.g., `@tanstack/zod-adapter@1.166.16`) and issues an all-clear. Source: [TanStack Advisory](https://tanstack.com)
- **2026-05-11T21:00:00Z** Official security advisory is published under tracking ID GHSA-g7cv-rxg3-hmpx. Source: [GHSA Database](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx)

## What Happened
On May 11, 2026, the threat group **TeamPCP** compromised the trusted release flow of the `@tanstack/*` project [Snyk Research](https://snyk.io/advisor). By crafting a pull request that triggered a poorly isolated `pull_request_target` GitHub Actions runner, the attackers executed malicious code within a privileged context [StepSecurity](https://www.stepsecurity.io/blog). The runner's OIDC tokens were intercepted, allowing the attackers to authenticate directly to the npm registry as a trusted publisher [Palo Alto Networks](https://paloaltonetworks.com). Within minutes, the attackers pushed 84 compromised packages before maintainers noticed the rogue build logs and intervened to take down the releases [TanStack Advisory](https://tanstack.com).

## Technical Analysis

### Initial Access
Initial access was achieved via a "Pwn Request" targeting the project's GitHub Actions workflow [StepSecurity](https://www.stepsecurity.io/blog). The workflow, configured with `pull_request_target` permissions, allowed untrusted forks to execute code with access to repository secrets and OIDC scopes. The attacker poisoned the GitHub Actions runner cache, inserting a malicious dependency loader that hijacked subsequent release stages.

### Package or Artifact Manipulation
The attackers did not modify the main branch codebase. Instead, they manipulated the build runtime, injecting a malicious payload loader directly into the build artifact compilation step. The resulting package tarball included an injected `optionalDependencies` pointer redirecting to a rogue fork (`"@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"`) and planted a heavily obfuscated payload named `router_init.js` in the root of the packages [Snyk Research](https://snyk.io/advisor).

### Execution Trigger
The malware utilized npm install lifecycle hooks (e.g., `preinstall` or `postinstall` script triggers) defined in `package.json`. Upon running `npm install` on a developer workstation or a CI runner, Node.js executed the lifecycle hooks, launching `router_init.js` through the system shell.

### Payload Behavior
The payload, `router_init.js` (a ~2.3 MB obfuscated loader), functioned as a credential-harvesting worm ("Mini Shai-Hulud") [Palo Alto Networks](https://paloaltonetworks.com). Once active, it profiled the host environment, searching for local files containing secrets. It harvested:
- AWS, Azure, and Google Cloud API credentials
- Kubernetes service account tokens
- HashiCorp Vault access configurations
- Local `.npmrc` publishing tokens
- SSH private keys
- GitHub personal access tokens (PATs) and `gh` CLI OAuth sessions

The malware also established persistence via local `.vscode/tasks.json` configurations and macOS LaunchAgents (`gh-token-monitor`). To deter response efforts, the payload monitored for token revocation and featured a destructive "dead man's switch" capable of wiping filesystems if its access was severed [TanStack Advisory](https://tanstack.com). [1]

### Exfiltration / C2
**Domains**:
- git-tanstack[.]com

**Ips**:

**Urls**:
- hxxps://git-tanstack[.]com

**Protocols**:
- https
- session

**Endpoints**:
- /api/v1/exfil

**Confidence**: high

Stolen secrets were exfiltrated via HTTPS to the typosquatted C2 server `git-tanstack[.]com` and routed securely over the decentralized Session/Oxen messenger network. [1]

### Propagation
The malware featured autonomous worm capabilities, attempting to use the stolen npm and GitHub tokens to automatically publish malicious package updates to other downstream packages owned by the compromised developer or organization.

### Obfuscation or Evasion
The `router_init.js` loader used complex multi-layered control-flow flattening, string encryption, and dead-code insertion to evade static analysis filters. Additionally, it attempted to download the Bun runtime (`setup_bun.js`) to execute its subsequent phases, circumventing Node-specific endpoint detection products.

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: npm
  - **packages**: @tanstack/zod-adapter,@tanstack/router,@tanstack/react-router,@tanstack/react-query,@tanstack/table-core
  - **versions**: 1.166.12,1.166.15
  - **repositories**: github.com/tanstack/router,github.com/tanstack/query
  - **container_images**:
  - **CI_CD_systems**: GitHub Actions
  - **developer_tools**: npm CLI,VS Code
  - **environments**: developer workstations,CI runners,build pipelines

**Credentials At Risk**:
- npm tokens
- GitHub tokens
- cloud credentials
- SSH keys
- environment variables

**Not Currently Known To Affect**:
- Production environments where install scripts are disabled (`--ignore-scripts`).

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c

### Domains
- git-tanstack[.]com
- tanstack[.]com
- snyk[.]io

### Urls
- hxxps://git-tanstack[.]com
- hxxps://tanstack[.]com
- hxxps://snyk[.]io


## Detection and Hunting

### Hunt Manifest: tanstack-pipeline-poisoning-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with TanStack CI/CD Release Pipeline Poisoning?
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
OUT = Path(os.environ.get("OUT", "hp-tanstack-pipeline-poisoning-scope"))

DOMAINS = ["git-tanstack[.]com","tanstack[.]com","snyk[.]io"]
URLS = ["https://git-tanstack[.]com","https://tanstack.com","https://snyk.io"]
HASHES = ["ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"]

# Collect unique indicators
indicators = set()
for group in [DOMAINS, URLS, HASHES]:
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
            print(f"[+] Querying npm view for {package}...")
            res = subprocess.run(["npm", "view", package, "name", "version", "time", "versions", "dist-tags", "maintainers", "dist.tarball", "dist.integrity", "scripts", "--json"], capture_output=True, text=True)
            if res.returncode == 0:
                (registry_dir / f"npm-{safe_name}.json").write_text(res.stdout)

print(f"[+] Wrote scope artifacts under {OUT}")
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Sources
1. [TanStack Official Postmortem](https://tanstack.com/blog/tanstack-pipeline-poisoning-security-postmortem). **Role:** DIRECT_SOURCE **Impact:** Detailed timeline, affected versions, and root cause analysis of the pipeline hijacking.
2. [GHSA-g7cv-rxg3-hmpx Advisory Record](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx). **Role:** DIRECT_SOURCE **Impact:** Official vulnerability tracking and affected version mapping.
3. [Snyk Security Analysis of TanStack Incident](https://snyk.io/blog/tanstack-pipeline-poisoning-pwn-request-attack). **Role:** PRIMARY_RESEARCH **Impact:** In-depth breakdown of the "Pwn Request" pattern and OIDC token hijacking vector.
4. [StepSecurity Incident Investigation Report](https://www.stepsecurity.io/blog/tanstack-pipeline-poisoning-investigation). **Role:** PRIMARY_RESEARCH **Impact:** Detailed technical analysis of the runner cache poisoning and loader persistence mechanics.
