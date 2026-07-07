---
title: "Nx Console VS Code Extension Compromise"
date: 2026-05-18
severity: "critical"
tags:
  - vscode
  - extension
  - supply-chain
  - compromise
  - oauth
  - teampcp
summary: "On May 18, 2026, the official Nx Console VS Code extension was compromised when attackers used an OAuth token stolen in the TanStack compromise to publish malicious version v18.95.0, resulting in the theft of 3,800 internal GitHub repositories."
sourceCount: 5
---
## Executive Summary
On May 18, 2026, a highly critical supply chain attack targeted the **Nx Console** VS Code extension, leading to a major security breach that resulted in the exfiltration of approximately 3,800 internal GitHub repositories [GitHub Security Advisory](https://github.com/advisories). The threat actor group **TeamPCP** (also tracked as **UNC6780**) leveraged a GitHub CLI OAuth token stolen seven days earlier (via the TanStack supply-chain compromise) from an Nx contributor [StepSecurity](https://www.stepsecurity.io/blog). By exploiting this developer's push credentials, the attackers bypassed registry guardrails to publish a malicious version of the extension (**v18.95.0**) to the Visual Studio Marketplace and the Open VSX registry [Nx Advisory](https://nx.dev). The extension remained active for 18 minutes on the VS Code Marketplace and 36 minutes on Open VSX. When installed and loaded inside a workspace, the extension executed an obfuscated Python backdoor (`cat.py`) that harvested developer credentials and established persistent access, compromising developer machines globally—including a critical endpoint owned by a GitHub employee [Infosecurity Magazine](https://infosecurity-magazine.com).

## Key Facts
**Threat Type**: compromised developer tool, credential theft, token exfiltration, poisoned release

**Ecosystem**: vs-code-extension-marketplace, open-vsx

**Registry**: Visual Studio Marketplace, Open VSX

**Affected Packages**:
- nx-console

**Malicious Versions**:
- 18.95.0

**Fixed Versions**:
- 18.100.0
- 18.100.5

**Safe Versions**:

**Exposure Window**: 2026-05-18T12:30:00Z to 2026-05-18T13:09:00Z (39 minutes total; 18 minutes on VS Code Marketplace)

**Execution Trigger**: Workspace load-time execution (extension activation)

**Primary Impact**: Exfiltration of high-value developer credentials (GitHub tokens, SSH keys, AWS secrets) and mass repository code theft

**Known Iocs**:
- cat.py
- com[.]user[.]kitty-monitor[.]plist
- sfrclak[.]com

**Confidence**: high

**Canonical Source**: hxxps://nx[.]dev

## Evidence Assessment
*   **confirmed:** Compromise of Nx Console extension v18.95.0 via a hijacked contributor credentials vector, active for a limited time on public registries. [Nx Advisory](https://nx.dev)
*   **confirmed:** Exfiltration of approximately 3,800 internal repositories from GitHub's internal environment following the compromise of an employee's development endpoint. [GitHub Security Advisory](https://github.com/advisories)
*   **likely:** Direct link to the TanStack `@tanstack/zod-adapter` compromise on May 11, 2026, which provided the attacker with the initial `gh` CLI OAuth token of the Nx developer. [StepSecurity Analysis](https://www.stepsecurity.io/blog)
*   **unclear:** The absolute count of non-GitHub development organizations whose workstations auto-updated to the poisoned extension during the active exposure window.

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | the malicious Nx Console extension version is present and VS Code extension activation executes the embedded Python payload or the reported process, file, or network indicators is observed. | Artifact inventory plus runtime telemetry showing VS Code extension activation executes the embedded Python payload or listed C2/process/file indicators. | Isolate affected hosts or runners, preserve artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, exposed credentials are replaced, and downstream audit modules show no suspicious follow-on use. |
| Presumed exposed | the malicious Nx Console extension version was installed, pulled, imported, built, or executed during the exposure window, but telemetry cannot prove exfiltration. | Lockfile, package cache, workflow, image pull, extension inventory, build log, or deployment record tied to the exposure window. | Rebuild from clean artifacts and rotate credentials available to the affected environment. | Credential owners confirm revocation of old material and clean artifacts are deployed. |
| Potentially exposed | The package, workflow, image, extension, or module appears in dependency or deployment records, but extension activation is not established. | Manifest, lockfile, build, deployment, or endpoint records plus a named telemetry gap. | Collect the missing execution and telemetry evidence before narrowing scope. | Every hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected version, artifact, mutable reference, or indicator appears in source, lockfiles, build outputs, deployments, package caches, or runtime telemetry. | Repository search, dependency inventory, build/deployment export, package cache query, and runtime telemetry query results. | Preserve the negative search output and keep the prevention controls active. | Search evidence covers developer endpoints, CI runners, production deployments, and package or image caches. |
| Unknown | Required inventory, build, endpoint, network, or audit telemetry is unavailable. | A gap statement naming unavailable systems, owners, and time windows. | Keep the asset in scope and make conservative rotation or rebuild decisions for high-value environments. | The missing evidence is recovered or the risk owner accepts residual uncertainty. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Dependency, workflow, extension, image, or module inventory covering developer endpoints, CI runners, and production deployments.
- Positive or negative search results for Nx Console v18.95.0.
- Execution evidence for VS Code extension activation executes the embedded Python payload.
- Process, file, DNS, proxy, firewall, or package-manager telemetry for listed indicators.
- Inventory of credentials, tokens, deployment paths, and downstream systems reachable from exposed environments.

## Timeline
- **2026-05-11T19:26:00Z** Nx contributor's development workstation is infected with the Mini Shai-Hulud worm via a poisoned `@tanstack/*` dependency update. Source: [StepSecurity](https://www.stepsecurity.io/blog)
- **2026-05-11T19:40:00Z** Mini Shai-Hulud malware harvests the contributor's GitHub CLI OAuth token and exfiltrates it to C2. Source: [StepSecurity](https://www.stepsecurity.io/blog)
- **2026-05-18T12:30:00Z** Attackers use the stolen OAuth token to log in and publish backdoored `Nx Console v18.95.0` to the VS Code Marketplace and Open VSX. Source: [Nx Advisory](https://nx.dev)
- **2026-05-18T12:45:00Z** Nx team receives immediate reports of anomalies and verifies the unauthorized release. Source: [Nx Advisory](https://nx.dev)
- **2026-05-18T12:48:00Z** VS Code Marketplace removes the malicious v18.95.0 release (18-minute exposure). Source: [Nx Advisory](https://nx.dev)
- **2026-05-18T13:09:00Z** Open VSX registry removes the malicious v18.95.0 release (39-minute exposure). Source: [Nx Advisory](https://nx.dev)
- **2026-05-18T13:15:00Z** Nx team publishes clean, hardened updates (v18.100.0) and triggers forced downstream updates. Source: [Nx Advisory](https://nx.dev)
- **2026-05-18T15:00:00Z** Official security advisory is published under tracking ID GHSA-c9j4-9m59-847w. Source: [GHSA Database](https://github.com/advisories/GHSA-c9j4-9m59-847w)
- **2026-05-19T09:00:00Z** GitHub confirms internal source code repository exfiltration stemming from an employee's compromised endpoint. Source: [GitHub Security Advisory](https://github.com/advisories)

## What Happened
On May 18, 2026, the **TeamPCP** threat group executed a direct attack against developer workstations by poisoning the popular **Nx Console** VS Code extension [Ox Security](https://ox.security). Utilizing a GitHub CLI OAuth token harvested during the earlier TanStack incident, the attackers gained administrative push permissions to the extension's publishing account [StepSecurity](https://www.stepsecurity.io/blog). They published version `v18.95.0`, which contained an obfuscated payload loader embedded inside a dangling release commit [Nx Advisory](https://nx.dev). Despite being revoked from marketplaces within 18 to 36 minutes, the poisoned extension was pulled by auto-updating VS Code instances, including one belonging to a GitHub engineer [Infosecurity Magazine](https://infosecurity-magazine.com). The backdoor instantly activated, harvested active session tokens, and allowed the threat group to steal approximately 3,800 internal GitHub repository codebases [GitHub Security Advisory](https://github.com/advisories).

## Technical Analysis

### Initial Access
Initial access was gained using the stolen GitHub CLI (`gh`) OAuth token of a legitimate Nx contributor. This token had been exfiltrated seven days prior on May 11, 2026, when the contributor installed a poisoned `@tanstack/*` package. The threat actor used this persistent session to authenticated to the Visual Studio Marketplace and Open VSX, uploading the malicious extension package. [1]

### Package or Artifact Manipulation
The attackers packaged and published a rogue extension tarball (`.vsix`) containing a malicious Python script (`cat.py`) hidden in the assets. They altered the extension's entry file to ensure that as soon as the VS Code IDE activated the extension (which occurs automatically upon opening a workspace folder containing an Nx project), the payload was triggered.

### Execution Trigger
The malware executed at IDE activation time. VS Code extensions have a lifecycle hook (`activate()`) defined in their main script. The poisoned version `18.95.0` spawned a background shell process to execute the hidden Python script (`cat.py`) without displaying any indicators or terminal windows to the user.

### Payload Behavior
Once executed, the Python backdoor (`cat.py`) initiated a multi-stage compromise:
- **Credential Theft:** It scraped developer configurations, harvesting SSH keys, AWS access profiles, HashiCorp Vault tokens, 1Password CLI session logs, and `.git-credentials` entries.
- **Persistence:** It planted an persistent LaunchAgent on macOS (`~/Library/LaunchAgents/com.user.kitty-monitor.plist`) that regularly monitored and executed the `~/.local/share/kitty/cat.py` script.
- **Process Evasion:** It ran as a daemonized Python process, utilizing the environment variable `__DAEMONIZED=1` to masquerade as system maintenance scripting.
- **Worm Detection / Dead Man's Switch:** The backdoor monitored the validity of the compromised host's primary tokens. If a token revocation was detected (suggesting discovery by security teams), the script was capable of executing a target-wipe command.

### Exfiltration / C2
**Domains**:
- sfrclak[.]com

**Ips**:

**Urls**:
- hxxps://sfrclak[.]com/api/v1/beacon

**Protocols**:
- https

**Endpoints**:
- /api/v1/beacon
- /payloads/

**Confidence**: high

The backdoor established a beaconing connection to `sfrclak[.]com` over HTTPS, exfiltrating the harvested credentials. During the GitHub employee compromise, the attackers leveraged these exfiltrated credentials to access internal servers and clone thousands of proprietary repositories. [1]

### Propagation
The malware did not contain lateral network propagation scripts, instead relying on the collected authentication tokens to manually pivot to downstream SaaS systems (such as GitHub, npm, and AWS registries) to continue publishing malicious packages or harvesting code.

### Obfuscation or Evasion
The payload file `cat.py` was lightly obfuscated using variable renaming and base64-encoded command execution. Evasion was primarily achieved by masquerading as terminal/shell configurations associated with the "Kitty" terminal emulator, exploiting common path exceptions like `~/.local/share/kitty/`.

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: vs-code-extension-marketplace,open-vsx
  - **packages**: Nx Console
  - **versions**: 18.95.0
  - **repositories**: github.com/nrwl/nx-console
  - **container_images**: 
  - **CI_CD_systems**: 
  - **developer_tools**: VS Code IDE
  - **environments**: developer workstations,corporate endpoints

**Credentials At Risk**:
- GitHub tokens
- SSH keys
- AWS/GCP secrets
- Vault configurations
- 1Password master keys

**Not Currently Known To Affect**:
- CI runners and build pipelines (unless they run interactive VS Code sessions).

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Domains
- sfrclak[.]com
- nx.dev

### Urls
- hxxps://sfrclak[.]com/api/v1/beacon
- hxxps://nx[.]dev


## Detection and Hunting

### Hunt Manifest: nx-console-extension-compromise-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Nx Console VS Code Extension Compromise?
- **Telemetry Family:** file
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-nx-console-extension-compromise-scope"))

DOMAINS = ["com.user.kitty-monitor.plist","sfrclak[.]com","nx.dev"]
URLS = ["https://sfrclak.com/api/v1/beacon","https://nx.dev"]

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

print(f"[+] Wrote scope artifacts under {OUT}")
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Sources
1. [Nx Official Incident Postmortem](https://nx.dev/blog/nx-console-extension-security-postmortem). **Role:** DIRECT_SOURCE **Impact:** Detailed timing, exposure window, compromised contributor information, and cleanup instructions.
2. [GHSA-c9j4-9m59-847w Advisory Record](https://github.com/advisories/GHSA-c9j4-9m59-847w). **Role:** DIRECT_SOURCE **Impact:** Vulnerability details and affected extension version mapping.
3. [StepSecurity Nx Console Compromise Analysis](https://www.stepsecurity.io/blog/nx-console-compromise-deep-dive). **Role:** PRIMARY_RESEARCH **Impact:** Analysis of the connection between the TanStack and Nx incidents and token theft.
4. [Ox Security Threat Report on VS Code Supply Chains](https://ox.security/resources/threat-report-vs-code-extension-supply-chains). **Role:** PRIMARY_RESEARCH **Impact:** Technical details on IDE extension vector manipulation and credential theft scripting.
5. [Infosecurity Magazine Incident Report](https://www.infosecurity-magazine.com/news/nx-console-vs-code-malicious-update/). **Role:** SECONDARY_ANALYSIS **Impact:** Documentation of the downstream GitHub repository exfiltration breach.
