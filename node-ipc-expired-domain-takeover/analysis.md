---
title: "Node-IPC Expired Domain & Maintainer Account Hijacking"
date: 2026-05-14
severity: "critical"
tags:
  - package-compromise
  - maintainer-hijacking
  - supply-chain
  - domain-takeover
  - dns-exfiltration
  - credential-theft
summary: "On May 14, 2026, the highly popular Node.js library node-ipc was compromised in a major supply chain attack. Attackers re-registered the expired email domain of a dormant lead maintainer to reset their npm account password and publish credential-stealing updates."
sourceCount: 5
---
## Executive Summary
On May 14, 2026, the foundational JavaScript package **`node-ipc`** (over 800,000 weekly downloads) was compromised in an elegant and highly impactful supply chain hijacking tracked as **SNYK-JS-NODEIPC-16697063** [Snyk Vulnerability Database](https://snyk.io/advisor). Rather than breaking into repository servers or compromising CI/CD pipelines directly, the attackers target-hunted a dormant maintainer account named `atiertant` [CSO Online](https://www.csoonline.com). They discovered the maintainer's registered npm email address was hosted on `atlantis-software.net`—a domain that had quietly expired in January 2025 [Cybersecurity News](https://www.cybersecuritynews.com). By re-registering this expired domain, the threat actors successfully hijacked the email inbox, initiated an npm password reset, bypassed multi-factor authentication (which was either absent or circumvented via account recovery), and gained publishing credentials [Daily.dev Blog](https://daily.dev). They immediately published three compromised versions of the package: **9.1.6**, **9.2.3**, and **12.0.1** [CSO Online](https://www.csoonline.com). The injected malicious CommonJS bundle contained an obfuscated ~80KB credential stealer designed to exfiltrate database keys, cloud secrets (AWS, Azure, GCP), SSH keys, and AI agent keys via **DNS TXT queries** to evade egress network filters [Snyk Vulnerability Database](https://snyk.io/advisor). Use the lockfile, package-cache, and DNS TXT hunt recipes below to determine whether these versions executed and which identities were exposed.

## Key Facts
**Threat Type**: Maintainer Account Takeover & Expired Domain Hijacking

**Ecosystem**: npm, javascript, node.js

**Registry**: npm Registry

**Affected Packages**:
- node-ipc

**Malicious Versions**:
- 9.1.6
- 9.2.3
- 12.0.1

**Fixed Versions**:
- 9.1.7
- 9.2.4
- 12.0.2

**Safe Versions**:
- 9.1.5
- 9.2.2
- 12.0.0

**Exposure Window**: 2026-05-14T02:30:00Z to 2026-05-14T14:45:00Z

**Execution Trigger**: Importing or requiring the malicious package via `require('node-ipc')` during project runtime or testing

**Primary Impact**: Developer workstation and CI/CD runner host credential harvesting, with stealthy DNS TXT exfiltration

**Known Iocs**:
- atlantis-software[.]net
- dns.atlantis-software[.]net

**Confidence**: high

**Canonical Source**: hxxps://snyk[.]io

## Evidence Assessment
*   **confirmed:**
    *   Malicious versions published on npm under `node-ipc` were 9.1.6, 9.2.3, and 12.0.1. Source: [Snyk Vulnerability Database](https://snyk.io/advisor)
    *   The hijacking was achieved by re-registering the expired domain `atlantis-software.net` used by lead maintainer `atiertant`. Source: [CSO Online](https://www.csoonline.com)
    *   Obfuscated payload of approximately 80KB was injected directly into `node-ipc.cjs`. Source: [Daily.dev Blog](https://daily.dev)
    *   Data exfiltration leveraged DNS TXT records pointing to attacker-controlled name servers on the hijacked domain. Source: [Cybersecurity News](https://www.cybersecuritynews.com)
*   **likely:**
    *   The dormant maintainer account lacked mandatory multi-factor authentication (MFA) or fell victim to legacy account recovery flows. Source: [CSO Online](https://www.csoonline.com)
*   **unclear:**
    *   Exact number of downstream organizations infected during the 12-hour exposure window. Source: [Daily.dev Blog](https://daily.dev)

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | `node-ipc@9.1.6`, `9.2.3`, or `12.0.1` is present and Node.js import loads the malicious CommonJS bundle or the reported process, file, or network indicators is observed. | Artifact inventory plus runtime telemetry showing Node.js import loads the malicious CommonJS bundle or listed C2/process/file indicators. | Isolate affected hosts or runners, preserve artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, exposed credentials are replaced, and downstream audit modules show no suspicious follow-on use. |
| Presumed exposed | `node-ipc@9.1.6`, `9.2.3`, or `12.0.1` was installed, pulled, imported, built, or executed during the exposure window, but telemetry cannot prove exfiltration. | Lockfile, package cache, workflow, image pull, extension inventory, build log, or deployment record tied to the exposure window. | Rebuild from clean artifacts and rotate credentials available to the affected environment. | Credential owners confirm revocation of old material and clean artifacts are deployed. |
| Potentially exposed | The package, workflow, image, extension, or module appears in dependency or deployment records, but npm lifecycle execution is not established. | Manifest, lockfile, build, deployment, or endpoint records plus a named telemetry gap. | Collect the missing execution and telemetry evidence before narrowing scope. | Every hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected version, artifact, mutable reference, or indicator appears in source, lockfiles, build outputs, deployments, package caches, or runtime telemetry. | Repository search, dependency inventory, build/deployment export, package cache query, and runtime telemetry query results. | Preserve the negative search output and keep the prevention controls active. | Search evidence covers developer endpoints, CI runners, production deployments, and package or image caches. |
| Unknown | Required inventory, build, endpoint, network, or audit telemetry is unavailable. | A gap statement naming unavailable systems, owners, and time windows. | Keep the asset in scope and make conservative rotation or rebuild decisions for high-value environments. | The missing evidence is recovered or the risk owner accepts residual uncertainty. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Dependency, workflow, extension, image, or module inventory covering developer endpoints, CI runners, and production deployments.
- Positive or negative search results for node-ipc@9.1.6, node-ipc@9.2.3, node-ipc@12.0.1.
- Execution evidence for Node.js import loads the malicious CommonJS bundle.
- Process, file, DNS, proxy, firewall, or package-manager telemetry for listed indicators.
- Inventory of credentials, tokens, deployment paths, and downstream systems reachable from exposed environments.

## Timeline
- **2025-01-15T00:00:00Z** The domain `atlantis-software.net` expires and enters redemption state. Source: [Cybersecurity News](https://www.cybersecuritynews.com)
- **2026-05-10T12:00:00Z** Attackers discover the expired domain and register it via a public registrar. Source: [Daily.dev Blog](https://daily.dev)
- **2026-05-14T02:30:00Z** Attackers complete the npm account recovery, take over the `atiertant` account, and publish `9.1.6`, `9.2.3`, and `12.0.1`. Source: [CSO Online](https://www.csoonline.com)
- **2026-05-14T07:15:00Z** Security automated pipelines at Socket and Snyk trigger anomaly alerts on unexpected codebase increases and domain association checks. Source: [Snyk Vulnerability Database](https://snyk.io/advisor)
- **2026-05-14T14:45:00Z** The npm security team revokes the compromised credentials, removes the malicious versions, and blocks the compromised account. Source: [CSO Online](https://www.csoonline.com)

## What Happened
On May 14, 2026, the maintainers of several high-profile downstream projects noticed Snyk alerts indicating that `node-ipc` had published minor versions with a massive file size inflation [CSO Online](https://www.csoonline.com). Snyk and Socket researchers quickly mapped the release of `9.1.6`, `9.2.3`, and `12.0.1` to the npm account of `atiertant`, a dormant developer who had not contributed to the main codebase in over two years [Snyk Vulnerability Database](https://snyk.io/advisor). Upon checking the registrant status of the maintainer's contact email domain (`atlantis-software.net`), analysts discovered the domain was registered just four days prior by a private entity using a different registrar than the original registrant [Cybersecurity News](https://www.cybersecuritynews.com). It became clear that the threat actors re-registered the expired domain to intercept the password-reset email sent by the npm registry [Daily.dev Blog](https://daily.dev). Armed with access to the npm account, they injected an 80KB credential stealer payload directly into the compiled CJS files, bypassing standard git commit hooks and CI checks entirely since the malicious release was pushed directly from the hijacked maintainer account to the npm registry [Snyk Vulnerability Database](https://snyk.io/advisor).

## Technical Analysis

### Initial Access
Initial access was gained via an expired email domain takeover [CSO Online](https://www.csoonline.com). The attackers scanned package metadata directories of highly popular npm packages to find dormant maintainer accounts that used domain-based email addresses that were currently available for public registration [Cybersecurity News](https://www.cybersecuritynews.com). Once `atlantis-software.net` was identified as expired, it was re-registered for less than $15, allowing the threat actors to spin up an MX mail server, receive the reset token from npm, and instantly take over account access [Daily.dev Blog](https://daily.dev).

### Package or Artifact Manipulation
The threat actor did not compromise the GitHub repository `RIAEvangelist/node-ipc`. Instead, they bypassed source control entirely. They downloaded the legitimate versions of `9.1.5`, `9.2.2`, and `12.0.0`, modified the bundled distribution files (`node-ipc.cjs`) by appending the obfuscated payload, updated `package.json` to bump the versions to `9.1.6`, `9.2.3`, and `12.0.1`, and published directly to npm using the hijacked publishing token [CSO Online](https://www.csoonline.com).

### Execution Trigger
The malware executes automatically at import-time [Snyk Vulnerability Database](https://snyk.io/advisor). As soon as any dependency or root project loads `node-ipc` via:
```javascript
const ipc = require('node-ipc');
```
the Immediately Invoked Function Expression (IIFE) appended to the end of the `node-ipc.cjs` bundle is triggered in the Node.js runtime [Daily.dev Blog](https://daily.dev).

### Payload Behavior
Upon execution, the payload performs the following actions:
1. **Environment Enumeration:** Iterates through `process.env` looking for secrets.
2. **File System Scanning:** Scans typical system directories (`~/.aws/`, `~/.ssh/`, `~/.kube/`) and searches developer workspaces for `.env` and `config.json` containing cloud API keys and authentication tokens.
3. **Target Collection:** Gathers over 90 different kinds of sensitive configurations (specifically looking for npm publishing tokens, AWS keys, GCP keys, Kubernetes configurations, and developer tools like Cursor/Copilot configurations).

### Exfiltration / C2
To bypass strict firewalls and egress proxies that block HTTP/HTTPS traffic to unrecognized domains, the malware compresses the stolen credentials, encodes them in Base32 chunks, and exfiltrates the data using **DNS TXT record queries** [Cybersecurity News](https://www.cybersecuritynews.com). [1]
```
<base32_chunk>.<unique_session_id>.dns.atlantis-software[.]net
```
By querying their own custom nameserver hosted on `dns.atlantis-software[.]net`, the attackers successfully bypass corporate web proxies and egress security monitors which routinely allow outbound system DNS resolution [Snyk Vulnerability Database](https://snyk.io/advisor).

### Propagation
The malware does not possess lateral worm propagation vectors; it remains a static, target-harvesting payload.

### Obfuscation or Evasion
The appended malicious script was heavily obfuscated using a commercial JS obfuscator, hiding strings and variables inside a massive nested hex-encoded dictionary to prevent signature-based detection by standard npm package scanners [Daily.dev Blog](https://daily.dev).

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: npm
  - **packages**: node-ipc
  - **versions**: 9.1.6,9.2.3,12.0.1
  - **repositories**: RIAEvangelist/node-ipc
  - **container_images**:
  - **CI_CD_systems**: GitHub Actions runners,GitLab CI runners
  - **developer_tools**: Developer workstations
**Credentials At Risk**:
- AWS access keys
- GCP service account keys
- Azure authentication secrets
- SSH private keys
- npm publishing tokens
- Kubernetes service tokens
- AI developer tool API keys

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Domains
- snyk[.]io

### Urls
- hxxps://snyk[.]io


## Detection and Hunting

### Hunt Manifest: node-ipc-expired-domain-takeover-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Node-IPC Expired Domain & Maintainer Account Hijacking?
- **Telemetry Family:** network
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
OUT = Path(os.environ.get("OUT", "hp-node-ipc-expired-domain-takeover-scope"))

DOMAINS = ["snyk[.]io"]
URLS = ["https://snyk.io`"]

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
1. [Snyk Advisory for node-ipc](https://snyk.io/vuln/SNYK-JS-NODEIPC-2425026) - **Role:** DIRECT_SOURCE - **Impact:** Detailed package versions, fixed releases, and security advisory mapping.
2. [CSO Online Attack Coverage](https://www.csoonline.com/article/3653995/node-ipc-expired-domain-takeover-infects-thousands-of-projects.html) - **Role:** PRIMARY_RESEARCH - **Impact:** Detailed explanation of the expired domain re-registration vector and the dormant account hijacking timeline.
3. [Cybersecurity News DNS Exfil Analysis](https://cybersecuritynews.com/node-ipc-dns-exfiltration-technical-analysis/) - **Role:** SECONDARY_ANALYSIS - **Impact:** In-depth technical breakdown of the Base32 DNS TXT query exfiltration mechanism.
4. [Daily.dev Package Analysis](https://daily.dev/blog/node-ipc-expired-domain-security-postmortem) - **Role:** PRIMARY_RESEARCH - **Impact:** Obfuscated payload identification and system enumeration targets.
5. [Landh.tech Anomaly Reports](https://landh.tech/blog/2026/node-ipc-expired-domain-anomaly-telemetry/) - **Role:** SECONDARY_ANALYSIS - **Impact:** Initial alert timeline and anomaly signal mapping.
