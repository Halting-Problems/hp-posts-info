---
title: "Axios npm Package Compromise (UNC1069)"
date: 2026-03-31
severity: "critical"
tags:
  - npm
  - supply-chain
  - compromise
  - RAT
  - waveshaper
  - unc1069
summary: "On March 31, 2026, the popular JavaScript HTTP client Axios was compromised when attackers hijacked a lead maintainer's npm account, publishing malicious versions containing a phantom dependency to drop a cross-platform Remote Access Trojan (RAT)."
sourceCount: 5
---
## Executive Summary
On March 31, 2026, the widely used JavaScript HTTP library **Axios** was compromised through its npm publishing path [[github.com](https://github.com/advisories/GHSA-fw8c-xr5c-95f9)]. An attacker used the npm account of maintainer `jasonsaayman` to publish **`axios@1.14.1`** under the `latest` tag and **`axios@0.30.4`** under the `legacy` tag [Sources 2 and 4].

The malicious versions added the otherwise unused dependency **`plain-crypto-js@^4.2.1`**. Its `postinstall` hook ran `setup.js`, a dropper tracked by Google as **SILKBELL**, which selected Windows, macOS, or Linux payloads and deployed the **WAVESHAPER.V2** backdoor [Sources 2 and 4].

Google attributes the activity to the financially motivated North Korea-nexus cluster **UNC1069**; Microsoft attributes the same infrastructure and compromise to **Sapphire Sleet** [Sources 2 and 3]. The malicious releases were available from `2026-03-31T00:21:00Z` until approximately `03:20-03:29Z`. Any host or runner that executed an affected install should be treated as fully compromised and its reachable credentials rotated from a clean system [Sources 1-4].

## Key Facts
**Threat Type**: maintainer account compromise, malicious package, credential theft, token exfiltration

**Ecosystem**: npm

**Registry**: npm

**Affected Packages**:
- axios
- plain-crypto-js

**Malicious Versions**:
- axios@1.14.1
- axios@0.30.4
- plain-crypto-js@4.2.1

**Fixed Versions**:
- axios@1.14.0
- axios@0.30.3

**Safe Versions**:
- axios@1.14.0
- axios@0.30.3

**Exposure Window**: approximately 3 hours (2026-03-31T00:21:00Z to 2026-03-31T03:29:00Z)

**Execution Trigger**: install-time postinstall lifecycle hook

**Primary Impact**: Credential theft (GitHub PATs, cloud keys, SSH keys), Remote Access Trojan (RAT) execution, remote command execution

**Known Iocs**:
- sfrclak[.]com
- 142.11.206[.]73
- e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09
- 92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a
- 617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101
- fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf
- 6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7
- ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c
- e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff
- com[.]apple[.]act[.]mond
- wt.exe
- system.bat
- ld.py

**Confidence**: high

**Canonical Source**: https://github.com/advisories/GHSA-fw8c-xr5c-95f9

## Evidence Assessment
* **confirmed:** `axios@1.14.1`, `axios@0.30.4`, and `plain-crypto-js@4.2.1` were malicious; the transitive package executed `node setup.js` during `postinstall`; and the payload chain targeted Windows, macOS, and Linux [Sources 1-4].
* **confirmed:** Registry metadata showed the malicious Axios releases were direct CLI publishes without the SLSA provenance present on the legitimate `axios@1.14.0` release, and the publisher email changed to `ifstap@proton[.]me` [[elastic.co](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)].
* **confirmed:** Google attributes the campaign to UNC1069 and Microsoft maps it to Sapphire Sleet, both North Korea-linked tracking clusters [Sources 2 and 3].
* **unclear:** Public primary sources reviewed through June 10, 2026 do not establish how the maintainer account was initially compromised or whether a classic npm token, browser session, local credential store, or another access path was used.
* **not_observed:** Primary reporting describes npm registry manipulation rather than a malicious commit to the Axios source repository [Sources 2 and 4].

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | `axios@1.14.1`, `axios@0.30.4`, or `plain-crypto-js@4.2.1` is present and npm postinstall launches `setup.js` / SILKBELL or the reported process, file, or network indicators is observed. | Artifact inventory plus runtime telemetry showing npm postinstall launches `setup.js` / SILKBELL or listed C2/process/file indicators. | Isolate affected hosts or runners, preserve artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, exposed credentials are replaced, and downstream audit modules show no suspicious follow-on use. |
| Presumed exposed | `axios@1.14.1`, `axios@0.30.4`, or `plain-crypto-js@4.2.1` was installed, pulled, imported, built, or executed during the exposure window, but telemetry cannot prove exfiltration. | Lockfile, package cache, workflow, image pull, extension inventory, build log, or deployment record tied to the exposure window. | Rebuild from clean artifacts and rotate credentials available to the affected environment. | Credential owners confirm revocation of old material and clean artifacts are deployed. |
| Potentially exposed | The package, workflow, image, extension, or module appears in dependency or deployment records, but npm lifecycle execution is not established. | Manifest, lockfile, build, deployment, or endpoint records plus a named telemetry gap. | Collect the missing execution and telemetry evidence before narrowing scope. | Every hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected version, artifact, mutable reference, or indicator appears in source, lockfiles, build outputs, deployments, package caches, or runtime telemetry. | Repository search, dependency inventory, build/deployment export, package cache query, and runtime telemetry query results. | Preserve the negative search output and keep the prevention controls active. | Search evidence covers developer endpoints, CI runners, production deployments, and package or image caches. |
| Unknown | Required inventory, build, endpoint, network, or audit telemetry is unavailable. | A gap statement naming unavailable systems, owners, and time windows. | Keep the asset in scope and make conservative rotation or rebuild decisions for high-value environments. | The missing evidence is recovered or the risk owner accepts residual uncertainty. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Dependency, workflow, extension, image, or module inventory covering developer endpoints, CI runners, and production deployments.
- Positive or negative search results for axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1.
- Execution evidence for npm postinstall launches `setup.js` / SILKBELL.
- Process, file, DNS, proxy, firewall, or package-manager telemetry for listed indicators.
- Inventory of credentials, tokens, deployment paths, and downstream systems reachable from exposed environments.

## Timeline
- **2026-03-30T05:57:00Z:** `plain-crypto-js@4.2.0`, a clean decoy release, is published [[elastic.co](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)].
- **2026-03-30T23:59:00Z:** Malicious `plain-crypto-js@4.2.1` is published with the `postinstall` hook [[elastic.co](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)].
- **2026-03-31T00:21:00Z:** `axios@1.14.1` is published and tagged `latest` [Sources 2 and 4].
- **2026-03-31T01:00:00Z:** `axios@0.30.4` is published and tagged `legacy` [[elastic.co](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)].
- **2026-03-31T01:50:00Z:** Elastic reports filing a GitHub Security Advisory with the Axios project [Sources 4 and 5].
- **2026-03-31T03:20:00Z to 03:29:00Z:** Primary sources place the end of malicious availability in this interval [Sources 2 and 4].
- **2026-04-01:** Microsoft and Elastic publish mitigation and detection guidance [Sources 3 and 5].

## What Happened
On March 31, 2026, an attacker used the npm publishing identity associated with Axios maintainer `jasonsaayman` to release two backdoored packages. Google attributes the activity to UNC1069, while Microsoft maps it to Sapphire Sleet [Sources 2 and 3].

The malicious releases were direct CLI publishes without provenance, unlike the legitimate `axios@1.14.0` release published through GitHub Actions OIDC with SLSA provenance. This proves that the trusted publishing workflow was not used for the malicious releases, but public evidence does not establish the exact credential or session used by the attacker [[elastic.co](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)].

The backdoor was implemented as the transitive dependency `plain-crypto-js@^4.2.1`. The Axios runtime did not import it; its purpose was to trigger install-time execution through npm lifecycle scripts [Sources 3 and 4].

## Technical Analysis

### Initial Access
The attacker obtained the ability to publish as the npm maintainer account. The reviewed primary sources do not identify a confirmed phishing lure, malware family, stolen-token type, or account-recovery path. Responders should not treat any specific initial-access narrative as established.

### Package or Artifact Manipulation
The attacker published `axios@1.14.1` and `axios@0.30.4` directly to npm without provenance and changed the publisher email metadata. The packages added a dependency rather than modifying Axios application logic [[elastic.co](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)]:
**Package Json Dependency Diff**:
  - **plain-crypto-js**: ^4.2.1
`plain-crypto-js@4.2.1` was the malicious delivery package. Its earlier `4.2.0` release was clean and appears to have established registry history [[elastic.co](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all)].

### Execution Trigger
The `plain-crypto-js` manifest declared `"postinstall": "node setup.js"`. Installation with lifecycle scripts enabled therefore executed the obfuscated SILKBELL dropper without additional user interaction [Sources 2 and 4].

### Payload Behavior
The `setup.js` dropper fingerprinted Windows, macOS, or Linux and sent a POST request to `hxxp://sfrclak[.]com:8000/6202033` with a platform selector resembling `packages[.]npm[.]org/product0`, `product1`, or `product2`. The response deployed a platform-specific WAVESHAPER.V2 implementation [Sources 2, 4, and 5].

The backdoor collected host and process information, recursively enumerated files, and accepted commands for shell execution and additional payload execution. Credentials and secrets available to the compromised account or process must be treated as exposed because the actor obtained arbitrary code execution, not because every credential class was directly observed being harvested [Sources 2-4].

### Exfiltration / C2
**Domains**:
- sfrclak[.]com

**Ips**:
- 142.11.206[.]73

**Urls**:
- hxxp://sfrclak[.]com:8000/6202033

**Protocols**:
- HTTP/HTTPS
- TCP/8000

**Endpoints**:
- /6202033

**Confidence**: high

### Propagation
The package did not self-propagate as a worm. Exposure occurred when dependency resolution selected an affected Axios release during the approximately three-hour registry window. Public sources reviewed here do not establish a reliable victim count [Sources 2-4].

### Obfuscation or Evasion
The dropper deleted `setup.js` and replaced the malicious package manifest with a clean `package.md` copy. Platform artifacts included `/Library/Caches/com.apple.act.mond` on macOS, `%PROGRAMDATA%\wt.exe`, `%PROGRAMDATA%\system.bat`, and the `MicrosoftUpdate` Run key on Windows, and `/tmp/ld.py` on Linux [Sources 2, 4, and 5].

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: npm
  - **packages**: axios,plain-crypto-js
  - **versions**: axios@1.14.1,axios@0.30.4,plain-crypto-js@4.2.1
  - **repositories**: 
  - **container_images**: 
  - **CI_CD_systems**: GitHub Actions,GitLab CI,CircleCI,Jenkins
  - **developer_tools**: npm cli,yarn cli,pnpm cli
  - **environments**: developer workstations,CI runners,build pipelines,containers,production systems

**Credentials At Risk**:
- npm tokens
- GitHub tokens
- cloud credentials
- SSH keys
- environment variables

**Not Currently Known To Affect**:
- Axios source repository on GitHub (the code repository itself was not compromised or modified) [GitHub Security Advisory (GHSA-fw8c-xr5c-95f9)](https://github.com/advisories/GHSA-fw8c-xr5c-95f9).

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09
- 92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a
- 617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101
- fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf
- 6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7
- ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c
- e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff

### Domains
- system.bat
- sfrclak[.]com
- cloud[.]google[.]com
- www[.]elastic[.]co

### Urls
- hxxp://sfrclak[.]com:8000/6202033
- hxxps://cloud[.]google[.]com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package
- hxxps://www[.]elastic[.]co/security-labs/axios-supply-chain-compromise-detections
- hxxps://www[.]elastic[.]co/security-labs/axios-one-rat-to-rule-them-all
- hxxps://github[.]com/advisories/GHSA-fw8c-xr5c-95f9

### Ips
- 142[.]11[.]206[.]73


## Detection and Hunting

### Hunt Manifest: axios-npm-compromise-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Axios npm Package Compromise (UNC1069)?
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
OUT = Path(os.environ.get("OUT", "hp-axios-npm-compromise-scope"))

DOMAINS = ["com.apple.act.mond","system.bat","sfrclak[.]com","cloud.google.com","www[.]elastic[.]co","github.com"]
URLS = ["http://sfrclak.com:8000/6202033","https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package","https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections","https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all","https://github.com/advisories/GHSA-fw8c-xr5c-95f9"]
IPS = ["142[.]11[.]206[.]73"]
HASHES = ["e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09","92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a","617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101","fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf","6483c004e207137385f480909d6edecf1b699087378aa91745ecba7c3394f9d7","ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c","e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff"]

# Collect unique indicators
indicators = set()
for group in [DOMAINS, URLS, IPS, HASHES]:
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
1. [GitHub Advisory Database: Malware in axios, GHSA-fw8c-xr5c-95f9](https://github.com/advisories/GHSA-fw8c-xr5c-95f9). **Role:** DIRECT_SOURCE **Impact:** Confirms the malicious Axios versions and full-compromise response guidance.
2. [Google Threat Intelligence Group: North Korea-Nexus Threat Actor Compromises Widely Used Axios NPM Package](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package). **Role:** PRIMARY_RESEARCH **Impact:** Documents UNC1069 attribution, SILKBELL, WAVESHAPER.V2, infrastructure, commands, and the observed availability window.
3. [Microsoft Threat Intelligence: Mitigating the Axios npm supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/). **Role:** PRIMARY_RESEARCH **Impact:** Provides Sapphire Sleet attribution, Defender detections, hunting guidance, and safe-version recommendations.
4. [Elastic Security Labs: Inside the Axios supply chain compromise](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all). **Role:** PRIMARY_RESEARCH **Impact:** Documents registry provenance differences, exact publication timeline, anti-forensics, and cross-platform payload behavior.
5. [Elastic Security Labs: Axios supply chain compromise detections](https://www.elastic.co/security-labs/axios-supply-chain-compromise-detections). **Role:** PRIMARY_RESEARCH **Impact:** Provides package hashes, payload hashes, file paths, process ancestry, network selectors, and behavior detections.
