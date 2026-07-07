---
title: "intercom-client npm Mini Shai-Hulud Compromise"
date: 2026-04-30
severity: "critical"
tags:
  - npm
  - package-compromise
  - supply-chain
  - credential-theft
  - shai-hulud
summary: "Intercom says an attacker published `intercom-client@7.0.4` on April 30, 2026 using credentials from a compromised developer account. The package executed a Bun-launched credential stealer during installation and was removed within hours."
sourceCount: 5
---

## Executive Summary
On April 30, 2026, `intercom-client@7.0.4`, the official Node.js SDK for Intercom, was published to npm with a malicious `preinstall` hook and two undocumented files: `setup.mjs` and `router_runtime.js` [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Socket](https://socket.dev/blog/intercom-s-npm-package-compromised-in-supply-chain-attack). The Intercom security advisory says credentials obtained from a compromised developer account were used, the artifact was not produced by Intercom's build pipeline, and the malicious version remained available for approximately two hours, from 15:00 to 17:00 UTC [Intercom advisory](https://github.com/intercom/intercom-node/security/advisories/GHSA-54pg-9963-v8vg).

The malicious release preserved the legitimate SDK while adding `"preinstall": "node setup.mjs"` to `package.json`. `setup.mjs` bootstrapped Bun and executed an 11,731,860-byte obfuscated JavaScript payload, `router_runtime.js`, designed to harvest GitHub, npm, cloud, SSH, environment-file, and local configuration secrets [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Intercom advisory](https://github.com/intercom/intercom-node/security/advisories/GHSA-54pg-9963-v8vg). Intercom closed the incident on June 8 after removing the malicious npm and PHP versions, rotating credentials, hardening its environment, and finding no evidence of unauthorized access to Intercom accounts or customer data [Intercom status](https://www.intercomstatus.com/us-hosting/incidents/01KQFN6VS6ARP1XBR1K1SBYY59).

## Key Facts
**Threat Type**: npm package compromise, preinstall credential stealer

**Ecosystem**: npm, javascript

**Registry**: npm

**Affected Packages**:
- intercom-client

**Malicious Versions**:
- 7.0.4

**Known Good Versions**:
- 7.0.3

**Execution Trigger**: npm install lifecycle preinstall hook

**Primary Impact**: GitHub, npm, AWS, GCP, Azure, and CI/CD secret theft

**Campaign Context**: Mini Shai-Hulud wave

**Known Iocs**:
- setup.mjs
- router_runtime.js
- "preinstall": "node setup.mjs"
- api[.]github[.]com/user
- private repository creation under victim GitHub account
- fe64699649591948d6f960705caac86fe99600bf76e3eae29b4517705a58f0e2
- 5ae8b2343e97cc3b2c945ec34318b63f27fa2db1e3d8fbaa78c298aa63db52ed

**Confidence**: high

**Canonical Source**: https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked

**Registry Exposure Window**: 2026-04-30T15:00:00Z/2026-04-30T17:00:00Z

**Vendor Status**: resolved 2026-06-08

## Evidence Assessment
* **confirmed:** `intercom-client@7.0.4` introduced a `preinstall` hook that was absent from prior releases [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Socket](https://socket.dev/blog/intercom-s-npm-package-compromised-in-supply-chain-attack).
* **confirmed:** The malicious release added `setup.mjs` and `router_runtime.js`, which did not exist in prior releases or the upstream GitHub repository [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Socket](https://socket.dev/blog/intercom-s-npm-package-compromised-in-supply-chain-attack).
* **confirmed:** The package unpacked size increased from roughly 6 MB to 17.8 MB, with the payload file accounting for the bulk of the anomaly [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked).
* **confirmed:** Registry metadata for `7.0.3` contains SLSA provenance while StepSecurity's preserved `7.0.4` metadata did not; Intercom says `7.0.4` was not produced by its build pipeline [npm registry](https://registry.npmjs.org/intercom-client) [Intercom advisory](https://github.com/intercom/intercom-node/security/advisories/GHSA-54pg-9963-v8vg).
* **confirmed:** Intercom attributes the publish to credentials obtained from a compromised developer account and identifies 15:00-17:00 UTC on April 30 as the registry exposure window [Intercom advisory](https://github.com/intercom/intercom-node/security/advisories/GHSA-54pg-9963-v8vg).
* **unclear:** Public evidence does not explain how a publish attributed by npm metadata to the configured GitHub Actions OIDC identity occurred outside Intercom's legitimate build pipeline.

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | `intercom-client@7.0.4` is present and npm preinstall launches Bun-backed loader files or the reported process, file, or network indicators is observed. | Artifact inventory plus runtime telemetry showing npm preinstall launches Bun-backed loader files or listed C2/process/file indicators. | Isolate affected hosts or runners, preserve artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, exposed credentials are replaced, and downstream audit modules show no suspicious follow-on use. |
| Presumed exposed | `intercom-client@7.0.4` was installed, pulled, imported, built, or executed during the exposure window, but telemetry cannot prove exfiltration. | Lockfile, package cache, workflow, image pull, extension inventory, build log, or deployment record tied to the exposure window. | Rebuild from clean artifacts and rotate credentials available to the affected environment. | Credential owners confirm revocation of old material and clean artifacts are deployed. |
| Potentially exposed | The package, workflow, image, extension, or module appears in dependency or deployment records, but npm lifecycle execution is not established. | Manifest, lockfile, build, deployment, or endpoint records plus a named telemetry gap. | Collect the missing execution and telemetry evidence before narrowing scope. | Every hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected version, artifact, mutable reference, or indicator appears in source, lockfiles, build outputs, deployments, package caches, or runtime telemetry. | Repository search, dependency inventory, build/deployment export, package cache query, and runtime telemetry query results. | Preserve the negative search output and keep the prevention controls active. | Search evidence covers developer endpoints, CI runners, production deployments, and package or image caches. |
| Unknown | Required inventory, build, endpoint, network, or audit telemetry is unavailable. | A gap statement naming unavailable systems, owners, and time windows. | Keep the asset in scope and make conservative rotation or rebuild decisions for high-value environments. | The missing evidence is recovered or the risk owner accepts residual uncertainty. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Dependency, workflow, extension, image, or module inventory covering developer endpoints, CI runners, and production deployments.
- Positive or negative search results for intercom-client@7.0.4.
- Execution evidence for npm preinstall launches Bun-backed loader files.
- Process, file, DNS, proxy, firewall, or package-manager telemetry for listed indicators.
- Inventory of credentials, tokens, deployment paths, and downstream systems reachable from exposed environments.

## Timeline
- **2026-04-30T14:41:04Z:** npm registry metadata records publication of `intercom-client@7.0.4` [npm registry](https://registry.npmjs.org/intercom-client).
- **2026-04-30T15:00:00Z to 2026-04-30T17:00:00Z:** Intercom's advisory identifies the approximately two-hour availability window for the malicious version [Intercom advisory](https://github.com/intercom/intercom-node/security/advisories/GHSA-54pg-9963-v8vg).
- **2026-05-01T09:35:35Z:** Intercom publishes `GHSA-54pg-9963-v8vg`, classifying the issue as critical and `CWE-506: Embedded Malicious Code` [Intercom advisory](https://github.com/intercom/intercom-node/security/advisories/GHSA-54pg-9963-v8vg).
- **2026-06-08T11:53:00Z:** Intercom closes the incident, reports completed credential rotation and hardening, and says it found no evidence of unauthorized access to customer data or Intercom accounts [Intercom status](https://www.intercomstatus.com/us-hosting/incidents/01KQFN6VS6ARP1XBR1K1SBYY59).

## What Happened
Attackers published a malicious patch version of the official `intercom-client` package. The SDK remained functional, but package installation triggered `setup.mjs` before normal install completion through npm's `preinstall` lifecycle hook [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Socket](https://socket.dev/blog/intercom-s-npm-package-compromised-in-supply-chain-attack).

The loader acquired or reused Bun and executed `router_runtime.js`, a single-line obfuscated payload of 11,731,860 bytes [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked). Exfiltration used the victim's own GitHub access: the payload authenticated to `api[.]github[.]com/user`, created a private repository, encrypted harvested secrets, and committed them there [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked).

## Technical Analysis
### Initial Access
npm metadata associated the publish with Intercom's configured GitHub Actions OIDC publisher identity, but the artifact lacked the SLSA attestations present in `7.0.3` [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [npm registry](https://registry.npmjs.org/intercom-client). Intercom's advisory adds that the malicious artifact was published with credentials obtained from a compromised developer account and was not produced by the legitimate build pipeline [Intercom advisory](https://github.com/intercom/intercom-node/security/advisories/GHSA-54pg-9963-v8vg). The exact bridge between those facts is not public.

### Package or Artifact Manipulation
The malicious diff centered on one lifecycle hook and two new files: `"preinstall": "node setup.mjs"`, `setup.mjs`, and `router_runtime.js` [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) [Socket](https://socket.dev/blog/intercom-s-npm-package-compromised-in-supply-chain-attack). The package size tripled in a single patch bump, a reliable anomaly for an SDK with no historical install hook [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked).

### Payload Behavior
The stealer targets GitHub, npm, cloud, Kubernetes, Vault, SSH, environment-file, local configuration, and metadata-service secrets [Intercom advisory](https://github.com/intercom/intercom-node/security/advisories/GHSA-54pg-9963-v8vg) [Socket](https://socket.dev/blog/intercom-s-npm-package-compromised-in-supply-chain-attack). StepSecurity reports token regex patterns for GitHub and npm tokens and a GitHub-based exfiltration path that creates private repositories under victim accounts [StepSecurity](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked). [1]

## Affected Assets and Blast Radius

**Affected Assets**:
  - **ecosystems**: npm,JavaScript
  - **registries**: npmjs.com
  - **packages**: intercom-client
  - **versions**: intercom-client@7.0.4
  - **repositories**: intercom/intercom-node
  - **ci_cd_systems**: GitHub Actions,npm publishing pipeline
  - **container_images**: 
  - **developer_tools**: Node.js package managers,CI runners

**Credentials At Risk**:
- GitHub tokens
- npm tokens
- cloud credentials
- CI/CD secrets
- environment variables
- package registry credentials

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
- 5f748fbc89cde66abefa826439c765a0081a027792e9da8d80fbf23571311622
- fe64699649591948d6f960705caac86fe99600bf76e3eae29b4517705a58f0e2
- 5ae8b2343e97cc3b2c945ec34318b63f27fa2db1e3d8fbaa78c298aa63db52ed

### Domains
- api[.]github[.]com
- metadata.google.internal

### Urls
- hxxps://github[.]com/oven-sh/bun/releases/download/bun-v1[.]3[.]13/

### Ips
- 169[.]254[.]169[.]254


## Detection and Hunting

### Hunt Manifest: intercom-client-npm-shai-hulud-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with intercom-client npm Mini Shai-Hulud Compromise?
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
OUT = Path(os.environ.get("OUT", "hp-intercom-client-npm-shai-hulud-scope"))

DOMAINS = ["setup.mjs","api.github.com","metadata.google.internal","github.com"]
URLS = ["https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/"]
IPS = ["169[.]254[.]169[.]254"]
HASHES = ["5f748fbc89cde66abefa826439c765a0081a027792e9da8d80fbf23571311622","fe64699649591948d6f960705caac86fe99600bf76e3eae29b4517705a58f0e2","5ae8b2343e97cc3b2c945ec34318b63f27fa2db1e3d8fbaa78c298aa63db52ed"]

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

## Remediation and Closure

### Containment

1. Isolate developer systems, CI runners, containers, and build environments that installed `intercom-client@7.0.4` during the 2026-04-30 exposure window.
2. Preserve `setup.mjs`, `router_runtime.js`, package-manager logs, lockfiles, process telemetry, and network records before cleanup.
3. Revoke GitHub, npm, cloud, Kubernetes, Vault, SSH, and deployment sessions reachable from the affected environment.

### Eradication

1. Rebuild affected environments from `intercom-client@7.0.3` or another vendor-confirmed safe version.
2. Remove internal cache entries and build artifacts matching the malicious tarball or file hashes.
3. Delete unauthorized GitHub exfiltration repositories only after preserving repository metadata, audit logs, commits, and access records.

### Recovery

1. Reissue exposed secrets from a clean administrative system and update dependent CI/CD and deployment systems.
2. Require provenance verification and reject unexpected lifecycle hooks for future `intercom-client` updates.
3. Confirm that current npm resolution returns the safe `7.0.3` dist-tag and no lockfile resolves to `7.0.4`.

### Closure Gates

- No developer endpoint, runner, container, lockfile, cache, or deployment contains `intercom-client@7.0.4`.
- The three listed SHA-256 hashes are absent from retained environments except preserved evidence.
- Every secret accessible between 2026-04-30T14:41:04Z and 2026-04-30T17:00:00Z has been dispositioned.
- GitHub, registry, cloud, and deployment audits show no unexplained follow-on activity.

## Sources
1. [Intercom security advisory: GHSA-54pg-9963-v8vg](https://github.com/intercom/intercom-node/security/advisories/GHSA-54pg-9963-v8vg) - **Role:** DIRECT_SOURCE - **Impact:** Compromised-account statement, exposure window, affected version, impact, and response guidance.
2. [Intercom status: compromised intercom-client and intercom-php versions](https://www.intercomstatus.com/us-hosting/incidents/01KQFN6VS6ARP1XBR1K1SBYY59) - **Role:** DIRECT_SOURCE - **Impact:** Removal, remediation, June 8 resolution, and no-evidence-of-customer-access statement.
3. [npm registry metadata: intercom-client](https://registry.npmjs.org/intercom-client) - **Role:** DIRECT_SOURCE - **Impact:** Publication timestamp, current dist-tag, safe-version provenance, and removal of `7.0.4`.
4. [StepSecurity: Shai-Hulud Worm Pivots to Multi-Cloud](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked) - **Role:** PRIMARY_RESEARCH - **Impact:** Artifact diff, hashes, package size, provenance anomaly, credential targets, and GitHub exfiltration behavior.
5. [Socket: Intercom's npm Package Compromised](https://socket.dev/blog/intercom-s-npm-package-compromised-in-supply-chain-attack) - **Role:** PRIMARY_RESEARCH - **Impact:** Independent artifact analysis, file hashes, Bun loader, and payload behavior.
