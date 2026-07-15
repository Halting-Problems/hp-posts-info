---
title: "Bitwarden CLI npm 2026.4.0 Credential Stealer"
date: 2026-04-22
severity: "critical"
tags:
  - npm
  - supply-chain
  - bitwarden
  - github-actions
  - credential-theft
  - ci-cd
summary: "Bitwarden confirmed that @bitwarden/cli@2026.4.0 was maliciously distributed through the npm CLI delivery path for a short April 22, 2026 window. CVE-2026-42994 tracks the incident; artifact analysis tied the package to bw_setup.js, bw1.js, Bun bootstrap, credential theft, and GitHub fallback channels."
sourceCount: 5
---

## Executive Summary
Bitwarden confirmed a malicious npm release of `@bitwarden/cli@2026.4.0` in the CLI npm delivery path on April 22, 2026. Bitwarden's public statement narrows affected users to npm CLI installs during the vendor-stated window of 5:57 PM to 7:30 PM ET on April 22, 2026, assigns **CVE-2026-42994**, and states that vault data, production data, and production systems were not found to be compromised [Sources 1 and 5].

JFrog analyzed the malicious package and found that it rewired `preinstall` and the `bw` binary entrypoint to `bw_setup.js`, which bootstrapped Bun `1.3.13` and ran `bw1.js`. The payload targeted developer and CI credentials, exfiltrated to `audit[.]checkmarx[.]cx/v1/telemetry`, resolved that domain to `94.154.172[.]43`, and used GitHub commit search and repository creation as fallback transport [[research.jfrog.com](https://research.jfrog.com/post/bitwarden-cli-hijack/)]. Socket independently tracked the same package/version, endpoint, IP, lock file, and GitHub artifact/workflow abuse patterns [[socket.dev](https://socket.dev/blog/bitwarden-cli-compromised)].

The npm registry metadata still records a `2026.4.0` timestamp even though the removed version is absent from the current versions list. Use `2026-04-22T21:22:59Z` to start collection and `2026-04-22T23:30:00Z` as the initial end bound; classify exposure by exact package/version plus execution evidence, not by generic Bitwarden usage [[registry.npmjs.org](https://registry.npmjs.org/@bitwarden%2fcli)].

## Key Facts
**Event Type**: legitimate npm package delivery compromise

**Cve**: CVE-2026-42994

**Ecosystem**: npm

**Package**:
  - **name**: @bitwarden/cli
  - **malicious_version**: 2026.4.0
  - **clean_replacement_versions**: 2026.4.1

**Collection Window Utc**:
  - **start**: 2026-04-22T21:22:59Z
  - **vendor_affected_start**: 2026-04-22T21:57:00Z
  - **vendor_affected_end**: 2026-04-22T23:30:00Z

**Execution Triggers**:
- npm preinstall runs bw_setup.js
- bw binary entrypoint points to bw_setup.js

**Payload Files**:
- bw_setup.js
- bw1.js

**Payload Hashes Sha256**:
  - **bw_setup_js**: 18f784b3bc9a0bcdcb1a8d7f51bc5f54323fc40cbd874119354ab609bef6e4cb
  - **bw1_js**: 8605e365edf11160aad517c7d79a3b26b62290e5072ef97b102a01ddbb343f14
  - **tampered_root_metadata**: 167ce57ef59a32a6a0ef4137785828077879092d7f83ddbc1755d6e69116e0ad

**Network Iocs**:
- audit[.]checkmarx[.]cx
- 94.154.172[.]43
- hxxps://audit[.]checkmarx[.]cx/v1/telemetry

**Github Iocs**:
- LongLiveTheResistanceAgainstMachines
- beautifulcastle
- Shai-Hulud: The Third Coming

**Runtime Iocs**:
- github.com/oven-sh/bun/releases/download/bun-v1.3.13
- bun-v1.3.13

**Credentials At Risk**:
- GitHub CLI tokens and PATs
- npm tokens
- SSH keys
- AWS credentials
- GCP credentials
- Azure credentials
- GitHub Actions secrets reachable through stolen tokens
- AI and MCP tool configuration files

## Evidence Assessment
* **confirmed:** Bitwarden publicly confirmed malicious distribution of `@bitwarden/cli@2026.4.0` through npm, assigned CVE-2026-42994, and limited the affected population to npm CLI users in the April 22, 2026 window [Sources 1 and 5].
* **confirmed:** JFrog identified `bw_setup.js`, `bw1.js`, the `preinstall` and `bin.bw` rewiring, Bun `1.3.13`, `audit[.]checkmarx[.]cx/v1/telemetry`, `94.154.172[.]43`, the GitHub fallback markers, and SHA-256 hashes for the loader, payload, and tampered metadata [[research.jfrog.com](https://research.jfrog.com/post/bitwarden-cli-hijack/)].
* **confirmed:** Socket reported the same package/version and called out `audit[.]checkmarx[.]cx`, `94.154.172[.]43`, `/tmp/tmp.987654321.lock`, package update artifacts, Bun execution, and GitHub Actions artifact/workflow abuse patterns [[socket.dev](https://socket.dev/blog/bitwarden-cli-compromised)].
* **unclear:** Public sources do not prove which third-party action, token path, or repository state produced the malicious npm package. Treat CI/CD compromise mechanism claims beyond the observed package behavior as unresolved unless new vendor evidence appears.
* **not_observed:** Bitwarden reported no evidence of end-user vault data access, production data compromise, or production system compromise [[community.bitwarden.com](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)].

## Impact Determination
| Classification | Criteria | Evidence to collect | Handling decision |
| --- | --- | --- | --- |
| Confirmed compromise | `@bitwarden/cli@2026.4.0` executed and any payload, network, GitHub fallback, or credential access indicator appears. | npm install output, lockfile/package cache, `bw_setup.js`, `bw1.js`, Bun `1.3.13`, `audit[.]checkmarx[.]cx`, `94.154.172[.]43`, `LongLiveTheResistanceAgainstMachines`, `beautifulcastle`, GitHub repo/artifact creation evidence. | Isolate the host or runner, preserve package/cache/process/network evidence, revoke credentials present on that environment, and run the downstream audits below. |
| Presumed exposed | `@bitwarden/cli@2026.4.0` was installed or pulled on a developer host, container build, or CI job, but runtime/network telemetry is missing. | Package manager cache, `package-lock.json`, npm registry proxy entries, CI job logs, image layer history, endpoint inventory. | Treat credentials reachable from that process as exposed unless negative execution evidence is complete. |
| Potentially exposed | `@bitwarden/cli` appears in dependency manifests or install scripts and the resolved version during the April 22 window is unknown. | Dependency manifests, historical lockfiles, package proxy records, CI log exports, build image SBOMs. | Collect resolver/version evidence until the asset moves to confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | Evidence shows no `@bitwarden/cli@2026.4.0` tarball, install, cache entry, image layer, process, or network selector in scope. | Negative repository search, package proxy query, CI job export, endpoint search, and image/cache inventory. | Keep the negative evidence with the case record and close this event for the asset. |
| Unknown | Required package, CI, endpoint, proxy, or registry telemetry is unavailable for the April 22 collection window. | A named telemetry gap with owner, system, and retention status. | Keep high-value developer/CI assets in scope and decide credential revocation based on reachable secret inventory. |

### Minimum Evidence To Collect
**Package Evidence**:
- @bitwarden/cli@2026.4.0 in package-lock.json, yarn.lock, pnpm-lock.yaml, npm-shrinkwrap.json, npm cache, or package proxy records
- npm registry metadata showing 2026.4.0 pulled by an internal cache or CI job

**Execution Evidence**:
- bw_setup.js
- bw1.js
- bun-v1.3.13
- /tmp/tmp.987654321.lock

**Network Evidence**:
- audit[.]checkmarx[.]cx
- 94.154.172[.]43
- hxxps://audit[.]checkmarx[.]cx/v1/telemetry

**Github Evidence**:
- LongLiveTheResistanceAgainstMachines
- beautifulcastle
- Shai-Hulud: The Third Coming
- unexpected GitHub Actions workflow, artifact, branch, or repository creation from an exposed token

## Timeline
* **2026-04-22T21:22:59Z:** npm registry metadata records `@bitwarden/cli@2026.4.0` in the package time map [[registry.npmjs.org](https://registry.npmjs.org/@bitwarden%2fcli)].
* **2026-04-22T21:57:00Z:** Bitwarden's affected-window statement starts at 5:57 PM ET [[community.bitwarden.com](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)].
* **2026-04-22T23:30:00Z:** Bitwarden states the malicious npm delivery window ended at 7:30 PM ET [[community.bitwarden.com](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)].
* **2026-04-23:** Bitwarden published the public notice and directed affected npm CLI users to uninstall `@bitwarden/cli`, clear npm cache, disable install scripts during cleanup, and install `2026.4.1` [[community.bitwarden.com](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)].
* **2026-04-23:** JFrog published artifact-level analysis of `bw_setup.js`, `bw1.js`, the primary exfiltration URL, fallback GitHub paths, hashes, and targeted local paths [[research.jfrog.com](https://research.jfrog.com/post/bitwarden-cli-hijack/)].
* **2026-04-23:** Socket published independent analysis of the same package/version and overlapping IOCs [[socket.dev](https://socket.dev/blog/bitwarden-cli-compromised)].
* **By 2026-05-10:** Bitwarden's updated notice states its review found no additional affected products or environments and records CVE-2026-42994 [[community.bitwarden.com](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)].

## What Happened
The malicious npm package kept Bitwarden CLI branding but changed the package execution path. JFrog observed a `preinstall` script of `node bw_setup.js` and a `bin.bw` value pointing to `bw_setup.js`, so both installation and direct CLI invocation could reach the malicious loader [[research.jfrog.com](https://research.jfrog.com/post/bitwarden-cli-hijack/)].

`bw_setup.js` checked for Bun, downloaded `bun-v1.3.13` from `github[.]com/oven-sh/bun` when needed, and used Bun to execute `bw1.js`. `bw1.js` then collected local developer and CI credential material, encrypted the collected result set, and sent it to `hxxps://audit[.]checkmarx[.]cx/v1/telemetry` with GitHub-based fallback paths if direct HTTPS exfiltration failed [[research.jfrog.com](https://research.jfrog.com/post/bitwarden-cli-hijack/)].

The GitHub abuse path matters for responders because the payload did not stop at local file theft. JFrog reports token validation against `https://api.github.com/user`, commit search for `LongLiveTheResistanceAgainstMachines`, fallback discovery using `beautifulcastle`, repository creation under a victim account, and GitHub Actions secret extraction through workflow execution and artifact retrieval [[research.jfrog.com](https://research.jfrog.com/post/bitwarden-cli-hijack/)]. Socket also calls out workflow file creation and artifacts such as `format-results.txt` [[socket.dev](https://socket.dev/blog/bitwarden-cli-compromised)].

## Technical Analysis
### Package Manipulation
**Package Identity**:
  - **registry**: npm
  - **package**: @bitwarden/cli
  - **malicious_version**: 2026.4.0
  - **modified_manifest_fields**: [object Object]
  - **mismatched_embedded_cli_version**: 2026.3.0

### Execution And Collection
The execution chain is `npm install` or `bw` invocation to `bw_setup.js`, then Bun `1.3.13`, then `bw1.js`. JFrog decoded credential targeting for `gh auth token`, GitHub and npm token patterns, environment variables, SSH paths, `.git-credentials`, `.npmrc`, `.env`, shell histories, AWS credentials, GCP credential DB files, and AI/MCP configuration paths [[research.jfrog.com](https://research.jfrog.com/post/bitwarden-cli-hijack/)].

### Exfiltration
**Primary Exfiltration**:
  - **domain**: audit[.]checkmarx[.]cx
  - **ip**: 94.154.172[.]43
  - **url**: hxxps://audit[.]checkmarx[.]cx/v1/telemetry
  - **encoding**: gzip plus RSA-OAEP-wrapped AES-256-GCM envelope

**Fallback Github Paths**:
- hxxps://api[.]github[.]com/search/commits?q=LongLiveTheResistanceAgainstMachines&sort=author-date&order=desc&per_page=50
- hxxps://api[.]github[.]com/search/commits?q=beautifulcastle%20&sort=author-date&order=desc

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: npm
  - **packages**: @bitwarden/cli@2026.4.0
  - **developer_hosts**: hosts that installed or ran @bitwarden/cli@2026.4.0
  - **ci_cd_systems**: runners that installed or ran @bitwarden/cli@2026.4.0
  - **containers**: images built while resolving @bitwarden/cli@2026.4.0
  - **source_control**: GitHub accounts and repositories reachable from stolen tokens
  - **package_registries**: npm accounts reachable from stolen npm tokens

**Not Currently Known To Affect**:
- Bitwarden web vault usage without npm CLI install
- Bitwarden browser extension
- Bitwarden server production systems per vendor statement

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- 18f784b3bc9a0bcdcb1a8d7f51bc5f54323fc40cbd874119354ab609bef6e4cb
- 8605e365edf11160aad517c7d79a3b26b62290e5072ef97b102a01ddbb343f14
- 167ce57ef59a32a6a0ef4137785828077879092d7f83ddbc1755d6e69116e0ad

### Domains
- tmp.987654321.lock

### Urls
- hxxps://audit[.]checkmarx[.]cx/v1/telemetry
- hxxps://api[.]github[.]com/search/commits?q=LongLiveTheResistanceAgainstMachines&sort=author-date&order=desc&per_page=50
- hxxps://api[.]github[.]com/search/commits?q=beautifulcastle%20&sort=author-date&order=desc
- hxxps://github[.]com/oven-sh/bun/releases/download/bun-v1[.]3[.]13

### Ips
- 94[.]154[.]172[.]43


## Detection and Hunting

### Hunt Manifest: bitwarden-cli-npm-compromised-action-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Bitwarden CLI npm 2026.4.0 Credential Stealer?
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
OUT = Path(os.environ.get("OUT", "hp-bitwarden-cli-npm-compromised-action-scope"))

VERSIONS = ["@bitwarden/cli@2026.4.0"]
FILES = ["bw_setup.js","bw1.js","/tmp/tmp.987654321.lock","package-updated.tgz"]
DOMAINS = ["tmp.987654321.lock","package-updated.tgz","audit.checkmarx.cx","api.github.com","github.com"]
URLS = ["https://audit.checkmarx.cx/v1/telemetry","https://api.github.com/search/commits?q=LongLiveTheResistanceAgainstMachines&sort=author-date&order=desc&per_page=50","https://api.github.com/search/commits?q=beautifulcastle%20&sort=author-date&order=desc","https://github.com/oven-sh/bun/releases/download/bun-v1.3.13"]
IPS = ["94[.]154[.]172[.]43"]
HASHES = ["18f784b3bc9a0bcdcb1a8d7f51bc5f54323fc40cbd874119354ab609bef6e4cb","8605e365edf11160aad517c7d79a3b26b62290e5072ef97b102a01ddbb343f14","167ce57ef59a32a6a0ef4137785828077879092d7f83ddbc1755d6e69116e0ad"]

# Collect unique indicators
OUT.mkdir(parents=True, exist_ok=True)
indicators_file = OUT / "ioc-indicators.txt"
indicators = set()
for group in [VERSIONS, FILES, DOMAINS, URLS, IPS, HASHES]:
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

    if "PACKAGES" in globals() and PACKAGES:
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
1. [Bitwarden Community Forums: Bitwarden Statement on Checkmarx Supply Chain Incident](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127) - **Role:** DIRECT_SOURCE - **Impact:** Vendor scope, affected window, non-impact statements, cleanup package version.
2. [JFrog Security Research: TeamPCP Campaign Spreads to npm via a Hijacked Bitwarden CLI](https://research.jfrog.com/post/bitwarden-cli-hijack/) - **Role:** PRIMARY_RESEARCH - **Impact:** Package manifest rewiring, loader/payload files, hashes, exfiltration, GitHub fallback selectors, credential targets.
3. [Socket: Bitwarden CLI Compromised in Ongoing Checkmarx Supply Chain Campaign](https://socket.dev/blog/bitwarden-cli-compromised) - **Role:** PRIMARY_RESEARCH - **Impact:** Independent IOC set and GitHub Actions workflow/artifact abuse context.
4. [npm registry metadata for @bitwarden/cli](https://registry.npmjs.org/@bitwarden%2fcli) - **Role:** REGISTRY_METADATA - **Impact:** Current versions list and `time` metadata for removed `2026.4.0`.
5. [CVE.org: CVE-2026-42994](https://www.cve.org/CVERecord?id=CVE-2026-42994) - **Role:** DIRECT_SOURCE - **Impact:** CVE record for the malicious `@bitwarden/cli@2026.4.0` npm distribution.
