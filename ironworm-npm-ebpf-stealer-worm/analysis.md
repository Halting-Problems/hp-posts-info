---
title: "IronWorm npm Supply-Chain Worm Uses eBPF Rootkit"
date: 2026-06-03
severity: "critical"
tags:
  - npm
  - ebpf
  - supply-chain
  - credential-theft
  - rust
summary: "JFrog Security disclosed IronWorm, a Rust-based npm information-stealing worm found in 36 package versions. It uses an eBPF rootkit and Tor for stealth and propagates through stolen credentials and trusted publishing workflows."
sourceCount: 3
---

## Executive Summary

On **2026-06-03**, JFrog Security disclosed **IronWorm**, a self-propagating infostealer found in 36 malicious npm package versions published through a compromised account on **2026-05-26** [[research.jfrog.com](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)] [[ox.security](https://www.ox.security/blog/ironworm-supply-chain-malware-hits-npm/)] [[registry.npmjs.org](https://registry.npmjs.org/weavedb-sdk)]. The malware targets developer environments, cloud resources, AI API keys, and cryptocurrency wallets [[research.jfrog.com](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)].

The worm executes a Rust-based ELF binary via package `preinstall` hooks during `npm install` [[research.jfrog.com](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)]. Once active on a host, it deploys an **eBPF (extended Berkeley Packet Filter) kernel rootkit** to hide its processes and file handles from system monitors and communicates with Command-and-Control (C2) servers over the Tor network [[research.jfrog.com](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)]. It spreads by harvesting publication credentials and, when running in CI, exchanging the runner's OIDC identity through npm Trusted Publishing for a short-lived package-scoped token [[research.jfrog.com](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)].

### Source-Watcher Candidate Queue

**Candidate Id**: ironworm-npm-ebpf-stealer-worm

**First Seen**: 2026-05-26

**Decision**: publish_ready

**Relationship**: architecturally_similar_to_shai_hulud_unconfirmed_attribution

**Dedupe Keys**:
- technique:ebpf-rootkit
- npm:asteroiddao
- github:ocrybit

**Starting Sources**:
- JFrog Security Research disclosure
- OX Security incident intelligence
- npm registry metadata for weavedb-sdk@0.45.3

## Key Facts

**Threat Type**: malicious npm package self-propagating worm

**Ecosystem**: npm

**Technique**: eBPF kernel rootkit, Tor network C2, Trusted Publishing abuse

**Campaign Name**: IronWorm

**Related Family**: Shai-Hulud

**Disclosed**: 2026-06-03

**Execution Trigger**:
- npm preinstall hook
- rust binary execution

**Known Affected Packages**:
- ai3
- aonote
- arjson
- arnext
- arnext-arkb
- atomic-notes
- create-arnext-app
- cwao
- cwao-tools
- cwao-units
- fpjson-lang
- hbsig
- monade
- roidjs
- test-ajs
- test-weavedb-sdk
- testnpmnmp
- wao
- warp-contracts-plugin-deploy-test
- wdb-cli
- wdb-core
- wdb-sdk
- weavedb-base
- weavedb-client
- weavedb-console
- weavedb-contracts
- weavedb-exm-sdk
- weavedb-exm-sdk-web
- weavedb-lite
- weavedb-node-client
- weavedb-offchain
- weavedb-sdk-base
- weavedb-sdk-node
- weavedb-tools
- weavedb-warp-contracts-plugin-deploy
- zkjson

**Credential Risk**:
- npm tokens
- GitHub OIDC tokens
- cloud provider credentials (AWS, GCP, Azure)
- SSH keys
- AI API keys (OpenAI, Anthropic, Gemini)
- cryptocurrency wallet files

## Evidence Assessment

| Claim | Status | Evidence |
| --- | --- | --- |
| JFrog disclosed a Rust-based, self-propagating npm infostealer worm on 2026-06-03. | confirmed | JFrog's technical writeup documents the worm behavior, its target credentials, and Rust implementation [[research.jfrog.com](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)]. |
| The campaign uses an eBPF rootkit and Tor for C2 stealth. | confirmed | Research analysis verified the loading of custom eBPF programs to filter process monitoring syscalls and Tor network configuration [[research.jfrog.com](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)] [[ox.security](https://www.ox.security/blog/ironworm-supply-chain-malware-hits-npm/)]. |
| The worm can propagate through npm Trusted Publishing from a compromised CI runner. | confirmed | JFrog documents the OIDC identity-token exchange and package-scoped automation token flow used by the malware [[research.jfrog.com](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)]. |
| The campaign produced 57 backdated malicious commits across nine organizations. | confirmed | JFrog reports the commit and organization counts from its investigation [[research.jfrog.com](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)]. |
| IronWorm is operated by the Shai-Hulud actor. | unclear | JFrog found architectural and commit-name similarities but characterized IronWorm as custom malware with its own infrastructure [[research.jfrog.com](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)]. |

## Impact Determination

| Classification | Criteria | Required evidence | Handling decision | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | Affected package version was installed and native execution or C2 traffic is observed. | Process creation logs, eBPF module load events, Tor network connection logs. | Isolate host, revoke active sessions, and rotate all credentials from a clean machine. | Complete system rebuild, token revocation logs, and downstream cloud trail audits showing zero anomalies. |
| Presumed exposed | Affected package name and version found in project lockfile or build log. | package-lock.json, pnpm-lock.yaml, yarn.lock, CI console logs. | Treat all reachable credentials (AWS, GCP, AI APIs, SSH) as compromised. | Full credential rotation and lockfile cleanup verified by git commit. |
| Potentially exposed | Dependency matches names of compromised packages, but version resolution is undetermined. | package.json dependencies, registry logs. | Verify exact resolved version in target environment. | Hit is confirmed as either clean (unaffected version) or escalated. |
| Not exposed | No affected package selectors or C2 indicators present in the network and workspace. | Negative audit results from endpoint and repo scans. | Maintain active monitoring for eBPF rootkit signatures. | All endpoints and code repos are scanned with negative results. |

## Timeline

- **2026-05-26:** npm registry metadata records publication of `weavedb-sdk@0.45.3`; its metadata now marks the release compromised and deprecated [[registry.npmjs.org](https://registry.npmjs.org/weavedb-sdk)].
- **2026-05-27:** npm registry metadata for the affected package set was modified as malicious releases were deprecated or removed [[registry.npmjs.org](https://registry.npmjs.org/weavedb-sdk)].
- **2026-06-03:** JFrog Security publishes findings detailing the IronWorm malware campaign [[research.jfrog.com](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)].
- **2026-06-10:** This review expanded the affected set to all 36 package versions reported by JFrog and OX Security.

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- 7750bab1a6c48831b5a889e6b799d1684d0a4f2a


## Detection and Hunting

### Hunt Manifest: ironworm-npm-ebpf-stealer-worm-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with IronWorm npm Supply-Chain Worm Uses eBPF Rootkit?
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
OUT = Path(os.environ.get("OUT", "hp-ironworm-npm-ebpf-stealer-worm-scope"))
OUT.mkdir(parents=True, exist_ok=True)
indicators_file = OUT / "indicators.txt"

HASHES = ["7750bab1a6c48831b5a889e6b799d1684d0a4f2a"]

# Collect unique indicators
indicators = set()
for group in [HASHES]:
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

1. Remove compromised versions of affected packages from dependencies and package locks.
2. Re-resolve dependencies using a clean registry cache.
3. Revoke npm publication tokens and GitHub classic/fine-grained tokens.
4. Rotate any keys harvested from the target endpoint.

## Sources

1. [JFrog Security Research: IronWorm, Shai-Hulud's Rustier Cousin](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/) - **Role:** PRIMARY_RESEARCH - **Impact:** Malware architecture, package list, propagation, credential targets, rootkit behavior, and campaign timeline.
2. [OX Security: IronWorm Supply Chain Malware Hits npm](https://www.ox.security/blog/ironworm-supply-chain-malware-hits-npm/) - **Role:** PRIMARY_RESEARCH - **Impact:** Independent package/version list and exposure metrics.
3. [npm registry metadata: weavedb-sdk](https://registry.npmjs.org/weavedb-sdk) - **Role:** DIRECT_SOURCE - **Impact:** Publication timestamp, deprecated status, preinstall hook, tarball integrity, and package shasum for `0.45.3`.
