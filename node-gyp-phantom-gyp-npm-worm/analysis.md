---
title: "Phantom Gyp npm Worm Abuses node-gyp Build Hooks"
date: 2026-06-05
severity: "critical"
tags:
  - npm
  - node-gyp
  - supply-chain
  - credential-theft
  - ci-cd
summary: "Snyk disclosed a June 2026 npm supply-chain wave that abuses native-addon build behavior through binding.gyp and node-gyp. The Phantom Gyp/Miasma activity affects packages including @vapi-ai, abandoned-package, and autotel packages and should be handled as install-time credential exposure."
sourceCount: 4
---

## Executive Summary

On **2026-06-04**, Snyk disclosed a self-propagating npm supply-chain campaign that abuses the normal `binding.gyp` and `node-gyp rebuild` path used by native Node.js addons [[snyk.io](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/)]. Snyk tracks the technique as **Phantom Gyp** and ties it to the Miasma / Mini Shai-Hulud style of install-time credential theft and propagation [[snyk.io](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/)] [[security.snyk.io](https://security.snyk.io/node-gyp-supply-chain-compromise-june-2026)].

This is supply-chain execution, not a passive vulnerable dependency. Affected package installation can execute during `npm install`, `pnpm install`, `yarn install`, or CI build steps before application code is imported. Treat any affected package execution on a developer workstation, CI runner, release builder, or container-build host as possible exposure of npm, GitHub, cloud, SSH, and deployment credentials.

### Source-Watcher Candidate Queue

**Candidate Id**: node-gyp-phantom-gyp-npm-worm

**First Seen**: 2026-06-04

**Decision**: publish_ready

**Relationship**: candidate_child_event_of_mini_shai_hulud_miasma

**Dedupe Keys**:
- technique:phantom-gyp
- tool:node-gyp
- file:binding.gyp
- npm:@vapi-ai/server-sdk
- npm:autotel-trpc

**Starting Sources**:
- Snyk primary research
- Snyk vulnerability intelligence page
- npm package registry metadata
- GitHub node-gyp project reference

## Key Facts

**Threat Type**: malicious npm package install-time execution

**Ecosystem**: npm

**Technique**: binding.gyp / node-gyp build hook abuse

**Campaign Name**: Phantom Gyp

**Related Family**: Miasma / Mini Shai-Hulud

**Disclosed**: 2026-06-04

**Execution Trigger**:
- npm lifecycle install
- node-gyp rebuild
- native addon binding.gyp processing

**Known Affected Packages**:
- @vapi-ai/server-sdk
- @vapi-ai/web
- @jagreehal/builder
- abandoned-package
- abandoned-package-2
- autotel-terminal
- autotel-client
- autotel-trpc

**Credential Risk**:
- npm tokens
- GitHub tokens
- cloud credentials
- SSH keys
- CI/CD deployment secrets

## Evidence Assessment

| Claim | Status | Evidence |
| --- | --- | --- |
| Snyk disclosed a node-gyp / binding.gyp supply-chain compromise on 2026-06-04. | confirmed | Snyk's research article and companion incident page describe the campaign and the Phantom Gyp technique [[snyk.io](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/)] [[security.snyk.io](https://security.snyk.io/node-gyp-supply-chain-compromise-june-2026)]. |
| The campaign uses normal native-addon build behavior as an execution path. | confirmed | Snyk specifically highlights `binding.gyp` and `node-gyp` as the abused build mechanism; the node-gyp project documents `binding.gyp` as the native addon build configuration file [[snyk.io](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/)] [[github.com](https://github.com/nodejs/node-gyp)]. |
| The package list includes `@vapi-ai`, `abandoned-package`, and `autotel` packages. | confirmed | Snyk's incident page lists affected packages and versions, and npm registry metadata can be used to confirm package identity and publication history [[security.snyk.io](https://security.snyk.io/node-gyp-supply-chain-compromise-june-2026)] [[npmjs.com](https://www.npmjs.com/)]. |
| Public sources currently prove downstream victim count or cloud-account abuse. | not_observed | Reviewed public sources do not provide a verified victim list or confirmed cloud-control-plane abuse count. |

## Impact Determination

| Classification | Criteria | Required evidence | Handling decision | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | Affected package/version was installed and lifecycle/build execution or credential-harvesting behavior is observed. | Lockfile/cache hit plus npm logs, process telemetry, build logs, proxy logs, or endpoint telemetry. | Isolate host or runner, preserve package artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, credentials rotated, and downstream audits show no unauthorized write activity. |
| Presumed exposed | Affected package/version was installed on a credential-bearing workstation, runner, or builder, but runtime telemetry is incomplete. | Lockfile, package cache, build log, container layer, or package-manager record. | Keep npm, GitHub, cloud, SSH, and deployment credentials in scope. | Owners confirm clean rebuilds and credential rotation or accept documented residual risk. |
| Potentially exposed | Dependency inventory shows affected package names but resolved versions or execution are unknown. | Manifest, lockfile, registry proxy logs, and build records. | Reconstruct package resolution and lifecycle execution. | Each hit is dispositioned as confirmed, presumed, or not exposed. |
| Not exposed | No affected package names, versions, caches, build logs, or selectors appear in complete evidence. | Negative repository, CI, package cache, endpoint, and proxy searches. | Preserve negative evidence and enforce lifecycle-script controls. | Evidence coverage includes endpoints, CI, build images, and package mirrors. |
| Unknown | Dependency, cache, endpoint, build, or audit telemetry is missing. | Named gap with owner and retention window. | Keep reachable credentials in scope until evidence or rotation closes the gap. | Missing evidence is recovered or risk owner accepts uncertainty. |

## Timeline

- **2026-06-03 to 2026-06-04:** Exposure window used by this post for local searches and audit exports, based on Snyk's June 2026 disclosure window [[snyk.io](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/)] [[security.snyk.io](https://security.snyk.io/node-gyp-supply-chain-compromise-june-2026)].
- **2026-06-04:** Snyk publishes its analysis of the node-gyp supply-chain compromise and Phantom Gyp behavior [[snyk.io](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/)].
- **2026-06-05:** This Halting Problems refresh found no existing local post for the Phantom Gyp node-gyp campaign and created this report.

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Domains
- binding.gyp


## Detection and Hunting

### Hunt Manifest: node-gyp-phantom-gyp-npm-worm-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Phantom Gyp npm Worm Abuses node-gyp Build Hooks?
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
OUT = Path(os.environ.get("OUT", "hp-node-gyp-phantom-gyp-npm-worm-scope"))
OUT.mkdir(parents=True, exist_ok=True)
indicators_file = OUT / "indicators.txt"

DOMAINS = ["binding.gyp","yarn.lock","bun.lock"]

# Collect unique indicators
indicators = set()
for group in [DOMAINS]:
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

1. Remove affected package versions from lockfiles, caches, internal mirrors, container layers, and build images.
2. Rebuild release artifacts from clean dependency resolution with lifecycle-script restrictions where feasible.
3. Rotate credentials reachable from exposed environments.
4. Preserve the script output, lockfile evidence, package-manager logs, and audit logs as closure evidence.

## Sources

1. [Snyk: Node-gyp supply-chain compromise and Phantom Gyp](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/)
2. [Snyk vulnerability intelligence: Node-gyp Supply Chain Compromise, June 2026](https://security.snyk.io/node-gyp-supply-chain-compromise-june-2026)
3. [npm registry](https://www.npmjs.com/)
4. [node-gyp project](https://github.com/nodejs/node-gyp)
