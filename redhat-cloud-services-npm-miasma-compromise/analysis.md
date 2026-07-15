---
title: "Red Hat Cloud Services npm Trusted-Publishing Compromise"
date: 2026-06-02
severity: "critical"
tags:
  - npm
  - redhat
  - supply-chain
  - ci-cd
  - oidc
  - credential-theft
  - mini-shai-hulud
summary: "Multiple @redhat-cloud-services npm packages were compromised on 2026-06-01 through trusted-publishing abuse tied to the Mini Shai-Hulud Miasma wave. The malicious releases added install-time payload execution, credential collection, destructive fallback behavior, and GitHub workflow tampering risk."
sourceCount: 4
---

## Executive Summary

On **2026-06-01**, researchers reported a new Mini Shai-Hulud child event affecting the `@redhat-cloud-services` npm scope. StepSecurity identified 31 malicious package versions across 29 packages, published through trusted publishing after an attacker compromised the `RedHatInsights/javascript-clients` GitHub workflow path and abused OIDC-based npm publishing [[stepsecurity.io](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)].

This is not a normal vulnerable dependency advisory. It is a supply-chain publish compromise against Red Hat Cloud Services client packages that can execute during `npm install`. The reported payload is called **Miasma**, also tracked as **The Spreading Blight**, and it overlaps the same Mini Shai-Hulud operational pattern of CI/CD compromise, credential theft, GitHub workflow tampering, and destructive pressure after token invalidation [[stepsecurity.io](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)] [[ox.security](https://www.ox.security/blog/new-npm-supply-chain-attack-redhat-cloud-services-compromised)].

Organizations should search for affected `@redhat-cloud-services/*` packages in source repositories, lockfiles, package caches, build logs, CI artifacts, and container layers. Any confirmed install on a developer workstation or runner with GitHub, npm, cloud, or deployment credentials should trigger credential rotation from a clean environment.

### Source-Watcher Candidate Queue

**Candidate Id**: redhat-cloud-services-npm-miasma-compromise

**First Seen**: 2026-06-01

**Decision**: publish_ready

**Relationship**: child_event_of_mini_shai_hulud_worm

**Dedupe Keys**:
- npm:@redhat-cloud-services
- repo:RedHatInsights/javascript-clients
- package:@redhat-cloud-services/patch-client@4.0.4
- payload:miasma
- campaign:mini-shai-hulud

**Starting Sources**:
- StepSecurity primary research
- OX Security primary research
- Mend primary research
- BleepingComputer Red Hat statement

## Key Facts

**Threat Type**: malicious npm package publish compromise

**Ecosystem**: npm

**Registry**: npm

**Campaign Context**: Mini Shai-Hulud / Miasma / The Spreading Blight

**Affected Scope**: @redhat-cloud-services

**Source Repository**: RedHatInsights/javascript-clients

**Reported Publish Date**: 2026-06-01

**Reported Package Count**: 29

**Reported Malicious Version Count**: 31

**Execution Trigger**: npm install lifecycle script

**Publish Path**: GitHub Actions trusted publishing / npm OIDC

**Credential Risk**:
- GitHub tokens
- npm publishing tokens
- cloud credentials
- CI/CD deployment credentials
- developer workstation secrets

## Evidence Assessment

| Claim | Status | Evidence |
| --- | --- | --- |
| Multiple `@redhat-cloud-services` npm packages were maliciously published on 2026-06-01. | confirmed | StepSecurity reports 31 malicious versions across 29 packages and lists exact package/version pairs [[stepsecurity.io](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)]. |
| The compromise path involved the `RedHatInsights/javascript-clients` GitHub repository and OIDC trusted publishing. | confirmed | StepSecurity describes the attacker-created pull request, merged branch, workflow execution, and trusted-publishing abuse path [[stepsecurity.io](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)]. |
| The payload is tracked as Miasma or The Spreading Blight and overlaps Mini Shai-Hulud behavior. | likely | StepSecurity and OX both connect the behavior to the Mini Shai-Hulud family and describe destructive or worm-like behavior [[stepsecurity.io](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)] [[ox.security](https://www.ox.security/blog/new-npm-supply-chain-attack-redhat-cloud-services-compromised)]. |
| The malicious code targets credentials and can tamper with GitHub repository state. | confirmed | StepSecurity and Mend describe credential theft, GitHub workflow manipulation, and repository-level changes [[stepsecurity.io](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)] [[mend.io](https://www.mend.io/blog/miasma-malware-analysis-a-deep-dive-into-the-red-hat-npm-supply-chain-attack/)]. |
| Red Hat says it removed the compromised package versions and rotated exposed tokens. | confirmed | BleepingComputer published a Red Hat statement saying affected versions were removed and exposed tokens were rotated [[bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/red-hat-npm-packages-compromised-to-steal-developer-credentials/)]. |
| Public sources currently prove downstream victim count or successful cloud abuse. | not_observed | None of the reviewed public sources provides a verified victim count or confirmed downstream cloud-control-plane abuse list. |

## Impact Determination

| Classification | Criteria | Required evidence | Handling decision | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | An affected package/version was installed or executed and endpoint, process, network, or GitHub audit telemetry shows Miasma selectors or credential collection behavior. | Lockfile/cache hit plus package install logs, process telemetry, shell history, endpoint telemetry, proxy logs, or GitHub audit activity. | Isolate the host or runner, preserve package artifacts, rotate reachable credentials, and audit follow-on GitHub/npm/cloud activity. | Affected packages are removed, credentials are rotated, and downstream audits show no unexplained write activity. |
| Presumed exposed | An affected package/version was installed on a developer workstation, CI runner, image build, or release environment but runtime telemetry is incomplete. | Dependency lock, package cache, build log, container layer, or npm install record. | Treat GitHub, npm, cloud, registry, and deployment credentials reachable from that environment as exposed. | Risk owners confirm clean rebuilds and credential rotation or accept residual risk. |
| Potentially exposed | Repositories or builds use `@redhat-cloud-services/*`, but exact resolved versions or install execution is not established. | Repository manifests, lockfiles, private registry logs, CI logs, and package-cache inventory. | Reconstruct package resolution and install execution before narrowing scope. | Each hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected package names, affected versions, package-cache artifacts, tarballs, or runtime selectors appear in complete evidence. | Negative search across repos, CI logs, package caches, endpoint telemetry, proxy logs, and registry mirrors. | Preserve negative evidence and keep lifecycle-script controls in place. | Evidence coverage includes developer endpoints, CI runners, production builds, and internal mirrors. |
| Unknown | Dependency inventory, package-cache data, runner telemetry, endpoint telemetry, or audit logs are unavailable. | Named gap with system owner and retention window. | Keep credentials in scope until evidence is recovered or rotation closes the gap. | Missing evidence is recovered or the risk owner accepts residual uncertainty. |

## Timeline

- **2026-06-01:** StepSecurity reports malicious `@redhat-cloud-services` package versions and ties the activity to a trusted-publishing workflow compromise [[stepsecurity.io](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)].
- **2026-06-01:** OX publishes its analysis of the Red Hat Cloud Services npm compromise and frames the activity as a Mini Shai-Hulud return wave [[ox.security](https://www.ox.security/blog/new-npm-supply-chain-attack-redhat-cloud-services-compromised)].
- **2026-06-01:** Mend publishes a companion analysis of the Miasma payload and highlights malicious behavior in the npm package set [[mend.io](https://www.mend.io/blog/miasma-malware-analysis-a-deep-dive-into-the-red-hat-npm-supply-chain-attack/)].
- **2026-06-02:** This Halting Problems refresh found no existing local post for the `@redhat-cloud-services` Miasma wave and created this child event report.

## Technical Analysis

The material supply-chain failure is not the mere existence of vulnerable package code. It is the use of trusted CI/CD publishing to push malicious package versions into the public npm registry. StepSecurity reports that the attacker opened a pull request in `RedHatInsights/javascript-clients`, got workflow-controlled publishing execution, and used the resulting OIDC trusted-publishing path to publish malicious versions [[stepsecurity.io](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)].

The payload belongs in the same response family as Mini Shai-Hulud because the defensive questions are the same: which package versions resolved, which install hooks executed, which credentials were reachable, and what GitHub/npm/cloud activity followed. OX and Mend both describe the payload as a new wave using Miasma or The Spreading Blight naming, with destructive and credential-theft behavior [[ox.security](https://www.ox.security/blog/new-npm-supply-chain-attack-redhat-cloud-services-compromised)] [[mend.io](https://www.mend.io/blog/miasma-malware-analysis-a-deep-dive-into-the-red-hat-npm-supply-chain-attack/)].

Treat successful installation on a runner as credential exposure unless telemetry proves the lifecycle script did not run. Lockfile-only evidence is not enough for confirmed compromise, but it is enough to keep the environment in scope until package-cache and install-log evidence is collected. [1]

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Domains
- registry[.]npmjs[.]org
- api[.]github[.]com
- github[.]com

### Urls
- hxxps://github[.]com/RedHatInsights/javascript-clients


## Detection and Hunting

### Hunt Manifest: redhat-cloud-services-npm-miasma-compromise-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Red Hat Cloud Services npm Trusted-Publishing Compromise?
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
OUT = Path(os.environ.get("OUT", "hp-redhat-cloud-services-npm-miasma-compromise-scope"))
OUT.mkdir(parents=True, exist_ok=True)
indicators_file = OUT / "indicators.txt"

DOMAINS = ["yarn.lock","bun.lock","registry.npmjs.org","api.github.com","github.com"]
URLS = ["https://github.com/RedHatInsights/javascript-clients"]

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

## Remediation and Closure

Remove affected packages from lockfiles, purge package-manager caches, rebuild containers from clean dependency state, and block affected package/version pairs in private registry policy. For environments that installed the malicious versions, rotate credentials from a clean host before reconnecting the original asset.

Closure requires negative evidence across repositories, package caches, build logs, CI runner artifacts, endpoint telemetry, and internal npm mirrors. If telemetry is unavailable, close the gap with broad credential rotation and a documented residual-risk decision.

## Sources

1. [StepSecurity: Multiple Red Hat Cloud Services npm Packages Compromised](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised)
2. [OX Security: New npm Supply Chain Attack - Red Hat Cloud Services Compromised](https://www.ox.security/blog/new-npm-supply-chain-attack-redhat-cloud-services-compromised)
3. [Mend: Miasma Malware Analysis - Red Hat npm Supply Chain Attack](https://www.mend.io/blog/miasma-malware-analysis-a-deep-dive-into-the-red-hat-npm-supply-chain-attack/)
4. [BleepingComputer: Red Hat npm packages compromised to steal developer credentials](https://www.bleepingcomputer.com/news/security/red-hat-npm-packages-compromised-to-steal-developer-credentials/)
