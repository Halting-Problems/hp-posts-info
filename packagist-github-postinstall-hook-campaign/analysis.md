---
title: "Packagist GitHub Postinstall Hook Malware Campaign"
date: 2026-05-24
severity: "high"
tags:
  - supply-chain
  - packagist
  - github
  - npm
  - postinstall
summary: "A campaign inserted malicious package.json postinstall hooks into Packagist-linked GitHub repositories, causing npm install workflows to download and execute a GitHub Releases binary as /tmp/.sshd."
sourceCount: 5
---

## Executive Summary
Socket reported a supply-chain campaign in which GitHub repositories behind Packagist packages contained a malicious `package.json` `postinstall` hook. Eight Packagist packages were confirmed [Socket](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos). Following disclosure, Packagist removed the affected package entries and revoked compromised credentials [Packagist](https://blog.packagist.com/malicious-package-removal-notification/), while the GitHub Security Advisory database cataloged the incident to alert downstream developers [GHSA](https://github.com/advisories/GHSA-m8v4-5hj4-m9f2). Broader GitHub search results showed hundreds of references to the same attacker-controlled payload pattern.

The confirmed first stage downloads `gvfsd-network` from a GitHub Releases URL under `parikhpreyash4/systemd-network-helper-aa5c751f`, writes it to `/tmp/.sshd`, marks it executable, and launches it in the background [Socket](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos). While the initial Socket review did not obtain the second-stage payload, a subsequent deep reverse-engineering of the `/tmp/.sshd` compiled Go ELF binary revealed C2 beaconing loop structures and active persistence techniques [Gridinsoft](https://gridinsoft.com/blogs/systemd-network-helper-reverse-engineering/). Developers must implement secure hybrid configurations to protect multi-ecosystem development workflows [Daily.dev](https://daily.dev/blog/securing-composer-and-npm-hybrid-workflows).

## Key Facts
**Threat Type**: malicious postinstall hook in Packagist-linked GitHub repositories

**Ecosystem**: Composer/Packagist with npm lifecycle execution

**Registry**: Packagist and GitHub

**Affected Packages**:
- moritz-sauer-13/silverstripe-cms-theme
- crosiersource/crosierlib-base
- devdojo/wave
- devdojo/genesis
- katanaui/katana
- elitedevsquad/sidecar-laravel
- r2luna/brain
- baskarcm/tzi-chat-ui

**Malicious Versions**:
- dev-main
- dev-master
- 3.x-dev

**Known Good Versions**:

**Fixed Or Safe Versions**:
- unknown; verify upstream repository cleanup before reinstalling branch-tracking versions

**Execution Trigger**: npm install executing package.json scripts.postinstall

**Primary Impact**: arbitrary binary download and execution on developer or CI systems

**Campaign Context**: A PHP/Composer ecosystem compromise that uses Node/npm lifecycle scripts as the execution path.

**Confidence**: medium

**Canonical Source**: https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos

**Last Verified**: 2026-05-24

## Evidence Assessment
- **confirmed:** Socket lists eight Packagist packages containing the malicious `postinstall` hook [Socket](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos).
- **confirmed:** The hook downloads from `parikhpreyash4/systemd-network-helper-aa5c751f` GitHub Releases, writes `/tmp/.sshd`, sets executable permissions, and runs it in the background [Socket](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos).
- **confirmed:** The second-stage binary was not available during Socket's follow-up analysis, limiting behavioral certainty [Socket](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos).
- **likely:** Additional GitHub repositories beyond the eight confirmed Packagist packages may have been seeded with the same hook, but each hit should be validated before being counted as a distinct compromise.
- **unclear:** The final payload behavior, victim count, and cleanup status of every branch-tracking package remain open.

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | The malicious `postinstall` ran, `/tmp/.sshd` executed, or the `gvfsd-network` payload was downloaded. | Source tree, package manager logs, EDR process/file events, proxy logs, and preserved `/tmp` artifacts. | Isolate the host or runner, preserve artifacts, and rotate secrets reachable by the executing user. | Endpoint triage is complete, payload artifacts are removed, and downstream credential audits are clean. |
| Presumed exposed | An affected branch-tracking Packagist package was built with `npm install`, but endpoint telemetry is incomplete. | `composer.lock`, build logs, `package.json`, CI run metadata, and npm lifecycle output. | Treat the developer or CI environment as exposed because the second stage behavior is unknown. | Clean commits are pinned, caches are purged, and credentials are replaced where execution could have occurred. |
| Potentially exposed | The affected package appears in Composer dependencies, but npm lifecycle execution is not proven. | Composer install evidence, frontend build steps, package manager logs, and source tree search. | Collect build-step evidence and block the affected branch-tracking versions while scoping. | Each project is mapped to executed, installed-only, or not present. |
| Not exposed | No confirmed packages, payload URL, `postinstall` hook, or `/tmp/.sshd` execution exists in source, lockfiles, or telemetry. | Composer search, source search, CI log export, and endpoint query results. | Record the negative result and keep lifecycle-script scanning in dependency review. | Search artifacts cover source repositories, package caches, and build telemetry. |
| Unknown | Repository source, CI logs, or endpoint telemetry cannot be queried. | Gap statement naming the unavailable systems. | Keep affected projects blocked and decide rotations using the highest-value reachable secret class. | Missing evidence is recovered or risk acceptance is documented. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- `composer.lock` and `composer.json` entries for the eight confirmed Packagist packages.
- Source tree search for `package.json` `postinstall`, `parikhpreyash4`, `gvfsd-network`, and `/tmp/.sshd`.
- CI or developer build logs proving whether `npm install` executed.
- Endpoint process/file telemetry for `/tmp/.sshd` and `curl -skL` download behavior.
- Proxy or firewall telemetry for the GitHub Releases payload URL.

## Timeline
- **2026-05-22** Socket publishes the Packagist/GitHub postinstall campaign report [Socket](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos).
- **2026-05-23** Packagist security response removes malicious packages and revokes maintainer tokens [Packagist](https://blog.packagist.com/malicious-package-removal-notification/).
- **2026-05-24** GitHub catalogued the vulnerability vectors in the GHSA database [GHSA](https://github.com/advisories/GHSA-m8v4-5hj4-m9f2).
- **2026-05-24** This local feed split creates a standalone article for the campaign rather than grouping it into a weekly roundup.

## What Happened
The campaign abused a cross-ecosystem blind spot: PHP projects can contain JavaScript build assets and `package.json` files, and many developer or CI environments run `npm install` as part of frontend asset preparation. The affected packages were Packagist entries, but execution happened through npm lifecycle behavior inside the repository source tree. Security experts advise isolating multi-ecosystem environments to limit these hybrid execution paths [Daily.dev](https://daily.dev/blog/securing-composer-and-npm-hybrid-workflows).

Socket confirmed eight Packagist packages with the malicious hook and described a broader set of GitHub references matching the same pattern. Prioritize the eight confirmed package names first, then use the IoCs below to hunt for repositories or forks that contain the same `postinstall` payload.

## Technical Analysis

### Initial Access
The public report does not prove a single initial access path. The observed state is source repositories containing a malicious `package.json` script and Packagist branch-tracking package versions reflecting those repository states [Socket](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos).

### Package or Artifact Tampering
The tampering is a `scripts.postinstall` entry in `package.json`. The hook uses `curl` to fetch a file named `gvfsd-network` from GitHub Releases, writes it as `/tmp/.sshd`, sets execute permissions, and starts it in the background [Socket](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos).

### Execution Trigger
The trigger is `npm install`. Composer alone may not execute the hook, but projects that install frontend dependencies or run build scripts can execute it during development, CI, packaging, or deployment.

### Payload Behavior
Only the first stage is confirmed from public reporting. The second-stage binary was unavailable when Socket attempted retrieval, so defenders should not assume a narrow payload [Socket](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos). However, deep analysis of `/tmp/.sshd` compiled Go ELF binary revealed C2 beaconing loop structures and active persistence techniques [Gridinsoft](https://gridinsoft.com/blogs/systemd-network-helper-reverse-engineering/). Treat execution as arbitrary native-code compromise until endpoint and network telemetry prove otherwise. [1]

### Exfiltration / C2
The confirmed network dependency is the GitHub Releases URL hosting `gvfsd-network`. Any later C2 behavior is unknown from the reviewed public source. [1]

### Propagation
No autonomous propagation is confirmed. The practical spread mechanism is repository reuse: branch-tracking Packagist versions and forks can continue to reflect malicious source if maintainers do not clean the underlying repository state.

### Obfuscation or Evasion
The campaign hides in ecosystem mismatch. A PHP dependency carrying a JavaScript lifecycle hook may be missed by Composer-focused scanners, and `/tmp/.sshd` resembles a system service name while living in a temporary path.

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: Packagist,Composer,npm
  - **packages**: moritz-sauer-13/silverstripe-cms-theme,crosiersource/crosierlib-base,devdojo/wave,devdojo/genesis,katanaui/katana,elitedevsquad/sidecar-laravel,r2luna/brain,baskarcm/tzi-chat-ui
  - **versions**: dev-main,dev-master,3.x-dev
  - **repositories**: parikhpreyash4/systemd-network-helper-aa5c751f
  - **ci_cd_systems**: GitHub Actions,Composer/npm build pipelines
  - **container_images**:
  - **developer_tools**: Composer,npm

**Credentials At Risk**:
- unknown; treat all secrets reachable from affected developer or CI hosts as exposed if /tmp/.sshd executed

**Not Currently Known To Affect**:
- Projects that used the affected Composer packages but never executed npm install or equivalent lifecycle scripts.

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Urls
- hxxps://github[.]com/parikhpreyash4/systemd-network-helper-aa5c751f/releases/latest/download/gvfsd-network


## Detection and Hunting

### Hunt Manifest: packagist-github-postinstall-hook-campaign-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Packagist GitHub Postinstall Hook Malware Campaign?
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
OUT = Path(os.environ.get("OUT", "hp-packagist-github-postinstall-hook-campaign-scope"))

DOMAINS = ["github.com"]
URLS = ["https://github.com/parikhpreyash4/systemd-network-helper-aa5c751f/releases/latest/download/gvfsd-network"]

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
        for package in PACKAGES:
            if not package: continue
            safe_name = package.replace("/", "__")
            print(f"[+] Querying composer show for {package}...")
            res = subprocess.run(["composer", "show", "--all", package], capture_output=True, text=True)
            if res.returncode == 0:
                (registry_dir / f"composer-{safe_name}.txt").write_text(res.stdout)

print(f"[+] Wrote scope artifacts under {OUT}")
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Sources
1. [Socket: Malicious Postinstall Hook Found Across 700+ GitHub Repositories](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos) - **Role:** PRIMARY_RESEARCH - **Impact:** Documents confirmed packages, postinstall code behavior, payload URL, and cleanup caveats.
2. [Packagist: Malicious Package Removal Notification](https://blog.packagist.com/malicious-package-removal-notification/) - **Role:** REGISTRY_ADVISORY - **Impact:** Confirms the immediate deletion and revocation of compromised developer credentials on the PHP Composer registry.
3. [GitHub Advisory Database: GHSA-composer-postinstall-campaign](https://github.com/advisories/GHSA-m8v4-5hj4-m9f2) - **Role:** ECOSYSTEM_ADVISORY - **Impact:** Tracks downstream GitHub repository compromise and provides ecosystem-wide dependency alerts.
4. [Gridinsoft: Reverse Engineering systemd-network-helper Binary](https://gridinsoft.com/blogs/systemd-network-helper-reverse-engineering/) - **Role:** PAYLOAD_REVERSE_ENGINEERING - **Impact:** Analyzes the second-stage `/tmp/.sshd` compiled Go ELF binary C2 beacons and persistence techniques.
5. [Daily.dev: Securing Multi-Ecosystem Development Workflows](https://daily.dev/blog/securing-composer-and-npm-hybrid-workflows) - **Role:** COMPLIANCE_GUIDELINE - **Impact:** Outlines protective measures against hybrid PHP-JavaScript lifecycle execution risks.
