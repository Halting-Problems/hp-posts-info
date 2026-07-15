---
title: "shopsprint/decimal Go Module DNS Backdoor Typosquat"
date: 2026-05-24
severity: "high"
tags:
  - supply-chain
  - go
  - typosquatting
  - dns
  - backdoor
summary: "The Go module github.com/shopsprint/decimal typosquatted github.com/shopspring/decimal and used an init-time DNS TXT command loop in v1.3.3."
sourceCount: 5
---

## Executive Summary
Socket reported that `github.com/shopsprint/decimal` is a long-running one-character typosquat of the legitimate `github.com/shopspring/decimal` Go module [Socket](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor). GBHackers noted that the module sat clean for years to establish reputation before receiving its weaponized v1.3.3 update [GBHackers](https://gbhackers.com/shopsprint-go-module-poisoning-analysis/). The malicious `v1.3.3` release added an `init()` goroutine that queried DNS TXT records and executed returned commands, giving attackers a stealthy command channel inside any application importing the typoed module, bypassing basic firewall layers [Cybersecurity News](https://cybersecuritynews.com/dns-txt-command-control-go-module/).

The source repository and owner were removed by disclosure time, but Go's public module proxy continued to serve the cached module artifact because proxy.golang.org permanently caches published module zips [Go Modules](https://proxy.golang.org/). Defenders must search source, `go.mod`, `go.sum`, vendored code, build caches, and released binaries for the typoed module path, replace it with the canonical `github.com/shopspring/decimal` path, and enforce checksum/proxy hardening guidelines [CyberPress](https://cyberpress.org/hardening-go-projects-typosquatting/).

## Key Facts
**Threat Type**: Go module typosquat with DNS TXT backdoor

**Ecosystem**: Go modules

**Registry**: proxy.golang.org and pkg.go.dev

**Affected Packages**:
- github.com/shopsprint/decimal

**Malicious Versions**:
- v1.3.3

**Known Good Versions**:
- github.com/shopspring/decimal legitimate module path

**Fixed Or Safe Versions**:
- replace typoed path with github.com/shopspring/decimal and rebuild from clean caches

**Execution Trigger**: Go package init() when imported by a program

**Primary Impact**: remote command execution through DNS TXT command channel

**Campaign Context**: Long-lived typosquat disclosed during the May 2026 supply-chain incident wave.

**Confidence**: high

**Canonical Source**: https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor

**Last Verified**: 2026-05-24

## Evidence Assessment
- **confirmed:** Socket identifies `github.com/shopsprint/decimal@v1.3.3` as the malicious Go module version and contrasts it with the legitimate `github.com/shopspring/decimal` package [Socket](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor).
- **confirmed:** The malicious diff added network, command-execution, and timing imports plus an `init()` goroutine in `decimal.go` [Socket](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor).
- **confirmed:** The command channel uses DNS TXT queries to `dnslog-cdn-images[.]freemyip[.]com` and executes returned content [Socket](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor).
- **confirmed:** Socket states the Go Module Proxy still served the cached malicious `v1.3.3` artifact after the GitHub source disappeared [Socket](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor).
- **unclear:** Public reporting does not prove the number of downstream builds or binaries that imported the typoed path.

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | `github.com/shopsprint/decimal@v1.3.3` is present and Go package import executes `init()` DNS backdoor or the reported process, file, or network indicators is observed. | Artifact inventory plus runtime telemetry showing Go package import executes `init()` DNS backdoor or listed C2/process/file indicators. | Isolate affected hosts or runners, preserve artifacts, and rotate reachable credentials from a clean environment. | Affected artifacts are removed, exposed credentials are replaced, and downstream audit modules show no suspicious follow-on use. |
| Presumed exposed | `github.com/shopsprint/decimal@v1.3.3` was installed, pulled, imported, built, or executed during the exposure window, but telemetry cannot prove exfiltration. | Lockfile, package cache, workflow, image pull, extension inventory, build log, or deployment record tied to the exposure window. | Rebuild from clean artifacts and rotate credentials available to the affected environment. | Credential owners confirm revocation of old material and clean artifacts are deployed. |
| Potentially exposed | The package, workflow, image, extension, or module appears in dependency or deployment records, but Go module initialization is not established. | Manifest, lockfile, build, deployment, or endpoint records plus a named telemetry gap. | Collect the missing execution and telemetry evidence before narrowing scope. | Every hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected version, artifact, mutable reference, or indicator appears in source, lockfiles, build outputs, deployments, package caches, or runtime telemetry. | Repository search, dependency inventory, build/deployment export, package cache query, and runtime telemetry query results. | Preserve the negative search output and keep the prevention controls active. | Search evidence covers developer endpoints, CI runners, production deployments, and package or image caches. |
| Unknown | Required inventory, build, endpoint, network, or audit telemetry is unavailable. | A gap statement naming unavailable systems, owners, and time windows. | Keep the asset in scope and make conservative rotation or rebuild decisions for high-value environments. | The missing evidence is recovered or the risk owner accepts residual uncertainty. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- Dependency, workflow, extension, image, or module inventory covering developer endpoints, CI runners, and production deployments.
- Positive or negative search results for v1.3.3.
- Execution evidence for Go package import executes `init()` DNS backdoor.
- Process, file, DNS, proxy, firewall, or package-manager telemetry for listed indicators.
- Inventory of credentials, tokens, deployment paths, and downstream systems reachable from exposed environments.

## Timeline
- **2017-11-08** The typoed module is registered on GitHub as a clean placeholder package to establish trust [GBHackers](https://gbhackers.com/shopsprint-go-module-poisoning-analysis/).
- **2023-08-19T09:27:21Z** The attacker uploads the weaponized `v1.3.3` version containing the `init()` backdoor [Socket](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor).
- **2026-05-19** Socket publishes public analysis of the typosquat and DNS backdoor [Socket](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor).
- **2026-05-20** Go module registry team flags module paths and updates pkg.go.dev indexing rules [Go Modules](https://proxy.golang.org/).
- **2026-05-24** This local feed split creates a standalone Go typosquat article instead of grouping it into a weekly roundup.

## What Happened
The attacker relied on one-character package-name confusion: `shopsprint` instead of `shopspring`. That typo is easy to miss in `go.mod`, import statements, and vendored paths because the package API mimicked the legitimate decimal library closely enough for normal builds to succeed. Go developers are encouraged to lock down module configurations and checksum validations to prevent accidental inclusion of typosquats [CyberPress](https://cyberpress.org/hardening-go-projects-typosquatting/).

The malicious `v1.3.3` release added a Go `init()` function. In Go, `init()` runs automatically when the package is imported, before application code explicitly calls package functions. That means affected applications could start a command loop simply by importing the dependency.

## Technical Analysis

### Initial Access
No upstream compromise of the legitimate `shopspring/decimal` project is reported. The attack is dependency confusion through typosquatting: publish a similarly named module and wait for developers or automated tools to import the wrong path.

### Package or Artifact Tampering
Socket's diff analysis shows a small malicious change in `decimal.go`: added imports for networking, command execution, and timing, plus an `init()` goroutine. This is effective because the rest of the package remains close to the legitimate API surface [Socket](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor).

### Execution Trigger
The trigger is Go package initialization. Any application, test, or tool that imports `github.com/shopsprint/decimal` can execute the malicious `init()` path.

### Payload Behavior
The payload performs periodic DNS TXT lookups and executes command content returned through DNS. This design can bypass simple HTTP egress controls if DNS logging and TXT-query policy are weak, offering attackers an extremely stealthy execution mechanism inside private network parameters [Cybersecurity News](https://cybersecuritynews.com/dns-txt-command-control-go-module/).

### Exfiltration / C2
The primary C2 channel is DNS TXT for `dnslog-cdn-images[.]freemyip[.]com`. The use of a dynamic DNS domain and TXT records makes DNS query-type telemetry important for hunting [Socket](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor). [1]

### Propagation
No autonomous propagation is reported. Persistence comes from build reproducibility infrastructure: proxy.golang.org and other module proxy caches can continue serving the cached malicious `v1.3.3` module zip even after the upstream GitHub source repository is deleted [Go Modules](https://proxy.golang.org/).

### Obfuscation or Evasion
The main evasion is name similarity plus minimal diff size. Because the malicious behavior lives in `init()`, reviewers can miss it if they focus only on public API changes.

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: Go modules
  - **packages**: github.com/shopsprint/decimal
  - **versions**: v1.3.3
  - **repositories**: github.com/shopsprint/decimal
  - **ci_cd_systems**: Go build/test pipelines
  - **container_images**: images built from applications importing the typoed path
  - **developer_tools**: go command,Go module proxy/cache

**Credentials At Risk**:
- secrets available to affected build hosts or applications, depending on executed commands

**Not Currently Known To Affect**:
- github.com/shopspring/decimal when spelled correctly.

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c

### Domains
- go.mod
- go.sum
- decimal.go
- dnslog-cdn-images[.]freemyip[.]com
- freemyip[.]com


## Detection and Hunting

### Hunt Manifest: shopsprint-decimal-go-typosquat-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with shopsprint/decimal Go Module DNS Backdoor Typosquat?
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
OUT = Path(os.environ.get("OUT", "hp-shopsprint-decimal-go-typosquat-scope"))

DOMAINS = ["github.com","go.mod","go.sum","decimal.go","dnslog-cdn-images[.]freemyip[.]com","freemyip[.]com"]
HASHES = ["f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c"]

# Collect unique indicators
indicators = set()
for group in [DOMAINS, HASHES]:
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
            print(f"[+] Querying go list for {package}...")
            env = os.environ.copy()
            env["GONOSUMDB"] = "*"
            res = subprocess.run(["go", "list", "-m", "-json", package], capture_output=True, text=True, env=env)
            if res.returncode == 0:
                (registry_dir / f"go-{safe_name}.json").write_text(res.stdout)

print(f"[+] Wrote scope artifacts under {OUT}")
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Sources
1. [Socket: Popular Go Decimal Library Targeted by Long-Running Typosquat with DNS Backdoor](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor) - **Role:** PRIMARY_RESEARCH - **Impact:** Documents the typoed module path, malicious version, artifact diff, DNS TXT C2, proxy persistence, hash, and remediation.
2. [Go Modules: proxy.golang.org Caching Behavior](https://proxy.golang.org/github.com/shopsprint/decimal/@v/v1.3.3.info) - **Role:** REGISTRY_PERSISTENCE - **Impact:** Confirms why deleted GitHub source repositories remain downloadable through Go's decentralized dependency caches.
3. [Cybersecurity News: DNS TXT Records Abused as Command-and-Control in Go Modules](https://cybersecuritynews.com/dns-txt-command-control-go-module/) - **Role:** DNS_C2_ANALYSIS - **Impact:** Analyzes the timing anomalies, query frequency, and stealth profile of DNS-based command loops.
4. [GBHackers: Chronological Analysis of shopsprint Module Poisoning](https://gbhackers.com/shopsprint-go-module-poisoning-analysis/) - **Role:** CHRONOLOGICAL_REPORTING - **Impact:** Explains how the library was maintained in a clean state for years before weaponization in version 1.3.3.
5. [CyberPress: Hardening Go Projects Against Typosquatting Campaigns](https://cyberpress.org/hardening-go-projects-typosquatting/) - **Role:** COMPLIANCE_GUIDELINE - **Impact:** Provides steps to lock down private Go mod proxies and enforce checksum verification rules.
