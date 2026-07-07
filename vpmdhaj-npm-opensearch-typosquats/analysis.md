---
title: "vpmdhaj npm OpenSearch Typosquats Steal Cloud and CI/CD Secrets"
date: 2026-05-28
severity: "critical"
tags:
  - npm
  - typosquatting
  - supply-chain
  - credential-theft
  - ci-cd
summary: "Microsoft reported 14 typosquatted npm packages under the vpmdhaj scope that impersonated OpenSearch, AWS SDK, STS, and Bun packages while collecting AWS, GitHub Actions, npm, Vault, Kubernetes, SSH, and local cloud configuration secrets."
sourceCount: 6
---

## Executive Summary
Microsoft Threat Intelligence reported a 14-package npm typosquat cluster under the `vpmdhaj` scope on May 28, 2026 [[microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)]. The packages impersonated OpenSearch, AWS SDK, STS, and Bun-adjacent names, then attempted to collect cloud and CI/CD credentials from developer and build environments [[microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)].

The strongest public indicators are the package names, the known malicious version pairs for `@vpmdhaj/opensearch-setup` and `@vpmdhaj/elastic-helper`, the SHA-256 values published by Microsoft, and exfiltration to `aab.sportsontheweb[.]net` over `/api/b` [[microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)]. The npm maintainer and package pages are useful for historical scoping and takedown confirmation, but Microsoft’s writeup is the primary source for behavior and IOCs [[npmjs.com](https://www.npmjs.com/~vpmdhaj)] [[npmjs.com](https://www.npmjs.com/package/@vpmdhaj/elastic-helper)].

Treat a confirmed install or execution in a CI runner, release job, developer workstation, or container build as credential exposure. The package set targeted AWS metadata and credential-provider flows, GitHub Actions OIDC request material, npm tokens, Vault tokens, Kubernetes service accounts, SSH keys, and local cloud configuration files [[microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)] [[docs.aws.amazon.com](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)].

## Key Facts
**Event Type**: npm typosquat credential theft cluster

**Ecosystem**: npm, node, bun, ci-cd, cloud

**Publisher Scope**: vpmdhaj

**Affected Packages**:
- @vpmdhaj/devops-tools
- @vpmdhaj/elastic-helper
- @vpmdhaj/opensearch-setup
- @vpmdhaj/search-setup
- app-config-utility
- elastic-opensearch-helper
- env-config-manager
- opensearch-config-utility
- opensearch-security-scanner
- opensearch-setup
- opensearch-setup-tool
- search-cluster-setup
- search-engine-setup
- vpmdhaj-opensearch-setup

**Known Malicious Versions**:
  - **@vpmdhaj/opensearch-setup**: 1.0.9102,1.0.9103
  - **@vpmdhaj/elastic-helper**: 1.0.7267,1.0.7268,1.0.7269,1.0.7270

**Credential Targets**:
- AWS environment, container, metadata, and web identity credentials
- GitHub Actions OIDC request token material
- npm tokens and npmrc credentials
- Vault tokens
- Kubernetes service account tokens
- SSH keys and local cloud configuration files

**Network Iocs**:
- aab.sportsontheweb[.]net
- www.sportsontheweb[.]net

**Path Iocs**:
- /api/b

**Sha256**:
- a39155771e93e65b05195c8a705dfc03aa85c2ec682505f0d557233a8f275145
- 9d962ed605bb4a39991f8fab9b1d2e423ea4d545f23fd44d9473a6423d94bbf

**Canonical Source**: https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/

## Evidence Assessment
* **confirmed:** Microsoft identified the `vpmdhaj` package set, credential theft behavior, exfiltration endpoint, file hashes, and remediation guidance [[microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)].
* **confirmed:** npm lifecycle scripts can execute during install flows when package manager configuration permits them, which makes package installation itself a relevant execution path to investigate [[docs.npmjs.com](https://docs.npmjs.com/cli/v11/using-npm/scripts)].
* **confirmed:** Bun is a JavaScript runtime and package/tooling context that defenders should include when investigating packages that impersonate Bun-related names or are executed through Bun workflows [[bun.com](https://bun.com/docs/runtime)].
* **confirmed:** AWS metadata and credential provider endpoints are high-value targets because they can return temporary credentials to properly authorized workloads [[docs.aws.amazon.com](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)].
* **unclear:** Public sources do not provide a complete package-version matrix for every package in the cluster. The exact ranges should be recovered from package-lock history, private registry mirrors, package caches, or npm audit logs.
* **not_observed:** Public sources do not currently prove compromise of legitimate OpenSearch, AWS SDK, STS, or Bun packages.

## Impact Determination
| Classification | Criteria | Required evidence | Handling decision |
| --- | --- | --- | --- |
| Confirmed compromise | A `vpmdhaj` package was installed or executed and credential collection or exfiltration indicators are observed. | Lockfile or package cache hit plus process, network, shell, CI, proxy, EDR, or CloudTrail evidence for the same environment. | Isolate the host or runner, preserve artifacts, rotate reachable credentials from a clean environment, and review downstream account activity. |
| Presumed exposed | A `vpmdhaj` package is present in a CI runner, release job, developer environment, container build, or package cache, but runtime telemetry is incomplete. | Manifest, lockfile, package-manager log, npm cache, private registry, or image layer evidence. | Treat secrets reachable from the environment as exposed unless negative telemetry proves non-execution and no lifecycle script execution. |
| Potentially exposed | A repository references OpenSearch, AWS SDK, STS, or Bun dependencies and package resolution history is missing. | Dependency manifests, lockfiles, private registry logs, npm proxy logs, CI job histories, and package-manager cache exports. | Reconstruct package resolution and execution before narrowing scope. |
| Not exposed | No package names, versions, hashes, domains, exfiltration paths, or credential marker behavior appear in dependency, cache, runtime, network, or audit evidence. | Negative search across repositories, package caches, runners, images, proxy logs, EDR telemetry, and cloud audit logs. | Preserve negative evidence and enforce package namespace and lifecycle-script controls. |
| Unknown | Required dependency, package-cache, runner, endpoint, proxy, or cloud telemetry is unavailable. | Named telemetry gap with owner, system, and retention window. | Keep credentials reachable from the environment in scope until evidence is recovered or risk owners accept rotation as closure. |

### Minimum Evidence To Collect
**Dependency Evidence**:
- package.json, package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock, bun.lock, bun.lockb
- private npm proxy and registry access logs
- npm, npx, pnpm, yarn, bun, and CI package install logs

**Runtime Evidence**:
- process command lines for npm, npx, node, bun, postinstall, and lifecycle scripts
- network logs for aab.sportsontheweb[.]net, www.sportsontheweb[.]net, and /api/b
- file access telemetry for .aws/config, .aws/credentials, .vault-token, npmrc files, SSH keys, and Kubernetes service account tokens

**Cloud Evidence**:
- AWS CloudTrail GetCallerIdentity, AssumeRole, AssumeRoleWithWebIdentity, and unusual session activity
- GitHub Actions OIDC token request logs and workflow run histories
- npm token creation, use, publish, and revocation logs

## Timeline
* **2026-05-28:** Microsoft published the analysis and IOCs for the `vpmdhaj` typosquat cluster [[microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)].
* **2026-05-28:** Microsoft stated that the 14 malicious packages were removed from npm and that affected users should rotate exposed credentials [[microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)].
* **2026-05-29:** This Halting Problems packet was added after dedupe confirmed no existing local post covered the `vpmdhaj` package set, `aab.sportsontheweb[.]net`, or the published hashes.

## What Happened
The actor created npm packages under the `vpmdhaj` scope with names close to packages and concepts a cloud or OpenSearch user might expect to install. Microsoft’s package list includes OpenSearch-themed names, AWS credential provider and STS-themed names, and a Bun-themed package [[microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)].

The payload behavior was credential oriented. Microsoft reported collection logic for environment variables, AWS credential sources, GitHub Actions OIDC request material, npm credentials, Vault tokens, Kubernetes service account tokens, SSH material, and local cloud configuration files [[microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)]. That makes the blast radius different from a simple developer workstation compromise: the same install in a CI runner may expose deployment credentials, cloud role sessions, registry tokens, and release automation paths.

Exfiltration used `aab.sportsontheweb[.]net` with the `/api/b` path, and Microsoft published two SHA-256 values for associated artifacts [[microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)]. In human-facing material, keep the domains defanged; use the machine-readable event profile and the audit script when exact matching is required.

## Technical Analysis
### Package and Registry Abuse
**Registry**: npm

**Scope**: vpmdhaj

**Impersonated Areas**:
- OpenSearch client and setup packages
- AWS SDK and credential provider packages
- AWS STS client packages
- Bun runtime/tooling package naming [1]

**Delivery Paths**:
- direct npm install
- npx-style ephemeral execution
- CI dependency restore
- container build dependency install
- Bun workflow dependency install or execution [1]

The public evidence does not show compromise of the real upstream projects. The risk is dependency confusion by name, typo, or malicious copycat package selection under an attacker-controlled npm scope [[microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)] [[npmjs.com](https://www.npmjs.com/~vpmdhaj)] [[npmjs.com](https://www.npmjs.com/package/@vpmdhaj/elastic-helper)].

### Execution Triggers
npm lifecycle scripts are a key collection point because package scripts can run during install-related flows unless disabled or blocked by policy [[docs.npmjs.com](https://docs.npmjs.com/cli/v11/using-npm/scripts)]. Bun also belongs in the scoping plan because Microsoft included a Bun-themed package name and Bun can execute JavaScript package workflows in environments that may not leave npm-style process names in telemetry [[microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)] [[bun.com](https://bun.com/docs/runtime)].

### Credential Collection
The cluster’s collection logic should be scoped as a multi-secret incident, not a single AWS-key event. Microsoft called out AWS credential flows, GitHub Actions OIDC request variables, npm credentials, Vault token material, Kubernetes service account files, local cloud configuration paths, and SSH material [[microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)]. AWS metadata services and container credential endpoints are especially sensitive because successful access can return temporary workload credentials [[docs.aws.amazon.com](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)].

### Exfiltration
**Domains**:
- aab.sportsontheweb[.]net
- www.sportsontheweb[.]net

**Urls**:
- hxxps://aab[.]sportsontheweb[.]net/api/b

**Http Headers**:
- x-forwarded-host

**Hashes Sha256**:
- a39155771e93e65b05195c8a705dfc03aa85c2ec682505f0d557233a8f275145
- 9d962ed605bb4a39991f8fab9b1d2e423ea4d545f23fd44d9473a6423d94bbf [1]

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: npm,Node.js,Bun,AWS,GitHub Actions,Vault,Kubernetes
  - **environments**: developer workstations,CI runners,release automation,container builds,private package mirrors,package-manager caches
  - **secret_material**: AWS access keys and temporary credentials,AWS web identity and container credentials,GitHub Actions OIDC request tokens,npm tokens,Vault tokens,Kubernetes service account tokens,SSH private keys,local cloud config files

**Not Currently Known To Affect**:
- legitimate OpenSearch packages
- legitimate AWS SDK packages
- legitimate Bun releases

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- a39155771e93e65b05195c8a705dfc03aa85c2ec682505f0d557233a8f275145
- 9d962ed605bb4a39991f8fab9b1d2e423ea4d545f23fd44d9473a6423d94bbf

### Domains
- aab[.]sportsontheweb[.]net
- www[.]sportsontheweb[.]net


## Detection and Hunting

### Hunt Manifest: vpmdhaj-npm-opensearch-typosquats-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with vpmdhaj npm OpenSearch Typosquats Steal Cloud and CI/CD Secrets?
- **Telemetry Family:** process
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
"""Generic IOC scope scanner for vpmdhaj-npm-opensearch-typosquats.

Searches repository trees and exported logs for literal IOC values from iocs.json.
Exit codes:
  0: no matches
  1: one or more indicators matched
  2: execution error
"""
import argparse
import fnmatch
import os
import sys
from pathlib import Path

OUT = Path(os.environ.get("OUT", "hp-vpmdhaj-npm-opensearch-typosquats-ioc-scope"))
CONTENT_INDICATORS = [
  "@vpmdhaj/opensearch-setup@1.0.9102",
  "@vpmdhaj/opensearch-setup@1.0.9103",
  "@vpmdhaj/elastic-helper@1.0.7267",
  "@vpmdhaj/elastic-helper@1.0.7268",
  "@vpmdhaj/elastic-helper@1.0.7269",
  "@vpmdhaj/elastic-helper@1.0.7270",
  "@vpmdhaj/devops-tools@1.0.0",
  "@vpmdhaj/search-setup@1.0.0",
  "app-config-utility@1.0.0",
  "elastic-opensearch-helper@1.0.0",
  "env-config-manager@1.0.0",
  "opensearch-config-utility@1.0.0",
  "opensearch-security-scanner@1.0.0",
  "opensearch-setup@1.0.0",
  "opensearch-setup-tool@1.0.0",
  "search-cluster-setup@1.0.0",
  "search-engine-setup@1.0.0",
  "vpmdhaj-opensearch-setup@1.0.0",
  "@vpmdhaj/aws-compat@1.0.0",
  "@vpmdhaj/aws-credential-provider-env@1.0.0",
  "@vpmdhaj/aws-credential-provider-http@1.0.0",
  "@vpmdhaj/aws-sdk-client-opensearch@1.0.0",
  "@vpmdhaj/aws-sdk-client-sts@1.0.0",
  "@vpmdhaj/aws-sdk-credential-provider-node@1.0.0",
  "@vpmdhaj/aws-sdk-types@1.0.0",
  "@vpmdhaj/bun@1.0.0",
  "@vpmdhaj/opensearch@1.0.0",
  "@vpmdhaj/opensearch-project@1.0.0",
  "@vpmdhaj/opensearch-js@1.0.0",
  "@vpmdhaj/sts-client@1.0.0",
  "a39155771e93e65b05195c8a705dfc03aa85c2ec682505f0d557233a8f275145",
  "9d962ed605bb4a39991f8fab9b1d2e423ea4d545f23fd44d9473a6423d94bbf",
  "aab[.]sportsontheweb[.]net",
  "www[.]sportsontheweb[.]net",
  "@vpmdhaj/opensearch-setup",
  "1.0.9102",
  "1.0.9103",
  "@vpmdhaj/elastic-helper",
  "1.0.7267",
  "1.0.7268",
  "1.0.7269",
  "1.0.7270",
  "@vpmdhaj/devops-tools",
  "1.0.0",
  "@vpmdhaj/search-setup",
  "app-config-utility",
  "elastic-opensearch-helper",
  "env-config-manager",
  "opensearch-config-utility",
  "opensearch-security-scanner",
  "opensearch-setup",
  "opensearch-setup-tool",
  "search-cluster-setup",
  "search-engine-setup",
  "vpmdhaj-opensearch-setup",
  "@vpmdhaj/aws-compat",
  "@vpmdhaj/aws-credential-provider-env",
  "@vpmdhaj/aws-credential-provider-http",
  "@vpmdhaj/aws-sdk-client-opensearch",
  "@vpmdhaj/aws-sdk-client-sts",
  "@vpmdhaj/aws-sdk-credential-provider-node",
  "@vpmdhaj/aws-sdk-types",
  "@vpmdhaj/bun",
  "@vpmdhaj/opensearch",
  "@vpmdhaj/opensearch-project",
  "@vpmdhaj/opensearch-js",
  "@vpmdhaj/sts-client"
]
PATH_INDICATORS = []
EXCLUDE_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}

def _iter_files(root):
    root = Path(root)
    if not root.exists():
        return
    if root.is_file():
        yield root
        return
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for name in files:
            yield Path(current) / name

def _path_matches(path):
    text = str(path)
    matches = []
    for indicator in PATH_INDICATORS:
        if not indicator:
            continue
        if indicator.startswith(("/", "~")):
            candidate = Path(os.path.expanduser(indicator))
            if candidate.exists() and path == candidate:
                matches.append(indicator)
        if indicator in text or fnmatch.fnmatch(text, indicator) or fnmatch.fnmatch(path.name, indicator):
            matches.append(indicator)
    return matches

def _content_matches(path):
    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return []
    return [indicator for indicator in CONTENT_INDICATORS if indicator and indicator in content]

def _scan_roots(roots):
    matches = []
    for root in roots:
        if not root:
            continue
        for path in _iter_files(root):
            for indicator in _path_matches(path):
                matches.append(f"{path}: path matched {indicator!r}")
            for indicator in _content_matches(path):
                matches.append(f"{path}: content matched {indicator!r}")
    return matches

def main():
    parser = argparse.ArgumentParser(description="Scan files and logs for Halting Problems IOC values")
    parser.add_argument("roots", nargs="*", default=["."], help="File or directory roots to scan")
    parser.add_argument("--log-root", default=os.environ.get("LOG_ROOT", ""), help="Optional exported log directory")
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    indicator_lines = sorted(set(CONTENT_INDICATORS + PATH_INDICATORS))
    (OUT / "ioc-indicators.txt").write_text("\n".join(indicator_lines) + "\n")

    roots = list(args.roots)
    if args.log_root:
        roots.append(args.log_root)
    matches = _scan_roots(roots)
    if matches:
        (OUT / "ioc-scope-matches.txt").write_text("\n".join(matches) + "\n")
        print(f"[!] Found {len(matches)} IOC matches; details written under {OUT}")
        return 1
    print(f"[+] No IOC matches found; indicator inventory written under {OUT}")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"[-] Execution failure: {exc}", file=sys.stderr)
        sys.exit(2)
```

### Hunt Manifest: vpmdhaj-npm-opensearch-typosquats-hunt-2
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with vpmdhaj npm OpenSearch Typosquats Steal Cloud and CI/CD Secrets?
- **Telemetry Family:** file
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
"""Generic IOC scope scanner for vpmdhaj-npm-opensearch-typosquats.

Searches repository trees and exported logs for literal IOC values from iocs.json.
Exit codes:
  0: no matches
  1: one or more indicators matched
  2: execution error
"""
import argparse
import fnmatch
import os
import sys
from pathlib import Path

OUT = Path(os.environ.get("OUT", "hp-vpmdhaj-npm-opensearch-typosquats-ioc-scope"))
CONTENT_INDICATORS = [
  "@vpmdhaj/opensearch-setup@1.0.9102",
  "@vpmdhaj/opensearch-setup@1.0.9103",
  "@vpmdhaj/elastic-helper@1.0.7267",
  "@vpmdhaj/elastic-helper@1.0.7268",
  "@vpmdhaj/elastic-helper@1.0.7269",
  "@vpmdhaj/elastic-helper@1.0.7270",
  "@vpmdhaj/devops-tools@1.0.0",
  "@vpmdhaj/search-setup@1.0.0",
  "app-config-utility@1.0.0",
  "elastic-opensearch-helper@1.0.0",
  "env-config-manager@1.0.0",
  "opensearch-config-utility@1.0.0",
  "opensearch-security-scanner@1.0.0",
  "opensearch-setup@1.0.0",
  "opensearch-setup-tool@1.0.0",
  "search-cluster-setup@1.0.0",
  "search-engine-setup@1.0.0",
  "vpmdhaj-opensearch-setup@1.0.0",
  "@vpmdhaj/aws-compat@1.0.0",
  "@vpmdhaj/aws-credential-provider-env@1.0.0",
  "@vpmdhaj/aws-credential-provider-http@1.0.0",
  "@vpmdhaj/aws-sdk-client-opensearch@1.0.0",
  "@vpmdhaj/aws-sdk-client-sts@1.0.0",
  "@vpmdhaj/aws-sdk-credential-provider-node@1.0.0",
  "@vpmdhaj/aws-sdk-types@1.0.0",
  "@vpmdhaj/bun@1.0.0",
  "@vpmdhaj/opensearch@1.0.0",
  "@vpmdhaj/opensearch-project@1.0.0",
  "@vpmdhaj/opensearch-js@1.0.0",
  "@vpmdhaj/sts-client@1.0.0",
  "a39155771e93e65b05195c8a705dfc03aa85c2ec682505f0d557233a8f275145",
  "9d962ed605bb4a39991f8fab9b1d2e423ea4d545f23fd44d9473a6423d94bbf",
  "aab[.]sportsontheweb[.]net",
  "www[.]sportsontheweb[.]net",
  "@vpmdhaj/opensearch-setup",
  "1.0.9102",
  "1.0.9103",
  "@vpmdhaj/elastic-helper",
  "1.0.7267",
  "1.0.7268",
  "1.0.7269",
  "1.0.7270",
  "@vpmdhaj/devops-tools",
  "1.0.0",
  "@vpmdhaj/search-setup",
  "app-config-utility",
  "elastic-opensearch-helper",
  "env-config-manager",
  "opensearch-config-utility",
  "opensearch-security-scanner",
  "opensearch-setup",
  "opensearch-setup-tool",
  "search-cluster-setup",
  "search-engine-setup",
  "vpmdhaj-opensearch-setup",
  "@vpmdhaj/aws-compat",
  "@vpmdhaj/aws-credential-provider-env",
  "@vpmdhaj/aws-credential-provider-http",
  "@vpmdhaj/aws-sdk-client-opensearch",
  "@vpmdhaj/aws-sdk-client-sts",
  "@vpmdhaj/aws-sdk-credential-provider-node",
  "@vpmdhaj/aws-sdk-types",
  "@vpmdhaj/bun",
  "@vpmdhaj/opensearch",
  "@vpmdhaj/opensearch-project",
  "@vpmdhaj/opensearch-js",
  "@vpmdhaj/sts-client"
]
PATH_INDICATORS = []
EXCLUDE_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}

def _iter_files(root):
    root = Path(root)
    if not root.exists():
        return
    if root.is_file():
        yield root
        return
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for name in files:
            yield Path(current) / name

def _path_matches(path):
    text = str(path)
    matches = []
    for indicator in PATH_INDICATORS:
        if not indicator:
            continue
        if indicator.startswith(("/", "~")):
            candidate = Path(os.path.expanduser(indicator))
            if candidate.exists() and path == candidate:
                matches.append(indicator)
        if indicator in text or fnmatch.fnmatch(text, indicator) or fnmatch.fnmatch(path.name, indicator):
            matches.append(indicator)
    return matches

def _content_matches(path):
    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return []
    return [indicator for indicator in CONTENT_INDICATORS if indicator and indicator in content]

def _scan_roots(roots):
    matches = []
    for root in roots:
        if not root:
            continue
        for path in _iter_files(root):
            for indicator in _path_matches(path):
                matches.append(f"{path}: path matched {indicator!r}")
            for indicator in _content_matches(path):
                matches.append(f"{path}: content matched {indicator!r}")
    return matches

def main():
    parser = argparse.ArgumentParser(description="Scan files and logs for Halting Problems IOC values")
    parser.add_argument("roots", nargs="*", default=["."], help="File or directory roots to scan")
    parser.add_argument("--log-root", default=os.environ.get("LOG_ROOT", ""), help="Optional exported log directory")
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    indicator_lines = sorted(set(CONTENT_INDICATORS + PATH_INDICATORS))
    (OUT / "ioc-indicators.txt").write_text("\n".join(indicator_lines) + "\n")

    roots = list(args.roots)
    if args.log_root:
        roots.append(args.log_root)
    matches = _scan_roots(roots)
    if matches:
        (OUT / "ioc-scope-matches.txt").write_text("\n".join(matches) + "\n")
        print(f"[!] Found {len(matches)} IOC matches; details written under {OUT}")
        return 1
    print(f"[+] No IOC matches found; indicator inventory written under {OUT}")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"[-] Execution failure: {exc}", file=sys.stderr)
        sys.exit(2)
```

## Remediation and Closure
1. Remove all `@vpmdhaj/*` dependencies and clear package-manager caches, private registry mirrors, CI caches, and container layers that contain the packages.
2. Rebuild affected artifacts from clean dependency locks and with npm lifecycle scripts disabled unless explicitly required.
3. Rotate AWS keys and sessions, GitHub Actions secrets and OIDC trust assumptions, npm automation tokens, Vault tokens, Kubernetes service account tokens, SSH keys, and any deployment credentials reachable from matching environments.
4. Review CloudTrail, GitHub audit logs, npm publish/access logs, Vault audit logs, Kubernetes audit logs, and proxy logs for follow-on use after the first package hit.
5. Add namespace deny rules for `@vpmdhaj/*`, require dependency review on new scoped packages, and alert on package manager execution from release and deployment jobs.

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Sources
1. [Microsoft Threat Intelligence: Typosquatted npm packages used to steal cloud and CI/CD secrets](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)
2. [npm maintainer profile: vpmdhaj](https://www.npmjs.com/~vpmdhaj)
3. [npm package page: @vpmdhaj/elastic-helper](https://www.npmjs.com/package/@vpmdhaj/elastic-helper)
4. [npm CLI documentation: scripts](https://docs.npmjs.com/cli/v11/using-npm/scripts)
5. [Bun documentation: runtime](https://bun.com/docs/runtime)
6. [AWS documentation: Instance metadata and user data](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
