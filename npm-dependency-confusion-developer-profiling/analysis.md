---
title: "Microsoft-tracked npm dependency-confusion developer-profiling campaign"
date: 2026-05-29
severity: "critical"
tags:
  - npm
  - dependency-confusion
  - supply-chain
  - ci-cd
  - developer-profiling
  - credential-theft
summary: "Microsoft attributed a 33-package npm dependency-confusion campaign to shared postinstall tradecraft that profiled developer environments, ran in reconnaissance-only mode, and beaconed to a shared command-and-control endpoint."
sourceCount: 4
---

## Executive Summary

Microsoft reported a dependency-confusion campaign that spread across multiple npm organizational scopes and used malicious postinstall payloads to profile developer environments during installation. The payloads collected host and environment metadata, ran in a reconnaissance-only mode, and used a shared command-and-control path with a common `X-Secret` header. The public article names 33 malicious packages overall, but the full package set is not exhaustively enumerated in the HTML, so this report preserves that uncertainty while documenting the directly observed artifacts.

The three registry artifacts in the candidate set all resolve to the same security-holding `0.0.1-security` release, which makes them useful anchors for hunting in lockfiles, package caches, build logs, and exported telemetry. The operational pattern is most relevant to developer endpoints, CI runners, and any environment where npm, Node.js, or Bun package installation can execute lifecycle hooks.

## Key Facts

- **Campaign type:** npm dependency confusion with developer profiling and postinstall execution
- **Reported scale:** 33 malicious packages across multiple organizational scopes [1]
- **Known packages in this candidate set:** `@cloudplatform-single-spa/logaas`, `@capibar.chat/ui-kit`, `@sber-ecom-core/sberpay-widget`
- **Known malicious versions:** `0.0.1-security` for the three registry artifacts [2] [3] [4]
- **Behavioral indicators:** `postinstall`, `RECON_ONLY`, `X-Secret`, and beaconing to `oob[.]moika[.]tech`
- **Primary exposure surface:** developer workstations, CI runners, and build environments that install dependencies from npm
- **Collection gap:** the public article indicates a broader cluster, but not every package artifact is surfaced in the HTML

## Evidence Assessment

| Claim | Status | Evidence |
| --- | --- | --- |
| Microsoft tracked a 33-package npm dependency-confusion campaign that profiled developer environments. | confirmed | The Microsoft article title and body describe the campaign at scale and its focus on profiling developer systems [1]. |
| The three registry artifacts resolve to a shared security-holding version. | confirmed | Each registry endpoint shows `0.0.1-security` as the published version [2] [3] [4]. |
| The payload runs during installation and uses a recon-only design. | confirmed | Microsoft describes a postinstall stager, a reconnaissance-only mode, and a server-side `RECON_ONLY` flag [1]. |
| The campaign uses shared infrastructure and a common `X-Secret` header. | confirmed | Microsoft documents a shared C2 endpoint and a common `X-Secret` header across the cluster [1]. |
| The public HTML exposes the complete package list. | not_observed | Microsoft describes the larger cluster, but the HTML available here does not fully enumerate every malicious registry artifact [1]. |

## Impact Determination

| Classification | Criteria | Handling |
| --- | --- | --- |
| Confirmed compromise | An affected package/version is installed and telemetry shows postinstall execution, outbound beaconing, or the `X-Secret` / `RECON_ONLY` indicators. | Isolate the host or runner, preserve artifacts, and rotate reachable credentials from a clean system. |
| Presumed exposed | An affected package/version resolved in a build or workstation, but runtime telemetry is incomplete. | Treat exposed credentials as compromised until clean rebuilds and log review complete. |
| Potentially exposed | Repositories or builds reference the package names, but exact resolution is unclear. | Reconstruct lockfiles, caches, and install logs before narrowing scope. |
| Not exposed | Complete evidence sets show none of the package names, versions, or behavioral indicators. | Preserve negative evidence and keep lifecycle-script controls in place. |
| Unknown | Dependency inventory or telemetry is missing. | Keep credentials in scope until evidence is recovered or the risk owner accepts residual uncertainty. |

## Minimum Evidence To Collect

- **Lockfiles and package caches** because they prove whether the malicious version resolved on the machine, which is the fastest way to confirm exposure for npm, Bun, or CI installs.
- **Package manager logs and shell history** because they can show the actual install command, the lifecycle hook invocation, and whether the host used `npm install` or another resolver.
- **Endpoint process telemetry** because the campaign depends on install-time execution, so a `node` or `bun` child process can turn an ambiguous package hit into a confirmed execution path.
- **Proxy, DNS, and EDR network logs** because they can reveal the outbound beaconing pattern to `oob[.]moika[.]tech` and any request carrying the shared `X-Secret` header.
- **CI job logs and workflow artifacts** because build systems are the likely place where package resolution, lifecycle hooks, and credential reachability intersect.

## Timeline

- **2026-05-29:** Microsoft publishes the article describing the campaign, its shared infrastructure, and the developer-profiling tradecraft [1].
- **2026-05-29:** The three registry endpoints in this candidate set resolve to the `0.0.1-security` release [2] [3] [4].
- **2026-05-29:** This report consolidates the three registry artifacts with the broader Microsoft-documented cluster and preserves the remaining enumeration gap.

## What Happened

Microsoft describes a two-burst dependency-confusion campaign that used malicious npm packages to execute a postinstall stager during dependency installation. The stager ran in a recon-only posture, gathered system information, hostnames, environment variables, and developer context, and then beaconed outward using a shared infrastructure pattern [1].

The article also notes that the packages impersonated internal enterprise dependencies across multiple organizational scopes. That matters operationally because the attack does not need a production server compromise to succeed; a single developer workstation or CI runner can expose npm tokens, GitHub credentials, cloud credentials, and other secrets reachable from the installation environment [1].

## Technical Analysis

The campaign is technically significant because it combines dependency confusion with install-time execution and post-exploitation readiness. Microsoft describes the payload as a heavily obfuscated `postinstall` stager that runs silently during `npm install`, gathers developer profiling data, and uses a shared `RECON_ONLY` flag that can be switched server-side for follow-on exploitation [1]. That means the malicious behavior is not limited to a one-time fetch: the same infrastructure can support staged escalation if exposed environments are useful enough to revisit.

The shared `X-Secret` header and the common `oob[.]moika[.]tech` endpoint provide strong hunting handles. Microsoft’s article attributes the same operator tradecraft across multiple organizational scopes, and the public HTML shows package families such as `@cloudplatform-single-spa/logaas`, `@capibar.chat/ui-kit`, and `@sber-ecom-core/sberpay-widget` among the broader set [1]. The registry endpoints for those three packages all report the same `0.0.1-security` release, which makes them especially important for lockfile, cache, and artifact triage [2] [3] [4].

A practical reading of the campaign is that a single install on a workstation or runner can be enough to expose more than one credential class. Even if the operator only wants reconnaissance first, the profile data can later steer targeted credential theft or cloud abuse from a more valuable environment [1].

## Affected Assets and Blast Radius

The machine-readable profile keeps the package names canonical and unversioned in `affected_assets.packages`, while version-specific exposure is recorded separately in `iocs.package_versions`. That split matters because the broader cluster is still incompletely enumerated in public HTML, but the known artifacts are enough to support targeted hunting.

The most likely blast radius includes:

- developer laptops with npm, Node.js, or Bun installed
- CI runners that execute package lifecycle scripts
- build containers that cache npm installs or preserve workspace artifacts
- release engineering systems that hold publishing tokens, cloud keys, or GitHub credentials

Because the payload is install-time and reconnaissance-driven, the blast radius should not be constrained to source repositories alone. Package caches, logs, and ephemeral build workspaces are just as important as checked-in code.

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:


## Detection and Hunting

### Hunt Manifest: npm-dependency-confusion-developer-profiling-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Microsoft-tracked npm dependency-confusion developer-profiling campaign?
- **Telemetry Family:** network
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
"""Generic IOC scope scanner for npm-dependency-confusion-developer-profiling.

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

OUT = Path(os.environ.get("OUT", "hp-npm-dependency-confusion-developer-profiling-ioc-scope"))
CONTENT_INDICATORS = [
  "@capibar.chat/ui-kit@0.0.1-security",
  "@ce-rwb/ce-tools-editor-admin@0.0.1-security",
  "@ce-rwb/ce-tools-editor-core@0.0.1-security",
  "@ce-rwb/ce-tools-editor-render@0.0.1-security",
  "@cloudplatform-single-spa/logaas@0.0.1-security",
  "@data-science/llm@0.0.1-security",
  "@payments-widget/payments-widget-sdk@0.0.1-security",
  "@sber-ecom-core/sberpay-widget@0.0.1-security",
  "@t-in-one/add_app_middleware_token@0.0.1-security",
  "@t-in-one/add_application@0.0.1-security",
  "@t-in-one/add_application_service_token@0.0.1-security",
  "@t-in-one/add_application_tid@0.0.1-security",
  "@t-in-one/application_id_storage_key_token@0.0.1-security",
  "@t-in-one/form_product_token@0.0.1-security",
  "@t-in-one/get_application_hid@0.0.1-security",
  "@t-in-one/only_difference_payload@0.0.1-security",
  "@t-in-one/prefill_bundle_data_token@0.0.1-security",
  "@t-in-one/prefill_credit_data_token@0.0.1-security",
  "@travel-autotests/npm-proto@0.0.1-security",
  "@wb-track/shared-front@0.0.1-security",
  "@wordpress/interactivity@0.0.1-security",
  "@wordpress/interactivity-js-modulepreload@0.0.1-security",
  "oob.moika.tech",
  "https://oob.moika.tech/payload",
  "https://github.cloudplatform-single-spa.io/platform/svp-baas.git",
  "https://docs.cloudplatform-single-spa.io/platform/svp-baas",
  "https://jira.cloudplatform-single-spa.io/projects/PLATFORM",
  "postinstall",
  "npm lifecycle hook",
  "dependency confusion",
  "developer environment fingerprinting",
  "credential reconnaissance",
  "developer context",
  "environment variables",
  "hostname",
  "RECON_ONLY",
  "POST /payload to oob.moika.tech with X-Secret",
  "npm registry metadata lookups for the affected scopes",
  "@capibar.chat/ui-kit",
  "0.0.1-security",
  "@ce-rwb/ce-tools-editor-admin",
  "@ce-rwb/ce-tools-editor-core",
  "@ce-rwb/ce-tools-editor-render",
  "@cloudplatform-single-spa/logaas",
  "@data-science/llm",
  "@payments-widget/payments-widget-sdk",
  "@sber-ecom-core/sberpay-widget",
  "@t-in-one/add_app_middleware_token",
  "@t-in-one/add_application",
  "@t-in-one/add_application_service_token",
  "@t-in-one/add_application_tid",
  "@t-in-one/application_id_storage_key_token",
  "@t-in-one/form_product_token",
  "@t-in-one/get_application_hid",
  "@t-in-one/only_difference_payload",
  "@t-in-one/prefill_bundle_data_token",
  "@t-in-one/prefill_credit_data_token",
  "@travel-autotests/npm-proto",
  "@wb-track/shared-front",
  "@wordpress/interactivity",
  "@wordpress/interactivity-js-modulepreload"
]
PATH_INDICATORS = [
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "scripts/postinstall.js",
  ".npmrc",
  ".github/workflows/*.yml"
]
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

### Hunt Manifest: npm-dependency-confusion-developer-profiling-hunt-2
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Microsoft-tracked npm dependency-confusion developer-profiling campaign?
- **Telemetry Family:** file
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
"""Generic IOC scope scanner for npm-dependency-confusion-developer-profiling.

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

OUT = Path(os.environ.get("OUT", "hp-npm-dependency-confusion-developer-profiling-ioc-scope"))
CONTENT_INDICATORS = [
  "@capibar.chat/ui-kit@0.0.1-security",
  "@ce-rwb/ce-tools-editor-admin@0.0.1-security",
  "@ce-rwb/ce-tools-editor-core@0.0.1-security",
  "@ce-rwb/ce-tools-editor-render@0.0.1-security",
  "@cloudplatform-single-spa/logaas@0.0.1-security",
  "@data-science/llm@0.0.1-security",
  "@payments-widget/payments-widget-sdk@0.0.1-security",
  "@sber-ecom-core/sberpay-widget@0.0.1-security",
  "@t-in-one/add_app_middleware_token@0.0.1-security",
  "@t-in-one/add_application@0.0.1-security",
  "@t-in-one/add_application_service_token@0.0.1-security",
  "@t-in-one/add_application_tid@0.0.1-security",
  "@t-in-one/application_id_storage_key_token@0.0.1-security",
  "@t-in-one/form_product_token@0.0.1-security",
  "@t-in-one/get_application_hid@0.0.1-security",
  "@t-in-one/only_difference_payload@0.0.1-security",
  "@t-in-one/prefill_bundle_data_token@0.0.1-security",
  "@t-in-one/prefill_credit_data_token@0.0.1-security",
  "@travel-autotests/npm-proto@0.0.1-security",
  "@wb-track/shared-front@0.0.1-security",
  "@wordpress/interactivity@0.0.1-security",
  "@wordpress/interactivity-js-modulepreload@0.0.1-security",
  "oob.moika.tech",
  "https://oob.moika.tech/payload",
  "https://github.cloudplatform-single-spa.io/platform/svp-baas.git",
  "https://docs.cloudplatform-single-spa.io/platform/svp-baas",
  "https://jira.cloudplatform-single-spa.io/projects/PLATFORM",
  "postinstall",
  "npm lifecycle hook",
  "dependency confusion",
  "developer environment fingerprinting",
  "credential reconnaissance",
  "developer context",
  "environment variables",
  "hostname",
  "RECON_ONLY",
  "POST /payload to oob.moika.tech with X-Secret",
  "npm registry metadata lookups for the affected scopes",
  "@capibar.chat/ui-kit",
  "0.0.1-security",
  "@ce-rwb/ce-tools-editor-admin",
  "@ce-rwb/ce-tools-editor-core",
  "@ce-rwb/ce-tools-editor-render",
  "@cloudplatform-single-spa/logaas",
  "@data-science/llm",
  "@payments-widget/payments-widget-sdk",
  "@sber-ecom-core/sberpay-widget",
  "@t-in-one/add_app_middleware_token",
  "@t-in-one/add_application",
  "@t-in-one/add_application_service_token",
  "@t-in-one/add_application_tid",
  "@t-in-one/application_id_storage_key_token",
  "@t-in-one/form_product_token",
  "@t-in-one/get_application_hid",
  "@t-in-one/only_difference_payload",
  "@t-in-one/prefill_bundle_data_token",
  "@t-in-one/prefill_credit_data_token",
  "@travel-autotests/npm-proto",
  "@wb-track/shared-front",
  "@wordpress/interactivity",
  "@wordpress/interactivity-js-modulepreload"
]
PATH_INDICATORS = [
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "scripts/postinstall.js",
  ".npmrc",
  ".github/workflows/*.yml"
]
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

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Remediation and Closure

1. Remove the affected package versions from active dependency graphs and rebuild from a clean source state.
2. Rotate any credentials that were reachable from the installed environment, including npm, GitHub, cloud, and deployment secrets.
3. Purge package caches, build workspaces, and ephemeral CI artifacts that may still contain the malicious release or its outputs.
4. Add lifecycle-script restrictions, provenance checks, and tighter dependency-confusion controls for developer workstations and CI runners.
5. Close the incident only after lockfiles, caches, and telemetry confirm that the affected package versions did not execute or that all reachable credentials were rotated.

## Sources

1. [Microsoft Security Blog - 33 malicious npm packages abuse dependency confusion to profile developer environments](https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/)
2. [npm registry - @cloudplatform-single-spa/logaas](https://registry.npmjs.org/@cloudplatform-single-spa%2flogaas)
3. [npm registry - @capibar.chat/ui-kit](https://registry.npmjs.org/@capibar.chat%2fui-kit)
4. [npm registry - @sber-ecom-core/sberpay-widget](https://registry.npmjs.org/@sber-ecom-core%2fsberpay-widget)
