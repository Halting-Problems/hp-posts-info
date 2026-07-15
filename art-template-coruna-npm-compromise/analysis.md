---
title: "art-template npm Coruna Browser Exploit Compromise"
date: 2026-05-24
severity: "high"
tags:
  - supply-chain
  - npm
  - browser
  - javascript
  - exploit-delivery
summary: "Unauthorized art-template releases 4.13.3, 4.13.5, and 4.13.6 modified the browser bundle to load remote JavaScript. The later chain delivered a Coruna iOS exploit framework; npm has removed 4.13.5 and 4.13.6, while 4.13.2 remains the last verified clean release."
sourceCount: 5
---

## Executive Summary

The npm package `art-template` was used to deliver remote browser-side JavaScript after publishing control moved away from the original maintainer. Artifact analysis identifies unauthorized loaders in `4.13.3`, `4.13.5`, and `4.13.6`; `4.13.4` does not contain the observed loader but was published by the same unauthorized account and should not be treated as a trusted recovery release [SafeDep](https://safedep.io/art-template-npm-supply-chain-compromise/) [Socket](https://socket.dev/blog/coruna-respawned-compromised-art-template-npm-package).

The affected code is in `lib/template-web.js`. It executes when the browser bundle is loaded directly or included in a client-side build; the package has no malicious install hook, and the Node.js entry point does not import that browser bundle. The 2026 payload chain led to a Coruna-like iOS exploit framework with Safari/iOS gating and staged remote modules.

As of **2026-06-10**, the npm registry has removed metadata and tarballs for `4.13.5` and `4.13.6`, sets `latest` to `4.13.4`, and retains `4.13.2` as the last release published by the original `aui` account [npm registry](https://registry.npmjs.org/art-template). Because `4.13.4` was published by the unauthorized `v4v5qc` account, defenders should pin to `4.13.2` or replace the package rather than follow `latest`.

## Key Facts

**Threat Type**: npm package compromise and browser exploit delivery

**Package**: art-template

**Verified Unauthorized Loader Versions**:
- 4.13.3
- 4.13.5
- 4.13.6

**Anomalous No Loader Observed**:
- 4.13.4

**Last Verified Clean Version**:
- 4.13.2

**Compromised File**: lib/template-web.js

**Execution Trigger**: browser executes the packaged UMD bundle

**Install Hook**: none observed

**Registry Status**:
  - **latest**: 4.13.4
  - **removed_versions**: 4.13.5,4.13.6

**Confidence**: high

**Last Verified**: 2026-06-10

## Evidence Assessment

- **confirmed:** Repacked npm artifacts for `4.13.2`, `4.13.3`, and `4.13.4` match registry integrity metadata.
- **confirmed:** `4.13.3` contains an appended `String.fromCharCode` loader for `git[.]youzzjizz[.]com/git[.]js` and contains only six files, breaking normal Node.js use.
- **confirmed:** Research copies of `4.13.5` and `4.13.6` contain plaintext loaders for `v3[.]jiathis[.]com`; npm no longer serves those tarballs.
- **confirmed:** `4.13.4` has no observed remote loader, but it was published by the same unauthorized publisher as `4.13.3`.
- **confirmed:** The original author's GitHub warning was deleted and now returns HTTP 410 [GitHub issue 665](https://github.com/goofychris/art-template/issues/665).
- **unknown:** Public evidence does not quantify websites that deployed the poisoned bundle or end users successfully compromised through this package path.

### Artifact Verification

**Registry Artifacts**:
  - **art-template_4_13_2**: [object Object]
  - **art-template_4_13_3**: [object Object]
  - **art-template_4_13_4**: [object Object]

**Removed Artifacts Reported By Research**:
  - **art-template_4_13_5_sha256**: 5b5fe5d92808a732d0d44246cd706295cc739ed7f4dcae19112df666bc5d4f7d
  - **art-template_4_13_6_sha256**: 101afde88ff8b5c02fd341eda55022a39203088c2ff11dcb73214911cf5afb77

## Impact Determination

| Classification | Criteria | Required evidence | Required action |
| --- | --- | --- | --- |
| Confirmed browser exposure | A deployed or cached asset contains an unauthorized loader or listed network indicator and was served to users. | Bundle hash/content hit, deployment timestamps, CDN metadata, and request logs. | Replace the dependency, rebuild from a clean cache, purge all caches, and preserve affected-session telemetry. |
| Presumed exposed | A frontend build used `4.13.3`, `4.13.5`, or `4.13.6`, but deployed assets are unavailable. | Lockfile, build logs, SBOM, and deployment records. | Rebuild and purge without waiting for proof of browser execution. |
| Potentially exposed | `4.13.4` or an affected version exists in a dependency tree, but browser bundling is unproven. | Import graph and production asset search. | Pin to `4.13.2` or replace the package, then verify no loader reached assets. |
| Not exposed | No unauthorized release or loader exists in lockfiles, caches, bundles, or deployed objects. | Source, package-cache, build-artifact, and CDN searches. | Preserve the negative evidence and add browser-bundle scanning. |

## Timeline

- **2018-11-13:** Original maintainer `aui` publishes `4.13.2`, the last verified clean release.
- **2025-03-12:** `v4v5qc` publishes `4.13.3` with an encoded browser loader.
- **2025-03-14:** `v4v5qc` publishes `4.13.4`; no loader is observed, but provenance remains unauthorized.
- **2026-05-19:** `npmpacketmaintainmember7` publishes `4.13.5` with a plaintext loader.
- **2026-05-20:** The same account publishes `4.13.6`; Socket and the original author disclose the compromise.
- **2026-05-21:** Registry metadata is modified; `4.13.5` and `4.13.6` are removed and `latest` points to `4.13.4`.
- **2026-06-10:** Registry state and available tarballs revalidated.

## Technical Analysis

`4.13.3` appends an obfuscated script loader to the UMD browser bundle. `4.13.5` and `4.13.6` append a `loadScript()` function that creates a script element and loads attacker-selected JavaScript. The Node.js entry point is not the trigger. [1]

The later delivery chain fingerprints the browser, applies Safari/iOS and anti-analysis gates, and requests content-addressed modules from downstream infrastructure. SafeDep reports that the retrieved modules match the Coruna exploit kit described by Google Threat Intelligence Group, including coverage of iOS 13 through 17.2.1 [Google GTIG](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit). [1]

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c
- 8064d4e0322f069b3dba13e7957ff0ca7dab7984
- 6e79ae622b7ef30f31fdbcc2dc65339e

### Domains
- git[.]youzzjizz[.]com
- v3[.]jiathis[.]com
- utaq.cfww.shop
- cfww.shop
- l1ewsu3yjkqeroy[.]xyz
- hm[.]baidu[.]com

### Urls
- hxxps://git[.]youzzjizz[.]com/git[.]js
- hxxps://v3[.]jiathis[.]com/code/jia[.]js?uid=artemplate
- hxxps://v3[.]jiathis[.]com/code/art[.]js
- hxxps://utaq[.]cfww[.]shop/gooll/49554fde7424c31c[.]js
- hxxps://l1ewsu3yjkqeroy[.]xyz/api/ip-sync/sync


## Detection and Hunting

### Hunt Manifest: art-template-coruna-npm-compromise-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with art-template npm Coruna Browser Exploit Compromise?
- **Telemetry Family:** file
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-art-template-coruna-npm-compromise-scope"))

VERSIONS = ["art-template 4.13.3","art-template 4.13.5","art-template 4.13.6"]
FILES = ["lib/template-web.js","49554fde7424c31c.js"]
DOMAINS = ["git[.]youzzjizz[.]com","v3[.]jiathis[.]com","utaq.cfww.shop","cfww.shop","l1ewsu3yjkqeroy[.]xyz","hm[.]baidu[.]com"]
URLS = ["https://git.youzzjizz.com/git.js","https://v3.jiathis.com/code/jia.js?uid=artemplate","https://v3.jiathis.com/code/art.js","https://utaq.cfww.shop/gooll/49554fde7424c31c.js","https://l1ewsu3yjkqeroy.xyz/api/ip-sync/sync"]
HASHES = ["f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c","8064d4e0322f069b3dba13e7957ff0ca7dab7984","6e79ae622b7ef30f31fdbcc2dc65339e"]

# Collect unique indicators
OUT.mkdir(parents=True, exist_ok=True)
indicators_file = OUT / "ioc-indicators.txt"
indicators = set()
for group in [VERSIONS, FILES, DOMAINS, URLS, HASHES]:
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

print(f"[+] Wrote scope artifacts under {OUT}")
```

## Remediation and Closure

1. Pin to `art-template@4.13.2` or replace the dependency. Do not use the current `latest` tag as a trust decision.
2. Delete package-manager and CI caches that may contain removed tarballs.
3. Rebuild browser assets from a verified dependency graph.
4. Purge CDN, service-worker, edge, and origin caches by object, not only by HTML route.
5. Search web telemetry for the listed domains, paths, and IPs and identify affected sessions.
6. Close only after clean bundles are deployed, stale objects are purged, and production requests no longer contain the selectors.

## Sources

1. [Socket: Coruna Respawned](https://socket.dev/blog/coruna-respawned-compromised-art-template-npm-package) - **Role:** PRIMARY_RESEARCH - **Impact:** Package compromise, browser-loader chain, payload analysis, and initial IOCs.
2. [SafeDep: art-template npm supply-chain compromise](https://safedep.io/art-template-npm-supply-chain-compromise/) - **Role:** PRIMARY_RESEARCH - **Impact:** Reproducible artifact diffs, publisher trail, hashes, expanded IOCs, and Coruna validation.
3. [npm registry: art-template](https://registry.npmjs.org/art-template) - **Role:** DIRECT_SOURCE - **Impact:** Current dist-tag, retained versions, publishers, integrity metadata, and removal state.
4. [GitHub: original-author warning, issue 665](https://github.com/goofychris/art-template/issues/665) - **Role:** DIRECT_SOURCE - **Impact:** Historical maintainer warning; the issue is deleted and returns HTTP 410 as of 2026-06-10.
5. [Google Threat Intelligence: Coruna](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit) - **Role:** PRIMARY_RESEARCH - **Impact:** Independent technical baseline for the Coruna exploit framework and affected iOS range.
