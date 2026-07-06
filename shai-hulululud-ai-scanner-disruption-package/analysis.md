---
title: "shai_hulululud npm Package Uses Prompt Injection and Token Flooding to Disrupt AI Malware Scanners"
date: 2026-06-16
severity: "medium"
tags:
  - npm
  - supply-chain
  - ai-tools
  - ai-assistants
  - malicious-package
  - anti-analysis
summary: "Socket identified shai_hulululud@1.0.48596 as a deliberately packed npm package that appears designed to probe or disrupt AI-assisted malware review with prompt-injection text, safety-triggering comments, context flooding, and obfuscated JavaScript."
sourceCount: 3
---

## Executive Summary

`shai_hulululud@1.0.48596` is a newly published npm package that Socket describes as targeting AI-based malware scanners rather than shipping the same credential-stealing workflow seen in recent Mini Shai-Hulud, Miasma, and Hades packages [1]. Socket says the package combines prompt-injection text, safety-triggering comment content, context flooding through repetition, and obfuscated JavaScript inside a single large `index.js` file [1].

Direct npm registry metadata confirms the package identity, its maintainer handle `ptchli_knldg`, and a rapid publication window on **2026-06-16** with version `1.0.48596` as the only published release [2]. We also retrieved the tarball directly from the npm registry for static inspection and confirmed that it contains only `package.json` plus a very large `index.js` artifact with an `eval(` call near the executable portion of the file [3].

This is best treated as a **new post** because the current evidence supports a distinct npm artifact deliberately shaped to interfere with AI-assisted review pipelines. The reviewed sources do **not** currently prove the same downstream credential theft behavior documented in Mini Shai-Hulud, Miasma, or Hades, so the overlap should be treated as a technique relationship rather than a merged campaign identity [1][3].

## Key Facts

| Fact | Value |
| --- | --- |
| **Affected Artifact** | `shai_hulululud@1.0.48596` |
| **Ecosystem** | npm |
| **Exposure Window** | 2026-06-16 publication onward until local quarantine or removal |
| **Execution Trigger** | Package ingestion, artifact inspection, or JavaScript execution of the shipped `index.js` |
| **Primary Risk** | AI-scanner anti-analysis, review disruption, and possible concealment of appended obfuscated JavaScript |
| **Immediate Action** | Quarantine the exact tarball, block the package/version in mirrors and CI, and verify human review covered any environment that ingested it |
| **Confidence** | medium |

## Evidence Assessment

- **confirmed:** Socket identified `shai_hulululud@1.0.48596` and described the package as a test of AI-based malware scanners using prompt-injection text, safety-triggering comments, context flooding, and obfuscated JavaScript [1].
- **confirmed:** npm registry metadata shows the package was created and published on 2026-06-16, has only one published version, and is associated with maintainer `ptchli_knldg` [2].
- **confirmed:** Direct static inspection of the retrieved tarball found only two files, `package/package.json` and `package/index.js`, with `index.js` measuring roughly 9.28 MB and containing an `eval(` call in the executable portion of the artifact [3].
- **confirmed:** Static measurement of the retrieved `index.js` shows approximately 33,120 lines, of which about 32,929 are comment lines, and one repeated comment prefix dominates roughly 32,928 lines of the file [3].
- **likely:** The repeated-comment structure is intended to flood or derail AI-assisted analysis contexts rather than to support a normal package runtime implementation [1][3].
- **unclear:** Public evidence reviewed here does not prove whether the obfuscated code includes a functional second-stage payload, network callback, or credential theft path [1][3].
- **not_observed:** We did not observe declared npm dependencies, a `bin` entry, or public evidence of live C2 infrastructure in the reviewed package metadata [2][3].

## Impact Determination

| Exposure Classification | Criteria | Required Evidence | Required Action | Closure Gate |
| --- | --- | --- | --- | --- |
| **Confirmed compromise** | Internal mirrors, caches, or scanner sandboxes contain the exact package name/version and the retrieved tarball or hash values. | Lockfiles, package-cache artifacts, proxy logs, artifact-store records, or quarantine outputs tying to `shai_hulululud@1.0.48596` or the known tarball hashes. | Quarantine the artifact, preserve copies for analysis, and document whether automated review completed or failed. | The package is removed from every cache and a reviewer confirms no silent analysis gap remains. |
| **Presumed exposed** | A repository, CI job, or internal registry resolved the package, but retained artifacts or scan logs are incomplete. | Dependency records, package-manager logs, or private-registry metadata. | Block the exact package/version and investigate whether review tooling skipped execution or downgraded findings. | All candidate environments are dispositioned with retained evidence or explicit risk acceptance. |
| **Potentially exposed** | AI-assisted dependency review touched untrusted npm artifacts during the publication window, but exact package-resolution evidence is missing. | Scanner telemetry, ingestion logs, or mirror access records with retention gaps. | Reconstruct package-resolution history before treating the environment as clean. | The ingestion path is either disproven or resolved to confirmed/presumed exposure. |
| **Not exposed** | No package name, tarball URL, version string, or known tarball hashes appear in complete repository, cache, and telemetry evidence. | Negative searches across package caches, lockfiles, mirrors, and scanner logs. | Preserve negative evidence and keep the package blocked. | Search evidence covers the relevant environments and time window. |
| **Unknown** | Mirror, cache, or scanner telemetry is unavailable. | Explicit gap statement naming the missing system and retention boundary. | Keep the package in scope until evidence is collected or the review gap is formally accepted. | The telemetry gap is closed or accepted by the owner. |

## Minimum Evidence To Collect

- **What to collect:** lockfiles, package-manager cache entries, and artifact-store records containing `shai_hulululud` or `1.0.48596`.
  **Where it normally comes from:** `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, npm cache directories, registry proxy metadata, and CI artifact retention.
  **Why it is relevant:** it proves whether the package was actually resolved or mirrored in your environment.
  **Which decision it resolves:** confirmed vs. presumed vs. not exposed.
- **What to collect:** AI-scanner or static-analysis job logs showing whether the artifact was fully processed, truncated, skipped, or terminated during review.
  **Where it normally comes from:** scanner pipelines, malware-review sandboxes, code-review automation, and CI logs.
  **Why it is relevant:** the core incident value is anti-analysis pressure against automated review, not only package presence.
  **Which decision it resolves:** whether the package only existed in inventory or materially disrupted analysis.
- **What to collect:** preserved copies of the tarball or hash records for `9dcce285116e31a5c8f8e3a4ed596a791e62c3e47185e4ee36c489422b1fbbbc` and `8478bad8f0661d2a5ea65a8dc4bf86114f77d939`.
  **Where it normally comes from:** package quarantine buckets, artifact mirrors, or EDR/sandbox export storage.
  **Why it is relevant:** hash-confirmed artifact identity lets responders distinguish this package from other Shai-Hulud-adjacent reporting.
  **Which decision it resolves:** confirmed exposure and closure integrity.

## Timeline

- **2026-06-16T13:01:59Z:** npm registry metadata records package creation for `shai_hulululud` [2].
- **2026-06-16T13:01:59Z:** npm registry metadata records publication of version `1.0.48596` as the only known release [2].
- **2026-06-16:** Socket publishes research describing the package as a direct attempt to probe or disrupt AI-based malware scanners [1].
- **2026-06-25:** Halting Problems retrieved the tarball from the registry and confirmed the minimal two-file package layout, oversized `index.js`, dominant repeated-comment structure, and presence of `eval(` in the artifact [3].

## What Happened

The package appears to have been published as an npm artifact intentionally shaped for hostile interaction with AI-assisted malware review. According to Socket, the file structure mixes policy-triggering prompt content, fake override instructions, heavy repetition, and obfuscated JavaScript in a way that targets the assumptions of AI scanners rather than the expectations of a normal runtime package [1].

Our static review of the tarball reinforces that framing. The package has no declared dependencies and no visible multi-file application structure; instead it ships almost entirely as one very large `index.js` dominated by repeated comments, with only a small amount of non-comment executable content at the end of the file [2][3].

## Technical Analysis

### Initial Access

The package entered scope through the npm registry trust boundary. Public metadata identifies the artifact as `shai_hulululud@1.0.48596` and ties it to a single maintainer identity in the registry metadata [2].

### Package or Artifact Manipulation

The tarball is unusually sparse for its size. The retrieved archive contains only `package/package.json` and `package/index.js`, which means nearly the entire incident surface is concentrated in one JavaScript file [3]. This is consistent with a package optimized for artifact-level anti-analysis rather than a conventional library distribution.

### Execution Trigger

The defensive problem begins before any meaningful business logic would be expected. Socket's reporting frames the artifact as an AI-scanner probe, while the direct artifact shows that any pipeline that ingests, summarizes, tokenizes, or executes the file will encounter a huge repeated-comment body and obfuscated trailing code [1][3].

### Payload Behavior

We confirmed a large single-file JavaScript artifact with an `eval(` call and a dominant repeated-comment structure, but the currently reviewed evidence does not prove a working second-stage or credential theft routine [3]. That distinction matters operationally: this is publishable as a hostile anti-analysis package even without proof of downstream exfiltration.

### Defense Evasion

The clearest observed behavior is anti-analysis. Socket says the file includes prompt-injection text, safety-triggering content, and context flooding, while our line-count inspection confirmed that comment repetition overwhelms the file's structure [1][3]. A package shaped this way can degrade AI review quality, trigger false refusals, or consume analysis context before a reviewer reaches the executable tail of the file.

### Exfiltration and Command and Control

No live attacker infrastructure was confirmed in the reviewed sources. The evidence currently supports artifact-level disruption and obfuscation, not a proven C2 path [1][3].

## Affected Assets and Blast Radius

The primary blast radius is the review pipeline itself. Repositories, mirrors, and malware-scanning environments that automatically ingest npm packages are most likely to be affected, especially when they depend heavily on AI summarization or autonomous triage.

| Asset / System | Exposure Notes |
| --- | --- |
| npm mirrors and caches | May retain the exact package tarball even if live registry state changes later [2][3]. |
| CI dependency review jobs | Could ingest the package and silently downgrade review quality if the pipeline trusts AI-only output [1]. |
| Malware-analysis sandboxes | May spend most of their review budget on repeated comment content instead of the executable tail [1][3]. |
| Human reviewers | At risk of missing the executable section if relying on truncated outputs or incomplete summaries [1][3]. |
| Developer endpoints | Only in scope if the package was actually fetched or executed locally; broader credential theft is not yet proven [2][3]. |

## Indicators of Compromise

The following selectors are appropriate for repository, cache, and telemetry scoping:

### Package and Version

- `shai_hulululud`
- `shai_hulululud@1.0.48596`
- `shai_hulululud-1.0.48596.tgz`

### Artifact Hashes

- `9dcce285116e31a5c8f8e3a4ed596a791e62c3e47185e4ee36c489422b1fbbbc`
- `8478bad8f0661d2a5ea65a8dc4bf86114f77d939`

### Artifact URLs

- `https://registry.npmjs.org/shai_hulululud`
- `https://registry.npmjs.org/shai_hulululud/-/shai_hulululud-1.0.48596.tgz`

## Detection and Hunting

### Hunt Manifest: shai-hulululud-ai-scanner-disruption-package-hunt-1
- **Title:** repository, cache, and exported telemetry scope
- **Question:** Does the telemetry scope contain selectors associated with the shai_hulululud AI-scanner anti-analysis npm package?
- **Telemetry Family:** file
- **Telemetry Context:** repository trees, package caches, and exported telemetry
- **Positive Signal:** Indicators of compromise matched in telemetry: package name/version, artifact hash, tarball URL, or repeated anti-analysis package content

```py
#!/usr/bin/env python3
"""IOC scope scanner for shai_hulululud AI-scanner disruption package.

Searches repository trees and exported logs for literal IOC values associated with
shai_hulululud@1.0.48596 and its retrieved tarball artifact.

Exit codes:
  0: no matches
  1: one or more indicators matched
  2: execution error
"""

import argparse
import fnmatch
import json
import os
import sys
from pathlib import Path

OUT = Path(os.environ.get("OUT", "hp-shai-hulululud-ai-scanner-disruption-package-ioc-scope"))
PACKAGES = ["shai_hulululud"]
PACKAGE_VERSIONS = ["shai_hulululud@1.0.48596"]
FILES = ["shai_hulululud-1.0.48596.tgz", "index.js"]
HASHES = [
    "9dcce285116e31a5c8f8e3a4ed596a791e62c3e47185e4ee36c489422b1fbbbc",
    "8478bad8f0661d2a5ea65a8dc4bf86114f77d939",
]
URLS = [
    "https://registry.npmjs.org/shai_hulululud",
    "https://registry.npmjs.org/shai_hulululud/-/shai_hulululud-1.0.48596.tgz",
    "https://socket.dev/blog/npm-package-uses-prompt-injection-and-token-flooding-to-disrupt-ai-malware-scanners",
]
PROCESS_PATTERNS = ["eval(", "shai_hulululud"]
CONTENT_INDICATORS = PACKAGES + PACKAGE_VERSIONS + FILES + HASHES + URLS + PROCESS_PATTERNS
PATH_INDICATORS = ["*shai_hulululud*", "*shai_hulululud-1.0.48596.tgz*"]
EXCLUDE_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}


def _iter_files(root: str | Path):
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


def _path_matches(path: Path) -> list[str]:
    text = str(path)
    matches: list[str] = []
    for indicator in PATH_INDICATORS:
        if indicator and (fnmatch.fnmatch(text, indicator) or fnmatch.fnmatch(path.name, indicator)):
            matches.append(indicator)
    return matches


def _content_matches(path: Path) -> list[str]:
    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return []
    return [indicator for indicator in CONTENT_INDICATORS if indicator and indicator in content]


def _scan_roots(roots: list[str]) -> list[str]:
    matches: list[str] = []
    for root in roots:
        if not root:
            continue
        for path in _iter_files(root):
            for indicator in _path_matches(path):
                matches.append(f"{path}: path matched {indicator!r}")
            for indicator in _content_matches(path):
                matches.append(f"{path}: content matched {indicator!r}")
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan files and logs for shai_hulululud IOC values")
    parser.add_argument("roots", nargs="*", default=["."], help="File or directory roots to scan")
    parser.add_argument("--log-root", default=os.environ.get("LOG_ROOT", ""), help="Optional exported log directory")
    parser.add_argument("--out", default=str(OUT), help="Output directory for scan artifacts")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    indicator_lines = sorted(set(CONTENT_INDICATORS + PATH_INDICATORS))
    (out_dir / "ioc-indicators.txt").write_text("\n".join(indicator_lines) + "\n", encoding="utf-8")

    roots = list(args.roots)
    if args.log_root:
        roots.append(args.log_root)
    matches = _scan_roots(roots)

    summary = {
        "roots": roots,
        "indicator_count": len(indicator_lines),
        "match_count": len(matches),
    }
    (out_dir / "scan-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    if matches:
        (out_dir / "ioc-scope-matches.txt").write_text("\n".join(matches) + "\n", encoding="utf-8")
        print(f"[!] Found {len(matches)} IOC matches; summary written to {out_dir / 'scan-summary.json'}")
        return 1

    print(f"[+] No IOC matches found; summary written to {out_dir / 'scan-summary.json'}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"[-] Execution failure: {exc}", file=sys.stderr)
        sys.exit(2)
```

## Downstream Abuse Audits

No platform-specific downstream credential rotation is justified from the public evidence alone. Instead, audit the integrity of the review process:

- verify whether AI-based malware scanners, code-review bots, or quarantine jobs skipped, refused, or truncated analysis for this artifact;
- confirm that any package mirror or malware-review workflow preserved the executable tail of the file for human review;
- document whether any environment executed the package rather than only storing or analyzing it.

## Remediation and Closure

1. **Preserve evidence:** retain the exact tarball, package metadata, and any scanner logs showing how the artifact was handled.
2. **Stop active ingestion:** block `shai_hulululud@1.0.48596` in private npm mirrors, CI allow-lists, and sandbox feeds.
3. **Contain affected environments:** isolate scanner sandboxes or review queues that may have silently failed on the artifact.
4. **Eradicate retained artifacts:** purge the package from caches, test mirrors, and staging registries once preservation is complete.
5. **Re-run review with humans in the loop:** confirm a reviewer inspected the executable tail of the file rather than only an AI-generated summary.
6. **Audit adjacent automation:** identify whether similar oversized single-file packages are bypassing normal review gates.
7. **Close only when:** searches are negative for the exact package/version/hash set or every retained copy is quarantined and reviewed.

## Sources

1. [Socket: npm Package Uses Prompt Injection and Token Flooding to Disrupt AI Malware Scanners](https://socket.dev/blog/npm-package-uses-prompt-injection-and-token-flooding-to-disrupt-ai-malware-scanners)
2. [npm registry metadata for shai_hulululud](https://registry.npmjs.org/shai_hulululud)
3. [npm tarball for shai_hulululud@1.0.48596](https://registry.npmjs.org/shai_hulululud/-/shai_hulululud-1.0.48596.tgz)
