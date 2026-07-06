---
title: "Pythagora gpt-pilot GitHub Compromise"
date: 2026-06-17
severity: "critical"
tags:
  - github
  - ci-cd
  - supply-chain
  - credential-theft
  - shai-hulud
  - python
summary: "An attacker hijacked a Pythagora co-founder's GitHub account, force-pushed a Shai-Hulud credential-stealer to gpt-pilot's main branch, and lost the payload twice to ruff lint failures before any public downstream execution was shown."
sourceCount: 2
---

## Executive Summary
On **2026-06-08**, StepSecurity reported that an attacker compromised a co-founder's GitHub account for `Pythagora-io/gpt-pilot` and force-pushed a credential-stealing Shai-Hulud variant into the repository's `main` branch [1]. The malicious chain introduced `_hooks.py`, `_runtime.bin`, and a modified `core/telemetry/__init__.py`, but the payload never made it through CI: `ruff format --check` failed on the first push, and `ruff check` failed on the second push [1].

This is a **campaign child event** in the broader Mini Shai-Hulud family rather than a duplicate of the existing registry-publish posts. The public evidence proves repository compromise and attempted payload insertion, but it does **not** prove downstream execution or exfiltration on a victim host. Treat any checkout, fork, mirror, or cached branch state that preserved the malicious commit chain as suspicious until it is revalidated from a clean head [1][2].

## Key Facts
**Threat Type**: GitHub repository compromise with attempted credential-stealer insertion

**Ecosystem**: GitHub, Python

**Registry**: GitHub repository history

**Affected Assets**:
- Pythagora-io/gpt-pilot
- `main` branch history
- `core/telemetry/_hooks.py`
- `core/telemetry/_runtime.bin`
- `core/telemetry/__init__.py`

**Malicious Versions**:
- force-pushed malicious commit chain rooted at `90f59f5de6819a43ffe9b6272e3ed65aaadca804`

**Known Good Versions**:
- clean chain rooted at `53154df1c66b42021f230c3fb6ef797c4b7c3e83`

**Execution Trigger**: force-push to `main`; any downstream checkout that consumed the rewritten history would inherit the payload

**Primary Impact**: attempted credential theft and repository persistence via a Shai-Hulud payload

**Campaign Context**: Mini Shai-Hulud child event

**Confidence**: high

**Canonical Source**: StepSecurity writeup on the `Pythagora-io/gpt-pilot` compromise

## Evidence Assessment
* **confirmed:** An attacker hijacked a co-founder's GitHub account and force-pushed a malicious chain to `main` [1].
* **confirmed:** The malicious chain introduced `_hooks.py`, `_runtime.bin`, and a modified `core/telemetry/__init__.py` [1].
* **confirmed:** CI blocked the first attempt with `ruff format --check` and blocked the second attempt with `ruff check` failures [1].
* **confirmed:** The public article identifies the payload as a Shai-Hulud credential-stealer and describes credential-targeting behavior against developer secrets [1].
* **unclear:** Public evidence does not show a successful downstream install, host execution, or exfiltration event outside the repository and CI environment [1][2].
* **unclear:** The deleted disclosure issue and the exact cleanup sequence are not fully available in the public record [1].

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | The malicious commit chain or payload files are present in repository history and a malicious push, checkout, or CI event is observed. | Git history plus CI logs, branch event logs, or artifact mirrors showing the rewritten chain. | Restore a clean branch head, preserve evidence, and review all forks and mirrors. | Clean history is re-established and downstream consumers are revalidated. |
| Presumed exposed | A mirror, fork, cache, or checkout preserved the malicious chain, but runtime evidence is incomplete. | Repo mirrors, clone caches, fork history, or CI exports tied to the exposure window. | Re-clone from a clean head and rotate credentials reachable from the affected environment. | Mirrors and caches are refreshed and credentials are rotated. |
| Potentially exposed | The repository appears in local inventory, but resolved history and CI execution are not yet proven. | Repository manifests, clone caches, or audit exports. | Collect branch and build telemetry before narrowing scope. | Each hit is dispositioned as confirmed, presumed, or not exposed. |
| Not exposed | No affected repo, commit, or payload file appears in source, fork, cache, or CI telemetry. | Negative searches across repositories, clones, and logs. | Preserve the clean evidence set. | Search coverage spans local repositories, mirrors, and CI exports. |
| Unknown | Required repository, CI, or endpoint telemetry is missing. | Named gap with owner and retention window. | Keep the repository in scope until evidence or rotation closes the gap. | Missing evidence is recovered or accepted by the risk owner. |

### Minimum Evidence To Collect
- Git history or branch export that preserves the malicious `90f59f5de6819a43ffe9b6272e3ed65aaadca804` chain and the clean `53154df1c66b42021f230c3fb6ef797c4b7c3e83` chain.
- CI logs showing the two failed `ruff` gates and the exact file paths they flagged.
- Repository or fork inventory showing whether any downstream clone captured the malicious head.
- Endpoint or log telemetry for any checkout that consumed the rewritten `main` history.

## Timeline
- **2026-06-08 11:01:38 UTC** First force-push to `main` via the compromised `LeonOstrez` account replaces the clean chain with the malicious chain [1].
- **2026-06-08 11:02:07 UTC** CI fails; `ruff format --check` catches a formatting violation in `_hooks.py` [1].
- **2026-06-08 11:13:07 UTC** The attacker force-pushes again after adjusting the payload [1].
- **2026-06-08 11:13:38 UTC** CI fails again; `ruff check` catches `E402` and `I001` in `core/telemetry/__init__.py` [1].
- **2026-06-08 ~11:30 UTC** A community member reports the compromise via a GitHub issue, which is later deleted [1].
- **2026-06-17** This site-worker pass classifies the finding as a publishable Mini Shai-Hulud child event and prepares the hunt packet.

## What Happened
The attacker did not need a registry publish to create impact. By compromising a maintainer account, they were able to rewrite the repository's `main` branch and insert a Shai-Hulud payload directly into source history [1]. That makes the repository itself the distribution point: any future checkout, mirror, or release process that trusted the rewritten head could inherit the malicious files.

The public record is also unusually strong because the payload tripped quality gates twice. The first push failed on formatting, and the second failed on import-order and module-layout checks. In practical defender terms, that means the malicious branch never earned a clean CI pass, which limits certainty about downstream execution but does not erase the compromise itself [1].

## Technical Analysis

### Initial Access
The initial access vector was GitHub account compromise. The attacker operated as `LeonOstrez`, a Pythagora co-founder and repository maintainer, and the repository had no branch protection on `main` [1]. That allowed a direct force-push over the existing commit chain.

### Package or Artifact Manipulation
The modified tree inserted `_hooks.py`, `_runtime.bin`, and edits to `core/telemetry/__init__.py` [1]. Those file names are important because they give defenders concrete selectors for repository-history hunting and mirror validation.

### Execution Trigger
The trigger was branch rewrite, not package installation. If a downstream mirror, checkout, or release pipeline consumed the rewritten `main` branch before cleanup, it would inherit the payload-bearing tree [1].

### Payload Behavior
StepSecurity characterizes the payload as a Shai-Hulud credential stealer. The task context further identifies the reported target classes as AWS keys, npm tokens, GitHub secrets, Kubernetes service accounts, HashiCorp Vault tokens, SSH keys, and persistence hooks for Claude Code and VS Code. Because CI blocked the malicious chain twice, the public evidence does not establish successful execution outside the repository [1].

### Exfiltration / C2
No validated downstream C2 or exfiltration sink is required to classify the repository compromise. The public evidence supports a repository-level incident with failed execution attempts, not a confirmed victim-side beaconing campaign [1][2].

### Propagation
Propagation is social and operational: a compromised maintainer account can rewrite trusted source history, and any mirror or checkout that trusts the rewritten head can spread the malicious tree downstream [1][2].

### Obfuscation or Evasion
The attacker relied on source-control trust and commit-history rewriting. The surprising defender was ruff, which blocked both malicious pushes before the payload could pass CI [1].

## Affected Assets and Blast Radius
**Affected Assets**:
- **ecosystems**: GitHub, Python
- **repositories**: Pythagora-io/gpt-pilot
- **ci_cd_systems**: GitHub Actions or equivalent repository CI
- **developer_tools**: ruff, Python toolchain

**Credentials At Risk**:
- GitHub credentials
- repository tokens
- CI secrets
- cloud credentials reachable from a downstream checkout
- SSH keys reachable from a downstream checkout

**Not Currently Known To Affect**:
- Public downstream hosts, because the source material does not prove execution outside repository and CI context.

## Indicators of Compromise
The following indicators of compromise can be used to scope exposure across local repositories, mirrors, and exported telemetry:

### Files
- `_hooks.py`
- `_runtime.bin`
- `core/telemetry/_hooks.py`
- `core/telemetry/__init__.py`

### Hashes
- `53154df1c66b42021f230c3fb6ef797c4b7c3e83`
- `90f59f5de6819a43ffe9b6272e3ed65aaadca804`

### Process Patterns
- `LeonOstrez`
- `ruff format --check`
- `ruff check`
- `E402`
- `I001`
- `No branch protection rules were configured on main`

## Detection and Hunting

### Hunt Manifest: pythagora-gpt-pilot-github-compromise-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Pythagora gpt-pilot GitHub Compromise?
- **Telemetry Family:** file
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
"""Scan repository trees and exported logs for the Pythagora gpt-pilot compromise selectors."""


import os
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
LOG_ROOT = Path(os.environ["LOG_ROOT"]) if os.environ.get("LOG_ROOT") else None
OUT = Path(os.environ.get("OUT", "hp-pythagora-gpt-pilot-github-compromise-scope"))
INDICATORS_FILE = OUT / "indicators.txt"

FILES = [
    "_hooks.py",
    "_runtime.bin",
    "core/telemetry/_hooks.py",
    "core/telemetry/__init__.py",
]
HASHES = [
    "53154df1c66b42021f230c3fb6ef797c4b7c3e83",
    "90f59f5de6819a43ffe9b6272e3ed65aaadca804",
]
PROCESS_PATTERNS = [
    "Pythagora-io/gpt-pilot",
    "LeonOstrez",
    "ruff format --check",
    "ruff check",
    "E402",
    "I001",
    "No branch protection rules were configured on main",
]
NETWORK_PATTERNS = [
    "CI run #27133204878",
]


def build_indicators() -> list[str]:
    items: list[str] = []
    for group in (FILES, HASHES, PROCESS_PATTERNS, NETWORK_PATTERNS):
        items.extend(group)
    # Preserve order while removing duplicates.
    return list(dict.fromkeys([item for item in items if item]))


def iter_text_matches(base: Path, indicators: Iterable[str]) -> list[str]:
    matches: list[str] = []
    if not base.exists():
        return matches

    excluded = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", OUT.name}
    for root, dirs, filenames in os.walk(base):
        dirs[:] = [d for d in dirs if d not in excluded]
        for filename in filenames:
            path = Path(root) / filename
            try:
                content = path.read_text(errors="ignore")
            except Exception:
                continue
            for indicator in indicators:
                if indicator in content:
                    matches.append(f"{path}: found {indicator!r}")
    return list(dict.fromkeys(matches))


def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(lines)
    if text:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    indicators = build_indicators()
    write_lines(INDICATORS_FILE, indicators)
    print(f"[+] Wrote {len(indicators)} indicators to {INDICATORS_FILE}")

    repo_matches = iter_text_matches(ROOT, indicators)
    if repo_matches:
        write_lines(OUT / "repository-indicator-matches.txt", repo_matches)
        print(f"[!] Found {len(repo_matches)} repository matches")
    else:
        print("[+] No repository matches")

    if LOG_ROOT is not None:
        log_matches = iter_text_matches(LOG_ROOT, indicators)
        if log_matches:
            write_lines(OUT / "exported-telemetry-indicator-matches.txt", log_matches)
            print(f"[!] Found {len(log_matches)} exported telemetry matches")
        else:
            print("[+] No exported telemetry matches")

    print(f"[+] Wrote scope artifacts under {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Sources

1. [StepSecurity: Pythagora-io/gpt-pilot Compromised on GitHub - Shai-Hulud Credential Stealer Blocked by Python Linter](https://www.stepsecurity.io/blog/pythagora-io-gpt-pilot-compromised-on-github-shai-hulud-credential-stealer-blocked-by-python-linter). **Role:** PRIMARY_RESEARCH **Impact:** Documents the hijacked maintainer account, the force-pushed malicious chain, the `ruff` lint failures, and the Shai-Hulud payload behaviors.
2. [GitHub issue 1182 and repository history for `Pythagora-io/gpt-pilot`](https://github.com/Pythagora-io/gpt-pilot/issues/1182). **Role:** PRIMARY_SOURCE **Impact:** Anchors the public disclosure trail and the repository history for `main`, including the malicious and clean commit chains referenced in the article.