---
title: "Claude Code GitHub Action Secret Exposure"
date: 2026-06-05
severity: "critical"
tags:
  - github-actions
  - ci-cd
  - ai-assistants
  - credential-theft
  - workflow-secrets
summary: "Microsoft reported that the Claude Code GitHub Action could expose workflow secrets through a Read-tool path that reached /proc/self/environ; Anthropic shipped v2.1.128 as the fixed release."
sourceCount: 2
---

## Executive Summary
Microsoft described a secret-exposure case in the Claude Code GitHub Action where untrusted issue or pull-request content could reach the action's Read tool and expose workflow secrets from the runner environment. Anthropic's v2.1.128 release is the published fixed boundary, but the public report does not include exact repository or workflow examples, so broad exploitation should remain scoped as uncertain rather than assumed [1][2].

The practical defender takeaway is narrow: look for repositories that route untrusted issue or PR content into Claude Code jobs, confirm whether those jobs had access to `ANTHROPIC_API_KEY` or other workflow secrets, and treat any evidence of `/proc/self/environ` access as an exposure event until proven otherwise [1][2].

## Key Facts
**Threat Type**: CI/CD secret exposure through an AI assistant workflow

**Ecosystem**: GitHub Actions

**Registry**: GitHub repositories

**Affected Assets**:
- Claude Code GitHub Action
- GitHub Actions runners
- CI/CD workflows processing untrusted issue or pull-request content

**Malicious Versions**:
- not publicly enumerated in the report

**Known Good Versions**:
- v2.1.128

**Fixed Or Safe Versions**:
- v2.1.128

**Execution Trigger**: workflow content routed through the Claude Code GitHub Action Read tool

**Primary Impact**: workflow secret exposure from the runner environment

**Campaign Context**: June 2026 agentic CI/CD incident with a public mitigation release but limited public exploitation detail.

**Confidence**: medium

**Canonical Source**: Microsoft security blog report and Anthropic release v2.1.128

**Last Verified**: 2026-06-05

## Evidence Assessment
- **confirmed:** Microsoft reported the case and tied the exposure to a Read-tool path that could reach `/proc/self/environ` [1].
- **confirmed:** Anthropic's `v2.1.128` release is the published fixed boundary in the supplied evidence set [2].
- **unclear:** The Microsoft article did not publish exact repository or workflow examples, so the full exploitation surface remains uncertain [1].
- **unclear:** Broader exploitation beyond the described Read-tool exposure path is not established in the public materials [1][2].

## Impact Determination
| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | The workflow or log export shows `anthropics/claude-code`, `v2.1.128`-boundary activity, secret material, or `/proc/self/environ` access. | Workflow file, job log, runner telemetry, and secret inventory. | Pause the workflow, preserve logs, and rotate any secret reachable from the job. | The exposure path is removed and downstream identity checks are clean. |
| Presumed exposed | The repository routes untrusted issue or PR content into Claude Code and had secrets available, but the exact runtime evidence is incomplete. | Workflow definition, job permissions, and secret availability. | Treat reachable secrets as exposed until you can rule out Read-tool access. | Owners verify rotation and no suspicious follow-on use. |
| Potentially exposed | The repo references Claude Code, but the specific run state, version, or secret availability is incomplete. | Repo search hits and workflow history. | Complete run-level scoping before classifying the asset. | Each matching workflow is dispositioned. |
| Not exposed | No Claude Code action reference, `ANTHROPIC_API_KEY`, or `/proc/self/environ` evidence exists in the scoped checkout or logs. | Negative checkout and log search results. | Keep the clean evidence set with the case record. | Search artifacts are preserved. |
| Unknown | Required checkout, workflow, or log telemetry is missing. | Named data gaps. | Keep the repository in the investigation queue. | Missing evidence is resolved or the owner accepts the gap. |

### Minimum Evidence To Collect
- Workflow definitions that reference `anthropics/claude-code` or pin `v2.1.128`, because they establish whether the action was present in the execution path.
- Job logs or exported runner telemetry that mention `ANTHROPIC_API_KEY` or `/proc/self/environ`, because they show whether the secret-bearing environment was reachable.
- Repository history for issue or pull-request handling workflows, because the report's exposure path depends on untrusted content reaching the action [1][2].

## Timeline
- **2026-05-04T23:01:47Z** Anthropic published the `v2.1.128` release boundary in the public release feed [2].
- **2026-06-05** Microsoft published the case writeup describing the Claude Code GitHub Action exposure path [1].
- **2026-06-05** This site-worker pass records the case as a standalone threat post with a matching local hunt.

## What Happened
Microsoft's report describes a workflow where the Claude Code GitHub Action processed untrusted issue or pull-request content and a Read tool path could expose the runner environment, including secrets such as `ANTHROPIC_API_KEY` [1]. The source material does not provide the exact repository or workflow examples, so defenders should treat the issue as a real exposure mechanism without assuming a wider, unproven mass-compromise campaign [1].

Anthropic's `v2.1.128` release gives the practical fixed boundary for responders who need a version marker during triage. For incident handling, the main question is not whether every Claude Code workflow was affected, but whether a specific checkout or log export shows the action, the fixed version boundary, and a path to `/proc/self/environ` [2].

## Technical Analysis
### Initial Access
The attack surface is not a package registry. It is a GitHub Actions workflow that accepts untrusted issue or pull-request content and hands that content to the Claude Code action, which means the relevant evidence is workflow logic, run history, and the secret set available to that job [1].

### Package or Artifact Tampering
The public evidence supplied here points to a GitHub release boundary, not a malicious tarball. Use `v2.1.128` as the version marker during scoping, and treat older references to the action as requiring additional review rather than immediate benign classification [2].

### Execution Trigger
The trigger is workflow execution. If the runner invokes Claude Code on attacker-influenced content, then the action's Read tool may traverse environment data that should not be available to untrusted input [1].

### Payload Behavior
The publicly described behavior is secret exposure from the runner environment via `/proc/self/environ`, with `ANTHROPIC_API_KEY` serving as the clearest named secret class in the task context [1][2].

### Exfiltration / C2
No public command-and-control endpoint was provided in the supplied sources, so the correct defender stance is to hunt for exposure evidence rather than assume a known remote sink [1][2].

### Propagation
No propagation mechanism is established in the public evidence. The case should be treated as workflow-local exposure, not as a self-replicating campaign, unless local repository history shows otherwise [1][2].

### Obfuscation or Evasion
The important evasion angle is contextual: a normal-looking assistant workflow can become risky when it is allowed to inspect environment state while processing untrusted content. That makes repository intent, not just file syntax, central to the review [1].

## Affected Assets and Blast Radius
**Affected Assets**:
- **ecosystems**: GitHub Actions, CI/CD
- **packages**:
- **versions**: v2.1.128
- **repositories**: anthropics/claude-code
- **ci_cd_systems**: GitHub Actions runners, workflows processing untrusted issue or pull-request content
- **container_images**:
- **developer_tools**: Claude Code GitHub Action

**Credentials At Risk**:
- `ANTHROPIC_API_KEY`
- any other workflow secret injected into the runner environment
- downstream tokens reachable from a compromised GitHub Actions job

**Not Currently Known To Affect**:
- repositories that do not invoke the Claude Code GitHub Action
- workflows that never expose secret-bearing environment data to the assistant path
- broader exploitation beyond the public Microsoft-described case

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:


## Detection and Hunting

### Hunt Manifest: claude-code-github-action-secret-exposure-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Claude Code GitHub Action Secret Exposure?
- **Telemetry Family:** process
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
"""Generic IOC scope scanner for claude-code-github-action-secret-exposure.

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

OUT = Path(os.environ.get("OUT", "hp-claude-code-github-action-secret-exposure-ioc-scope"))
CONTENT_INDICATORS = [
  "anthropics/claude-code",
  "v2.1.128",
  "ANTHROPIC_API_KEY",
  "/proc/self/environ"
]
PATH_INDICATORS = [
  ".github/workflows/*.yml",
  "action.yml"
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

### Hunt Manifest: claude-code-github-action-secret-exposure-hunt-2
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Claude Code GitHub Action Secret Exposure?
- **Telemetry Family:** process
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
"""Generic IOC scope scanner for claude-code-github-action-secret-exposure.

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

OUT = Path(os.environ.get("OUT", "hp-claude-code-github-action-secret-exposure-ioc-scope"))
CONTENT_INDICATORS = [
  "anthropics/claude-code",
  "v2.1.128",
  "ANTHROPIC_API_KEY",
  "/proc/self/environ"
]
PATH_INDICATORS = [
  ".github/workflows/*.yml",
  "action.yml"
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

## Sources
1. [Microsoft Security Blog: Securing CI/CD in an Agentic World — Claude Code GitHub Action case](https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-an-agentic-world-claude-code-github-action-case/) - **Role:** PRIMARY_RESEARCH - **Impact:** Public description of the Read-tool secret-exposure path and the uncertainty around exact repository examples.
2. [Anthropic Claude Code v2.1.128 release](https://github.com/anthropics/claude-code/releases/tag/v2.1.128) - **Role:** PRIMARY_RESEARCH - **Impact:** Fixed-release boundary used for scoping and remediation.
