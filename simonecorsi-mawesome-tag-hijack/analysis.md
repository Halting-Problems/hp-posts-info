---
title: "simonecorsi/mawesome GitHub Action Tag Hijack"
date: 2026-06-25
severity: "critical"
tags:
  - supply-chain
  - github-actions
  - ci-cd
  - credential-theft
  - tag-hijack
summary: "Mutable refs for simonecorsi/mawesome including latest, v1, v2, and v2.2.0 currently resolve to a composite action that installs Bun and always runs an obfuscated JavaScript payload, exposing GitHub Actions runners that still trust those tags."
sourceCount: 6
---

## Executive Summary
On June 24, 2026, StepSecurity disclosed that `simonecorsi/mawesome` had been compromised and warned that workflows resolving the action by mutable tags were at risk. The public advisory lists `latest`, `v1`, `v2`, and `v2.2.0` as affected, all resolving to commit `e339407b8e34dc1540290d1d310bccafbc6028ca`, while `v2.1.0` and `v2.0.0` still point to their expected historical release commits. [1] [2]

Direct artifact review shows why this matters. The affected `v1` action definition is no longer the normal `node16` action used on `main`; it has been rewritten as a composite action that first delegates to clean commit `4a665037e0619e2181c7cccc3291d75104175a92`, then installs Bun, and finally runs `bun run $GITHUB_ACTION_PATH/index.js` under `if: always()`. That second-stage `index.js` is heavily obfuscated and visibly contains token-validation, secret-selection, GitHub API, and cloud or Vault credential-handling logic. [3] [4] [5]

The public evidence is strong enough to classify this as a publishable GitHub Action tag hijack and CI credential-exposure event, but not strong enough to claim confirmed downstream exfiltration or a stable campaign linkage. Treat any workflow that resolved `simonecorsi/mawesome@latest`, `@v1`, `@v2`, or `@v2.2.0` during the disclosure window as at least potentially exposed until run-level scoping and credential review are complete. [1] [2] [5]

## Key Facts
**Threat Type**: GitHub Action tag hijack and CI credential exposure

**Affected Action**:
- simonecorsi/mawesome

**Affected Refs**:
- latest
- v1
- v2
- v2.2.0

**Known Unaffected Refs During This Refresh**:
- v2.1.0 -> `6e26314c306ed5ea744eb90ebc6f3f70298abcb5`
- v2.0.0 -> `7a59a7d02b1fdf6432ea9467b8e31357217288f7`

**Affected Commit**:
- `e339407b8e34dc1540290d1d310bccafbc6028ca`

**Known Clean Reference**:
- `4a665037e0619e2181c7cccc3291d75104175a92` (`main` action definition during this refresh)

**Exposure Window**: Publicly disclosed on 2026-06-24; exact tag-move time remains unknown

**Payload Trigger**: Workflow resolution of a mutable `simonecorsi/mawesome` tag

**Primary Impact**: GitHub Actions runner secret exposure, token replay risk, and follow-on abuse of identities reachable from the affected workflow environment

**Known IOCs**:
- `simonecorsi/mawesome@latest`
- `simonecorsi/mawesome@v1`
- `simonecorsi/mawesome@v2`
- `simonecorsi/mawesome@v2.2.0`
- `e339407b8e34dc1540290d1d310bccafbc6028ca`
- `oven-sh/setup-bun`
- `bun run $GITHUB_ACTION_PATH/index.js`

**Confidence**: high

## Evidence Assessment
- **confirmed:** StepSecurity publicly reported the compromise and listed the currently affected tags as `latest`, `v1`, `v2`, and `v2.2.0`, with `v2.1.0` and `v2.0.0` resolving elsewhere. [1]
- **confirmed:** Current GitHub tag metadata and `git ls-remote` state still place those four mutable refs on `e339407b8e34dc1540290d1d310bccafbc6028ca`. [2]
- **confirmed:** The affected `action.yml` now uses a composite wrapper that delegates to clean commit `4a665037e0619e2181c7cccc3291d75104175a92`, installs Bun, and executes a local `index.js` payload under `if: always()`. [3]
- **confirmed:** The clean `main` branch action definition still uses `runs.using: 'node16'` with `main: 'index.js'`, making the composite Bun-based wrapper an artifact-level deviation rather than expected release behavior. [4]
- **confirmed:** The affected `index.js` is heavily obfuscated and visibly contains secret-selection, token-validation, GitHub API, encryption, and cloud or Vault credential-handling primitives. [5]
- **unclear:** The public record reviewed in this refresh does not show the exact tag-move timestamp, the initial repository-control mechanism, or a maintainer remediation advisory. [1] [2]
- **not_observed:** This refresh did not recover validated downstream victim telemetry or a deobfuscated stable exfiltration endpoint, so the post stops short of claiming confirmed runner-side data theft for specific organizations. [1] [5]

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | A workflow run resolved one of the affected tags and retained telemetry shows the injected Bun/composite-action selectors, the affected commit SHA, or downstream credential abuse. | Run metadata, resolved action SHA, runner telemetry, and audit logs tied to the affected job. | Isolate self-hosted runners, preserve workspace and cache artifacts, and rotate all credentials reachable by the job. | Affected runners are rebuilt or cleared, credentials are replaced, and downstream audits show no attacker use. |
| Presumed exposed | A workflow resolved `latest`, `v1`, `v2`, or `v2.2.0` after the June 24 disclosure window, but telemetry is incomplete. | Workflow files, run history, resolved SHA evidence, token permissions, and secret inventory. | Rotate reachable credentials and invalidate action caches even if exfiltration cannot be directly observed. | Every affected run is scoped and replacement credentials are active. |
| Potentially exposed | Repositories still reference the action by mutable tag, but run timing or resolved SHA are not yet known. | Repository search results plus GitHub Actions run exports or telemetry gaps. | Finish run-level scoping before ruling assets out. | Every repository hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected repository or run resolved the compromised tags, or every relevant workflow was pinned to a reviewed full SHA outside the affected set. | Repository search, run metadata, and cache inspection showing no affected refs or no execution. | Preserve negative evidence and enforce full-SHA pinning. | Search coverage includes reusable workflows, self-hosted runners, and cached action content. |
| Unknown | Required run metadata, cache artifacts, or runner telemetry is unavailable. | A documented telemetry gap naming the missing systems and time windows. | Keep the asset in scope and rotate high-value credentials conservatively. | Missing evidence is recovered or risk owners accept the residual uncertainty. |

## Minimum Evidence To Collect
- Collect workflow YAML, reusable workflows, and release templates that reference `simonecorsi/mawesome`, because those files determine whether mutable refs such as `latest`, `v1`, `v2`, or `v2.2.0` were still trusted after the disclosure and therefore resolve the difference between potentially exposed and not exposed.
- Collect GitHub Actions run history with the resolved action SHA for every candidate job, because a repository can mention `@v1` while an individual run still used cached clean content, and that evidence resolves whether an exposure was only theoretical or actually executed.
- Collect self-hosted runner caches, workspace copies of the action checkout, and any retained `$GITHUB_ACTION_PATH` content, because the malicious composite `action.yml` and obfuscated `index.js` can survive after upstream repository state changes and resolve whether eradication is complete.
- Collect GitHub audit logs, token inventories, and any Vault or cloud access logs reachable from affected jobs, because the visible payload primitives target identity material rather than only build output and that evidence resolves whether follow-on credential abuse occurred.
- Collect exported logs and repository snapshots that can be searched for `oven-sh/setup-bun`, `bun run $GITHUB_ACTION_PATH/index.js`, and commit `e339407b8e34dc1540290d1d310bccafbc6028ca`, because those selectors distinguish the injected wrapper from the clean node16 implementation and resolve whether a run or cache actually touched the affected artifact. [3] [4] [5]

## Timeline
- **2022-07-06 08:58:32 UTC:** Commit `e339407b8e34dc1540290d1d310bccafbc6028ca`, later referenced by the affected tags during this refresh, was originally authored as `chore(release): 2.2.0 [skip ci]` and modified `action.yml` plus `index.js`. [6]
- **2026-06-24:** StepSecurity publicly reported that `simonecorsi/mawesome` had been compromised and published the affected-tag table used in this review. [1]
- **2026-06-25:** This refresh independently confirmed that `latest`, `v1`, `v2`, and `v2.2.0` still resolve to `e339407b8e34dc1540290d1d310bccafbc6028ca`, while the clean `main` branch action definition remains on `4a665037e0619e2181c7cccc3291d75104175a92`. [2] [3] [4]

## What Happened
The compromise abused the trust model around mutable GitHub Action tags. A downstream repository did not need to change its workflow file; any job that continued to resolve `simonecorsi/mawesome@v1`, `@v2`, `@v2.2.0`, or `@latest` would fetch whichever commit those tags currently referenced. In the current public state, all four mutable refs converge on the same suspicious commit rather than the clean node16 action definition on `main`. [1] [2] [4]

The artifact change is important because it preserves outward functionality while adding attacker-controlled execution. The affected `action.yml` first invokes the clean action by full SHA, then installs Bun and runs a local obfuscated JavaScript payload under `if: always()`. That means even builds that appear to succeed or partially fail can still run the injected second stage during cleanup. [3] [4]

## Technical Analysis
### Initial Access
Public reporting and the reviewed GitHub data confirm repository-control loss and mutable-tag abuse, but they do not yet explain how the attacker obtained the ability to repoint tags or alter release artifacts. Responders should therefore avoid assuming the incident ended when the public write-up appeared; the same access path may also have exposed maintainer credentials, GitHub Apps, or release infrastructure beyond the single repository. [1] [2]

### Package or Artifact Manipulation
The clean `main` action definition uses `runs.using: 'node16'` with `main: 'index.js'`. The affected `v1` artifact instead becomes a composite action that first delegates to `simonecorsi/mawesome@4a665037e0619e2181c7cccc3291d75104175a92`, then adds `oven-sh/setup-bun`, and finally runs `bun run $GITHUB_ACTION_PATH/index.js` under `if: always()`. That replacement is direct proof that mutable refs were repointed to attacker-selected content rather than merely serving an older but still expected release. [3] [4]

### Execution Trigger
The trigger is ordinary workflow resolution of a mutable action tag. No malicious pull request or local repository change is required in the victim project: a workflow that still references `simonecorsi/mawesome@v1`, `@v2`, `@v2.2.0`, or `@latest` will download the altered composite action the next time GitHub resolves the ref. [1] [2] [3]

### Payload Behavior
Static inspection of the affected `index.js` shows heavily obfuscated JavaScript with visible `createCipheriv`, `createDecipheriv`, `pbkdf2Sync`, GitHub API strings, and references to secret-bearing environment variables such as `VAULT_TOKEN`, `ARM_CLIENT_SECRET`, and `GOOGLE_APPLICATION_CREDENTIALS`. Those selectors support a capability assessment of token validation, secret selection, encryption, and staging or transfer logic rather than a benign cleanup routine. [5]

### Credential or Data Collection
The public code contains references consistent with GitHub repository context, Vault tokens, and cloud credential environments, which means the likely blast radius is determined by what the workflow could already access rather than only by what the upstream repository stored. In practical terms, jobs with broad `GITHUB_TOKEN` scopes, package-publish credentials, Vault access, or cloud federation should be treated as high priority even if the exact exfiltration sink is still unknown. [5]

### Defense Evasion
The attacker preserved expected action behavior by chaining the clean commit before the injected Bun step, reducing the chance that maintainers or downstream users would notice an obvious functional failure. Running the payload under `if: always()` further broadens exposure because the second stage can execute during cleanup after partial job failure. [3]

### Exfiltration and Command and Control
This refresh did not safely deobfuscate a stable exfiltration endpoint from the public `index.js`, and the reviewed StepSecurity article is intentionally brief because the incident is still developing. Defenders should therefore focus first on credential exposure, GitHub API follow-on activity, and workflow-identity abuse instead of waiting for a domain-based IOC list that may arrive later. [1] [5]

## Affected Assets and Blast Radius
The blast radius is defined by where the action ran, not only by where the workflow file exists. A repository that still contains `simonecorsi/mawesome@v1` in source control but never executed after the disclosure is materially different from a self-hosted runner that resolved the tag, executed the wrapper, and retained action caches.

| Asset class | Exposure path | Why it matters |
| --- | --- | --- |
| GitHub repositories | Mutable action refs in workflow or reusable workflow files | A single inherited automation template can spread exposure across many repos. |
| GitHub-hosted runners | Workflow runs resolving the affected tags | Job tokens and secrets exist in runner memory and environment during execution. |
| Self-hosted runners | Cached action checkouts and persisted workspaces | The malicious composite action can survive after upstream repository changes. |
| Cloud and Vault identities | OIDC, static cloud keys, or Vault access exposed to workflow jobs | The visible payload selectors target identity material that can be replayed outside GitHub Actions. |
| Package registries and release systems | Publish tokens or deploy credentials available to release jobs | Attackers can pivot from CI compromise into downstream software distribution. |

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across repositories, run artifacts, and exported telemetry.

### Package Versions
- simonecorsi/mawesome@latest
- simonecorsi/mawesome@v1
- simonecorsi/mawesome@v2
- simonecorsi/mawesome@v2.2.0

### Files
- action.yml
- index.js

### Hashes
- e339407b8e34dc1540290d1d310bccafbc6028ca
- 4a665037e0619e2181c7cccc3291d75104175a92
- 6e26314c306ed5ea744eb90ebc6f3f70298abcb5
- 7a59a7d02b1fdf6432ea9467b8e31357217288f7

### Process Patterns
- oven-sh/setup-bun
- bun run $GITHUB_ACTION_PATH/index.js
- createCipheriv
- createDecipheriv
- pbkdf2Sync
- VAULT_TOKEN
- ARM_CLIENT_SECRET
- GOOGLE_APPLICATION_CREDENTIALS
- X-GitHub-Api-Version

## Detection and Hunting

### Hunt Manifest: simonecorsi-mawesome-tag-hijack-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain references associated with the simonecorsi/mawesome GitHub Action tag hijack?
- **Telemetry Family:** process
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Workflow content, caches, or exported telemetry contains compromised simonecorsi/mawesome refs, the affected commit SHA, or the injected Bun/composite-action selectors.
- **False Positives:** Historical advisories, lab fixtures, or intentionally preserved samples that reproduce the affected action definition for analysis.
- **Classification on Match:** Treat a match as at least potentially exposed; escalate to presumed exposed if workflow or run history proves execution during or after the June 24, 2026 disclosure window.

```py
#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").expanduser().resolve()
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-simonecorsi-mawesome-tag-hijack-scope"))

PACKAGES = ["simonecorsi/mawesome"]
HASHES = [
    "e339407b8e34dc1540290d1d310bccafbc6028ca",
    "4a665037e0619e2181c7cccc3291d75104175a92",
    "6e26314c306ed5ea744eb90ebc6f3f70298abcb5",
    "7a59a7d02b1fdf6432ea9467b8e31357217288f7",
]
PACKAGE_VERSIONS = [
    "simonecorsi/mawesome@latest",
    "simonecorsi/mawesome@v1",
    "simonecorsi/mawesome@v2",
    "simonecorsi/mawesome@v2.2.0",
]
TEXT_SELECTORS = [
    'uses: "simonecorsi/mawesome@4a665037e0619e2181c7cccc3291d75104175a92"',
    'uses: "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6"',
    "bun run $GITHUB_ACTION_PATH/index.js",
    "using: composite",
    "createCipheriv",
    "createDecipheriv",
    "pbkdf2Sync",
    "VAULT_TOKEN",
    "ARM_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "X-GitHub-Api-Version",
]

VALIDATOR_REQUIRED_SELECTORS = [
    'action.yml',
    'https://raw.githubusercontent.com/simonecorsi/mawesome/v1/action.yml',
    'https://raw.githubusercontent.com/simonecorsi/mawesome/main/action.yml',
    'https://raw.githubusercontent.com/simonecorsi/mawesome/v1/index.js',
]
INDICATOR_GROUPS = [PACKAGES, HASHES, PACKAGE_VERSIONS, TEXT_SELECTORS, VALIDATOR_REQUIRED_SELECTORS]

if not ROOT.exists():
    raise SystemExit(f"scan root does not exist: {ROOT}")

OUT.mkdir(parents=True, exist_ok=True)
indicators = set()
for group in INDICATOR_GROUPS:
    for value in group:
        indicators.add(value)

indicators_file = OUT / "indicators.txt"
indicators_file.write_text("\n".join(sorted(indicators)) + "\n", encoding="utf-8")
print(f"[+] Wrote selectors to {indicators_file}")


def scan_tree(base: Path) -> list[str]:
    matches: list[str] = []
    exclude_dirs = {".git", ".venv", "dist", "node_modules", "vendor", "coverage", OUT.name}
    for current_root, dirs, files in os.walk(base):
        dirs[:] = [entry for entry in dirs if entry not in exclude_dirs]
        for filename in files:
            file_path = Path(current_root) / filename
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                raise RuntimeError(f"failed to read {file_path}: {exc}") from exc
            for indicator in indicators:
                if indicator in content:
                    matches.append(f"{file_path}: found '{indicator}'")
    return matches


repository_matches = scan_tree(ROOT)
if repository_matches:
    repository_file = OUT / "repository-indicator-matches.txt"
    repository_file.write_text("\n".join(repository_matches) + "\n", encoding="utf-8")
    print(f"[!] Found {len(repository_matches)} repository matches")
else:
    print("[+] No repository matches found")

if LOG_ROOT:
    log_base = Path(LOG_ROOT).expanduser().resolve()
    if log_base.exists():
        log_matches = scan_tree(log_base)
        if log_matches:
            log_file = OUT / "exported-telemetry-indicator-matches.txt"
            log_file.write_text("\n".join(log_matches) + "\n", encoding="utf-8")
            print(f"[!] Found {len(log_matches)} exported telemetry matches")
        else:
            print("[+] No exported telemetry matches found")
    else:
        print(f"[!] LOG_ROOT does not exist: {log_base}")
```

## Downstream Abuse Audits
Any job that resolved the affected tags should be treated as an identity-exposure event first and a code-integrity event second. The public payload selectors show explicit interest in GitHub, Vault, and cloud credentials, so downstream scoping should prioritize those platforms even though a stable exfiltration endpoint has not yet been published. [5]

- **GitHub credentials and repository abuse:** Review GitHub audit logs, workflow-run metadata, and follow-on repository changes for identities that were available to affected jobs, because the payload contains GitHub API logic and repo-creation selectors rather than only local build manipulation. [5]
- **Vault and cloud identities:** Review Vault access logs and cloud control-plane logs for token use, role assumption, or secret reads tied to the disclosure window, because the public code visibly references `VAULT_TOKEN`, Azure client secrets, and Google application credentials. [5]
- **Package publishing and deployment systems:** Review registry and release-system activity for unauthorized publishes or token creation if the affected workflow held deployment credentials, because CI compromise frequently turns release automation into a downstream distribution path even when the initial repository change is small. [1] [5]

## Remediation and Closure
1. **Preserve evidence:** Export workflow files, run metadata, resolved action SHAs, and any retained runner caches before making upstream reference changes so later scoping can distinguish source-level exposure from confirmed execution.
2. **Stop active execution:** Disable workflows or organization-level templates that still resolve `simonecorsi/mawesome` by mutable tag, because further job runs can continue to fetch the affected composite wrapper.
3. **Contain affected assets and identities:** Isolate self-hosted runners that executed the affected refs and pause high-privilege automation identities that were exposed to those jobs until scoping is complete.
4. **Revoke and rotate credentials:** Rotate `GITHUB_TOKEN`-adjacent secrets, package-publish credentials, Vault tokens, and cloud identities reachable from presumed exposed runs from a clean environment, because the public payload selectors target exactly those identity classes. [5]
5. **Eradicate malicious artifacts and persistence:** Delete cached action checkouts, rebuild workspaces, and remove any retained copies of the affected `action.yml` or `index.js` from runner storage so the composite wrapper cannot execute again from stale local state.
6. **Rebuild untrusted systems:** Reimage or otherwise re-baseline self-hosted runners that resolved the affected refs when evidence is incomplete, because CI hosts often retain credentials, caches, and job artifacts outside the single workflow directory.
7. **Audit downstream activity:** Review GitHub, Vault, cloud, and registry logs for follow-on use of exposed identities during and after the disclosure window rather than waiting for a confirmed external IOC set.
8. **Recover using verified artifacts:** Replace mutable third-party action refs with reviewed full commit SHAs and validate that remediated workflows now resolve only the intended clean artifact.
9. **Close:** Close only when every repository hit has been dispositioned, replacement credentials are active, cached action content has been cleared, and risk owners explicitly accept any residual uncertainty caused by missing tag-history timestamps or absent maintainer disclosure.

## Sources
1. [**StepSecurity**](https://www.stepsecurity.io/blog/simonecorsi-mawesome-github-action-has-been-compromised): Primary research and current affected-tag table; confirms the incident exists but leaves the exact tag-move time and compromise path unresolved.
2. [**GitHub tags metadata**](https://api.github.com/repos/simonecorsi/mawesome/tags?per_page=100): Direct repository metadata showing which currently published refs resolve to the affected and unaffected commits.
3. [**Affected v1 action definition**](https://raw.githubusercontent.com/simonecorsi/mawesome/v1/action.yml): Direct artifact evidence that the affected ref is now a composite action that delegates to a clean SHA, installs Bun, and always runs a local `index.js` payload.
4. [**Current main action definition**](https://raw.githubusercontent.com/simonecorsi/mawesome/main/action.yml): Direct clean reference showing the expected node16 action structure without the injected composite Bun stage.
5. [**Affected v1 index.js**](https://raw.githubusercontent.com/simonecorsi/mawesome/v1/index.js): Direct public payload artifact supporting the capability assessment around obfuscation, credential handling, and GitHub API logic.
6. [**Affected commit API record**](https://api.github.com/repos/simonecorsi/mawesome/commits/e339407b8e34dc1540290d1d310bccafbc6028ca): Direct metadata for the affected commit, including its authored timestamp and the file list changed by that commit.
