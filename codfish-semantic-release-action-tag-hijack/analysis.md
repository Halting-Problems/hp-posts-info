---
title: "codfish/semantic-release-action GitHub Action Tag Hijack"
date: 2026-06-24
severity: "critical"
tags:
  - supply-chain
  - github-actions
  - ci-cd
  - credential-theft
  - tag-hijack
summary: "An attacker force-pushed a malicious composite action into codfish/semantic-release-action and moved fifteen published tags to that commit, exposing GitHub Actions runners that still trusted mutable refs such as v3, v4, and v5."
sourceCount: 5
---

## Executive Summary
On 2026-06-24, StepSecurity reported that `codfish/semantic-release-action` was compromised at **15:39:06 UTC**, with the attacker force-pushing a malicious commit and repointing several published action tags to that ref. Any workflow that continued to resolve those mutable tags after the hijack ran attacker-controlled code inside its GitHub Actions runner. [1]

Direct GitHub artifact checks confirm the risk remained live during this refresh. The tags API showed fifteen published refs — `v2.2.1`, every reviewed `v3.x` tag, every reviewed `v4.x` tag, and both `v5` tags — all resolving to commit `5792aba0e2180b9b80b77644370a6889d5817456`, while the maintained `main` branch still referenced the clean docker-based action definition at commit `8f9a58f2acdc190c356f79159b5de2548cdb63cd`. [2] [3] [4]

StepSecurity's analysis says the payload attempted to read `Runner.Worker` process memory for plaintext secrets, harvest GitHub OIDC material and Personal Access Tokens, encrypt collected data, and propagate into other repositories reachable with stolen credentials. Treat any affected run as a credential-exposure event even if no external exfiltration domain has been publicly decoded yet. [1]

## Key Facts
**Threat Type**: GitHub Action tag hijack and CI credential theft

**Affected Action**:
- codfish/semantic-release-action

**Affected Refs**:
- v2.2.1
- v3
- v3.0.0
- v3.1.0
- v3.1.1
- v3.2.0
- v3.3.0
- v3.4.0
- v3.4.1
- v3.5.0
- v4
- v4.0.0
- v4.0.1
- v5
- v5.0.0

**Malicious Commit**:
- 5792aba0e2180b9b80b77644370a6889d5817456

**Known Clean Reference**:
- 8f9a58f2acdc190c356f79159b5de2548cdb63cd (`main` action definition during this refresh)

**Exposure Window**: 2026-06-24T15:39:06Z to unknown

**Payload Trigger**: Workflow resolution of a compromised mutable `codfish/semantic-release-action` tag

**Primary Impact**: GitHub Actions runner secret theft, token replay risk, and attacker follow-on repository modification using credentials exposed to the job

**Known IOCs**:
- codfish/semantic-release-action@v5
- codfish/semantic-release-action@v4
- codfish/semantic-release-action@v3
- 5792aba0e2180b9b80b77644370a6889d5817456
- `oven-sh/setup-bun`
- `bun run $GITHUB_ACTION_PATH/index.js`

**Confidence**: high

## Evidence Assessment
- **confirmed:** StepSecurity reports a same-day repository compromise at 15:39:06 UTC, malicious tag repointing, and runner-side secret theft behavior. [1]
- **confirmed:** Fifteen currently published tags resolve to the same injected commit `5792aba0e2180b9b80b77644370a6889d5817456`. [2]
- **confirmed:** The compromised `action.yml` is no longer docker-based; it first delegates to the clean commit, then installs Bun and executes a bundled `index.js` payload under `if: always()`. [3]
- **confirmed:** The clean `main` branch action definition at `8f9a58f2acdc190c356f79159b5de2548cdb63cd` still uses a Docker runner and does not contain the injected Bun/composite steps. [4]
- **unclear:** Public reporting has not yet identified the initial repository-control mechanism, the full victim count, or a stable external exfiltration endpoint. [1]

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | A workflow run resolved one of the hijacked tags and runner telemetry shows the malicious Bun/composite selectors, memory-access behavior, or downstream credential abuse. | Run logs, resolved action SHA, runner process telemetry, and GitHub audit events tied to the affected job. | Isolate self-hosted runners, preserve workspace and cache artifacts, and rotate all credentials reachable by the job. | Affected runners are rebuilt or cleared, credentials are replaced, and downstream audits show no attacker use. |
| Presumed exposed | A workflow resolved one of the hijacked tags on or after 2026-06-24T15:39:06Z, but telemetry is incomplete. | Workflow files, run history, resolved SHA evidence, token permissions, and secret inventory. | Rotate reachable credentials and invalidate action caches even if exfiltration cannot be directly observed. | Every affected run is scoped and replacement credentials are active. |
| Potentially exposed | Repositories reference the action by mutable tag, but run timing or resolved SHAs are not yet known. | Repository search results plus GitHub Actions run exports or telemetry gaps. | Finish run-level scoping before ruling assets out. | Every repository hit is dispositioned as confirmed compromise, presumed exposed, or not exposed. |
| Not exposed | No affected repository or run resolved the compromised tags, or every relevant workflow was pinned to a reviewed full SHA outside the malicious set. | Repository search, run metadata, and cache inspection showing no affected refs or no execution. | Preserve negative evidence and enforce full-SHA pinning. | Search coverage includes reusable workflows, self-hosted runners, and cached action content. |
| Unknown | Required run metadata, cache artifacts, or runner telemetry is unavailable. | A documented telemetry gap naming the missing systems and time windows. | Keep the asset in scope and rotate high-value credentials conservatively. | Missing evidence is recovered or risk owners accept the residual uncertainty. |

### Minimum Evidence To Collect
- Workflow YAML, reusable workflows, and release templates that reference `codfish/semantic-release-action`, so responders can determine whether mutable refs remained in use after the hijack window.
- GitHub Actions run history showing the resolved action SHA for each candidate job, because a repository may mention `v5` while an individual run still used cached clean content.
- Self-hosted runner caches or workspace copies of the action checkout, because the malicious `action.yml` and `index.js` can persist outside GitHub's current repository state.
- GitHub audit logs, token inventories, and cloud trust-policy logs for identities reachable from affected jobs, because StepSecurity observed token harvesting and propagation logic rather than a one-shot build failure. [1]
- Repository and telemetry searches for `oven-sh/setup-bun`, `bun run $GITHUB_ACTION_PATH/index.js`, and commit `5792aba0e2180b9b80b77644370a6889d5817456`, because those selectors distinguish the injected composite action from the clean docker-based implementation. [2] [3] [4]

## Timeline
- **2026-06-24T15:39:06Z:** StepSecurity says the attacker force-pushed the malicious commit and moved published action tags to that ref. [1]
- **2026-06-24T16:04:06Z:** GitHub repository metadata showed a same-day update after the compromise window, indicating maintainer activity in the affected repository. [2]
- **2026-06-24T16:31:43Z:** A new `testing` branch appeared in repository metadata during the response window. [2]
- **2026-06-24T18:26:38Z:** StepSecurity published the public technical write-up for the compromise. [1]

## What Happened
The compromise abused the trust model around mutable GitHub Action tags. Downstream repositories could continue using familiar references such as `v3`, `v4`, or `v5` without changing their workflow files, yet the next run would fetch whichever commit the tag currently pointed to. In this case, fifteen published tags now resolve to the same injected commit rather than the clean implementation on `main`. [2] [4]

The malicious action did not simply replace the legitimate logic with a failing stub. The injected `action.yml` first called the clean commit by full SHA and then ran attacker-controlled Bun code under `if: always()`, preserving expected release behavior while guaranteeing payload execution even when earlier steps failed. That design sharply increases the chance that affected organizations will mistake a successful release for a safe release. [3] [4]

## Technical Analysis
### Initial Access
Public reporting confirms repository control and tag repointing but does not yet explain how the attacker obtained write access. That uncertainty matters because responders should not assume the risk ended with tag restoration; the compromise path may also have exposed maintainer tokens, GitHub Apps, or release credentials outside the affected repository itself. [1]

### Package or Artifact Manipulation
The clean action on `main` is docker-based, with `runs.using: docker` and `image: Dockerfile`. The compromised `action.yml` instead becomes a composite action that first delegates to the clean SHA `8f9a58f2acdc190c356f79159b5de2548cdb63cd`, then adds `oven-sh/setup-bun` and a `bun run $GITHUB_ACTION_PATH/index.js` execution step. That artifact-level change is direct proof that mutable refs had been repointed to attacker-selected content. [3] [4]

### Execution Trigger
The trigger condition is ordinary workflow resolution of a mutable action tag. No malicious pull request or local repository change is required in the victim project: a workflow that still references `codfish/semantic-release-action@v5`, `@v4`, `@v3`, or the other affected tags will download the altered composite action the next time GitHub resolves the ref. [1] [2]

### Payload Behavior
StepSecurity reports that the injected JavaScript payload is heavily obfuscated, attempts to read `Runner.Worker` memory for plaintext secrets, harvests GitHub OIDC material and PAT-like tokens, encrypts collected data, and tries to backdoor additional repositories reachable with the stolen credentials. Even without a public C2 endpoint, those behaviors make the incident operationally equivalent to a runner secret compromise rather than a simple availability issue. [1]

### Defense Evasion
The attacker preserved expected release behavior by chaining the clean action before the malicious Bun step, reducing the chance that maintainers or downstream users would notice a failure. Running the payload under `if: always()` also means the malicious code can execute after partial job failure, which widens exposure across builds that may appear unsuccessful yet still leaked credentials. [3]

### Exfiltration and Command and Control
StepSecurity says the current public analysis window did not yet decode a stable external exfiltration endpoint from the obfuscated payload. Defenders should therefore focus on run-level credential exposure, GitHub API follow-on activity, and repository modifications reachable from affected identities instead of waiting for a domain-based IOC list that may arrive later. [1]

## Affected Assets and Blast Radius
The blast radius is defined by where the action ran, not only where the workflow file exists. A repository that referenced `codfish/semantic-release-action@v5` but never executed after 15:39:06 UTC is materially different from a self-hosted runner that resolved the tag, executed the payload, and retained workspace caches.

| Asset class | Exposure path | Why it matters |
| --- | --- | --- |
| GitHub repositories | Mutable action refs in workflow or reusable workflow files | A single inherited release template can spread exposure across many repos. |
| GitHub-hosted runners | Workflow runs resolving the compromised tags | Job tokens and secrets exist in runner memory during execution. |
| Self-hosted runners | Cached action checkouts and persisted workspaces | The malicious composite action can survive after the upstream repo changes. |
| Cloud identities | `id-token: write` or cloud credentials exposed to release jobs | Stolen OIDC or cloud credentials can be replayed outside GitHub Actions. |
| Package registries and release systems | Publish tokens or deploy credentials available to semantic-release jobs | Attackers can pivot from CI compromise into downstream software distribution. |

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across repositories, run artifacts, and exported telemetry.

### Package Versions
- codfish/semantic-release-action@v2.2.1
- codfish/semantic-release-action@v3
- codfish/semantic-release-action@v3.0.0
- codfish/semantic-release-action@v3.1.0
- codfish/semantic-release-action@v3.1.1
- codfish/semantic-release-action@v3.2.0
- codfish/semantic-release-action@v3.3.0
- codfish/semantic-release-action@v3.4.0
- codfish/semantic-release-action@v3.4.1
- codfish/semantic-release-action@v3.5.0
- codfish/semantic-release-action@v4
- codfish/semantic-release-action@v4.0.0
- codfish/semantic-release-action@v4.0.1
- codfish/semantic-release-action@v5
- codfish/semantic-release-action@v5.0.0

### Files
- action.yml
- index.js

### Hashes
- 5792aba0e2180b9b80b77644370a6889d5817456
- 8f9a58f2acdc190c356f79159b5de2548cdb63cd

### Process Patterns
- oven-sh/setup-bun
- bun run $GITHUB_ACTION_PATH/index.js
- Runner.Worker memory access

## Detection and Hunting

### Hunt Manifest: codfish-semantic-release-action-tag-hijack-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain references associated with the codfish/semantic-release-action tag hijack?
- **Telemetry Family:** process
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Workflow content, caches, or exported telemetry contains compromised codfish/semantic-release-action refs, the malicious commit SHA, or the injected Bun/composite-action selectors.
- **False Positives:** Historical documentation, archived advisories, or lab fixtures that intentionally preserve the malicious selectors.
- **Classification on Match:** Treat a match as at least potentially exposed; escalate to presumed exposed if a workflow or run history proves execution during or after the tag hijack window.

```py
#!/usr/bin/env python3
import os
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").expanduser().resolve()
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-codfish-semantic-release-action-tag-hijack-scope"))

PACKAGES = ["codfish/semantic-release-action"]
HASHES = [
    "5792aba0e2180b9b80b77644370a6889d5817456",
    "8f9a58f2acdc190c356f79159b5de2548cdb63cd",
]
PACKAGE_VERSIONS = [
    "codfish/semantic-release-action@v5.0.0",
    "codfish/semantic-release-action@v5",
    "codfish/semantic-release-action@v4.0.1",
    "codfish/semantic-release-action@v4.0.0",
    "codfish/semantic-release-action@v4",
    "codfish/semantic-release-action@v3.5.0",
    "codfish/semantic-release-action@v3.4.1",
    "codfish/semantic-release-action@v3.4.0",
    "codfish/semantic-release-action@v3.3.0",
    "codfish/semantic-release-action@v3.2.0",
    "codfish/semantic-release-action@v3.1.1",
    "codfish/semantic-release-action@v3.1.0",
    "codfish/semantic-release-action@v3.0.0",
    "codfish/semantic-release-action@v3",
    "codfish/semantic-release-action@v2.2.1",
]
TEXT_SELECTORS = [
    'uses: "codfish/semantic-release-action@8f9a58f2acdc190c356f79159b5de2548cdb63cd"',
    "oven-sh/setup-bun",
    "bun run $GITHUB_ACTION_PATH/index.js",
    "using: composite",
]

VALIDATOR_REQUIRED_SELECTORS = [
    'action.yml',
    'Runner.Worker memory access',
    'https://raw.githubusercontent.com/codfish/semantic-release-action/5792aba0e2180b9b80b77644370a6889d5817456/action.yml',
    'https://raw.githubusercontent.com/codfish/semantic-release-action/8f9a58f2acdc190c356f79159b5de2548cdb63cd/action.yml',
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
    exclude_dirs = {".git", ".venv", "dist", "node_modules", "vendor", "coverage"}
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
        raise SystemExit(f"LOG_ROOT does not exist: {log_base}")

print(f"[+] Scope artifacts written under {OUT}")
```

## Downstream Abuse Audits
- **GitHub repositories and Actions tokens:** Review audit logs for unexpected workflow edits, release creation, tag movement, repository invitations, PAT creation, and pushes initiated by identities reachable from affected runs.
- **GitHub OIDC trust relationships:** Enumerate jobs with `permissions.id-token: write` and inspect downstream cloud sign-ins tied to those workflows after 2026-06-24T15:39:06Z.
- **Package registries and deployment systems:** Audit npm, PyPI, container registry, and release credentials exposed to semantic-release jobs because the attacker targeted automation contexts that frequently hold publish rights.
- **Self-hosted runner persistence:** Inspect runner caches, working directories, and shell histories for retained copies of the compromised action checkout and post-run repository modifications.

## Remediation and Closure
1. **Preserve evidence:** Export workflow definitions, run metadata, runner logs, cache entries, and the resolved action SHA for every suspected job before modifying repositories or caches.
2. **Stop active execution:** Disable workflows or replace the affected action refs with reviewed full SHAs before any further release jobs run.
3. **Contain affected assets and identities:** Isolate self-hosted runners that executed the compromised refs and temporarily narrow GitHub environment or branch protections if automated release identities are still active.
4. **Revoke and rotate credentials:** Replace `GITHUB_TOKEN`-backed secrets, PATs, registry credentials, cloud credentials, and any other secrets available to affected jobs from a clean environment.
5. **Eradicate malicious artifacts and persistence:** Delete cached action content, clean persistent workspaces, and remove any unauthorized repository changes or newly added automations that appeared after the exposure window.
6. **Rebuild untrusted systems:** Rebuild self-hosted runners or restore them from a known-clean image when runner integrity cannot be established from logs alone.
7. **Audit downstream activity:** Review GitHub audit trails, registry publishing logs, and cloud control-plane events for follow-on abuse using credentials that were reachable from affected runs.
8. **Recover using verified artifacts:** Re-enable release pipelines only after workflows pin full SHAs, least-privilege permissions are restored, and replacement credentials are validated.
9. **Close:** Close the incident only when every repository hit has been dispositioned, compromised refs are removed, replacement credentials are active, and residual telemetry gaps are explicitly accepted by the risk owner.

## Sources
1. [StepSecurity: codfish/semantic-release-action GitHub Action has been compromised](https://www.stepsecurity.io/blog/supply-chain-compromise-codfish-semantic-release-action) - **Role:** PRIMARY_RESEARCH - **Impact:** compromise time, malicious behavior, payload goals, and attacker workflow.
2. [GitHub tags API: codfish/semantic-release-action](https://api.github.com/repos/codfish/semantic-release-action/tags?per_page=100) - **Role:** DIRECT_SOURCE - **Impact:** current tag-to-commit mappings showing fifteen published refs on the same injected SHA.
3. [Raw malicious action.yml at 5792aba0e2180b9b80b77644370a6889d5817456](https://raw.githubusercontent.com/codfish/semantic-release-action/5792aba0e2180b9b80b77644370a6889d5817456/action.yml) - **Role:** DIRECT_SOURCE - **Impact:** proof of the composite-action conversion, Bun setup step, and payload execution path.
4. [Raw clean action.yml at 8f9a58f2acdc190c356f79159b5de2548cdb63cd](https://raw.githubusercontent.com/codfish/semantic-release-action/8f9a58f2acdc190c356f79159b5de2548cdb63cd/action.yml) - **Role:** DIRECT_SOURCE - **Impact:** clean docker-based baseline used to confirm the malicious delta.
5. [GitHub repository API: codfish/semantic-release-action](https://api.github.com/repos/codfish/semantic-release-action) - **Role:** DIRECT_SOURCE - **Impact:** repository metadata showing same-day response activity and branch state during this refresh.
