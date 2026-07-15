# Research Packet: TrapDoor Cross-Ecosystem Crypto Stealer Campaign

## Packet Metadata
```yaml
packet_version: "2.0"
event_id: "trapdoor-cross-ecosystem-crypto-stealer-2026-05-24"
event_name: "TrapDoor Cross-Ecosystem Crypto Stealer Campaign"
research_date: "2026-05-24"
last_verified: "2026-05-24"
publication_state: "publish_ready"
confidence: "medium"
confidence_reason: "Socket provides primary cross-registry analysis, OSV confirms multiple PyPI malicious-package records in the same campaign, and the attacker GitHub Pages repository remains directly observable. Confidence is medium rather than high because the campaign is active and the complete affected package/version list is still changing."
dedupe_keys:
  - "campaign:trapdoor:2026-05"
  - "pypi:eth-security-auditor:0.1.0"
  - "pypi:env-loader-cli:0.1.0"
  - "npm:dev-env-bootstrapper"
  - "crates:sui-framework-helpers:0.1.0"
```

Local feed check on 2026-05-24: no matches were found in `src/content/threat-posts` or `~/second-brain` for `TrapDoor`, `ddjidd564`, `eth-security-auditor`, `env-loader-cli`, `sui-framework-helpers`, `trap-core.js`, or `ddjidd564.github.io`.

## Source Inventory
| Source Name | Role | URL | Access Type | Evidence Provided | Reliability Notes | Last Checked |
| --- | --- | --- | --- | --- | --- | --- |
| Socket TrapDoor research | PRIMARY_RESEARCH | https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates | TRULY_PUBLIC_NO_KEY | Campaign scope, package names, publication timing, execution triggers, payload behavior, infrastructure, IOCs, registry reporting status. | Original vendor research with cross-registry behavioral analysis. | 2026-05-24 |
| OSV PyPI malicious-package list | DIRECT_SOURCE | https://osv.dev/list?ecosystem=PyPI | TRULY_PUBLIC_NO_KEY | Multiple recent PyPI malicious package records tied to the wave, including `env-loader-cli`, `data-pipeline-check`, `git-config-sync`, `defi-risk-scanner`, `cryptowallet-safety`, `solidity-build-guard`, and `eth-security-auditor`. | Official OSV vulnerability database listing. | 2026-05-24 |
| OSV MAL-2026-4272 | DIRECT_SOURCE | https://osv.dev/vulnerability/MAL-2026-4272 | TRULY_PUBLIC_NO_KEY | Confirms `env-loader-cli` malicious code, campaign label `2026-05-eth-security-auditor`, import-time exfiltration, IOCs, affected versions `0.1.0` and `0.1.1`, and reporter metadata. | Official OSV record imported from OpenSSF malicious-packages data. | 2026-05-24 |
| Attacker GitHub Pages repository | DIRECT_SOURCE | https://github.com/ddjidd564/defi-security-best-practices/tree/gh-pages | TRULY_PUBLIC_NO_KEY | Directly observable infrastructure repository, branch, payload directories, `trap-core`, `.cursorrules`, `CLAUDE.md`, and lure/security-themed files. | Direct artifact host. Treat content as adversary-controlled, not as reliable narrative. | 2026-05-24 |
| docs.rs package page for `sui-framework-helpers` | DIRECT_SOURCE | https://docs.rs/crate/sui-framework-helpers/0.1.0 | TRULY_PUBLIC_NO_KEY | Confirms a Rust crate named `sui-framework-helpers` version `0.1.0` with source listing and 2026-05-24 version metadata. | Direct package documentation mirror for the crates.io artifact. | 2026-05-24 |
| Xygeni AuditorTrap research | PRIMARY_RESEARCH | https://xygeni.io/nl/blog/auditortrap-a-22-package-fake-crypto-security-guild-on-npm-with-two-parallel-payloads/ | TRULY_PUBLIC_NO_KEY | Similar Web3/security-tool lure pattern and npm package cluster context. | Adjacent research. Do not use to merge campaigns without hard infrastructure overlap. | 2026-05-24 |

## Feed And Watch List
```yaml
TRULY_PUBLIC_NO_KEY:
  - "https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates"
  - "https://socket.dev/supply-chain-attacks/trapdoor-crypto-stealer-campaign"
  - "https://osv.dev/list?ecosystem=PyPI"
  - "https://osv.dev/vulnerability/MAL-2026-4272"
  - "https://github.com/ddjidd564/defi-security-best-practices/tree/gh-pages"
  - "https://docs.rs/crate/sui-framework-helpers/0.1.0/source/"
PUBLIC_BUT_RATE_LIMITED:
  - "https://api.osv.dev/v1/vulns/MAL-2026-4272"
  - "https://registry.npmjs.org/<package>"
  - "https://pypi.org/pypi/<package>/json"
API_KEY_OR_AUTH_REQUIRED: []
PAID_OR_RESTRICTED:
  - "VirusTotal Intelligence"
  - "Socket package alert details beyond public pages"
PAGE_WATCH_FALLBACK:
  - "https://www.npmjs.com/package/dev-env-bootstrapper"
  - "https://pypi.org/project/eth-security-auditor/"
  - "https://crates.io/crates/sui-framework-helpers"
CANDIDATE_FEED_UNVERIFIED:
  - "OpenSSF malicious-packages repository paths for every TrapDoor package"
```

## Executive Findings
- TrapDoor is an active cross-ecosystem software supply chain campaign reported by Socket on 2026-05-24. Socket says it spans npm, PyPI, and Crates.io, with more than 34 malicious packages and 384 or more related versions/artifacts.
- The campaign targets crypto, DeFi, Solana, Sui/Move, AI, and security-tooling developers with packages that look like environment scanners, wallet safety tools, model-routing helpers, deployment validators, and build utilities.
- Execution paths are ecosystem-specific: npm packages use postinstall hooks, PyPI packages run on import and execute remote JavaScript through `node -e`, and Rust crates use `build.rs` during compilation.
- Socket reports shared infrastructure at `ddjidd564[.]github[.]io/defi-security-best-practices/`, GitHub account `ddjidd564`, campaign marker `P-2024-001`, and payload `trap-core.js`.
- OSV independently confirms malicious PyPI records tied to campaign `2026-05-eth-security-auditor`, including import-time exfiltration and URLs under `ddjidd564.github.io/defi-security-best-practices/`.
- Defensive priority is not just package removal. Any developer workstation, CI runner, container build host, or wallet-development host that installed or executed these packages should be treated as potentially compromised because the payloads target SSH keys, GitHub tokens, AWS credentials, browser data, environment variables, crypto wallets, and AI assistant instruction files.

## Claim Ledger
```yaml
claims:
  - claim_id: C001
    claim: "TrapDoor spans npm, PyPI, and Crates.io and includes more than 34 malicious packages and 384 or more related versions/artifacts."
    status: confirmed
    confidence: medium
    evidence_type: "primary_research"
    sources:
      - name: "Socket TrapDoor research"
        url: "https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates"
        role: "PRIMARY_RESEARCH"
    notes: "Campaign scope may grow because Socket described it as active."
  - claim_id: C002
    claim: "The earliest package Socket observed was PyPI package eth-security-auditor 0.1.0, uploaded on 2026-05-22 at 20:20:18 UTC, with the wheel at 20:22:04 UTC."
    status: confirmed
    confidence: medium
    evidence_type: "primary_research"
    sources:
      - name: "Socket TrapDoor research"
        url: "https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates"
        role: "PRIMARY_RESEARCH"
    notes: "Use as Socket-observed first-seen, not necessarily global first-seen."
  - claim_id: C003
    claim: "OSV records identify env-loader-cli as malicious, assign it to campaign 2026-05-eth-security-auditor, and list affected versions 0.1.0 and 0.1.1."
    status: confirmed
    confidence: high
    evidence_type: "direct_source"
    sources:
      - name: "OSV MAL-2026-4272"
        url: "https://osv.dev/vulnerability/MAL-2026-4272"
        role: "DIRECT_SOURCE"
    notes: "OSV record includes reporter source and malicious-package origin metadata."
  - claim_id: C004
    claim: "PyPI TrapDoor packages execute on import and download or execute remote JavaScript from attacker-controlled GitHub Pages infrastructure."
    status: confirmed
    confidence: high
    evidence_type: "direct_source"
    sources:
      - name: "OSV MAL-2026-4272"
        url: "https://osv.dev/vulnerability/MAL-2026-4272"
        role: "DIRECT_SOURCE"
      - name: "Socket TrapDoor research"
        url: "https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates"
        role: "PRIMARY_RESEARCH"
    notes: "OSV states import-time exfiltration and remote malicious script execution for env-loader-cli; Socket generalizes across the PyPI set."
  - claim_id: C005
    claim: "npm TrapDoor packages use postinstall execution and a shared trap-core.js payload."
    status: confirmed
    confidence: medium
    evidence_type: "malware_analysis"
    sources:
      - name: "Socket TrapDoor research"
        url: "https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates"
        role: "PRIMARY_RESEARCH"
    notes: "Direct registry pages should be rechecked before publication if package removals alter availability."
  - claim_id: C006
    claim: "Crates.io TrapDoor packages use build.rs scripts that execute during Rust package compilation."
    status: confirmed
    confidence: medium
    evidence_type: "malware_analysis"
    sources:
      - name: "Socket TrapDoor research"
        url: "https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates"
        role: "PRIMARY_RESEARCH"
      - name: "docs.rs sui-framework-helpers 0.1.0"
        url: "https://docs.rs/crate/sui-framework-helpers/0.1.0/source/"
        role: "DIRECT_SOURCE"
    notes: "docs.rs confirms source listing includes build.rs for at least one package named in the campaign."
  - claim_id: C007
    claim: "The attacker used AI-facing files such as .cursorrules and CLAUDE.md as persistence or prompt-injection surfaces."
    status: confirmed
    confidence: medium
    evidence_type: "primary_research"
    sources:
      - name: "Socket TrapDoor research"
        url: "https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates"
        role: "PRIMARY_RESEARCH"
      - name: "Attacker GitHub Pages repository"
        url: "https://github.com/ddjidd564/defi-security-best-practices/tree/gh-pages"
        role: "DIRECT_SOURCE"
    notes: "Direct repo listing shows both file names; the effectiveness across AI tools is uncertain."
  - claim_id: C008
    claim: "TrapDoor is not currently covered on the local haltingproblems.com feed."
    status: confirmed
    confidence: high
    evidence_type: "local_feed_dedupe"
    sources:
      - name: "Local rg search"
        url: "local:/home/sam/haltingproblems.com/src/content/threat-posts"
        role: "DIRECT_SOURCE"
      - name: "Local rg search"
        url: "local:/home/sam/second-brain"
        role: "DIRECT_SOURCE"
    notes: "Searched TrapDoor, package names, infrastructure, and campaign markers on 2026-05-24."
```

## Event Cluster
```yaml
event_id: "trapdoor-cross-ecosystem-crypto-stealer-2026-05-24"
event_name: "TrapDoor Cross-Ecosystem Crypto Stealer Campaign"
parent_campaign_id: "none"
is_campaign_level: true
attack_types:
  - "malicious package"
  - "cross-registry campaign"
  - "postinstall malware"
  - "import-time malware"
  - "build-script malware"
  - "credential theft"
  - "crypto wallet theft"
  - "AI assistant instruction poisoning"
affected_assets:
  ecosystems:
    - "npm"
    - "PyPI"
    - "Crates.io"
  registries:
    - "npmjs.com"
    - "pypi.org"
    - "crates.io"
  packages:
    npm:
      - "async-pipeline-builder"
      - "build-scripts-utils"
      - "chain-key-validator"
      - "crypto-credential-scanner"
      - "defi-env-auditor"
      - "defi-threat-scanner"
      - "deployment-key-auditor"
      - "dev-env-bootstrapper"
      - "eth-wallet-sentinel"
      - "llm-context-compressor"
      - "mnemonic-safety-check"
      - "model-switch-router"
      - "node-setup-helpers"
      - "project-init-tools"
      - "prompt-engineering-toolkit"
      - "solidity-deploy-guard"
      - "token-usage-tracker"
      - "wallet-backup-verifier"
      - "wallet-security-checker"
      - "web3-secrets-detector"
      - "workspace-config-loader"
    pypi:
      - "cryptowallet-safety"
      - "data-pipeline-check"
      - "defi-risk-scanner"
      - "env-loader-cli"
      - "eth-security-auditor"
      - "git-config-sync"
      - "solidity-build-guard"
    crates:
      - "move-analyzer-build"
      - "move-compiler-tools"
      - "move-project-builder"
      - "sui-framework-helpers"
      - "sui-move-build-helper"
      - "sui-sdk-build-utils"
  versions:
    - "env-loader-cli 0.1.0"
    - "env-loader-cli 0.1.1"
    - "eth-security-auditor 0.1.0"
    - "sui-framework-helpers 0.1.0"
    - "many other versions still being tracked"
  repositories:
    - "https://github.com/ddjidd564/defi-security-best-practices/tree/gh-pages"
  vendors: []
  ci_cd_systems:
    - "developer CI runners"
    - "GitHub Actions"
    - "GitLab CI"
    - "CircleCI"
    - "Travis CI"
  container_images: []
  developer_tools:
    - "Cursor"
    - "Claude Code style CLAUDE.md workflows"
    - "AI coding assistant project instruction files"
    - "Rust cargo build"
    - "Python import workflows"
    - "npm install workflows"
  credentials_at_risk:
    - "SSH private keys"
    - "GitHub tokens"
    - "AWS credentials"
    - "cloud credentials"
    - "browser profile data"
    - "crypto wallet data"
    - "environment variables"
    - "API keys"
identifiers:
  cve: []
  ghsa: []
  osv:
    - "MAL-2026-4272"
    - "MAL-2026-4271"
    - "MAL-2026-4273"
    - "MAL-2026-4260"
    - "MAL-2026-4259"
    - "MAL-2026-4262"
    - "MAL-2026-4261"
  snyk: []
  other:
    - "P-2024-001"
```

## Artifact Analysis
```yaml
artifact_analysis:
  malicious_artifacts:
    - "trap-core.js"
    - ".cursorrules"
    - "CLAUDE.md"
    - "build.rs"
    - "postinstall hooks in npm package manifests"
    - "Python import-time loaders that invoke node -e"
  known_good_artifacts: []
  diff_summary: "Socket reports ecosystem-specific malicious execution paths: npm postinstall hooks, PyPI import-time remote JavaScript execution, and Rust build.rs execution during compilation. OSV confirms import-time credential exfiltration for env-loader-cli."
  execution_trigger: "npm install postinstall, Python import, Rust cargo build/build.rs"
  payload_behavior:
    - "credential file discovery"
    - "environment variable harvesting"
    - "AWS and GitHub credential validation"
    - "crypto wallet and keystore collection"
    - "browser profile and login database collection"
    - "SSH-key based lateral movement attempts"
    - "AI assistant instruction file planting"
    - "remote configuration and payload retrieval from GitHub Pages"
  persistence:
    - ".cursorrules"
    - "CLAUDE.md"
    - "Git hooks"
    - "shell hooks"
    - "systemd"
    - "cron"
    - "SSH propagation"
  exfiltration:
    - "GitHub Pages hosted command/config infrastructure"
    - "GitHub Gists for Rust keystore exfiltration, per Socket"
    - "remote URLs under ddjidd564.github.io/defi-security-best-practices/"
  propagation:
    - "SSH-based propagation attempts from stolen keys"
    - "AI instruction file seeding"
    - "malicious PRs to developer and AI projects, per Socket"
  evasion:
    - "benign-sounding package names"
    - "AI/security audit disguise layer"
    - "zero-width Unicode in AI-facing instruction files, per Socket"
    - "Fernet/ECDH encryption in npm payloads, per Socket"
    - "XOR encryption with cargo-build-helper-2026 in Crates.io packages, per Socket"
  provenance:
    present: null
    type: "unknown"
    issuer: "unknown"
    identity: "unknown"
    workflow_ref: "unknown"
    verified: null
    notes: "No trustworthy package provenance evidence was located during this packet. Registry publishing accounts and exact provenance/signing state require follow-up."
```

## Timeline
```yaml
timeline:
  first_seen: "2026-05-22T20:20:18Z"
  malicious_publish_time: "2026-05-22T20:20:18Z"
  discovery_time: "unknown"
  removal_time: "unknown"
  disclosure_time: "2026-05-24"
  patch_or_fix_time: "unknown"
  source_disagreements:
    - "Socket headline says 34 packages while article summary text says 36 malicious packages. Treat package count as 34+ until campaign page/package list stabilizes."
```

- **2026-05-22T20:20:18Z** Socket's earliest observed package, `eth-security-auditor@0.1.0`, was uploaded to PyPI.
- **2026-05-22T20:22:04Z** Socket reports the `eth-security-auditor` wheel publication time.
- **2026-05-24T05:42:09Z** OSV published `MAL-2026-4272` for `env-loader-cli`.
- **2026-05-24** Socket published public TrapDoor campaign research.
- **2026-05-24** Local feed dedupe found no existing TrapDoor coverage.

## Indicators And Observables
```yaml
iocs:
  package_versions:
    - "PyPI/env-loader-cli 0.1.0"
    - "PyPI/env-loader-cli 0.1.1"
    - "PyPI/eth-security-auditor 0.1.0"
    - "Crates.io/sui-framework-helpers 0.1.0"
    - "npm/dev-env-bootstrapper version unknown"
  files:
    - "trap-core.js"
    - ".cursorrules"
    - "CLAUDE.md"
    - "build.rs"
    - "Cargo.toml"
  hashes: []
  domains:
    - "ddjidd564[.]github[.]io"
  urls:
    - "hxxps://ddjidd564[.]github[.]io/defi-security-best-practices/"
    - "hxxps://ddjidd564[.]github[.]io/defi-security-best-practices/config.json"
    - "hxxps://ddjidd564[.]github[.]io/defi-security-best-practices/payloads/compliance-scanner-light.js"
    - "hxxps://ddjidd564[.]github[.]io/defi-security-best-practices/payloads/risk-profiler.js"
  ips: []
  registry_metadata:
    - "OSV campaign: 2026-05-eth-security-auditor"
    - "OSV MAL-2026-4272: PyPI/env-loader-cli"
  github_audit_events:
    - "Pull requests adding .cursorrules or CLAUDE.md to AI/developer repositories"
    - "References to campaign marker P-2024-001"
  process_patterns:
    - "npm postinstall spawning node for trap-core.js"
    - "python importing package then spawning node -e"
    - "cargo build executing unexpected build.rs network or filesystem collection logic"
    - "unexpected systemd, cron, shell hook, or Git hook creation after package install"
  network_patterns:
    - "HTTP(S) requests to ddjidd564[.]github[.]io from developer workstations or CI runners"
    - "GitHub API credential validation immediately after package install"
    - "AWS STS or metadata credential validation immediately after package install"
  provenance_signals:
    - "new low-volume packages with security, wallet, DeFi, AI, or build-helper naming"
    - "recently published versions with postinstall, import-time, or build.rs execution"
```

## Detection Opportunities
```yaml
detection:
  lockfile_hunts:
    - "Search package-lock.json, pnpm-lock.yaml, yarn.lock for TrapDoor npm package names."
    - "Search requirements.txt, poetry.lock, Pipfile.lock, uv.lock for TrapDoor PyPI package names."
    - "Search Cargo.lock for TrapDoor Crates.io package names."
    - "Search composer/npm/Python/Rust dependency inventories for ddjidd564, P-2024-001, and trap-core.js."
  filesystem_hunts:
    - "Find .cursorrules or CLAUDE.md files created or modified soon after package installation."
    - "Find trap-core.js in npm cache, package manager cache, workspaces, and CI artifacts."
    - "Find Rust build.rs files in new low-volume Sui/Move helper crates."
    - "Find Git hooks, shell profile modifications, systemd units, or cron entries created after installing named packages."
  process_hunts:
    - "npm -> node trap-core.js"
    - "python -> node -e"
    - "cargo -> build.rs -> network or file discovery commands"
    - "node/python/rust build process invoking ssh, git, aws, gh, curl, wget, systemctl, crontab"
  network_hunts:
    - "Egress to ddjidd564[.]github[.]io from developer or CI networks."
    - "GitHub token validation or AWS credential validation after package install."
    - "GitHub Gist creation or upload from cargo build hosts."
  ci_cd_hunts:
    - "New .cursorrules, CLAUDE.md, Git hooks, shell hooks, systemd, or cron artifacts committed by build jobs."
    - "Unexpected SSH outbound activity from CI runners after dependency installation."
    - "Package install steps followed by cloud metadata access or credential-validation API calls."
  registry_hunts:
    - "New packages with wallet, DeFi, model routing, prompt engineering, security audit, or build-helper naming from new publishers."
    - "Packages with install/import/build hooks plus outbound network behavior."
  sigma_candidates:
    - "Process Creation: Python spawning node -e during import or test execution."
    - "Process Creation: npm lifecycle hook creates persistence files."
    - "Network: CI runner outbound to ddjidd564.github.io."
  yara_candidates:
    - "Detect trap-core.js string markers, P-2024-001, ddjidd564.github.io, cargo-build-helper-2026, .cursorrules, CLAUDE.md."
  telemetry_requirements:
    - "EDR process creation with parent-child command lines."
    - "DNS and HTTP proxy logs from developer and CI networks."
    - "Package lockfile inventory."
    - "GitHub audit logs and PR metadata."
    - "Cloud audit logs for token validation and metadata access."
```

## Remediation And Prevention
- **Immediate:** Block installation of the listed npm, PyPI, and Crates.io package names in package managers, artifact proxies, SCA policy, and CI dependency allowlists.
- **Immediate:** Search lockfiles, package caches, build logs, container layers, and developer workstations for listed packages, `trap-core.js`, `P-2024-001`, `ddjidd564.github.io`, `.cursorrules`, and `CLAUDE.md`.
- **Immediate:** Treat affected hosts as compromised. Rotate SSH keys, GitHub tokens, cloud credentials, registry tokens, crypto wallet material, API keys, environment secrets, and CI/CD credentials from a clean host.
- **Short-term:** Preserve package artifacts, lockfiles, package-manager caches, process execution logs, DNS/proxy logs, GitHub audit events, and CI job logs before cleanup.
- **Short-term:** Rebuild developer workstations, CI runners, and containers that executed the packages where secrets were available.
- **Long-term:** Enforce dependency cooldowns, block packages with lifecycle/build/import execution unless explicitly approved, monitor AI assistant instruction files, restrict CI egress, and require package reputation checks for new security/crypto/dev-tool packages.

## Open Questions And Collection Gaps
- The complete package/version list is still moving. Pull the Socket campaign page and OSV/OpenSSF malicious-package data again before final publication.
- Exact npm and crates.io malicious version numbers need direct registry confirmation for every listed package.
- Registry removal/yank status is incomplete.
- Provenance/signing/trusted-publishing status was not established.
- The relationship between TrapDoor and Xygeni's AuditorTrap cluster should not be asserted without hard infrastructure or payload overlap.
- The effectiveness of `.cursorrules` and `CLAUDE.md` prompt-injection persistence depends on local AI tool behavior and remains tool-specific.

## Publication Decision
```yaml
publication_state: "publish_ready"
why: "The event is absent from the local feed, has primary Socket analysis, direct OSV malicious-package records for part of the campaign, and directly observable attacker infrastructure. Publish with active-campaign caveats and a clear note that package counts may change."
required_human_review:
  - "Recheck Socket campaign page for final package count."
  - "Recheck OSV/OpenSSF records for new package identifiers."
  - "If adding all malicious versions, verify direct registry metadata first."
writer_instructions:
  - "Write as a campaign-level post, not a single package incident."
  - "Use medium confidence for campaign scope and high confidence for OSV-confirmed PyPI package facts."
  - "Defang ddjidd564.github.io in prose and YAML."
  - "Do not claim actor attribution beyond the observed GitHub account/infrastructure."
```

## Machine-Readable Event Profile
```json
{
  "schema_version": "2.0",
  "event_id": "trapdoor-cross-ecosystem-crypto-stealer-2026-05-24",
  "event_name": "TrapDoor Cross-Ecosystem Crypto Stealer Campaign",
  "parent_campaign_id": "none",
  "is_campaign_level": true,
  "publication_state": "publish_ready",
  "confidence": "medium",
  "confidence_reason": "Socket provides primary cross-registry analysis and OSV confirms multiple PyPI malicious package records in the same campaign. Confidence is medium because the campaign is active and package counts may change.",
  "attack_types": [
    "malicious package",
    "cross-registry campaign",
    "postinstall malware",
    "import-time malware",
    "build-script malware",
    "credential theft",
    "crypto wallet theft",
    "AI assistant instruction poisoning"
  ],
  "sources": {
    "direct": [
      "https://osv.dev/list?ecosystem=PyPI",
      "https://osv.dev/vulnerability/MAL-2026-4272",
      "https://github.com/ddjidd564/defi-security-best-practices/tree/gh-pages",
      "https://docs.rs/crate/sui-framework-helpers/0.1.0"
    ],
    "primary_research": [
      "https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates",
      "https://xygeni.io/nl/blog/auditortrap-a-22-package-fake-crypto-security-guild-on-npm-with-two-parallel-payloads/"
    ],
    "correlated": []
  },
  "affected_assets": {
    "ecosystems": ["npm", "PyPI", "Crates.io"],
    "registries": ["npmjs.com", "pypi.org", "crates.io"],
    "packages": [
      "async-pipeline-builder",
      "build-scripts-utils",
      "chain-key-validator",
      "crypto-credential-scanner",
      "defi-env-auditor",
      "defi-threat-scanner",
      "deployment-key-auditor",
      "dev-env-bootstrapper",
      "eth-wallet-sentinel",
      "llm-context-compressor",
      "mnemonic-safety-check",
      "model-switch-router",
      "node-setup-helpers",
      "project-init-tools",
      "prompt-engineering-toolkit",
      "solidity-deploy-guard",
      "token-usage-tracker",
      "wallet-backup-verifier",
      "wallet-security-checker",
      "web3-secrets-detector",
      "workspace-config-loader",
      "cryptowallet-safety",
      "data-pipeline-check",
      "defi-risk-scanner",
      "env-loader-cli",
      "eth-security-auditor",
      "git-config-sync",
      "solidity-build-guard",
      "move-analyzer-build",
      "move-compiler-tools",
      "move-project-builder",
      "sui-framework-helpers",
      "sui-move-build-helper",
      "sui-sdk-build-utils"
    ],
    "versions": ["env-loader-cli 0.1.0", "env-loader-cli 0.1.1", "eth-security-auditor 0.1.0", "sui-framework-helpers 0.1.0"],
    "repositories": ["https://github.com/ddjidd564/defi-security-best-practices/tree/gh-pages"],
    "vendors": [],
    "ci_cd_systems": ["developer CI runners", "GitHub Actions", "GitLab CI", "CircleCI", "Travis CI"],
    "container_images": [],
    "developer_tools": ["Cursor", "Claude Code style CLAUDE.md workflows", "Rust cargo build", "Python import workflows", "npm install workflows"],
    "credentials_at_risk": ["SSH keys", "GitHub tokens", "AWS credentials", "cloud credentials", "browser data", "crypto wallet data", "environment variables", "API keys"]
  },
  "timeline": {
    "first_seen": "2026-05-22T20:20:18Z",
    "malicious_publish_time": "2026-05-22T20:20:18Z",
    "discovery_time": "unknown",
    "removal_time": "unknown",
    "disclosure_time": "2026-05-24",
    "patch_or_fix_time": "unknown"
  },
  "artifact_analysis": {
    "malicious_artifacts": ["trap-core.js", ".cursorrules", "CLAUDE.md", "build.rs", "npm postinstall hooks", "Python import-time node -e loaders"],
    "execution_trigger": "npm postinstall, Python import, Rust build.rs",
    "payload_behavior": ["credential harvesting", "wallet theft", "AWS and GitHub credential validation", "SSH lateral movement", "AI instruction file planting", "persistence"],
    "provenance": {
      "present": null,
      "type": "unknown",
      "verified": null
    }
  },
  "iocs": {
    "package_versions": ["env-loader-cli 0.1.0", "env-loader-cli 0.1.1", "eth-security-auditor 0.1.0", "sui-framework-helpers 0.1.0"],
    "files": ["trap-core.js", ".cursorrules", "CLAUDE.md", "build.rs"],
    "hashes": [],
    "domains": ["ddjidd564.github.io"],
    "urls": [
      "https://ddjidd564.github.io/defi-security-best-practices/",
      "https://ddjidd564.github.io/defi-security-best-practices/config.json",
      "https://ddjidd564.github.io/defi-security-best-practices/payloads/compliance-scanner-light.js",
      "https://ddjidd564.github.io/defi-security-best-practices/payloads/risk-profiler.js"
    ],
    "ips": [],
    "process_patterns": ["npm -> node trap-core.js", "python -> node -e", "cargo -> build.rs"],
    "network_patterns": ["developer or CI host egress to ddjidd564.github.io", "post-install GitHub or AWS credential validation"]
  },
  "detection": {
    "lockfile_hunts": ["Search npm, PyPI, and Cargo lockfiles for listed packages."],
    "filesystem_hunts": ["Find trap-core.js, .cursorrules, CLAUDE.md, build.rs, new Git hooks, shell hooks, systemd units, and cron jobs after package installation."],
    "process_hunts": ["Alert on npm, python, or cargo build chains spawning node, ssh, git, aws, gh, curl, wget, systemctl, or crontab unexpectedly."],
    "network_hunts": ["Alert on developer or CI egress to ddjidd564.github.io."],
    "ci_cd_hunts": ["Correlate dependency installation with outbound GitHub/AWS validation and new persistence artifacts."],
    "registry_hunts": ["Flag new low-volume security, wallet, DeFi, AI, and build-helper packages with lifecycle/build/import execution."]
  },
  "open_questions": [
    "Complete package/version list is still changing.",
    "Exact npm and Crates.io malicious versions need direct registry confirmation package by package.",
    "Registry removal status is incomplete.",
    "No actor attribution beyond observed infrastructure."
  ],
  "defender_takeaways": {
    "detection": "Prioritize lockfile/package-cache searches, process execution telemetry, and egress to ddjidd564.github.io.",
    "hunting": "Look for package install/import/build triggers followed by credential discovery, AI instruction file writes, Git hooks, shell hooks, systemd, cron, or SSH activity.",
    "remediation": "Block packages, preserve evidence, rotate secrets from clean hosts, and rebuild developer or CI systems that executed affected packages.",
    "prevention": "Use dependency cooldowns, registry allowlists, lifecycle-script controls, CI egress restrictions, and monitoring for AI assistant instruction files."
  }
}
```
