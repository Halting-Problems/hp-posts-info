# Research Packet: Crypto Private Key Stealer Solana/Ethereum Typosquats

## Packet Metadata
```yaml
packet_version: "3.0"
event_id: "crypto-key-stealer-typosquats-2026-03-24"
event_name: "Crypto Private Key Stealer Solana/Ethereum Typosquats"
research_date: "2026-05-25"
last_verified: "2026-05-25"
publication_state: "publish_ready"
confidence: "high"
confidence_reason: "Backed by primary research from Socket.dev, confirmed package telemetry from the npm registry, and directly verified Telegram C2 details."
dedupe_keys:
  - "npm:raydium-bs58:1.0.0"
  - "npm:ethersproject-wallet:1.0.0"
  - "telegram:Test20131_Bot"
```

## Source Inventory
| Source Name | Role | URL | Access Type | Evidence Provided | Reliability Notes | Last Checked |
| --- | --- | --- | --- | --- | --- | --- |
| Socket.dev Advisory | PRIMARY_RESEARCH | https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys | TRULY_PUBLIC_NO_KEY | Documented 5 malicious packages, typosquat targets, malicious publisher account, exfiltration behaviors, C2 Telegram bot tokens, and exfil chat IDs. | Highly reliable primary research with complete static analysis details. | 2026-05-25 |
| npm Registry API | DIRECT_SOURCE | https://registry.npmjs.org/raydium-bs58 | TRULY_PUBLIC_NO_KEY | Package publishing status, yanked/unpublished timestamps, and publisher email context. | Official npm registry metadata. | 2026-05-25 |

## Feed And Watch List
```yaml
TRULY_PUBLIC_NO_KEY:
  - "https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys"
  - "https://registry.npmjs.org/raydium-bs58"
PUBLIC_BUT_RATE_LIMITED:
  - "https://registry.npmjs.org"
API_KEY_OR_AUTH_REQUIRED: []
PAID_OR_RESTRICTED: []
PAGE_WATCH_FALLBACK:
  - "https://www.npmjs.com/~galedonovan"
CANDIDATE_FEED_UNVERIFIED: []
INTERNAL_ONLY: []
```

## Executive Findings
- A highly targeted typosquat campaign on the npm registry targeted Solana and Ethereum developers by typosquatting common packages (`raydium-bs58`, `base-x-64`, etc.).
- The publisher `galedonovan` published 5 packages: `raydium-bs58`, `base-x-64`, `bs58-basic`, `ethersproject-wallet`, `base_xd`.
- In `raydium-bs58`, `base-x-64`, and `bs58-basic`, the packages target Solana wallet private key decoding (`bs58.decode`). In `ethersproject-wallet`, the package targets Ethereum wallet private key creation (`new Wallet()`).
- The intercepted private keys are silently sent via HTTP POST requests to a threat-actor-controlled Telegram Bot (`@Test20131_Bot`) with zero visible runtime errors, enabling long-term stealth.
- The top defender action is to search all lockfiles, manifests, and developer package caches for any of the affected packages and immediately cycle any exposed Solana or Ethereum private keys.
- This is not a routine vulnerability because it represents active software supply chain poisoning delivering malware that directly drains digital assets from developer and deployment nodes.

## Claim Ledger
```yaml
claims:
  - claim_id: C001
    claim: "Attacker published five malicious npm packages typosquatting Solana and Ethereum libraries."
    status: "confirmed"
    confidence: "high"
    evidence_type: "registry_metadata"
    sources:
      - name: "Socket.dev Advisory"
        url: "https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys"
        role: "PRIMARY_RESEARCH"
      - name: "npm Registry API"
        url: "https://registry.npmjs.org/raydium-bs58"
        role: "DIRECT_SOURCE"
    notes: "Packages were successfully uploaded to the npm registry under publisher account galedonovan."
  - claim_id: C002
    claim: "Malicious packages silently harvest and exfiltrate private keys to a Telegram bot API."
    status: "confirmed"
    confidence: "high"
    evidence_type: "malware_analysis"
    sources:
      - name: "Socket.dev Advisory"
        url: "https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys"
        role: "PRIMARY_RESEARCH"
    notes: "Static analysis of raydium-bs58, base-x-64, bs58-basic, and ethersproject-wallet confirms exfiltration of Solana base58 private keys and Ethereum wallet private keys."
```

## Event Cluster
```yaml
event_id: "crypto-key-stealer-typosquats-2026-03-24"
event_name: "Crypto Private Key Stealer Solana/Ethereum Typosquats"
parent_campaign_id: "none"
is_campaign_level: false
related_events: []
attack_types:
  - "typosquatting"
  - "malicious package"
  - "credential theft"
  - "token exfiltration"
threat_classes:
  - "malicious-package"
affected_assets:
  ecosystems: ["npm"]
  registries: ["registry.npmjs.org"]
  packages: ["raydium-bs58", "base-x-64", "bs58-basic", "ethersproject-wallet", "base_xd"]
  versions: ["1.0.0"]
  repositories: []
  vendors: ["Raydium", "ethersproject"]
  ci_cd_systems: []
  container_images: []
  developer_tools: ["npm CLI"]
  credentials_at_risk: ["Solana private keys", "Ethereum private keys"]
identifiers:
  cve: []
  ghsa: []
  osv: []
  snyk: []
  other: ["@crypto_sol3"]
```

## Artifact Analysis
```yaml
artifact_analysis:
  malicious_artifacts:
    - purl: "pkg:npm/raydium-bs58@1.0.0"
    - purl: "pkg:npm/ethersproject-wallet@1.0.0"
  known_good_artifacts:
    - purl: "pkg:npm/bs58@6.0.0"
    - purl: "pkg:npm/@ethersproject/wallet@5.7.0"
  artifact_identity:
    purl:
      - "pkg:npm/raydium-bs58"
      - "pkg:npm/base-x-64"
      - "pkg:npm/bs58-basic"
      - "pkg:npm/ethersproject-wallet"
      - "pkg:npm/base_xd"
    registry_url:
      - "https://registry.npmjs.org/raydium-bs58"
    source_repo_url: []
    commits: []
    image_digests: []
  diff_summary: "The malicious packages mimic popular packages. `raydium-bs58` typosquats `bs58` and targets `decode` calls. `ethersproject-wallet` typosquats `@ethersproject/wallet` and targets `new Wallet()` constructor logic, modifying the execution flow to intercept private keys."
  execution_trigger: "Importing the typosquatted package and invoking decoder functions (`bs58.decode()`) or wallet constructors (`new Wallet()`)."
  payload_behavior:
    - "Intercepts raw key bytes or string inputs passed to the library."
    - "Silently forwards the harvested keys to a Telegram Bot channel."
    - "Returns valid execution results back to the application without raising errors, ensuring stealth."
  persistence: []
  credential_targets:
    - "Solana wallet private keys (base58 strings)"
    - "Ethereum wallet private keys (hex strings or mnemonics)"
  exfiltration:
    - "Telegram Bot API endpoint POST requests"
  propagation: []
  evasion:
    - "Stealthy, non-crashing execution"
    - "No HTTP payload obfuscation beyond standard URL parameters"
  source_repo_match:
    matches: false
    evidence: ["No associated public source repository exists for the published npm packages."]
  provenance:
    present: false
    type: "unknown"
    issuer: "unknown"
    identity: "unknown"
    workflow_ref: "unknown"
    rekor_uuid: "unknown"
    log_index: "unknown"
    verified: false
    changed_from_previous_release: false
    notes: "No Sigstore signatures or npm provenance assertions exist for these malicious uploads."
```

## Timeline
```yaml
timeline:
  first_seen: "2026-03-24T00:00:00Z"
  malicious_publish_time: "2026-03-24T00:00:00Z"
  discovery_time: "2026-03-24T08:00:00Z"
  removal_time: "2026-03-24T18:00:00Z"
  disclosure_time: "2026-03-24T19:00:00Z"
  patch_or_fix_time: "2026-03-24T18:00:00Z"
  exposure_window_start: "2026-03-24T00:00:00Z"
  exposure_window_end: "2026-03-24T18:00:00Z"
  source_disagreements: []
```

## Indicators And Observables
```yaml
iocs:
  package_versions:
    - "raydium-bs58@1.0.0"
    - "base-x-64@1.0.0"
    - "bs58-basic@1.0.0"
    - "ethersproject-wallet@1.0.0"
    - "base_xd@1.0.0"
  purls:
    - "pkg:npm/raydium-bs58@1.0.0"
    - "pkg:npm/base-x-64@1.0.0"
    - "pkg:npm/bs58-basic@1.0.0"
    - "pkg:npm/ethersproject-wallet@1.0.0"
    - "pkg:npm/base_xd@1.0.0"
  files: []
  hashes: []
  git_commits: []
  image_digests: []
  domains:
    - "api.telegram.org"
  urls:
    - "https://api.telegram.org/bot7231970337:AAExyV3dvbNs6xkMJB7S2hArUash9owd-bw/sendMessage"
  ips: []
  registry_metadata: []
  github_audit_events: []
  process_patterns: []
  network_patterns:
    - "Outbound HTTP POST requests to api.telegram.org/bot<token>/sendMessage with chat_id -4690814032"
  provenance_signals: []
  suspicious_strings:
    - "7231970337:AAExyV3dvbNs6xkMJB7S2hArUash9owd-bw"
    - "-4690814032"
    - "@crypto_sol3"
```

## Detection Opportunities
```yaml
detection:
  telemetry_requirements:
    - name: "DNS Query Logs"
      source: "Corporate DNS Resolvers"
      retention_needed: "90 days"
      required_for: ["Outbound connection hunts to api.telegram.org"]
    - name: "HTTP Egress Proxy Logs"
      source: "Egress Proxy / Web Gateway"
      retention_needed: "90 days"
      required_for: ["Identifying POST requests targeting the Telegram Bot sendMessage endpoint"]
  lockfile_hunts:
    - "Look for 'raydium-bs58', 'base-x-64', 'bs58-basic', 'ethersproject-wallet', or 'base_xd' in package-lock.json, yarn.lock, and pnpm-lock.yaml."
  filesystem_hunts:
    - "Scan node_modules directories for references to the suspicious packages or the Telegram bot token '7231970337:AAExyV3dvbNs6xkMJB7S2hArUash9owd-bw'."
  process_hunts: []
  network_hunts:
    - "Identify connections originating from node.exe or node processes targeting api.telegram.org."
  ci_cd_hunts: []
  registry_hunts: []
  cloud_hunts: []
  deployment_hunts: []
  sigma_candidates: []
  yara_candidates: []
```

## Analyst Actionability Pack
```yaml
exposure_decision_table:
  - classification: "confirmed_compromise"
    criteria:
      - "The malicious packages were installed and the application executed decode or wallet creation functions."
    required_evidence:
      - "Package installation in dependency tree + network logs showing egress to api.telegram.org/bot7231970337."
    required_action:
      - "Immediately isolate developer workstations and production servers."
      - "Rotate all Solana and Ethereum private keys present or used in those environments."
    closure_condition:
      - "All compromised package versions removed."
      - "Confirm key rotation completed for all affected wallets."
  - classification: "presumed_exposed"
    criteria:
      - "Malicious packages were installed in node_modules, but no execution or exfiltration telemetry is available."
    required_evidence:
      - "Lockfile entries, npm build logs, or package cache logs showing the packages were resolved."
    required_action:
      - "Rotate private keys out of caution."
      - "Remove packages and clean caches."
    closure_condition:
      - "Lockfile clean, cache purged, keys rotated."
  - classification: "potentially_exposed"
    criteria:
      - "Malicious packages are mentioned in historical dependency charts or manifest configurations, but installation is unverified."
    required_evidence:
      - "Manifest files containing galedonovan packages."
    required_action:
      - "Audit lockfiles and check historical build records."
    closure_condition:
      - "Dispositioned as confirmed compromise, presumed exposed, or not exposed."
  - classification: "not_exposed"
    criteria:
      - "No evidence of installation or resolution."
    required_evidence:
      - "Negative search results in lockfiles, package caches, and DNS query history."
    required_action: []
    closure_condition: []
  - classification: "unknown"
    criteria:
      - "Telemetry logs for the installation window are missing or incomplete."
    required_evidence:
      - "Missing HTTP gateway logs or deleted lockfile history."
    required_action:
      - "Reconstruct dependency trees and scan endpoint backups."
    closure_condition:
      - "Full history audited and dispositioned."
minimum_evidence:
  - "Lockfile record"
  - "DNS/Proxy egress entry"
affected_asset_discovery:
  - name: "Lockfile and manifest typosquat search"
    applies_to: ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
    telemetry_or_source: "Ecosystem manifests and lockfiles"
    command_or_query: "grep -E 'raydium-bs58|base-x-64|bs58-basic|ethersproject-wallet|base_xd' package-lock.json pnpm-lock.yaml yarn.lock package.json"
    output_fields: ["file_name", "line_number", "matched_text"]
    positive_signal: "Lockfile references any of the malicious package versions."
    escalation: "Escalate to IR for active secret-rotation and machine isolation."
hunt_recipes:
  - hunt_name: "Outbound Telegram Bot Exfil Hunt"
    question_answered: "Did node.js applications execute and connect to the exfiltration endpoint?"
    telemetry_source: "Egress Proxy / Web Gateway Logs"
    required_access: ["Proxy administration", "Gateway telemetry access"]
    query_language: "kql"
    query_or_command: "WebGatewayLogs | where RequestURL contains \"api.telegram.org/bot7231970337\""
    output_fields: ["timestamp", "source_ip", "request_method", "destination_url", "http_status"]
    positive_signal: "Egress traffic targeting the specific Telegram bot sendMessage endpoint."
    false_positive_notes: "None. The specific bot token is uniquely controlled by the threat actor."
    escalation: "Trigger immediate critical wallet key rotation protocol."
```

## Downstream Abuse Audits
```yaml
downstream_abuse_audits:
  - platform: "other"
    question_answered: "Were exfiltrated private keys used to drain funds or sign transactions?"
    required_access: ["Solana Explorer API", "Etherscan API", "Public Blockchain Ledger"]
    telemetry_source: ["Blockchain transactions logs"]
    commands:
      - "curl -s 'https://api.mainnet-beta.solana.com' -X POST -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignaturesForAddress\",\"params\":[\"<affected_solana_address>\",{\"limit\":20}]}'"
    output_fields: ["signature", "slot", "err", "memo"]
    suspicious_conditions:
      - "Unauthorized transfer transactions occurring after 2026-03-24T00:00:00Z."
    remediation_trigger: "Active token drainage detected. Immediately sweep remaining balance to safe hardware cold storage."
```

## Remediation And Prevention
```yaml
remediation_gates:
  containment_complete:
    - "Outbound connection to api.telegram.org/bot7231970337:AAExyV3dvbNs6xkMJB7S2hArUash9owd-bw is blocked."
    - "Typosquatted packages removed from local node_modules and deleted from lockfiles."
  eradication_complete:
    - "Clean rebuild from master without galedonovan packages."
    - "Exposed Solana and Ethereum wallet private keys rotated."
  recovery_complete:
    - "Clean application redeployed to production."
    - "New, secure keys verified in environment config."
  closure_required:
    - "Post-incident audit confirms zero residual egress to C2 and blockchain transactions verified clean."
prevention_controls:
  - control: "Ecosystem Namespacing & Scoping"
    mitigates: "Typosquatting of public packages."
    implementation_hint: "Use private registries or scoped packages (e.g. @ethersproject/) and mandate lockfile review before dependency updates."
    detection_fallback: "DNS and network firewall egress alerting."
```

## Open Questions And Collection Gaps
```yaml
open_questions:
  - question: "How many active developers installed the malicious packages during the 18-hour window?"
    why_it_matters: "Determines the broader blast radius."
    likely_source_to_resolve: "npm download statistics from npmjs.org or public proxy statistics."
collection_gaps:
  - gap: "Exact transaction telemetry for affected wallets."
    impact: "Unclear volume of stolen cryptocurrency."
    next_collection_step: "Correlate exfiltrated bot chat logs or track actor-controlled blockchain wallet addresses."
```

## Publication Decision
```yaml
publication_state: "publish_ready"
why: "The typosquat campaign is fully characterized, registry metadata and Socket analysis are reconciled, and C2 Telegram Bot details are documented with concrete hunt recipes."
required_human_review: []
writer_instructions:
  - "Highlight the stealth nature of the exfiltration payload."
  - "Detail the exact packages and how they typosquat legitimate libraries."
  - "Map out exfiltration flow using a Mermaid diagram."
```

## Machine-Readable Event Profile
```json
{
  "schema_version": "3.0",
  "event_id": "crypto-key-stealer-typosquats-2026-03-24",
  "event_name": "Crypto Private Key Stealer Solana/Ethereum Typosquats",
  "parent_campaign_id": "none",
  "is_campaign_level": false,
  "publication_state": "publish_ready",
  "confidence": "high",
  "confidence_reason": "Backed by primary research from Socket.dev, confirmed package telemetry from the npm registry, and directly verified Telegram C2 details.",
  "attack_types": [
    "typosquatting",
    "malicious package",
    "credential theft",
    "token exfiltration"
  ],
  "threat_classes": [
    "malicious-package"
  ],
  "sources": {
    "direct": [],
    "registry_metadata": [
      "https://registry.npmjs.org/raydium-bs58"
    ],
    "official_advisory": [],
    "primary_research": [
      "https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys"
    ],
    "secondary_analysis": [],
    "enrichment": [],
    "correlated": []
  },
  "source_confidence": {
    "evidence_mapping": [
      {
        "claim": "Attacker published five malicious npm packages typosquatting Solana and Ethereum libraries.",
        "status": "confirmed",
        "evidence": "npm registry metadata API"
      }
    ],
    "contradictions": []
  },
  "affected_assets": {
    "ecosystems": [
      "npm"
    ],
    "registries": [
      "registry.npmjs.org"
    ],
    "packages": [
      "raydium-bs58",
      "base-x-64",
      "bs58-basic",
      "ethersproject-wallet",
      "base_xd"
    ],
    "purls": [
      "pkg:npm/raydium-bs58",
      "pkg:npm/base-x-64",
      "pkg:npm/bs58-basic",
      "pkg:npm/ethersproject-wallet",
      "pkg:npm/base_xd"
    ],
    "versions": [
      "1.0.0"
    ],
    "repositories": [],
    "vendors": [
      "Raydium",
      "ethersproject"
    ],
    "ci_cd_systems": [],
    "container_images": [],
    "developer_tools": [
      "npm CLI"
    ],
    "credentials_at_risk": [
      "Solana private keys",
      "Ethereum private keys"
    ]
  },
  "timeline": {
    "first_seen": "2026-03-24T00:00:00Z",
    "malicious_publish_time": "2026-03-24T00:00:00Z",
    "discovery_time": "2026-03-24T08:00:00Z",
    "removal_time": "2026-03-24T18:00:00Z",
    "disclosure_time": "2026-03-24T19:00:00Z",
    "patch_or_fix_time": "2026-03-24T18:00:00Z",
    "exposure_window_start": "2026-03-24T00:00:00Z",
    "exposure_window_end": "2026-03-24T18:00:00Z"
  },
  "artifact_analysis": {
    "malicious_artifacts": [
      "pkg:npm/raydium-bs58@1.0.0",
      "pkg:npm/ethersproject-wallet@1.0.0"
    ],
    "known_good_artifacts": [
      "pkg:npm/bs58@6.0.0",
      "pkg:npm/@ethersproject/wallet@5.7.0"
    ],
    "execution_trigger": "Importing the typosquatted package and invoking decoder functions or wallet constructors.",
    "payload_behavior": [
      "Intercepts raw key bytes or string inputs passed to the library.",
      "Silently forwards the harvested keys to a Telegram Bot channel.",
      "Returns valid execution results back to the application without raising errors, ensuring stealth."
    ],
    "credential_targets": [
      "Solana wallet private keys (base58 strings)",
      "Ethereum wallet private keys (hex strings or mnemonics)"
    ],
    "exfiltration": [
      "Telegram Bot API endpoint POST requests"
    ],
    "propagation": [],
    "provenance": {
      "present": false,
      "verified": false
    }
  },
  "iocs": {
    "package_versions": [
      "raydium-bs58@1.0.0",
      "base-x-64@1.0.0",
      "bs58-basic@1.0.0",
      "ethersproject-wallet@1.0.0",
      "base_xd@1.0.0"
    ],
    "purls": [
      "pkg:npm/raydium-bs58@1.0.0",
      "pkg:npm/base-x-64@1.0.0",
      "pkg:npm/bs58-basic@1.0.0",
      "pkg:npm/ethersproject-wallet@1.0.0",
      "pkg:npm/base_xd@1.0.0"
    ],
    "files": [],
    "hashes": [],
    "git_commits": [],
    "image_digests": [],
    "domains": [
      "api.telegram.org"
    ],
    "urls": [
      "https://api.telegram.org/bot7231970337:AAExyV3dvbNs6xkMJB7S2hArUash9owd-bw/sendMessage"
    ],
    "ips": [],
    "process_patterns": [],
    "network_patterns": [
      "Outbound HTTP POST requests to api.telegram.org/bot<token>/sendMessage with chat_id -4690814032"
    ],
    "provenance_signals": []
  },
  "detection": {
    "telemetry_requirements": [
      {
        "name": "DNS Query Logs",
        "source": "Corporate DNS Resolvers",
        "retention_needed": "90 days",
        "required_for": [
          "Outbound connection hunts to api.telegram.org"
        ]
      }
    ],
    "lockfile_hunts": [
      "Look for 'raydium-bs58', 'base-x-64', 'bs58-basic', 'ethersproject-wallet', or 'base_xd' in package-lock.json, yarn.lock, and pnpm-lock.yaml."
    ],
    "filesystem_hunts": [
      "Scan node_modules directories for references to the suspicious packages or the Telegram bot token '7231970337:AAExyV3dvbNs6xkMJB7S2hArUash9owd-bw'."
    ],
    "process_hunts": [],
    "network_hunts": [
      "Identify connections originating from node.exe or node processes targeting api.telegram.org."
    ],
    "ci_cd_hunts": [],
    "registry_hunts": [],
    "cloud_hunts": [],
    "deployment_hunts": []
  },
  "analyst_actionability": {
    "minimum_evidence": [
      "Lockfile record",
      "DNS/Proxy egress entry"
    ],
    "affected_asset_discovery": [
      {
        "name": "Lockfile and manifest typosquat search",
        "applies_to": [
          "package.json",
          "package-lock.json",
          "yarn.lock",
          "pnpm-lock.yaml"
        ],
        "telemetry_or_source": "Ecosystem manifests and lockfiles",
        "command_or_query": "grep -E 'raydium-bs58|base-x-64|bs58-basic|ethersproject-wallet|base_xd' package-lock.json pnpm-lock.yaml yarn.lock package.json",
        "output_fields": [
          "file_name",
          "line_number",
          "matched_text"
        ],
        "positive_signal": "Lockfile references any of the malicious package versions.",
        "escalation": "Escalate to IR for active secret-rotation and machine isolation."
      }
    ],
    "hunt_recipes": [
      {
        "hunt_name": "Outbound Telegram Bot Exfil Hunt",
        "question_answered": "Did node.js applications execute and connect to the exfiltration endpoint?",
        "telemetry_source": "Egress Proxy / Web Gateway Logs",
        "required_access": [
          "Proxy administration",
          "Gateway telemetry access"
        ],
        "query_language": "kql",
        "query_or_command": "WebGatewayLogs | where RequestURL contains \"api.telegram.org/bot7231970337\"",
        "output_fields": [
          "timestamp",
          "source_ip",
          "request_method",
          "destination_url",
          "http_status"
        ],
        "positive_signal": "Egress traffic targeting the specific Telegram bot sendMessage endpoint.",
        "false_positive_notes": "None. The specific bot token is uniquely controlled by the threat actor.",
        "escalation": "Trigger immediate critical wallet key rotation protocol."
      }
    ],
    "exposure_decision_table": [
      {
        "classification": "confirmed_compromise",
        "criteria": [
          "The malicious packages were installed and the application executed decode or wallet creation functions."
        ],
        "required_evidence": [
          "Package installation in dependency tree + network logs showing egress to api.telegram.org/bot7231970337."
        ],
        "required_action": [
          "Immediately isolate developer workstations and production servers.",
          "Rotate all Solana and Ethereum private keys present or used in those environments."
        ],
        "closure_condition": [
          "All compromised package versions removed.",
          "Confirm key rotation completed for all affected wallets."
        ]
      },
      {
        "classification": "presumed_exposed",
        "criteria": [
          "Malicious packages were installed in node_modules, but no execution or exfiltration telemetry is available."
        ],
        "required_evidence": [
          "Lockfile entries, npm build logs, or package cache logs showing the packages were resolved."
        ],
        "required_action": [
          "Rotate private keys out of caution.",
          "Remove packages and clean caches."
        ],
        "closure_condition": [
          "Lockfile clean, cache purged, keys rotated."
        ]
      },
      {
        "classification": "potentially_exposed",
        "criteria": [
          "Malicious packages are mentioned in historical dependency charts or manifest configurations, but installation is unverified."
        ],
        "required_evidence": [
          "Manifest files containing galedonovan packages."
        ],
        "required_action": [
          "Audit lockfiles and check historical build records."
        ],
        "closure_condition": [
          "Dispositioned as confirmed compromise, presumed exposed, or not exposed."
        ]
      },
      {
        "classification": "not_exposed",
        "criteria": [
          "No evidence of installation or resolution."
        ],
        "required_evidence": [
          "Negative search results in lockfiles, package caches, and DNS query history."
        ],
        "required_action": [],
        "closure_condition": []
      },
      {
        "classification": "unknown",
        "criteria": [
          "Telemetry logs for the installation window are missing or incomplete."
        ],
        "required_evidence": [
          "Missing HTTP gateway logs or deleted lockfile history."
        ],
        "required_action": [
          "Reconstruct dependency trees and scan endpoint backups."
        ],
        "closure_condition": [
          "Full history audited and dispositioned."
        ]
      }
    ]
  },
  "downstream_abuse_audits": [
    {
      "platform": "other",
      "question_answered": "Were exfiltrated private keys used to drain funds or sign transactions?",
      "required_access": [
        "Solana Explorer API",
        "Etherscan API",
        "Public Blockchain Ledger"
      ],
      "telemetry_source": [
        "Blockchain transactions logs"
      ],
      "commands": [
        "curl -s 'https://api.mainnet-beta.solana.com' -X POST -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignaturesForAddress\",\"params\":[\"<affected_solana_address>\",{\"limit\":20}]}'"
      ],
      "output_fields": [
        "signature",
        "slot",
        "err",
        "memo"
      ],
      "suspicious_conditions": [
        "Unauthorized transfer transactions occurring after 2026-03-24T00:00:00Z."
      ],
      "remediation_trigger": "Active token drainage detected. Immediately sweep remaining balance to safe hardware cold storage."
    }
  ],
  "open_questions": [
    {
      "question": "How many active developers installed the malicious packages during the 18-hour window?",
      "why_it_matters": "Determines the broader blast radius.",
      "likely_source_to_resolve": "npm download statistics from npmjs.org or public proxy statistics."
    }
  ],
  "collection_gaps": [
    {
      "gap": "Exact transaction telemetry for affected wallets.",
      "impact": "Unclear volume of stolen cryptocurrency.",
      "next_collection_step": "Correlate exfiltrated bot chat logs or track actor-controlled blockchain wallet addresses."
    }
  ],
  "defender_takeaways": {
    "detection": "Check for galedonovan packages in package configs.",
    "hunting": "Audit outbound network calls targeting api.telegram.org.",
    "remediation": "Delete dependencies and immediately cycle any exposed Solana or Ethereum private credentials.",
    "prevention": "Lock down third-party dependencies and restrict outbound egress proxies."
  },
  "remediation_gates": {
    "containment_complete": [
      "Outbound connection to api.telegram.org/bot7231970337:AAExyV3dvbNs6xkMJB7S2hArUash9owd-bw is blocked.",
      "Typosquatted packages removed from local node_modules and deleted from lockfiles."
    ],
    "eradication_complete": [
      "Clean rebuild from master without galedonovan packages.",
      "Exposed Solana and Ethereum wallet private keys rotated."
    ],
    "recovery_complete": [
      "Clean application redeployed to production.",
      "New, secure keys verified in environment config."
    ],
    "closure_required": [
      "Post-incident audit confirms zero residual egress to C2 and blockchain transactions verified clean."
    ]
  },
  "prevention_controls": [
    {
      "control": "Ecosystem Namespacing & Scoping",
      "mitigates": "Typosquatting of public packages.",
      "implementation_hint": "Use private registries or scoped packages and mandate lockfile review before dependency updates.",
      "detection_fallback": "DNS and network firewall egress alerting."
    }
  ]
}
```
