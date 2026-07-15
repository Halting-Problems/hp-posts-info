# Research Packet: Laravel-Lang Composer Tag Rewrite RCE Compromise

## Packet Metadata
```yaml
packet_version: "2.0"
event_id: "laravel-lang-composer-tag-compromise-2026-05-22"
event_name: "Laravel-Lang Composer Tag Rewrite RCE Compromise"
research_date: "2026-05-24"
last_verified: "2026-05-24"
publication_state: "publish_ready"
confidence: "high"
confidence_reason: "StepSecurity provides confirmed tag rewrite and detonation evidence; Socket provides broader package scope and payload analysis."
dedupe_keys:
  - "composer:laravel-lang:tag-rewrite:2026-05-22"
  - "domain:flipboxstudio.info"
```

## Source Inventory
| Source Name | Role | URL | Access Type | Evidence Provided | Reliability Notes | Last Checked |
| --- | --- | --- | --- | --- | --- | --- |
| StepSecurity Laravel-Lang | PRIMARY_RESEARCH | https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack | TRULY_PUBLIC_NO_KEY | Confirmed repositories, tag windows, process tree, C2, IOCs. | Strong runtime detonation evidence. | 2026-05-24 |
| Socket Laravel-Lang | PRIMARY_RESEARCH | https://socket.dev/blog/laravel-lang-compromise | TRULY_PUBLIC_NO_KEY | Broader package scope, 700+ versions, payload behavior, remediation. | Broader scope; treat cleanup status as developing. | 2026-05-24 |

## Feed And Watch List
```yaml
TRULY_PUBLIC_NO_KEY:
  - "https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack"
  - "https://socket.dev/blog/laravel-lang-compromise"
PUBLIC_BUT_RATE_LIMITED:
  - "https://packagist.org/packages/laravel-lang/lang"
API_KEY_OR_AUTH_REQUIRED:
  - "GitHub audit logs for affected maintainers"
PAID_OR_RESTRICTED: []
PAGE_WATCH_FALLBACK:
  - "https://github.com/Laravel-Lang/lang/tags"
CANDIDATE_FEED_UNVERIFIED: []
```

## Executive Findings
- Laravel-Lang package tags were rewritten to malicious commits.
- Composer autoload loaded `src/helpers.php` when `vendor/autoload.php` was required.
- The payload fetched from `flipboxstudio[.]info`, dropped temporary loaders, and targeted local and CI/cloud secrets.
- Any host or runner that installed affected tags during the window requires secret rotation.

## Claim Ledger
```yaml
claims:
  - claim_id: C001
    claim: "Laravel-Lang release tags were rewritten to malicious commits."
    status: "confirmed"
    confidence: "high"
    evidence_type: "primary_research"
    sources:
      - name: "StepSecurity Laravel-Lang"
        url: "https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack"
        role: "PRIMARY_RESEARCH"
    notes: "Four repositories confirmed by StepSecurity."
  - claim_id: C002
    claim: "Socket reports roughly 700+ affected historical versions."
    status: "confirmed"
    confidence: "medium"
    evidence_type: "primary_research"
    sources:
      - name: "Socket Laravel-Lang"
        url: "https://socket.dev/blog/laravel-lang-compromise"
        role: "PRIMARY_RESEARCH"
    notes: "Broader than StepSecurity's confirmed repository subset."
```

## Event Cluster
```yaml
event_id: "laravel-lang-composer-tag-compromise-2026-05-22"
event_name: "Laravel-Lang Composer Tag Rewrite RCE Compromise"
parent_campaign_id: "none"
is_campaign_level: false
attack_types:
  - "git tag hijacking"
  - "composer package compromise"
  - "remote code execution"
affected_assets:
  ecosystems: ["Composer", "Packagist"]
  registries: ["packagist.org"]
  packages: ["laravel-lang/lang", "laravel-lang/http-statuses", "laravel-lang/actions", "laravel-lang/attributes"]
  versions: ["rewritten historical tags"]
  repositories: ["Laravel-Lang/lang", "Laravel-Lang/http-statuses", "Laravel-Lang/actions", "Laravel-Lang/attributes"]
  vendors: ["Laravel-Lang"]
  ci_cd_systems: ["GitHub Actions", "Composer build pipelines"]
  container_images: []
  developer_tools: ["Composer", "Laravel"]
  credentials_at_risk: ["GitHub tokens", "CI/CD secrets", "cloud credentials", "Kubernetes tokens", "Vault tokens", "SSH keys", ".env secrets"]
identifiers:
  cve: []
  ghsa: []
  osv: []
  snyk: []
  other: ["flipboxstudio.info"]
```

## Artifact Analysis
```yaml
artifact_analysis:
  malicious_artifacts: ["src/helpers.php", "composer.json autoload.files", "/tmp/.laravel_locale/<id>.php"]
  known_good_artifacts: ["maintainer-confirmed clean commit SHAs"]
  diff_summary: "Tags pointed to commits that introduced autoloaded PHP helper code."
  execution_trigger: "Composer autoload"
  payload_behavior: ["remote payload fetch", "background execution", "secret harvesting", "artifact cleanup"]
  persistence: ["none confirmed beyond dependency/tag trust"]
  exfiltration: ["flipboxstudio.info /exfil"]
  propagation: ["dependency resolution from rewritten tags"]
  evasion: ["hidden /tmp paths", "self-deleting artifacts", "historical tag trust"]
  provenance:
    present: false
    type: "unknown"
    issuer: "unknown"
    identity: "unknown"
    workflow_ref: "unknown"
    verified: null
    notes: "No trusted publishing provenance reported."
```

## Timeline
```yaml
timeline:
  first_seen: "2026-05-22T22:32:00Z"
  malicious_publish_time: "2026-05-22T22:32:00Z/2026-05-23T00:00:00Z"
  discovery_time: "2026-05-22/2026-05-23"
  removal_time: "unknown"
  disclosure_time: "2026-05-23"
  patch_or_fix_time: "unknown"
  source_disagreements:
    - "StepSecurity confirms four repositories; Socket reports broader package impact."
```

## Indicators And Observables
```yaml
iocs:
  package_versions: ["Laravel-Lang rewritten historical tags"]
  files: ["src/helpers.php", "/tmp/.laravel_locale/<id>.php", "/tmp/.<8 hex chars>"]
  hashes: ["2f0ee073c6f29d66188a845592029c9b52528f04"]
  domains: ["flipboxstudio[.]info"]
  urls: ["hxxps://flipboxstudio[.]info/payload", "hxxps://flipboxstudio[.]info/exfil"]
  ips: []
  registry_metadata: ["tag rewrites"]
  github_audit_events: ["unexpected Laravel-Lang tag update"]
  process_patterns: ["php Composer autoload spawning hidden temp payload"]
  network_patterns: ["GET payload then POST exfil to flipboxstudio[.]info"]
  provenance_signals: ["tag recreated during attack window"]
```

## Detection Opportunities
```yaml
detection:
  lockfile_hunts: ["composer.lock Laravel-Lang packages resolved after 2026-05-22T22:32:00Z"]
  filesystem_hunts: ["vendor Laravel-Lang src/helpers.php"]
  process_hunts: ["orphaned PHP or hidden /tmp payload after Composer autoload"]
  network_hunts: ["flipboxstudio[.]info"]
  ci_cd_hunts: ["Composer install/update during rewrite window"]
  registry_hunts: ["tag-to-commit SHA verification"]
  sigma_candidates: ["Composer Autoload Spawns Hidden PHP Temp Payload"]
  yara_candidates: ["PHP helper loader with flipboxstudio strings"]
  telemetry_requirements: ["composer.lock inventory", "process telemetry", "DNS/proxy logs", "CI logs"]
```

## Remediation And Prevention
- Freeze Laravel-Lang updates and pin to verified clean commit SHAs.
- Rebuild from clean dependency caches.
- Rotate all secrets reachable from systems that loaded affected Composer autoload paths.
- Monitor tag rewrites and treat mutable tags as unsafe for critical production dependencies.

## Open Questions And Collection Gaps
- Final cleanup status for every rewritten tag.
- Complete affected package list beyond the four StepSecurity-confirmed repositories.
- Downstream victim count.

## Publication Decision
```yaml
publication_state: "publish_ready"
why: "High-confidence public evidence and clear defender action."
required_human_review: []
writer_instructions:
  - "Publish as standalone critical article."
```

## Machine-Readable Event Profile
```json
{
  "schema_version": "2.0",
  "event_id": "laravel-lang-composer-tag-compromise-2026-05-22",
  "event_name": "Laravel-Lang Composer Tag Rewrite RCE Compromise",
  "parent_campaign_id": "none",
  "is_campaign_level": false,
  "publication_state": "publish_ready",
  "confidence": "high",
  "confidence_reason": "StepSecurity provides confirmed tag rewrite and detonation evidence; Socket provides broader package scope.",
  "attack_types": ["git tag hijacking", "composer package compromise", "remote code execution", "credential theft"],
  "sources": {
    "direct": [],
    "primary_research": ["https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack", "https://socket.dev/blog/laravel-lang-compromise"],
    "correlated": []
  },
  "affected_assets": {
    "ecosystems": ["Composer", "Packagist"],
    "registries": ["packagist.org"],
    "packages": ["laravel-lang/lang", "laravel-lang/http-statuses", "laravel-lang/actions", "laravel-lang/attributes"],
    "versions": ["rewritten historical tags"],
    "repositories": ["Laravel-Lang/lang", "Laravel-Lang/http-statuses", "Laravel-Lang/actions", "Laravel-Lang/attributes"],
    "vendors": ["Laravel-Lang"],
    "ci_cd_systems": ["GitHub Actions", "Composer build pipelines"],
    "container_images": [],
    "developer_tools": ["Composer", "Laravel"],
    "credentials_at_risk": ["GitHub tokens", "CI/CD secrets", "cloud credentials", "Kubernetes tokens", "Vault tokens", "SSH keys", ".env secrets"]
  },
  "timeline": {
    "first_seen": "2026-05-22T22:32:00Z",
    "malicious_publish_time": "2026-05-22T22:32:00Z/2026-05-23T00:00:00Z",
    "discovery_time": "2026-05-22/2026-05-23",
    "removal_time": "unknown",
    "disclosure_time": "2026-05-23",
    "patch_or_fix_time": "unknown"
  },
  "artifact_analysis": {
    "malicious_artifacts": ["src/helpers.php", "composer.json autoload.files"],
    "execution_trigger": "Composer autoload",
    "payload_behavior": ["remote payload fetch", "background execution", "credential harvesting"],
    "provenance": {}
  },
  "iocs": {
    "package_versions": ["Laravel-Lang rewritten tags"],
    "files": ["src/helpers.php", "/tmp/.laravel_locale/<id>.php"],
    "hashes": ["2f0ee073c6f29d66188a845592029c9b52528f04"],
    "domains": ["flipboxstudio.info"],
    "urls": ["https://flipboxstudio.info/payload", "https://flipboxstudio.info/exfil"],
    "ips": [],
    "process_patterns": ["php Composer autoload spawning hidden temp payload"],
    "network_patterns": ["flipboxstudio.info payload and exfil"]
  },
  "detection": {
    "lockfile_hunts": ["composer.lock Laravel-Lang packages"],
    "filesystem_hunts": ["src/helpers.php"],
    "process_hunts": ["hidden /tmp PHP payload"],
    "network_hunts": ["flipboxstudio.info"],
    "ci_cd_hunts": ["Composer install/update during rewrite window"],
    "registry_hunts": ["tag-to-commit SHA verification"]
  },
  "open_questions": ["tag cleanup status", "complete affected package list", "victim count"],
  "defender_takeaways": {
    "detection": "Correlate lockfiles, CI runs, PHP process telemetry, and egress.",
    "hunting": "Verify tag SHAs and search for autoloaded helper files.",
    "remediation": "Rebuild clean and rotate secrets after execution.",
    "prevention": "Pin immutable SHAs for high-risk Composer dependencies."
  }
}
```
