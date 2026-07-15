# Research Packet: actions-cool GitHub Actions Tag Hijack Credential Theft

## Packet Metadata
```yaml
packet_version: "2.0"
event_id: "actions-cool-github-actions-tag-hijack-2026-05-18"
event_name: "actions-cool GitHub Actions Tag Hijack Credential Theft"
research_date: "2026-05-24"
last_verified: "2026-05-24"
publication_state: "publish_ready"
confidence: "high"
confidence_reason: "StepSecurity provides tag timing, affected action counts, imposter commit behavior, runner memory scraping details, and exfiltration domain."
dedupe_keys:
  - "github-action:actions-cool/issues-helper:tag-hijack"
  - "github-action:actions-cool/maintain-one-comment:tag-hijack"
```

## Source Inventory
| Source Name | Role | URL | Access Type | Evidence Provided | Reliability Notes | Last Checked |
| --- | --- | --- | --- | --- | --- | --- |
| StepSecurity actions-cool research | PRIMARY_RESEARCH | https://www.stepsecurity.io/blog/actions-cool-issues-helper-github-action-compromised-all-tags-point-to-imposter-commit-that-exfiltrates-ci-cd-credentials | TRULY_PUBLIC_NO_KEY | Affected tags, imposter commits, Runner.Worker memory scraping, exfiltration domain, detections. | Strong CI runtime and tag evidence. | 2026-05-24 |

## Feed And Watch List
```yaml
TRULY_PUBLIC_NO_KEY:
  - "https://www.stepsecurity.io/blog/actions-cool-issues-helper-github-action-compromised-all-tags-point-to-imposter-commit-that-exfiltrates-ci-cd-credentials"
PUBLIC_BUT_RATE_LIMITED:
  - "https://api.github.com/repos/actions-cool/issues-helper/tags"
  - "https://api.github.com/repos/actions-cool/maintain-one-comment/tags"
API_KEY_OR_AUTH_REQUIRED:
  - "GitHub audit logs for affected organizations"
PAID_OR_RESTRICTED: []
PAGE_WATCH_FALLBACK:
  - "https://github.com/actions-cool/issues-helper/tags"
  - "https://github.com/actions-cool/maintain-one-comment/tags"
CANDIDATE_FEED_UNVERIFIED: []
```

## Executive Findings
- All reviewed tags for two actions-cool GitHub Actions were moved to imposter commits.
- The payload read GitHub Actions `Runner.Worker` memory and exfiltrated secrets to `t[.]m-kosche[.]com`.
- Any workflow run using affected tags should be handled as a CI credential exposure.

## Claim Ledger
```yaml
claims:
  - claim_id: C001
    claim: "53 issues-helper tags and 15 maintain-one-comment tags were reported as affected."
    status: "confirmed"
    confidence: "high"
    evidence_type: "primary_research"
    sources:
      - name: "StepSecurity actions-cool research"
        url: "https://www.stepsecurity.io/blog/actions-cool-issues-helper-github-action-compromised-all-tags-point-to-imposter-commit-that-exfiltrates-ci-cd-credentials"
        role: "PRIMARY_RESEARCH"
    notes: "Use current tag checks before publication if cleanup has changed."
```

## Event Cluster
```yaml
event_id: "actions-cool-github-actions-tag-hijack-2026-05-18"
event_name: "actions-cool GitHub Actions Tag Hijack Credential Theft"
parent_campaign_id: "none"
is_campaign_level: true
attack_types: ["GitHub Action tag hijack", "CI/CD credential theft", "runner memory scraping"]
affected_assets:
  ecosystems: ["GitHub Actions"]
  registries: ["GitHub"]
  packages: ["actions-cool/issues-helper", "actions-cool/maintain-one-comment"]
  versions: ["53 issues-helper tags", "15 maintain-one-comment tags"]
  repositories: ["actions-cool/issues-helper", "actions-cool/maintain-one-comment"]
  vendors: ["actions-cool"]
  ci_cd_systems: ["GitHub Actions"]
  container_images: []
  developer_tools: ["GitHub Actions workflows"]
  credentials_at_risk: ["GitHub Actions secrets", "GitHub tokens", "OIDC tokens", "cloud credentials", "package registry credentials", "deployment credentials"]
identifiers:
  cve: []
  ghsa: []
  osv: []
  snyk: []
  other: ["t.m-kosche.com"]
```

## Artifact Analysis
```yaml
artifact_analysis:
  malicious_artifacts: ["imposter action commits", "malicious action JavaScript/Python"]
  known_good_artifacts: ["verified full commit SHAs before tag hijack"]
  diff_summary: "Mutable action tags pointed to commits not reachable from default branch."
  execution_trigger: "workflow references hijacked action tag"
  payload_behavior: ["Runner.Worker memory scraping", "secret extraction", "HTTPS exfiltration"]
  persistence: ["none confirmed"]
  exfiltration: ["t[.]m-kosche[.]com"]
  propagation: ["workflow references to mutable tags"]
  evasion: ["tag indirection", "commits not reachable from default branch"]
  provenance:
    present: false
    type: "unknown"
    issuer: "unknown"
    identity: "unknown"
    workflow_ref: "unknown"
    verified: null
    notes: ""
```

## Timeline
```yaml
timeline:
  first_seen: "2026-05-18T19:10:24Z"
  malicious_publish_time: "2026-05-18T19:10:24Z/2026-05-18T19:31:09Z"
  discovery_time: "2026-05-19"
  removal_time: "unknown"
  disclosure_time: "2026-05-19"
  patch_or_fix_time: "unknown"
  source_disagreements: []
```

## Indicators And Observables
```yaml
iocs:
  package_versions: ["actions-cool/issues-helper affected tags", "actions-cool/maintain-one-comment affected tags"]
  files: [".github/workflows/*.yml"]
  hashes: ["8064d4e0322f069b3dba13e7957ff0ca7dab7984", "6e79ae622b7ef30f31fdbcc2dc65339e"]
  domains: ["t[.]m-kosche[.]com"]
  urls: []
  ips: []
  registry_metadata: ["action tags moved to imposter commits"]
  github_audit_events: ["workflow run using affected action tag"]
  process_patterns: ["python3 reading /proc/<Runner.Worker PID>/mem", "bun executing unexpected action code"]
  network_patterns: ["HTTPS traffic from runner to t[.]m-kosche[.]com"]
  provenance_signals: ["action tag target not reachable from default branch"]
```

## Detection Opportunities
```yaml
detection:
  lockfile_hunts: []
  filesystem_hunts: ["workflow references to actions-cool/issues-helper or actions-cool/maintain-one-comment"]
  process_hunts: ["python3 reading /proc/*/mem", "unexpected bun execution"]
  network_hunts: ["t[.]m-kosche[.]com"]
  ci_cd_hunts: ["affected action runs during compromise window"]
  registry_hunts: ["action tag targets not reachable from default branch"]
  sigma_candidates: ["Python Reads GitHub Actions Runner.Worker Memory"]
  yara_candidates: ["Action JavaScript referencing Runner.Worker memory and t.m-kosche.com"]
  telemetry_requirements: ["workflow inventory", "runner process telemetry", "runner egress logs"]
```

## Remediation And Prevention
- Disable workflows using affected actions until reviewed.
- Rotate all secrets exposed to affected runs.
- Replace mutable action tags with verified full commit SHAs.
- Enforce third-party action pinning and least-privilege workflow permissions.

## Open Questions And Collection Gaps
- Successful downstream exfiltration count.
- Initial access path for tag movement.
- Cleanup status for each affected tag.

## Publication Decision
```yaml
publication_state: "publish_ready"
why: "High-confidence CI/CD credential theft with clear action-tag detections."
required_human_review: []
writer_instructions:
  - "Publish as standalone critical GitHub Actions article."
```

## Machine-Readable Event Profile
```json
{
  "schema_version": "2.0",
  "event_id": "actions-cool-github-actions-tag-hijack-2026-05-18",
  "event_name": "actions-cool GitHub Actions Tag Hijack Credential Theft",
  "parent_campaign_id": "none",
  "is_campaign_level": true,
  "publication_state": "publish_ready",
  "confidence": "high",
  "confidence_reason": "StepSecurity provides tag timing, affected counts, runtime behavior, and exfiltration domain.",
  "attack_types": ["GitHub Action tag hijack", "CI/CD credential theft", "runner memory scraping"],
  "sources": {
    "direct": [],
    "primary_research": ["https://www.stepsecurity.io/blog/actions-cool-issues-helper-github-action-compromised-all-tags-point-to-imposter-commit-that-exfiltrates-ci-cd-credentials"],
    "correlated": []
  },
  "affected_assets": {
    "ecosystems": ["GitHub Actions"],
    "registries": ["GitHub"],
    "packages": ["actions-cool/issues-helper", "actions-cool/maintain-one-comment"],
    "versions": ["53 issues-helper tags", "15 maintain-one-comment tags"],
    "repositories": ["actions-cool/issues-helper", "actions-cool/maintain-one-comment"],
    "vendors": ["actions-cool"],
    "ci_cd_systems": ["GitHub Actions"],
    "container_images": [],
    "developer_tools": ["GitHub Actions workflows"],
    "credentials_at_risk": ["GitHub Actions secrets", "GitHub tokens", "OIDC tokens", "cloud credentials", "package registry credentials", "deployment credentials"]
  },
  "timeline": {
    "first_seen": "2026-05-18T19:10:24Z",
    "malicious_publish_time": "2026-05-18T19:10:24Z/2026-05-18T19:31:09Z",
    "discovery_time": "2026-05-19",
    "removal_time": "unknown",
    "disclosure_time": "2026-05-19",
    "patch_or_fix_time": "unknown"
  },
  "artifact_analysis": {
    "malicious_artifacts": ["imposter action commits", "malicious action JavaScript/Python"],
    "execution_trigger": "workflow references hijacked action tag",
    "payload_behavior": ["Runner.Worker memory scraping", "secret extraction", "HTTPS exfiltration"],
    "provenance": {}
  },
  "iocs": {
    "package_versions": ["actions-cool/issues-helper tags", "actions-cool/maintain-one-comment tags"],
    "files": [".github/workflows/*.yml"],
    "hashes": ["8064d4e0322f069b3dba13e7957ff0ca7dab7984", "6e79ae622b7ef30f31fdbcc2dc65339e"],
    "domains": ["t.m-kosche.com"],
    "urls": [],
    "ips": [],
    "process_patterns": ["python3 reading /proc/<Runner.Worker PID>/mem", "bun executing unexpected action code"],
    "network_patterns": ["HTTPS to t.m-kosche.com"]
  },
  "detection": {
    "lockfile_hunts": [],
    "filesystem_hunts": ["workflow references to actions-cool actions"],
    "process_hunts": ["python3 /proc/*/mem reads", "unexpected bun execution"],
    "network_hunts": ["t.m-kosche.com"],
    "ci_cd_hunts": ["affected action runs during compromise window"],
    "registry_hunts": ["action tags not reachable from default branch"]
  },
  "open_questions": ["victim exfiltration count", "initial access path", "cleanup status"],
  "defender_takeaways": {
    "detection": "Compare action tag targets with branch reachability and runner telemetry.",
    "hunting": "Find all workflows using affected actions by tag.",
    "remediation": "Rotate exposed secrets and pin actions to full SHAs.",
    "prevention": "Enforce action SHA pinning and least-privilege workflow permissions."
  }
}
```
