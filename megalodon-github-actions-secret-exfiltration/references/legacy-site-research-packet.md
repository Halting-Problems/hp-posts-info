# Research Packet: Megalodon GitHub Actions Secret Exfiltration Campaign

## Packet Metadata
```yaml
packet_version: "2.0"
event_id: "megalodon-github-actions-secret-exfiltration-2026-05-22"
event_name: "Megalodon GitHub Actions Secret Exfiltration Campaign"
research_date: "2026-05-24"
last_verified: "2026-05-24"
publication_state: "publish_ready"
confidence: "medium"
confidence_reason: "StepSecurity provides campaign scope, workflow names, payload behavior, and C2. Confidence remains medium because the SafeDep dataset was not independently fetched in this packet."
dedupe_keys:
  - "github-actions:megalodon:5561-repositories"
```

## Source Inventory
| Source Name | Role | URL | Access Type | Evidence Provided | Reliability Notes | Last Checked |
| --- | --- | --- | --- | --- | --- | --- |
| StepSecurity Megalodon research | PRIMARY_RESEARCH | https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories | TRULY_PUBLIC_NO_KEY | Repository and commit counts, workflow names, payload scope, C2 IP, hunting pivots. | Developing public analysis; dataset not fetched here. | 2026-05-24 |

## Feed And Watch List
```yaml
TRULY_PUBLIC_NO_KEY:
  - "https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories"
PUBLIC_BUT_RATE_LIMITED:
  - "GitHub public repository search"
API_KEY_OR_AUTH_REQUIRED:
  - "GitHub code search at scale"
  - "GitHub audit logs"
PAID_OR_RESTRICTED: []
PAGE_WATCH_FALLBACK: []
CANDIDATE_FEED_UNVERIFIED:
  - "SafeDep Megalodon CSV dataset cited by StepSecurity"
```

## Executive Findings
- Megalodon injected malicious GitHub Actions workflows into thousands of public repositories.
- StepSecurity reports 5,561 affected repositories and 5,718 malicious commits.
- Payloads collected broad CI/CD and cloud secrets and posted archives to `216[.]126[.]225[.]129:8443`.

## Claim Ledger
```yaml
claims:
  - claim_id: C001
    claim: "Megalodon affected 5,561 public repositories and 5,718 malicious commits according to StepSecurity."
    status: "confirmed"
    confidence: "medium"
    evidence_type: "primary_research"
    sources:
      - name: "StepSecurity Megalodon research"
        url: "https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories"
        role: "PRIMARY_RESEARCH"
    notes: "Dataset should be fetched for per-repository appendix."
```

## Event Cluster
```yaml
event_id: "megalodon-github-actions-secret-exfiltration-2026-05-22"
event_name: "Megalodon GitHub Actions Secret Exfiltration Campaign"
parent_campaign_id: "none"
is_campaign_level: true
attack_types: ["workflow injection", "CI/CD credential theft", "secret exfiltration"]
affected_assets:
  ecosystems: ["GitHub Actions", "GitHub repositories"]
  registries: ["GitHub"]
  packages: []
  versions: ["5,718 malicious commits"]
  repositories: ["5,561 public repositories"]
  vendors: []
  ci_cd_systems: ["GitHub Actions"]
  container_images: []
  developer_tools: ["GitHub Actions", "repository workflow automation"]
  credentials_at_risk: ["GitHub tokens", "GitHub Actions secrets", "OIDC tokens", "cloud credentials", "SSH private keys", "Docker credentials", "npm tokens", "Kubernetes configs", "Vault tokens", "Terraform credentials"]
identifiers:
  cve: []
  ghsa: []
  osv: []
  snyk: []
  other: ["Megalodon"]
```

## Artifact Analysis
```yaml
artifact_analysis:
  malicious_artifacts: ["SysDiag workflow", "Optimize-Build workflow"]
  known_good_artifacts: []
  diff_summary: "Malicious commits added disguised GitHub Actions workflow files."
  execution_trigger: "GitHub Actions workflow run"
  payload_behavior: ["environment collection", "credential file collection", "archive creation", "HTTPS exfiltration"]
  persistence: ["workflow files persisted until removed"]
  exfiltration: ["216[.]126[.]225[.]129:8443/collect"]
  propagation: ["malicious commits across many repositories"]
  evasion: ["benign-looking workflow names", "CI optimization framing"]
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
  first_seen: "unknown"
  malicious_publish_time: "unknown"
  discovery_time: "2026-05-22"
  removal_time: "mixed"
  disclosure_time: "2026-05-22"
  patch_or_fix_time: "unknown"
  source_disagreements: []
```

## Indicators And Observables
```yaml
iocs:
  package_versions: []
  files: [".github/workflows/SysDiag.yml", ".github/workflows/Optimize-Build.yml"]
  hashes: ["1c9e803c80cc7fed000022d4c94f4b5bc2e90062", "7f6120bb10c870b9fde146961a18e5bf0b3d4401", "acac5a9854650c4ae2883c4740bf87d34120c038"]
  domains: []
  urls: ["hxxps://216[.]126[.]225[.]129:8443/collect"]
  ips: ["216[.]126[.]225[.]129"]
  registry_metadata: []
  github_audit_events: ["workflow addition by unexpected bot identity"]
  process_patterns: ["workflow collects environment variables and credential files"]
  network_patterns: ["POST to 216[.]126[.]225[.]129:8443/collect"]
  provenance_signals: ["workflow names SysDiag or Optimize-Build"]
```

## Detection Opportunities
```yaml
detection:
  lockfile_hunts: []
  filesystem_hunts: ["SysDiag.yml", "Optimize-Build.yml", "216.126.225.129"]
  process_hunts: ["archive creation and broad credential collection in runner"]
  network_hunts: ["216[.]126[.]225[.]129:8443"]
  ci_cd_hunts: ["new suspicious workflows and unexpected bot-authored commits"]
  registry_hunts: []
  sigma_candidates: ["GitHub Actions Runner Posts Secret Archive To 216.126.225.129:8443"]
  yara_candidates: ["workflow content collecting AWS, Docker, npm, Kubernetes, Vault, Terraform, SSH, and OIDC secrets"]
  telemetry_requirements: ["GitHub audit logs", "workflow history", "runner egress logs"]
```

## Remediation And Prevention
- Remove malicious workflow files and revert malicious commits.
- Rotate all secrets exposed to affected workflow runs.
- Require code owner review for `.github/workflows/**`.
- Restrict default `GITHUB_TOKEN` permissions and runner egress.

## Open Questions And Collection Gaps
- Complete per-repository remediation status.
- Initial access methods for malicious commits.
- Private repository exposure outside the public dataset.

## Publication Decision
```yaml
publication_state: "publish_ready"
why: "Large-scale CI/CD credential theft campaign with actionable workflow and network IOCs."
required_human_review:
  - "Fetch SafeDep dataset for appendix if per-repository listing is needed."
writer_instructions:
  - "Publish as standalone critical GitHub Actions campaign article."
```

## Machine-Readable Event Profile
```json
{
  "schema_version": "2.0",
  "event_id": "megalodon-github-actions-secret-exfiltration-2026-05-22",
  "event_name": "Megalodon GitHub Actions Secret Exfiltration Campaign",
  "parent_campaign_id": "none",
  "is_campaign_level": true,
  "publication_state": "publish_ready",
  "confidence": "medium",
  "confidence_reason": "StepSecurity provides scope and behavior; external dataset was not fetched here.",
  "attack_types": ["workflow injection", "CI/CD credential theft", "secret exfiltration"],
  "sources": {
    "direct": [],
    "primary_research": ["https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories"],
    "correlated": []
  },
  "affected_assets": {
    "ecosystems": ["GitHub Actions", "GitHub repositories"],
    "registries": ["GitHub"],
    "packages": [],
    "versions": ["5,718 malicious commits"],
    "repositories": ["5,561 public repositories"],
    "vendors": [],
    "ci_cd_systems": ["GitHub Actions"],
    "container_images": [],
    "developer_tools": ["GitHub Actions", "repository workflow automation"],
    "credentials_at_risk": ["GitHub tokens", "GitHub Actions secrets", "OIDC tokens", "cloud credentials", "SSH private keys", "Docker credentials", "npm tokens", "Kubernetes configs", "Vault tokens", "Terraform credentials"]
  },
  "timeline": {
    "first_seen": "unknown",
    "malicious_publish_time": "unknown",
    "discovery_time": "2026-05-22",
    "removal_time": "mixed",
    "disclosure_time": "2026-05-22",
    "patch_or_fix_time": "unknown"
  },
  "artifact_analysis": {
    "malicious_artifacts": ["SysDiag workflow", "Optimize-Build workflow"],
    "execution_trigger": "GitHub Actions workflow run",
    "payload_behavior": ["environment collection", "credential file collection", "archive creation", "HTTPS exfiltration"],
    "provenance": {}
  },
  "iocs": {
    "package_versions": [],
    "files": [".github/workflows/SysDiag.yml", ".github/workflows/Optimize-Build.yml"],
    "hashes": ["1c9e803c80cc7fed000022d4c94f4b5bc2e90062", "7f6120bb10c870b9fde146961a18e5bf0b3d4401", "acac5a9854650c4ae2883c4740bf87d34120c038"],
    "domains": [],
    "urls": ["https://216.126.225.129:8443/collect"],
    "ips": ["216.126.225.129"],
    "process_patterns": ["workflow collects environment variables and credential files"],
    "network_patterns": ["POST 216.126.225.129:8443/collect"]
  },
  "detection": {
    "lockfile_hunts": [],
    "filesystem_hunts": ["SysDiag.yml", "Optimize-Build.yml", "216.126.225.129"],
    "process_hunts": ["archive creation and broad credential collection in runner"],
    "network_hunts": ["216.126.225.129:8443"],
    "ci_cd_hunts": ["new suspicious workflows and unexpected bot-authored commits"],
    "registry_hunts": []
  },
  "open_questions": ["remediation status", "initial access methods", "private repository exposure"],
  "defender_takeaways": {
    "detection": "Monitor workflow additions and runner egress.",
    "hunting": "Search workflow files, commit authorship, and C2 egress.",
    "remediation": "Remove workflows and rotate every exposed secret.",
    "prevention": "Require code owner review for GitHub workflow changes."
  }
}
```
