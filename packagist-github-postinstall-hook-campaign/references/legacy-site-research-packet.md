# Research Packet: Packagist GitHub Postinstall Hook Malware Campaign

## Packet Metadata
```yaml
packet_version: "2.0"
event_id: "packagist-github-postinstall-hook-campaign-2026-05-22"
event_name: "Packagist GitHub Postinstall Hook Malware Campaign"
research_date: "2026-05-24"
last_verified: "2026-05-24"
publication_state: "publish_ready"
confidence: "medium"
confidence_reason: "Socket confirms eight Packagist packages and the first-stage postinstall hook, but second-stage behavior and broader GitHub hit count remain unresolved."
dedupe_keys:
  - "packagist:postinstall:/tmp/.sshd:parikhpreyash4"
```

## Source Inventory
| Source Name | Role | URL | Access Type | Evidence Provided | Reliability Notes | Last Checked |
| --- | --- | --- | --- | --- | --- | --- |
| Socket Packagist postinstall research | PRIMARY_RESEARCH | https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos | TRULY_PUBLIC_NO_KEY | Confirmed packages, postinstall script, payload URL, cleanup caveats. | Strong first-stage evidence; second-stage unavailable. | 2026-05-24 |

## Feed And Watch List
```yaml
TRULY_PUBLIC_NO_KEY:
  - "https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos"
PUBLIC_BUT_RATE_LIMITED:
  - "https://packagist.org"
API_KEY_OR_AUTH_REQUIRED:
  - "GitHub code search at scale"
PAID_OR_RESTRICTED: []
PAGE_WATCH_FALLBACK:
  - "https://github.com/parikhpreyash4/systemd-network-helper-aa5c751f"
CANDIDATE_FEED_UNVERIFIED:
  - "broader GitHub references to the same postinstall hook"
```

## Executive Findings
- Eight Packagist packages are confirmed with a malicious `package.json` `postinstall` hook.
- The hook downloads `gvfsd-network`, writes `/tmp/.sshd`, chmods it, and runs it.
- The second-stage binary was unavailable in public reporting, so execution impact remains broad.

## Claim Ledger
```yaml
claims:
  - claim_id: C001
    claim: "Eight Packagist packages contained the malicious postinstall hook."
    status: "confirmed"
    confidence: "high"
    evidence_type: "primary_research"
    sources:
      - name: "Socket Packagist postinstall research"
        url: "https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos"
        role: "PRIMARY_RESEARCH"
    notes: "Broader GitHub count should be validated separately."
```

## Event Cluster
```yaml
event_id: "packagist-github-postinstall-hook-campaign-2026-05-22"
event_name: "Packagist GitHub Postinstall Hook Malware Campaign"
parent_campaign_id: "none"
is_campaign_level: true
attack_types: ["malicious postinstall", "source repository compromise", "binary download and execution"]
affected_assets:
  ecosystems: ["Packagist", "Composer", "npm"]
  registries: ["packagist.org", "GitHub"]
  packages: ["moritz-sauer-13/silverstripe-cms-theme", "crosiersource/crosierlib-base", "devdojo/wave", "devdojo/genesis", "katanaui/katana", "elitedevsquad/sidecar-laravel", "r2luna/brain", "baskarcm/tzi-chat-ui"]
  versions: ["dev-main", "dev-master", "3.x-dev"]
  repositories: ["parikhpreyash4/systemd-network-helper-aa5c751f"]
  vendors: []
  ci_cd_systems: ["Composer/npm build pipelines"]
  container_images: []
  developer_tools: ["Composer", "npm"]
  credentials_at_risk: ["unknown; all secrets reachable from hosts executing /tmp/.sshd"]
identifiers:
  cve: []
  ghsa: []
  osv: []
  snyk: []
  other: ["gvfsd-network", "/tmp/.sshd"]
```

## Artifact Analysis
```yaml
artifact_analysis:
  malicious_artifacts: ["package.json scripts.postinstall", "/tmp/.sshd", "gvfsd-network"]
  known_good_artifacts: []
  diff_summary: "PHP/Composer repositories included npm lifecycle code that downloaded and executed a native binary."
  execution_trigger: "npm install postinstall"
  payload_behavior: ["download GitHub Releases binary", "chmod executable", "background execution"]
  persistence: ["unknown"]
  exfiltration: ["unknown"]
  propagation: ["branch-tracking Packagist versions and repository forks"]
  evasion: ["hidden /tmp filename", "cross-ecosystem execution path"]
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
  package_versions: ["confirmed Packagist branch-tracking versions"]
  files: ["package.json", "/tmp/.sshd"]
  hashes: []
  domains: ["github[.]com"]
  urls: ["hxxps://github[.]com/parikhpreyash4/systemd-network-helper-aa5c751f/releases/latest/download/gvfsd-network"]
  ips: []
  registry_metadata: ["dev-main/dev-master/3.x-dev branch tracking"]
  github_audit_events: ["package.json postinstall introduction"]
  process_patterns: ["curl -skL to /tmp/.sshd", "chmod +x /tmp/.sshd"]
  network_patterns: ["download gvfsd-network from GitHub Releases"]
  provenance_signals: ["PHP project containing unexpected npm postinstall"]
```

## Detection Opportunities
```yaml
detection:
  lockfile_hunts: ["composer.lock confirmed Packagist packages"]
  filesystem_hunts: ["parikhpreyash4", "gvfsd-network", "/tmp/.sshd", "scripts.postinstall"]
  process_hunts: ["/tmp/.sshd execution"]
  network_hunts: ["GitHub Releases gvfsd-network URL"]
  ci_cd_hunts: ["npm install in affected PHP projects"]
  registry_hunts: ["branch-tracking Packagist versions"]
  sigma_candidates: ["NPM Postinstall Downloads GitHub Release Binary To /tmp/.sshd"]
  yara_candidates: []
  telemetry_requirements: ["source search", "process telemetry", "proxy logs", "CI logs"]
```

## Remediation And Prevention
- Remove malicious postinstall hooks and pin packages to clean commits.
- Purge Composer and npm caches.
- Isolate systems where `/tmp/.sshd` executed.
- Rotate secrets because second-stage behavior is unknown.

## Open Questions And Collection Gaps
- Behavior of `gvfsd-network`.
- Distinct affected repository count beyond the eight confirmed packages.
- Cleanup status of every branch-tracking package.

## Publication Decision
```yaml
publication_state: "publish_ready"
why: "Confirmed first-stage arbitrary execution and actionable IOCs."
required_human_review: []
writer_instructions:
  - "Publish as standalone high-severity article."
```

## Machine-Readable Event Profile
```json
{
  "schema_version": "2.0",
  "event_id": "packagist-github-postinstall-hook-campaign-2026-05-22",
  "event_name": "Packagist GitHub Postinstall Hook Malware Campaign",
  "parent_campaign_id": "none",
  "is_campaign_level": true,
  "publication_state": "publish_ready",
  "confidence": "medium",
  "confidence_reason": "Socket confirms affected packages and first-stage hook; second-stage behavior is unknown.",
  "attack_types": ["malicious postinstall", "source repository compromise", "arbitrary binary execution"],
  "sources": {
    "direct": [],
    "primary_research": ["https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos"],
    "correlated": []
  },
  "affected_assets": {
    "ecosystems": ["Packagist", "Composer", "npm"],
    "registries": ["packagist.org", "GitHub"],
    "packages": ["moritz-sauer-13/silverstripe-cms-theme", "crosiersource/crosierlib-base", "devdojo/wave", "devdojo/genesis", "katanaui/katana", "elitedevsquad/sidecar-laravel", "r2luna/brain", "baskarcm/tzi-chat-ui"],
    "versions": ["dev-main", "dev-master", "3.x-dev"],
    "repositories": ["parikhpreyash4/systemd-network-helper-aa5c751f"],
    "vendors": [],
    "ci_cd_systems": ["Composer/npm build pipelines"],
    "container_images": [],
    "developer_tools": ["Composer", "npm"],
    "credentials_at_risk": ["unknown; secrets reachable from hosts executing /tmp/.sshd"]
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
    "malicious_artifacts": ["package.json scripts.postinstall", "/tmp/.sshd", "gvfsd-network"],
    "execution_trigger": "npm install postinstall",
    "payload_behavior": ["download GitHub Releases binary", "chmod executable", "background execution"],
    "provenance": {}
  },
  "iocs": {
    "package_versions": ["confirmed Packagist dev branch versions"],
    "files": ["package.json", "/tmp/.sshd"],
    "hashes": [],
    "domains": ["github.com"],
    "urls": ["https://github.com/parikhpreyash4/systemd-network-helper-aa5c751f/releases/latest/download/gvfsd-network"],
    "ips": [],
    "process_patterns": ["curl -skL to /tmp/.sshd", "chmod +x /tmp/.sshd"],
    "network_patterns": ["download gvfsd-network from GitHub Releases"]
  },
  "detection": {
    "lockfile_hunts": ["composer.lock confirmed packages"],
    "filesystem_hunts": ["parikhpreyash4", "gvfsd-network", "/tmp/.sshd", "scripts.postinstall"],
    "process_hunts": ["/tmp/.sshd execution"],
    "network_hunts": ["GitHub Releases gvfsd-network URL"],
    "ci_cd_hunts": ["npm install in affected PHP projects"],
    "registry_hunts": ["branch-tracking Packagist versions"]
  },
  "open_questions": ["second-stage behavior", "full affected repository count", "cleanup status"],
  "defender_takeaways": {
    "detection": "Hunt for lifecycle scripts and /tmp executable drops in Composer projects.",
    "hunting": "Start with confirmed packages and expand to source-code pattern matches.",
    "remediation": "Remove hooks, pin clean commits, purge caches, and rotate secrets after execution.",
    "prevention": "Review package.json scripts in non-JavaScript dependencies."
  }
}
```
