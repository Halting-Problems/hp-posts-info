# Research Packet: shopsprint/decimal Go Module DNS Backdoor Typosquat

## Packet Metadata
```yaml
packet_version: "2.0"
event_id: "shopsprint-decimal-go-typosquat-2026-05-19"
event_name: "shopsprint/decimal Go Module DNS Backdoor Typosquat"
research_date: "2026-05-24"
last_verified: "2026-05-24"
publication_state: "publish_ready"
confidence: "high"
confidence_reason: "Socket provides Go Module Proxy artifact diff evidence, malicious version, DNS C2 behavior, and hash."
dedupe_keys:
  - "go:github.com/shopsprint/decimal:v1.3.3"
```

## Source Inventory
| Source Name | Role | URL | Access Type | Evidence Provided | Reliability Notes | Last Checked |
| --- | --- | --- | --- | --- | --- | --- |
| Socket shopsprint/decimal research | PRIMARY_RESEARCH | https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor | TRULY_PUBLIC_NO_KEY | Typoed module, v1.3.3 malicious diff, DNS TXT C2, proxy persistence, hash, remediation. | Strong artifact diff from Go Module Proxy. | 2026-05-24 |

## Feed And Watch List
```yaml
TRULY_PUBLIC_NO_KEY:
  - "https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor"
PUBLIC_BUT_RATE_LIMITED:
  - "https://pkg.go.dev/github.com/shopsprint/decimal"
  - "https://proxy.golang.org/github.com/shopsprint/decimal/@v/v1.3.3.zip"
API_KEY_OR_AUTH_REQUIRED: []
PAID_OR_RESTRICTED: []
PAGE_WATCH_FALLBACK: []
CANDIDATE_FEED_UNVERIFIED: []
```

## Executive Findings
- `github.com/shopsprint/decimal@v1.3.3` typosquatted `github.com/shopspring/decimal`.
- The malicious version added a Go `init()` DNS TXT command loop.
- Go Module Proxy cache persistence means removed GitHub source does not eliminate exposure.

## Claim Ledger
```yaml
claims:
  - claim_id: C001
    claim: "github.com/shopsprint/decimal v1.3.3 contains an init-time DNS TXT command backdoor."
    status: "confirmed"
    confidence: "high"
    evidence_type: "artifact_diff"
    sources:
      - name: "Socket shopsprint/decimal research"
        url: "https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor"
        role: "PRIMARY_RESEARCH"
    notes: "Socket analyzed module proxy artifact diff."
```

## Event Cluster
```yaml
event_id: "shopsprint-decimal-go-typosquat-2026-05-19"
event_name: "shopsprint/decimal Go Module DNS Backdoor Typosquat"
parent_campaign_id: "none"
is_campaign_level: false
attack_types: ["typosquatting", "Go init malware", "DNS command and control"]
affected_assets:
  ecosystems: ["Go modules"]
  registries: ["proxy.golang.org", "pkg.go.dev"]
  packages: ["github.com/shopsprint/decimal"]
  versions: ["v1.3.3"]
  repositories: ["github.com/shopsprint/decimal"]
  vendors: []
  ci_cd_systems: ["Go build/test pipelines"]
  container_images: ["images built from affected code"]
  developer_tools: ["go command", "Go module cache"]
  credentials_at_risk: ["secrets reachable from affected build or runtime hosts"]
identifiers:
  cve: []
  ghsa: []
  osv: []
  snyk: []
  other: ["dnslog-cdn-images.freemyip.com"]
```

## Artifact Analysis
```yaml
artifact_analysis:
  malicious_artifacts: ["decimal.go init() DNS TXT loop"]
  known_good_artifacts: ["github.com/shopspring/decimal"]
  diff_summary: "One-character typoed module kept legitimate API shape while adding command-channel imports and init() behavior."
  execution_trigger: "Go package init()"
  payload_behavior: ["DNS TXT command polling", "command execution"]
  persistence: ["Go Module Proxy cached malicious artifact"]
  exfiltration: ["unknown"]
  propagation: ["dependency typo and cached module retrieval"]
  evasion: ["name similarity", "small diff", "DNS command channel"]
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
  first_seen: "2017-11-08"
  malicious_publish_time: "2023-08-19T09:27:21Z"
  discovery_time: "2026-05-19"
  removal_time: "mixed"
  disclosure_time: "2026-05-19"
  patch_or_fix_time: "unknown"
  source_disagreements: []
```

## Indicators And Observables
```yaml
iocs:
  package_versions: ["github.com/shopsprint/decimal v1.3.3"]
  files: ["go.mod", "go.sum", "decimal.go"]
  hashes: ["f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c"]
  domains: ["dnslog-cdn-images[.]freemyip[.]com", "freemyip[.]com"]
  urls: []
  ips: []
  registry_metadata: ["Go Module Proxy serves cached v1.3.3"]
  github_audit_events: ["commit introducing shopsprint import"]
  process_patterns: ["Go application importing github.com/shopsprint/decimal"]
  network_patterns: ["TXT queries to dnslog-cdn-images[.]freemyip[.]com"]
  provenance_signals: ["module path differs from shopspring by one character"]
```

## Detection Opportunities
```yaml
detection:
  lockfile_hunts: ["go.mod and go.sum github.com/shopsprint/decimal"]
  filesystem_hunts: ["GOMODCACHE and vendor shopsprint decimal"]
  process_hunts: ["unexpected child processes from affected Go applications"]
  network_hunts: ["TXT queries to dnslog-cdn-images[.]freemyip[.]com"]
  ci_cd_hunts: ["Go builds downloading shopsprint/decimal v1.3.3"]
  registry_hunts: ["block shopsprint/decimal"]
  sigma_candidates: ["DNS TXT Query To freemyip Dynamic DNS From Build Or Application Host"]
  yara_candidates: ["Go decimal.go containing net.LookupTXT and os/exec.Command in init()"]
  telemetry_requirements: ["Go dependency inventory", "DNS logs with query type", "build logs"]
```

## Remediation And Prevention
- Replace `github.com/shopsprint/decimal` with `github.com/shopspring/decimal`.
- Purge module caches and rebuild binaries.
- Rotate secrets from affected build or runtime hosts.
- Enforce exact-path allowlists for critical Go modules.

## Open Questions And Collection Gaps
- Downstream victim count.
- Commands served over DNS TXT.
- Built binaries still containing the typoed module.

## Publication Decision
```yaml
publication_state: "publish_ready"
why: "High-confidence artifact diff and clear typo/C2 indicators."
required_human_review: []
writer_instructions:
  - "Publish as standalone Go typosquat article."
```

## Machine-Readable Event Profile
```json
{
  "schema_version": "2.0",
  "event_id": "shopsprint-decimal-go-typosquat-2026-05-19",
  "event_name": "shopsprint/decimal Go Module DNS Backdoor Typosquat",
  "parent_campaign_id": "none",
  "is_campaign_level": false,
  "publication_state": "publish_ready",
  "confidence": "high",
  "confidence_reason": "Socket provides Go Module Proxy artifact diff evidence.",
  "attack_types": ["typosquatting", "Go init malware", "DNS command and control"],
  "sources": {
    "direct": [],
    "primary_research": ["https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor"],
    "correlated": []
  },
  "affected_assets": {
    "ecosystems": ["Go modules"],
    "registries": ["proxy.golang.org", "pkg.go.dev"],
    "packages": ["github.com/shopsprint/decimal"],
    "versions": ["v1.3.3"],
    "repositories": ["github.com/shopsprint/decimal"],
    "vendors": [],
    "ci_cd_systems": ["Go build/test pipelines"],
    "container_images": ["images built from affected code"],
    "developer_tools": ["go command", "Go module cache"],
    "credentials_at_risk": ["secrets reachable from affected build or runtime hosts"]
  },
  "timeline": {
    "first_seen": "2017-11-08",
    "malicious_publish_time": "2023-08-19T09:27:21Z",
    "discovery_time": "2026-05-19",
    "removal_time": "mixed",
    "disclosure_time": "2026-05-19",
    "patch_or_fix_time": "unknown"
  },
  "artifact_analysis": {
    "malicious_artifacts": ["decimal.go init() DNS TXT loop"],
    "execution_trigger": "Go package init()",
    "payload_behavior": ["DNS TXT command polling", "command execution"],
    "provenance": {}
  },
  "iocs": {
    "package_versions": ["github.com/shopsprint/decimal@v1.3.3"],
    "files": ["go.mod", "go.sum", "decimal.go"],
    "hashes": ["f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c"],
    "domains": ["dnslog-cdn-images.freemyip.com", "freemyip.com"],
    "urls": [],
    "ips": [],
    "process_patterns": ["Go application importing github.com/shopsprint/decimal"],
    "network_patterns": ["TXT dnslog-cdn-images.freemyip.com"]
  },
  "detection": {
    "lockfile_hunts": ["go.mod and go.sum shopsprint/decimal"],
    "filesystem_hunts": ["GOMODCACHE and vendor shopsprint decimal"],
    "process_hunts": ["unexpected child processes from affected Go apps"],
    "network_hunts": ["TXT dnslog-cdn-images.freemyip.com"],
    "ci_cd_hunts": ["Go builds downloading shopsprint/decimal"],
    "registry_hunts": ["block shopsprint/decimal"]
  },
  "open_questions": ["victim count", "DNS commands", "downstream binary exposure"],
  "defender_takeaways": {
    "detection": "Search module paths and DNS TXT telemetry.",
    "hunting": "Find typoed imports in source, caches, SBOMs, and binaries.",
    "remediation": "Replace with shopspring/decimal, purge caches, rebuild, rotate secrets.",
    "prevention": "Allowlist critical Go module paths."
  }
}
```
