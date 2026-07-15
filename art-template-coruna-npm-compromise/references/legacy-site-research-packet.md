# Research Packet: art-template npm Coruna Browser Exploit Compromise

## Packet Metadata
```yaml
packet_version: "2.0"
event_id: "art-template-coruna-npm-compromise-2026-05-20"
event_name: "art-template npm Coruna Browser Exploit Compromise"
research_date: "2026-05-24"
last_verified: "2026-05-24"
publication_state: "publish_ready"
confidence: "high"
confidence_reason: "Socket provides package version, artifact, network, hash, and browser delivery analysis."
dedupe_keys:
  - "npm:art-template:4.13.5"
  - "npm:art-template:4.13.6"
```

## Source Inventory
| Source Name | Role | URL | Access Type | Evidence Provided | Reliability Notes | Last Checked |
| --- | --- | --- | --- | --- | --- | --- |
| Socket art-template research | PRIMARY_RESEARCH | https://socket.dev/blog/coruna-respawned-compromised-art-template-npm-package | TRULY_PUBLIC_NO_KEY | Affected versions, injected script loads, domains, hashes, browser targeting, remediation. | Deep public malware analysis; final exploit modules still developing. | 2026-05-24 |

## Feed And Watch List
```yaml
TRULY_PUBLIC_NO_KEY:
  - "https://socket.dev/blog/coruna-respawned-compromised-art-template-npm-package"
PUBLIC_BUT_RATE_LIMITED:
  - "https://registry.npmjs.org/art-template"
API_KEY_OR_AUTH_REQUIRED: []
PAID_OR_RESTRICTED: []
PAGE_WATCH_FALLBACK:
  - "https://www.npmjs.com/package/art-template"
CANDIDATE_FEED_UNVERIFIED: []
```

## Executive Findings
- `art-template@4.13.5` and `4.13.6` were compromised with browser-side script injection.
- The injected chain loaded attacker infrastructure under `v3[.]jiathis[.]com` and `cfww[.]shop`.
- The incident affects deployed web assets, not just developer install hosts.

## Claim Ledger
```yaml
claims:
  - claim_id: C001
    claim: "art-template 4.13.5 and 4.13.6 were compromised."
    status: "confirmed"
    confidence: "high"
    evidence_type: "primary_research"
    sources:
      - name: "Socket art-template research"
        url: "https://socket.dev/blog/coruna-respawned-compromised-art-template-npm-package"
        role: "PRIMARY_RESEARCH"
    notes: "Socket also describes 4.13.3 as an earlier encoded loader stage."
```

## Event Cluster
```yaml
event_id: "art-template-coruna-npm-compromise-2026-05-20"
event_name: "art-template npm Coruna Browser Exploit Compromise"
parent_campaign_id: "none"
is_campaign_level: false
attack_types: ["npm package compromise", "browser JavaScript injection", "exploit delivery"]
affected_assets:
  ecosystems: ["npm"]
  registries: ["npmjs.com"]
  packages: ["art-template"]
  versions: ["4.13.5", "4.13.6"]
  repositories: []
  vendors: []
  ci_cd_systems: ["frontend build pipelines"]
  container_images: []
  developer_tools: ["npm", "JavaScript bundlers", "CDN deployment systems"]
  credentials_at_risk: ["unknown"]
identifiers:
  cve: []
  ghsa: []
  osv: []
  snyk: []
  other: ["Coruna-like browser exploit delivery"]
```

## Artifact Analysis
```yaml
artifact_analysis:
  malicious_artifacts: ["lib/template-web.js", "49554fde7424c31c.js"]
  known_good_artifacts: []
  diff_summary: "Browser bundle was modified to load remote scripts from attacker infrastructure."
  execution_trigger: "browser loads affected bundled asset"
  payload_behavior: ["remote script load", "browser fingerprinting", "Safari/iOS targeting", "exploit module staging"]
  persistence: ["browser/CDN cache persistence possible"]
  exfiltration: ["l1ewsu3yjkqeroy[.]xyz beacon path reported"]
  propagation: ["downstream web builds and caches"]
  evasion: ["anti-bot checks", "Safari/iOS gating", "staged content-addressed modules"]
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
  discovery_time: "2026-05-20"
  removal_time: "unknown"
  disclosure_time: "2026-05-20"
  patch_or_fix_time: "unknown"
  source_disagreements: []
```

## Indicators And Observables
```yaml
iocs:
  package_versions: ["art-template 4.13.5", "art-template 4.13.6"]
  files: ["lib/template-web.js", "49554fde7424c31c.js"]
  hashes: ["dd9c0268c8944e6ddf90d4d0c81aa843785b7a9ee965faa635841ed9fc0ba086", "387d7ea5ca733b1e7219c943f4b461877a8df0148adfef42b1538b6c398fbb41"]
  domains: ["v3[.]jiathis[.]com", "utaq[.]cfww[.]shop", "cfww[.]shop", "l1ewsu3yjkqeroy[.]xyz", "ipv4[.]icanhazip[.]com"]
  urls: ["hxxps://v3[.]jiathis[.]com/code/art.js", "hxxps://utaq[.]cfww[.]shop/gooll/gooll.html", "hxxps://utaq[.]cfww[.]shop/gooll/49554fde7424c31c.js", "hxxps://l1ewsu3yjkqeroy[.]xyz/api/ip-sync/sync"]
  ips: []
  registry_metadata: ["art-template affected npm versions"]
  github_audit_events: []
  process_patterns: []
  network_patterns: ["browser requests to v3[.]jiathis[.]com and cfww[.]shop infrastructure"]
  provenance_signals: ["unexpected maintainer/stewardship change before malicious releases"]
```

## Detection Opportunities
```yaml
detection:
  lockfile_hunts: ["package-lock/pnpm-lock/yarn.lock art-template 4.13.5 or 4.13.6"]
  filesystem_hunts: ["v3.jiathis.com", "cfww.shop", "l1ewsu3yjkqeroy.xyz in built assets"]
  process_hunts: []
  network_hunts: ["browser/proxy/CDN telemetry for listed domains"]
  ci_cd_hunts: ["frontend builds using affected versions"]
  registry_hunts: ["block art-template 4.13.5 and 4.13.6"]
  sigma_candidates: ["Proxy Browser Load of art-template Coruna Infrastructure"]
  yara_candidates: ["JavaScript bundle with v3.jiathis.com/code/art.js"]
  telemetry_requirements: ["lockfiles", "built assets", "WAF/proxy/CDN logs"]
```

## Remediation And Prevention
- Remove affected versions and rebuild assets from clean dependency caches.
- Invalidate CDN and browser caches where feasible.
- Hunt web telemetry for listed domains.
- Scan built assets for unexpected third-party script loads.

## Open Questions And Collection Gaps
- Final exploit module behavior.
- Production website exposure.
- Whether `4.13.3` should be blocked with the same urgency.

## Publication Decision
```yaml
publication_state: "publish_ready"
why: "Actionable affected versions and browser IOCs."
required_human_review: []
writer_instructions:
  - "Publish as standalone high-severity npm/browser supply-chain article."
```

## Machine-Readable Event Profile
```json
{
  "schema_version": "2.0",
  "event_id": "art-template-coruna-npm-compromise-2026-05-20",
  "event_name": "art-template npm Coruna Browser Exploit Compromise",
  "parent_campaign_id": "none",
  "is_campaign_level": false,
  "publication_state": "publish_ready",
  "confidence": "high",
  "confidence_reason": "Socket provides package, artifact, hash, and browser delivery evidence.",
  "attack_types": ["npm package compromise", "browser exploit delivery", "JavaScript injection"],
  "sources": {
    "direct": [],
    "primary_research": ["https://socket.dev/blog/coruna-respawned-compromised-art-template-npm-package"],
    "correlated": []
  },
  "affected_assets": {
    "ecosystems": ["npm"],
    "registries": ["npmjs.com"],
    "packages": ["art-template"],
    "versions": ["4.13.5", "4.13.6"],
    "repositories": [],
    "vendors": [],
    "ci_cd_systems": ["frontend build pipelines"],
    "container_images": [],
    "developer_tools": ["npm", "JavaScript bundlers", "CDN deployment systems"],
    "credentials_at_risk": ["unknown"]
  },
  "timeline": {
    "first_seen": "unknown",
    "malicious_publish_time": "unknown",
    "discovery_time": "2026-05-20",
    "removal_time": "unknown",
    "disclosure_time": "2026-05-20",
    "patch_or_fix_time": "unknown"
  },
  "artifact_analysis": {
    "malicious_artifacts": ["lib/template-web.js", "49554fde7424c31c.js"],
    "execution_trigger": "browser loads affected bundle",
    "payload_behavior": ["remote script load", "browser fingerprinting", "Safari/iOS targeting"],
    "provenance": {}
  },
  "iocs": {
    "package_versions": ["art-template@4.13.5", "art-template@4.13.6"],
    "files": ["lib/template-web.js", "49554fde7424c31c.js"],
    "hashes": ["dd9c0268c8944e6ddf90d4d0c81aa843785b7a9ee965faa635841ed9fc0ba086", "387d7ea5ca733b1e7219c943f4b461877a8df0148adfef42b1538b6c398fbb41"],
    "domains": ["v3.jiathis.com", "utaq.cfww.shop", "cfww.shop", "l1ewsu3yjkqeroy.xyz", "ipv4.icanhazip.com"],
    "urls": ["https://v3.jiathis.com/code/art.js", "https://utaq.cfww.shop/gooll/gooll.html", "https://utaq.cfww.shop/gooll/49554fde7424c31c.js", "https://l1ewsu3yjkqeroy.xyz/api/ip-sync/sync"],
    "ips": [],
    "process_patterns": [],
    "network_patterns": ["browser requests to v3.jiathis.com and cfww.shop infrastructure"]
  },
  "detection": {
    "lockfile_hunts": ["art-template 4.13.5 or 4.13.6"],
    "filesystem_hunts": ["v3.jiathis.com", "cfww.shop", "l1ewsu3yjkqeroy.xyz"],
    "process_hunts": [],
    "network_hunts": ["v3.jiathis.com", "utaq.cfww.shop", "l1ewsu3yjkqeroy.xyz"],
    "ci_cd_hunts": ["frontend builds with affected versions"],
    "registry_hunts": ["block affected npm versions"]
  },
  "open_questions": ["final exploit behavior", "production site exposure", "4.13.3 risk"],
  "defender_takeaways": {
    "detection": "Scan built browser assets and web telemetry.",
    "hunting": "Find affected lockfiles and deployed bundles.",
    "remediation": "Rebuild and invalidate caches.",
    "prevention": "Monitor frontend bundles for unexpected remote script loads."
  }
}
```
