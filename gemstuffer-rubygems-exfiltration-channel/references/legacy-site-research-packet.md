# Research Packet: GemStuffer RubyGems Exfiltration Channel

## Packet Metadata
```yaml
packet_version: "2.0"
event_id: "gemstuffer-rubygems-exfiltration-channel-2026-05-13"
candidate_id: "gemstuffer-rubygems-exfiltration-channel"
event_name: "GemStuffer Campaign Abuses RubyGems as Exfiltration Channel Targeting UK Local Government"
research_date: "2026-05-28"
last_verified: "2026-05-28"
publication_state: "publish_ready"
decision: "new_incident_post"
confidence: "medium"
confidence_reason: "Socket provides primary reverse-engineering and a public campaign tracker, while RubyGems public timeframe metadata independently confirms yanked May 12, 2026 package versions with embedded ModernGov council content and hashes. The original delivery vector and publisher account identities remain unresolved in public evidence."
dedupe_keys:
  - "campaign:gemstuffer"
  - "ecosystem:rubygems"
  - "source:https://socket.dev/blog/gemstuffer"
```

## Source Inventory
| # | Source Name | Role | URL | Evidence Provided | Reliability Notes | Last Checked |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Socket GemStuffer research | PRIMARY_RESEARCH | https://socket.dev/blog/gemstuffer | Campaign name, attack chain, representative payload code, API key handling, file hashes, IOCs, recommended response. | Direct researcher write-up with code snippets and redacted credentials. | 2026-05-28 |
| 2 | Socket GemStuffer campaign tracker | PRIMARY_RESEARCH | https://socket.dev/supply-chain-attacks/gemstuffer | Public tracker states 155 affected package artifacts and provides package/version publish and detection rows. | Tracker is dynamic and Cloudflare-protected for direct CLI fetch; browser text view was used for row samples. | 2026-05-28 |
| 3 | RubyGems.org API guide | DIRECT_REGISTRY_DOCS | https://guides.rubygems.org/rubygems-org-api/ | Documents gem push endpoint, yanking endpoint, version metadata fields, hashes, and timeframe_versions API. | Registry operator documentation. | 2026-05-28 |
| 4 | RubyGems.org status history | DIRECT_REGISTRY_STATUS | https://status.rubygems.org/history | Confirms temporary disabling of new user registrations from May 12, 2026 08:54 UTC to May 16, 2026 05:12 UTC. | Registry operator status page; details are minimal. | 2026-05-28 |
| 5 | RubyGems.org data dumps page | DIRECT_REGISTRY_DOCS | https://rubygems.org/pages/data | Confirms weekly sanitized PostgreSQL dumps are available for registry-scale follow-up without scraping. | Registry operator documentation; useful next collection path. | 2026-05-28 |

## Executive Findings
- GemStuffer is publishable as a standalone Halting Problems post. It is not a conventional dependency-install compromise, but it is supply-chain abuse because the actor used RubyGems package creation and release mechanics as an exfiltration and storage channel.
- Socket reports more than 100 gems in the campaign and the public tracker lists 155 package artifacts. The representative artifacts observed in tracker rows were Ruby platform packages published on May 12, 2026 and detected within minutes.
- RubyGems public API timeframe queries independently confirm yanked versions for representative names such as `agenda-sample-yard`, `bot9evil`, `fetchrootx2`, `soufetchabc`, and `lambeth71b`. Those API responses include version timestamps, SHA-256 digests, authors fields, summary fields, download counts, `yanked: true`, and gem URIs.
- The exfiltration mechanics are confirmed at code level: scrape ModernGov council pages, write the response into a valid gem archive, and push the archive to RubyGems through either `gem push` with an injected `/tmp/gemhome/.gem/credentials` file or a direct `Net::HTTP::Post` to the RubyGems gem-create endpoint.
- Public evidence does not confirm initial delivery, host victims, full publisher account mapping, or whether all 155 tracked artifacts contain scraped data versus related spam/probe packages. These stay `unknown` or `not_observed`.

## Claim Ledger
```yaml
claims:
  - claim_id: C001
    claim: "GemStuffer used RubyGems as a data transport or public drop channel rather than primarily as a mass developer compromise mechanism."
    status: "confirmed"
    confidence: "high"
    evidence:
      - source: 1
        detail: "Socket states the packages wrapped scraped council responses into valid .gem archives and published them back to RubyGems."
  - claim_id: C002
    claim: "Socket was tracking 155 package artifacts in the campaign tracker."
    status: "confirmed"
    confidence: "high"
    evidence:
      - source: 1
        detail: "The article says the tracker contains 155 package artifacts."
      - source: 2
        detail: "The campaign tracker page displays Affected Package Artifacts: 155."
  - claim_id: C003
    claim: "Representative tracker rows include agenda-sample-yard 0.1.1, bot9evil 0.1.0, fetchrootx2 0.0.1, soufetchabc 0.0.3, wandcabfetchfix21736 0.0.1, wandscrawlr 0.0.1, slnleaker5 0.0.1, fetchrootx1 0.0.1, and lambeth71b 0.0.1."
    status: "confirmed"
    confidence: "high"
    evidence:
      - source: 2
        detail: "Tracker row text lists these package/version pairs with UTC publish and detection times."
  - claim_id: C004
    claim: "RubyGems API metadata confirms representative GemStuffer packages were yanked and exposes their version SHA-256 digests."
    status: "confirmed"
    confidence: "high"
    evidence:
      - source: 3
        detail: "RubyGems documents version metadata fields including sha, yanked, and created_at through timeframe_versions."
      - source: "local_verification"
        detail: "2026-05-28 API query for 2026-05-12T02:20:00Z..03:30:00Z returned yanked rows for agenda-sample-yard 0.1.0/0.1.1, bot9evil 0.1.0, fetchrootx2 0.0.1, soufetchabc 0.0.1/0.0.2/0.0.3, and lambeth71b 0.0.1."
  - claim_id: C005
    claim: "The samples scraped Lambeth, Wandsworth, and Southwark ModernGov portals."
    status: "confirmed"
    confidence: "high"
    evidence:
      - source: 1
        detail: "Socket provides code snippets with the three hosts and calendar URL construction."
      - source: "local_verification"
        detail: "RubyGems timeframe metadata included descriptions containing ModernGov calendar URLs and r.jina.ai-wrapped council URLs."
  - claim_id: C006
    claim: "Some variants used a fabricated HOME under /tmp/gemhome and hardcoded RubyGems API keys; others used a direct HTTP POST with Authorization and application/octet-stream."
    status: "confirmed"
    confidence: "high"
    evidence:
      - source: 1
        detail: "Socket provides both credential-injection and direct Net::HTTP::Post snippets."
      - source: 3
        detail: "RubyGems documents POST /api/v1/gems with an Authorization header and binary gem body."
  - claim_id: C007
    claim: "RubyGems temporarily disabled new account registration during the broader May 2026 spam-publishing response."
    status: "confirmed"
    confidence: "high"
    evidence:
      - source: 4
        detail: "RubyGems status history lists the incident from May 12 08:54 UTC to May 16 05:12 UTC."
  - claim_id: C008
    claim: "The campaign compromised existing legitimate RubyGems packages."
    status: "not_observed"
    confidence: "medium"
    evidence:
      - source: 1
        detail: "Socket cites Ruby Central saying the broader incident was limited to newly registered accounts and that existing packages and installs were unaffected."
  - claim_id: C009
    claim: "Publisher account handles and complete account-to-package mapping are known publicly."
    status: "unknown"
    confidence: "low"
    evidence:
      - source: 2
        detail: "The tracker rows expose package/version metadata, not a complete publisher identity ledger."
      - source: 3
        detail: "RubyGems public version metadata does not include full user information."
  - claim_id: C010
    claim: "The original delivery vector that placed payload.rb, script.rb, evil.rb, or related Ruby files on a host is known."
    status: "unknown"
    confidence: "low"
    evidence:
      - source: 1
        detail: "Socket recommends identifying the delivery vector and states the implant does not self-propagate."
```

## Representative Registry Verification
```yaml
registry_api_window:
  from: "2026-05-12T02:20:00Z"
  to: "2026-05-12T03:30:00Z"
  verification_date: "2026-05-28"
  api: "https://rubygems.org/api/v1/timeframe_versions.json"
representative_rows:
  - package: "agenda-sample-yard"
    version: "0.1.0"
    created_at: "2026-05-12T03:06:19.784Z"
    sha256: "3d88cfacb4c5c254e8f2e460c8321a18bf96a275d9a0364502aad9662b26f4db"
    yanked: true
    authors: "a"
    downloads_count: 47
  - package: "agenda-sample-yard"
    version: "0.1.1"
    created_at: "2026-05-12T03:25:33.962Z"
    sha256: "2e4e099275efb8f886824a8eccdc595e624cd08ebb1772bd427710e08ff3ab24"
    yanked: true
    authors: "a"
    downloads_count: 52
  - package: "bot9evil"
    version: "0.1.0"
    created_at: "2026-05-12T03:23:17.445Z"
    sha256: "94d6c0b589704c8cc75e19f7250d6bfda473266dd7dd7e23fd14bd1bb972a717"
    yanked: true
    authors: "a"
    downloads_count: 59
  - package: "fetchrootx2"
    version: "0.0.1"
    created_at: "2026-05-12T03:21:50.962Z"
    sha256: "986342f884d531d686eeda19eb2cdc32eecea3f9d49ad6be6d493b5e680fc38b"
    yanked: true
    authors: "x"
    downloads_count: 49
  - package: "soufetchabc"
    version: "0.0.3"
    created_at: "2026-05-12T03:18:31.634Z"
    sha256: "75608fbc0307555c0f8eafe03f323c556dd4b2a7a05fa17ab4a13b7ef1d86eb7"
    yanked: true
    authors: "x"
    downloads_count: 46
  - package: "lambeth71b"
    version: "0.0.1"
    created_at: "2026-05-12T03:13:47.068Z"
    sha256: "34212b88108cab6ded037257d6fbc79a61b4c2ea8ecddc6c513b5aad1f308638"
    yanked: true
    authors: "71"
    downloads_count: 61
```

## Artifact Analysis
```yaml
artifact_analysis:
  malicious_artifacts:
    - "valid .gem archives containing scraped HTTP responses"
    - "/tmp/<package><epoch_timestamp><pid>/lib/result.txt"
    - "/tmp/<package><epoch_timestamp><pid>/x.gemspec"
    - "/tmp/gemhome/.gem/credentials"
    - "payload.rb"
    - "script.rb"
    - "evil.rb"
    - "yardload.rb"
    - "yard_plugin.rb"
    - "exploit.rb"
    - "extconf.rb"
    - "fetcher.rb"
  known_good_artifacts: []
  execution_trigger: "unknown delivery vector; observed Ruby payload execution on a host with RubyGems publishing capability through embedded API keys"
  payload_behavior:
    - "collect Time.now, Dir.pwd, script path, and ARGV"
    - "fetch ModernGov calendar and agenda pages"
    - "write response bodies to gem archive content"
    - "build and publish gem to RubyGems"
  exfiltration:
    - "RubyGems package upload used as data staging channel"
  propagation:
    - "not_observed"
  credential_exposure:
    - "hardcoded RubyGems API keys embedded in payloads; full values redacted in public reporting"
  provenance:
    present: false
    verified: null
    notes: "No trusted publishing, signing, or source repository provenance is available for the junk package set in public evidence."
```

## Detection Opportunities
```yaml
detection:
  registry_hunts:
    - "RubyGems timeframe_versions rows in 2026-05-12T02:20:00Z..2026-05-12T03:30:00Z with ModernGov domains, mgCalendarMonthView, ieList, mgCommittee, or r.jina.ai-wrapped council URLs in info/description."
    - "New RubyGems package versions with yanked=true, no runtime dependencies, authors such as a/x/tmp/71, synthetic built_at 1980-01-02T00:00:00Z, and names containing lamb, wand, south, fetch, crawl, leaker, runner, yard, or agenda."
  filesystem_hunts:
    - "/tmp/gemhome/.gem/credentials"
    - "/tmp/rubydocran_*"
    - "/tmp/<package><epoch><pid>/lib/result.txt"
    - "payload.rb, script.rb, evil.rb, yardload.rb, yard_plugin.rb, exploit.rb, extconf.rb, fetcher.rb"
  process_hunts:
    - "ruby process writing /tmp/gemhome/.gem/credentials"
    - "ruby spawning gem build or gem push"
    - "ruby issuing Net::HTTP::Post to RubyGems gem create endpoint"
  network_hunts:
    - "outbound POST to RubyGems gem create endpoint from hosts that do not publish gems"
    - "Ruby process fetching ModernGov council calendar URLs with User-Agent Mozilla/5.0"
  telemetry_requirements:
    - "proxy or egress logs with method, host, path, user agent, process, and account"
    - "EDR file and process telemetry for /tmp and gem CLI execution"
    - "CI job logs and shell histories on Ruby-capable systems"
    - "RubyGems organization/account audit exports where available"
```

## Remediation And Prevention
- Report and yank confirmed package versions; preserve metadata before removal because yanking can hide standard package pages.
- Revoke all RubyGems API keys observed in payloads and audit new keys created near May 12, 2026.
- Block `POST` requests to the RubyGems gem-create endpoint from CI, developer, and production segments that do not intentionally publish Ruby gems.
- For legitimate publishers, restrict egress to known release runners and add package-name allowlists.
- Preserve `/tmp/gemhome`, staging directories, `.gem` archives, and logs before deleting them.
- Treat any host that executed the payload as a general Ruby process compromise until endpoint telemetry proves no additional payloads, shell commands, or credential reads occurred.
- Use RubyGems weekly data dumps for registry-scale retrospective analysis rather than scraping live package pages.

## Open Questions And Collection Gaps
- Complete 155-artifact package/version list with publisher account handles.
- Exact RubyGems API key identities, scopes, creation times, and revocation times.
- Initial delivery vector for `payload.rb`, `script.rb`, `evil.rb`, and related payload filenames.
- Whether every tracker package contained scraped council data or whether some were probes, spam, or decoy package versions.
- Whether any private or non-public council content was collected; public evidence only supports public-facing ModernGov content.

## Publication Decision
```yaml
publication_state: "publish_ready"
decision: "new_incident_post"
why: "The incident meets the site threshold as registry abuse with package artifacts used for exfiltration and storage. The final article must avoid claiming mass developer compromise or confirmed private-data theft."
required_human_review: []
```

## Machine-Readable Event Profile
```json
{
  "schema_version": "2.0",
  "event_id": "gemstuffer-rubygems-exfiltration-channel-2026-05-13",
  "event_name": "GemStuffer RubyGems Exfiltration Channel",
  "parent_campaign_id": "none",
  "is_campaign_level": true,
  "publication_state": "publish_ready",
  "confidence": "medium",
  "confidence_reason": "Primary research and RubyGems registry metadata confirm the technique and representative yanked package artifacts; publisher identities, full package set, and original delivery vector remain incomplete publicly.",
  "attack_types": ["registry abuse", "package artifact data staging", "hardcoded registry credential use", "public-sector scraping"],
  "sources": {
    "direct": ["https://guides.rubygems.org/rubygems-org-api/", "https://status.rubygems.org/history", "https://rubygems.org/pages/data"],
    "primary_research": ["https://socket.dev/blog/gemstuffer", "https://socket.dev/supply-chain-attacks/gemstuffer"],
    "correlated": []
  },
  "affected_assets": {
    "ecosystems": ["RubyGems", "Ruby"],
    "registries": ["RubyGems.org"],
    "packages": ["agenda-sample-yard", "bot9evil", "fetchrootx2", "soufetchabc", "wandcabfetchfix21736", "wandscrawlr", "slnleaker5", "fetchrootx1", "lambeth71b", "probeextwand", "designfetchdemo", "lambethx33zzz", "wandocal1", "wandcabm10266dsgn4", "sl-yard-probe2", "lambexploitabc1", "wandscrawlq", "lambcrawlxyz", "swmeetfetcha", "lbdeepgeta", "slfetchrootabc", "zzsouthrunnerb", "slnleakerext", "runnerhack1778553910", "southfetchprobe42"],
    "versions": ["0.0.1", "0.0.2", "0.0.3", "0.0.5", "0.1.0", "0.1.1", "1.0.0", "1.2.3", "9.8.0", "9.9.0"],
    "repositories": [],
    "vendors": ["Lambeth Council", "Wandsworth Council", "Southwark Council"],
    "ci_cd_systems": ["unknown"],
    "developer_tools": ["Ruby", "RubyGems gem CLI"],
    "credentials_at_risk": ["RubyGems API keys embedded in payloads", "credentials reachable from any host where the unknown delivery vector executed"]
  },
  "timeline": {
    "first_seen": "2026-05-12T02:20:00Z",
    "malicious_publish_time": "2026-05-12T02:20:00Z/2026-05-12T03:30:00Z",
    "discovery_time": "2026-05-13",
    "removal_time": "mixed; representative RubyGems API rows show yanked=true as of 2026-05-28",
    "disclosure_time": "2026-05-13",
    "patch_or_fix_time": "unknown"
  },
  "artifact_analysis": {
    "malicious_artifacts": ["payload.rb", "script.rb", "evil.rb", "yardload.rb", "yard_plugin.rb", "exploit.rb", "extconf.rb", "fetcher.rb", ".gem archives containing scraped responses"],
    "execution_trigger": "unknown",
    "payload_behavior": ["scrape ModernGov pages", "build RubyGems packages", "push packages with embedded RubyGems API keys"],
    "provenance": {}
  },
  "iocs": {
    "package_versions": ["agenda-sample-yard 0.1.1", "bot9evil 0.1.0", "fetchrootx2 0.0.1", "soufetchabc 0.0.3", "lambeth71b 0.0.1"],
    "files": ["payload.rb", "script.rb", "evil.rb", "yardload.rb", "yard_plugin.rb", "exploit.rb", "extconf.rb", "fetcher.rb", "/tmp/gemhome/.gem/credentials", "/tmp/rubydocran_*", "lib/result.txt", "x.gemspec"],
    "hashes": ["239440c830e17530dda0a8a06ed2708860998750a1e3ed2239e919465dc59420", "c2d6bcacc88177e0f2c8c262726f86f37e671b1692c8bc135bac4b610ddcf31a", "34212b88108cab6ded037257d6fbc79a61b4c2ea8ecddc6c513b5aad1f308638", "2e4e099275efb8f886824a8eccdc595e624cd08ebb1772bd427710e08ff3ab24", "94d6c0b589704c8cc75e19f7250d6bfda473266dd7dd7e23fd14bd1bb972a717"],
    "domains": ["rubygems.org", "moderngov.lambeth.gov.uk", "democracy.wandsworth.gov.uk", "moderngov.southwark.gov.uk"],
    "urls": ["https://rubygems.org/api/v1/gems", "https://moderngov.lambeth.gov.uk/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1", "https://democracy.wandsworth.gov.uk/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1", "https://moderngov.southwark.gov.uk/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1"],
    "ips": [],
    "process_patterns": ["ruby writing /tmp/gemhome/.gem/credentials", "ruby running gem build", "ruby running gem push", "ruby Net::HTTP::Post to RubyGems"],
    "network_patterns": ["POST https://rubygems.org/api/v1/gems", "GET ModernGov mgCalendarMonthView.aspx with User-Agent Mozilla/5.0"]
  },
  "detection": {
    "registry_hunts": ["Query RubyGems timeframe_versions for May 12, 2026 versions containing ModernGov domains or known package/version pairs."],
    "filesystem_hunts": ["Search /tmp, gem caches, CI workspaces, and shell histories for GemStuffer filenames, /tmp/gemhome, and known package names."],
    "process_hunts": ["Find ruby processes invoking gem build, gem push, or Net::HTTP::Post to RubyGems from non-release hosts."],
    "network_hunts": ["Find RubyGems gem-create POSTs and ModernGov calendar scraping from developer, CI, or production hosts."],
    "ci_cd_hunts": ["Identify CI jobs with Ruby installed that made outbound RubyGems publish requests outside approved release workflows."]
  },
  "open_questions": ["complete 155 artifact list", "publisher account mapping", "initial delivery vector", "private-data exposure status"],
  "defender_takeaways": {
    "detection": "Treat unexpected RubyGems publishing traffic as exfiltration-capable egress, not merely release activity.",
    "hunting": "Correlate ModernGov scraping, /tmp gem staging, and RubyGems gem-create POSTs in the same host or CI job window.",
    "remediation": "Yank confirmed gems, revoke embedded RubyGems keys, preserve staging artifacts, and restrict gem publishing to approved release runners.",
    "prevention": "Block registry publish endpoints from systems that consume packages but never publish them."
  }
}
```
