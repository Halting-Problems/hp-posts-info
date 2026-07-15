---
title: "elementary-data PyPI and GHCR GitHub Actions Compromise"
date: 2026-04-25
severity: "critical"
tags:
  - pypi
  - github-actions
  - ghcr
  - supply-chain
  - credential-theft
summary: "A malicious `elementary-data==0.23.3` release was pushed to PyPI and GHCR after attackers exploited a GitHub Actions script-injection path, adding an interpreter-startup `.pth` infostealer."
sourceCount: 5
draftStatus: "packet-draft"
---

## Executive Summary
On April 24, 2026 at 22:20:47 UTC, a malicious `elementary-data==0.23.3` release was uploaded to PyPI [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection). The same release workflow also pushed a compromised multi-architecture container image to GitHub Container Registry at `ghcr.io/elementary-data/elementary`, including the `0.23.3` and `latest` tags [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).

The attacker exploited a script-injection vulnerability in an Elementary GitHub Actions workflow, used the workflow's `GITHUB_TOKEN` to forge a release commit, and dispatched the legitimate publishing pipeline without modifying the `master` branch [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection). The malicious wheel and source distribution added a top-level `elementary.pth` file, which Python executes at interpreter startup when installed in `site-packages`; this means the payload could run even if the victim never explicitly imported `elementary` [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).

Snyk tracks the incident as `SNYK-PYTHON-ELEMENTARYDATA-16316110`, affecting only `elementary-data==0.23.3`, and notes that Elementary Cloud, the Elementary dbt package, and other CLI versions were not affected [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PYTHON-ELEMENTARYDATA-16316110). The clean replacement is `0.23.4` [PyPI](https://pypi.org/project/elementary-data/).

## Key Facts
```yaml
threat_type: "GitHub Actions script injection, forged release, PyPI/GHCR credential stealer"
ecosystem: "pypi, python, container"
registry:
  - "PyPI"
  - "GitHub Container Registry"
affected_packages:
  - "elementary-data"
malicious_versions:
  - "0.23.3"
fixed_versions:
  - "0.23.4"
known_good_versions:
  - "0.23.2"
execution_trigger: "Python interpreter startup through elementary.pth"
primary_impact: "dbt, data warehouse, cloud, SSH, API token, environment variable, and developer secret theft"
known_iocs:
  - "elementary.pth"
  - "ghcr.io/elementary-data/elementary:0.23.3"
  - "ghcr.io/elementary-data/elementary:latest"
  - "igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud"
  - "X-Rise-To-The-Trinny: agree"
  - "trin.tar.gz"
  - "$TMPDIR/.trinny-security-update"
confidence: "high"
canonical_source: "https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection"
```

## Source Confidence & Evidence Mapping
* **confirmed:** `elementary-data==0.23.3` was the malicious PyPI release; `0.23.4` is the clean replacement [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection) [PyPI](https://pypi.org/project/elementary-data/).
* **confirmed:** The malicious release added `elementary.pth`, which executes at Python interpreter startup from `site-packages` [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).
* **confirmed:** The incident also affected GHCR images tagged `0.23.3` and `latest`, with the clean `0.23.2` image available by digest for comparison [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).
* **confirmed:** Snyk identifies the payload as an embedded credential stealer targeting dbt profiles, data warehouse credentials, cloud keys, API tokens, SSH keys, `.env` files, and environment variables [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PYTHON-ELEMENTARYDATA-16316110).
* **unclear:** The public sources do not identify the threat actor or confirm whether any stolen credentials were used after exfiltration.

## Timeline
- **2026-04-24T22:20:47Z** `elementary-data==0.23.3` is uploaded to PyPI with a malicious top-level `elementary.pth` file [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).
- **2026-04-24T22:20:47Z** The same release process pushes compromised GHCR images tagged `0.23.3` and `latest` [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).
- **2026-04-25T00:00:00Z** StepSecurity publishes its technical writeup and identifies the forged release path [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).
- **2026-04-25T00:00:00Z** The Elementary team removes `0.23.3`, removes the malicious GHCR image, and publishes clean `0.23.4` [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection) [PyPI](https://pypi.org/project/elementary-data/).
- **2026-04-28T00:00:00Z** Snyk publishes advisory `SNYK-PYTHON-ELEMENTARYDATA-16316110` [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PYTHON-ELEMENTARYDATA-16316110).

## What Happened
The attacker did not need to land a conventional malicious pull request on the default branch. Instead, they abused a script-injection weakness in a GitHub Actions workflow and used the workflow's own token to forge a release commit that looked signed by automation [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection). The release tag pointed to an orphaned commit that bumped the version to `0.23.3` and added `elementary.pth`, rather than a normal branch commit reviewed through the project workflow [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).

Because `.pth` files are evaluated by Python at interpreter startup, the malicious code could execute in any environment where the package was installed, independent of application-level imports [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection). The same release run produced a compromised container image, expanding the blast radius to teams pulling `ghcr.io/elementary-data/elementary:latest` in data engineering deployments [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).

## Technical Analysis
### Initial Access
Initial access came through a GitHub Actions script-injection vector, not through a direct commit to `master` [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection). The key failure was allowing attacker-influenced workflow input to execute with a token capable of causing release publication.

### Package or Artifact Manipulation
The malicious delta was narrow: a version bump plus a single top-level `elementary.pth` file containing a large base64-wrapped payload [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection). That small source delta belied a serious runtime impact because `.pth` execution happens automatically at interpreter startup.

### Payload Behavior
Snyk reports that the malware harvested dbt profiles, Snowflake, BigQuery, Redshift, AWS, GCP, Azure, API token, SSH key, `.env`, and active environment variable secrets [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PYTHON-ELEMENTARYDATA-16316110). StepSecurity lists the C2/exfiltration domain as `igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud`, the exfiltration header as `X-Rise-To-The-Trinny: agree`, and the staged archive as `trin.tar.gz` [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).

## Detection and Hunting
```yaml
hunt_queries:
  dependency_lockfiles:
    - "elementary-data==0.23.3"
  container_images:
    - "ghcr.io/elementary-data/elementary:0.23.3"
    - "ghcr.io/elementary-data/elementary:latest pulled before 0.23.4 cleanup"
    - "sha256:31ecc5939de6d24cf60c50d4ca26cf7a8c322db82a8ce4bd122ebd89cf634255"
  filesystem:
    - "elementary.pth"
    - "$TMPDIR/.trinny-security-update"
    - "%TEMP%\\.trinny-security-update"
    - "trin.tar.gz"
  network:
    - "igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud"
  http_headers:
    - "X-Rise-To-The-Trinny: agree"
```

## Remediation Workflow
* **Immediate:** Remove `elementary-data==0.23.3`; upgrade to `0.23.4` or return to `0.23.2` after verifying package hashes [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PYTHON-ELEMENTARYDATA-16316110) [PyPI](https://pypi.org/project/elementary-data/).
* **Immediate:** Rebuild any container image based on `ghcr.io/elementary-data/elementary:0.23.3` or `:latest` pulled during the affected window; avoid relying on mutable tags during incident response [StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection).
* **Immediate:** Rotate data warehouse, dbt, cloud provider, API, SSH, CI/CD, Docker, Kubernetes, and GitHub credentials exposed to affected environments [Snyk Vulnerability Database](https://security.snyk.io/vuln/SNYK-PYTHON-ELEMENTARYDATA-16316110).
* **Short-term:** Audit GitHub Actions workflows for script injection, untrusted PR/title/body interpolation, broad `GITHUB_TOKEN` permissions, and release workflows triggerable by forged refs.
* **Long-term:** Require digest-pinned production images, artifact provenance verification, release workflow approval gates, and least-privilege workflow tokens.

## Open Questions
- Which deployments pulled the compromised GHCR `latest` tag before cleanup?
- Were any exfiltrated dbt, warehouse, cloud, or SSH credentials used after collection?
- Which exact workflow input enabled the script injection, and do sibling repositories share it?

## Sources
1. [StepSecurity: elementary-data Compromised on PyPI and GHCR](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection) - **Role:** PRIMARY_RESEARCH - **Impact:** Timeline, attack path, `.pth` execution, GHCR digest, C2 indicators.
2. [Snyk Vulnerability Database: SNYK-PYTHON-ELEMENTARYDATA-16316110](https://security.snyk.io/vuln/SNYK-PYTHON-ELEMENTARYDATA-16316110) - **Role:** ENRICHMENT_DATA - **Impact:** Advisory ID, affected version, severity, credential classes.
3. [Snyk: Malicious Release of elementary-data PyPI Package](https://snyk.io/es/blog/malicious-release-of-elementary-data-pypi-package-steals-cloud-credentials-from-data-engineers/) - **Role:** PRIMARY_RESEARCH - **Impact:** Data engineering target profile and remediation context.
4. [PyPI project page: elementary-data](https://pypi.org/project/elementary-data/) - **Role:** DIRECT_SOURCE - **Impact:** Clean replacement release evidence.
5. [Elementary GitHub issue #2205](https://github.com/elementary-data/elementary/issues/2205) - **Role:** DIRECT_SOURCE - **Impact:** Maintainer incident notice referenced by StepSecurity and Snyk.

---
### Machine-Readable Event Profile (Format B)
```json
[
  {
    "event_id": "elementary-data-pypi-ghcr-compromise-2026-04-24",
    "event_name": "elementary-data PyPI and GHCR GitHub Actions Compromise",
    "parent_campaign_id": null,
    "is_campaign_level": false,
    "confidence": "high",
    "confidence_reason": "StepSecurity provides detailed direct artifact and workflow evidence, Snyk confirms advisory coverage, and PyPI shows the clean replacement release.",
    "attack_types": ["malicious package", "GitHub Actions compromise", "CI/CD compromise", "poisoned release", "compromised container image", "credential theft", "token exfiltration"],
    "direct_sources": [
      { "name": "PyPI project page: elementary-data", "url": "https://pypi.org/project/elementary-data/" },
      { "name": "Elementary GitHub issue #2205", "url": "https://github.com/elementary-data/elementary/issues/2205" }
    ],
    "correlated_sources": [
      { "name": "StepSecurity elementary-data analysis", "url": "https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection", "role": "PRIMARY_RESEARCH", "contribution": "workflow attack path, timeline, and IOCs" },
      { "name": "Snyk Vulnerability Database", "url": "https://security.snyk.io/vuln/SNYK-PYTHON-ELEMENTARYDATA-16316110", "role": "ENRICHMENT_DATA", "contribution": "advisory metadata and affected version" },
      { "name": "Snyk elementary-data writeup", "url": "https://snyk.io/es/blog/malicious-release-of-elementary-data-pypi-package-steals-cloud-credentials-from-data-engineers/", "role": "PRIMARY_RESEARCH", "contribution": "credential theft scope" }
    ],
    "affected_assets": {
      "ecosystems": ["pypi", "python", "container"],
      "packages": ["elementary-data"],
      "versions": ["0.23.3"],
      "repositories": ["elementary-data/elementary"],
      "vendors": ["Elementary"],
      "CI_CD_systems": ["GitHub Actions"],
      "container_images": ["ghcr.io/elementary-data/elementary:0.23.3", "ghcr.io/elementary-data/elementary:latest"],
      "developer_tools": ["dbt", "data engineering CLI environments"]
    },
    "timeline": {
      "first_seen": "2026-04-24T22:20:47Z",
      "malicious_publish_time": "2026-04-24T22:20:47Z",
      "discovery_time": "2026-04-25T00:00:00Z",
      "removal_time": "2026-04-25T00:00:00Z",
      "disclosure_time": "2026-04-25T00:00:00Z",
      "patch_or_fix_time": "2026-04-25T00:00:00Z"
    },
    "matching_signals": {
      "package_names": ["elementary-data"],
      "affected_versions": ["0.23.3"],
      "identifiers": { "cve": "N/A", "ghsa": "N/A", "osv": "N/A" },
      "shared_claims": "Forged release added elementary.pth and published to PyPI plus GHCR.",
      "shared_root_cause": "GitHub Actions script injection with release-capable token permissions.",
      "shared_affected_parties": "Data engineers and CI/CD environments installing elementary-data or pulling the GHCR image."
    },
    "iocs": {
      "domains": ["igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud"],
      "ips": [],
      "urls": [],
      "hashes": ["sha256:31ecc5939de6d24cf60c50d4ca26cf7a8c322db82a8ce4bd122ebd89cf634255", "sha256:b3bbfafde1a0db3a4d47e70eb0eb2ca19daef4a19410154a71abee567b35d3d9"],
      "scripts": ["elementary.pth", "trin.tar.gz"]
    },
    "defender_takeaways": {
      "detection": "Alert on elementary-data 0.23.3, elementary.pth, the trinny marker file, and unpinned GHCR pulls during the affected window.",
      "hunting": "Search data engineering hosts, dbt jobs, CI runners, and container clusters for affected Python packages and GHCR image digests.",
      "remediation": "Upgrade to 0.23.4, rebuild affected containers, rotate exposed credentials, and remove the malicious marker and archive artifacts.",
      "prevention": "Harden GitHub Actions against script injection, minimize GITHUB_TOKEN permissions, require release approvals, and pin container images by digest."
    }
  }
]
```
