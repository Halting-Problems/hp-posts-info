---
title: "actions-cool GitHub Actions Tag Hijack Credential Theft"
date: 2026-05-18
severity: "critical"
tags:
  - supply-chain
  - github-actions
  - ci-cd
  - credential-theft
summary: "StepSecurity reported that all tags for actions-cool/issues-helper, and the related actions-cool/maintain-one-comment action, were moved to imposter commits that downloaded Bun, scraped Runner.Worker memory, and exfiltrated secrets to t.m-kosche.com."
sourceCount: 1
---

## Executive Summary

StepSecurity reported that all tags for actions-cool/issues-helper, and the related actions-cool/maintain-one-comment action, were moved to imposter commits that downloaded Bun, scraped Runner.Worker memory, and exfiltrated secrets to t.m-kosche.com.

This folder ports older Astro-era supply-chain coverage into the canonical `hp-posts-info` authoring shape so the Next.js/Postgres importer can serve it. The current status is `needs_review`: the source-backed indicators are captured, but the pass intentionally does not claim fresh artifact diffing beyond the cited primary research.

## Key Facts

* **Affected assets:** actions-cool/issues-helper, actions-cool/maintain-one-comment.
* **Execution trigger:** workflow resolves a mutable GitHub Action tag moved to an imposter commit.
* **Credential risk:** GitHub, OIDC, cloud, package-registry, and developer credentials reachable from impacted CI or developer environments.
* **Relationship:** migrated from the older Astro blog supply-chain roundup into a standalone Next.js/Postgres-ready incident folder.

## Defender Handling

Run the included scope scanner over repository exports, package caches, CI logs, and endpoint telemetry. Treat matches in live dependency manifests, lockfiles, workflow definitions, or runner process/network logs as exposure signals until the owning team confirms whether the malicious artifact actually executed.

## Open Questions

This migration captures coverage and source-backed selectors. Before marking publish-ready, perform fresh artifact diffing, validate current package/action cleanup status, and reconcile exact downstream victim counts from direct maintainer or platform sources.

## Sources

1. [StepSecurity primary research](https://www.stepsecurity.io/blog/actions-cool-issues-helper-github-action-compromised-all-tags-point-to-imposter-commit-that-exfiltrates-ci-cd-credentials). **Role:** PRIMARY_RESEARCH **Impact:** Primary source for affected assets, execution trigger, payload behavior, and published IOCs.
