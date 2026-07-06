---
title: "Miasma npm Phantom Gyp Self-Spreading Worm"
date: 2026-06-03
severity: "critical"
tags:
  - supply-chain
  - npm
  - miasma
  - phantom-gyp
summary: "StepSecurity reported the Miasma worm as a 57-package, 286-plus-version npm compromise that abused binding.gyp/Phantom Gyp execution, downloaded Bun, stole CI and developer credentials, and used GitHub repositories as exfiltration and propagation infrastructure."
sourceCount: 1
---

## Executive Summary

StepSecurity reported the Miasma worm as a 57-package, 286-plus-version npm compromise that abused binding.gyp/Phantom Gyp execution, downloaded Bun, stole CI and developer credentials, and used GitHub repositories as exfiltration and propagation infrastructure.

This folder ports older Astro-era supply-chain coverage into the canonical `hp-posts-info` authoring shape so the Next.js/Postgres importer can serve it. The current status is `needs_review`: the source-backed indicators are captured, but the pass intentionally does not claim fresh artifact diffing beyond the cited primary research.

## Key Facts

* **Affected assets:** @evolvconsulting/evolv-coder-lite, @jagreehal/workflow, @vapi-ai/server-sdk, ai-sdk-ollama, autotel, autotel-adapters, autotel-audit, autotel-aws, autotel-backends, autotel-cli, autotel-cloudflare, autotel-devtools ....
* **Execution trigger:** node-gyp processes binding.gyp shell expansion during npm install.
* **Credential risk:** GitHub, OIDC, cloud, package-registry, and developer credentials reachable from impacted CI or developer environments.
* **Relationship:** migrated from the older Astro blog supply-chain roundup into a standalone Next.js/Postgres-ready incident folder.

## Defender Handling

Run the included scope scanner over repository exports, package caches, CI logs, and endpoint telemetry. Treat matches in live dependency manifests, lockfiles, workflow definitions, or runner process/network logs as exposure signals until the owning team confirms whether the malicious artifact actually executed.

## Open Questions

This migration captures coverage and source-backed selectors. Before marking publish-ready, perform fresh artifact diffing, validate current package/action cleanup status, and reconcile exact downstream victim counts from direct maintainer or platform sources.

## Sources

1. [StepSecurity primary research](https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm). **Role:** PRIMARY_RESEARCH **Impact:** Primary source for affected assets, execution trigger, payload behavior, and published IOCs.
