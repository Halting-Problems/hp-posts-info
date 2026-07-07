---
title: "Laravel-Lang Composer Tag Rewrite RCE Compromise"
date: 2026-05-24
severity: "critical"
tags:
  - supply-chain
  - packagist
  - composer
  - laravel
  - credential-theft
summary: "Four Laravel-Lang repositories were compromised through rewritten Composer tags that loaded a PHP backdoor through Composer autoload. Maintainers restored the tags on May 23, but installs from the exposure window require credential rotation and commit-level verification."
sourceCount: 5
---

## Executive Summary
Laravel-Lang packages were compromised through rewritten Git tags, causing Composer installs that trusted historical version tags to resolve to malicious commits. StepSecurity confirmed four affected repositories and specific tag rewrite windows beginning on 2026-05-22, while Socket reported broader Laravel-Lang impact across roughly 700+ historical package versions [StepSecurity](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack) [Socket](https://socket.dev/blog/laravel-lang-compromise).

The malicious commits added `src/helpers.php` and registered it through Composer `autoload.files`, so execution occurred when a PHP application loaded `vendor/autoload.php`. Hosts or CI runners that installed affected tags during the exposure window should be treated as potentially compromised because the payload fetched second-stage code, dropped temporary loaders under `/tmp`, and targeted local secrets and CI/cloud credentials [StepSecurity](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack) [Socket](https://socket.dev/blog/laravel-lang-compromise).

Maintainers closed the four public incident issues as fixed on **2026-05-23**, and Packagist currently exposes post-incident releases for the affected packages. That restoration does not retroactively make cached malicious artifacts or lockfiles safe; defenders must compare locked source SHAs and rebuild dependency caches [GitHub incident issue](https://github.com/Laravel-Lang/http-statuses/issues/277) [Packagist metadata](https://repo.packagist.org/p2/laravel-lang/http-statuses.json).

## Key Facts
**Threat Type**: Composer package tag rewrite and RCE backdoor

**Ecosystem**: Composer

**Registry**: Packagist

**Affected Packages**:
- laravel-lang/lang
- laravel-lang/http-statuses
- laravel-lang/actions
- laravel-lang/attributes

**Malicious Versions**:
- laravel-lang/lang@15.30.0
- laravel-lang/lang@15.28.5
- laravel-lang/lang@15.28.4
- laravel-lang/lang@15.28.3
- laravel-lang/lang@15.28.2
- laravel-lang/lang@15.28.1
- laravel-lang/lang@15.28.0
- laravel-lang/lang@15.27.0
- laravel-lang/lang@15.26.5
- laravel-lang/lang@15.26.4
- laravel-lang/lang@15.26.3
- laravel-lang/lang@15.26.2
- laravel-lang/lang@15.26.1
- laravel-lang/lang@15.26.0
- laravel-lang/lang@15.25.0
- laravel-lang/lang@15.24.5
- laravel-lang/lang@15.24.4
- laravel-lang/lang@15.24.3
- laravel-lang/lang@15.24.2
- laravel-lang/lang@15.24.1
- laravel-lang/lang@15.24.0
- laravel-lang/lang@15.23.3
- laravel-lang/lang@15.23.2
- laravel-lang/lang@15.23.1
- laravel-lang/lang@15.23.0
- laravel-lang/lang@15.22.8
- laravel-lang/lang@15.22.7
- laravel-lang/lang@15.22.6
- laravel-lang/lang@15.22.5
- laravel-lang/lang@15.22.4
- laravel-lang/lang@15.22.3
- laravel-lang/lang@15.22.2
- laravel-lang/lang@15.22.1
- laravel-lang/lang@15.22.0
- laravel-lang/lang@15.21.1
- laravel-lang/lang@15.21.0
- laravel-lang/lang@15.20.2
- laravel-lang/lang@15.20.1
- laravel-lang/lang@15.20.0
- laravel-lang/lang@15.19.9
- laravel-lang/lang@15.19.8
- laravel-lang/lang@15.19.7
- laravel-lang/lang@15.19.6
- laravel-lang/lang@15.19.5
- laravel-lang/lang@15.19.4
- laravel-lang/lang@15.19.3
- laravel-lang/lang@15.19.2
- laravel-lang/lang@15.19.1
- laravel-lang/lang@15.19.0
- laravel-lang/lang@15.18.0
- laravel-lang/lang@15.17.1
- laravel-lang/lang@15.17.0
- laravel-lang/lang@15.16.0
- laravel-lang/lang@15.15.0
- laravel-lang/lang@15.14.0
- laravel-lang/lang@15.13.0
- laravel-lang/lang@15.12.1
- laravel-lang/lang@15.12.0
- laravel-lang/lang@15.11.7
- laravel-lang/lang@15.11.6
- laravel-lang/lang@15.11.5
- laravel-lang/lang@15.11.4
- laravel-lang/lang@15.11.3
- laravel-lang/lang@15.11.2
- laravel-lang/lang@15.11.1
- laravel-lang/lang@15.11.0
- laravel-lang/lang@15.10.0
- laravel-lang/lang@15.9.7
- laravel-lang/lang@15.9.6
- laravel-lang/lang@15.9.5
- laravel-lang/lang@15.9.4
- laravel-lang/lang@15.9.3
- laravel-lang/lang@15.9.2
- laravel-lang/lang@15.9.1
- laravel-lang/lang@15.9.0
- laravel-lang/lang@15.8.1
- laravel-lang/lang@15.8.0
- laravel-lang/lang@15.7.5
- laravel-lang/lang@15.7.4
- laravel-lang/lang@15.7.3
- laravel-lang/lang@15.7.2
- laravel-lang/lang@15.7.1
- laravel-lang/lang@15.7.0
- laravel-lang/lang@15.6.2
- laravel-lang/lang@15.6.1
- laravel-lang/lang@15.6.0
- laravel-lang/lang@15.5.6
- laravel-lang/lang@15.5.5
- laravel-lang/lang@15.5.4
- laravel-lang/lang@15.5.3
- laravel-lang/lang@15.5.2
- laravel-lang/lang@15.5.1
- laravel-lang/lang@15.5.0
- laravel-lang/lang@15.4.1
- laravel-lang/lang@15.4.0
- laravel-lang/lang@15.3.1
- laravel-lang/lang@15.3.0
- laravel-lang/lang@15.2.2
- laravel-lang/lang@15.2.1
- laravel-lang/lang@15.2.0
- laravel-lang/lang@15.1.5
- laravel-lang/lang@15.1.4
- laravel-lang/lang@15.1.3
- laravel-lang/lang@15.1.2
- laravel-lang/lang@15.1.1
- laravel-lang/lang@15.1.0
- laravel-lang/lang@15.0.0
- laravel-lang/lang@14.8.1
- laravel-lang/lang@14.8.0
- laravel-lang/lang@14.7.0
- laravel-lang/lang@14.6.0
- laravel-lang/lang@14.5.2
- laravel-lang/lang@14.5.1
- laravel-lang/lang@14.5.0
- laravel-lang/lang@14.4.0
- laravel-lang/lang@14.3.7
- laravel-lang/lang@14.3.6
- laravel-lang/lang@14.3.5
- laravel-lang/lang@14.3.4
- laravel-lang/lang@14.3.3
- laravel-lang/lang@14.3.2
- laravel-lang/lang@14.3.1
- laravel-lang/lang@14.3.0
- laravel-lang/lang@14.2.9
- laravel-lang/lang@14.2.8
- laravel-lang/lang@14.2.7
- laravel-lang/lang@14.2.6
- laravel-lang/lang@14.2.5
- laravel-lang/lang@14.2.4
- laravel-lang/lang@14.2.3
- laravel-lang/lang@14.2.2
- laravel-lang/lang@14.2.1
- laravel-lang/lang@14.2.0
- laravel-lang/lang@14.1.5
- laravel-lang/lang@14.1.4
- laravel-lang/lang@14.1.3
- laravel-lang/lang@14.1.2
- laravel-lang/lang@14.1.1
- laravel-lang/lang@14.1.0
- laravel-lang/lang@14.0.1
- laravel-lang/lang@14.0.0
- laravel-lang/lang@13.12.1
- laravel-lang/lang@13.12.0
- laravel-lang/lang@13.11.0
- laravel-lang/lang@13.10.0
- laravel-lang/lang@13.9.1
- laravel-lang/lang@13.9.0
- laravel-lang/lang@13.8.0
- laravel-lang/lang@13.7.0
- laravel-lang/lang@13.6.1
- laravel-lang/lang@13.6.0
- laravel-lang/lang@13.5.1
- laravel-lang/lang@13.5.0
- laravel-lang/lang@13.4.0
- laravel-lang/lang@13.3.0
- laravel-lang/lang@13.2.8
- laravel-lang/lang@13.2.7
- laravel-lang/lang@13.2.6
- laravel-lang/lang@13.2.5
- laravel-lang/lang@13.2.4
- laravel-lang/lang@13.2.3
- laravel-lang/lang@13.2.2
- laravel-lang/lang@13.2.1
- laravel-lang/lang@13.2.0
- laravel-lang/lang@13.1.4
- laravel-lang/lang@13.1.3
- laravel-lang/lang@13.1.2
- laravel-lang/lang@13.1.1
- laravel-lang/lang@13.1.0
- laravel-lang/lang@13.0.1
- laravel-lang/lang@13.0.0
- laravel-lang/lang@12.24.3
- laravel-lang/lang@12.24.2
- laravel-lang/lang@12.24.1
- laravel-lang/lang@12.24.0
- laravel-lang/lang@12.23.2
- laravel-lang/lang@12.23.1
- laravel-lang/lang@12.23.0
- laravel-lang/lang@12.22.1
- laravel-lang/lang@12.22.0
- laravel-lang/lang@12.21.10
- laravel-lang/lang@12.21.9
- laravel-lang/lang@12.21.8
- laravel-lang/lang@12.21.7
- laravel-lang/lang@12.21.6
- laravel-lang/lang@12.21.5
- laravel-lang/lang@12.21.4
- laravel-lang/lang@12.21.3
- laravel-lang/lang@12.21.2
- laravel-lang/lang@12.21.1
- laravel-lang/lang@12.21.0
- laravel-lang/lang@12.20.5
- laravel-lang/lang@12.20.4
- laravel-lang/lang@12.20.3
- laravel-lang/lang@12.20.2
- laravel-lang/lang@12.20.1
- laravel-lang/lang@12.20.0
- laravel-lang/lang@12.19.4
- laravel-lang/lang@12.19.3
- laravel-lang/lang@12.19.2
- laravel-lang/lang@12.19.1
- laravel-lang/lang@12.19.0
- laravel-lang/lang@12.18.6
- laravel-lang/lang@12.18.5
- laravel-lang/lang@12.18.4
- laravel-lang/lang@12.18.3
- laravel-lang/lang@12.18.2
- laravel-lang/lang@12.18.1
- laravel-lang/lang@12.18.0
- laravel-lang/lang@12.17.1
- laravel-lang/lang@12.17.0
- laravel-lang/lang@12.16.1
- laravel-lang/lang@12.16.0
- laravel-lang/lang@12.15.2
- laravel-lang/lang@12.15.1
- laravel-lang/lang@12.15.0
- laravel-lang/lang@12.14.2
- laravel-lang/lang@12.14.1
- laravel-lang/lang@12.14.0
- laravel-lang/lang@12.13.1
- laravel-lang/lang@12.13.0
- laravel-lang/lang@12.12.0
- laravel-lang/lang@12.11.5
- laravel-lang/lang@12.11.4
- laravel-lang/lang@12.11.3
- laravel-lang/lang@12.11.2
- laravel-lang/lang@12.11.1
- laravel-lang/lang@12.11.0
- laravel-lang/lang@12.10.0
- laravel-lang/lang@12.9.9
- laravel-lang/lang@12.9.8
- laravel-lang/lang@12.9.7
- laravel-lang/lang@12.9.6
- laravel-lang/lang@12.9.5
- laravel-lang/lang@12.9.4
- laravel-lang/lang@12.9.3
- laravel-lang/lang@12.9.2
- laravel-lang/lang@12.9.1
- laravel-lang/lang@12.9.0
- laravel-lang/lang@12.8.4
- laravel-lang/lang@12.8.2
- laravel-lang/lang@12.8.1
- laravel-lang/lang@12.8.0
- laravel-lang/lang@12.7.3
- laravel-lang/lang@12.7.2
- laravel-lang/lang@12.7.1
- laravel-lang/lang@12.7.0
- laravel-lang/lang@12.6.1
- laravel-lang/lang@12.6.0
- laravel-lang/lang@12.5.8
- laravel-lang/lang@12.5.7
- laravel-lang/lang@12.5.6
- laravel-lang/lang@12.5.5
- laravel-lang/lang@12.5.4
- laravel-lang/lang@12.5.3
- laravel-lang/lang@12.5.2
- laravel-lang/lang@12.5.1
- laravel-lang/lang@12.5.0
- laravel-lang/lang@12.4.0
- laravel-lang/lang@12.3.2
- laravel-lang/lang@12.3.1
- laravel-lang/lang@12.3.0
- laravel-lang/lang@12.2.3
- laravel-lang/lang@12.2.2
- laravel-lang/lang@12.2.1
- laravel-lang/lang@12.2.0
- laravel-lang/lang@12.1.5
- laravel-lang/lang@12.1.4
- laravel-lang/lang@12.1.3
- laravel-lang/lang@12.1.2
- laravel-lang/lang@12.1.1
- laravel-lang/lang@12.1.0
- laravel-lang/lang@12.0.10
- laravel-lang/lang@12.0.9
- laravel-lang/lang@12.0.8
- laravel-lang/lang@12.0.7
- laravel-lang/lang@12.0.6
- laravel-lang/lang@12.0.5
- laravel-lang/lang@12.0.4
- laravel-lang/lang@12.0.3
- laravel-lang/lang@12.0.2
- laravel-lang/lang@12.0.1
- laravel-lang/lang@12.0.0
- laravel-lang/lang@11.0.20
- laravel-lang/lang@11.0.19
- laravel-lang/lang@11.0.18
- laravel-lang/lang@11.0.17
- laravel-lang/lang@11.0.16
- laravel-lang/lang@11.0.15
- laravel-lang/lang@11.0.14
- laravel-lang/lang@11.0.13
- laravel-lang/lang@11.0.12
- laravel-lang/lang@11.0.11
- laravel-lang/lang@11.0.10
- laravel-lang/lang@11.0.9
- laravel-lang/lang@11.0.8
- laravel-lang/lang@11.0.7
- laravel-lang/lang@11.0.6
- laravel-lang/lang@11.0.5
- laravel-lang/lang@11.0.4
- laravel-lang/lang@11.0.3
- laravel-lang/lang@11.0.2
- laravel-lang/lang@11.0.1
- laravel-lang/lang@11.0.0
- laravel-lang/lang@10.9.6
- laravel-lang/lang@10.9.5
- laravel-lang/lang@10.9.4
- laravel-lang/lang@10.9.3
- laravel-lang/lang@10.9.2
- laravel-lang/lang@10.9.1
- laravel-lang/lang@10.9.0
- laravel-lang/lang@10.8.0
- laravel-lang/lang@10.7.2
- laravel-lang/lang@10.7.1
- laravel-lang/lang@10.7.0
- laravel-lang/lang@10.6.0
- laravel-lang/lang@10.5.2
- laravel-lang/lang@10.5.1
- laravel-lang/lang@10.5.0
- laravel-lang/lang@10.4.14
- laravel-lang/lang@10.4.13
- laravel-lang/lang@10.4.12
- laravel-lang/lang@10.4.11
- laravel-lang/lang@10.4.10
- laravel-lang/lang@10.4.9
- laravel-lang/lang@10.4.8
- laravel-lang/lang@10.4.7
- laravel-lang/lang@10.4.6
- laravel-lang/lang@10.4.5
- laravel-lang/lang@10.4.4
- laravel-lang/lang@10.4.3
- laravel-lang/lang@10.4.2
- laravel-lang/lang@10.4.1
- laravel-lang/lang@10.4.0
- laravel-lang/lang@10.3.0
- laravel-lang/lang@10.2.0
- laravel-lang/lang@10.1.12
- laravel-lang/lang@10.1.11
- laravel-lang/lang@10.1.10
- laravel-lang/lang@10.1.9
- laravel-lang/lang@10.1.8
- laravel-lang/lang@10.1.7
- laravel-lang/lang@10.1.6
- laravel-lang/lang@10.1.5
- laravel-lang/lang@10.1.4
- laravel-lang/lang@10.1.3
- laravel-lang/lang@10.1.2
- laravel-lang/lang@10.1.1
- laravel-lang/lang@10.1.0
- laravel-lang/lang@10.0.2
- laravel-lang/lang@10.0.1
- laravel-lang/lang@10.0.0
- laravel-lang/lang@9.1.3
- laravel-lang/lang@9.1.2
- laravel-lang/lang@9.1.1
- laravel-lang/lang@9.1.0
- laravel-lang/lang@9.0.1
- laravel-lang/lang@9.0.0
- laravel-lang/lang@8.1.3
- laravel-lang/lang@8.1.2
- laravel-lang/lang@8.1.1
- laravel-lang/lang@8.1.0
- laravel-lang/lang@8.0.3
- laravel-lang/lang@8.0.2
- laravel-lang/lang@8.0.1
- laravel-lang/lang@8.0.0
- laravel-lang/lang@7.0.9
- laravel-lang/lang@7.0.8
- laravel-lang/lang@7.0.7
- laravel-lang/lang@7.0.6
- laravel-lang/lang@7.0.5
- laravel-lang/lang@7.0.4
- laravel-lang/lang@7.0.3
- laravel-lang/lang@7.0.2
- laravel-lang/lang@7.0.1
- laravel-lang/lang@7.0.0
- laravel-lang/lang@6.1.4
- laravel-lang/lang@6.1.3
- laravel-lang/lang@6.1.2
- laravel-lang/lang@6.1.1
- laravel-lang/lang@6.1.0
- laravel-lang/lang@6.0.3
- laravel-lang/lang@6.0.2
- laravel-lang/lang@6.0.1
- laravel-lang/lang@6.0.0
- laravel-lang/lang@5.0.0
- laravel-lang/lang@4.0.11
- laravel-lang/lang@4.0.10
- laravel-lang/lang@4.0.9
- laravel-lang/lang@4.0.8
- laravel-lang/lang@4.0.7
- laravel-lang/lang@4.0.6
- laravel-lang/lang@4.0.5
- laravel-lang/lang@4.0.4
- laravel-lang/lang@4.0.3
- laravel-lang/lang@4.0.2
- laravel-lang/lang@4.0.1
- laravel-lang/lang@4.0.0
- laravel-lang/lang@3.0.62
- laravel-lang/lang@3.0.61
- laravel-lang/lang@3.0.60
- laravel-lang/lang@3.0.59
- laravel-lang/lang@3.0.58
- laravel-lang/lang@3.0.57
- laravel-lang/lang@3.0.56
- laravel-lang/lang@3.0.54
- laravel-lang/lang@3.0.53
- laravel-lang/lang@3.0.52
- laravel-lang/lang@3.0.51
- laravel-lang/lang@3.0.50
- laravel-lang/lang@3.0.49
- laravel-lang/lang@3.0.48
- laravel-lang/lang@3.0.47
- laravel-lang/lang@3.0.46
- laravel-lang/lang@3.0.45
- laravel-lang/lang@3.0.44
- laravel-lang/lang@3.0.43
- laravel-lang/lang@3.0.42
- laravel-lang/lang@3.0.41
- laravel-lang/lang@3.0.40
- laravel-lang/lang@3.0.39
- laravel-lang/lang@3.0.38
- laravel-lang/lang@3.0.37
- laravel-lang/lang@3.0.36
- laravel-lang/lang@3.0.35
- laravel-lang/lang@3.0.34
- laravel-lang/lang@3.0.33
- laravel-lang/lang@3.0.32
- laravel-lang/lang@3.0.31
- laravel-lang/lang@3.0.30
- laravel-lang/lang@3.0.29
- laravel-lang/lang@3.0.28
- laravel-lang/lang@3.0.27
- laravel-lang/lang@3.0.26
- laravel-lang/lang@3.0.25
- laravel-lang/lang@3.0.24
- laravel-lang/lang@3.0.23
- laravel-lang/lang@3.0.22
- laravel-lang/lang@3.0.21
- laravel-lang/lang@3.0.20
- laravel-lang/lang@3.0.19
- laravel-lang/lang@3.0.18
- laravel-lang/lang@3.0.17
- laravel-lang/lang@3.0.16
- laravel-lang/lang@3.0.15
- laravel-lang/lang@3.0.14
- laravel-lang/lang@3.0.13
- laravel-lang/lang@3.0.12
- laravel-lang/lang@3.0.11
- laravel-lang/lang@3.0.10
- laravel-lang/lang@3.0.9
- laravel-lang/lang@3.0.8
- laravel-lang/lang@3.0.7
- laravel-lang/lang@3.0.6
- laravel-lang/lang@3.0.5
- laravel-lang/lang@3.0.4
- laravel-lang/lang@3.0.3
- laravel-lang/lang@3.0.2
- laravel-lang/lang@3.0.1
- laravel-lang/lang@3.0.0
- laravel-lang/lang@2.0.43
- laravel-lang/lang@2.0.42
- laravel-lang/lang@2.0.41
- laravel-lang/lang@2.0.40
- laravel-lang/lang@2.0.39
- laravel-lang/lang@2.0.38
- laravel-lang/lang@2.0.37
- laravel-lang/lang@2.0.36
- laravel-lang/lang@2.0.35
- laravel-lang/lang@2.0.34
- laravel-lang/lang@2.0.33
- laravel-lang/lang@2.0.32
- laravel-lang/lang@2.0.31
- laravel-lang/lang@2.0.30
- laravel-lang/lang@2.0.29
- laravel-lang/lang@2.0.28
- laravel-lang/lang@2.0.27
- laravel-lang/lang@2.0.26
- laravel-lang/lang@2.0.25
- laravel-lang/lang@2.0.24
- laravel-lang/lang@2.0.23
- laravel-lang/lang@2.0.22
- laravel-lang/lang@2.0.21
- laravel-lang/lang@2.0.20
- laravel-lang/lang@2.0.19
- laravel-lang/lang@2.0.18
- laravel-lang/lang@2.0.17
- laravel-lang/lang@2.0.16
- laravel-lang/lang@2.0.15
- laravel-lang/lang@2.0.14
- laravel-lang/lang@2.0.13
- laravel-lang/lang@2.0.12
- laravel-lang/lang@2.0.11
- laravel-lang/lang@2.0.10
- laravel-lang/lang@2.0.9
- laravel-lang/lang@2.0.8
- laravel-lang/lang@2.0.7
- laravel-lang/lang@2.0.6
- laravel-lang/lang@2.0.5
- laravel-lang/lang@2.0.4
- laravel-lang/lang@2.0.3
- laravel-lang/lang@2.0.2
- laravel-lang/lang@2.0.1
- laravel-lang/lang@1.0.2
- laravel-lang/http-statuses@v3.4.5
- laravel-lang/http-statuses@v3.4.4
- laravel-lang/http-statuses@v3.4.3
- laravel-lang/http-statuses@v3.4.2
- laravel-lang/http-statuses@v3.4.1
- laravel-lang/http-statuses@v3.4.0
- laravel-lang/http-statuses@v3.3.1
- laravel-lang/http-statuses@v3.3.0
- laravel-lang/http-statuses@v3.2.2
- laravel-lang/http-statuses@v3.2.1
- laravel-lang/http-statuses@v3.2.0
- laravel-lang/http-statuses@v3.1.5
- laravel-lang/http-statuses@v3.1.4
- laravel-lang/http-statuses@v3.1.3
- laravel-lang/http-statuses@v3.1.2
- laravel-lang/http-statuses@v3.1.1
- laravel-lang/http-statuses@v3.1.0
- laravel-lang/http-statuses@v3.0.8
- laravel-lang/http-statuses@v3.0.7
- laravel-lang/http-statuses@v3.0.6
- laravel-lang/http-statuses@v3.0.5
- laravel-lang/http-statuses@v3.0.4
- laravel-lang/http-statuses@v3.0.3
- laravel-lang/http-statuses@v3.0.2
- laravel-lang/http-statuses@v3.0.1
- laravel-lang/http-statuses@v3.0.0
- laravel-lang/http-statuses@v2.1.3
- laravel-lang/http-statuses@v2.1.2
- laravel-lang/http-statuses@v2.1.1
- laravel-lang/http-statuses@v2.1.0
- laravel-lang/http-statuses@v2.0.1
- laravel-lang/http-statuses@v2.0.0
- laravel-lang/http-statuses@v1.0.10
- laravel-lang/http-statuses@v1.0.9
- laravel-lang/http-statuses@v1.0.8
- laravel-lang/http-statuses@v1.0.7
- laravel-lang/http-statuses@v1.0.6
- laravel-lang/http-statuses@v1.0.5
- laravel-lang/http-statuses@v1.0.4
- laravel-lang/http-statuses@v1.0.3
- laravel-lang/http-statuses@v1.0.2
- laravel-lang/http-statuses@v1.0.1
- laravel-lang/http-statuses@v1.0.0
- laravel-lang/http-statuses@3.13.1
- laravel-lang/http-statuses@3.13.0
- laravel-lang/http-statuses@3.12.1
- laravel-lang/http-statuses@3.12.0
- laravel-lang/http-statuses@3.11.1
- laravel-lang/http-statuses@3.11.0
- laravel-lang/http-statuses@3.10.5
- laravel-lang/http-statuses@3.10.4
- laravel-lang/http-statuses@3.10.3
- laravel-lang/http-statuses@3.10.2
- laravel-lang/http-statuses@3.10.1
- laravel-lang/http-statuses@3.10.0
- laravel-lang/http-statuses@3.9.0
- laravel-lang/http-statuses@3.8.5
- laravel-lang/http-statuses@3.8.4
- laravel-lang/http-statuses@3.8.3
- laravel-lang/http-statuses@3.8.2
- laravel-lang/http-statuses@3.8.1
- laravel-lang/http-statuses@3.8.0
- laravel-lang/http-statuses@3.7.0
- laravel-lang/http-statuses@3.6.3
- laravel-lang/http-statuses@3.6.2
- laravel-lang/http-statuses@3.6.1
- laravel-lang/http-statuses@3.6.0
- laravel-lang/http-statuses@3.5.0
- laravel-lang/http-statuses@2.1.4
- laravel-lang/http-statuses@1.0.11
- laravel-lang/actions@1.13.1
- laravel-lang/actions@1.13.0
- laravel-lang/actions@1.12.4
- laravel-lang/actions@1.11.1
- laravel-lang/actions@1.11.0
- laravel-lang/actions@1.10.2
- laravel-lang/actions@1.10.1
- laravel-lang/actions@1.10.0
- laravel-lang/actions@1.9.0
- laravel-lang/actions@1.8.10
- laravel-lang/actions@1.8.9
- laravel-lang/actions@1.8.8
- laravel-lang/actions@1.8.7
- laravel-lang/actions@1.8.6
- laravel-lang/actions@1.8.5
- laravel-lang/actions@1.8.4
- laravel-lang/actions@1.8.3
- laravel-lang/actions@1.8.2
- laravel-lang/actions@1.8.1
- laravel-lang/actions@1.8.0
- laravel-lang/actions@1.7.0
- laravel-lang/actions@1.6.1
- laravel-lang/actions@1.6.0
- laravel-lang/actions@1.5.6
- laravel-lang/actions@1.5.5
- laravel-lang/actions@1.5.4
- laravel-lang/actions@1.5.3
- laravel-lang/actions@1.5.2
- laravel-lang/actions@1.5.1
- laravel-lang/actions@1.5.0
- laravel-lang/actions@1.4.5
- laravel-lang/actions@1.4.4
- laravel-lang/actions@1.4.3
- laravel-lang/actions@1.4.2
- laravel-lang/actions@1.4.1
- laravel-lang/actions@1.4.0
- laravel-lang/actions@1.3.1
- laravel-lang/actions@1.3.0
- laravel-lang/actions@1.2.1
- laravel-lang/actions@1.2.0
- laravel-lang/actions@1.1.3
- laravel-lang/actions@1.1.2
- laravel-lang/actions@1.1.1
- laravel-lang/actions@1.1.0
- laravel-lang/actions@1.0.1
- laravel-lang/actions@1.0.0
- laravel-lang/attributes@v2.4.1
- laravel-lang/attributes@v2.4.0
- laravel-lang/attributes@v2.3.4
- laravel-lang/attributes@v2.3.3
- laravel-lang/attributes@v2.3.2
- laravel-lang/attributes@v2.3.1
- laravel-lang/attributes@v2.3.0
- laravel-lang/attributes@v2.2.0
- laravel-lang/attributes@v2.1.2
- laravel-lang/attributes@v2.1.1
- laravel-lang/attributes@v2.1.0
- laravel-lang/attributes@v2.0.9
- laravel-lang/attributes@v2.0.8
- laravel-lang/attributes@v2.0.7
- laravel-lang/attributes@v2.0.6
- laravel-lang/attributes@v2.0.5
- laravel-lang/attributes@v2.0.4
- laravel-lang/attributes@v2.0.3
- laravel-lang/attributes@v2.0.2
- laravel-lang/attributes@v2.0.1
- laravel-lang/attributes@v2.0.0
- laravel-lang/attributes@v1.1.3
- laravel-lang/attributes@v1.1.2
- laravel-lang/attributes@v1.1.1
- laravel-lang/attributes@v1.1.0
- laravel-lang/attributes@v1.0.11
- laravel-lang/attributes@v1.0.10
- laravel-lang/attributes@v1.0.9
- laravel-lang/attributes@v1.0.8
- laravel-lang/attributes@v1.0.7
- laravel-lang/attributes@v1.0.6
- laravel-lang/attributes@v1.0.5
- laravel-lang/attributes@v1.0.4
- laravel-lang/attributes@v1.0.3
- laravel-lang/attributes@v1.0.2
- laravel-lang/attributes@v1.0.1
- laravel-lang/attributes@v1.0.0
- laravel-lang/attributes@2.16.1
- laravel-lang/attributes@2.16.0
- laravel-lang/attributes@2.15.8
- laravel-lang/attributes@2.14.2
- laravel-lang/attributes@2.14.1
- laravel-lang/attributes@2.14.0
- laravel-lang/attributes@2.13.6
- laravel-lang/attributes@2.13.5
- laravel-lang/attributes@2.13.4
- laravel-lang/attributes@2.13.3
- laravel-lang/attributes@2.13.2
- laravel-lang/attributes@2.13.1
- laravel-lang/attributes@2.13.0
- laravel-lang/attributes@2.12.1
- laravel-lang/attributes@2.12.0
- laravel-lang/attributes@2.11.4
- laravel-lang/attributes@2.11.3
- laravel-lang/attributes@2.11.2
- laravel-lang/attributes@2.11.1
- laravel-lang/attributes@2.11.0
- laravel-lang/attributes@2.10.10
- laravel-lang/attributes@2.10.9
- laravel-lang/attributes@2.10.8
- laravel-lang/attributes@2.10.7
- laravel-lang/attributes@2.10.6
- laravel-lang/attributes@2.10.5
- laravel-lang/attributes@2.10.4
- laravel-lang/attributes@2.10.3
- laravel-lang/attributes@2.10.2
- laravel-lang/attributes@2.10.1
- laravel-lang/attributes@2.10.0
- laravel-lang/attributes@2.9.5
- laravel-lang/attributes@2.9.4
- laravel-lang/attributes@2.9.3
- laravel-lang/attributes@2.9.2
- laravel-lang/attributes@2.9.1
- laravel-lang/attributes@2.9.0
- laravel-lang/attributes@2.8.1
- laravel-lang/attributes@2.8.0
- laravel-lang/attributes@2.7.0
- laravel-lang/attributes@2.6.2
- laravel-lang/attributes@2.6.1
- laravel-lang/attributes@2.6.0
- laravel-lang/attributes@2.5.1
- laravel-lang/attributes@2.5.0
- laravel-lang/attributes@1.1.5
- laravel-lang/attributes@1.1.4

**Known Good Versions**:
- laravel-lang/lang@15.31.0 or later post-incident releases
- laravel-lang/http-statuses@3.13.1
- laravel-lang/attributes@2.16.2 or later post-incident releases

**Fixed Or Safe Versions**:
- versions whose source reference matches restored Packagist/GitHub metadata

**Execution Trigger**: Composer autoload.files loading src/helpers.php

**Primary Impact**: remote code execution, CI/CD credential theft, developer and application secret theft

**Campaign Context**: One of several May 2026 supply-chain incidents targeting mutable source-control trust anchors.

**Confidence**: high

**Canonical Source**: https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack

**Last Verified**: 2026-06-10

## Evidence Assessment
- **confirmed:** StepSecurity reports tag rewrites across four Laravel-Lang repositories, including `laravel-lang/lang`, `laravel-lang/http-statuses`, `laravel-lang/actions`, and `laravel-lang/attributes` [StepSecurity](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack).
- **confirmed:** The malicious Composer path uses `autoload.files` to load `src/helpers.php`, which executes when `vendor/autoload.php` is required [StepSecurity](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack).
- **confirmed:** Socket reports a broader Laravel-Lang compromise affecting roughly 700+ historical versions and describes credential collection across cloud, CI/CD, Kubernetes, Vault, browser, SSH, and application configuration sources [Socket](https://socket.dev/blog/laravel-lang-compromise).
- **confirmed:** Maintainers closed the incident issues as fixed on 2026-05-23, and Packagist serves restored or post-incident source references for all four packages [GitHub incident issue](https://github.com/Laravel-Lang/http-statuses/issues/277) [Packagist metadata](https://repo.packagist.org/p2/laravel-lang/http-statuses.json).
- **unclear:** A complete public mapping from every poisoned historical tag to its restored commit is not available in a single signed advisory; verify the exact `composer.lock` source SHA rather than trusting only a version string.

## Impact Determination

| Classification | Criteria | Required evidence | Required action | Closure condition |
| --- | --- | --- | --- | --- |
| Confirmed compromise | A host or runner installed an affected Laravel-Lang tag and loaded `vendor/autoload.php` with the malicious helper or reached `flipboxstudio[.]info`. | `composer.lock`, vendor tree, process telemetry, DNS/proxy events, and CI logs. | Isolate the host or runner, preserve the vendor tree, and rotate local, CI/CD, cloud, Kubernetes, Vault, SSH, and application secrets. | Clean dependencies are deployed and downstream audit modules show no suspicious credential use. |
| Presumed exposed | Affected tags were installed after the rewrite window and Composer autoload likely ran, but network telemetry is absent. | Dependency install time, lockfile source SHAs, application boot logs, and CI job timeline. | Rotate secrets reachable from the application, developer host, or CI runner from a clean environment. | Affected dependency paths are rebuilt and credential owners confirm revocation of old material. |
| Potentially exposed | Laravel-Lang packages appear in manifests, but install timing, tag SHA, or autoload execution is not established. | Manifest, lockfile, package cache, CI install records, and application deployment history. | Collect source SHA and execution evidence before narrowing host and credential scope. | Each install is mapped to a clean or malicious commit and execution state. |
| Not exposed | No affected packages or rewritten SHAs exist in lockfiles, package caches, vendor trees, or CI jobs. | Composer lockfile search, vendor tree search, and CI dependency install export. | Record the clean result and maintain tag drift monitoring. | Search evidence covers production, CI, and developer build paths. |
| Unknown | Lockfiles, vendor trees, or process/network telemetry are missing. | Named missing data sources and affected application owners. | Keep the system in scope and make conservative rotation decisions for high-value secrets. | Missing data is recovered or risk acceptance is recorded. |

### Minimum Evidence To Collect

**Minimum Evidence**:
- `composer.lock` entries and source commit SHAs for Laravel-Lang packages.
- CI or host install times relative to 2026-05-22T22:32:00Z.
- Vendor tree evidence for `src/helpers.php` and Composer `autoload.files` entries.
- Process, DNS, proxy, or EDR telemetry for `flipboxstudio[.]info` and hidden `/tmp` payloads.
- Inventory of GitHub, cloud, Kubernetes, Vault, SSH, and application secrets reachable by affected hosts.

## Timeline
- **2026-05-22T22:32:00Z** StepSecurity reports the Laravel-Lang tag rewrite window beginning for `laravel-lang/lang` [StepSecurity](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack).
- **2026-05-22 to 2026-05-23** StepSecurity reports tag rewrites across the four confirmed repositories it analyzed [StepSecurity](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack).
- **2026-05-23** Socket publishes broader Laravel-Lang compromise research covering roughly 700+ historical versions [Socket](https://socket.dev/blog/laravel-lang-compromise).
- **2026-05-23T20:18Z** Maintainers close the `http-statuses`, `actions`, and `attributes` incident issues with a "Fixed" response; the `lang` incident issue had closed earlier that day [GitHub incident issue](https://github.com/Laravel-Lang/http-statuses/issues/277).
- **2026-05-24** This local feed split created a standalone Laravel-Lang article instead of including it only in a weekly roundup.
- **2026-05-27** Packagist publishes a supply-chain security update citing the Laravel-Lang incident and taken-over GitHub credentials as the attack pattern [Packagist security update](https://blog.packagist.com/an-update-on-composer-packagist-supply-chain-security/).

## What Happened
Attackers gained the ability to rewrite release tags in Laravel-Lang repositories. That matters because Composer users often pin semver tags and assume historical tags are immutable. If a tag is moved, a fresh install can receive a malicious commit while still appearing to satisfy a legitimate version constraint.

The malicious commits added a helper file and autoload registration. StepSecurity's isolated GitHub Actions detonation showed execution through Composer autoload, staging under `/tmp`, outbound traffic to `flipboxstudio[.]info`, and short-lived dropper artifacts [StepSecurity](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack). Socket's broader analysis connects the Laravel-Lang package set to credential harvesting that targets developer and CI environments [Socket](https://socket.dev/blog/laravel-lang-compromise).

## Technical Analysis

### Initial Access
The public reports do not prove the exact initial credential or account compromise path. The observed capability was source-control write access sufficient to rewrite historical tags. StepSecurity notes shared malicious commit characteristics and fake author metadata across the confirmed repositories [StepSecurity](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack).

### Package or Artifact Tampering
The malicious artifact adds `src/helpers.php` and modifies Composer metadata so the file is loaded automatically. This is a high-leverage PHP package tampering method because many Laravel applications load Composer's autoloader early in process startup.

### Execution Trigger
Execution does not require direct use of a Laravel-Lang API. The trigger is `vendor/autoload.php`, which is routinely loaded by web applications, CLI commands, test runners, and CI jobs [StepSecurity](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack).

### Payload Behavior
StepSecurity observed a PHP loader that fetched from `flipboxstudio[.]info`, wrote hidden temporary files, launched background execution, and then removed artifacts [StepSecurity](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack). Socket reports broader collection of cloud metadata, CI/CD tokens, Kubernetes tokens, Vault tokens, browser data, password-manager data, source-control credentials, VPN configs, SSH keys, `.env` files, and local application configs [Socket](https://socket.dev/blog/laravel-lang-compromise).

### Exfiltration / C2
Known infrastructure includes `flipboxstudio[.]info`, with `/payload` and `/exfil` paths reported in the technical writeups. Treat egress to this domain from PHP, Composer, CI runners, or Laravel application hosts as a high-priority incident. [1]

### Propagation
No autonomous worm behavior is confirmed. The propagation path was dependency resolution: a fresh Composer install or update that trusted a rewritten tag could receive the poisoned commit until tags were restored and caches were cleaned.

### Obfuscation or Evasion
The attack hides in historical tag trust and normal Composer autoload behavior. Runtime evasion includes hidden `/tmp` paths, background execution, and rapid artifact deletion in the observed detonation [StepSecurity](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack).

## Affected Assets and Blast Radius
**Affected Assets**:
  - **ecosystems**: Composer,Packagist
  - **packages**: laravel-lang/lang,laravel-lang/http-statuses,laravel-lang/actions,laravel-lang/attributes
  - **versions**: rewritten historical tags reported by StepSecurity,roughly 700+ affected historical versions reported by Socket
  - **repositories**: Laravel-Lang/lang,Laravel-Lang/http-statuses,Laravel-Lang/actions,Laravel-Lang/attributes
  - **ci_cd_systems**: GitHub Actions,Composer-based build pipelines
  - **container_images**: 
  - **developer_tools**: Composer,Laravel applications

**Credentials At Risk**:
- GitHub tokens
- CI/CD secrets
- cloud credentials
- Kubernetes tokens
- Vault tokens
- SSH private keys
- .env secrets

**Not Currently Known To Affect**:
- Official Laravel framework packages, based on Socket's distinction between Laravel-Lang third-party packages and Laravel framework packages.

## Indicators of Compromise
The following indicators of compromise (IOCs) can be used to scope exposure across local repositories, systems, and telemetry exports:

### Hashes
- 2f0ee073c6f29d66188a845592029c9b52528f04

### Domains
- helpers.php
- autoload.files
- flipboxstudio[.]info
- autoload.php

### Urls
- hxxps://flipboxstudio[.]info/payload
- hxxps://flipboxstudio[.]info/exfil


## Detection and Hunting

### Hunt Manifest: laravel-lang-composer-tag-compromise-hunt-1
- **Title:** local repository and exported telemetry scope
- **Question:** Does the telemetry scope contain patterns associated with Laravel-Lang Composer Tag Rewrite RCE Compromise?
- **Telemetry Family:** process
- **Telemetry Context:** host filesystem or log export
- **Positive Signal:** Indicators of compromise matched in telemetry: local repository and exported telemetry scope

```py
#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
LOG_ROOT = os.environ.get("LOG_ROOT", "")
OUT = Path(os.environ.get("OUT", "hp-laravel-lang-composer-tag-compromise-scope"))
OUT.mkdir(parents=True, exist_ok=True)
indicators_file = OUT / "indicators.txt"

DOMAINS = ["helpers.php","autoload.files","flipboxstudio[.]info","autoload.php"]
URLS = ["https://flipboxstudio.info/payload","https://flipboxstudio.info/exfil"]
HASHES = ["2f0ee073c6f29d66188a845592029c9b52528f04"]

# Collect unique indicators
indicators = set()
for group in [DOMAINS, URLS, HASHES]:
    for val in group:
        if val:
            indicators.add(val)

with open(indicators_file, "w") as f:
    for ind in sorted(indicators):
        f.write(ind + "\n")

print(f"[+] Written unique selectors to {indicators_file}")

# Walk local directory
print(f"[+] Scanning directory: {ROOT} for selectors...")
matches = []
exclude_dirs = {"node_modules", "vendor", "dist", ".git"}
for root, dirs, filenames in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in exclude_dirs]
    for filename in filenames:
        filepath = Path(root) / filename
        try:
            content = filepath.read_text(errors="ignore")
            for ind in indicators:
                if ind in content:
                    matches.append(f"{filepath}: found '{ind}'")
        except Exception:
            pass  # pass # return or raise not needed here  # pass # return or raise not needed here

if matches:
    (OUT / "repository-indicator-matches.txt").write_text("\n".join(matches) + "\n")
    print(f"[!] Found {len(matches)} matches in codebase!")

# Optional Log Scanning
if LOG_ROOT and os.path.exists(LOG_ROOT):
    print(f"[+] Scanning telemetry log directory: {LOG_ROOT}...")
    log_matches = []
    for root, _, filenames in os.walk(LOG_ROOT):
        for filename in filenames:
            filepath = Path(root) / filename
            try:
                content = filepath.read_text(errors="ignore")
                for ind in indicators:
                    if ind in content:
                        log_matches.append(f"{filepath}: found '{ind}'")
            except Exception:
                pass  # pass # return or raise not needed here  # pass # return or raise not needed here
    if log_matches:
        (OUT / "exported-telemetry-indicator-matches.txt").write_text("\n".join(log_matches) + "\n")
        print(f"[!] Found {len(log_matches)} matches in logs!")

    if PACKAGES:
        registry_dir = OUT / "registry"
        registry_dir.mkdir(exist_ok=True)
        for package in PACKAGES:
            if not package: continue
            safe_name = package.replace("/", "__")
            print(f"[+] Querying composer show for {package}...")
            res = subprocess.run(["composer", "show", "--all", package], capture_output=True, text=True)
            if res.returncode == 0:
                (registry_dir / f"composer-{safe_name}.txt").write_text(res.stdout)

print(f"[+] Wrote scope artifacts under {OUT}")
```

## Downstream Abuse Audits
Compromised workstations expose active API credentials, requiring immediate rotated revocation. The following platforms are at risk:
- **GitHub OIDC and PATs**: Attackers harvested SSH private keys and Git Personal Access Tokens. Auditors must inspect recent action runs and release logs during the exposure window.
- **Cloud IAM Credentials**: AWS, Azure, and GCP session tokens. CloudTrail and Activity Logs should be queried for AssumeRole or write operations originating from unexpected IP addresses.
- **NPM and Package Registries**: Publishing tokens and credentials. Registry profiles must be audited for unauthorized version publishes or token additions.

## Sources
1. [StepSecurity: Laravel-Lang Supply Chain Attack](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack) - **Role:** PRIMARY_RESEARCH - **Impact:** Confirmed repositories, tag rewrite timing, detonation behavior, process tree, network activity, and IOCs.
2. [Socket: Laravel Lang Compromised with RCE Backdoor Across 700+ Versions](https://socket.dev/blog/laravel-lang-compromise) - **Role:** PRIMARY_RESEARCH - **Impact:** Historical version scope, Composer autoload execution, payload behavior, credential targets, and remediation guidance.
3. [Laravel-Lang http-statuses incident issue 277](https://github.com/Laravel-Lang/http-statuses/issues/277) - **Role:** PROJECT_DIRECT_SOURCE - **Impact:** Repository-specific rewrite window, IOCs, and maintainer restoration status.
4. [Packagist: An Update on Composer and Packagist Supply Chain Security](https://blog.packagist.com/an-update-on-composer-packagist-supply-chain-security/) - **Role:** ECOSYSTEM_DIRECT_SOURCE - **Impact:** Registry response context and confirmation of the Laravel-Lang incident.
5. [Packagist metadata: laravel-lang/http-statuses](https://repo.packagist.org/p2/laravel-lang/http-statuses.json) - **Role:** REGISTRY_DIRECT_SOURCE - **Impact:** Current post-incident release and source-reference state.
