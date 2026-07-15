# Claim Ledger: vpmdhaj npm OpenSearch Typosquats

| Claim | Confidence | Evidence |
| --- | --- | --- |
| Microsoft reported 14 typosquatted npm packages under the `vpmdhaj` scope that targeted cloud and CI/CD credentials. | confirmed | Microsoft Threat Intelligence, 2026-05-28. |
| The package set impersonated OpenSearch, AWS SDK, STS, and Bun-related package names. | confirmed | Microsoft package list and npm namespace/package pages. |
| Microsoft observed credential collection paths for AWS, GitHub Actions OIDC, npm, Vault, Kubernetes service accounts, cloud config files, and SSH material. | confirmed | Microsoft technical details. |
| Exfiltration used `aab.sportsontheweb.net` and the `/api/b` path, with `x-forwarded-host` among the request metadata. | confirmed | Microsoft IOCs and behavior description. |
| The packages were removed from npm by the time of publication. | confirmed | Microsoft remediation section; npm pages may currently resolve only as historical package/profile pages or removal notices. |
| Exact complete version coverage is publicly known only for package/version pairs called out by Microsoft; other package version ranges remain unknown from public sources. | unclear | Microsoft listed concrete versions for `@vpmdhaj/opensearch-setup` and `@vpmdhaj/elastic-helper`, but not every package/version in the cluster. |
