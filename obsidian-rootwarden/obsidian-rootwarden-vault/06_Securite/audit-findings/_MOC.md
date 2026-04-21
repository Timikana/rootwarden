---
type: moc
layer: transverse
tags: [moc, security, audit]
last_reviewed: 2026-04-21
---

# Audit findings (MOC)

Source : [[Code/docs/SECURITY_AUDIT|SECURITY_AUDIT.md]]. 28+ failles corrigées (3 audits).

```dataview
TABLE severity, status, version_fixed FROM "06_Securite/audit-findings" WHERE file.name != "_MOC" SORT severity
```

## Notables

- [[06_Securite/audit-findings/finding-brute-force]] - v1.14.1
- [[06_Securite/audit-findings/finding-hash-chain-no-kms]] - open, mitigation future
- [[06_Securite/audit-findings/finding-session-revoke]] - v1.14.5
- [[06_Securite/audit-findings/finding-api-key-single]] - v1.14.4
- [[06_Securite/audit-findings/finding-password-reuse]] - v1.14.6
- [[06_Securite/audit-findings/finding-rgpd-no-export]] - v1.14.7
- [[06_Securite/audit-findings/finding-ci-no-sast]] - v1.14.3
- [[06_Securite/audit-findings/finding-api-key-legacy-broken]] - v1.16.1
