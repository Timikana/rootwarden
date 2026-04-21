---
type: vision
layer: L0
tags: [vision, roadmap]
last_reviewed: 2026-04-21
status: stable
---

# Roadmap

Source temporelle : [[Code/CHANGELOG|CHANGELOG.md]]. Cette note ne duplique pas, elle pointe.

## Livrés (versions marquantes)

- **v1.14.1-1.14.7** - hardening DevSecOps (brute-force, hash chain, API keys, session revoke, password history, HIBP, RGPD).
- **v1.15.0** - modules [[02_Domaines/graylog]] + [[02_Domaines/wazuh]].
- **v1.15.1** - CI SAST bandit fix ([[07_CI-CD/job-sast-python]]).

## Chantiers identifiés (`status: unverified`)

- KMS externe pour `self_hash` audit log (cf. [[06_Securite/hash-chain]] - limitation documentée).
- [[02_Domaines/supervision]] : intégration alertes vers webhooks existants.

## Voir aussi

- [[12_Journal/_MOC]] · [[00_Vision/README]]
