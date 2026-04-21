---
type: diagram
layer: L1
tags: [architecture, ci]
path: .github/workflows/ci.yml
last_reviewed: 2026-04-21
status: stable
---

# CI pipeline - DAG

Source : [[Code/.github/workflows/ci.yml|ci.yml]]. 11 jobs.

```mermaid
flowchart LR
  lp[lint-python] --> tp[test-python]
  lp --> sast[sast-python]
  lp --> scapy[sca-python]
  lph[lint-php] --> scaph[sca-php]
  lp --> bd[build-docker]
  lph --> bd
  tp --> bd
  tf[trivy-fs]
  ss[secrets-scan]
  bd --> sec[security-scan]
  bd --> tag[auto-tag]
  sec --> tag
  ss --> tag
  sast --> tag
  scapy --> tag
  scaph --> tag
  tf --> tag
```

## Bloquant sur main

`auto-tag` dépend de **tous** les scans sécurité → aucune release possible si CVE critique non résolue.

## Voir aussi

- [[07_CI-CD/_MOC]] · [[07_CI-CD/workflow-ci]] · [[07_CI-CD/release-flow]]
