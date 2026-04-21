---
type: moc
layer: transverse
tags: [moc, ci]
last_reviewed: 2026-04-21
---

# 07 - CI/CD (MOC)

```dataview
TABLE blocking, needs FROM "07_CI-CD" WHERE file.name != "_MOC" SORT file.name
```

## Workflow

[[07_CI-CD/workflow-ci]] - [[Code/.github/workflows/ci.yml]]

## Jobs (11)

- [[07_CI-CD/job-lint-python]] · [[07_CI-CD/job-lint-php]]
- [[07_CI-CD/job-test-python]]
- [[07_CI-CD/job-build-docker]] · [[07_CI-CD/job-security-scan]]
- [[07_CI-CD/job-secrets-scan]] · [[07_CI-CD/job-sast-python]]
- [[07_CI-CD/job-sca-python]] · [[07_CI-CD/job-sca-php]] · [[07_CI-CD/job-trivy-fs]]
- [[07_CI-CD/job-auto-tag]]

## Voir aussi

- [[01_Architecture/ci-pipeline-dag]] · [[07_CI-CD/release-flow]] · [[07_CI-CD/tags]]
