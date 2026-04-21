---
type: table
layer: transverse
tags: [db, module/wazuh]
migration_introduced: 034
columns: [machine_id, fim_paths_json, log_format, syscheck_frequency, ar_enabled, sca_enabled, rootcheck_enabled]
last_reviewed: 2026-04-21
---

# wazuh_machine_options

Override options par serveur. FIM paths validés regex-safe, `syscheck_frequency ∈ [60, 604800]`.
