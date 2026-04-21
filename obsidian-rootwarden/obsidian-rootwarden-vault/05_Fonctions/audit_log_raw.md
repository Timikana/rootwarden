---
type: function
layer: L5
language: php
path: www/adm/includes/audit_log.php
tags: [audit, security]
version_introduced: 1.14.2
last_reviewed: 2026-04-21
status: stable
---

# audit_log_raw($user_id, $action, $data)

**Fichier** : [[Code/www/adm/includes/audit_log.php]]

## Algo

```
BEGIN
  SELECT self_hash FROM user_logs ORDER BY id DESC LIMIT 1 FOR UPDATE
  prev = row.self_hash OR 'GENESIS'
  ts = UNIX_TIMESTAMP()
  self = SHA2(prev | user_id | action | ts, 256)
  INSERT user_logs (user_id, action, data, prev_hash, self_hash)
COMMIT
```

## Voir aussi

- [[06_Securite/hash-chain]] · [[01_Architecture/flow-hash-chain]] · [[05_Fonctions/audit_seal]] · [[05_Fonctions/audit_verify]]
