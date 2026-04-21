---
type: ops
layer: transverse
tags: [ops, db]
last_reviewed: 2026-04-21
---

# Restore

```bash
gunzip -c backups/rootwarden-YYYYMMDD.sql.gz | docker exec -i rootwarden_db mysql -u root -p rootwarden
```

⚠️ Après restore, vérifier [[08_DB/tables/user_logs|hash chain]] : un mismatch est attendu si des rows ont été ré-injectées - seal manuel via [[05_Fonctions/audit_seal]].
