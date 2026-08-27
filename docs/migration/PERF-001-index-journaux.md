# PERF-001 — Les quatre tables les plus grosses n'avaient aucun index sur leur date

Mesuré le **2026-08-27**, session 4 (base & performance). Migration `062_index_journaux_et_purge.sql`.

Tout chiffre de ce document porte sa commande de remesure. Les mesures de latence sont
prises **dans le conteneur** `rootwarden_db`, dont les données vivent dans un volume Docker :
la réserve du plan sur les montages liés (258×) ne s'y applique pas.

---

## 1. Ce qui a été trouvé

Les quatre tables les plus volumineuses du schéma sont toutes des journaux. Toutes sont
filtrées et triées sur leur colonne de **date**. Aucune ne portait d'index dessus.

| table | lignes | rythme mesuré | index de date avant |
|---|---|---|---|
| `user_logs` | 4 830 | 51,9 / jour | **aucun** |
| `login_history` | 4 191 | 45,1 / jour | **aucun** (`idx_user_date` commence par `user_id`) |
| `active_sessions` | 3 908 | 260,5 / jour | **aucun** |
| `login_attempts` | 1 | — (vidée avant chaque suite) | **aucun** |

```bash
P=$(grep -oP '^MYSQL_ROOT_PASSWORD=\K.*' srv-docker.env)
sudo -n docker exec -e MYSQL_PWD="$P" rootwarden_db mysql -uroot rootwarden -e "
SELECT 'user_logs' t, COUNT(*) n, ROUND(COUNT(*)/GREATEST(DATEDIFF(MAX(created_at),MIN(created_at)),1),1) par_jour FROM user_logs
UNION ALL SELECT 'login_history', COUNT(*), ROUND(COUNT(*)/GREATEST(DATEDIFF(MAX(created_at),MIN(created_at)),1),1) FROM login_history
UNION ALL SELECT 'active_sessions', COUNT(*), ROUND(COUNT(*)/GREATEST(DATEDIFF(MAX(created_at),MIN(created_at)),1),1) FROM active_sessions;"
```

Six requêtes réelles étaient touchées. **Cinq en `type: ALL` ou `Using filesort`.**

| appelant | requête | avant |
|---|---|---|
| `legacy/profile.php:374` | `active_sessions WHERE user_id = ? ORDER BY last_activity DESC LIMIT 10` | `ref` + **filesort de 2 132 lignes pour en rendre 10** |
| `legacy/profile.php:341` | `user_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 15` | `ref` + **filesort de 1 263 lignes pour en rendre 15** |
| `JournalAudit::lignes()` | `user_logs JOIN users ORDER BY created_at DESC LIMIT 50` | **`ALL` (4 709 lignes) + filesort** |
| `scheduler.py` purge | `DELETE FROM user_logs WHERE created_at < ?` | **`ALL`** |
| `scheduler.py` purge | `DELETE FROM login_history WHERE created_at < ?` | **`ALL`** |
| `scheduler.py` purge | `DELETE FROM login_attempts WHERE attempted_at < ?` | **`ALL`** |
| `legacy/auth/login.php:47` | `DELETE FROM login_attempts WHERE attempted_at < …` | **`ALL`, et à CHAQUE tentative de connexion** |

Le dernier est le plus notable : ce n'est pas une tâche de fond, c'est le **chemin de
connexion**. Chaque tentative faisait un parcours complet de `login_attempts` — la table
qui grossit précisément quand quelqu'un attaque le portail.

---

## 2. Avant / après, mesuré

Trois séries de **200 itérations** par requête, via des procédures stockées dans un schéma
jeté (`rw_perf_bench`, supprimé depuis) qui ne lisait que les tables réelles. Médiane des
trois séries. **Aucune donnée réelle n'a été modifiée pour cette mesure.**

| requête | avant | après | facteur |
|---|---|---|---|
| `active_sessions` (profil, 10 lignes) | **14,700 ms** | **0,493 ms** | **× 30** |
| `user_logs` (profil, 15 lignes) | **4,064 ms** | **0,651 ms** | **× 6,2** |
| journal d'audit (page, 50 lignes) | **6,025 ms** | **0,541 ms** | **× 11** |

`EXPLAIN` après, sur la requête de page du journal :

```
type: index   key: idx_ulogs_created   rows: 50   Extra: Backward index scan
```

Elle lisait 4 709 lignes et les triait ; elle en lit **50**, dans l'ordre de l'index.
Les deux requêtes de profil n'ont **plus de `filesort`** (`Extra: NULL`).
Les trois purges passent de `ALL` à `range`.

---

## 3. Deux résultats qui ne suivent pas — et pourquoi ce n'est pas un défaut

Il faut le dire aussi clairement que le reste, sans quoi la table ci-dessus se lit comme
une victoire uniforme qu'elle n'est pas.

**`DELETE FROM active_sessions WHERE last_activity < NOW() - 7 jours` reste en `ALL`.**
L'index existe et n'est pas choisi : le prédicat vise **1 117 lignes sur 3 908**, soit
28,6 %. À cette sélectivité, un parcours séquentiel coûte moins qu'un parcours d'index
suivi de 1 117 accès à une clé primaire de 128 caractères. C'est une décision correcte de
l'optimiseur. Vérifié : sur un prédicat sélectif (12 lignes sur 3 908) il choisit
`range` sur `idx_sessions_activity` avec `rows: 12`. **C'est l'état de régime** — après la
première purge, chaque passage n'a plus que la traîne de la veille à retirer.

**L'export du journal (`JournalAudit::toutesPourExport()`) reste en `ALL` + filesort.**
Il n'a pas de `LIMIT` : il lit tout par construction. Trier 4 709 lignes en mémoire y est
moins cher qu'un parcours d'index à accès aléatoires. C'est également correct. Le gain
mesuré porte sur la requête **de page**, qui est celle qu'un exploitant déclenche.

---

## 4. Ce que la migration fait, et ce qu'elle coûtera en production

Six index créés, **deux retirés**.

```sql
CREATE INDEX idx_ulogs_created        ON user_logs (created_at);
CREATE INDEX idx_ulogs_user_created   ON user_logs (user_id, created_at DESC);
DROP   INDEX user_id                  ON user_logs;
CREATE INDEX idx_sessions_activity    ON active_sessions (last_activity);
CREATE INDEX idx_sessions_user_activity ON active_sessions (user_id, last_activity DESC);
DROP   INDEX idx_user                 ON active_sessions;
CREATE INDEX idx_lhist_created        ON login_history (created_at);
CREATE INDEX idx_lattempts_attempted  ON login_attempts (attempted_at);
```

Les deux retraits ne sont pas un nettoyage opportuniste : `user_id` et `idx_user` sont des
**préfixes** stricts des nouveaux composites, donc sans usage propre. La contrainte de clé
étrangère reste portée par le composite, dont `user_id` est la colonne de tête — vérifié en
appliquant réellement la migration, pas en le supposant.

**Idempotence prouvée, pas affirmée** : la ligne `062` a été retirée de `schema_migrations`
et la migration rejouée. Résultat : `0 statement(s) execute(s), 8 tolere(s) idempotent(s)`.

**Coût en production.** MySQL 9.2 crée ces index en `INPLACE` avec DML concurrente
autorisée : aucune interruption d'écriture. Le coût est en E/S et proportionnel au volume.
Sur le banc (≈ 4 800 lignes par table) l'ensemble a pris **1,1 s**. Sur une base de
production plus ancienne, à lancer hors heure de pointe. Les deux `DROP INDEX` sont
instantanés.

---

## 5. Ce qui n'est PAS corrigé ici, et qui est plus grave que le reste

**La purge ne tourne pas.** `_purge_old_logs()` (`backend/scheduler.py:365-369`) sort
immédiatement si `LOG_RETENTION_DAYS <= 0`, et la variable est **commentée** dans
`srv-docker.env` comme dans `srv-docker.env.example` — donc `0`, donc jamais.

```bash
grep -n "LOG_RETENTION_DAYS" srv-docker.env
```

Conséquence directe et mesurable : **rien n'a jamais été purgé**. `user_logs` remonte au
2026-05-26, jour de la remise à zéro de la base.

Et le piège est ailleurs que dans les journaux. **Quatre nettoyages qui ne sont PAS des
politiques de rétention vivent à l'intérieur de cette même porte** :

| nettoyage | nature réelle |
|---|---|
| `active_sessions` inactives depuis 7 jours | hygiène de session |
| `temporary_permissions` expirées | hygiène de droits |
| `password_reset_tokens` expirés ou consommés | hygiène de secrets |
| scans CVE hors rétention | rétention, à sa place |

Les trois premiers n'ont rien à voir avec la durée de conservation d'un journal, et ils
sont pourtant éteints par la même variable. Mesure du 2026-08-27 :

| compte | sessions en base | plus ancienne |
|---|---|---|
| `rw-test-super` (16) | **2 132** | 2026-08-15 |
| `rw-test-user` (14) | **1 094** | 2026-08-15 |
| `superadmin` (1) | **619** | 2026-08-12 |

`legacy/auth/verify.php:66` interroge cette table à chaque page protégée
(`SELECT 1 … WHERE session_id = ? AND user_id = ?`) : c'est la **liste de révocation**
côté serveur, et elle n'expire jamais d'elle-même. Une ligne seule n'ouvre rien — il faut
encore présenter le `session_id` — mais une liste de révocation qui ne vieillit pas ne
remplit qu'à moitié son office, et `profile.php:374` affiche ces lignes à l'utilisateur
comme « vos sessions actives ».

**Ce n'est pas corrigé, et c'est délibéré : la correction est une décision d'exploitation,
pas un détour de performance.** Trois issues, dans l'ordre de ce que je recommande :

1. **sortir les trois nettoyages d'hygiène de la porte `LOG_RETENTION_DAYS`** et les faire
   tourner sans condition. C'est un changement de comportement du planificateur : il
   supprimerait des lignes qu'aujourd'hui personne ne supprime ;
2. activer `LOG_RETENTION_DAYS` — mais cela emporte aussi les journaux d'audit, et
   `user_logs` porte une **chaîne scellée** : purger par la tête romprait la vérification
   d'intégrité. À examiner avant d'activer, pas après ;
3. ne rien faire et laisser croître.

L'issue 2 touche une chaîne d'audit. Je ne la déclenche pas.

---

## 6. Ce que je n'ai pas mesuré

- **Aucune mesure au navigateur.** Le banc était tenu par la session 7. Les gains ci-dessus
  sont mesurés au niveau SQL ; ce qu'un exploitant perçoit sur `profile.php` ou
  `/journal-audit` n'a pas été chronométré de bout en bout ;
- **la pagination profonde du journal** (`OFFSET n`) reste en O(offset), et `compte()` fait
  un `COUNT(*)` sur des `LIKE '%…%'` non indexables. Relevé, non traité ;
- **`login_attempts` porte trois index commençant tous par `ip_address`.** Possible
  redondance, non mesurée — il faudrait relever les requêtes réelles avant de toucher quoi
  que ce soit ;
- **le schéma des relations est SAIN**, et il faut le dire aussi nettement qu'un reproche :
  76 colonnes de clé étrangère déclarées, et seulement **trois** colonnes de relation sans
  contrainte (`notifications.user_id`, `tasks.machine_id`, `tasks.created_by`). Ce n'est pas
  le problème de ce schéma.

---

## 7. Remesure

```bash
sudo -n docker exec rootwarden_python sh -c "cd /app && python db_migrate.py --status" | tail -5
sudo -n docker exec -e MYSQL_PWD="$P" rootwarden_db mysql -uroot rootwarden -e "
EXPLAIN SELECT l.id,l.action,l.created_at,u.name FROM user_logs l
JOIN users u ON l.user_id=u.id ORDER BY l.created_at DESC LIMIT 50\G"
# attendu : key: idx_ulogs_created, rows: 50, Backward index scan, PAS de filesort
```
