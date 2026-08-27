# PERF-002 — Le journal d'audit : une jointure qui ne filtre rien, et une pagination en O(page)

Mesuré le **2026-08-27**, session 4, après PERF-001 (les index sont donc en place).

**Le fichier concerné n'est pas à moi.** `laravel/app/Services/JournalAudit.php` appartient à la
session 3. Ce document mesure et remet l'`EXPLAIN` ; il ne corrige pas.

**Ce qui n'est PAS mesuré ici est dit avant le reste** : aucune mesure de temps. La session 3 tenait
le banc pour F6, et une sonde répétée y aurait ajouté de la charge — c'est précisément ce qui a déjà
brouillé une mesure aujourd'hui. Tout ce qui suit est **structurel** (`EXPLAIN`, schéma), obtenu par
des requêtes uniques. Les gains ne sont donc **pas chiffrés** : ils se voient dans le plan
d'exécution, pas au chronomètre. Un avant/après en millisecondes reste à prendre.

---

## 0. Ce qui va bien, et il faut le dire

**Il n'y a pas de N+1.** Un chargement de `/journal-audit` fait exactement **deux** requêtes :
`compte()` puis `lignes()` (`JournalAuditController::__invoke`). La vue ne rouvre rien par ligne.
C'était la première chose cherchée ; elle n'est pas là.

---

## 1. `compte()` joint `users` alors que la jointure ne peut RIEN filtrer

`JournalAudit::requete()` construit une base commune aux deux requêtes :

```php
$q = DB::table('user_logs as l')->join('users as u', 'l.user_id', '=', 'u.id');
```

`lignes()` en a besoin — elle affiche `u.name`. **`compte()` n'en a pas besoin**, et la jointure y
est démontrablement sans effet :

| ce qui le prouve | mesure |
|---|---|
| `user_logs.user_id` est `NOT NULL` | `IS_NULLABLE = NO` |
| une contrainte de clé étrangère l'impose | `user_logs_ibfk_1 → users(id) ON DELETE CASCADE` |
| lignes sans utilisateur correspondant | **0** (`LEFT JOIN … WHERE u.id IS NULL`) |

Une jointure interne qui ne peut retirer aucune ligne ne change pas un `COUNT`. Elle change en
revanche le **plan choisi**, et dans le mauvais sens dès qu'un filtre de date est posé — c'est le
filtre le plus naturel de cette page :

```sql
SELECT COUNT(*) FROM user_logs l JOIN users u ON l.user_id = u.id
WHERE l.created_at >= '2026-08-01 00:00:00'
```

| | avec la jointure | sans la jointure |
|---|---|---|
| table pilote | `users` (`index`, 10 lignes) | `user_logs` |
| accès à `user_logs` | `ref` sur `idx_ulogs_user_created` | **`range`**, `Using index for skip scan` |
| lignes examinées | **10 × 1 179 ≈ 11 790** entrées d'index | **1 573** |

L'optimiseur pilote par `users` — dix lignes, ça paraît malin — puis fait dix parcours `ref` et
filtre la date **après**. Sans la jointure il attaque directement par la date. Le rapport de lignes
examinées est d'environ **7,5**.

> **Recommandation à la session 3** : ne joindre `users` dans `compte()` que si le filtre
> `utilisateur` est effectivement posé. La jointure reste indispensable dans `lignes()`.
> **Gain non chiffré** — le rapport ci-dessus est un compte de lignes estimé par l'optimiseur, pas
> un temps.

---

## 2. La pagination profonde retombe en parcours complet — et c'est atteignable AUJOURD'HUI

`lignes()` fait `->offset(($page-1) * 50)->limit(50)`. Un `OFFSET` se paie en lisant puis en jetant
les `n` premières lignes : le coût croît avec le **numéro de page**.

Ce n'est pas une projection. Le journal porte **4 841 lignes, soit 97 pages** de 50.

| page | plan mesuré |
|---|---|
| **1** (`OFFSET 0`) | `type: index`, `key: idx_ulogs_created`, `rows: 50`, `Backward index scan` |
| **96** (`OFFSET 4750`) | **`type: ALL`, `key: NULL`, `rows: 4720`, `Using filesort`** |

L'optimiseur abandonne l'index parce qu'à cet `OFFSET` il doit de toute façon tout lire. La première
page est un parcours borné à 50 lignes ; la dernière est un tri complet de la table. Et la dernière
page est **le lien « ›| » de la pagination**, donc à un clic.

Le remède classique est la pagination **par curseur** (`WHERE created_at < :dernier_vu`), qui rend
chaque page indépendante du numéro. Elle change l'interface — plus de saut direct à la page N — donc
ce n'est pas un détour de performance mais une décision de conception. **À la session 3 et au Lead.**

---

## 3. `LIKE '%…%'` n'est pas indexable, et aucun index n'y changera rien

Les deux filtres de texte (`utilisateur`, `action`) sont posés en `like '%' . $v . '%'`. Un joker en
**tête** interdit tout parcours d'index :

```
EXPLAIN SELECT COUNT(*) … WHERE l.action LIKE '%bashrc%'
  type: ALL   key: NULL   rows: 4720   Extra: Using where
```

**Ce n'est pas un défaut à corriger par un index** — c'est une propriété du prédicat. Le dire évite
qu'on ajoute un index qui ne servira jamais. Trois issues, aucune n'est neutre :

1. laisser en l'état, en sachant que ce filtre coûte un parcours complet ;
2. chercher par **préfixe** (`LIKE 'bashrc%'`), qui devient indexable — mais change le résultat que
   l'utilisateur obtient ;
3. un index **FULLTEXT** sur `action`, qui change le schéma et la sémantique de la recherche.

La 2 et la 3 modifient ce que la page **trouve**. Ce n'est pas à la couche base de trancher.

---

## 4. Récapitulatif, et à qui va quoi

| constat | gravité | propriétaire |
|---|---|---|
| pas de N+1 | — | *rien à faire* |
| jointure inutile dans `compte()` | faible, mais gratuite à corriger | **session 3** |
| pagination en O(page), dernière page en parcours complet | modérée, croît avec le volume | **session 3 + Lead** (change l'interface) |
| `LIKE '%…%'` non indexable | structurelle | **Lead** (change ce que la page trouve) |

Aucun de ces trois points n'est corrigeable depuis `backend/` ou `mysql/`. Rien n'a été modifié.

---

## 5. Remesure

```bash
P=$(grep -oP '^MYSQL_ROOT_PASSWORD=\K.*' srv-docker.env)
Q() { sudo -n docker exec -e MYSQL_PWD="$P" rootwarden_db mysql -uroot rootwarden -e "$1"; }

# la jointure ne peut rien filtrer
Q "SELECT COUNT(*) FROM user_logs l LEFT JOIN users u ON l.user_id=u.id WHERE u.id IS NULL"   # 0

# la derniere page
Q "SELECT CEIL(COUNT(*)/50) FROM user_logs"
Q "EXPLAIN SELECT l.id,l.action,l.created_at,u.name FROM user_logs l
   JOIN users u ON l.user_id=u.id ORDER BY l.created_at DESC LIMIT 50 OFFSET 4750\G"
```
