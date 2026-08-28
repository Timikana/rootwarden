# Les quatre correctifs demandés : deux sont déjà faits, un est prêt, un est un arbitrage

Session 4. Relevé **2026-08-28 · 13:50 UTC** (15:50 CEST), **lecture pure** — le LOT tourne, aucun
`docker exec`, aucun pytest, aucun redémarrage. **Rien n'est appliqué.**

---

## 0. Le dossier du redémarrage — vérifié, pas repris

**E-230 est bien fermé.** `backend/routes/helpers.py:264` :

```python
"SELECT permission FROM temporary_permissions "
"WHERE user_id = %s AND expires_at > NOW()", (user_id,))
…
perms[nom] = True      # ajoute seulement, ne retire jamais
```

Et sa requête a son **propre `try`** : une table illisible dégrade vers « les permanentes seules »
plutôt que de refuser toute authentification.

**Le lot, remesuré :**

| | |
|---|---|
| `StartedAt` du conteneur | **2026-08-27 · 12:28 UTC**, inchangé — aucun redémarrage pendant le LOT |
| commits touchant `backend/` depuis | **37** |
| **modules dont le code change** | **20** |
| fichiers de test ignorés | 7 |

---

## 1. ⚠ E-90 — **DÉJÀ CORRIGÉ, ET BRANCHÉ PARTOUT**

`_conclut_geste` n'émet `SUCCESS_MACHINE::` **que si la liste d'échecs est vide**, et `_upsert_agent`
n'est atteint qu'à travers `effet_si_reussi`.

**Vérifié branché** : 4 appels de `_conclut_geste` (`:914`, `:1219`, `:1872`, `:2058`) et 2 de
`_conclut_desinstallation` (`:1126`, `:1974`). Les deux `_upsert_agent` du chemin de déploiement sont
**dans des `lambda`** — ils ne jouent qu'en l'absence d'échec. Les trois autres appels appartiennent
aux routines de détection, pas au déploiement.

**Aucun diff à produire.** Il est écrit, il est complet, et il est **inerte** comme les 19 autres
modules.

## 2. ⚠ `generic_reconfigure` — **DÉJÀ CORRIGÉ AUSSI**

Le cas « annonce un succès sans avoir rien écrit » est traité en amont :

```python
if not config_content:
    yield f"ERROR_MACHINE::…aucune configuration a ecrire…Rien n'a ete modifie.\n"
    continue
```

et les deux étapes suivantes alimentent `echecs` (`_echec("ecriture de la configuration", rc_cfg)`,
`_echec("redemarrage du service", rc_svc)`) avant `_conclut_geste`.

**Aucun diff à produire.**

## 3. ⚠ LA CLÉ PSK — **RÉEL, DIFF PRÊT, NON APPLIQUÉ**

C'est le seul des quatre qui appelle un correctif, et **le code se condamne lui-même** :

```python
# Ecriture PSK — DECISIVE quand une PSK est configuree :
# sans elle l'agent ne peut pas parler au serveur.
if psk_value:
```

Or `psk_value` vaut `None` **aussi bien quand aucune PSK n'est configurée que quand le déchiffrement
a échoué** — ce dernier cas n'étant qu'un `logger.warning`. Conséquence :

> Une PSK **est** configurée, son déchiffrement échoue → tout le bloc est sauté, **rien n'entre dans
> `echecs`**, et `_conclut_geste` émet `SUCCESS_MACHINE::`. **L'agent part sans sa clé et le portail
> annonce la réussite** — sur l'étape que le commentaire déclare décisive.

**C'est E-217 sous une autre forme** : une valeur unique pour deux états. Là c'était `''` pour
« vide » et « illisible » ; ici c'est `None` pour « absente » et « illisible ».

**Le diff couvre les deux, et le second n'était pas demandé** : une PSK qui **déchiffre en vide** est
illisible elle aussi (`decrypt_password` rend `''`, et la colonne peut porter le chiffre PHP de la
chaîne vide).

```
scratchpad/E-231-psk-illisible.patch
  git apply --check  -> s'applique proprement
  ast.parse          -> syntaxe valide
  arbre              -> INTACT, aucun fichier backend modifié
```

## 4. E-73 — **CE N'EST PAS UN DIFF, C'EST UN ARBITRAGE**

Sa propre qualification le dit : *« la corriger demande de choisir entre poser le fuseau du conteneur,
stocker en UTC assumé et convertir à l'affichage, ou aligner les deux horloges — un choix d'exploitant
qui touche le backend et l'affichage. »*

**Et le périmètre n'est pas une colonne** : `cve_scan_schedules.next_run`, `ssh_audit_schedules`,
`last_run`, *« et toute colonne d'horodatage écrite par le backend »*.

| option | coût | ce qu'elle casse |
|---|---|---|
| poser le fuseau du conteneur sur CEST | une variable d'environnement | **rien de visible — et c'est le piège** : les valeurs déjà en base restent en UTC, donc l'affichage devient juste pour les futures et faux pour les anciennes |
| stocker en UTC assumé, convertir à l'affichage | backend **et** les deux portails | rien, mais c'est le plus large |
| aligner les deux horloges | infrastructure | hors du dépôt |

**Aucune n'est un diff que je puisse préparer seule**, et la première — la moins chère — est celle qui
introduit une incohérence entre l'ancien et le nouveau. *Le correctif le plus simple d'un défaut
d'horodatage est presque toujours celui qui coupe l'historique en deux.*

**Le scheduler n'est pas en défaut** et il faut le redire : il compare `next_run <= now` avec la même
horloge, dans le même conteneur. **Rien ne se déclenche trop tôt.** Le défaut est un **affichage**.
