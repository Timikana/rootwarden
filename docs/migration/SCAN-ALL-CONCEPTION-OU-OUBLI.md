# `/ssh-audit/scan-all` et `/docker/scan_all` : conception ou oubli ?

Session 4. Relevé **2026-08-28 · 14:00 UTC** (16:00 CEST), **lecture pure** — le LOT tourne.

**Réponse : les deux ne sont pas le même cas.** L'une est cohérente, l'autre non.

---

## 1. `/docker/scan_all` — **conception, et cohérente**

| couche | ce qu'elle exige |
|---|---|
| page legacy | **il n'y en a pas** — `legacy/docker/` n'existe pas |
| page portée | `role:2`, **sans permission** (`web.php:276`) |
| route backend | `role(2)`, sans permission |

**Et il n'existe aucune colonne `can_manage_docker`** dans le schéma. Il n'y a donc rien à exiger : la
page et la route disent la même chose, et c'est « rôle 2 ».

**Le voisin immédiat le confirme comme un choix** : `/graylog`, deux lignes plus haut dans le même
fichier, porte `['role:2', 'perm:can_manage_graylog']`. **L'auteur a décidé par module, pas par
oubli** — il a mis une permission là où elle existe.

**Rien à corriger.**

## 2. ⚠ `/ssh-audit/scan-all` — **incohérence, et pas celle qu'on attend**

| couche | ce qu'elle exige |
|---|---|
| page legacy (`ssh-audit/index.php:12-13`) | `ROLE_USER` **ou plus** + **`can_audit_ssh`** |
| route backend | **`role(2)`**, *aucune permission* |
| proxy | `/ssh-audit/` est en liste blanche, **absent d'`ADMIN_ONLY`** |

`can_audit_ssh` **existe** dans le schéma, et il est employé ailleurs — c'est la permission que E-211
vient d'ajouter à `GET /ssh-audit/policies`.

### Les deux gardes ne s'ordonnent pas

Ce n'est pas le cas habituel « la route est plus faible que la page ». **Aucune des deux n'implique
l'autre :**

- la page est **plus souple sur le rôle** (elle admet un rôle 1) et **plus stricte sur la
  permission** ;
- la route est **plus stricte sur le rôle** et **n'a aucune permission**.

Deux conséquences symétriques, et la seconde est celle qui compte :

1. un **rôle 1 portant `can_audit_ssh`** passe la page et **se fait refuser par la route** — c'est la
   famille d'E-230, que le correctif des permissions temporaires vient de fermer sur un autre axe ;
2. **un rôle 2 SANS `can_audit_ssh` ne peut pas ouvrir la page — et peut appeler la route.** Le proxy
   ne l'arrête pas : `/ssh-audit/` est autorisé et hors `ADMIN_ONLY`.

> **La route que la consigne permanente désigne comme « à ne jamais lancer » est atteignable par un
> compte à qui le portail refuse d'afficher le module.**

C'est le défaut signature de ce dépôt — *la garde est sur la page, pas sur la requête* — sous une forme
que le relevé habituel ne voit pas, parce que **la route a l'air plus stricte** : elle exige un rôle
supérieur. *Une garde plus stricte sur un axe peut être plus permissive sur un autre, et un
rapprochement qui ne compare qu'un axe conclut à l'envers.*

### Ce qui n'est PAS mesuré, et pourquoi

**Combien de comptes sont dans le cas 2** — rôle 2 sans `can_audit_ssh`. La base n'est joignable que
par `docker exec`, et **le LOT tourne** : la consigne l'interdit. Le chiffre est donc **inconnu**, et
je préfère le dire que l'estimer.

*L'écart est structurel et ne dépend pas de ce chiffre* — mais sa **portée**, si. À mesurer au calme,
en lisant ce que les lignes disent et pas seulement en les comptant.

## 3. Ce que je ne propose pas

**Aucun correctif.** Le gel tient, et l'écrire serait inerte. Et le choix n'est pas évident : aligner
la route sur la page demanderait d'**abaisser** son rôle à 1 tout en **ajoutant** la permission —
c'est-à-dire d'élargir un axe pour en resserrer un autre, sur la route la plus dangereuse du module.
**C'est un arbitrage, pas un diff.**
