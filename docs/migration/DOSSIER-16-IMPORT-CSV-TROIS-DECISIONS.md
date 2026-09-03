# DOSSIER 16 — L'import CSV : trois décisions, et deux décident qui peut créer un compte privilégié

**Pour signature de l'exploitant.** *Ce dossier ne conçoit rien : il pose trois questions dont les issues
sont déjà rédigées au plan.* **Caractérisé le 2026-08-26 (`v1.37.69`) ; mesures revérifiées par moi le
2026-09-03 à 09:50 CEST.**

> **Le port de cet import est bloqué depuis huit jours, et pas par un manque de conception.** *Il est
> bloqué sur trois arbitrages, dont deux touchent la création de comptes privilégiés par fichier.*

---

## 0. Ce que l'import fait réellement — et aucune de ses deux descriptions ne le dit

    comptes.php:20   « l'import de COMPTES par fichier CSV »
    le plan          « import par fichier CSV (SERVEURS) »

**Les deux désignent `legacy/adm/includes/import_csv.php`, et chacune en nomme une part.** *Le fichier
écrit dans QUATRE tables :*

    INSERT INTO machines       les serveurs
    INSERT INTO users          les COMPTES
    INSERT INTO permissions    une ligne par compte, les 15 droits a ZERO
    INSERT INTO user_logs      UNE entree par import (pas par ligne)

> **Qui prend la tâche sous le libellé « import CSV des serveurs » croit porter une lecture de fichier.**
> *Il porterait un geste qui crée des comptes.*

**Ce qui est bien bâti et doit être préservé au portage** : `roleMap` est une **liste fermée** avec défaut
au rôle 1 (`:150-:151`), et une clause **anti-escalade** empêche un non-superadmin de créer un rôle
supérieur ou égal au sien (`:156`).

---

## 1. DÉCISION — la colonne `sudo` du format CSV (E-130)

### La mesure

    import_csv.php:162   $sudo = (int)($data['sudo'] ?? 0);       <- AUCUN controle de role
                  :166   ->execute([… $roleId, $active, $sudo]);  <- ecrit tel quel

    api/toggle_sudo.php:26   checkAuth([ROLE_SUPERADMIN])   // Superadmin uniquement
                       :47   refuse meme de modifier SON PROPRE sudo

**`users.sudo` est la précondition du repli `NOPASSWD: ALL` du module `ssh/`.**

> **Un rôle 2 porteur de `can_admin_portal` obtient par un fichier ce que le geste dédié réserve au rôle
> 3 — et que ce geste refuse même de s'accorder à lui-même.**

### Les trois issues, telles que le plan les a écrites

    a) exiger le role 3 pour cette colonne
    b) la refuser a l'import
    c) la garder en l'etat

**Pourquoi ce n'est pas à moi** : *« Retirer une colonne d'un format de fichier documenté change un
contrat. »* **Une session précédente avait déjà refusé de trancher, et j'ai failli le faire par omission
en demandant un panneau.**

### Ma recommandation, à contredire

**(a) — exiger le rôle 3 pour cette colonne.** *Elle aligne l'import sur le geste dédié sans retirer la
colonne du format, donc sans casser un contrat documenté. (b) casserait le contrat ; (c) laisse une
escalade par fichier.*

---

## 2. DÉCISION — un compte importé est inutilisable (E-131)

    mot de passe aleatoire que personne ne connait
    $sendWelcome  MORT
    `email` FACULTATIF  ->  aucune recuperation possible

**Trois issues du plan** : *rendre `email` obligatoire · afficher le mot de passe généré **une fois**,
comme le fait déjà D3 · forcer `force_password_change`.*

**Ma recommandation** : **`email` obligatoire ET `force_password_change`**, pas l'affichage du mot de
passe. *Les deux premières sont cumulables et ne montrent aucun secret ; la troisième fait dépendre
l'accès d'un affichage unique qu'on peut manquer.* **⚠ Et `force_password_change` a un coût connu : la
page de changement est portée (`POST /profil/mot-de-passe`), mais le bandeau qui l'annonçait envoyait
vers l'ancien portail jusqu'à ce matin (E-362, corrigé à 05:42).**

---

## 3. DÉCISION — la politique de mot de passe sur les MACHINES (E-132)

**Le portage passera `false`, comme le formulaire** — *un mot de passe de machine est imposé par la
machine.* **C'est une divergence assumée avec l'import du legacy, et elle se déclare plutôt qu'elle ne se
tranche.** *Aucune recommandation : c'est un constat à valider.*

---

## 4. ⚠ Un CINQUIÈME effet que personne n'avait nommé, et il n'est pas dans les trois décisions

    import_csv.php:120 et :181
      INSERT INTO user_logs (user_id, action) VALUES (?, ?)
      -> ni `prev_hash` ni `self_hash` : les inserts sont NUS

    les ecrivains qui CHAINENT : adm/includes/audit_log.php · audit_seal.php · audit_verify.php

**`user_logs` porte une chaîne de hachage depuis la migration `036`.** *Chaque import ajoute donc un
orphelin à la chaîne d'audit — la classe des 1385 orphelins déjà relevés.*

> **Un panneau qui promettrait « une trace d'audit » promettrait une trace NON CHAÎNABLE.** *Ce n'est pas
> une décision de portage : c'est un défaut du legacy que le portage ne doit pas reproduire.*

**Relevé par la session 3. Je ne l'avais pas vu, et j'annonçais « une entrée d'audit par ligne » — c'est
une par import.**

---

## 5. Ce qui se passe si on ne fait rien

**Rien ne se dégrade.** *L'import reste sur le legacy, il fonctionne, sa suite passe à **7 PASS / 0
FAIL** (`tests/e2e/go-adm-import-csv.mjs`, volontairement hors LOT tant que le portage n'existe pas).*

**Le coût est un coût d'archivage** : *le jour où `legacy/adm/` tombe, l'import disparaît* — et E-130
disparaît avec lui, ce qui est le seul effet **favorable** de l'inaction. **Mais la capacité aussi.**

---

## Ce qui n'est pas mesuré

- **si la colonne `sudo` a jamais été utilisée dans un import réel.** *Cela demanderait de lire
  `user_logs` en production, et l'entrée d'import ne porte qu'un compte de serveurs* ;
- **combien de comptes existants portent `sudo = 1`.** *Je n'interroge pas la base* ;
- **le format CSV documenté.** *Je dis que retirer une colonne change un contrat ; je n'ai pas lu la
  documentation qui l'établit* ;
- **E-129**, le garde SSRF en trois copies comparant des préfixes de chaîne : *nommé au plan comme
  correctif de production à décider, hors du périmètre de ce dossier.*
