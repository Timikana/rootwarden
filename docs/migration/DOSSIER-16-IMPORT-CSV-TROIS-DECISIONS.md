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

**⚠ CORRECTION 10:05 — la phrase qui portait la sévérité d'E-130 est périmée.** *Le plan et la première
version de ce dossier écrivaient : « `users.sudo` est la précondition du repli `NOPASSWD: ALL` ». C'est
**vrai du schéma et faux du chemin.** Relevé par la session 3, chaîne revérifiée par moi maillon par
maillon.*

    configure_servers.py:1050  if  policy && preset && preset != 'none'  -> add_to_sudoers(policy)
                        :1052  elif policy && preset == 'none'           -> REMOVE_from_sudoers
                        :1054  elif sudo                                 -> add_to_sudoers()  # NOPASSWD ALL
                        :1057  else                                      -> remove_from_sudoers

    ssh_utils.py:956-959   le MEME `if mid:` remplit allowed_servers ET sudo_policies[mid]
                           'preset': record.get('sudo_preset') or 'none'   -> JAMAIS None
    configure_servers:932  UN SEUL appelant de configure_user, garde par
                           `if mid in user.get('allowed_servers', [])`
    configure_servers:1230 UN SEUL instanciateur de production ; all_users vient de
                           load_data_from_db (:1197), source unique

**Donc `mid ∈ allowed_servers` ⟹ `sudo_policies[mid]` existe ⟹ la troisième branche ne tire JAMAIS.**

### ⚠⚠ RÉVISION 10:20 — E-130 est RENVERSÉE : le geste de rôle 3 est SANS EFFET LUI AUSSI

**Relevé par la session 3, cinq affirmations revérifiées par moi une par une.**

    051:7    sudo_preset ENUM(…) NOT NULL DEFAULT 'none'
             -> la colonne n'est JAMAIS nulle, `policy_for_machine` toujours un dict plein
             -> la branche du repli est MORTE PAR LE SCHEMA, pas par le collecteur

    toggle_sudo.php:61   UPDATE users SET sudo = ? WHERE id = ?      <- users.sudo SEUL
    seul ECRIVAIN de sudo_preset :  update_server_access.php:123     (verifie : les autres
                                    fichiers ne font que LIRE, backend en lecture seule)
    declencheur SQL de rattrapage : AUCUN CREATE TRIGGER dans les migrations
    051:37-38  rattrapage A UN COUP : WHERE u.sudo=1 AND uma.sudo_preset='none'
               -> les comptes crees APRES ne sont JAMAIS convertis

> **`users.sudo` ne confère plus rien sur aucune machine — ni par l'import, NI PAR LE GESTE DE RÔLE 3 que
> la caractérisation cite comme la référence bien gardée.** *Le seul chemin d'octroi vivant est la liste
> déroulante de préréglage de `manage_access.php`.*

**Donc E-130 n'est PAS « une escalade par fichier ».** *C'est une **interface de privilège qui mente dans
les deux sens** : elle montre accordé ce qui ne l'est pas, et le déploiement défait silencieusement ce
qu'elle affiche — **y compris pour un rôle 3 accomplissant le geste légitime.***

**Et le commentaire posé juste au-dessus de la branche décrit un cas que le schéma rend impossible :**

    # policy=None -> fallback bool users.sudo

*Un commentaire qui affirme plus que le code — la classe traquée tout au long de ce chantier, sur le
chemin même dont il s'agit.*

### ⚠ LA SÉVÉRITÉ N'EST PAS NULLE : ELLE EST DIFFÉRÉE — et elle décide de l'ORDRE

> **Le jour où quelqu'un répare `toggle_sudo.php` en écrivant aussi `sudo_preset`, tout compte portant
> `users.sudo = 1` obtiendrait `NOPASSWD: ALL` sur chaque machine qu'il atteint** — *les comptes importés
> sans garde inclus.*

    1. FERMER la colonne `sudo` a l'import   (role 3 + coercition + compte-rendu par ligne)
    2. SEULEMENT ENSUITE reparer le chemin d'octroi

**Réparer (2) avant (1) armerait par un correctif ce que le correctif venait empêcher.**

*C'est l'argument le plus fort pour l'issue (a), et il ne dit plus « aligner l'import sur le geste
dédié » — **le geste dédié est cassé aussi.*** **Il dit : fermer la porte avant de rebrancher le
courant.**

### Le fait intermédiaire, qui reste vrai : le déploiement RETIRE le sudo

**Avec `preset = 'none'`, c'est la DEUXIÈME branche qui tire — `remove_from_sudoers`.**

> **Un compte importé avec `sudo = 1` et sans ligne de préréglage ne se voit pas seulement refuser
> `NOPASSWD: ALL` : il se voit RETIRER le sudo à chaque déploiement.** *La base dit « accordé », la page
> l'affiche accordé, et la machine ne l'a pas.*

**Ce que ça retire à E-130** : *aucune règle `sudoers` n'atteint une machine aujourd'hui depuis un
`sudo=1` importé.* **L'urgence tombe.**

**Ce que ça ajoute** : *un privilège **accordé en base, contredit par le déploiement, et montré comme
accordé à l'écran**. Aucun test ne l'exerce, aucun écran ne dit qu'il ne fait rien — et il redevient
effectif au premier changement de la branche ou du collecteur.*

> **Un privilège inerte est pire qu'un privilège visible : rien ne le mesure.** *E-130 reste un défaut de
> moindre privilège et d'INTÉGRITÉ — ce n'est pas un chemin d'escalade vivant.*

**Réserve de cette mesure, à dire** : *elle est établie par LECTURE de la chaîne, sans l'exercer.* **Le
seul point de doute est un désaccord de type entre la clé `mid` de `sudo_policies` (issue de
`record.get('machine_id')`, une requête) et `self.machine['id']` (une autre).** *Les deux viennent d'un
`cursor(dictionary=True)` sur des colonnes INT, donc ils s'accordent — mais c'est une lecture, pas un
clic.*

### Les trois issues, telles que le plan les a écrites

    a) exiger le role 3 pour cette colonne
    b) la refuser a l'import
    c) la garder en l'etat

**Pourquoi ce n'est pas à moi** : *« Retirer une colonne d'un format de fichier documenté change un
contrat. »* **Une session précédente avait déjà refusé de trancher, et j'ai failli le faire par omission
en demandant un panneau.**

### Ma recommandation, à contredire — et sa FORME n'est pas tranchée

**(a) — exiger le rôle 3 pour cette colonne.** *Elle aligne l'import sur le geste dédié sans retirer la
colonne du format, donc sans casser un contrat documenté. (b) casserait le contrat ; (c) laisse accorder
un privilège que le déploiement contredit.*

**⚠ Mais « exiger le rôle 3 » ne dit pas ce qu'un rôle 2 OBTIENT, et le legacy a déjà choisi la moins
bonne forme pour `role_id` :**

    ce que fait role_id   :156  if ($myRole < 3 && $roleId >= $myRole) { $roleId = 1; }
                                coercition SILENCIEUSE — l'importeur n'apprend RIEN
    ce qui existe deja    :143  $results['errors'][] = "Ligne $lineNum ($name) : doublon ignore"
                                un canal PAR LIGNE, deja utilise

**Forme recommandée, relevée par la session 3 : coercer `sudo` à 0 ET rendre compte par ligne**, avec la
machinerie qui existe déjà.

> **Un importeur qui croit avoir accordé `sudo` et ne l'a pas accordé prendra la décision suivante sur une
> croyance fausse.**

**Et un second arbitrage, plus petit, qui n'est pas dans ce dossier et qu'il faut ne pas perdre** : *la
coercition de `role_id` est correcte et MUETTE.* **Elle a le même angle mort. Je ne propose pas de la
changer ici ; je la nomme pour qu'elle ne se perde pas.**

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

---

# ⚠ AJOUT 12:50 — E-131 : cinq comptes portent DÉJÀ l'état que votre décision produirait

**Remesuré par la session 5, en base. Mon chiffre était hérité et faux dans les deux sens.**

    comptes ACTIFS                                    12   (je portais 10)
    `force_password_change = 1`                        8   (je portais 6)
    SANS adresse de courriel                           6
    LES DEUX A LA FOIS                                 5   <- personne n'avait celui-la

**Le flux de réinitialisation s'indexe sur l'adresse** — `WHERE email = ? AND active = TRUE`.

> **Cinq comptes actifs doivent déjà changer leur mot de passe et n'ont aucune adresse. La
> réinitialisation en libre-service ne les atteint pas, par construction.** *Ils exigent un geste
> d'administration.*

### Ce que ça change à la décision E-131

**J'avais recommandé : `email` obligatoire ET forcer `force_password_change`.** *Puis j'ai suspendu cette
recommandation faute de chemin de réinitialisation. Voici la version corrigée :*

    porter la reinitialisation est NECESSAIRE et NON SUFFISANT
      -> elle debloque 3 des 8 comptes forces ; les 5 autres restent hors d'atteinte

**Donc rendre `email` OBLIGATOIRE à l'import n'est pas un raffinement de confort : c'est ce qui empêche de
créer un sixième, un septième compte dans cet état.** *La recommandation `email` obligatoire est **renforcée**
par cette mesure ; la recommandation `force_password_change` reste conditionnée au portage de la
réinitialisation.*

**Et une question qui vous revient et que je ne tranche pas** : *les cinq comptes existants — les
raccroche-t-on (leur poser une adresse), ou les laisse-t-on à un geste d'administration ?* **Ce n'est pas
du portage : c'est une décision sur des comptes réels.**

---

## ⚠ Et deux défauts du legacy à NE PAS porter à l'identique — vérifiés par moi

### a) La limite de débit échoue OUVERTE, et sa justification n'a plus d'objet

    legacy/auth/forgot_password.php:53   } catch (PDOException $e) {
                                  :54       // Si la table n'existe pas encore …
                                  :55       return true;

**Toute `PDOException` désarme les 3 demandes/IP/heure** — *pas seulement une table absente : connexion
perdue, verrou, droits.* **Et la table EXISTE** (`mysql/migrations/016_password_reset_tokens.sql`), donc la
justification écrite ne couvre plus rien. **Le portage doit échouer FERMÉ.**

### b) L'oracle de TEMPS n'est pas refermé — le correctif a égalisé le MAUVAIS terme

    adresse INCONNUE  :115   password_hash(bin2hex(random_bytes(32)))
    adresse CONNUE    :87    password_hash($token)
                      + UPDATE + INSERT
                      :110   sendPasswordResetEmail(...)   <- SMTP SYNCHRONE dans la requete

**Un envoi SMTP dure des ordres de grandeur de plus qu'un bcrypt.** *Le correctif a égalisé le terme le
moins coûteux et laissé le plus coûteux d'un seul côté : **la branche « l'adresse existe » est nettement
plus lente**.* **L'énumération subsiste, inversée par rapport à l'implémentation naïve.**

> **C'est « le commentaire affirme plus que le code » dans sa forme la plus retorse : la mesure qu'il
> décrit est RÉELLE, elle porte sur le MAUVAIS TERME.** *Le message identique, lui, est bien là et
> correct — c'est le temps qui trahit.*

**Le portage doit sortir l'envoi de la requête** (`Mail::queue`). *Non exercé : le démontrer demanderait de
chronométrer des requêtes avec envoi réel, ce qui est un interdit du chantier.*

### ✅ Et ce qui est BIEN fait et se reprend tel quel

    jeton   32 octets · bcrypt en base, JAMAIS en clair · 1 heure
            re-valide AVANT l'ecriture (protection double-soumission)
            consomme, et TOUS les autres jetons du compte invalides
    message identique dans les deux branches, hors du `if`

**La table `password_reset_tokens` se reprend telle quelle.**

**⚠ Et un corollaire à connaître** : *un compte ayant perdu son mot de passe ET son second facteur n'a
aucun chemin, ni avant ni après le portage.*
