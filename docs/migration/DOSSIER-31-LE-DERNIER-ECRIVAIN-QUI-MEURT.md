# DOSSIER 31 — Le dernier écrivain qui meurt

**2026-09-05, 12:30 CEST.** *Sur la campagne Q3 de 0b (`f58cf38`), recoupée par une sonde
indépendante. La Q3 est CLOSE sur les treize fichiers multi-gestes.*

> **Une table dont le dernier écrivain part avec le legacy ne produit AUCUNE erreur. Le
> lecteur survit, continue de répondre, et présente comme complet un jeu de données qui
> s'arrête au jour de l'extinction.**

---

## 1. LA FAMILLE, MESURÉE DEUX FOIS PAR DEUX INSTRUMENTS DIFFÉRENTS

### Au niveau TABLE — exactement une

    login_history      ecrivains legacy 1 (`auth/login.php`)  ·  ecrivains portes 0
                       lecteurs portes  1 (`ExportRgpd.php`)
    5067 lignes · derniere ecriture 2026-09-05 08:42:44  ->  VIVANTE

    balayage : 65 tables candidates citees par le legacy
    temoin POSITIF : `users` ecrite par 6 fichiers portes -> la sonde voit le portage
    temoin ATTENDU : `login_history` sort bien de la classe

**Et le piège du nom voisin a été écarté** : *`login_attempts` n'est pas la même table —
colonnes `username/success/step` contre `user_id/user_agent/status`, 25 lignes contre
5067.* **L'export RGPD porté ne lit QUE `login_history`.**

### Au niveau COLONNE — deux, et la sonde par table ne pouvait pas les voir

    last_failed_login_at        ecrivains legacy 1  ·  portes 0   lue par les DEUX exports
    password_expiry_override    ecrivains legacy 2  ·  portes 0
    password_expires_at         lue par deux taches du planificateur (releve 0b)

    temoin POSITIF : `password` est bien vue comme ecrite par le portage

> **Une sonde qui demande « cette table est-elle écrite ? » répond OUI — parce que `users`
> l'est, abondamment.** *La colonne, elle, ne l'est plus. C'est pourquoi cette famille a
> traversé toutes nos passes précédentes.*

---

## 2. ⛔ POURQUOI C'EST LE PIRE CAS DE TOUTE LA CAMPAGNE

**Trois des quatre lecteurs survivants sont soit un LIVRABLE LÉGAL, soit un ENVOI DE
COURRIEL À DES HUMAINS.**

    login_history          -> section « historique de connexion » de l'export art. 20
    last_failed_login_at   -> les DEUX exports RGPD
    password_expires_at    -> deux taches du planificateur, dont une qui ENVOIE

**Et l'ironie est dans le fichier lui-même.** *`ExportRgpd.php:33-39` existe précisément
pour que les coupes s'annoncent :*

> *« Le legacy borne `login_history` à 1000 lignes et rien dans le fichier produit ne dit
> qu'il a été coupé : la personne reçoit un JSON qui se présente comme complet. »*
> **→ chaque section bornée porte désormais `_total`, `_exportees` et `_tronque`.**

**Aucun de ces trois marqueurs n'attraperait le gel.** *Rien n'est tronqué : la donnée
s'arrête, simplement. Le compteur `_total` dirait la vérité sur un ensemble qui a cessé de
croître.* **Le dispositif conçu pour empêcher exactement ce mensonge est aveugle à cette
forme-là.**

---

## 3. LES NEUF GESTES NON PORTÉS, EN DEUX FAMILLES — la Q3 est close

### ① LE LIBRE-SERVICE — 4 gestes (voir `DOSSIER-30`)

    changer son adresse de courriel     absent des DEUX cotes
    poser sa propre cle SSH             l'unique ecriture est gardee `role:3`
    fermer toutes ses autres sessions   DEGRADE, atteignable en repetant
    supprimer son propre compte         seule la suppression administrative existe

### ② LE DERNIER ÉCRIVAIN — 3 gestes, plus 2 isolés

    INSERT login_history                alimente l'export RGPD porte
    last_failed_login_at                alimente l'export RGPD porte
    password_expires_at                 lue par deux taches du planificateur
    ---
    le re-hachage bcrypt a la connexion (`login.php:165`)
      `password_needs_rehash` rend ZERO occurrence cote portage. Sans lui, un compte
      cree sous un cout ancien le garde indefiniment.
      ⚠ et le commentaire du legacy note que ce geste avait ete ANNONCE SANS ETRE FAIT
      avant d'etre corrige : **le portage a herite de la version corrigee du
      COMMENTAIRE et pas du GESTE.**
    password_expiry_override

> **Aucune des deux familles ne se voit d'une passe par table ni par route.** *La première
> parce que c'est l'ACTEUR qui distingue, et qu'il n'apparaît que dans la garde. La
> seconde parce que la colonne EST écrite — par le legacy.*

---

## 4. CE QUE J'ARBITRE, ET CE QUI REVIENT À L'EXPLOITANT

### ⛔ Arbitré : `legacy/auth/login.php` NE S'ARCHIVE PAS

**Il est le dernier écrivain de `login_history` et de `last_failed_login_at`, tous deux lus
par un livrable légal porté.** *Et c'est une FEUILLE : son interdit ne bloque aucun autre
fichier.*

### ⚖ À l'exploitant — et la question est simple à poser

**Pour chacune des trois données, une seule question :**

> **Cette donnée doit-elle continuer d'exister après l'extinction, oui ou non ?**

    OUI  -> il faut un ecrivain porte. Trois ecritures, dans le flux de connexion
            deja porte (`ConnexionController`). Petit.
    NON  -> il faut RETIRER la section de l'export et la tache du planificateur,
            sans quoi ils continueront de presenter comme vivant ce qui est fige.

**Ce que je ne veux pas, c'est la troisième issue — celle qui arrive toute seule** : *garder
les lecteurs, perdre les écrivains, et ne rien dire.* **C'est la seule des trois qui
produit un livrable légal faux, et c'est celle vers laquelle l'inaction nous mène.**

---

## 5. LA LEÇON D'INSTRUMENT, ET ELLE EST DE 0b

**Trois artefacts de sonde trouvés pendant la campagne, AUCUN ne s'est signalé :**

    `UPDATE (\w+)`             a lu « la table Zabbix » dans un LIBELLE de tableau
    `->update\(\s*\[(.*?)\]`   non gourmand : s'arrete au premier `]` INTERNE
    sonde par COLONNE          ne voit pas une suppression par ENTITE

> **« Une sonde muette et une sonde juste rendent le même silence — et sur les trois
> campagnes de ce jour, ce n'est jamais l'instrument qui m'a avertie, c'est toujours une
> contradiction avec autre chose. »**

**C'est l'argument le plus solide pour le protocole « apparier avant d'assigner » : il ne
rend pas les sondes meilleures, il MULTIPLIE LES OCCASIONS DE CONTRADICTION.**

---

# ⚠ UN QUATRIÈME MEMBRE (14:45) — et son lecteur est dans le fichier qui l'a déclaré morte

**`password_expiry_override`.** *Mesuré après la livraison de E-418.*

    ECRIVAINS PORTES        0
    lu par le PORTAGE       `MotDePasse.php:94`   pour CALCULER l'expiration
                            `ExportRgpd.php:102`  il figure dans l'export RGPD
    lu par le LEGACY        `verify.php:172,:187` · `profile.php:186` · `functions.php:228`
    ecrit par               `legacy/adm/api/update_user.php:49` — ET PAR LUI SEUL
    donnees                 0 compte sur 12 porte un override -> DORMANT

> **Le dossier recensait trois membres. Il y en a quatre, et le quatrième a été trouvé en
> cherchant si un fichier pouvait être archivé — pas en cherchant des membres.**

## Ce que la découverte apprend, et c'est une méthode

**La session qui a livré les trois premières écritures avait elle-même déclaré cette
colonne morte, dans son propre code :**

> *« Le legacy la calcule et l'enregistre, mais personne ne la lit. »*

**Elle a corrigé cette affirmation en découvrant un lecteur dans un AUTRE dépôt
(`backend/scheduler.py`, qui envoie un courriel). Le lecteur de la colonne VOISINE est
dans SON PROPRE FICHIER, deux lignes au-dessus du geste qu'elle venait de porter.**

    « personne ne la lit »  etait infere de  « pas le portail que je comparais »

> **Un « personne » se mesure sur les TROIS arbres, ou il ne se mesure pas.** *Et sa forme
> honnête n'est jamais « personne » : c'est « aucun lecteur dans legacy, portage et
> backend, à telle heure ».*

## ⛔ Conséquence sur l'extinction

**`legacy/adm/api/update_user.php` reste RETENU** — Q4 le déclare libre (0 appelant), Q3 le
retient. **Levée : porter l'écriture de `password_expiry_override`.**

**Et `legacy/auth/login.php` reste retenu pour une AUTRE raison** : Q3 est levée par
E-418, mais **Q4 lui trouve 7 appelants vivants** (`enable_2fa`, `forgot_password`,
`logout`…). *Il partira avec sa grappe d'authentification, pas avant.*

> **Deux fichiers annoncés archivables, deux verdicts contraires, et deux raisons
> différentes. Un fichier n'est archivable que si les QUATRE questions passent — et une
> seule session ne les voit jamais toutes.**
