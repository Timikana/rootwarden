# MISSION — finir les capacités non portées de RootWarden

**À donner telle quelle à une session de portage.** Établi par la session 8 (DSI délégué) le
**2026-09-02**, sur mesures horodatées.

> # ⛔ ARRÊTE-TOI. CE DOCUMENT EST FAUX, ET SA LISTE A ÉTÉ RÉFUTÉE DIX FOIS.
>
> **Corrigé le 2026-09-05 à 23:52 par la session 8, qui l'avait écrit.**
>
> **Le §2 ci-dessous liste des capacités « à porter ». DIX d'entre elles étaient DÉJÀ
> PORTÉES** — `fail2ban`, `politiques`, `serveurs`, `bashrc`, `sftp`, `groups`, le test de
> connexion, le cycle de vie, « créer un relevé planifié »… **Sur les dix, AUCUNE n'a été
> trouvée en la portant. Toutes l'ont été en la mesurant.**
>
> ## La cause, et elle n'était pas trouvable item par item
>
> **Cette liste a été bâtie en inventoriant les ENTRÉES DE MENU, puis elle est lue comme un
> inventaire de GESTES.** *Une entrée de menu et un geste ne sont pas la même population, et
> l'unité n'était nommée nulle part.*
>
> > **Dix relevés l'ont réfutée item par item ; UNE SEULE question sur la façon dont elle a
> > été fabriquée les réfute tous.** *Avant de vérifier le contenu d'un artefact de
> > planification, demande comment il a été fait.*
>
> ## Ce qui remplace cette liste
>
> **Il y a TROIS mécanismes par lesquels une capacité se perd, et ils demandent trois travaux
> différents :**
>
>     depreciation              -> ARBITRER ce qu'on garde   laisse un `_deprecated/`
>     arbitrage                 -> DECIDER                   laisse un dossier ouvert
>     sous-lot declare complet  -> FINIR + corriger la
>                                  declaration                ⛔ laisse une CASE COCHEE
>
> **Les deux premiers laissent une trace qu'on peut chercher. Le troisième laisse un artefact
> qui dit « rien à voir ici ».** *Exemples mesurés : `/ssh-audit/backups` dans A2 et
> `/ssh-audit/trends` dans A1 — deux sous-lots marqués PORTÉS.*
>
> ## Et la CAUSE du troisième, qui est un défaut de processus
>
>     I1 PORTÉ `3c3fe98`    F1 PORTÉ `v1.38.0`    F3 PORTÉ `v1.38.4`
>
> **Toutes les déclarations de portage citent un COMMIT. Aucune ne cite un PÉRIMÈTRE.** *Le
> périmètre vit dans le découpage du module, écrit des jours plus tôt par une autre session, et
> **rien ne confronte les deux à la livraison**.*
>
> **RÈGLE POSÉE** : *une déclaration « PORTÉ » qui ne cite pas le découpage qu'elle prétend
> clore est un accusé de réception, pas une déclaration.*
>
>     forme exigee : « A1 PORTE `3c3fe98` — perimetre <doc>§<n>, N gestes, N cables »
>
> ## Ce que tu fais à la place du §2
>
> **Lis `docs/migration/DECISIONS-DSI.md`, entrées E-425 à E-440.** *Le travail restant y est
> décrit, et il n'est pas « porter des capacités » : c'est **finir des sous-lots déclarés
> complets et corriger les déclarations qui les couvrent**.*
>
> **Le §2 est conservé ci-dessous comme ARCHIVE** — pour qu'on puisse voir de quoi une liste
> fausse a l'air, et parce que ses §3, §5 et §6 (interdits, pièges, forme) restent valides.
>
> ---
>
> **L'avertissement d'origine, qui s'est vérifié bien au-delà de ce qu'il annonçait :**
>
> **⚠ CE DOCUMENT A DÉJÀ POURRI UNE FOIS, EN QUATRE HEURES.** *Son §2 listait « test de connexion » à
> porter — il l'était depuis sept jours — et son §3 interdisait le « cycle de vie », porté et joignable
> depuis le 26 août.* **Les deux ont été trouvés par des sessions qui ont vérifié avant d'exécuter.**
>
> **Donc : mesure avant de porter, même ce qui est écrit ici.** *Un document qui liste ce qui reste à
> faire est exactement le genre d'artefact qui devient faux sans que personne ne le touche — c'est le
> défaut que ce chantier a payé cinq fois, et celui-ci ne s'en exempte pas.*

---

## 0. LIS D'ABORD, DANS CET ORDRE

1. `docs/migration/PLAN-DE-MIGRATION.md` **en entier** — le §8 est un catalogue de pièges dont chacun a
   coûté une régression ;
2. `docs/migration/MODULE-CAPACITES-RESTANTES.md` — **l'inventaire, 16 capacités, chacune portant son
   objet** ;
3. `docs/migration/DECISIONS-DSI.md` — les arbitrages déjà rendus. **Ne rouvre pas ce qui est tranché.**

---

## 1. L'ÉTAT, MESURÉ — ne le refais pas, il est daté

    menu            32 / 32 entrees portees — plus une seule ne mene au legacy
    capacites       16 inventoriees :  10 portables MAINTENANT (11 - le test de connexion,
                                   deja porte, mesure le 2026-09-02)
                                        4 exigent l'arbitrage de l'exploitant
                                        1 est une decision deja prise (politique en lecture seule)
    legacy          159 fichiers .php metier encore SERVIS, 13 dossiers en place
    LOT             164 executions · 2550 PASS · 1 FAIL (defaut de CHARGE, suite saine seule)
    non pousses     259 commits, qui n'existent que sur cette machine

> **« 32/32 » compte la NAVIGATION, pas la CAPACITÉ.** *C'est l'erreur que l'exploitant a relevée, et
> elle vaut d'être retenue : un chiffre mesure un objet, et se lit comme s'il en mesurait un autre.*

---

## 2. CE QUE TU PORTES — **DIX**, par risque croissant

**Aucune n'exige un mot de l'exploitant. Commence par le haut.**

| # | capacité | module | ce qu'elle touche |
|---|---|---|---|
| 1 | **apparier les 5 catalogues non vérifiés** | `bashrc` `fail2ban` `politiques` `serveurs` `sftp` | **rien** — lecture pure |
| 2 | **créer un relevé planifié** | `ssh_audit` | écrit en base |
| 3 | **créer un groupe** | `groups` | écrit en base, **jamais une machine** |
| ~~4~~ | ~~**test de connexion**~~ | `serveurs` | ⚠ **DÉJÀ PORTÉ** — `serveur-tester` → `POST /server_status`, suite de 516 lignes. **Rien à porter.** Mesuré le 2026-09-02 |
| 5 | **import par fichier CSV** | `serveurs` | écrit en base |
| 6 | **afficher `sshd_config`** | `ssh_audit` | **lecture** SSH distante |
| 7 | **désactiver une jail** | `fail2ban` | modifie un service distant — *réversible* |
| 8 | **géolocaliser une adresse** | `fail2ban` | appel sortant, aucune machine touchée |
| 9 | **relever un serveur** | `ssh_audit` | **session SSH réelle**, lecture seule |
| 10 | **scan de dérive de masse** | `groups` | *le seul geste de masse sans arbitrage* : `drift_scan` **n'ouvre aucune session SSH** |
| 11 | **rouvrir les 2 capacités PERDUES** | `superv` | voir §4 — **ce n'est pas du portage, c'est une réparation** |

---

## 3. ⛔ CE QUE TU NE PORTES PAS — sans un mot explicite de l'exploitant

*Ces gestes installent, détruisent ou visent le parc entier sur des machines réelles.*

    ssh_audit   relever TOUT LE PARC     <- sa route n'accepte AUCUN machine_id :
                                            sa portee EST le parc, production comprise.
                                            Une fixture borne un argument ; elle ne borne
                                            pas une route sans parametre de portee.
    ssh_audit   MODIFIER `sshd_config`   <- le fichier qui decide de l'acces SSH
    groups      scan CVE de masse        <- session SSH par machine + courriel par machine a resultats
    fail2ban    installer · redemarrer le service
    wazuh       install · install_all · uninstall · restart · detect · group
    ssh         le declenchement du deploiement   <- c'est K4. Il a ete LANCE sur la
                                            PRODUCTION le 27/08 a 22:43, et n'a echoue
                                            qu'a la phase de dechiffrement — panne
                                            depuis REPAREE.
    serveurs    ~~cycle de vie d'une machine~~   <- ⚠ CORRIGE le 2026-09-02 : il est
                DEJA PORTE et JOIGNABLE. `POST /serveurs/{id}/cycle` ->
                `ServeursController::cycle`, gardee `role:2` + `perm:can_admin_portal`,
                formulaire rendu PAR MACHINE (serveurs.blade.php:265), transitions
                calculees cote serveur par `cyclesProposables()` — liste FERMEE.
                Son propre commentaire dit : « aucun de ces trois gestes n'est
                destructeur, ils sont reversibles par leur voisin » — SAUF
                « Retirer du parc », qui NE SE DEFAIT PAS.
                Rien a porter ; a savoir avant de croire qu'il est hors d'atteinte.

**Et les interdits permanents du chantier, sans exception** : ne joins **jamais** `srv-zabbix` (id 1,
`192.168.0.244`, PROD) · n'ouvre **jamais** `/adm/health_check.php` · ne touche pas `rw-test-user`
(id 14) · n'accorde pas `can_manage_iptables` à `rw-test-admin`.

**Si tu dois exercer un geste sur une machine, c'est la 3** : `OpenCVE-Test-OnPrem`, `192.168.0.2`,
serveur de test **dédié**, `pk=0` `sa=0` — *elle n'a rien à révoquer, et c'est une machine RÉELLE, donc
elle reproduit les pièges qu'un conteneur ne montre pas.*

---

## 4. ⚠ LES DEUX CAPACITÉS PERDUES — à réparer, pas à porter

| capacité | ce que la page AFFICHE | ce qui est VRAI |
|---|---|---|
| **modifier le jeton d'API de supervision** | *« reste sur l'ancien portail »* | **`/supervision/` rend 404.** Le legacy ne la sert plus |
| **rattacher un serveur à un profil** | *« depuis le tableau de déploiement, pas encore porté »* | exact côté portage, **et le tableau du legacy est archivé** |

> **La page envoie l'utilisateur vers un chemin qui n'existe plus.** *Ce n'est ni « portée » ni « à
> porter » : c'est fermée, et l'écran continue d'indiquer la sortie.*

**Deux issues, et l'une est un arbitrage produit — remonte-le, ne le tranche pas** : soit on porte la
capacité, soit on retire la phrase qui promet un chemin mort. **Ne laisse pas le libellé en l'état :
c'est la seule des trois options qui soit fausse.**

---

## 5. LES SIX PIÈGES QUI ONT DÉJÀ COÛTÉ, ET QUI SONT SUR TON CHEMIN

**1. Déclare tes manques par ce que ton JS APPELLE, jamais par les routes Laravel.** *Une capacité qui
passe par la passerelle n'a AUCUNE route Laravel* — `pare-feu` a déclaré absente une validation qu'elle
savait faire, pendant cinq jours, pour cette raison exacte.

**2. Avant de porter, vérifie que ce n'est pas DÉJÀ écrit sous un nom français.** `comptes-distants` et
`pare-feu` ont dormi cinq jours parce qu'on cherchait `remote_users` et `iptables`. **Cherche l'artefact
dans `laravel/`, pas la clé du menu.**

**2bis. ⚠ Et cherche aussi la COUCHE, pas seulement le nom.** *Une capacité peut être portée **sans route
backend et sans route de passerelle** : une simple écriture Laravel en base.* **Le cycle de vie des
machines a été compté absent parce que `grep /server_lifecycle` sur le JS rendait zéro** — il n'appelle
pas la passerelle, il fait `DB::table('machines')->update(...)`. *Chercher un chemin backend rend zéro
pour une capacité entièrement présente.*

> **Et l'artefact le plus fiable n'est ni la route ni le nom : ce sont les LIBELLÉS.** *`serveurs.php`
> porte quatre clés de résultat pour le test de connexion — `test_en_cours`, `test_en_ligne`,
> `test_hors_ligne`, `test_echec`.* **Personne n'écrit quatre messages de résultat pour un geste que sa
> page n'accomplit pas.**

**3. Ne recopie aucun prédicat de bornage.** `pourMisesAJour`, `Iptables::machines`,
`Machines::compteursPerimetre` existent — *trois implémentations d'une même règle finiront par diverger.*

**4. Un ensemble vide satisfait toute propriété universelle.** `[].every()` rend `true`,
`Math.max(...[])` rend `-Infinity`. **Distingue « zéro mesuré » de « je n'ai pas su lire »** — une base
injoignable n'est pas un parc vide.

**5. Contrôle que chaque classe CSS existe dans `rw.css` AVANT le premier rendu.** *PurgeCSS ne garde que
le vu*, et ce dépôt a payé **quatre fois** une classe absente qui ne lève aucune erreur — dont une
pastille à **1,06:1** de contraste, invisible avec un HTML parfaitement juste. **Mesure le style
CALCULÉ ; aucune assertion DOM ne voit ça.**

**6. `rw.css` est partagé** : annonce au Lead avant d'y écrire.

---

## 6. LA FORME, NON NÉGOCIABLE

- **i18n FR/EN dans le MÊME commit**, jeux de clés **comparés** — pas « ajoutés » ;
- **`data-rw="…"`** sur chaque région que tu veux pouvoir asserter ;
- **captures à 1920, 1400 et 390** dans `tests/e2e/screenshots/<module>/` — **REGARDÉES**, pas seulement
  prises : *une assertion DOM ne voit ni un pavé illisible ni une pastille invisible* ;
- **jamais d'écriture dans l'arbre pendant qu'un LOT tourne** — `ps -ef | grep rejouer-lot` **avant** ;
- **committe par CHEMINS** (`git commit -- <chemins>`), jamais par l'index : **l'index est partagé entre
  sept sessions**, et un commit a déjà emporté les fichiers d'une autre ;
- **aucune mention d'IA** nulle part — ni code, ni commit, ni doc ;
- **`version.txt` + CHANGELOG + doc + i18n** déroulés avant chaque commit de fonctionnalité.

---

## 7. CE QUE JE VEUX EN RETOUR

1. **ce que tu as porté**, et **ce que tu n'as PAS porté avec la raison**, dit aussi nettement ;
2. **tes captures**, envoyées et regardées ;
3. **et si une capacité ne peut pas être rendue honnêtement, ne la porte pas et dis-le.** *Moins plutôt
   que faux — un onglet complet et menteur coûte plus cher qu'un onglet incomplet et franc.*

> **Le portage des pages est fini. Ce qui reste est le portage des GESTES, et c'est là que le legacy
> survit** : 159 fichiers répondent encore, dont `documentation.php` et sa console d'API, joignable tant
> qu'elle est servie.
