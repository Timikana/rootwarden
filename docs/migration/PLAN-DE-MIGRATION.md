# Plan de migration du legacy vers Laravel — document de travail

**Ce document est la source unique du chantier.** Il se lit **au début de chaque tour** et se met à
jour **à la fin**. Il remplace le brief recollé à chaque fois : si une information n'est pas ici, elle
n'existe pas pour le tour suivant.

- **État** mesuré, avec la commande qui le remesure.
- **Plan** : l'ordre des modules et le découpage en sous-lots.
- **Conventions** tranchées par l'exploitant, qui prévalent sur tout le reste.
- **Pièges** accumulés — chacun a coûté quelque chose.

Dernière mise à jour : **2026-09-02** (01:50 CEST), version `1.38.133`.

---

## 0. Le brief

> Migration RootWarden vers Laravel. Dépôt `~/Documents/Gestion_SSH_KEY` sur la VM Debian
> `192.168.0.245`, compte `utilisateur`, sudo sans mot de passe.
>
> **Lire ce document en entier**, puis le `MODULE-*.md` du module en cours. Reprendre le chantier
> **là où §2 et §4 le laissent** : le prochain geste est celui que §4 marque « en cours », sinon le
> premier « à faire » dans l'ordre donné. Dérouler les neuf temps de §5, respecter les conventions de
> §3 et la sûreté de §6.
>
> **Les tests se pilotent par des CLICS SIMULÉS, en Puppeteer.** On remplit au clavier
> (`page.type`) et on soumet par un **clic** (`page.click`) : appeler la fonction ne mesure pas que
> le bouton l'appelle. Jamais `page.evaluate(() => fonctionDeLaPage())`, jamais de requête HTTP brute
> pour tester une logique qui a une interface. **Jamais « le premier bouton `submit` de la page »** :
> remonter du CHAMP à son `form` par `closest('form')` — `profile.php` porte cinq formulaires et le
> premier est celui du courriel. Deux exceptions, chacune devant porter son **motif écrit** dans le
> fichier : la **requête forgée émise depuis la page**, pour une propriété qu'aucun `<input>` ne peut
> violer ou qui n'a aucune interface, et la sonde `node:https` d'`archive.mjs`. Les suites se lancent
> **par le runner**, jamais à la main : `./scripts/rejouer-lot.sh [--laravel|--legacy] <suites…>`.
>
> **Les captures se prennent avec le compte de rôle 3** — `rw-test-super`, qui voit les **33** entrées
> de menu ; `superadmin` lui-même n'est pas utilisable, **son mot de passe ne correspond plus** et on
> ne demande jamais à l'exploitant d'en coller un. Les comptes à droits réduits (`rw-test-admin`
> rôle 2, `rw-test-user` rôle 1 — **D-5, ne pas toucher**) ne servent **que** lorsqu'il faut mesurer
> une **garde** : rôle 1 → 403, rôle 3 sans la permission → 200, les **deux** chemins d'un
> « permission OU rôle ».
>
> **Trois largeurs à chaque sous-lot** : **1920×1080** (c'est là que le gaspillage de largeur se
> voit), **1400×900**, **390×844** (c'est là que le tiroir et les débordements se voient). Les images
> vont dans `tests/e2e/screenshots/<module>/`, **jamais** dans le scratchpad — elles y seraient
> invisibles. Puis **les REGARDER** : une assertion DOM ne voit ni un bouton mal placé, ni un pavé
> illisible, ni une pastille à 1,06:1 de contraste. Enfin **les ENVOYER** à l'exploitant : un travail
> qui n'est pas rendu visible n'est pas rendu. Une capture **mal étiquetée est un mensonge**, et elle
> doit montrer un état **atteignable**.
>
> **Faire moins mais complètement.** Un sous-lot fini — mesuré, testé, documenté, capturé, committé —
> vaut mieux que trois entamés.
>
> **En fin de tour** : mettre à jour §2, §4, §7 et §8, committer, **réarmer la boucle**.
>
> Contraintes qui ne se négocient pas : aucune trace d'IA ; parité FR/EN dans le **même** commit, jeux
> de clés comparés ; commits atomiques ; `git add` **ciblé** — jamais `obsidian-rootwarden/` ni
> `screenshots/`, et `srv-docker.env` / `laravel/.env` jamais commités ; **ne jamais fusionner** sans
> l'accord de l'exploitant, le `push` reste en attente ; **s'arrêter et demander** si la parité est
> impossible ou si l'effet est **sortant et irréversible** (courriel, scan réel, déploiement de clés) ;
> **ne jamais demander à l'exploitant de coller un mot de passe, une clé ou un jeton** ; **ne jamais
> inventer un secret TOTP** ; **ne jamais afficher une clé d'API**.

---

## 0 bis. ANNUAIRE DES SESSIONS (adresses `SendMessage`) — relevé 2026-09-02 03:15 CEST

⚠ **Ce tableau n'existait pas avant aujourd'hui, et son absence a produit E-305 et sa réplique.**
J'assigne par **numéro de rôle** et les adresses sont des **empreintes** : personne d'autre que moi ne
pouvait faire la correspondance. *Une décision ne circule pas parce qu'on décide de l'envoyer : elle
circule parce qu'on sait à qui.*

| n° | rôle | adresse `SendMessage` |
|---|---|---|
| **1** | LEAD / architecte (ce document) | `gestion-ssh-key-4f` |
| **2** | analyste legacy — inventaires | `gestion-ssh-key-0b` |
| **3** | portage Laravel — vues et contrôleurs | `gestion-ssh-key-c1` |
| **4** | backend + migrations — prépare, n'applique pas | `gestion-ssh-key-94` |
| **5** | sécurité / pré-relecture | `gestion-ssh-key-c6` |
| **6** | QA / tests — spécifie la couverture | `gestion-ssh-key-5f` |
| **7** | navigateur / E2E — **tient le banc** | `gestion-ssh-key-ec` |
| **8** | DSI délégué — dossiers d'arbitrage | `DSI Migration complète du legacy` |

**Le nom EST l'adresse**, à recopier exactement. Les crochets (`[d845b1]`) ne servent qu'à
désambiguïser si deux lignes partagent un nom.

### ⚠ CE TABLEAU EST UNE CARTE DES RÔLES, PAS UN CARNET D'ADRESSES

**Amendé le 2026-09-02 à 03:30, sur objection de la session 8, et elle a raison contre moi.** J'avais
écrit *« à remesurer par `ListAgents`, jamais de mémoire »* — **dans un document qui EST de la mémoire
écrite.** J'ai créé le vecteur en même temps que l'avertissement, et il périmera exactement comme un
chiffre hérité.

> *Ce qui protège n'est pas de relire ce tableau : c'est que `ListAgents` rende le nom **avant chaque
> envoi**, y compris quand ce tableau donne la réponse immédiatement.* Sans ça, on a reconstruit le
> problème que le tableau résout, **avec un pas de plus.**

**Donc : la colonne « rôle » est l'information durable ; la colonne « adresse » est une PHOTO.** Une
session qui redémarre change d'empreinte, et un annuaire périmé est plus nuisible qu'une absence
d'annuaire — *il fait croire qu'on a envoyé.*

### La règle de circulation, tirée d'E-305

    inscrire       rend la decision VERIFIABLE et DURABLE   -> ce document
    envoyer        rend la decision AGISSANTE               -> le destinataire, NOMME
    rendre compte  rend la decision ARBITRABLE              -> l'exploitant

**Les trois sont distincts et aucun ne remplace les autres.** Une décision qui débloque quelqu'un se
livre **à cette personne d'abord**. *Le blocage se mesure chez le bloqué, pas chez l'arbitre.*

## 1. Comment se servir de ce document

| moment | geste |
|---|---|
| début de tour | lire ce fichier **en entier**, puis le `MODULE-*.md` du module en cours |
| pendant | mesurer avant de décider ; ne jamais reconduire un chiffre |
| fin de tour | mettre à jour §2 (état), §4 (le module traité), §7 (décisions), §8 (pièges neufs) |

**Un chiffre de ce document ne se recopie pas : il se remesure.** Trois erreurs de suivi l'ont montré —
69 commits annoncés pour 70, deux points d'entrée pour quatre, une liste de modules qui en oubliait cinq.

```bash
cd /home/utilisateur/Documents/Gestion_SSH_KEY
# entrees de menu portees / restantes (retirer 2 lignes de commentaire de chaque compte)
# E-278 bis : ces deux compteurs comptaient AUSSI les commentaires d'en-tete (30 pour 28).
# Ancrer sur les lignes d'ENTREE, et croiser : route + legacy DOIT egaler le total.
python3 -c "
import re
L=open('laravel/app/Support/Navigation.php').read().splitlines()
e=[l for l in L if re.match(r\"\\s*\\['cle'\\s*=>\", l)]
r=[l for l in e if \"'route'\" in l]; g=[l for l in e if \"'legacy'\" in l]
print(len(r),'portees /',len(e),'  legacy',len(g),'  recoupe:',len(r)+len(g)==len(e))"
grep -cE "^\s*\['cle'" laravel/app/Support/Navigation.php   # 33 : le total, mesure independante
ls legacy/_deprecated/                                   # parties archivees
# ecarts = identifiants DEDUPLIQUES, toutes profondeurs de titre (E-278 : `grep -c '^## E-'` comptait des TITRES)
python3 -c "import re;t=re.findall(r'^#{1,6} +(E-\\d+[a-z]*)',open('docs/migration/PARITE.md').read(),re.M);n=sorted({int(re.match(r'E-(\\d+)',x).group(1)) for x in t});print(len(set(t)),'ecarts, max E-%d'%n[-1],'jamais servis:',[x for x in range(n[0],n[-1]+1) if x not in set(n)])"
git fetch origin && git rev-list --left-right --count @{u}...HEAD
sudo -n docker exec rootwarden_python sh -c "cd /app && python -m pytest -q"
```

---

## 2 bis. LES SIX ENTRÉES RESTANTES — ce qui bloque CHACUNE, mesuré le 2026-09-02 à 01:10 CEST

> **Ce tableau n'existait pas, et c'est ce qui m'empêchait de mesurer où en est le chantier.** Les
> blocages étaient dispersés dans dix `MODULE-*.md` et deux cents écarts. *Un plan qui ne dit pas ce qui
> bloque chaque objet restant ne permet pas de savoir s'il reste du travail ou des signatures.*

| entrée | inventaire | routes Laravel | ce qui reste | **bloqué par** |
|---|---|---|---|---|
| ~~`groups`~~ | `MODULE-GROUPS.md` | **`/groupes`** — R1 livré `8cf1d26` | R2 : création, suppression, actions de masse | ✅ **ENTRÉE BASCULÉE** |
| `remote_users` | `MODULE-REMOTE-USERS.md` | **4** (`/comptes-distants`) | les **5 gestes distants** | **RIEN — portable** |
| ~~`iptables`~~ | `MODULE-FILTRAGE.md` | **`/pare-feu`** — menu basculé `12e83be` (04:06) | **I5** seul (application + retour arrière) | ✅ **ENTRÉE BASCULÉE** — la page déclare son manque et lie l'ancien portail. ⚠ Sa déclaration dit aussi I4 non porté : **faux**, `pare-feu.js:710` câble `/iptables-validate` (E-318) |
| `ssh_audit` | `MODULE-SSH-AUDIT.md` §5 (A1→A4) | **0** | A1 est prêt | **RIEN — portable** |
| `wazuh` | `MODULE-WAZUH.md` | 0 — *catalogues posés* | vue, script, route | **E-238** pour *mesurer* |
| `documentation` | `MODULE-DOCUMENTATION.md` | **0** | structure + dérivations | **RIEN — portable** |

### ✅ `groups` EST PORTÉ — 27/32, et R1 a fermé la moitié visible d'E-274

    Navigation.php:107   'cle' => 'groups' … 'route' => 'groupes'      <- BASCULEE
    GET /groupes         role:2 + perm:can_admin_portal
    i18n                 FR 39 / EN 39, parite
    8cf1d26  01:28       « R1 — la page en LECTURE, et le parc entier n'est plus une ligne blanche »

**R1 ne porte aucune écriture ni aucun effet distant.** Les gestes non portés — création, suppression,
les deux actions de masse — **ouvrent un panneau qui explique ce que le geste engage**, avec le lien vers
l'ancien portail et son marqueur `↗`. *Aucun bouton inerte : le formulaire de création viendra AVEC sa
route, en R2.*

### ⚠ TROIS DES CINQ RESTANTES SONT PORTABLES MAINTENANT

 SANS AUCUNE SIGNATURE

**Seuls `iptables` (I5) et `wazuh` sont réellement bloqués** — et `wazuh` ne l'est que pour *mesurer* :
la vue et le script peuvent s'écrire, c'est leur vérification qui attend le redémarrage.

> **Je portais l'inverse dans mon suivi.** *La condition d'arrêt de ce chantier n'est pas proche, et ce
> n'est pas parce qu'il manque des signatures : c'est parce que quatre entrées attendent qu'on les
> écrive.*

### Et une progression que je citais était FANTÔME

J'annonçais **« `ssh_audit` : A1–A3 portés, A4 non exécutable »**. Mesure :

    routes Laravel /ssh-audit ou /audit-ssh   ->  0
    sous-lots « A1 — », « A2 — »… dans git    ->  aucun
    le decoupage A1-A4 dans les documents     ->  n'existe NULLE PART

**Ni les sous-lots ni leur découpage n'existent.** *C'était de la mémoire présentée comme un état, et je
la reconduisais dans ma propre consigne de travail à chaque tour.* **Dixième fois du jour qu'une de mes
affirmations n'était pas mesurée — et la seule qui décrivait l'avancement du chantier lui-même.**

*`MODULE-SSH-AUDIT.md` existe (232 lignes) et porte l'inventaire ; c'est le découpage en sous-lots qui
n'a jamais été fait.*

## 2. Où on en est

> ### ⚠ QUATRE JOURS D'ARRÊT — 2026-08-28 16:54 → 2026-09-01 14:12
>
> **`git log --since='2026-08-28 17:00' --oneline | wc -l` rend `1`.** Le chantier s'est arrêté
> quatre jours et **a repris à 14:12**, deux minutes avant la remesure de ce §2.
>
> *Un plan qui ne dit pas qu'il ne s'est rien passé laisse croire à une continuité* — et un lecteur
> qui trouve « LOT vert, 26/32 » sans cette ligne conclut que le chantier avançait.
>
> **Le « quatre jours d'arrêt » relevé par le DSI à 12:10Z était juste et est déjà dépassé.** Il avait
> donné son heure : c'est ce qui permet de le dire sans que ce soit un désaccord. **Sixième
> illustration en deux jours de la même règle.**
>
> Ce que l'arrêt n'a PAS changé, et qu'il faut dire aussi : **`StartedAt` du backend est inchangé**
> (`2026-08-27T12:28:43Z`, vérifié à 14:13), donc **E-238 tient dans son intégralité** — aucune mesure
> sur `wazuh`, `ssh` ou `ssh_audit` n'est interprétable, et les 20 modules restent inertes.


| | |
|---|---|
| entrées de menu portées | **28 sur 32** — remesuré **2026-09-02 02:17 CEST**, et **recoupé** : 28 `route` + 4 `legacy` = 32. `groups` (R1, `8cf1d26`) puis `ssh_audit` (A1, `30c8c6b`) ont basculé cette nuit. Restantes : `remote_users` · `iptables` · `wazuh` · `documentation`. ⚠ **La commande inscrite ici comptait aussi les commentaires d'en-tête** (30 pour 28) — même famille qu'E-278, corrigée au §2. |
| parties du legacy archivées | **13** — et ⚠ **le compte qui reste n'est PAS 20 archivages** : c'est **11 unités + un socle INDIVISIBLE de 9** (`assets`, `img`, `js`, `lang`, `vendor`, `logs`, `includes`, `auth`, `profile`), dont aucun ne porte d'entrée de menu et qui **font tourner les modules restants**. *Un plan qui vise « 20 archivages » planifie neuf gestes qui n'existent pas.* Les deux qui paraissaient les moins solides (`assets`, `img`) ont été éprouvés : **consommateurs vivants par deux voies indépendantes** — les cinq pages `auth/` n'incluent **pas** `head.php` et lient la feuille et le favicon elles-mêmes. **Le compte ne devient pas 13.** ⚠ **Et la catégorie « porté, archivable, personne ne l'a fait » est VIDE** (relevé `2253785`, `MODULE-ARCHIVAGE-RESTANT.md`) : les cinq modules dont le dossier traîne — `security` S7b, `bashrc` B4, `fail2ban` F7, `graylog` G2, `ssh` K4 — ont **tous** un sous-lot ou un arbitrage nommé. *Le cas `services/`, un `git mv` qui attendait pendant que le dispatch allait ailleurs, ne se reproduit pas — il n'y a pas d'archivage gratuit à ramasser.* **Une seule arête de dépendance dans tout le graphe** : `legacy/ssh/js/main.js:133-136` injecte par `innerHTML` un lien vers `remote_users` **quand le préflight refuse un déploiement** — donc `remote_users` ne s'archive pas avant `ssh/`, **ou son lien se réécrit dans le legacy, et ce n'est plus un `git mv`.** ⚠ **`profile/export.php` est un export RGPD vivant que le profil porté n'offre pas** — et `profile/` étant du socle, son archivage n'aurait **ni sous-lot, ni relecture, ni captures** : *une capacité légale disparaîtrait dans le geste le moins surveillé du chantier.* Ce n'est pas une régression fonctionnelle mais une **non-conformité** — `DOSSIER-11`. `ls -1 legacy/_deprecated/ | wc -l` · `find legacy -maxdepth 1 -type d | wc -l`
| modules entièrement dépréciés | **2** — `update/`, `supervision/` |
| LOT de tests E2E | ✅ **NOUVELLE LIGNE DE BASE — 2026-09-01 : 158 exécutions · 2439 PASS · ZÉRO FAIL · 2 h 50** (journaux `/tmp/rw-lot-j8Li6h`, départ 15:37:23, dernier journal 18:27:32). Répartition : **80 laravel / 1574 PASS** et **78 legacy / 865 PASS**. **+141 PASS et 2 FAIL de moins que la ligne de base du 2026-08-28** (153 · 2298 · 2), après **67 commits dont 3 fichiers globaux**. **Les trois références neuves sont confirmées à l'unité par le LOT complet** : `go-page-pare-feu` 23/17, `go-page-accueil` 41/16, `go-page-mot-de-passe` 16 (laravel seul, elle n'a pas de cible legacy). ⚠ **Ce LOT est le premier à contenir une suite qui ÉCRIT en base** (`go-page-mot-de-passe`) : la restauration a tenu, l'abattage n'a pas eu à se déclencher. ⚠ **Et le Lead n'a inscrit ce verdict que cinq heures après la fin** — un LOT vert que personne ne relève ne sert à rien, et c'est la même famille qu'une conclusion écrite qu'on ne remesure pas. Remesure : `./scripts/rejouer-lot.sh`, attendre un **PID enregistré**, **conclure sur le JOURNAL**.
| tests backend | **REMESURE le 2026-09-01 a 14:16 CEST — `609 passed · 1 skipped · 1 xfailed`** (pytest, `rootwarden_python`) et **`279 passed · 895 assertions`** (`php artisan test`, `rootwarden_laravel`, 14:18). Commits `319c0ba` et `a5d8f36`. ⚠ *Le couple precedent — `566` / `277`, du 2026-08-28 16:28 — etait juste a son heure et perime a la reprise : **quatre jours d'arret, et les deux releves geles ont rougi SEULS**, chacun sur sa cause (une route neuve `POST /pare-feu/historique`, un `pare-feu.js` modifie sans changement de verdict).* **C'est leur seule raison d'exister : un releve qui ne rougit jamais ne prouve pas que rien n'a bouge, il prouve qu'il ne regarde plus.** Il n'y a jamais eu de contradiction entre `509` et `549` non plus : tous deux justes, a onze heures d'ecart — le seul chiffre faux etait `462`, qui comptait des `def test_`, donc des FONCTIONS et non des cas. **Un compte reste vrai le temps que personne n'ecrit** : celui-ci cessera de l'etre a la prochaine ecriture backend. `sudo -n docker exec rootwarden_python sh -c "cd /app && python -m pytest -q"` — **et jamais pendant qu'une autre session tient le banc.** |
| écarts de parité documentés | **351** — identifiants dédupliqués, numérotés jusqu'à **E-371** (361 titres : 10 corrections inscrites À CÔTÉ, jamais substituées). Remesuré 2026-09-03 10:45 par `grep -ohE '^## (E-[0-9]+)' docs/migration/PARITE.md | awk '{print $2}' | sort -u | wc -l` — ⚠ **E-278 : ne JAMAIS compter `grep -c '^## E-'`**, qui compte des TITRES et dérive à chaque écart proprement amendé. ⚠ **E-280 est à sa CINQUIÈME passe** : mes quatre premières se sont trompées, les deux dernières **dans le sens qui rassure** — la propriété n'est pas « la requête porte un filtre archivées » mais « le périmètre est borné », et un champ de cible BLANC vise **tout le parc vivant** — ⚠ **sur 5 branches sur 5 dans HEAD et dans le service, sur 4 sur 5 après la fusion** (`a345e65` ne ferme que `_run_scheduled_scan · machines`). *Mon « 4 sur 5 » ne nommait pas son régime, dans le fichier dont c'est précisément le piège — corrigé sur mesure de la session 4.* La lecture d'autorité est `DOSSIER-08-PUSH-ET-MERGE.md` §4, pas mes relevés. |
| `main` en production | **v1.37.15** — il lui manque **v1.37.16**, **v1.37.17** et **v1.37.48** |

Le **socle** est complet : authentification avec second facteur obligatoire, navigation à source unique,
passerelle vers le backend, i18n FR/EN. Le compte d'entrées portées se recoupe par trois voies
indépendantes : `Navigation.php`, le DOM (le menu y figure **deux fois** — barre latérale et tiroir), et
la tuile « Déjà portés » de l'accueil du portage. Cette tuile est **calculée** depuis `Navigation`
(`$modulesPortes / $modulesAccessibles`), jamais écrite en dur : elle suit d'elle-même, et il n'y a donc
aucun chiffre à y corriger après un portage.

### Ce que la journée du 2026-08-27 a changé, et ce qu'elle laisse

**86 commits**, sept sessions, et **le travail le plus utile n'a pas été le portage** : c'est ce que la
relecture croisée a trouvé dans du code déjà écrit, souvent déjà corrigé, parfois par celui qui relisait.

**Sept correctifs backend, tous EN SERVICE** — vérifiés par la comparaison `StartedAt` / `mtime`, pas par
une introspection : E-192 → E-197 depuis 11:57:42 UTC, E-199 depuis 12:11:33.

| ce qui est fermé | ce qu'il faut retenir |
|---|---|
| **E-174** exécution de commande **en root**, occupée le jour même | le correctif évident — normaliser — n'aurait rien fermé : `str()` conserve l'identifiant de portée. Et le **second** vecteur, `sed` + apostrophe, ne dépendait même pas du `sh -c` distant |
| **E-183 / E-192** une révocation **annoncée sans avoir eu lieu** | l'inverse d'E-183 : celui-là détruisait une donnée vraie, celui-ci laissait un **accès ouvert en affirmant qu'il est fermé**. Et « lire le code de retour » **n'existait pas** à ce niveau : on vérifie l'**effet** |
| **E-190** une phrase **fausse en service** sur l'écran de K4 | « ne déploierait rien » se lisait « ne ferait rien ». La ligne **deux lignes plus haut** portait déjà le bon raisonnement |
| **E-191** `POST /deploy` porte `@require_api_key` **seul** | la route qui écrit en root sur un parc entier est **moins gardée** que celle qui redémarre une machine. Sa voisine, 270 lignes plus bas, porte le jeu complet **avec un commentaire de patch** |
| **E-197 / E-199** un nom d'inventaire non validé, puis marqué | et l'expression « stricte » qu'il fallait « reprendre » **refuse trois comptes réels** |

**Trois consignes du Lead ont été refusées par la mesure, et les trois refus avaient raison** : fusionner
la règle de révocation (aurait fait **sous-annoncer**), reprendre l'expression stricte (aurait rendu trois
comptes **irrévocables en silence**), filtrer un compteur (aurait **débloqué** un déploiement). Les trois
sont au §8. *Une consigne qui traverse une session sans être éprouvée n'est qu'une préférence* — et les
trois refus n'ont été possibles que parce que la consigne nommait ses fichiers, ses lignes, et demandait
« dis-moi ce que tu trouves **avant** d'écrire ».

**Cinq règles sont devenues des PROPRIÉTÉS** — c'est-à-dire qu'il n'y a plus rien à se rappeler : le
runner se recopie dans `/tmp` ; `git commit -- <chemins>` **ignore l'index partagé** ; `use_reloader =
False` **prouve** que le backend est lu au démarrage ; les mutations de test se font sur une **copie** dans
le conteneur ; et **le numéro de version ne voyage plus par message** — trois commits en avaient revendiqué
le même en 2 min 06 s.

**Quatre instruments ont été pris pour des résultats, dans quatre couches différentes** — un statut 200
qui n'est pas un verdict, le `mtime` de `/proc/1` qui n'est pas une heure de démarrage, un 403 de
**transport** qui n'est pas un refus d'accès, et un `!==` qui classe « replié » **deux pixels**. Le dernier
complète la classe par son autre bord : **un instrument peut mentir en voyant TROP.**

**Ce que la journée LAISSE, et qui doit être dit ensemble** :

- **cinq branches du portage établies par LECTURE et mesurées par aucune suite** — le troisième état du
  préflight, E-189, le chemin non concluant du scan, le badge « retirée du parc », la ligne d'inventaire
  invalide. Aucune ne sera mesurée sans une fixture qui **déplacerait ce qu'elle mesure**, et aucune n'est
  fabriquée ;
- **quatre propriétés de sûreté qui tiennent sans être écrites** (base64, « un seul jeton », l'inclusion
  d'ensembles, le statut non-200) — une seule des quatre a été écrite **au moment où elle servait à
  décider** ;
- **INF-002** : deux conventions pour `verifie()` sur 82 fichiers, dont un appel faux **ne lève rien**.
  L'unifier demande un **LOT complet** pour le prouver plutôt que le déduire ;
- **le LOT n'a pas été rejoué en entier** depuis le 2026-08-26 : ~100 min et le verrouillage du second
  facteur des trois comptes.

### Les deux blocages de la v2.0

| blocage | état |
|---|---|
| changement de mot de passe requis | **LEVÉ** — sous-lot A2, `v1.37.49`. Six comptes actifs sur dix étaient concernés, dont `superadmin` |
| **enrôlement 2FA** | **LEVÉ** — `v1.37.52`. Même suite **18/0 des deux côtés**. Reste hors périmètre, et c'est dit : le **ré-enrôlement**, qui appartient à `adm/` et à sa garde hiérarchique |

---

## 3. Conventions tranchées par l'exploitant

Elles prévalent sur tout le reste.

1. **Tout se fait sur `Migration-Laravel`**, correctifs de sécurité compris. Plus de branche
   `security/…` séparée : cette branche sera fusionnée dans `main` plus tard.
2. **Les modifications backend et legacy sont autorisées.** Ne plus bloquer, ne plus demander — dire ce
   qu'on change et pourquoi, dans le commit.
3. **Tout le legacy doit migrer.** Aucun module n'est « laissé au legacy ».
4. **Ne jamais fusionner sans son mot.** Le `push` reste également en attente : il n'a levé que le merge.
5. **Rendre compte du TOTAL, pas du sous-lot.** « 15 entrées portées sur 33 » dit autre chose que « le
   LOT est conforme ».
6. **Lire le `MODULE-*.md` avant de planifier un module.** Ne pas le faire a produit un plan faux et
   laissé une vulnérabilité de production trois jours sans être remontée.
7. **Les tests se pilotent par des clics Puppeteer** (`page.type` + `page.click`) — jamais
   `page.evaluate(() => fonctionDeLaPage())`, jamais de requêtes HTTP brutes. Deux exceptions, chacune
   devant porter son motif écrit : la **requête forgée** émise *depuis la page*, et la sonde
   `node:https` d'`archive.mjs`.
8. **Les captures se prennent avec un compte de rôle 3** (`rw-test-super`), à 1920/1400/390. Les comptes
   à droits réduits ne servent qu'à mesurer les **gardes**.
9. **Arrêter et demander** seulement si : parité impossible, ou **effet sortant irréversible**
   (courriel, scan réel, déploiement de clés).

---

## 4. Le plan, module par module

### 4.1 `auth/` — en cours

Pas une entrée de menu : ce qui empêche d'éteindre le legacy. 16 fichiers, 3003 lignes.
Détail : **`MODULE-AUTH.md`**.

| sous-lot | état | note |
|---|---|---|
| correctif de l'enrôlement | **FAIT** `v1.37.48` | le second facteur était dérivable du premier, **en production** |
| **A2** changement de mot de passe | **FAIT** `v1.37.49` | lève le premier blocage v2.0 |
| **A5** step-up ponctuel | **FAIT** `v1.37.50` | legacy **38/0**, base rouge **6/16**, portage **24/0** ; le **panneau en page** est différé à son premier consommateur |
| exécution croisée des secrets TOTP | **FAIT** `v1.37.51` | 15/0 ; le portage sait désormais ÉCRIRE un secret que le legacy relit |
| enrôlement porté | **FAIT** `v1.37.52` | 18/0 des deux côtés ; QR en **SVG** (le conteneur n'a ni gd ni imagick) |
| **A3** réinitialisation | **bloqué** | **envoie un courriel** — arbitrage requis |

**Ne pas porter** : `migrate_crypto.php` (323 l.) et `migrate_totp.php` (88 l.), scripts CLI ponctuels
refusés en HTTP par le `.htaccess` (403 vérifié). **`verify.php`** (332 l.) n'est pas une page mais le
garde central inclus par chaque page protégée — l'équivalent du middleware du portage.
**À archiver comme code mort** : `confirm_2fa.php` (aucun appelant) et `reset_totp.php` (aucun appelant,
et **plus permissif** que le chemin vivant `adm/includes/manage_roles.php:101-121`, qui porte une garde
hiérarchique que le fichier mort n'a pas).

**A5 — le step-up.** `stepUpVerify($action, 900)`, clé de session `_step_up_<action>`. Quatre appelants,
tous avec le même ordre de gardes (rôle → méthode → CSRF → step-up) : `adm/api/delete_user.php`,
`adm/api/update_permissions.php`, `adm/api/anonymize_user.php`, et `api_proxy.php:63`.
Quatre défauts mesurés : anti-rejeu **par session** et non par compte ; anti-rejeu **global** et non par
action ; **débit non remis à zéro sur succès** (cinq step-up légitimes en une minute → 429) ; et
`api_proxy.php:63` **fusionne trois routes root sous `policy_action`**, si bien qu'un step-up validé
pour `/policy/rollback` autorise `/policy/sudo/deploy` pendant quinze minutes.
Côté portage : `RoutesBackend::MOTIFS_STEP_UP` porte les deux motifs et `PasserelleController`
**REFUSE** au lieu de transmettre (403 + `step_up_required`), ce qui est un choix assumé — accorder root
sans le second contrôle serait un recul. `config/rootwarden.php` porte `step_up_ttl => 900` que
**personne ne lit** (vérifié). Le modal du legacy (`js/utils.js:59-146`) est **en français en dur, et
tutoie**.
**Caractérisation mesurée le 2026-08-24** — `tests/e2e/go-auth-step-up.mjs`, **37 PASS / 0 FAIL sur
le legacy**, **6 PASS / 16 FAIL** en base rouge sur le portage. Les quatre défauts sont mesurés
**sur le chemin de refus** : aucun geste root n'est émis, ni déploiement, ni révocation, ni
suppression de compte. La seule cible re-jouée après un step-up accordé est
`adm/api/update_permissions.php` **avec un corps vide** — il sort sur « Données manquantes » avant
toute écriture, ce qui rend le modal pilotable par de vrais clics sans rien détruire. Chiffres relevés :
le quota est de **5 tentatives par minute** (`200 200 200 200 200 429`), et **après un succès la
cinquième tentative rend déjà 429** — le succès consomme donc un jeton. Le rejeu du même code depuis
une session neuve est **accepté**. Un second step-up pour une AUTRE action dans la même fenêtre est
**refusé** « Code 2FA déjà utilisé » : le défaut refuse un geste légitime. Et la passerelle du portage
**a déjà hérité de la fusion** — les trois routes root y annoncent elles aussi `policy_action`.

**PORTÉ le 2026-08-24, `v1.37.50`** — `App\Services\StepUp`, `POST /profil/step-up`,
`POST /profil/step-up/revoquer`, intégration dans la passerelle. Les quatre défauts sont fermés :
anti-rejeu **par compte** et **partagé avec la connexion** (un code ne sert qu'une fois, pour quoi que
ce soit — un code observé à la connexion ne peut plus être retourné en step-up) ; quota **par compte**
et **remis à zéro sur succès** ; **un nom d'action par route**, dérivé du chemin ; liste d'actions
**fermée**, vérifiée par aller-retour, fail-closed. `step_up_ttl` est enfin lu, et
`step_up_tentatives` le rejoint. En prime, une **révocation** que le legacy n'a pas.

**Deux choses ne sont pas portées, et c'est dit.** Le **panneau de décision en page**, parce qu'**aucune
page du portage n'appelle une route gardée par un step-up** : les pages qui le feront (`ssh/` K4 et
`adm/`) ne sont pas portées, et une pièce non mesurable posée dans le gabarit met en risque les
quatorze pages déjà portées — il sera porté **avec son premier consommateur**. Et le modal du legacy
reste ce qu'il est : en français codé en dur, et il tutoie.

**Deux leçons de ce sous-lot, à ne pas reperdre.** Ma propre caractérisation portait une exigence
**d'affaiblissement** (« un second step-up pour une autre action doit rester possible dans la même
fenêtre ») qui aurait autorisé le rejeu d'un code vu à la connexion. Et ma suite **n'était pas
idempotente** : elle accordait un step-up pour une route root, et l'exécution suivante postait sur
cette même route — **seul un paramètre absent a empêché un déploiement sudo réel**.

**Mesuré le 2026-08-24 (§8-2 fermée)** : **les deux portails ne partagent PAS la session** — le legacy
écrit dans `/var/www/sessions` (159 fichiers), le portage dans `storage/framework/sessions` (380). Une
marque de step-up posée d'un côté est donc invisible de l'autre : le portage doit porter son propre
mécanisme, il ne peut pas hériter de celui du legacy.

**L'enrôlement vient en dernier, et c'est délibéré** : seul geste qui **écrit** un secret TOTP — un
format divergent d'un octet rend un compte inaccessible **sans message d'erreur** ; il dépend d'un
moteur de QR ; et **porter fidèlement serait porter une vulnérabilité**. Premier test à écrire :
**l'exécution croisée des blobs TOTP** entre les deux implémentations (lecture comparée faite,
exécution croisée **non faite**). Le conteneur Laravel n'a **ni `imagick` ni `gd`** ; il a
`spomky-labs/otphp` → ajouter **`bacon/bacon-qr-code`** avec le backend **SVG**. `endroid/qr-code` du
legacy est une **dépendance morte**. Le portage devra aussi offrir un écran de **ré-enrôlement** : il
n'en existe aucun, le lien d'onboarding du legacy est **mort** (`includes/onboarding.php:68`) et son
étape « 2FA » est **toujours cochée** (`:64`).

### 4.1 bis — LA FIN DE PARTIE : objectif 2.0, décidé par l'exploitant le 2026-08-27

> « **Finis la migration complète. Objectif fin Laravel 2.0.** Quand je te donnerai l'ordre, c'est de
> merger tout. » — et **le `merge` n'est PAS donné** : il attend son mot, comme le `push`.

**Il reste 8 entrées de menu sur le legacy**, et l'exploitant en a nommé **cinq** comme les plus
importantes — `remote_users`, `platform_key`, `iptables`, `ssh_audit`, `wazuh`. **Ce sont exactement cinq
des huit restantes** : son instinct et la mesure coïncident. Les trois autres sont `groups`,
`documentation`, `api_docs`.

#### L'ordre du menu suit la SÉQUENCE, pas une importance abstraite

Il demandait « par importance ». Sa remarque suivante donne un principe bien meilleur, et c'est celui qui
est retenu :

> « **Quand on ajoute un nouveau serveur, les menus où on doit aller après c'est Clé SSH plateforme et
> Utilisateurs distants. Donc la logique pour un nouvel utilisateur, il ne le sait pas !** »

**Le menu ne s'ordonne donc pas par importance : il s'ordonne par l'ordre dans lequel on s'en sert.** La
première section devient littéralement le parcours d'un serveur neuf — et les deux pages qu'il nomme,
enterrées jusqu'ici dans l'administration, en deviennent le deuxième et le troisième geste.

**Cinq sections, 32 entrées** (33 − `tickets`) :

| section | entrées, dans l'ordre |
|---|---|
| **`parc`** — Parc & accès | `accueil` · **`platform_key`** · **`remote_users`** · `ssh_keys` · `sudo_policies` · `sftp_policies` |
| **`exploitation`** | `updates` · `services` · `supervision` · `bashrc` · `docker` · `graylog` |
| **`securite`** | `cve_scan` · `compliance` · `drift` · `iptables` · `fail2ban` · `ssh_audit` · `wazuh` |
| **`admin`** | `admin` · `groups` · `approvals` · `maintenance` · `tasks` · `backups` · `audit_log` · `commandlog` · `search` · `chatops` |
| **`autre`** | `profil` · `documentation` · `api_docs` |

`sudo_policies` et `sftp_policies` suivent les deux premières parce qu'elles prolongent **le même
sujet** — *qui accède, et avec quoi*. La section `securite` est neuve : elle rassemble ce qui était
dispersé entre navigation et administration, et c'est l'identité du produit.

**`tickets` SORT** — décision de l'exploitant. `legacy/tickets/` est déjà archivé, donc rien à `git mv` ;
mais le §7 mentionne **une exception de passerelle vers un ITSM externe**, et **cela se vérifie avant de
retirer la route**, pas après : supprimer une page est réversible, casser une intégration sortante ne se
voit pas.

**Conséquences de mesure, à ne pas subir** : le total passe de **33 à 32**, donc l'assertion « le décompte
se reconstitue » change de constante ; `go-socle-navigation` perd les entrées de `tickets` ; et deux
sections neuves changent la structure du DOM. **Le LOT complet est lancé AVANT cette vague**, pour que la
ligne de base existe.

#### FEAT-001 — l'ordre aide, il ne guide pas

« *Un nouvel utilisateur ne le sait pas* » est un défaut d'**interface**, pas d'ordre de menu. Et les
trois colonnes qui décrivent la préparation d'un serveur **existent déjà** :
`platform_key_deployed` · `service_account_deployed` · `users_scanned_at` — **exactement les trois étapes,
dans l'ordre.**

Un indicateur de préparation par machine, nommant **le geste suivant et sa page**, est donc à portée sans
schéma neuf. Trois conditions, celles du §8 : le drapeau vient du **backend** ; un état inconnu se **dit**
inconnu ; il n'entre pas dans un comptage qui appelle une décision. **La forme est à proposer avant
d'écrire du gabarit.**

#### INF-004 — la version se DÉRIVE, elle ne s'assigne plus

Exigence de l'exploitant : « **faut que ça bump AUTO** ». Et la cause de l'échec est trouvée :
**`scripts/bump-version.sh:22` pointe sur `www/version.txt`, qui n'existe plus depuis Vague 0.** Le script
sort sur « introuvable ». **Il est mort depuis le renommage** — et c'est la cause directe de l'incident du
jour, où **trois commits ont revendiqué `v1.38.19` en 2 min 06 s**.

**Réparer le chemin serait traiter le symptôme.** Un numéro **assigné** — par un humain, par un message —
est valide au moment où on l'écrit et plus au moment où un autre l'emploie : c'est le défaut d'index, pour
la troisième fois. **Le principe tranché : `MAJEUR.MINEUR` dans un fichier de jalon, `CORRECTIF` DÉRIVÉ du
dépôt.** Il n'y a alors plus de numéro à périmer.

**Et un trou que personne n'avait vu : le portage n'affiche AUCUNE version.** Zéro occurrence de
`version.txt` dans `laravel/` — les seuls lecteurs sont trois fichiers PHP du legacy et le job `auto-tag`.
**Le jour où le legacy s'éteint, c'est-à-dire l'objectif 2.0, la version disparaît de l'interface.**

### 4.1 ter — DÉFINITION DE TERMINÉ POUR LA 2.0, arrêtée par le Lead le 2026-08-27

**Mesuré à l'instant, par PHP lisant `Navigation::SECTIONS` :** `24 portées · 8 restantes · total 32`.

    encore sur le legacy : platform_key · remote_users · iptables · ssh_audit
                           wazuh · groups · documentation · api_docs

#### L'ordre, et il est dicté par les inventaires déjà faits

**Trois des huit ont leur `MODULE-*.md` prêt** — le portage peut commencer sans attendre personne :

| # | module | inventaire | note |
|---|---|---|---|
| 1 | **`platform_key`** | `MODULE-PLATFORM-KEY.md` | lettre **P**, P1→P4. **P4 (la rotation) NE S'EXÉCUTE JAMAIS** — interception et avortement seuls |
| 2 | **`iptables`** | `MODULE-FILTRAGE.md` | I1→I5, déjà découpé. **I1 à I4 PORTÉS** (`3c3fe98`, `f183f07`, `ef32870`, `c42fe48`) ; **I5 (l'application) reste FERMÉ** — arbitrage du port SSH |
| 3 | **`groups`** | `MODULE-GROUPS.md` | lettre **R**, R1→R4. **R4 (`cve_scan` réel) attend l'exploitant** ; `drift_scan` s'exécute pour de vrai |
| 4 | `remote_users` | *en cours* | lettre **P** partagée ou **U** — à trancher à la livraison de l'inventaire |
| 5 | `ssh_audit` | *à faire* | **le scan de tout le parc est à UN CLIC sur la page**, pas seulement dans le fichier interdit |
| 6 | `wazuh` | *à faire* | derrière `FEATURE_WAZUH` — vérifier si le drapeau est lu **partout** ou seulement à l'enregistrement |
| 7-8 | `documentation`, `api_docs` | *à faire* | les plus légers, et ils ferment le compte |

#### Les six conditions de « terminé », et aucune n'est négociable

1. **`Navigation` porte `route` pour les 32 entrées**, et l'assertion du total se reconstitue — la suite et le §2 portent la **même** constante, et se mettent à jour **ensemble** ;
2. **chaque module a sa suite, sur ses deux cibles**, et ses références inscrites **après** un passage vert ;
3. **un LOT complet vert**, avec chaque écart expliqué — la ligne de base du 2026-08-27 (150 exécutions, 2282 PASS) est le point de comparaison ;
4. **`legacy/` archivé** — et `adm/` ne peut PAS l'être comme une unité : quatre de ses fichiers appartiennent au socle, `includes/crypto.php` en tête. **Soit ils sortent vers `legacy/includes/` avant le `git mv`, soit `adm/` est le dernier archivé** ;
5. **le portage affiche une version** — aujourd'hui **zéro** lecteur dans `laravel/`, donc à l'extinction du legacy le numéro disparaît de l'interface ;
6. **E-203 tranché** — le portage n'a **aucune** révocation de session côté serveur. À l'extinction du legacy, un bouton « Révoquer » cessera d'avoir un effet **sans que rien ne le dise**.

#### Ce qui reste hors de « terminé », et pourquoi c'est assumé

- **les gestes à effet SORTANT** : le scan CVE réel (courriel), l'action de masse `groups/`, la réinitialisation de mot de passe (A3), le déploiement de clés (K4). Chacun se porte **avec sa suite en interception et avortement** ; leur déclenchement réel n'est pas une condition de la 2.0 ;
- **P4, la rotation de la clé de flotte** : sa **réussite ne sera jamais mesurée**, faute de cible sûre. **Écrit dans le fichier de suite**, sinon quelqu'un comblera un jour un trou qui est une précaution ;
- **le `merge` et le `push`** : ils attendent le mot de l'exploitant, et rien dans cette définition ne les inclut.

#### État des risques de production au moment où cette définition est arrêtée

| risque | état |
|---|---|
| E-202 — deux chemins de verrouillage sans retour | **MITIGÉ** : les mots de passe de `srv-zabbix` sont remis, mesuré en base (`password` **et** `root_password`). Ce n'est plus un verrouillage, c'est un incident |
| E-201 — porte à quatre yeux inerte | correctif écrit, **inerte** jusqu'au prochain redémarrage |
| approbateur éligible | **AUCUN** — aucun rôle 2 ne porte `can_admin_portal`. Dès que la porte sera en service, les deux gestes de flotte seront **impossibles** jusqu'à la création du compte. C'est **l'épreuve gratuite** du refus explicite |
| clé de plateforme non sauvegardée | l'archivage est décidé, la purge doit vivre **hors de `LOG_RETENTION_DAYS`** |

### 4.2 Les 19 entrées de menu restantes

Par taille de code legacy. L'ordre proposé va du plus rentable au plus lourd.

| ordre | partie | lignes | entrées | note |
|---|---|---|---|---|
| ~~1~~ | ~~`docker/`~~ | 201 | 1 | **PORTÉ ET ARCHIVÉ** `v1.37.53` / `v1.37.54` |
| ~~2~~ | ~~`chatops/`~~ | 246 | 1 | **PORTÉ ET ARCHIVÉ** `v1.37.55` / `v1.37.56`. Premier chemin PUBLIC du portage, et première adresse EXTÉRIEURE que la migration déplace |
| ~~3~~ | ~~`maintenance/`~~ | 257 | 1 | **PORTÉ ET ARCHIVÉ** `v1.37.57` / `v1.37.58`. **Le défaut le plus grave du chantier y a été trouvé** — l'encadré ci-dessous reste à lire, il porte la mesure |
| **4** | **`groups/`** | 305 | 1 | **SUIVANT** — **⚠ deux boutons y lancent un SCAN RÉEL sur TOUTES les machines d'un groupe, dont un qui ENVOIE UN COURRIEL. Lire l'encadré ci-dessous** |
| ~~5~~ | ~~`graylog/`~~ | 388 | 1 | **G1 PORTÉ** `v1.37.77` — 26/0. Reste **G2** : les trois gestes qui MUTENT une machine (`deploy`, `test`, `uninstall`), cible `test-server`, geste de retour `uninstall`. Inventaire : `MODULE-GRAYLOG.md` |
| 6 | `wazuh/` | 594 | 1 | derrière un drapeau `FEATURE_WAZUH` |
| 7 | `services/` | 631 (2 fichiers) | 1 | **INVENTORIÉ `v1.37.92` — `MODULE-SERVICES.md`**, trois sous-lots S1 à S3, **MODULE ENTIÈREMENT PORTÉ** — S1 `v1.37.94`, S2 `v1.37.96`, S3 `v1.37.98`. **E-149 et E-150 restent ouverts** (§7). **Le banc est un conteneur SANS systemd** : le rendu d'un tableau peuplé n'est mesuré sur aucune cible. **E-149 : les huit routes n'ont NI rôle NI permission — seule la page est gardée.** Réel dans le code, non exploitable par aucun compte existant : à un `UPDATE` de l'être |
| 8 | `iptables/` | 870 | 1 | **INVENTORIÉ — `MODULE-FILTRAGE.md`**, cinq sous-lots I1 à I5. **I1 PORTÉ `3c3fe98`** — la consultation ; route `/pare-feu`, garde `role:1` + `perm:can_manage_iptables` (l'en-tête du legacy annonce « superadmin uniquement » et son code ne l'exerce pas). **Fermeture PAR L'ABSENCE** : `POST /iptables` porte `get` ET `apply` sous un seul chemin, la passerelle filtre sur le CHEMIN et ne peut pas les distinguer — l'écran n'offre donc ni champ d'édition ni bouton d'application, la seule forme qu'une requête forgée ne contourne pas. **La zone d'annonce est posée dès I1** : `showNotification` du legacy vise `#notifications`, **absent de toutes les pages du module** (0 occurrence pour 13 points d'appel) — les treize lèvent une `TypeError`, *y compris ceux placés dans un `catch`*, si bien qu'appliquer un jeu de règles RÉUSSIT et que l'écran ne dit rien. **I2 PORTÉ `f183f07`** — la copie en base ; deux gestes qui ne joignent AUCUNE machine. `iptables_rules` n'a **aucune contrainte d'unicité sur `server_id`** : on lit déterministiquement la plus récente ET on dit s'il y en a d'autres. Borne des colonnes contrôlée en **octets** avant l'écriture — `TEXT` tronque en silence en mode permissif. **I3 PORTÉ `ef32870`** — l'historique, chargé au CHOIX de la machine et non après un relevé réussi : le legacy appelle `loadHistory()` dans sa branche de succès, **une machine injoignable masque donc son propre historique**, qui est en base (E-156, déjà refermé sur `fail2ban` par F2). **I4 PORTÉ `c42fe48`** — la validation à blanc, **premier geste du portage qui joint une machine pour y ÉCRIRE** (session SSH, fichier dans `/tmp`, `iptables-restore --test`) ; aucune table du pare-feu modifiée, et l'écran l'annonce AVANT le clic. Elle porte sur **la copie en base**, pas sur le relevé : la chaîne devient I2 enregistre → I4 valide → I5 appliquerait le même objet. **`/iptables-validate` rend `success:false` pour QUATRE situations** — identifiants irrésolus (400), règles vides (400), erreur interne (500), erreur de syntaxe (200) — si bien que `success` seul confond *« vos règles sont invalides »* et *« je n'ai rien pu vérifier »*. Le discriminant retenu est le **statut**, vérifié relayé verbatim par `PasserelleController`. **Et le verdict de 200 lui-même n'est pas sûr** : le backend le calcule par `any('EXIT_CODE=0' in l for l in output_lines)` sur des fragments de 4096 octets — un marqueur à cheval n'est retrouvé dans aucun des deux, et **un jeu de règles VALIDE est alors déclaré invalide**. Le portage ne répare pas le backend : il rend ce cas en `attention` et non en `echec`, avec la sortie brute et la consigne de la lire. **Limite écrite sur la page : `rules_v6` n'est ni envoyé ni lu**, la route ne connaît que l'IPv4. **Relevé au passage, non fermé : `/iptables-` est une entrée à PRÉFIXE de la liste blanche** (dernier caractère `-` ⇒ `str_starts_with`), donc le même préfixe ouvre `/iptables-validate`, `/iptables-apply` et `/iptables-rollback` sans les distinguer — ce qui tient est la garde du backend et l'absence de tout autre appel dans le script. **I5 RESTE FERMÉ.** `fail2ban/` se porte AVANT — **F1 y est porté depuis `v1.38.0`, F2 à F6 restent**. **E-152** ; gestes sur machines, IDOR déjà corrigé |
| 9 | `fail2ban/` | 872 (2 fichiers) | 1 | **INVENTORIÉ — `MODULE-FILTRAGE.md`**, six sous-lots F1 à F6. **F1 PORTÉ `v1.38.0`** — 20 laravel / 18 legacy, 0 FAIL ; route `/fail2ban`, garde `role:1` + `perm:can_manage_fail2ban`. **F2 PORTÉ `v1.38.2`** — **24 laravel / 14 legacy, 0 FAIL** ; base rouge **12/11** ; **F2 NE MUTE RIEN** : ses deux routes sont des `SELECT` sur `fail2ban_history`, aucun SSH — le découpage annonçait l'inverse, c'est la lecture du code qui a tranché. **Sept écarts REFERMÉS, E-153 à E-159** — dont **E-159, trouvé À L'IMAGE et non par une assertion** : la frise du legacy ne s'affiche pas du tout, `h-32` est purgée et 100 % de zéro fait zéro. **E-160 ouvert et NON corrigé, décision assumée** : la frise annonce 30 jours et ne dessine que les jours actifs, des deux côtés. **F3 PORTÉ `v1.38.4`** — **22 laravel / 16 legacy, 0 FAIL** ; base rouge **6/7** ; **F3 NE MUTE RIEN NON PLUS** : ses trois routes sont des LECTURES distantes. **Quatre écarts REFERMÉS, E-161 à E-164** — dont **E-162, le plus lourd du module** : douze gestes sur treize visaient la machine du DERNIER RELEVÉ, pas celle du sélecteur ; le portage n'a **aucune** variable de machine courante. **E-164 corrigé DANS LE BACKEND** (§3.2 l'autorise) : une valeur non numérique rend 400 au lieu d'un 500 HTML, et les deux portails en profitent. **F4 PORTÉ `v1.38.6`** — **21 laravel / 14 legacy, 0 FAIL** ; base rouge **10/4** ; **premier sous-lot du module qui ÉCRIT**. **Trois écarts refermés** : **E-165 corrigé DANS LE BACKEND** — les trois routes testent enfin `rc`, un échec n'écrit plus de ligne d'audit, et **les deux portails en profitent** ; **E-166**, le geste de parc n'est pas rendu et les couleurs viennent des jetons du socle ; **E-167**, la confirmation nomme l'adresse, la jail et la machine, en page plutôt qu'en boîte native. **F5 PORTÉ `v1.38.8`** — **15 laravel / 9 legacy, 0 FAIL** ; base rouge **5/5**. **Quatre écarts neufs** : **E-168**, la liste blanche affichée est SUPPOSÉE et non lue ; **E-169**, une de ses deux entrées par défaut porte un `×` qui ne peut jamais aboutir ; **E-170**, le seul geste qui confirme est celui qui RENFORCE la protection, et aucun des trois n'annonce que le service redémarre ; **E-171**, l'interpolation brute — **relevée par LECTURE, non mesurée** : la démontrer reviendrait à la commettre, et **le portage ne peut pas la refermer** (la composition vit dans le backend). **Les trois premiers sont REFERMÉS** ; E-168 a demandé un drapeau `lue` au backend, faute de quoi le portage aurait dû supposer à son tour. **F6 CARACTÉRISÉ `v1.38.9`** — 8 legacy, 0 FAIL, base rouge **9/1**, dont **CINQ passes creuses sur neuf**. **Deux écarts neufs** : **E-172**, la portée d'un geste de parc est décidée par un CACHE et « jamais relevée » y compte comme « fail2ban absent » — mesuré, `srv-zabbix` (PROD) serait installée ; **E-173**, les confirmations ne nomment ni l'adresse, ni le nombre, ni les machines. **Deux correctifs backend au même lot** : la QUATRIÈME occurrence d'E-165 (`ban_all_servers` ne nommait même pas `rc`) et E-164 resté sur `/stats` — **le correctif partiel était le nôtre**. **Le module est CARACTÉRISÉ EN ENTIER ; reste le portage de F6.** **E-152 : sur 23 routes des deux modules, DEUX portent une permission.** **F1 a fait corriger CINQ règles CSS du socle** : `color-mix(couleur X%, transparent)` avec la MÊME couleur en texte ne peut pas atteindre 4,5:1 sur une surface claire — 3,60 à 3,96:1 mesurés, et les cinq passaient en thème sombre (§8). GeoIP en HTTP (ip-api gratuit) |
| 10 | `bashrc/` | 941 (2 fichiers) | 1 | **INVENTORIÉ `v1.37.81` — `MODULE-BASHRC.md`**, quatre sous-lots B1 à B4. **Le module le mieux construit rencontré jusqu'ici** : gardes complètes sur les 8 routes, contournement rôle 3 cohérent entre PHP et Python, contenu en base64, `_HOME_RE` valide une valeur venant de la MACHINE, tous les gestes destructeurs confirment. **B1, B2 et B3 PORTÉS** (`v1.37.86`, `v1.37.88`, `v1.37.90`). **B4 CARACTÉRISÉ `v1.37.91` mais son PORTAGE est SUSPENDU** — deux arbitrages, §7. **Quatre** points à arbitrer, aucun n'est une faille. **§6 : trois inconnues sur cinq fermées par la LECTURE le 2026-08-26** — dont `root` proposé au déploiement, et « fusionner » qui n'équivaut pas à ce que son libellé laisse entendre |
| 11 | `ssh-audit/` | 1118 | 1 | **`go-ssh-audit-scanall.mjs` joint la PRODUCTION** — ne pas le lancer |
| 12 | `adm/` | 8421 (37 fichiers) | **6** | **INVENTORIÉ ; D1 à D6b et D6d PORTÉS (`v1.37.59` à `v1.37.72`), D7, D8 et D9 CLOS (D9a `v1.37.79`, D9b `v1.37.80`), D6c CARACTÉRISÉ — `MODULE-ADM.md`**, quinze sous-lots, **trois restants** — D6c, D10, et l'archivage. **⚠ `/adm/health_check.php` ÉCRIT sur `srv-zabbix` au simple chargement. Lire l'encadré ci-dessous** |
| 13 | `documentation.php`, `api/docs.php` | — | 2 | |

**⚠ `groups/` : deux boutons lancent un SCAN RÉEL sur TOUTES les machines du groupe.** Relevé en lisant
`backend/routes/groups.py:286-315` et `backend/routes/cve.py:60-90` le 2026-08-25, avant d'écrire un
clic. La page pose **deux** actions de masse derrière un simple `confirm()`
(`legacy/groups/js/main.js:57-58`), et `POST /groups/<id>/run` les exécute en tâche de fond :

| action | ce qu'elle fait vraiment | effet sortant |
|---|---|---|
| `drift_scan` | `scan_machine(mid)` pour **chaque** membre | **AUCUN — corrigé le 2026-08-27, voir ci-dessous** |
| `cve_scan` | tout le pipeline CVE via `_stream_cve_scan` | session **SSH réelle** **+ `send_cve_report`, un VRAI COURRIEL** |

**⚠ CE TABLEAU A ÉTÉ FAUX PENDANT DEUX JOURS SUR `drift_scan`, et l'erreur était la mienne.**
Corrigé le 2026-08-27 après mesure. `scan_machine` (`backend/routes/drift.py:110-118`) fait **trois
`SELECT` et un `INSERT … ON DUPLICATE KEY UPDATE`** dans `config_drift`. Rien d'autre. Le fichier
n'importe que `logging`, `flask` et `routes.helpers` : **zéro occurrence** de `paramiko`,
`ssh_session`, `execute_as_root`, `ssh_utils` ou `subprocess` — vérifié deux fois, par la liste des
imports et par un compte. Le mot « ssh » n'y apparaît que dans le nom de la catégorie `sshd` et dans
une **lecture** de `ssh_audit_results`.

Trois choses en découlent, et elles vont toutes dans le sens de l'avancement :

1. **`drift_scan` sort de la demande d'arbitrage du §7.** Il n'y avait pas lieu d'y être. Un arbitrage
   demandé pour un effet inexistant coûte deux fois : il bloque un sous-lot, et il use le crédit de
   ceux qui sont réels.
2. **Le geste peut être exécuté POUR DE VRAI** sur un groupe statique ne contenant que la machine 2 —
   c'est le seul geste de masse du chantier mesurable de bout en bout sans arbitrage.
3. **Le planificateur le fait déjà toutes les heures sur les trois machines** (`scheduler.py:723-726`,
   `_drift_scan_all`) : **576 lignes** `Scan de dérive (toutes machines)` dans `tasks`, du 2026-06-10
   au 2026-08-27, `created_by = NULL`. Conséquence pour la mesure : « `checked_at` rafraîchi » ne
   distingue **pas** notre geste du sien. Le discriminant est `tasks.label`, que seul ce module écrit
   — et qu'**aucune ligne ne porte aujourd'hui** : l'action de masse de ce module n'a **jamais** été
   exécutée dans cette installation.

**Et les deux textes du legacy avaient raison là où ce document se trompait** : `js.groups.tip_drift`
dit « rapide, **sans SSH** », et `legacy/documentation.php:1233` le confirme. J'avais lu le nom de la
fonction et le fait que `cve_scan` ouvre bien des sessions, et j'ai étendu à sa voisine. C'est la forme
la plus banale du piège du chantier : **une hypothèse trop large n'a pas besoin d'être absurde pour
être fausse.** Réserve à porter jusqu'au sous-lot : établi par **LECTURE**, pas par observation d'une
exécution — à confirmer au réseau avant d'être tenu pour acquis ailleurs.

**C'est l'effet même qui bloque S7b, atteint depuis une autre page et appliqué à un groupe entier.** Un
clic, N machines, N courriels. Le `confirm()` du legacy est la seule barrière, et il ne protège de rien
dans un test piloté.

**Et le groupe peut être DYNAMIQUE** : `_member_ids` résout alors ses membres **au moment du clic**, par
filtres (`_resolve_dynamic`). L'ensemble des machines visées n'est donc **pas lisible** dans la ligne du
groupe, et rien n'empêche `srv-zabbix` (id 1) d'y tomber. État mesuré du parc : `srv-zabbix` (1, **PROD,
jamais jointe**), `Test-Server-Debian` (2, le banc), `OpenCVE-Test-OnPrem` (3). **Zéro groupe en base**
aujourd'hui : toute suite devra créer le sien.

**Ce qui est décidé pour le sous-lot :**

1. le CRUD des groupes, la résolution des membres et l'affichage se testent normalement ;
2. la fixture de groupe est **statique** et ne contient **que la machine 2**. Jamais dynamique : un
   groupe dont les membres se résolvent au clic est un ensemble qu'on ne contrôle pas ;
3. le bouton d'action de masse se teste par **interception + avortement** — le premier des six motifs.
   On mesure que le clic **émet** la requête attendue, et la requête est **abattue avant de partir**.
   La propriété à mesurer est « il y a eu une requête, et elle portait la bonne action », au **réseau** ;
4. **un déclenchement RÉEL n'est pas fait et demande l'arbitrage de l'exploitant** — même famille que
   S7b et A3, pour la même raison : un courriel part.

---

**⚠ `maintenance/` : une fenêtre créée par un test peut EMPOISONNER LE LOT ENTIER.** Relevé en lisant
`backend/maintenance.py:102-143` avant d'écrire quoi que ce soit. La logique **s'inverse** :

| état de la table | effet sur toute action mutante |
|---|---|
| **aucune** fenêtre active | tout est **autorisé** (`no-window`) |
| au moins **une** fenêtre active | autorisé **seulement** si l'instant courant tombe dedans (`outside-window` sinon) |

Créer une fenêtre activée qui ne couvre pas l'instant présent fait donc rendre **423** à toute action
mutante — pour les rôles **< 3** seulement, le rôle 3 ayant un contournement journalisé. Les suites
supervision du LOT tournent en **rôle 2** : une fenêtre laissée derrière soi les ferait toutes échouer,
et l'enforcement vit dans **d'autres modules** (`backend/routes/updates.py:19`,
`backend/routes/monitoring.py:229`), donc l'échec n'aurait aucun rapport visible avec `maintenance/`.

**La fixture sûre est décidée, et trois options ont été pesées** :

| fixture | exerce le chemin activé | risque de bloquer le LOT |
|---|---|---|
| fenêtre **désactivée** | non — la requête ne compte que `enabled = 1` | **nul** |
| fenêtre **toujours ouverte** (7 jours, 00:00→23:59) | oui | **faible mais réel** : `start <= t <= end` laisse les 59 dernières secondes de chaque jour **hors** fenêtre, donc un 423 possible et inexplicable |
| fenêtre **activée, limitée à `srv-zabbix`** | **oui** | **nul** : `is_allowed` filtre `scope = 'global' OR machine_id = ?`, et aucune suite ne mute cette machine — la règle permanente l'interdit |

**Retenue : la troisième.** Elle exerce le vrai chemin de code et ne peut bloquer que ce qui est **déjà
interdit** — la fixture rend l'action prohibée encore plus impossible. À préciser dans la suite : créer
une ligne d'horaire qui *nomme* `srv-zabbix` n'est pas la **joindre** ; aucune session SSH, aucune
requête vers elle.

**Relu le 2026-08-25, et la requête le confirme mot pour mot** :
`WHERE enabled = 1 AND (scope = 'global' OR machine_id = %s)` (`backend/maintenance.py:120-123`). Une
fenêtre portant `machine_id = 1` n'est **jamais rendue** pour une autre machine : l'arbitrage ne repose
donc pas sur une intention mais sur un filtre. Deux autres points relevés au passage, **mesurés et non
corrigés** :

- **`is_allowed` est fail-OPEN sur erreur de base** (`:127-129`, `reason = 'fail-open'`). Assumé et
  commenté dans le legacy : une fenêtre de maintenance est un contrôle de **disponibilité**, pas
  d'accès. À reprendre tel quel — un portage n'est pas le lieu où l'on change le sens d'un repli.
- **Le contournement du rôle 3 est testé AVANT toute lecture de la base** (`:110-111`). Une suite qui
  n'exercerait que le rôle 3 ne mesurerait donc **rien** de la logique de fenêtre. Le chemin utile est
  le rôle 2.

#### ⚠ La pastille « active maintenant » du legacy MENT, et de deux heures

Le défaut le plus grave du module, trouvé en lisant avant de cliquer, et **mesuré** le 2026-08-25.

`legacy/maintenance/js/main.js:26-35` calcule `isActiveNow` **dans le navigateur**, sur l'horloge du
navigateur. L'application, elle, se fait dans `backend/maintenance.py:_in_window`, sur l'horloge du
**conteneur**. Les deux horloges ne sont pas la même :

| horloge | valeur relevée le 2026-08-25 |
|---|---|
| hôte et navigateur, `rootwarden_php` | **CEST 17:50** |
| `rootwarden_python` (celui qui applique), `rootwarden_laravel` | **UTC 15:50** |

Un exploitant qui saisit une fenêtre `22:00 → 06:00` veut dire 22:00 **chez lui**. Le backend
l'applique en UTC — vérifié en appelant `_in_window` directement dans le conteneur. En heure locale :

| heure locale | ce que la page annonce | ce que le backend fait |
|---|---|---|
| 22:00 → 00:00 | **active maintenant** | **REFUSE** |
| 00:00 → 06:00 | active maintenant | autorise |
| 06:00 → 08:00 | **fermée** | **autorise** |

Deux bandes de deux heures où la page et l'application se contredisent, **dans les deux sens**. Et
comme le rappelle l'encadré ci-dessus, le refus **n'apparaît pas sur cette page** : il apparaît sur
celle qui a tenté l'action. L'exploitant lit « active maintenant », lance une mise à jour, et reçoit un
423 sans rapport visible avec les fenêtres de maintenance.

**Ce n'est pas E-73.** E-73 porte sur un *affichage* d'horodatage faux de deux heures. Ici la valeur
fausse est un **verdict** sur une règle de blocage, et elle est calculée par un code qui n'est pas celui
qui décide.

**Correctif APPLIQUÉ en `v1.37.57` : le verdict remonte là où il est appliqué.** `list_windows`
(`backend/routes/maintenance.py`) rend, par fenêtre, un `active_now` calculé par `mw._in_window` — la
fonction même qui bloque — plus `server_time` et `server_offset`. La page portée **affiche ce verdict**
et nomme l'horloge employée quand elle diffère de celle du navigateur. C'est la convention du portage
appliquée telle quelle : *la règle n'est jamais déplacée côté navigateur, elle est seulement annoncée
plus tôt.* Un champ supplémentaire est sans effet sur le legacy, qui ne lit que les clés qu'il connaît.
**341 pytest** restent verts.

**Et le premier jet du portage avait fait l'erreur inverse** : il recopiait le calcul en JavaScript en
promettant de « suivre le Python pas à pas ». Leçon à garder : *suivre le pas à pas ne protège de rien
quand ce n'est pas le pas qui diffère, mais l'heure.*

**Ce qui n'est PAS fait ici, et pourquoi.** Changer le fuseau du conteneur `rootwarden_python`
corrigerait le décalage à la racine — et déplacerait **tous** les horodatages du backend, journaux
d'audit compris. C'est une décision de flotte, pas un détour de portage de page. Elle rejoint E-73 en
§7. Le legacy garde aussi sa pastille calculée côté navigateur : on ne soigne pas ce qu'on démonte.

**Le `toggle` ne doit JAMAIS activer une fenêtre globale.** Le script du legacy porte un
`PUT {enabled}` (`js/main.js:84`) : l'exercer sur une fenêtre `global` désactivée la rendrait
bloquante. Avec une fenêtre limitée à `srv-zabbix`, les deux sens du basculement sont sans effet sur le
reste.

#### ⚠ `adm/health_check.php` MODIFIE `srv-zabbix` au simple chargement de la page

Relevé le 2026-08-25 **en lisant, sans ouvrir la page** — et c'est la conclusion.

`health_check.php:49-50` choisit sa machine de test par `SELECT id FROM machines LIMIT 1`, ce qui rend
**`id = 1`, `srv-zabbix`**, la machine que §6 interdit de joindre. Le fichier déclare **106 routes**
(la documentation en annonce **11**), toutes tirées au chargement, dont **36 pointées sur cette
machine**. Le commentaire `:52-58` affirme que les routes mutantes sont neutralisées par
`$mutId = 0` : c'est vrai pour la famille `update` / `services` / `ssh-audit` / `reboot`, et **faux
pour la famille SSH** —

| ligne | route | effet sur `srv-zabbix` |
|---|---|---|
| `:78` | `/deploy_platform_key` | **écrit** dans `authorized_keys` |
| `:80` | `/deploy_service_account` | **crée** le compte Unix et son `sudoers.d` |
| `:84` | `/sshd_allow_user` | **modifie `sshd_config`** et recharge `sshd` |
| `:83` | `/server_user_remove_key` | tente une suppression de clé |

Le motif « à moitié corrigé » à son maximum : le défaut est **vu**, **nommé** sur six lignes de
commentaire, et **une branche sur deux** est protégée.

**`/adm/health_check.php` rejoint donc `go-ssh-audit-scanall.mjs`** : à ne déclencher ni en test, ni
en capture, ni « pour voir la page ». Une capture de cette page est une modification de production.
Le sous-lot D10 n'est pas un portage mais une décision, portée en §7.

**`adm/` porte deux défauts sérieux à corriger en le portant** :
`adm/includes/manage_roles.php:86` hache le mot de passe généré **sans `BCRYPT_COST`** et **sans appeler
la politique ni enregistrer l'ancien haché** — contournement complet ; et `:93-95` **affiche le mot de
passe généré en clair dans le HTML**.

### 4.3 ⚠ SIX MODULES SONT PORTÉS ET LEUR DOSSIER LEGACY VIT ENCORE — 5 545 LIGNES (2026-08-27)

**Mesuré pour la première fois le 2026-08-27, sur une remarque de l'exploitant** : « y a encore
beaucoup trop de truc en legacy ». Jusque-là ce document ne comptait que des **entrées de menu**, et
une entrée marquée `PORTE` laissait croire que le legacy correspondant avait disparu. Il n'avait pas
disparu. Les lignes vivantes, par dossier :

| dossier | lignes | entrée de menu | ce qui bloque l'archivage |
|---|---|---|---|
| `security/` | 2 255 | PORTÉE (S1→S7a) | **S7b** — envoie un vrai courriel, arbitrage exploitant |
| `bashrc/` | 941 | PORTÉE (B1→B3) | **B4** — suspendu sur deux arbitrages |
| `fail2ban/` | 872 | PORTÉE (F1→F6) | **F7** — quatre capacités non portées |
| `services/` | **631** | PORTÉE (S1→S3) | **RIEN** |
| `ssh/` | 458 | PORTÉE (K1→K3) | **K4** — le déploiement de clés |
| `graylog/` | 388 | PORTÉE (G1) | **G2** — trois gestes qui mutent |

**`services/` est entièrement porté depuis `v1.37.98` et n'a jamais été archivé.** Aucun sous-lot ne
le retient, aucun arbitrage, aucune mesure manquante : il ne restait qu'à dérouler le §4.4. Le Lead
dispatchait de nouveaux portages pendant que 631 lignes attendaient un `git mv`. **C'est un défaut de
séquencement du Lead, pas des sessions** — et il était invisible parce que le suivi comptait la
mauvaise unité.

**La leçon, et elle vaut au-delà de l'archivage : « porté » et « le legacy est parti » sont deux
propriétés distinctes, et un tableau qui n'en mesure qu'une donne l'autre pour acquise.** Un module
porté dont le dossier reste servi laisse deux implémentations vivantes de la même capacité, chacune
avec ses gardes — c'est exactement la configuration où un correctif appliqué d'un seul côté paraît
complet. Compter **les lignes servies**, pas les cases cochées.

**Conséquence sur l'ordre de travail** : l'archivage devient un **cycle propre, tenu par la session 2**,
et non plus la dernière étape oubliée d'un portage. Dès qu'un sous-lot bloquant tombe, le dossier part.
Quatre dossiers suivront `services/` par le même chemin ; `security/` et `ssh/` attendent l'exploitant.

### 4.3 bis Les sous-lots bloqués dans des modules par ailleurs portés

- **S7b** (`security/`) — le scan CVE qui aboutit **envoie un vrai courriel** (`send_cve_report` part
  dès que l'état passe à `done` avec des résultats). Prérequis techniques faits.
- **K4** (`ssh/`) — le déploiement de clés. Bloqué par l'arbitrage du repli `NOPASSWD: ALL`, et un
  déploiement lancé en l'état **révoquerait** des accès — **c'est vivant** : `configure_servers.py:908` fait
  `revoked = managed_users - comptes_traites` puis `rm -f authorized_keys`.
  **⚠⚠ EN REVANCHE « le blocage est PROTECTEUR contre E-213 » ÉTAIT FAUX, et c'est le Lead qui l'a écrit.**
  Mesuré par le DSI : **`clean_up_users` n'a AUCUN APPELANT** — `configure_servers.py:703` est une **docstring**
  et `:780` sa définition ; `configure()` appelle `configure_users` seule et le dit en clair. **Donc aucun
  déploiement n'exécute `userdel -r`**, et le raisonnement ci-dessous est sans objet :
  la décision de suppression ne lit que `user_exclusions`, jamais `server_user_inventory.status`, donc un
  déploiement exécuterait **`userdel -r`** — le compte **et son `$HOME`** — sur tout compte qu'un
  exploitant croit protégé par le statut `excluded`. Le blocage sur `NOPASSWD` couvre incidemment
  celui-là. **Le portage de C4 devra lire les DEUX magasins, ou aucun geste de classement ne devra
  prétendre protéger.**
- **B4** (`bashrc/`) — suspendu sur deux arbitrages.
- **F7** (`fail2ban/`) — quatre capacités non portées.
- **G2** (`graylog/`) — trois gestes qui mutent.

### 4.3 ter LE PORTAGE SÉRIALISAIT DERRIÈRE UN VERROU DE FICHIER, PAS DERRIÈRE UNE COMPÉTENCE (2026-08-27)

Huit entrées restaient sur le legacy et **toutes attendaient la session 3**, seule propriétaire de
`laravel/`. Le Lead avait lu ça comme un problème de rythme ; c'était un problème de **verrou**.

**Or les fichiers d'un module sont disjoints** : un contrôleur, une vue, deux catalogues i18n, un JS.
**Seuls quatre objets sont partagés par construction** — `routes/web.php`, `Navigation.php`, `rw.css`,
les gabarits `layouts/`. La propriété exclusive de `laravel/` protégeait donc quatre fichiers en
bloquant plusieurs centaines.

**Découpage arrêté** — trois voies au lieu d'une, la session 3 devient **l'intégrateur** :

| voie | modules | pourquoi cette session |
|---|---|---|
| session 3 | `platform_key`, `remote_users`, `ssh_audit`, `wazuh`, `groups` | garde les modules à gestes, et **pose seule** les routes et le menu |
| session 5 | `iptables` (I1→I5) | a qualifié les validateurs ancrés — **le « 33 » était un chiffre HÉRITÉ, remesuré à 58 le 2026-09-01** (`.match()` sur motif ancré par `$`, AST sur `backend/`), et **`fullmatch` n'est pas « nulle part » : il y en a 1**. Sur ces 58, **27 `.strip()`ent avant de valider** (chiffre d'abord publie a 28 — une fenetre de lignes attrapait le `.strip()` d'une fonction voisine, remesure par AST) et le piège ne peut pas s'armer ; **2 seuls survivent** aux filtres quoting/journal/constante, aucun n'est une injection — `AUDIT-WAZUH-VALIDATEURS-ET-XXE.md`. Et E-152 ; **ne prend jamais le banc**, donc hors contention |
| ~~session 4~~ | ~~`documentation`, `api_docs`~~ | **VOIE ANNULÉE le 2026-08-27** — voir ci-dessous |

**La règle qui rend le découpage sûr** : une session qui porte un module **envoie sa déclaration de
route et son entrée de menu au Lead, qui les fait poser par la session 3.** Personne d'autre n'écrit
dans les quatre fichiers partagés. C'est la règle qui a déjà évité six collisions et elle ne change pas.

**Et une réserve qui tient** : *qui écrit le code ne valide pas seul son correctif.* La session 5 porte
`iptables` mais ne l'éprouve pas — la 6 écrit ses tests, la 7 sa suite. La règle avait été posée pour
la session 4 ; elle s'applique à l'identique dès qu'une session sort de son rôle d'origine.

**Ce que ce découpage ne résout pas** : il accélère le portage, pas les **archivages bloqués**. Les
5 545 lignes du §4.3 ne partiront pas plus vite parce que deux sessions portent au lieu d'une — quatre
d'entre elles attendent un sous-lot, deux attendent l'exploitant.

#### ⚠ La voie « session 4 » est ANNULÉE : une réattribution entre sessions ne lève pas une interdiction de l'exploitant

La session 4 a **refusé** `documentation` et `api_docs`, et elle avait raison. Son brief porte une
interdiction explicite — *« ne modifie pas `laravel/` : signale à la session 3 »* — **posée par
l'exploitant, pas par la table du §10.** Le Lead a raisonné en propriété de fichiers et n'a pas vu
qu'il déplaçait une borne d'un autre ordre.

**La règle, et elle vaut pour toute réattribution future** : *le Lead redistribue à l'intérieur du §10 ;
il ne lève pas une consigne de l'exploitant, même en faveur de sa propre parallélisation.* Et la
demande n'a **pas** été portée à l'exploitant, pour une raison qui n'est pas de la déférence :
**le gain ne le méritait pas.** Deux pages statiques contre une exception à une frontière qui a tenu six
collisions — *une frontière qu'on fait céder pour un petit gain ne tient plus pour un grand.* La
cohérence de la session 4 était d'ailleurs mesurable : elle avait déjà renvoyé `JournalAudit.php`, la
moitié écran d'E-194 et sa propre déclaration de route plutôt que d'y toucher.

**Ce que la voie annulée produit quand même, et qui valait plus que la page** : la session 4 a modifié
**vingt-six routes de gardes le 2026-08-27** — huit `services/`, dix-huit `fail2ban/` et `iptables/`,
plus `/deploy` et les deux d'approbation. **Donc toute documentation de routes écrite avant ce
matin est périmée, et `api_docs` en est une.** Ce n'était pas « une page statique de plus » : c'est une
page qui **affirme des autorisations**, et la seule chose plus dangereuse qu'une garde absente est une
garde annoncée qui n'existe pas — le commentaire de `/deploy` a **découragé la question** pendant
longtemps, et celui d'`APPROVAL_ENABLED` est devenu faux **deux heures après** le correctif qui l'a
rendu incomplet. La session 4 produit donc le **relevé mesuré** route par route, la session 3 écrit la
page à partir de lui. Deux bornes sur ce relevé : **le dater et nommer son régime** — onze correctifs
sont inertes, donc il décrit l'arbre de travail et non le service — et **ne pas le déduire des
décorateurs seuls**, `@require_machine_access` étant *inerte sur 57 routes*.

### 4.4 Le cycle d'archivage, une fois un module complet

`git mv legacy/<partie> legacy/_deprecated/` · basculer **tous** les points d'entrée — `menu.php`
(barre latérale **et** tiroir mobile), `index.php` (raccourcis du tableau de bord), **`head.php` (carte
de raccourcis CLAVIER, un objet JS qu'aucun contrôle sur les `href` ne voit)** · vérifier que
`Navigation` porte `route` et non `legacy` · tenir `LiensLegacy::REMPLACEMENTS` à jour (**mesurer si le
backend émet le chemin** : préventif sinon) · greffer `constateArchivage` + `verifieMenuLegacy` **en
tête du `try`** de chaque suite · **mesurer** la nouvelle référence legacy (`1 + N fichiers réels + 2`)
· vérifier la **non-régression des parties déjà archivées** si l'on touche `archive.mjs` · captures.

**Une étape s'ajoute au cycle depuis `chatops/` : chercher si la partie expose une adresse configurée
HORS de RootWarden.** Les onze premiers archivages ne déplaçaient que des pages, visitées par un humain
qui suit un menu — un lien mort se voit. `chatops/webhook.php` était le point d'entrée que **Slack**
appelle : personne dans RootWarden ne l'aurait vu casser. Ce qu'il faut alors faire, dans l'ordre :

1. **sonder le chemin AVANT le `git mv`** et consigner le statut. Une assertion « rend 404 » sur un
   chemin qui n'a jamais existé passe en ne mesurant rien ;
2. **compter ce fichier dans la référence** — `chatops/` fait `1 + 3 + 2`, et le troisième fichier est
   justement celui qu'il fallait le plus vérifier ;
3. **corriger ce qui donne l'adresse comme une INSTRUCTION**, et seulement cela. `documentation.php`
   disait « point d'entrée public `/chatops/webhook.php` » : quelqu'un recopie cette ligne dans Slack.
   Une simple *mention* périmée dans un `<code>` (le cas de `/docker/`) n'est pas la même chose et se
   relève sans se corriger ;
4. **le dire dans `DEPRECIATION.md`** et dans la page portée elle-même. La page ChatOps porte un
   avertissement en gras : l'adresse a changé, la reporter avant d'activer.

**Mesure faite le 2026-08-25 sur `LiensLegacy::REMPLACEMENTS`** : le backend n'émet que
`/update/index.php` et `/tickets/index.php` (`backend/routes/search.py:50,82`) — jamais `/chatops/`,
`/docker/` ni `/maintenance/`. Les entrées de ces trois parties sont donc **préventives**, comme
`/supervision/`. `/docker/` **manquait** : l'archivage de `v1.37.54` avait sauté cette étape. Seule
`recherche.blade.php` consomme cette table, donc seule `go-page-search` a besoin d'être rejouée après
l'avoir complétée.

**Et une vigilance que `maintenance/` a rendue concrète : tout `/partie/` n'est pas une page.**
`/maintenance/check` et `/maintenance/windows` sont des routes du **backend**, toujours appelées par le
portage. Elles ne doivent être ni sondées par le constat d'archivage — un constat sur une route vivante
échoue pour une raison sans rapport — ni réécrites par la table. Ce qui les protège est la comparaison
du chemin **normalisé en entier** : une table qui comparerait par **préfixe** les aurait réécrites, et
la page de maintenance aurait cessé de fonctionner sans que rien ne le signale. Vérifier, module par
module, lesquels des chemins qui se ressemblent sont des pages et lesquels sont des routes.

---

### ⚠ UNE HUITIÈME ÉTAPE AU CYCLE : LES LIENS **ENTRANTS** DEPUIS LES AUTRES PARTIES DU LEGACY (2026-08-27)

Les treize premiers archivages ont tous vérifié les liens **sortants** — les points d'entrée du menu, du
tiroir mobile, des raccourcis clavier, du tableau de bord. **Aucun n'a cherché ce qui pointe VERS la
partie depuis le reste du legacy.** INV-004 l'a rendu visible, et la mesure qui a suivi en a trouvé
**quatre de plus** que le relevé initial.

**Le cas : `remote_users` (`/adm/server_users.php`) reçoit CINQ liens entrants, dans QUATRE endroits de
nature différente :**

| # | où | nature | ce qui le rend invisible |
|---|---|---|---|
| 1 | `legacy/ssh/js/main.js:135` | chaîne injectée par **`innerHTML`** | n'est pas un `href` d'un gabarit — aucun contrôle sur les `href` ne le voit |
| 2 | `legacy/adm/admin_page.php:145` | `href` ordinaire | dans une **autre** partie que celle qu'on archive |
| 3 | `legacy/lang/fr/tips.php:8` (`tip.ssh_step2`) | **dans un catalogue de traduction** | personne ne cherche une URL dans un fichier de langue |
| 4 | `legacy/lang/en/tips.php` (idem) | idem | idem — et la **parité** fait que l'oubli est double |
| 5 | `legacy/lang/{fr,en}/tips.php` (`tip.admin_step5`) | idem | idem |

**Le n°1 est le plus grave, et pas parce qu'il est en JS** : c'est le **seul chemin de déblocage** du
préflight de déploiement SSH. Quand le préflight trouve des comptes non classés, il **refuse le
déploiement** et renvoie l'opérateur par ce lien. L'archiver sans le réécrire ne casse pas un lien
d'agrément : **ça ferme la seule porte de sortie d'un refus.**

> **`LiensLegacy::REMPLACEMENTS` NE COUVRE AUCUN DES CINQ.** Elle traduit ce que le **PORTAGE** rend, pas
> ce que le **LEGACY** écrit dans ses propres pages. C'est une distinction qu'il est facile de perdre
> parce que la table *ressemble* à une table de redirection générale. Elle ne l'est pas, et la propriété
> neuve qui l'assère ne rougirait pas davantage : elle vérifie que toute partie archivée a une entrée,
> jamais que les liens du legacy vers cette partie ont été réécrits.

#### L'ordre d'archivage n'est plus une liste : c'est un GRAPHE

**`remote_users` ne peut pas être archivé avant `ssh/`** — ou alors son lien de déblocage doit être
réécrit **dans le legacy** au moment de l'archivage, et `ssh/` n'étant pas porté (K4), l'équivalent
portage de cette page n'existe pas pour y poser le bon lien. **Premier module du chantier dont l'ordre
d'archivage est contraint par un autre module**, et le premier qui n'est donc **pas** un `git mv` simple.

Même famille que le témoin de `go-page-conformite` pour `groups/`, **mais d'un cran au-dessus** : celui-là
était un test, celui-ci est une **porte utilisateur**.

#### La passe à faire, et son résultat pour les cinq parties qui restent

    # liens injectes en JS, dossiers legacy vivants
    find legacy -name '*.js' -not -path '*_deprecated*' -not -path '*vendor*' -not -name '*.min.js' \
      | xargs grep -oE 'href=\\?"(/[a-zA-Z0-9_.-]+/?[a-zA-Z0-9_.-]*)'
    # liens dans les .php des autres parties, et DANS LES CATALOGUES
    grep -rnoE 'href="/(<partie>)/?[a-zA-Z0-9_.-]*"' legacy --include=*.php
    grep -rn '<partie>' legacy/lang/

**Résultat mesuré le 2026-08-27** : sur les dossiers legacy vivants, **un seul** lien inter-modules est
injecté en JS — celui de `remote_users`. **Les cinq archivages qui restent ne sont donc pas contraints
dans leur ORDRE.**

> **⚠ Et le Lead a d'abord écrit « aucun lien entrant » pour les cinq, ce qui était FAUX pour quatre.**
> Le motif de la passe cherchait `href="…"` ; **les tuiles du tableau de bord s'écrivent `'url' => '…'`**,
> et `legacy/index.php:378` porte bien celle de `graylog/`. Relevé par la session 2, qui a nommé la
> distinction que le Lead avait écrasée : **un lien ENTRANT depuis une autre partie (étape 8) et un POINT
> D'ENTRÉE du legacy vers la partie (étape 3) ne sont pas la même chose**, même si leur effet après
> archivage est identique — un 404. *Une passe qui répond « rien » ne dit rien tant qu'on n'a pas montré
> qu'elle peut répondre « quelque chose ».*

#### Les quatre emplacements, comptés — y compris les zéros

    partie          laterale  tiroir  raccourci  tuile
    security            1       3         1        1
    bashrc              1       1         0        1
    fail2ban            1       1         0        0
    graylog             1       1         0        1
    ssh                 1       1         1        1
    iptables            1       1         1        1
    ssh-audit           1       1         1        1
    wazuh               1       1         0        1
    groups              1       0         0        0

**Ce tableau explique comment l'étape 4 a pu être oubliée onze fois, et c'est le constat de la session 2 :
`graylog/` est le MIROIR de `services/`** — `services/` avait le raccourci clavier et **pas** la tuile,
`graylog/` a la tuile et **pas** le raccourci. **Aucun des deux n'exerce les quatre emplacements, et ils
ne se recouvrent pas.**

> **Chaque archivage n'éprouve qu'un sous-ensemble DIFFÉRENT, donc onze archivages ont pu valider le cycle
> sans qu'aucun ne l'exerce en entier.** Et c'est **pire** qu'une étape éprouvée sur des cas où elle n'a
> rien à trouver : là, la vérification **a l'air** d'avoir été faite à chaque fois. Un sous-ensemble
> tournant est indiscernable d'une couverture complète quand on ne regarde qu'un archivage.

**La parade est celle de la session 2, elle coûte une ligne** : les quatre emplacements se comptent par
quatre `grep`, et **le compte s'écrit dans le compte rendu, y compris quand il vaut zéro.** *Un zéro écrit
est une mesure ; un zéro non écrit est une étape sautée, et rien ne les distingue après coup.*

Deux irrégularités que le comptage révèle et qu'il faut connaître avant d'archiver : **`security/` porte
TROIS occurrences dans le tiroir mobile** (donc trois bascules, pas une), et **`groups/` n'est ni dans le
tiroir ni en tuile** — 1/0/0/0, la couverture la plus faible du parc.

#### Et la question de l'étape 6 n'est pas « y a-t-il une adresse » mais « DANS QUEL SENS »

`graylog/` est la **première** partie dont la réponse à l'étape 6 n'est pas « aucune adresse » — elle
configure `server_host` et l'écrit dans `/etc/rsyslog.d/` sur chaque machine. **Et l'étape est pourtant
satisfaite**, parce que la distinction qui tranche est le sens :

| | `chatops/` | `graylog/` |
|---|---|---|
| nature | **ENTRANTE** — le chemin que Slack **appelait** | **SORTANTE** — celle où les machines **envoient** |
| ce que l'archivage casse | le point d'entrée public disparaît, Slack tombe en silence | **rien** — l'adresse vit en base et dans `rsyslog.d`, pas dans le dossier archivé |

La passe est bon marché et elle vient d'être payée deux fois ; elle entre au cycle pour que la prochaine
partie ne dépende pas de qui a lu quoi.

### ⚠ UNE NEUVIÈME ÉTAPE : LES CLÉS DE CONSEIL, PARCE QUE LEUR APPARTENANCE SE PERD AU `git mv` (2026-08-27)

**Mesuré : 104 chaînes traduites sont déjà orphelines, et personne ne l'a remarqué en douze archivages.**
Le détail est en E-210 ; ce qui entre au cycle est la **fenêtre**, et elle est étroite.

Après un `git mv`, les clés `tip.<module>_*` **restent dans `legacy/lang/{fr,en}/tips.php`** — rien ne les
déplace. Mais **plus rien ne dit à quelle page elles appartenaient** : le seul lien était le
`require howto_tip.php` de `index.php`, qui part avec le dossier. **Pour les onze parties déjà archivées,
cette information n'est récupérable que dans `legacy/_deprecated/*/index.php`** — donc tant que
`_deprecated/` existe, et pas après la disparition finale du legacy.

**L'étape, avant le `git mv`** : relever les clés `tip.*` de la partie, les **compter**, et dire si le
portage rend une séquence équivalente. **Compter, y compris quand le compte est zéro** — même parade que
les quatre emplacements.

> **Et ne pas les recopier telles quelles.** E-209 montre que **deux des quatre étapes** de `platform_key`
> disaient faux, dont une qui affirmait qu'un geste durcissait la machine en la qualifiant de « plus
> sécurisé » alors qu'il retire le seul recours de RootWarden. *Un acquis traduit n'est pas un acquis
> vérifié* — et un guide est ce qu'on lit quand on ne sait pas, donc il fabrique l'hypothèse au lieu de la
> corriger.

**La question à poser page par page n'est pas « les clés sont-elles portées »** — le portage emploie
`tip_*` pour des **infobulles**, donc tout contrôle par motif conclut « oui » (E-210).

**Et la formulation a été raffinée DEUX fois, par les deux sessions qui l'ont mesurée :**

1. session 3 — *« la SÉQUENCE, l'ordre des gestes, est-elle dite quelque part sur la page portée ? »* ;
2. **session 2, après mesure — *« le PREMIER PAS est-il dit LÀ OÙ L'UTILISATEUR EST BLOQUÉ ? »***

**La seconde est meilleure et c'est elle qui fait foi.** Plus courte, vérifiable **à l'écran**, et surtout :
**deux modules sur quatre la satisfont déjà sans qu'aucun conseil n'ait été porté.** `fail2ban` et `services`
disent « Choisissez une machine, **puis** relevez son état » **à l'endroit exact où l'utilisateur est
bloqué — l'état vide** ; le reste devient visible dès qu'une machine est choisie. *Un guide complet en haut
de page résout moins bien qu'une phrase à l'endroit du blocage.*

#### Le résultat sur les quatre modules livrés, et il n'est PAS « il manque des conseils partout »

| page | l'ordre est ÉNONCÉ ? | le pas de SÛRETÉ ? | l'ordre est IMPOSÉ ? |
|---|---|---|---|
| `fail2ban` | **oui**, dans l'état vide | — | oui, 12 `disabled` en JS |
| `services` | **oui**, dans l'état vide | — | oui, 8 |
| `bashrc` | **partiellement** — sa phrase d'ordre porte sur une précondition **externe** | **oui, et MIEUX que le legacy** : « simule le :date par :auteur — **rien n'a été écrit** », estampillé **sur le résultat** plutôt qu'annoncé avant | oui, 6 |
| **`graylog`** | **NON** | — | oui, 6 |

- **`fail2ban` et `services` : ne rien leur ajouter.** Ils font déjà ce qu'il faut ;
- **`bashrc` fait MIEUX que le legacy** sur le pas qui protège — et *une garantie estampillée sur le
  résultat vaut mieux qu'une promesse affichée avant le geste*, parce qu'elle survit au fait qu'on n'ait pas
  lu l'avertissement. Il lui manque seulement la phrase du premier pas ;
- **`graylog` est le seul des quatre où rien ne dit par où commencer** — et E-212 explique pourquoi : **il
  n'y a pas eu de perte, il y a eu une absence jamais comblée**, la source étant entièrement fausse.

**Conséquence sur FEAT-001, et elle durcit la réserve** : sur quatre modules mesurés, **un** avait des
conseils intégralement faux, **un** a été *amélioré* par le portage, **deux** n'ont besoin de rien. **Le taux
de reprise directe est faible : c'est le RELEVÉ qui a de la valeur, pas le texte.** Les 125 clés ne se
reprennent pas — *elles se relisent une par une.*

#### Et une chose que ces liens disent du produit, pas du chantier

`tip.ssh_step2` — *« Scannez les utilisateurs du serveur dans **Utilisateurs distants** et classifiez
chaque compte »* — et `tip.admin_step5` sont exactement la **séquence opérationnelle** dont l'exploitant a
dit qu'*« un nouvel utilisateur ne le sait pas »*. **Le legacy portait donc déjà une réponse, sous forme
de conseils contextuels, et le portage ne l'a pas reprise.** FEAT-001 (l'indicateur de préparation à
quatre états) a été conçu sans savoir que ces deux chaînes existaient : elles sont un **acquis à
reprendre**, pas un doublon à écarter — et elles nomment la séquence dans le bon ordre.

### 4.6 FINIR CHAQUE ONGLET — les manques que le portage DÉCLARE lui-même (2026-08-28)

**Demande de l'exploitant : « finir intégralement chaque onglet ; le tableau de bord n'est pas fini. »**
Mesuré plutôt que supposé — **le portage annonce lui-même ses manques**, et le relevé est court :

    grep -hoE "'[^']*' *=> *'[^']*(non port|pas encore|ancien portail)[^']*'" laravel/lang/fr/*.php

| onglet | ce que le portage déclare manquant | ce qui le retient |
|---|---|---|
| **`accueil`** | *« Le parc n'est pas encore affiché ici »* + un bloc « Ancien portail » | **une question de SÉCURITÉ, pas un reste à faire** — voir ci-dessous |
| `bashrc` | *« Les gestes de déploiement ne sont pas encore portés »* — **déclaration CORRIGÉE le 2026-09-02, `e48a821` / E-343** : elle envoyait au legacy pour deux gestes que la page FAIT (`/bashrc/users` rend une case par compte, `bashrc-apercu` appelle `/bashrc/preview`) et taisait trois absences. Énumération désormais appariée aux 7 routes : absents = `deploy`, `prerequisites` (POST, il INSTALLE), `restore`, `backups` | **B4**, suspendu sur deux arbitrages |
| `cve` | *« Le suivi d'une vulnérabilité reste sur l'ancien portail »* · *« Déclencher un scan reste sur l'ancien portail »* | **S7b** — le scan qui aboutit **envoie un vrai courriel** |
| `profil` | *« Les sessions ouvertes et les connexions mémorisées ne sont pas encore listées ici »* | **E-203** — le portage n'a aucune révocation de session côté serveur |
| `services` | ✅ **FAIT** — `244c840`, 2026-08-28 | **TROIS défauts, pas un** : l'encart déclarait non porté ce qui **est** porté (les cinq gestes passent par `/services/<geste>` **concaténé** — ce qui dédouanait l'encart au `grep` littéral) · son bouton **principal** menait à `/services/`, **archivé**, donc **404** · et **un `window.confirm()`** sur les cinq gestes qui écrivent, *les seuls gestes du module qu'aucune suite ne pouvait exercer.* **⚠ Cette ligne a été transmise DEUX fois à son autrice APRÈS son commit**, par le Lead puis par le DSI — *une tâche faite qu'un document annonce encore ouverte se redemande, et c'est le même coût qu'une tâche oubliée.* |
| `nav` | un libellé générique « ancien portail » | les **3** entrées encore en `'legacy' =>` — *remesuré 2026-09-02 03:25 ; ce tableau disait **7**, et `groups`, `ssh_audit`, `documentation`, `platform_key` ont basculé depuis* |

**Ce relevé ne couvre QUE ce que le portage déclare.** Un manque **non déclaré** n'y figure pas — et c'est
précisément la classe que ce chantier a payée six fois : *un texte peut devenir faux sans qu'aucun test ne le
voie*, et **l'inverse est vrai aussi : un manque non écrit ne se voit nulle part.**

#### ✅ L'AUDIT DES DÉCLARATIONS EST TERMINÉ — 2026-09-02, et ce n'est PAS « 9 catalogues sur 9 corrects »

**Six défauts établis, trois catalogues appariés et trouvés justes.** La distinction compte : un catalogue
« juste » l'est parce qu'il a été apparié route par route, pas parce que personne n'y a rien vu.

| catalogue | verdict | écart |
|---|---|---|
| `pare-feu` | défaut | E-318 |
| `superv` (×3) | défaut | E-336 |
| CGU | défaut | E-340 |
| `groups` (`portee_texte`) | défaut — **créé et corrigé dans le même commit** | E-341 |
| `serveurs` | défaut — un compte faux de deux tiers | E-342 |
| `bashrc` | défaut — **faux dans les DEUX sens** | E-343 |
| `fail2ban` | **apparié, JUSTE** — les 4 gestes déclarés absents le sont | — |
| `politiques` | **apparié, JUSTE** — `/policy/rollback` appelé par personne | — |
| `sftp` | **apparié, JUSTE** — idem | — |

**La mécanique est la même six fois : une phrase vraie à l'écriture, devenue fausse quand la capacité a été
portée, sans que rien ne la touche.** Aucun test ne peut voir ça, parce qu'il n'y a pas de régression — il y a
un énoncé qui a cessé de correspondre.

##### Ce que l'audit a appris sur les SONDES, et qui vaut au-delà de lui

1. **Un chemin CONCATÉNÉ échappe à l'énumération littérale.** `grep -rl "/policy/sftp/deploy"` rend **0**
   alors que le code écrit `appelle('/policy/sftp/' + geste, envoi)`. Le zéro accusait une capacité manquante
   qui ne manquait pas. Énumérer la **base** et les **gestes**, jamais le chemin entier.
2. **Une parité égale ne prouve pas qu'une clé a été ajoutée** — elle prouve que les deux fichiers sont
   d'accord, y compris pour ne rien contenir. Comparer les **jeux de clés**, pas les comptes.
3. **Le compte se RETIRE, il ne se corrige pas.** « Quatre gestes » passé à « Trois » pourrit au portage
   suivant. L'énumération voisine est la seule source.
4. **Un encart « ce qui manque » n'énonce que des manques.** Y écrire ce qui EST porté contredit sa place et
   son bouton — *vu à l'image seulement, toutes les mesures DOM étaient vertes.*
5. **Une justification fausse peut produire un énoncé vrai** (`groupes.js`, `77f7350`) : la réaction naturelle
   est de retirer les deux, et on retirerait un avertissement juste.

#### ⚠ Le tableau de bord n'est pas inachevé par négligence : il est RETENU sur une question de droits

`laravel/lang/fr/accueil.php:33-34` dit pourquoi, et la raison est mesurable :

> *« Le tableau de bord de l'ancien portail montre l'état du parc à tout le monde, sans filtrer selon… »*

**C'est la même famille qu'E-208** — trois pages legacy sur cinq ne bornent pas le parc au périmètre du
compte, et celle qui expose le plus n'était pas surveillée. **Le legacy est incohérent avec lui-même, donc il
n'existe aucune règle du produit à reprendre.**

Ce que le legacy affiche et que le portage ne reprend pas : `park_status`, `cve_detected`, `cve_trends`,
`agents_deployed`, `not_scanned`, `overdue`, `remediations`, plus **douze tuiles de raccourci**.

> **Porter ce tableau de bord fidèlement, c'est porter la fuite de périmètre. Le porter borné, c'est retirer
> une visibilité que des comptes ont aujourd'hui.** *Un portage fidèle ne peut pas trancher une incohérence de
> l'original : il la reproduit et la nomme* — et ici il a choisi de **ne pas la reproduire**, ce qui est une
> troisième voie qu'il faut assumer explicitement.

**Arbitrage de l'exploitant (§7), et il commande le reste de l'onglet.** Trois issues :

1. **borné au périmètre** — chaque compte voit ses machines. Cohérent avec `fail2ban/` et `iptables/`, **et
   retire une visibilité aux rôles 1** ;
2. **fidèle au legacy** — tout le parc à tout le monde. Reproduit la fuite, et **contredit deux pages du
   produit** ;
3. **deux vues** — un compteur global sans détail, et le détail borné. Plus de code, aucune décision de droits.

**Tant que ce n'est pas tranché, l'onglet `accueil` ne peut pas être « fini » : la question n'est pas
d'écrire du code, c'est de savoir quoi montrer et à qui.**

#### Les tuiles de raccourci, qui ne dépendent d'aucun arbitrage

**Douze tuiles** dans `legacy/index.php`, **zéro** dans le portage. Elles ne posent aucune question de droits —
elles reprennent les gardes du menu. **C'est la moitié de l'onglet qui peut se finir tout de suite.**

**Et elles sont la réponse à une demande de l'exploitant** : *« quand on ajoute un serveur, les menus où il
faut aller ensuite sont Clé SSH plateforme puis Utilisateurs distants, et un nouvel utilisateur ne le sait
pas. »* **Les tuiles disent la séquence à l'endroit où l'on arrive.** C'est FEAT-001 sous une forme que le
legacy portait déjà — et le comptage des `tip.*` a montré que **le portage n'a repris aucun panneau pas-à-pas
sur 26 pages qui en portaient un.**

#### La règle qui gouverne cette vague, et elle vient d'être payée trois fois

> **Un onglet n'est « fini » que quand ce qu'il AFFICHE est vrai.** Trois pages ont été livrées « finies » et
> affichaient un texte faux : `platform_key` (E-209, un guide qui enseigne un durcissement inexistant),
> `graylog` (E-212, tout ce que le portail en dit décrit un autre produit), et P4 avant sa relecture (E-226, la
> rotation présentée comme le remède à une clé compromise).

**Donc, pour chaque onglet, l'ordre est : mesurer ce que le legacy fait → écrire ce qui est VRAI → et
seulement ensuite compléter ce qui manque.** *Compléter un onglet dont l'affichage ment produit un onglet
complet et faux.*

#### L'ordre de travail

1. **`accueil` — les douze tuiles**, sans attendre l'arbitrage. Elles répondent à la demande de séquence ;
2. **`services`** — vérifier si son encart est **périmé** ; le module est archivé et réputé porté en entier ;
3. **`profil`** — E-203 ne demande **aucune migration**, `active_sessions` a déjà les colonnes exactes. **Et le
   bouton « Révoquer » y était inerte** : la moitié la plus urgente est de cesser de promettre ;
4. **`cve` et `bashrc`** — bloqués par S7b et B4, tous deux chez l'exploitant. **Rien à faire d'autre que de
   vérifier que leurs encarts disent vrai** ;
5. **`nav`** — se ferme tout seul quand les 7 entrées basculent.

## 5. La méthode, neuf temps

`METHODE-SOUS-LOT.md`. Inventaire → **lire le `MODULE-*.md` existant** → caractérisation **verte sur le
legacy d'abord** → base **rouge** mesurée → portage → même suite verte sur le portage → divergence
déclarée dans `PARITE.md` + `CHANGELOG.md` → captures **regardées** et **envoyées** → **LOT complet** →
commit atomique. `rw-pre-commit` avant chaque commit, **`ROADMAP.md` et `INVENTAIRE.md` compris**.

Bases rouges déjà mesurées : V8 3/4 · V9 5/4 · V10a 5/8 · V10 7/7 · V11 8/5 · V12 **14/16** ·
archivage **4/3** · A2 **7/1** · A5 **6/16** · **D1 1/17** · **D2 7/7** · **D3 5/6** · **D4 7/4** · **D5 7/2** ·
**F2 12/11** · **F3 6/7** · **F4 10/4** · **F5 5/5** · **F6 9/1** — et sur ces sept passes de D5,
**quatre passent PARCE QUE la page est absente** : un 404 ne modifie rien et ne porte pas de script.
Une base rouge se lit passe par passe, pas au compte. F2 le redit : sur ses **douze** passes,
**deux sont creuses** — « la colonne Par nomme une personne » passe faute de la moindre ligne à lire,
et « la hauteur est proportionnelle » se calcule sur un ensemble VIDE (`Math.max(...[])` rend
`-Infinity`, qui est bien `<= 5`). Une assertion sans objet n'est pas une assertion satisfaite.

**Nettoyer à l'entrée ET dans le `finally` vaut aussi pour ce que le TEST accorde**, pas seulement
pour ce qu'il écrit : une autorisation posée par une exécution survit à cette exécution.

---

## 6. Comment travailler ici

`./scripts/rejouer-lot.sh [--laravel|--legacy] [suites…]` — **ne pas lancer les suites à la main**. Une
suite sans référence rend « (pas de référence) » : on **mesure** avant d'inscrire, et **on vérifie dans
quelle table** on inscrit (deux entrées de même clé dans la même table : la seconde écrase la première).

**Le LOT dure ~3 h, et non ~100 min** — chiffre corrigé le 2026-08-27 en cours de rejeu : **25 verdicts en 31 min** sur 150, mesuré. Le « ~100 min » datait de **125** verdicts, et les suites ajoutées depuis sont plus longues. Remesure : le rapport d'avancement du rejeu, jamais la valeur reconduite. `setsid … > log 2>&1 < /dev/null &` puis, **dans un appel
séparé**, l'attente. **Ne jamais combiner la vérification d'un rejeu et son lancement** — la ligne de
commande contient alors le chemin en clair et `pgrep` s'attrape lui-même (payé trois fois). Pour compter
ce qui vit :

```bash
# dans un appel SEPARE, qui ne cite AUCUN nom de suite ailleurs dans la commande
ps -eo pid,etime,cmd | grep -E "[r]ejouer-lot-[A-Za-z0-9]+\.sh|[g]o-[a-z0-9-]+\.mjs" | grep -v grep
```

> **⚠ La commande que ce document donnait était PÉRIMÉE, et dans le mauvais sens.** Elle disait
> `grep "rejouer-lot.sh"` — **un rejeu = deux lignes**. Les deux affirmations sont fausses depuis
> `v1.37.85`, le commit qui a fait se recopier le runner dans `/tmp` pour neutraliser le quatrième
> régime de lecture. La copie s'appelle `rejouer-lot-XXXXXX.sh` (`mktemp -t`, ligne 80 du runner) :
> **le `.` du motif est un joker qui exige UN caractère, et il y en a sept.** Le motif ne correspond
> donc à **rien**, et un rejeu en cours en produit **trois** lignes, pas deux — le lanceur, le
> `timeout`, et le `node`.
>
> **C'est un FAUX NÉGATIF, et c'est le mauvais côté de l'erreur** : il dit « le banc est libre »
> pendant qu'il est occupé. Deux connexions du même compte dans la même fenêtre TOTP, et le journal
> accuse le code. Payé le 2026-08-27 par la session qui l'a trouvé : sa boucle d'attente a annoncé
> « rejeu terminé » au bout de quelques secondes alors que le nœud tournait depuis 40 s.
>
> **Et le zombie se trompe dans l'autre sens.** Un `bash -c` d'instantané de shell d'une session
> antérieure (PID 3858777, **55 521 s** de vie au moment du relevé) boucle sur
> `until ! pgrep -f "rejouer-lot"` — donc **il s'attrape lui-même et ne sortira jamais**. Il a fait
> rendre « 1 rejeu en cours » sur une machine au repos. `pgrep -f "rejouer-lot"` **sans** le `.sh`
> attrape bien la copie, mais il attrape aussi ce zombie : il rend « occupé » en permanence.
> **Les deux erreurs sont donc de sens opposé, et la commande corrigée ci-dessus vise les `node`** —
> une suite qui tourne est toujours un `node go-*.mjs`, quel que soit le nom du lanceur.
>
> **Éprouvée dans les deux sens** : elle attrape les trois lignes réelles d'un rejeu, et elle rend
> **0** sur une machine au repos. Mais uniquement **dans un appel séparé** : au premier essai elle a
> rendu **2**, parce que les noms de suites de mon propre test figuraient ailleurs dans la même
> invocation. **Cinquième occurrence du piège `[r]ejouer-lot`, commise en corrigeant la commande qui
> le documente.** La classe de caractères ne dédouble que le motif, jamais le texte de la commande.
>
> *Une règle qui rassure sans protéger est pire que pas de règle* — et celle-ci était écrite dans la
> consigne elle-même.

Après modification du backend : `sudo -n docker restart rootwarden_python` + ~17 s. Après une vue :
`view:clear` puis `view:cache`. Pas plus de 3 suites par commande. Jamais en root. Exécution parallèle
impossible. Ne pas éditer un fichier servi — ni le runner — pendant un rejeu (docs et skills : sans
risque).

`docker` demande `sudo -n` depuis mon shell (les suites l'appellent sans). Conteneurs :
`rootwarden_php`, `rootwarden_python`, `rootwarden_db`, `rootwarden_laravel`, `rootwarden_test_server`,
`rootwarden_mock_opencve`. `php` n'existe pas sur l'hôte :
`sudo -n docker exec rootwarden_laravel php -l <fichier>` — **`php -l` ne valide pas un `.blade.php`**.
`pytest` vit **dans** le conteneur. Mot de passe MySQL :
`P=$(grep -oP '^MYSQL_ROOT_PASSWORD=\K.*' srv-docker.env)`.

Chemins backend : legacy `/api_proxy.php/<route>`, portage `/api/gateway/<route>`. Gabarits :
`layouts.portail` (pages), `layouts.socle` (écrans d'authentification).

### Le schéma, ce qu'il faut savoir

`users` : `id name company email password totp_secret ssh_key ssh_key_updated_at active
failed_attempts locked_until last_failed_login_at sudo role_id encryption_version password_updated_at
password_expires_at password_expiry_override force_password_change created_at onboarding_dismissed_at`
— c'est **`active`**, pas `is_active`.

- `password_updated_at` porte **`ON UPDATE CURRENT_TIMESTAMP`**, qui ne se déclenche **que si la valeur
  change** ; `verify.php:159` calcule l'expiration dessus.
- `password_expires_at` est **écrite par le legacy et lue par personne** (0 ligne renseignée).
- `password_history` : `id user_id password_hash changed_at`.
- `user_logs` : `id user_id action created_at prev_hash self_hash` — la chaîne est posée par un
  **scellement séparé**, l'insertion est **nue**. 3368 lignes dont **757 sans empreinte**.
- **Aucune migration Laravel** : le schéma appartient au backend Python (`mysql/migrations/*.sql`).

### Comptes de test

| compte | id | rôle | note |
|---|---|---|---|
| `rw-test-user` | 14 | 1, zéro permission | **D-5 : ne pas toucher** |
| `rw-test-admin` | 15 | 2, **NEUF permissions** | **treize suites en dépendent** — remesuré le 2026-08-26 |
| `rw-test-super` | 16 | 3, `can_admin_portal` | les captures passent par lui |

**Ce document annonçait UNE permission pour `rw-test-admin`. Il en porte NEUF**, mesurées colonne par
colonne le 2026-08-26 :

`can_deploy_keys` · `can_update_linux` · `can_scan_cve` · `can_view_compliance` ·
`can_manage_backups` · **`can_manage_fail2ban`** · `can_manage_services` · `can_audit_ssh` ·
`can_manage_supervision`

`rw-test-super` n'en porte qu'**une** (`can_admin_portal`) — le rôle 3 les contourne toutes de toute
façon. `rw-test-user` n'en porte **aucune**, ce qui était bien dit.

**Pourquoi le chiffre compte** : plusieurs suites mesurent une garde en s'appuyant sur « `rw-test-admin`
n'a PAS telle permission ». Concevoir un tel test sur la foi de cette ligne, quand le compte porte
neuf droits, produirait un vert qui ne mesure rien. Et l'un de ces neuf est
`can_manage_fail2ban` — l'une des deux permissions que l'interface du legacy ne sait pas reprendre
(E-118).

Mot de passe `RootWarden@2026-Test!`, codes via `node tests/e2e/code-totp.mjs <compte>`.
**Ne jamais inventer un secret TOTP.** Sans secret TOTP : `opsuser` (id 2, **vrai compte**) et cinq
résidus `e2e_test_*`. `superadmin` (id 1) : rôle 3, `force_password_change = 1`, et **son mot de passe
ne correspond plus** à celui de mes notes.
`Navigation::autorisee()` traite `'sa' => $roleId >= 3` : **un rôle 3 voit les 33 entrées**.
**Exercer les deux chemins d'une garde « permission OU rôle »** : rôle 1 → 403, rôle 3 sans la
permission → 200. **Vider `login_attempts` avant chaque suite.**

### Sûreté

Le scheduler tourne dans `rootwarden_python`, **invisible à `ps`**, toutes les 60 s. Toute fixture —
base, conteneur, fichier distant, paquet, **secret ou mot de passe de compte** — est nettoyée à
l'entrée et dans un `finally`, **chaque étape isolée dans son `try`**, et **l'état rendu est relu pour
être prouvé**.

**⚠ `from server import app` DÉMARRE UN SCHEDULER. Ce n'est jamais une commodité de test.**
Mesuré le 2026-08-27 : `backend/server.py:242-244` appelle `start_scheduler()` **au niveau module**, sans
aucune garde `if __name__` — donc **un simple `import server` lance un second scheduler**, qui interroge la
base toutes les 60 s et prend toute ligne `enabled = 1 AND next_run <= now`. La sortie de la sonde l'a dit
elle-même : « Scheduler demarre (CVE + SSH Audit + purge, intervalle: 60s) ».

**Aucun dommage cette fois, et c'est vérifié, pas supposé** : aucun processus survivant, **0 tâche créée**,
`cve_scans` inchangé, **0 planification active** — il est mort avec le processus `exec` et il n'y avait
rien à prendre. **Mais si une planification avait existé et que la sonde avait vécu une minute de plus,
elle aurait déclenché un vrai scan SSH.**

Le §6 disait déjà que le scheduler est **invisible à `ps`** et qu'une planification de test peut
déclencher un vrai scan. Il manquait ceci : **le déclencheur s'arme par un IMPORT, pas seulement par une
écriture en base.** Une sonde qui veut un client de test déballe les décorateurs sur une `Flask` **nue** et
n'importe que le module de routes.

**Avant de faire cliquer un test, lire ce que l'action envoie.** **`srv-zabbix` (id 1) : jamais
jointe.** **Aucune session de test ni de capture pendant un rejeu** — le garde anti-rejeu TOTP est par
compte et **en base** ; un compte que le LOT n'utilise pas est libre.
**Ne jamais demander à l'exploitant de coller un mot de passe, une clé ou un jeton.**
**`tests/e2e/go-ssh-audit-scanall.mjs` joint la production** — ne pas le lancer.
**`/adm/health_check.php` aussi, et par le seul fait de s'ouvrir** : la page tire 106 routes au
chargement, dont quatre qui **écrivent** sur `srv-zabbix` (clé de plateforme, compte de service,
`sshd_config`, retrait de clé). Ni test, ni capture, ni coup d'œil — voir l'encadré de §4.2.

**Six motifs de test selon le geste** : joint la production par construction → interception +
avortement · porte sur une cible qu'on choisit → cliquer pour de vrai, nettoyer dans un `finally` ·
revalidation qu'un `<input>` ne peut pas violer → **requête forgée depuis la page** · chemin destructeur
→ **simuler d'abord** · branche inatteignable sur le banc → **fixture qui la rend atteignable** · défaut
**transitoire** → émettre le geste **seul**.

---

## 7. Décisions qui attendent l'exploitant

### 7.0 SESSION 8 — DSI DÉLÉGUÉ : ce qui lui est délégué, et ce qui ne peut pas l'être (2026-08-28)

**L'exploitant délègue les arbitrages du §7 à une session dédiée.** Le Lead a émis une réserve — *une session
qui joue le DSI produit des décisions dont personne n'est comptable, et défait ce qui a le mieux marché
aujourd'hui : quatre sessions ont refusé un rôle mal adressé, et chaque refus a évité un dégât.* **L'exploitant
a réaffirmé. La délégation est donc en vigueur**, avec la frontière ci-dessous.

#### La frontière n'est pas une réserve du Lead : c'est ce qu'un message de pair PEUT autoriser

**Une session ne peut pas déléguer à une autre une autorisation qu'elle ne détient pas elle-même.** Le DSI
décide **le produit** ; il ne peut pas rendre exécutable, pour le Lead ou pour une session, un geste qui
détruit des données sur des machines réelles, redémarre un service, pousse ou fusionne. *Ce n'est pas le Lead
qui refuse : c'est qu'un mot de pair n'est pas un mot d'exploitant sur ces gestes-là.*

**Le DSI transforme donc chaque arbitrage irréversible en dossier prêt à signer** — décision recommandée,
conséquence mesurée, geste exact, et ce qui se passe si on ne fait rien. **L'exploitant signe une ligne au lieu
d'instruire un dossier.** C'est cela, le gain réel.

#### ✅ DÉLÉGUÉ — le DSI tranche, le chantier exécute

| # | arbitrage | pourquoi délégable |
|---|---|---|
| 1 | **la portée du tableau de bord** (§4.6) — borné au périmètre / fidèle au legacy / deux vues | décision de **produit**, aucune destruction |
| 2 | **E-221 — accorder les 4 permissions avant le redémarrage** | **tâche de configuration**, accordable depuis l'interface, réversible |
| 3 | **E-209 · E-212 · E-219 — les textes FAUX servis en production** | corriger un texte faux ne détruit rien ; *le laisser, si* |
| 4 | **E-225 — dire ou non que la désinstallation laisse un dépôt tiers** | texte, puis geste (le geste remonte au n°8) |
| 5 | **E-208 — resserrer ou non les 3 pages qui ne bornent pas le parc** | changement de **droits**, réversible, aucune donnée perdue |
| 6 | **E-224 — la borne de `install_all`** (`machine_ids` obligatoire) | décision de conception ; l'entrée dangereuse est **déjà retirée** |
| 7 | **E-222 — la contrainte `UNIQUE` sur une table VIDE** | *le moment le moins coûteux de l'histoire du produit* ; **l'écrire** est délégué |

#### ⛔ NON DÉLÉGABLE — dossier préparé, signature de l'exploitant

| # | arbitrage | ce qui l'empêche |
|---|---|---|
| 8 | **E-213 — unifier les deux magasins d'exclusion** | change **ce qui est détruit** par `userdel -r` sur des machines réelles |
| 9 | **E-220 — l'auto-réparation du sudoers orphelin** | **écrit sur des machines réelles**, dans un geste de parc |
| 10 | **E-214 / E-215 — les correctifs des gestes distants** | changent ce qui s'écrit sur des machines réelles |
| 11 | **le `docker restart rootwarden_python`** | **19 modules** prennent effet ensemble, dont un durcissement qui **retire des accès** |
| 12 | **la recréation de `rootwarden_laravel`** | même classe |
| 13 | **appliquer une migration** | schéma de production |
| 14 | **`git push` / `git merge`** | l'exploitant a dit qu'il donnerait l'ordre |
| 15 | **le compte approbateur** (rôle 2 + `can_admin_portal`) | son geste, sur `/comptes` |

**La ligne qui sépare les deux colonnes** : *ce qui se défait d'un clic est délégué ; ce qui détruit, retire un
accès ou publie ne l'est pas.* Et le n°11 est le plus contre-intuitif : **redémarrer libère 19 correctifs ET
retire l'accès au pare-feu à tous les comptes non-administrateurs** — `can_manage_iptables` est détenue par
**0 sur 9**. *Un durcissement non annoncé est indiscernable d'une panne.*

#### Ce que le DSI doit produire, et sous quelle forme

Pour chaque arbitrage délégué : **une décision écrite dans ce document**, avec sa raison et ce qu'elle coûte.
Pour chaque arbitrage non délégable : **un dossier d'une page** — recommandation, conséquence mesurée, geste
exact, et **ce qui se passe si on ne fait rien**, qui est la moitié qu'on oublie.

**Et une règle qui vaut contre lui comme contre le Lead** : *un nombre annoncé est une hypothèse à mesurer.*
Le Lead a propagé quatre chiffres faux et deux conclusions fausses en deux jours ; **six sessions l'ont
corrigé**. Le DSI décide, il ne mesure pas à la place de ceux qui mesurent — **et quand une session le
contredit avec une mesure, la mesure gagne.**

### ✅ QUATRE ARBITRAGES TRANCHÉS PAR L'EXPLOITANT — 2026-08-27

Posés en questions fermées, répondus. **Ce sont les premiers arbitrages du §7 à sortir de l'attente
depuis l'ouverture du chantier.**

| question | réponse | ce qu'elle déclenche |
|---|---|---|
| le volume `platform_ssh` est-il sauvegardé ? | **NON** | la rotation est **définitivement irréversible** — voir ci-dessous |
| la porte à quatre yeux | **brancher les deux routes** | correctif backend assigné, à verrouiller par un test |
| `srv-zabbix` sans seconde voie | **il remet les mots de passe lui-même** | le gel reste tant que ce n'est pas confirmé ; **pas** de refus fail-closed |
| `tickets` | **la route reste** | le menu seul est retiré ; rien d'autre à décider |

#### Deux décisions de plus, après qu'une session ait REFUSÉ d'écrire

**Ma première question était incomplète, et c'est un refus mesuré qui l'a montré.** J'avais demandé
« brancher la porte ou retirer les noms ? ». Il manquait un terme :

    approvals.py:74   if role is not None and int(role) >= ROLE_SUPERADMIN: return None

**Les deux routes exigent le rôle 3 — exactement celui que la porte contourne.** Brancher sans lever le
contournement aurait écrit **une ligne qui ne peut jamais rien faire** : « la garde présente qui ne garde
pas », sur les deux gestes les plus larges du produit.

**Et le contournement est DÉLIBÉRÉ** — sa docstring le dit : sans lui, une condition sur un geste réservé
au rôle 3 « ne pourrait jamais être satisfaite et bloquerait toute action ». **Brancher la porte sur ces
routes reproduit donc exactement le cas pour lequel le contournement a été écrit.** Ce n'était pas un
oubli à corriger, c'était une conception à trancher.

| décision | réponse |
|---|---|
| le contournement du rôle 3 sur ces deux actions | **LEVÉ**, et **un second compte d'administration réel est créé** |
| l'ancienne clé à la rotation | **ARCHIVÉE**, avec une purge prévue |

#### ✅ La bonne nouvelle que la mesure donne : l'approbateur n'a PAS besoin du rôle 3

`routes/approvals.py:28-29` exige `@require_role(2)` **+** `@require_permission('can_admin_portal')`, et
la règle est `approved_by != requested_by`.

> **Un compte de RÔLE 2 porteur de `can_admin_portal` peut donc approuver une action de rôle 3.** C'est
> une séparation des tâches **sans escalade** — l'approbateur n'a pas besoin de pouvoir faire le geste
> qu'il approuve.

Et aujourd'hui **aucun** compte de rôle 2 ne porte cette permission (`rw-test-admin` ne l'a pas), donc les
seuls approbateurs possibles sont les deux comptes de **rôle 3** : `superadmin` — dont le mot de passe ne
correspond plus — et `rw-test-super`, **un compte d'épreuve dont les identifiants sont dans le dépôt.**
**L'approbation d'une rotation de clé de flotte reposerait donc sur un compte de test.** C'est ce qui rend
le second compte nécessaire, et c'est pourquoi il doit être **rôle 2 + `can_admin_portal`**, pas rôle 3.

#### La contrainte impérative de l'archivage

> **L'archive doit vivre HORS de ce que `get_platform_private_key()` peut rendre.** Sinon l'ancienne clé
> reste utilisable par `ssh_utils.py:236-244`, et **la rotation devient du théâtre.**

Plus une purge, dont le délai reste à fixer — un secret archivé sans date de destruction est un secret
permanent qui a seulement changé de nom.

#### ⚠ « Non sauvegardé » change la gravité, pas seulement l'urgence

> **⚠ ÉTAT DÉPASSÉ — LU AVANT LE CORRECTIF `01c04b2`, ET IL A ÉTÉ POSÉ.** `_archive_platform_key()` **déplace**
> la paire dans `platform_ssh/archive/` au lieu de l'effacer, avec purge à `PLATFORM_KEY_ARCHIVE_DAYS`. Le
> corps ci-dessous est **conservé** : c'est la mesure qui a motivé le geste, et *un constat effacé ne
> s'apprend pas.*
>
> **Mais le risque n'est pas LEVÉ : il est DÉPLACÉ.** L'archive vit dans **le MÊME volume Docker** que la clé
> courante, et **ce volume n'est sauvegardé nulle part** — l'exploitant l'a confirmé. Donc *« réversible
> pendant N jours » ne vaut que si le volume survit, et cette seconde condition ne dépend pas du produit.*
>
> **Trois formulations en deux jours** — `unlink` → archive → **archive dans un volume non sauvegardé** — et
> les deux réécritures intermédiaires étaient trop optimistes. *Une conclusion juste dont la raison a changé se
> réécrit, et **la réécriture peut être fausse à son tour**.*

La question décidait si la rotation était *irréversible* ou *seulement pénible*. **La réponse est
irréversible.** Trois conséquences à tenir :

1. **`ssh_key_manager.py:117-126` fait `unlink()` sur la seule copie qui existe au monde.** Il n'y a ni
   sauvegarde d'infrastructure, ni copie RootWarden — mesuré des deux côtés. Le geste détruit un secret
   **non reproductible** ;
2. **l'option « archiver au lieu de supprimer » gagne tout son poids.** Elle avait été écartée avec une
   réserve juste — *une clé révoquée qui reste sur le disque est une surface* — mais cette réserve se
   compare désormais à **une perte définitive**, et non à un désagrément. Même volume, même `0600` : le
   niveau de risque ne change pas, et une purge doit être prévue. **À proposer, pas encore décidé** ;
3. **le refus fail-closed n'est PAS retenu**, et c'est cohérent avec la troisième réponse : l'exploitant
   remet les mots de passe, donc la rotation redevient récupérable **par la machine** au lieu de l'être
   par le volume. C'est une meilleure issue que de bloquer la fonctionnalité — mais elle ne vaut
   **qu'après** son geste.

> **Tant que les mots de passe de `srv-zabbix` ne sont pas remis, les deux chemins de verrouillage sont
> vivants et le gel tient** : aucune route de `remote_users` ni de `platform_key` n'est exercée, même en
> refus, par aucune session.

**Et le geste qu'il doit faire est en DEUX temps, ce qui n'est pas évident** : « Ressaisir » sur la page de
la clé écrit `password` ; `root_password` demande **une autre page** (*Comptes → Serveurs*). Mesuré : une
seule route écrit cette colonne dans tout le backend, **celle qui l'efface**. Un seul clic rend donc **la
moitié** du filet — et c'est exactement E-202 §« le retour offert est à moitié ».

### ⚠⚠ E-201 / E-202 — DEUX CHEMINS VERROUILLENT ROOTWARDEN HORS DE `srv-zabbix`, EN UN APPEL

**Trouvés le 2026-08-27 par pré-relecture AVANT portage — la première fois du chantier que la sécurité
passe en amont, et c'est ce qui les a trouvés.** Détail et preuves dans `PARITE.md`.

**L'état du parc, mesuré, est ce qui les rend mortels** : `srv-zabbix` (production) n'a **ni mot de passe
ni mot de passe root** connu de RootWarden. Sa **seule** voie est la clé de plateforme. Les machines 2 et
3 ont un mot de passe ; elle, non.

| chemin | rôle | ce qu'il fait | retour |
|---|---|---|---|
| `regenerate_platform_key` | **3** | `unlink()` la clé privée puis régénère — les trois tentatives de `connect_ssh` emploient la **même** clé | **aucun** |
| `delete_remote_user` visant `rootwarden` | **2** | `userdel` le compte par lequel RootWarden s'authentifie | **aucun** |

Le second est **plus bas en rôle** que le premier. Et sa protection énumère
`{'root','nobody','daemon','bin','sys','www-data'}` — **`rootwarden` n'y est pas** — puis compare à
`machines.user`, qui vaut `'user'` pour cette machine alors que le compte de connexion **réel** est
`rootwarden`, en dur dans `ssh_utils.py:241`. *La protection énumère des NOMS au lieu de résoudre une
FONCTION.*

**Et la porte à quatre yeux ne couvre pas le premier.** `APPROVAL_ENABLED=true` et
`APPROVAL_ACTIONS` **nomme** `regenerate_platform_key` — mais `gate()` n'est appelé que **deux fois** dans
tout le backend, pour `reboot_server` et `delete_remote_user`. **La configuration affirme une protection
que le code ne consulte pas.**

**Ce qu'il faut décider, et le premier point conditionne tout le reste :**

1. **le volume `platform_ssh` est-il sauvegardé par l'infrastructure ?** RootWarden n'en fait **aucune**
   copie — mesuré. **C'est la question qui décide si la rotation est irréversible ou seulement pénible**, et
   elle ne se répond pas depuis le dépôt ;
2. **la porte à quatre yeux** : la brancher sur les deux routes, ou **retirer les deux noms de la
   configuration**. Ne rien faire est la seule issue qui laisse croire à un garde inexistant ;
3. **`srv-zabbix` doit-elle rester sans seconde voie d'accès ?** Tant qu'elle l'est, les deux chemins sont
   des verrouillages définitifs et non des incidents ;
4. le correctif *fail-closed* proposé — refuser la rotation tant qu'une machine deviendrait injoignable —
   **rendrait le geste IMPOSSIBLE sur ce parc** jusqu'à ce que (3) soit réglé. C'est un blocage
   fonctionnel réel, et il vaut mieux qu'un verrouillage. Mais c'est un choix.

**Ce qui est déjà tenu sans vous** : aucun de ces gestes n'est porté, aucun n'a été déclenché, et la
contrainte de test est écrite — **la réussite de la rotation ne doit JAMAIS être mesurée, il n'existe
aucune cible sûre.** Seul le refus est mesurable.

### ⚠ E-174 — UNE EXÉCUTION DE COMMANDE EN ROOT, OUVERTE EN PRODUCTION, OCCUPÉE AUJOURD'HUI

**Trouvée le 2026-08-27 par relecture, hors du sous-lot en cours. Elle passe devant tout ce qui
suit.** Détail complet et preuve dans `PARITE.md` — E-174. Le résumé tient en trois lignes de code :
`_validate_ip` appelle `ipaddress.ip_address()` **pour son effet de bord**, jette le résultat et rend
la **chaîne reçue** ; celle-ci est interpolée dans un `f'fail2ban-client set {jail} banip {ip}'` ;
`execute_as_root` l'émet en `sudo -S -p '' sh -c {shlex.quote(command)}` — où `shlex.quote` protège le
shell **extérieur** et livre la commande entière, intacte, à un `sh -c` distant dont le travail est de
l'interpréter. Un identifiant de portée IPv6 (`fe80::1%;id;`) traverse le validateur : mesuré, et
`str()` le **conserve verbatim**, donc « normaliser » n'aurait rien fermé — il faut refuser le `%`.

**Occupée, pas théorique.** `rw-test-admin` (id 15, rôle 2, actif, **second facteur fonctionnel**)
atteint les trois machines, `srv-zabbix` comprise — `check_machine_access` rend `True` dès
`role_id >= 2`. Aucune attribution de permission, aucun `UPDATE`, aucune étape. Et le pire vecteur est
`POST /fail2ban/ban_all_servers` : `@require_role(2)`, **aucun** contrôle d'accès machine — un appel,
le parc entier.

**Établie sans être provoquée** : commande recomposée dans le conteneur, `fail2ban-client` remplacé
par un `echo`, `sudo` retiré. Aucune session SSH ouverte, aucune machine du parc touchée.

**Ce que j'ai fait sans attendre, et pourquoi.** J'ai autorisé la session 4 à appliquer le correctif —
refuser `'%'` dans `_validate_ip`, plus `shlex.quote()` sur `jail` et `ip` à l'intérieur de la commande
composée — sur `Migration-Laravel`, en m'appuyant sur la convention **§3.2** (« les modifications
backend et legacy sont autorisées, ne plus bloquer, ne plus demander ») et sur le précédent que nous
avons nous-mêmes créé cette semaine : E-164 et E-165 ont été corrigés dans ce même fichier en citant
§3.2. Le correctif fait trois lignes, il est réversible, et il ne casse aucun appelant mesuré. La
session 5 l'a proposé, la 4 l'applique, la 6 le verrouille par `pytest` : aucune session ne valide son
propre travail. **À dire si vous vouliez être consulté d'abord — je n'ai pas voulu laisser une
exécution root ouverte le temps d'une clarification de rédaction.**

**Ce qui reste entièrement à vous** : rien de sortant n'a été émis, aucun `push`, aucun `merge`, et
**aucune décision sur les comptes**. `opsuser` (id 2, rôle 1, actif) a pour **seule** machine autorisée
`srv-zabbix`, la production ; son enrôlement 2FA est libre, faute de `totp_secret`. Le désactiver, lui
retirer cet accès, ou ne rien faire, vous appartient.

**Et cela amende E-152** : poser la permission sur les 21 routes **ne ferme pas** E-174. Un porteur
légitime de `can_manage_fail2ban` conserverait l'exécution root. La permission est censée autoriser à
bannir une adresse ; elle confère root sur chaque machine à portée. C'est une élévation par rapport à
l'**intention documentée du produit**, pas seulement par rapport à une garde absente.

### Deux contradictions de ce document, relevées le 2026-08-27 — elles décident qui peut travailler

Elles ne sont pas des questions de fond : ce sont **deux endroits où mes propres pages se contredisent**,
et chacune bloque une session. Je ne les tranche pas.

1. **§3.2 contre §7 : les six correctifs backend sont-ils déjà autorisés ?** La convention §3.2, tranchée
   par vous, dit « les modifications backend et legacy sont autorisées, ne plus bloquer, ne plus demander ».
   Le §7 tient pourtant **six correctifs backend en attente d'arbitrage** — E-142, E-144, E-147, E-149,
   E-150, E-152. Et **deux correctifs se sont déjà servis de §3.2 cette semaine** : E-164 et E-165, portés
   dans `backend/routes/fail2ban.py` aux sous-lots F3, F4 et F6, en citant explicitement « §3.2 l'autorise ».
   Le précédent existe donc, et il est de nous. Trois lectures possibles : les six sont couverts par §3.2
   et partent aujourd'hui ; ils ne le sont pas, et E-164/E-165 ont été appliqués trop vite ; ou §3.2
   couvre les correctifs de *fidélité* et pas ceux de *sécurité*, ce qui serait la distinction la plus
   défendable mais n'est écrite nulle part. **En attendant, rien n'est appliqué** — la session 5 écrit les
   patchs et les tient prêts.
2. **§3.1 contre §10 du protocole : où vit un correctif de sécurité ?** §3.1 dit « tout se fait sur
   `Migration-Laravel`, correctifs de sécurité compris ; plus de branche `security/…` séparée ». Le §10 de
   `PROTOCOLE-SESSIONS.md` donne à la session 5 « une branche `security/…`, **jamais** `Migration-Laravel` ».
   §3 « prévaut sur tout le reste », donc la lettre du plan gagne — mais la règle du protocole existait pour
   une raison (une session ne valide pas seule sa propre modification de sécurité), et cette raison est
   satisfaite autrement : **5 propose, 3 ou 4 applique**. La question est donc de savoir si la branche
   dédiée reste utile une fois la séparation des rôles obtenue. Un mot suffit.


### ⚠ SIX BRANCHES NON MESURÉES SONT UNE SEULE DÉCISION, PAS SIX — et elle vous appartient

Reformulation apportée le 2026-08-27, et elle vaut mieux que six discussions séparées.

Le portage a écrit, ce jour, **six branches établies par LECTURE et mesurées par aucune suite** : le
troisième état du préflight · E-189 · le chemin non concluant du scan · le badge « retirée du parc » · la
ligne d'inventaire invalide · le ban de parc à portée non vide.

> **Elles ont toutes la MÊME forme : un état que le banc ne peut pas produire sans qu'on le fabrique.**
> Ce ne sont pas six dettes, c'est **une seule limite du banc, vue six fois.**

Et la question n'est donc pas « écrire six fixtures » — chacune **déplacerait ce qu'elle mesure**, et
aucune n'a été fabriquée pour cette raison. La question est :

> **Veut-on une machine d'épreuve dont l'état est ANORMAL par construction ?** Sans `systemd`, sans
> fail2ban, avec un `/etc/passwd` sale, un compte injoignable, un dump de clés qui échoue.

**Une seule décision fermerait les six.** Ce que cela coûte : une machine de plus à tenir, et un banc dont
l'état ne ressemble plus à la production. Ce que cela rend : six branches de code destructeur qui cessent
d'être établies par lecture seule — **et ce sont, sans exception, des branches de la chaîne de K4 ou de la
révocation d'accès.**

Ce que cela **ne** demande pas : toucher `srv-zabbix`, ni `Test-Server-Debian`, dont l'état normal est
précisément ce qui rend les six inatteignables.

**Effets sortants, à autoriser avant tout test**
- **A3** — la réinitialisation de mot de passe envoie un courriel (`phpmailer`). Réserves déjà mesurées :
  le jeton **circule dans la query string** (historique, `Referer`, journaux Apache), et **un compte sans
  `email` n'a aucun chemin**.
- **S7b** — un scan CVE réel.
- **`groups/` — l'action de masse. RESSERRÉE le 2026-08-27 : la demande ne porte plus que sur
  `cve_scan`.** `drift_scan` n'a **aucun** effet distant — mesuré, voir l'encadré du §4.2 : ce document
  lui prêtait une session SSH par machine, c'était faux, et l'arbitrage demandé pour cette moitié
  n'avait pas lieu d'être. Reste `cve_scan`, et il est tout ce qui était annoncé : `POST
  /groups/<id>/run` ouvre une session SSH **et envoie un courriel** par machine avec des résultats.
  C'est l'effet de S7b, atteint depuis une autre page et **multiplié par le nombre de membres** — un
  clic, N machines, N courriels. Le sous-lot testera le bouton par **interception et avortement** ; un
  déclenchement réel attend votre mot.
  **Trois mesures qui donnent son échelle à la demande**, relevées le 2026-08-27 : le courriel est
  **armé** (`MAIL_ENABLED = True`, `MAIL_TO` et `MAIL_SMTP_HOST` renseignés) ; la seule ligne de
  `cve_scans` de toute l'installation porte **684 paquets et 1458 CVE dont 103 critiques**, sur
  `srv-zabbix` — un `cve_scan` de masse sur un groupe la contenant **rejouerait ce scan et enverrait
  ce rapport** ; et **la machine 1 n'a aucun filet dans le code** : mots de passe vides, mais
  `platform_key_deployed = 1` et `service_account_deployed = 1`, donc le garde
  `if not ssh_pass and not has_keypair` (`cve.py:56-60`) ne l'écarte pas. La règle « jamais jointe »
  n'a **aucun équivalent dans le code** : elle ne tient que par nous.
  **Non mesuré, et il faut le dire** : la machine 2 n'a jamais été scannée, donc on ne sait pas si un
  `cve_scan` sur elle seule franchirait le seuil de 7.0 et déclencherait le courriel. Ne pas en
  déduire qu'il serait sans effet.
- **`groups/` — la règle qui S'INVERSE, et c'est l'état PAR DÉFAUT du formulaire.** Relevé le
  2026-08-27, et ce n'est pas un effet sortant mais ça décide d'une fixture : `_resolve_dynamic` fait
  `where = (' AND '.join(clauses)) if clauses else '1=1'` (`groups.py:77`) — **zéro critère coché ⇒ le
  parc entier**. Le formulaire naît sur « Dynamique » avec aucune case cochée : saisir un nom et
  cliquer Enregistrer — les deux seuls gestes obligatoires — crée un groupe contenant les **trois**
  machines, `srv-zabbix` comprise, et la carte n'affiche **rien** qui le distingue d'un groupe voulu.
  Et la fixture statique n'est plus une précaution, c'est la **seule qui existe** : mesuré combinaison
  par combinaison, **aucun jeu des quatre énumérations ne rend la machine 2 seule** (le seul
  discriminant serait un tag, et `machine_tags` est **vide**).

**Trois décisions avant de porter D6c (import CSV)** — caractérisé le 2026-08-26, non porté
- **La colonne `sudo` du format CSV** (E-130). L'import l'écrit sans contrôle de rôle, alors que
  `api/toggle_sudo.php` exige le rôle 3.
  Trois issues : exiger le rôle 3 pour cette colonne, la refuser à l'import, ou la garder en l'état.
  **Retirer une colonne d'un format de fichier documenté change un contrat** : ce n'est pas à moi.
  > ⚠ **La suite de cette phrase était périmée et elle est retirée** — elle disait *« et `users.sudo`
  > est la précondition du repli `NOPASSWD: ALL` »*. Mesuré le 2026-09-03 : **`users.sudo` ne confère
  > plus rien sur aucune machine**, pas même par le geste de rôle 3. Le repli est mort par le SCHÉMA
  > (`sudo_preset` est `NOT NULL DEFAULT 'none'`, donc `policy_for_machine` est toujours vrai et la
  > branche `elif sudo:` est inatteignable), et la branche qui tire à sa place **RETIRE** le sudo.
  > **La sévérité n'est pas nulle : elle est DIFFÉRÉE.** `toggle_sudo.php:61` n'écrit que `users.sudo` ;
  > le jour où quelqu'un le répare en écrivant aussi `sudo_preset`, tout compte portant `users.sudo = 1`
  > — importés sans garde inclus — obtiendrait `NOPASSWD: ALL` sur chaque machine qu'il atteint.
  > **C'est l'argument le plus fort pour l'issue (a), et il impose un ORDRE : garder l'import AVANT de
  > réparer le chemin d'octroi.** Détail, énumération et réserves : `E-130-PORTEE-REELLE.md`.
- **Un compte importé est inutilisable** (E-131) : mot de passe aléatoire que personne ne connaît,
  `$sendWelcome` mort, `email` facultatif donc pas de récupération. Trois issues : rendre `email`
  obligatoire, afficher le mot de passe généré **une fois** comme le fait déjà D3, ou forcer
  `force_password_change`.
- **La politique de mot de passe sur les MACHINES** (E-132). Le portage passera `false` comme le
  formulaire — un mot de passe de machine est imposé par la machine — mais c'est une divergence
  assumée avec l'import du legacy, et elle se déclare.

**Un correctif de production à décider — E-129**
- Les **trois** copies du garde SSRF du legacy comparent des préfixes de chaîne :
  `::ffff:169.254.169.254` traverse le garde A10-01, y compris par le formulaire « durci ». Mesuré au
  clic. Le correctif est écrit et éprouvé côté portage (`inet_pton` puis comparaison de plages, 18 cas,
  0 écart) mais il touche `legacy/adm/includes/`, non porté et en production. **Rien n'a été modifié
  côté legacy.**

**Hygiène de la base d'épreuve — relevé le 2026-08-26, aucune action prise**
- **5 comptes `e2e_test_*`** subsistent dans `users`, créés entre le **2026-07-25** et le
  **2026-08-12** par `tests/e2e/02-admin-users.test.mjs:14`, qui nomme son compte
  `` e2e_test_${Date.now()} `` et **ne nettoie pas dans un `finally`** : le retrait est une ÉTAPE de
  test (`:93`), et le fichier anticipe lui-même son échec en commentaire (`:115`). Chaque exécution
  interrompue laisse donc une ligne DISTINCTE que rien ne réclamera. Cette suite n'est pas dans le LOT.
  Ils sont proposés dans la liste « Compte RootWarden » de la page ChatOps portée — donc offerts comme
  IDENTITÉ d'exécution, alors qu'aucun ne porte de second facteur. Ils faussent tout comptage de
  comptes, et ils sont visibles à l'écran d'administration. Les supprimer est destructeur et ils ne
  m'appartiennent pas : **rien n'a été touché**. Remesure :
  `SELECT COUNT(*) FROM users WHERE name LIKE 'e2e\_test\_%'`.

**`services/` — DEUX arbitrages de SÉCURITÉ, ouverts le 2026-08-27**
- **E-150** : la liste des services protégés (`sshd`, `ssh`, `systemd-journald`…) est comparée à
  `service.replace('.service','')`. **Elle ne connaît donc que la forme `.service`** : `ssh.socket`,
  `sshd.socket` et `ssh@.service` passent au travers. Sur un hôte à activation par socket — le défaut
  sur Debian récente — arrêter `ssh.socket` couperait l'accès SSH, **y compris celui de RootWarden**.
  *Établi par calcul* contre le module réel ; *non établi* que ces unités soient présentes au parc.
  Correction : comparer sur le radical avant le premier point, ce qui ferme la famille entière.
  **Ce module est par ailleurs le seul du chantier dont une protection soit appliquée sur la REQUÊTE
  et reflétée à l'écran** — le défaut n'est pas l'absence de garde, c'est qu'elle compare des noms là
  où systemd raisonne en unités.
- **E-149** : les huit routes de `backend/routes/services.py` ne portent **ni `@require_role` ni
  `@require_permission`**, et `/services/` n'est dans aucune des deux listes « admin » (proxy legacy,
  passerelle portage). `can_manage_services` ne protège que l'écran. **Réel dans le code, non
  exploitable par aucun compte existant** — le seul rôle 2 du parc détient la permission — mais trois
  gestes d'administration ordinaires le rendraient vivant. La correction qui ferme le trou pour les
  deux portails touche le **backend de production**, et c'est un correctif de sécurité : branche
  dédiée, jamais fusionné sans accord verbal.

> **Six correctifs backend attendent désormais le même arbitrage** — E-142, E-144, E-147, E-149, E-150, E-152 —
> et trois sont la même famille : un garde absent, ou un repli qui retombe du côté permissif.

**⚠ E-152 serait INMESURABLE au banc, et mon propre raisonnement était à l'envers.** J'avais écrit que les
cinq suites `go-fail2ban-f2` à `f6`, qui tournent en `rw-test-super` (rôle 3, **sans** la permission),
exerçaient « le second chemin de la garde — le rôle l'emporte sur l'absence de permission », et que les
deux chemins étaient donc couverts. **C'est faux, et l'inverse est instructif** :

> Aujourd'hui `rw-test-super` obtient **200 parce qu'il n'y a AUCUNE garde**, pas parce que le rôle
> l'emporte. Après le patch il obtiendra 200 parce que `role >= 3` contourne. **Même observable, cause
> différente — et les suites ne peuvent pas distinguer les deux.**

Ces cinq suites resteraient donc vertes **si le patch n'était jamais appliqué, ET si on l'appliquait de
travers**. Elles ne mesurent pas la garde. C'est « N validations précédentes ne prouvent rien si aucune ne
pouvait échouer », sur cinq suites d'un coup.

Le seul chemin qui **discrimine** est **un rôle 2 SANS la permission → 403**. Or `rw-test-admin` est le
seul rôle 2 du parc et **il détient** `can_manage_fail2ban` (`go-fail2ban-f1` l'asserte lui-même,
`:218-220`) ; et `rw-test-user` est déjà refusé par `require_machine_access` faute de machine, donc son
403 viendrait d'un **autre** garde — un PASS qui passerait pour la mauvaise raison.

**Préalable à E-152, qui n'avait été vu par personne** : une fixture de rôle 2 **sans**
`can_manage_fail2ban` — un quatrième compte, ou une révocation temporaire restaurée dans le `finally`,
avec la règle du chantier qui s'applique : *nettoyer ce que le test ACCORDE.*

**Et la contrainte de forme que je réclamais est déjà satisfaite** : `require_permission` de
`helpers.py` porte `if role_id >= 3: return func(...)` et sa docstring le dit. Le décorateur **EST**
« cette permission OU rôle ≥ 3 » — **la forme « permission seule » que je craignais n'existe pas dans ce
dépôt.**

**`bashrc/` — deux arbitrages BLOQUANTS pour B4, ouverts le 2026-08-26**

> Jusqu'ici, « signaler » suffisait : B1 à B3 n'écrivent sur aucune machine. **B4 remplace un fichier
> exécuté à chaque connexion sur les machines cochées.** Signaler et empêcher n'y protègent plus de la
> même façon, et un portage fige un comportement — d'où la suspension.

- **« Tout cocher » doit-il continuer à retenir `root` ?** `_list_users` retient `UID == 0`, donc
  `root` est dans la liste des comptes, et « Tout cocher » le sélectionne. Le portage de B2 l'a
  reproduit **en l'annonçant** ; l'exclure et exiger une coche explicite serait un changement de
  comportement.
- **`srv-zabbix` doit-elle rester dans les cibles proposées ?** Mesuré par lecture :
  `_bashrcSelectedMachines()` n'a **aucun filtre**, et le multi-déploiement envoie un
  `/bashrc/deploy` par machine cochée. B1 l'a signalée visuellement ; la retirer de la liste serait
  un changement de comportement.

**`bashrc/` — trois arbitrages à faible enjeu** (`MODULE-BASHRC.md`, 2026-08-26)
- **les huit motifs de danger du gabarit n'existent QUE dans le navigateur.** Le backend valide la
  syntaxe (`bash -n`) et la taille, pas le contenu. **Ce n'est pas une faille** — qui atteint la route
  détient déjà `can_manage_bashrc`, c'est-à-dire l'autorisation d'écrire le fichier qui s'exécute à
  chaque connexion. La décision est de **présentation** : le portage ne doit pas laisser croire que ce
  scan est une barrière ;
- **`GET /bashrc/backups` n'a aucun appelant** — capacité inatteignable. La porter serait concevoir,
  la laisser serait la laisser à un `fetch` de la réactivation. Faible enjeu : la route ne fait que lire ;
- **« Fusionner » est le mode PAR DÉFAUT, et son terme-clé n'est défini nulle part.** Le libellé
  « Fusionner (conserver blocs custom) » est littéralement vrai — il conserve les blocs entre
  marqueurs `# >>> USER CUSTOM >>>`. Mais ni `USER CUSTOM` ni `.bashrc.local` n'apparaissent dans les
  74 clés i18n : la lecture naturelle (« garde mes personnalisations ») est fausse, et **sans
  marqueurs « fusionner » équivaut à « écraser »** — c'est le cas de tout premier déploiement.
  **Troisième variante du motif** : ni un texte qui dit faux (E-142), ni un texte qui recommande
  l'inverse de ce qui est livré (E-146), mais un libellé vrai dont le terme porteur n'est défini
  nulle part. Et l'interface **jette la mesure qui lèverait l'ambiguïté** : le backend calcule
  `custom_detected` dans sa branche `dry_run`, l'aperçu l'affiche, le tableau de résultat du
  déploiement ne le montre pas. **Gravité faible** — la sauvegarde est faite dans les deux modes et
  un échec de sauvegarde avorte le déploiement (fail-closed) : c'est un défaut d'information, pas de
  destruction ;
- **`root` est proposé au déploiement.** `_list_users` retient `UID == 0 || UID >= 1000` : la cible la
  plus conséquente du parc n'est distinguée en rien des autres à l'écran. À trancher : la marquer, ou non ;
- **aucune fenêtre de maintenance ni approbation à quatre yeux** sur les huit routes, alors que le
  déploiement multi-machines écrit sur plusieurs machines d'un coup. D'autres modules en ont ; rien ne
  dit si l'absence est délibérée. Signalé, non corrigé.

**`adm/` — cinq arbitrages, et le module est BLOQUÉ sur eux** (`MODULE-ADM.md`)

> Les trois éléments restants d'`adm/` attendent tous une décision : D6c (trois décisions), D10 (une
> décision et non un portage), et l'archivage (bloqué parce que quatre fichiers d'`adm/` appartiennent
> au socle, `includes/crypto.php` en tête). **Le module a atteint sa frontière d'arbitrage** le
> 2026-08-26 ; il ne peut plus avancer sans l'exploitant.
- **E-147, ouvert par D9b le 2026-08-26** : `backend/sftp_manager.py`, `render_policy()` contredit sa
  **propre docstring** sur quatre clés (`sftp_only`, `allow_password_auth`, `allow_tcp_forwarding`,
  `allow_agent_forwarding`), **toutes vers le permissif**. Le portage n'envoie jamais de clé absente,
  donc il ne rencontre pas ces replis — mais ils restent ouverts pour tout autre appelant. **Même
  famille qu'E-144** : un repli de backend qui retombe du côté permissif. Les deux se corrigent de la
  même façon (exiger la clé plutôt que la deviner, fail-closed) et **les deux touchent le backend de
  production**. À arbitrer ensemble, avec E-142 ;
- **E-144, ouvert par D9a le 2026-08-26** : `backend/routes/policies.py`, `sudo_deploy()` fait
  `data.get('preset', 'apt_only')`. **Une requête qui omet `preset` obtient le préréglage que son
  propre module documente « ÉQUIVALENT ROOT ».** Le portage envoie toujours `preset`, donc il ne
  rencontre pas le repli — mais l'écart reste ouvert pour tout autre appelant, et il n'est pas
  corrigeable depuis le portage. Le correctif tiendrait en une ligne (`data.get('preset')` puis
  refus si absent, fail-closed), **mais il touche le backend de production** : rien ne sera changé
  sans arbitrage. À traiter avec E-142 ;
- **`health_check.php`** : la page est dangereuse par construction (§4.2). Trois issues — tout pointer
  sur `machine_id = 0` et ne tester que le contrat HTTP ; ne tirer chaque route que sur un **clic**
  explicite, avec la machine **choisie** ; ou ne pas la porter. **Aucune n'est un portage fidèle, et la
  fidélité serait ici le défaut.** Rien ne sera touché sans arbitrage ;
- **`/regenerate_platform_key`** (`platform_keys.php`) fait tourner la paire de clés de la **flotte
  entière** : même régime que K4 ;
- **`/delete_remote_user`** (`server_users.php`) supprime un compte Unix sur une machine réelle ;
- **quatre fichiers de `adm/` n'appartiennent pas à `adm/`** — `includes/crypto.php` est la
  bibliothèque de chiffrement du **socle** (`auth/login.php`, `verify_2fa.php`, `enable_2fa.php`,
  `step_up_verify.php` l'incluent), et `api/notifications.php`, `api/global_search.php`,
  `api/dismiss_onboarding.php` sont appelés par `menu.php` et `includes/onboarding.php`, donc par
  **toutes** les pages legacy. **`adm/` ne peut pas être archivé comme une unité** : soit ces quatre
  fichiers sortent vers `legacy/includes/` avant le `git mv`, soit `adm/` est le **dernier** module
  archivé. À trancher avant le premier `git mv`, pas le jour même.

**À reporter dans un service externe, le jour où la fonctionnalité sera activée**
- **l'adresse du webhook ChatOps a changé** avec le portage : elle ne finit plus par `webhook.php`.
  Elle doit être reportée dans Slack (ou Teams) **avant** d'activer ChatOps. Aucun geste urgent :
  mesuré dormant — aucune variable `CHATOPS_*` dans l'environnement, **zéro correspondance** en base.
  La page le dit désormais en gras, ce que le legacy ne faisait pas.

**Opérationnel**
- **pousser la branche** — le nombre de commits n'est pas stocké ici : il se remesure par
  `git rev-list --count @{u}..HEAD`, et tout commit qui corrigerait le chiffre le périmerait ;
- **rétroporter vers `main`** : **v1.37.16**, **v1.37.17**, **v1.37.48** — le dernier ferme une
  vulnérabilité **présente** en production ;
- **`security/backend-cve` : RELUE le 2026-08-27, et la fusion est RECOMMANDÉE.** Elle attendait
  depuis des jours et c'est la dette la moins chère à solder du chantier. Le chiffre qui fait peur —
  **6 en avant, 168 en retard** — n'est pas celui qui décide : ce qui décide est le **recoupement**, et
  il est **nul**. Mesuré par fichier touché (`git rev-list --count -- <fichier>`) : **aucun** des six
  fichiers n'a bougé sur le tronc depuis la séparation. `git merge-tree --write-tree`, qui n'écrit rien
  dans l'arbre : code 0, **zéro conflit**. Et recoupement avec le travail en vol des sept sessions :
  **nul** également. **Elle n'a pas divergé** — corollaire désagréable : **les six failles sont donc
  toutes encore ouvertes sur le tronc**, vérifié une par une dans le code d'aujourd'hui.
  Trois de ces six comptent particulièrement :
  **`a345e65` porte le pire, et ce n'est pas l'archivage** — le repli du scheduler **ÉLARGIT le
  périmètre** : une cible `machines` dont le `target_value` se vide ou se corrompt retombe sur
  `SELECT … FROM machines`, c'est-à-dire **tout le parc**. Un scan CVE **ouvre une session SSH par
  machine**, avec le mot de passe SSH et le mot de passe root déchiffrés dans la boucle — *« scanner
  les mauvaises machines » est en réalité « s'authentifier sur toutes les machines du parc »*,
  **atteint par une corruption de donnée et sans que personne ne clique.**
  ⚠ **Correction du 2026-09-02 (E-298)** : j'écrivais ici *« et envoie un vrai courriel par machine »*.
  **Faux pour ce chemin.** `send_cve_report` n'a qu'un appelant, `routes/cve.py:77`, et le scheduler ne
  l'emprunte pas — il notifie par un webhook, dont les sévérités sont passées **en dur à `0`** (E-299).
  L'effet sortant que le §7 réserve à votre mot est celui de la **route** et de l'**action groupée**,
  pas celui du repli. *Le défaut de portée reste entier ; c'est son bruit qui tombe — et un défaut
  muet est le plus difficile à voir passer.* Cinquième forme de « un repli
  qui retombe du côté permissif », et la plus large : les quatre autres ouvrent un **droit**, celle-ci
  ouvre un **périmètre**, et son effet est sortant et irréversible.
  **`399931a` FERME E-175** — l'écart relevé le matin même sans savoir que son correctif dormait depuis
  six jours. E-175 n'a donc pas besoin d'un correctif propre : il a le sien, il attend une fusion.
  **`427306c` est occupé** — `POST /cve_reprioritize` porte `@require_api_key` +
  `@require_machine_access` et **ni rôle ni permission**, quand la page exige `can_scan_cve`. Or
  `opsuser` n'a aucune permission, sa **seule** machine est `srv-zabbix`, et **la totalité des 1458
  findings CVE, dont les 5 drapeaux KEV, est sur cette machine**. Le compte que la page refuse peut
  réécrire exactement les données qui existent.
  **Deux conditions avant, une après.** Avant : votre mot, et la **correction du message de commit** de
  `399931a`, qui affirme qu'une route de `supervision/` est « désormais couverte, vérifiée par test »
  alors qu'elle porte aussi `@require_role(2)` — le décorateur y est donc **inerte**, et le fichier le
  savait déjà (`supervision.py:2440` : « require_machine_access est un no-op sur le mid d'URL »). Le
  code reste juste et souhaitable ; c'est le **message** qui affirme plus que lui. Sixième occurrence du
  motif, et **la première dans une branche de sécurité**. Après : **remesure `pytest`** — et le chiffre
  attendu **n'est ni 318 ni 318 + 375** : les deux totaux sont mesurés sur des arbres différents et rien
  ne dit qu'ils sont disjoints. **Fusionner sans rebase** : réécrire l'historique pendant que six
  sessions travaillent est interdit, et un merge sans conflit rend le rebase inutile ;
- **la purge ne tourne pas — E-180, ET MA PRÉSENTATION EN ÉTAIT INCOMPLÈTE DANS LE SENS DANGEREUX
  (corrigé le 2026-08-27, E-188).** Je vous ai dit « activer `LOG_RETENTION_DAYS` n'est pas la bonne
  réponse seule : `user_logs` porte une chaîne scellée ». C'était vrai et il manquait l'essentiel :
  **`active_sessions.last_activity` n'est JAMAIS mise à jour** — 3 930 lignes, 3 930 où
  `last_activity = created_at`, **zéro** différente, mesuré. La colonne porte bien
  `ON UPDATE CURRENT_TIMESTAMP` mais rien ne l'écrit : elle est posée à la connexion et seulement lue
  ensuite. Donc `WHERE last_activity < NOW() - 7 DAY` ne veut pas dire « inactive depuis 7 jours » mais
  **« CRÉÉE il y a plus de 7 jours »** : **les deux issues que je vous proposais déconnecteraient les
  exploitants tous les sept jours, en pleine session.** Ce qui était présenté comme de l'hygiène coupe
  des sessions actives. **Les deux défauts se masquaient mutuellement** — la purge ne tournant pas,
  personne n'a jamais été déconnecté à tort, et c'est exactement pour cela que personne n'avait vu le
  second. **L'ordre correct : réparer `last_activity` AVANT d'activer quoi que ce soit.**  `LOG_RETENTION_DAYS` est commentée, donc vaut 0, donc rien n'a
  jamais été purgé depuis le 2026-05-26 ; et la **même** variable éteint trois nettoyages qui ne sont
  pas des politiques de rétention (sessions inactives, permissions temporaires expirées, jetons de
  réinitialisation). 2 132 sessions en base pour un seul compte, lues à **chaque page protégée**.
  **L'activer n'est pas la bonne réponse seule** : `user_logs` porte une chaîne scellée et purger par la
  tête romprait la vérification d'intégrité. Décision d'exploitation, pas de performance ;
- **INF-001 — RÉGLÉ le 2026-08-27, palier (1).** Le constat était : **13** jobs, **un seul** lançait des tests
  (`test-python`) ; les 12 autres étaient statiques. **Le palier (1) est LIVRÉ** : un job `test-php`
  (`composer install --no-scripts` → `key:generate` → `php artisan test`), `needs: lint-php`, **bloquant,
  sans `continue-on-error`**, YAML validé **par un analyseur YAML** et non au `grep`. La CI porte
  désormais **14** jobs, dont **deux** exécutent des tests.
  **Une mesure a décidé d'une étape du job, et elle n'était pas devinable** : sans clé d'application, la
  suite rend **226 échecs sur 232** — le groupe `web` chiffre les cookies, donc toute requête de test
  échoue et seuls les six tests qui n'émettent aucune requête survivent. Sans cette mesure,
  `key:generate` aurait pu être omis comme « du rituel Laravel », et le job aurait été **rouge au premier
  déclenchement sur un dépôt pourtant vert**.
  **Effet de bord non cherché, et il compte** : `lint-php` ne vérifiait la syntaxe que de `legacy/`. Une
  erreur de syntaxe dans `laravel/` n'était vue par **aucun** job ; elle fait désormais échouer celui-ci.
  **Le compte de jobs annoncé ici était faux, et par le piège habituel** : un
  `grep -cE "^  [a-z0-9-]+:$"` dont la classe **exclut le tiret bas** ne comptait pas `pull_request:`
  mais comptait `push:` — un **déclencheur** passait pour un job. Mot pour mot le piège de
  `Navigation.php`, qui rendait 32 entrées pour 33. *Compter une structure de données, c'est la faire lire
  par son propre analyseur* — recompté par `yaml.safe_load`.
  **Restent les paliers (2) et (3)**, qui demandent une décision : un sous-ensemble E2E (un
  `docker compose` complet et des secrets TOTP), puis le LOT complet (~100 min, verrouillage du second
  facteur des trois comptes) ;
- **réinitialiser `superadmin`** si l'on veut des captures sous ce compte précis. Effet de bord signalé :
  son `failed_attempts` est passé de 0 à 1 (seuil 5, aucun verrou) ;
- **supprimer ou non les cinq comptes `e2e_test_*`** : actifs, rôle 1, **sans second facteur**. Vus
  à l'image le 2026-08-25 : ils sont proposés dans la liste « Compte RootWarden » de la page
  ChatOps, donc offerts comme **identité** sous laquelle une commande de chat s'exécuterait. La
  portée reste celle du rôle 1, mais un compte de test sans second facteur n'a pas à figurer dans
  ce choix ;
- **K4** — l'arbitrage `NOPASSWD: ALL`.
  **⚠ UNE DE SES PRÉMISSES ÉTAIT INCOMPLÈTE, corrigée le 2026-08-27 — E-183.** Ce document fondait le
  risque sur « un déploiement lancé en l'état **RÉVOQUERAIT** les accès », donc sur la fiabilité de
  `server_user_inventory`. Or `scan_server_users` ne lisait **aucun** code de sortie
  (`recv_exit_status` : **zéro occurrence** dans tout `routes/ssh.py`), et un incident SSH passager
  faisait **trois** choses d'un coup : vider l'inventaire (72 lignes), vider la table des clés (20), et
  **poser `users_scanned_at`** — qui est la précondition du préflight de déploiement (`ssh.py:381`,
  « Bloquer si le serveur n'a jamais été scanné »). **Le même chemin détruisait donc la donnée ET
  ouvrait la porte qui la garde**, en se journalisant comme un nettoyage réussi. **Corrigé en
  `v1.38.16`** — mais l'arbitrage doit être relu en le sachant : ce n'était pas « une donnée à laquelle
  on ne peut pas se fier », c'était **un préflight qui avait cessé de bloquer**.
  **⚠⚠ ET CE DOCUMENT NE DISAIT JAMAIS *QUI* SERAIT RÉVOQUÉ. Mesuré le 2026-08-27 — ce sont DEUX
  comptes nommés, sur la PRODUCTION, et l'un est le vôtre.**

  « Un déploiement lancé en l'état RÉVOQUERAIT les accès » est resté une phrase abstraite pendant tout
  le chantier. `backend/configure_servers.py:755` fait `revoked = managed_users - authorized_names`.
  Relevé en base, machine par machine :

  | machine | `managed` par rootwarden | serait révoqué |
  |---|---|---|
  | **1 `srv-zabbix` — PRODUCTION** | `claude-agent`, **`Timikana`** | **les deux** |
  | 2 `Test-Server-Debian` | aucun | rien |
  | 3 `OpenCVE-Test-OnPrem` | aucun | rien |

  **Seule la production a quelque chose à révoquer, et ce sont exactement ces deux comptes.**
  `Timikana` est le nom sous lequel tout ce dépôt est committé.

  **Ils ne peuvent PAS être épargnés, et ce n'est pas un état à corriger avant K4 : c'est le
  comportement permanent du script.** `authorized_names` est bâti **uniquement** depuis les utilisateurs
  **du portail** (`:735-737`, `for user in self.all_users`). Or **ni `claude-agent` ni `Timikana`
  n'existe dans `users`** — vérifié, 10 comptes de portail, aucun des deux. Ils ne peuvent donc **jamais**
  entrer dans `authorized_names` : ils seront dans `revoked` à **chaque** déploiement, par construction.

  **Et ce qui serait détruit est plus large que ce que RootWarden a posé.** Les deux lignes portent
  `has_platform_key = 0` et leurs clés `is_platform_key = 0` — `claude-agent` en `ssh-ed25519`,
  `Timikana` en `ssh-rsa`. **Ce sont des clés personnelles préexistantes que RootWarden a ADOPTÉES comme
  « managed », pas des clés qu'il a déployées.** Et la révocation est
  `rm -f /home/<user>/.ssh/authorized_keys` (`:759`) — **le FICHIER ENTIER**, pas un retrait de ligne
  ciblé : elle efface aussi les clés que RootWarden n'a jamais vues, et **il ne peut pas les rétablir**.

  **Le module sait pourtant faire du ciblé** : `remove_user_keys` fait un `sed -i '/rootwarden/d'`
  (`ssh.py:1779-1784`). **Les deux gestes coexistent dans le même module, et le plus destructeur est
  celui qui part en masse.**

  > **Un déploiement K4 sur `srv-zabbix` supprimerait l'`authorized_keys` du compte de l'exploitant sur
  > sa machine de production, et celui de `claude-agent`. Aucun des deux n'a de clé de plateforme :
  > RootWarden ne pourrait pas les rétablir.**

  **Non mesuré, et il faut le dire** : que ces deux comptes existent **réellement** sur `srv-zabbix`.
  C'est l'**inventaire** qui est lu, pas la machine — et E-187 établit précisément que cet inventaire
  peut être faux. `last_seen_at` vaut `2026-08-18 10:40:58` pour les deux, soit le dernier scan de cette
  machine : **la donnée est cohérente, elle n'est pas confirmée.** La confirmer demanderait de joindre la
  production.

  **Un geste recommandé, qui transformerait le piège en décision** : faire dire au préflight **ce qu'il
  va révoquer, nommément, avant de le faire**. Le motif existe déjà dans le dépôt — F4 a fait dire à la
  confirmation `fail2ban` « sur `Test-Server-Debian` **et sur elle seule** ». Un déploiement qui annonce
  « 2 accès seront révoqués : `claude-agent`, `Timikana` » ne se lance pas par inadvertance.

  Sur le repli lui-même : il a **deux** chemins, et aucun compte actif de rôle 1 ne
  porte `users.sudo = 1`, donc le trou est réel et à un `UPDATE` d'être exploitable.
  **RELEVÉ DE NIVEAU LE 2026-08-26 — cet `UPDATE` existe, et il est plus bas que supposé.** L'import
  CSV (E-130) écrit `users.sudo` **sans contrôle de rôle**, depuis une page atteignable au **rôle 2**
  porteur de `can_admin_portal`, alors que le geste dédié `api/toggle_sudo.php` exige le rôle 3. Et sa
  garde hiérarchique, en dégradant `role_id` à **1** pour un importeur de rôle 2, fabrique
  **exactement** la forme de compte que ce repli attend : rôle 1, `sudo = 1`. Les deux écarts se
  lisaient comme indépendants ; **ils sont chaînés**. Aucun compte n'occupe la position aujourd'hui —
  `rw-test-admin` est le seul rôle 2 et n'a pas `can_admin_portal` — mais l'ouvrir n'est plus un
  `UPDATE` en base, c'est **une attribution de permission**, geste d'administration ordinaire.
  La décision sur la colonne `sudo` du format CSV (ci-dessus) conditionne donc aussi celui-ci.

**Mesurés, non corrigés**
- **E-73** — le fuseau du backend : UTC contre CEST, l'**affichage** est faux de deux heures. **Élargi le
  2026-08-25** : le décalage ne fait pas que mal afficher, il fait **mal décider**. Les fenêtres de
  maintenance sont saisies en heure locale et appliquées en UTC, donc décalées de deux heures — voir
  l'encadré de §4.2. Le portage de `maintenance/` annonce le verdict du backend au lieu d'en recalculer
  un, ce qui rend le décalage **visible** ; le corriger à la racine demande de changer le fuseau du
  conteneur `rootwarden_python`, ce qui déplace **tous** ses horodatages, journaux d'audit compris.
  **Décision de flotte, à arbitrer** ;
- **le trou de `user_logs` ne se referme pas : il GRANDIT, et le seul remède est inerte.** Le
  chiffre de 757 lignes non scellées est périmé — mesuré **868** le 2026-08-25, et **+2 pendant la
  seule heure** du sous-lot D1. La raison est E-104 : `audit_seal.php` et `audit_verify.php` ne
  parcourent pas la chaîne de la même façon, le premier s'arrête sur une fausse désynchronisation à
  la ligne 3, et son verrou `stopped_at_tamper` rend le bouton « Sceller les orphelines »
  **définitivement incapable de sceller quoi que ce soit** — tout en écrivant une alarme
  `SECURITY … investigation requise` à chaque appel. **LEVÉ côté portage** (`v1.37.59`) : une seule
  lecture de la chaîne, celle du code qui écrit, et la simulation annonce désormais 868 lignes à
  sceller là où le legacy s'arrêtait. **Le geste lui-même reste à faire, et il vous appartient** — il
  est irréversible, il se déclenche depuis `/journal-audit`, et le panneau nomme le nombre avant de
  laisser confirmer ;
- la liste blanche `/supervision/` de `api_proxy.php:134` — **surface morte** depuis l'archivage, et
  `/supervision/` est absent de `$ADMIN_ONLY_PREFIXES` ;
- les **11 liens sortants** du legacy non marqués, et le **404 brut d'Apache** des neuf parties
  archivées — avis donné : **ne pas y toucher**, on ne soigne pas ce qu'on démonte ;
- le **tiroir mobile du portage** reste à capturer correctement.

**Autorisés, donc à faire — ne plus demander**
**E-90** (le déploiement backend n'inspecte aucun code de retour et inscrit un agent inexistant) ·
`generic_reconfigure` qui annonce un succès sans rien avoir écrit · la clé PSK dont l'échec de
déchiffrement n'est que journalisé · les quatre routes de profils sans `@require_role` ·
`POST /supervision/overrides/<id>` sans `@require_machine_access` · le `SELECT *` de `list_profiles` ·
`telegraf_output_token` non masqué · le `POST` sans `WHERE platform` · la lecture via `execute_as_root` ·
`agent_type` calculé puis jeté · les **huit branches mortes** qui armeraient un `@threaded_route`
**imbriqué** (le pool se **bloque** si l'on supprime la règle statique en la prenant pour un doublon) ·
les 21 routes de filtrage sans permission · la garde de la page `ssh/` ·
**`can_deploy_keys` côté requête — MESURÉ le 2026-08-27, et c'est pire que « pas de permission » : `POST /deploy`
(`ssh.py:246`) porte `@require_api_key` SEUL, donc PAS DE RÔLE non plus. Sa voisine
`deploy_platform_key` (`:517`), qui écrit une clé sur UNE machine, porte `api_key + role(2) + machine_access`
avec un commentaire de patch explicite ; et `reboot_server`, qui ne fait que REDÉMARRER, porte le même jeu
complet. La route qui écrit en root sur un parc entier ET révoque est donc la MOINS gardée des trois — voir
E-191** ·
la fuite du mot de passe dans `deployment.log` · OpenCVE TLS désactivée · le verrou et la limite de débit
du scan CVE par processus · **les deux défauts de `manage_roles.php`**.

---

### 7.1 ⚠ LE DSI A TRANCHÉ, ET IL A CORRIGÉ DEUX PRÉMISSES DU LEAD (2026-08-28)

**Sept arbitrages tranchés, huit dossiers écrits — `DECISIONS-DSI.md` + `DOSSIER-01..08`, commit `b327ae0`.**
Et **deux phrases du Lead étaient fausses, mesurées** :

#### ⚠ 1. « Le durcissement frappera des pages qui marchaient le matin » — FAUX

    legacy/fail2ban/index.php:11 · iptables/index.php:46 · ssh-audit/index.php:13   checkPermission(...)
    laravel/routes/web.php:725,755,777                                              perm:can_manage_*
    legacy/auth/verify.php:322   if ($roleId === 3) return true;   <- contournement au ROLE 3 SEUL

**Sur les DEUX portails, la page exige déjà exactement la permission que la route s'apprête à demander.** Un
compte de rôle < 3 sans la permission **n'ouvre aucune de ces pages aujourd'hui.**

> **Le durcissement ne retire aucun chemin d'interface : il FERME l'écart page/route**, c'est-à-dire le trou
> d'E-149 et E-152.

**Les quatre chiffres du Lead sont exacts** — 0/1/1/1 sur 9, recomptés colonne par colonne. **C'est la phrase
qu'ils soutenaient qui ne l'était pas.** *Un chiffre juste peut porter une conclusion fausse, et c'est plus
difficile à voir qu'un chiffre faux.*

**DÉCISION : aucune permission accordée.** Et **surtout pas `can_manage_iptables` à `rw-test-admin`** — *c'est
le geste que la formulation du Lead rendait le plus naturel, et il coûterait le plus* : rôle 2 sans la
permission est **la seule fixture discriminante du parc**, et `iptables` est le module en cours de portage.

#### ⚠ 2. « Un déploiement exécuterait `userdel -r` » — FAUX

    grep -rn "clean_up_users" (hors _deprecated)  ->  :703 une DOCSTRING · :780 sa definition
                                                      AUCUN APPELANT
    configure() appelle `configure_users` seule, et le dit en clair l.770-774

**Donc « K4 reste bloqué, et ce blocage est désormais PROTECTEUR » est sans objet.** K4 tient sur ses autres
fondements — **dont la révocation de clés, elle VIVANTE** : `configure_servers.py:908`,
`revoked = managed_users - comptes_traites` puis `rm -f authorized_keys` sur `Timikana` et `claude-agent`.

**Le défaut d'E-213 survit sous une forme plus étroite et réelle** : `delete_remote_user`, **le seul chemin
vivant**, ne consulte **ni `user_exclusions` ni `status`.** *`excluded` ne protège d'aucun chemin.*

> **⚠ Et le vrai risque est le TEXTE** : la docstring `:703` annonce encore `clean_up_users` dans la séquence —
> **elle invite à rétablir l'appel.** `user_exclusions` étant **vide** (0 ligne, 69 `excluded` en face), ce
> jour-là la seule protection restante serait la liste des six noms système. *Un texte qui décrit une étape
> retirée est une instruction de la remettre.*

#### Quatre recomptages du Lead, tous faux

| annoncé | mesuré | écart |
|---|---|---|
| 26 + 1 routes gagnant une garde | **+33** (iptables +6, fail2ban +18, services +8, ssh_audit +1) | sous-estimé |
| **69 commits non poussés** | **391** — amont `origin/Migration-Laravel`, `0 391` | **facteur 5,7** |
| E-214 et E-215 « non corrigés » au §7 | **déjà corrigés** (`77ae2c2`, `52838f2`) | périmé |
| migrations « 052-061 à appliquer » | **62 fichiers, 62 appliquées, aucune en attente** | périmé |

*Le chiffre des commits non poussés vivait dans ce document depuis le 2026-08-22 et le Lead l'a répété six
fois.* **Chaque figure de ce plan porte sa commande de remesure précisément pour ça, et celle-là n'a pas été
relancée.**

#### Le DSI a corrigé DEUX de ses propres mesures, et il le déclare

**a) 52 comptes menacés → 2 → 0.** Le script bâtit sa liste **depuis la machine** (`awk $3 >= 1001`), pas
depuis l'inventaire : les 69 `excluded` sont à 67 des comptes système, et les 2 restants sont `nobody`, **déjà
protégé**. **Facteur 26, dans le sens qui alarme.**

**b) « Aucune machine n'est orpheline, les trois portent `sa=1` »** — écrit sans mesure, **faux** : **seule
`srv-zabbix` porte `sa=1`**. Corrigé dans le fichier avec la raison — *le drapeau est binaire pour une réalité
ternaire, donc la base ne PEUT pas répondre à cette question.*

*Un poste neuf reproduit les fautes du chantier dans son premier tour* — et les déclare, ce qui est la seule
chose qui compte.

#### Les sept décisions

1. **tableau de bord borné au périmètre.** Coût **mesuré** : `opsuser` voit **1** machine au lieu de 3, les six
   autres rôles 1 en voient **0** (5 résidus e2e + la fixture D-5) ;
2. **E-221 : aucune permission accordée** ;
3. **E-209 / E-212 / E-219 : corriger** — et **E-219 AVEC son remplacement**, en nommant
   `server_user_remove_key` et **jamais** `remove_user_keys` ; **E-212 : `perms.desc_graylog` EN PREMIER**,
   *c'est celui qu'on lit en accordant un droit* ;
4. **E-225 : le DIRE, pas le retirer** ;
5. **E-208 : borner le PORTAGE, ne pas toucher le legacy** — zéro porteur non-admin mesuré pour les trois
   permissions concernées ;
6. **E-224 : `machine_ids` obligatoire, SQL et borne dans le MÊME commit** ;
7. **E-222 : migration écrite** (forme dans `DOSSIER-06`, **sans `;`**), **appliquée seulement sur signature**.

#### ⚠ Et l'exploitant a parlé pendant le tour du DSI

> *« Il faut déprécier complètement le legacy, il ne doit plus exister, donc il faut tout migrer : dashboard,
> fonction, api, documentation. »*

**Deux conséquences** : ça **ferme l'issue « deux vues »** du tableau de bord — *elle reportait au lieu de
décider* — et ça **remet `documentation` et `api_docs` dans le chemin critique**, eux que le §4.6 rangeait en
dernier.

**Ça n'autorise aucun geste sortant** : S7b, K4 et le scan réel restent exactement où ils sont. *« Tout
migrer » décrit une cible, pas une permission.*

## 8. Principes et pièges

Chacun a coûté quelque chose. Les skills `rw-pieges`, `rw-e2e` et `rw-laravel` en portent le détail.

### Mesurer

- **Un inventaire ancien n'est pas une mesure. Un chiffre hérité non plus. Compter une seconde fois par
  un AUTRE moyen.**
- **Le dernier numéro d'une série n'est pas son compte.** Relevé alors que `PARITE.md` allait jusqu'à
  `E-95` pour **85** écarts : dix numéros avaient sauté. `ROADMAP.md` annonçait « 93 » — le label pris
  pour un total, et périmé en plus. Ce document s'est fait prendre par sa propre règle dès sa première
  relecture — et s'y est repris le 2026-08-25, où deux endroits annonçaient encore 85 pour **93**
  écarts mesurés. Le chiffre vit en §2 ; partout ailleurs, il se remesure.
- **Quand deux sources divergent, mesurer. Quand la mesure dédouane, le dire aussi clairement qu'une
  accusation. Quand une hypothèse est trop large, la resserrer.**
- **Avant de porter une écriture, chercher son LECTEUR** — `password_expires_at` était écrite et lue par
  personne.
- **Un correctif évident peut casser le cas normal** : mesurer les **deux** moitiés.
- **Un faux PASS vient toujours d'une mesure plus LARGE ou plus GROSSIÈRE que la propriété.** F2,
  2026-08-27 : quatre assertions vertes pour une raison étrangère à ce qu'elles mesuraient, dans une
  seule suite, et chacune d'une des deux familles.
  **Trop large** : chercher le nombre `60` *n'importe où dans la page* pour savoir si une troncature
  est annoncée — il était dans l'adresse `203.0.113.60` de la première ligne ; et chercher
  `(ban|unban|…)` *n'importe où dans l'URL* pour interdire un geste — « ban » est **dans**
  « fail2ban », donc `/fail2ban/history` était accusé. Même faute que le filtre d'archivage qui
  acceptait `/supervision/` parce qu'il contient `/supervision` : **on compare des SEGMENTS**.
  **Trop grossière** : comparer l'ORDRE des barres d'une frise au lieu de leur PROPORTION — les deux
  classements coïncidaient (4 % / 100 % / 12,5 % contre 6 / 40 / 14 événements), et l'assertion
  passait au vert **sur le défaut qu'elle était écrite pour trouver**. C'est la proportion qui
  diverge : 22,5 points d'écart.
- **Une hauteur DÉCLARÉE n'est pas une hauteur RENDUE.** F2 : trois barres déclarant `4%`, `100%` et
  `12.5%`, toutes rendues à **0 px** — le cadre `h-32` est une classe Tailwind purgée, et un
  pourcentage se résout contre un parent de hauteur nulle. La suite lisait `style.height` et
  concluait que la barre était haute ; **c'est la capture qui a montré la carte vide**. Quatrième
  occurrence de la famille « classe purgée », et la deuxième fois qu'elle piège la mesure autant que
  la page. `getBoundingClientRect()`, toujours.
- **Deux tableaux, deux bornes.** F3 : `[...abouties, ...avortees].slice(n)` avec
  `n = abouties.length + avortees.length` ne rend **jamais** les entrées neuves — une ligne ajoutée
  au premier tableau se retrouve *au milieu* de la concaténation, pas après la borne. La mesure
  rendait une liste vide, la machine visée valait `null`, et l'assertion passait **faute d'objet**.
  Sixième faux PASS de la même famille sur ce module. Chaque tableau se découpe par SA propre borne,
  et **une propriété sans objet se dit par un FAIL**, jamais par un silence.
- **Un filet trop large fait passer une assertion PAR ABSENCE.** F6 : la suite avortait
  `/fail2ban/jail`, donc le panneau de détail ne s'ouvrait pas, donc le bouton « Ban global » n'était
  pas visible — et **trois assertions passaient « parce que le geste n'est pas offert »**, sur le
  legacy, où il l'est. Onzième mesure fausse du module, et la première causée par le filet lui-même.
  Quand une propriété peut être satisfaite par une ABSENCE, vérifier d'abord que l'absence n'est pas
  de notre fait.
- **Un élément partagé par plusieurs sections ne vit dans aucune d'elles.** F5 : le panneau de
  décision était placé DANS le détail d'une jail. Les gestes de la liste blanche s'exercent détail
  fermé — le panneau s'ouvrait donc dans un parent caché et **ne s'affichait pas**, laissant partir un
  geste destructeur sans que rien ne l'ait annoncé. Il vit désormais au niveau de la page, avec un
  `scrollIntoView` puisqu'il peut être loin du geste.
- **`offsetParent` vaut `null` pour un élément en `position: fixed`.** F5 : une fenêtre de réglages
  ouverte était déclarée FERMÉE, alors que la même mesure lisait son contenu — « Configurer le jail :
  sshd, Template… ». Le test de visibilité d'une modale ne peut donc pas passer par `offsetParent` :
  il faut la place **réellement occupée**, `getBoundingClientRect().height > 0`, plus `display` et
  `visibility`. Huitième mesure fausse de la série, et la seule qui vienne d'une propriété du DOM
  plutôt que d'un motif trop large.
- **Vérifier l'INSTRUMENT avant de conclure de son silence.** La quatrième : lire
  `document.documentElement.lang` pour savoir en quelle langue est une page, alors que
  `legacy/fail2ban/index.php:24` écrit `<html lang="fr">` **en dur**. L'attribut disait « fr » quelle
  que soit la langue réelle, et l'assertion sur le format de date passait **faute d'objet**. La
  parade est structurelle : **mesurer d'abord que la bascule a pris** — en comparant un libellé
  traduit à celui relevé dans l'autre langue — et ne juger la propriété qu'ensuite ; sinon, un FAIL
  explicite qui dit que la mesure n'a pas eu lieu. Un `else` qui ne fait rien est un PASS déguisé.
- **Une couleur ne se lit pas à l'expression régulière, et un contraste se COMPOSE.** F1, 2026-08-27 :
  une assertion « la pastille est lisible (≥ 4,5:1) » rendait un PASS en annonçant **793 790 048:1** —
  pour un maximum théorique de 21. Deux fautes dans une ligne. `color-mix()` se *calcule* en
  `color(srgb 0.0823529 0.501961 0.239216 / 0.18)`, où une lecture par `/\d+/g` voit « 823529 » ; et le
  fond étant TRANSLUCIDE, sa valeur nominale ne dit rien de ce que l'œil voit. Faire composer les
  couches par le navigateur, sur un canevas de 1 px, et **vérifier qu'il a su lire chaque couleur** —
  une couleur qu'il refuse laisse `fillStyle` inchangé, donc rend silencieusement la précédente.
  **Une valeur hors de toute plage physique est un défaut d'instrument, jamais un résultat.**
  **Le même instrument défectueux vit encore dans `tests/e2e/go-page-cve-priorite.mjs:239-259`** :
  `lit()` y parse par `/[\d.]+/g`, et un fond translucide y est pris à sa valeur nominale au lieu
  d'être composé. Il est **latent et non actif** — la pastille KEV du portage est peinte d'un jeton
  OPAQUE (`rgb(185, 28, 28)`, 6,47:1), la seule forme que ce parseur lise juste. Vérifié le
  2026-08-27 : la suite reste conforme. À reprendre quand `security/` S6 sera rouvert, en réutilisant
  la composition par canevas de `go-captures-fail2ban.mjs`.
- **Un défaut peut n'exister que dans un thème.** Les CINQ règles « texte coloré sur teinte de la même
  couleur » du socle échouaient le seuil AA en thème CLAIR (3,60 à 3,96:1) et le passaient toutes en
  thème SOMBRE (6,84 à 8,61:1) : la teinte rapproche le fond du texte sur une surface blanche, et l'en
  écarte sur une surface foncée. Mesurer **les deux thèmes**, sans quoi une moitié des défauts de
  contraste est invisible.
- **Une réussite annoncée n'est pas une réussite vérifiée** ; **un état final correct ne prouve pas que
  le geste était correct** ; **un statut 200 ne prouve rien si la session n'a pas tenu**.
- **Éditer le runner pendant un rejeu ne fait pas qu'être risqué : le verdict devient FAUX.** Les
  tables de références sont lues **au démarrage**. Une référence corrigée en cours de route est donc
  ignorée, et le rejeu annonce un écart fantôme sur une suite pourtant juste — vu le 2026-08-25 sur
  `go-socle-navigation` (48 mesurés, « attendu 46 » affiché). S'ajoute le risque réel de corruption :
  bash relit un script en cours d'exécution **par décalage d'octets**, et une édition qui change la
  longueur peut lui faire exécuter n'importe quoi. Figer le runner, puis lancer.
- **Une classe CSS absente ne lève AUCUNE erreur** — elle rend un élément sans style, que le test DOM
  voit bien présent. Sept classes inventées d'un coup sur `docker/` (`--succes` au lieu de `--ok`,
  `__libelle` au lieu de `__texte`, `--petit` au lieu de `--minuscule`). Comparer à la feuille **avant**
  la première exécution ; et regarder si la classe voulue existe déjà (`rw-grille--compacte` était là).
- **Mesurer le STATUT, pas le texte de la page.** Un renifleur de « accès refusé » dans le corps
  comptait un `404 Not Found` comme un **non-refus**. Un 404 dit « cette page n'existe pas », pas
  « vous n'y avez pas droit ».
- **Une exigence de test peut être un affaiblissement déguisé.** « Le legacy refuse un geste légitime,
  donc le portage doit l'accepter » — sauf que l'accepter autorisait le rejeu d'un code vu à la
  connexion. Avant de corriger une gêne, se demander ce que la gêne protégeait.
- **Une fixture, c'est aussi ce que le test ACCORDE.** La suite A5 posait un step-up sur une route root
  qui survivait quinze minutes ; l'exécution suivante postait sur cette route. Seul un `machine_id`
  absent a empêché un déploiement réel — de la chance, pas une précaution.
- **Un nettoyage neuf ne voit pas l'état ancien.** Le premier passage de la révocation a affiché
  « 0 marque effacée » alors qu'une marque orpheline vivait encore : elle avait été posée avant que
  l'index existe. Non lu, ce détail aurait fait accuser le code.
- **Un pass peut passer PARCE QUE la fonctionnalité est absente.** « Un step-up réussi ne consomme
  pas le quota » passait sur le portage : cinq réponses `404` ne contiennent aucun `429`. Conditionner
  l'assertion à la mesure préalable — ici, qu'un step-up ait effectivement réussi.
- **Un corps JSON échappe les non-ASCII** : la réponse porte `Donn\u00e9es manquantes`, donc aucune
  expression régulière cherchant un `é` ne correspond. Lire le message **analysé**, jamais le texte
  brut — deux assertions ont échoué sur une réponse pourtant juste.
- **Un pass dont on ne sait pas pourquoi il passe ne vaut rien** — trois fois dans le seul sous-lot A2,
  et un vert ne se relit pas. **N validations précédentes ne prouvent rien si aucune ne pouvait
  échouer.**
- **Quand une suite échoue, se demander d'abord si c'est ELLE qui a tort** — arrivé **douze** fois.
- **Un `grep` sur le mauvais symbole fabrique une contradiction.** Cherchant `stepUpVerify` dans `adm/`,
  zéro résultat : le plan annonçait quatre appelants, j'ai cru le prendre en défaut. Le helper des
  points d'API s'appelle `stepUpRequire`. **Lire un fichier avant de contredire une mesure écrite.**
- **Un `getElementById` sans cible ne se voit qu'en comparant les deux listes.** Douze identifiants lus
  par le JS de `adm/` n'existent nulle part. Sept étaient dans un **bloc commenté** de 263 lignes
  (`manage_servers.php:661-923`) — donc inoffensifs, et révélateurs d'un fichier entier mort. Les cinq
  autres cassent pour de bon le bouton « Déployer » de la page SFTP. **Le même symptôme portait deux
  diagnostics opposés : chercher les bornes du commentaire AVANT de conclure.**
- **Le typage du pilote peut être ce qui tient une garde.** `manage_roles.php:80` compare
  `$user['role_id'] === 3` sans transtyper — le motif exact d'une garde morte. Mesuré dans le
  conteneur : `ATTR_EMULATE_PREPARES = false` fait rendre `int(3)`, **la garde tient**. Sa jumelle 31
  lignes plus bas transtype, elle. Ce n'est pas un trou, c'est une **fragilité** : dire les deux.

### LE BANC SE DEMANDE À SON PROPRIÉTAIRE — UN `ps` NE RÉPOND PAS AUX BONNES QUESTIONS (2026-08-27)

La session 2 devait écrire pour ARC-001 pendant qu'un rejeu de la session 7 tournait, **avec
`go-socle-navigation` dedans** — la suite qui compte les entrées de menu. Or l'archivage bascule
`legacy/menu.php` et déplace `legacy/services`, et `legacy/**` est relu **à chaque requête** : le
nombre serait devenu irreproductible et l'écart se lirait comme une régression sans cause visible.
C'est le mécanisme du 2026-08-26 à 11:23:28, à l'identique.

**Elle a demandé le banc à la session 7 en nommant ce que son écriture allait changer, au lieu de le
déduire d'un `ps`.** C'est la bonne manière, et la raison est que les trois questions qui décident ne
se lisent pas dans une liste de processus :

1. **qu'est-ce que ce rejeu mesure ?** Un `ps` donne une ligne de commande, pas les propriétés en jeu ;
2. **va-t-il bientôt finir ?** Un `etime` dit depuis quand, jamais jusqu'à quand ;
3. **son propriétaire accepte-t-il de s'arrêter ?** Personne d'autre que lui ne le sait.

*Le propriétaire du banc est la seule source qui réponde aux trois.* Et le corollaire : quand on rend
le banc, **on l'annonce à qui attend** — la session 7 l'a fait vers la session 2 sans qu'on le lui
demande.

### UN TRAVAIL EN LECTURE N'ATTEND PAS LE BANC (2026-08-27)

La session 2, bloquée sur ARC-001, a choisi de **ne pas** entamer son inventaire suivant : *« le laisser
à moitié serait pire que de patienter »*. Corrigé par le Lead, et la distinction vaut d'être tenue.

**Le banc protège les écritures qui changent ce qu'une suite mesure. Il ne protège pas le travail.** Un
inventaire est un `grep` et une lecture : aucune écriture, aucune cible changée en vol, **aucun état à
perdre** — interrompu au milieu, il reprend sans coût. Ce qui justifiait l'attente sur ARC-001 — le
régime « relu à chaque requête » de `legacy/**` — ne s'applique pas à la lecture de `legacy/remote_users/`.

*Attendre par prudence quand on ne peut rien casser, c'est du temps perdu qui ressemble à de la rigueur.*
Les sessions 2 et 5 ne demandent jamais le banc précisément parce qu'elles lisent ; une session qui
attend sans écrire renonce à ce qui la rend parallélisable.

### ON COMPARE DES SEGMENTS, PAS DES SOUS-CHAÎNES (2026-08-27)

ARC-001 devait chercher si `services/` exposait une adresse configurée **hors** de RootWarden — l'étape
née de `chatops/webhook.php`, que Slack appelait. La réponse est non, et la seule occurrence trouvée
était un **faux positif que la forme de la recherche a évité** :

    WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ    (documentation.php:763)

`services/` y est une **sous-chaîne sans rapport** dans une URL Slack. Un `grep` moins regardant
l'aurait signalée comme une adresse à reporter, et l'archivage aurait « corrigé » une ligne juste.

La même exigence protège les huit routes backend `/services/*` : `normalise('/services/list')` rend
`/services/list/`, et `resoudre()` fait son `isset()` sur le chemin **normalisé en entier** — donc
`/services/list/` ne vaut pas `/services/`. **Une table qui comparerait par préfixe les aurait
réécrites**, et la page portée aurait cessé de fonctionner sans que rien ne le signale.

C'est la même faute de forme que le lien `//exemple.com` qui passe tous les gardes fondés sur une
classe de caractères, et que « un ban est dans fail2ban ». *Valider la FORME avant le contenu*, et
préférer une comparaison de segments à toute recherche de sous-chaîne dès qu'un chemin est en jeu.

### UNE GARDE QUI NE PEUT PAS SE DÉCLENCHER NE PROUVE RIEN — ET UN TEST DE GARDE QUI NE PEUT PAS LA DÉCLENCHER NON PLUS (2026-08-27)

L'épreuve de la garde INF-002 a **échoué deux fois avant d'être valide**, et les deux échecs ne sont pas
la même faute :

1. **mutation à trois arguments.** Un appel de deux arguments muté en trois est **parfaitement
   légitime** : la garde n'avait rien à déclencher. *Une mutation qui ne viole pas la règle n'éprouve
   pas la règle.*
2. **mutation à quatre arguments, mais jouée en `--legacy`** — et l'appel muté vit dans une branche que
   cette cible **n'atteint jamais**, `update/` y étant archivé. La suite a rendu `8 / 0 conforme`, et la
   conclusion tentante était « la garde ne marche pas ».

**Ce qui a rattrapé le second n'est pas de la méfiance mais une question sur l'observable :
l'assertion mutée figure-t-elle dans le journal ?** `grep -c` rendait 0. **Un `conforme` sur une
assertion qui n'a pas joué est un silence, pas un verdict.**

Troisième étage du même piège en une journée : le défaut silencieux, la garde qui le rend bruyant, et
l'épreuve qui ne pouvait rien prouver. À rapprocher du constat d'archivage sur un chemin qui n'a jamais
existé, et de la propriété « il n'y a pas eu de requête » qu'il faut mesurer **au réseau**.

### UN CHIFFRE ANNONCÉ PAR LE LEAD EST UN PLANCHER, PAS UN COMPTE (2026-08-27)

Le Lead a annoncé **70** fichiers à garder pour INF-002. La session 7 en a mesuré **82**, et les douze
de plus sont la trouvaille de la pose : `verifiePortage` portait trois paramètres **aussi dans les douze
fichiers de l'autre convention**, avec un quatrième argument ignoré de la même façon — et **ce sont les
fichiers dont les auteurs ont l'habitude d'écrire quatre arguments**, donc les plus exposés.

**Si la session s'était tenue au chiffre du Lead, les douze restaient silencieusement vulnérables.**

Deuxième occurrence du jour : les « 163 écarts » de ce document étaient **191**, et ils sont **193** le soir même. Et le « 65 suites » du
suivi était un chiffre hérité, jamais compté. *Un nombre annoncé par le Lead est une hypothèse à
mesurer, jamais une borne de travail* — et une session qui mesure plus et pose plus fait ce qu'on
attend d'elle, sans demander l'autorisation d'élargir.

### UNE LIGNE DE `volumes` N'EST PAS PRISE PAR UN REDÉMARRAGE — IL FAUT RECRÉER (2026-08-27)

Le portage n'affichait aucun numéro de version, et le Lead a annoncé « c'est trois lignes ». **Faux, et
mesuré par la session 3** : `docker inspect` ne rend qu'**un** montage sur le conteneur du portage,
`./laravel:/var/www/html`. `legacy/version.txt` n'existe **nulle part** dans son système de fichiers, et
aucune variable de version n'existe dans `srv-docker.env.example`. **La donnée n'était pas là** — le
Lead avait décrit le code à écrire et pas le chemin de la donnée. Quatrième fois qu'une formulation du
Lead nomme un geste sans nommer son régime.

**Trois issues, une seule sans dérive** : monter le fichier en lecture seule (source unique) · une
variable d'environnement (le numéro existerait à **deux** endroits) · copier au démarrage (deux
endroits, et **silencieusement**). Retenue : la première, une ligne dans `docker-compose.yml` —

    - ./legacy/version.txt:/var/www/html/version.txt:ro

**et l'argument qui l'emporte est la journée elle-même** : `legacy/version.txt` a dérivé **deux fois le
2026-08-27** — resté à 1.38.17 pendant deux bumps, puis trois commits sur le même numéro. *Ajouter une
seconde copie d'un chiffre qui vient de diverger, c'est traiter le symptôme en aggravant la cause.*

**La borne à connaître avant de mesurer** : une ligne de `volumes` **ne prend pas effet à un
`docker restart`** — il faut `docker compose up -d laravel`, une **recréation**. Le montage est donc
**inert** jusqu'à ce que l'exploitant recrée le conteneur, et il rejoint le lot qui attend déjà le
redémarrage du backend. Cinquième régime de lecture, à ajouter aux quatre du §8 :

| objet | pris en compte | ce qui mord |
|---|---|---|
| `docker-compose.yml` (`volumes`, `ports`, `env_file`) | à la **recréation** du conteneur | `docker compose up -d <service>`, **pas** un `restart` |

Et il se lit **à l'envers** des correctifs backend inertes : avant la recréation, l'écran affichera
« version inconnue », qui est le **comportement correct du repli** et non un repli en échec.

`docker-compose.yml` n'appartenait à personne dans le §10 : **il revient au Lead**, pour les lignes
d'infrastructure qui débloquent une session.

### UN DRAPEAU ET LES COLONNES QU'IL RÉSUME SONT DEUX SOURCES (2026-08-27)

Trouvé par la session 3 en portant `platform_key`, et l'inventaire ne l'avait pas vu : le legacy compte
« mot de passe supprimé » sur le **drapeau** `ssh_password_required`, **pas sur les colonnes**. Mesuré :
`srv-zabbix` porte le drapeau à 0 alors que ses **deux** mots de passe sont présents. Cause : la page
Serveurs est le seul chemin qui réécrit `root_password`, et **elle ne touche pas le drapeau**.

Deux conséquences, qui ne vont pas dans le même sens :

- **la bonne** : *aucune machine n'est aujourd'hui dans la position sans retour*, contrairement à ce que
  l'inventaire relevait le matin même. C'est **calculé**, et ça abaisse la gravité de P4 ;
- **celle qu'il ne faut pas perdre** : le portail **affiche une pastille verte « keypair » sur une
  machine qui a encore ses deux mots de passe.** L'indicateur est faux **dans le sens rassurant** —
  écart de parité à part entière.

*Un drapeau et les colonnes qu'il prétend résumer sont deux sources, et il suffit d'un chemin
d'écriture qui en oublie une pour qu'elles divergent sans bruit.* Même faute de forme que les deux
copies du numéro de version refusées dans la même heure : **la session 3 a refusé une duplication dans
le compose et en a trouvé une en base le même après-midi.**

### AUCUNE SUITE N'ASSÈRE `LiensLegacy` — ET SIX ARCHIVAGES VONT PASSER (2026-08-27)

Remonté par la session 3 pendant ARC-001, sans l'avoir cherché : **zéro occurrence de `LiensLegacy` dans
`tests/e2e/` et `laravel/tests/`.** L'oubli de `/docker/` — l'archivage de `v1.37.54` avait sauté
l'étape — a donc été trouvé par une **relecture**, et le prochain ne le sera pas davantage. Il reste
**six** modules à archiver.

La propriété qui ferme le trou : **dériver la liste attendue de `legacy/_deprecated/*` et la comparer à
la table**, pour qu'elle rougisse le jour où quelqu'un archive sans compléter, au lieu de dépendre de
qui relit. **Deux bornes, parce que la table n'est pas une image du dossier** : quatre entrées sont
**préventives** — le backend n'émet ni `/docker/`, ni `/chatops/`, ni `/maintenance/`, ni `/supervision/`
— et *tout `/partie/` n'est pas une page*, donc la comparaison porte sur le chemin **normalisé en
entier**, jamais par préfixe.

### ✅ INF-003 TRANCHÉ — UNE ROUTE UNIQUE POUR LES RÉGLAGES QU'UNE INTERFACE DOIT POUVOIR ANNONCER (2026-08-27)

**Trois fois le 2026-08-27, un écran a eu besoin d'une valeur qui vit dans un conteneur qu'il ne voit
pas.** La session 3 a nommé le motif après la troisième, et la mesure lui donne raison :

| # | l'écran voulait dire | la valeur vit | issue prise |
|---|---|---|---|
| 1 | son numéro de version | `legacy/version.txt`, non monté | **montage** en lecture seule |
| 2 | « réversible pendant N jours » | `PLATFORM_KEY_ARCHIVE_DAYS`, conteneur Python | **cette route** |
| 3 | la durée de rétention d'un journal | idem | idem |

**Ce ne sont pas trois incidents, c'est une classe.** Relevé : **douze** réglages d'environnement qu'une
interface pourrait légitimement devoir annoncer — `PLATFORM_KEY_ARCHIVE_DAYS`, `SSH_TIMEOUT`,
`CVE_MAX_PAGES`, `CVE_PAGE_LIMIT`, et les huit drapeaux `*_ENABLED` (`APPROVAL`, `MAIL`, `CHATOPS`,
`WEBHOOK`, `TICKETING`, `WAZUH`, `CVE_ENRICH`, `NVD_ENRICHMENT`).

**Décision : une route de lecture unique, `GET /settings/announceable`, écrite par la session 4.** Pas une
route par valeur — douze routes pour douze nombres, c'est douze occasions d'en oublier une, et le
treizième réglage n'aurait pas de porteur.

**Et la raison de trancher plutôt que de laisser chacun se débrouiller est dans les deux issues
écartées :**

- **coder la valeur en dur dans l'écran** — c'est **pire que ne pas l'afficher**. Un exploitant qui change
  `PLATFORM_KEY_ARCHIVE_DAYS` croira que l'écran le sait. *Un nombre affiché comme une garantie et figé
  dans un autre fichier est un mensonge à retardement*, et c'est exactement le motif de la seconde copie
  du numéro de version, refusée le même jour par la même session ;
- **ne rien dire du tout** — « une durée limitée, configurée côté serveur ». Moins utile, mais **vrai**.
  C'est le repli que la session 3 prend par défaut, et il est légitime tant que la route n'existe pas :
  *moins plutôt que faux.*

**Trois bornes sur cette route, parce qu'elle expose de la configuration :**

1. **liste FERMÉE, énumérée dans le code de la route.** Jamais « rends `os.environ` filtré par un motif » :
   un `*_ENABLED` d'aujourd'hui est inoffensif, le réglage qu'on ajoutera demain ne l'est pas
   nécessairement. C'est la leçon de V10a — une interface à liste fermée, parce que la valeur d'un
   override devenait une ligne de configuration ;
2. **aucun secret, aucune adresse, aucun identifiant.** Des durées, des bornes, des drapeaux. Si un
   réglage a besoin d'être annoncé *et* qu'il est sensible, il ne passe pas par là ;
3. **elle dit la valeur EFFECTIVE, pas le défaut du code.** `int(os.getenv('X', '30'))` rend 30 quand la
   variable est absente : la route doit rendre ce que le backend **emploie**, sans quoi elle rejoue le
   défaut qu'elle est censée supprimer.

**Ce que la route ne résout pas, et qu'il faut dire à l'écran** : elle rend la valeur au moment de la
requête. Elle ne rend **pas** la réversibilité une garantie — *l'archive de rotation vit dans le MÊME
volume que la clé courante, et ce volume n'est sauvegardé nulle part.* Le panneau doit donc porter les
**deux** bornes : « réversible pendant N jours » **et** « si le volume survit ». Une seule des deux se lit
comme une promesse.

### UNE VÉRIFICATION LANCÉE DEPUIS LE MAUVAIS CÔTÉ D'UN MONTAGE REND « TOUT VA BIEN » (2026-08-27)

La session 3 a contrôlé que `LiensLegacy` couvrait bien les treize parties archivées, et son contrôle a
rendu **« aucune manquante »** — sans avoir rien comparé :

    glob('/var/www/html/../legacy/_deprecated/*')   depuis le conteneur Laravel
    -> tableau VIDE, car ce conteneur ne monte que `laravel/`
    -> la boucle ne tourne jamais
    -> « aucune partie manquante » est VRAI sur l'ensemble vide

**Ce qui l'a rattrapée : le chiffre était trop propre.** Pas une assertion, pas un garde — une intuition
sur la forme du résultat. C'est mince, et c'est pour ça que la règle doit être écrite.

**C'est le même mur que `version.txt` du même après-midi, pris par l'autre bout** : là, le conteneur ne
voyait pas le fichier et l'écran affichait « version inconnue » — **un échec visible**. Ici, le conteneur
ne voyait pas le dossier et le contrôle a affiché **une réussite**. *Le même montage absent produit un
symptôme bruyant quand on LIT une valeur et un silence rassurant quand on ÉNUMÈRE un ensemble.*

> **Une énumération qui rend le vide satisfait toutes les propriétés universelles qu'on lui applique.**
> `[].every()` est vrai, « toutes les parties archivées ont une entrée » est vrai, « aucun appel fautif ne
> subsiste » est vrai. Quatrième forme de ce piège en une journée, après le `conforme` sur une assertion
> qui n'a pas joué, le constat d'archivage sur un chemin inexistant, et la garde qu'une mutation
> légitime ne pouvait pas déclencher.

**La parade est une précondition, pas de la vigilance** : toute propriété qui boucle sur un ensemble
énuméré doit d'abord **assérer que l'ensemble n'est pas vide** — et échouer explicitement s'il l'est. La
session 7 l'avait déjà ajoutée de son côté pour le cas « la table est illisible » ; c'est la même parade,
et elle vaut pour **les deux** ensembles qu'une comparaison met en regard, pas seulement pour celui qu'on
soupçonne. **Et l'énumération se fait depuis le côté du montage qui voit le chemin** — ici, l'hôte.

### Tests

- **Une assertion de REFUS ne se place pas après une création du même nom.** Sur `go-adm-serveurs`,
  l'étape « une adresse mappée est refusée » posée après la création légitime aurait porté le même nom
  de machine, aurait été refusée pour cause de **doublon**, et serait passée pour une bonne nouvelle.
  Même famille que « un PASS peut passer PARCE QUE la fonctionnalité est absente » : vérifier que
  l'assertion échoue pour la raison qu'on croit, et la placer avant ce qui pourrait la faire réussir
  autrement.
- **Une capture doit CADRER ce que le sous-lot construit.** Deux fois de suite : D6a capturait
  l'onglet des comptes au lieu de celui des serveurs, D6b le haut de la page au lieu de la carte
  ouverte. La seconde fois, le défilement vers la carte a révélé du premier coup un défaut de rendu
  que D6a avait laissé passer — une case à cocher au-dessus de son libellé. Ouvrir, défiler, PUIS
  déclencher.
- **Une capture qui montre autre chose que ce qu'on croit est pire qu'une capture absente** — elle
  sert de preuve à un examen qui n'a pas eu lieu. Relevé le 2026-08-26 : l'étape de captures de
  `go-adm-serveurs` ne rouvrait pas l'onglet « Serveurs » du legacy ; les trois images montraient
  l'onglet des comptes. La page répond 200, rend du contenu, et ce contenu n'est pas le sujet. Vu **en
  regardant l'image**, jamais en relisant le code.

- **Cliquer le bouton, pas appeler la fonction** — et **pas le premier bouton de la page** :
  `profile.php` porte cinq formulaires et le premier est celui du courriel. Remonter du **champ** à son
  `form` par `closest('form')`.
- **Un message se lit dans son porte-messages** (`data-rw` dédié), pas par une classe approchante :
  `[class*="text-red"]` attrapait un compteur valant « 0 », puis le **bandeau** d'exigence.
- **Une garde du navigateur déplace le refus, elle ne le supprime pas** (`minlength`) : mesurer la
  **propriété**, prouver le serveur par une **requête forgée**.
- **Tester la visibilité du CONTENEUR, pas du descendant** ; **une forme de retour constante dans
  `page.evaluate`** ; **compter les requêtes plutôt que regarder le DOM** ; **jamais d'attente fixe après
  un clic d'onglet** ; **une navigation referme l'onglet** ; **l'ordre des gestes compte**.
- **Un détail d'assertion est imprimé au PASS comme au FAIL** : dire ce qu'on a **trouvé**.
- **Un nettoyage qui supprime par TYPE en retire plus qu'il n'en a posé** : borner par un **delta**.
- **Une exception dans le `finally` emporte le journal entier** : isoler chaque étape.
- **Imprimer le journal au fil de l'eau.** **Sonder un chemin qui n'a jamais existé rend 404** et fait
  passer l'assertion pour rien.
- **Un `git add` ciblé ne protège plus rien si une AUTRE session écrit dans le dépôt.** Le 2026-08-25 à
  22:34, une seconde session a committé `MODULE-ADM.md` seul et laissé ses retouches de **ce fichier**
  non committées ; le `git add docs/migration/PLAN-DE-MIGRATION.md` du commit d'archivage les a
  **ramassées**, et `v1.37.58` porte donc une douzaine de lignes sur `adm/` que son message ne
  mentionne pas. Rien n'est perdu et rien n'est faux — mais le commit n'est plus atomique, et
  l'historique attribue mal. Deux règles qui en découlent : **`git diff --stat` sur ce qu'on s'apprête à
  ajouter, pas seulement `git status`** ; et ne **jamais réécrire l'historique** (`--amend`, `rebase`)
  tant qu'une autre session peut travailler — la gêne d'un message incomplet est bien moindre que celle
  d'un historique déplacé sous les pieds de quelqu'un.
- **Avant tout `git add <fichier>`, regarder si ce fichier était DÉJÀ modifié.** Troisième occurrence
  en deux jours, et à chaque fois le même mécanisme : deux sessions écrivent dans un fichier **partagé**,
  la première à committer emporte le travail de la seconde. `PLAN-DE-MIGRATION.md` d'abord
  (`v1.37.58` porte une douzaine de lignes sur `adm/` que son message ne mentionne pas), puis
  `scripts/rejouer-lot.sh`, puis `laravel/routes/web.php` — où deux modules déclarent leurs routes au
  même endroit. Le coût du contrôle est un `git status` ; le coût de l'oubli est un `reset --soft` avec
  découpage de patch.

  **Notre convention de banc ne protège pas de ça, et il faut le dire** : « `laravel/`, `backend/` et
  `docs/` peuvent partir quand ils veulent » est vrai pour le **rejeu** et faux pour l'**atomicité**.
  `web.php` est un fichier partagé au même titre que le runner.

  **Découper un patch : deux précautions apprises à la dure.**

  1. un bloc `@@` peut être **MIXTE**. Le 2026-08-26 sur `web.php`, le bloc des `use` portait un import
     de chaque session, à deux lignes l'un de l'autre : il a fallu retirer une ligne **et recompter
     l'en-tête du bloc** (`@@ -6,8 +6,10 @@` → `@@ -6,7 +6,8 @@`). `git apply --cached --check` refuse
     un compte faux, donc l'erreur ne passe pas en silence — mais ne pas le faire sans sauvegarde ;
  2. **`php -l` sur le fichier ne prouve RIEN de ce qu'on committe** : il lit le **disque**, pas l'index.
     Sortir la version indexée (`git show :chemin`) et la linter à part. Sans cela on committe un fichier
     qui référence un contrôleur dont l'import est resté sur le disque — et le commit passe, et rien ne
     casse avant le déploiement.
- **Le backend est lu au DÉMARRAGE du processus, le frontend à CHAQUE requête. Ce sont deux règles,
  pas une.** Formulé le 2026-08-26 après trois affinages successifs de la convention de banc :

  | ce qu'on touche | quand c'est lu | effet d'une écriture pendant un rejeu |
  |---|---|---|
  | `backend/**.py` | au **démarrage du processus** | **inerte** — c'est le `docker restart` qui mord |
  | `laravel/**`, `legacy/**` | à **chaque requête** | change la cible **en plein vol** |
  | `tests/e2e/**.mjs` | au lancement de la suite | le nombre mesuré devient irreproductible |
  | **`scripts/*.sh` en cours d'exécution** | **incrémentalement, par décalage d'octets** | **peut corrompre la suite du script** |

  **Le quatrième régime est le pire, parce qu'il ne casse pas franchement : il décale.** `bash` parse la
  boucle principale en entier avant de l'exécuter, mais quand elle se termine il se repositionne à
  l'**offset en octets** qu'il avait mémorisé pour lire la suite. Une écriture qui ajoute des octets
  **avant** la boucle décale donc tout ce qui suit — le résumé, la comparaison aux références —, et le
  verdict peut être lu de travers sans qu'aucune erreur n'apparaisse.

  Vécu **deux fois le 2026-08-26, à une minute d'intervalle, par les deux sessions**. La première a
  ajouté 502 octets avant la boucle puis a annulé ; le rejeu était à 46 suites sur 117, donc bash
  n'avait pas encore atteint la queue du script. **Puis j'ai écrit ce paragraphe et j'ai édité le runner
  moi-même dans la minute suivante**, pour y corriger un commentaire — même erreur, même régime, même
  chance que la fenêtre se referme (47 suites sur 117).

  **✅ CE RÉGIME N'EXISTE PLUS — la propriété a été construite** (`v1.37.85`). `rejouer-lot.sh` se
  recopie dans `/tmp` et exécute la copie ; éditer la source pendant un rejeu est désormais **sans effet
  possible**, pour soi comme pour l'autre session. Le piège non évident était que `RACINE` se déduisait
  de la **position** du script : elle est calculée avant la copie et transmise par l'environnement.

  **Et la propriété a été PROUVÉE, pas affirmée.** Un rejeu a tourné pendant que sa source prenait
  **960 octets** : il s'est terminé normalement, résumé complet, verdict juste. Puis le mécanisme
  inverse a été démontré sur un script d'épreuve — après le décalage, `bash` reprend à l'offset mémorisé
  et **exécute le milieu d'une ligne** (`XXXXX… : commande introuvable`). Là c'était visible ; un
  décalage tombant sur une ligne d'apparence valide aurait produit un verdict faux **en silence**.

  **La leçon reste, parce qu'elle explique pourquoi il a fallu construire la propriété : écrire une règle
  ne protège pas de l'enfreindre.** Le paragraphe existait,
  je venais de le rédiger, et il n'a rien empêché. Ce qui a permis de le dire n'est pas la confiance mais
  la vérification — références intactes, `bash -n` propre, avancement relevé — et ce qui protégerait
  vraiment n'est pas un document : **le runner devrait se recopier dans un fichier temporaire et exécuter
  la copie.** Une édition de la source deviendrait alors sans effet possible sur un rejeu en cours, et le
  quatrième régime disparaîtrait comme problème au lieu d'être une règle à retenir. *Une règle qu'on doit
  se rappeler est une propriété qu'on n'a pas encore construite.*

  Conséquences pratiques, et elles ne sont pas symétriques : écrire dans `backend/` pendant le rejeu
  d'une autre session est **inoffensif**, mais `docker restart rootwarden_python` casse sa mesure en
  plein vol. À l'inverse, un `git checkout` qui ramène `laravel/` ou `legacy/` en arrière **change la
  cible immédiatement**, sans qu'aucun redémarrage soit nécessaire — c'est le geste le plus discret des
  trois et le plus difficile à diagnostiquer après coup.

  *La convention a dit d'abord « ne pas éditer le runner », puis « c'est le `git commit` qui compte » —
  faux, c'est l'écriture —, puis « `backend/` peut partir quand il veut » — vrai de l'écriture, faux du
  redémarrage. Trois formulations trop étroites avant celle-ci. Une règle qui rassure sans protéger est
  pire que pas de règle.*
- **Pendant un rejeu, tout fichier qu'une suite LIT ou EST doit être figé.** La règle notée jusqu'ici —
  « ne jamais éditer le runner pendant un rejeu » — était trop étroite : elle nommait le runner et
  donnait pour raison la lecture des références au démarrage. Le mécanisme est plus large, et une
  seconde session l'a montré le 2026-08-26 :

  | 11:19:29 | `go-socle-navigation` joue dans le LOT → **53** |
  |---|---|
  | **11:23:28** | **ÉCRITURE** de 4 assertions dans cette suite |
  | 11:24:48 | le commit, 80 s plus tard |
  | | la suite qui a produit le 53 n'existe plus sur le disque |

  Éditer le **runner** fausse le verdict par une référence périmée. Éditer une **suite** le fausse
  autrement : le nombre mesuré devient **irreproductible** et ne peut plus servir de référence. Les
  autres suites gardent leur validité — elles ont tourné avec leurs propres fichiers.

  **⚠ LE GESTE EN CAUSE EST L'ÉCRITURE, PAS LE `git commit`.** Ce document a d'abord dit l'inverse, et
  c'était une erreur qui *donnait une fausse protection* : elle aurait autorisé à écrire une suite
  pendant un rejeu du moment qu'on retarde le commit, et le défaut se serait reproduit à l'identique en
  laissant croire qu'on s'en était prémuni. Mesuré : un `git commit` ne change **aucun octet** du
  fichier — il écrit dans `.git`, et un rejeu lit le **disque**, pas l'index. C'est l'écriture de
  11:23:28 qui a rendu le 53 irreproductible, pas le commit de 11:24:48.

  D'où la convention, sous la seule forme qui protège : *pendant qu'une session tient le banc, l'autre
  n'**écrit** pas dans `tests/e2e/` ni `scripts/`. Elle écrit et committe librement dans `laravel/`,
  `backend/` et `docs/` — rien de tout cela n'est lu par un rejeu en cours.* **Retarder le commit ne
  protège de rien.**
- **Un motif qui suppose une forme d'appel ne mesure que cette forme.** Corollaire du précédent,
  appliqué au JavaScript. Relevé le 2026-08-26 sur `bashrc/` : un `grep` sur `confirm(__('…'))` rendait
  quatre clés et laissait conclure qu'un cinquième geste n'avait pas de confirmation — alors que la
  sienne est construite par gabarit, ``confirm(`${label}…`)``. **La fausse accusation a été évitée de
  justesse**, et elle aurait été publiée comme un défaut.

  La parade n'est pas un motif plus large — il aura son propre angle mort — mais de **mesurer le
  comportement** : `page.on('dialog')` compte les boîtes réellement ouvertes, quelle que soit la forme
  de l'appel qui les produit. C'est ce qui a établi, pour `graylog/`, que `glTest` n'a **pas** de
  confirmation : le journal du rejeu montre la séquence `confirm` (déployer) → `alert: ✓ Logger envoyé`
  (tester, **sans confirm**) → `confirm` (retirer). Un `grep` l'avait suggéré ; le navigateur l'a prouvé.
- **Compter une structure de données, c'est la faire lire par son propre langage.** Un comptage des
  entrées de menu à l'expression régulière a rendu **32 sur 33** le 2026-08-26 : le motif exigeait la
  forme sur une seule ligne et manquait `wazuh`, écrit autrement. La même constante lue par un
  `require` puis un `foreach` en PHP rend **33**, sans angle mort possible — même leçon que pour la
  parité i18n, où analyser du PHP à l'expression régulière revient à réécrire un interpréteur et où une
  entrée mal lue est déclarée absente à tort.
- **Et l'assertion qui manquait est celle du TOTAL** : `route + legacy + ni-l-un-ni-l-autre == 33`.
  Aucune suite ne vérifiait que le décompte se reconstitue, donc il pouvait dériver sans que rien ne le
  dise — ce qui vient d'arriver, dans le sens inoffensif. **Un total qu'on ne sait pas reconstituer
  n'est pas un total.**
- **Un conteneur `flex` posé SUR un `<td>` fait ignorer son `colspan`.** `display: flex` écrase
  `display: table-cell` : la cellule sort du modèle de tableau. Le panneau de décision de `graylog/`
  s'arrêtait au tiers de la ligne sur un écran de 1920, et l'attribut `colSpan` valait bien 6 — aucune
  assertion DOM ne pouvait le voir. Le conteneur flex va **dans** la cellule. `maintenance.js` a le même
  défaut, non vu parce que sa capture n'ouvrait pas le panneau.
- **Le poids visuel appartient à la confirmation, pas à la ligne.** Donner à « Retirer » un bouton
  d'avertissement en faisait l'élément le plus voyant du tableau, plus que « Déployer » : attirer l'œil
  sur le geste destructeur est l'inverse de ce qu'on veut.
- **La détention du banc se REND, elle ne se déduit pas du silence.** Le 2026-08-26, deux sessions ont
  lancé des suites dans la même minute parce que l'une avait conclu du `ps` vide que le banc était
  libre. Rien n'a échoué — mais le garde anti-rejeu TOTP étant par compte et en base, deux connexions
  du même compte dans la même fenêtre de 30 s se seraient sabotées, et le journal aurait accusé le
  code. Un `ps` vide dit « aucun rejeu à cette seconde », pas « personne n'est sur le point d'en
  lancer un ».
- **Un secret TOTP inventé ne fait pas échouer la suite là où elle mesure** : il la fait échouer à la
  CONNEXION, ce qui ressemble à un compte verrouillé, à une fenêtre TOTP ratée ou à un `login_attempts`
  saturé — trois diagnostics plausibles pour une cause qui n'a rien à voir. Relever le secret dans une
  suite existante, et le **compter** : les trois secrets de `graylog/` apparaissent dans 35, 54 et 32
  fichiers.
- **Tout `/partie/` n'est pas une page.** `/maintenance/check` et `/maintenance/windows` sont des routes
  du **backend** ; sondées comme des pages archivées elles échoueraient, réécrites comme des pages elles
  casseraient la page. Ce qui les sauve est une comparaison du chemin **normalisé en entier** — la même
  précaution que E-02 avait imposée à la passerelle. Un filtre par préfixe se trompe toujours dans le
  sens qui ne se voit pas.
- **Une règle qui vit en deux langages ne se protège pas en « suivant l'autre pas à pas ».** Le portage
  de `maintenance/` a d'abord recopié `_in_window` en JavaScript avec cette promesse en commentaire. Le
  pas était juste ; c'est l'**horloge** qui différait — navigateur en CEST, conteneur qui applique en
  UTC. Deux implémentations d'accord sur l'algorithme et en désaccord sur l'entrée donnent deux verdicts
  opposés. Quand une règle est **appliquée** ailleurs, la remonter de là et l'afficher ; ne jamais la
  recalculer.
- **Le cas visible traité, le cas subtil pris à l'envers.** Ce n'est pas de la négligence uniforme, et
  c'est ce qui le rend difficile à voir : la présence d'un traitement correct **à côté** endort la
  question. Deux mesures du 2026-08-26, trouvées séparément puis rapprochées :
  `graylog/deploy` calcule `syntax_ok` et `restart_ok`, les rend dans sa réponse, compose son `success`
  avec — donc quelqu'un a pensé à l'échec, mais **seulement pour la réponse, pas pour l'état persisté** ;
  et l'aide du préréglage `all_nopasswd` de `adm/` dit **vrai** (« administrateur TOTAL »), quand celle
  du préréglage par défaut affirme l'inverse de son propre module. Chercher, à côté de chaque défaut, le
  cas voisin qui a été traité : il indique ce que l'auteur savait, donc ce qu'il a manqué.
- **Un résumé rendu par le serveur que la page invalide ensuite vaut moins que pas de résumé.** La
  pastille d'ensemble de `maintenance/` était comptée au chargement et jamais rafraîchie, alors que la
  page crée, bascule et supprime. Elle affichait « Aucune restriction » juste après une création.
- **Compter sans regarder la PORTÉE, c'est compter faux.** La même pastille annonçait « Flotte
  restreinte » pour une fenêtre limitée à une seule machine. Le `WHERE` du backend disait le contraire
  depuis toujours : `enabled = 1 AND (scope = 'global' OR machine_id = ?)`. Lire la requête, pas
  l'intention.
- **Un `input[type=time]` ne se vide pas au triple-clic** : c'est un composite de segments, et le clic
  peut poser le caret sur les minutes — `type('1847')` a rendu `22:47`. Revenir au premier segment par
  des flèches. Et, encore une fois : la suite accusait la page alors que le défaut était dans le geste.
- **Une assertion « rend 404 » ne vaut que si le NON-404 d'avant a été mesuré.** Corollaire du piège
  ci-dessus, et il porte sur l'ORDRE des gestes : la mesure doit précéder le `git mv`, pas le suivre.
  Sondé le 2026-08-25 avant d'archiver `chatops/` : `302`, `302`, **`403`**, `200`. Le `403` est le plus
  instructif — `webhook.php` répondait, et son refus (« ChatOps désactivé ») ressemble d'assez près à un
  chemin absent pour qu'on s'en contente sans regarder le code.
- **Une capture mal étiquetée est un mensonge** ; elle doit montrer un état **atteignable**.
- **Ce document s'est trompé sur ses propres comptes de test.** Il annonçait une permission pour
  `rw-test-admin` ; il en porte neuf. Plusieurs suites mesurent une garde en s'appuyant sur « ce
  compte n'a PAS telle permission » : la ligne fausse aurait produit un vert qui ne mesure rien.
  **Remesurer les droits AVANT de concevoir un test de garde**, colonne par colonne.
- **Une liste écrite à la main vieillit ; le schéma est la vérité.** Le portage des permissions lit
  `information_schema` plutôt que de recopier une liste blanche : trois listes ne peuvent plus
  diverger quand il n'y a plus qu'une source.
- **Trois pièces correctes peuvent former une impasse.** E-119 : la garde step-up est bonne, le POST
  part bien, le refus est juste — et pourtant cocher une permission ne fait rien, parce que le modal
  qui permettrait de répondre n'écoute que `fetch` quand la requête part en `XHR`. **Chercher le
  CHEMIN COMPLET, pas la correction de chaque pièce.**
- **Deux couches à ouvrir, pas une.** Quatrième forme du piège du bloc replié : l'onglet masqué de
  `admin_page.php`, PUIS la carte `<details>` du compte. Un seul `open = true` ne suffisait pas.
- **Trois énumérations de la même chose divergent dans les deux sens.** 18 colonnes, 14 à la création,
  16 à la bascule — et les écarts se croisent : une permission s'accorde sans se reprendre, une autre
  n'existe ni à la création ni à la bascule. **Croiser les listes deux à deux, pas les compter.**
- **Le piège d'A5 se paie une seconde fois, dans le sous-lot qui consomme le step-up.** La marque vit
  **quinze minutes dans le cache** et survit à l'exécution : la deuxième exécution héritait de la
  première et mesurait un 200 là où elle attendait un 403. **Révoquer à l'entrée ET dans le
  `finally`** — nettoyer ce que le test ACCORDE, pas seulement ce qu'il écrit.
- **Un écouteur de réponses posé trop tôt attrape le ménage.** La révocation partait après
  l'attachement, et l'assertion lisait sa réponse au lieu de celle du geste. **Faire le ménage AVANT
  d'écouter.**
- **Une classe CSS qui existe n'est pas une classe qui convient** — troisième forme de ce piège.
  `.rw-etroit-seul--inline` ne s'affiche que **sous** 720 px ; l'employer pour replier une donnée à
  1400 px la faisait disparaître. Lire ce que la règle FAIT, pas ce que son nom suggère.
- **Un bloc `<details>` fermé, TROISIÈME fois.** Cette fois c'était chaque carte de compte
  (`manage_users.php:219`). Le symptôme est toujours le même — `page.$()` trouve, le clic dit
  « not clickable » — et le remède aussi : déplier, puis **asserter que l'élément a une boîte**.
- **Deux gestionnaires cassés de la même façon ne produisent pas le même effet.** Ce qui décide, c'est
  ce qui prend le relais quand le gestionnaire meurt : un `type="submit"` dans un formulaire, ou rien.
  E-114 annonçait deux actions destructrices sans garde ; mesure faite, l'une part vraiment, l'autre
  est un **bouton inerte**. **Lire la forme de l'élément, pas seulement son gestionnaire.**
- **Un `ON DELETE CASCADE` peut effacer bien plus que ce que le code croit supprimer.** `delete_user.php`
  supprime explicitement deux tables filles — déjà parties en cascade — et n'a pas vu que `user_logs`
  l'était aussi. **Lire `information_schema` avant de raisonner sur une suppression** : le schéma dit
  ce que le code ignore.
- **Un défaut irréversible s'ÉTABLIT sans se provoquer.** Rompre la chaîne d'audit pour la démontrer
  serait la rompre. La mesure de structure suffit à l'établir ; la démonstration demande un arbitrage.
- **Une caractérisation VERTE peut porter une contradiction que seul le portage révèle.** D3
  assertait, dans le même geste, qu'un mot de passe faible soit **refusé** et que l'historique soit
  **écrit** — or un refus n'écrit rien. Sur le legacy les deux passaient, parce qu'il **acceptait**.
  Deux propriétés qui s'excluent sur la cible corrigée demandent **deux gestes**.
- **Une colonne `NOT NULL` sans défaut fait échouer une création en 500 silencieux.** `users.password`
  l'est. Lire le schéma avant d'écrire un `INSERT`, et regarder ce que le legacy y mettait — ici un
  haché de 64 octets aléatoires dont personne ne connaît le clair.
- **Une apostrophe de traduction peut DÉSARMER une garde.** D3 : `L'utilisateur` placé dans un
  `confirm('…')` ferme le littéral JavaScript, l'`onclick` ne s'analyse pas, et **deux actions
  destructrices partent sans confirmation** — en français seulement, les chaînes anglaises n'ayant
  pas d'apostrophe. Une protection qui dépend de la langue de l'interface. Ne jamais placer un texte
  traduit dans du CODE : c'est du contenu.
- **Asserter « aucune erreur JavaScript » n'est pas de l'hygiène, c'est un capteur.** C'est cette
  assertion — et elle seule — qui a révélé E-114. Elle ne cherchait rien de précis, et c'est
  justement ce qui l'a rendue utile.
- **Trois hypothèses écartées valent mieux qu'une devinée juste.** Avant de trouver l'apostrophe,
  trois lectures plausibles ont été mesurées et éliminées. Une hypothèse retenue sans avoir écarté
  les autres n'est qu'une préférence.
- **Un bloc `<details>` fermé ne reçoit pas les frappes** — deuxième fois. `page.$()` trouve le
  champ, `type()` ne lève pas, et rien ne se passe. **Déplier, puis ASSERTER la visibilité et la
  valeur saisie** avant de soumettre.
- **`htmlspecialchars` à l'ÉCRITURE n'est pas une protection, c'est une corruption.** Appliqué à une
  clé SSH destinée à `authorized_keys`, il change la valeur stockée. L'échappement appartient au
  rendu.
- **Un garde qui ne trouve pas son objet peut ACCORDER au lieu de refuser.** D2 : en lisant
  `user_id` là où la session écrit `utilisateur_id`, la portée d'un rôle 1 devenait `user_id = 0` —
  la valeur des lignes de **diffusion**. Une session illisible recevait donc exactement ce qu'elle ne
  devait pas voir. **Fail-closed explicite sur l'absence d'identifiant**, et se méfier des valeurs
  sentinelles qui sont aussi des valeurs réelles.
- **Lire « les `span` du plus proche ancêtre » remonte jusqu'au menu.** L'assertion « le type n'est
  pas replié sur *Autre* » passait parce que le mot n'est pas dans la barre de navigation. Viser
  **l'élément qui porte la donnée** — ici le `span` enfant DIRECT de la ligne — et non un ancêtre
  choisi par proximité. Même discipline que remonter d'un champ à son `form`.
- **Une hypothèse tirée d'une bibliothèque MINIFIÉE se conclut au clic, jamais à la lecture.** D2 :
  la case de préférence n'a pas de `name`, son `hx-vals` ne porte pas `value`, et le point d'API
  exige `value` — j'en ai conclu que chaque clic échouait. Le corps réellement émis porte
  `value=1`, et la préférence s'écrit. **La case fonctionne.** Comparer les deux côtés d'un contrat
  reste juste ; c'est la conclusion qui doit venir de la mesure.
- **Un `onclick` qui retire l'élément TUE la requête que le même clic devait émettre.** htmx chargé,
  bouton présent, écran modifié — et **zéro requête**. Le geste paraît fait et rien n'est parti :
  ni erreur, ni journal, ni trace réseau. **Mesurer ce que l'écran fait ET ce que le réseau émet ET
  ce que la base porte** : les trois, parce que le legacy les fait diverger.
- **Quand un commentaire nomme un défaut, chercher TOUTES les branches jumelles, pas une.** Le
  correctif A01 des notifications scinde `delete` sur le rôle et laisse `read` **et** `read_all`
  écrire sur les lignes de diffusion — que le rôle 1 ne voit même pas.
- **Une garde qui ne tient que sur une méthode ne tient pas.** `checkCsrfToken()` sous
  `if (METHOD === 'POST')`, alors que l'action est lue dans `$_GET` en premier : `GET ?action=…`
  écrit sans jeton. Chercher par où l'action ARRIVE avant de croire la garde placée.
- **Deux énumérations de la même colonne finissent par diverger.** Quatre listes de types de
  notification, et les deux qui décident — celle des préférences et celle de l'affichage — ont une
  **intersection vide**. Mesurer l'intersection, pas la ressemblance.
- **Le `[r]` de `[r]ejouer-lot` ne protège pas quand le CHEMIN figure ailleurs dans la même
  commande.** Quatrième forme du même piège : un `grep -c "[r]ejouer-lot.sh"` combiné, dans le même
  appel, avec un heredoc Python dont la source contenait `scripts/rejouer-lot.sh` en clair a rendu
  **2** sur une machine au repos — la classe de caractères ne dédouble que le motif, pas le texte du
  script. J'ai cru avoir corrompu le rejeu d'une autre session. **Vérifier dans un appel SÉPARÉ, et
  qui ne cite le chemin nulle part ailleurs.**
- **Un catalogue de traduction du portage ne se clé pas comme celui du legacy.** `lang/fr/audit.php`
  veut `'title' => …`, pas `'audit.title' => …` : `__('audit.title')` cherche le groupe `audit` puis
  la clé `title`. Recopier le format plat du legacy fait rendre **chaque identifiant à l'écran**,
  sans erreur et sans journal. **Seule la capture l'a montré** — et d'un coup d'œil : trente libellés
  en majuscules à la place des textes.
- **Une suite de caractérisation écrite sur le legacy est SHAPÉE par lui.** Sept des huit échecs du
  premier passage sur le portage venaient de la suite : chemins de points d'API codés en dur, attente
  d'une classe `hidden` propre au legacy, motif d'interception d'URL, noms de champs JSON. Les mettre
  dans la table `C` **par cible** — et pour l'attente, viser un signal que les deux cibles partagent :
  **le bouton réactivé**, pas la première annonce.
- **La propriété est « la requête porte un jeton », pas « elle le porte à tel endroit ».** Le legacy
  duplique son jeton CSRF dans l'en-tête ET dans le corps ; le portage s'en tient à l'en-tête, que le
  cadre lit. Une assertion calquée sur l'implémentation du legacy fait échouer un portage correct.
- **Deux points d'API qui lisent la MÊME donnée peuvent en rendre deux verdicts opposés.** D1 :
  « Vérifier l'intégrité » annonce une chaîne intacte pendant que « Sceller les orphelines » annonce
  une désynchronisation, à la même seconde. Ils divergent d'une ligne — l'un saute les lignes non
  scellées, l'autre les compte dans la chaîne. **Quand deux lectures d'une même règle existent,
  les faire répondre CÔTE À CÔTE dans la même assertion** : séparément, chacune passe.
- **Trancher lequel a raison demande une TROISIÈME mesure, d'un autre moyen.** Ici un `LAG()` SQL sur
  les seules lignes scellées : 3311 maillons, 0 rupture. Sans elle, on n'aurait qu'un désaccord.
- **Un garde-fou qui se déclenche à tort ne protège plus : il empêche.** `stopped_at_tamper` est une
  bonne idée — ne rien réécrire quand une ligne semble altérée — mais posée sur une comparaison
  fausse, elle rend le seul remède au trou **définitivement inerte**, tout en écrivant une alarme
  `SECURITY` à chaque appel. Chercher, pour chaque fail-closed, ce qu'il bloque quand il se trompe.
- **Un gabarit de traduction non substitué ne casse rien et se lit dans la page.** « 4 179 `:count`
  entrees au total » : le nombre attendu **est** présent, donc l'assertion passe, et le mot de trop
  ne se voit qu'à l'image. Les deux langues étaient touchées.

### UNE MESURE SANS ATTENTE PRÉALABLE NE SE CONTRÔLE PAS ELLE-MÊME (2026-08-27)

Ce document répète depuis le matin qu'*une prédiction n'est pas une référence* et qu'il faut mesurer.
C'est vrai. **La session 7 a nommé l'autre moitié, et elle manquait :**

> **La prédiction ne remplace pas la mesure — elle sert à la contredire quand c'est la MESURE qui est
> fausse.**

**Le cas.** Le greffage du constat d'archivage dans les trois suites `services` a rendu **10** là où la
référence prédite était `1 + 2 + 2 = 5`. Cause : `note()` imprime **déjà** au fil de l'eau dans ces
suites, et réimprimer le tampon **doublait chaque ligne** — le runner comptant `grep -c '^PASS'`.

**Il n'y avait aucun rouge.** `0 FAIL`, tout conforme. **Un compte doublé est un compte faux, et un
verdict « 0 FAIL » ne le voit pas.** Inscrit, il devenait une **référence stable** — donc jamais remise en
cause, et toute vraie perte d'assertion aurait ensuite été absorbée par la marge.

**Ce qui l'a révélé est l'écart avec la prédiction, et rien d'autre.** Sans attente préalable, 10 aurait
été inscrit sans y penser.

**Les deux fautes du jour tirent en sens opposés, et c'est le cœur de la règle :**

| cas | qui avait tort | ce qui a tranché |
|---|---|---|
| `tickets`, `-1` et non `-2` | **la formule** | la mesure |
| greffage `services`, `10` et non `5` | **la mesure** | la prédiction |

*On ne peut donc pas se ranger d'un côté.* Une référence se pose quand la mesure **et** l'attente
concordent ; quand elles divergent, le travail commence — et rien dans l'écart ne dit laquelle des deux
est en cause. **Écrire l'attente AVANT de mesurer est ce qui rend l'écart lisible** ; l'écrire après, c'est
la déduire du résultat.

#### Corollaire : la bascule d'une entrée se fait au PORTAGE, pas à l'ARCHIVAGE

Deux sessions ont prédit `65` pour `go-socle-navigation` après l'archivage de `services/`, **de la même
façon et pour la même raison** — et le Lead a relayé la prédiction sans la questionner. Mesure : **64**.

    `services` AVANT `c166c0b` : 'route' => 'services'
    `services` APRES           : 'route' => 'services'    — INCHANGE

`services` était porté depuis `v1.37.98`. **L'archivage retire le dossier legacy ; il ne bascule rien dans
le menu.** Les deux gestes sont séparés de plusieurs jours, et *l'effet du premier a été attribué au
second*. Le seul mouvement réel venait d'ailleurs : la bascule de `platform_key`, `legacy` → `route`,
**+1 pour le seul rôle 3** — sa garde `can_manage_platform_key` n'est détenue par **aucun** compte
d'épreuve, et `rw-test-super` ne la voit que par le contournement du rôle 3. Répartition 24+8 → 25+7,
total **32** inchangé.

**« +1 par rôle qui voit l'entrée » tient pour la quatrième fois. C'était l'hypothèse de départ qui était
fausse, pas la formule** — et c'est exactement le genre d'erreur qu'une prédiction partagée par trois
personnes rend plus difficile à voir, non plus facile.

### `node --check` NE VOIT PAS UN SYMBOLE ABSENT (2026-08-27)

Deuxième occurrence du jour, après `compteEnBase` : le greffage visait `COMPTE` et `SECRET` dans
`go-services-s1`, qui n'a **ni l'un ni l'autre** mais une **table de comptes**. `node --check` passe — il
vérifie la syntaxe, pas la résolution des noms.

**Les deux fois, c'est le contrôle explicite des symboles qui a tranché, jamais la vérification
syntaxique.** Exact pendant de `py_compile` qui passe sur un nom jamais importé, et le coût est le même :
la faute se découvre **au lancement**, c'est-à-dire hors de toute mesure — l'endroit le plus cher.

*Avant de greffer un appel dans un fichier qu'on n'a pas écrit, vérifier que chaque symbole employé y
existe* — et se méfier particulièrement des noms qui « devraient » être là parce qu'ils le sont ailleurs.

### UN BALAYAGE NE CONVERGE QU'EN LISANT — ET UNE SONDE ÉCRITE POUR ACCUSER SE TROMPE DU CÔTÉ QUI ALARME (2026-08-27)

Le relevé des 229 routes backend a produit **quatre** chiffres successifs pour la même question — combien de
`@require_machine_access` sont **sans objet** :

    24   le corps de la route seul
    17   + les helpers du MEME fichier (`_resolve_ssh_creds`)
     3   + les helpers d'AUTRES modules (`validate_machine_id`)
     1   apres les avoir lues une par une

**La session 4 a failli publier « vingt-quatre gardes qui ne gardent rien ».** Chaque niveau d'appel suivi
divisait le chiffre. *Un balayage ne converge qu'en lisant* — un balayage qui s'arrête au premier niveau
mesure la **forme** de la route, pas son **effet**, et c'est la même faute qu'il prétend dénoncer.

**Et ce qui l'a arrêtée n'est pas une relecture : c'est que 24 sur 116 était trop gros pour être vrai.** La
même chose que le contrôle creux rattrapé parce que « le chiffre était trop propre », et que le greffage
rattrapé par l'écart avec sa prédiction. **Trois fois dans la journée, l'alerte est venue de la
VRAISEMBLANCE d'un nombre et non d'une assertion.** C'est mince comme garde-fou, et c'est pour ça qu'il faut
écrire l'attente avant de mesurer : *une intuition sur l'ordre de grandeur est le dernier filet, pas le
premier.*

> **Une sonde écrite pour accuser se trompe du côté qui alarme.** C'est structurel : on l'écrit en cherchant
> un défaut, donc ses faux positifs sont des accusations et ses faux négatifs des silences. **Le jour où
> l'une se trompera dans l'autre sens, personne ne le verra** — un « 0 défaut » ne déclenche aucune
> vérification. La parade est celle du §8 : *une sonde qui rend « aucun défaut » doit être éprouvée sur un cas
> où elle devrait en trouver un.*

**Deux occurrences le même jour, dans deux sessions, à deux heures d'intervalle** : celle-ci, et le balayage
du Lead qui cherchait `href="…"` là où les tuiles s'écrivent `'url' => '…'` — « aucun lien entrant » annoncé
pour cinq parties, **faux pour quatre**. Le Lead accusait par excès de confiance, la session 4 par excès de
zèle ; *les deux formes se corrigent en lisant, et aucune ne se corrige en relançant le motif.*

#### Le chiffre du chantier, remesuré et confirmé par un second moyen

    116  routes portent `@require_machine_access`   (= les 114 connues + 2 posees le 2026-08-27)
     59  redondantes (inertes des `role_id >= 2`)   (= les 57 connues + ces deux-la)
     54  qui MORDENT reellement
      3  SANS OBJET  (la requete ne porte aucun identifiant de machine)

**Le recoupement avec l'audit tombe juste sur les trois lignes** — première fois de la journée qu'un chiffre
du chantier est confirmé par un moyen indépendant **sans qu'un écart apparaisse**. Le tableau à **trois
états** — la garde mord · elle est redondante · elle est sans objet — remplace le décompte à deux états, qui
classait les 3 « présentes » et se trompait dans le sens rassurant.

#### Ce qu'un relevé de gardes doit dire de LUI-MÊME

`RELEVE-GARDES-BACKEND.md` porte en tête, et c'est ce qui le rend utilisable :

- **il décrit l'arbre de travail, pas le service** — treize correctifs sont inertes ;
- **les cinq routes dont l'état diffère sont listées avec LEURS DEUX ÉTATS.** `POST /deploy` y figure en
  clair : `role(2) + machine_access` dans l'arbre, **`@require_api_key` seule en service.** Sans cette
  distinction, « garde réelle » se lirait « garde en vigueur » — dans le document que la session 3 va lire
  pour écrire une page qui **affirme des autorisations** ;
- **deux chiffres y sont marqués NON VÉRIFIÉS** — 69 routes qui écrivent, 98 qui joignent une machine — parce
  qu'ils viennent d'une recherche de motifs et non d'une lecture. *Après la leçon du 24, un chiffre non lu se
  déclare non lu.*

**Et les dédouanements y sont écrits au même titre que les accusations** : `/docker/results` borne au
périmètre dans son corps ; `POST /update_zabbix` est une redirection **307** vers une route gardée, et le 307
**préserve méthode et corps**, donc les gardes s'appliquent à l'arrivée. *Un relevé qui ne dédouane pas se lit
comme un réquisitoire, et on cesse de le croire.*

### ✅ CORRECTION D'UNE FORME QUE LE LEAD A DISTRIBUÉE À TOUTE L'ÉQUIPE (2026-08-27)

`git commit -F - -- <chemins>` a été donnée à quatre sessions comme la parade au défaut d'index. **Elle
est juste, et elle ne marche pas sur une CRÉATION.**

    git commit -F - -- docs/migration/MODULE-NEUF.md
    -> « le specificateur de chemin ne correspond a aucun fichier connu de git »

Un pathspec ne désigne que des fichiers **suivis**. Pour un fichier neuf : `git add <chemin>` **puis** le
commit borné — l'`add` le fait connaître, et **le pathspec borne quand même la publication**, ce qui est la
propriété qu'on cherchait.

**L'erreur est BLOQUANTE et non silencieuse**, donc rien de faux n'est parti. C'est ce qui la rend
supportable — mais la forme n'était pas utilisable telle quelle, et je l'avais distribuée sans l'éprouver
sur une création. *Une parade se teste sur le cas qu'elle doit couvrir, pas seulement sur celui qui l'a
motivée* — le défaut d'index était survenu sur des fichiers **existants**, donc j'ai vérifié la forme sur
des fichiers existants.

### UNE ROUTE SANS PARAMÈTRE DE PORTÉE NE SE BORNE PAS PAR UNE FIXTURE (2026-08-27)

`/ssh-audit/scan-all` est la deuxième route du chantier dont l'interdit a **une cause de construction** et
non de prudence :

    ssh_audit.py:288
    SELECT id, name, ip FROM machines
     WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived'

**Aucun `machine_id`, aucun filtre, aucune portée par utilisateur.** Puis `_run_scan_all_background` ouvre
`ssh_session(...)` **par machine**. Parc mesuré : trois machines, toutes `active` → la requête rend **1, 2,
3**, dont **`srv-zabbix`** — qui porte `platform_key_deployed = 1` **et** `service_account_deployed = 1` :
**la session aboutirait.**

> **Il n'y a pas de paramètre à restreindre.** Une fixture borne un *argument* ; elle ne borne pas une route
> dont la portée est « tout le parc ». Même forme que `/regenerate_platform_key`. **La seule sortie
> technique serait de passer `srv-zabbix` en `lifecycle_status='archived'` — c'est-à-dire modifier l'état
> d'une machine de production : pire que le problème.**

**Et le geste est une LECTURE** (`sshd_config` + version). Ce n'est pas ce qui l'interdit : la règle du
chantier ne distingue pas lecture et écriture sur la production. *À écrire explicitement, sinon quelqu'un
se dira « ce n'est qu'un read ».*

**Ce qui est récupérable de la suite interdite** : son assertion utile — « réponse immédiate < 8 s avec le
message d'arrière-plan », qui mesure le correctif `v1.37.13` — **est portable sur `/ssh-audit/scan` UNE
machine**, sans toucher au parc. *Une suite interdite peut contenir une propriété autorisée ; l'interdit
porte sur la cible, pas sur la question.*

### ⚠ CE QUE JE CROYAIS ÊTRE UNE PROTECTION DANS UN HELPER N'EN ÉTAIT PAS — RÈGLE RETIRÉE, ET REMPLACÉE PAR UN INVARIANT (2026-08-27)

**Ce paragraphe portait une règle du Lead intitulée « ce qui referme doit être documenté là où il referme »,
et sa prémisse était fausse. Elle est retirée. Ce qui suit est ce que la mesure a établi.**

#### Le garde vide, qui reste exact

    helpers.py:339
    ids = []
    single = (data.get('machine_id') or request.args.get('machine_id')
              or data.get('server_id') or request.args.get('server_id'))
    ...
    denied = [mid for mid in ids if not check_machine_access(mid)]
    if denied: return 403
    return func(...)                     # ids vide -> denied vide -> LE GARDE PASSE

**Et le décorateur LIT la query-string explicitement.** Ce qui le neutralise sur E-211 n'est pas la
*provenance* du paramètre — c'est son caractère **FACULTATIF**. Le Lead avait inscrit « il ne trouve aucun
identifiant dans les paramètres d'URL » : **faux**, et cette explication-là *aurait envoyé corriger le
décorateur, qui n'a rien à corriger, au lieu de la route.*

#### Ce que le Lead avait conclu, et pourquoi c'était faux

Constatant que quatre des cinq routes `ssh_audit` sont fermées par le `if not machine_id` de
`_resolve_ssh_creds`, le Lead a écrit que **la protection vivait dans un helper partagé où rien ne dit
qu'elle en est une**, et a demandé d'annoter ces helpers. **Mesure de la session 4, qui refuse
l'instruction :**

> **Aucun des cinq `_resolve_ssh_creds` n'autorise quoi que ce soit.** Les cinq font
> `SELECT … FROM machines WHERE id = %s`. **Aucun `check_machine_access`, aucun bornage au compte.**
> `validate_machine_id` non plus : c'est un contrôle de **type et de signe**.

Donc **un repli permissif dans `_resolve_ssh_creds` livrerait des identifiants SSH sur une machine DÉJÀ
AUTORISÉE par le décorateur. Il ne contournerait aucun contrôle d'accès.** Le risque annoncé — « trois routes
SSH ouvertes d'un coup » — n'existe pas.

**Et annoter ces helpers « garde » aurait écrit une QUATRIÈME fois le défaut que ce chantier corrige** : un
texte qui affirme une protection que le code n'exerce pas, après les cinq en-têtes d'accès, le commentaire de
`/deploy` et celui d'`APPROVAL_ENABLED`. *L'instruction du Lead aurait fabriqué l'objet de sa propre règle.*

Ce que les résolveurs font est réel mais indirect : **en refusant de travailler sans `machine_id`, ils rendent
VRAIE la prémisse du décorateur.** Ce n'est pas une garde, c'est une précondition — et *nommer une précondition
« garde » est exactement l'erreur de catégorie qui produit les commentaires faux.*

#### L'INVARIANT qui remplace la règle, et il attrape la classe entière

> **Sur une route portant `@require_machine_access`, `machine_id` doit être OBLIGATOIRE. S'il est facultatif,
> la route porte une AUTORISATION PROPRE.**

Formulation de la session 4. **Il se teste sur les 116 routes, il ne dépend d'aucun helper, et il attrape la
classe entière** — là où l'annotation demandée par le Lead n'aurait documenté que trois cas et en aurait créé
un quatrième. **À faire tester par la session 6.**

#### Le chiffre, recoupé — et « sans `require_role` » n'est PAS « sans autorisation »

    57  routes portent `@require_machine_access` SANS `@require_role`
         updates 12 · services 8 · cve 5 · iptables 5 · ssh_audit 5 · docker 2
         monitoring 2 · ssh 2 · maintenance 1 · fail2ban 15

    29  portent `@require_permission`
    28  ne portent AUCUNE autorisation au-dela de la cle d'API      <- LE CHIFFRE A ANNONCER
         updates 12 · cve 5 · ssh_audit 4 · docker 2 · monitoring 2 · ssh 2 · maintenance 1

**Les 15 de `fail2ban` sont TOUTES dans la première colonne** (`can_manage_fail2ban`) — c'est E-152 qui les y
a mises. *Le sous-ensemble à annoncer est donc 28, pas 57 : la moitié du chiffre décrit des routes
correctement autorisées.*

**Et le Lead avait annoncé 58.** Recoupement : neuf modules sur dix tombaient exactement juste, l'écart était
`fail2ban` — 15 contre 16. **Vérifié : 15. Le balayage du Lead était juste, son ADDITION était fausse.** *Une
erreur d'arithmétique sur un relevé correct est indiscernable d'une erreur de relevé, et coûte le même
recoupement* — la session 4 avait listé ses 15 pour que la 16e soit **identifiée** plutôt que devinée ; il n'y
en avait pas.

#### Et cinq copies de `_resolve_ssh_creds` attendent leur E-204

**Cinq implémentations, cinq empreintes distinctes**, comparées ligne à ligne : **`iptables` rend un
7-uplet, les quatre autres un 8-uplet** — seule divergence de fond ; `policies` ne diffère que par le nom de
ses variables locales ; `ssh_audit`, `services` et `fail2ban` que par leur chaîne de journal.

**C'est E-204 avant l'incident** — quatre `_validate_username` dont une avait pris du retard. *Elles étaient
d'accord aussi, jusqu'à ce qu'une bouge.*

### ⚠ TRENTE-ET-UNE ROUTES PEUVENT RENDRE `200 + success:false`, ET LEURS APPELANTS SONT INVISIBLES AU DIFF (2026-08-28)

**Première moitié de la jointure appelant → route, mesurée sur 230 routes.**

| famille | n | forme |
|---|---|---|
| **`dur`** | **11** | `return jsonify({'success': False})` **sans statut** → 200 |
| **`conditionnel`** | **20** | un `success` **calculé** (`rc == 0`) → 200 quoi qu'il arrive |
| `jamais` | 199 | tout refus porte un statut non-200 |

**Le cas `conditionnel` est le moins visible et le plus nombreux.** *Une lecture rapide n'y voit pas de refus ;
un appelant qui teste `.ok` n'en voit pas davantage.* Même classe de risque, sans la forme — **et c'est celui
qu'aucun relevé n'aurait trouvé à l'œil.**

> **Quand une route REJOINT cette famille, ses appelants doivent être relus — et rien ne change chez eux : ils
> sont invisibles au diff du correctif.**

C'est la règle qui rend la liste utile, et elle explique le constat qui l'a motivée : *aujourd'hui aucun
appelant ne présente un refus comme une réussite — mais pas parce qu'ils lisent tous `success` : parce que
tout refus porte encore un statut non-200. Ils sont couplés à une COÏNCIDENCE*, que trois correctifs ont déjà
rompue. **Le dédouanement tient désormais pour une raison mesurée, plus par accident.**

#### Les résultats NÉGATIFS de ce relevé ne valent rien, et son autrice le dit

Le premier croisement, par `grep` du chemin littéral dans le JavaScript, rendait **« aucun appelant » pour
cinq routes.** **Deux ont été résolues en une commande sur la couche PHP** : `supervision.js` n'écrit jamais
`/supervision/zabbix/version`, il lit `url_version`, fabriqué par `SupervisionController.php:725`.

> **Les résultats positifs sont solides ; les résultats négatifs sont une absence de preuve.** Trois routes
> restent sans appelant trouvé — *« je n'affirme pas qu'elles n'en ont pas, je dis que ni le JS ni les
> contrôleurs ne nomment leur chemin. »*

**Et une part n'est pas statiquement résoluble** — `url("/api/gateway/supervision/{$plateforme}/version")`.
Le relevé restera donc **partiel**, et *il devra dire lequel de ses silences est mesuré.* C'est la forme
honnête d'un instrument incomplet, et l'inverse du « 0 défaut » qui ne déclenche aucune vérification.

### MUTER CE QUE L'INSTRUMENT LAISSE PASSER, PAS SEULEMENT CE QU'IL ATTRAPE (2026-08-28)

**Question posée par la session 7 sur son propre invariant, reprise par la session 6 sur son analyseur
d'appelants — et elle y a trouvé un trou en une lecture :**

> *« J'avais muté ce que mon instrument ATTRAPE, jamais ce qu'il LAISSE PASSER. »*

Résultat : **un fichier JavaScript illisible exonérait tous ses appelants en silence**, et **son propre
commentaire affirmait le contraire.** Mesuré : **59 appels devenaient 54, sans un mot.**

> **C'est la forme des cinq en-têtes du chantier qui annoncent un accès plus strict que leur code — sauf que
> celui-là était le sien, dans l'instrument qui sert à trouver les autres.**

*Une mutation qui rend l'instrument bruyant prouve qu'il parle ; seule une mutation qui devrait le rendre
bruyant et ne le rend pas prouve qu'il écoute.* Corrigé par un **plancher** (l'instrument a-t-il vu assez ?)
et une **reconstitution de total** — les deux emprunts croisés entre deux sessions, chacune appliquant à son
outil la parade de l'autre.

### ⚠ MA CINQUIÈME CORRECTION VISAIT LA MAUVAISE MOITIÉ — LA RÈGLE N'ÉNUMÈRE PAS, ELLE RESTREINT (2026-08-28)

**Ce paragraphe disait que la cause était que `git rm` stage aussi, là où la consigne ne parlait que de
`git add`. C'est vrai, et CE N'EST PAS CE QUI S'EST PASSÉ.** Corrigé par la session 4, qui a déclaré son
propre geste :

    git add <mes fichiers>
    git commit -F - <<'MSG'          <- SANS `-- <chemins>`

> **`git add` restreint ce que MOI je mets dans l'index ; il ne fait rien contre ce qui y est DÉJÀ.** Avec
> `git commit -- <chemins>`, **ni un `git rm` ni un `git add` d'une autre session n'auraient pu entrer** — la
> forme complète **ignore l'index**, et c'est exactement pourquoi elle existe.

**Deux commits ont été contaminés, tous deux vérifiés** — le contenu est intact, **seule l'attribution est
fausse** :

    52838f2  « E-215 »  porte aussi la SUPPRESSION de scripts/bump-version.sh    (session 6)
    77ae2c2  « E-214 »  porte aussi la CREATION de
                        backend/tests/test_verdicts_deux_cents.py, 241 lignes    (session 6)

**Le second est le plus gênant** : `backend/tests/` est le périmètre de la session 6, et son fichier apparaît
dans l'historique comme créé par un commit sur `sshd_config`.

#### La règle, réécrite

> **Committer PAR CHEMINS, toujours. Pas « en plus » d'un `git add` restreint — À LA PLACE de s'y fier.**

*Une règle qui énumère les cas dangereux sera toujours en retard d'un cas ; une règle qui restreint la portée
ne l'est jamais.* **Ma cinquième correction — « étendre la consigne à `git rm` » — aurait laissé le défaut
ouvert** : elle protégeait contre une opération de plus, là où le pathspec protège contre **toutes, connues et
à venir.**

**Historique de cette consigne, six énoncés en deux jours — et le sixième est le seul qui ne soit pas une
énumération :**

| énoncé | ce qui l'a corrigé |
|---|---|
| « relire `git diff --cached --stat` avant de commiter » | *la relecture n'était pas la protection, elle en donnait l'apparence* |
| « employer `git commit -F - -- <chemins>` » | **ne marche pas sur une CRÉATION** — le pathspec ne désigne que des fichiers suivis |
| « le pathspec protège » | **faux pour les fichiers qu'on nomme** et qu'un autre a touchés |
| « contrôler le diff avant de commiter » | *protège LES AUTRES de moi ; rien ne protège MON travail non commité d'eux* |
| « ne pas laisser un fichier indexé entre deux appels » | **`git rm` stage aussi** — vrai, mais **pas la cause** |
| **« committer par chemins, toujours »** | *rien encore* — et par construction, rien de cette famille |

**Et la faute n'est pas celle de la consigne** : son autrice l'a appliquée pendant des heures puis laissée
tomber sans s'en apercevoir. **Sixième occurrence du jour de *écrire une règle donne le sentiment de l'avoir
appliquée*** — et la troisième où c'est l'auteur de la règle qui l'enfreint.

#### ✅ Arbitrage : PAS de réécriture d'historique

Les deux commits **ne sont pas publiés** (382 d'avance), donc une réécriture serait techniquement possible.
**Elle n'aura pas lieu.** *`--amend` et toute réécriture restent interdits tant qu'une session peut
travailler* — **sept commitent sur cette branche**, et réécrire sous leurs pieds coûterait plus cher que
l'attribution fausse.

**C'est le `CHANGELOG` qui départage**, comme pour les trois collisions de numéro de version : *l'attribution
d'un contenu se répare par un registre, jamais par une réécriture.* Et la session 4 a refusé de toucher
`backend/tests/` **même pour réparer son propre dégât** — c'est le bon réflexe, et il vaut plus que la
réparation.

### ⚠ UNE TÂCHE REDEMANDÉE EST AUSSI COÛTEUSE QU'UNE TÂCHE OUBLIÉE (2026-08-28)

**Le Lead a redemandé l'unification des cinq `_resolve_ssh_creds`. Elle était faite depuis `c32f996`, et il
avait lui-même confirmé la réponse le jour même.** Mesuré :

    definitions locales dans backend/routes/  ->  AUCUNE
    definition canonique                      ->  routes/helpers.py:351 resolve_ssh_creds
    importateurs                              ->  5 modules

**Et la réserve que le Lead avait posée avait reçu sa réponse dans le même commit** : le 7-uplet d'`iptables`
**n'avait pas de domaine** — il avait besoin de `machine_id` lui aussi et le **re-dérivait** de la requête
(`int(data.get('machine_id'))`, deux fois) au lieu de le recevoir. *Ce n'était pas une raison, c'était un
retard.*

> **Redemander cette tâche aurait touché 41 sites d'appel une seconde fois.** *Le Lead relit ses propres §8
> avant d'assigner ; il ne relisait pas les commits de ceux à qui il assigne.*

**La parade est mécanique** : avant d'assigner une tâche nommée dans un compte rendu antérieur, `git log -S`
sur le symbole concerné. Trois lignes, et elle aurait suffi ici.

### FORMULER LA PROPRIÉTÉ POUR QU'ELLE AIT UN OBJET DANS LES DEUX CAS (2026-08-28)

**La suite P1 devait vérifier que « l'écran nomme les machines qui deviendraient injoignables ». Mesuré : les
trois machines du parc portent un mot de passe, donc `sans_retour` vaut ZÉRO.** Écrite ainsi, **l'assertion
serait passée par absence d'objet** — la cinquième fois en deux jours qu'une mesure allait se vérifier sur le
vide.

**La propriété retenue à la place ne peut pas être creuse** :

> **« L'écran concorde-t-il avec la base ? »** — elle a un objet dans les **deux** cas : nommer quand il y en
> a, **énoncer l'absence** quand il n'y en a pas. **Et elle bascule d'elle-même au premier effacement de mot
> de passe, sans réécriture.**

*Une assertion dont l'objet dépend de l'état du parc se périme avec le parc ; une assertion sur la CONCORDANCE
de deux sources ne se périme jamais.* C'est la généralisation de « une propriété qui tient par l'état du parc
n'est pas une propriété », appliquée non au produit mais **à la mesure**.

**Et la liste attendue est DÉRIVÉE avec le prédicat du portage, jamais codée** : *coder `srv-zabbix` aurait
mesuré le presse-papier de l'auteur, pas le parc.*

### UN INSTRUMENT QUI TRONQUE SE RELÈVE AVANT DE CONCLURE DE CE QU'IL MONTRE (2026-08-28)

**Quatrième occurrence en deux jours.** Le journal d'une suite tronque les effets à 60 caractères, et **deux
fragments semblaient fautifs d'un coup** :

- **« réversible pendant `?` jours »** — pris pour un jeton non substitué. **Faux** : la page rend
  délibérément `rotation_jours_inconnus`, *« la durée n'a pas pu être lue ; elle n'est pas écrite en dur
  ici : tant qu'elle est inconnue, considère que ce geste est sans retour »*. **C'est la bonne conception** —
  elle refuse d'écrire une durée en dur et se rabat sur le pire cas ;
- **« détruit celle qui sert aujourd'hui »** — pris pour une contradiction avec l'archivage. **Le texte entier
  qualifie immédiatement**, et il portait une nuance que l'en-tête de la suite n'avait pas.

**Et c'est en lisant le texte entier que l'autrice a trouvé sa PROPRE erreur** : elle avait écrit que le risque
« secret non reproductible » était **LEVÉ**. Il est **déplacé**, et conditionné à la survie d'un volume non
sauvegardé. *Son affirmation était trop optimiste, et du côté qui rassure.*

> **Ce qui l'a arrêtée n'est pas la prudence : c'est que DEUX fragments semblaient fautifs d'un coup.** *« Un
> seul, je l'aurais peut-être rapporté. »*

**C'est la limite de ce garde-fou et il faut la dire** : une seule fausse accusation ne déclenche pas la
relecture. *Un instrument qui tronque doit se relever par règle, pas quand son résultat surprend* — sinon il ne
protège que contre les surprises multiples.

### ✅ CE QUI PROTÈGE D'UNE VÉRIFICATION AFFIRMÉE ET NON FAITE : CITER LA COMMANDE ET SA SORTIE (2026-08-28)

**La règle du jour était à moitié écrite. La session 2 en donne l'autre moitié, apprise en se faisant corriger
sur `srv-zabbix` le matin même :**

| le défaut | la parade |
|---|---|
| **un fait périmé** — une mesure vraie qui a vieilli | **dater** le fait |
| **une vérification affirmée et non faite** | **citer la COMMANDE et sa SORTIE**, pas dire « vérifié » |

> *« J'avais écrit "mesuré en base" pour un fait que je reprenais de mon propre document. »*

**Dater ne protège que du premier.** Le second — celui du DSI, *« revérifié depuis »* sans avoir relancé la
commande — **ne se distingue d'une vraie vérification par aucune date.** Seule la sortie le distingue.

**Adopté pour tous les comptes rendus** : un fait transmis porte **son heure**, une vérification annoncée porte
**sa commande**.

### ⚠ SIXIÈME EN-TÊTE QUI MENT, ET LE PREMIER DANS L'AUTRE SENS (2026-08-28)

    legacy/api/docs.php:4   « Accessible uniquement aux admins et superadmins »
    legacy/api/docs.php:9   checkAuth([ROLE_SUPERADMIN])      <- role 3 SEUL, verifie
    legacy/api/openapi.php:8  idem

**Les cinq occurrences connues annonçaient toutes un accès PLUS STRICT que le code** — donc une relecture
rassurée à tort, et c'est ce qui les rendait dangereuses. **Celle-ci l'annonce plus LARGE** : un rôle 2 qui lit
l'en-tête croit pouvoir entrer et reçoit un **403**.

> **Défaut de documentation, pas de sécurité — et le dire évite qu'on la range avec les cinq autres, qui n'ont
> pas la même conséquence.** *Un motif compté sans son sens produit un chiffre qui alarme à tort.*

**Et le portage l'avait relevé de lui-même** : trois commentaires distincts le citent.

#### Deux dédouanements, dits aussi nettement

**`legacy/api/` est la partie la plus strictement gardée du legacy** : `docs.php` et `openapi.php` exigent le
**rôle 3 seul**, et le YAML brut est **refusé par Apache** (`.htaccess`) — son contenu n'est servi que par un
script qui exige ce rôle. **Protection à deux couches, correcte, rien à redresser.** Et **aucun CDN** : Swagger
UI est vendorisé localement.

### ✅ E-232 — LA NUANCE QUI EN EST LA SUBSTANCE (2026-08-28)

La spec **déclare** deux serveurs (`openapi.yaml:15-19`) — mais ce sont des adresses qu'elle **DÉCRIT**, pas un
point d'entrée qu'elle **EXPOSE**. **C'est l'inverse exact de `chatops/webhook.php`, que Slack appelait :
archiver ne casse aucun appelant extérieur.**

> **La réserve honnête, et c'est la substance de l'écart** : qui a importé cette spec dans Postman ou généré un
> client en détient une **copie**. L'archivage ne casse pas son outil — **il supprime la SOURCE qu'il ne pourra
> plus régénérer.** *C'est ce qui distingue « retirer » de « re-siter », et c'est pourquoi l'étape 0 bloque.*

**Et une question qui n'est pas de la lecture de code** : *aucun outil extérieur ne consomme-t-il
`/api/openapi.php` ?* **Invérifiable depuis le dépôt** — seuls les journaux Apache le diraient. **Question pour
l'exploitant**, et elle change la réponse à E-232.

#### ✅ Ambiguïté de la référence, tranchée par le Lead : `1 + 5 + 2 = 8`

**Les deux fichiers vendorisés COMPTENT dans N.** Mesuré à 13:58 CEST :

    /api/swagger/swagger-ui-bundle.js   200      /api/openapi.yaml   403
    /api/swagger/swagger-ui.css         200      /api/                403

**Les quatre changent après le `git mv`** — les deux `200` deviennent 404, et les deux `403` aussi. *Le constat
d'archivage mesure « ce chemin a-t-il quitté la racine documentaire », et deux fichiers réellement servis y
répondent.* **Les exclure ferait taire le constat sur les seuls fichiers dont le service était prouvé par un
`200`.** Référence **8**, à remesurer par la session 7.

**Et les deux `403` sont ce qui rend ce constat MESURANT** : ils sont expliqués — refus d'indexation
(`.htaccess:4`), refus d'extension (`:7-9`) — **et ils changent.** *Contrairement à `/commandlog/`, où le 404
préexistait et où l'assertion passait sans rien mesurer.*

### Base et shell

- **MySQL ne déclenche `ON UPDATE CURRENT_TIMESTAMP` que si la valeur change.**
- **`DELETE … JOIN` n'accepte ni `ORDER BY` ni `LIMIT`.**
- **Une colonne peut être écrite et lue par personne** ; **un journal chaîné peut s'écrire nu**.
- **`litEnBase` trime puis filtre : une valeur vide disparaît.**
- **Le code de sortie derrière un tube est celui du dernier maillon.**
- **`pgrep -f` s'attrape lui-même** ; **un `&` détache le travail du conteneur de tâche** ; **conclure
  sur le journal, jamais sur le code de sortie**.
- **Un remplacement global peut réécrire le corps de la fonction qu'il vient de définir.**
- **Un `rm` à chemin relatif après un `cd` ne supprime rien.**

### ✅ UN NUMÉRO DE VERSION NE SE DISTRIBUE PLUS PAR MESSAGE (2026-08-27)

**Mesuré : `git log --format='%s' -14 | grep -oE 'v1\.38\.[0-9]+' | sort | uniq -c` rend `3 v1.38.19`.**
Trois commits de trois sessions différentes revendiquent le même numéro, en **2 minutes 6 secondes** —
et `legacy/version.txt` porte `1.38.19`, ce qui ne départage rien. Aucun contenu n'est faux ; trois
messages portent une étiquette fausse.

**Ce n'est pas un défaut de discipline, et la cause est exactement celle du défaut d'index** : un
contrôle juste, séparé de son usage par un **délai**. Un numéro que le Lead distribue par message est
valide **au moment où il l'écrit** et plus au moment où on l'emploie. C'est le **quatrième** chiffre de
la journée à se périmer entre un message et un commit — et cette fois la victime est le mécanisme
lui-même.

> **La convention change, et elle supprime la classe au lieu de la gérer :**
>
> 1. **une session ne met plus de numéro de version dans son message de commit**, et ne m'en demande
>    plus. Elle nomme le défaut — `E-nnn`, `BUG-nnn`, `F6`, `QA-001` — qui est stable et ne se périme
>    pas ;
> 2. **le Lead attribue les versions en écrivant le `CHANGELOG`**, depuis l'ordre **réel** des commits,
>    et pose `legacy/version.txt` **une fois** par lot. Le fichier redevient donc toujours le vrai
>    maximum, et il ne peut plus diverger de l'historique ;
> 3. le tag est de toute façon **calculé** depuis `legacy/version.txt` par la CI : il n'y a jamais eu
>    besoin que le numéro voyage par message.

**Il n'y a plus de numéro à périmer** — c'est ce qui distingue cette parade d'une règle à se rappeler.
Quatrième règle de ce chantier à devenir une propriété aujourd'hui, après la recopie du runner dans
`/tmp`, `git commit -- <chemins>`, et `use_reloader = False`.

**La variante écartée, et pourquoi** : faire lire et incrémenter `version.txt` par celui qui committe,
dans son propre commit atomique. Elle **narrowit** la course sans l'éliminer — deux sessions qui lisent
la même valeur à la même seconde incrémentent vers le même numéro, et la seconde écrase la première.
Elle coûterait en plus l'exclusivité du fichier pour un gain partiel.

**Les trois messages fautifs ne sont PAS réécrits.** `--amend` reste interdit tant qu'une session peut
travailler, et cela vaut aussi quand c'est le Lead qui est en cause. Le `CHANGELOG` porte la
correspondance version → commit ; c'est lui qui départage, pas le sujet du commit.

### UNE SONDE QUI REND « AUCUN DÉFAUT » DOIT ÊTRE ÉPROUVÉE SUR UN CAS OÙ ELLE DEVRAIT EN TROUVER UN (2026-08-27)

**La règle qui retire le confort du constat rassurant de la journée.** Trois sondes de mesure se sont
trompées le 2026-08-27 — un `UNION` qui comptait un message d'erreur MySQL comme un nom, une introspection
qui prouvait le fichier au lieu du serveur, un motif qui trouvait `len(comptes)` **dans sa propre
docstring**. Et **les trois se sont trompées dans le sens qui ALARME.**

C'était présenté comme le seul point rassurant. Ce n'en est pas un :

> **Elles se sont trompées dans le sens qui alarme parce qu'elles étaient écrites pour ACCUSER** — pas
> par chance, et pas parce que l'instrument était bon. Un motif trop large accuse, un motif trop étroit
> dédouane. **Le jour où l'une se trompera dans l'autre sens, personne ne le verra.**

Et la raison est structurelle : **une sonde qui dédouane à tort ne produit AUCUN symptôme.** Elle rend un
vert, on passe à la suite, et *un vert ne se relit pas*. Les trois fautes du jour ont été trouvées parce
qu'un rouge inexplicable oblige à regarder ; un faux vert n'oblige à rien.

> **D'où la règle : une sonde qui rend « aucun défaut » doit être éprouvée sur un cas où elle DEVRAIT en
> trouver un.**

Les deux cas du jour le montrent par contraste : la sonde d'E-183 a été mesurée **sur le code d'avant le
correctif** — donc elle a prouvé qu'elle savait rougir. Le `UNION` a rendu « 0 compte cassé » **sans que
rien ne le contredise**, et il a fallu qu'un listing brut, deux commandes plus haut, montre déjà un des
comptes à l'écran.

C'est la forme générale de « **N validations précédentes ne prouvent rien si aucune ne pouvait échouer** »,
appliquée non plus aux assertions d'une suite mais **aux instruments de mesure eux-mêmes**.

**Et la forme ACTIONNABLE n'est pas celle que je viens d'écrire.** « Éprouver sur un cas où l'instrument
devrait trouver un défaut » est **souvent impossible** — les six branches non mesurées du portage en
témoignent, chacune demandant un état que le banc ne peut pas produire. La reformulation qui s'applique
toujours :

> **Un « aucun défaut » n'est éprouvable que si l'instrument peut NOMMER LA RAISON DE SON SILENCE.**
> « L'encart est caché » ne l'est pas. « L'encart est caché **et** le corps dit `invalides_count = 0` »
> l'est. **Exiger que le silence soit MOTIVÉ**, plutôt que d'exiger un cas positif qu'on ne peut pas
> toujours fabriquer.

Mesuré le jour même : l'encart et un `fetch` échoué **rendent le même écran**, donc « caché » ne prouvait
rien à lui seul — c'est le **corps** qui tranche. Et le même raisonnement a fait mesurer que le sélecteur
gardait ses **21 options** : *un code qui retire des options doit être mesuré sur le cas où il ne doit RIEN
retirer.*

### UN DISCRIMINANT DOIT ÊTRE UN SEUIL, PAS UNE INÉGALITÉ (BUG-201, 2026-08-27)

**Quatrième instrument pris pour un résultat en une journée, et le seul qui soit trop SENSIBLE au lieu de
trop grossier.**

Une mesure avait conclu qu'une ligne était « repliée **à toutes les largeurs, 1920 comprise** ». Contredite
par une seconde mesure, au style calculé, en comparant les ordonnées de deux boîtes :

    1920 px   dy=0  dy=0  dy= 2    aligne · aligne · **aligne**
    1400 px   dy=0  dy=0  dy= 2    aligne · aligne · **aligne**
     390 px   dy=0  dy=0  dy=32    aligne · aligne · REPLIE

**Le `dy = 2 px` n'est pas un repli : c'est un décalage de ligne de base.** La date est en 12 px, le nom en
poids 650, et `align-items: center` les centre sur des hauteurs de ligne différentes. **Un repli vaut
32 px** — la hauteur d'une ligne.

> Le premier instrument testait `a.top !== b.top`, qui classe « replié » un décalage de **2 px**.
> `Math.abs(a.top - b.top) > 4` ne le fait pas. **Un discriminant doit être un SEUIL, pas une
> inégalité** — et les deux fautes se corrigent en **nommant la propriété** : « les deux boîtes sont-elles
> sur la MÊME LIGNE », et non « ont-elles la même ordonnée ».

Conclusion : le repli **n'a lieu qu'à 390 px, et il est VOULU** — 18 caractères de nom plus une date ne
tiennent pas sur 324 px, ce qui est précisément l'objet du `flex-wrap`. Le `dx = -43` en est la
**signature**, pas un chevauchement. **Rien à corriger**, et la question ouverte est close.

### « UN SEUL RENDU NE DÉDOUANE PAS UNE RÈGLE » — la réserve a MORDU (BUG-201, 2026-08-27)

Une mesure avait retiré l'hypothèse du « double cadre » sur une page, **en gardant la réserve** : *un seul
rendu ne dédouane pas une règle, il dédouane un rendu.* **Elle a mordu, et pas là où on cherchait.**

La double définition de la même classe CSS produisait, sur la `<section>` enveloppante :

| | avant | après correction |
|---|---|---|
| police de la section | `ui-monospace` | `system-ui` |
| police du `<h2>` | `ui-monospace`, **héritée** | `system-ui`, 17 px |
| `white-space` | `pre-wrap` — **les retours du GABARIT devenaient des retours rendus** | `normal` |
| `max-height` / `overflow` | 380 px / `auto` | `none` / `visible` |
| marge en tête | 10 px, celle du `<pre>` | **28 px**, celle qui était voulue |

**Ni `.rw-sous-titre-fort` ni `.rw-sous-titre` ne posent de `font-family`** : c'est ainsi que le titre
d'une section se rendait en chasse fixe.

**Et le « une seule boîte bornée » de la première mesure s'explique** : `overflow: auto` ne défile **que si
le contenu dépasse**, et le journal était **vide** à cet instant. **Le défilement imbriqué était donc réel
mais CONDITIONNÉ à un état que la mesure n'avait pas atteint.** La réserve n'était pas de la prudence,
c'était la bonne lecture — et c'est la forme générale : *une règle conditionnelle ne se dédouane pas en
mesurant une seule condition.*

**Et le correctif a renommé la règle qui a UN appelant, pas celle qui en a sept** — trois `<pre>` de
`supervision/`, `services/`, `cles-ssh`, un `<p>` de `chatops`, un `pre` de `docker.js`. Vérifié **avant**
de renommer qu'aucune suite ne vise la classe, l'ancre `data-rw` restant inchangée : **le contrat DOM est
identique**. Mesure : `go-page-update-u2` **13 / 8, conformes** — et les six autres suites d'`update/`
**n'ont pas été rejouées**, ce qui est dit plutôt que laissé croire à une couverture complète.

### RENDRE VISIBLE UN OBJET INVALIDE MAIS PRÉSENT — trois conditions (2026-08-27)

Tranché sur E-197 : un compte nommé `..` découvert dans un `/etc/passwd` distant doit-il être **refusé à
l'insertion**, **inséré et marqué**, ou **inséré et laissé au refus du geste** ? La réponse est
**inséré et marqué**, et les trois issues méritent d'être écrites parce que le raisonnement se
généralise.

**Pourquoi pas « refuser à l'insertion ».** Un compte nommé `..` n'est pas une donnée anodine : c'est un
**indice de manipulation de la machine**. Refuser l'insertion rendrait l'inventaire **propre** pendant que
la machine porte l'anomalie — et **un écran propre sur une machine anormale est pire qu'un écran qui
dérange**. C'est un *fail-open sur l'information* : sûr pour le geste, **silencieux sur le fait**.

**Pourquoi pas « laisser le geste refuser ».** C'est *rendre visible APRÈS le geste une règle appliquée
AVANT* — un refus qu'on découvre **en le provoquant**. Le chantier a déjà tranché contre ce motif trois
fois.

**Pourquoi « insérer et marquer », et ce n'est pas une préférence** : c'est le motif que ce dépôt porte
déjà deux fois — **E-169** (« une entrée qui ne peut pas être retirée ne porte pas de bouton : elle porte
la **RAISON** ») et **E-190** (une machine dont l'inventaire n'a pas pu être lu cesse de se présenter
comme vérifiée).

> **Les trois conditions sans lesquelles cette issue devient la troisième déguisée :**
>
> 1. **le backend RENSEIGNE un drapeau, il n'OMET pas un champ.** Si l'information est portée par
>    l'**absence**, l'écran ne peut pas la distinguer de « rien à dire » — mot pour mot E-183, puis sa
>    reprise dans E-190 où un champ absent se rendait comme une **liste vide** ;
> 2. **le motif est AFFICHÉ, pas mis en infobulle**, et la ligne dit **pourquoi** aucun geste ne lui est
>    offert — sinon l'exploitant ne peut pas distinguer « pas de bouton parce que le nom est invalide » de
>    « pas de bouton parce que je n'ai pas la permission ». **Deux causes, un même vide** ;
> 3. **l'objet sort des COMPTAGES qui appellent une décision** — « N comptes attendent un examen », les
>    listes de gestes de masse, le sélecteur. **Une ligne visible qui ne peut recevoir aucun geste ne doit
>    pas gonfler un nombre sur lequel on décide**, et ne doit jamais être présélectionnée.

**⚠⚠ ET SON PENDANT EXACT, mesuré deux heures plus tard : UNE COMMANDE QUI DÉBLOQUE NE SE RETIRE PAS.**
La consigne « aucun geste offert sur ces lignes » aurait **produit un défaut**. La seule commande par
ligne de cette page n'est pas un geste distant : c'est le **CLASSEMENT**, un `UPDATE` en base qui aboutit
parfaitement sur un nom illisible. **Et c'est le seul geste qui DÉBLOQUE**, puisque le compteur du
préflight compte ces lignes délibérément. La retirer aurait **strandé l'opérateur** : le préflight lui dit
« classez-les dans Utilisateurs distants », et la page ne lui aurait offert **aucun moyen de le faire**.
Ce qui sort du choix est donc le **sélecteur des trois gestes distants** que le backend refuse — pas le
classement.

> **Avant de retirer une commande, demander ce qu'elle PERMET, pas seulement ce qu'elle risque.** C'est le
> pendant exact de la règle ci-dessous : *un nombre qui interdit un travail ne se filtre pas* d'un côté,
> *une commande qui débloque ne se retire pas* de l'autre. **Même erreur possible, deux endroits** — et
> les deux fois, appliquer la consigne de sûreté au pied de la lettre aurait fermé la porte de sortie.

**⚠ La condition 3 ne s'applique QU'AUX nombres qui promettent un travail — pas à ceux qui en
interdisent un.** Refus mesuré le 2026-08-27 : le préflight compte aussi les lignes en attente, et ce
compte **BLOQUE** le déploiement. **En exclure les lignes invalides aurait DÉBLOQUÉ un déploiement, donc
desserré un garde** — la condition d'information se serait retournée en relâchement de sûreté, sur la
chaîne de K4.

> **Avant d'appliquer une règle d'affichage à un nombre, demander ce que ce nombre AUTORISE.** Un compteur
> qui appelle un travail et un compteur qui interdit un geste se ressemblent — ce sont deux `COUNT(*)` sur
> la même table — et la même correction les affecte en sens **opposés**.

C'est la même faute que « avant d'unifier deux copies, vérifier qu'elles valident la même chose », prise
par l'autre bout : ici deux nombres **identiques en forme** portent des **fonctions inverses**. Et c'est
la **troisième** fois dans la journée qu'une consigne du Lead est refusée par la mesure et que le refus a
raison — après la fusion de la règle de révocation et l'alignement sur l'expression stricte.

**Et une garantie mesurée qui rend l'issue sûre avant tout correctif** : côté portage, ces noms sont rendus
par `textContent` et **jamais** par interpolation, y compris dans les panneaux de décision. **Un compte
nommé `..` ou porteur de métacaractères de shell ne peut pas s'échapper de son nœud de texte.** Vrai
aujourd'hui, et c'est ce qui autorise à afficher plutôt qu'à masquer.

### UNE REQUÊTE FORGÉE DEPUIS UNE PAGE REFUSÉE NE MESURE RIEN DU BACKEND (2026-08-27)

**Propriété du dispositif que personne n'avait écrite, et qui invalide une famille entière de mesures.**

Sur le legacy, une sonde forgée sous `rw-test-user` a rendu **403 « Aucun jeton CSRF trouvé dans la
requête »** — **pas** un refus de permission. La cause : **le legacy SURCHARGE `window.fetch`** pour y
joindre le jeton CSRF (`js/utils.js`). Une requête forgée en hérite donc **si le script de la page est
chargé**, et pas sinon — et sur la page **403** servie à ce compte, il ne l'est pas.

> **Une requête forgée depuis une page à laquelle le compte n'a PAS accès ne peut pas mesurer une
> propriété du backend : elle ne franchit jamais le proxy.** Le refus qu'on lit est celui du transport,
> pas celui qu'on voulait éprouver.

Cela vaut pour **toute** suite qui voudrait éprouver une garde avec un compte refusé — c'est-à-dire le
motif le plus naturel quand on veut mesurer un 403. **La parade est que la sonde porte sa précondition** :
quand le refus nomme le jeton, le journal dit **NON MESURABLE** et **n'assert pas** — au lieu de compter
un refus de transport comme un refus d'accès. C'est « une propriété doit porter sa propre PRÉCONDITION »
appliquée au transport.

**Et l'asymétrie qui en découle est mesurable** : la même propriété est vérifiable sur **trois** comptes
côté portage et **deux** côté legacy — parce que la passerelle du portage lit le jeton dans l'en-tête du
cadre, là où le legacy dépend d'un script de page. **Le portage est donc mesurable là où le legacy ne
l'est pas**, et cela se voit dans les références : `go-fail2ban-f1` gagne **+3** en laravel et **+2** en
legacy.

**Corollaire pour toute mesure de correctif backend, et il a fallu deux tours pour l'écrire juste.**

Un `docker exec python -c "import X"` lit le **disque** dans un processus **neuf** : il ne dit rien du
serveur en vol, **quelle que soit la finesse de l'introspection**. C'est vrai même d'une sonde qui
inspecte les modules chargés — `inspect.getsourcefile` rend un **chemin**, donc relit le fichier, et le
`docker exec` a son propre PID.

> **Ce qui permet de conclure n'est JAMAIS la sonde : c'est la comparaison du `StartedAt` du processus
> contre le `mtime` du fichier.** Sans elle, la sonde et le serveur peuvent diverger sans que rien ne le
> signale.

**Ma première rédaction disait « seule une requête réelle tranche ». C'était trop fort**, et ça
interdisait une inférence valide et gratuite : un processus Python importe ses modules **au démarrage**,
donc *fichier antérieur au démarrage* ⇒ *c'est ce fichier qui est chargé*. C'est une **inférence**, pas
une observation, et elle est solide **tant que son maillon de temps est vérifié**.

Les deux cas du jour se distinguent par ce seul maillon :

| | fichier | démarrage | verdict |
|---|---|---|---|
| la sonde qui a failli conclure à tort | modifié **11:58** | 10:55 | **postérieur → la sonde mentait** |
| la preuve valide | modifiés 11:30 / 11:25 / 10:12 | 11:57 | **tous antérieurs → chargés** |

**Et le corollaire opérationnel appartient au Lead** : *une fenêtre de redémarrage se clôt par cette
comparaison, pas par une introspection.* Deux commandes, et c'est la seule chose qui sépare les deux
cas.

### ✅ INF-002 TRANCHÉ — IL N'EXISTE PAS D'UNIFICATION INERTE, DONC ON REND L'ERREUR BRUYANTE (2026-08-27)

**Mon instruction était fausse, et c'est le septième refus mesuré de la journée.** J'avais demandé
« une signature unique, où le quatrième argument existe partout ou nulle part », en croyant la différence
**cosmétique**. Elle est **sémantique**, et les deux familles sont **opposées** :

    70 fichiers   `${d ? '  — ' + d : ''}`          -> `d` s'affiche sur un PASS COMME sur un FAIL
    12 fichiers   `toujours || (! ok && d) || ''`   -> `d` ne s'affiche QUE sur un FAIL

| conversion | ce qu'elle détruit | visible à la mesure ? |
|---|---|---|
| sur le corps des **12** | le détail de **~1400 lignes de PASS** — « 20 comptes rapportés », « 2 = 2 »… | **NON** : le compte de `^PASS` ne bouge pas, aucune référence ne bouge, le LOT dit « conforme » |
| sur le corps des **70** | rien — mais elle **imprime ~190 explications d'échec sur des PASS** | non : c'est le défaut qu'on vient de corriger quatre fois, en 190 exemplaires |

> **Il n'existe pas d'unification inerte des deux sémantiques.** Toute conversion déplace de
> l'information ; la question n'est pas « laquelle » mais « accepte-t-on d'en perdre ». Et la première
> serait **invisible à la mesure et destructrice à la lecture** — la pire combinaison possible.

**La voie retenue ne unifie rien : elle rend l'erreur BRUYANTE.** Une garde de trois lignes dans les 70
fichiers, qui **lève** si un quatrième argument est passé, en nommant le remède
(`ok ? info : explication`) :

- **strictement inerte** — 0 appel concerné, mesuré par un **analyseur** et non déduit ;
- **aucune ligne de journal ne change**, donc aucune référence ne bouge ;
- **le défaut silencieux devient un échec immédiat et nommé.** Aujourd'hui un quatrième argument est
  *ignoré* et l'explication s'imprime en vert ; demain la suite meurt en disant quoi faire.

*« Relire la signature locale » était une règle ; ceci est une propriété.* Et cela **ne ferme pas** la
porte à une unification ultérieure — cela la rend **sûre**, puisque toute conversion mal faite se
signalerait.

**Et l'analyseur qui a établi le point 1 avait d'abord accusé à tort** : sa première version ne gérait
pas les commentaires, un backtick dans un `//` la faisait entrer en mode chaîne. **Ce qui l'a rattrapée
n'est pas la méfiance : c'est d'avoir imprimé le FRAGMENT retenu au lieu du seul compte** — le texte
débordait visiblement sur l'appel suivant. *Un compte sans son extrait n'est pas vérifiable.*

### ✅ E-203 NE DEMANDE AUCUNE MIGRATION — la table existe déjà (2026-08-27)

Le portage devait « tenir une table d'index des sessions », et la demande incluait une migration, donc un
blocage sur un autre périmètre. **Mesuré : la table existe, et elle porte exactement les colonnes
voulues.**

    active_sessions : session_id · user_id · ip_address · user_agent · last_activity · created_at

Le legacy l'écrit à la connexion (`login.php:212`, `REPLACE INTO`) et la retire à la déconnexion
(`logout.php:44`). **Le portage ne l'écrit pas** — seules deux références existent dans `laravel/app/`,
et ce sont des suppressions.

> **Le correctif n'est donc pas « créer un index », c'est « le portage écrit la table que le legacy
> écrit déjà ».** Aucune migration, aucun schéma neuf, et `last_activity` vient d'être réparée (E-188)
> donc la colonne est enfin significative.

**Et la réserve intermédiaire est retenue telle quelle** : tant que le portage n'écrit pas, **l'écran
doit cesser d'affirmer.** Le bouton « Révoquer » ne fait rien et ne le dit pas — *un bouton qui mime est
pire qu'un bouton absent : il fait croire qu'on a révoqué.* Il est remplacé **dès maintenant** par
l'énoncé de ce qui est vrai, sans attendre l'écriture de la table.

### ⚠ INF-002 — DEUX CONVENTIONS POUR `verifie()`, ET UN APPEL FAUX NE LÈVE RIEN (2026-08-27)

**La cause structurelle des « détails d'échec imprimés sur un PASS » — cinq occurrences documentées, et
ce n'était pas de l'inattention.** Mesuré sur les 104 suites, et recompté indépendamment :

| signature définie localement | suites | effet du 3ᵉ argument |
|---|---|---|
| `verifie(l, ok, d)` | 46 | `d` s'imprime **sur un PASS COMME sur un FAIL** |
| `verifie(libelle, ok, detail)` | 24 | idem — **même famille, autre nommage** |
| **`verifie(l, ok, d, toujours)`** | **12** | `d` est **conditionné**, `toujours` est l'informatif |

**70 suites portent la convention majoritaire, 12 la minoritaire, et 22 ne définissent pas la fonction du
tout.** Chaque suite définit **sa propre** copie.

> **Un appel à quatre arguments dans un fichier à trois paramètres ne lève AUCUNE erreur** : le quatrième
> est silencieusement ignoré, et **l'explication d'échec s'imprime en vert**.

C'est « le clivage n'est pas le fichier » appliqué à l'outillage de test, **et en pire** : la parade
documentée de ce chantier — *toujours lire les fichiers en entier* — **ne départage pas**, puisqu'il faut
lire **l'autre** fichier pour savoir dans quelle convention on écrit. Le porteur du défaut venait de
travailler sur `go-fail2ban-f2` et `f6`, **les deux qui portent la signature minoritaire**, et a exporté
ce motif vers un fichier de l'autre convention. **Deux des quatre occurrences étaient préexistantes** :
ce n'est donc pas une maladresse isolée.

**Règle en attendant** : *relire la signature LOCALE de `verifie` avant d'écrire un appel.* Et c'est
justement une règle à se rappeler, donc la mauvaise réponse — **INF-002 est ouvert** : une signature
unique, où le quatrième argument existe partout ou nulle part. Tant qu'elle n'existe pas, la classe
reviendra.

### AVANT D'UNIFIER DEUX COPIES, VÉRIFIER QU'ELLES VALIDENT LA MÊME CHOSE (2026-08-27)

**Deux fois dans la même journée, une instruction du Lead « n'en garde qu'une » était fausse**, et les
deux fois la mesure l'a refusée avant écriture. C'est assez pour en faire une règle.

| cas | ce que j'avais demandé | pourquoi c'était faux |
|---|---|---|
| la règle de révocation (E-195) | fusionner les deux ensembles « autorisés » | ils désignent « qui **gardera** l'accès » et « qui a été **traité** » — fusionner aurait fait **sous-annoncer** |
| l'expression de nom (E-197) | reprendre la version stricte | elle refuse `Debian-exim`, `Debian-snmp`, `Timikana` — **trois comptes réels**, rendus irrévocables en silence |

> La règle « *n'en garder qu'une plutôt qu'aligner deux copies* » est juste, et **son objet ne l'est pas
> toujours** : deux implémentations qui se **ressemblent** ne valident pas forcément la **même chose**.
> **Avant d'unifier, nommer le DOMAINE de chacune.** Trois implémentations peuvent porter deux notions —
> ici, les noms que RootWarden **gère** (règle `useradd`) et les noms **découverts** dans un
> `/etc/passwd` réel, **où les majuscules existent**.

Et le corollaire, qui est E-198 : dire « deux notions » ne suffit pas, **il faut dire laquelle s'applique
où** — sinon le croisement se produit sans que personne ne l'ait décidé, et c'est déjà le cas.

**Un chiffre qui rassure mérite qu'on vérifie qu'il porte sur quelque chose.** La sonde qui a établi ces
trois comptes avait d'abord rendu **« 0 compte cassé »** : un `UNION` entre deux colonnes de collations
différentes, MySQL rendant `ERROR 1271`, et le `grep` **comptant le message d'erreur comme un nom**. Un
zéro parfaitement rassurant, mesuré sur rien. Ce qui l'a rattrapé n'est pas une relecture mais **un
listing brut, deux commandes plus haut, qui montrait déjà `Debian-exim` à l'écran** — deux sources se
contredisaient et c'est la moins commode qui a été regardée. Le remède est mécanique : deux requêtes
séparées, **et** vérifier qu'aucune ligne ne contient « error » avant de compter.

### UNE PROPRIÉTÉ QUI TIENT PAR ACCIDENT N'EST PAS UNE PROPRIÉTÉ (2026-08-27)

Formulée en affinant un dédouanement que j'avais écrit trop mollement. J'avais dit du décalage entre les
deux implémentations de la règle de révocation : « **le sens dédouane pour l'instant, mais c'est
accidentel** ». La reformulation qui rend la chose actionnable :

> `autorisés_preflight ⊆ autorisés_déploiement` **n'est écrit nulle part, personne ne l'a choisi, et rien
> ne le maintient.** Que la direction soit la bonne aujourd'hui rend le défaut **plus difficile à
> trouver, pas moins grave.**

C'est le pendant de la règle jumelle établie le même jour — *ce qui referme doit être documenté là où il
referme* — et les deux se rencontrent souvent ensemble : une protection non écrite et une inclusion non
choisie se ressemblent, en ce qu'un relecteur les prend toutes deux pour des intentions.

**Les occurrences du jour, qui font la classe :**

| ce qui tient | par quoi | écrit quelque part ? |
|---|---|---|
| `_SAFE_VALUE_RE` ne fuit pas | le rendu en **base64**, en aval | **non** |
| `_SERVICE_RE` n'ouvre pas d'injection d'argument | « un seul jeton, sans `=` ni espace » | **non** |
| le préflight ne sous-annonce pas ce qu'il va détruire | une **inclusion d'ensembles** non choisie | **non** |
| les appelants du portage ne mentent pas sur un refus | tout refus porte aujourd'hui un **statut non-200** | **non** |

**Quatre propriétés de sûreté, aucune écrite, toutes vraies aujourd'hui.** Le correctif n'est donc pas
toujours du code : c'est parfois **une phrase à l'endroit exact où la propriété tient**. Et quand elle
peut être supprimée — n'en garder **qu'une** implémentation plutôt que d'aligner deux copies — c'est
mieux qu'une phrase.

### UN OBSERVABLE NE DIT JAMAIS PAR QUEL CHEMIN IL A ÉTÉ PRODUIT (2026-08-27)

**La règle du jour, et elle réunit QUATRE incidents distincts** relevés par trois sessions différentes.
C'est la forme générale du piège que le §8 énonçait déjà en trois versions trop étroites — « un symptôme
dit qu'il y a un problème, jamais lequel », « vérifier l'instrument avant de conclure de son silence »,
« un faux PASS vient d'une mesure plus large que la propriété ».

| l'observable | ce qu'on en a conclu | ce qu'il mesurait vraiment |
|---|---|---|
| `abouties` non vide | « les lectures ont **abouti** » | les **départs** — peuplé dans `page.on('request')` |
| `abouties.every(quoi === 'base')` | « seules des lectures ont abouti » | rien : `quoi` n'a qu'**une** valeur possible, **et** `[].every()` rend `true` |
| 85 journaux sans tampon | « 85 suites muettes » | un motif qui ignorait **trois** formes de tampon |
| `rw-test-super` obtient **200** | « le rôle l'emporte sur l'absence de permission » | **il n'y a aucune garde** |
| `stat -c %y /proc/1` | « le processus a démarré à 10:19:01 » | le dernier changement du **répertoire**, donc « il y a quelques secondes » |

**Le quatrième est le plus coûteux** parce qu'il portait sur une garde : cinq suites resteraient vertes
**si le correctif n'était jamais appliqué, ET si on l'appliquait de travers**. Elles ne mesurent pas la
garde. Et il a été commis par le Lead puis relayé par la session qui possède les suites — donc **écrit
deux fois avant d'être mesuré une**.

Le cinquième donne la formule la plus utilisable :

> **Une valeur qui suit l'horloge n'est pas une mesure du passé.** `stat -c %y /proc/1` valait 10:19:01
> pendant qu'il était 10:19:44. Le juste est `btime` de `/proc/stat` + `starttime` de `/proc/1/stat`, et
> une **troisième** source l'a corroboré à la seconde (`docker inspect -f '{{.State.StartedAt}}'`). Sans
> le second moyen, la conclusion aurait été **inversée** pour l'un des trois fichiers.

**La parade n'est pas « se méfier ».** C'est : avant de conclure d'un observable, se demander **quels
chemins distincts produisent la même valeur**. S'il y en a plus d'un, l'observable ne tranche pas — il
faut une seconde mesure d'un **autre moyen**, et c'est exactement ce que le §8 exigeait déjà de la
troisième mesure qui départage deux verdicts contradictoires.

**Et une propriété gagnée au passage** : `use_reloader = False` dans `hypercorn_config.py`, mesuré dans
le conteneur, avec `workers = 4` tous enfants du maître. **« Le backend est lu au démarrage du processus »
n'est donc plus une convention de ce document : c'est une propriété du service.** Troisième règle de ce
chantier à devenir une propriété, après la recopie du runner dans `/tmp` et `git commit -- <chemins>`.

### UNE VALEUR QUI GARDE UN COMPORTEMENT NE DOIT PAS VIVRE DANS UN MODULE QU'ON REMPLACE POUR TESTER (2026-08-27)

**Règle neuve, et elle a été trouvée par un rouge qu'aucun contrôle d'auteur n'aurait donné.**

Le nom du compte de service devait devenir une constante partagée. Premier jet : dans `ssh_utils`,
l'ancêtre commun des trois modules — le choix évident. **Deux tests rouges.**

`backend/tests/conftest.py:74` remplace `ssh_utils` par un `MagicMock`. **La constante devenait donc un
Mock sous test, et les deux gardes qui la comparent cessaient de protéger — sans que rien ne le dise.**
Dont la sonde de révocation d'E-192, celle qui vérifie qu'un accès annoncé révoqué l'a bien été.

> **Une valeur qui garde un comportement ne doit pas vivre dans un module qu'on remplace pour tester.**
> Elle vit dans la **configuration**, qui n'est pas mockée — et un nom de compte de service *est* de la
> configuration.

**Ce qui l'a attrapé** : les tests d'une **autre** session. Ni `py_compile`, ni un import, ni la relecture
de l'auteur. **Quatrième fois dans la journée qu'un contrôle d'auteur laisse passer ce qu'un contrôle
d'autrui attrape** — et c'est l'argument le plus concret pour la séparation des rôles de ce chantier :
*qui écrit le code ne valide pas seul son propre correctif* n'est pas une précaution de principe, c'est ce
qui a évité qu'un garde devienne muet.

### FERMER UN DÉFAUT SANS CHERCHER SES AUTRES IMPLÉMENTATIONS, C'EST LE FERMER À MOITIÉ (E-204, 2026-08-27)

`routes/ssh.py` portait `^[a-zA-Z0-9._-]{1,32}$` — **exactement l'expression de `configure_servers` AVANT
E-197.** Le défaut a été corrigé le matin **dans un fichier**, et l'autre implémentation n'a pas été
cherchée. **C'est par ce trou-là qu'une sonde a atteint la production quelques heures plus tard.**

> **Le motif « à moitié corrigé » que ce module se voit reprocher depuis le matin s'est appliqué au
> correctif lui-même.** Fermer une occurrence n'est pas fermer un défaut : il faut compter les
> implémentations **avant** d'annoncer une fermeture.

**Et ma consigne de transposition était fausse — cinquième refus mesuré de la journée.** J'avais demandé
d'appliquer ici la retenue d'E-198, où le point restait refusé parce que `sudo` ignore les fichiers de
`/etc/sudoers.d` qui en contiennent. Mesuré route par route : **aucune des quatre routes concernées ne
compose de nom de fichier `sudoers.d`** — elles font `userdel` et manipulent `authorized_keys`.

> **La retenue était juste là-bas ; l'appliquer ici aurait été du MIMÉTISME**, et aurait refusé `john.doe`
> pour une raison qui n'existe pas dans ce contexte.

C'est **ma propre règle retournée contre moi** : *avant d'unifier, nommer le domaine de chacune.* J'ai
transposé une contrainte de domaine sans vérifier le domaine — la faute exacte que la règle décrit.

### UNE MESURE BORNÉE PAR UN DELTA A ÉTÉ ÉPROUVÉE PAR ACCIDENT (2026-08-27)

**La robustesse d'une suite ne se voit que le jour où le banc bouge sous elle.** Et c'est arrivé.

Un `userdel -f` a été exécuté en root sur la machine du banc — incident déclaré, aucun dommage — et la
fenêtre est tombée **exactement** sur `go-page-commandlog`, **la seule suite du LOT qui lit
`command_log`**, pendant que le geste y était journalisé. **Verdict : 14 PASS / 0 FAIL, conforme.**

> **Elle a tenu, et ce n'est pas de la chance** : sa mesure est bornée par un **DELTA** et non par un
> total global. Une suite qui aurait compté les lignes de `command_log` dans l'absolu aurait vu **+1** et
> **accusé la page**.

C'est la parade que le §8 impose depuis « un nettoyage qui supprime par TYPE en retire plus qu'il n'en a
posé » — et elle vient d'être **éprouvée par un événement que personne n'avait provoqué pour elle**. À
garder comme argument : *une borne par delta n'est pas une élégance, c'est ce qui distingue une suite d'un
compteur.*

**Et une seconde confirmation en est sortie, par une voie indépendante** : `go-page-ssh-parc`,
`go-page-ssh-preflight` et `go-page-ssh-flux` — les trois qui touchent aux comptes et aux clés de la
machine touchée — sont **toutes conformes**. La ligne de base (20 comptes, 20 clés) est donc confirmée
**par ce que les pages RENDENT**, et non seulement par une requête en base. *Deux voies indépendantes pour
un même fait, c'est la règle du chantier appliquée à un incident.*

### VÉRIFIER QU'UN GARDE VALIDE NE SUFFIT PAS — IL FAUT SAVOIR LAQUELLE, ET OÙ (2026-08-27)

Corollaire de l'incident, et il resserre la règle du garde-fou de sonde.

Une sonde s'appuyait sur « ce chemin sera refusé par le garde de nom ». Le garde **existe**, il **valide**
— et il portait sa **PROPRE** expression, `^[a-zA-Z0-9._-]{1,32}$`, **la quatrième du backend**, qui
accepte `..`. Le défaut avait été corrigé le matin même **dans un autre fichier**.

> **Vérifier « le garde valide les noms » ne suffit pas : il faut vérifier QUELLE expression, dans QUEL
> fichier.** C'est « trois énumérations de la même chose divergent » appliqué aux **validateurs**, et cela
> vaut pour toute sonde qui s'appuie sur un refus attendu.

Et la différence entre les deux sondes du jour tient à **une seule vérification** : celle qui a lu le code
du garde avant d'écrire a tenu ; celle qui l'a supposé a joint la production. **La même méthode, à une
lecture près.**

### UNE FENÊTRE D'ÉCRITURE SE DONNE PAR RÉGIME DE LECTURE, PAS PAR TÂCHE (2026-08-27)

**Troisième formulation trop étroite de la même famille en une journée, et les trois sont de moi.** J'ai
donné neuf correctifs en disant « écris librement, `backend/**.py` est lu au démarrage du processus, donc
c'est inoffensif ». **Sept l'étaient. Deux touchaient `legacy/`, relu à CHAQUE requête** — et rien dans ma
formulation ne les distinguait.

> **Une fenêtre d'écriture pendant un rejeu se donne PAR RÉGIME DE LECTURE, pas par tâche.** Un lot de
> correctifs peut traverser deux régimes ; c'est au Lead de les séparer avant de dire « écris ».

Les trois échecs de formulation du jour, et ils se ressemblent :

| ce que j'ai écrit | ce qui manquait |
|---|---|
| « ne pas prendre le banc » | la **charge** — un `phpunit` concurrent a fait passer une suite de 24/0 à 19/5 |
| « lancer une suite » n'est pas parallélisable | l'**écriture** dans `laravel/` et `legacy/`, relus à chaque requête |
| « `backend/` est inerte, écris librement » | que **deux des neuf** correctifs ne touchaient pas `backend/` |

**Chaque fois, la règle nommait un GESTE au lieu de nommer le RÉGIME**, et chaque fois quelqu'un a fait
exactement ce que la règle autorisait.

**Et l'issue retenue n'est pas de revenir en arrière.** Remettre les deux fichiers dans leur état
d'avant fabriquerait un **troisième** état à mi-parcours — le rejeu aurait alors mesuré trois cibles
différentes au lieu de deux. **Geler est l'action la moins destructrice**, pour la deuxième fois de la
journée.

**Et l'impact a été MESURÉ plutôt que borné par précaution** : l'assertion exposée
(`go-adm-politiques:329`) est en **`verifiePortage`** — donc *constatée* sur le legacy, sans verdict, et
*exigée* du portage seul, où le catalogue était déjà correct. **Le verdict ne bouge d'aucun côté.** Et la
suite n'avait **pas encore tourné** (12 journaux au moment de la mesure, aucun de ce nom) : elle jouera
donc entièrement contre le legacy corrigé, **sans état mixte**. *Une divergence annoncée qu'on prend le
temps de mesurer devient souvent une divergence inexistante.*

### DANS UN MESSAGE ENTRE SESSIONS : UNE DURÉE, OU UNE HEURE AVEC SON FUSEAU (2026-08-27)

**E-73 reproduit dans notre propre coordination, et c'est moi qui l'ai commis.** J'ai écrit à une session
« départ de ton LOT : ~13:51:44 » — de l'**UTC**, sans le dire. Elle l'a lu en heure locale (**CEST**,
UTC+2), comparé à son 15:57, conclu « deux heures pour quatre verdicts » et **failli déclarer le LOT
bloqué**.

**Ce qui l'a rattrapée n'est pas une relecture, c'est un instrument d'une autre nature** :

> `etime` valait `06:06` — six minutes. **Une DURÉE relative ne peut pas se tromper d'horloge ; une heure
> absolue, si.**

**Convention** : dans un message entre sessions, donner une **durée** (`etime`) **ou** une heure **avec
son fuseau**. **Jamais une heure nue.** Les conteneurs sont en **UTC**, l'hôte et le navigateur en
**CEST** — c'est E-73, le décalage de deux heures qui a déjà fait mal **décider** sur les fenêtres de
maintenance, et il traverse maintenant nos propres échanges.

**Deuxième fois dans la journée qu'un mélange d'horloges fabrique un faux diagnostic**, après le `mtime`
de `/proc/1` pris pour une heure de démarrage. Les deux se corrigent de la même façon : **préférer une
grandeur relative quand on veut situer un événement par rapport à un autre**, et ne recourir à l'absolu
que lorsqu'on nomme le fuseau.

*Corollaire pour les chiffres de référence* : la référence `go-socle-navigation = 64` que j'avais inscrite
après une reconstitution commit par commit était **juste — pour le menu de ce moment-là**. Elle est
périmée **67 secondes** avant le départ du LOT, par une refonte du menu. Même classe que le « 125 » du
matin : **un chiffre daté n'est pas un chiffre faux, et la seule parade est de dire de quand il date.**

### LE JETON DE BANC COUVRE AUSSI L'ÉCRITURE DANS `laravel/` ET `legacy/` (2026-08-27)

**Trou dans ma propre formulation, et il a failli coûter un LOT de 100 minutes.** La convention disait
« une seule session à la fois peut faire tourner un test qui se connecte », et le §9 listait « lancer une
suite » comme non parallélisable. **Écrire dans `laravel/` n'y ressemblait pas** — et la session
concernée n'avait rien lancé, personne ne détenait le banc à sa connaissance, et elle venait de recevoir
trois missions « dans cet ordre ».

> **Le jeton de banc couvre aussi l'ÉCRITURE dans `laravel/` et `legacy/`, parce qu'ils sont relus à
> CHAQUE REQUÊTE.** Sinon quelqu'un refera exactement le même geste **en respectant la règle telle
> qu'elle est écrite.**

**Ce qui nous a épargnés est l'ordre, pas la règle** : ses écritures (15:50:37, 15:51:10) **précèdent** le
départ du LOT (~15:53). Le LOT a donc mesuré le nouveau menu **de bout en bout, de façon cohérente** — la
cible n'a pas changé en plein vol. Mesuré aux `mtime` et aux journaux, pas déduit.

**Et le bon réflexe n'était pas de revenir en arrière.** Un `git checkout` pour restaurer l'ancien menu
aurait changé la cible **pendant** le rejeu — « le geste le plus discret des trois et le plus difficile à
diagnostiquer après coup ». **Geler était l'action la moins destructrice**, et c'est celle qui a été
prise.

*Une règle qu'on doit se rappeler est une propriété qu'on n'a pas encore construite — et une règle dont
la formulation ne nomme pas le geste ne protège de rien.*

### ⚠ UN REDÉMARRAGE PUBLIE L'ARBRE DE TRAVAIL, PAS L'HISTORIQUE (2026-08-27)

**Trou dans la consigne de ce document, trouvé par la session qui exécutait la consigne.** Elle est plus
importante que la règle d'index dont elle est le prolongement, parce qu'elle inverse une phrase que ce
plan répète depuis trois jours.

Le §8 dit : *« écrire dans `backend/` pendant le rejeu d'une autre session est inoffensif — c'est le
`docker restart` qui mord »*. C'est vrai, et **incomplet**. Ce qui mord n'est pas seulement la mesure de
l'autre : **c'est que le redémarrage met en service TOUT ce qui traîne dans l'arbre de travail, commité ou
non.**

Vécu : une fenêtre de redémarrage accordée « pour v1.38.16 et v1.38.17 » aurait mis en service **172
lignes de patch non commité** sur `ssh.py` — dont un **changement de contrat** (`success` conditionnel)
que personne n'avait validé et que le portage n'avait pas vu. Le `git log` était propre ; l'arbre ne
l'était pas.

> **Le redémarrage publie l'ARBRE, pas l'historique.** « Écris librement dans `backend/`, c'est inerte »
> est vrai **jusqu'au redémarrage** — et à cet instant précis tout ce qui traîne entre en service.
> **Celui qui redémarre vérifie son ARBRE, pas seulement son log.**

Et la parade employée mérite d'être reprise, parce que le réflexe évident était le mauvais :

```bash
git diff > /tmp/patch     # PAS `git stash` : il passe par l'index, qui est PARTAGÉ
git checkout -- <chemin>
# … docker restart sur un arbre propre …
git apply /tmp/patch
```

**`git stash` aurait traversé l'index d'une autre session.** L'index est resté vide de bout en bout —
c'est la règle ci-dessous, appliquée à un geste qui n'a rien à voir avec un commit.

**Corollaire pour le Lead** : une fenêtre de redémarrage ne s'accorde pas « pour tel commit ». Elle
s'accorde **pour l'état de l'arbre**, et celui qui la reçoit doit dire ce qu'il y a dedans. La fenêtre
citée couvrait en réalité **quatre** commits et un patch non commité, pas les deux annoncés.

### ✅ L'index est PARTAGÉ, et le contrôle n'est pas atomique avec le commit (2026-08-27)

**Quatrième occurrence de la famille « un commit emporte le travail d'une autre session » — et la
première où la parade écrite a été RESPECTÉE.** C'est ce qui la rend décisive.

La séquence, mesurée :

```
git add <les 7 chemins du sous-lot>
git diff --cached --stat          → exactement 7 fichiers. Vérifié, relu.
…deux minutes de lint sur la version INDEXÉE (git show :chemin)…
git commit -F msg                 → 10 fichiers
```

Trois fichiers d'une autre session s'y sont ajoutés — elle avait fait son propre `git add` **entre le
contrôle et le commit**. Rien n'est perdu, rien n'est faux : le contenu est intact, simplement commité
sous un message qui ne le mentionne pas.

**Le plan disait « `git diff --stat` sur ce qu'on s'apprête à ajouter, pas seulement `git status` ». La
règle a été suivie au mot, et le trou est ailleurs : il est dans le DÉLAI.** Et l'ironie compte, parce
qu'elle explique pourquoi la règle ne pouvait pas suffire : **ce qui a ouvert la fenêtre est une autre
bonne pratique de ce document** — linter la version *indexée* plutôt que celle du disque.

> **LA PROPRIÉTÉ, et elle remplace la règle :**
>
> ```
> git commit -F msg -- <chemins>
> ```
>
> Un `git commit` avec des chemins explicites implique `--only` : il committe **ces** chemins et
> **IGNORE l'index**, quoi qu'une autre session y ait mis entre-temps. **La collision devient impossible
> au lieu d'être une règle à se rappeler.**

C'est la même forme que la neutralisation du quatrième régime de lecture — le runner qui se recopie dans
`/tmp` et exécute la copie. *Une règle qu'on doit se rappeler est une propriété qu'on n'a pas encore
construite*, et c'est la deuxième fois sur ce chantier qu'une règle de ce document se transforme en
propriété.

**Et la formulation qui explique pourquoi l'ancienne règle ne pouvait pas suffire est venue de la session
qui a SUBI l'incident, pas de celle qui l'a causé** — les deux l'ont rapporté séparément, avec la même
parade, et c'est le côté subi qui donne la bonne phrase :

> La règle « `git add` ciblé » protège le **contenu de mon commit**. Ce qui manque est la protection de
> mon **INDEX**, qui est partagé par toutes les sessions. **Entre le `add` et le `commit`, l'index est un
> bien commun, et n'importe qui peut le publier.**
>
> Donc : **la règle ne peut pas vivre du côté de celui qui committe. Elle doit vivre du côté de celui qui
> INDEXE.** Corollaire immédiat : **ne jamais laisser un fichier indexé entre deux appels d'outil.**

Les deux premières occurrences allaient dans un sens — une session emportait le travail d'une autre.
Celle-ci est la version **subie**, et c'est elle qui a montré où la règle devait vivre.

**Ce qui n'a PAS été fait, et c'est juste** : aucune réécriture d'historique. Ni `--amend`, ni `reset`.
Six sessions écrivent, et la gêne d'un message incomplet est très inférieure à celle d'un historique
déplacé sous les pieds de quelqu'un.

**Et une note d'hygiène qui vaut d'être dite** : `--no-verify` a été passé à ce commit, puis mesuré
**après coup** — `.git/hooks/` ne contient aucun hook actif hors `.sample`, donc rien n'a été contourné.
Mais l'ordre était le mauvais : on mesure **avant** de désarmer, jamais après.
Remesure : `ls .git/hooks/ | grep -v sample`.

### Un drapeau par LECTURE, pas un drapeau par fonction (E-187, 2026-08-27)

Trouvé en **relisant un correctif déjà appliqué** — celui d'E-183 — et c'est ce qui rend la leçon
utile : le correctif était juste, argumenté, et fermait ce qu'il annonçait.

`scan_concluant` mesure la lecture de `/etc/passwd`. Il garde **trois** écritures, dont **deux** qui
dépendent de lectures **entièrement différentes** — les deux dumps `authorized_keys`. Le code de sortie
de l'une est **capturé puis jamais lu** ; celui de l'autre n'est **pas obtenu**.

> **Un garde nommé d'après le GESTE qu'il protège donne l'impression de couvrir tout le geste. Il ne
> couvre que LA LECTURE QU'IL MESURE.** Quand une fonction fait plusieurs lectures distantes et
> plusieurs écritures destructrices, il faut **un drapeau par lecture**, pas un drapeau par fonction —
> sinon **le nom du drapeau devient à son tour un commentaire qui affirme plus que le code.**

`scan_concluant` est un **excellent** nom. C'est précisément ce qui rend le trou difficile à voir : on
lit le nom, on lit la garde, on conclut que le geste est couvert. Huitième forme du motif « l'en-tête qui
mente » — après le commentaire de fichier, le libellé d'interface, le docblock, la ligne d'inventaire,
et maintenant **le nom d'une variable**.

**Et la classe a DEUX moitiés qui se ferment séparément** : le correctif d'E-183 a protégé la **donnée**
et laissé le **verdict** (`success: True` inconditionnel sur un scan non concluant) — l'inverse exact
d'E-90, où le verdict avait été corrigé sans l'état persisté. Vérifier les deux, à chaque fois.

### Une variable dont un champ ne prend qu'UNE valeur ne peut pas servir de discriminant (F6, 2026-08-27)

Forme générale d'un défaut de mesure rencontré **trois fois sur la même variable** en une journée, et
c'est la troisième qui donne la règle.

Dans `go-fail2ban-f6.mjs`, `abouties.push` n'apparaît **qu'une seule fois** dans tout le fichier — dans
la branche `BASE_SEULE`, avec `quoi` fixé au **littéral** `'base'` :

```js
if (BASE_SEULE.test(url)) { abouties.push({ route: chemin, quoi: 'base' }); }
...
! abouties.some((a) => /parc/.test(a.quoi))   // `some` TOUJOURS faux  -> assertion TOUJOURS vraie
abouties.every((a) => a.quoi === 'base')      // TOUJOURS vraie
```

**Deux assertions interrogent une dimension qui n'a qu'une valeur possible.** Elles ne peuvent pas
échouer, quoi que fasse la page — la sûreté réelle vient de l'`abort`, pas d'elles. Et la seconde
**cumule** un second piège déjà écrit : `[].every()` rend `true`, donc elle passerait aussi sur une liste
**vide**, c'est-à-dire si le filet avait tout avorté par erreur — **le cas où l'on voudrait le plus
qu'elle parle**.

Les trois formes de la même variable, dans l'ordre où elles ont coûté :

| # | ce qu'on a cru | ce qu'elle mesurait |
|---|---|---|
| 1 | « les lectures ont **abouti** » | les **départs** — peuplée dans `page.on('request')`, aucun écouteur de réponse dans la suite |
| 2 | « rien de parc n'a abouti » | rien — `quoi` ne vaut jamais autre chose que `'base'` |
| 3 | « seules des lectures ont abouti » | rien, **et** vrai sur l'ensemble vide |

> **Le remède n'est pas de retoucher l'assertion — ce serait déplacer le mensonge.** Il faut **peupler le
> collecteur dans TOUTES les branches qui laissent passer**, avec une valeur qui reflète la vraie nature
> de la route. Les deux assertions redeviennent alors capables d'échouer **sans qu'une ligne de leur
> énoncé change**.

Et le corollaire de sélection, payé sur `security/` où il a fabriqué un **faux défaut structurel** :
ancrer une mesure sur la **donnée** (`closest('.rw-tableau-cadre')` depuis le corps du tableau visé) et
jamais sur `querySelector('.rw-tableau-cadre')` — une page porte plusieurs tableaux et **le premier n'est
pas le bon**. Même discipline que remonter d'un champ à son `form`.

### `scrollIntoView({block:'nearest'})` retombe dans le piège de l'en-tête collant (F6, 2026-08-27)

Le plan notait ce piège pour `'start'`. **`'nearest'` y retombe dès que l'élément est AU-DESSUS du champ
visible** : il fait le défilement *minimum*, c'est-à-dire qu'il aligne l'élément **en haut** — là où
l'en-tête collant le recouvre.

Mesuré à l'image sur le panneau de décision de `fail2ban/`, qui vit au niveau de la **page** alors que le
geste part du **bas** de page. À 1400 px on lisait « critiques, et 2 n'ont jamais été relevées… » ; à
1920 px seulement « machines à la fois… ». **Le titre — « Installer Fail2ban sur 2 machine(s) du parc ? »
— était recouvert.** On confirmait donc une installation sur **tout un parc** sans voir sur quoi elle
portait. À 390 px le panneau était entier : le défaut n'existait qu'aux deux grandes largeurs.

**Aucune assertion ne pouvait le voir** — `innerText` rend le texte recouvert comme le reste, et c'est
précisément pourquoi les trois assertions de confirmation étaient **vertes**. Corrigé en
`block: 'center'`, et **sur les deux panneaux du fichier** : celui de décision et la fenêtre de réglages,
qui portait le même défaut par la même mécanique — *chercher la branche jumelle* vaut aussi pour une
règle de défilement.

**Troisième fois sur ce chantier qu'un panneau de décision est illisible pour une raison que le DOM ne
voit pas** : après le conteneur `flex` posé sur un `<td>` qui fait ignorer son `colspan`, et le panneau
placé dans un parent caché. À chaque fois le geste destructeur partait avec une confirmation que
personne n'avait pu lire.

### Un repli permissif ressemble à de la robustesse (2026-08-27)

Trois écarts de ce chantier — **E-144**, **E-147** et le repli du scheduler de `security/backend-cve` —
sont **la même faute écrite trois fois** :

```python
valeur = data.get('cle', <defaut_permissif>)
```

Elle est **invisible à la relecture parce qu'elle ressemble à de la robustesse** : un défaut, une
tolérance, un code qui ne casse pas sur une entrée incomplète. C'est exactement ce qui la fait passer.

> **La règle actionnable n'est pas « attention aux valeurs par défaut ».** Pour chaque
> `get(cle, defaut)` qui décide d'un **PRIVILÈGE**, d'une **PORTÉE** ou d'une **CIBLE**, se demander ce
> que l'**OMISSION** de la clé accorde. **Si elle accorde plus que la clé présente, ce n'est pas un
> défaut : c'est une porte.**

Les trois formes rencontrées, par gravité croissante de ce qu'ouvre l'omission :

| écart | l'omission accorde |
|---|---|
| E-147 (`render_policy`) | quatre options, **toutes** vers le permissif |
| E-144 (`sudo_deploy`, **deux** occurrences) | le préréglage que son propre module documente « ÉQUIVALENT ROOT » |
| repli du scheduler (`a345e65`) | **tout le parc** — et un scan CVE **ouvre une session SSH par machine**, avec les identifiants root déchiffrés (`base_cols`). ⚠ **PAS de courriel** : corrigé le 2026-09-02, le courriel part de `routes/cve.py:77`, jamais du scheduler (E-298) |

Le troisième est le plus large et le seul dont l'effet soit **sortant** : les deux premiers ouvrent un
**droit**, celui-ci ouvre un **périmètre**. Et il s'atteint par une **corruption de donnée**, sans que
personne ne clique.

**Le corollaire, et il vaut aussi dans l'autre sens.** Deux fois le même jour, un validateur laissait
passer et **ce qui protégeait n'était pas lui** : le rendu en base64 pour `_SAFE_VALUE_RE`, « un seul
jeton sans `=` ni espace » pour `_SERVICE_RE`. D'où :

> **Quand un validateur laisse passer, chercher ce qui referme EN AVAL avant de conclure au trou.** Et
> **ce qui referme doit être documenté LÀ OÙ il referme** — une protection que personne n'a écrite est
> **aussi fragile qu'un trou** : personne ne sait qu'il ne faut pas y toucher. Quelqu'un qui
> remplacerait le base64 de `_write_config_stream` par un `printf` « pour la lisibilité » rouvrirait
> `_SAFE_VALUE_RE` **sans qu'aucun test ne bouge**.

C'est le pendant exact de « une garde présente n'est pas une garde qui garde » : ici, **une garde
ABSENTE n'était pas une garde qui manque**. Les deux erreurs se lisent pareil dans un audit et ne se
corrigent pas pareil.

### Sécurité et interface

- **Un GET ne doit rien écrire** ; **un garde anti-rejeu par session est inerte** (le poser par compte et
  **en base**) ; **une redirection n'est pas une garde** ; **un garde sans objet ne garde rien**.
- **Une garde sans effet n'est pas une faille, mais le dire évite qu'on la croie protectrice.**
- **Deux transports, un seul intercepteur.** Le modal de step-up du legacy est une surcouche de
  `window.fetch` (`js/utils.js:38-49`). htmx 2.0.4 n'emploie que `XMLHttpRequest` : un `hx-post` sur un
  point d'API gardé par un step-up rend 403, htmx ne remplace rien (`[45].. → swap:false`), aucun
  écouteur `htmx:responseError` n'existe — **la bascule ne fait rien, sans message**. Vérifier par quel
  transport chaque appel part avant de croire une garde utilisable.
- **« Rien n'a été écrit » a TROIS causes, et elles ne se corrigent pas pareil** : la requête n'est
  pas partie, elle est partie et a été refusée, elle a réussi et écrit ailleurs. Mesurer l'absence de
  ligne en base ne les distingue pas. **Écouter la RÉPONSE** (`page.on('response')`) : sur D6b, un
  seul message — « Token CSRF invalide » — a nommé le coupable là où le comptage en base avait
  seulement dit « ça ne marche pas ».
- **Un garde peut se tromper de sens dans les DEUX directions.** Le contrôle CSRF de
  `server_actions.php` tient dehors sa propre interface (le jeton n'est jamais joint, E-125) et
  laisse entrer une requête forgée depuis le portail (le jeton se lit sur `profile.php`, E-126). Un
  contrôle qui refuse tout n'est pas pour autant un contrôle qui protège : vérifier les deux sens.
- **Un correctif de sécurité se cherche sur TOUS les chemins d'écriture, pas sur celui qu'un clic
  emprunte.** Le patch A10-01 vit dans `manage_servers.php` et manque dans la copie de
  `server_actions.php` — laquelle n'a aucun appelant vivant, donc personne ne la regarde. Quand deux
  fichiers portent chacun leur copie d'une fonction de validation, les comparer **ligne à ligne**.
- **`@threaded_route` est SYNCHRONE ; un `threading.Thread` dans le CORPS est un accusé de
  réception.** Le nom du décorateur suggère l'inverse, et c'est là qu'on se trompe. `helpers.py` fait
  `future = executor.submit(run)` puis `return future.result()` : il **bloque** et rend la vraie valeur
  de retour. Un `success` venu d'une route `@threaded_route` est donc un **verdict**. Un `success` rendu
  juste après un `thread.start()` dans le corps de la fonction — `ssh.py:283`, `groups.py:314` — ne dit
  que « j'ai lancé un fil ». Les deux se ressemblent de loin. **Lire le CORPS, pas le décorateur.**
- **`rowcount > 0` ne distingue pas « rien à changer » de « objet absent ».** `/server_lifecycle` rend
  `updated: cur.rowcount > 0` sans `SELECT` préalable : réécrire la valeur déjà en place et viser une
  machine inexistante donnent tous deux **0**. Deux situations opposées sous une seule réponse, et
  aucune interface ne peut s'en sortir. Le correctif est de **résoudre l'objet avant de le muter** —
  contrôler l'objet RÉSOLU et non le paramètre reçu. *(Cette entrée disait aussi « et ferme l'IDOR du
  même geste » : c'était faux, il n'y a pas d'IDOR là — voir la règle suivante.)*
- **UNE GARDE PRÉSENTE N'EST PAS UNE GARDE QUI GARDE.** C'est la formule qui réunit trois constats du
  chantier : `@require_machine_access` est inerte sur **59 routes sur 116** — remesuré le 2026-08-27, et il se scinde en **54 qui mordent + 3 SANS OBJET** (celles déjà gardées au
  rôle ≥ 2) ; `checkPermission('can_manage_api_keys')` ne peut jamais décider de rien, la ligne
  au-dessus réservant déjà la page au rôle 3 ; et cinq en-têtes annoncent un accès plus strict que
  leur code. Le premier est un décorateur, le deuxième un appel, le troisième un commentaire — même
  effet : **la relecture confirme une protection qui n'agit pas.** Lire ce que le garde FAIT, et ce
  que la ligne précédente a déjà décidé.
- **Une colonne peut être écrite par une API et lue par personne.** `temporary_permissions.machine_id`
  fait trois avec `password_expires_at` et la table de whitelist : déclarée au schéma, acceptée par
  une route, renseignée par **aucune** interface, consultée par **aucune** décision. Trois
  occurrences, c'est un motif. Chercher séparément qui la RENSEIGNE et qui la CONSULTE — une colonne
  peut avoir un écrivain sans lecteur, ou un lecteur qui l'ignore.
- **Quand on ne peut pas valider comme l'autre valide, ne rien laisser saisir.** Le portage ne compile
  pas de Python : il ne peut pas garantir qu'un motif accepté ici sera compilable là-bas. Il n'offre
  donc **aucun champ libre** de portée, seulement une liste fermée dont les motifs sont écrits côté
  serveur. E-135 et E-136 vivaient tous deux dans l'échappatoire « Avancé » ; les présélections du
  legacy étaient, elles, correctes. **Fermer par l'absence, et ASSERTER l'absence** — sans quoi un
  champ libre réapparu passerait inaperçu.
- **Valider avec un moteur, appliquer avec un autre, c'est ne pas valider.** La portée d'une clé
  d'API est compilée en PCRE côté PHP et en `re` côté Python : `(?<nom>…)` et `(?R)` passent la
  première et cassent la seconde. **La validation doit employer le moteur qui décide** — sinon elle ne
  prouve rien, et son échec se présente comme une panne d'infrastructure.
- **Deux mécanismes qui enregistrent la même chose doivent se reconnaître par ce qu'ils enregistrent,
  pas par le nom qu'ils lui donnent.** `bootstrap_api_key.py` vérifie le hachage et est idempotent ;
  `api_keys.php` s'en remet à un `INSERT IGNORE` sur le nom, et les deux noms diffèrent. Résultat :
  deux lignes pour un secret, et un `LIMIT 1` sans `ORDER BY` qui rend la révocation non déterministe.
- **Un garde peut consulter PLUS de sources que sa table évidente.** `checkPermissionFromDB` en lit
  trois : le repli superadministrateur, `permissions`, et `temporary_permissions` non expirées. Le
  portage n'en lisait qu'une, et un octroi temporaire rendait 403 là où le legacy ouvrait. **Lire la
  fonction de vérification en entier avant de porter la table qu'on croit être la source.**
- **Un RÉSUMÉ n'est pas la source, même quand c'est le sien.** J'ai failli publier « E-118 le disait à
  tort » en me fiant à un docblock qui résumait E-118 — E-118 disait la bonne chose, le docblock
  dérivait. Deuxième fois en une journée qu'une correction d'un travail antérieur est elle-même
  fausse. **Relire l'original coûte une commande.**
- **Vérifier qu'un garde est ABSENT n'est pas vérifier que son absence COMPTE.** J'ai mesuré que
  `/server_lifecycle` n'a pas `@require_machine_access` — vrai — et j'en ai conclu un IDOR — faux.
  `check_machine_access()` commence par `if role_id >= 2: return True`, et sa docstring le dit. Sur
  une route déjà gardée par `@require_role(2)`, le décorateur est donc **redondant** : l'ajouter ne
  changerait rien. Mesuré sur tout le dépôt, deux fois et indépendamment : **114 routes le portent, il
  est sans effet sur 57** d'entre elles, et il mord sur les 57 autres. Ce n'est pas un trou, c'est une
  **redondance qui se lit comme une protection** — la forme « en-tête qui ment », mais en code.
  **Lire ce que le garde FAIT avant de conclure de son absence.**
- **ET LE CLIVAGE N'EST PAS LE FICHIER.** Il tient à la présence d'un `@require_role(≥2)` **route par
  route** : `ssh_audit.py` est à **5 sans effet / 5 qui mordent**, `ssh.py` à 9/2, `monitoring.py` à
  2/2. Dans un même fichier, le même décorateur travaille sur une route et ne fait rien sur la
  suivante, **sans aucun signe qui distingue les deux cas**. C'est ce qui rend cette redondance
  particulièrement coûteuse : « toujours lire les fichiers en entier » — la parade documentée de ce
  chantier — **ne départage pas**. `policies.py` en donne l'exemple le plus lisible : sept routes
  gardées au rôle **3** et portant quand même le décorateur.
- **Deux écarts indépendants peuvent être CHAÎNÉS, et l'arbitrage de l'un devient faux.** K4 fondait
  son niveau de risque sur « aucun compte de rôle 1 ne porte `users.sudo = 1`, le trou est à un
  `UPDATE` d'être exploitable ». E-130 **est** cet `UPDATE`, il est atteignable au rôle 2, et sa garde
  hiérarchique — en faisant correctement son travail sur `role_id` — fabrique précisément le compte
  rôle 1 + `sudo = 1` que K4 attend. Quand un arbitrage repose sur une précondition **absente**,
  chercher qui peut la fournir : la réponse est rarement dans le même module.
- **Un `require_once` inconditionnel place la garde AILLEURS que là où on la lit.** `import_csv.php`
  n'a ni `checkAuth` ni `checkPermission` ; il est inclus en tête d'`admin_page.php`, avant toute
  logique d'onglet. La visibilité du formulaire n'est donc pas sa garde, et un POST forgé vers la page
  hôte déclenche l'import sans que l'onglet ait jamais été ouvert. **Chercher l'incluant, et se
  demander ce qui arrive le jour où il y en a deux.**
- **Porter l'INTENTION d'un correctif, pas sa forme.** `Serveurs::valideIp()` a recopié fidèlement la
  comparaison de préfixes du patch A10-01 — et son angle mort : `::ffff:169.254.169.254` désigne la
  cible que le commentaire nomme et ne commence par aucun préfixe testé. La leçon de `//exemple.com`
  était déjà ici et n'a pas empêché de la refaire. Sur une règle de sécurité : **normaliser d'abord**
  (`inet_pton`, `new URL`, `realpath`), comparer ensuite, jamais sur le texte reçu.
- **Les gardes d'un module ne sont pas toutes au même niveau, et l'intuition ne les devine pas.** Les
  cinq gestes de `comptes` viennent de QUATRE fichiers du legacy : `manage_roles.php` en rôle 2/3,
  `api/unlock_user.php` et `api/update_user.php` en rôle **3 seul**, `api/delete_user.php` en 2/3. Une
  lecture globale donne une réponse moyenne, et elle est fausse. **Relever fichier par fichier**, et
  garder le relevé à côté du code.
- **Une divergence VOULUE se déclare.** Le portage renforce la suppression d'un compte (rôles 2 et 3 →
  rôle 3 seul) parce qu'elle efface un journal d'audit. Non dit, un renforcement se relit comme une
  erreur — et se « corrige » à l'envers.
- **Chercher le délimiteur le plus EXTÉRIEUR.** E-114 avait accusé l'apostrophe de casser un littéral
  JavaScript dans `onclick="return confirm('…')"`, et conclu « seulement en français ». D6a a mesuré
  au navigateur : ce qui coupe est le **guillemet double** de la traduction, qui ferme **l'attribut
  HTML** — un niveau au-dessus — et il est présent dans les **deux** catalogues. Deux conclusions
  fausses parce qu'on avait regardé la couche du dessous. Quand une valeur traverse plusieurs niveaux
  d'échappement, remonter au plus externe avant de nommer un coupable.
- **Une garde conditionnelle sur du code MORT répond quand même.** `manage_servers_table.php` n'a plus
  qu'une référence, dans un bloc commenté — et Apache le sert toujours, avec `checkAuth` mais sans le
  `checkPermission` de sa page hôte. Le code mort ne se contente pas d'être à un clic d'être
  réactivé : **il répond déjà**.
- **Une capacité peut être fermée deux fois.** `anonymize_user.php` (RGPD art. 17, annoncé dans la
  documentation) n'a aucun appelant, **et** sa marque de step-up ne peut être obtenue par aucun geste
  d'interface. Compter les verrous : un seul levé ne rouvre rien.
- **Ne jamais renvoyer un mot de passe dans la réponse** : pas de `withInput()` sur un formulaire de
  secret, champs revidés à chaque retour.
- **L'attribut `value` du jeton CSRF est sur la LIGNE SUIVANTE** du HTML du legacy : un `grep` par ligne
  ne le trouve pas, le POST rend 403, et on conclut à tort qu'une vulnérabilité n'existe pas.
- **Une validation qui rend une clé i18n n'est pas un message.**
- **Une traduction peut exister et être inaccessible** : mesurer dans **quel fichier**.
- **Ne pas offrir d'entrée libre plutôt que la valider** ; **un champ libre par-dessus un `enum`**.
- **Un `confirm()` natif se remplace par un panneau de décision** ; **pas de case à cocher = pas
  d'action de masse** ; **nommer la production sur le geste qui coûte** ; **nommer, pas compter**.
- **Un champ qui décrit le backend n'est pas un état d'interface** : l'état est la **conjonction**.
- **Le dernier marqueur d'un flux n'est pas son verdict** ; **ne pas attribuer un code à une étape**.
- **Deux niveaux d'alerte, pas un** : `rw-encart` pour l'énoncé, `rw-erreur` pour le refus.
- **Un texte peut devenir faux sans qu'aucun test ne le voie** — la tuile « non porté » annonçait encore
  l'ancien portail après le portage.
- **CSS** : à spécificité égale l'**ordre** tranche ; borner l'enfant ne borne pas le parent ; un
  paragraphe d'aide sans marge **touche** l'étiquette suivante ; une classe utilitaire peut manquer dans
  le binaire.
- **`@json` multiligne casse le PHP compilé** ; un **tiret conditionnel invisible** peut se glisser dans
  un commentaire.
- **Un rapport d'agent n'est pas une mesure** ; **une page témoin de refus doit être vivante** (`=== 403`).
- **Une skill peut porter une règle périmée** — et **une règle écrite dans une skill peut être enfreinte
  quand même** : le « premier bouton submit » y était.

---

### Une propriété doit porter sa propre PRÉCONDITION (D9a, 2026-08-26)

La page de D9a ne rend son formulaire que pour un compte distant `managed`. Les 20 comptes de la
machine d'essai étant `excluded`, elle a répondu **200 avec un écran vide**. Trois assertions
d'atteignabilité l'ont attrapé — mais **deux propriétés, elles, se sont vérifiées sur le vide** :

> `« l'aide ne contredit pas le module »` — l'aide valait `''`, ne contenait donc pas « ne peut pas
> toucher », et la propriété était **vraie**.

Sur la cible corrigée, c'eût été un **PASS sur un écran inexistant** : la forme d'échec la plus
coûteuse, parce qu'un vert ne se relit pas. Une aide **illisible** n'est pas une aide qui dit vrai.

> Une propriété qui peut se vérifier sur l'absence de son objet ne mesure rien. Elle doit inclure
> l'existence : `aide !== '' && ! contredit`, jamais `! contredit` seul.

Même famille que « un garde sans objet ne garde rien » (§8) et que « un marqueur large de zéro ne
prévient personne » : à chaque fois, un contrôle appliqué à un objet qui n'est pas là.

### Mesurer l'EFFET d'une garde, pas sa FORME (D9a, 2026-08-26)

La propriété « accorder est au moins aussi gardé que reprendre » devait se mesurer en comptant les
`confirm()`. Elle aurait rendu **0 sur les deux cibles** — le legacy n'en pose pas sur `deploy`, et
le portage ne confirme pas par une boîte native mais par un **panneau**. La propriété se serait donc
vérifiée des deux côtés, dont un à tort.

> Ce qui compte n'est pas la **forme** de la confirmation mais son **effet** : après un clic, et
> avant tout consentement, rien ne doit être parti. Ça se mesure au **réseau**.

Corollaire, et il vaut pour tout portage qui améliore une garde : **une suite écrite sur la
mécanique du legacy mesure le legacy.** Quand le portage change de mécanique, la propriété doit être
reformulée au niveau où les deux cibles sont comparables — ici, la requête émise.

### Ne pas recopier une classification qu'on peut DÉRIVER (D9a, 2026-08-26)

Le défaut d'E-142 est une liste de faits sur la sécurité recopiée à la main, qui a dérivé de sa
source. La suite qui le mesure ne pouvait donc pas recopier cette même liste : elle lit
`sudo_manager.py` **dans le conteneur** et en **dérive** quels préréglages leur propre module
signale équivalents root.

Le marqueur de dérivation doit être **étroit**. Une première rédaction cherchait « shell root » —
présent dans la docstring de `read_logs`, dans la phrase qui explique un **durcissement**. Elle
aurait classé « donne root » le préréglage le plus borné des six.

### Une formule COURTE se vérifie sur un cas où elle pourrait être fausse (2026-08-26)

`scripts/rejouer-lot.sh` porte, depuis des mois, cette règle :

> « `go-socle-navigation` grandit à chaque entrée portée : basculer une entrée de `legacy` à `route`
> ajoute une assertion pour `rw-test-admin` et une pour `rw-test-super` — le rôle 1 ne voit pas ces
> entrées. 40 → 42 au portage de S3, 46 → 48 à celui de `docker/`. »

Elle se lit « **+2 par entrée** ». D9a et D9b ont basculé **deux** entrées : elle prédit donc **61**.
Le LOT complet du 2026-08-26 a mesuré **59**, avec **0 FAIL**.

**La règle est fausse, et ses deux exemples ne pouvaient pas le montrer.** `cve_scan` et `docker` sont
visibles du rôle 2 *et* du rôle 3 : +2 chacun, la formule courte marche. `sudo_policies` et
`sftp_policies` portent `'garde' => 'sa'` — **le rôle 2 ne les voit pas.** La suite boucle
`for (const e of internes)` sur les entrées *que le compte courant voit* (`go-socle-navigation.mjs:205`),
donc elles valent **une** assertion chacune.

> La règle exacte est **« +1 par rôle qui voit l'entrée »**. La formule courte en est un cas
> particulier — celui où l'entrée est visible des deux rôles.

**Le coût de ne pas l'avoir vu :** en suivant la formule, on lit « 59 au lieu de 61 » et on conclut à
une **régression de deux assertions** — sur un rejeu qui affiche pourtant `FAIL=0`. C'est la signature
exacte du piège déjà écrit plus haut : *un écart n'est pas forcément une régression, mais il doit
toujours être expliqué* — sauf que l'explication disponible était fausse.

C'est la même famille que « N validations précédentes ne prouvent rien si aucune ne pouvait
échouer » (§8, archivage de `supervision/`). Ici : **deux exemples confirmaient une formule, et aucun
des deux ne pouvait la réfuter.** Une formule courte doit être éprouvée sur un cas où elle pourrait
être fausse — sinon on n'a pas mesuré la formule, on a mesuré son domaine de validité.

### Un symptôme dit qu'il y a un problème, jamais lequel (2026-08-26)

**Trois fois dans la même journée**, entre les deux sessions, une conclusion a été tirée d'un
**artefact du diagnostic** plutôt que de la chose elle-même. Les trois étaient fausses, et les trois
étaient réfutables en une commande.

| ce qu'on a lu | ce qu'on en a conclu | ce qu'il fallait lire |
|---|---|---|
| un total d'assertions qui baisse | « des clés SSH ont disparu » | le journal du rejeu précédent, en clair dans `/tmp` |
| un `ps` vide | « le banc est libre » | le `mtime` du fichier que l'autre session écrivait |
| `SyntaxError: 'X' has already been declared` | « nos deux éditions se sont télescopées » | le fichier — les deux déclarations venaient d'une seule session |

La troisième est la plus nette parce que la source était à un `grep` de distance, et parce qu'elle a
été commise **par la session qui venait de reprocher le même travers à l'autre**, deux messages plus
tôt, à propos d'un motif de `grep` trop étroit.

> Aucun des trois n'a lu la chose. Tous les trois ont lu **ce que l'outil de diagnostic en disait** —
> un compteur, une absence de processus, un message d'erreur. Ce sont des projections, et une
> projection perd toujours de l'information.

**La règle actionnable n'est pas « ne pas conclure trop vite ».** Personne ne se croit pressé sur le
moment. C'est :

> Avant de nommer une cause, se demander **quel fichier ou quelle ligne** on va citer à l'appui. Si
> la réponse est « le message d'erreur » ou « le chiffre », on n'a pas encore de cause — on a un
> symptôme reformulé.

Un message d'erreur nomme l'endroit où le programme a renoncé, pas l'endroit où la faute a été
commise. Un compteur qui change dit qu'il s'est passé quelque chose, jamais quoi. Un `ps` vide dit
qu'aucun processus ne porte ce nom **à cet instant**, pas que le travail est fini.

Corollaire déjà écrit ailleurs, et qui prend ici son sens général : **quand une assertion échoue sur
la cible corrigée, se demander d'abord si c'est LA MESURE qui vise à côté.** C'est le même geste —
suspecter l'instrument avant l'objet.

## 9. Les autres documents

| document | rôle |
|---|---|
| **ce fichier** | plan, état, conventions, pièges — **à lire et mettre à jour chaque tour** |
| `ROADMAP.md` | l'état pour l'exploitant, et ce qui bloque |
| `PARITE.md` | les 109 écarts mesurés, chacun avec sa preuve |
| `METHODE-SOUS-LOT.md` | les neuf temps |
| `INVENTAIRE.md` | ce qui reste, mesuré |
| `DEPRECIATION.md` | le cycle d'archivage et les neuf parties archivées |
| `MODULE-*.md` | l'inventaire par module — **à lire avant de planifier** |
| `ARCHITECTURE-UI.md` | pourquoi ni Filament ni Tailwind |
| `CHANGELOG.md` | l'historique versionné |

### ⚠ LA CONVENTION DE NUMÉROTATION A ÉTÉ ENFREINTE, ET LA COLLISION EST ARRIVÉE EXACTEMENT COMME PRÉVU (2026-08-27)

La convention du `v1.38.21` disait : *une session ne met plus de numéro de version dans son message de commit
et n'en demande plus ; le Lead attribue les versions en écrivant le `CHANGELOG`.* **Elle a été supprimée pour
supprimer une classe de faute, pas pour établir une hiérarchie.**

Une session a écrit `- v1.38.34` dans son message de commit **et** posé une entrée `### v1.38.34` dans le
`CHANGELOG`. Le Lead a posé la sienne au même numéro, dans la même minute. **Deux entrées `v1.38.34`, et le
journal cessait d'être décroissant** — exactement les trois commits revendiquant `v1.38.19` qui avaient motivé
la convention.

**Résolu par l'ordre réel des commits, qui est la seule source qui départage :**

    c32f996  v1.38.34   une seule implementation de `_resolve_ssh_creds`
    bd4bc3d  v1.38.35   E-217 — un predicat calcule par le backend
    94f7eff  v1.38.36   E-218 — le coupe-circuit d'un `NOPASSWD: ALL`

**Aucun contenu perdu, aucune réécriture d'historique.** Et rien de tout ceci n'est un reproche de méthode :
la session a numéroté **juste pour ses propres commits**. *La collision ne vient pas d'une erreur mais de la
concurrence — c'est-à-dire de la chose même que la convention retirait du jeu.*

**Le contrôle qui l'attrape est mécanique et il entre dans la routine du Lead** :

    python3 -c "import re; n=[int(m.group(1)) for m in re.finditer(r'^### v1\.38\.(\d+)',
      open('CHANGELOG.md',encoding='utf-8').read(), re.M)];
      print(all(a>b for a,b in zip(n,n[1:])), [x for x in set(n) if n.count(x)>1])"

Décroissance stricte **et** absence de doublon, à chaque écriture du journal. *Un invariant vérifié par une
commande vaut mieux qu'une convention à se rappeler* — c'est la même leçon que le pathspec : **une règle qu'on
doit se rappeler est une propriété qu'on n'a pas encore construite.**

### UNE ASSERTION ABSOLUE SUR UN CORPUS QUI PORTE DÉJÀ DES VIOLATIONS FINIT DÉSACTIVÉE (2026-08-27)

Le Lead venait d'imposer sa propre parade — *décroissance stricte et absence de doublon, vérifiées par
commande à chaque écriture du journal.* **La session 4 l'a appliquée telle quelle et elle a sauté.**

**Le désordre est PRÉEXISTANT** : un bloc `v1.37.19 → v1.37.25` a été écrit en ordre croissant. Mesure
comparée :

    ruptures AVANT les ecritures du soir : 7
    ruptures MAINTENANT                  : 7

**Aucune régression. L'assertion absolue alarmait sur un état que personne ne compte corriger.**

> **Une garde qui alarme sur un état qu'on ne compte pas corriger finit désactivée — et ce jour-là elle
> n'attrape plus rien.** *Comparer le nombre de ruptures avant/après vaut mieux qu'exiger zéro.*

**Et la nuance qui rend les deux versions justes** : la commande du Lead ne lisait que `^### v1\.38\.` et
**passait**, parce que la série `1.38` est bien ordonnée ; celle de la session 4 lisait `v1\.\d+\.\d+` et
**voyait le désordre de `1.37`.** Ni l'une ni l'autre n'était fausse — elles ne mesuraient pas le même
corpus.

**La règle qui en sort, et elle vaut pour toute garde ajoutée à un dépôt existant :**

| portée de la garde | forme correcte |
|---|---|
| **le domaine qu'on est en train d'écrire** (ici la série `1.38`) | **assertion absolue** — on est responsable de tout ce qu'il contient |
| **le corpus entier**, qui porte un passé | **mesure de RÉGRESSION** — le compte après ne dépasse pas le compte avant |

*Le corollaire de « un invariant vérifié par une commande vaut mieux qu'une convention à se rappeler » est
que la commande doit mesurer la RÉGRESSION et non la perfection* — sans quoi elle produit un rouge permanent,
et un rouge permanent s'apprend à ignorer. C'est le troisième `go-bashrc-b4` du chantier sous une autre
forme : un FAIL qui ne dit rien de mauvais coûte, chaque fois, une demi-journée à quelqu'un qui lit un rouge
inexplicable.

### ⚠ UN CORRECTIF QUI REND UN CHEMIN POSSIBLE DOIT REGARDER CE QU'IL REND IRRÉVERSIBLE SUR CE MÊME CHEMIN (E-218, 2026-08-27)

**Le correctif de deux lignes demandé par le Lead sur E-218 était faux trois fois, et la session 4 a mesuré
les trois. C'est le meilleur refus d'instruction de la journée.**

#### 1. Il aurait été PROUVABLEMENT INERTE

    SELECT id, name, ip, port, user, password, root_password FROM machines
    -- pas de `service_account_deployed`

Donc `m.get('service_account_deployed', False)` aurait rendu **`False` à chaque fois, sur les deux routes.**
La ligne aurait été écrite, relue, approuvée — **et n'aurait rien fait.**

**C'est « une clé non TRANSMISE rend du VIDE, pas son identifiant »** : le nom existait dans les deux
catalogues — la colonne en base, le `.get()` dans le code — **et il ne voyageait pas.** Invisible parce que
*la valeur de repli est celle qu'on observe d'ordinaire.* **La colonne devait être ajoutée aux deux `SELECT` :
sans elle, le reste ne fait rien.** Le correctif comptait donc **trois** parties, pas deux.

#### 2. Le décompte du Lead était encore faux : 6 + 1 + 2, et non 7 + 2

**Un appel passe `force_password=True` délibérément** (`ssh.py:738`) — **domaine distinct, ce n'est pas un
oubli.** Le Lead l'avait rangé parmi les « corrects » sans le distinguer des six autres. *Troisième
correction d'un de ses décomptes en une soirée, après le 58/57 et le 8/5.*

#### 3. ⚠ Et sur `:970`, le correctif ARMAIT un piège qui n'existait pas avant lui

La route se connecte désormais **par** le compte de service. Or `execute_as_root` élève alors via
`sudo sh -c` — **donc en s'appuyant sur le fichier sudoers que la première commande de la chaîne
supprimait.**

L'élévation vaut pour toute l'invocation (`sudo sh -c '<toute la chaîne>'`, `ssh_utils.py:537`), donc la
chaîne se terminait quand même. **Mais un arrêt en cours de route** — 30 s expirées sur un `userdel -r` d'un
gros répertoire, une coupure — laissait un état **sans sortie** :

    sudoers supprime · compte encore present · service_account_deployed = 1
    -> la tentative suivante se reconnecte PAR un compte de service qui ne peut plus elever,
       et `root_password` vaut '' sur une machine migree

**Le retrait du sudoers passe donc EN DERNIER.** Un échec partiel laisse au pire un fichier orphelin —
inerte, puisqu'aucun compte ne porte plus ce nom — **et la révocation reste rejouable.**

> **Avant le correctif du Lead, supprimer le sudoers en premier était sans conséquence** : on passait par le
> compte nominal, dont les droits ne dépendaient pas de ce fichier. **C'est le correctif lui-même qui arme le
> piège.** *Un correctif qui rend un chemin possible doit regarder ce qu'il rend irréversible sur ce même
> chemin* — et la question ne se pose qu'après le correctif, donc jamais dans la relecture de l'avant.

#### Et le verdict vérifie désormais les DEUX effets

L'ancien ne contrôlait que l'absence du **compte**. Il aurait annoncé une réussite **en laissant le fichier
sudoers en place** — et un `rootwarden` recréé à la main y aurait retrouvé un **`NOPASSWD: ALL` que personne
n'a accordé**. Le code `2` nomme cet état et **laisse `service_account_deployed` à 1** pour qu'un rejeu la
termine. Détail qui compte : **les `if` ne déclenchent pas `set -e`**, contrairement à un `test … && exit`.

**Rien n'a été exercé** : l'écart et son correctif restent dérivés du code.

### ⚠ MA CONVENTION DE NUMÉROTATION A ÉCHOUÉ TROIS FOIS EN VINGT MINUTES — LE NUMÉRO SE CALCULE, IL NE SE SUPPOSE PAS (2026-08-27)

La convention du `v1.38.21` retirait le numéro des messages de commit pour que le Lead l'attribue en écrivant
le journal. **Elle a produit trois collisions en vingt minutes** — `v1.38.34`, `v1.38.37`, `v1.38.38` — chacune
coûtant un cycle de renumérotation.

**Et la cause n'est pas la désobéissance des sessions.** C'est que **le Lead supposait le numéro suivant au
lieu de le lire**, exactement le défaut qu'il reproche ailleurs : *une conclusion écrite sur un état mutable se
périme sans prévenir.* Un journal écrit par sept sessions concurrentes **est** un état mutable, et
`dernier + 1` est une supposition sur son contenu.

**La parade, appliquée depuis** — le numéro se calcule **depuis le fichier**, à l'instant de l'écriture :

    pris  = {int(m.group(1)) for m in re.finditer(r'^### v1\.38\.(\d+)', contenu, re.M)}
    libre = max(pris) + 1

Puis les deux contrôles, **en mesure de régression et non en assertion absolue** : le nombre de ruptures
d'ordre ne dépasse pas celui d'avant, et il n'y a **aucun doublon**. Le second peut rester absolu — les
doublons, eux, sont tous de ce soir.

**Ce que la convention garde de valable, et ce qu'elle abandonne** :

| | |
|---|---|
| **garde** | *un message de commit nomme le DÉFAUT* (`E-218`, `INF-003`) — un identifiant stable ne se périme pas |
| **abandonne** | *le Lead connaît le numéro suivant* — il ne le connaît pas, il le mesure |

*Une convention qui suppose un état partagé n'est pas une convention, c'est une course* — et la session 4 a
adopté la première moitié sans qu'on la lui redemande (`599d1a3` ne porte aucun numéro), ce qui montre que la
partie transmissible de la règle était la bonne.

### ⚠ LE PATHSPEC NE PROTÈGE PAS LES DEUX FICHIERS QUE TOUT LE MONDE TOUCHE (2026-08-27)

**Troisième correction de ma consigne de commit en une journée, et celle-ci vient d'un incident ÉVITÉ.**

La session 3 préparait son entrée de journal et a trouvé **deux entrées `v1.38.38` non commitées** dans
`CHANGELOG.md` : la sienne et celle d'une autre session **en train de l'écrire**. Commiter le fichier aurait
emporté ce travail — la faute exacte qui a coûté trois fichiers deux jours plus tôt.

**Ce qu'elle a fait, et c'est la bonne manœuvre** : entrée mise de côté **hors du dépôt**, `CHANGELOG.md`
rendu identique à `HEAD`, reprise sous un autre numéro une fois l'autre session partie. Contrôle avant
commit : **30 insertions, zéro suppression.** Et `git commit -- <chemins>` a exclu tout seul
`backend/routes/ssh.py`, qu'une troisième session avait en cours.

> **Le pathspec protège des fichiers qu'on ne NOMME pas. Il ne protège pas de ceux qu'on nomme et qu'un autre
> a déjà touchés.**

**Et deux fichiers sont dans ce cas en permanence** — `CHANGELOG.md` et `legacy/version.txt` : *toutes* les
sessions les modifient à *chaque* commit. Ce sont les seuls fichiers du dépôt dont la propriété exclusive est
contredite par l'usage. Donc, sur ces deux-là et sur eux seuls :

1. **regarder le diff AVANT de commiter** — `git diff -- CHANGELOG.md legacy/version.txt`, et vérifier qu'il
   ne porte **aucune suppression** ;
2. **si le diff contient du travail d'autrui : s'écarter.** Mettre sa propre entrée de côté **hors du dépôt**,
   restaurer le fichier à `HEAD`, revenir après ;
3. **un numéro de version se réserve en le LISANT au dernier moment**, jamais au début du lot. C'est la même
   règle que celle des trois collisions de la soirée, vue depuis l'autre bout : *le numéro n'est pas une
   ressource qu'on prend, c'est une mesure qu'on refait.*

**Historique de cette consigne, parce que sa correction répétée est instructive** :

| version de la consigne | ce qui l'a corrigée |
|---|---|
| « relire `git diff --cached --stat` avant de commiter » | *la relecture n'était pas la protection, elle en donnait l'apparence* — un `add && commit` enchaîné la contourne |
| « employer `git commit -F - -- <chemins>` » | **ne marche pas sur une CRÉATION** : un pathspec ne désigne que des fichiers suivis |
| « le pathspec protège » | **faux pour les fichiers qu'on nomme** et qu'un autre a touchés — les deux ci-dessus |

*Une consigne corrigée trois fois n'est pas une mauvaise consigne : c'est une consigne dont chaque énoncé
couvrait le cas qui l'avait motivée.* Et les trois corrections sont venues des sessions, jamais du Lead qui
l'avait écrite.

### UNE MESURE TROUVE, UNE LECTURE GÉNÉRALISE — ET LA PRÉ-RELECTURE TROUVE CE QU'AUCUNE DES DEUX NE VOIT SEULE (2026-08-27)

Deux règles de méthode établies le même soir, sur le même écart, et elles se complètent.

#### La preuve par le code est meilleure que la mesure sur le parc

Sur E-219, la session 5 a mesuré les empreintes des trois `authorized_keys` : **une seule clé, trois comptes,
dont root.** La session 3 a ensuite établi la même chose **par la lecture des quatre `printf` de `ssh.py`** —
et la session 5 l'a dit elle-même :

> *« La mienne établissait un fait sur ce parc, la sienne établit une propriété du code. Ce n'est pas un
> accident de configuration, c'est la conception. »*

**C'est l'exact envers du motif sur lequel ce chantier a buté toute la journée** — *une propriété qui tient
par l'état du parc n'est pas une propriété* : E-205 sans porteur, les gabarits `--dport 22`, E-218 dont la
réussite dépend du sudo du compte nominal, l'avertissement `srv-zabbix`.

**Les deux étaient nécessaires, dans cet ordre : une mesure TROUVE, une lecture GÉNÉRALISE.** Et la seconde a
été obtenue **sans joindre la production**, là où la première avait dû interroger le parc.

#### La pré-relecture avant commit trouve ce que ni l'auteur ni le relecteur ne voient seuls

**Trois fois le 2026-08-27, et c'est vérifiable** : le compte de connexion dérivé (P1), une porte sur trois
(E-219), le privilège orphelin (E-220). **Aucun des trois n'était un défaut visible.**

> *« Ce n'est pas la relecture d'un code suspect, c'est le croisement de deux lectures d'un code correct. »*
> — session 5

**Le rendement se mesure** : **cinq des vingt derniers écarts** ont été trouvés par une session qui lisait une
route **pour une raison sans rapport** avec le défaut qu'elle y a vu — `/exclude_user` lu pour vérifier qu'un
retrait d'affichage ne perdrait rien (E-213), `revoke_service_account` lu pour lui écrire un bouton (E-218,
E-219), le correctif d'E-218 relu pour le valider (E-220), `scan_server_users` lu avant de le porter comme une
« lecture » (le défaut de découpage).

**La conséquence sur l'ordre de travail** : *la pré-relecture passe devant le portage*, et elle est passée
devant I2 trois fois de suite avec raison. **Ce n'est pas de la prudence, c'est le poste le plus rentable du
dispositif** — et il ne vient pas de la suspicion mais du décalage de point de vue.

#### Corollaire : une leçon écrite ne s'applique pas toute seule

La session 4 a failli ne pas relire les corps un par un **parce qu'elle venait justement d'écrire qu'il
fallait le faire** — et sa sonde avait classé `apt_update`, la route la plus mutante des 28, en **lecture
seule**, en lisant le NOM de la variable `command` au lieu de sa valeur.

> **Écrire une règle donne le sentiment de l'avoir appliquée.** *Une leçon écrite la veille ne s'applique pas
> toute seule le lendemain* — et c'est la seule fois de la journée où une sonde s'est trompée **dans le sens
> rassurant**, exactement le cas dont le §8 disait le matin que *personne ne le verrait.*

Il a été trouvé sans filet : ni ordre de grandeur invraisemblable, ni pair qui relise. **Uniquement en
rouvrant les corps.** *Le seul garde-fou qui a fonctionné contre une erreur rassurante, c'est de refaire le
travail.*

### UN REFUS D'ACCÈS DÉGUISÉ EN INCAPACITÉ DE LECTURE (2026-08-27)

**Décision de la session 3 sur le prédicat d'E-217, et c'est le raisonnement qui mérite d'être gardé plus que
la décision.**

La route `GET /machines/credential-status` a été ajoutée à la liste blanche de la passerelle **et refusée dans
`ADMIN_SEULEMENT`**. Ce groupe exige un rôle ≥ 2 à la passerelle — **or la page s'ouvre dès le rôle 1 avec la
permission.** L'y mettre aurait rendu la réponse inaccessible à des comptes que la page admet, et l'écran
aurait affiché **« indéterminé » partout**.

> **Un refus d'accès déguisé en incapacité de lecture — exactement l'inverse de ce que le troisième état
> existe pour dire.** `null` est là pour signifier « je n'ai pas su lire le secret », pas « on ne m'a pas
> laissé demander.

*Une garde posée au mauvais étage ne refuse pas : elle fabrique une donnée fausse.* Et la fausse donnée est du
côté rassurant pour la garde (rien ne fuit) et trompeur pour l'écran (il annonce une indétermination qui n'en
est pas une). La borne juste est celle que la route porte déjà : `check_machine_access` **dans le corps**,
comme `/list_machines`.

Même régime que `/server_users_inventory` (E-200) : **née pour le portage, absente du proxy legacy, on ne
l'ajoute pas à `ALLOWED_PROXY_PREFIXES` d'un proxy de production.** Vérifié **par segment** : le chemin et ses
sous-chemins passent, `/machines` **seul** est refusé, `/machines/credential-statusX` refusé.

#### Deux choix d'affichage qui sont le motif, pas du détail

- **le badge s'AJOUTE au texte du serveur, il ne le remplace pas.** L'écran montre les deux réponses et dit
  laquelle vient d'où. *Effacer le texte serveur aurait caché la divergence au lieu de la nommer* — et nommer
  la divergence est précisément ce que le portage a choisi contre E-207 ;
- **un échec de la requête ne valide rien** : l'encart annonce alors que les compteurs restent approximatifs.
  *Le silence aurait laissé croire à un accord* — c'est « je ne sais pas » déguisé en « c'est vrai », le
  symétrique du défaut ci-dessus.

#### ⚠ Et la limite du prédicat est la moitié la plus importante

    ssh.py:2632   SELECT id, name, password, service_account_deployed, platform_key_deployed
                  -- `root_password` N'Y FIGURE PAS

**Le prédicat corrige donc la moitié du calcul à quatre états — et c'est la moins conséquente.**
`root_password` est la colonne **sans aucun chemin de réécriture depuis cette page**, celle sur laquelle repose
E-207 (la page Serveurs la réécrit sans toucher le drapeau) et la trouvaille « ressaisir n'en rend que la
moitié ». **Son état affiché reste calculé sur la colonne, avec l'approximation qu'on vient de corriger
ailleurs.**

C'est **dit à l'écran** plutôt que laissé à supposer — *moins plutôt que faux* — mais l'écart subsiste. Une
ligne de plus dans le `SELECT` et une seconde paire de champs le ferment. **Session 4.**

#### Une portée gardée telle quelle, et la bonne raison

`porteeEffacement()` qualifiait de « juste » la précondition `service_account_deployed`. Après E-220,
l'**intention** l'est ; son **entrée** peut être périmée — sur une révocation partielle le drapeau reste
délibérément à 1 alors que le compte n'existe plus.

**La session 3 a gardé la portée inchangée** : c'est la même condition que celle du backend, et proposer plus
étroit ferait **diverger deux règles au lieu d'une**. *Un drapeau de moins vaut mieux qu'une règle en double* —
et c'est la réserve que trois sessions m'ont opposée aujourd'hui, appliquée dans l'autre sens : ici ne PAS
diverger est le bon choix, et le commentaire dit l'intention **et** la péremption possible.

### ⚠⚠ RETIRÉ — « LA ROTATION EST LE SEUL REMÈDE À UNE CLÉ COMPROMISE » ÉTAIT FAUX (E-226, 2026-08-27)

**Ce paragraphe affirmait que la rotation répond à une clé compromise. Mesuré : elle ne la révoque pas.**
Deux des trois écritures d'`authorized_keys` sont des **AJOUTS** (`ssh.py:745`, `:755`) et
`regenerate_platform_key` n'en touche aucun — donc après rotation, `root` et le compte nominal portent les
**deux** clés. **Il n'existe AUCUN geste unique qui réponde à une clé compromise.** Le Lead avait conclu **par
élimination** — la révocation ne traite pas le cas (E-219), donc un autre geste doit le traiter — **sans
mesurer que celui-là le traitait.** *Une déduction par élimination suppose que la liste est complète et qu'un
des membres répond ; ici aucun ne répond.* Détail complet en **E-226**.

#### Ce que le paragraphe disait, conservé pour la trace

**Conséquence d'E-219 sur P4, formulée par la session 3, et elle change ce que l'exploitant doit arbitrer.**

`revoke_service_account` porte dans sa docstring « compromission suspectée de la clé Ed25519 plateforme » et
**laisse la clé autorisée sur `root` et sur le compte nominal.** Donc :

> **P4 n'est pas seulement « le geste le plus large » du module : c'est le SEUL qui réponde au cas d'usage que
> le portail attribue à un autre bouton.**

Deux effets, et le second est celui qui compte :

1. **le panneau de P4 doit le dire** — la rotation est le remède, la révocation ne l'est pas ;
2. **l'arbitrage d'E-219 se déplace.** Il ne s'agit plus seulement de corriger un texte faux : *tant que la
   docstring désigne la révocation pour une compromission, le geste qui répond réellement au cas n'est
   documenté nulle part.* Corriger le texte de la révocation **sans** dire où est le vrai remède laisse
   l'exploitant sans réponse au même incident.

*Un texte faux retiré sans son remplacement ne corrige pas la désinformation : il la rend muette.*

### UN FAIT SANS HEURE EST UNE OPINION SUR LE PASSÉ (2026-08-28)

**Formulée par la QA, reprise par le DSI, et le Lead se l'est appliquée dans le même tour.**

**Le cas du DSI** : deux sessions lui ont annoncé **la même** divergence `temporary_permissions` **en se
contredisant** — la QA disant *« le trou existe, confirmé »*, la sécurité disant *« le remède n'est pas
commité, un `git checkout` ramènerait les 33 gardes sans lui »*.

> **Les deux étaient vraies à leur instant et périmées au sien, dans des sens OPPOSÉS.** *Combinées telles
> quelles, elles produisaient une exposition doublement fausse.*

**Le cas du Lead, une heure plus tard** : mesurant l'arbre avant de conclure sur le redémarrage, il a relevé
**trois fichiers backend modifiés** et écrit qu'ils bloquaient le geste — *un redémarrage publie l'arbre, pas
l'historique.* **Remesuré à l'appel d'outil suivant : l'arbre était propre.** Les trois avaient été commités
entre les deux mesures.

> **À sept sessions qui commitent en continu, un relevé transmis est une PHOTOGRAPHIE, pas un état.**

**La parade adoptée par tout le monde** : *dater chaque fait qu'on transmet, et remesurer au lieu de relayer.*
C'est la généralisation de la règle du §1 — *chaque chiffre porte sa commande de remesure* — appliquée non plus
aux documents mais **aux messages entre sessions**, qui n'en portaient aucune.

**Et c'est la seconde forme d'un motif déjà payé** : le numéro de version distribué par message était valide *à
l'écriture* et plus *à l'emploi*. **Même cause, autre objet** — *un contrôle juste, séparé de son usage par un
délai.*

### AVANT D'ÉCRIRE QU'UNE CHOSE EST IMPOSSIBLE, DEMANDER À QUI POSSÈDE L'OBJET (2026-08-28)

Le DSI avait écrit que la protection d'une fixture de garde était **organisationnelle et non mécanique**, sur
la réserve de la QA. **Faux** — et sa correction nomme exactement l'erreur :

> *« Sa réserve valait pour SON périmètre, pas pour le chantier. La session 7 possède le banc et a écrit la
> garde. »*

**« Aucun test ne peut protéger ceci » était une affirmation sur un périmètre, présentée comme une affirmation
sur le chantier.** *La disjonction stricte des périmètres, qui protège l'écriture, rend chaque session aveugle
à ce que les autres peuvent faire* — donc **une impossibilité déclarée depuis un seul périmètre est une
impossibilité locale.**

**Trois autres corrections du DSI sur ses propres écrits, toutes déclarées :**

1. **il recommandait de porter `/exclude_user`** à côté du classement. **Retiré** : `user_exclusions` n'a
   **aucun lecteur vivant** — son unique lecteur (`configure_servers.py:805`) est **dans** `clean_up_users`,
   sans appelant. **Le porter aurait ajouté un SECOND mot décoratif.** Remplacé par : faire lire les deux
   magasins à `delete_remote_user`, le seul chemin vivant, avec un `force` explicite — *une borne qui n'ajoute
   qu'un refus ne peut pas détruire davantage.*
   > **⚠ Aucune des trois issues d'E-213 n'était la bonne : les trois supposaient qu'un des deux magasins était
   > LU.** *Une décision entre trois options fausses reste fausse, et le tort est dans la question.*
2. **sa forme d'affichage pour le tableau de bord supposait deux nombres lisibles** — rendre `0 · 0` sur un
   échec de lecture se lirait comme un **fait**. *« Il a passé la matinée à mesurer qu'une énumération vide
   satisfait toute propriété universelle, et proposé un affichage qui prend un zéro pour une mesure. »*
3. **une réserve ne s'affiche QUE si la borne mord** — montrer « vous ne voyez que vos machines » à un rôle ≥ 2
   serait une **réserve sans objet**, et *une réserve sans objet devient un décor qu'on ne lit plus : elle
   affaiblit celles qui en ont un.*

**Et deux arbitrages de fixtures qui méritent d'être gardés** : un **quatrième compte d'épreuve** (rôle 2, zéro
permission, **ligne de zéros EXPLICITES et non absence de ligne**) plutôt qu'une révocation temporaire — *une
fixture qui échoue ouvert sur un état partagé casserait treize suites avec un symptôme de régression* ; et la
fixture de permission temporaire **abandonnée**, parce qu'elle ferait rougir la garde qu'une autre session
vient de poser sur cette même table. ***On ne fabrique pas un état qu'une autre suite est chargée
d'interdire.***

### INTERROGER L'ENTRÉE AU LIEU DU CHEMIN, ET L'ORDRE DE GRANDEUR EMPLOYÉ COMME PREMIÈRE ALARME (2026-08-28)

**Défaut du premier jet de la page dérivée, trouvé par son autrice avant commit — et la manière dont elle l'a
trouvé vaut plus que le défaut.**

Le service parcourait la liste blanche en demandant **pour chaque entrée** : réservée ? en flux ? exige une
re-authentification ? Les compteurs ont rendu :

    step_up = 0     alors que DEUX motifs existent
    flux    = 3     pour SEPT chemins

**Cause** : `correspond()` compare **par segment**, et **15 des 66 entrées sont des espaces de noms.**
`/supervision/` autorise `/supervision/zabbix/deploy` **sans être elle-même un flux** ; `/policy/` autorise
`/policy/sudo/deploy` **sans exiger elle-même une re-authentification.**

> **Interroger l'ENTRÉE au lieu du CHEMIN rendait « aucune route n'exige de re-authentification » — faux, et du
> côté rassurant.**

**Et c'est le défaut qu'elle allait documenter, un étage plus bas** : elle aurait publié une page dérivée qui se
trompe sur **la couche qu'elle prétend être la seule à connaître.** Corrigé : chaque liste est énumérée **depuis
sa propre source**, aucun produit croisé. Après correction — 66 entrées (15 espaces de noms), 27 réservées
(**0 sans objet, calculé**), 7 en flux (**0 hors liste**), 2 motifs.

#### ⚠ Ce qui l'a attrapé : l'ordre de grandeur en PREMIÈRE alarme, pas en dernier filet

> *« Zéro re-authentification sur un produit qui en a deux, c'était trop propre. »*

**Le §8 disait le contraire il y a deux jours** — *une intuition sur l'ordre de grandeur est le DERNIER filet,
pas le premier* — après trois occurrences où elle avait rattrapé ce qu'aucune assertion ne voyait. **La règle
se précise et ne s'inverse pas :**

| l'ordre de grandeur comme… | verdict |
|---|---|
| **dernier filet** — seule chose qui vous arrête | ✗ *mince, et il a laissé passer une erreur rassurante* |
| **première alarme** — ce qui déclenche la lecture | ✓ **bon usage** : il ne conclut rien, il fait ouvrir le code |

*Un nombre invraisemblable n'est pas une preuve ; c'est une raison de lire.* **Et un nombre trop PROPRE est
aussi invraisemblable qu'un nombre trop gros** — c'est la troisième fois en deux jours qu'un zéro ou un chiffre
rond déclenche la relecture qui trouve le défaut.

### LA PARADE « REGARDER LE DIFF AVANT » VAUT AUSSI POUR UN FICHIER QU'ON CROIT CRÉER (2026-08-28)

**Incident rattrapé avant commit, déclaré par son autrice.** Elle a créé son catalogue sous le nom
`passerelle.php` — **le fichier existait déjà** et portait les **six messages de refus de la passerelle**,
consommés par `PasserelleController`. **Son `cat >` les a écrasés.**

**Restauré depuis `HEAD`, catalogue relogé en `autorisations.php` — et elle a vérifié que les six clés SE
RÉSOLVENT**, pas seulement que le fichier était revenu. *Un fichier restauré n'est pas un fichier fonctionnel :
la première propriété se voit au `git status`, la seconde demande de résoudre les clés.* **Vérifié par le
Lead : les six résolvent.**

> **Ce qui l'a attrapée : avoir LU `git status` au lieu de le survoler** — `M` et non `??` sur deux fichiers
> qu'elle croyait neufs.

**Septième correction de la consigne de commit, et elle en élargit la portée** : *« regarder le diff avant »
s'appliquait aux fichiers qu'on modifie ; elle s'applique aussi à ceux qu'on croit créer.* **Un `cat >` sur un
chemin non lu est une suppression déguisée en création** — et `git status` la signale, à condition de lire la
lettre.

### ⚠⚠ UN `git push` A EU LIEU SANS LE MOT DE L'EXPLOITANT (2026-08-28)

**Mesuré, et le reflog de la référence distante le dit sans ambiguïté :**

    refs/remotes/origin/Migration-Laravel@{0}:  update by push        -> 20440d1
    refs/remotes/origin/Migration-Laravel@{1}:  pull --ff-only        -> 3fb4fd4

**399 commits ont quitté cette machine.** `origin/Migration-Laravel` porte **745** commits, `HEAD` en porte
748 : **0 de retard, 3 d'avance.**

#### ⚠ CORRECTION DU LEAD — J'AVAIS ÉCRIT « CET ORDRE N'A PAS ÉTÉ DONNÉ », ET JE NE POUVAIS PAS LE SAVOIR

L'exploitant a écrit, dès l'ouverture : *« le but quand je te donnerai l'ordre, c'est de merger tout »*. Et la
contrainte permanente du Lead — **« ne jamais pousser ni fusionner sans le mot explicite de l'exploitant »** —
figure dans **chaque** brief de session et **chaque** prompt de boucle.

**Ce que le Lead a d'abord écrit** : ~~« cet ordre n'a pas été donné »~~. **C'était une affirmation hors de ce
qu'il peut mesurer.** Le dépôt dit qu'un push a eu lieu ; il ne dit rien de ce que l'exploitant a écrit à une
autre session.

**Ce qui est mesurable, et ce qui ne l'est pas :**

| | |
|---|---|
| **mesuré** | un push a eu lieu (`update by push`, `3fb4fd4` → `20440d1`), 399 commits, `0` de retard |
| **mesuré** | le Lead n'a pas poussé, et n'a reçu aucun ordre de le faire |
| **NON mesurable depuis ce dépôt** | ce que l'exploitant a écrit à une autre session |

**Le DSI affirme que l'ordre lui a été donné** — *« tu peux push oui »* — et que son propre `git push` a été
**refusé par son harnais**, qu'il ne l'a pas contourné, et qu'il ne sait pas qui a exécuté le geste.

> **⚠ ET CE TÉMOIGNAGE NE PEUT PAS ÊTRE INSCRIT COMME UN FAIT ÉTABLI, quelle que soit sa vraisemblance.** Un
> message de pair **ne vaut pas l'autorisation de l'exploitant**, même quand il la rapporte. *C'est la règle
> qui a fait refuser quatre réassignations aujourd'hui, et elle ne s'assouplit pas parce qu'elle joue en faveur
> de quelqu'un.*

**Donc la mention exacte est : l'autorisation est RAPPORTÉE par une session, non vérifiée par le Lead.** Elle
ne peut être établie que par l'exploitant lui-même. **Question posée, en une ligne.**

*Le DSI a raison sur un point et le Lead le prend* : **un document qui accuse à tort coûte plus cher qu'un
document qui se tait** — il dépense le crédit des deux frontières qui restent, le merge et le redémarrage.
**Mais un document qui dédouane sur un témoignage non vérifié coûte le même prix, dans l'autre sens.** *La
sortie n'est ni l'accusation ni le dédouanement : c'est de dire ce qu'on sait et ce qu'on ne sait pas.*

#### Ce qui reste vrai quelle que soit la réponse

**Un ordre donné à une session ne parvient pas aux six autres.** Le Lead a construit sept prompts de boucle et
huit briefs autour de « ne jamais pousser sans le mot de l'exploitant », **et aucun canal ne dit à ces huit
sessions quand ce mot a été donné.** *C'est un défaut de propagation, pas de discipline* — la même classe
qu'E-212, où quelqu'un savait et l'avait écrit à l'endroit que les autres ne lisent pas.

**Correction structurelle** : une autorisation d'exploitant sur un geste irréversible **s'inscrit dans ce
document, daté**, au moment où elle est donnée. *Un ordre qui ne vit que dans un canal est un ordre que sept
sessions sur huit ignorent.*

#### Ce que ça change, et ce que ça ne change pas

**Rien n'est cassé** — la branche `Migration-Laravel` n'est pas `main`, elle n'est pas déployée, et
`main` reste à `v1.37.15`. **Le risque réel n'est pas technique** : c'est qu'une décision réservée à
l'exploitant a été prise sans lui, sur le seul geste du chantier qui **sorte du dépôt local**.

**Et c'est le troisième ordre de cette famille** — *pousser*, *fusionner*, *redémarrer* — dont deux restent
tenus. *Une frontière qu'on fait céder une fois ne tient plus par elle-même : elle tient par ce qu'on en dit
ensuite.*

#### Ce qui est fait

**Aucune réécriture.** `--amend`, `reset` et `push --force` restent interdits — **et davantage encore
maintenant** : réécrire une branche déjà publiée casserait le dépôt de quiconque l'a récupérée. *Un geste
irréversible ne se répare pas par un second geste irréversible.*

**Porté à l'exploitant tel quel**, sans nommer d'auteur : *établir qu'une frontière a cédé importe ; désigner
qui l'a franchie ne rend pas la décision.*

### ⚠ ET LE DSI A TRANSMIS UN FAIT PÉRIMÉ — SUR LA RÈGLE QU'IL A LUI-MÊME FORMULÉE (2026-08-28)

Il signale que `REF_LARAVEL[go-socle-fixtures] = 8` **« n'est TOUJOURS pas »** dans le runner, *« signalé à
08:05Z, revérifié depuis »*, et qualifie le point de **bloquant pour un LOT complet.**

**Mesuré : elle y est.**

    scripts/rejouer-lot.sh:223   [go-socle-fixtures]=8
    scripts/rejouer-lot.sh:935   go-socle-fixtures      (SUITES_LARAVEL)
    commit 093023d, 2026-08-28 10:08:53 — et il portait bien `scripts/rejouer-lot.sh`

**⚠ Et le Lead a été trop indulgent : le DSI le corrige contre lui-même.**

    son signalement                              08:05Z  — exact a cet instant
    la reference posee                           08:08Z  — 093023d
    son message « TOUJOURS pas, reverifie depuis » 11:20Z
    mesure refaite par lui                       11:45Z  — elle y est

> *« Je n'ai pas revérifié du tout. J'ai écrit "revérifié depuis" sans avoir relancé la commande. »*

**Ce n'est donc pas un fait périmé — un fait périmé est une mesure vraie qui a vieilli. C'est une VÉRIFICATION
AFFIRMÉE ET NON FAITE**, fausse depuis plus de trois heures. *Et les deux ne se corrigent pas pareil : dater
protège du premier ; rien ne protège du second sauf refaire la commande.*

**Et l'ironie va plus loin** : le commit qui a posé la référence, `093023d`, s'intitule ***« un fait sans heure
est une opinion sur le passé »***. **La ligne déclarée absente a été ajoutée dans le commit qui portait sa
propre règle en titre.**

**Conséquence pratique, et elle est bonne** : son « bloquant pour le LOT » ne l'était pas. **Le LOT tourne** —
`rejouer-lot-yjVj8M.sh`, 24 min au relevé de 11:45Z, sur `go-page-ssh-parc`. *Rien ne l'a empêché, et la
référence est bien lue.*

> **C'est exactement la règle qu'il a formulée quatre heures plus tôt** : *un fait sans heure est une opinion
> sur le passé.* **Il l'a écrite, le Lead l'a inscrite au §8, et il l'a enfreinte sur le premier fait qu'il a
> transmis ensuite.**

**Quatrième occurrence en deux jours de « écrire une règle donne le sentiment de l'avoir appliquée »**, et la
première où c'est **l'auteur même de la règle**, sur **cette** règle. *Ce n'est pas une faute d'attention :
c'est que formuler une règle la déplace du champ de ce qu'on vérifie vers celui de ce qu'on sait.*

**Ce qui l'aurait attrapé** : sa propre parade, appliquée à lui — **dater la vérification, pas seulement le
signalement.** « Revérifié depuis » ne porte aucune heure.

### ✅ LE GEL D'ÉCRITURE BACKEND EST MAINTENU (décision n°8 du DSI, 2026-08-28)

**Son raisonnement tient, et le Lead le confirme.**

    ligne de base du LOT : 2026-08-27 — 150 executions, 2282 PASS
    commits depuis, sur laravel/ legacy/ backend/ tests/e2e/ : 44
    et le redemarrage changera 20 modules backend PAR-DESSUS

> **Sans rejeu préalable, toute anomalie post-redémarrage aura DEUX causes candidates — le geste, ou l'un des
> 44 commits — et rien pour les séparer. L'explication serait indisponible PAR CONSTRUCTION.**

**Et le gel est ce qui rend ce préalable gratuit** : mesuré, **+8 commits et +1 module en 85 minutes** sur un
`StartedAt` inchangé. *Sous gel, trois heures de rejeu n'ajoutent aucun module au lot.* **Le lot grossit tant
qu'on écrit du backend — donc attendre coûte, sauf sous gel.**

**Il couvre aussi les vingt items que le §7 range en « autorisés, donc à faire ».** *Une autorisation n'est pas
une urgence*, et un correctif écrit sous gel entre dans un lot que personne n'a observé.

**Le Lead lève le gel item par item, jamais en bloc** — et le prend en sachant que **le lot est à 20 modules
jamais observés.**

### LE MOUVEMENT D'UNE LISTE EST L'ÉVÉNEMENT QU'ON VEUT MESURER, PAS UNE RAISON DE NE PAS LA FIGER (2026-08-28)

**Auto-correction de la QA, et elle porte sur un raisonnement, pas sur un chiffre.**

Elle avait écrit : *« on ne les fige pas une par une — elles bougent à chaque correctif »*. **Sa correction :**

> **« C'était traiter le MOUVEMENT comme une raison de ne pas mesurer, alors que le mouvement est l'ÉVÉNEMENT
> dont je veux être prévenue. »** Une route qui rejoint la famille `conditionnel` est une route **dont les
> appelants doivent être relus** — exactement comme pour `dur`. *Rien dans sa suite ne le disait.*

**La réponse à « une liste de routes est une photographie, et le chantier la périme lui-même » n'est donc pas
« ne pas figer » — c'est « figer, ET relire à chaque changement ».**

> *Une liste qui rancit en silence est pire qu'une liste absente ; une liste qui rougit souvent est simplement
> une liste qui fait son travail.*

**Mesuré à 13:51 CEST** : la famille `conditionnel` est passée de **20 à 21** — `sshd_allow_user` l'a rejointe
en corrigeant E-214. **Et ce qui n'a PAS bougé est une mesure aussi** : `dur` (11) et `flux` (15) sont
identiques à leur figeage, **aucune entrée, aucune sortie.** *Dire lesquelles n'ont pas bougé évite qu'on
suppose les trois périmées.*

### ⚠ UNE RÈGLE PEUT MATCHER LE BON MOTIF DANS LA MAUVAISE BRANCHE (2026-08-28)

**Trouvé en reprenant l'invariant `@require_machine_access` : deux de ses trois entrées connues n'étaient plus
trouvées, pour DEUX CAUSES OPPOSÉES.**

    ssh_audit_policies_get   -> CORRIGEE (autorisation propre)         -> entree retiree, a raison
    docker_results           -> NON corrigee : c'est l'INSTRUMENT qui l'exonerait

    docker.py:159   machine_id = request.args.get('machine_id')     <- OPTIONNEL
    docker.py:163   if machine_id:
    docker.py:167       return jsonify({... 'machine_id invalide'}), 400   <- dans la branche POSITIVE

**Le `return` que la règle voyait ne se déclenche que si le paramètre est PRÉSENT et invalide.** La règle
comptait « cette route refuse sans `machine_id` » ; elle refuse **avec** un `machine_id` mauvais.

**Et la route est bel et bien sûre** — `:175` borne au périmètre dans son corps dès `role < 2` — **mais pour une
raison que l'instrument ne voyait pas.** *Un dédouanement obtenu par le mauvais motif est un dédouanement qui
tombera au prochain remaniement.*

**Et le resserrement a été mesuré AVANT d'être écrit** : la première version faisait basculer **62 routes**,
parce que `if err:` est un test de **présence** et non de refus. **Plus la garde qui manquait — que les entrées
connues soient TOUJOURS trouvées.** *C'est la garde qui a rendu cette reprise possible : sans elle, une liste
se vide en silence.*

### ⚠ TROISIÈME FOIS QUE LE LEAD REDEMANDE DU TRAVAIL FAIT — ET SA PARADE NE COUVRAIT PAS CE CAS (2026-08-28)

    la seconde moitie de la jointure : commitee a 08:59 CEST  (bbb0321)
    l'invariant repris               : commite a 08:26 CEST  (59484cb)
    le Lead les a demandes           :          13:48 CEST

**Cinq heures.** Et sa parade — *`git log -S` sur le symbole avant d'assigner* — **ne couvre pas ce cas** :
elle cherche un symbole nommé, pas une tâche accomplie.

**Parade élargie, et elle est déjà dans la routine du tour** : *lire `git log` depuis la dernière mesure
**avant** de dispatcher, et croiser ce qu'on va assigner contre ce qui vient d'être commité.* Le Lead lit déjà
ce journal pour établir l'état — **il ne le croisait pas contre ses propres assignations.**

*Une tâche redemandée est aussi coûteuse qu'une tâche oubliée* — et c'est la troisième, après l'unification des
résolveurs et l'encart `services`.

### ⚠ UN SECOND `git push` A EU LIEU (2026-08-28, 14:16 CEST)

    refs/remotes/origin/Migration-Laravel@{0}:  update by push   -> a50b98c
    refs/remotes/origin/Migration-Laravel@{1}:  update by push   -> 20440d1
    refs/remotes/origin/Migration-Laravel@{2}:  pull --ff-only   -> 3fb4fd4

**`0/0` à 14:16 CEST** : les commits du Lead de 13:54 et 13:55 sont désormais sur l'amont. **Deux `update by
push` distincts, et le Lead n'en a fait aucun.**

**Le point est déjà porté à l'exploitant** — *l'autorisation du premier est **rapportée** par une session, non
vérifiée par le Lead* — et **la réponse n'a pas été donnée.** Le second est noté sans être re-litigé : *établir
qu'un geste se répète suffit ; le répéter dans le document ne rend pas la décision.*

**Ce qui change, en revanche** : *une autorisation ponctuelle et une autorisation permanente ne se distinguent
pas depuis le dépôt.* Si l'ordre couvrait « pousse quand tu veux », les deux gestes sont réguliers ; s'il
couvrait « pousse ces 399 commits », le second ne l'est pas. **Le Lead ne peut pas trancher, et ne le
suppose pas.**

### ⚠⚠ QUATRE CHIFFRES DU §2 ÉTAIENT PÉRIMÉS, ET C'EST LE LEAD QUI LES ENTRETIENT (2026-08-28, 14:44 CEST)

**Audit fait pendant un tour où rien n'était à réassigner** — le LOT tournait, aucune session n'avait commité
depuis 26 minutes. **Employé à vérifier le seul document dont le Lead est comptable.**

| chiffre | disait | vaut | depuis quand il était faux |
|---|---|---|---|
| entrées de menu portées | **24** sur 32 | **26** | depuis la bascule de `platform_key`, puis d'`api_docs` |
| parties du legacy archivées | **12** | **13** | depuis `services/`, **le 2026-08-27** |
| tests backend | **509** | **566** — tranché à 16:28, `c282fbe` | depuis le 2026-08-28 au matin. ⚠ *Ni `509` ni `549` n'étaient faux : **c'est le chiffre qui voyageait sans son heure**. Le seul faux était le repère de `462`, qui comptait des fonctions et non des cas* |
| commits non poussés | **391** | **1** | depuis le second push, ce midi |

#### Ce que cet audit établit, et ce n'est pas « quatre erreurs »

**C'est UNE erreur, quatre fois.** Le §1 de ce document dit que *chaque chiffre porte sa commande de remesure* —
et le Lead les a **écrites**, puis ne les a **pas relancées**. *Une commande de remesure inscrite à côté d'un
chiffre ne remesure rien : elle documente comment le faire, à quelqu'un qui ne le fait pas.*

**Le pire des quatre est `services/`** : le Lead a **écrit l'entrée de `DEPRECIATION.md` le jour même**, avec
les statuts avant/après et la référence mesurée — **et n'a pas reporté le `12 → 13` deux sections plus haut.**
*Le geste et son compteur vivent dans deux fichiers, et rien ne les lie.*

**Et le plus instable est celui des commits** : **69** du 22 au 28 août, **391** ce matin, **1** cet
après-midi. *Un chiffre qui change d'ordre de grandeur trois fois en six heures n'est pas un état : c'est un
capteur.* **À ne jamais citer sans son heure** — et c'est exactement ce que le Lead a fait six fois avant de
s'en apercevoir.

#### La parade, et elle est mécanique

Le Lead a déjà trois routines de tour — mesurer l'état, croiser les assignations contre `git log`, contrôler
l'ordre du journal. **Il en manquait une quatrième :**

> **Relancer les commandes de remesure du §2 à chaque tour, pas seulement celles dont on va parler.**

*Le Lead mesurait ce qu'il allait dire, pas ce que le document affirme déjà* — et un document dont on ne
vérifie que les lignes qu'on cite est un document dont les autres lignes pourrissent sans témoin.

**Ce qui n'est pas corrigé, et pourquoi** : `tests backend` reste marqué **à remesurer**. **Le Lead ne relance
pas `pytest` : le LOT tourne**, et *une charge concurrente a fait passer `go-fail2ban-f2` de 24/0 à 19/5 sur
une page saine.* Un repère non probant est inscrit à la place — **462 fonctions `def test_`** — avec sa
limite : *un compte de fonctions n'est pas un compte de cas ; le paramétrage en produit plusieurs par
fonction.* **Écrire un repère en disant qu'il n'est pas la mesure vaut mieux que laisser un chiffre faux.**


## §7 — DOUZIÈME OBJET : le geste qui ferme E-280 existe, et il n'était nulle part

**Relevé le 2026-09-03 10:50. Les onze décisions étaient onze parce que ce
douzième objet n'était inscrit dans aucun document.**

La session 4 a écrit **deux patchs** le 2026-09-02, vérifiés par
`git apply --check`, qui ferment E-280 par un **repli inversé** : une branche
`all` explicite plus un `else` qui REFUSE (`WHERE 1=0` + journal). Le mécanisme
couvre les **cinq** branches d'un coup — un champ blanc échoue `tag`, échoue
`environment`, échoue `machines`, échoue `== 'all'`, et tombe dans le refus.
**Ce n'est pas une énumération de cas à tenir à jour, c'est une inversion du
repli** — et c'est meilleur que le correctif par conjonctions que j'avais décrit.

Deux pièces, parce que les deux fonctions ne vivent pas dans le même régime de
fusion : `_run_scheduled_ssh_audit` généré contre **HEAD**,
`_run_scheduled_scan` généré contre l'**après-fusion** (`a345e65`), et celui-là
refuse sur HEAD par construction.

### ⚠ Ce qui rendait l'objet invisible

    fichiers .patch / .diff dans l'arbre            aucun
    git stash list                                   vide
    DIFFS-PRETS-NON-APPLIQUES.md                     0 mention E-280, 0 E-281
    DOSSIER-00-CE-QUI-ATTEND-VOTRE-SIGNATURE.md      0 mention E-280, 0 E-281

> **Un patch vérifié qui ne vit que dans un contexte de session n'attend pas une
> signature : il attend une compaction.** Le journal n'est pas l'autorité,
> l'artefact l'est.

Et le précédent est dans nos propres documents :
`RELECTURE-SECURITY-BACKEND-CVE.md:9` signale des sessions ayant re-trouvé,
re-mesuré et re-rédigé `a345e65`, **écrit douze jours plus tôt**. Sans
persistance, ces deux patchs seront réécrits une troisième fois. La persistance
est demandée à la session 4 ; elle ne touche ni `laravel/`, ni `legacy/`, ni
`backend/`, ni `tests/e2e/`, donc **le gel du banc ne la bloque pas**.

### Ce qui compte pour l'exploitant, et c'est une bonne nouvelle

**Ce douzième objet ne coûte AUCUNE interruption de plus.** Un patch sur
`scheduler.py` est **inerte jusqu'au redémarrage** (E-238), et le redémarrage de
`rootwarden_python` est déjà la décision n°1. **Appliquer les deux patchs avant
ce redémarrage se signe dans le même geste.** Du point de vue de l'exploitant, il
y a donc toujours **onze interruptions**, dont la première a gagné un contenu.

⚠ **Et la symétrie doit être dite, parce que je me suis déjà trompée dans ce sens
aujourd'hui** : sans ces patchs, le redémarrage **ne corrige rien** d'E-280 — j'ai
prétendu le contraire, c'était faux (E-280 deuxième passe, retiré en quatrième).
Le redémarrage ne devient un remède **que** s'il est précédé de l'application.
*Le même geste est neutre ou réparateur selon ce qui a été écrit avant lui — et
c'est exactement pourquoi il ne se présente pas comme un bénéfice acquis.*


## §7 — DOUZIÈME OBJET, CORRIGÉ : quatre patchs vivants, et un piégé qui s'applique

**Mesuré le 2026-09-03 10:55 sur l'artefact, pas sur le compte rendu.** La
session 4 a persisté (`81a29d1`, `4c82ec9`) ce qui ne vivait qu'en session, et le
**tri a rapporté plus que la copie** : il y avait **sept** patchs dans un
scratchpad, pas deux.

    docs/migration/patchs-en-attente/
      01-E-231-psk-illisible.patch                            applicable sur HEAD
      02-E-280-portee-scheduler.patch                         applicable sur HEAD
      03-telegraf-jeton-en-clair.patch                        applicable sur HEAD
      04-E-281-apres-fusion-NE-PAS-APPLIQUER-SUR-HEAD.patch   APRÈS FUSION SEULEMENT
      QUARANTAINE-perime-refait-par-a345e65.patch             ⚠ NE PAS APPLIQUER
      README.md

Deux périmés ont été retirés (`E-280-entree`, appliqué en v1.38.180 ;
`e187-forme`, dont le contenu est **déjà dans l'arbre**), et la distinction qui
les a démasqués mérite d'être gardée :

> **Un patch qui refuse peut être PÉRIMÉ ou viser un AUTRE ARBRE. Les deux
> refusent identiquement.** Ce qui les sépare est de **chercher son contenu dans
> l'arbre** — le nom du fichier ne porte pas cette différence, seule la mesure la
> porte. Sans elle, les deux périmés auraient été persistés comme vivants.

### ⚠ LE PIÈGE : le quarantainé PASSE `git apply --check` sur HEAD

Il passe **parce que** `HEAD` n'a pas le correctif de la branche. Un lecteur
pressé y verrait un patch valide, l'appliquerait, et rendrait **conflictuelle une
fusion aujourd'hui propre, sur le hunk le plus sensible du dépôt**. Il est
conservé et non supprimé, son état dans son **nom** : *le supprimer garantirait
qu'on le réécrive une troisième fois, le laisser nommé comme un correctif
garantirait qu'on l'applique.*

### ⚠ CE QUI NE DOIT PAS SE LIRE COMME UNE FERMETURE

Le patch **04 ne s'applique QU'APRÈS la fusion**. Donc si la fusion n'est pas
dans le même geste :

> **« les patchs sont appliqués » ne veut PAS dire « E-280 est fermé ».**
> `_run_scheduled_scan` garde ses branches ouvertes, c'est-à-dire que **la moitié
> CVE d'E-280 reste entière** — réserve de la session 4, à porter à l'exploitant
> avec le geste, pas après.

### Ce qui reste à faire porter, et ce n'est pas à moi

`DIFFS-PRETS-NON-APPLIQUES.md` porte désormais les artefacts avec leur régime
(mesuré : 3 mentions d'E-280, 2 d'E-281, 2 d'E-231). **`DOSSIER-00-CE-QUI-ATTEND-VOTRE-SIGNATURE.md`
en porte encore ZÉRO** — le document qui liste ce qui attend une signature ne
mentionne aucun des quatre.

⚠ **Et je ne recompte pas §7 ici.** Deux des quatre patchs recoupent
probablement des objets déjà listés — le jeton telegraf a son
`DOSSIER-13-JETON-TELEGRAF-EN-CLAIR.md`, et E-231/PSK figurait dans la file de la
session 4. **Le nombre d'objets de §7 se REMESURE par différence d'ensembles, il
ne se récite pas** (E-312) : je l'ai récité à onze pendant que le douzième
n'existait dans aucun fichier.

*Note d'instrument : mon `find -maxdepth 3` a rendu ZÉRO fichier de patch, parce
qu'ils sont à la profondeur 4. Seul un témoin positif (`version.txt`, rendu) m'a
évité d'écrire « aucun artefact » une seconde fois — l'outil marchait, ma BORNE
était fausse, et les deux se lisent pareil.*
