# RootWarden — Roadmap

**Chantier en cours : la migration du frontend vers Laravel.** Branche de travail
`Migration-Laravel`, cible **v2.0 avec bascule DIRECTE** (pas de coexistence longue).

Dernière mesure : **2026-08-25**, version `1.37.55`. Les chiffres de ce document sont
**mesurés**, pas reconduits — voir « Comment vérifier » en fin de page.

> **Le plan de travail vit dans [`docs/migration/PLAN-DE-MIGRATION.md`](docs/migration/PLAN-DE-MIGRATION.md)** :
> l'ordre des modules, le découpage en sous-lots, les conventions et les pièges. Ce
> document-ci dit **où on en est** ; celui-là dit **comment on avance**.

---

## ⛔ URGENT — LA PRODUCTION EXPOSE LES SECRETS TOTP, ET LE CORRECTIF EST SUR CETTE BRANCHE DEPUIS LE 2026-08-23

> **⚠ CETTE SECTION DISAIT « NON CORRIGÉ » PENDANT CINQ JOURS. C'ÉTAIT FAUX, ET C'EST CE QUI A RENDU LE
> CORRECTIF INVISIBLE.** Réécrite le **2026-08-28 à 15:20 CEST**, chaque affirmation vérifiée par lecture.

### Le défaut, tel qu'il est ENCORE en production

    origin/main : www/auth/enable_2fa.php:33
    if (!isset($_SESSION['temp_user'])) { header("Location: login.php"); exit(); }

`temp_user` est l'état posé par `login.php` **après le mot de passe et avant le second facteur**. La page
n'exige rien de plus. **Quiconque détient un mot de passe appelle cette page, reçoit le secret TOTP du compte
en clair plus son QR code, et génère ses codes indéfiniment.**

*`login.php` renvoie certes vers `verify_2fa.php` quand un secret existe — mais c'est une **redirection**, pas
une garde : rien n'empêche d'appeler cette page directement, et `verify.php` l'autorise explicitement pendant
que la 2FA est en attente.*

Mesuré le **2026-08-20**, reproduit le **2026-08-23**.

### ✅ CE QUI EST CORRIGÉ SUR CETTE BRANCHE — les QUATRE défauts, vérifiés ligne par ligne le 2026-08-28

    23a6063   2026-08-23 19:06   fix(security): le second facteur n'est plus derivable du premier - v1.37.48

| défaut | correctif, sur cette branche | vérifié |
|---|---|---|
| **le secret divulgué au mot de passe seul** | `if (!empty($existingSecret)) { header("Location: verify_2fa.php"); exit(); }` — *un compte qui possède déjà un secret n'a rien à faire ici ; le renvoyer ferme la divulgation sans retirer aucune capacité* | `enable_2fa.php:65-67` |
| **aucune limitation de débit** | **5 tentatives / session / 60 s ET 10 / IP / 10 min** — la même que les deux autres portes 2FA | `:113-134`, table `login_attempts` |
| **anti-rejeu inerte** (motif E-01) | `$dejaVu = isset($_SESSION['last_totp_hash']) && … === $codeHash`, posé **avant** la vérification | `:149-150` |
| **écriture en base sur un GET sans CSRF** | l'écriture est **dans** la branche `REQUEST_METHOD === 'POST'`, et **`checkCsrfToken()` est APPELÉE**, pas seulement le jeton émis | `:104-105`, écriture `:170` |

**Le quatrième a été vérifié contre le piège du chantier** — *un jeton CSRF émis dans le formulaire n'est pas
un jeton validé* : `:239` l'émet, **`:105` le valide.** Les deux sont nécessaires ; seule la seconde protège.

### ⛔ CE QUI RESTE : LA PRODUCTION

    git merge-base --is-ancestor 23a6063 origin/main   ->  NON
    origin/main                                        ->  v1.37.15
    versions manquantes sur main                       ->  79, dont v1.37.48

> **La production est vulnérable depuis cinq jours, avec son correctif à une branche de distance.**

**Le Lead ne fusionne pas et ne pousse pas** — c'est réservé à l'exploitant, et cette frontière ne cède pas
même pour ceci. **Deux formes possibles, au choix de l'exploitant** : une branche `security/2fa-enrolment` ne
portant **que** `23a6063`, prête à fusionner ; ou le cherry-pick direct sur `main`.

### ⚠ ET LA LEÇON EST D'UNE FORME NEUVE

Ce chantier a numéroté **six** occurrences de *un texte qui affirme PLUS que le code ne fait* — en-têtes
d'accès, libellés de bouton, guides de procédure, descriptions de permission, une docstring de « kill-switch ».
**Celle-ci affirme MOINS.**

> **Un texte qui dit « non corrigé » d'une chose corrigée ne rend pas le défaut visible : il rend le CORRECTIF
> invisible.** Personne ne cherche un correctif qu'un document déclare absent — et le Lead a récité « il manque
> `v1.37.48` » dans son propre §2 pendant deux jours **sans jamais regarder ce que `v1.37.48` était.**

*Un numéro de version cité sans son contenu est une étiquette, pas une information.*

---

## Où on en est, en un chiffre — REMESURÉ le 2026-08-28 à 15:12 CEST

> **⚠ Les six chiffres de ce tableau étaient périmés de cinq jours.** Ils disaient 18/33, 12 archivées,
> 97 écarts, 341 pytest, 93 exécutions au LOT. *Ce fichier porte sa propre section « Comment vérifier ces
> chiffres » — et personne ne l'avait relancée.* **Une commande de remesure écrite à côté d'un chiffre ne
> remesure rien.**

| | |
|---|---|
| entrées de menu portées | **26 sur 32** — restantes : `remote_users` `iptables` `ssh_audit` `wazuh` `groups` `documentation` |
| parties du legacy archivées | **13** — `approvals` `backups` `chatops` `commandlog` `docker` `drift` `maintenance` `search` `services` `supervision` `tasks` `tickets` `update` |
| modules entièrement dépréciés | **2** — `update/`, `supervision/` |
| LOT de tests E2E | ligne de base du **2026-08-27** : **150 exécutions, 2282 PASS, 3 FAIL** — *aucun des trois n'était une régression*. **Un LOT complet TOURNE au moment de cette mesure** ; il est le préalable au redémarrage backend |
| tests backend | **à remesurer après le LOT** — **509** date du 2026-08-27, la QA en publie **549** le 2026-08-28. *Ne pas relancer `pytest` pendant un rejeu : une charge concurrente a fait passer une suite de 24/0 à 19/5 sur une page saine* |
| écarts de parité documentés | **220** — numérotés jusqu'à **E-233** ; dix numéros, E-23 à E-32, n'ont jamais servi. *Le dernier numéro n'est donc pas un compte* |
| commits non poussés | **4** — `0` de retard. ⚠ *Ce chiffre a dit **69** du 22 au 28 août, **391** le matin du 28, **1** puis **4** l'après-midi : **deux `git push` ont eu lieu**, aucun du Lead.* **C'est un capteur, pas un état** |

**La migration n'est pas finie — mais elle est à 26/32, soit 81 % des entrées de menu.** Le socle est complet :
authentification, navigation, passerelle, i18n FR/EN. **Et l'exploitant a demandé la dépréciation COMPLÈTE du
legacy** : tableau de bord, fonctions, API, documentation.

---

## Ce qui bloque la v2.0

Deux capacités seulement, mais elles suffisent à interdire la bascule. Mesuré le
2026-08-23 : **6 comptes actifs sur 10** sont concernés par chacune.

| blocage | état du portage | conséquence après bascule directe |
|---|---|---|
| **enrôlement 2FA** | impasse explicite, dont le seul lien sort vers `enable_2fa.php` du legacy | aucun compte neuf ne peut obtenir un second facteur |
| **changement de mot de passe requis** | `force_password_change` est **détecté** et annoncé par un bandeau, aucun formulaire n'est offert | les comptes marqués ne peuvent jamais satisfaire l'exigence — **`superadmin` en fait partie** |

Aucun chemin d'authentification ne passe sans second facteur : c'est voulu, et c'est
précisément ce qui rend l'enrôlement bloquant.

### Et le blocage v2.0 et la vulnérabilité de production sont LE MÊME FICHIER

`legacy/auth/enable_2fa.php` est à la fois **la seule page d'enrôlement qui existe** — donc ce
qui interdit d'éteindre le legacy — et **la page qui divulgue les secrets TOTP en
production**. Les deux problèmes ont un seul objet, et trois conséquences qui ne se déduisent
pas l'une de l'autre :

1. **on ne peut pas éteindre le legacy** sans porter l'enrôlement, quel que soit l'état du
   correctif ;
2. **le correctif ne dispense pas du portage** : il ferme la divulgation, il ne déplace pas la
   capacité ;
3. **le portage ne dispense pas du rétroportage** : la production tourne sur `main`, que la
   branche de migration n'atteint pas.

*Corriger, porter, rétroporter sont trois gestes distincts sur un seul fichier. Aucun ne rend
les deux autres inutiles* — et les traiter comme un seul est exactement ce qui a laissé le
correctif cinq jours sans être remarqué.

Détail et découpage : `docs/migration/MODULE-AUTH.md`.

---

## Ce qui reste à porter — RECENSÉ le 2026-08-28

> **⚠ Cette section annonçait « 15 entrées de menu » et listait `services/` `chatops/`
> `docker/` `maintenance/` `graylog/` `fail2ban/` `bashrc/` — tous portés, la plupart
> ARCHIVÉS.** Elle contredisait le tableau d'état du même fichier. Recensée à la source :

    grep -c "'legacy' =>" laravel/app/Support/Navigation.php   ->  6
    grep -c "'cle' =>"    laravel/app/Support/Navigation.php   ->  32

*Le recensement se fait sur `'legacy' =>` — la clé qui marque une entrée pointant **encore**
vers le portail legacy. Ni un décompte de fichiers ni une liste tenue à la main.*

### Les 6 entrées restantes

| entrée | cible legacy | PHP | PHP **+ JS** | sous-lots |
|---|---|---|---|---|
| `remote_users` | `/adm/server_users.php` | 387 | 387 | — |
| `iptables` | `/iptables/` | 369 | **870** | I3–I5, **I5 bloqué** (arbitrage du port SSH) |
| `ssh_audit` | `/ssh-audit/` | 336 | **1118** | A1–A3, **A4 non exécutable** |
| `wazuh` | `/wazuh/` | 291 | **594** | — |
| `groups` | `/groups/index.php` | 134 | **305** | action de masse jamais déclenchée |
| `documentation` | `/documentation.php` | 1756 | 1756 | — |

**Les deux colonnes de volume sont l'une et l'autre exactes, et ne répondent pas à la même
question** : *PHP seul* mesure la logique serveur ; *PHP + JS* mesure **ce qu'il y a à
réimplémenter**, parce que le portage réécrit son propre JS (`laravel/public/js/*.js`) et
n'en reprend aucune ligne. **C'est la seconde qui dimensionne le travail.** L'ancien chiffre
« 870 » n'était pas faux — il répondait à cette question-là, sans le dire.

### Plus `auth/` : 15 fichiers, 3118 lignes, AUCUNE entrée de menu

Ce n'est pas un module métier : **c'est ce qui empêche d'éteindre le legacy.** L'enrôlement
2FA n'existe que là. Deux de ses fichiers sont du **code mort** (`confirm_2fa.php`,
`reset_totp.php`) — établi par `MODULE-AUTH.md`, contre un relevé refait de zéro qui les
comptait vivants.

### Plus deux sous-lots bloqués par un arbitrage, dans des modules par ailleurs portés

- **S7b** (`security/`) — le scan CVE qui aboutit **envoie un vrai courriel**
  (`send_cve_report` part dès que l'état passe à `done` avec des résultats). Prérequis
  techniques faits, en attente d'autorisation ;
- **K4** (`ssh/`) — le déploiement de clés. Bloqué par l'arbitrage du repli `NOPASSWD: ALL`,
  et un déploiement lancé en l'état **révoquerait** des accès : il ne « ferait pas rien ».

### Et « porté » ne veut pas dire « fini » — §4.6 du plan

L'exploitant a demandé que **chaque onglet** soit complet, pas seulement atteignable. Deux
onglets portés restent incomplets pour cause d'arbitrage (`cve` par S7b, `bashrc` par B4), et
**5545 lignes de legacy sont portées mais non archivées** — le legacy les sert encore.

---

## Décisions qui attendent l'exploitant

Elles sont toutes documentées avec leur mesure dans `docs/migration/PARITE.md`.

**Effets sortants, à autoriser avant tout test :**
- **A3** — la réinitialisation de mot de passe envoie un courriel (le legacy embarque
  `phpmailer`). Même famille que S7b ;
- **S7b** — un scan CVE réel.

**Correctifs backend mesurés, non appliqués faute d'autorisation :**
- **E-90** — le déploiement d'agent de supervision n'inspecte **aucun** code de retour et
  inscrit dans l'inventaire un agent qui n'existe pas. Relevé : trois étapes en échec
  (codes 127, 100, 127) puis `SUCCESS_MACHINE:: Deploiement reussi`. La ligne fausse est
  **transitoire** — la détection qui suit l'efface — donc elle ne se voit qu'en isolant le
  geste ;
- `generic_reconfigure` annonce un succès sans avoir rien écrit quand la configuration
  globale manque, et son marqueur ment après un `code 127` ;
- la clé PSK dont l'échec de déchiffrement n'est que journalisé ;
- **E-73** — le fuseau du backend : UTC contre CEST, l'**affichage** est faux de deux heures.

**Gardes et surfaces :**
- quatre routes de profils de supervision sans `@require_role` ;
- `POST /supervision/overrides/<id>` sans `@require_machine_access` ;
- la liste blanche `/supervision/` de `legacy/api_proxy.php:134` — **surface morte** depuis
  l'archivage, et `/supervision/` est absent de `$ADMIN_ONLY_PREFIXES` côté legacy ;
- huit branches mortes qui armeraient un `@threaded_route` **imbriqué** : supprimer la règle
  statique en la prenant pour un doublon **bloquerait** le pool ;
- 21 routes de filtrage sans permission ; la garde de la page `ssh/` ; `can_deploy_keys`
  côté requête ; la fuite du mot de passe dans `deployment.log` ; OpenCVE TLS désactivée.

**Comptes et exploitation :**
- **cinq comptes `e2e_test_*` actifs, rôle 1, sans second facteur** — résidus d'exécutions
  E2E, à supprimer ou non ;
- **`main` tourne en production à `v1.37.15`** et il lui manque **79 versions**, dont
  **`v1.37.48` — le correctif de la divulgation des secrets TOTP** (voir la première section :
  la production est vulnérable, le correctif est ici). `v1.37.16` et `v1.37.17` en font
  partie. **Le rétroportage attend le mot de l'exploitant** : le Lead ne pousse ni ne
  fusionne, même pour ceci ;
- la branche `security/backend-cve` (6 correctifs backend, 318 pytest verts) attend une
  **relecture** et n'a jamais été fusionnée ;
- rotation automatique des secrets — seule feature de l'ancienne roadmap produit non
  démarrée.

**Ergonomie du legacy, avis donné : ne pas y toucher** (on ne soigne pas ce qu'on démonte) :
- le legacy ne marque pas ses **11 liens sortants** vers le portage — ni marqueur, ni
  `target` — alors que le portage marque l'inverse ;
- le 404 d'un chemin archivé est la page brute d'Apache, sans repère ni retour.

---

## Dette documentaire — constatée le 2026-08-23

Reproche de l'exploitant, et il était fondé. Seul `CHANGELOG.md` suivait le rythme des
commits ; tout le reste avait décroché, **y compris les documents qui disent ce qui reste**.
Trois documents ne mentionnaient **pas une seule fois** Laravel ni le port 8444.

| document | version annoncée avant correction | état |
|---|---|---|
| `CHANGELOG.md` | 1.37.47 | à jour |
| `ROADMAP.md` | 1.35.0 | **réécrit** (ce document) |
| `README.md` / `README.en.md` | 1.37.7 / 1.37.1 | corrigés |
| `ARCHITECTURE.md` | 1.37.5 | corrigé |
| `ONBOARDING.md` | 1.37.15 | corrigé |
| `docs/migration/INVENTAIRE.md` | 1.36.0 | corrigé |
| `docs/migration/MODULE-AUTH.md` | — | corrigé |
| `docs/migration/MODULE-SUPERVISION.md` | 1.37.44 | complété (V12 + archivage) |
| `OPERATIONS.md` | aucune | corrigé (section 0 : deux frontends à exploiter) |
| `CONTRIBUTING-SECURITY.md` | 1.37.1 | corrigé (conventions du portage) |
| `docs/API.md` | 1.2.3 | **encore en retard** — décrit le backend, inchangé par la migration, mais ne dit pas qu'il a désormais deux appelants |
| `docs/SECURITY_AUDIT.md` | 1.37.1 | **volontairement figé** : c'est le compte rendu daté d'un audit, pas un document vivant |
| `ONBOARDING.md` | 1.37.15 | corrigé, mais **`.gitignore:123` l'exclut** — il se partage par lien, pas par commit |

**Ce que cette dette a coûté**, et c'est la raison de l'inscrire ici plutôt que de la
corriger en silence : `docs/migration/MODULE-AUTH.md` existait depuis le 2026-08-20 avec un
inventaire meilleur qu'un relevé refait de zéro le 2026-08-23 — et il **corrigeait** ce
relevé sur deux points (`confirm_2fa.php` et `reset_totp.php` sont du **code mort**). Ne pas
lire les documents du chantier a directement produit un plan faux. De même,
`INVENTAIRE.md` gelé à v1.36.0 est la raison pour laquelle une liste de modules restants en
oubliait cinq.

---

## Ce qui est exclu (décision)

- ❌ SSO / OIDC / LDAP
- ❌ HA / multi-nœud
- ❌ toute migration de schéma côté Laravel : la base appartient au backend Python et
  évolue par `mysql/migrations/*.sql`
- ❌ étape de construction côté portage : CSS écrit à la main, jetons et classes `.rw-*`

---

## Dette technique connue, documentée, non bloquante

- **CSP** conserve `'unsafe-inline'` (migration vers un nonce à faire avec test navigateur) ;
- **clé d'hôte SSH** : `AutoAddPolicy`, pas de TOFU/`known_hosts` — décision de conception ;
- **CI** : actions GitHub à épingler par SHA, images de base par digest ;
- routes mutantes par machine (`fail2ban`, `services`, `iptables`) gardées par
  `require_machine_access` seul — à durcir en `require_role(2)` si le rôle 1 doit être
  lecteur seul (décision de gouvernance) ;
- centre de tâches : **reprise** et instrumentation des déploiements interactifs à venir ;
- GeoIP (`fail2ban_manager`) en HTTP (ip-api gratuit est en HTTP seul) ;
- **3 suites E2E laissent fuir le mot de passe de la base** dans leur sortie ;
- `/tasks/list?status=` rend un 500 ; injection de formule CSV ; `go-page-backups` ne
  nettoie pas ce qu'il crée ; `npm audit` non traité.

---

## Comment vérifier ces chiffres

Aucun nombre de ce document ne doit être recopié sans être remesuré. **Et ce n'est pas
suffisant : les six chiffres du tableau d'état ont vécu cinq jours périmés, et une section
entière annonçait 15 entrées restantes contre 6, dans le fichier qui porte ces commandes.**

> **Une commande de remesure écrite à côté d'un chiffre ne remesure rien.** Elle doit être
> LANCÉE, et toutes — pas seulement celles dont on va parler.

**⚠ Les deux commandes de recensement inscrites ici étaient à réparer** — elles portaient un
facteur d'ajustement à la main :

    grep -c "'route'"  Navigation.php   # « moins 2 lignes de commentaire »  -> 28
    grep -c "'legacy'" Navigation.php   # « moins 2 »                        -> 8

Le `-2` compte les commentaires qui mentionnent le mot : il tombait juste le 2026-08-28, et
**devient faux au premier commentaire ajouté**. *Un facteur d'ajustement à la main, c'est un
chiffre périmé caché à l'intérieur d'une commande.* Et `grep -c "'route' =>"` rend **0** —
le fichier aligne ses `=>` sur deux espaces, ce qui défait tout motif à espace unique. *C'est
la même cause qui a fait rendre « aucun lien entrant » pour quatre modules qui en avaient.*

```bash
# entrees de menu : ancrer sur la ligne d'entree, aucun facteur d'ajustement, ' *=>' tolere l'alignement
n=laravel/app/Support/Navigation.php
grep -cE "^\s*\['cle' *=>" $n                              # 32 entrees au total
grep -E "^\s*\['cle' *=>" $n | grep -cE "'legacy' *=>"     # 6 restantes
grep -E "^\s*\['cle' *=>" $n | grep -cE "'route' *=>"      # 26 portees

# parties archivees
ls legacy/_deprecated/

# le LOT (~95 min), lance en arriere-plan puis attendu dans un appel SEPARE
setsid ./scripts/rejouer-lot.sh > /tmp/lot.out 2>&1 < /dev/null &
echo $! > /tmp/lot.pid                       # le PID : aucun motif a matcher
until ! kill -0 "$(cat /tmp/lot.pid)" 2>/dev/null; do sleep 20; done
tail -3 /tmp/lot.out                         # conclure sur le JOURNAL, jamais sur le code de sortie

# a defaut de PID (lot lance par une autre session) : exclure SON PROPRE pid
until ! pgrep -f "[r]ejouer-lot" | grep -vqx "$$"; do sleep 20; done

# tests backend (pytest vit DANS le conteneur, il n'y a pas de venv sur l'hote)
sudo -n docker exec rootwarden_python sh -c "cd /app && python -m pytest -q"

# ecarts de parite
grep -c "^## E-" docs/migration/PARITE.md

# avance reelle sur l'amont
git fetch origin && git rev-list --left-right --count @{u}...HEAD
```

**⚠ La boucle d'attente inscrite ici était auto-bloquante, et la classe de caractères ne
suffisait pas.** Mesuré le 2026-08-28 : `pgrep -f "[r]ejouer-lot"` a rendu **trois** PID, dont
`834207` — **le shell qui posait la question.**

> `[r]ejouer-lot` empêche le motif de matcher **son propre texte**. Il n'empêche rien du
> reste : **toute autre mention du nom littéral sur la même ligne de commande réarme
> l'auto-capture** — un `tail /tmp/rejouer-lot.out`, un `grep rejouer-lot`, un commentaire.
> *La classe de caractères est nécessaire, pas suffisante.*

Et le coût est asymétrique : un faux « ça tourne encore » ne rend pas une erreur, il rend une
**attente infinie**. **Attendre un PID enregistré ne matche aucun texte et ne peut pas se
capturer lui-même.**

---

## Documents du chantier

| document | ce qu'il contient |
|---|---|
| `docs/migration/METHODE-SOUS-LOT.md` | les neuf temps d'un sous-lot — à suivre, pas à improviser |
| `docs/migration/PARITE.md` | les **220** écarts mesurés entre legacy et portage, avec leur preuve — numérotés jusqu'à E-233, *dix numéros n'ont jamais servi* |
| `docs/migration/INVENTAIRE.md` | ce qui reste, mesuré |
| `docs/migration/DEPRECIATION.md` | le cycle d'archivage et les **13** parties déjà archivées |
| `docs/migration/ARCHITECTURE-UI.md` | pourquoi ni Filament ni Tailwind, décidé sur mesure |
| `docs/migration/MODULE-*.md` | l'inventaire par module (`AUTH`, `SECURITY`, `SSH`, `SUPERVISION`, `UPDATE`, `FILTRAGE`) |
| `CHANGELOG.md` | l'historique versionné, seul document resté à jour de bout en bout |
