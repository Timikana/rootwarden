# RootWarden — Roadmap

**Chantier en cours : la migration du frontend vers Laravel.** Branche de travail
`Migration-Laravel`, cible **v2.0 avec bascule DIRECTE** (pas de coexistence longue).

Dernière mesure : **2026-08-25**, version `1.37.55`. Les chiffres de ce document sont
**mesurés**, pas reconduits — voir « Comment vérifier » en fin de page.

> **Le plan de travail vit dans [`docs/migration/PLAN-DE-MIGRATION.md`](docs/migration/PLAN-DE-MIGRATION.md)** :
> l'ordre des modules, le découpage en sous-lots, les conventions et les pièges. Ce
> document-ci dit **où on en est** ; celui-là dit **comment on avance**.

---

## ⛔ URGENT — une vulnérabilité en PRODUCTION, hors périmètre migration

**Le second facteur est dérivable du premier.** `legacy/auth/enable_2fa.php` ne garde que
`isset($_SESSION['temp_user'])`, l'état posé **après le mot de passe et avant le second
facteur**. Conséquence, reproduite le 2026-08-23 (et déjà relevée le 2026-08-20) :

```
POST /auth/login.php  (mot de passe seul)  -> 302 vers verify_2fa.php   [2FA EN ATTENTE]
GET  /auth/enable_2fa.php                  -> 200, 17 547 octets
                                              contient le secret TOTP du compte EN CLAIR
                                              + son QR code
```

Le fichier est **identique octet pour octet** à `www/auth/enable_2fa.php` sur `origin/main`
(`sha256 be0bfda6…`) — donc **la production est concernée**. Quiconque détient un mot de
passe peut lire le secret TOTP du compte et générer ses codes indéfiniment.

Trois défauts secondaires du même fichier : **aucune limitation de débit** sur la
vérification (là où `verify_2fa.php` en a deux), **anti-rejeu inerte** (motif E-01), et une
**écriture en base sur un GET, sans jeton CSRF**.

**Non corrigé.** Un correctif touche le chemin d'authentification en production : il doit
partir sur une branche `security/…` et n'être fusionné que sur validation verbale explicite.
Détail complet : `docs/migration/MODULE-AUTH.md` §2.

---

## Où on en est, en un chiffre

| | |
|---|---|
| entrées de menu portées | **16 sur 33** |
| parties du legacy archivées | **10** (`commandlog` `approvals` `drift` `backups` `tasks` `tickets` `search` `update` `supervision` `docker`) |
| modules entièrement dépréciés | **2** (`update/`, `supervision/`) |
| LOT de tests E2E | **93 exécutions, 1301 assertions, 0 échec** |
| tests backend | **341 pytest** |
| écarts de parité documentés | **90** (`docs/migration/PARITE.md`, numérotés jusqu'à **E-100** — dix numéros, E-23 à E-32, n'ont jamais été utilisés) |
| commits non poussés | **72** (0 de retard sur `origin/Migration-Laravel`) |

**La migration n'est pas finie.** 14/33, c'est 42 % des entrées de menu. Le socle, lui,
est complet : authentification, navigation, passerelle vers le backend, i18n FR/EN.

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

Détail et découpage : `docs/migration/MODULE-AUTH.md`.

---

## Ce qui reste à porter

**19 entrées de menu**, par taille de code legacy :

| partie | lignes | entrées de menu |
|---|---|---|
| `adm/` | 8421 (37 fichiers) | **6** — comptes, journal d'audit, comptes distants, clés de plateforme, politiques sudo, politiques sftp |
| `ssh-audit/` | 1118 | 1 |
| `bashrc/` | 941 | 1 |
| `fail2ban/` | 872 | 1 |
| `iptables/` | 870 | 1 |
| `services/` | 631 | 1 |
| `wazuh/` | 594 | 1 |
| `graylog/` | 388 | 1 |
| `groups/` | 305 | 1 |
| `maintenance/` | 257 | 1 |
| `chatops/` | 246 | 1 |
| `docker/` | 201 | 1 |
| `documentation.php`, `api/docs.php` | — | 2 |

**Plus `auth/`** : 16 fichiers, 3003 lignes, **aucune entrée de menu** — ce n'est pas un
module métier mais ce qui empêche d'éteindre le legacy.

**Plus deux sous-lots bloqués** par un arbitrage, dans des modules par ailleurs portés :

- **S7b** (`security/`) — le scan CVE qui aboutit **envoie un vrai courriel**
  (`send_cve_report` part dès que l'état passe à `done` avec des résultats). Prérequis
  techniques faits, en attente d'autorisation ;
- **K4** (`ssh/`) — le déploiement de clés. Bloqué par l'arbitrage du repli
  `NOPASSWD: ALL`, et un déploiement lancé en l'état **révoquerait** des accès.

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
- **`main` tourne en production à `v1.37.15`** et il lui manque `v1.37.16` et `v1.37.17`,
  **deux correctifs de sécurité** qui n'existent que sur la branche de migration. Le
  rétroportage attend une décision ;
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

Aucun nombre de ce document ne doit être recopié sans être remesuré — c'est ce qui a
produit trois erreurs de suivi (69 commits au lieu de 70, deux points d'entrée au lieu de
quatre, une liste de modules qui en oubliait cinq).

```bash
# entrees de menu portees / restantes
grep -c "'route'"  laravel/app/Support/Navigation.php   # portees (moins 2 lignes de commentaire)
grep -c "'legacy'" laravel/app/Support/Navigation.php   # restantes (moins 2)

# parties archivees
ls legacy/_deprecated/

# le LOT (~95 min), lance en arriere-plan puis attendu dans un appel SEPARE
setsid ./scripts/rejouer-lot.sh > /tmp/lot.out 2>&1 < /dev/null &
until ! pgrep -f "[r]ejouer-lot"; do sleep 20; done; tail -3 /tmp/lot.out

# tests backend (pytest vit DANS le conteneur, il n'y a pas de venv sur l'hote)
sudo -n docker exec rootwarden_python sh -c "cd /app && python -m pytest -q"

# ecarts de parite
grep -c "^## E-" docs/migration/PARITE.md

# avance reelle sur l'amont
git fetch origin && git rev-list --left-right --count @{u}...HEAD
```

---

## Documents du chantier

| document | ce qu'il contient |
|---|---|
| `docs/migration/METHODE-SOUS-LOT.md` | les neuf temps d'un sous-lot — à suivre, pas à improviser |
| `docs/migration/PARITE.md` | les 90 écarts mesurés entre legacy et portage, avec leur preuve |
| `docs/migration/INVENTAIRE.md` | ce qui reste, mesuré |
| `docs/migration/DEPRECIATION.md` | le cycle d'archivage et les dix parties déjà archivées |
| `docs/migration/ARCHITECTURE-UI.md` | pourquoi ni Filament ni Tailwind, décidé sur mesure |
| `docs/migration/MODULE-*.md` | l'inventaire par module (`AUTH`, `SECURITY`, `SSH`, `SUPERVISION`, `UPDATE`, `FILTRAGE`) |
| `CHANGELOG.md` | l'historique versionné, seul document resté à jour de bout en bout |
