# QA — matrice de non-régression

Document de la **session 6, QA / non-régression**. Il porte deux choses, et deux
seulement : **ce qui est mesuré**, et **ce qui ne l'est pas**.

Il ne remplace pas `PARITE.md` — celui-ci tient les écarts, et il appartient au Lead.
Ici on tient les **instruments** : quelle suite mesure quelle propriété, sur quelle
cible, et **par quelle mutation on a prouvé qu'elle pouvait échouer**.

Dernière mesure : **2026-08-27**, version `1.38.9`.

---

## 0. La règle qui organise ce document

> **Un test qui ne peut pas échouer ne prouve rien.**

Chaque suite inscrite ici porte donc une ligne **« preuve d'échec »** : la mutation
appliquée au code, et les tests qui sont passés au rouge. Sans cette ligne, une
suite est *écrite* mais pas *éprouvée*, et il faut le dire.

Corollaire déjà payé onze fois sur `fail2ban/` : **un PASS peut passer PARCE QUE la
fonctionnalité est absente.** Une assertion dont la propriété peut se vérifier sur
l'absence de son objet ne mesure rien.

---

## 1. Les trois étages de mesure, et ce que chacun ne peut pas voir

| étage | ce qu'il mesure | ce qu'il ne peut PAS voir | propriétaire |
|---|---|---|---|
| **`backend/tests/`** (pytest) | la logique d'une route Python, SSH et base remplacés | tout ce qui dépend d'une vraie machine ou d'un vrai schéma | session 6 |
| **`laravel/tests/`** (PHPUnit) | les **gardes** et la logique pure du portage | qu'une page **autorisée** rende son contenu ; le jeton CSRF ; le rendu | session 6 |
| **`tests/e2e/`** (Puppeteer) | le comportement au navigateur, sur les deux portails | ce qui n'a pas d'interface ; ce qui coûte trop cher à atteindre | session 7 |

**Aucun des trois ne remplace les deux autres, et il faut savoir lequel manque.**
Exemple mesuré : les tests PHPUnit ne peuvent pas mesurer le CSRF — le cadre
**exempte** les tests (`PreventRequestForgery::runningUnitTests`, ligne 99 de
`vendor/laravel/framework/.../PreventRequestForgery.php`). Une assertion CSRF écrite
en Feature passerait **sans rien mesurer** ; c'est `go-socle-passerelle.mjs` qui la
porte.

---

## 2. QA-001 — les deux correctifs de `fail2ban/` sont verrouillés

`backend/tests/test_fail2ban.py` · **27 PASS, 2 XFAIL, 0 FAIL**
Commande : `sudo -n docker exec rootwarden_python sh -c "cd /app && python -m pytest tests/test_fail2ban.py -q"`

### E-165 — une réussite se VÉRIFIE

Quatre routes recevaient le code de retour de la commande distante et ne le
testaient pas. Deux propriétés distinctes sont verrouillées, et **c'est la seconde
qui compte** :

| propriété | comment elle est mesurée |
|---|---|
| la réponse dit l'échec (`success: False`, `exit_code`) | lecture du corps **analysé**, jamais du texte brut |
| **aucune ligne d'audit n'est écrite** | `_log_ban_action` est **INTERCEPTÉE** par un enregistreur |

L'interception est le point. Un journal d'audit **ne se relit pas**, on lui fait
confiance : mesurer l'état final ne distingue pas « rien n'a été écrit » de « la
ligne était déjà là ». L'interception permet d'affirmer **qu'il n'a pas été écrit**.

Les quatre routes sont couvertes, y compris `ban_all_servers` — la plus large, celle
où `rc` n'était même pas *nommé*, et dont le résumé « banni sur 3/3 serveurs » se
calculait sur des gestes dont aucun n'était vérifié. Le test à deux machines mesure
que le verdict global tombe **et** que l'audit ne porte que la machine qui a abouti :
c'est leur divergence qui rendait le défaut invisible.

### E-164 — une faute de la REQUÊTE se refuse, elle ne casse pas

Trois propriétés, et la troisième est celle qu'on oublie :

1. le statut est **400** ;
2. le corps est du **JSON** (la page 500 d'origine était du HTML : l'appelant
   échouait aussi à la lire) ;
3. **le refus arrive AVANT toute session SSH** — une requête mal formée ne doit
   joindre aucune machine. Mesuré par un compteur d'ouvertures sur la session SSH
   factice, pas déduit.

Les bornes de `days` (1 à 90) sont mesurées sur **le paramètre réellement passé à la
requête SQL**, pas sur le statut : un 200 ne dit rien de la valeur employée.

### Preuve d'échec — la mutation et ses rouges

Le correctif a été **retiré du code**, la suite relancée, puis le fichier restauré
(empreinte SHA-256 vérifiée identique, `git diff` vide).

| mutation appliquée | occurrences | effet |
|---|---|---|
| `if rc != 0:` → `if False:` | **4** | E-165 annulé |
| `except (TypeError, ValueError):` → `except ZeroDivisionError:` | **2** | E-164 annulé |

**Résultat sur le code muté : 16 FAILED, 11 passed, 2 xfailed.**
Résultat après restauration : **27 passed, 2 xfailed** — identique au témoin.

Les 11 qui restent vertes sont les cas **normaux** (rc = 0, valeur numérique valide)
et les caractérisations : c'est attendu, et c'est ce qui prouve que la suite mesure
bien deux moitiés — *un correctif évident peut casser le cas normal*.

---

## 3. QA-002 — les gardes du portage, côté PHP

`laravel/tests/` · **230 PASS, 757 assertions, 0 FAIL**
Commande : `sudo -n docker exec rootwarden_laravel php artisan test`

Avant ce lot : **3 fichiers**, tous des gabarits Laravel d'origine, et le seul test
Feature était **ROUGE** (`ExampleTest` attendait 200 sur `/`, qui redirige vers
`/accueil`). Les deux gabarits ont été remplacés, pas rafistolés.

### Les trois fichiers, et pourquoi il en faut trois

| fichier | propriété | ce qu'il ne dit pas seul |
|---|---|---|
| `Feature/InventaireDesGardesTest` | ce que chaque route **DÉCLARE** | déclarerait juste sur un middleware cassé |
| `Feature/CombinaisonsDeGardesTest` | ce que chaque **combinaison** de gardes FAIT | mesure des routes temporaires, pas le portail |
| `Feature/GardesDeRoutesTest` | que les **vraies routes** refusent vraiment | ne peut pas atteindre le cas autorisé |

Aucun des trois, seul, ne dit « telle route refuse tel compte ». Les trois ensemble
le disent.

### L'attente est ÉCRITE, pas dérivée

`tests/Support/TableDesGardes.php` fige les **84 routes authentifiées** avec leurs
gardes, et les **25 routes publiques** avec la **raison** de chacune.

Il aurait été plus court de lire les gardes dans le routeur et de les comparer à
elles-mêmes : ce serait un test **qui ne peut pas échouer**, puisque retirer `role:2`
changerait aussi l'attente. Une attente n'a de valeur que si elle vient d'ailleurs
que de la chose mesurée.

Deux assertions d'ensemble ferment les angles morts du relevé :

- **toute route du portail est dans l'une des deux listes** — une route neuve hors du
  groupe authentifié ne peut plus passer inaperçue. C'est la classe de défaut la plus
  coûteuse du chantier, relevée **trois fois dans trois modules** : « la garde est sur
  la PAGE, pas sur la REQUÊTE » ;
- **le total se reconstitue** : `authentifiées + publiques == routes déclarées`. *Un
  total qu'on ne sait pas reconstituer n'est pas un total.*

### Un 403 ne dit pas QUI a refusé

Les tests ne lisent pas le statut seul : ils lisent **l'exception portée par la
réponse**, dont le message nomme le garde (`acces.role_insuffisant` contre
`acces.permission_manquante`). Et pour la permission, le double de `Droits`
**enregistre ses consultations** : on affirme que le garde a bel et bien été
**interrogé**, pas seulement qu'un refus a eu lieu.

Sans cela, une route dont le garde `perm:` disparaîtrait pourrait rendre 403 pour une
autre raison et l'assertion resterait verte.

Symétriquement, le test du visiteur asserte que les droits **n'ont PAS** été
interrogés : un garde qui lirait les droits d'un visiteur travaillerait sur un
identifiant nul — *la valeur qui a déjà ouvert les lignes de diffusion à un rôle 1*.

### Preuve d'échec

Trois mutations, appliquées à **mes propres fichiers** (aucune écriture dans
`laravel/routes/` ni `laravel/app/`, dont la session 7 tenait le banc au même
moment) :

| mutation | rouges obtenus |
|---|---|
| la table annonce `role:3` là où la route porte `role:2` | **2** — `InventaireDesGardes` **et** `GardesDeRoutes` |
| la table annonce une permission que la route ne porte pas | **2** — les deux mêmes |
| une route **publique** inscrite comme authentifiée | **3** — dont l'assertion du visiteur |

Témoin avant et après : **221 passed** sur ces deux fichiers, à l'identique.

**Ce que ces mutations prouvent, et ce qu'elles ne prouvent pas.** Elles prouvent que
la suite détecte une route **moins gardée que le relevé** — c'est la direction de la
régression. Elles ne prouvent pas encore la mutation symétrique (retirer une garde
dans `routes/web.php` et vérifier les mêmes rouges) : ce fichier appartient à la
session 3 et est relu à **chaque requête**, donc l'éditer pendant le rejeu d'une
autre session changerait sa cible en plein vol. **À faire quand le banc est libre**,
et à inscrire ici.

---

## 4. Ce que la mesure a trouvé — à arbitrer par le Lead

Aucun de ces points n'a été corrigé : la session QA qualifie et transmet.

### 4.1 E-164 n'est refermé qu'à moitié — `server_id` reste

`int(server_id)` vit **à l'intérieur** du `try` qui rend « Erreur interne » sur
`/fail2ban/stats` (`backend/routes/fail2ban.py:657`) et sur `/fail2ban/history`
(`:345`). Un identifiant non numérique y obtient donc **500**.

Mesuré, pas supposé : `assert 500 == 400` sur les deux routes.

**La gravité est moindre que celle d'E-164 d'origine, et il faut le dire** : ce 500
est du **JSON** (`{"success": false, "message": "Erreur interne"}`), pas une page
HTML. La moitié « l'appelant ne peut même pas lire la réponse » est fermée ; la
moitié « la faute est dans la requête, le statut dit qu'elle est dans le serveur »
ne l'est pas.

Les deux tests correspondants sont dans la suite, marqués `xfail(strict=True)` : ils
ne rougissent pas aujourd'hui, et ils **rougiront le jour du correctif**, ce qui
obligera à retirer le marqueur plutôt qu'à oublier l'écart. Verrouiller le 500 actuel
aurait figé le défaut au lieu de le signaler.

*Troisième occurrence du motif « à moitié corrigé » sur ce module, et la deuxième fois
que le correctif partiel est le nôtre.*

**Attribution : session 4 (BASE & PERFORMANCE).**

### 4.2 Dix-sept routes portent une permission qui ne peut jamais décider

Mesuré en faisant lire le routeur par PHP lui-même, pas à l'œil :

> `perm:x` rend la main dès que le rôle vaut 3 (« cette permission OU superadmin »).
> Sur une route **déjà réservée au rôle 3**, la permission déclarée est **inerte**.

| famille | routes |
|---|---|
| `role:3` + `perm:can_admin_portal` | 14 (`comptes/*`, `permissions/*`, `journal-audit/*`, `notifications/preferences`) |
| `role:3` + `perm:can_manage_api_keys` | 3 (`cles-api`, création, révocation) |

**Ce n'est pas un trou** — l'accès est *plus* strict, pas moins. C'est la forme
« garde présente qui ne garde pas », déjà relevée 57 fois côté backend sur
`@require_machine_access` : **la relecture y confirme une protection qui n'agit
pas.** Le fait est désormais mesuré par une assertion
(`CombinaisonsDeGardesTest::le_role_3_court_circuite_la_permission`) au lieu d'être
supposé.

**Décision demandée** : garder (fidélité au legacy) ou retirer la permission inerte
de ces 17 déclarations. Aucune urgence, aucun risque d'accès.

### 4.3 Neuf routes portent un rôle et **aucune** permission

`/acces-sftp` (rôle 3), `/politiques` (rôle 3), `/docker` (rôle 2), `/taches`
(rôle 2), et les cinq de `/notifications` (rôle 1).

C'est une **information**, pas un verdict : le relevé le dit explicitement pour
qu'on ne le prenne pas pour un oubli. La question à confronter au legacy, module par
module, est de savoir si ces pages y exigeaient une permission. **INCONNU — je ne le
referme pas.**

### 4.4 La passerelle est une exception, et elle est nommée

`GET|POST|… /api/gateway/{chemin?}` porte `session.authentifiee` et **rien d'autre** :
elle relaie ~200 routes du backend derrière une seule déclaration, et ses gardes
vivent **dans le contrôleur** (liste blanche, réserve administrateur,
re-authentification ponctuelle). Une assertion tient cette exception **unique dans sa
famille** : une autre route de relais sans rôle apparaîtrait au rouge.

**Non encore mesurée côté PHPUnit** : la logique interne de la passerelle. Voir §6.

---

## 5. INF-001 — la CI ne lance aucun test applicatif du portage

Mesuré sur `.github/workflows/ci.yml` : **14 jobs**, dont **un seul** exécute des
tests — `test-python` (pytest). Les autres sont statiques : ruff, `php -l`, bandit,
semgrep, gitleaks, pip-audit, composer audit, Trivy, build Docker, auto-tag.

Conséquences, en l'état :

| ce qui n'est pas joué en CI | conséquence |
|---|---|
| `php artisan test` | **230 assertions de garde** ne protègent que la machine qui les lance |
| les **104 suites** `tests/e2e/` | la non-régression du chantier est **entièrement manuelle** |

**Proposition, dans cet ordre de coût croissant :**

1. **un job `test-php`** — `composer install` puis `php artisan test`. Aucune
   infrastructure : la suite est hermétique par construction (SQLite en mémoire, ni
   MySQL ni backend). **C'est le seul geste de cette liste qui ne coûte rien**, et
   c'est celui qui verrouille les gardes ;
2. **un sous-ensemble E2E** en CI — il demande la base, les deux portails et les
   trois comptes de test, donc un `docker compose` complet et des secrets TOTP. Coût
   réel, décision de l'exploitant ;
3. le LOT complet reste manuel : **~100 min**, et il verrouille le second facteur des
   trois comptes d'épreuve.

Le point 1 est celui que je recommande de trancher en premier.

---

## 6. Ce qui N'EST PAS mesuré — à lire comme le reste

- **le chemin autorisé sur les vraies routes** : qu'une page ouverte à un compte
  rende son contenu. Il demande la base du banc et le backend ; c'est `tests/e2e/`.
  Les tests PHPUnit mesurent la **chaîne de gardes** sur des routes temporaires, pas
  le rendu du portail ;
- **le jeton CSRF**, exempté dans les tests par le cadre lui-même (§1) ;
- **la passerelle** (`PasserelleController`) : traversée de chemin, liste blanche,
  réserve administrateur, re-authentification — et surtout la propriété *« la requête
  refusée n'est jamais partie vers le backend »*, qui se mesure avec `Http::fake()` et
  `assertNothingSent`. **Écrit nulle part aujourd'hui. Premier candidat du prochain
  lot** ;
- **`RoutesBackend`** : la comparaison par **segment** plutôt que par préfixe
  (`/searchall` refusé, `/search/xyz` accepté), et l'aller-retour fail-closed des noms
  d'action de step-up. Logique pure, entièrement testable, **non testée** ;
- **`Droits`** : la lecture des permissions **temporaires** non expirées (E-134). Elle
  demande un vrai schéma SQLite posé par le test ; faisable, non fait ;
- **la mutation symétrique** des gardes (§3, dernier paragraphe) ;
- **`backend/`** hors `fail2ban/` : les correctifs de la session 4 sur `supervision/`
  (E-90, `generic_reconfigure`) ne sont pas encore verrouillés par un test de la
  session 6.

---

## 7. Journal des mesures

| date | ce qui a été mesuré | résultat |
|---|---|---|
| 2026-08-27 | `backend/tests/` **avant** ce lot | 348 passed, 27 fichiers de test |
| 2026-08-27 | `backend/tests/` **après** `test_fail2ban.py` | **375 passed, 2 xfailed**, 28 fichiers |
| 2026-08-27 | mutation des deux correctifs `fail2ban` | **16 FAILED** — la suite peut échouer |
| 2026-08-27 | `laravel/tests/` **avant** | 1 passed, **1 failed** (gabarit d'origine) |
| 2026-08-27 | `laravel/tests/` **après** | **230 passed, 757 assertions** |
| 2026-08-27 | 3 mutations du relevé de gardes | **2, 2 et 3 rouges** — la suite peut échouer |

Chaque chiffre porte sa commande de remesure :

```bash
sudo -n docker exec rootwarden_python  sh -c "cd /app && python -m pytest -q"
sudo -n docker exec rootwarden_laravel php artisan test
grep -cE "^  [a-z0-9-]+:$" .github/workflows/ci.yml   # jobs de la CI : 14
ls tests/e2e/go-*.mjs | wc -l                      # suites E2E, toutes manuelles
```
