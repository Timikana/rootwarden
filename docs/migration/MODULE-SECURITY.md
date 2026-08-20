# Module `security/` — inventaire et découpage

Deuxième **module** de la migration, après `update/`. Comme lui, il ne se porte pas d'une pièce :
ce document le mesure, puis le découpe en sous-lots portables un par un.

Établi le 2026-08-20, avant toute modification, selon `METHODE-SOUS-LOT.md` §1.

---

## 1. Ce que pèse le module

| Fichier | Lignes | Rôle |
|---|---|---|
| `legacy/security/js/main.js` | 1026 | tout le comportement : scan, rendu, filtres, planification, suivi |
| `legacy/security/compliance_report.php` | 579 | rapport de conformité du parc — HTML, CSV, PDF |
| `legacy/security/index.php` | 549 | la page : cartes serveur, panneau de planification, presets cron |
| `legacy/security/cve_export.php` | 101 | export CSV d'un scan, une machine |
| **total** | **2255** | |

**Deux des trois pages n'appellent aucune route backend.** `compliance_report.php` et
`cve_export.php` sont du PDO local de bout en bout. Seule `index.php` parle au backend Python, et
uniquement via `legacy/api_proxy.php`.

### Deux corrections de périmètre, avant de commencer

- **`backend/routes/policies.py` n'appartient pas à ce module.** Ses 9 routes (`/policy/sudo/*`,
  `/policy/sftp/*`, `/policy/rollback`, `/policy/deployments`, `/policy/list`) ne sont appelées que
  par `legacy/adm/server_user_sudo.php` et `legacy/adm/server_user_sftp.php`. Zéro référence dans
  `legacy/security/`. Elles relèvent de `adm/`, sont toutes `@require_role(3)` et portent un step-up
  2FA imposé par `api_proxy.php` — donc plus risquées. **À ne pas embarquer ici.**
- **Le CSRF n'est jamais posé par `main.js`.** Il est ajouté par le *wrapper* `window.fetch` de
  `legacy/js/utils.js:14-33`. La dépendance est implicite et invisible dans le module : elle doit
  être reproduite explicitement côté Laravel, sans quoi chaque appel part sans jeton.

---

## 2. La garde, et ce qu'elle ne garde pas

| Page | Rôles admis | Permission | Cloisonnement des données |
|---|---|---|---|
| `index.php` | 1, 2, 3 | `can_scan_cve` | rôle ≥ 2 → tout le parc ; rôle 1 → jointure `user_machine_access` |
| `cve_export.php` | 1, 2, 3 | `can_scan_cve` | contrôle IDOR explicite, réponse **404** et non 403, pour ne pas divulguer l'existence de la machine |
| `compliance_report.php` | 1, 2, 3 | `can_view_compliance` | **aucun** |

### `compliance_report.php` sert le parc entier à un rôle 1, et son en-tête dit le contraire

L'en-tête du fichier annonce, ligne 13 : « Acces : admin (2) et superadmin (3) ». La garde réelle,
ligne 19, est `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])`. **Le commentaire ment**, et
c'est ce qui rend le défaut durable : une relecture de l'en-tête ne peut pas le voir.

Aucune des collectes ne filtre par utilisateur — `FROM machines m ORDER BY m.name`,
`FROM users u JOIN roles r`. Ce qu'un rôle 1 porteur de `can_view_compliance` obtient donc, en
HTML, en CSV (`?format=csv`) et en PDF (`?format=pdf`) :

1. **tout le parc** : nom, IP, **port**, **utilisateur SSH**, version, cycle de vie, criticité,
   environnement, dates de dernière vérification / redémarrage / mise à jour de sécurité — y
   compris les machines qui ne lui sont pas attribuées ;
2. **tous les comptes** : nom, e-mail, actif, sudo, présence de clé SSH, **âge de la clé**,
   **présence d'un secret 2FA**, date de dernier mot de passe, rôle — soit la carte des comptes les
   plus faibles du portail ;
3. **la posture par serveur avec les écarts en clair** : « sshd non audite », « N CVE critique(s) »,
   « fail2ban absent », « N derive(s) config ». C'est une liste de cibles priorisée ;
4. l'historique des 10 dernières modifications iptables, **avec leur auteur**.

`checkPermission` accepte en outre une **permission temporaire** non expirée
(`legacy/auth/verify.php:269-300`) : l'accès peut avoir été accordé pour un temps et rester lisible.

**C'est une décision d'exploitant, pas un choix de portage.** Porter la page telle quelle porte la
fuite ; la restreindre à `role >= 2` corrige un défaut de sécurité sous couvert de migration. Voir
§5, décision D-1.

### Le hash « preuve d'intégrité » n'est vérifiable par personne

Lignes 28-30, le code énonce sa propre règle : les mots de passe chiffrés « n'ont rien a faire dans
un rapport exporte (HTML/CSV/PDF) **ni dans le hash SHA-256 d'integrite** ». La requête suivante,
ligne 41, sélectionne `u.totp_secret` et `u.ssh_key`. Ligne 141 :

```php
$reportData = json_encode(compact('servers', 'users', 'remStats', 'date'));
$reportHash = hash('sha256', $reportData);
```

Le raisonnement a été tenu pour une table et pas pour la suivante.

**Ce que ce n'est PAS** : une fuite de secret. Vérifié aux trois rendus — CSV ligne 174, PDF ligne
247, HTML ligne 464 — `totp_secret` et `ssh_key` ne sortent jamais qu'en booléen
(`!empty($u['totp_secret']) ? 'Oui' : 'Non'`). Le secret ne quitte pas le serveur.

**Ce que c'est** : un antécédent de hash qui contient des champs absents du rapport. Le lecteur du
rapport ne peut pas recalculer l'empreinte à partir de ce qu'il tient. Une preuve d'intégrité
invérifiable vaut exactement autant que pas de preuve. Parade au portage : sélectionner
`u.totp_secret IS NOT NULL AS has_2fa` et `u.ssh_key IS NOT NULL AS has_ssh_key` — le hash redevient
recalculable *et* la règle de la ligne 28 est enfin tenue partout.

---

## 3. Les commandes exactes du scan, à recopier dans l'en-tête du test

`POST /cve_scan` ouvre une session SSH par machine et n'exécute que des lectures
(`backend/cve_scanner.py`) :

```
dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null                       # timeout 30
grep -i '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]'
uname -r 2>/dev/null
cat /etc/os-release 2>/dev/null
ssh -V 2>&1 | head -1
openssl version 2>/dev/null | head -1
apache2 -v 2>/dev/null | head -1
nginx -v 2>&1 | head -1
systemctl is-active docker 2>/dev/null && docker --version 2>/dev/null | head -1
```

**Aucun `sudo`, aucune écriture sur la cible.** À dire explicitement dans l'en-tête du test :
contrairement à `update/`, ce module ne modifie rien sur le serveur distant.

En revanche, un seul clic déclenche côté serveur : un envoi de courriel, deux notifications
d'abonnés, un webhook, un auto-ticket KEV si `TICKETING_AUTO_KEV`, et — le seul effet destructif du
module — **l'auto-résolution des remédiations ouvertes non revues**
(`UPDATE cve_remediation SET status='resolved'`, `cve_scanner.py:1085-1100`), sur des données de
suivi humain, sans que l'écran l'annonce.

`POST /cve_scan` répond par un **FLUX** : `Response(locked_stream(), mimetype='text/plain')`, en
JSON-lines. Il ne se porte pas comme un JSON. La passerelle doit relayer sans tampon, comme
`api_proxy.php` le fait déjà (`X-Accel-Buffering: no`, `flush()` par bloc).

---

## 4. Ce que le croisement JS ↔ backend a donné

**Aucun désaccord de clés.** Les 12 corps envoyés correspondent clé par clé aux clés lues. C'est
l'inverse de `update/`, où le JS envoyait `{date,time,repeat}` à une route qui lisait
`interval_minutes` (E-18). Ici ce sont les **réponses d'erreur** qui sont perdues, pas les requêtes.

Défauts relevés, à porter comme corrections ou à consigner dans `PARITE.md` :

| # | Défaut | Effet mesurable |
|---|---|---|
| E-23 | `runScan` ne teste jamais `resp.ok` avant `resp.body.getReader()` (`main.js:240-294`) | les deux **429** structurels du backend — throttle 60 s par utilisateur, verrou global de scan — sont avalés en silence : le bouton se réactive, aucun message, rien. Le `catch` ne fait qu'un `console.error` |
| E-24 | La colonne « Suivi » disparaît dès qu'on filtre, cherche ou pagine | `buildRows` produit 6 `<td>` ; `loadMoreFindings`, `searchFindings` et `filterFindings` en reconstruisent **5**. Après un « Voir plus » ou un filtre, la remédiation et la création de ticket ne sont plus atteignables, et l'en-tête est désaligné. Deux des trois écritures du module ne vivent que sur la première page non filtrée |
| E-25 | `scanAll()` casse pour un admin sans machine | `#btn-scan-all` est rendu hors du `if (empty($machines))`, mais `#global-progress` ne l'est pas → `TypeError` sur `.classList`, sans garde nulle. Même famille que E-21/E-22 |
| E-26 | Un rôle 1 déclenche un 403 à chaque chargement | `loadSchedules` est câblée sans condition alors que `#schedules-list` n'est rendu que sous `$role >= 2`. Sans dégât visible, mais un appel refusé par page vue dans les journaux |
| E-27 | Le rôle exigé par l'UI et par le backend divergent | la page s'ouvre à un rôle 1 et lui affiche le `<select>` de remédiation et le bouton 🎟, alors que `/cve_remediation` est `@require_role(2)` et `/tickets` est `@require_role(2)` + `@require_permission('can_admin_portal')`, doublé d'un refus proxy. Deux contrôles qui échouent toujours |
| E-28 | Le clamp anti-fréquence du cron n'est pas rejoué en `PUT` | `POST /cve_schedules` impose un intervalle minimum de 600 s ; `PUT /cve_schedules/<id>` ne le contrôle pas. Un admin crée `0 3 * * *` puis le mute en `* * * * *` |
| E-29 | `status` de `/cve_remediation` sans liste blanche | l'UI n'offre que 4 valeurs, le backend en produit une cinquième, et la route accepte n'importe quelle chaîne |
| E-30 | Injection de formule CSV | `fputcsv` sans neutralisation de `= + - @` en tête de cellule, sur les noms de machines, de comptes, et les motifs d'écart |
| E-31 | `dotColor` construit ses classes Tailwind par concaténation | `` `bg-${color}-${…}` `` : `bg-blue-400`, `bg-green-500`, `bg-red-500` ne sont littéraux nulle part et peuvent être purgés au build. Piège connu, voir `rw-pieges` |
| E-32 | Fuite de synthèse parc au rôle 1 dans `index.php` | l'agrégat `servers_scanned` / `total_cves` / `total_critical` (lignes 197-208) n'est pas filtré par `user_machine_access` et s'affiche dès `count($machines) > 1` : un lecteur avec deux machines lit les compteurs du parc entier |

Points morts à ne pas porter : `#conn-status` (aucun JS ne le touche, le test de connexion a migré
côté PHP) et `_cveFindings[machineId + '_search']` (écrit, jamais relu).

### i18n

Les 10 clés `js.cve_*` du repli existent en FR **et** en EN, et aucun `t()` de `index.php` ou de
`compliance_report.php` ne manque. En revanche **~35 littéraux français sont en dur dans
`main.js`** et devront tous devenir des clés, plus les `title=` et les libellés « Source CVE » /
« Rapide » / « Hybride » / « Precis » de `index.php`. Un `toLocaleString('fr-FR')` fige la locale
(`main.js:392`).

Le seul `confirm()` natif du module — « Supprimer cette planification ? », `main.js:865` — **n'a
aucune clé, ni FR ni EN**. Il est intraduisible en l'état. Au portage il devient un panneau de
décision en ligne, conformément à `METHODE-SOUS-LOT.md` §7.

---

## 5. Découpage en sous-lots

Du plus simple au plus risqué. Chaque sous-lot est portable et testable seul.

| Lot | Contenu | Routes | SSH | Écrit |
|---|---|---|---|---|
| **S1** ✔ | export CSV d'un scan (`cve_export.php`) — **PORTÉ le 2026-08-20** (v1.37.20) | aucune | non | non |
| **S2a** ✔ | rapport de conformité, page HTML — **PORTÉ le 2026-08-20** (v1.37.21) | aucune | non | non |
| **S2c** ✔ | export CSV du rapport — **PORTÉ le 2026-08-20** (v1.37.22) | aucune | non | non |
| **S2b** ✔ | export PDF du rapport — **PORTÉ le 2026-08-20** (v1.37.23) | aucune | non | non |
| **S3** | consultation des CVE, lecture seule | `GET /cve_results`, `GET /cve_compare` | non | non |
| **S4** | planification des scans | `GET/POST/PUT/DELETE /cve_schedules`, `GET /cron_preview` | non | oui |
| **S5** | suivi et ticketing | `POST /cve_remediation`, `POST /tickets` | non | oui + **sortie tierce** |
| **S6** | re-priorisation EPSS / KEV | `POST /cve_reprioritize` | non | oui |
| **S7** | le scan lui-même | `POST /cve_scan` — **FLUX** | **oui** | oui + **destructif** |

**S1 d'abord** parce que c'est le plus petit périmètre du module et qu'il porte une règle d'accès
explicite : le contrôle IDOR à reproduire à l'identique, **404 et non 403**.

**Porté le 2026-08-20** (v1.37.20) : `App\Services\ScansCve` + `ExportCveController`, route
`/export-cve` gardée `role:1` + `perm:can_scan_cve`, catalogue `cve.php` FR+EN.
`tests/e2e/go-page-cve-export.mjs` — 16 PASS sur le legacy, 20 sur le portage.

Ce que S1 a rapporté, au-delà de lui-même :
- **E-33** — l'export du legacy n'est pas un CSV en dev/préprod : 1 465 blocs HTML `Deprecated`
  mêlés au fichier. La parade du portage est structurelle (charge utile assemblée avant envoi) et
  vaut pour S2, qui hérite du même défaut sur `compliance_report.php`.
- **E-34** — le contrôle IDOR n'est mesurable par AUCUN compte de test. L'intention de départ
  (« ce lot valide le harnais de permissions ») ne tient donc pas : il valide les gardes de rôle et
  de permission, mais pas le cloisonnement par machine. Un quatrième compte de fixture est à
  arbitrer.
- **E-35** — la route n'est atteignable qu'en tapant son adresse jusqu'à S3.

**S2 s'est révélé trop gros pour un seul sous-lot, et a été redécoupé** — un document de migration
n'est pas une promesse. `compliance_report.php` pèse 579 lignes : sept collectes SQL, une notation de
posture, sept sections HTML **et** un export CSV. Le HTML et le CSV sont désormais **S2a** et **S2c**.

**S2a — porté le 2026-08-20** (v1.37.21) : `App\Services\Conformite` (les sept collectes + la
posture + l'empreinte), `RapportConformiteController`, `resources/views/rapport-conformite.blade.php`,
route `/rapport-conformite` gardée `role:2` + `perm:can_view_compliance`, catalogue `conformite.php`
FR+EN (64 clés), et l'entrée `Navigation` basculée de `legacy` vers `route`.
`tests/e2e/go-page-conformite.mjs` — 13 PASS sur chaque cible.

Ce que S2a a rapporté :
- **D-1 appliquée** (E-36) : la garde passe à `role:2`, celle que l'en-tête du fichier annonçait.
  Mais la divergence **n'est mesurable par aucun compte de test** — même manque de fixture que E-34.
- **La première mesure du module qui distingue une garde par PERMISSION d'une garde par RÔLE** :
  `rw-test-admin` entre ici et reste refusé sur `journal-commandes`. Le premier jet de cette
  assertion visait `/commandlog/`, **archivé donc 404** — elle passait au vert sans rien mesurer.
- **L'empreinte est identique à l'octet** entre legacy et portage (E-37) : 4 480 octets d'antécédent
  et le même SHA-256, à date figée. D-2 reste donc ouverte sans risque de régression.
- **Six libellés d'écarts étaient en dur** dans le PHP du legacy (E-38) : la colonne « Écarts »
  restait en français quelle que soit la langue.
- Les exports CSV et PDF restent servis par l'ancien portail, **et la page le dit** (E-39).

**S2c — porté le 2026-08-20** (v1.37.22) : `ExportConformiteController`, route
`/rapport-conformite/csv` gardée comme la page, et `Conformite::rapport()` **extrait** pour que la
page et l'export ne puissent pas divergerr. 10 PASS sur le legacy, **17 sur le portage**. E-33 s'y est
rejoué exactement : 34 blocs d'avertissement, sections gonflées à 13/13/34 contre 3/3/10 — voir
E-40 à E-42.

~~S2c portera l'export CSV, où **E-33 se rejoue**~~ : `compliance_report.php` écrit lui aussi au fil
de l'eau dans `php://output`. Sa branche PDF porte déjà un `ob_end_clean()` dont le commentaire
nomme exactement le défaut — « purger tout output parasite (notices PHP capturées par ob_start en
mode debug) avant d'émettre le binaire PDF » —, mais la branche CSV, elle, n'a jamais été protégée.
Quelqu'un avait rencontré le problème et n'en avait corrigé qu'une moitié.

**S2b séparé** de S2 : dépendance Composer distincte, sortie binaire, et la purge `ob_end_clean()`
sans laquelle le PDF est corrompu — un piège déjà payé une fois, à ne pas re-payer en même temps
qu'autre chose.

**S2b — porté le 2026-08-20** (v1.37.23) : `ExportConformitePdfController` + la vue dédiée
`rapport-conformite-pdf.blade.php`, route `/rapport-conformite/pdf` sous la **même** garde que la page
et le CSV (`role:2` + `perm:can_view_compliance`). `Conformite::rapport()` portait déjà tout : S2b
n'écrit que le rendu. Le bouton PDF de la page S2a est passé sur la route portée et l'annonce
`conformite.pdf_a_venir` a disparu. Suite de caractérisation `go-page-conformite-pdf` : **14 PASS**
côté portage, **13** côté legacy (l'écart est E-45, mesuré et rendu en constat).

La dépendance : `dompdf/dompdf ^3.1` était **absente du portage** et a été ajoutée — **6 paquets, 0
retiré, 0 modifié**, en v3.1.6, soit exactement la version du legacy. Elle n'exige que `ext-dom` et
`ext-mbstring`, tous deux présents ; `gd` n'est que *suggéré*, « needed to process images », et le
rapport n'en porte aucune.

Ce que S2b a rapporté :

- **E-43** — la branche PDF est **la seule des cinq** occurrences du motif « le legacy documente son
  défaut là où il le commet » où la moitié protégée l'était vraiment. Vérifié des deux côtés. Son
  `ob_start()` est vestigial ; le portage n'ouvre aucun tampon, donc n'a rien à purger.
- **E-44** — le PDF du legacy en dit **moins** que sa propre page : six sections contre sept, cinq
  colonnes de comptes contre six. Le portage l'aligne (pare-feu, âge des clés). Écart voulu.
- **E-45** — aucun `<thead>` dans les tableaux du PDF du legacy : les 10 lignes de comptes arrivent
  page 2 **sans en-tête**, resté page 1. Corrigé dans le portage. **Ce défaut ne se voyait pas sur le
  texte extrait** — il a fallu rendre les pages en images.
- l'empreinte d'intégrité **n'est pas reproductible** : deux générations du même rapport à cinq
  minutes d'écart donnent deux empreintes. Ce que E-42 annonçait, désormais mesuré → **D-2**.
- le mot de passe root de la base **sortait dans les messages d'échec** des suites : corrigé pour les
  trois suites du module (`tests/e2e/lib-base.mjs`), signalé pour trois suites plus anciennes.

### `compliance_report.php` est intégralement porté, et pourtant pas archivable

Ses points d'entrée ont été énumérés : **`format=csv`, `format=pdf`, et la page**. Rien d'autre. Le
`$_GET['_pdf_render'] = true;` de la ligne 194 est **écrit et jamais lu** — un second vestige de
l'approche abandonnée, à côté de l'`ob_start()` vestigial. Les trois branches sont donc portées, par
S2a, S2c et S2b.

**Il reste néanmoins servi**, parce que `cve_scan.php` (S3 à S7) l'est aussi et que l'archivage se
fait par module, pas par fichier. Ses quatre portes sont déjà mesurées — les mêmes quatre que
`update/`, ce qui confirme la règle apprise là-bas :

| Point d'entrée | Fichier |
|---|---|
| barre latérale | `legacy/menu.php:155` |
| tiroir mobile | `legacy/menu.php:250` |
| tuile « accès rapides » | `legacy/index.php:384` |
| raccourci clavier `g` puis `r` | `legacy/head.php:210` |

Contrôlé au passage : **aucune des sept pages déjà archivées ne figure encore dans la table des
raccourcis clavier**, et `update/` y a bien été redirigé vers le portage. Pas de 404 atteignable au
clavier.

Le menu du portage, lui, pointe déjà sur la route interne (`Navigation.php:66`), et les deux boutons
d'export de la page portée sont internes depuis S2b : plus aucun aller-retour vers l'ancien portail
depuis ce rapport.

**Le module `security/` n'est donc PAS archivable** : S3 à S7 vivent encore dans `cve_scan.php`.

### Inventaire de S3 — mesuré le 2026-08-20 (METHODE-SOUS-LOT §1)

Trois inventaires menés en parallèle sur des fichiers **disjoints** : le PHP de la page, son JS, et le
versant backend + passerelle. **Tout ce qui suit a été re-vérifié à la main** — un rapport d'agent
n'est pas une mesure. Les rares points non revérifiés sont marqués comme tels.

#### La garde, aux trois endroits — sixième occurrence du défaut

| Endroit | Ce qui est appliqué |
|---|---|
| la **page** `legacy/security/index.php:37-38` | `checkAuth([USER,ADMIN,SUPERADMIN])` + `checkPermission('can_scan_cve')` → rôle ≥ 1 **avec** la permission |
| le **proxy** `legacy/api_proxy.php` | `checkAuth` rôle ≥ 1, `/cve_` en liste blanche (`:119`), **absent de `$ADMIN_ONLY_PREFIXES`**, et `checkPermission` n'y apparaît pas une seule fois |
| la **passerelle** `laravel/app/Support/RoutesBackend.php:35` | `/cve_` en liste blanche, **absent** de `ADMIN_SEULEMENT` et de `MOTIFS_STEP_UP` — relevé fidèle du legacy, défaut inclus |
| le **backend** `backend/routes/cve.py` | `cve_results` (`:207-210`) et `cve_compare` (`:311-314`) portent `require_api_key` + `require_machine_access` + `threaded_route`. **Ni rôle, ni permission.** |

**`grep -c require_permission backend/routes/cve.py` rend 0**, et `can_scan_cve` n'existe dans tout le
backend **que dans une fixture de test** (`backend/tests/conftest.py:152`). La permission ne coupe donc
**rien** sur le chemin de la requête : elle ne garde que des pages. C'est la sixième fois que ce défaut
est mesuré dans ce projet.

Conséquence pour le portage : la route de S3 portera `role:1` + `perm:can_scan_cve`, comme celle de S1
(`laravel/routes/web.php:156`) — **le portage sera donc plus strict que le legacy sur ce chemin**, et
il faut le déclarer.

#### Le décorateur d'accès et la route ne lisent pas le même paramètre

`require_machine_access` (`backend/routes/helpers.py:331-332`) résout l'identifiant ainsi :

```python
single = (data.get('machine_id') or request.args.get('machine_id')
          or data.get('server_id') or request.args.get('server_id'))
```

**le corps JSON d'abord, la query ensuite.** Or `cve_results` (`cve.py:217`), `cve_compare`
(`cve.py:322`) et `cve_history` (`cve.py:302`) lisent **exclusivement** `request.args`. Un GET portant
un corps JSON avec une machine autorisée et une query avec la machine d'autrui ferait donc autoriser
l'une et servir l'autre.

**Précondition mesurée : aucune des deux passerelles ne relaie le corps d'un GET.** Le portage
l'exclut explicitement (`AVEC_CORPS = ['POST','PUT','PATCH']`,
`PasserelleController.php:35`) ; le legacy ne lit `php://input` qu'à `api_proxy.php:260`, hors de sa
branche GET. Le trou est **réel dans le backend et fermé aujourd'hui par accident** — pas par
décision. À dire des deux façons : ce n'est pas exploitable, et ce n'est pas protégé.

Et le décorateur **ne refuse pas quand aucun identifiant n'est trouvé** : `ids` reste vide, `denied`
aussi, la route est appelée. Son propre docstring nomme pourtant ce défaut — « le décorateur était un
no-op et n'imposait aucun contrôle » — pour la variante au pluriel qu'un correctif antérieur a
traitée. **La moitié corrigée est celle du nom de clé, pas celle de l'absence.** Le motif « à moitié
corrigé », cette fois dans le commentaire qui décrit le défaut.

#### Le module CVE ignore entièrement le cycle de vie des machines

`grep -c lifecycle_status` rend **0** sur `backend/routes/cve.py` **et** sur `backend/cve_scanner.py`,
alors que **dix autres fichiers** du backend l'appliquent. Côté page, même motif à l'intérieur du même
fichier :

| Requête | Filtre `archived` |
|---|---|
| `index.php:42-45`, branche **rôle ≥ 2** | **présent** |
| `index.php:47-54`, branche **rôle 1** | **ABSENT** |
| `index.php:292-296` (S4) | présent |

L'oubli tombe sur la branche de l'utilisateur le moins privilégié : un rôle 1 voit et peut scanner une
machine qu'un admin ne voit plus. Et `cve_scan_all` (`cve.py:42-44`) fait
`SELECT ... FROM machines` **sans aucune clause `WHERE`** alors que le chemin planifié équivalent
(`backend/scheduler.py:299`) filtre bien les archivées — le scan-all manuel se connecte donc en SSH à
des machines retirées du parc. *(le point sur `scheduler.py` vient d'un inventaire d'agent, non
revérifié ; le `SELECT` sans `WHERE`, lui, est vérifié.)*

#### Le résumé de parc fuit ce que la liste filtre

`index.php:196-207` n'est joint **ni à `machines` ni à `user_machine_access`** : il agrège le dernier
scan complet de **toutes** les machines de la base, archivées comprises, et s'affiche dès que le compte
en a deux. Un rôle 1 lit donc les compteurs CVE de la flotte entière ; un admin y voit des machines
absentes du tableau juste en dessous. **Le portage le bornera aux machines réellement affichées** —
précédent accepté : `Conformite::serveurs()` en S2a a ajouté le filtre de cycle de vie qui manquait.

#### Le tableau des vulnérabilités se désaligne dès qu'on l'utilise

L'en-tête (`js/main.js:542-547`) a **six** colonnes — CVE, Package, Version, Severite, Resume,
Suivi — et `buildRows` en produit six. Mais **les trois autres générateurs n'en produisent que cinq**
(comptage refait à la main) :

| Générateur | `<td>` |
|---|---|
| `buildRows` (`:467-498`) | 6 |
| `loadMoreFindings` (`:589-599`) | **5** |
| `searchFindings` (`:624-634`) | **5** |
| `filterFindings` (`:660-671`) | **5** |

Pire : « Voir plus » **ajoute** ses lignes à cinq colonnes derrière les lignes à six — le même tableau
mélange les deux formes. Et le commentaire de `sevCell` (`:45-48`) revendique précisément d'avoir
« centralisé pour rester cohérent entre `buildRows` et la pagination » : il a centralisé **une colonne
sur six**, et la jumelle non protégée est justement celle qui manque.

#### Le reste, mesuré et à traiter dans ce lot

- **`loadLastResults` (`:121-134`), seul chargeur de S3, est muet en panne** : ses trois chemins
  d'échec n'écrivent que dans la console. Proxy tombé = carte serveur vide, sans un mot.
- **Le compteur « n / m CVE » ne s'affiche jamais en dessous de 50 CVE** : `#findings-count-{id}` et
  `#load-more-{id}` ne sont créés que s'il y a une page suivante, alors que la recherche et les
  filtres s'en servent toujours. Gardés par un `if`, donc silencieux.
- **Aucune donnée CVE n'est insérée par `textContent`** : tout passe par `innerHTML`. Le portage rendra
  par `textContent`, comme les sept pages déjà portées.
- **`esc()` (`:739`) n'échappe pas l'apostrophe** alors que son docblock affirme empêcher l'XSS. Sur 32
  appels, **deux** sont dans une chaîne JS délimitée par apostrophes à l'intérieur d'un attribut
  (`:485`, `:492`) et tous deux ne reçoivent que `f.cve_id`. Un identifiant CVE n'en porte pas :
  **latent, pas armé** — et ces deux sites sont dans la colonne « Suivi », donc **S5**.
- **`#conn-status` (`index.php:106`) est un bandeau figé au rendu serveur**, jamais touché par le JS
  (zéro occurrence) : si le backend tombe ou revient, l'écran ne bouge pas avant rechargement.
  `#servers-container` et `$api_url` sont morts aussi.
- **24 chaînes d'interface en dur** côté PHP, et beaucoup plus côté JS ; les dates sont figées en
  `'fr-FR'` (`:392`, `:925-926`) alors que le socle expose la langue. `<html lang="fr">` est codé en
  dur (`index.php:85`).
- **Le test de connexion OpenCVE est fait en PHP** par cURL direct sur `https://python:5000`
  (`index.php:68`), hors proxy, **vérification TLS désactivée** (`:72-73`), `API_KEY` en clair (`:63`).
  L'en-tête du fichier (`:23-26`) l'annonce pourtant « côté client (JavaScript) » : **cinquième
  en-tête du projet qui ne dit pas le code**.

#### La contrainte qui commande l'ordre des lots

`renderResults` est appelé depuis **deux** endroits : `loadLastResults` (S3) et `runScan` (S7). S3 ne
peut donc pas être porté sans **figer dès maintenant un contrat de rendu** que S7 réutilisera — sinon
le portage de S7 dupliquera le générateur, exactement ce que le legacy a fait quatre fois.

Second point d'architecture : **le portage lira la base directement**, comme S1 l'a fait avec
`ScansCve`, plutôt que de passer par la passerelle. Cela ferme d'un coup, pour le portage, l'absence de
permission sur la requête et l'écart corps/query du décorateur — sans toucher au backend Python. En
contrepartie, la comparaison de deux scans (dont le diff est fait en Python, `cve.py:368-370`) devra
être réimplémentée dans le service. C'est la ligne déjà suivie par S1.

#### Ce que S3 ne pourra pas prouver

Sans compte de fixture de rôle 1 portant `can_scan_cve` **et** une ligne `user_machine_access`
(**D-5**), la branche rôle 1 de cette page — donc son filtre `archived` manquant et son résumé de parc
qui fuit — **n'est pas mesurable par un test**. À dire dans `PARITE.md` plutôt qu'à contourner en
déplaçant des droits : un test qui déplace les droits ne mesure plus l'application réelle.

**S3 en troisième** : deux routes sans écriture ni SSH, mais c'est là que vit tout le rendu du
module. Le gros du travail de vues et des ~35 clés i18n se paie ici, une fois ; les lots suivants
s'y branchent. E-24 et le point mort `#conn-status` se corrigent dans ce lot.

**S4** : quatre écritures en base, un `@require_role(2)` à respecter **côté vue aussi** (E-26), la
clé i18n manquante du `confirm()`, et E-28 à trancher. Le scheduler reste Python
(`backend/scheduler.py:614-628`) : Laravel n'écrit que la table, il ne déclenche rien. Test existant
à reprendre : `tests/e2e/go-cve-schedules.mjs`.

**S5** : premier lot avec un effet **hors du parc** — sortie HTTP vers Jira/GLPI/ServiceNow derrière
le garde SSRF de `ticketing._post`. E-27 et E-29 s'y règlent.

**S6** : la route réécrit en bloc les scores de tous les findings du dernier scan, et son résultat
dépend de deux services externes (FIRST.org EPSS, CISA KEV), avec un 503 si indisponibles.
L'attente du test doit viser **le contenu**, jamais un délai.

**S7 en dernier**, et c'est le seul qui touche les machines. Ce qu'il faut avoir en tête :
- c'est un **flux**, pas un JSON (§3) ;
- neuf commandes SSH en lecture seule, aucun `sudo`, rien de modifié sur la cible (§3) ;
- deux **429** structurels que le legacy avale en silence (E-23) : le test de caractérisation doit
  *constater* ce silence côté legacy avant de l'exiger côté Laravel ;
- E-25 à corriger ;
- une cascade d'effets de bord à un seul clic, dont **l'auto-résolution des remédiations** (§3) ;
- tests existants à reprendre : `tests/e2e/05-cve-scan.test.mjs`, `tests/e2e/go-security.mjs`.

### Ce qui ne sera pas porté sans arbitrage explicite

`whitelistCve` (`main.js:1013-1026`) est du **code mort** : une seule occurrence dans tout
`legacy/` et `laravel/`, sa déclaration. Aucun `onclick`, aucun écouteur, aucun HTML. Elle est la
seule consommatrice de `_cfg.username`, qui meurt avec elle. La capacité « accepter un faux
positif » existe pourtant côté serveur (`GET`/`POST`/`DELETE /cve_whitelist`) et **personne n'a
jamais pu la demander depuis cette page**. Un seul cas mort ici, là où `update/` en avait trois ;
même verdict : **ne pas le porter**, l'offrir est une décision produit. À noter aussi que
`whitelisted_by` y était fourni par le client — l'attribution d'une acceptation de risque était
falsifiable. Si la capacité est un jour offerte, elle doit venir de `get_current_user()`.

Jamais atteintes par ce frontend, à laisser où elles sont : `POST /cve_scan_all` (`scanAll()` boucle
des appels unitaires), `GET /cve_history`, `GET /cve_remediation`, `GET /cve_remediation/stats`
(`compliance_report.php` recalcule ces chiffres en SQL local), et le paramètre `per_machine_cvss`,
documenté dans l'OpenAPI mais jamais envoyé.

---

## 6. Les décisions à prendre avant S2

- **D-1 — TRANCHÉE le 2026-08-20 : le portage restreint à `role >= 2`.** Décision de l'exploitant.
  Le portage appliquera donc la garde que l'en-tête du fichier annonce depuis toujours, et non celle
  que son `checkAuth` appliquait. À porter dans S2, avec une entrée dans `PARITE.md` : c'est une
  divergence VOULUE avec le legacy, pas un oubli. Le legacy lui-même n'est pas modifié par cette
  décision — il est archivé au moment où S2 aboutit.
  Reste ouvert : faut-il une lecture pour un rôle 1 sur SES machines seulement ? Rien ne l'exige
  aujourd'hui, la page n'ayant jamais su cloisonner ; à rouvrir si un usage se manifeste.
- **D-2 — le hash d'intégrité.** Retirer `totp_secret` et `ssh_key` de l'antécédent (§2) rend
  l'empreinte recalculable, mais **change la valeur du hash** : les rapports déjà émis ne se
  vérifieront plus contre la nouvelle formule. À dire dans le CHANGELOG.
- **D-3 — E-32, la synthèse parc au rôle 1** dans `index.php` : même nature que D-1, sur une autre
  page. À trancher avec elle, pour ne pas laisser les deux pages en désaccord.
- **D-4 — E-28**, le clamp cron manquant en `PUT` : le rejouer côté Laravel, c'est corriger un
  défaut backend depuis le frontend. Le backend reste intact sauf autorisation ; la parade côté vue
  seule est contournable.

Voir `PARITE.md` pour les écarts E-23 à E-32, `DEPRECIATION.md` pour l'archivage du module quand
les huit sous-lots seront portés, et `METHODE-SOUS-LOT.md` pour l'ordre de travail de chacun.
