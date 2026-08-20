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
| **S1** | export CSV d'un scan (`cve_export.php`) | aucune | non | non |
| **S2** | rapport de conformité, HTML + CSV | aucune | non | non |
| **S2b** | export PDF du rapport | aucune | non | non |
| **S3** | consultation des CVE, lecture seule | `GET /cve_results`, `GET /cve_compare` | non | non |
| **S4** | planification des scans | `GET/POST/PUT/DELETE /cve_schedules`, `GET /cron_preview` | non | oui |
| **S5** | suivi et ticketing | `POST /cve_remediation`, `POST /tickets` | non | oui + **sortie tierce** |
| **S6** | re-priorisation EPSS / KEV | `POST /cve_reprioritize` | non | oui |
| **S7** | le scan lui-même | `POST /cve_scan` — **FLUX** | **oui** | oui + **destructif** |

**S1 d'abord** parce que c'est le plus petit périmètre du module et qu'il porte une règle d'accès
explicite : le contrôle IDOR à reproduire à l'identique, **404 et non 403**. Son test de
caractérisation — deux comptes, deux machines, un 404 attendu — valide le harnais de permissions
avant tout le reste.

**S2 ensuite** : aucune route, aucun SSH, aucun état à remettre à zéro entre deux mesures, mais
beaucoup de SQL et deux décisions de sécurité qui méritent leur propre commit (D-1 et D-2 ci-dessous).

**S2b séparé** de S2 : dépendance Composer distincte, sortie binaire, et la purge `ob_end_clean()`
sans laquelle le PDF est corrompu — un piège déjà payé une fois, à ne pas re-payer en même temps
qu'autre chose.

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

- **D-1 — `compliance_report.php` et le rôle 1.** Porter la garde telle quelle (`ROLE_USER` admis,
  parc entier, aucun cloisonnement) ou la restreindre à `role >= 2` comme son en-tête l'affirme
  déjà ? Le premier choix porte la fuite dans le neuf ; le second corrige un défaut de sécurité
  sous couvert de migration, et prive peut-être d'un usage réel. **Question d'exploitant.**
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
