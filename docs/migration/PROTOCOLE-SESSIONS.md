# Protocole de travail à plusieurs sessions

Écrit le **2026-08-27**, après audit du dépôt et **trois jours de travail réel à deux sessions** — dont
six incidents de collision mesurés. Ce document est la partie que **toutes** les sessions doivent
connaître. Les prompts de rôle vivent dans les terminaux ; celui-ci vit dans le dépôt.

---

## 1. La contrainte qui décide de tout : le banc est UNIQUE

Ce n'est pas une préférence, c'est une mesure.

| ressource | exemplaires |
|---|---|
| base de données (`rootwarden_db`) | **1** — toutes les fixtures s'y croisent |
| portail legacy (8443), portail porté (8444), backend Python | **1 chacun** |
| comptes de test | **3** (`rw-test-user` rôle 1, `rw-test-admin` rôle 2, `rw-test-super` rôle 3) |
| machine mutable du banc | **1** (`Test-Server-Debian`, id 2) |
| machine de production, jamais jointe | `srv-zabbix`, id 1 |

**Et le garde anti-rejeu TOTP est PAR COMPTE et EN BASE.** Deux sessions qui ouvrent une session avec
`rw-test-super` dans la même fenêtre de 30 s se sabotent — et l'échec ressemble à un compte verrouillé,
à une fenêtre TOTP ratée ou à une régression du portage. Trois diagnostics plausibles pour une cause qui
n'a rien à voir.

> **Une seule session à la fois peut faire tourner un test qui se connecte.** Ce n'est pas
> négociable et aucune organisation ne le contourne.

### Le jeton de banc

La détention **se rend explicitement**. Elle ne se déduit jamais d'un `ps` vide : un `ps` vide dit
« aucun rejeu à cette seconde », pas « personne n'est sur le point d'en lancer un ».

    « Je prends le banc pour <TASK-ID>, ~N minutes. »
    « Je rends le banc. Rien de moi ne tourne. »

Vécu le 2026-08-26 : deux sessions ont lancé des suites dans la même minute parce que l'une avait
conclu du `ps` vide. Rien n'a échoué — par chance.

---

## 2. La deuxième contrainte : cinq fichiers absorbent la moitié des commits

Mesuré sur les 112 commits des trois derniers jours :

| fichier | commits qui le touchent |
|---|---|
| `docs/migration/PLAN-DE-MIGRATION.md` | **77** |
| `scripts/rejouer-lot.sh` | **60** |
| `legacy/version.txt` | **59** |
| `CHANGELOG.md` | **57** |
| `docs/migration/PARITE.md` | **47** |
| `laravel/routes/web.php` | 24 |
| `laravel/app/Support/Navigation.php` | 11 |
| `laravel/public/css/rw.css` | 11 |

**À deux sessions, ces fichiers ont produit six incidents en une journée** : un commit qui emporte le
travail non commité de l'autre (trois fois), une édition du runner pendant un rejeu (deux fois), une
suite modifiée pendant un rejeu (une fois).

### La parade est structurelle, pas disciplinaire

**Le Lead est le SEUL à écrire les cinq fichiers de tête.** Les porteurs de module lui transmettent
leurs entrées ; ils ne les écrivent pas. Une collision qui ne peut pas arriver vaut mieux qu'une règle
qu'on doit se rappeler.

Pour les fichiers de second rang (`routes/web.php`, `Navigation.php`, `rw.css`), qui sont
structurellement partagés entre modules : **annoncer avant d'écrire**, et découper au patch si l'autre
session y est déjà.

---

## 3. Les quatre régimes de lecture

Ce qu'on touche n'a pas le même effet selon **quand c'est lu**. Quatre régimes, mesurés :

| ce qu'on touche | quand c'est lu | effet d'une écriture pendant un rejeu |
|---|---|---|
| `backend/**.py` | au **démarrage du processus** | **inerte** — c'est `docker restart` qui mord |
| `laravel/**`, `legacy/**` | à **chaque requête** | change la cible **en plein vol** |
| `tests/e2e/**.mjs` | au lancement de la suite | le nombre mesuré devient **irreproductible** |
| `scripts/*.sh` en cours d'exécution | ~~par décalage d'octets~~ | **✅ neutralisé, voir ci-dessous** |

Le quatrième était le pire — `bash` lit un script par offset, donc une écriture avant la boucle décale
la queue et le verdict peut être lu de travers **sans erreur visible**. **Il n'existe plus** :
`rejouer-lot.sh` se recopie dans `/tmp` et exécute la copie (`v1.37.85`). Prouvé en faisant tourner un
rejeu pendant que sa source prenait 960 octets — verdict juste, résumé complet.

> Une règle qu'on doit se rappeler est une propriété qu'on n'a pas encore construite.

Les trois autres régimes restent des règles. **Le troisième est celui qui reste dangereux** : ne pas
écrire dans `tests/e2e/` ni dans les références du runner pendant le rejeu d'une autre session.

---

## 4. Source de vérité

Le projet a déjà la sienne, et elle est meilleure que des fichiers génériques parce qu'elle est
alimentée depuis trois jours. **Ne pas créer `docs/current-status.md` ni `docs/tasks.md` en doublon.**

| rôle demandé | fichier réel |
|---|---|
| statut courant, plan, décisions ouvertes | `docs/migration/PLAN-DE-MIGRATION.md` — §0 brief, §2 état, §4 plan par module, §7 décisions en attente, §8 pièges |
| feature matrix / écarts legacy ↔ portage | `docs/migration/PARITE.md` — 145 écarts, E-01 à E-147 |
| méthode | `docs/migration/METHODE-SOUS-LOT.md` — les neuf temps |
| état des parties démontées | `docs/migration/DEPRECIATION.md` |
| inventaire par module, **à lire avant de planifier** | `docs/migration/MODULE-*.md` (10 fichiers) |
| audit des gardes backend | `docs/migration/AUDIT-GARDES-BACKEND.md` |
| journal des livraisons | `CHANGELOG.md` |

**Toute session commence par lire `PLAN-DE-MIGRATION.md` EN ENTIER**, puis le `MODULE-*.md` du module
qu'elle touche. Ne pas le faire a déjà produit un plan faux et laissé une vulnérabilité de production
trois jours sans être remontée.

---

## 5. Identifiants de tâche

Le projet numérote déjà par **sous-lot de module** : `A1`…`A5` (auth), `S1`…`S7b` (security),
`K1`…`K4` (ssh), `V1`…`V12` (supervision), `U1`…`U6b` (update), `D1`…`D10` (adm), `G1`/`G2` (graylog),
`B1`… (bashrc). **Garder cette numérotation** — elle est dans 145 écarts et 112 commits.

Y ajouter, pour ce qui n'est pas un sous-lot de portage :

| préfixe | usage |
|---|---|
| `SEC-nnn` | trouvaille de sécurité |
| `PERF-nnn` | mesure de performance |
| `BUG-nnn` | défaut trouvé au navigateur |
| `INF-nnn` | outillage, banc, CI |

Une session dit **toujours** sur quel identifiant elle travaille.

---

## 6. Format de compte rendu

À la fin de chaque tâche, dans le message au Lead **et** dans le corps du commit :

    TASK:
    STATUS:              vert / rouge / bloqué-arbitrage
    FICHIERS MODIFIES:
    TESTS EXECUTES:      suite, cible, PASS/FAIL — jamais « les tests passent »
    RESULTAT:
    RISQUES:
    IMPACT SECURITE:
    IMPACT PERFORMANCE:  avec mesure avant/après, ou « non mesuré »
    RISQUE DE REGRESSION:
    DECISIONS REQUISES:
    ACTION SUIVANTE RECOMMANDEE:

**Deux règles sur ce rapport, apprises à la dure :**

- **un chiffre porte sa commande de remesure**, jamais sa valeur seule. Un nombre de commits, un compte
  d'écarts, un total d'assertions se périment au commit suivant ;
- **dire ce qui n'est PAS mesuré aussi clairement que ce qui l'est.** « Corrigé dans les deux fichiers,
  prouvé dans un seul » vaut infiniment mieux que « corrigé ».

---

## 7. Ce qu'aucune session ne fait sans l'exploitant

| interdit | pourquoi |
|---|---|
| `git push`, `git merge` | jamais sans son mot explicite |
| réécrire l'historique (`--amend`, `rebase`) | jamais tant qu'une autre session peut travailler |
| joindre `srv-zabbix` (id 1) | production |
| lancer `tests/e2e/go-ssh-audit-scanall.mjs` | **joint la production** |
| déclencher un scan CVE qui aboutit | **envoie un vrai courriel** (S7b) |
| déclencher `POST /groups/<id>/run` | scan réel sur **toutes** les machines du groupe, courriel compris |
| déployer des clés (K4) | **révoquerait** des accès en l'état |
| demander de coller un mot de passe, une clé ou un jeton | jamais, en aucune circonstance |
| inventer un secret TOTP | il fait échouer la suite **à la connexion**, ce qui se diagnostique de travers |
| toucher `rw-test-user` (id 14) | D-5, lecture seule |

---

## 8. Les pièges de mesure qui ont déjà coûté

À lire avant d'écrire une assertion. Le détail est au §8 du plan ; voici les six qui reviennent.

1. **Un symptôme dit qu'il y a un problème, jamais lequel.** Trois conclusions fausses en un jour, toutes
   tirées d'un **artefact du diagnostic** — un message d'erreur, un compteur qui bouge, un `ps` vide.
   Aucun des trois n'était la chose elle-même.
2. **Un total qui change dit QU'il s'est passé quelque chose, jamais QUOI.** Le journal du rejeu
   précédent le dit, lui : ils sont conservés dans `/tmp/rw-lot-*/`, à portée d'un `grep`.
3. **Un écart à zéro FAIL veut dire « une assertion a cessé de s'exécuter ».** Trois fois : des
   assertions vivant dans un `if` sur un état du banc.
4. **Une suite qui dépend de données partagées préexistantes qu'elle ne crée pas accusera la page.**
   Elle ne peut pas distinguer « la page est fausse » de « le banc est vide ».
5. **Une garde présente n'est pas une garde qui garde.** `@require_machine_access` est sur 114 routes et
   **inerte sur 57** — celles qui portent déjà `@require_role(≥2)`.
6. **Un motif qui suppose une forme d'appel ne mesure que cette forme.** Mesurer le **comportement**
   (`page.on('dialog')`) plutôt que grepper la forme.

Et deux règles de geste : **cliquer le bouton, pas appeler la fonction** ; et jamais « le premier bouton
de la page » — remonter du champ à son `form`, ou de la ligne à son bouton, et **relire l'identifiant
visé**.

---

## 9. Travail parallèle : ce qui l'est vraiment

| activité | parallélisable ? |
|---|---|
| lire, inventorier, auditer | **oui**, sans limite |
| écrire le code d'un module (contrôleur, vue, JS, i18n) | **oui**, si modules disjoints |
| écrire une suite dans `tests/e2e/` | **non** pendant le rejeu d'un autre |
| lancer une suite, prendre des captures | **NON — jamais**, jeton de banc |
| écrire les cinq fichiers de tête | **non** — réservé au Lead |
| `docker restart rootwarden_python` | **non** pendant le rejeu d'un autre |

### Sur `git worktree`

Aucun worktree n'est utilisé aujourd'hui, et **il ne résoudrait pas le problème principal** : les
conteneurs servent le dépôt principal par montage. Un worktree isole les fichiers, pas le banc, ni la
base, ni les trois comptes de test. Il n'apporte donc rien tant que la contention est sur le banc — et il
ajoute le risque de porter un module contre un frontend qui n'est pas celui qui tourne.

**À réserver** à un cas précis : un travail long et purement statique (analyse, réécriture massive sans
exécution), où l'isolement des fichiers vaut plus que l'accès au banc.

---

## 10. L'équipe à SEPT sessions — table de propriété disjointe

Décision de l'exploitant du 2026-08-27. Sept sessions permanentes. Ce qui rend le nombre tenable est
la **disjonction stricte** de la propriété des fichiers, et le fait que **trois sessions sur sept
n'ont jamais besoin du banc**.

| # | session | propriété EXCLUSIVE | banc |
|---|---|---|---|
| 1 | **LEAD / ARCHITECTE** | `PLAN-DE-MIGRATION.md`, `PARITE.md`, `DEPRECIATION.md`, `CHANGELOG.md`, `ROADMAP.md`, `legacy/version.txt`, `scripts/rejouer-lot.sh` | non |
| 2 | **ANALYSTE LEGACY** | `docs/migration/MODULE-*.md` | **jamais** |
| 3 | **BACKEND LARAVEL** | `laravel/app/`, `laravel/resources/`, `laravel/public/`, `laravel/lang/`, `laravel/routes/` | partagé |
| 4 | **BASE & PERFORMANCE** | `mysql/migrations/`, `backend/` | partagé |
| 5 | **SÉCURITÉ** | `docs/SECURITY_AUDIT.md`, `docs/migration/AUDIT-*.md` — **et une branche `security/…`, jamais `Migration-Laravel`** | **jamais** |
| 6 | **QA / NON-RÉGRESSION** | `laravel/tests/`, `backend/tests/`, `docs/migration/QA-*.md` | partagé |
| 7 | **NAVIGATEUR / E2E** | `tests/e2e/`, `tests/pw/` | **priorité** |

### Le jeton de banc ne circule qu'entre 3, 4, 6 et 7

Et **7 a la priorité** : ses mesures sont la non-régression du projet. Quand 7 demande le banc, les
autres le rendent au prochain point d'arrêt propre. Le Lead tranche les égalités.

Les sessions 2 et 5 ne le demandent jamais — elles lisent. C'est ce qui permet d'avoir sept sessions au
lieu de trois : **quatre sessions se coordonnent, trois travaillent sans contrainte.**

### Les frontières qui restaient ambiguës, tranchées

| fichier | propriétaire | pourquoi |
|---|---|---|
| `backend/routes/*.py` | **4**, pas 3 | c'est la couche données et API ; 3 ne fait que la consommer par la passerelle |
| `backend/tests/*.py` | **6**, pas 4 | qui écrit le code ne valide pas seul son propre correctif |
| `laravel/tests/` | **6** | il est vide aujourd'hui (3 fichiers) — c'est un trou mesuré, il lui appartient |
| `laravel/routes/web.php` | **3** | mais toute route neuve est ANNONCÉE au Lead, deux modules y déclarent |
| `laravel/public/css/rw.css` | **3** | partagé par construction entre modules : annoncer avant d'écrire |
| les correctifs de sécurité | **5 propose, 3 ou 4 applique** | une session ne valide pas seule une modification de sécurité qu'elle vient d'écrire |
