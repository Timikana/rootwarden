# Changelog - RootWarden

Toutes les modifications notables sont documentées ici.  
Format : [Semantic Versioning](https://semver.org/lang/fr/) - `MAJEUR.MINEUR.PATCH`

---

## [Non publié] — Migration v2.0 : dépréciation du frontend legacy (branche `Migration-Laravel`)

> **⚠ `main` tourne en production a v1.37.15.** Cette branche est a **v1.37.94** et n'a jamais ete
> fusionnee. Deux correctifs de **securite** n'existent donc que sur elle :
> `6dea479` (**v1.37.16**, 7 correctifs issus de l'audit de migration) et `94a4ffe` (**v1.37.17**, le
> mot de passe root ne sort plus dans le flux SSH). Il n'existe **aucune branche `main` locale** : un
> `git push origin main` ne publierait rien — il faut d'abord la materialiser depuis `origin/main`.
> Le retroportage de ces deux correctifs attend une decision de l'exploitant.

### Vague 0 — `www/` devient `legacy/`

Le frontend legacy est renommé `www/` → `legacy/` (227 fichiers). **Aucun changement de
comportement** : le dossier reste la racine documentaire du conteneur `rootwarden_php`.
Le déplacement est fait *avant* tout portage — le faire à la fin, avec trente modules déjà
modifiés, aurait produit un commit géant et conflictuel.

Points d'ancrage repris hors du dossier : `docker-compose.yml` (4 montages côté hôte),
`docker-compose.prod.yml`, `php/Dockerfile`, `php/entrypoint.sh`, `.github/workflows/ci.yml`
(l'auto-tag lit désormais `legacy/version.txt`), `.gitignore`, `.gitleaks.toml`,
`.semgrep/rules-rootwarden.yml`, `scripts/sync-obsidian-vault.py`, `maj.sh`,
`backend/routes/chatops.py`, les quatre documents racine et les quatre skills du projet.

Laissés intacts délibérément : les chemins `/var/www/html` et `/var/www/sessions` (internes au
conteneur) et les références de `CHANGELOG.md` (traces historiques — les réécrire falsifierait
l'historique).

Supprimé : `www/C:/Program Files/Git/var/www/html/test-server`, arborescence vide non suivie par
git, née d'un chemin POSIX traduit en chemin Windows par Git Bash.

**Vérification** : nouveau test de caractérisation `tests/e2e/go-vague0-legacy.mjs`, joué avant
puis après. Il suit les liens du menu et compte les sous-ressources en échec page par page.
37 pages, toutes en 200, toutes garnies, mêmes actifs, une seule sous-ressource en échec avant
comme après (favicon absent sur `/api/docs.php`, préexistant).

### ⚠ Note d'exploitation

Le montage change de chemin côté hôte. Après récupération, les conteneurs doivent être
**recréés**, pas seulement redémarrés :

```bash
docker compose --env-file srv-docker.env up -d php
```

### Socle — squelette Laravel et conteneur

Squelette Laravel **13.17** neuf dans `laravel/`, servi sur `${LARAVEL_PORT:-8444}` en
parallèle du legacy (8443), qui reste la référence. Aucune page portée à ce stade.

Le conteneur `rootwarden_laravel` était un **orphelin** : ses étiquettes le rattachaient à un
service `laravel:` qui n'existait plus dans `docker-compose.yml`. Il est supprimé et le service
est redéclaré.

**Trois migrations par défaut supprimées** (`create_users_table`, `create_cache_table`,
`create_jobs_table`). La première est la plus dangereuse : `users` existe déjà avec ses colonnes
`role_id`, `totp_secret`, `failed_attempts`. Le schéma appartient au backend Python.
Voir `laravel/database/migrations/README.md`.

Corollaire moins visible : Laravel 13 propose par défaut `SESSION_DRIVER=database`,
`QUEUE_CONNECTION=database` et `CACHE_STORE=database`, qui exigent précisément les tables
supprimées. Laissés tels quels, ils cassent l'application à la **première requête**, avec une
erreur SQL et non un message clair. `.env.example` les place sur `file` / `sync` / `file`.

Identifiants de base lus en repli sur `MYSQL_*` dans `config/database.php` plutôt que recopiés
sous `DB_*` : un mot de passe présent à deux endroits finit par diverger.

**Vérifié** : `/up` répond 200, la page d'accueil répond 200, `APP_KEY` est générée, Laravel voit
les **63 tables** partagées, et le schéma est **intact** — aucune table `migrations`, `sessions`,
`cache` ni `jobs` créée, toujours 63 tables. Le legacy répond toujours sur 8443.

### Conteneur Laravel : la sonde échouait pour une raison mesurable

Le conteneur restait « unhealthy » en permanence, ce qui avait été noté sans être diagnostiqué.
Cause trouvée : **sur un hôte Windows, le bind mount est ~258× plus lent que le système de
fichiers du conteneur** — 9 300 ms contre 36 ms pour lire 1 500 fichiers PHP. Le legacy charge
~5 fichiers par page, Laravel plusieurs centaines : une première requête à froid dépasse 6 s,
puis retombe à 0,17 s une fois le cache du système chaud. Le délai de la sonde passe de 5 s à
20 s (`start_period` 60 s). Le conteneur est **healthy**, zéro échec.

⚠ **Conséquence pour toute la migration** : les mesures de latence faites sur cet hôte sont
suspectes. L'écart relevé précédemment sur la recherche (2,2 s contre 24 ms au legacy) compare
surtout un nombre de fichiers chargés ; il doit être re-mesuré sur un hôte Linux avant d'être
traité comme un défaut applicatif.

### Nouvelles variables d'environnement

`LARAVEL_PORT=8444` et `APP_TIMEZONE=Europe/Paris`, ajoutées à `srv-docker.env.example` — les
exploitants les récupèrent automatiquement via `./maj.sh`.

### Socle — caractérisation de l'authentification, et un défaut trouvé

Nouveau test `tests/e2e/go-socle-auth.mjs`, joué avec les **trois comptes de test dédiés** et
non en superadmin. Il mesure six invariants de la chaîne d'authentification avant d'y toucher :
page protégée sans session, mot de passe seul insuffisant (aucun chemin sans second facteur,
pour aucun rôle), page protégée toujours refusée entre le mot de passe et le second facteur,
mauvais mot de passe, régénération de l'identifiant de session, passage par les conditions
d'utilisation. **Cible legacy : 13 PASS / 0 FAIL / 1 écart connu.**

#### ⚠ Le rejeu d'un code TOTP est accepté (défaut de production)

Mesuré, pas déduit : sur `rw-test-super` (rôle 3, `can_admin_portal`), **le même code TOTP a
ouvert deux sessions authentifiées** dans la même fenêtre de 30 secondes, depuis deux contextes
de navigateur distincts.

`legacy/auth/verify_2fa.php` porte pourtant une garde anti-rejeu. Elle ne se déclenche jamais :
`$_SESSION['last_totp_hash']` n'est posé que dans la branche de succès (ligne 96) puis supprimé
onze lignes plus bas (ligne 126), dans la même requête, et jamais posé sur un échec. La condition
de la ligne 92 est donc structurellement inatteignable.

Et même corrigée, elle resterait sans effet : une garde portée par la **session** ne peut rien
contre un rejeu venu d'une session **neuve** — c'est-à-dire exactement le scénario d'attaque.

Le portage doit porter cette garde par **compte**, persistée en base (la colonne se demande côté
Python, aucune migration Laravel). L'écart est consigné dans `docs/migration/PARITE.md` (E-01)
avec une attente **par cible** : écart connu côté legacy, exigence côté Laravel.

Le défaut est présent sur `main`, donc en production. Il n'est pas corrigé côté legacy à ce
jour — la décision appartient à l'exploitant.

### Socle — portage de l'authentification (le même test passe sur les deux cibles)

Chaîne d'authentification portée sur Laravel : mot de passe, second facteur TOTP, conditions
d'utilisation, déconnexion, garde de session. **`cible=laravel : 14 PASS / 0 FAIL / 0 écart`**,
avec le même `go-socle-auth.mjs` qui donnait `13 PASS / 1 écart connu` sur le legacy.

**E-01 est corrigé.** `App\Services\Totp` détermine *à quelle fenêtre* appartient le code
présenté — un booléen de validité ne suffisait pas, la garde a besoin du numéro de fenêtre —
puis retient la dernière fenêtre consommée **par compte** et refuse toute fenêtre déjà
consommée. Stockage : cache applicatif (pilote fichier), et non une colonne en base, pour ne
pas engager un schéma qui appartient au backend Python. Contrepartie assumée et écrite dans
`PARITE.md`.

Autres points du portage :
- La décision d'accès vit dans **un seul** middleware (`session.authentifiee`). Entre le mot
  de passe et le second facteur, la session ne porte qu'un `compte_temporaire` et ne franchit
  pas ce garde — vérifié sur les trois rôles.
- Rotation de l'identifiant de session **deux fois** : après le mot de passe et après le
  second facteur.
- Le secret TOTP est relu **en base** au moment de la vérification ; il ne transite jamais par
  la session. Le rôle et l'état actif sont eux aussi revérifiés à cet instant.
- `App\Support\TotpCrypto` porte fidèlement le déchiffrement du legacy (sodium, AES-GCM, CBC
  historique, clair) : le même secret doit rester lisible par les deux frontends.
- Compteurs partagés avec le legacy : verrouillage par compte après 5 échecs, table
  `login_attempts` par IP, une 2FA réussie enregistrée en `success=1`.
- Message d'erreur **identique** que le compte existe ou non, pour ne pas révéler quels
  identifiants existent.
- Les chemins du legacy (`/index.php`, `/profile.php`, `/auth/login.php`…) redirigent vers les
  routes portées, ce qui permet au **même** test de viser les deux cibles sans être réécrit.
- CSS écrit à la main (`public/css/rw.css`), jetons + classes `.rw-*`, thème sombre par
  préférence système, aucune étape de construction.
- i18n : `lang/{fr,en}/auth.php`, **24 clés = 24 clés**, zéro clé morte à l'écran.

Volontairement **non porté** à ce stade, et signalé à l'écran plutôt que silencieusement
absent : l'enrôlement d'un second facteur, la re-authentification ponctuelle (step-up), la
politique de mot de passe et la réinitialisation. Un compte sans secret TOTP arrive sur une
impasse explicite qui renvoie vers l'ancien portail — jamais sur un accès accordé.

`legacy/auth/` **n'est pas archivé** : l'ancien portail sert encore toutes les pages métier et
a besoin de sa propre authentification.

### Socle — gabarit et navigation

Gabarit du portail porté : barre latérale, en-tête, tiroir mobile, et le menu complet des
**33 entrées** relevées sur le legacy avec leurs gardes à l'identique.

**Le menu a une source unique.** Le legacy décrit le sien deux fois — barre latérale et tiroir
mobile — avec la logique de droits recopiée dans les deux. `App\Support\Navigation` le décrit
une fois ; les deux rendus incluent le même partiel, et un test vérifie qu'ils rendent les mêmes
entrées.

Chaque entrée porte `route` (page portée, lien interne) **ou** `legacy` (non portée, lien
externe), jamais les deux : l'état du portage se lit d'un coup d'œil. Les 31 entrées non portées
s'affichent avec un marqueur visible et s'ouvrent dans un nouvel onglet — un lien qui change de
portail sans le dire trahit l'utilisateur.

Les droits sont lus **en base** (`App\Services\Droits`, mémorisé pour la durée de la requête),
jamais depuis la session : le legacy porte lui-même l'avertissement « ne jamais utiliser
`$_SESSION['permissions']` pour une décision de sécurité », puis s'en sert quand même pour son
menu.

Le tiroir mobile est piloté par une case à cocher masquée : **aucune ligne de JavaScript**.

**Vérifié** (`tests/e2e/go-socle-navigation.mjs`, **28 PASS / 0 FAIL**), avec les trois comptes
dédiés et non en superadmin :
- le menu croît strictement avec les droits — **3 < 13 < 33** ;
- le superadmin voit les 33 entrées déclarées ; un rôle sans permission ne voit pas la section
  administration, et ce qu'il voit est un sous-ensemble de ce que voit le superadmin ;
- barre latérale et tiroir rendent les mêmes entrées ;
- chaque lien porté **résout en 200** — le test suit les liens, parce que sept entrées de menu
  ont rendu 404 pendant des semaines sur la tentative précédente sans qu'aucune suite ne clique
  dessus ;
- aucune clé de traduction morte à l'écran ;
- le marqueur « ancien portail » est mesuré **en largeur rendue** : présent dans le HTML mais
  large de zéro, il ne préviendrait personne.

Libellés du menu **générés** depuis le legacy, non recopiés : 74 libellés accentués transcrits à
la main sont 74 occasions de faute. `lang/{fr,en}/nav.php`, **42 clés = 42 clés**.

Lot antérieur rejoué après modification du gabarit : authentification **14 PASS** sur Laravel,
**13 PASS / 1 écart connu** sur le legacy, vague 0 inchangée.

### Socle — refonte de l'interface, vue à l'image et non seulement assertée

Nouveau `tests/e2e/go-captures-socle.mjs` : 16 captures du socle à **1920, 1400 et 390 px**.
Elles ont été **ouvertes et jugées** — c'est ce qui a révélé trois défauts qu'aucune assertion
DOM ne voyait :

- environ **1000 px vides de chaque côté** sur un écran de 1920, à cause d'un
  `max-width: 960px` sur le contenu ;
- « Connecté en tant que » affiché **deux fois**, dans l'en-tête et dans le corps ;
- « ancien portail » répété **31 fois** dans le menu d'un superadmin, noyant les libellés ;
- la liste du menu **coupée en plein libellé** par le pied de barre latérale.

Refonte :
- **La page prend toute la largeur.** `.rw-contenu` n'a plus de `max-width` ; `.rw-grille`
  (`auto-fit`, minimum 280 px) donne 2 colonnes sur écran moyen et 4 sur grand écran. Seule la
  prose reste bornée à 68 caractères (`.rw-prose`) — un paragraphe centré sur 1900 px se relit
  ligne par ligne.
- **Boutons repositionnés.** Action principale à droite en pied de formulaire, action secondaire
  à gauche. Compte et déconnexion remontent dans l'en-tête : en pied de barre latérale, ils
  bornaient la liste du menu.
- **Marqueur des pages non portées** : une flèche discrète, expliquée **une seule fois** par une
  légende en tête de menu, le détail restant dans le `title` de chaque entrée.
- **Guidage** : fil d'étapes sur les trois écrans d'authentification (identifiants → second
  facteur → accès), aide sous les champs, tuiles d'orientation sur l'accueil (modules
  accessibles, déjà portés, second facteur, ancien portail), et un état vide qui explique
  *pourquoi* le parc n'est pas encore affiché plutôt que de le laisser manquer.

**Un piège payé et corrigé au passage** : repositionner les boutons a fait de « Refuser et se
déconnecter » le premier `button[type=submit]` de la page des conditions d'utilisation. Les
scripts, ancrés sur « le premier bouton », se déconnectaient en croyant entrer. Les éléments
pilotés par les tests portent désormais un attribut **`data-rw`** stable — un test ancré sur un
rang dans le DOM est fragile par construction.

i18n : deux modules créés (`accueil`, `profil`), deux étendus (`auth`, `nav`).
**auth 34 = 34 · nav 43 = 43 · accueil 16 = 16 · profil 7 = 7**, zéro écart.

Lot complet rejoué après refonte du gabarit : navigation **28 PASS**, authentification **14 PASS**
sur Laravel, **13 PASS / 1 écart connu** sur le legacy, vague 0 inchangée.

### Socle — passerelle vers le backend Python

`/api/gateway/…` remplace `api_proxy.php`. C'est l'endpoint le plus puissant du portail : il
transmet toutes les routes du backend, clé d'API côté serveur. Les contrôles s'appliquent
**dans l'ordre** et sont fail-closed à chaque étape : session authentifiée, falsification de
requête, traversée de chemin, liste blanche, réserve d'administration, ré-authentification
exigée, transmission.

**Le filtrage compare des segments, plus des préfixes** (`PARITE.md` E-02). Le legacy compare
par début de chaîne : `/search` autorise `/searchall`, et toute route Python future dont le nom
commence par un préfixe autorisé devient publique sans décision. Le portage lit chaque entrée
selon sa forme — espace de noms (`/fail2ban/`), racine délibérée (`/cve_`), ou route exacte.

Vérifié **avant** de resserrer, sur les **201 routes réellement déclarées** dans `backend/` :
les deux filtres rendent le même verdict, zéro différence. Le resserrement ne retire aucun
accès et refuse en plus `/searchall`, `/command_logger`, `/updateXYZ`. Mesuré en situation :
`/searchall` rend **405 sur le legacy** (donc transmis au backend) contre **403 sur le portage**.

Les permissions envoyées au backend sont relues **en base**, pas prises dans la session. Le
statut du backend est propagé tel quel. La ré-authentification ponctuelle n'étant pas portée,
les routes qui l'exigent sont **refusées** plutôt que transmises — accorder une action qui donne
root sans le second contrôle que le legacy exige serait un recul.

**Vérifié** (`tests/e2e/go-socle-passerelle.mjs`) : **Laravel 10 PASS / 0 FAIL**,
**legacy 5 PASS / 0 FAIL / 1 écart connu**.

#### Deux erreurs de mesure, corrigées

Un `fetch` same-origin sans jeton CSRF passait, ce qui a d'abord fait conclure à une absence de
protection. C'était faux : Laravel 13 remplace le contrôle par jeton par un contrôle
**d'origine** (`PreventRequestForgery`), et une requête same-origin **doit** passer — ce n'est
pas une falsification. La propriété à mesurer est qu'une requête *cross-site* soit refusée ;
le navigateur interdisant de forger `Sec-Fetch-Site`, le test la rejoue depuis Node avec les
cookies de session. Résultat : **cross-site 419**, same-origin transmis.

Et les sondes mutantes ne sont plus jouées contre le legacy : un POST refusé par son contrôle
CSRF invalide la session, son JS de sondage part vers la page de connexion, et cette navigation
détruit le contexte d'exécution — le lot expirait sans rien mesurer. Vérifié qu'aucune action
n'a été déclenchée : le legacy a répondu 403, le backend n'a jamais vu la requête.

Nouvelle variable : `BACKEND_INTERNAL_URL` (et `BACKEND_TIMEOUT`) dans `srv-docker.env.example`.
i18n : module `passerelle`, **6 clés = 6 clés**.

### Socle — i18n : le socle est complet

Bascule FR/EN portée : middleware `Langue` (priorité `?lang=` > session > cookie > `fr`),
sélecteur inclus par les **deux** gabarits, persistance en session et cookie (365 jours).

La liste blanche `['fr','en']` est reprise comme **contrôle de sécurité**, pas comme
commodité : côté legacy, un pentest avait montré qu'un cookie `lang` forgé permettait
d'inclure un fichier arbitraire. Toute valeur hors liste retombe sur le défaut — vérifié avec
`de`, `../../etc/passwd` et `fr; DROP TABLE users`.

Le sélecteur reste atteignable **avant toute connexion** : quelqu'un qui ne lit pas le français
doit pouvoir basculer pour comprendre l'écran de connexion lui-même.

#### Le repli de langue masque la moitié des défauts

Avec `APP_FALLBACK_LOCALE=en`, une clé absente des **deux** langues affiche son identifiant —
visible. Mais une clé présente en anglais et **absente en français** affiche le texte anglais :
invisible à l'œil, et invisible à un test qui cherche des identifiants à l'écran.

`tests/e2e/go-socle-i18n.mjs` fait donc **deux** contrôles distincts : aucun identifiant à
l'écran dans les deux langues, **et** parité des jeux de clés module par module. Le second passe
par PHP dans le conteneur — analyser des fichiers PHP à l'expression régulière reviendrait à
réécrire un interpréteur, et une clé mal lue serait déclarée absente à tort.

**Vérifié : 23 PASS / 0 FAIL**, 110 clés françaises comparées, zéro écart.

Corrigé au passage un commentaire qui disait l'inverse du code : le cookie de préférence part
**chiffré** (middleware `EncryptCookies`) ; le dernier argument booléen de `cookie()` est `raw`,
pas le chiffrement.

#### Le socle est complet

| Pièce | Lot |
|---|---|
| Authentification (TOTP obligatoire, anti-rejeu par compte) | 14 PASS · legacy 13 + 1 écart |
| Gabarit et navigation (33 entrées, source unique) | 28 PASS |
| Interface (largeur, boutons, guidage) | captures regardées |
| Passerelle (filtrage par segment) | 10 PASS · legacy 5 + 1 écart |
| i18n (bascule, parité) | 23 PASS |

Restent **non portés**, et signalés à l'écran plutôt que silencieusement absents : enrôlement
d'un second facteur, ré-authentification ponctuelle, politique de mot de passe, réinitialisation.
Aucune page métier n'est portée : `legacy/` est intact, rien n'est encore archivé.

### Première page métier portée — et premier archivage du legacy

`commandlog` (journal des commandes, lecture seule) est porté sur `/journal-commandes`, puis
**archivé** : `legacy/commandlog/` a été déplacé dans `legacy/_deprecated/`.

**La preuve que l'archivage cherchait** : avant, `https://localhost:8443/commandlog/` répondait
302 ; après le déplacement, la même URL répond **404**, et son script aussi. Plus rien ne les
sert. C'est réversible par le mouvement inverse — c'est pourquoi `git mv` et non `git rm`.

L'entrée de menu **du legacy** a été redirigée vers le nouveau portail plutôt que laissée sur
une page archivée : un menu qui mène à un 404 est exactement le défaut que ce chantier corrige.
Nouvelle variable `LARAVEL_URL`. Effet mesurable : le test de la vague 0 collecte désormais
**36 liens internes** au lieu de 37 — la progression de la migration, pas une régression.

Le portage :
- Deux middlewares génériques, `role:2` et `perm:can_admin_portal`, la garde vivant **dans la
  route** et nulle part ailleurs. Les deux refus donnent des messages distincts sans détailler
  ce qui manque.
- Rendu par `textContent`, jamais par interpolation : une commande journalisée contient par
  nature des caractères de shell.
- Les libellés que le script affiche sont posés **en données** dans la page : une chaîne écrite
  en dur dans du JS échappe à la parité FR/EN.
- Accents rétablis — le legacy écrit « Tracabilite », « Rafraichir », « Resultat ».
- État vide qui explique quoi faire, et non un tableau muet.

**Les données de test sont réelles** : deux commandes privilégiées ont été déclenchées sur
`Test-Server-Debian` pour alimenter le journal, plutôt que d'insérer des lignes fictives. Au
passage, un constat : **`su` échoue sur cette machine** — le mot de passe root enregistré ne
fonctionne pas, donc aucune mise à jour ne peut y aboutir.

**Vérifié : 14 PASS / 0 FAIL sur les deux cibles**, avec les trois comptes. Lot rejoué :
navigation 29, i18n 23, auth Laravel 14, passerelle 10, vague 0 inchangée.

`PARITE.md` E-03 consigne une nuance : le legacy ne séquence pas ses chargements, un résultat
périmé a été observé **une fois**, mais il **ne se reproduit pas de façon fiable**. Le portage
numérote ses chargements et seul le dernier écrit — la possibilité est retirée par
construction. C'est ce qui est affirmé, et rien de plus.

### Serveur de test : `su` ne pouvait pas fonctionner — et ce que ça a révélé

Le conteneur `test-server` portait `security_opt: no-new-privileges:true`, un drapeau qui
**interdit toute élévation de privilège**. `su` et `sudo` y échouaient quel que soit le mot de
passe, avec « The "no new privileges" flag is set ». Or ce conteneur existe précisément pour
recevoir des opérations privilégiées — déploiement de clés, mises à jour, iptables, scan CVE.
Le drapeau annulait sa seule raison d'être. Retiré de ce service, **conservé sur php, laravel,
python et db**.

Le mot de passe root enregistré pour la machine 2 était **correct** : même empreinte que
`TEST_SERVER_ROOT_PASSWORD`. Le diagnostic précédent (« le mot de passe ne fonctionne pas »)
était faux — c'était un symptôme, pas la cause. Vérifié : `whoami` rend `root`, une mise à jour
de sécurité aboutit en `code 0`.

#### ⚠ Ce que ce déblocage a mis au jour : le mot de passe root fuit dans le flux affiché

Une fois `sudo` fonctionnel, le flux de `/security_updates` contient **le mot de passe root de
la machine cible, en clair, à la ligne 2** — l'écho du terminal. Ce flux est le texte affiché
dans l'interface pendant une mise à jour.

**Reproductible : 3 essais sur 3, toujours à la même ligne.**

`execute_as_root_stream` porte pourtant une défense explicite contre exactement cela (« Patch
A09 » : mise en tampon jusqu'au premier saut de ligne pour jeter la ligne d'écho). Elle est
présente dans le module chargé, appelée aux deux endroits — et elle ne l'attrape pas sur le
chemin `mode=sudo`. Le mécanisme précis n'est pas établi.

Portée : quiconque possède `can_update_linux` sur une machine obtient son mot de passe root en
lançant une mise à jour. Si un mot de passe est réutilisé sur le parc, la portée dépasse la
machine.

Ce défaut n'apparaissait pas ici tant que `sudo` échouait. Sur un serveur réel, où `sudo`
fonctionne, **il est actif**. Les journaux, eux, sont propres : `log_scrub.py` filtre — zéro
occurrence dans les journaux Docker comme dans les fichiers. La fuite est dans la réponse HTTP,
que le nettoyeur ne couvre pas.

**Non corrigé** : le backend Python est hors du périmètre de cette migration, et une
modification de ce genre demande un arbitrage. Signalé pour décision.

### Seconde page métier portée — approbations à quatre yeux

`approvals` est porté sur `/approbations`, puis **archivé** : `legacy/approvals/` a rejoint
`legacy/_deprecated/`. L'URL legacy répond **404**, `index.php` et `js/main.js` aussi, et
l'entrée de menu du legacy mène désormais au portage.

La page pilote le garde-fou qui protège les actions destructrices — suppression d'un compte
distant, redémarrage, régénération de la clé de plateforme, révocation d'un compte de service :
elles exigent l'aval d'un second administrateur. `APPROVAL_ENABLED` documenté dans
`srv-docker.env.example`, à `false` par défaut.

**Le test décide pour de vrai.** Les demandes sur lesquelles il travaille sont produites par des
appels réels du compte `rw-test-admin` (rôle 2) sur la machine `id=2`, et il mène un **rejet
complet** : la demande quitte l'onglet « en attente » et se retrouve dans « rejetées ». Un test
sur une page vide n'aurait rien prouvé.

Deux écarts assumés, documentés dans `docs/migration/PARITE.md` :

- **E-04** — le motif de rejet ne passe plus par `prompt()` et la confirmation plus par
  `confirm()`. Une ligne de confirmation s'ouvre **sous la demande concernée**, avec le champ de
  motif. La boîte native recouvrait précisément la ligne qu'on est en train de juger, ne se
  stylait pas — action destructrice et annulation au même poids visuel — et bloquait tout
  pilotage, si bien que le test ne pouvait pas rejeter réellement.
- **E-05** — la règle des quatre yeux est rendue **visible** : le bouton *Approuver* de sa
  propre demande est désactivé et porte l'explication, au lieu de laisser cliquer pour rien. La
  règle reste appliquée par le backend, seul endroit où elle vaut. Cette branche **n'est pas
  exercée** par le test : aucun compte de test n'est à la fois demandeur et porteur de
  `can_admin_portal`, et aucun droit n'a été modifié pour forcer le cas.

### Le tableau dit maintenant qu'il défile

Une capture à 390 px a montré deux demandes dont la colonne *Décision* — la seule raison d'être
de la page — était hors écran, sans le moindre indice qu'on pouvait y accéder. Le cadre de
tableau porte désormais des ombres de bord : deux voiles qui glissent avec le contenu et deux
ombres collées au cadre, sans une ligne de JavaScript. L'indice n'apparaît que s'il reste
quelque chose à atteindre, et disparaît quand le tableau tient dans la largeur.

Le jeton `--rw-bord-defilement` est défini par thème : une ombre noire ne se voit pas sur un
fond sombre, et la première version était strictement invisible là où elle servait.

### Une partie archivée ne laisse plus une suite rouge derrière elle

Archiver `commandlog` avait laissé son test à `4 PASS / 7 FAIL` : il cherchait une page qui
n'existe plus. Deux parties archivées auraient fait deux suites rouges permanentes — après quoi
on ne lit plus les rouges.

`tests/e2e/archive.mjs` porte le **constat d'archivage**, partagé par toutes les pages portées.
Sur la cible legacy, le test sonde d'abord l'URL ; 404 signifie archivée, et il bascule sur ce
qui a du sens après le déplacement : la partie et ses fichiers ne répondent plus, et **le menu
du legacy mène au portage**. Cette dernière vérification est celle qui compte : sans elle, on
installerait soi-même un 404 dans un menu.

### Deux sondes qui mesuraient autre chose que ce qu'elles croyaient

- **Des attentes fixes de 1,5 s** dans le test du journal des commandes. Elles ont tenu tant que
  la table était courte, puis ont produit deux faux échecs dès qu'elle a grossi : la passerelle
  répondait après le réveil et la sonde lisait encore le filtre précédent. Le test annonçait
  « le filtre ne filtre pas » ; le filtre allait bien. Remplacées par une attente du
  **changement puis de la stabilité**. Même correction dans le script de captures, qui
  photographiait « Chargement… ».
- **Des sous-ressources qui n'ont jamais existé.** Le constat d'archivage sondait
  `/approvals/approvals.js` : 404, assertion verte — mais le script s'appelle `js/main.js`. Une
  assertion creuse est pire qu'une assertion absente, elle occupe la place. Les chemins réels
  sont désormais sondés, et `/tasks/index.php` répond 302 : c'est ce qui prouve que le 404 des
  autres vient de l'archivage et non d'un chemin mal écrit.

### Troisième page métier portée — détection de dérive de configuration

`drift` est porté sur `/derive-config`, puis **archivé** : `legacy/drift/` a rejoint
`legacy/_deprecated/`. L'URL legacy répond **404**, `index.php` et `js/main.js` aussi, et
l'entrée de menu du legacy mène au portage. Le menu du legacy compte désormais **34 liens
internes** contre 37 au départ — exactement les trois pages portées.

**La première page dont la permission décide vraiment.** Les deux pages précédentes exigeaient
`can_admin_portal`, que seul le superadministrateur possède parmi les comptes de test : rien ne
distinguait une garde par permission d'une garde par rôle. Celle-ci exige
`can_view_compliance`, que porte `rw-test-admin` (rôle 2). Le même compte est donc **autorisé
ici et refusé ailleurs** — la seule configuration qui prouve que la permission est lue.

**Le test écrit vraiment en base.** Il re-scanne `Test-Server-Debian` et vérifie que
l'horodatage affiché avance, puis lance un scan global et vérifie qu'aucune machine n'est
laissée en arrière. `backend/routes/drift.py` a été lu avant d'écrire ce test : `scan_all` ne
fait **aucun appel SSH**, il recalcule depuis des données déjà en base. C'est ce qui rend le
bouton sans danger sur un parc qui contient une machine de production — et la page le dit
maintenant à l'écran, description et infobulle comprises.

Deux écarts assumés, documentés dans `docs/migration/PARITE.md` :

- **E-06** — le détail d'un écart est **affiché** sous sa pastille, et non caché dans un
  attribut `title`. C'est la seule information actionnable de la page : « Fail2ban installé mais
  arrêté » ne demande pas la même chose que « Fail2ban non installé ». Une infobulle ne s'ouvre
  ni au doigt, ni au clavier, ni pour un lecteur d'écran. Le détail n'apparaît que sur les
  catégories non conformes, pour ne pas noyer les lignes qui demandent une action. Au passage,
  `?` et `—` deviennent « Jamais évalué » et « Non évalué » : un point d'interrogation dans un
  tableau de conformité se lit aussi bien comme « inconnu » que comme « erreur ».
- **E-07** — le résultat d'un scan est écrit dans une région d'annonce persistante
  (`role="status"`, `aria-live="polite"`) au lieu d'une bulle qui s'efface. Un scan change ce qui
  est affiché ; une bulle disparue ne dit plus si les valeurs qu'on relit sont celles d'avant ou
  celles d'après.

### Deux tests qui mesuraient mal

- **Attendre le calme n'est pas attendre le résultat.** Le test de dérive attendait que le
  tableau cesse de bouger après un re-scan. Or pendant le scan, le bouton affiche « Scan en
  cours » et le tableau ne bouge plus du tout : la sonde trouvait le calme immédiatement, lisait
  les horodatages d'avant, et rapportait que le scan n'avait rien fait — alors que la requête
  avait abouti et la base été écrite. Il attend désormais **la condition qu'il va asserter**.
- **Une assertion trop stricte mesure l'horloge.** « Chaque horodatage a changé » échouait quand
  une machine venait d'être re-scannée dans la même seconde. La propriété juste est que le plus
  ancien horodatage d'après ne soit pas antérieur au plus récent d'avant : aucune machine
  oubliée, sans dépendre de la résolution de l'affichage.

### Un test qui détruisait ses propres données

Le test des approbations travaillait sur des demandes créées à la main avant lui, et en rejetait
une à chaque exécution. Après quelques passages la file était vide et il échouait — non pas
parce que la page était cassée, mais parce qu'il avait consommé ce dont il dépendait. Il produit
maintenant ses propres demandes, avec le compte qui en produit légitimement (`rw-test-admin`,
rôle 2), sur des comptes cible inexistants et horodatés. Il y gagne une assertion : les actions
destructrices répondent bien **202, en attente d'approbation**.

### Interface

Quatre tuiles de résumé qui remplissent la largeur, action principale en haut à droite. La
grille des tuiles descend à 160 px de largeur minimale : à 190 px, un téléphone n'en affichait
qu'une par ligne et repoussait le tableau — la donnée — sous quatre écrans de contexte. Sur
grand écran, rien ne change : `auto-fit` effondre les pistes vides et les quatre tuiles
s'étirent.

### Quatrième page métier portée — sauvegardes de la base

`backups` est porté sur `/sauvegardes`, puis **archivé** : `legacy/backups/` a rejoint
`legacy/_deprecated/`. L'URL legacy répond **404**, `index.php` et `js/main.js` aussi, et
l'entrée de menu du legacy mène au portage. Le menu du legacy compte **33 liens internes** contre
37 au départ — exactement les quatre pages portées.

**Le test crée et contrôle pour de vrai.** Le répertoire de sauvegardes était vide : le test
produit une sauvegarde (0,27 Mo, 63 tables, 5 368 instructions) puis la contrôle. Il ne **restaure
jamais** — `/admin/backups/restore` fait un `DROP TABLE` sur la base partagée par le legacy,
Laravel et le backend Python, ce qui détruirait les sessions et les données des autres suites en
cours. La restauration réelle reste donc non couverte, et c'est écrit plutôt que sous-entendu.

Deux écarts assumés, documentés dans `docs/migration/PARITE.md` :

- **E-08** — la confirmation d'une restauration **empêche** l'erreur au lieu de la reprocher. Le
  legacy demande le nom du fichier par `prompt()`, compare après coup et annonce « le nom ne
  correspond pas » : le geste a déjà été fait. Le portage ouvre une confirmation sous la ligne,
  et le bouton reste **inactif tant que la saisie diffère**. Le chemin d'erreur devient
  vérifiable — il ne l'était pas, la boîte native étant annulée avant toute saisie.
- **E-09** — le contrôle d'une sauvegarde dit ce qu'il vérifie. Le legacy annonce, en trois
  endroits, qu'il « recharge la sauvegarde dans une base temporaire ». `verify_backup()` ne fait
  rien de tel : il compare l'empreinte sha256, décompresse le dump et compte les `CREATE TABLE`.
  **Aucune instruction n'est exécutée.** Un dump lisible mais inapplicable passe le contrôle sans
  réserve. Le portage appelle la même route et ne change que les mots : « Contrôler », et un
  verdict « lisible et intacte — 63 tables, 5 368 instructions, empreinte conforme » au lieu de
  « valide ». Un libellé qui promet plus qu'il ne tient conduit à ne pas faire le contrôle qu'on
  croit déjà fait.

### Une permission qui garde la page, pas la capacité

Mesuré pendant ce portage, et **laissé tel quel** : la page des sauvegardes exige
`can_admin_portal`, mais le backend ne demande que le rôle 2 sur `/admin/backups`. Depuis une
session `rw-test-admin` refusée sur la page avec un 403, l'appel
`GET /api/gateway/admin/backups` répond **200 avec la liste**.

Rien n'a été changé : resserrer la passerelle retirerait à un rôle 2 une possibilité qu'il a
aujourd'hui, ce qui est un changement de droits et non une décision de portage. Le relevé est
consigné, l'arbitrage revient à l'exploitant.

### Deux corrections de sonde

- **Lire la première annonce venue, c'est lire « en cours ».** Le test attendait que la région
  d'annonce soit non vide et récoltait « Contrôle en cours… » au lieu du verdict. Le signal juste
  est le bouton, désactivé pendant l'appel et réactivé dans le même bloc synchrone que
  l'écriture du verdict — il ne dépend ni de la cible ni de la langue.
- **Asserter sur un mot qu'on a soi-même choisi.** L'attente cherchait « valide » dans le
  verdict, alors que le portage a précisément renoncé à ce mot. Elle porte désormais sur ce que
  le contrôle **rapporte** : deux nombres, un compte de tables et un compte d'instructions,
  quelle que soit la langue.

### Un archivage qui fait tomber une exception de `.gitignore`

`.gitignore` exclut `backups/` — le répertoire de stockage — avec une exception explicite pour
`legacy/backups/**`, qui est du code. Le déplacement vers `legacy/_deprecated/backups/` a fait
tomber cette exception : le dossier archivé est retombé sous la règle générale.

Les deux fichiers étant déjà suivis, le renommage les a préservés et rien n'a été perdu — ce qui
masquait complètement le problème. L'exception est étendue à l'archive. À vérifier après chaque
archivage : `git check-ignore -v legacy/_deprecated/<partie>/`.

### Interface

Un nom de fichier n'est pas une commande : `.rw-code` coupe à n'importe quel caractère, ce qui
donnait « rootwa / rden_b / ackup_ » sur six lignes à 390 px — illisible, et impossible à
comparer d'un coup d'œil alors que c'est exactement ce qu'on demande avant de confirmer une
restauration. `.rw-code--fichier` garde le nom d'une pièce ; le débordement appartient au cadre
du tableau, qui défile et le dit.

### Cinquième page métier portée — centre de tâches

`tasks` est porté sur `/taches`, puis **archivé** : `legacy/tasks/` a rejoint
`legacy/_deprecated/`. L'URL legacy répond **404**, `index.php` et `js/main.js` aussi, et l'entrée
de menu du legacy mène au portage. Le menu du legacy compte **32 liens internes** contre 37 au
départ — exactement les cinq pages portées.

**Gardée par le seul rôle**, sans aucune permission : c'est ce que fait le legacy, et le portage
le reproduit. Inventer une permission au détour d'un portage serait un changement de droits.

### Deux défauts trouvés en écrivant la caractérisation

**1. Le filtre par statut n'a jamais fonctionné.** `/tasks/list?status=<x>` répond **500** pour
tout statut. Cause lue dans les journaux du backend : `1052 Column 'status' in where clause is
ambiguous`. La requête filtrée joint `machines`, qui porte aussi une colonne `status`, et la clause
`WHERE status = %s` n'est pas qualifiée. La requête de comptage, sans jointure, passe — d'où une
erreur qui n'apparaît qu'à la seconde requête.

Le legacy n'écrit le tableau que sur succès et ne fait rien sur échec : sélectionner « Échec »
laisse **cent tâches « Réussie »** affichées, sans un mot. La page présente des données exactes
comme si elles répondaient à une question qu'on ne lui a pas posée.

**E-10** — le portage vide le tableau et dit que le filtrage a échoué côté serveur, en nommant le
statut demandé. Montrer moins est préférable à montrer faux ; un `if (réussi)` sans `else` fabrique
un écran rassurant et faux, exactement comme un `catch` vide fabrique un rapport rassurant et faux.

Le correctif backend tient en un mot — `t.status = %s` — mais il change le comportement du filtre,
et le backend reste intact pendant cette migration. Il attend une autorisation.

**2. Le menu est plus strict que la page.** La page n'exige aucune permission ; l'entrée de menu
vit dans un bloc gardé par `can_admin_portal`. Mesuré avec `rw-test-admin` (rôle 2, sans cette
permission) : l'entrée est **absente du menu**, et `GET /tasks/` répond **200 avec la page**.

C'est le miroir de ce qui a été relevé sur les sauvegardes, dans l'autre sens — là la page était
plus stricte que la capacité, ici le menu est plus strict que la page. Même leçon : **ce qui est
caché n'est pas gardé.** L'écart est reproduit tel quel et consigné ; le corriger d'un côté ou de
l'autre change des droits.

### Un rafraîchissement mesuré par les appels, pas par l'écran

L'auto-rafraîchissement se vérifie en comptant les requêtes vers `/tasks/list`, pas en regardant si
le tableau change : sur un historique stable, un rafraîchissement parfaitement fonctionnel ne
change rien à l'écran. Compter les appels mesure la fonction ; regarder le tableau mesurerait la
stabilité des données. Le test vérifie aussi que décocher la case **arrête vraiment** les appels —
zéro requête sur sept secondes.

La case dit désormais sa période : « Actualiser toutes les 5 s ». « Rafraîchir auto » ne permettait
pas de savoir si ce qu'on lit date de cinq secondes ou de cinq minutes.

### Interface

`flex-shrink: 0` sur le bloc d'actions d'en-tête gardait sa largeur naturelle et le faisait
**déborder de l'écran** au lieu de se replier : à 390 px, « Actualiser toutes les 5 s » sortait du
champ, coupé net. Le bloc peut retrécir et passer à la ligne. Trouvé en regardant la capture, pas
en assertant.

### Sixième page métier portée — ticketing ITSM

`tickets` est porté sur `/tickets`, puis **archivé** : `legacy/tickets/` a rejoint
`legacy/_deprecated/`. L'URL legacy répond **404**, `index.php` et `js/main.js` aussi, et l'entrée
de menu du legacy mène au portage. Le menu du legacy compte **31 liens internes** contre 37 au
départ — exactement les six pages portées.

Garde identique de bout en bout, pour une fois : `role:2` + `can_admin_portal` sur la page **et**
sur `/tickets` côté backend.

**Création réelle, sans appel externe.** `TICKETING_ENABLED=false` : le backend ne joint aucun
ITSM et enregistre un ticket `local`. Lu dans `backend/ticketing.py` avant d'écrire le test —
cliquer « Créer » sans savoir où part la requête n'aurait pas été raisonnable.

### Le formulaire manuel ne peut créer qu'un ticket par machine

`create_or_get_ticket()` dédoublonne sur `(source, ref, machine_id)`. Un ticket manuel n'ayant ni
référence ni source variable, **la clé se réduit à la machine**. Deux résumés entièrement
différents sur la même machine sont fusionnés — mesuré en direct. Sur un parc de trois machines,
il existe quatre créations manuelles possibles, et ensuite plus aucune.

L'encart d'aide du legacy annonce pourtant « ne pas créer plusieurs tickets pour la même alerte ».
Les tickets nés d'une CVE portent bien la référence du CVE et se dédoublonnent par alerte ; seul
le chemin manuel est concerné.

**E-11** — le portage énonce la vraie clé dans son aide, avertit **avant le clic** quand la
machine choisie est déjà pourvue (en citant le ticket existant), et dit « aucun ticket créé »
plutôt que « dédoublonné ». La règle reste appliquée par le backend ; elle est seulement rendue
lisible au moment où elle compte.

### Un libellé de champ n'est pas une pastille — défaut du portage, vu à l'image

**E-12** — `.rw-etiquette` était défini **deux fois** dans la feuille de style : d'abord comme
libellé de champ, ensuite comme pastille de catégorie. La seconde l'emportant, **tous les libellés
de formulaire du portail étaient rendus en pastille bleue**, y compris « Identifiant » et « Mot de
passe » sur l'écran de connexion — le tout premier écran du produit.

Aucune assertion ne pouvait le voir : les libellés étaient présents, corrects, traduits et
associés à leur champ. Seule la capture le montrait. C'est le défaut `escHtml()` défini deux fois
relevé dans le legacy, reproduit ici, et il aura vécu plusieurs vagues. La pastille s'appelle
désormais `.rw-badge`.

### Deux corrections de sonde, dont une déjà connue

- **Un test ne doit pas saturer un espace de clés borné.** Le test créait toujours sur la
  machine 2 : il a réussi une fois, puis a rapporté deux échecs dès la cible suivante, ayant
  consommé le seul créneau. Il choisit désormais une machine sans ticket manuel, exclut la machine
  de production, et dit laquelle des deux branches — création ou fusion — il a jouée.
- **Encore une attente fixe.** Après l'envoi, le test dormait 1 000 ms puis lisait le tableau
  d'avant, et rapportait « la création n'ajoute rien » alors que le ticket était bien créé. Il
  attend maintenant la **relecture de la liste** — signal qui vaut pour une création comme pour une
  fusion, là où attendre un changement de nombre de lignes ne finirait jamais dans le second cas.

### Une décision recopiée qui ne l'a pas été

Le contrôleur des tickets avait besoin de la liste des machines, déjà écrite dans celui du journal
des commandes. Plutôt que de la recopier — « une décision recopiée finit par diverger » —, elle
vit dans `App\Services\Machines`, et le journal y est rebranché. Le service porte en commentaire
la raison de son absence de filtre d'accès, et l'avertissement de ne pas la reprendre pour une page
ouverte à des comptes sans permission.

### Interface

Le formulaire de création utilise `rw-carte--pleine` : `.rw-carte` est plafonnée à 420 px, ce qui
convient à l'écran de connexion mais laissait ici deux colonnes à l'étroit et 1 200 px de vide à
côté.

### Septième page métier portée — recherche globale

`search` est porté sur `/recherche`, puis **archivé** : `legacy/search/` a rejoint
`legacy/_deprecated/`. L'URL legacy répond **404**, `index.php` et `js/main.js` aussi, et
l'entrée de menu du legacy mène au portage. Le menu du legacy compte **30 liens internes** contre
37 au départ — exactement les sept pages portées.

**Dernière page du gabarit.** Les sept parties bâties sur le même patron sont portées et
archivées. La suite (`update/`, `security/`, `supervision/`, `iptables/`, `adm/`) sont des modules
à plusieurs pages : ils demanderont des sous-lots.

### La recherche menait déjà à une page disparue

Le backend Python ne connaît qu'un frontend : il écrit les liens de ses résultats en dur vers
l'ancien portail — `/tickets/index.php`, `/adm/audit_log.php`, `/update/index.php`. **Chaque
partie archivée en transforme un en 404.** Mesuré sur le legacy pendant cette vague : une
recherche sur « Ticket » rendait trois résultats pointant vers `/tickets/index.php`, archivé à la
vague précédente — 404.

C'est le défaut relevé dans le legacy — sept 404 ont vécu dans un menu que personne ne suivait —
sauf qu'ici c'est la migration qui le fabrique, et il se serait aggravé à chaque vague.

**E-13** — `App\Support\LiensLegacy` traduit ces liens : une partie portée mène à sa route sans
marqueur, une partie encore servie par l'ancien portail y mène avec la **même flèche que le
menu**, `target="_blank"` et un `title` explicite. La table est construite une fois et servie
telle quelle au navigateur, pour qu'il n'en existe jamais deux versions.

**Mettre à jour cette table est désormais une étape du cycle d'archivage**, et le test de la
recherche la garde : il suit chaque lien rendu et vérifie qu'aucun ne répond 404.

### Trois attentes qui mesuraient autre chose

Cette page a coûté trois corrections de sonde, toutes de la même famille :

- **Attendre une condition déjà satisfaite.** « La ligne d'état est non vide » l'était avant
  toute frappe — la consigne « tapez au moins deux caractères » est affichée au chargement. Le
  test croyait n'avoir aucun résultat pour « Test-Server ».
- **Attendre un changement que l'état transitoire satisfait.** « La ligne d'état a changé » est
  vrai dès l'affichage de « Recherche… » : le test lisait alors les résultats de la recherche
  précédente. Les deux cibles annonçant « N résultat(s) pour "terme" », l'attente porte désormais
  sur la **citation du terme** — signal exact, et indépendant de tout libellé.
- **Une assertion creuse.** « La ligne d'état contient un chiffre » passait sur « Tapez au moins
  2 caractères ». Elle exige maintenant que la ligne cite le terme cherché.

Et une quatrième, sur le fond : exiger « il existe au moins un lien marqué » échouait sur une
recherche dont tous les résultats sont portés. Ce qui doit tenir est une **implication** — tout
lien sortant est marqué, aucun lien interne ne l'est.

### Ce qui n'est pas mesuré

**La latence.** Le montage de fichiers de ce poste est ~258× plus lent que le système du
conteneur ; l'écart relevé précédemment (2,2 s contre 24 ms) dirait surtout combien de fichiers
chaque cible charge. Il reste à re-mesurer sur un hôte Linux avant d'être traité comme un défaut.

### Interface

`display: block` sur le libellé du champ de recherche : un `<label>` est en ligne par défaut, et
`max-width` ne s'applique pas à un élément en ligne. Sans lui, le champ s'étendait sur 1 375 px.

### Inventaire du module `update/` — le premier qui ne se porte pas d'une pièce

Les sept pages précédentes tenaient en ~150 lignes chacune. `update/` en pèse **2 094** : 712 de
PHP et 1 382 de JavaScript, 27 fonctions, 13 routes backend. Le porter d'un bloc produirait un
commit qu'on ne peut ni relire ni tester. `docs/migration/MODULE-UPDATE.md` le mesure et le
découpe en six sous-lots — U1 parc et filtres, U2 journal, U3 constats sans effet, U4
planification, U5 redémarrage, U6 mises à jour — dans cet ordre, U6 en dernier.

Aucun code n'est modifié par cette vague : c'est un relevé, fait avant d'y toucher.

### Ce que la lecture du code a établi

**La permission garde la page, pas la capacité — et ici sur des commandes root.** Dix des douze
routes du module n'ont ni `require_role` ni `require_permission`, seulement
`require_machine_access` — lequel accorde tout le parc dès le rôle 2. Un compte rôle 2 sans
`can_update_linux` est refusé sur la page et peut néanmoins lancer `apt_update`, `custom_update`
ou `dpkg_repair`. C'est le même écart que sur les sauvegardes, mais il porte sur des actions
destructrices. **Non mesuré** : aucun compte de test n'a cette forme, et en fabriquer un
reviendrait à changer des droits.

**La fuite du mot de passe root est plus étroite que ce qui avait été annoncé.**
`execute_as_root_stream()` a trois branches ; seules celles qui envoient le mot de passe ouvrent
un PTY, et un PTY fait écho. La branche « compte de service » n'envoie aucun mot de passe.
`srv-zabbix` (production) a `service_account_deployed = 1` : elle prend cette branche. Les deux
machines de test ne l'ont pas.

Ce qui avait été signalé — « actif sur les serveurs réels » — était donc trop large : la fuite
concerne les machines **dont le compte de service n'est pas déployé**. La correction est portée
au document. Ce qui reste inexpliqué y est écrit comme tel : la défense « Patch A09 » devrait
couvrir la première ligne, et la mesure place pourtant le mot de passe en ligne 2 ; le mécanisme
n'est pas établi, il n'est donc pas décrit.

### Une hypothèse vérifiée, et fausse

`/list_machines` ne porte aucun décorateur de rôle. Lu ainsi, il paraissait exposer tout le parc
— IP et compte SSH compris — à n'importe quel compte authentifié. **Mesuré depuis une session
rôle 1 sans permission : 200 avec une liste vide.** La route ne délègue pas son cloisonnement à
un décorateur, elle le fait elle-même en joignant `user_machine_access`.

Consigné parce que la lecture seule menait à une accusation infondée : l'absence de décorateur
n'est pas l'absence de garde.

### Un doublon qui compte pour le portage

`list_machines` et `filter_servers` existent deux fois — points d'entrée PHP dans
`legacy/update/functions/`, et routes du backend Python. Le JavaScript du legacy appelle les PHP,
que le portage ne peut pas atteindre. Il passera par les routes backend, qui rendent **moins de
colonnes** : U1 devra combler l'écart sous peine de perdre la version Linux et l'horodatage du
dernier contrôle.

### Module `update/`, sous-lot U1 — parc et filtres

Premier morceau d'un module découpé. `/mises-a-jour` porte le tableau du parc (treize colonnes),
les filtres environnement / criticité / réseau, le rafraîchissement et les trois relevés par
machine — version Linux, disponibilité, dernier redémarrage. Lecture seule.

**La page legacy reste servie** : le lancement des mises à jour, la planification et le
redémarrage appartiennent à U3–U6. Pas d'archivage, pas de redirection du menu, pas d'entrée dans
`LiensLegacy` avant la fin du module. La page portée l'annonce dans un encart, avec un lien marqué
vers la page complète — faire disparaître des capacités sans un mot ferait croire qu'elles
n'existent plus.

**Garde reprise du legacy** : `role:1` + `perm:can_update_linux`. Le rôle 1 est donc **admis** s'il
porte la permission, et ne voit alors que les machines de `user_machine_access` — un cloisonnement
réel, reproduit à l'identique dans `App\Services\Machines::pourMisesAJour()`. **Non exerçable** :
aucun compte de test ne cumule rôle 1 et `can_update_linux`, et en fabriquer un reviendrait à
changer des droits. Le test le dit plutôt que de le passer sous silence.

### Rafraîchir la liste vidait une colonne

**E-14** — la page affiche treize colonnes, rendues au chargement depuis la base ; le legacy les
recharge depuis `update/functions/list_machines.php`, qui n'en `SELECT`ionne que onze.
`populateMachineTable()` lit pourtant `maj_secu_date`, `maj_secu_last_exec_date` et `last_reboot`,
avec un repli `?? "N/A"`.

Mesuré : la colonne « dernier redémarrage » passe de renseignée à vide au clic sur « Rafraîchir »,
sans qu'on l'ait demandé et sans rien annoncer. Les deux autres colonnes étaient déjà vides sur ce
parc — une colonne vide qui reste vide ne prouve rien, et c'est écrit ainsi plutôt que d'affirmer
une perte de trois colonnes qui n'a pas été observée.

Le portage fait passer le rafraîchissement **et** le filtrage par `/filter_servers`, qui rend les
quatorze colonnes, exclut les machines archivées et applique le même cloisonnement. Un
rafraîchissement ne peut plus appauvrir ce qui était affiché.

### Ce que U1 ne porte pas encore

Le filtre par **étiquette**. Le legacy le rend — un `<select>` alimenté par
`SELECT DISTINCT tag FROM machine_tags` — et `/filter_servers` accepte le paramètre `tag`. Il a
été manqué au relevé et n'est pas porté. C'est noté dans `MODULE-UPDATE.md` plutôt que U1 déclaré
clos.

### Une règle globale posée pour un cas particulier

`flex-wrap: wrap` avait été ajouté à `.rw-tableau__actions` pour que les trois boutons de relevé
tiennent dans leur colonne. Vu à l'image : ils s'empilaient, chaque ligne devenait trois fois plus
haute, et la classe est partagée avec les pages d'approbation et de sauvegarde. La règle est
désormais portée par un modificateur — `.rw-tableau__actions--releves` — et le débordement
appartient au cadre du tableau, qui défile et le dit.

### U1 complété — le filtre par étiquette

Le quatrième filtre du parc, manqué au relevé de la vague précédente et noté comme tel plutôt que
U1 déclaré clos. Il est porté : le contrôleur lit les étiquettes distinctes, le champ les propose,
et `/filter_servers` reçoit le paramètre `tag`.

**Les étiquettes sont écrites par `adm/`**, module non porté, et **aucune route backend ne permet
d'en poser**. La page ne fait que les lire. Un parc sans étiquette est un état normal : le champ
reste affiché mais désactivé, et son libellé dit « Aucune étiquette au parc » — plutôt qu'une
liste vide qui laisserait croire à une panne.

La table `machine_tags` était vide. Une étiquette de test (`banc-essai` sur `Test-Server-Debian`,
jamais sur la machine de production) sert de fixture ; le test la consomme sans la consommer —
elle est idempotente et n'épuise aucun espace de clés. Sans étiquette, le test constate que le
filtre n'est pas exerçable au lieu d'échouer.

### Deux assertions creuses, dans le même bloc

Le filtre par étiquette a d'abord été mesuré **par-dessus le filtre par environnement resté
actif**. « 3 → 2 » passait, et les deux lignes rendues étaient celles de l'environnement. Une
assertion qui mesure la combinaison de deux filtres ne dit rien du second.

Corrigé en deux temps :

- l'attente exige désormais que le résultat soit **exactement la machine étiquetée**, pas un
  simple décompte — un filtre inopérant qui laisse un autre filtre actif ne peut plus passer ;
- les autres filtres sont remis à zéro **et le parc complet réaffiché** avant de mesurer. Sans ce
  retour à un état connu, l'attente « le nombre de lignes a changé » était déjà vraie — l'écran
  portait encore les deux lignes du filtre précédent — et la sonde rendait la main sur un rendu
  périmé. C'est la troisième fois que cette famille de piège se paie : **attendre une condition
  déjà satisfaite n'attend rien**.

### Module `update/`, sous-lot U2 — le journal d'exécution

Présentation pure : aucune route backend. Le journal est alimenté par les autres sous-lots, qui
l'atteindront par `window.rwJournal`. Porté avec son contrat complet — un panneau par serveur créé
une seule fois, en-tête fixe avec case « Suivre », ligne de progression qui se remplace, suivi
automatique qui se désactive quand on remonte lire.

**Correction d'une lecture faite trop vite** : `getServerLogWindow` n'ouvre **aucune fenêtre
navigateur**. Il crée un panneau dans la page. L'inventaire du module parlait de « fenêtres par
serveur », ce qui laissait entendre des popups — ce n'en sont pas.

### `appendLog` était défini deux fois

**E-15** — dans `domManipulation.js`, qui écrit dans la zone générale `#logs`, puis dans
`apiCalls.js`, qui écrit dans `#logs-container`. Deux déclarations globales, `apiCalls.js` chargé
en second : sa définition gagne, l'autre est du code mort.

Mesuré :

- **`#logs` n'est alimentée par personne** — la page rend un cadre qui reste vide quoi qu'il
  arrive ;
- **les messages généraux se déposent parmi les panneaux de serveur**, `appendToLogs()` appelant
  `appendLog()` sans nom de serveur ;
- **`clearLog()` vide une zone toujours vide**, et cinq fonctions l'appellent.

Troisième occurrence de ce défaut dans le projet : `escHtml()` défini deux fois dans le legacy,
`.rw-etiquette` dans notre propre feuille de style (E-12), et maintenant `appendLog`. Une
déclaration globale ne signale jamais qu'elle en écrase une autre.

Le portage expose un point d'entrée **unique et nommé**, déclaré dans une fermeture. Un message
sans serveur va dans la zone générale, qui est réellement affichée et **dit qu'elle est vide**
quand elle l'est.

### Un bouton pour vider

Le legacy n'expose `clearLogs()` qu'à ses actions internes : rien ne permet de repartir d'un
journal propre à la main. Le portage ajoute le bouton, avec une infobulle qui précise qu'il
n'efface **aucune trace enregistrée** — la traçabilité durable vit dans le journal des commandes.

### Deux détails d'assertion qui annonçaient l'inverse du résultat

`verifie('...', vrai, 'introuvable dans les deux zones')` affichait « introuvable » sur un **PASS**.
Le détail d'une attente décrit ce qu'on a **mesuré**, pas ce qu'on aurait dit en cas d'échec. Deux
occurrences corrigées dans le test de U2.

### Une capture qui s'arrêtait au pli

La capture de la page ne montrait pas le journal : il vit sous le pli, et la prise de vue est de la
hauteur du champ visible. Elle fait maintenant défiler jusqu'à lui avant de photographier — sans
quoi elle ne montrait rien de ce qui venait d'être porté.

### Module `update/`, sous-lot U3 — le constat des paquets en attente

Porté : « paquets en attente ». **Non porté : la simulation** — la raison est mesurée plus bas.

Ce qui a été **lu dans `backend/routes/updates.py` avant tout clic**, comme la méthode l'exige :
`/pending_packages` ouvre une session SSH et lance en root
`apt-get update -qq 2>/dev/null; apt list --upgradable`. Elle n'installe rien et ne supprime rien.
Elle n'est pas pour autant *sans effet* : `apt-get update` **réécrit l'index local des paquets** de
la machine. Le sous-lot s'appelait « les constats sans effet » ; c'est une écriture, même si ce
n'est pas un changement d'état du système, et l'inventaire du module le dit maintenant.

Le backend **découpe lui-même** la sortie et ne renvoie que des noms et des versions : aucune ligne
brute ne remonte au navigateur. C'est ce qui permet de porter ce constat-ci.

L'action est groupée sur la sélection, comme dans le legacy. Elle porte un **compteur de
sélection** : la règle « il faut au moins une machine » se lit *avant* le geste au lieu de se
découvrir après. Le résultat s'écrit dans le journal d'exécution porté en U2, par
`window.rwJournal`, sur le panneau du serveur concerné. Une machine qui ne répond pas est nommée,
et le constat n'est alors pas annoncé comme réussi.

### « Aucun paquet en attente » ne veut pas dire « la machine est à jour »

**E-16.** Dans la commande ci-dessus, la stderr d'`apt-get update` part dans `/dev/null` et les
deux commandes sont séparées par un **point-virgule** et non par `&&`. `apt list` s'exécute donc
même quand le rafraîchissement a échoué, et rend l'ancien index. La réponse vaut
`{"success": true, "count": 0}` dans les deux cas.

Mesuré sur la machine 2, à quelques minutes d'intervalle : `/pending_packages` a répondu
`count: 0`, pendant que le flux de la simulation sur la **même machine** portait
`W: Failed to fetch ... Temporary failure resolving 'deb.debian.org'` puis `Some index files failed
to download. They have been ignored, or old ones used instead.` Le rafraîchissement avait échoué et
le constat annonçait « rien à faire ».

Le portage ne peut pas rendre une information que le backend a jetée. Il cesse en revanche de
promettre plus que ce que la fonction fait : l'état vide porte une seconde ligne disant que le
constat lit l'**index local** et ne garantit pas qu'il ait pu être rafraîchi.

### La simulation n'est pas portée : son flux porte le mot de passe root

**E-17.** `/dry_run_update` rend `Response(generate(), 'text/plain')` — le flux SSH tel quel — et le
legacy dépose **chaque ligne non vide** de ce flux dans le journal. Mesure sur la machine 2 : la
deuxième ligne du flux est le **mot de passe root en clair**.

Mécanisme, établi cette fois : `execute_as_root_stream()` porte un correctif (« Patch A09 ») qui
jette tout ce qui précède le premier `\n`, en supposant que l'écho PTY du mot de passe est la
première ligne. Reproduction du même enchaînement sur une commande inoffensive (`id -u`), morceaux
bruts lus sur le canal : `'<mot de passe>\r\n'`, `'<mot de passe>\r\n'`, `'0\r\n'`. **Le mot de
passe est échoté deux fois** ; le correctif n'en jette qu'un.

La branche `service_account` (sudo NOPASSWD, sans PTY ni mot de passe) n'est pas concernée. Seule
`srv-zabbix` porte `service_account_deployed = 1` : **toutes les autres machines du parc sont dans
le cas qui fuit**.

Rien n'a été corrigé — c'est le backend Python, qui reste intact, et c'est une décision de sécurité.
Trois points sont posés dans `PARITE.md` (E-17) : corriger la fonction, retirer ou non
`/dry_run_update` de la liste blanche de la passerelle, et l'ordre à tenir pour U6, dont
`/security_updates` diffuse par la **même** fonction.

### Vérification

Nouveau test `tests/e2e/go-page-update-u3.mjs`, vert sur les deux cibles avant le commit :
9 PASS / 0 FAIL côté legacy, 15 PASS / 0 FAIL côté Laravel. Il mesure en **requêtes** (aucun appel
n'est émis sans machine cochée ; un seul appel pour la machine cochée ; la machine 1, en production,
n'est jamais désignée) et attend **le contenu** — la ligne dans le panneau du serveur, puis le
bouton redevenu actif — plutôt qu'un délai. Il vérifie aussi qu'aucune partie du portage n'appelle
`/dry_run_update`.

### Module `update/`, sous-lot U4 — la planification

Portées : la planification générale et la planification de mise à jour de sécurité. Ce que les
deux routes font, **lu avant tout clic** : elles écrivent un fichier dans `/etc/cron.d/` sur la
machine distante, en root, puis redémarrent cron. La seconde écrit en plus `machines.maj_secu_date`
dans la base partagée.

Le legacy présente deux fenêtres modales qui répètent le même formulaire ; le portage n'en pose
qu'un, ouvert par les deux actions de la ligne, et adapte son titre, sa description et sa route.

### La planification générale n'avait jamais rien planifié

**E-18.** `saveAdvancedSchedule()` envoie `{machine_id, date, time, repeat}` à `/schedule_update`,
qui attend `interval_minutes` et refuse **avant toute session SSH**. Mesuré sur la machine 2 depuis
la page legacy : réponse **400**, et `/etc/cron.d/auto_update_advanced` **absent** après le geste.

La route dont le contrat correspond au formulaire existe — `/schedule_advanced_update` — et
personne ne l'appelle. Symétriquement, la fonction qui respecte le contrat de `/schedule_update`,
`scheduleUpdate()`, lit `#update-interval`, un élément qui n'existe nulle part dans la page, et
n'a elle-même aucun appelant. Les deux moitiés sont là, elles ne se rejoignent pas.

Le portage appelle la route qui correspond au formulaire. Porter fidèlement aurait porté un bouton
qui échoue à chaque clic.

### La récurrence promet ce que cron ne sait pas exprimer

**E-19.** cron n'a pas de champ année : « ne pas répéter » écrit `mm hh JJ MM *`, qui revient
**chaque année**. Le seul choix qui promet une exécution unique en programme une infinité.

Et le même mot ne veut pas dire la même chose selon le formulaire : la planification générale place
l'hebdomadaire le **lundi** et le mensuel le **premier du mois**, quelle que soit la date choisie,
là où la planification de sécurité suit la date. Mesuré sur la machine 2, avec le **mardi**
15/09/2026 à 03:30 en « toutes les semaines » : `30 03 * * 1` d'un côté, `30 03 * * 2` de l'autre.

Le portage affiche, **avant le geste**, l'expression cron qui sera écrite et sa lecture en clair,
avec la réserve quand elle s'applique — et seulement quand elle s'applique. Le test compare
l'**aperçu affiché** au **fichier posé sur la machine** : une promesse d'écran et une réalité de
machine, deux artefacts indépendants.

### La colonne des actions ne pouvait plus être atteinte

Cinq boutons par ligne au lieu de trois : la colonne, **dernière de treize**, sortait entièrement
du champ à 1920 px — seul le premier bouton restait visible. La borner ne changeait rien, puisque
c'était sa position qui la mettait hors d'atteinte. Elle est remontée juste après le nom du
serveur et se replie dans une largeur bornée. Les lignes sont plus hautes ; les données, elles, se
parcourent en défilant sans dommage. Le commentaire de la règle CSS, qui plaidait le contraire
depuis U1, a été récrit avec elle.

### Ce que U4 a montré sans que ce soit un défaut de parité

- Le serveur de test **n'a pas de démon cron** : `systemctl restart cron || service cron restart
  || true` réussit silencieusement, le fichier est écrit et rien ne le lira. Le test mesure donc le
  **fichier**, ce qui est exactement ce que la route produit — et aucun `apt full-upgrade` ne peut
  se déclencher sur le banc d'essai.
- Le cron de sécurité embarque un **jeton HMAC** (`X-Update-Token`) dans un fichier en **0644**. Ce
  jeton ne permet qu'une chose, et pour cette machine seulement : marquer `maj_secu_last_exec_date`
  à l'instant présent. Un utilisateur local de la machine peut donc la faire passer pour « mise à
  jour » sans qu'elle le soit. La défense tient contre un porteur de compte du portail, pas contre
  un utilisateur local de la machine concernée. Signalé, non corrigé — c'est le backend.

### Vérification

Nouveau test `tests/e2e/go-page-update-u4.mjs`, vert sur les deux cibles avant le commit :
7 PASS / 0 FAIL côté legacy, 14 PASS / 0 FAIL côté Laravel. Il **relit le cron sur la machine 2**
par `tests/e2e/cron-machine.py`, exécuté dans le conteneur du backend — une planification qu'on ne
relit pas n'est pas prouvée. Il nettoie avant **et** après : les deux fichiers cron effacés,
`maj_secu_date` remise à NULL.

### Module `update/`, sous-lot U5 — le redémarrage

Ce que fait la route, **lu avant tout clic** : `/reboot_server` est la seule route mutante du module
à exiger un rôle (`@require_role(2)`), et elle passe **deux gardes avant toute session SSH** — la
fenêtre de maintenance (423 en dehors) puis l'approbation à quatre yeux (202 avec l'identifiant de
la demande). Elle ne laisse passer que dans trois cas : action non soumise à approbation, demandeur
superadmin, ou **demande déjà approuvée** — consommée, et le redémarrage part. C'est ce dernier cas
qui a envoyé deux redémarrages réels sur la machine 2 le 2026-08-18.

### Avant l'action la plus destructive, le legacy affiche la clé de traduction

**E-20.** `rebootSelected()` pose deux `confirm()` natifs. Les deux textes existent, longs et
soignés, dans `legacy/lang/fr/updates.php` : ils énumèrent les sessions coupées, les services
interrompus, l'absence de retour en arrière. Mais ils vivent dans le catalogue **PHP**, lu par
`t()`, alors que `__()` lit le catalogue **`js.`**.

Dialogues capturés au vol sur la page legacy : « **updates.reboot_confirm1** » puis
« **updates.reboot_confirm2** ». L'opérateur voit deux fois un identifiant technique — aucune
conséquence, aucun nom de machine, aucun décompte.

Et les deux boîtes posent la **même** question : deux « OK » d'affilée sont un réflexe, pas deux
décisions.

### Le portage empêche l'erreur au lieu de la répéter

**E-21.** La décision se prend en ligne, dans un panneau qui nomme les machines, dit ce qui sera
interrompu, et annonce **avant le geste** que la demande sera mise en attente et non exécutée. Le
bouton de confirmation naît **désactivé** et ne s'active que si le nombre de machines est recopié —
mesuré : « 2 » saisi pour une machine laisse le bouton inerte, « 1 » l'active.

**Le délai est offert.** `/reboot_server` accepte `delay_minutes` de 0 à 1440 et lance alors
`shutdown -r +N`, qui prévient les sessions ouvertes ; le legacy envoie toujours `0`. Le portage
propose immédiat, 5 min, 15 min, 1 heure — une capacité que le backend avait et que l'interface
cachait.

**Une demande d'approbation n'est pas une erreur.** Le backend rend `202` avec `success: false` et
`pending_approval: true` ; le legacy ne regarde que `success` et peint en rouge le fonctionnement
nominal de la règle des quatre yeux. Le portage lit `pending_approval` et annonce la demande avec
son numéro. Mesuré : zéro ligne d'erreur dans le panneau après la demande.

**Le journal range la ligne sous le nom de la machine.** Le legacy cherche
`getElementById('server-' + id)`, un élément qui n'existe pas dans la page, et retombe sur `#<id>`.
Mesuré, après la même demande : panneau `#2` côté legacy, `Test-Server-Debian` côté portage.

### Un test de redémarrage qui ne redémarre pas — et qui le prouve

Le test ne joue jamais de redémarrage, et ne se contente pas de l'affirmer : il se connecte en
**rôle 2** (jamais 3, que la porte laisse passer), **vérifie avant de cliquer** qu'aucune demande
approuvée n'attend d'être consommée — et s'arrête sans rien faire sinon —, puis compte les traces
`command_log` de contexte `reboot` **avant et après**. Elles ne s'écrivent qu'après l'exécution
SSH : inchangées, la commande n'est jamais partie. Relevé : `2` avant, `2` après, sur les deux
cibles. La demande créée est effacée à la fin.

### Une attente fixe qui passait seule et échouait en série

Le test U2 attendait 2 500 ms après un filtrage avant de lire le journal. Joué seul il passait ;
enchaîné derrière deux autres suites, il échouait — « aucune trace ». La trace arrivait, plus tard.
L'attente interroge désormais le journal jusqu'à ce qu'il porte quelque chose. C'est la règle déjà
payée trois fois : viser le contenu attendu, jamais un délai.

### Vérification

Nouveau test `tests/e2e/go-page-update-u5.mjs`, vert sur les deux cibles : 9 PASS / 0 FAIL côté
legacy, 17 PASS / 0 FAIL côté Laravel. Le garde-fou d'état vit dans `tests/e2e/reboot-garde.py`,
qui ne touche aucune machine — il lit et nettoie la seule base.

### Correctif backend — le mot de passe root ne sort plus dans le flux SSH (v1.37.17)

**Ce concerne aussi l'ancien portail**, pas seulement le portage : les deux consomment la même
fonction. À reporter sur `main`.

**Symptôme, mesuré.** Les routes qui diffusent leur sortie SSH en direct — `/dry_run_update` et
`/security_updates` — plaçaient le **mot de passe root en clair à la deuxième ligne** du flux rendu
au navigateur. Le legacy dépose chaque ligne de ce flux dans le journal d'exécution : le mot de
passe s'affichait donc à l'écran. Reproductible 3 fois sur 3.

Périmètre : toutes les machines dont le compte de service **n'est pas déployé** — soit, sur ce
parc, toutes sauf `srv-zabbix`. La branche `service_account` (sudo NOPASSWD, sans PTY ni mot de
passe) n'a jamais été concernée.

**Cause racine.** `execute_as_root_stream()` portait un correctif — commenté « Patch A09 » — qui
jetait tout ce qui précède le **premier saut de ligne**, en supposant que l'écho PTY du mot de
passe est la première ligne renvoyée. La supposition était juste ; ce qui était faux, c'est qu'il
n'y en aurait **qu'une**.

Reproduction du même enchaînement sur une commande inoffensive (`sudo -S -p '' sh -c 'id -u'`, PTY,
écriture immédiate du mot de passe), morceaux bruts lus sur le canal :

```
morceau 1 : '<mot de passe>\r\n'
morceau 2 : '<mot de passe>\r\n'
morceau 3 : '0\r\n'
```

Le mot de passe est **échoté deux fois**. Le filtre en jetait un ; le second traversait.

**Correctif.** Le filtre ne porte plus sur une **position** mais sur le **contenu** : sur une
fenêtre bornée de début de flux, toute **ligne complète égale au secret** est jetée, quel que soit
son rang, et les autres passent. Il couvre ainsi l'écho double, l'écho unique, l'absence d'écho, et
l'invite « Mot de passe : » que `su` écrit avant.

Le texte est bufferisé jusqu'au saut de ligne : un écho scindé sur une frontière `recv(4096)` est
reconstitué **avant** d'être comparé — ce qu'un simple `replace` ne savait pas faire, et qui était
la raison d'être du correctif précédent. La fenêtre est bornée **en lignes et en octets** pour que
le flux ne puisse jamais rester bloqué dans le tampon.

La logique est remontée au niveau module, dans `filtre_echo_mot_de_passe()` : une règle qui protège
un secret ne doit pas vivre enfermée dans une fermeture où rien ne peut l'éprouver.

**Tests.** `backend/tests/test_ssh_echo_mot_de_passe.py`, 11 cas : l'écho double (le défaut mesuré),
l'écho simple, l'absence d'écho, l'écho scindé entre deux lectures, l'invite de `su` avant l'écho,
une ligne qui *cite* le secret sans l'être, les deux bornes de la fenêtre, le fragment final sans
saut de ligne, le secret vide, et l'absence de tout fragment de six caractères.

Le fichier charge le **vrai** module par `importlib` : `conftest.py` remplace `ssh_utils` par un
`MagicMock`, et un mock se laisse dépaqueter en silence — le test aurait été vert sans rien
mesurer.

Suite backend complète : **296 tests verts**.

**Vérification en direct**, sur la machine 2, avant/après :

| | Ligne 2 du flux de `/dry_run_update` |
|---|---|
| avant | le mot de passe root, en clair (3 essais sur 3) |
| après | `W: Failed to fetch ...` — la vraie sortie (4 essais sur 4) |

Aucun fragment de six caractères du mot de passe ne subsiste, et la sortie de la commande est
intacte (42 lignes contre 43 : la ligne d'écho en moins).

**Ce que cela débloque.** Le sous-lot U6 du module `update/` — les mises à jour de sécurité, qui
diffusent par cette même fonction — et la simulation, restée au legacy pour cette raison (E-17).

### Module `update/`, sous-lot U6a — la simulation et les mises à jour de sécurité

Les deux actions qui **diffusent** leur sortie. Elles n'étaient pas portables tant que leur flux
portait le mot de passe root ; le correctif v1.37.17 lève cette raison, et la simulation — restée
au legacy depuis U3 — rejoint le portage.

Ce que font les routes, **lu avant tout clic** : `/dry_run_update` lance
`apt-get update && apt-get upgrade --dry-run` et n'installe rien. `/security_updates` lance
`apt-get update && apt-get upgrade --only-upgrade -y` et **installe**.

### Ce que le libellé du legacy ne dit nulle part

`/security_updates` commence par vérifier si apt ou dpkg tourne déjà. Si c'est le cas, elle fait un
`killall -9 apt apt-get dpkg`, **supprime les fichiers de verrou** et lance `dpkg --configure -a`
avant de continuer. Une installation en cours ailleurs est donc interrompue sans préavis. Le
panneau de décision du portage le dit **avant** le geste ; le bouton « Appliquer » naît désactivé
et ne s'active que si l'on recopie `SECURITE`.

### Le mot de passe root, vérifié sur le journal réellement affiché

Le test compare le journal **tel qu'il apparaît à l'écran** au mot de passe de la machine, via
`tests/e2e/secret-absent.py` exécuté dans le conteneur du backend — le secret n'en sort jamais, et
le script ne répond que par ABSENT ou PRESENT. Vérifié sur les **deux cibles**, après la simulation
et après la mise à jour : ni le mot de passe entier, ni le moindre fragment de six caractères. Le
correctif protège donc aussi l'ancien portail, et c'est mesuré.

### La passerelle relaie les flux morceau par morceau

`RoutesBackend::EN_FLUX` nomme les deux routes dont le corps est un flux ; pour elles, la passerelle
ne lit plus tout le corps avant de répondre — elle relaie par morceaux de 8 Kio, avec un délai
propre (`BACKEND_TIMEOUT_FLUX`, 900 s par défaut). Une mise à jour de sécurité dépasse largement les
120 s ordinaires, et garder plusieurs minutes de sortie en mémoire n'a pas de sens.

**Ce que la mesure dit du direct, et qui corrige une hypothèse de départ.** Je pensais que le legacy
affichait la progression ligne à ligne et que buffer serait une régression. Mesuré : le backend
livre son corps **d'un seul tenant** entre conteneurs — Guzzle reçoit les en-têtes à 0,5 s puis les
1 076 octets d'un coup à 7,5 s. Aucune des deux interfaces n'affiche donc de progression
aujourd'hui. Le relais par morceaux reste juste et utile — il ne bufferise pas de notre côté et
suivra si le backend se met à livrer progressivement — mais il ne faut pas lui prêter un direct
qu'il n'a pas.

### `hidden` ne cachait pas — trouvé en regardant la capture

La feuille du navigateur applique `[hidden] { display: none }` avec une spécificité nulle :
`.rw-panneau-decision { display: flex }` la battait. Le panneau de décision du redémarrage restait
donc **à l'écran** en permanence, et la capture a montré deux panneaux ouverts côte à côte.

Pire : le test de U5 lisait `p.hidden`, **l'attribut**, et déclarait donc caché un panneau bien
visible. Une assertion qui mesurait autre chose que ce qu'elle croyait — la même famille de défaut
que celles déjà payées.

Trois corrections : `[hidden] { display: none !important; }` rend la convention fiable pour tous les
composants ; ouvrir un panneau de décision **referme les autres** — trois décisions concurrentes sur
la même sélection ne peuvent que tromper ; et les tests mesurent désormais le **rendu**
(`getClientRects()`), pas l'attribut.

### Vérification

Nouveau test `tests/e2e/go-page-update-u6.mjs`, vert sur les deux cibles : 8 PASS / 0 FAIL côté
legacy, 13 PASS / 0 FAIL côté Laravel. Le test de U3, qui affirmait que la simulation n'était pas
portée, assert désormais l'inverse — cette assertion avait fait son temps.

### Module `update/`, sous-lot U6b — la mise à jour complète et la réparation dpkg

Le module `update/` est **entièrement porté** pour ce que l'ancienne page offrait réellement.

Ce que font les routes, **lu avant tout clic**. `/update` consulte la fenêtre de maintenance
(423 dehors), puis — si apt ou dpkg tourne déjà — les **tue** (`killall -9`), supprime leurs quatre
verrous et lance `dpkg --configure -a`, avant seulement de diffuser
`apt update && apt full-upgrade -y`. C'est un flux, ajouté à `RoutesBackend::EN_FLUX`.
`/dpkg_repair` fait `killall -9 apt apt-get dpkg`, `rm -f` sur les quatre verrous, puis
`dpkg --configure -a`, et rend du JSON.

Le panneau de décision est **générique** : les deux actions ont la même forme — nommer les
machines, dire les conséquences, dire la réserve, exiger un mot recopié (`MISE A JOUR`, `REPARER`).
U4, U5 et U6a en ont chacun un ; en ajouter deux de plus n'aurait rien appris à la page.

### Deux routes du serveur ne sont pas portées, et c'est un constat mesuré

**E-22.** `/apt_update` et `/custom_update` existent côté backend, mais **aucun bouton de l'ancienne
page ne les appelle** : `aptUpdate()` (`apiCalls.js:444`) et `customUpdate()` (`apiCalls.js:490`)
n'ont aucun appelant, et lisent cinq éléments de formulaire — `#apt-method`, `#specific-packages`,
`#excluded-packages`, `#update-packages`, `#exclude-packages` — **absents de la page**. Chacune
lèverait un `TypeError` dès sa première ligne si on l'atteignait.

C'est le troisième cas de cette famille dans ce module, après `scheduleUpdate()` (E-18) et
`#server-<id>` (E-21). Le test le **constate sur la cible legacy** plutôt que de le supposer :
aucun `onclick` ne les nomme, et les cinq champs sont introuvables.

Les porter reviendrait à **inventer une capacité**, pas à en migrer une. La page le dit à l'écran
plutôt que de les faire disparaître en silence : l'encart, qui annonçait un portage partiel,
énumère désormais ce qui n'est **pas** repris et pourquoi.

### Ce que la relecture du portage a trouvé

Le fichier `mises-a-jour.js` a grossi sur sept sous-lots. Une relecture intégrale a sorti quatre
défauts, dont un que je venais d'introduire :

- **`fermeLesAutresPanneaux` ignorait le panneau de U6b.** Ouvrir « Mise à jour complète » puis
  « Redémarrer » laissait **deux panneaux ouverts**, deux boutons de confirmation activables et
  deux sélections figées en même temps. Le docblock disait « trois panneaux » ; il y en a quatre.
- **La planification ne réinitialisait aucun champ à l'ouverture.** Planifier sur une machine,
  fermer, rouvrir sur une autre : la date de la première restait, l'aperçu la déclarait valide et
  **le bouton naissait actif**. Un clic posait le cron avec la date d'une autre machine. Les trois
  autres panneaux repartaient d'un état connu ; celui-là non. Et `sched-save` était le seul bouton
  de confirmation sans `disabled` dans la vue.
- **Un `fetch` qui rejette laissait cinq boutons figés pour toujours.** Le `try` d'`appelle()`
  n'entourait que `r.json()`, pas `fetch()` : une coupure réseau remontait à l'appelant, qui
  s'arrêtait **avant** de réactiver son bouton. Corrigé à la source — `appelle()` ne rejette plus,
  il rend un échec explicite que chaque appelant sait déjà annoncer, et l'erreur part en console
  plutôt que d'être avalée.
- **Trois masquages de portée** : `message`, `corps` et `heure` redéclarés dans des blocs
  imbriqués. Rien ne cassait, mais c'est la famille `escHtml` / `appendLog` / `.rw-etiquette`,
  payée trois fois. Renommés.

### Une attente qui s'arrêtait avant la première ligne

Le test attendait que le journal **cesse de changer**. Or entre l'envoi de la requête et l'arrivée
du flux, il porte déjà l'annonce « en cours » et ne bouge plus pendant qu'apt travaille : l'attente
s'arrêtait donc **avant** la sortie — 5 lignes relevées côté portage contre 128 côté legacy. Elle
vise maintenant le contenu attendu. Quatrième fois que cette règle se paie.

Et le test perdait sa sélection entre deux actions : le legacy relit le parc après une mise à jour
et re-rend le tableau, ce qui décoche tout. La machine de test est désormais retenue **avant chaque
action**, et le test le vérifie.

### Quatre boutons rouges ne signalent plus rien

La barre porte six actions, dont quatre destructives. Toutes en rouge, aucune ne ressort. Le rouge
reste pour ce qui **interrompt un service** — réparation dpkg, redémarrage ; les deux mises à jour
prennent une teinte d'avertissement.

### Vérification

Nouveau test `tests/e2e/go-page-update-u6b.mjs`, vert sur les deux cibles : 14 PASS / 0 FAIL côté
legacy, 20 PASS / 0 FAIL côté Laravel. Il vérifie aussi que le mot de passe root reste absent du
journal après les deux actions, sur les deux cibles.

### Ce qui reste à signaler, non corrigé

- **`/apt_update` et `/dpkg_repair` ne consultent pas la fenêtre de maintenance**, là où `/update`,
  `/security_updates` et `/custom_update` le font. `dpkg_repair` tue des processus apt et supprime
  des verrous **sans fenêtre, sans approbation et sans permission**.
- **`/custom_update` et `/dpkg_repair` n'écrivent aucune trace bastion.** La plus destructive des
  trois est la moins tracée.
- **`/apt_update` journalise sous le contexte `custom_update`** (`updates.py:461`) : les traces
  d'un `full-upgrade` se rangent sous le nom d'une autre route.
- **`apt-mark unhold` n'est pas dans un `finally`** : si `apt-get` lève, les paquets exclus restent
  `hold` indéfiniment sur la machine.
- **Les noms de paquets non conformes sont filtrés en silence** : un envoi partiellement invalide
  reçoit un 200 de succès alors que seule une partie a été traitée.
- **Les cinq actions de la page ne s'excluent pas mutuellement** : rien n'empêche de lancer une
  réparation dpkg pendant une simulation, alors qu'elle tuerait l'apt de celle-ci.

### Premier module archivé — `update/`

`update` est porté sur `/mises-a-jour` par sept sous-lots (U1 à U6b), puis **archivé** :
`legacy/update/` a rejoint `legacy/_deprecated/`. **Neuf URL** répondent 404 — la page, les deux
scripts et les cinq `functions/*.php` — là où elles rendaient 302 ou 200 avant. Le couple
302 → 404 est mesuré des deux côtés ; sans le premier, le second ne prouverait rien.

Les sept archivages précédents portaient sur des **pages** du même gabarit. Un module a plus de
portes : `update/` avait **quatre** points d'entrée, dont trois qu'aucun archivage n'avait
rencontrés — le tiroir mobile (`menu.php:233`, écrit à la main, sans `$sideLink`), le raccourci
clavier `g` puis `u` (`head.php:208`) et la tuile du tableau de bord (`index.php:366`).

### La page portée n'était pas atteignable depuis le menu

Trouvé en relisant `App\Support\Navigation` : l'entrée `updates` portait encore
`'legacy' => '/update/'`. `/mises-a-jour` existait depuis sept sous-lots et **n'était joignable que
par URL directe** — chaque clic sur « Mises a jour » dans le portail neuf renvoyait à l'ancien.

**Porter une page ne la rend pas atteignable.** Deux menus se redirigent, celui du legacy *et*
celui du portage. Les sept pages précédentes n'avaient pas ce défaut parce qu'elles étaient nées
avec leur entrée `route` ; celle-ci a traversé sept sous-lots avec son entrée `legacy`.

### Le menu menait au portage, et le lien ne répondait pas

Le défaut le plus utile de cet archivage, et il ne vient pas de `update/`.

`verifieMenuLegacy()` vérifiait que le `href` **cite** la route portée. Il ne l'a jamais suivi.
Mesuré : `LARAVEL_URL` valait `https://localhost:8444` alors que le portage écoute **en clair** sur
ce port — la poignée de main TLS échoue franchement. Les **huit** entrées redirigées, les sept
précédentes comprises, menaient à un lien mort depuis le 2026-08-18, et huit suites vertes le
disaient réparé.

L'assertion mesurait la chaîne, pas l'accessibilité. `archive.mjs` suit désormais le lien et
vérifie qu'il répond ; les sept suites déjà archivées passent de 4 à **5 PASS**. La valeur a été
corrigée dans `srv-docker.env` (local, jamais commité) ; `srv-docker.env.example` garde
`https://${SERVER_NAME}:${LARAVEL_PORT}`, juste en production derrière TLS.

### `LiensLegacy` cesse d'être préventif

Pour les sept pages, la table des remplacements était une précaution : le backend n'émettait aucun
de ces chemins. Ici, `backend/routes/search.py` écrit `/update/index.php` **en dur pour chaque
machine trouvée**. Sans `'/update/' => 'mises-a-jour'` dans le même commit que le déplacement, la
recherche globale mène à un 404 mesurable — c'est E-13, et le test de la recherche l'attrape.

### Une suite retirée, et le trou qu'elle cachait

`go-update-filter.mjs` gardait la régression v1.37.12 — le bouton « Filtrer » doit **repeupler** le
tableau, et non lever un `TypeError` sur une mauvaise clé JSON. Codée en dur sur le legacy, sans
bascule de cible, elle serait rouge en permanence : « après quoi plus personne ne lit les rouges ».

Avant de la retirer, il fallait prouver que sa régression était couverte. Elle ne l'était pas tout
à fait : `go-page-update-u1.mjs` assertait `filtre.machines.every(m => …)`, et **`[].every()` rend
`true`** — un tableau vidé passait au vert, c'est-à-dire exactement le défaut gardé. U1 assert
maintenant d'abord que le filtre repeuple le tableau, sur un environnement que le parc porte.

Quatre suites hors-lot citaient encore la page. `go.mjs` et `go-sec-v1.23.mjs` ne la visitent plus ;
`go-security-fixes.mjs` retourne son assertion `200` en `404` et devient témoin de l'archivage ;
et l'étape [6] de `06-supervision.test.mjs` est retirée — elle vérifiait l'**absence** d'un
sélecteur sur `/update/`, or sur une page 404 il est absent aussi : elle serait passée au vert sans
rien mesurer. Un faux vert vaut moins que pas de test.

### Ce que l'archive rend à sa nouvelle adresse

`legacy/_deprecated/` n'est protégé par aucun `.htaccess` ni règle Apache — le dossier reste sous
la racine documentaire. `update/` est le premier à y poser des **points d'entrée serveur**, les cinq
`functions/*.php`. Mesuré : ils rendent **500 avec un corps vide**, leurs `require_once` relatifs ne
résolvant plus d'un niveau plus bas. Aucune donnée n'est servie — mais c'est un accident de chemin,
pas un garde. À mesurer à chaque archivage plutôt qu'à supposer.

### Ce que l'archivage emporte

`/apt_update` et `/custom_update` (E-22) ne sont pas portées : leur code JS existait sans appelant
et lisait cinq champs absents de la page. Le serveur sait toujours les faire ; l'encart de la page
portée le **dit**, et ne renvoie plus vers une page qui n'existe pas — son lien vers l'ancien
portail a été retiré avec la clé i18n correspondante.

Le test de la vague 0 collecte **29 liens internes** contre 30 avant. La baisse est de **un** alors
que quatre points d'entrée ont été redirigés : il ne collecte que la barre latérale depuis
`/index.php`. La formule des sept pages — « exactement les N entrées redirigées » — ne vaut plus
pour un module.

### Bascule du poste de developpement vers une VM Debian

Le developpement quitte Windows pour une VM Debian 13 (`192.168.0.245`). Deux scripts portent la
bascule : `scripts/migrer-vers-vm.sh` (poste source, avec `--dry-run`) et
`scripts/installer-sur-vm.sh` (moitie distante).

Le depot passe par **`git bundle`** et non par un `git clone` : les commits de
`Migration-Laravel` n'etaient pousses nulle part, le depot distant ne les connaissait pas.
`srv-docker.env`, `laravel/.env`, un `mysqldump` et la memoire du projet suivent a part — aucun
n'est suivi par git.

**Deux pieges payes pendant la bascule.** Le bloc distant etait d'abord embarque dans un heredoc,
lui-meme dans une chaine passee a `eval` : trois couches de citation, les `$` sont arrives
litteralement et `apt-get` a recu « $besoin » comme nom de paquet. Il vit desormais dans son propre
fichier. Et `mysqladmin ping` REUSSIT pendant l'initialisation de MySQL, avant que le mot de passe
root ne soit applique : l'attente rendait « base prete » et la restauration echouait ensuite sur
« Access denied ». Elle attend maintenant une requete qui S'AUTHENTIFIE.

Trois choses que Windows masquait : `laravel/.env` absent du bundle (gitignore) faisait rendre 500
a Laravel ; le meme fichier en `600 root:root` restait illisible pour Apache, qui tourne en
`www-data` ; et Chromium refuse de tourner en root sans `--no-sandbox`, ce qui impose de jouer les
suites sous un compte ordinaire.

### La methode d'un sous-lot, ecrite

`docs/migration/METHODE-SOUS-LOT.md` — l'ordre de travail des sept sous-lots de `update/`, avec
pour chaque etape les defauts qu'elle a reellement attrapes : l'inventaire par agents, la lecture
du backend avant tout clic, le harnais Puppeteer, les regles d'attente, la mesure en requetes, les
captures qu'il faut REGARDER. Les ecarts restent dans `PARITE.md`, la recette d'archivage dans
`DEPRECIATION.md` : le document dit dans quel ORDRE travailler, il ne les repete pas.

### Rejeu du LOT sur la VM Debian : un controle qui ne controlait plus rien

Le LOT entier a ete rejoue sur la VM. Deux suites sont tombees, aucune pour une raison de code.

`go-socle-i18n` rendait 0 PASS / 1 FAIL. Elle fait lire les catalogues de langue par PHP *dans le
conteneur*, et lui passait le script ainsi :

```js
execSync(`docker exec rootwarden_laravel php -r ${JSON.stringify(script)}`)
```

`JSON.stringify` entoure le script de guillemets DOUBLES, et `execSync` remet le tout a `/bin/sh`.
Un shell POSIX developpe `$variable` entre guillemets doubles : `$ecarts`, `$total`, `$f`, `$m`,
`$fr`, `$en`, `$k` sont tous arrives VIDES cote conteneur. Le PHP n'etait plus du PHP. Sur le poste
Windows la commande ne passait pas par le meme shell, et le defaut ne se voyait pas — d'ou le
`MSYS_NO_PATHCONV` que le code portait encore.

Le script part desormais par un TABLEAU d'arguments, via `execFileSync`, sans shell intermediaire
donc sans developpement — sur toute plateforme. La suite rend 23 PASS, et le controle qu'elle porte
existe a nouveau : 490 cles francaises comparees, jeux de cles fr/en identiques, `maj` a 170 = 170.

**Ce que le defaut coutait** : une suite qui echoue bruyamment se remarque. Celle-ci echouait a
l'appel, avant la moindre assertion — la parite FR/EN n'etait plus verifiee par personne, et rien
ne le disait.

`go-page-update-u4` rendait 11 PASS / 3 FAIL, puis 14 PASS aux deux passages suivants, sans
qu'une ligne change. Le banc d'essai venait d'etre cree : sa premiere session SSH a ete acceptee,
authentifiee, puis fermee par le serveur (`EOF in transport thread` juste apres `userauth is OK`).
La sequence exacte de la route, jouee dix fois en isolation, passe dix fois. **Un `sshd` frais
authentifie avant d'etre pret a servir** — le meme piege que `mysqladmin ping`, et une session
reussie ne suffit pas a le prouver : celle du controle d'attente avait rendu `uid 0`.

### Le harnais E2E redevient reproductible

`.gitignore` ignorait `package-lock.json` a tous les niveaux. `tests/e2e/package-lock.json`
existait donc sur chaque poste sans etre suivi : `npm ci` refusait de tourner, seul `npm install`
passait, et chaque poste resolvait ses propres versions de puppeteer et de ses dependances. Un LOT
de tests dont l'outillage varie d'un poste a l'autre ne mesure pas la meme chose partout.

Le verrou du harnais est desormais suivi (`!tests/e2e/package-lock.json`), l'exclusion generale
restant en place pour le reste du depot. `npm ci` reinstalle le harnais a l'identique ; verifie en
effacant `node_modules`, en le reconstruisant par `npm ci`, puis en rejouant deux suites.

Deux points laisses ouverts, volontairement. `npm audit` signale quatre vulnerabilites hautes,
toutes dans `extract-zip`, dependance transitive de puppeteer 23 qui sert a decompresser Chromium a
l'installation ; le correctif passe par une montee de version majeure de puppeteer, qui touche tout
le harnais. Et `laravel/package.json` n'a pas de verrou : la chaine Vite/Tailwind n'est pas
installee sur la VM, `laravel/public/css/rw.css` etant compile et suivi.

### Inventaire du module `security/`, avant tout portage

`docs/migration/MODULE-SECURITY.md` mesure le module (2255 lignes, 4 fichiers) et le decoupe en
huit sous-lots, du plus simple — l'export CSV d'un scan — au plus risque : le scan lui-meme, seul
lot qui ouvre des sessions SSH et seul a repondre par un FLUX et non par un JSON.

**Deux corrections de perimetre d'entree.** `backend/routes/policies.py` n'appartient pas a ce
module : ses neuf routes ne sont appelees que par `adm/`, sont toutes `@require_role(3)` et portent
un step-up 2FA — les embarquer ici aurait melange deux niveaux de risque. Et deux des trois pages
(`compliance_report.php`, `cve_export.php`) n'appellent AUCUNE route backend : elles sont du PDO
local de bout en bout.

**Ce que le croisement JS ↔ backend a donne.** Aucun desaccord de cles, contrairement a `update/`
ou le JS envoyait `{date,time,repeat}` a une route qui lisait `interval_minutes` (E-18). Ici ce sont
les **reponses d'erreur** qui sont perdues : `runScan` ne teste jamais `resp.ok` avant de lire le
flux, si bien que les deux 429 structurels du backend — throttle de 60 s par utilisateur, verrou
global de scan — sont avales en silence. Le bouton se reactive, et rien ne s'affiche (E-23).

Le defaut le plus consequent est ailleurs : **la colonne « Suivi » disparait des qu'on filtre,
cherche ou pagine** (E-24). `buildRows` produit six cellules, `loadMoreFindings`, `searchFindings`
et `filterFindings` en reconstruisent cinq. Deux des trois ecritures utilisateur du module ne sont
donc joignables que sur la premiere page non filtree. Dix ecarts en tout, E-23 a E-32.

**Un seul code mort** — `whitelistCve`, une declaration et aucun appelant — la ou `update/` en avait
trois. La capacite « accepter un faux positif » existe cote serveur et personne n'a jamais pu la
demander depuis cette page ; `whitelisted_by` y etait de surcroit fourni par le client, donc
l'attribution d'une acceptation de risque etait falsifiable. Non portee.

**Deux constats de securite qui attendent une decision d'exploitant.** `compliance_report.php`
annonce dans son en-tete « Acces : admin (2) et superadmin (3) » et admet en realite `ROLE_USER`,
sans aucun cloisonnement des donnees : un role 1 obtient tout le parc avec IP, port et utilisateur
SSH, tous les comptes avec leur e-mail et l'age de leur cle, et la posture par serveur **avec les
ecarts en clair** — une liste de cibles priorisee. Le commentaire qui mentait est ce qui rend le
defaut durable : une relecture de l'en-tete ne pouvait pas le voir.

Et le hash « preuve d'integrite » du rapport n'est verifiable par personne : le code enonce
lui-meme, ligne 28, que les secrets chiffres n'ont rien a faire dans l'antecedent du SHA-256, puis
la requete suivante y fait entrer `totp_secret` et `ssh_key`. Ce n'est **pas** une fuite — verifie
aux trois rendus, ces colonnes ne sortent qu'en booleen — mais l'antecedent contient des champs
absents du rapport, donc le lecteur ne peut pas recalculer l'empreinte. Une preuve invraisemblable
vaut autant que pas de preuve.

Aucune ligne de code n'a ete portee : ce document precede le premier sous-lot.

### v1.37.19 — les quatre defauts sortis par la relecture integrale de `mises-a-jour.js`

`laravel/public/js/mises-a-jour.js` a pris sept sous-lots dans une seule fermeture. Une relecture
entiere du fichier — pas des tests verts — y a trouve quatre defauts, tous les quatre reproduits
par une assertion AVANT d'etre corriges, et deux d'entre eux exercent des actions destructrices sur
des machines reelles.

**Le delai de redemarrage ne repartait pas d'un etat connu.** `ouvreRedemarrage()` remettait le
nombre a recopier a vide et redesactivait son bouton, mais **jamais le champ de delai** — le seul
des quatre panneaux dans ce cas, alors que la note de la vague precedente affirmait deja que « les
quatre panneaux vident desormais leurs champs ». Consequence : un delai choisi pour une machine
survivait a la fermeture du panneau et repartait avec la suivante. Le geste delibere porte sur le
NOMBRE, donc personne ne relit un delai qu'il n'a pas touche : `shutdown -r +60` partait a la place
du redemarrage immediat attendu. L'assertion, avant correctif : « delai relu : « 60 » minute(s) ».

**Le compteur de selection survivait au tableau qu'il decrivait.** La branche d'erreur de la
relecture du parc vide le tableau puis `return` — avant l'appel a `compteSelection()`, qui ne vit
que dans la branche de succes. A l'ecran, deux affirmations contradictoires en meme temps : le
tableau dit « Impossible de relire le parc. » et le compteur dit « 1 machine retenue » ; l'action
suivante repond alors « aucune machine retenue », ce que l'ecran dementait. Mesure sur
`data-nombre`, pose par le code a cote du libelle : l'assertion ne depend d'aucune traduction.

**Une machine ARCHIVEE etait affichee, cochable, et pouvait recevoir un `apt full-upgrade` ou un
redemarrage** — puis disparaissait sans un mot au premier « Rafraichir », le nombre de lignes
changeant tout seul. `Machines::pourMisesAJour()` n'avait aucun filtre sur `lifecycle_status` la ou
`/filter_servers`, qui sert les relectures de la MEME page, exclut les archivees. Le commentaire de
la vue affirmait pourtant que « le MEME code sert le premier rendu et les suivants, il ne peut donc
pas exister deux versions du tableau qui divergent » : c'etait vrai du RENDU, faux des DONNEES.
Mesure : la machine 3 archivee le temps du controle, les deux sources interrogees, la valeur
d'origine (`active`, et non `NULL`) remise ensuite.

**Quatre colonnes de dates changeaient de forme au rafraichissement.** Le premier rendu les tient
du controleur, au format MySQL (`2026-07-25 14:29:14`) ; les relectures les tiennent de
`/filter_servers`, qui applique `isoformat()` cote Python (`2026-07-25T14:29:14`). Le rendu etant
commun aux deux sources, la normalisation l'est aussi : un helper `horodatage()`, applique aux six
points de rendu, plutot que six correctifs. L'assertion a ete verifiee AVEC DENTS — le helper
neutralise le temps d'une mesure, elle echoue en citant la forme ISO.

**Trois commentaires qui mentaient** ont ete corriges avec eux, la regle du projet etant qu'un
commentaire faux est pire que pas de commentaire : l'en-tete du JS annoncait « sous-lot U1 : parc et
filtres » pour un fichier qui porte U1 a U6b ; le commentaire du groupe d'actions annoncait « une
seule pour l'instant » et « la simulation n'est PAS portee » devant six boutons dont la simulation ;
et l'en-tete du controleur affirmait que les mises a jour, la planification et le redemarrage
« restent servis par l'ancien portail jusqu'a U6 », faux depuis l'archivage.

Enfin, `pourMisesAJour()` journalise desormais son echec. Son commentaire pretendait que
« l'indisponibilite du parc se voit » : une base injoignable rendait exactement le meme ecran qu'un
parc vide, texte d'aide compris, et rien n'en gardait trace.

**Ce que la relecture n'a PAS trouve**, et qui est dit ici pour que la prochaine ne le recherche
pas : aucune declaration en double ni masquage de portee sur 87 declarations, aucun ecouteur pose
deux fois sur 22, aucune fonction sans appelant sur 41, aucun `getElementById` visant un
identifiant absent sur 49 compares, et la liste des panneaux freres de `fermeLesAutresPanneaux`
enumere bien les quatre — la regression du sous-lot precedent est reparee. Parite i18n inchangee a
170 = 170 : les quatre correctifs n'ont demande aucune cle nouvelle.

**Reference du LOT mise a jour** : `go-page-update-u1` passe de 14 a **18** (precondition de
selection, message d'echec, compteur, forme des dates) et `go-page-update-u5` de 17 a **18** (delai
remis a son defaut). Tout le reste du LOT est inchange et rejoue vert, backend compris (296 pytest).

### v1.37.20 — module `security/`, sous-lot S1 : l'export CSV d'un scan

Premier sous-lot du deuxieme module. `App\Services\ScansCve` porte les lectures de `cve_scans` et
`cve_findings` — les sous-lots S3 et S6 s'y adosseront plutot que de recopier les memes requetes —,
`ExportCveController` rend le fichier, et la route `/export-cve` est gardee `role:1` +
`perm:can_scan_cve`, exactement la garde du legacy. Catalogue `cve.php` en FR et EN, 14 cles
identiques de part et d'autre : les libelles du fichier exporte n'ont rien a faire en dur dans un
controleur, un rapport se lit dans la langue de qui l'exporte.

**Le controle de cloisonnement porte sur l'OBJET RESOLU, pas sur le parametre recu** : on verifie
l'acces au `machine_id` DU SCAN, jamais a celui recu dans l'URL — `?scan_id=N` n'en porte aucun, et
un garde qui lirait le parametre laisserait passer toute cette branche. Son refus rend **404 et non
403**, avec le MEME corps que « aucun scan trouve » ; le test verifie que les deux corps sont
identiques, deux reponses distinctes suffisant a renseigner sur l'existence de la machine.

**Ce que la caracterisation a trouve, et qui n'etait pas cherche (E-33).** Sur ce poste, l'export du
legacy N'EST PAS UN CSV. `verify.php` pose `display_errors=1` quand `DEBUG_MODE=true` ; sur
PHP 8.4.24 chaque `fputcsv()` sans son argument `$escape` leve un `E_DEPRECATED` ; et les
**1 465 appels** du fichier injectent autant de blocs HTML `<b>Deprecated</b>` DANS le flux
telecharge. Mesure croisee sur le meme scan : 4 374 enregistrements cote legacy contre 1 458 cote
portage, pour 1 458 vulnerabilites reelles en base — soit 2 916 enregistrements etrangers, exactement
deux par ligne. `srv-docker.env.example` posant `DEBUG_MODE=false`, une production neuve n'est pas
touchee : la corruption est propre au dev et a la preprod. Elle vaut pour les trois fichiers de
l'application qui appellent `fputcsv`, dont `compliance_report.php`, que S2 portera.

La parade est **structurelle** : la charge utile est assemblee en memoire puis rendue d'un bloc, au
lieu d'etre ecrite au fil de l'eau dans `php://output`. Rien ne part avant que tout soit ecrit, donc
aucun avertissement ne peut s'y glisser — **un telechargement ne doit jamais heriter de
`display_errors`**. Et `$escape` est passe explicitement A SA VALEUR HISTORIQUE : la depreciation
porte sur l'ABSENCE de l'argument, pas sur sa valeur ; le passer tait l'avertissement sans changer un
octet. Basculer sur `''`, conforme a la RFC 4180 et futur defaut, modifierait les cellules portant un
antislash — c'est une decision, pas un effet de bord.

**Deux mesures qui disaient vrai en regardant des octets differents.** Le BOM UTF-8 semblait absent
du portage : `charCodeAt(0)` rendait `0x22`. Il etait bien la — `Response.text()` RETIRE le BOM au
decodage, par specification, donc chercher `U+FEFF` dans le texte decode ne peut jamais reussir.
Lire les octets bruts donne `EF BB BF` sur les DEUX cibles. Cote legacy, le premier caractere apres
decodage etait `<` : le BOM est ecrit avant la premiere ligne, et l'avertissement du premier
`fputcsv` s'insere juste apres.

**Et un test qui comptait des lignes la ou il fallait compter des enregistrements.** Un resume de CVE
contient des retours a la ligne ; entre guillemets ils appartiennent au champ, ce qui est du CSV
valide. Le decoupage naif rendait 7 576 « lignes » pour 1 458 vulnerabilites, et faisait passer les
suites de champ pour des lignes etrangeres. Le test decoupe desormais en respectant les guillemets,
et rend exactement 1 458 — le compte de la base. Les « 33 cellules lisibles comme une formule »
relevees au premier passage etaient le meme artefact : avec un decoupage correct, il n'y en a aucune.

**Ce que ce lot ne prouve PAS (E-34).** Son intention de depart etait de valider le harnais de
permissions. Il valide les gardes de ROLE et de PERMISSION — un role 1 sans `can_scan_cve` recolte
403, les roles 2 et 3 exportent — mais **pas le cloisonnement par machine** : cette branche exige un
role 1 PORTANT `can_scan_cve`, et aucun compte de test ne l'est. `rw-test-user` a zero permission,
et `user_machine_access` n'attribue aucune machine aux comptes de test. Le test le CONSTATE plutot
que de deplacer des droits pour se satisfaire : `rw-test-user` est la reference « role 1, zero
permission » de toutes les autres suites.

**E-35** : la route n'est atteignable qu'en tapant son adresse. Le legacy declenche l'export depuis
un bouton de `security/index.php`, qui appartient au sous-lot S3 — aucune entree de menu ne manque,
c'est le decoupage.

Aucune capture : ce sous-lot n'a pas d'interface, il rend un fichier.

LOT entier rejoue, versant Laravel et versant legacy, tout conforme ; 296 pytest verts ; parite i18n
504 = 504.

### v1.37.21 — module `security/`, sous-lot S2a : le rapport de conformite

`compliance_report.php` pesait 579 lignes pour sept collectes SQL, une notation de posture, sept
sections HTML ET un export CSV. **Trop gros pour un seul sous-lot** : le decoupage a ete corrige en
S2a (la page) et S2c (l'export CSV) — un document de migration n'est pas une promesse.

`App\Services\Conformite` porte les sept collectes, le bareme de posture et l'empreinte ;
`RapportConformiteController` assemble ; la vue rend sept sections ; la route est gardee `role:2` +
`perm:can_view_compliance` ; le catalogue `conformite.php` compte 64 cles en FR et en EN. L'entree
`Navigation` passe de `legacy` a `route` — sans quoi la page portee n'aurait ete joignable qu'en
tapant son adresse, comme l'entree `updates` l'a ete pendant sept sous-lots.

**D-1 appliquee (E-36).** Le fichier annoncait « Acces : admin (2) et superadmin (3) » et sa garde
admettait `ROLE_USER`, sans cloisonner aucune donnee : un role 1 porteur de `can_view_compliance`
obtenait tout le parc avec IP, port et utilisateur SSH, tous les comptes, la posture par serveur AVEC
LES ECARTS EN CLAIR, et les dix dernieres modifications de pare-feu avec leur auteur. Le commentaire
faux est ce qui a rendu le defaut durable. La route porte desormais la garde que le fichier
annoncait — et la divergence **n'est mesurable par aucun compte de test**, ce qui est dit plutot que
tu : elle exige un role 1 PORTANT la permission, et il n'en existe pas.

**Ce que S2a mesure, et que rien ne mesurait encore dans ce module** : la paire qui distingue une
garde par PERMISSION d'une garde par ROLE. `rw-test-admin` porte `can_view_compliance` et pas
`can_admin_portal` : il entre sur le rapport et reste refuse sur `journal-commandes`. Le premier jet
de cette assertion etait un FAUX VERT — elle visait `/commandlog/`, partie ARCHIVEE qui rend 404, et
se contentait de « pas 200 ». La page temoin doit etre VIVANTE et l'assertion exiger 403.

**L'empreinte est reprise telle quelle, et elle est identique a l'octet (E-37).** Son antecedent
porte `totp_secret` et `ssh_key`, absentes du rapport — le lecteur ne peut donc pas la recalculer, et
une preuve invraisemblable vaut autant que pas de preuve. La corriger change sa valeur, donc c'est la
decision D-2, en attente. Mesure faite pour que cette decision se prenne sans risque : a date figee,
les deux implementations rendent **4 480 octets d'antecedent et le meme SHA-256**. Le portage
n'introduit aucune derive.

**Six libelles echappaient a la parite FR/EN (E-38)** : le legacy construisait ses motifs d'ecart en
francais, en dur, dans son calcul de posture. La colonne « Ecarts » — celle qui dit quoi faire —
restait en francais quelle que soit la langue. Six cles desormais.

**Les cinq collectes facultatives journalisent leur echec.** Le legacy les entoure d'un
`catch (\Exception $e) {}` VIDE : une table absente rend une section vide, et rien n'en garde trace.
Un vide est un etat NORMAL ici — ces tables appartiennent a des modules qui peuvent n'avoir jamais
tourne — mais un vide et une erreur ne doivent pas se ressembler.

**Ce que seules les CAPTURES ont montre.** Deux defauts qu'aucune assertion ne voyait :
les legendes des tuiles de resume ne voulaient rien dire — des cles d'en-tete de colonne reutilisees,
« Utilisateur » sous « 4 / 10 », « Age de la cle » sous « 0 » ; et a 390 px la colonne « Ecarts »
etait **entierement hors du champ**, exactement comme la colonne d'actions des mises a jour. Sous
720 px l'IP s'efface et les ecarts reviennent sous le nom du serveur, avec le composant
`.rw-detail-ecart` deja employe par la derive de configuration — une information qu'on n'atteint
qu'en decouvrant le defilement horizontal n'est pas offerte. La page porte aussi ses regles
d'impression : c'est sa raison d'etre, et la barre laterale n'a rien a faire sur le papier.

**Trois defauts de mes propres outils, releves en cours de route.** Le script de captures se
reconnectait a chaque largeur avec le meme compte : le garde anti-rejeu a refuse, et il a
**photographie l'ecran de connexion en annoncant « quatre vues »** — il verifie desormais qu'il est
sur la bonne page avant de declencher. Un `grep -c` rendant 0 **sort avec un code non nul** et a
coupe une chaine `&&`, si bien qu'une modification de gabarit n'a jamais tourne alors que la
commande semblait avoir reussi. Et le garde anti-rejeu **traverse les suites** : deux suites
consecutives utilisant le meme compte dans la meme fenetre de 30 s se telescopent, la session reste
anonyme, et les appels rendent la page de connexion en 200. `go-socle-passerelle` rougissait une fois
sur deux et `go-page-update-u3` mourait sur un `null` : ce n'etait pas de la flakiness. Le lanceur du
LOT attend maintenant le basculement de la fenetre.

**Un constat qui ne vient pas du portage** : cinq comptes `e2e_test_*` abandonnes par
`02-admin-users.test.mjs` faussent la posture du rapport — « 2FA activee : 4 / 10 » la ou le parc
reel compte cinq comptes. Une page faite pour reveler une posture faible la mesure faussement, a
cause d'une suite qui ne nettoie pas ce qu'elle pose. Rien n'a ete supprime : ce sont des lignes
d'une base partagee.

**Reference du LOT mise a jour** : `go-socle-navigation` passe de 38 a **40** (une entree de plus est
portee), `go-socle-i18n` compare **568 cles** au lieu de 504, et `go-page-conformite` entre au LOT
avec **13 PASS sur chaque cible**. Tout le reste est inchange et rejoue vert sur les deux versants,
296 pytest compris.

### Ouvrir les deux portails depuis un autre poste

Les deux portails se pointaient l'un vers l'autre par des URL en `localhost`, ce qui ne vaut que
depuis la machine hote : **un lien servi a un navigateur mene au localhost DU VISITEUR.** Depuis un
poste du reseau, les huit entrees de menu du legacy redirigees vers le portage, la vingtaine
d'entrees « ancien portail » du portage, et les deux boutons d'export du rapport de conformite
menaient tous nulle part.

C'est le second piege de cette variable. Le premier etait le SCHEMA — `srv-docker.env.example`
portait encore `LARAVEL_URL=https://…` alors que le portage ecoute EN CLAIR sur ce port : une
installation neuve reproduisait le lien mort. Les deux sont corriges dans l'exemple, avec
`LEGACY_URL`, qui n'y figurait pas du tout, et un avertissement pose la ou `SERVER_NAME=localhost`
est defini — c'est cette valeur qui alimente les deux.

**Et la suite de navigation ecrivait l'adresse du legacy EN DUR** (`https://localhost:8443`) : trois
assertions tombaient des que `LEGACY_URL` pointait ailleurs. Elle mesurait une VALEUR DE DEPLOIEMENT
la ou la propriete a verifier est « l'entree vise le portail legacy, quelle que soit son adresse ».
Elle lit desormais la meme source que la page (`app.url_legacy`), et ne peut donc plus la
contredire ; `E2E_LEGACY` reste prioritaire pour forcer la main.

Verification faite par des REQUETES et non par comparaison de chaines, sur l'adresse reseau de la
VM et non sur localhost : les deux portails repondent, le rapport de conformite et l'export CSV
renvoient vers la connexion faute de session. La VM ne porte aucun pare-feu, les trois ports
(8080, 8443, 8444) ecoutent sur toutes les interfaces.

### v1.37.22 — module `security/`, sous-lot S2c : l'export CSV du rapport

`ExportConformiteController` rend le fichier, la route `/rapport-conformite/csv` porte la meme garde
que la page (`role:2` + `perm:can_view_compliance`), et **`Conformite::rapport()` a ete EXTRAIT** :
la page et l'export presentent les memes chiffres, et deux calculs separes finissent par ne plus dire
la meme chose. C'est la prevention du defaut trouve sur la page des mises a jour, ou le premier rendu
et les relectures venaient de deux requetes qui ne s'accordaient pas. La date est passee par
l'appelant et non calculee dans le service : elle entre dans l'antecedent de l'empreinte, et deux
appels a une minute d'intervalle produiraient deux empreintes pour un meme rapport.

**E-33 s'est rejoue exactement (E-40).** Mesure sur le meme rapport, au meme instant : le legacy rend
**34 blocs d'avertissement PHP** dans le fichier, s'ouvre sur `<br />` au lieu de son titre, et gonfle
ses sections a **13 / 13 / 34** la ou le parc compte 3 machines et la base 10 comptes. Le portage rend
**3 / 3 / 10**, soit exactement la source, et zero avertissement.

**Ce qui rend ce defaut remarquable, c'est qu'il etait deja connu.** La branche PDF DU MEME FICHIER
porte un `ob_end_clean()` dont le commentaire le nomme mot pour mot — « purger tout output parasite
(notices PHP captures par ob_start en mode debug) avant d'emettre le binaire PDF -> evite un PDF
corrompu prefixe de "<br />..." ». Quelqu'un l'a rencontre, l'a nomme precisement, et n'a protege
**qu'une branche sur deux**. C'est le troisieme « a moitie corrige » de ce seul fichier, apres
l'en-tete qui annonce une garde plus stricte que le code (E-36) et la regle du hash enoncee a
l'endroit ou elle est violee (E-37).

Le BOM part desormais par `fwrite` et non par `fprintf` : le legacy passe les trois octets du BOM en
deuxieme argument de `fprintf`, qui est un **format**. Aucun n'est un caractere special, donc il s'en
sort — par chance, pas par construction.

**Deux perimetres differents, repris tels quels (E-41)** : le CSV liste TOUS les comptes, la page
saute les inactifs. Le service nomme les deux populations separement pour qu'on ne les confonde pas,
et le test l'asserte. Restreindre l'un ou elargir l'autre change ce que le rapport DIT.

**D-2 reste ouverte** : l'empreinte est reprise telle quelle, avec son antecedent qui porte des
colonnes absentes du rapport. Mesure deja faite (E-37) : la corriger ne fait que changer sa valeur.

### Deux suites corrigees, pour la meme raison

`go-page-search` ecrivait l'adresse du legacy EN DUR. Des que `LEGACY_URL` a pointe sur l'adresse de
la VM, les liens legacy ont cesse de commencer par la constante, ont ete classes comme INTERNES, et
leur `target="_blank"` a fait tomber « aucun lien interne n'est marque ». **Deuxieme suite atteinte**
apres `go-socle-navigation` : un test ne doit pas ecrire en dur une valeur de DEPLOIEMENT, il doit la
lire a la meme source que la page. Les deux lisent maintenant `app.url_legacy`.

`go-page-update-u3` mourait sur un `null` vingt lignes apres l'assertion qui le detectait :
`TypeError` non rattrapee, tampon de resultats jamais imprime, « 0 PASS » rapporte. L'echec a ete
diagnostique **trois fois de suite** comme de la flakiness, faute de savoir ce que la page contenait.
Elle sort maintenant par le chemin normal, en disant l'URL reellement atteinte, le titre, et si c'est
l'ecran de connexion ou le bouton qui manque. Une suite qui meurt sur un `null` ne dit pas ce qu'elle
a mesure.

**Reference du LOT** : `go-page-conformite-csv` entre avec **10 PASS sur le legacy** et **17 sur le
portage** ; `go-socle-i18n` compare **581 cles**. Tout le reste inchange et rejoue vert sur les deux
versants, 296 pytest compris.

### Quatre modules inventories, et un defaut qui revient cinq fois

`docs/migration/MODULE-AUTH.md`, `MODULE-SSH.md`, `MODULE-SUPERVISION.md` et `MODULE-FILTRAGE.md`
mesurent quatre chantiers avant de les toucher, selon METHODE-SOUS-LOT.md §1. Aucune ligne portee.

**Le meme defaut, cinq fois : la garde protege la PAGE, pas la REQUETE.** Verifie dans le code,
module par module. `POST /deploy` porte `@require_api_key` + `@threaded_route` et rien d'autre — son
docstring l'assume sans le voir, « la route n'est pas decoree car elle utilise deja un thread dedie »,
et un thread n'est pas une garde. Quatre routes de profils de supervision n'ont aucun
`@require_role`. Sur les 23 routes de filtrage reseau, DEUX portent un `@require_permission`. Et
`/deploy`, `/supervision/` et `/iptables` sont tous absents de `$ADMIN_ONLY_PREFIXES` du proxy.

**Et QUATRE en-tetes de fichier annoncent un acces plus strict que le code n'applique** :
`ssh/index.php:12-15` « Acces refuse pour les utilisateurs standards (role_id = 1) »,
`iptables/index.php:14` « superadmin uniquement », `fail2ban/index.php:5` « admin (2), superadmin
(3) », apres `compliance_report.php:13` (E-36). Ce qui rend ces trous durables, ce n'est pas leur
subtilite : c'est qu'une relecture d'en-tete les CONFIRME.

**Le motif « a moitie corrige », cinq fois aussi.** La branche PDF de `compliance_report.php` porte
la parade que sa branche CSV n'a pas (E-40). `manage_whitelist` compose sa ligne en base64 dans une
branche de son `||` et l'interpole brute dans l'autre. La branche preflight de `ssh/js/main.js`
echappe tout, sa branche de journal fait `innerHTML +=`. L'attribution d'une action a ete corrigee
dans `iptables` et pas dans `fail2ban`. Les fuites de connexion MySQL, corrigees dans un helper et
oubliees a cinq autres endroits du meme fichier.

**Ce que les inventaires ont evite de porter** : un ecran d'enrolement 2FA qui divulgue le secret
d'un compte deja enrole a qui n'a que le mot de passe ; un `clean_up_users()` mort portant `userdel -r`
— ici le code mort est PLUS dangereux que le code vivant ; une capacite d'overrides par machine dont
aucune interface n'a jamais existe ; et un scan de parc synchrone qui contredit textuellement une
regle ecrite dans `helpers.py`.

**Le blocage de sortie de la 2.0 est identifie** : `legacy/auth/` porte quatre capacites non portees,
dont l'enrolement du second facteur. Aucun chemin d'authentification ne passe sans 2FA, donc on ne
peut pas eteindre le legacy tant que l'enrolement n'existe que la — un compte neuf arrive sur une
impasse. Ce n'est pas un module metier, c'est une condition de sortie, et elle n'etait dans aucun
plan.

Chaque document se termine par ce qui reste A MESURER et n'a pas ete deduit. Le plus urgent :
`mysql/init.sql:40` declare `users.password_updated_at` en `ON UPDATE CURRENT_TIMESTAMP`, et
`verify.php:158` calcule l'expiration du mot de passe dessus. Si c'est effectif, toute ecriture sur la
ligne `users` — dont `login.php:155` a chaque connexion reussie — repousse la date. La politique
d'expiration serait alors neutralisee par l'usage normal. A mesurer sur une base reelle avant de
porter quoi que ce soit de `auth/`.

### Le lanceur du LOT entre dans le depot, et deux skills avec lui

Le lanceur du LOT vivait dans un repertoire temporaire et **mourait avec la
session** : chaque reprise repayait les six prealables un par un.
`scripts/rejouer-lot.sh` les porte desormais, compare le resultat aux chiffres de
reference et rend `conforme`, `ECART attendu=N` ou `ECHEC`.

```bash
./scripts/rejouer-lot.sh                    # tout, les deux versants
./scripts/rejouer-lot.sh --legacy go-page-conformite
```

Les six prealables, chacun paye par au moins une seance de diagnostic : le relais
`sudo -n docker` (plutot que d'accorder au compte une appartenance au groupe, qui
vaut un acces root permanent), le profil compose `preprod` pour le banc d'essai,
`E2E_BASE` posee DANS LES DEUX SENS, `login_attempts` vide avant CHAQUE suite,
l'attente du basculement de la fenetre TOTP entre deux suites, et le cas
particulier de `go-vague0-legacy`.

**Deux skills nouvelles**, sur les deux manques les plus repetes :

`rw-lot` porte les prealables, les chiffres de reference et **les trois signatures
d'echec qui ont deja trompe** — une assertion « refusee » qui echoue sur un 200
sans qu'aucun compte ne soit verrouille (la session n'a pas tenu, regarder le
CORPS) ; un « 0 PASS » qui veut dire « la suite n'a rien DIT », pas « elle n'a
rien mesure » ; et un ecart de +1/-1 sans FAIL, souvent une assertion
conditionnelle. Elle dit aussi pourquoi l'execution parallele des suites reste
impossible, et que ce n'est pas une question de memoire.

`rw-inventaire` porte le gabarit d'un inventaire de module : les douze questions a
poser pour chaque route, la **checklist des gardes en TROIS endroits** — la page,
le proxy, le backend, un seul suffit a laisser passer — et les quatre motifs de
defaut qui reviennent : l'en-tete qui mente (quatre fichiers), le « a moitie
corrige » (cinq occurrences), le code mort parfois plus dangereux que le vivant,
et la capacite inatteignable. Elle rappelle enfin qu'un rapport d'agent n'est pas
une mesure : les affirmations lourdes se verifient soi-meme, et les preconditions
se mesurent.

**Et un doublon supprime avant qu'il ne divergе.** `rw-pieges` portait deja les
prealables du LOT ; ils n'y sont plus, remplaces par un renvoi vers `rw-lot`. Deux
copies auraient vecu separement — c'est exactement le defaut « a moitie corrige »
que ce catalogue reproche au legacy cinq fois. `rw-e2e` renvoie desormais au
lanceur plutot qu'a l'invocation manuelle.

### v1.37.23 — module `security/`, sous-lot S2b : l'export PDF du rapport

`ExportConformitePdfController` et une vue dediee `rapport-conformite-pdf.blade.php` — pas un
`@media print` de la page : le gabarit du portail porte une barre laterale, un en-tete collant et des
jetons de theme dont dompdf ne sait rien. Route `/rapport-conformite/pdf`, meme garde que la page et
le CSV (`role:2` + `perm:can_view_compliance`). `Conformite::rapport()` portait deja tout : ce
sous-lot n'ecrit que le rendu. Le bouton PDF de la page est passe sur la route portee et l'annonce
`conformite.pdf_a_venir` a disparu — **plus aucun aller-retour vers l'ancien portail depuis ce
rapport**.

**La dependance manquait.** `dompdf` etait absent du portage : ajoute en `^3.1`, resolu en **v3.1.6**,
soit exactement la version du legacy — **6 paquets ajoutes, 0 retire, 0 modifie**. Il n'exige que
`ext-dom` et `ext-mbstring`, tous deux presents ; `gd` n'est que *suggere*, « needed to process
images », et le rapport n'en porte aucune.

**Comment on mesure un binaire.** Un PDF ne se lit pas comme du texte : dompdf compresse ses flux,
donc un `grep` sur les octets ne trouve pas le contenu. La suite mesure a deux niveaux — la STRUCTURE
sur les octets bruts (`%PDF-` en tout premier, l'equivalent du BOM de S1 et S2c, plus `%%EOF`), et le
CONTENU par `pdftotext`, croise avec la base : le rapport doit NOMMER chaque machine du parc. Le
fichier temporaire porte des donnees du parc, il est efface dans un `finally`.

**E-43 — la moitie protegee l'etait vraiment.** Contrairement aux quatre autres occurrences du motif
« le legacy documente son defaut la ou il le commet », la branche PDF tient sa promesse : mesure faite
des deux cotes, le PDF du legacy commence bien par `%PDF-` et ne porte aucun fragment HTML. Son
`ob_start()` (ligne 276) est en revanche **vestigial** — le HTML est monte par concatenation, rien
n'est capture ; il n'existe que pour donner quelque chose a purger a `ob_end_clean()`. Le portage ne le
reproduit pas : il n'ouvre aucun tampon, donc il n'a rien a purger.

**E-45 — un tableau qui changeait de page perdait son en-tete.** Le legacy monte ses tableaux en
`<table><tr><th>` sans un seul `<thead>` : dompdf ne repete alors rien. Mesure sur le document reel —
cote legacy, les **10 lignes de comptes arrivent en page 2 et leur en-tete est reste en page 1** : dix
lignes de « Oui / Non / — » sans rien qui nomme les colonnes, sur un document dont la raison d'etre
est d'etre lu par quelqu'un qui ne connait pas l'outil. Le portage enveloppe ses six en-tetes dans
`<thead>`. **Aucune assertion de texte ne pouvait voir ce defaut** : sur le document aplati l'en-tete
est present, une fois. Il a fallu rendre les pages en images (`pdftoppm`) et les REGARDER — quatrieme
defaut d'affichage que seule l'image revele. L'ancrage en test a donc du devenir une mesure PAGE PAR
PAGE : toute page portant au moins deux noms de comptes lus en base doit porter l'en-tete.

**E-44 — le PDF du legacy en dit moins que sa propre page** : six sections contre sept, cinq colonnes
de comptes contre six. Ce qu'on imprime et qu'on archive en disait moins que ce qu'on regarde. Le
portage aligne le PDF sur la page — section pare-feu, colonne « age de la cle ». Ecart voulu, aucun
calcul change.

**L'empreinte d'integrite n'est pas reproductible, et c'est desormais mesure.** E-42 l'annoncait comme
une hypothese : deux generations du meme rapport a cinq minutes d'ecart donnent bien deux empreintes,
l'instant de generation entrant dans l'antecedent. Elle ne prouve donc que la non-alteration d'un
fichier donne, pas que deux exports decrivent le meme etat. Comportement du legacy, repris tel quel ;
a trancher avec **D-2**.

**Le mot de passe root de la base sortait dans les messages d'echec des suites.** `mysql` ne prend son
mot de passe que par la ligne de commande, et `execFileSync` recopie tout l'argv dans le message quand
la commande echoue : une suite qui tombait imprimait `docker exec ... mysql -uroot -p<le mot de
passe>`. C'est le defaut corrige cote SSH en **v1.37.17**, reapparu dans l'outillage de test. Les
trois suites du module lisent desormais la base par `tests/e2e/lib-base.mjs`, qui expurge l'erreur —
et qui supprime au passage **cinq copies du meme lecteur**. Trois suites plus anciennes portent encore
le motif (`07-maintenance`, `08-approvals`, `09-docker-idor`) : hors perimetre, signale.

**`compliance_report.php` est integralement porte** — ses points d'entree ont ete enumeres, il n'en a
que trois (la page, `format=csv`, `format=pdf`), et le `$_GET['_pdf_render'] = true;` de la ligne 194
est **ecrit et jamais lu**, second vestige de l'approche abandonnee. Le fichier reste neanmoins servi :
l'archivage se fait par module et `cve_scan.php` porte encore S3 a S7. Ses quatre portes sont deja
mesurees (les memes quatre que `update/`), et il a ete verifie qu'**aucune des sept pages archivees ne
figure encore dans la table des raccourcis clavier** du legacy.

**Reference du LOT** : `go-page-conformite-pdf` entre avec **13 PASS sur le legacy** et **14 sur le
portage** — l'ecart est E-45, mesure cote legacy mais rendu en constat par `verifiePortage`, le rejeu
du LOT comptant tout `FAIL` comme une regression. Tout le reste inchange et rejoue vert sur les deux
versants, pytest compris.

### v1.37.24 — module `security/`, sous-lot S3 : la consultation des resultats CVE

`ScanCveController` + `ComparaisonCveController`, la vue `scan-cve.blade.php`,
`public/js/scan-cve.js`, cinq methodes ajoutees a `ScansCve`. Routes `/scan-cve` et
`/scan-cve/comparaison` sous `role:1` + `perm:can_scan_cve` — la garde de la page legacy, celle que S1
porte deja. **L'entree de menu est basculee** : 12 entrees portees, 21 encore sur l'ancien portail.

**AUCUNE ROUTE BACKEND N'EST APPELEE, et c'est une decision mesuree.** Le legacy peint cette page par
un `GET /cve_results` par machine a travers le proxy. Trois mesures ont impose un autre chemin :
`grep -c require_permission backend/routes/cve.py` rend **0** sur 19 routes et `can_scan_cve` n'existe
dans tout le backend que dans une fixture de test — la permission ne garde aucune requete, seulement
des pages ; `require_machine_access` resout l'identifiant de machine par le CORPS JSON d'abord
(`helpers.py:331-332`) alors que les trois routes GET lisent EXCLUSIVEMENT `request.args`, si bien que
le garde autoriserait une machine et la route en servirait une autre ; et le decorateur ne refuse pas
quand aucun identifiant n'est trouve. Le portage lit donc la base, comme S1, derriere sa propre garde.
Le backend Python n'est pas touche. Les routes backend restent ouvertes : **une decision de
l'exploitant est en attente**.

**E-49 — LE TABLEAU SE DESALIGNAIT DES QU'ON L'UTILISAIT.** L'en-tete du legacy porte six colonnes et
un seul de ses quatre generateurs de lignes en produit six. Mesure dans le navigateur :

    apres chargement     50 lignes : 50x6 cellules
    apres « Voir plus » 100 lignes : 50x5 cellules ET 50x6
    apres une recherche   9 lignes : 9x5
    apres un filtre     100 lignes : 100x5

Le meme tableau melange les deux formes apres une pagination et la colonne « Suivi » disparait des
qu'on filtre — **sans aucune erreur JS**. Le commentaire de `sevCell` revendique pourtant d'avoir
« centralise pour rester coherent entre buildRows et la pagination » : une colonne sur six. Le portage
n'a **qu'UN generateur**, appele par tous les gestes, et son en-tete est rendu par le gabarit. Le
compteur existe desormais meme sous 50 CVE, et le bouton de pagination se cache au lieu de quitter le
DOM.

**E-46 et E-47 — deux fuites de perimetre.** Le filtre des machines archivees est present dans la
branche `role >= 2` de la page et **absent de la branche role 1** : un lecteur voit une machine qu'un
administrateur ne voit plus. Et le resume de parc n'est joint ni a `machines` ni a
`user_machine_access` : il agrege le dernier scan de TOUTE la base, archivees comprises, des que le
compte voit deux machines. Le portage pose le filtre UNE FOIS avant le branchement de role, et calcule
le resume SUR LA LISTE QU'IL AFFICHE. Un agregat doit porter le meme perimetre que la liste qu'il
resume.

**E-50** — rien n'etait rendu par `textContent`, et `esc()` n'echappe pas l'apostrophe alors que son
docblock affirme empecher l'XSS (latent : ses deux sites en contexte d'attribut ne recoivent qu'un
identifiant CVE, qui n'en porte pas). Le portage rend tout par `textContent`.

**TROIS DEFAUTS D'AFFICHAGE QUE SEULE L'IMAGE A MONTRES**, sur mon propre rendu, alors que le test
etait vert : l'identifiant CVE se coupait sur TROIS lignes, et le resume, en s'etalant, poussait le
tableau a 1789 px dans un cadre de 1048 — chassant hors du champ la colonne « Suivi », celle dont
l'absence etait justement le defaut du legacy. Corrige en trois temps, chacun re-mesure : identifiant
insecable, resume tronque avec son texte entier en infobulle (1048 px, le cadre exact), et sous 720 px
le prefixe `CVE-` s'efface avec des cellules resserrees — 367 px au lieu de 427, ce qui ramene la
severite dans le champ sans defilement. Deux autres corrections venues de la meme capture : six
apostrophes manquantes dans les libelles francais (« d un », « l ancien »), et trois tuiles qui
portaient la MEME legende « a corriger en premier » alors qu'elle est fausse pour deux d'entre elles.

**CE QUE CE SOUS-LOT NE PROUVE PAS, et le dit** : la base ne porte qu'UN scan complet, donc le diff de
deux scans n'est pas mesurable — seul son etat « moins de deux scans » l'est, et la suite l'exige ; le
defaut « pas de compteur sous 50 CVE » n'est pas mesurable non plus ; et la branche role 1, donc E-46
et E-47, exige le compte de fixture de **D-5**. Fabriquer un second scan changerait les chiffres que
les suites de conformite asserent deja.

**Reference du LOT** : `go-page-cve-consultation` entre avec **13 PASS sur le legacy** et **16 sur le
portage**. 47 nouvelles cles i18n, `cve` a **63 = 63**. Tout le reste rejoue vert sur les deux versants,
pytest compris.

### v1.37.25 — module `security/`, sous-lot S4 : la planification des scans CVE

`PlanificationsCve` + `PlanificationsCveController`, le bloc de planification ajoute a
`scan-cve.blade.php`, `public/js/planification-cve.js`, et un fichier de langue `planif` (**63 = 63**
cles). Cinq routes internes — liste, creation, modification, suppression, apercu — sous **`role:2`** +
`perm:can_scan_cve` : le bloc du legacy vit sous `$role >= 2` et ses routes portent `require_role(2)`,
la garde est donc reprise cran par cran, la consultation restant ouverte au role 1.

**AUCUNE DEPENDANCE AJOUTEE.** `dragonmantank/cron-expression`, deja present comme dependance du
framework, valide une expression ET calcule deux occurrences successives — donc l'intervalle. Il rend
la MEME echeance que `croniter` cote Python : `0 3 * * *` → `2026-08-21 03:00:00` des deux cotes,
verifie.

**E-51 — LE CLAMP ANTI-FREQUENCE N'ETAIT PAS REJOUE A LA MODIFICATION.** C'est le seul defaut de cette
migration mesure d'abord dans le code, puis **PROUVE EN FONCTIONNEMENT** :

    creation « * * * * * »           400, « Frequence cron trop elevee », rien ecrit
    MODIFICATION vers « * * * * * »  200 — ET LA BASE PORTE « * * * * * »
    modification « pas du cron »     200 — ET LA BASE PORTE « pas du cron »

A la creation (`cve.py:500-517`) le code valide, calcule DEUX occurrences et refuse sous 600 s ; son
commentaire nomme le risque — « `* * * * *` lancait un scan par minute -> ban OpenCVE upstream + DoS
interne ». Au PUT (`cve.py:549-566`), `cron_expression` est ajoute a la requete LIGNE 556, AVANT toute
validation ; le bloc suivant ne recalcule que `next_run`, sans `is_valid` ni comparaison, et un
`except Exception: pass` avale l'echec — l'`UPDATE` ecrit quand meme. **Neuvieme « a moitie corrige »
du projet**, et le commentaire qui nomme le risque est quarante lignes au-dessus de la branche non
protegee. Dans le portage, la MEME fonction valide les deux chemins : son parametre `$creation` ne
change QUE la liste des champs obligatoires, jamais la severite des controles.

**E-55 — trois validations manquaient, dont une qui rendait un 500 au lieu d'un 400.** `target_type`
est un `ENUM('all','tag','machines')` sans aucune liste blanche cote code : une valeur hors liste
remontait l'erreur MySQL 1265 nue, donc une page HTML d'erreur 500 (mesure). `min_cvss` n'etait ni
borne ni meme converti au PUT, alors que la colonne est un `DECIMAL(3,1)`. `name` etait exige non vide
a la creation mais PAS au PUT. `scan_source`, juste a cote dans la meme boucle de champs, a sa liste
blanche et elle EST rejouee — le motif « a moitie corrige » a l'echelle d'une seule fonction.
Le portage ajoute en outre un refus que le scheduler exige : une cible `machines` dont la liste est
vide ou illisible est REFUSEE, parce que cote scheduler une telle cible **retombe sur tout le parc**.

**E-54 — une planification n'avait pas d'auteur.** La colonne `created_by` existe et pointe vers
`users(id)` ; le legacy ne l'ecrit jamais. Ce n'est pas une attribution falsifiable, c'est une
attribution ABSENTE. Mesure : `NULL` cote legacy, `15` cote portage.

**E-53 — la phrase de recurrence etait produite en Python, donc intraduisible.** Le legacy rend « Tous
les jours a 03:00 » fabrique par `cve.py:460-474`, avec ses abreviations de jours francaises : aucun
mecanisme du portage ne peut la traduire. Le portage affiche les cinq prochaines executions reelles,
dans la langue de la session — et il dit « Trop frequent » EN ROUGE au fil de la saisie, la ou le
legacy ne le signale qu'a l'envoi.

**E-56 — deux gestes non reproduits** : le `confirm()` natif de la suppression, remplace par une
confirmation EN LIGNE sous la ligne concernee ; et l'appel emis pour un role qui n'a pas le bloc — le
legacy branche `loadSchedules` pour TOUS les roles alors que son bloc est sous `$role >= 2`, si bien
qu'un role 1 emet un `GET /cve_schedules` refuse a chaque affichage de page. Le portage ne rend le bloc
NI ne charge son script en dessous du role 2.

**LA SURETE A COMMANDE LA CONCEPTION DU TEST, et c'est le point a retenir.** Une planification arme le
scheduler, demarre SANS CONDITION par `backend/server.py:240-247` : aucune variable d'environnement ne
le gouverne, il tourne comme thread dans le conteneur, **invisible a `ps`**, se reveille toutes les
60 s et prend toute ligne active dont l'echeance est passee. Un test qui cree une planification par
minute peut donc declencher un vrai scan SSH, sur `srv-zabbix` qui est EN PRODUCTION. La parade n'est
pas un nettoyage rapide mais une cible inoffensive PAR CONSTRUCTION : toutes les planifications creees
visent un tag QUI N'EXISTE PAS, dont la branche fait une jointure interne — zero machine, zero SSH.
`all` et `machines` sont interdits comme cibles de test, `machines` avec une liste illisible retombant
sur tout le parc. Verifie apres chaque rejeu : un seul scan CVE en base, celui du 25/07, et zero
planification residuelle.

**DEUX ERREURS DE MA PART, corrigees.** Un intitule de colonne nommait autre chose que son contenu —
« Suivi » au lieu d'« Actions », par reemploi d'une cle de S5 — vu a la capture. Et j'avais annonce 21
assertions cote portage : la mesure en donne **20**, parce qu'il n'y a que QUATRE `verifiePortage`, le
clamp a la creation tenant des deux cotes. Une reference se mesure, elle ne se deduit pas.

**CE QUI RESTE AU BACKEND, et attend une decision** : les cinq routes Python sont inchangees. Un role 2
sans `can_scan_cve` peut toujours creer, modifier et supprimer une planification, et le clamp y reste
contournable par un PUT.

**Reference du LOT** : `go-page-cve-planification` entre avec **16 PASS sur le legacy** et **20 sur le
portage**.

### v1.37.94 — `services/` S1 porte : une assertion revele une regression du portage

`/services`, **legacy 16 PASS / portage 19 PASS, 0 FAIL**.

#### L'assertion « second temoin » a paye des sa premiere execution

S1 asserte que le refus oppose au role 1 **laisse une trace en journal** — un temoin independant du
statut HTTP. Sur le portage, elle a ECHOUE : `ExigePermission` refusait correctement (403, mesure)
**sans rien enregistrer**, la ou le legacy ecrit « Permission refusee : <permission> »
(`auth/verify.php:307-312`).

**Une regression de piste d'audit que seule cette assertion pouvait voir** : le 403 etait juste, la
garde faisait son travail, et rien ne manquait a l'ecran. Corrigee dans le meme lot.

> Un 403 dit que la page a refuse ; le journal dit que le refus a ete ENREGISTRE. Ce ne sont pas les
> memes proprietes, et seule la seconde survit a la session.

Le middleware sert **toutes** les routes `perm:` : `go-adm-audit` a ete rejoue apres la correction —
**34 PASS, conforme**. Le compte d'orphelines de `user_logs` passe de 998 a 1000, mais cette suite
mesure un DELTA dans sa propre execution, pas une valeur fixe. La ligne part sans empreinte de
chaine, exactement comme celle du legacy, et la coherence mesuree porte sur la sous-chaine SCELLEE.

**L'echec d'ecriture ne bloque jamais le refus** : le refus est la propriete de securite, sa trace
une propriete d'audit. Faire dependre la premiere de la seconde transformerait une base indisponible
en porte ouverte.

#### Deux corrections de presentation, mesurees puis portees
- **Les filtres sont montres des le depart, desactives, avec la raison.** Le legacy les garde dans le
  DOM mais MASQUES jusqu'au chargement d'un serveur (`etat=false categorie=false recherche=false`).
  Une assertion d'existence les declarait bons.
- **Aucun cadre vide avant le premier geste.** Le legacy affiche un panneau de journaux noir et vide
  des l'ouverture ; ici un texte dit qu'il n'y a rien.

#### E-149 n'est pas referme, et le code le dit
Les huit routes backend n'ont toujours ni role ni permission. `App\Services\ServicesSystemd` porte
le constat en tete, avec la mesure qui en borne la portee : reel dans le code, non exploitable par
aucun compte existant. **§7 du plan.**

### v1.37.93 — `services/` S1 caracterise : trois chemins de garde, et deux admis pour des raisons differentes

`go-services-s1.mjs`, **legacy 16 PASS / 0 FAIL**. Le portage reste a faire.

#### Le triple chemin, MESURE — et il differe de celui de `bashrc/`
La page admet **le role 1** (`checkAuth([ROLE_USER, ADMIN, SUPERADMIN])`), ce qui rend les trois
chemins distincts et mesurables :

    rw-test-user   role 1, SANS la permission  -> 403   le role 1 ne contourne pas
    rw-test-admin  role 2, AVEC la permission  -> 200   par la PERMISSION
    rw-test-super  role 3, SANS la permission  -> 200   par le CONTOURNEMENT DE ROLE

**Les deux 200 sont obtenus pour des raisons differentes.** C'est la seule facon de distinguer « la
garde laisse passer parce que la permission est la » de « parce que le role l'emporte ».

La precondition — **qui** detient `can_manage_services` — est mesuree AVANT les trois. Si elle
changeait de mains, deux attendus deviendraient faux sans que rien ne le signale : la suite passerait
au vert en mesurant autre chose.

#### Un SECOND temoin de la garde, independant du statut HTTP
Le refus oppose au role 1 **laisse une trace en journal** (`Permission refusee :
can_manage_services`). Un 403 dit que la page a refuse ; cette ligne dit que le refus a ete
enregistre — ce n'est pas la meme propriete, et la suite asserte les deux.

#### Deux constats pour le portage, vus a l'image puis mesures
- **Les trois filtres sont presents mais INVISIBLES au chargement.** Une assertion d'existence les
  aurait declares bons ; ils ne paraissent qu'une fois un serveur charge.
- **Un panneau de journaux VIDE est affiche des le chargement** — un cadre noir qui ne dit rien, la
  ou la convention du chantier veut qu'un etat vide DISE ce qui manque et pourquoi.

#### Un defaut de mesure, et il accusait la suite elle-meme
Le controle final cherchait `action LIKE '%service%'` et rapportait **une ligne** — qui etait
« Permission refusee : can_manage_services », c'est-a-dire **le journal du refus que la suite venait
de provoquer en mesurant la garde**. Elle s'accusait d'avoir pilote un service. Le module ecrit
`service_<action>` : le motif est desormais `'service|_%' ESCAPE '|'`, et la ligne de refus est
devenue une assertion au lieu d'un faux positif.

#### E-149 reste un constat de LECTURE, et c'est dit dans la suite
Le demontrer au navigateur exigerait un compte de role 2 sans la permission — le seul role 2 du parc
la detient, et le role 1 qui ne l'a pas est arrete par `@require_machine_access`, qui pour lui n'est
pas inerte. Le fabriquer modifierait un compte que la convention D-5 protege. **On dit ce qu'on a lu,
on ne le maquille pas en mesure.**

### v1.37.92 — `services/` inventorie : E-149, seule la PAGE est gardee

`MODULE-SERVICES.md`, en lecture seule. `bashrc/` B4 et `adm/` etant tous deux bloques sur arbitrage,
ce tour ouvre le module suivant dans l'ordre du plan.

#### E-149 — sixieme occurrence du motif, et la premiere non documentee

Les **huit** routes de `backend/routes/services.py` portent `@require_api_key`,
`@require_machine_access` et `@threaded_route` — **ni `@require_role`, ni `@require_permission`**. Et
`/services/` est absent des deux listes « admin » : `$ADMIN_ONLY_PREFIXES` cote legacy,
`ADMIN_SEULEMENT` cote portage.

`check_machine_access()` ouvre par « role >= 2 : acces a tout ». Pour un role 2 ou 3, le seul garde
restant sur la requete est donc `@require_api_key` — et c'est le proxy qui fournit cette cle.
**`can_manage_services` ne protege que l'ecran.**

#### Lu, puis mesure — et la mesure change la portee

Le constat ci-dessus est LU dans les quatre couches. La base, elle, dit :

    comptes de role 2 au parc : 1   dont avec la permission : 1
    rw-test-user   role 1  permission=0  et AUCUNE machine dans user_machine_access

**Le trou est reel dans le code et n'est exploitable par aucun compte existant aujourd'hui.** Le seul
role 2 detient la permission ; le role 1 qui ne l'a pas est arrete par `@require_machine_access`, qui
pour lui n'est PAS inerte. Meme situation que le repli `NOPASSWD: ALL` de `ssh/` : a un `UPDATE`
d'etre exploitable. Dire « n'importe qui peut arreter les services » serait faux aujourd'hui ; le
taire serait pire demain.

#### Ce que la mesure dedouane
- **Tous les gestes mutants confirment**, et la confirmation NOMME le service ET le serveur.
- **Le nom de service est valide** par liste blanche avec un plafond de 200 caracteres.
- **`@require_machine_access` n'est pas decoratif ici** — la page admet le role 1, pour qui le
  decorateur consulte reellement `user_machine_access`.

#### Rien n'est corrige
C'est un correctif de securite, et la convention du depot les veut sur une branche dediee, jamais
fusionnes sans accord verbal. La seule correction qui ferme le trou pour les DEUX portails touche le
backend de production. **Quatre correctifs backend attendent maintenant le meme arbitrage** —
E-142, E-144, E-147, E-149 — et trois sont la meme famille.

### v1.37.91 — `bashrc/` B4 caracterise : les ecritures distantes, toutes avortees

`go-bashrc-b4.mjs`, **legacy 15 PASS / 0 FAIL**. **Le portage est SUSPENDU** — voir §7 du plan.

Corps reellement intercepte au clic sur « Deployer » :

    {"machine_id":2,"users":["root"],"mode":"merge","dry_run":false}

`root`, en mode « fusionner » — qui, sans blocs marques `USER CUSTOM`, equivaut a « ecraser »
(§4.5). Quatre ecritures avortees sur l'execution, aucun journal `[bashrc]` produit.

#### Ce que le legacy fait BIEN, et qui est desormais mesure
- **Le deploiement confirme, et NOMME les comptes** : « Confirmez le deploiement du .bashrc pour ces
  utilisateurs ? root ».
- **Le multi-deploiement ENUMERE les machines** par leur nom dans sa boite.

Contrairement a D9a et D9b, ou `deploy` partait au premier clic, ce module-ci garde ses gestes.

#### Ce que la mesure etablit
- **Une requete part PAR MACHINE COCHEE** : deux machines cochees, deux requetes. Le
  multi-deploiement n'est pas une route, c'est une boucle cote client.
- **La simulation emprunte la MEME route que le deploiement reel.** Sa sureté ne tient qu'au champ
  `dry_run` du corps. Le backend l'honore (`if dry_run: … continue` avant toute ecriture), mais sur
  le reseau une simulation et un deploiement sont la meme requete a un champ pres.

#### Ce qui n'est PAS mesure au navigateur, et pourquoi
La propriete qui compte le plus — **une machine de PRODUCTION cochee serait-elle deployee ?** —
exigerait de cocher `srv-zabbix`. Le filet l'avorterait, mais un trou du cote « laisse passer »
ferait partir un deploiement reel sur la production, et **deux filets de cette session ont eu des
trous**. La reponse est donc LUE : `_bashrcSelectedMachines()` n'a aucun filtre, et la boucle envoie
un `/bashrc/deploy` par entree. Cocher `srv-zabbix` enverrait `machine_id: 1`.

La suite mesure le MECANISME sur les machines 2 et 3, et asserte qu'aucune requete n'a vise la 1.

#### Un defaut de mesure declare plutot que corrige
Les deux `Failed to fetch` releves viennent **du filet**, pas de la page : avorter produit une erreur
reseau indiscernable d'un defaut. En B1 c'etait evitable — la route avortee a tort etait une lecture.
**Ici non** : ce sont precisement les ecritures qu'il faut avorter. L'assertion porte donc sur
« aucune erreur ETRANGERE a l'avortement », et le compte est rapporte tel quel.

### v1.37.90 — `bashrc/` B3 porte : la reconnaissance dit enfin ce qu'elle NE verifie PAS

`/bashrc`, onglet Gabarit. **legacy 16 PASS / portage 19 PASS, 0 FAIL.**

#### E-148 — un des huit motifs de danger du legacy est largement inerte

`bashrcTemplateScanDanger()` teste `\b>\s*\/dev\/[sh]d[a-z]` pour la redirection vers un disque.
**`\b` exige un caractere de MOT juste avant le `>`** — or dans `cat x > /dev/sda`, la forme
normale, il y a un espace. Mesure :

    NON DETECTE : cat x > /dev/sda      <- la forme courante
    NON DETECTE : cat x >/dev/sda
    NON DETECTE : echo y >> /dev/sdb    <- l'ajout
    detecte     : x> /dev/sda           <- la seule forme reconnue

Le motif ne reconnait que la forme collee, que personne n'ecrit. Le portage retire le `\b` : les
quatre formes sont reconnues, sans faux positif sur un gabarit sain (verifie sur les huit motifs).

#### Ce que le portage ajoute
- **L'avertissement ENONCE SA PORTEE.** Il nomme le motif reconnu — le legacy le fait aussi — puis
  dit ce qu'il ne verifie pas : « ni ce que fait le reste du fichier, ni ce que fera celui-ci une
  fois deploye ». Le backend ne controle que la syntaxe ; un lecteur qui ignore la limite pretera a
  la reconnaissance une portee qu'elle n'a pas.
- **Deux confirmations distinctes** : celle qui NOMME ce qui a ete reconnu, et celle qui rappelle la
  portee du geste. Une phrase unique dirait moins dans le cas grave.
- **Les motifs vivent dans `Bashrc::MOTIFS_DANGEREUX`**, une seule source cote portage, jamais
  recopies dans le JS.

#### Deux defauts de mesure, tous deux dans l'instrument
- **Un test par mot-cle ne distingue pas une affirmation de sa negation.** L'assertion « l'ecran ne
  se presente pas comme une validation » cherchait `valid|verifi|conforme` — et elle a echoue sur le
  portage, dont l'encart dit « Elle NE verifie NI… », un DESAVEU. La propriete utile n'est pas
  l'absence d'un mot mais la presence d'une limite : elle cherche desormais un enonce de portee.
  **Sur le legacy elle est FAUSSE**, ce qui est plus informatif que l'ancienne, toujours vraie.
- **Ma verification des motifs cassait sur son propre delimiteur.** `preg_match("/$motif/")` avec des
  motifs contenant `/` : cinq des huit « ne compilaient pas ». C'est l'outil qui echouait, pas la
  chose verifiee.

#### Un defaut de rendu, vu a l'image
L'editeur heritait de la police proportionnelle du document. Le gabarit est du shell et s'appuie sur
des bannieres `# =====` alignees : l'alignement se perdait et l'indentation cessait de se lire.
Nouvelle classe `.rw-saisie--code`.

### v1.37.89 — `bashrc/` B3 caracterise : le premier sous-lot du module qui ECRIT

`go-bashrc-b3.mjs`, **legacy 16 PASS / 0 FAIL**. Le portage reste a faire.

B3 ecrit — en base, jamais sur une machine — mais **ce qui est ecrit est ce que toutes les machines
recevraient** au prochain deploiement. Trois precautions, dans cet ordre :

1. **le contenu d'epreuve est INERTE** : le gabarit d'origine plus UNE LIGNE DE COMMENTAIRE. Meme si
   la restauration echouait, les machines recevraient un `.bashrc` fonctionnel. On ne se repose pas
   sur la restauration pour etre sur ;
2. **l'original est copie DANS LA TABLE** sous un autre nom, avant toute navigation ;
3. **la restauration se verifie par un SHA-256**, pas par une longueur.

#### Ce que le legacy fait BIEN, et qui se mesure maintenant
L'avertissement de danger **nomme le motif reconnu** (« curl|sh ») et **ne se presente pas comme une
validation**. C'est exactement ce qu'il faut : le backend ne verifie que la syntaxe (`bash -n`) et la
taille, donc un ecran qui parlerait de « contenu valide » promettrait une barriere inexistante. Le
portage n'aura qu'a ne pas regresser.

#### Deux defauts de mesure, et le second a laisse une trace
- **Octets contre caracteres.** `LENGTH()` compte des OCTETS, `CHAR_LENGTH()` des CARACTERES, et la
  `.value` d'un `<textarea>` est en caracteres. Le gabarit fait **22 412 octets pour 17 814
  caracteres** : la suite comparait les deux et accusait la page de charger un contenu tronque. Les
  « 4 598 octets manquants » n'etaient que de l'UTF-8 multi-octets.
- **Defaire un geste n'est pas restaurer un etat.** La restauration reconstruisait l'original en
  RETIRANT la ligne posee (`REPLACE()` + `TRIM(TRAILING …)`). Elle a laisse le gabarit dans un
  TROISIEME etat — ni l'original, ni celui qu'on venait d'ecrire. Il a fallu le remettre a la main
  depuis le fichier de repli du module, dont l'empreinte se trouvait etre celle d'origine. **C'est
  la precaution 1 qui a fait que l'incident n'a rien casse** : le contenu laisse en place etait
  fonctionnel. La sauvegarde est desormais une COPIE, pas une reconstruction.

#### Une correction qui vaut pour toutes les suites
`verifiePortage()` imprimait « ecart assume du legacy — <detail> » **meme quand la propriete tenait**,
et le detail se lisait alors comme une contradiction (« affichee 9ee8e473, attendue 9ee8e473 »). Il
dit desormais laquelle des deux choses il a mesuree. Meme famille que le detail d'echec imprime sur
un PASS : **une ligne qui affirme toujours la meme chose ne mesure rien.**

### v1.37.88 — `bashrc/` B2 porte : les lectures distantes, et le signal que le legacy jetait

`/bashrc`, **legacy 14 PASS / portage 15 PASS, 0 FAIL**. Les deux routes de lecture passent par la
passerelle, joignent reellement `Test-Server-Debian` et n'ecrivent rien.

#### Ce que le portage montre et que le legacy ne montre pas
- **`has_custom`, par compte, AVANT le choix.** La route `/bashrc/users` rend ce champ pour chaque
  compte ; le legacy le jette dans sa liste. C'est pourtant le seul signal qui dit si « fusionner »
  preservera quoi que ce soit — et il arrive au moment ou l'on choisit, pas apres. Voir
  `MODULE-BASHRC.md` §4.5 : sans blocs marques `USER CUSTOM`, « fusionner » equivaut a « ecraser ».
- **`root` se signale** — badge « administrateur » et ligne teintee. Son `.bashrc` s'execute a chaque
  connexion administrateur ; le legacy l'affiche comme les autres.
- **« Tout cocher » annonce qu'il retient `root`.** Le comportement est porte a l'identique — c'est
  un changement de comportement, il appartient a l'exploitant — mais il ne se fait plus en silence.

#### Trois defauts de rendu, tous vus A L'IMAGE
- **Le diff s'affichait sur UNE SEULE LIGNE.** `.rw-code--fichier` porte `white-space: nowrap` parce
  qu'il est fait pour UN NOM DE FICHIER : la classe avait ete detournee. Un diff a plat ne se lit
  pas, il se devine. Nouvelle classe `.rw-diff`, rendu ligne a ligne, ajouts et retraits distingues
  par une couleur **et** par leur signe `+`/`-` — la couleur seule ne dit rien a qui ne la distingue
  pas. Meme travers que le `.rw-inline` de D9a : **une classe existante employee pour ce qu'elle ne
  fait pas.**
- **Le badge de `root` repetait son nom** : la ligne affichait « root root ». Il nomme desormais le
  ROLE.
- **Une cle i18n reutilisee pour deux sens.** `plusieurs` valait « :nb machines selectionnees » pour
  le compteur et « plusieurs machines sont cochees » pour les comptes : le second aurait ecrase le
  premier a l'ecran. Renommee `plusieurs_cochees`.

#### Un choix de perimetre, ecrit dans le code
L'apercu envoie `mode: 'merge'` en dur — le defaut du legacy. Le selecteur de mode appartient au
DEPLOIEMENT (B4). **A relier au selecteur des qu'il existe** : un apercu qui montre un autre mode que
celui qui sera deploye est pire que pas d'apercu.

### v1.37.87 — `bashrc/` B2 caracterise : les lectures distantes ABOUTISSENT, et la production reste hors d'atteinte

`go-bashrc-b2.mjs`, **legacy 14 PASS / 0 FAIL**. Le portage reste a faire.

C'est la premiere suite du module qui joint REELLEMENT une machine : elle enumere les comptes de
`Test-Server-Debian` par SSH (`root`, `testuser`) et lit le `.bashrc` de `root` pour en construire un
diff — `571 o → 17814 o`. Aucune ecriture.

#### La propriete « jamais la production » se MESURE, elle n'est pas construite

La page propose les TROIS machines du parc, `srv-zabbix` comprise. Le filet ne se contente donc pas
d'avorter les routes d'ecriture : il **lit le `machine_id` de chaque requete** et avorte tout ce qui
ne vise pas la machine 2. **Un `machine_id` indetermine est avorte aussi** — sans identifiant on ne
sait pas ou ca va, donc fail-closed. Le verdict porte sur ce qui a ABOUTI :

    PASS  aucune requete aboutie ne visait une autre machine que la 2
    PASS  aucune requete aboutie n'ecrivait

#### Trois defauts de MESURE, et les trois etaient dans l'instrument

- **Le filet a bloque la page elle-meme.** `/\/bashrc\//` attrapait `GET /bashrc/` : la suite
  mourait sur `ERR_BLOCKED_BY_CLIENT` avant de rien mesurer. Le garde vise desormais les NOMS DE
  ROUTES (`users`, `preview`, …), que la page ne porte pas. **Deuxieme fois sur ce module que le
  filet produit l'echec qu'il rapporte.**
- **`on` n'est pas un compte : c'est la case « Tout ».** Un `<input type=checkbox>` sans attribut
  `value` rend `"on"`. La suite le listait comme un compte — et comme il vient EN PREMIER,
  `cases[0].click()` cochait « tout selectionner », ce qui retient `root` avec le reste. Sur cette
  page, c'est exactement le geste dangereux. Le compte est desormais vise PAR SA VALEUR.
- **`verifie()` imprimait le detail d'echec sur les PASS.** Sixieme correction a la main dans ce
  depot : `PASS … — aucune requete n'est partie`. La signature l'empeche maintenant — le detail
  d'echec ne sort que sur un FAIL, et un detail valable dans les deux verdicts passe en quatrieme
  argument. *Une regle qu'on doit se rappeler est une propriete qu'on n'a pas encore construite.*

#### Deux constats pour le portage
- **`root` est bien propose** dans la liste des comptes (`_list_users` retient `UID == 0`). Le
  portage devra decider de le signaler ou non — c'est en §6.4 de `MODULE-BASHRC.md`.
- La case « Tout » selectionne `root` avec les autres, sans rien dire.

### v1.37.86 — `bashrc/` B1 porte : la production ne se fond plus dans la liste

`/bashrc`, **legacy 17 PASS / portage 18 PASS, 0 FAIL**. Le module n'a AUCUN defaut de securite
(`MODULE-BASHRC.md` §3) : les trois corrections sont de PRESENTATION, et toutes trois avaient ete
vues A L'IMAGE, invisibles a toute assertion DOM.

#### Corrige cote portage
- **`srv-zabbix` ne se fond plus dans la liste.** Le legacy l'affiche avec la meme case a cocher que
  les machines d'essai — et `_list_users` propose `root` : la page permettait de cocher production
  + `root` et de deployer. Le portage la teinte, lui pose un lisere, un badge « Production », et
  annonce en TETE du tableau qu'une machine de production y figure. La sensibilite se lit sur DEUX
  colonnes (`environment = PROD` OU `criticality = CRITIQUE`) — une machine peut etre critique sans
  etre en production, et l'inverse. `OTHER` et une valeur vide comptent comme sensibles : un
  environnement inconnu ne se range pas du cote sur.
- **Le compteur s'ENONCE** : « Aucune machine selectionnee — un deploiement ne deploierait rien. »
  Le legacy affiche « Serveurs cibles 0 », et un `0` se lit comme une donnee, pas comme un etat.
  Quand la selection contient une machine de production, le compteur le DIT.
- **Une SIMULATION n'est pas un deploiement.** La seule ligne `[bashrc]` de la base est une
  simulation du 2026-07-25 sur `srv-zabbix`. Le legacy l'exclut de sa colonne — donc « jamais
  deploye », ce qui est vrai mais perd l'information. Le portage la rend **sur sa propre ligne** :
  « simule le … — rien n'a ete ecrit ».

#### Trois defauts attrapes dans le portage, dont un qui rendait la page 500
- **`@json` avec un litteral de tableau inline casse le PHP compile.** Sa lecture d'arguments
  decoupe sur les virgules de premier niveau sans suivre les crochets : le compile devenait
  `json_encode([... )`, sans crochet fermant. **`@json` prend une VARIABLE** — le motif employe en
  D9a et D9b, oublie ici.
- **La requete du dernier deploiement attrapait trop large** : tout `[bashrc]` portant un
  `machine_id`, donc un `restore` se serait affiche comme un deploiement. Alignee sur le motif du
  legacy, `[bashrc] deploy%`, simulations exclues.
- **Un commentaire affirmait que `environment` et `criticality` sont du texte libre** — ce sont des
  `enum`. Corrige : laisser un commentaire qui dit l'inverse du schema serait le defaut meme que ce
  chantier traque.

#### Deux defauts de MESURE, corriges dans la suite
- Le controle i18n rapportait `bashrc.blade` et `bashrc.js` comme des cles manquantes : ce sont des
  **noms de fichiers** dans une pile d'appels. Il lisait la PAGE D'ERREUR. Le motif exclut desormais
  les extensions, **et la precondition « la page rend » est asserte avant** — « aucun identifiant
  trouve » sur une page en erreur serait vrai pour la pire des raisons.
- La simulation etait rendue dans un `<span>`, donc collee a « jamais deploye » : les deux se
  lisaient comme une seule phrase. Presenter la simulation ACCOLEE au verdict de deploiement est
  exactement ce que ce bloc existe pour eviter.

#### La regle de navigation, corrigee au tour precedent, fait sa premiere prediction
Basculer `bashrc` (garde `can_manage_bashrc`, que `rw-test-admin` n'a pas) devait ajouter **une**
assertion et non deux. Mesure : **59 -> 60**. La formule courte « +2 par entree » aurait predit 61.

### v1.37.84 — `bashrc/` B1 caracterise : le triple chemin de garde, MESURE

`tests/e2e/go-bashrc-b1.mjs` — **legacy 16 PASS / 0 FAIL**, vert au premier rejeu. Le portage reste
a faire.

#### Ce que B1 mesure, et qu'aucune autre suite du chantier n'exerce

Le **chemin du milieu** d'une garde « permission OU role ». Les trois lignes sont des releves :

    INFO  comptes d'epreuve detenant `can_manage_bashrc` : (aucun)
    PASS  rw-test-user  (role 1) est refuse  — statut 403
    PASS  rw-test-admin (role 2) est refuse  — statut 403      <- le chemin du milieu
    PASS  rw-test-super (role 3) est admis   — statut 200      <- contournement de role

La precondition est verifiee AVANT les trois : si un compte d'epreuve recevait la permission,
l'attendu du milieu changerait sans que rien ne le signale. C'est la seule facon de distinguer « la
garde laisse passer parce que la permission est la » de « parce que le role l'emporte ».

#### Trois defauts vus A L'IMAGE, qu'aucune assertion DOM n'attrape
- **`srv-zabbix` (PRODUCTION) est une ligne comme les autres** dans le tableau des cibles : meme
  case a cocher, aucun marqueur. Avec `root` deployable (§6.4), la page permet de cocher production
  + `root` et de deployer.
- **« Deployer » est le bouton VERT** — la couleur la moins alarmante de la palette, donnee au geste
  qui ecrit un `.bashrc` sur toutes les machines cochees. « Deployer multi » est violet. Le codage
  n'est pas seulement arbitraire : **il est inverse par rapport au risque**.
- **« Serveurs cibles 0 »** — un compteur a zero affiche comme un chiffre au lieu d'etre enonce.

Le module n'a AUCUN defaut de securite (voir `MODULE-BASHRC.md` §3). Ces trois points sont de
PRESENTATION — precisement le registre ou ce chantier a trouve ses defauts les plus couteux.

#### Un defaut de MESURE corrige avant de conclure

La premiere execution rapportait `erreurs JavaScript : Failed to fetch`. **C'etait le filet de la
suite qui la produisait** : il avortait `GET /bashrc/template`, une route qui lit le gabarit EN BASE
et ne joint aucune machine. L'instrument fabriquait le defaut qu'il rapportait ensuite, et
l'assertion aurait echoue sur le portage pour une erreur creee par la mesure.

Le filet distingue desormais par METHODE : le `GET` passe, le `POST` (qui ecrit) reste avorte. Et
l'assertion finale ne vaut plus un `true` constant — elle mesure ce qui a ete avorte.

### v1.37.82 — `bashrc/` : trois inconnues de l'inventaire fermees PAR LA LECTURE

Le banc etant toujours pris par le LOT complet d'une autre session, ce tour ferme par la lecture
trois des cinq points que `MODULE-BASHRC.md` §6 declarait non mesures. Les trois restent listes,
BARRES, avec leur reponse : un inventaire qui efface ses propres questions perd la trace de ce qui
etait incertain, et de ce qui a leve l'incertitude.

#### Ce que la lecture a trouve, et qui n'etait pas dans le premier tour

**« Fusionner » est le mode PAR DEFAUT, et son terme-cle n'est defini nulle part.** Le libelle
« Fusionner (conserver blocs custom) » est LITTERALEMENT VRAI : `_extract_custom_blocks()` conserve
bien les blocs entre marqueurs `# >>> USER CUSTOM >>>`. Mais ni `USER CUSTOM` ni `.bashrc.local`
n'apparaissent dans les 74 cles i18n du module. La lecture naturelle — « garde mes personnalisations »
— est donc fausse, et **sans marqueurs « fusionner » equivaut a « ecraser »** : c'est le cas de tout
premier deploiement.

**Troisieme variante du motif du chantier.** Ni un texte qui dit faux (E-142), ni un texte qui
recommande l'inverse de ce qui est livre (E-146), mais un libelle vrai dont le terme porteur n'est
defini nulle part. Il ne se corrige pas en le rendant « plus juste » — il l'est deja — mais en
DEFINISSANT son terme.

**Et l'interface JETTE la mesure qui leverait l'ambiguite.** Le backend calcule `custom_detected` dans
sa branche `dry_run` — exactement « est-ce que fusionner va preserver quoi que ce soit pour ce
compte ? ». L'apercu l'affiche (`bashrc.js:271`) ; le tableau de resultat du deploiement
(`bashrc.js:313-322`) ne le montre pas. L'information est calculee, elle traverse le reseau, elle est
jetee au rendu. **Forme inverse des defauts precedents** : pas un texte qui ment, mais une mesure
vraie que l'interface abandonne.

**Gravite faible, et il faut le dire aussi.** La sauvegarde est faite des que le fichier existe, dans
les DEUX modes, et un echec de sauvegarde AVORTE le deploiement pour ce compte (fail-closed). C'est un
defaut d'information, pas de destruction.

#### Les deux autres inconnues fermees
- **`root` EST propose au deploiement** — `_list_users` retient `UID == 0 || UID >= 1000`. La cible la
  plus consequente du parc n'est distinguee en rien des autres a l'ecran. A trancher au portage.
- **`preview` a un cas vide propre** — `_read_remote_bashrc` ouvre par `if [ -f … ]` et rend `""` ;
  le diff est alors integralement en ajout, sans exception.

Et un troisieme releve du meme genre que ceux du premier tour : `_USERNAME_RE` est **reapplique aux
lignes venues de la machine**, apres le `awk`. Troisieme endroit ou ce module traite une donnee
distante comme hostile, apres `_HOME_RE` et la validation des noms recus du client. C'est une
constante de conception, pas un accident.

#### Ce qui reste non mesure (§6)
Le **triple chemin de garde** et les references du LOT. Les deux exigent le banc.

### v1.37.81 — `bashrc/` inventorie : le module le mieux construit du chantier

Inventaire en LECTURE SEULE, mene pendant qu'un LOT complet occupait le banc. Aucune mesure au
navigateur : `MODULE-BASHRC.md` §6 dit explicitement ce qui reste a mesurer, et pourquoi.

**Il faut le dire aussi nettement qu'on rapporte un defaut : ce module n'en a pas de serieux.**
Chercher des defauts n'est pas en trouver, et un inventaire qui n'en rapporterait pas sincerement
serait moins utile qu'un inventaire qui en rapporte.

#### Ce que la mesure dedouane
- **Les huit routes portent la pile complete** de decorateurs, et le contournement du role 3 est
  IDENTIQUE des deux cotes (`checkPermissionFromDB` en PHP, `require_permission` en Python). Aucune
  divergence a porter.
- **L'en-tete du fichier dit VRAI** — il annonce « admin (2) + superadmin (3) + `can_manage_bashrc` »
  et c'est ce que le code applique. Quatre autres modules du depot annoncent plus strict qu'ils
  n'appliquent.
- **Aucune valeur client ne s'interpole nue** : contenu en base64, nom de compte valide par
  `^[a-z_][a-z0-9_-]{0,31}$` avant son interpolation dans `chown`, et le **home venu du `/etc/passwd`
  DISTANT** valide par `^/[A-Za-z0-9._/-]{1,128}$` — avec le vecteur et la parade ecrits a cote. Les
  TROIS fonctions qui touchent au home refusent un home non conforme : le contraire du
  « a moitie corrige ».
- **Tous les gestes destructeurs confirment**, et le deploiement multi-machines ENUMERE les machines
  par leur nom. C'est exactement ce que D9a et D9b ont du AJOUTER.

#### Trois points a arbitrer, aucun n'est une faille
- les huit motifs de danger du gabarit n'existent QUE dans le navigateur ; le backend valide la
  syntaxe et la taille. Qui atteint la route detient deja l'autorisation d'ecrire ce fichier — la
  decision est de PRESENTATION, pas de securite ;
- `GET /bashrc/backups` n'a aucun appelant : capacite inatteignable ;
- aucune fenetre de maintenance ni approbation a quatre yeux sur les huit routes.

#### Un piege de releve, corrige avant d'etre rapporte
Un `grep` sur `confirm(__('...'))` ne rendait que quatre cles et laissait croire que `deploy` n'en
avait pas — sa confirmation est construite par gabarit, `confirm(\`${label}…\`)`. **Un motif qui
suppose une forme d'appel ne mesure que cette forme.** Verifie avant d'etre ecrit ; c'eut ete une
accusation fausse.

#### Ce qui reste a mesurer (§6)
Le **triple chemin de garde**, deduit et non mesure. La base dit que `rw-test-super` (role 3) n'a PAS
`can_manage_bashrc` : c'est donc lui qui exercera le contournement par le ROLE, et `rw-test-admin`
(role 2, sans la permission) qui doit etre REFUSE. Le chemin du milieu est celui qu'aucune suite du
chantier n'exerce d'ordinaire.

### v1.37.80 — `adm/` D9b : l'acces SFTP porte, et les trois cases que l'ecran conseillait de decocher

**D9 est clos.** E-142 etait une aide qui disait FAUX. Celui-ci est plus net, parce que les aides du
legacy disent **vrai** — et recommandent, chacune, l'inverse de ce qui est livre :

| reglage | ce que l'aide dit | etat livre |
|---|---|---|
| connexion par mot de passe | « Decoche : il DOIT utiliser une cle SSH (nettement plus sur, **recommande**). » | **coche** |
| tunnels reseau | « Si ce n'est pas necessaire, **decoche : c'est plus sur**. » | **coche** |
| rebond de cle | « Si ce n'est pas necessaire, **decoche**. » | **coche** |

Et `sftp_only` — la restriction qui donne son nom a la page — est livre **decoche**. Ecarts **E-146**
et **E-147**.

#### Ce que cela produisait

Corps reellement intercepte au premier clic sur « Deployer » (E-143 vaut aussi ici, le JS est partage) :
`{"sftp_only":false,"allow_password_auth":true,"allow_tcp_forwarding":true,"allow_agent_forwarding":true}`
— un bloc `Match User` **sans** `ForceCommand internal-sftp`, **sans** `ChrootDirectory`, **sans**
`PermitTTY no`. Ce n'est pas une restriction SFTP : c'est un shell complet avec tunnels. Et un bloc
`Match User` **remplace**, pour ce compte, ce que la configuration generale de la machine aurait
donne : sur une machine durcie, le deployer **elargit** l'acces.

#### Ajoute
- `laravel/app/Services/AccesSftp.php` — chaque reglage classe `restreint` ou `ouvre`, et l'etat
  initial en est **derive** : ajouter un reglage ne peut pas faire naitre un defaut permissif par
  oubli.
- `AccesSftpController.php`, `resources/views/acces-sftp.blade.php`, `public/js/acces-sftp.js`,
  `lang/{fr,en}/sftp.php` — 63 cles, parite stricte.
- Route `GET /acces-sftp` en `role:3` seul. Entree de menu `sftp_policies` basculee.
- `tests/e2e/go-adm-sftp.mjs` — **12 PASS legacy / 16 PASS portage, 0 FAIL**.

#### Corrige cote portage
- **La position de depart est la plus fermee** : transfert de fichiers seulement, cle SSH
  obligatoire, aucun tunnel. Le corps emis est exactement l'exemple que la docstring du module donne.
- **Deployer et retirer se confirment**, par un panneau qui **enumere ce qui elargit l'acces** plutot
  que d'annoncer un deploiement en bloc.
- Chaque reglage qui elargit porte un marqueur **sur sa propre ligne**.
- L'etat initial **s'explique** a l'ecran : un etat qu'on ne s'explique pas se change au hasard.

#### Porte pour arbitrage
- **E-147** : `sftp_manager.render_policy()` contredit sa docstring sur quatre cles, toutes vers le
  permissif. Non corrigeable depuis le portage. A traiter avec E-142 et E-144.

### v1.37.79 — `adm/` D9a : les droits sudo portés, et le préréglage par défaut qui affirmait l'inverse de son module

**Deux défauts, et ils se composaient.**

L'écran affichait sous son préréglage **par défaut** : « Il ne peut pas toucher au reste du
systeme. » Le module qui produit cette règle même, `backend/sudo_manager.py:80-84`, écrit :
« AVERTISSEMENT : ce preset est EQUIVALENT ROOT. » Et un clic sur « Déployer » partait **sans aucune
confirmation** — alors que « Supprimer », qui *retire* le droit, en demandait une.

Un seul clic envoyait donc le préréglage équivalent root, pré-sélectionné, dont l'aide affirmait le
contraire. Écarts **E-142**, **E-143** et **E-144**.

#### Ajouté
- `laravel/app/Services/Politiques.php` — liste fermée des six préréglages et leur **portée**
  (`root` / `borné` / `inconnu`), le troisième disant qu'on ne *sait* pas plutôt qu'adoucissant.
- `laravel/app/Http/Controllers/PolitiquesController.php`, `resources/views/politiques.blade.php`,
  `public/js/politiques.js`, `lang/{fr,en}/politiques.php` — 71 clés, parité stricte.
- Route `GET /politiques` en `role:3` seul, comme le legacy et comme les onze routes du backend.
- `tests/e2e/go-adm-politiques.mjs` — **12 PASS legacy / 18 PASS portage, 0 FAIL**.

#### Corrigé côté portage
- **Le préréglage retenu par défaut ne donne plus root** : `read_logs` au lieu d'`apt_only`.
  Divergence assumée — un défaut est ce que la plupart des gens laisseront en place.
- **Déployer se confirme**, par un panneau qui nomme la machine, le compte et la portée réelle.
  Retirer aussi. L'audit, qui *lit*, n'en demande pas.
- **Un préréglage qui donne root l'annonce**, par un marqueur mesuré à **1100 px** de large : un
  marqueur large de zéro ne prévient personne.
- L'aide dit ce que le module documente — et **la garantie n'est pas une phrase** : la suite lit
  `sudo_manager.py` dans le conteneur à chaque exécution, en **dérive** quels préréglages sont
  signalés équivalents root, et refuse que l'écran les contredise.

#### Non porté, et dit
- L'**annulation d'un déploiement** réécrit un sudoers sur la machine : l'historique offre un lien
  marqué `↗` vers l'ancien portail, pas un bouton inerte.
- Le versant **SFTP** est D9b.

#### Porté pour arbitrage
- **E-144** : `sudo_deploy()` fait `data.get('preset', 'apt_only')`. Une requête sans `preset`
  obtient l'équivalence root. Non corrigeable depuis le portage.

### v1.37.78 — `graylog/` : l'etat persiste suit le VERDICT du geste, dans les deux sens

Entree ecrite APRES le commit `d190949`, qui l'avait omise — manquement a la
checklist releve par la seconde session. Le trou de numerotation entre v1.37.77 et
v1.37.79 venait de la.

Defaut releve en lisant `backend/routes/graylog.py` avant d'ecrire un clic de G2, et
corrige avec ses tests. **348 pytest verts** (341 + 7 neufs).

**LES DEUX ROUTES ECRIVAIENT LEUR ETAT SANS REGARDER LE RESULTAT.** `deploy()` posait
`forward_deployed=True` sans consulter `syntax_ok` ni `restart_ok`, alors que sa
reponse rendait `success: false`. `uninstall()` allait plus loin : il **jetait** le
code de retour de sa commande, ecrivait `forward_deployed=False` sans condition, et
rendait `success: True` quoi qu'il arrive.

| geste echoue | ce que l'ecran affirmait | la realite |
|---|---|---|
| `deploy` | « Transfert actif » | rien ne part |
| `uninstall` | « Non deploye », `success: true` | **le transfert continue** |

Le premier fait perdre des journaux. **Le second est une affirmation de
confidentialite** : quelqu'un qui retire le transfert pour une raison de conformite
recevait une confirmation franche d'un geste qui pouvait n'avoir rien fait. Et le
marqueur etant ECRIT EN BASE, il survit a la session — le message d'echec disparait
au rechargement, la pastille reste.

**LE CAS VISIBLE AVAIT ETE TRAITE, LE SUBTIL NON**, et c'est la forme du defaut plus
que le defaut lui-meme. `deploy` calcule bien `syntax_ok` et `restart_ok`, les rend
dans sa reponse, et compose son `success` avec : quelqu'un a donc pense a l'echec —
mais seulement pour la REPONSE, pas pour l'ETAT PERSISTE. `uninstall`, lui, ne pense
pas a l'echec du tout. Le meme motif que le prereglage `all_nopasswd` de D9a, dont
l'aide disait vrai quand celle du prereglage par defaut disait faux : ce n'est pas une
negligence uniforme, c'est le cas non evident pris a l'envers.

**CE QUE LE CORRECTIF POSE.** `forward_deployed` signifie « la configuration
RootWarden est ACTIVE sur cette machine » — donc `syntax_ok and restart_ok`. Les
fichiers sont ecrits AVANT ces deux controles, leur presence sur le disque ne prouve
rien. `last_deploy_at` n'est pose qu'en cas de succes : une tentative ratee n'est pas
un deploiement. `uninstall` capture son code de retour et, en cas d'echec, NE TOUCHE
PAS a l'etat — ecrire `False` affirmerait un retrait qui n'a pas eu lieu.

**LA PAGE LE DIT DANS LA LANGUE DE LA PERSONNE.** Le message du backend n'est pas
traduit ; le portage ajoute `err_retrait_actif` (FR et EN) pour ce cas precis, parce
que c'est le seul ou l'utilisateur croit avoir ARRETE quelque chose. Parite i18n
graylog : 68 cles FR = 68 EN.

**SEPT TESTS, ET ILS PEUVENT ECHOUER** — verifie plutot que suppose. En remettant
l'ancien fichier une minute : **3 failed, 4 passed**. Avec le correctif : **7
passed**. Les trois qui basculent sont exactement ceux du defaut.

Ils sont unitaires et non E2E parce que la branche d'echec n'est pas atteignable
depuis l'interface sans casser `rsyslog` sur une machine reelle : la session SSH est
factice, `execute_as_root` est SCRIPTE, et `_upsert_state` est INTERCEPTE plutot que
dirige vers la base — ce qui permet d'asserter non seulement ce qui a ete ecrit mais
QU'IL NE L'A PAS ETE. Un test qui lirait la base ne distinguerait pas « ecrit False »
de « pas ecrit ».

Le blueprint `graylog` n'etait PAS enregistre dans l'application de test : aucune de
ses routes n'etait joignable par un test HTTP. Ajoute.

**Le conteneur n'a pas ete redemarre** : le Python est lu au demarrage du processus,
donc ce commit etait inerte jusqu'au redemarrage suivant, et la seconde session tenait
le banc. Voir §8 du plan.

PARITE.md E-145. Detail dans docs/migration/MODULE-GRAYLOG.md §5.

### v1.37.77 — `graylog/` G1 porte : « Tester » executait une commande a distance sans rien demander

**18 entrees de menu portees sur 33.** Legacy 25/0, portage 26/0, base rouge 7/12.

**LE MODULE A DEUX SURFACES DE NATURE DIFFERENTE, ET G1 S'ARRETE A LA PREMIERE.** La configuration et
les gabarits lisent et ecrivent en base, sans joindre aucune machine. `deploy`, `test` et `uninstall`
ouvrent chacun une session SSH REELLE et executent en root : `apt-get install -y rsyslog`, ecriture
dans `/etc/rsyslog.d/`, `logger`, `systemctl restart rsyslog`. Les melanger ferait d'une suite de
lecture une suite qui installe des paquets. G1 mesure entierement la premiere surface et ne touche pas
la seconde ; G2 viendra avec sa cible (`test-server`, machine 2) et son geste de retour.

**LE DEFAUT PRINCIPAL : deux gestes sur trois demandent confirmation, le troisieme non.** `glDeploy`
(js:90) et `glUninstall` (js:107) posent un `confirm()`. **`glTest` (js:100) n'en a AUCUN** : un seul
clic ouvre une session SSH sur la machine de la ligne. Et c'est celui dont le nom suggere le moins
qu'il touche la machine.

Le tableau liste **toutes** les machines non archivees — la requete n'exclut que
`lifecycle_status = 'archived'` — donc `srv-zabbix` (production) y figure avec ses trois boutons, et
rien dans le legacy ne distingue sa ligne de celle du banc.

**PORTAGE** : les trois gestes ouvrent une confirmation EN PAGE qui NOMME la machine et son adresse, et
qui dit ce qui va se passer. Un encart de quatre lignes le dit AVANT le clic, et signale que le tableau
contient les machines de production — le legacy ne l'ecrit nulle part.

**CE QUE LA SUITE NE CLIQUE PAS, ET C'EST ECRIT DANS LE FICHIER.** Elle ouvre l'onglet Machines et LIT
le tableau ; elle ne clique aucun bouton de ligne. Cliquer « Tester » pour voir ce qu'il fait aurait
joint une machine pour de vrai, et sur la ligne de `srv-zabbix` cela aurait joint la production.

**DEUX DEFAUTS DE MON PROPRE PORTAGE, VUS A L'IMAGE ET INVISIBLES AU DOM.**

`.rw-panneau-decision` porte `display: flex`. Pose SUR un `<td>`, il ecrase `display: table-cell` : la
cellule SORT du modele de tableau et son `colspan` est ignore. Le panneau s'arretait a 745 px sur un
ecran de 1920, le reste de la ligne restant blanc — et l'attribut `colSpan` valait bien 6, donc aucune
assertion DOM ne pouvait le voir. Correctif : le conteneur flex va DANS la cellule. Mesure apres
correction : 1590/1618, 1070/1098, 907/923 px. Une assertion a ete ajoutee, sans quoi la correction
n'aurait aucun temoin. **`maintenance.js` a le meme defaut** (v1.37.57) : a corriger dans son propre
commit, avec sa suite rejouee.

Second defaut de la meme image : « Retirer » portait `rw-bouton--avertissement`, ce qui en faisait
l'element le plus voyant du tableau, plus que « Deployer ». Attirer l'oeil sur le geste destructeur est
l'inverse de ce qu'on veut.

**IL N'EXISTE AUCUNE ROUTE `/graylog/history`.** Le premier jet du portage l'appelait quand meme ;
verifie avant d'executer. Le legacy rend cet onglet en PHP depuis `user_logs`, filtre sur le prefixe de
chaine `[graylog]%` — un marqueur, pas une colonne. Le portage fait pareil. **Le commentaire d'en-tete
du controleur a du etre reecrit** : il annoncait « ce controleur ne lit rien lui-meme », ce qui devenait
faux ; le laisser aurait fait la sixieme occurrence du motif « le commentaire affirme plus que le code ».

**AUCUNE DONNEE NE SORT, ET C'EST MESURE** : `graylog_config` pointe sur `graylog.test`, et
`getent hosts graylog.test` depuis `rootwarden_python` NE RESOUT PAS. Un deploiement configurerait
rsyslog pour transferer vers un neant. C'est ce qui distingue ce module de `groups/`.

**La fixture de configuration est un reglage de FLOTTE** : la ligne existante est sauvegardee, modifiee,
puis restauree dans un `finally`, etat relu pour etre prouve. Le gabarit d'epreuve est borne par son
nom — un `DELETE FROM graylog_templates` emporterait les quatre gabarits reels.

**Les deux chemins de la garde sont exerces sans toucher a aucun droit** : `rw-test-super` (role 3)
atteint la page parce que le role 3 contourne `checkPermission` ; `rw-test-admin` (role 2 sans
`can_manage_graylog`) mesure le chemin « permission » ; `rw-test-user` le chemin « role ». 403 des deux
cotes. La garde de la route porte `perm:can_manage_graylog` et NON `can_admin_portal` : les confondre
elargirait l'acces a tous les administrateurs du portail.

Contrastes mesures aux trois largeurs : onglet actif 16,4:1, pastille 5,2:1, encart 5,44:1.
Tests : `tests/e2e/go-page-graylog-g1.mjs`, `tests/e2e/go-captures-graylog.mjs`.
Parite i18n graylog : 67 cles FR = 67 EN. PARITE.md E-138, E-139, E-140.
Inventaire prealable : `docs/migration/MODULE-GRAYLOG.md`.

### v1.37.76 — `adm/` D8 inventorie : la page est plus permissive que tout ce qu'elle offre

Inventaire mene **en lecture seule**, sans un seul clic — le banc etait prete a la seconde session,
qui porte `graylog/`. C'est exactement la fenetre ou deux sessions avancent sans se gener.

**Le sous-lot le plus dangereux d'`adm/`** : sept routes, dont un `userdel` distant irreversible.

#### La page admet le role 1, six de ses sept routes exigent le role 2

`server_users.php:11` : `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])`. La ligne 12 exige en
plus `can_manage_remote_users`.

| route | role exige | ce qu'elle fait |
|---|---|---|
| `/server_user_keys` (GET) | **aucun** | liste les cles d'un compte distant |
| `/scan_server_users` | 2 | enumere les comptes d'une machine |
| `/sshd_allow_user` | 2 | modifie `sshd_config` |
| `/remove_user_keys` | 2 | efface les `authorized_keys` |
| `/delete_remote_user` | 2 | **`userdel` distant, irreversible** |
| `/admin/user_inventory/classify` | 2 | classe un compte |
| `/admin/user_inventory/classify_bulk` | 2 | classe en masse |

Et la page **ne distingue aucun role dans son rendu** — mesure : `ROLE_` n'apparait qu'a la ligne 11.
Un role 1 porteur de la permission verrait donc tous les boutons et recevrait 401 sur six d'entre eux,
sans que rien ne le previenne avant le clic.

**C'est le miroir du defaut habituel du depot.** D'ordinaire la garde est sur la PAGE et pas sur la
REQUETE ; ici la page est plus LARGE que ses requetes. Ce n'est pas une faille — le backend refuse —
mais une interface qui propose des gestes qu'elle sait impossibles.

#### Etat vivant

`can_manage_remote_users` est une colonne reelle, **creable et basculable**, et **un seul compte la
porte : `superadmin`, role 3**. L'admission du role 1 est donc **latente** — meme formulation que K4 :
le trou est reel et a une attribution de permission d'etre atteignable.

#### Le seul `@require_machine_access` du module qui fasse quelque chose

`/server_user_keys` n'a **aucune garde de role** : un role 1 l'atteint, et le decorateur le borne
alors a ses propres machines. C'est le cas ou il MORD, au sens de la mesure des 57 sur 114. Les deux
passerelles s'accordent pour la laisser hors de leur liste « administration seulement » — coherent, et
delibere.

#### Trois decisions pour le port

Aligner la garde de la page sur ses actions **ou** rendre visible ce qu'un role 1 peut reellement
faire ; separer VERIFIER d'AGIR comme pour `ssh/` ; et **ne jamais declencher `/delete_remote_user`
depuis une suite** — interception avec avortement, on clique le vrai bouton et rien n'aboutit.

### v1.37.75 — `adm/` D7 : les cles d'API portees, et deux ecarts fermes PAR L'ABSENCE

**20 entrees de menu portees sur 33** — non : inchange a **19**, `api_keys.php` n'etant dans aucun
menu. Legacy **11/0**, portage **15/0**, suite inscrite au LOT.

#### Deux ecarts fermes en ne proposant plus rien

E-135 (portee validee en PCRE, appliquee en Python) et E-136 (portee non ancree) vivent tous les deux
dans l'echappatoire « Avance : editer les regex manuellement ». Les **preselections par module** du
legacy, elles, sont correctes et **toutes ancrees**.

Le portage les reprend **a l'identique** et n'offre rien d'autre. Ce portage ne compile pas de
Python : la seule facon de garantir qu'un motif accepte ici sera compilable la-bas est de ne rien
laisser saisir. Une entree libre validee se contourne par une requete forgee ; une entree libre
absente, non.

**Et la suite ASSERTE cette absence** — un champ libre reapparu passerait inapercu autrement.

La page **montre les motifs** sous chaque module : une portee qu'on coche sans voir ce qu'elle couvre
n'est pas une decision. Et une portee **vide** — qui vaut toutes les routes cote backend, `if scope:`
— est refusee a la creation et signalee en toutes lettres dans la liste.

#### E-137 ferme par le HACHAGE

`ClesApi::assureCleEnvironnement()` interroge le hachage, exactement comme `bootstrap_api_key.py` —
le seul des deux mecanismes qui fut idempotent. **Mesure au clic : creer une cle produit 0 ligne
supplementaire cote portage, 1 cote legacy.**

Une ligne **revoquee** compte aussi : si l'exploitant a revoque cette cle, la reposer irait contre sa
decision. La verification ne filtre donc pas sur `revoked_at`.

#### La cle en clair ne transite par AUCUN stockage

Elle n'est pas passee en message de session : le pilote est `file`, elle atterrirait sur le disque du
conteneur, la ou le legacy ne l'ecrit nulle part. Le controleur rend donc la vue **directement** en
reponse au POST. Le prix est connu et assume — recharger repropose le formulaire au navigateur,
exactement comme le legacy, et la seconde soumission echouerait sur l'unicite du nom.

Mesure : affichee une fois, **absente apres rechargement**. La suite le verifie sans jamais imprimer
la valeur, et prend ses captures apres rechargement.

#### Un defaut de rendu vu a l'image

Au 390 px, c'est la colonne **Action** qui cedait la place, le prefixe restant — exactement l'inverse
de la convention. **C'est l'appoint qui s'efface, jamais le geste.** `Prefixe` est passe en
`.rw-colonne-secondaire` et « Revoquer » est de nouveau atteignable au doigt.

#### Le point d'entree

La page n'est dans **aucun menu**, ni sur le legacy ni sur le portage : elle s'atteint depuis
l'en-tete de la page d'administration et depuis le tableau de bord. Le portage pose donc un lien
equivalent sur `/comptes`, **visible au seul role 3** — l'afficher plus bas menerait a un 403.

### v1.37.74 — `adm/` D7 caracterise : une portee validee par un moteur, appliquee par un autre

`tests/e2e/go-adm-cles-api.mjs` — **11 PASS / 0 FAIL sur le legacy**. **Non inscrite dans le LOT** :
`/cles-api` n'existe pas cote portage, la suite y serait rouge. Elle s'inscrira avec le port.

**Cette suite n'imprime jamais une cle.** La table ne stocke que `key_prefix` et `key_hash` ; la cle
n'existe en clair qu'une fois, dans la reponse de sa creation. Tout se mesure donc en BOOLEENS et en
LONGUEURS, et les captures sont prises APRES rechargement — une capture prise sur la page de creation
deposerait un secret vivant dans un fichier que personne ne surveille.

#### E-135 — validee en PCRE, appliquee en Python

`api_keys.php:47` compile chaque motif de portee avec `preg_match` ; `helpers.py:88` l'applique avec
`re.search`. Six motifs soumis aux deux moteurs : PHP les accepte **tous**, Python en refuse **deux** —
`(?<nom>…)` (groupe nomme a la PCRE) et `(?R)` (recursion). Puis mesure au clic : le formulaire accepte
`(?<zone>/cve_.*)` et cree la cle.

**Ce que la mesure DEDOUANE** : ce n'est pas une faille. L'exception remonte au `except Exception`
global, qui rend `(None, None)`, et le correctif **A07-02** n'accorde le repli `Config.API_KEY` que si
`API_KEY_BOOTSTRAP` est posee — **elle ne l'est pas** (mesure). Fail-closed. La consequence est une cle
rendue inutilisable et un journal qui accuse la base (« API key DB lookup failed ») pour un motif que
l'exploitant vient de saisir. **Avec le drapeau pose, le meme chemin serait fail-open.**

#### E-136 — la portee n'est pas ancree

`re.search` cherche n'importe ou : `/deploy` couvre `/x/deploy_platform_key`, `/cve_scan` couvre
`/admin/cve_scan_all`. Un exploitant qui borne une cle a `/deploy` lui accorde **tout chemin contenant
« deploy »** — dont `/deploy_platform_key`. Meme classe qu'E-02, deja tranchee pour la passerelle, sur
une autre surface.

#### E-137 — creer une cle enregistre une SECONDE fois la cle d'environnement

| mecanisme | nom pose | verification |
|---|---|---|
| `bootstrap_api_key.py:40` | `proxy-internal-legacy-bootstrap-YYYYMMDD` | **par le HACHAGE** — idempotent |
| `api_keys.php:86` | `proxy-internal-legacy` | **`INSERT IGNORE` sur le NOM** |

Les noms different, `key_hash` n'est pas unique : le doublon passe. Mesure au clic — 1 ligne de plus,
et `COUNT(DISTINCT key_hash)` sur les lignes `proxy-internal-legacy%` vaut **1**. Un secret, deux
enregistrements actifs.

**Et voici ce que ca produit** : `_validate_api_key_from_db` fait `WHERE key_hash = %s LIMIT 1`
**sans `ORDER BY`**. Apres avoir revoque l'une des deux, MySQL peut rendre l'une ou l'autre — la cle
est refusee alors qu'un enregistrement actif existe, ou continue d'ouvrir alors qu'on vient de la
revoquer. **La revocation devient non deterministe dans les deux sens.**

#### Le piege du `<details>`, sixieme occurrence et la plus retorse

Le champ de portee vit dans un `<details>` **imbrique** dans celui du formulaire. Deplier un niveau ne
suffit pas : sans la remontee complete, le nom se saisit, la cle se cree, et la **portee est perdue en
silence**. Le geste reussit, l'assertion echoue, et rien ne dit pourquoi. La suite relit desormais ce
qu'elle vient de saisir avant de soumettre.

### v1.37.73 — E-134 : le portage ignorait les permissions TEMPORAIRES

Trouve **en inventoriant D7**, sur une question qui n'avait rien a voir : `adm/api_keys.php` est garde
par `checkPermission('can_manage_api_keys')`, et lire ce que `checkPermission` fait vraiment a montre
qu'il consulte **trois** sources, pas une.

| source | ce qu'elle fait |
|---|---|
| role | `if ($roleId === 3) return true;` |
| `permissions` | la table permanente |
| **`temporary_permissions`** | `WHERE user_id = ? AND permission = ? AND expires_at > NOW()` |

`App\Services\Droits::permissions()` **n'en lisait que la deuxieme**. Un octroi temporaire ouvrait la
page sur l'ancien portail et rendait **403** ici.

La divergence allait dans le sens RESTRICTIF — elle ne fermait rien qui devait s'ouvrir — mais elle
cassait la parite, et elle rendait **inoperante** une capacite bien vivante.

#### Ce n'est pas une capacite morte

Trois routes backend (octroi role 3, liste et revocation role 2), le **formulaire complet** dans
`manage_permissions.php:184-267`, la purge des expirees par le planificateur a deux endroits, la purge
RGPD dans `privacy.php`, et une migration dediee.

**D5 a donc porte `manage_permissions.php` en laissant dehors la moitie de son interface**, et je ne
l'avais pas vu. D'ou un sous-lot **D5b** : porter les trois gestes.

#### Ferme pour la LECTURE, mesure sur les DEUX cibles

Assertion de **parite stricte**, pas d'ecart assume :

    sans octroi                  403
    octroi temporaire de 1 h     200
    apres revocation             403   — sans reconnexion

La derniere ligne compte autant que les autres : les droits sont relus a chaque requete.

References : `go-adm-permissions` legacy 10 -> **15**, portage 14 -> **19**.

#### Deux constats annexes

**`machine_id` est declare, jamais renseigne, jamais filtre.** La table le porte, la route d'octroi
l'accepte, `checkPermissionFromDB` ne le filtre pas, et le formulaire n'offre aucun selecteur. Un
octroi qui se croirait limite a une machine vaudrait partout. Le portage reprend ce comportement tel
quel et le signale, plutot que de corriger en silence une regle qu'aucune interface n'exerce.

**`can_manage_api_keys` ne garde rien** : consultee a un seul endroit, sur une page deja reservee au
role 3, qui contourne toute permission. Elle n'est pas seulement inatteignable — elle est **sans
objet**.

#### Ce que j'ai failli publier de faux

La premiere redaction d'E-134 accusait **E-118** de dire que cette permission « garde
`adm/api_keys.php` ». **E-118 dit exactement le contraire, et correctement.** Ce qui derivait, c'etait
le docblock de `Permissions.php` — un resume que j'avais relaye sans relire la source. Corrige avant
publication ; le docblock aussi.

C'est la **deuxieme fois de la journee** qu'une correction d'un travail anterieur est elle-meme a
corriger. Regle au §8 : **un resume n'est pas la source, meme quand c'est le sien.**

### v1.37.72 — `adm/` D6d : cycle de vie et test de connexion portes

**19 entrees de menu portees sur 33** (inchange : D6d enrichit une page deja portee). Legacy
**12/0**, portage **14/0**.

#### E-133 — `updated` recouvre deux situations opposees

`POST /server_lifecycle` rend `{'success': True, 'updated': cur.rowcount > 0}` **sans `SELECT`
prealable**. Or `rowcount` vaut 0 aussi bien quand on reecrit la valeur deja en place que quand la
machine n'existe pas :

| situation | rowcount | ce que ca veut dire |
|---|---|---|
| reecriture de la valeur en place | 0 | rien a faire — **succes** |
| machine inexistante | 0 | cible fausse — **echec** |

Une interface qui affiche « echec » ment dans le premier cas, une qui affiche « fait » ment dans le
second. **L'information n'est pas dans la reponse.** Mesure : `200 {"success":true,"updated":false}`.

**Par une requete FORGEE, et c'est le point interessant** : aucun clic ne peut produire ce cas, parce
que l'interface n'offre **jamais** le bouton de l'etat courant. Bonne propriete du legacy, reprise et
assertee. Le defaut est donc **latent** par l'interface — ce qui abaisse sa gravite sans changer sa
nature.

#### Le portage ferme l'ecart par la STRUCTURE

Le cycle de vie s'ecrit **en base**, sans passer par la route du backend : celle-ci ne fait qu'un
`UPDATE` sur `machines` — aucun effet distant, aucune session SSH, aucun courriel — il n'y a donc rien
a heriter d'un aller-retour, sauf son defaut. Meme decision que V4 pour `supervision_config`.

`Serveurs::definitCycle()` **resout la machine avant de la muter** et rend trois issues au lieu de
deux : `introuvable`, `inchange`, `fait`. L'ambiguite ne se corrige pas au niveau du libelle — elle se
corrige en **allant chercher l'information qui manquait**, et un `SELECT` suffit.

Le **test de connexion** passe par la passerelle : sa sonde TCP appartient au backend et
`/server_status` est deja en liste blanche. Il ne part **que sur un clic** — `health_check.php` a
montre ce que coute une page qui joint le parc en s'ouvrant — et le bouton se desactive pendant les
5 s de la sonde, sans quoi on clique trois fois en croyant que rien ne se passe. La lecture de la
reponse est fail-closed : sans `success`, on annonce un **echec de test**, jamais un etat de machine.

#### Un test qui ne pouvait pas echouer, attrape par un `(aucune)`

Le premier jet de l'etape cherchait le bouton de l'etat courant sur une machine deja dans cet etat,
ne le trouvait pas, ne declenchait aucune requete — et son assertion passait sur une **chaine vide**.
Seule la ligne `reponse a une reecriture sans effet : (aucune)` l'a revele. La suite exige desormais
d'avoir mesure quelque chose avant de conclure.

#### Deux defauts de rendu vus a l'image

Les boutons de cycle ne se poussaient pas a gauche : `.rw-jetons` porte `margin: 6px 0 10px`, qui
ecrase le `margin-right: auto` de `.rw-actions__gauche`. Et « Archiver » portait le rouge danger — le
meme que « Retirer du parc », alors que l'un est reversible et l'autre non. **Deux rouges cote a cote
pour deux niveaux de consequence ne signalent plus rien** : le rouge reste au seul geste qui ne se
defait pas.

### v1.37.71 — correction : verifier qu'un garde est ABSENT n'est pas verifier que son absence COMPTE

`v1.37.69` inscrivait un **IDOR** sur `POST /server_lifecycle`, au motif qu'il n'a pas
`@require_machine_access` la ou sa voisine `/server_status` le porte. **C'etait faux**, et la
correction est plus instructive que le constat.

`check_machine_access()` (`helpers.py:299-300`) commence par :

    if role_id >= 2:
        return True

et sa propre docstring le dit : « Admins (role >= 2) ont acces a tout ». Sur une route egalement
gardee par `@require_role(2)`, tout appelant qui franchit la garde de role franchit le controle
d'acces **sans condition**. Le decorateur y est donc **redondant** : l'ajouter a `/server_lifecycle`
ne changerait strictement rien.

**Il n'existe pas de « role 2 restreint » a un sous-ensemble de machines.** C'est une decision de
conception du produit, pas un oubli — mon « IDOR » supposait une categorie qui n'existe pas.

#### La mesure, sur tout le depot

**114 routes portent `@require_machine_access`, et il est SANS EFFET sur 57 d'entre elles** — celles
deja gardees au role >= 2 (`supervision.py`, `wazuh.py`, `policies.py`, `ssh.py`, `bashrc.py`…). Il
mord sur les 57 autres, atteignables au role 1 (`updates.py`, `services.py`, `fail2ban.py`,
`iptables.py`, `cve.py`…).

Ce n'est pas un trou : c'est une **redondance qui se lit comme une protection** — la forme « en-tete
qui ment », mais en code plutot qu'en commentaire. L'uniformiser a son interet, pour que le code cesse
de suggerer un controle qu'il n'apporte pas, mais **ce n'est pas un correctif de securite**.

#### Ce qui protege reellement `/server_status`

Son CORPS, pas son decorateur : refus d'un `machine_id` absent (`:72-74`), puis **resolution de l'IP
en base** au lieu d'accepter une IP brute — patch A01-02, ecrit dans sa docstring.

#### Ce qui reste entier

**L'ambiguite de `updated` est un defaut reel et independant.** `{'success': True, 'updated':
cur.rowcount > 0}` sans `SELECT` prealable : « rien a changer » et « machine absente » rendent tous
deux 0. Le correctif — resoudre l'objet avant de le muter — vaut pour dire la verite sur le resultat,
pas pour restreindre un acces.

#### La regle, au §8

**Verifier qu'un garde est ABSENT n'est pas verifier que son absence COMPTE.** J'ai mesure la premiere
proposition et relaye la seconde sans la mesurer. Lire ce que le garde FAIT avant de conclure de son
absence.

### v1.37.70 — E-130 chaine avec l'arbitrage K4, et le releve de niveau

Une relecture croisee a elargi E-130 sur quatre points, tous **verifies ici** avant d'etre inscrits.
Le quatrieme change le niveau d'un arbitrage deja ouvert.

#### La visibilite du formulaire n'est pas la garde — il n'y en a pas

`admin_page.php:44` fait `require_once includes/import_csv.php` **inconditionnellement, avant toute
logique d'onglet**. Le traitement s'execute des qu'un POST porte `import_type`, **que le formulaire
ait ete rendu ou non** : un POST forge vers `admin_page.php` suffit, l'onglet n'a jamais besoin d'etre
ouvert.

Et `import_csv.php` n'a **aucune garde propre** — zero `checkAuth`, zero `checkPermission`. Il depend
entierement de qui l'inclut. Il n'y a qu'un incluant aujourd'hui ; le jour ou une autre page l'inclut,
elle herite de l'exposition sans que rien ne le signale.

#### CINQUIEME en-tete qui ment

`admin_page.php:14-16` annonce « une seconde verification stricte via la BDD n'autorise que le
superadmin ». **Elle n'existe pas** : la ligne 41 est `checkPermission('can_admin_portal')`, qui admet
le role 2. C'est tres probablement ainsi que le trou a survecu — quiconque a relu l'en-tete a cru le
fichier reserve au role 3. Apres `compliance_report.php`, `ssh/index.php`, `iptables/index.php` et
`fail2ban/index.php`.

#### E-130 CHAINE avec K4, et c'est le vrai sujet

L'arbitrage K4 justifie son niveau ainsi : « aucun compte actif de role 1 ne porte `users.sudo = 1`,
donc le trou est reel et **a un `UPDATE` d'etre exploitable** ».

**L'import CSV EST cet `UPDATE`**, et il est atteignable un cran plus bas — role 2 porteur de
`can_admin_portal`, la ou `api/toggle_sudo.php` exige le role 3.

Pire, et il faut le lire deux fois : la garde hierarchique de l'import **fabrique exactement la forme
de compte que K4 attend**. Pour un importeur de role 2, `role=admin` est degrade a **role 1** — la
garde faisant correctement son travail — tandis que `sudo` reste a **1**, jamais touche. Soit : role 1
avec `sudo = 1`, la precondition du repli `NOPASSWD: ALL`, obtenue au role 2, au moyen d'un fichier.

Les deux ecarts se lisaient comme independants. **Ils sont chaines.**

#### Etat vivant

| | |
|---|---|
| comptes de role 2 | `rw-test-admin` (id 15) — `can_admin_portal = 0`, `sudo = 0` |
| comptes portant `sudo = 1` | `superadmin` (id 1, role 3) **seul** |

**Personne n'occupe la position aujourd'hui.** Mais l'ouvrir n'est plus un `UPDATE` en base : c'est
**une attribution de permission**, geste d'administration ordinaire.

#### Deux regles au §8

- **deux ecarts independants peuvent etre CHAINES, et l'arbitrage de l'un devient faux.** Quand un
  arbitrage repose sur une precondition ABSENTE, chercher qui peut la fournir — la reponse est rarement
  dans le meme module ;
- **un `require_once` inconditionnel place la garde AILLEURS que la ou on la lit.** Chercher l'incluant,
  et se demander ce qui arrive le jour ou il y en a deux.

### v1.37.69 — `adm/` D6c caracterise : l'import CSV contourne une garde de role 3

`tests/e2e/go-adm-import-csv.mjs` — **7 PASS / 0 FAIL sur le legacy**. La suite **n'est pas encore
inscrite dans le LOT** : cote portage l'import n'existe pas, elle y serait rouge, et une reference
rouge rendrait le LOT rouge. Elle s'inscrira avec le port.

#### E-130 — `users.sudo` s'ecrit par un fichier, sans la garde de role 3 du geste dedie

`users.sudo` est la **precondition du repli `NOPASSWD: ALL`** du module `ssh/`, le point le plus
dangereux du depot. Le geste dedie pour la poser, `adm/api/toggle_sudo.php`, porte
`checkAuth([ROLE_SUPERADMIN])` — role 3 SEUL.

`import_csv.php:162` lit `$data['sudo']` et l'ecrit directement. **Aucun controle de role.** La garde
hierarchique du fichier existe, elle est correcte, et elle ne touche que `$roleId`.

Mesure au navigateur, un fichier depose dans le formulaire :

    compte importe (role|sudo|courriel) : 2|1|(nul)

Le drapeau est retire dans la seconde qui suit.

**CE QUI EST MESURE ET CE QUI EST LU, dit separement** : la CAPACITE d'ecrire `sudo = 1` est mesuree
au clic, au role 3. La FRANCHISSABILITE au role 2 est etablie par LECTURE — le formulaire vit sur
`admin_page.php`, gardee par `can_admin_portal` qui admet le role 2, et rien sur le chemin du `sudo`
ne consulte le role. Aucun compte d'epreuve n'est a la fois role 2 et porteur de la permission : il
n'y a pas de quoi la mesurer au navigateur. Meme prudence que sur le repli lui-meme.

#### E-131 — un compte importe est inutilisable, et irrecuperable

Le mot de passe genere (`bin2hex(random_bytes(8))`) n'est **ni affiche, ni stocke, ni envoye** :
la variable meurt a la fin de l'iteration. `$sendWelcome`, qui l'aurait envoye, est **du code mort** —
lu une fois, jamais utilise, et **aucun formulaire n'emet `send_welcome`**. Reste la reinitialisation,
qui exige un `email` — colonne **facultative** du CSV. Mesure : `courriel : (nul)`.

Le compte est donc cree, actif, sans acces et sans recuperation. Il occupe un nom, compte dans les
listes, et apparait dans les selecteurs d'identite — c'est exactement ce qui est arrive aux cinq
comptes `e2e_test_*` du §7.

#### E-132 — la politique de mot de passe des COMPTES s'applique aux MACHINES, sur un seul chemin

`import_csv.php:89` appelle `encryptPassword($data['password'])` **sans son second argument**, donc
avec `$validate = true` ; `manage_servers.php:115` passe `false`. Mesure : une ligne CSV portant
`motdepasse` ne cree aucune machine, la meme valeur passe par le formulaire.

Le choix du formulaire est le bon : **un mot de passe de machine est impose par la machine**, pas
choisi ici. L'import applique donc une regle sans objet, et en silence.

#### E-129 s'etend : il y a TROIS copies du garde SSRF, pas deux

`import_csv.php:66-70` en porte une version a **cinq** conditions au lieu de sept, toujours par
prefixes. Mesuree au clic, par depot de fichier : `::ffff:169.254.169.254` est importee.

| copie | conditions | tombe |
|---|---|---|
| `manage_servers.php` | 7 | oui |
| `import_csv.php` | 5 | oui |
| `server_actions.php` | 0 | oui |

Trois copies, trois niveaux de completude, **aucune qui tienne**.

#### Ce qui marche, et qu'il faut dire aussi

L'import de serveurs cree bien la machine, chiffre les deux secrets en `sodium:`, et pose les
etiquettes de la colonne `tags`. La garde hierarchique sur `role_id` est correcte : un role 2 qui
importe `role=admin` obtient un role 1. **C'est uniquement `sudo` qui echappe au controle.**

#### Le piege de mesure, repaye une cinquieme fois — puis une sixieme

Le formulaire d'import de serveurs vit dans un PANNEAU D'ONGLET masque, pas dans un `<details>` : le
deplier ne suffit pas. Puis la correction a **deplace** le probleme — ouvrir l'onglet des serveurs
FERME celui des comptes, et l'etape suivante mesurait a son tour un panneau masque. L'onglet suit
desormais le formulaire vise.

#### Trois decisions avant le port

Que faire de la colonne `sudo` du format CSV, comment rendre utilisable un compte importe, et le
correctif E-129 cote legacy. Toutes trois en §7 du plan. **Le port de D6c attend ces reponses** :
retirer une colonne d'un format de fichier documente change un contrat.

### v1.37.68 — deux defauts du PORTAGE, trouves par relecture croisee

Une seconde session a relu D1 -> D6b en lecture seule et a trouve **deux defauts que mes suites n'ont
pas vus** — tous deux dans du code que je venais d'ecrire. Verifies ici avant d'etre relayes, puis
corriges, puis munis d'un garde-fou dont on a PROUVE qu'il peut echouer.

#### 1. Le garde SSRF que je venais de « completer » ne tenait pas — E-129

Le correctif A10-01 compare des PREFIXES DE CHAINE (`strpos($ip, '169.254.') === 0`). J'avais porte
cette regle fidelement, et j'y avais meme AJOUTE le multicast en gardant cette forme. Or :

    169.254.169.254           refusee
    ::ffff:169.254.169.254    ACCEPTEE   <- la MEME adresse
    ::ffff:a9fe:a9fe          ACCEPTEE   <- la meme, en hexadecimal
    ::ffff:127.0.0.1          ACCEPTEE
    ::ffff:224.0.0.1          ACCEPTEE

Mesure au clic : le formulaire d'ajout du legacy — **la copie « durcie », celle qui porte le
correctif** — cree la machine avec `::ffff:169.254.169.254`. Ce n'est donc pas E-127 sous un autre
angle : E-127 dit qu'une des deux copies n'a pas le garde, E-129 dit que **le garde lui-meme ne tient
pas**. Donner la copie durcie a `server_actions.php` n'aurait rien ferme.

C'est de la fidelite AU MAUVAIS NIVEAU : ce qu'il fallait porter, c'est l'INTENTION du correctif. La
lecon (« valider la FORME avant le contenu, ne jamais recopier une regle de securite ») etait au plan
depuis `//exemple.com`, et je l'ai ratee quand meme.

`Serveurs::valideIp()` reduit desormais l'adresse par `inet_pton`, ramene les notations mappee et
compatible a leur IPv4, puis compare des OCTETS : 0/8, 127/8, 169.254/16, 224/4, 240/4 cote IPv4 ;
`::`, `::1`, `fe80::/10`, `ff00::/8` cote IPv6. **18 cas mesures, 0 ecart.**

**Le legacy reste vulnerable** : le correctif touche un fichier de production non porte. Rien n'y a ete
modifie ; la decision est en §7 du plan.

#### 2. Deux gardes AFFAIBLIES par le portage

Le pire resultat possible pour une migration.

| geste | legacy | portage (avant) | portage (apres) |
|---|---|---|---|
| poser la cle SSH d'un compte | `api/update_user.php:31` **role 3 seul** | `role:2` | **`role:3`** |
| deverrouiller un compte | `api/unlock_user.php:23` **role 3 seul** | `role:2` | **`role:3`** |
| supprimer un compte | `api/delete_user.php` roles 2 et 3 | `role:3` | `role:3`, renforcement DELIBERE |

Un role 2 pouvait poser la cle SSH sur le compte d'un role 3 — donc, la cle une fois deployee, obtenir
un acces machine sous une identite qui n'est pas la sienne. Le legacy l'interdisait par le ROLE ; le
portage avait descendu le niveau **et** omis la garde hierarchique que `motDePasse` et
`reinitialiserTotp` portent.

La cause : les cinq gestes de `comptes` viennent de **quatre fichiers differents** du legacy et ne sont
pas au meme niveau. Une lecture globale du module donne une reponse moyenne, et la moyenne est fausse.

Le renforcement sur la suppression (E-116 : supprimer un compte efface son journal d'audit) est
desormais DIT dans `web.php` — non declare, un renforcement se relit comme une erreur.

#### Deux garde-fous, tous deux prouves capables d'echouer

- `go-adm-comptes` lit les gardes **reellement enregistrees** par le routeur et les compare a un
  tableau releve fichier par fichier. Le motif de ne pas passer par un clic est ecrit : aucun compte
  disponible ne distingue `role:2 + perm` de `role:3`, un role 2 sans la permission recevant 403 dans
  les deux cas. Verifie : **0** ecart avec l'attente juste, **2** avec celle d'avant le correctif,
  **1** sur une route absente. Reference legacy 13 -> 14, portage 17 -> 18 ;
- `go-adm-serveurs` tape `::ffff:169.254.169.254` **dans le formulaire** et verifie qu'aucune machine
  n'est creee. L'etape est placee AVANT la creation legitime : posee apres, elle aurait porte le meme
  nom, aurait ete refusee pour cause de DOUBLON, et serait passee pour une bonne nouvelle. Reference
  portage 20 -> 21, legacy inchangee a 18 (l'ecart y est constate).

#### Ce sur quoi la relecture s'est trompee

Elle donnait `manage_servers.php:770` comme appelant vivant de `server_actions.php`. Le bloc commente
va de `:661` a `:923` : la ligne 770 est dedans. Le fond ne change pas — le fichier est bien vivant,
par ses quatre autres appels.

### v1.37.67 — `adm/` D6b : quatre gestes qui ne marchent pas, et un garde qui se trompe deux fois de sens

**19 entrees de menu portees sur 33** (inchange : D6b enrichit une page deja portee). Legacy **10/0**,
portage **18/0**.

**D6 a ete redecoupe une SECONDE fois, et pour une raison mesuree.** L'inventaire l'avait decoupe par
FICHIER, or deux capacites de la carte serveur ne vivent dans aucun de ses fichiers : `setLifecycle` et
`testServerConnection` appellent le BACKEND. D6b garde `server_actions.php` ; l'import CSV devient
**D6c** ; le cycle de vie et le test de connexion deviennent **D6d**.

#### Quatre ecarts, tous mesures au navigateur

- **E-125** — les **quatre** gestes vivants d'etiquettes et de notes sont **INERTES**. Le clic emet
  bien sa requete, et le serveur repond `{"success":false,"message":"Token CSRF invalide"}`. Quatre
  pieces correctes et une liste incomplete : `admin_page.php` rend le meta, `menu.php` charge
  `utils.js`, `utils.js` enrobe `window.fetch` et pose l'en-tete — **mais seulement si l'URL contient
  `api_proxy.php`, `/adm/api/` ou `/auth/`**. `/adm/includes/` n'est dans aucune des trois. Le point
  d'action refuse sa propre interface.
- **E-126** — un role 2 **refuse en 403** sur `admin_page.php` pose quand meme une etiquette : jeton
  CSRF lu sur `profile.php`, `200 {"success":true}`, **1 ligne reellement ecrite en base**.
  `server_actions.php` porte `checkAuth([2,3])` et zero `checkPermission`.
- **E-127** — le correctif SSRF **A10-01 n'a ete applique qu'a un des deux chemins d'ecriture**. La
  copie de `validateInput()` de `server_actions.php` tient en une ligne, sans aucun garde : le chemin
  AJAX accepte **169.254.169.254** — l'adresse que le commentaire du correctif nomme explicitement — et
  cree la machine. Sixieme occurrence du motif « a moitie corrige », et la plus consequente.
- **E-128** — `delete_note` supprime par le seul identifiant, sans regarder la machine.

#### Le contraste est le vrai sujet

Le meme controle CSRF **tient dehors l'interface legitime** (E-125) et **laisse entrer la requete
forgee** (E-126, E-127), puisque le jeton se lit dans un champ cache de `profile.php`, ouvert a tout
compte authentifie. Un garde qui se trompe de sens dans les deux directions.

#### Comment la cause a ete trouvee

Le premier jet de la suite concluait « le clic n'ecrit pas ». Vrai, et inutilisable : « rien n'a ete
ecrit » a trois causes — la requete n'est pas partie, elle est partie et a ete refusee, elle a reussi
et ecrit ailleurs — et elles ne se corrigent pas de la meme facon. La suite ecoute desormais la
REPONSE du point d'action, et c'est elle qui a nomme le coupable en un mot.

#### Le portage

Etiquettes et notes vivent dans chaque carte de `/serveurs`, sous `role:2` + `perm:can_admin_portal`.

- **Quatre formulaires, zero `fetch`.** Plus de liste d'URL a tenir a jour, donc plus d'entree a y
  oublier — et les quatre gestes marchent **sans une ligne de JavaScript**. Le legacy rechargeait la
  page apres chaque succes : le rendu est le meme, pour une piece mobile en moins.
- **Une note se resout par le COUPLE** machine + note : viser la note d'une autre machine ne supprime
  rien.
- **La regle de normalisation est ANNONCEE** sous le champ. Le legacy ampute la saisie en silence, et
  le fait deux fois — en JavaScript, ou cela ne protege rien, et en PHP.
- **La borne de cinq notes s'enonce.** Le legacy coupe a cinq sans le dire : on croit voir tout.
- **Deux requetes au lieu de deux par machine.** Le legacy emet une requete d'etiquettes et une de
  notes DANS sa boucle d'affichage.

#### Un defaut de rendu que D6a m'avait cache

La case « Nettoyer les comptes obsoletes » s'affichait AU-DESSUS de son libelle : `.rw-champ` n'est
qu'une marge, et le libelle est un `display: block`. Les captures de D6a ne descendaient pas jusqu'a
une carte ouverte ; celles de D6b y defilent, et le defaut est apparu a la premiere image. **Deux fois
de suite, une capture montrait autre chose que son sujet.**

### v1.37.66 — les 33 confirmations de la page d'administration, mesurees au navigateur

`tests/e2e/go-adm-permissions.mjs` gagne une etape : elle demande au moteur si chaque attribut
`onclick` portant un `confirm()` **s'analyse**. `new Function(code)` compile **sans executer** — aucune
boite ne s'ouvre, aucun formulaire ne part — et un `\'` echappe ne peut pas la tromper, la ou un
decompte d'apostrophes se serait laisse faire.

**Resultat : 33 boutons, 33 non analysables.**

| bouton | occurrences | forme | consequence |
|---|---|---|---|
| `change_password` | 10 | `submit`, dans un form | le geste part **sans confirmation** |
| `reset_2fa` | 10 | `submit`, dans un form | le geste part **sans confirmation** |
| suppression de compte | 10 | sans `type`, hors form | bouton **inerte** |
| `delete_server` | 3 | `submit`, dans un form | le geste part **sans confirmation** |

**23 des 33 sont des `submit` dans un formulaire.** Le code recu par le navigateur est coupe la ou le
guillemet ouvre : `return confirm('Reinitialiser le mot de passe de `.

Cette mesure **ferme la correction d'E-114** ouverte par D6a (`v1.37.65`), et confirme que ses deux
conclusions etaient fausses : ce n'est pas « seulement en francais » — les deux catalogues portent le
guillemet — et le troisieme bouton **ne fonctionne pas** davantage que les autres. C'est exactement le
pas que le premier jet avait saute.

Le portage porte **zero** bouton a `confirm()` : ses confirmations sont des panneaux, ou le texte est
pose par `textContent`. Reference portage 13 -> **14** ; legacy inchangee a 10, l'ecart y etant
constate et non asserte.

Le journal de l'etape **regroupe** ses lignes par cas : onze comptes fois trois boutons donnaient 33
lignes identiques, et un journal qu'on ne relit pas ne sert a rien.

### v1.37.65 — `adm/` D6a : un fragment mort qui repond, et une confirmation qui ne s'execute pas

**19 entrees de menu portees sur 33** (inchange : D6a ajoute une page sous l'entree « Admin », reliee
par une sous-navigation, et n'ouvre pas d'entree nouvelle). Legacy **18/0**, portage **20/0**, base
rouge mesuree a 7/2 avant portage.

**D6 pesait 1 746 lignes et a ete redecoupe.** D6a prend la page (`manage_servers.php` 939 l. et son
fragment `manage_servers_table.php` 352 l.), D6b prendra les actions (`server_actions.php`,
`import_csv.php`).

#### Cinq ecarts, tous mesures

- **E-120** — `manage_servers_table.php` est **mort par navigation** : sa seule reference dans tout le
  depot est le `fetch()` de `manage_servers.php:709`, **a l'interieur d'un bloc commente** de 263
  lignes. Apache le sert quand meme, et il appelle `checkAuth([2,3])` **sans** le
  `checkPermission('can_admin_portal')` que sa page hote exige. Mesure au navigateur avec un compte de
  role 2 sans cette permission : **403** sur la page, **200** sur le fragment, inventaire du parc
  rendu. Sixieme occurrence de « la garde est sur la PAGE, pas sur la REQUETE » — cette fois sur du
  code mort qui repond encore.
- **E-121** — le **guillemet double** de `servers.confirm_delete` ferme l'attribut `onclick`. Le
  navigateur ne recoit que `return confirm('Supprimer le serveur ` : le gestionnaire ne s'attache pas,
  et le bouton etant `type="submit"` dans le formulaire, **la machine est retiree du parc sans
  qu'aucune boite n'ait paru**. Dans les **deux** langues.
- **E-122** — 68 lignes de recherche, filtres, tri et pagination, mortes **deux fois** : aucun controle
  n'emet leurs parametres, et un second `query()` sans `WHERE` ecrase leur resultat.
- **E-123** — le commentaire du correctif A10-01 annonce le refus du **multicast (224/4)** ; aucune des
  sept conditions ne le teste.
- **E-124** — la legende affiche **PREPROD**, valeur que la liste fermee refuse, et tait **OTHER**, la
  seule que le formulaire offre en quatrieme. Vu **a l'image**.

#### Ce que la mesure a DEDOUANE

Le fragment rend bien deux colonnes « Mot de Passe » — mais ce sont des `<input type="password">`
**vides** : **6 champs, 0 rempli**. Aucun secret stocke n'est imprime. S'arreter aux en-tetes de
colonnes aurait fait annoncer une fuite de justificatifs ; c'est une divulgation d'inventaire.

#### Ce que D6a a fait corriger AILLEURS

La cause de E-121 n'est pas l'apostrophe mais le **guillemet**, un niveau de delimiteur au-dessus.
Deux conclusions d'**E-114** (sous-lot D3) sont donc fausses — « seulement en francais » et « le
troisieme bouton fonctionne » : les trois chaines de `manage_roles.php` portent deux guillemets
chacune, dans les deux langues, et coupent leur attribut aux 58e, 49e et 49e caracteres. Une note de
correction est ajoutee a E-114 ; la confirmation **au navigateur** sur cette page reste a faire et est
inscrite en §7 du plan.

#### Le portage

`/serveurs`, garde par `role:2` + `perm:can_admin_portal` — la garde de la page hote, appliquee **au
seul endroit qui repond** : il n'y a pas de fragment separe.

- **Trois gestes, trois routes.** Le legacy les distingue par le `name` du bouton clique dans un POST
  unique vers la page ; un `name` oublie sur un `<button>` y transforme une modification en creation.
- **Le retrait ouvre un panneau** qui nomme la machine et dit ce que le geste engage — et surtout ce
  qu'il n'engage pas : la machine elle-meme n'est pas touchee, aucun acces n'y est revoque. Le texte
  est pose par `textContent`. La suite verifie que l'ouverture du panneau **n'ecrit rien**.
- **Le garde SSRF est porte ET complete** : les huit conditions, dont celle que le commentaire du
  legacy promettait. Comparaison sur le premier octet (224 a 239), pas sur le texte.
- **Les 68 lignes mortes ne sont PAS portees.** Porter du code mort, ce n'est plus migrer, c'est
  concevoir. Le filtre reste a l'affichage, et porte sur les **trois** champs que la recherche morte
  visait — tous trois affiches dans l'en-tete de la carte.
- **Les mots de passe de machines sont chiffres** par `App\Support\SecretExploitation`, schema
  `sodium:` dont l'aller-retour avec le backend Python a ete mesure. Verifie en base par la suite :
  `sodium:|sodium:`.
- **Une sous-navigation relie les trois onglets** d'`admin_page.php`, desormais tous portes. Elle
  reutilise `.rw-onglets`, et l'onglet des permissions n'apparait qu'au role 3 — sa route l'exige, et
  un onglet visible menant a un 403 donne a croire a un droit qu'on n'a pas.

#### Trois defauts de rendu, vus a l'image et corriges

`.rw-pastille` est une pastille **de texte** : vide, elle ne rendait qu'un rectangle invisible. L'etat
porte desormais son libelle (« en ligne », « hors ligne », « etat inconnu ») — une information qui ne
tient qu'a la couleur n'est pas lue par tout le monde. Le bloc d'ajout a repris l'affordance de
depliant, et le champ de filtre son gabarit.

#### Un defaut de la suite elle-meme

L'etape de captures ne rouvrait pas l'onglet « Serveurs » du legacy : les trois images montraient
l'onglet des comptes. Vu **en regardant l'image**. Une capture qui montre autre chose que ce qu'on
croit sert de preuve a un examen qui n'a pas eu lieu.

#### Reste en base, signale et non touche

**5 comptes `e2e_test_*`** crees entre le 2026-07-25 et le 2026-08-12 par des suites anterieures.
Destructeur a retirer, et ils n'appartiennent pas a ce chantier : arbitrage inscrit en §7.

### v1.37.64 — le chiffrement des secrets n'est pas propre a la supervision

`App\Support\SecretSupervision` devient `App\Support\SecretExploitation`. **Aucun changement de
comportement** : meme schema, meme etiquette de derivation, meme sortie.

Le nom datait de son premier appelant, pas de son role. Le sous-lot D6a doit chiffrer les mots de
passe SSH des machines, et il utilise exactement ce schema — celui de `encryptPassword`
(`legacy/adm/includes/crypto.php:127`), dont l'aller-retour avec le backend Python a ete **mesure**
le 2026-08-22. Ecrire `SecretSupervision::chiffre($motDePasseSsh)` aurait installe une fausse piste
durable : la prochaine relecture aurait cherche un rapport avec Zabbix la ou il n'y en a pas.

La separation qui compte, elle, ne bouge pas : les secrets d'EXPLOITATION (mots de passe de
machines, secrets partages de supervision) derivent avec `rootwarden-aes`, les secrets TOTP avec
`rootwarden-totp` dans `App\Support\TotpCrypto`. Melanger les deux rendrait un secret illisible par
le portail qui ne l'a pas ecrit.

Trois sites de code touches (`Services/Supervision.php`, `routes/web.php`, la classe), zero test
modifie.

### v1.37.63 — `adm/` D5 : la bascule de permission fonctionne enfin

**19 entrees de menu portees sur 33** (D5 ajoute une page a un module deja porte). Legacy 10/0,
portage 13/0 (`tests/e2e/go-adm-permissions.mjs`).

**E-119 — trois pieces correctes qui formaient une impasse.** La garde step-up de
`update_permissions.php:60` est bonne, le POST htmx part bien, et le refus 403 est juste. Mais le
modal qui permettrait d'y repondre est une surcouche de `window.fetch`, et htmx n'emploie que
`XMLHttpRequest` : la surcouche ne voit jamais la requete, aucun geste d'interface ne permet
d'obtenir la marque, et htmx ne remplace rien sur un 4xx. Mesure : le POST part, le 403 revient,
`can_scan_cve` reste a 0, l'ecran ne bouge pas. **Cocher une permission ne faisait rien, en silence,
meme pour un role 3.**

Le portage garde la MEME exigence et lui donne un chemin : le panneau de re-authentification EN PAGE
ecrit pour D4. Mesure apres portage : refus annonce, panneau ouvert, code saisi, et `can_scan_cve`
passe a 1.

**E-118 — trois listes pour les memes droits, et les ecarts se croisaient.** 18 colonnes, 14 posables
a la creation, 16 basculables ensuite. `can_manage_fail2ban` s'accordait sans se reprendre ;
`can_manage_api_keys` etait inatteignable dans les deux sens — alors que toutes deux gardent de
vraies pages. Le portage LIT LA LISTE DANS LE SCHEMA : une colonne ajoutee devient reglable, une
colonne retiree disparait partout a la fois. Il ne peut plus y avoir de divergence, parce qu'il n'y a
plus qu'une source.

L'interpolation du nom de colonne reste inevitable — PDO ne lie pas un nom de colonne — mais elle est
desormais bornee par le schema lui-meme, ce qui est plus sur qu'une liste blanche recopiee : une
liste vieillit, le schema est la verite.

**LA MESURE A DEDOUANE `update_server_access.php`**, et c'est dit aussi nettement que le reste : le
correctif A01 pose bien `if ($currentRoleId < 3)` sur la branche `update_sudo`, la liste de presets
est fermee et le `runas` valide par une expression reguliere. Aucun defaut a signaler.

**ET LE PLAN SE TROMPAIT SUR SES PROPRES COMPTES DE TEST.** Il annoncait UNE permission pour
`rw-test-admin` ; il en porte NEUF, mesurees colonne par colonne — dont `can_manage_fail2ban`, l'une
des deux que le legacy ne sait pas reprendre. Plusieurs suites mesurent une garde en s'appuyant sur
« ce compte n'a pas telle permission » : concevoir un test sur cette ligne aurait produit un vert qui
ne mesure rien. Corrige en §6 du plan.

45 cles FR et EN, jeux compares — les DIX-HUIT permissions sont nommees, y compris les deux que le
legacy laisse hors de son interface. Garde de page : role 3 + `can_admin_portal`. La garde
hierarchique vit dans le controleur, parce qu'elle depend de la CIBLE.

Ecarts : **E-118 et E-119**, les deux fermes par ce portage.

### v1.37.62 — `adm/` D4 : le geste sur devient atteignable, et le step-up sort de l'attente

**19 entrees de menu portees sur 33** (inchange : D4 ajoute des gestes a une page deja portee).
Legacy 10/0, portage **21/0** (`tests/e2e/go-adm-suppression.mjs`). L'ecart de onze assertions n'est
pas un gonflement : le portage exerce un PARCOURS que le legacy n'a pas.

**LE PANNEAU DE STEP-UP, DIFFERE DEPUIS A5, EST ECRIT — ET MESURE.** Le sous-lot A5 avait porte le
mecanisme (`v1.37.50`) en differant explicitement son panneau de decision « a son premier
consommateur, faute de pouvoir le mesurer ». D4 est ce consommateur. Le parcours complet est
desormais exerce de bout en bout : confirmation qui naît DESACTIVEE, saisie fausse qui la laisse
inerte, saisie exacte du nom qui l'active, `DELETE 403 {"step_up_required":true,
"action":"compte_supprimer"}`, panneau de re-authentification EN PAGE, code a six chiffres, et le
geste qui repart de lui-meme.

`StepUp::ACTIONS_PORTAGE` etend la liste FERMEE aux gestes du portage. `RoutesBackend` ne couvre que
les chemins transmis au backend — c'est son objet, et l'y elargir aurait brouille son sens.

**E-116 — supprimer un compte EMPORTAIT son journal d'audit.** `information_schema` rend 34 cles
etrangeres vers `users`, dont douze en CASCADE — et `user_logs.user_id` en fait partie. Comme le
sous-lot D1 a rendu ce journal VERIFIABLE, en retirer du milieu ROMPT la chaine. Le portage pose la
garde qui manquait : **un compte qui porte un journal ne se supprime pas**. La page demande l'etat
AVANT d'ouvrir son panneau, dit combien de lignes seraient emportees, et propose l'anonymisation.

Ce defaut n'a pas ete provoque pour le demontrer : rompre la chaine est irreversible sur un artefact
que l'exploitant suit. Il est etabli par la mesure du schema, et la suite n'agit que sur un compte
fraichement cree — dont `user_logs` est vide — en VERIFIANT cette precondition avant de cliquer.

**E-117 — le geste RGPD devient atteignable.** `anonymize_user.php` fait exactement ce qu'il faut, et
son commentaire ligne 117 le dit : « les user_logs et login_history sont CONSERVES pour tracabilite
legale ». Il est garde, documente — et aucun element de l'interface du legacy ne l'appelle. Ici les
deux gestes sont offerts cote a cote, et c'est l'anonymisation qui est proposee des que le compte
porte un journal.

**UN PIEGE REPRODUIT, ET C'EST LA LECON DU SOUS-LOT.** La premiere version de la suite a echoue a sa
DEUXIEME execution : la marque de step-up vit dans le cache quinze minutes et SURVIT a l'execution,
si bien que le `DELETE` rendait 200 au lieu de 403. C'est mot pour mot la lecon d'A5 — « une fixture,
c'est aussi ce que le test ACCORDE » — payee dans le sous-lot qui consomme le step-up. La suite
revoque desormais a l'entree et dans son `finally`.

**Vu a l'image et NON RESOLU** : les deux nouveaux boutons portent le tableau au-dela du cadre a
1400 px, et « Anonymiser » y est coupe. Le cadre defile et le signale, mais la regle du chantier veut
que la colonne actionnable ne cede jamais. Une tentative de repli du courriel a ete ANNULEE :
`.rw-etroit-seul--inline` ne s'affiche que SOUS 720 px — une classe qui existe et veut dire autre
chose. A reprendre avec D5.

70 cles FR et EN, jeux compares. Gardes : role 3 + `can_admin_portal` SUR LA ROUTE pour les deux
gestes, plus les refus reprris du legacy — soi-meme, rang egal ou superieur, dernier
super-administrateur actif.

Ecarts : **E-116 et E-117**, les deux fermes par ce portage.

### v1.37.61 — `adm/` D3 : la politique de mot de passe s'applique enfin a l'administrateur

**19 entrees de menu portees sur 33.** Legacy 13/0, portage 17/0
(`tests/e2e/go-adm-comptes.mjs`). `go-socle-navigation` passe de 51 a 52, mesure : une seule ligne
« Admin », celle de `rw-test-super`, et elle resout en 200 sur `/comptes`.

**QUATRE DEFAUTS FERMES.**

**E-112 — la politique etait contournee par le SEUL chemin qui fixe le mot de passe d'autrui.**
Libre-service : 15 caracteres, quatre classes, non reutilise, historique ecrit. Administrateur : huit
caracteres, rien d'autre. `password123` etait refuse a quelqu'un pour lui-meme et accepte a un
administrateur pour autrui, et `password_history` restait vide — si bien que le mot de passe pose
pouvait etre repose aussitot. `Comptes::definitMotDePasse()` est desormais le SEUL point d'ecriture :
il applique la politique et ecrit l'historique, quel que soit l'auteur du geste.

**LA MESURE A DEDOUANE SUR LE COUT, et c'est dit aussi nettement que le reste.** `PASSWORD_DEFAULT`
rend `$2y$12$`, exactement comme `BCRYPT_COST` : le hache n'etait PAS plus faible. Le defaut etait
LATENT — `BCRYPT_COST` se lit dans une variable d'environnement, et si l'exploitant la releve, ce
chemin ne suivrait pas. Le portage lit le cout au meme endroit que le legacy, donc les deux portails
restent d'accord et un compte reste connectable des deux cotes.

**E-113 — le mot de passe genere ne traverse plus la page.** Le legacy le place dans le HTML, d'ou il
part dans l'historique du navigateur — et `strip_tags` l'AMPUTE au passage, l'alphabet contenant `<`
et `>` : `ab<cd>ef12` s'affichait `abef12`, si bien que l'administrateur recopiait une chaine qui
n'etait pas celle enregistree. Ici il arrive dans la reponse du geste, s'affiche une fois, et ne
survit pas au rechargement — c'est ce que la suite mesure. L'alphabet du generateur exclut les
caracteres de balisage, et le tirage garantit une occurrence de chaque classe : un mot de passe
genere ne peut pas etre refuse par notre propre politique.

**E-114 — l'apostrophe qui desarmait deux confirmations.** Le legacy place ses chaines traduites dans
des litteraux JavaScript entre apostrophes ; `L'utilisateur` et `l'utilisateur` fermaient le
litteral, l'`onclick` ne s'analysait pas, et « Reinitialiser la 2FA » comme « Supprimer
l'utilisateur » partaient SANS confirmation — en francais seulement. Le portage n'a aucune boite
native : le texte traduit y est du CONTENU, pose par `textContent`, et le probleme ne peut pas
exister. Le panneau de decision NOMME le compte vise et dit ce que le geste engage.

**E-115 — un seul ecrivain pour la cle SSH, et il valide.** Le legacy en a trois, qui ne s'accordent
ni sur la validation, ni sur le journal, ni sur la forme stockee — dont un qui applique
`htmlspecialchars` A L'ECRITURE sur une valeur que `ssh/` deploie dans `authorized_keys`. Ici la
forme est verifiee (algorithme en liste fermee, corps base64, une seule ligne), la valeur est stockee
TELLE QUELLE, et l'echappement appartient au rendu.

**CHAQUE ECRITURE EST JOURNALISEE, ET SCELLEE.** Le legacy a un point d'entree qui n'ecrit rien dans
`user_logs`. Ici chaque geste journalise, et l'insertion reprend la chaine de hachage que le sous-lot
D1 verifie — une ecriture nue creuserait le trou que D1 vient de mesurer.

**Ce qui n'est PAS porte, et la page le DIT** : `admin_page.php` porte trois onglets ; seuls les
comptes le sont. La page affiche un encart qui nomme les deux autres et offre un lien marque vers
l'ancien portail, plutot que de laisser croire qu'ils ont disparu.

51 cles FR et EN, jeux compares. Garde de page : role 2 + `can_admin_portal`, relevee du legacy. La
garde HIERARCHIQUE — un role 2 ne touche pas un role 3 — vit dans le controleur, parce qu'elle depend
de la CIBLE et pas seulement de l'auteur. La reinitialisation du second facteur exige le role 3 SUR
LA ROUTE.

Ecarts : **E-112 a E-115**, les quatre fermes par ce portage.

### v1.37.60 — `adm/` D2 : « Marquer lu » ne marquait rien, et l'ecran l'affirmait

**Notifications portees.** Legacy 16/0, portage 20/0 (`tests/e2e/go-adm-notifications.mjs`). Le
sous-lot DEBORDE du module : la page vit a la racine du legacy (`notifications.php`), le point d'API
dans `adm/api/`, et la pastille dans `menu.php` — donc sur toutes les pages. 541 lignes.

**QUATRE DEFAUTS FERMES.**

**E-108 — « Marquer lu » ne marquait rien.** Le bouton du legacy porte
`onclick="… this.remove();"` : il se retire du DOM PENDANT l'evenement de clic, si bien que htmx —
charge, verifie — n'emet AUCUNE requete. Le surlignage disparait, le bouton aussi, la base ne bouge
pas. Trois mesures convergent sur la meme seconde : htmx present / zero POST / bouton disparu. Ni
erreur, ni journal, ni trace reseau. **Dans le portage, l'ecran ne bouge qu'APRES la reponse du
serveur**, et le compteur de la pastille vient de cette meme reponse — deux appels peuvent se
croiser, un seul ne le peut pas.

**E-109 — un GET ecrivait, sans le moindre jeton.** `checkCsrfToken()` n'est appele que sous
`if (METHOD === 'POST')`, alors que l'action est lue dans `$_GET` en premier :
`GET ?action=read_all` rendait `200 {"updated":2}`. Chaque geste qui ecrit est desormais un **POST**
sur sa propre route ; le seul GET est le compteur. Mesure apres portage : **405**.

**E-110 — le correctif A01 ne couvrait qu'une branche sur trois.** Son commentaire nomme pourtant le
probleme. `delete` scinde sur le role ; `read` et `read_all` gardaient `OR user_id = 0` pour tout le
monde, alors que la LECTURE filtre — un role 1 ecrivait donc sur des lignes qu'il ne voit pas. Le
portage calcule la portee **une fois**, dans `Notifications::portee()`, et les quatre gestes s'y
adossent : il ne peut plus y avoir de branche oubliee, parce qu'il n'y a plus de branche.

**E-111 — quatre vocabulaires pour la colonne `type`.** Le partage n'etait pas arbitraire : il suit
le CHEMIN D'EMISSION du backend. `notify()` / `notify_admins()` inserent sans consulter les
preferences (cve_critical, server_offline, perm_granted, perm_expired, password_expiry) ;
`notify_subscribed()` les consulte (cve_scan, security_alert, ssh_audit). **La page du legacy nomme
exactement les premiers et affiche « Autre » pour les seconds** — donc precisement pour ceux dont on
a regle la preference. Mesure sur la meme pastille : legacy « Autre », portage « Scan CVE ». La liste
du portage porte **les douze**, et un type inconnu sort sous son nom brut, qui se diagnostique.

**Ce que le portage NE corrige PAS, et le dit a l'ecran** : les cinq types du chemin direct restent
inconfigurables tant que `notify()` ne consulte pas les preferences. La page de reglages porte un
encart qui les nomme, plutot que de laisser croire qu'elle les gouverne.

**Un defaut de mon propre code, trouve par la mesure et corrige.** En lisant `user_id` la ou la
session ecrit `utilisateur_id`, la portee d'un role 1 devenait `user_id = 0` — c'est-a-dire
EXACTEMENT les lignes de diffusion. Un identifiant illisible n'interdisait pas l'acces, il
l'accordait. `portee()` est desormais fail-closed sur `$userId <= 0`.

**64 cles FR et EN**, jeux compares. La cloche vit dans l'en-tete du gabarit, son compte **rendu par
le serveur** — un appel de moins par page, et une pastille qui ne peut pas etre en retard sur ce que
la page affiche.

**Gardes.** Boite de reception : role 1, comme le legacy. Reglages : **role 3 + `can_admin_portal`
sur la ROUTE**, la ou le legacy ne conditionne que l'affichage de ses cases.

Ecarts : **E-108 a E-111**, les quatre fermes par ce portage.

### v1.37.59 — `adm/` D1 : le bouton qui devait boucher le trou ne pouvait rien sceller

**18 entrees de menu portees sur 33.** Legacy 32/0, portage 34/0 (`tests/e2e/go-adm-audit.mjs`).
Premier sous-lot du plus gros module restant : le journal d'audit, 711 lignes sur les 8 421 de `adm/`.

**Le defaut, mesure au clic.** Le legacy porte DEUX parcours de la chaine de hachage de `user_logs`,
et ils ne s'accordent pas devant une ligne non scellee : `audit_verify.php:44` la **saute** sans
avancer la tete, `audit_seal.php:79` **calcule** son hachage et avance. Sur la meme base, a la meme
seconde, « Verifier l'integrite » annonce une chaine intacte pendant que « Sceller les orphelines »
annonce une desynchronisation a la ligne 3 et refuse d'ecrire.

**Qui a raison se lit dans le code qui ECRIT.** `adm/includes/audit_log.php:111-115`, seul chemin
d'insertion scellee, selectionne `WHERE self_hash IS NOT NULL` : la chaine inscrite saute les
orphelines **par construction**. Deux mesures independantes le confirment — les donnees ligne a ligne
(la ligne 3 porte le hachage de la ligne 1) et un `LAG()` SQL sur les seules lignes scellees : **3311
maillons, 0 rupture**.

**Ce que le defaut coutait.** `stopped_at_tamper` verrouille le bloc d'`UPDATE` : le bouton
« Sceller les orphelines » ne pouvait sceller **aucune** ligne, jamais, tout en ecrivant une alarme
`SECURITY … investigation requise` a chaque appel pour une ligne intacte. Le trou grandissait seul —
**757** lignes non scellees annoncees au plan, **868** mesurees.

**Le portage n'a qu'UNE lecture de la chaine**, `JournalAudit::parcourt()`, partagee par la
verification et le scellement : elles ne *peuvent* plus diverger. Le scellement redevient possible, et
comme il est **irreversible**, sa decision se prend dans un panneau en page qui **nomme le nombre de
lignes** et n'active sa confirmation qu'a la saisie exacte de ce nombre — controle **repete cote
serveur**. Le garde-fou SQL `WHERE self_hash IS NULL` et le refus de reecrire une ligne deja scellee
sont repris tels quels.

**Trois defauts d'affichage, dont deux vus SEULEMENT a l'image** :
- la page annoncait « 4 179 **`:count`** entrees au total » — gabarit jamais substitue, **en FR et en
  EN** (E-105) ;
- `.bg-yellow-600` etait **absente du binaire CSS**, donc le bouton « Sceller » rendait sans fond et
  avait l'air desactive (E-106, **quatrieme** occurrence du piege Tailwind) ;
- les six verdicts ecrits par le JavaScript etaient en **francais code en dur** dans un fichier par
  ailleurs bilingue, `confirm()` natif compris (E-107).

**Sur le portage** : 41 cles FR et EN, jeux compares ; les libelles du script poses **en donnees** ;
plus aucune boite native. L'export CSV est **assemble en memoire puis rendu d'un bloc** — la parade
posee apres l'incident de `cve_export.php`, ou un avertissement PHP emis au fil de l'ecriture
s'inserait dans le fichier telecharge.

**Gardes.** La page et l'export : role 2 + `can_admin_portal`. Les deux gestes d'integrite : **role 3
sur la ROUTE**, la ou le legacy ne cache que les boutons de sa page — aucun de ses seize points d'API
`adm/` ne porte de `checkPermission`.

**La suite n'emet jamais le scellement pour de vrai** : le clic est intercepte et abattu, et la
simulation passe par une requete forgee depuis la page, motif ecrit dans le fichier — le legacy porte
bien un mode simulation, mais **aucun element de son interface ne l'emet**.

Ecarts : **E-104 a E-107**, les quatre fermes par ce portage.

### v1.37.58 — `maintenance/` archive : deux chemins qui se ressemblent et ne sont pas de meme nature

Douzieme partie du legacy demontee. Cycle du §4.4 deroule, y compris l'etape ajoutee la veille :
sonder AVANT le `git mv`. `/maintenance/` **302**, `/maintenance/index.php` **302**,
`/maintenance/js/main.js` **200** — aucun ne rendait 404, les trois le rendent maintenant.
Reference legacy **24 -> 5** (1 + 2 fichiers reels + 2).

**LE PIEGE DE CE MODULE : `/maintenance/check` ET `/maintenance/windows` NE SONT PAS DES PAGES.** Ce
sont des routes du backend Python, que le portage appelle toujours. Elles ne sont donc ni sondees par le
constat d'archivage — un constat sur une route vivante echouerait, pour une raison sans rapport avec
l'archivage — ni reecrites par `LiensLegacy::REMPLACEMENTS`.

Ce second point tient a un detail deja paye ailleurs : la table compare le chemin **normalise en
entier**, donc `/maintenance/check` ne vaut pas `/maintenance/`. Verifie et non suppose —
`/maintenance/` et `/maintenance/index.php` rendent un lien INTERNE, `/maintenance/check` et
`/maintenance/windows` partent toujours vers le backend. **Une table qui comparerait par prefixe les
aurait reecrites, et la page de maintenance aurait cesse de fonctionner sans que personne ne fasse le
lien** — le refus ne serait apparu ni ici ni dans les journaux du portage.

L'entree `/maintenance/` est ajoutee preventivement, comme `/docker/`, `/chatops/` et `/supervision/` :
mesure refaite, le backend n'ecrit que `/update/index.php` et `/tickets/index.php`. Seule
`recherche.blade.php` consomme cette table : `go-page-search` rejouee, **12/0** au portage et **5/0** au
legacy.

**`documentation.php` est releve et NON corrige, cette fois** — et la distinction est celle posee la
veille. Sa section nomme « la page `/maintenance/` » dans une balise `<code>` : une MENTION perimee,
comme pour `docker/`, et non une instruction de configuration exterieure comme l'etait l'adresse du
webhook ChatOps. Elle cite aussi `GET /maintenance/check?machine_id=`, qui reste EXACT puisque c'est une
route de backend. Le reste de la section decrit la regle d'inversion et le fail-open, et il est juste.

**Un seul point d'entree de menu** (`legacy/menu.php:129`), pour la meme raison mesuree que pour
`docker/` et `chatops/` : le tiroir mobile du legacy est incomplet. Ni `legacy/index.php` ni
`legacy/head.php` ne citaient la page.

**Surfaces devenues mortes, relevees et non touchees** : `api_proxy.php` garde `/maintenance/` dans sa
liste blanche et `/maintenance/windows` dans sa liste reservee a l'administration. Le proxy du legacy
meurt d'un bloc, avec le legacy. `maintenance_windows` reste en base : la table est lue et ecrite par le
portage, et par l'enforcement du backend.

### v1.37.57 — `maintenance/` porte, et la pastille qui MENTAIT de deux heures

**17 entrees de menu portees sur 33.** Legacy 24/0, portage 29/0.

**LE DEFAUT LE PLUS GRAVE DU CHANTIER, TROUVE EN LISANT AVANT DE CLIQUER.** La pastille « ouverte
maintenant » du legacy est calculee DANS LE NAVIGATEUR
(`legacy/maintenance/js/main.js:26-35`), sur l'horloge du navigateur. L'application se fait dans
`backend/maintenance.py:_in_window`, sur l'horloge du CONTENEUR. Releve du jour : navigateur en
**CEST 19:09**, `rootwarden_python` en **UTC 17:09**. Deux heures.

La demonstration tient en quatre lignes de journal. La suite cree une fenetre `18:48 -> 19:28` a 19:09
locale — la plage encadre l'instant du navigateur, pas celui du serveur :

    INFO  horloge du navigateur : 19:09
    INFO  horloge du conteneur qui applique : 17:09
    INFO  verdict du backend pour cette fenetre : FERMEE
    INFO  cellule d'etat de la ligne d'epreuve : « Ouverte »

Le legacy annonce « Ouverte ». Le backend refusera. Et comme l'enforcement vit dans d'AUTRES modules
(`routes/updates.py:19`, `routes/monitoring.py:229`), le refus n'apparait pas sur cette page :
l'exploitant lit « Ouverte », lance une mise a jour, recoit un **423** sans rapport visible. Pour une
fenetre `22:00 -> 06:00` saisie normalement, il y a DEUX bandes de deux heures ou la page et
l'application se contredisent, dans les deux sens.

**CE N'EST PAS E-73**, qui porte sur un AFFICHAGE faux de deux heures. Ici la valeur fausse est un
VERDICT sur une regle de blocage, rendu par un code qui n'est pas celui qui decide. E-73 est neanmoins
elargi : le decalage ne fait pas que mal afficher, il fait mal DECIDER.

**CORRECTIF — le verdict remonte la ou il est applique.** `list_windows` rend desormais, par fenetre, un
`active_now` calcule par `mw._in_window` — la fonction meme qui bloque — plus `server_time` et
`server_offset`. Le JavaScript du portage ne recalcule plus rien, il AFFICHE. La regle n'est pas
deplacee vers le navigateur : elle y est annoncee telle qu'elle sera appliquee. **341 pytest** toujours
verts apres cette modification backend.

Le premier jet du portage recopiait pourtant le calcul en JavaScript, en promettant de « suivre le
Python pas a pas ». C'etait la mauvaise reponse : **suivre le pas a pas ne protege de rien quand ce
n'est pas le pas qui differe, mais l'heure.**

**ET LE VERDICT EST EXPLIQUE.** Une ligne nomme l'horloge du serveur, et seulement quand elle differe de
celle du navigateur — une mention permanente cesse d'etre lue. Lire « Fermee » sur une plage qui
contient visiblement l'heure qu'il est passerait sinon pour une panne.

**DEUX AUTRES DEFAUTS, DANS MON PROPRE PORTAGE, TROUVES PAR LA MEME ASSERTION.** La pastille d'ensemble
comptait les fenetres activees SANS REGARDER LEUR PORTEE et annoncait « Flotte restreinte » des la
premiere — faux, et faux precisement dans le cas du banc d'essai, ou la fenetre ne vise qu'une machine.
La requete du backend le dit : `WHERE enabled = 1 AND (scope = 'global' OR machine_id = %s)`. D'ou
TROIS etats et non deux. Puis, la portee corrigee, la pastille restait « Aucune restriction » apres une
creation : rendue par le serveur au chargement, jamais rafraichie, alors que la page cree, bascule et
supprime. Un resume serveur que la page invalide par ses propres gestes vaut moins que pas de resume.
Sans cette assertion, les deux corrections n'auraient eu **aucun temoin**.

**LA FIXTURE NE POUVAIT PAS EMPOISONNER LE LOT, et c'est mesure et non suppose.** Fenetre activee mais
de portee `machine` sur `srv-zabbix`, la machine qu'aucune suite ne mute. Le `WHERE` ci-dessus ne la
rend jamais pour une autre machine : la fixture ne peut bloquer que ce qui est deja interdit. Nommer
cette machine dans une ligne d'horaire n'est pas la JOINDRE — aucune requete ne part vers elle. La suite
RELIT `scope` et `machine_id` juste apres la creation et supprime la ligne a l'instant si la portee
n'est pas celle convenue.

**La boite native disparait** : le legacy supprime derriere un `confirm()`, le portage ouvre un panneau
de decision en ligne. **Les deux chemins de la garde sont exerces** — `rw-test-admin` (role 2 sans
`can_admin_portal`) et `rw-test-user` (role 1), 403 des deux cotes.

**UN GESTE DE TEST QUI AVAIT TORT.** Remplir un `input[type=time]` par
`click({ clickCount: 3 })` puis `type('1847')` a rendu `22:47` : c'est un composite de segments, le clic
avait pose le caret sur les MINUTES. La suite accusait la page alors que le defaut etait dans le geste.

**MESURE A L'IMAGE, pas seulement au DOM** : contrastes des pastilles neuves a **5,2:1** et **5,03:1**,
au-dessus du seuil AA — le projet a paye trois fois une pastille invisible dont le HTML etait juste.
Captures 1920/1400/390 par `tests/e2e/go-captures-maintenance.mjs`, regardees et envoyees.

Tests : `tests/e2e/go-page-maintenance.mjs`, clics simules. Parite i18n maint : 52 cles FR = 52 EN.
PARITE.md E-101, E-102, E-103.

### v1.37.56 — `chatops/` archive : la premiere adresse EXTERIEURE que la migration deplace

Cycle du §4.4 deroule : `git mv legacy/chatops legacy/_deprecated/`, bascule du point d'entree
(`legacy/menu.php:138`), greffe de `constateArchivage` + `verifieMenuLegacy` en tete de la suite.
Reference legacy **21 -> 6** : 1 (la partie rend 404) + **3** fichiers reels + 2 (le lien du menu mene
au portage, et il aboutit). MESUREE.

**TROIS fichiers, et le troisieme n'est pas une page.** `webhook.php` est le point d'entree PUBLIC que
Slack appelle. Son 404 est VOULU — le portage expose `/chatops/webhook` — mais c'est la premiere fois
qu'un archivage deplace une adresse configuree **hors de RootWarden**. Les onze archivages precedents
ne deplacaient que des pages, visitees par un humain qui suit un menu.

**Les quatre chemins ont ete sondes AVANT le deplacement**, precisement pour que les assertions ne
soient pas creuses : `/chatops/` **302**, `/chatops/index.php` **302**, `/chatops/webhook.php` **403**
(« ChatOps desactive », le refus du backend), `/chatops/js/main.js` **200**. Aucun ne rendait 404.
Apres archivage, les quatre le rendent. Une assertion qui passerait parce que le chemin n'a jamais
existe occupe la place d'une mesure sans en etre une.

**`documentation.php` est CORRIGE ici, alors qu'il ne l'avait pas ete pour `docker/`.** La difference
est de nature. Pour `docker/`, la page nommait un chemin mort dans une balise `<code>` : une mention
perimee. Pour ChatOps elle donnait une **instruction de configuration exterieure** — « point d'entree
public `/chatops/webhook.php` » — que quelqu'un recopie dans Slack. La laisser aurait fait echouer
l'integration le jour de son activation, sans message et sans trace cote RootWarden. La section porte
desormais l'adresse du portage et un avertissement en gras. `documentation.php` reste non porte et
garde ses chaines en dur : ce n'est pas le lieu de le reprendre.

**Un seul point d'entree de menu**, comme pour `docker/`, et pour la meme raison mesuree : le tiroir
mobile du legacy est incomplet et ne portait pas ChatOps. Ni `legacy/index.php` ni `legacy/head.php`
ne le citaient.

**Surfaces devenues mortes, relevees et NON touchees** : `api_proxy.php:148` et `:179` gardent
`/chatops/users` dans leur liste blanche et leur liste reservee a l'administration. Retirer une entree
d'une liste reservee a l'administration par habitude, au detour d'un commit d'archivage, est exactement
le geste qu'on ne fait pas. Le proxy du legacy meurt d'un bloc, avec le legacy.

**L'archivage est sans risque parce que la fonctionnalite est DORMANTE** : aucune variable `CHATOPS_*`
dans `srv-docker.env`, zero correspondance en base, backend fail-closed. Aucun webhook reel ne pointait
vers l'adresse qui disparait. Si ChatOps avait ete actif, il aurait fallu prevenir AVANT, pas apres —
et c'est ce que dit `DEPRECIATION.md`.

`chatops_users` (migration 059) reste en base : la table est lue et ecrite par le portage.

**Une etape du cycle sautee a la v1.37.54 est reparee ici.** `LiensLegacy::REMPLACEMENTS` recoit
`/chatops/` **et** `/docker/` — ce dernier manquait. Mesure refaite : le backend n'ecrit que
`/update/index.php` et `/tickets/index.php` (`backend/routes/search.py:50,82`), donc les deux entrees
sont PREVENTIVES et ne reparent aucun 404 constate. C'est exactement ce qui les rend faciles a oublier,
et ce qui fait qu'on s'en apercoit le jour ou un resultat de recherche cite le chemin. Resolution
prouvee, pas supposee : `/chatops/index.php` et `/docker/index.php` rendent desormais un lien INTERNE,
tandis qu'un chemin non porte (`/adm/audit_log.php`) part toujours vers l'ancien portail.
`recherche.blade.php` est le seul consommateur de cette table : `go-page-search` rejouee, **12/0** au
portage et **5/0** au legacy.

**LOT complet apres archivage : 95 executions, 1330 assertions, 0 echec, ZERO ecart.** Le total baisse
de 1345 a 1330, et la baisse s'explique entierement : `go-page-chatops` passe de 21 a 6 sur la cible
legacy parce que la suite CONSTATE le 404 au lieu de parcourir la page.

### v1.37.55 — ChatOps porte : le premier chemin PUBLIC du portage

**16 entrees de menu portees sur 33.** Legacy 21/0, portage 22/0, base rouge 4/13.

**Le module a deux pieces de nature OPPOSEE.** La page de configuration est ordinaire : elle lit et
ecrit des correspondances « identifiant chat -> compte » par trois routes du backend, derriere
`role:2` ET `perm:can_admin_portal`. Le `webhook.php`, lui, est un passthrough PUBLIC, sans session et
sans jeton CSRF, que Slack appelle — le premier chemin public du portage qui accepte un POST.

**Ce que le relais ne fait SURTOUT PAS : recopier les en-tetes en bloc.** Quatre en-tetes sont nommes
un par un, en constante, liste FERMEE. Recopier l'ensemble transmettrait un `Cookie` ou un
`Authorization` du client vers le backend et transformerait ce relais en CONFUSION D'IDENTITE : le
backend croirait parler a un appelant authentifie. La liste fermee n'est pas une elegance, c'est la
garde.

**Et le refus est MESURE.** Une requete forgee sans signature ni jeton rend
`403 {"text":"ChatOps desactive."}` sur les deux cibles. Deux proprietes distinctes : le webhook
n'exige PAS de CSRF (Slack n'en presente aucun, un webhook qui l'exigerait ne fonctionnerait pas) et
une commande non signee EST refusee (sinon la route serait une porte ouverte, publique, vers un
executeur de commandes). L'authentification reelle vit dans le backend, sur la signature Slack ou un
jeton partage — fail-closed verifie en LISANT backend/routes/chatops.py:34.

**La fonctionnalite est DORMANTE, et c'est ce qui rend ce portage sans risque** : aucune variable
CHATOPS_* dans srv-docker.env, zero correspondance en base. Aucune requete ne part vers Slack.

**⚠ EXPLOITATION : l'adresse du webhook CHANGE.** Elle ne finit plus par `webhook.php`. Le legacy
affiche l'adresse sans dire qu'elle bougera ; le portage ajoute une ligne en gras qui demande de la
reporter dans la messagerie AVANT d'activer ChatOps. Sans mapping ni secret aujourd'hui l'impact est
nul, mais une bascule silencieuse aurait casse la fonctionnalite le jour de son activation, sans
message et sans trace.

**La boite native disparait.** Le legacy supprime derriere un `confirm()` : cette boite recouvre la
ligne sur laquelle on decide, ne se style pas, et BLOQUE Puppeteer. Le portage ouvre un panneau de
decision EN LIGNE. La suite accepte explicitement la boite du legacy et verifie qu'AUCUNE n'apparait
cote portage.

**Les deux chemins de la garde sont exerces** : `rw-test-admin` a le role 2 mais PAS
`can_admin_portal` (mesure en base), donc il mesure le chemin « permission » avec le role satisfait ;
`rw-test-user` mesure le chemin « role ». Les deux rendent 403 des deux cotes.

Tests : `tests/e2e/go-page-chatops.mjs`. Captures 1920/1400/390 au compte de role 3.
Parite i18n chatops : 35 cles FR = 35 EN. PARITE.md E-100.

### v1.37.54 — `docker/` archive : dixieme partie du legacy demontee

Cycle du §4.4 deroule : `git mv legacy/docker legacy/_deprecated/`, bascule du point d'entree,
greffe de `constateArchivage` + `verifieMenuLegacy` en tete de la suite. Reference legacy
**16 -> 5** : 1 (la partie rend 404) + 2 fichiers reels + 2 (le lien du menu mene au portage, et il
aboutit). MESUREE, pas calculee de tete.

**UN SEUL POINT D'ENTREE A BASCULER, ET C'EST UNE MAUVAISE NOUVELLE POUR LE LEGACY.** Le cycle
previent qu'il faut basculer TOUS les points d'entree — barre laterale, tiroir mobile, raccourcis du
tableau de bord, carte de raccourcis clavier de `head.php`. Ici il n'y en avait qu'un, et la raison
est mesuree : **le tiroir mobile du legacy est INCOMPLET** — 22 liens contre 32 dans la barre
laterale, `docker` absent. Une dizaine d'entrees sont inaccessibles sur mobile depuis toujours.

C'est exactement la derive que `App\Support\Navigation` rend impossible cote portage : la barre et le
tiroir incluent le MEME partiel, et un test verifie qu'ils rendent les memes entrees. Le legacy decrit
son menu deux fois, et les deux descriptions ont diverge sans que rien ne le signale. NON CORRIGE : on
ne soigne pas ce qu'on demonte, et les dix entrees concernees seront portees.

**Deux surfaces devenues mortes**, relevees et non touchees : `api_proxy.php:151` garde `/docker/` dans
sa liste blanche (comme `/supervision/` avant elle), et `documentation.php:1052` nomme « la page
`/docker/` » dans une balise `<code>` — sans lien cliquable, mais le chemin rend desormais 404.
`documentation.php` est lui-meme une entree de menu a porter.

PARITE.md E-99.

### v1.37.53 — la page Docker portee : la premiere des 19 entrees de menu restantes

**15 entrees de menu portees sur 33.** `docker/` est la plus petite des restantes : 201 lignes, deux
fichiers. Meme suite sur les deux cibles — legacy 16/0, portage 16/0, base rouge 1/9.

**LE SCAN N'EST PAS UNE LECTURE, ET LA PAGE LE DIT MAINTENANT.** Releve en lisant le backend AVANT
d'ecrire un seul clic : `docker_monitor.py:116` lance un `git fetch` dans le depot de chaque projet
compose de la machine visee — ca ecrit dans `.git/` et ca fait sortir la MACHINE sur le reseau — et
`docker_registry.py` interroge le registre distant. Surtout, `/docker/scan_all` frappe TOUTES les
machines, srv-zabbix (production) comprise ; la machine est bien dans le selecteur, mesure. Le legacy
presente ces boutons comme des gestes anodins ; le portage porte un encart qui nomme la production sur
le geste qui coute.

**AUCUNE MACHINE N'EST JOINTE PAR LA SUITE** : les deux boutons sont INTERCEPTES ET AVORTES. On mesure
que le clic emet la bonne requete, vers la bonne route, avec la bonne charge — et rien ne part.

**Le defaut que le portage ne reprend pas.** `legacy/docker/js/main.js:14` fait `await fetch(...)`
SANS `try` : quand le backend est injoignable, le rejet remonte hors du gestionnaire de clic et le
message d'erreur pourtant prevu n'apparait JAMAIS — l'exploitant clique, rien ne se passe. `scanAll`,
lui, enveloppe son `fetch` : l'asymetrie est un oubli. Le portage enveloppe chaque appel et ajoute une
cle `err_reseau` que le legacy n'a pas.

**Le legacy est DEDOUANE sur un point ou je l'accusais.** J'avais ecrit l'ecart « le refus rend
HTTP 200 avec une page habillee ». La mesure dit l'inverse : il rend un vrai 403. L'ecart etait une
accusation sans fondement, il a ete RETIRE.

**Une assertion qui lisait le texte au lieu du code.** Le premier jet reniflait le corps a la recherche
de « acces refuse » ; sur la base rouge la page rendait « 404 Not Found », que le renifleur comptait
comme un NON-refus. La propriete est le STATUT, et il doit valoir 403.

**Sept classes CSS inventees**, et aucune n'aurait leve d'erreur : une classe absente produit un
element sans style, que le test DOM voit bien present. Relevees par comparaison avec la feuille avant
la premiere execution.

Garde `role:2` SEULE, reprise telle quelle : c'est la seule entree de menu gardee par le ROLE et non
par une permission. Non corrige au detour d'un portage.

Tests : `tests/e2e/go-page-docker.mjs` 16/0 des deux cotes. Captures 1920/1400/390 au compte de
role 3. PARITE.md E-98.

### v1.37.52 — l'enrolement du second facteur porte : LE DERNIER BLOCAGE DE LA v2.0 TOMBE

**C'etait la derniere chose qui empechait d'eteindre l'ancien portail.** L'enrolement n'existait que
cote legacy : un compte neuf n'avait AUCUN chemin vers un second facteur sur le portage. L'ecran
affichait une impasse explicite renvoyant vers l'ancien portail — honnete, mais redhibitoire pour une
bascule directe.

**Le portage est celui du legacy CORRIGE, pas du legacy.** `enable_2fa.php` divulguait le secret d'un
compte deja enrole a qui ne presentait que le mot de passe (corrige en v1.37.48, PARITE E-94). Les
trois proprietes qui ferment ce trou sont reprises comme des INVARIANTS, chacun mesure :

- un compte qui a DEJA un secret n'atteint jamais l'ecran — verifie DEUX fois, a l'affichage et de
  nouveau a l'activation : entre les deux, un autre chemin a pu enroler ce compte, et ecraser son
  secret le rendrait inaccessible ;
- le secret vit en SESSION et ne touche la base qu'APRES la preuve : un GET n'ecrit rien ;
- il ne CHANGE PAS d'un affichage a l'autre, sans quoi le QR scanne et le code attendu ne
  concorderaient jamais.

**Le code d'enrolement passe par le MEME anti-rejeu que la connexion** : le secret de session est
chiffre a la volee pour etre presente a Totp::verifie, donc au compteur de fenetre monotone par
compte. Un code employe pour enroler ne peut donc pas etre rejoue pour ouvrir une session.

**Un seul chemin ouvre une session.** La verification et l'enrolement partagent desormais
ouvreLaSession() : deux copies de ce chemin auraient fini par diverger, et c'est le chemin ou une
divergence ACCORDE UN ACCES. Le compte y est relu en base a cet instant plutot que repris d'un objet
charge plus tot.

**Le QR diverge par NATURE, et les deux sont corrects.** Le legacy rend un PNG en base64 via gd ; le
conteneur du portage n'a ni gd ni imagick (mesure), il rend un SVG en ligne via bacon/bacon-qr-code.
La suite mesure « un QR est present », pas « une balise <img> est presente » : exiger la forme du
legacy aurait fait echouer un portage correct.

**Le fond blanc du QR n'est pas une coquetterie** : un lecteur lit des modules sombres sur fond CLAIR.
Un SVG pose sur le fond sombre du theme serait illisible A LA CAMERA, et le DOM n'en dirait rien. Le
cadre impose #fff quel que soit le theme, et la capture le MESURE.

**Non porte, et dit** : le re-enrolement (remettre un second facteur a un compte qui en a deja un).
Il n'existe pas non plus dans le legacy sous forme d'ecran — le seul chemin vivant est
adm/includes/manage_roles.php:101-121, qui porte une garde HIERARCHIQUE, et reset_totp.php est du code
mort PLUS PERMISSIF que ce chemin. Le re-enrolement appartient a adm/ et a sa garde.

**Tests.** `tests/e2e/go-auth-enrolement.mjs` — **18 PASS / 0 FAIL des DEUX cotes**. La suite n'etait
jusque-la jouee que sur le legacy et sortait par « sans objet » sur le portage.
`tests/e2e/go-captures-enrolement.mjs` — captures a 1920, 1400 et 390, compte de ROLE 3, avec mesure
de la taille RENDUE du QR et de son fond calcule. La fixture retire le second facteur du compte de
capture puis le RESTAURE dans un `finally`, etat RELU pour etre prouve : d'autres suites du LOT se
connectent avec ce compte.

**Deux defauts vus a l'image, pas aux assertions.** Le bouton principal passait sur deux lignes et
devenait plus haut que son voisin (libelle raccourci a « Activer »). Et avant cela l'ecran rendait
ENTIEREMENT VIDE : `$temporaire['name']` n'existe pas, la cle de session s'appelle `nom`. Une cle de
tableau SUPPOSEE au lieu d'etre lue, et la page tombait en 500 — que seule la lecture du journal a
revelee, l'assertion ne disant que « pas de QR ».

**Exploitation.** Nouvelle dependance `bacon/bacon-qr-code` (backend SVG, aucune extension PHP
requise). Aucune migration.

### v1.37.51 — le portage sait ECRIRE un secret TOTP, et l'execution croisee le prouve

**Prerequis de l'enrolement — le dernier blocage de la v2.0.** Le portage savait DECHIFFRER un
secret TOTP mais pas en ECRIRE un. `App\Support\TotpCrypto::chiffre()` est le miroir exact de
`encryptTotpSecret()` (`legacy/includes/totp_crypto.php:18`), meme ordre de moteurs — sodium
d'abord, AES-256-GCM en repli — et meme comportement FAIL-CLOSED : sans cle, ou si le chiffrement
echoue, on leve. Le repli « rendre le secret en clair » que le legacy portait avant son correctif
A02-04 n'est PAS reintroduit.

**Pourquoi ce test passe avant tout le reste.** Les deux portails partagent la base : un blob ecrit
par l'un doit etre lisible par l'autre. Un format divergent d'un octet ne produit **aucun message
d'erreur** — il rend le compte inaccessible d'un cote, et on ne le decouvre que le jour ou quelqu'un
n'arrive plus a se connecter. La lecture comparee des deux fichiers avait ete faite ; l'EXECUTION
croisee, non. Deux implementations qui se ressemblent a la lecture peuvent diverger a l'execution :
une etiquette HKDF, un ordre de concatenation, un `hex2bin` qui echoue en silence.

**Tests.** `tests/e2e/go-auth-totp-croise.mjs`, **15 PASS / 0 FAIL**. Il fait executer les DEUX
implementations reelles, chacune dans SON conteneur — pas une reimplementation en JavaScript, qui ne
prouverait que la comprehension du format. Mesure : les deux choisissent sodium, le portage relit ce
que le legacy ecrit ET l'inverse, un blob altere d'un octet est refuse **par le vide** des deux
cotes, un prefixe inconnu est refuse, et un secret historique sans prefixe est rendu tel quel des
deux cotes.

**Sans navigateur, et c'est le motif.** La convention veut des tests pilotes par des clics ; elle
porte sur la logique qui a une INTERFACE. Ici la propriete est un format de donnees partage entre
deux processus PHP : elle n'a aucune surface a cliquer, et la mesurer par l'interface reviendrait a
enroler un vrai compte pour lire un octet. Aucune ecriture en base, aucun compte touche.

**Mesure au passage** : le conteneur `rootwarden_laravel` a **sodium et openssl** mais **ni gd ni
imagick** — ce qui confirme qu'il faudra `bacon/bacon-qr-code` en backend SVG pour l'ecran
d'enrolement. Le legacy, lui, a les quatre.

**Signale** : deux numerotations de sous-lots coexistent. `MODULE-AUTH.md` appelle A3 le step-up et
A5 l'enrolement ; les commits et le plan appellent A5 le step-up. L'ordre d'execution reel est
inchange. Un encadre en tete de `MODULE-AUTH.md` §7 le dit desormais.

### v1.37.50 — `auth/` sous-lot A5 : la re-authentification ponctuelle portee

**Symptome.** Le portage REFUSAIT en bloc les routes qui donnent root (403 +
`portage: non_porte`). Le refus n'etait pas un trou — accorder root sans le second controle que le
legacy exige aurait ete un recul — mais la capacite manquait : apres une bascule directe, personne
n'aurait plus pu deployer ni annuler une politique sudo depuis le portail.

**Cause racine.** Le step-up du legacy (`legacy/auth/step_up.php`, quatre appelants et aucun autre)
n'avait pas d'equivalent cote portage. `RoutesBackend::MOTIFS_STEP_UP` portait les motifs, et
`config/rootwarden.php` portait meme `step_up_ttl => 900` que **personne ne lisait**.

**Correctif.** `App\Services\StepUp` + `POST /profil/step-up` + integration dans la passerelle.
Les QUATRE defauts du legacy sont mesures puis fermes :

- **l'anti-rejeu vivait en session** : le meme code, rejoue depuis une session NEUVE, etait ACCEPTE.
  La garde est desormais le compteur de fenetre MONOTONE par compte de `Totp::verifie`, PARTAGE avec
  la connexion — un code ne sert qu'UNE FOIS, pour quoi que ce soit. Un code observe a la connexion ne
  peut donc plus etre retourne en step-up, ce qui est l'escalade meme que le step-up existe pour
  empecher ;
- **le quota etait par session et jamais remis a zero** : apres un succes, la cinquieme tentative
  suivante rendait deja 429. Il est desormais par COMPTE et **remis a zero sur succes** ;
- **`api_proxy.php:63` fusionne trois routes root sous `policy_action`**, si bien qu'un step-up
  consenti pour ANNULER une politique autorisait un DEPLOIEMENT sudo pendant quinze minutes. Le
  portage nomme l'action PAR ROUTE (`policy_sudo_deploy`, `policy_sftp_deploy`, `policy_rollback`),
  et le nom est DERIVE du chemin : ajouter un motif suffit a doter la route de son nom ;
- **la liste des actions est FERMEE**, verifiee par aller-retour et fail-closed. Le legacy accepte
  n'importe quel nom d'action et pose `_step_up_<ce que le client a envoye>`.

**Deux ajouts que le legacy n'a pas** : `POST /profil/step-up/revoquer` pour rendre ses privileges
(chez le legacy la marque vit quinze minutes et rien ne permet de l'abreger), et
`step_up_tentatives` en configuration.

**Une exigence de ma propre caracterisation etait dangereuse et a ete retiree.** Le premier jet
demandait qu'un second step-up pour une AUTRE action reste possible dans la meme fenetre de 30 s, au
motif que le refus du legacy gene un geste legitime. C'etait une exigence d'AFFAIBLISSEMENT : elle
aurait autorise le rejeu d'un code observe a la connexion. Le refus est la bonne reponse ; ce qui
cloche chez le legacy est qu'il refuse depuis la SESSION, donc de façon contournable.

**Ma suite n'etait pas idempotente, et c'etait un vrai risque.** Elle accordait un step-up pour une
route root, et l'execution suivante postait sur cette meme route quinze minutes plus tard. Seul un
`machine_id` absent a empeche un deploiement sudo reel. La suite rend desormais les privileges a
l'entree ET dans son `finally`. Effet secondaire heureux : la branche « une marque laisse passer la
requete », d'abord declaree non mesurable sur le portage, l'est devenue — apres LECTURE du backend
(`backend/routes/policies.py:220-225` et `:44-47` refusent sur `machine_id` manquant AVANT tout
`ssh_session`).

**Deux choses ne sont pas portees, et c'est dit.** Le panneau de decision en page, parce
qu'**aucune page du portage n'appelle une route gardee par un step-up** — les pages qui le feront
(`ssh/` K4 et `adm/`) ne sont pas portees, et une piece non mesurable dans le gabarit met en risque
les quatorze pages deja portees ; il sera porte avec son premier consommateur. Et le modal du legacy
reste ce qu'il est : integralement en francais code en dur, et il tutoie.

**Tests.** `tests/e2e/go-auth-step-up.mjs` — legacy **38 PASS / 0 FAIL**, base rouge du portage
**6 / 16**, portage **24 / 0**. Tout est mesure sur le CHEMIN DE REFUS : aucun geste root n'est emis.
Voir `docs/migration/PARITE.md` E-96.

**Exploitation.** Nouvelle variable optionnelle `STEP_UP_TENTATIVES` (defaut 5). Aucune migration.
Les marques vivent dans le cache applicatif : un `cache:clear` REFERME les autorisations en cours au
lieu de les ouvrir.

### v1.37.49 — `auth/` sous-lot A2 : le changement de mot de passe porte

**L'UN DES DEUX BLOCAGES DE LA v2.0 TOMBE.** Mesure : **six comptes actifs sur dix** portent
`force_password_change = 1`, dont **`superadmin`**. Le portage DETECTAIT le drapeau et l'annoncait
par un bandeau, mais **n'offrait aucun formulaire** — il renvoyait vers l'ancien portail, qui
n'existera plus apres la bascule. Details : `docs/migration/PARITE.md` **E-95**.

Base rouge **7 PASS / 1 FAIL** → portage **27 / 0** (legacy **26 / 0**).

**LA POLITIQUE EST CELLE DU LEGACY, A L'IDENTIQUE** — obligation, pas style : les deux portails
partagent la base, donc une regle plus laxiste d'un cote serait un contournement de l'autre. Quinze
caracteres, quatre classes, les cinq derniers haches refuses **plus le courant**, HIBP en option, et
**une seule cle i18n** pour les cinq regles de complexite (nommer la regle qui a echoue renseigne
autant l'attaquant que la personne).

**DEUX COLONNES, DEUX TRAITEMENTS OPPOSES, tous deux mesures :**
- **`password_updated_at` est ecrite EXPLICITEMENT.** Le legacy ne l'ecrit pas et compte sur
  `ON UPDATE CURRENT_TIMESTAMP` — or la clause se declenche a TOUTE modification reelle de la ligne
  `users` : un echec de connexion suivi d'un succes remet `failed_attempts` a 0, la ligne change, et
  le compteur de jours d'expiration repart de zero. La politique serait vaincue par une faute de
  frappe. Elle est desactivee aujourd'hui (`PASSWORD_EXPIRY_DAYS` non definie), donc le defaut est
  **LATENT** — mais on ne s'appuie pas sur un effet de bord ;
- **`password_expires_at` n'est PAS ecrite.** Le legacy la calcule et l'enregistre, mais **personne ne
  la lit** : `verify.php:159` calcule depuis `password_updated_at`. Mesure : **0 ligne renseignee**.
  La porter reviendrait a porter une colonne morte.

**LE JOURNAL S'ECRIT NU, ET C'EST CORRECT.** `user_logs` porte `prev_hash`/`self_hash` et
l'administration offre une verification de chaine — de quoi croire qu'il faut la calculer. Mesure :
**3368 lignes dont 757 sans empreinte**, aucun declencheur, et la chaine est posee par un
**scellement separe**. Le legacy est **dedouane** ; en revanche 757 lignes non scellees laissent un
trou dans la verification — affaire d'`adm/`.

**HIBP PORTE MAIS INERTE** : opt-in, k-anonymity (seuls cinq caracteres de l'empreinte SHA-1 sortent,
jamais le mot de passe), **fail-open assume**. La variable n'est definie dans **aucun** conteneur :
**aucune requete ne sort**.

**LE REFUS DU MOT DE PASSE TROP COURT DIVERGE, ET LES DEUX SONT CORRECTS.** Le legacy refuse cote
serveur avec un message ; le portage pose `minlength`, donc **le navigateur refuse d'emettre la
requete**. Une assertion qui exigeait un message faisait echouer une garde agissant PLUS TOT : la
suite mesure la **propriete** (pas accepte, hache inchange) et prouve la revalidation SERVEUR **par
une requete forgee** — `minlength` est une commodite qu'un attaquant ne respecte pas. Defense en
profondeur verifiee des deux cotes.

**TROIS DEFAUTS DE LA SUITE, TROIS PASS POUR UNE MAUVAISE RAISON :** la soumission etait ancree sur
« le premier bouton submit » alors que `profile.php` porte CINQ formulaires — le premier etant celui
du COURRIEL (adresse verifiee intacte apres coup) ; le message se lisait par une classe approchante,
qui attrapait un compteur valant « 0 » cote legacy puis le BANDEAU d'exigence cote portage ; et
`DELETE ... JOIN ... ORDER BY ... LIMIT` que **MySQL refuse**, dont l'exception partait dans le
`finally` et emportait le journal entier.

**UN TEXTE DEVENU FAUX, CORRIGE** : la tuile « non porte » annoncait « effectuez le changement depuis
l'ancien portail » alors que le changement venait d'etre porte.

**FICHIERS.** `laravel/app/Services/MotDePasse.php` (neuf) · `laravel/config/rootwarden.php` (la
politique, `env()` n'etant lu que depuis `config/`) · `PortailController::changerMotDePasse()` ·
`laravel/routes/web.php` · `laravel/resources/views/profil.blade.php` ·
`laravel/lang/{fr,en}/profil.php` (**21 cles = 21**) · `tests/e2e/go-auth-mot-de-passe.mjs` (neuf,
pilotee par des CLICS) · `scripts/rejouer-lot.sh` · `docs/migration/PARITE.md` (**E-95**).
**Backend Python et legacy inchanges.**

### v1.37.48 — SECURITE : le second facteur n'est plus derivable du premier

**VULNERABILITE PRESENTE EN PRODUCTION.** Trouvee en inventoriant `auth/` pour le porter,
documentee le 2026-08-20 dans `docs/migration/MODULE-AUTH.md`, **reproduite et corrigee le
2026-08-23**. Details : `docs/migration/PARITE.md` **E-94**.

**SYMPTOME.** `legacy/auth/enable_2fa.php` ne gardait que `isset($_SESSION['temp_user'])` —
l'etat pose par `login.php` APRES le mot de passe et AVANT le second facteur. Avec le mot de
passe seul, aucun code jamais fourni :

    POST /auth/login.php        -> 302 vers verify_2fa.php     [2FA EN ATTENTE]
    GET  /auth/enable_2fa.php   -> 200, 17 547 octets
                                   contient le secret TOTP du compte EN CLAIR + son QR

**CAUSE.** `login.php` renvoie vers `verify_2fa.php` quand un secret existe, mais c'est une
REDIRECTION, pas une garde : rien n'empechait d'appeler la page directement, et `verify.php`
l'autorise explicitement pendant que la 2FA est en attente.

**PORTEE.** `sha256(legacy/auth/enable_2fa.php)` etait egal a
`sha256(origin/main:www/auth/enable_2fa.php)` (`be0bfda6...`), et `main` tourne en production.
Quiconque detenait un mot de passe pouvait lire le secret TOTP du compte et generer ses codes
indefiniment.

**QUATRE CORRECTIFS**, sur cette branche (l'exploitant a demande que tout s'y fasse) :
- **un compte deja enrole est renvoye** vers `verify_2fa.php` : ca ferme la divulgation sans
  retirer aucune capacite — il n'existe de toute facon AUCUN ecran de re-enrolement pour un
  compte authentifie ;
- **un GET n'ecrit plus rien** : le secret vit en SESSION jusqu'a la validation du premier
  code. Il etait ecrit des l'affichage, sans jeton CSRF, avant toute preuve — une visite
  abandonnee laissait un secret enrole que personne ne detenait ;
- **la limitation de debit des deux autres portes 2FA est appliquee** : 5 tentatives par
  session sur 60 s ET 10 par IP sur 10 min (`login_attempts`, etape `'2fa'`). Elle manquait
  ici seule, la ou `verify_2fa.php` et `confirm_2fa.php` l'avaient ;
- **l'anti-rejeu devient effectif** : l'empreinte n'etait posee que dans la branche de succes
  puis supprimee dans la meme requete (motif E-01) ; elle est posee a CHAQUE tentative.

**LE CAS NORMAL EST MESURE AUSSI.** Un correctif evident peut casser le cas normal : refuser la
page a un compte deja enrole ne doit rien retirer a un compte sans second facteur.
`tests/e2e/go-auth-enrolement.mjs` (**18 PASS / 0 FAIL**, reference legacy inscrite) deroule
l'enrolement complet — page servie a 200 avec son QR, RIEN ecrit par l'affichage, secret STABLE
entre deux affichages, un code valide acheve l'operation, secret ecrit CHIFFRE. La suite ne
figure pas dans les suites du portage : il n'y a pas encore d'enrolement a y mesurer. La suite est
**pilotee par des clics Puppeteer** (`page.type` + `page.click`), convention du projet : un
premier jet passait par `node:https` sans navigateur et mesurait des statuts, pas l'ecran. La
regle INVERSE figurait dans la skill `rw-e2e` (« preferer `page.evaluate` aux clics fragiles »)
jusqu'au 2026-08-23 — corrigee dans le meme mouvement.

**PREMIERE FIXTURE QUI MUTE UN SECRET DE COMPTE** : `rw-test-admin`, valeur sauvegardee,
effacee, restauree dans un `finally`, etat RELU pour etre prouve — treize suites dependent de
ce compte.

**UN DETAIL QUI A FAILLI DISCULPER A TORT** : l'attribut `value` du jeton CSRF est sur la LIGNE
SUIVANTE du HTML. Un `grep` par ligne ne le trouve pas, le POST rend 403, et un premier essai
concluait que la vulnerabilite n'existait pas.

**RESTE OUVERT** : aucun ecran de RE-enrolement pour un compte authentifie.
`legacy/includes/onboarding.php` propose `/auth/enable_2fa.php` comme action de l'etape « 2FA »,
mais un compte connecte n'a plus de `temp_user` — le lien est mort et l'etape est toujours
cochee. Le portage devra offrir ce chemin.

**FICHIERS.** `legacy/auth/enable_2fa.php` · `tests/e2e/go-auth-enrolement.mjs` (neuf) ·
`scripts/rejouer-lot.sh` · `docs/migration/PARITE.md` (**E-94**) · `legacy/version.txt`.
Backend Python et portage Laravel **inchanges**.

### v1.37.47 — `supervision/` ARCHIVE : le deuxieme module deprecie, et une aide d'archivage qui mentait

Le module est porte en entier (V1 a V12, treize suites) : `legacy/supervision/` passe dans
`legacy/_deprecated/`. **Deuxieme MODULE deprecie**, apres `update/`. Neuf parties archivees au total.

**QUATRE POINTS D'ENTREE, ALORS QUE LE DECOUPAGE EN ANNONCAIT DEUX.** Barre laterale et tiroir mobile
(`menu.php`), raccourci du tableau de bord (`index.php`), et surtout la **carte de raccourcis CLAVIER**
(`head.php`, `g` puis `v`) — un objet JavaScript, pas un `<a href>` : aucun controle portant sur les liens
ne peut le voir. Taper `g v` aurait navigue vers le 404 qu'on venait d'installer.

**LE DEFAUT LE PLUS UTILE PORTE SUR L'OUTILLAGE PARTAGE (E-92).** `tests/e2e/archive.mjs` filtrait les
liens du menu par `href.includes(routeportee)`. La route portee est `/supervision`, l'ancien chemin legacy
`/supervision/` : le second **contient** le premier. Base rouge, anciens liens en place :

    PASS  l'entree de menu du legacy mene au portage  — /supervision/
    EXCEPTION TypeError: Invalid URL

L'assertion annoncait une reussite **en affichant le chemin archive**. Seule l'exception levee ensuite par
`new URL('/supervision/')` a revele le probleme : si l'ancien lien avait ete absolu, le PASS serait passe
inapercu. C'est le PREMIER des neuf modules ou la collision est possible — `/update/` contre
`/mises-a-jour`, `/tasks/` contre `/taches` : aucun recouvrement, donc huit archivages ont valide un filtre
qui ne pouvait pas les trahir.

Correction : le lien doit etre **absolu** et son `pathname` doit **etre** la route, pas la contenir ; et
`repond()` rend 0 au lieu de lever, pour qu'un href relatif produise un verdict et non une exception au
milieu d'une suite. Les huit parties deja archivees restent vertes (mesure : `update-u1`, `tickets`,
`drift`).

**LA PROPRIETE POSEE EST NEGATIVE ET COUVRE LES QUATRE EMPLACEMENTS**, lue sur le tableau de bord servi :
plus aucun `href="/supervision/"`, plus aucun `: '/supervision/'`. Base rouge : **3 liens et 1 raccourci** —
les quatre, comptes une seconde fois et par un autre moyen.

**DEUX PORTES DEDOUANEES**, que le precedent d'`update` avait signalees : `App\Support\Navigation` porte
`'route' => 'supervision'` depuis V1 (le menu du PORTAGE n'a jamais pointe vers le legacy, contrairement a
`updates`), et `backend/routes/search.py` n'emet jamais `/supervision/`. L'entree ajoutee a
`LiensLegacy::REMPLACEMENTS` est donc **preventive**, la ou celle d'`update` reparait un 404 mesurable.

**CE QUI RESTE, ET QUI N'EST PAS DU RESSORT D'UN ARCHIVAGE.** La seule occurrence subsistante de
`/supervision/` est la liste blanche de `legacy/api_proxy.php:134` — une route de **backend**, pas un lien.
Le proxy du legacy continue de relayer les routes de supervision alors qu'aucune page ne les appelle plus :
surface morte, d'autant plus notable que `/supervision/` est **absent de `$ADMIN_ONLY_PREFIXES`** cote
legacy. La retirer restreindrait ce que le legacy autorise — changement de droits, pas consequence
mecanique du deplacement. **Laissee en place, signalee a l'exploitant.**

**LES TREIZE SUITES.** Constat d'archivage greffe **en tete du `try`**, avant toute fixture : rien n'est
pose, donc `process.exit()` peut court-circuiter le `finally` sans rien laisser sur la machine de test ni en
base. Les **trois** fichiers du module sont sondes, pas un echantillon. References legacy mesurees :
**6** pour douze suites, **8** pour `onglets`.

**VU A L'IMAGE, ET LAISSE TEL QUEL.** Deux constats qui depassent ce sous-lot, tous deux signales a
l'exploitant : (1) **le legacy ne signale pas ses liens sortants** — `$sideLink` n'ajoute ni marqueur ni
`target`, et sur la capture « Supervision » est rendu trait pour trait comme une entree interne alors qu'il
mene a un autre portail sur un autre port, dans le meme onglet ; **11 entrees** sont dans ce cas, huit
l'etaient deja. Le portage marque l'inverse et un test y mesure la largeur RENDUE du marqueur : la regle
existe, ecrite pour un seul sens. (2) **le 404 d'un chemin archive est la page brute d'Apache**, sans
repere ni retour — vrai pour les neuf parties archivees. Ni l'un ni l'autre n'est corrige : soigner
l'ergonomie de ce qu'on demonte est un mauvais investissement.

**FICHIERS.** `legacy/supervision/` → `legacy/_deprecated/supervision/` · `legacy/menu.php`,
`legacy/index.php`, `legacy/head.php` (les quatre points d'entree) ·
`laravel/app/Support/LiensLegacy.php` · `tests/e2e/archive.mjs` (le correctif partage) · les treize
`tests/e2e/go-page-supervision-*.mjs` · `scripts/rejouer-lot.sh` · `docs/migration/PARITE.md` (**E-92**,
**E-93**) · `docs/migration/DEPRECIATION.md`. **Backend Python inchange.**

### v1.37.46 — module `supervision/`, sous-lot V12 : le deploiement, dernier geste du module

**DERNIER SOUS-LOT DU MODULE.** Le deploiement d'un agent est porte : geste **par ligne**, panneau de
decision rendu par le serveur qui **enumere les etapes**, verdict tire du **flux entier**, **verification
apres coup**, journal montre. Base rouge mesuree avant de porter : **14 PASS / 16 FAIL**. Apres :
**31 PASS / 0 FAIL** (legacy : 19 / 0). Details dans `docs/migration/PARITE.md` **E-90** et **E-91**.

**CE QUE LA MESURE A TROUVE (E-90).** Le backend n'inspecte **aucun** code de retour : `yield from
execute_as_root_stream(...)` ignore la valeur rendue. Releve sur le banc d'essai, trois etapes en echec
(codes **127**, **100**, **127** : `wget` absent, paquet hors index, `systemctl` absent) et le flux conclut
`SUCCESS_MACHINE::... Deploiement reussi`. Pire, `_upsert_agent` inscrit l'agent : la base affirmait
`zabbix 7.0, config_deployed = 1` la ou `dpkg-query` ne trouvait aucun paquet. La ligne fausse est
**transitoire** — la detection de version qui suit l'efface, sur les deux portails — donc la suite l'isole
par une **requete forgee** sans detection apres. **Backend laisse INTACT** faute d'autorisation.

**CE QUE LE PORTAGE AJOUTE (E-91).**

- **les etapes sont NOMMEES, pas comptees, et rendues PAR PLATEFORME** : `zabbix_deploy` purge l'agent en
  place avant d'installer et tire un `.deb` sur `repo.zabbix.com` ; `generic_deploy` ne purge pas,
  sauvegarde la configuration, et **Prometheus n'ajoute aucun depot externe**. Aucune phrase ne cite un
  nombre — la liste EST le decompte ;
- **le verdict vient du flux entier**, `(code N)` parse comme protocole. Le legacy affiche « Deploiement
  reussi » en vert ; le portage affiche « a **ECHOUE** (code 127, 100, 127) » ;
- **la verification confronte l'inventaire** : « AUCUN agent n'est detecte [...] c'est l'inventaire qui a
  tort ». Plus parlante qu'en V11, qui faisait constater une absence ;
- **le bouton est desactive avec l'explication** quand le backend refuserait — et seulement la :
  `zabbix_deploy` rend **400** sans configuration globale, `generic_deploy` **installe quand meme** ;
- **aucune case a cocher, aucune action de masse**, et **ouvrir un panneau n'envoie rien** — propriete
  mesuree au RESEAU, ce qui permet de lire l'avertissement sur la ligne de `srv-zabbix` sans la joindre.

**LA 19e CLE CASSEE, ET LA PLUS INSTRUCTIVE.** `confirm_deploy` **existe**, en FR et en EN, correctement
redigee — dans `lang/{fr,en}/supervision.php`, donc hors de l'espace `js.` que le script charge. Ecrite,
correcte, **inaccessible** : la boite native affiche `confirm_deploy`.

**DEUX CORRECTIFS DE MON PROPRE PORTAGE.** Le bouton « Reconfigurer » de V10 se desactivait d'apres la
configuration de **Zabbix** quel que soit le selecteur (famille E-79, deplacee du chemin vers l'etat) :
l'etat bloque vient desormais d'une table par plateforme, **fail-closed**. Et
`configurationParPlateforme()` etait interrogee **six fois** par requete : elle est memorisee pour la duree
de la requete, l'ecriture invalidant la memoire.

**PASSERELLE.** Les quatre chemins `/supervision/<plateforme>/deploy` passent **en flux** (delai 900 s au
lieu de 120 s). Decision prise sur mesure et contraire a celle de V10 : le deploiement a ete mesure a
**9 270 ms** sur le banc, mais c'est un **plancher** — le banc n'a ni DNS ni paquet a telecharger. Un
depassement rendrait une erreur de passerelle alors que l'installation continuerait sur la machine.
`estUnFlux` etant evaluee **apres** les trois refus, aucune garde n'est touchee.

**VU A L'IMAGE.** L'enonce du geste et l'avertissement de PRODUCTION portaient la meme classe : sur le
geste le plus couteux du module, rien ne distinguait « voici ce qui va se passer » de « ce serveur est en
production ». L'enonce est devenu un encart neutre.

**FICHIERS.** `laravel/app/Http/Controllers/SupervisionController.php` (`etapesDuDeploiement()`,
`boutonsBloques()`, route `deploiement`, libelles), `laravel/app/Services/Supervision.php` (memorisation),
`laravel/app/Support/RoutesBackend.php` (`EN_FLUX`), `laravel/resources/views/supervision.blade.php`,
`laravel/public/js/supervision.js` (`verdictDeploiement()`, `verifieDeploiement()`,
`majBoutonsBloques()`), `laravel/lang/{fr,en}/superv.php` (**264 cles = 264**),
`tests/e2e/go-page-supervision-deploiement.mjs` (neuf), `scripts/rejouer-lot.sh`,
`docs/migration/PARITE.md`. **Backend Python inchange.**

### v1.37.45 — module `supervision/`, sous-lot V11 : la desinstallation, une reussite VERIFIEE et non annoncee

**Symptome.** Le legacy demande de confirmer une DESTRUCTION par un `confirm()` natif qui affiche
`confirm_uninstall` — la cle existe sous `supervision.*` et dans AUCUN des deux `js.php`, donc `__()` la
rend telle quelle. Mesure a l'ecran : `confirm: confirm_uninstall`. **Dix-huitieme** cle de cette famille,
et la pire par son emplacement. Et le legacy ne verifie RIEN apres coup.

**Fix.** Un geste PAR LIGNE derriere un panneau de decision qui NOMME ce qui part : le service arrete, le
paquet purge avec sa configuration, la ligne d'inventaire — en precisant qu'elle ne bouge QUE si la
commande reussit, contrepartie du correctif v1.37.44.

**LA PROPRIETE CENTRALE : LE PORTAGE VERIFIE APRES COUP.** Le backend ne peut plus mentir, mais il ne peut
pas tout garantir — et « il n'y avait rien a purger » n'est pas « desinstalle ». Le portage rejoue la
detection de version (V6) une fois le geste fini, et dit ce qu'elle trouve, dans un porte-messages
DISTINCT du verdict : « la commande a rendu un succes » et « plus aucun agent n'est detecte » ne sont pas
la meme affirmation.

**LA FIXTURE QUI REND CETTE PROPRIETE MESURABLE.** On ne peut pas installer un vrai agent sur le banc
d'essai. La suite pose donc un FAUX binaire `zabbix_agent2` — un script qui n'imprime qu'une version :
`dpkg-query` ne le voit pas (ce n'est pas un paquet), donc la commande rend `RIEN_A_PURGER` et un code 0 ;
`command -v` le trouve, donc la detection de version le voit. La commande dit oui, la verification dit
non :

    verdict      : « Aucun agent n'etait installe sur Test-Server-Debian : il n'y avait rien
                     a desinstaller. »
    verification : « ATTENTION : un agent est TOUJOURS detecte sur ce serveur (version 7.0.99).
                     La commande a beau avoir rendu un succes, l'agent est encore la. »

**CINQ ISSUES** tirees du contenu du flux : purge, RIEN A PURGER, echec, inacheve, refus.

**UN EFFET QUE JE N'AVAIS PAS PREVU, mesure et conserve.** La desinstallation avait vide l'inventaire — a
juste titre de son point de vue, puisqu'elle avait rendu 0. La verification retrouve l'agent, et la route
de version REPOSE la ligne (`_upsert_agent`). L'inventaire finit donc juste, non parce que la
desinstallation avait raison, mais parce que la verification l'a corrigee. Cela ne se voit qu'EN BASE, et
une assertion le mesure.

**NOMMER LA PRODUCTION, SUR LE GESTE QUI DETRUIT.** Vu a l'image : le panneau nommait la machine sans dire
qu'elle etait en production, et « srv-zabbix » se lit comme « Test-Server-Debian » dans une phrase. Un
exploitant a le droit de desinstaller un agent d'un serveur de production — ce n'est pas au portail de le
lui interdire — mais le lui DIRE au moment ou il decide, oui. Mesure DANS LES DEUX SENS : avertissement
cache sur DEV, nommant `srv-zabbix` sinon. Et ouvrir ce panneau n'emet aucune requete : la production
n'est pas jointe pour mesurer qu'on previent a son sujet.

**LE PERIMETRE A ETE MESURE AVANT D'ETRE PAYE** : `apt-get autoremove --dry-run` rend « 0 to remove » sur
le banc d'essai, et la suite l'inscrit dans son journal a chaque execution.

**DEUX DEFAUTS DE MA SUITE.** Elle assertait la chaine brute du faux binaire (`7.0.99-faux-v11`) alors que
la route de version EXTRAIT le numero par `(\d+\.\d+[\.\d]*)` et n'affiche que `7.0.99` — la suite avait
tort, pas le portage. Et un detail d'assertion disait « journal absent ou vide » sur un PASS.

**UNE LACUNE DE COUVERTURE FERMEE, sur une question de l'exploitant.** Les douze suites du module se
connectaient TOUTES en `rw-test-admin`, qui porte `can_manage_supervision`. Or la regle du projet est
qu'une permission vaut « cette permission OU superadmin (role 3) », et `rw-test-super` est role 3 SANS
cette permission (mesure en base). Le second chemin de la garde n'etait donc jamais exerce : un
durcissement qui l'aurait casse serait passe inapercu. `supervision-onglets` mesure maintenant les deux —
role 1 → **403**, role 3 sans permission → **200** — DES DEUX COTES, donc en parite. Sa reference passe de
14 a **16** cote portage et de 11 a **13** cote legacy.

**Tests.** `go-page-supervision-desinst` : base rouge 8 PASS / 5 FAIL, puis **29 PASS sur le portage** et
**15 sur le legacy**. i18n : 22 cles FR + 22 EN dans le meme commit, **231 = 231**. 341 pytest inchanges
(aucune modification backend dans ce commit). LOT complet rejoue.

**Reference du LOT** : `go-page-supervision-desinst` entre avec **15 PASS sur le legacy** et **29 sur le
portage**, et `supervision-onglets` passe a 16/13. Le LOT passe a **82 executions de suite** pour **1158 assertions**.

### v1.37.44 — securite : la desinstallation ne peut plus annoncer un succes qu'elle n'a pas verifie

Deux correctifs sur le chemin DESTRUCTEUR, autorises ensemble avant V11 et V12.

**(1) LE CODE DE SORTIE DE LA DESINSTALLATION ETAIT FABRIQUE.** Les quatre etapes finissaient CHACUNE par
`|| true` et jetaient leur stderr : la chaine ne pouvait pas sortir autrement qu'en 0. Puis
`SUCCESS_MACHINE::` etait emis et `_remove_agent` appele INCONDITIONNELLEMENT. Mesure du 2026-08-23 :

    Exécution terminée (code 0).
    SUCCESS_MACHINE::2::Agent Zabbix desinstalle de Test-Server-Debian.
    inventaire : 1 ligne avant -> 0 apres

…sur une machine ou l'agent n'avait **jamais** ete installe. Si la purge avait echoue, l'exploitant aurait
vu le meme succes vert et le meme inventaire vide, l'agent continuant de tourner. Voir PARITE.md E-88.

**POURQUOI UNE GARDE `dpkg-query` PLUTOT QU'UN SIMPLE RETRAIT DU `|| true`.** Mesure :
`apt-get purge -y zabbix-agent` rend **100** quand le paquet n'est pas dans l'index du DEPOT — pas
seulement quand il n'est pas installe. Retirer le `|| true` sans plus aurait fait echouer la
desinstallation sur toute machine ou le depot Zabbix n'est pas configure, c'est-a-dire le cas general. La
commande demande donc d'abord a `dpkg-query` ce qui est REELLEMENT installe :

    rien d'installe       -> `RIEN_A_PURGER`, code 0 HONNETE (l'agent n'est pas la)
    paquets installes     -> la purge tourne, et son VRAI code remonte

`systemctl stop` garde son `|| true` : un service deja arrete, ou un systeme sans systemd, n'est pas un
echec de la desinstallation. La purge, elle, EST l'operation.

**L'INVENTAIRE SUIT DESORMAIS CE QU'ON A PU CONSTATER** (`_conclut_desinstallation`) : code 0 -> la ligne
est retiree (purge reussie OU rien a purger : dans les deux cas il n'y a plus d'agent) ; code non nul ou
inconnu -> `ERROR_MACHINE::` et l'inventaire n'est PAS touche. Un inventaire qui oublie un agent encore
installe est pire qu'un inventaire qui n'a pas su.

**`apt-get autoremove -y` RETIRE DES QUATRE COMMANDES.** Il retire tout paquet que le systeme juge devenu
inutile — pas seulement les dependances de l'agent. Une desinstallation d'agent n'a pas a decider cela
pour l'administrateur ; `apt-get purge` suffit a retirer l'agent ET sa configuration. Mesure sans le
payer : `apt-get autoremove --dry-run` rend « 0 to remove » sur le banc d'essai — ce qui exonere le BANC,
pas la commande.

**La commande etait DUPLIQUEE** : `zabbix_uninstall` en portait une copie en ligne, a cote de celle du
registre. Deux exemplaires a corriger, et le second aurait ete oublie. Une seule source desormais.

**(2) LE ROLLBACK ETAIT DESARME AU MOMENT OU IL SERVAIT.** `_backup_agent_config` faisait
`test -f X && cp X Y || echo 'NO_FILE'`. En shell, `||` se declenche si A OU B a echoue : un `cp` en echec
empruntait donc la branche « pas de fichier ». Mesure des trois cas :

    fichier absent              -> [NO_FILE]  rc=0     (voulu)
    fichier present, cp reussi  -> []         rc=0
    fichier present, cp ECHOUE  -> [NO_FILE]  rc=0     <- INDISCERNABLE du premier

La fonction rendait `None`, et les appelants qui gardent leur repli par `if backup_path:` le desarmaient
donc precisement quand il servait — le `>` de l'ecriture tronque le fichier avant d'ecrire, laissant une
configuration tronquee et rien pour la retablir. SIX routes en dependent, dont le deploiement (V12). La
forme corrigee teste l'existence D'ABORD, et le `cp` n'est tente que dans la branche ou le fichier
existe : son echec LEVE. Voir PARITE.md E-83.

**`execute_as_root_stream` REND SON CODE DE SORTIE.** Ajout purement ADDITIF : `yield from` sans
affectation l'ignore, donc aucun appelant existant ne change. Il permet aux routes de flux de DECIDER au
lieu d'annoncer.

**Verification apres correctif**, meme appel qu'avant :

    START_MACHINE::2::Desinstallation agent Zabbix sur Test-Server-Debian.
    RIEN_A_PURGER
    Exécution terminée (code 0).
    SUCCESS_MACHINE::2::zabbix desinstalle de Test-Server-Debian.

Le flux DIT maintenant qu'il n'y avait rien a purger, et l'inventaire n'est vide que parce que le code
est 0 — ce qui est vrai.

**Tests.** 12 tests neufs (`test_supervision_uninstall.py`), **341 pytest** au total. Verification ciblee
des deux suites qui exercent la sauvegarde (`supervision-ecriture` 38, `supervision-reconf` 27) :
conformes. Le LOT complet accompagne le portage de V11, au commit suivant.

### v1.37.43 — module `supervision/`, sous-lot V10 : la reconfiguration, et un verdict qui ne recopie pas le marqueur

**Symptome.** Le flux de reconfiguration se termine par `Exécution terminée (code 127).` puis
`SUCCESS_MACHINE::2::Reconfiguration reussie`. Le legacy recopie le marqueur : il annonce une reussite
alors que le redemarrage a echoue DEUX LIGNES plus haut. Et il n'a AUCUNE confirmation — `reconfigureSingle`
part au premier clic, la ou `deploy` et `uninstall` ouvrent au moins un `confirm()`.

**Fix.** Le portage lit le flux ENTIER et en tire QUATRE issues : reussite, **partielle**, echec, inacheve.
Mesure des deux cotes, meme geste, meme machine sans `systemctl` :

    legacy  : « Reconfiguration reussie pour Test-Server-Debian. »
    portage : « Configuration poussee sur Test-Server-Debian, mais une commande distante
                a ECHOUE (code 127). Le fichier est en place et le service ne tourne
                peut-etre pas : lisez le journal ci-dessous… »

**ON PARSE LE NOMBRE, PAS LA PHRASE.** « Exécution terminée (code N). » est une phrase francaise,
susceptible de changer ; `(code N)` est la partie protocole. Le verdict s'appuie sur `/\(code (\d+)\)/`,
sur les prefixes `ERROR:` / `WARN:` et sur les marqueurs — jamais sur un libelle traduisible.
**LE JOURNAL EST MONTRE**, pas resume : le donner sous le verdict permet de le VERIFIER au lieu de le
croire.

**QUATRE EFFETS ENUMERES, et le decoupage n'en annoncait que trois** : sauvegarde datee, ecriture cle par
cle, **ecriture d'une cle PSK** si la configuration globale en porte une, redemarrage. Le quatrieme est
CONDITIONNEL et sa condition est MESUREE : sans PSK, la ligne est cachee. Annoncer un effet qui n'aura pas
lieu est aussi faux que d'en taire un.

**L'ECRITURE FUSIONNE, ELLE NE TRONQUE PAS.** `_write_config_stream` purge chaque cle au `sed` puis
l'ajoute : les lignes que le portail ne gere pas SURVIVENT. La suite pose `Timeout=42` avant le geste et
verifie qu'elle est toujours la apres. C'est la semantique INVERSE de l'editeur (V9), qui tronque avec
`>` — deux gestes voisins sur le meme fichier, deux comportements opposes.

**PAR LIGNE, PAS SUR SELECTION** : mesure, le legacy offre 1 geste de masse et 3 cases a cocher ; le
portage 3 gestes par ligne et 0 case. **UNE REGLE APPLIQUEE PAR LE BACKEND SE REND VISIBLE** :
`zabbix_reconfigure` rend 400 « Aucune configuration globale » tant que la table est vide — le bouton est
donc DESACTIVE, avec l'explication en infobulle, et la section l'annonce.

**LA PASSERELLE BUFFERISE, DECISION PRISE SUR MESURE** : `/supervision/` reste hors de `EN_FLUX` parce
qu'une reconfiguration d'UNE machine dure **1,4 s**. Tenir la connexion ouverte n'apporterait rien a ce
prix. A remesurer si V11 ou V12 changent cet ordre de grandeur.

**DEUX DEFAUTS DE MA SUITE.** `/Reconfigure/` est un PREFIXE de « Reconfigurer » et passait donc sur la
page francaise — deuxieme motif trop large en deux sous-lots, apres `override_Hostname` qui contenait
« name ». Et un detail d'assertion qui disait « journal absent ou vide » sur un PASS : le detail est
imprime dans les deux cas, il doit dire ce qu'on a TROUVE.

**ET UNE CAPTURE QUI MONTRAIT UN ETAT INATTEIGNABLE.** Le script forcait `disabled = false` sur un bouton
que le portage desactive : l'image montrait un panneau ouvert a cote de « Aucune configuration globale
enregistree ». Reprise avec une vraie configuration globale — regarder le rendu ne sert que si le rendu
est celui qu'un exploitant peut atteindre.

**RESTE DECLARE ET NON CORRIGE**, hors autorisation : `generic_reconfigure` annonce `SUCCESS_MACHINE::`
sans rien avoir ecrit quand la configuration globale manque, et un echec de dechiffrement du PSK n'est que
journalise (E-85).

**Tests.** `go-page-supervision-reconf` : base rouge 7 PASS / 7 FAIL, puis **27 PASS sur le portage** et
**13 sur le legacy**. i18n : 20 cles FR + 20 EN dans le meme commit, **209 = 209**. 329 pytest inchanges
(aucune modification backend). LOT complet rejoue.

**Reference du LOT** : `go-page-supervision-reconf` entre avec **13 PASS sur le legacy** et **27 sur le
portage**. Le LOT passe a **80 executions de suite** pour **1110 assertions** (compte au journal du rejeu).

### v1.37.42 — module `supervision/`, sous-lot V10a : les reglages par machine, avec une liste FERMEE

**Ce n'est pas un portage, c'est une conception autorisee.** `supervision_overrides` n'avait JAMAIS eu
d'interface, dans aucun des deux portails : la priorite `overrides > profil > globale` existait avec son
etage le plus fort INATTEIGNABLE. L'exploitant a tranche pour « corriger l'injection ET porter une
interface bornee » — v1.37.41 a corrige, ce commit porte.

**LA DECISION DE DESSIN : NE PAS OFFRIR D'ENTREE LIBRE PLUTOT QUE LA VALIDER.** Huit champs, huit noms
fixes — exactement ceux que `_build_config_lines` traite par leur nom (`Hostname`, `Server`,
`ServerActive`, `HostMetadata`, `ListenPort`, `TLSConnect`, `TLSAccept`, `TLSPSKIdentity`) — et AUCUN champ
ou saisir un NOM de parametre. Valider une entree libre et ne pas en offrir ne se valent pas : la seconde
ne se contourne pas par une requete forgee. La suite en emet une, justement, pour exercer la revalidation
du controleur : valeur multiligne refusee, valeur hors liste fermee refusee, port hors bornes refuse.

**LE FORMULAIRE POSTE VERS LE PORTAGE, PAS VERS LA PASSERELLE, et le test en fait une propriete.**
`POST /supervision/overrides/<id>` est la seule route du module touchant une machine SANS
`@require_machine_access` (E-85, declare et non corrige, hors du perimetre autorise). Ecrire en base avec
une liste fermee, c'est ne pas heriter de cette laxite — meme raison qu'en V4.

**CE GESTE NE JOINT AUCUNE MACHINE, ET LA PAGE LE DIT.** Ces valeurs vivent en base et ne partiront qu'a
la prochaine reconfiguration. La suite le MESURE : zero requete vers la passerelle pendant
l'enregistrement. C'est ce qui distingue ce sous-lot de V9. **Vider un champ SUPPRIME le reglage**, il ne
l'enregistre pas vide — un `param_value` vide serait relu comme une ligne `Cle=`, une directive sans
valeur.

**UN DEFAUT DE MON PROPRE PORTAGE, TROUVE PAR MA PROPRE SUITE, ET SA CAUSE EST DANS LE CADRE.** Le premier
jet ne supprimait JAMAIS rien. Laravel place `ConvertEmptyStringsToNull` dans le groupe `web` : une chaine
vide arrive donc en `null`, EXACTEMENT comme un champ absent — alors que vide signifie « supprime ce
reglage » et absent « ne le touche pas ». Mesure :

    POST a="" b="v"   ->  input('a') = NULL     has('a') = true     input('b') = "v"

Le code testait `input(...) === null` et sautait les champs vides. Corrige par `has()`. Un intergiciel du
cadre avait rendu deux choses differentes identiques, et seule la suite l'a vu — pas la relecture.

**DEUX DEFAUTS DE MA SUITE.** Un motif `/nom|name|param/`, cense prouver qu'aucun champ ne saisit un NOM
de parametre, echouait sur `override_Hostname` — il contient « name » — et ne disait rien de plus que la
comparaison a la liste FERMEE ; remplace par une propriete non mesuree jusque-la (le formulaire poste vers
le portage). Et une NAVIGATION referme l'onglet : les panneaux arrivent `hidden`, donc apres chaque
aller-retour de formulaire le bouton suivant vit dans un panneau cache — l'echec apparaissait deux gestes
plus loin, en « Node is either not clickable ».

**ON N'AFFICHE PAS SEULEMENT CE QU'ON SAIT ECRIRE.** Un reglage pose hors de la liste fermee — par l'API,
ou avant ce portage — EXISTE et AGIT. L'ecran l'annonce en le nommant, tout en disant qu'il ne peut pas le
modifier. Mesure avec une fixture `Timeout`.

**UN DEFAUT VU A L'IMAGE.** `.rw-etiquette-champ` met TOUTE l'etiquette en capitales gras — juste pour un
intitule, illisible pour une phrase — et seule `.rw-saisie` y etait remise a plat : chaque champ portait
cinq lignes de capitales sous lui. Corrige par une regle placee JUSTE APRES celle de `.rw-saisie`, parce
qu'a specificite egale l'ordre tranche.

**Tests.** `go-page-supervision-reglages` : base rouge 5 PASS / 8 FAIL, puis **32 PASS sur le portage** et
**8 sur le legacy** (cote legacy, la suite ne mesure qu'une chose : qu'il n'y a rien). i18n : 31 cles FR +
31 EN dans le meme commit, **189 = 189**. 329 pytest inchanges.

**Reference du LOT** : `go-page-supervision-reglages` entre avec **8 PASS sur le legacy** et **32 sur le
portage**. Le LOT passe a **78 executions de suite** pour **1070 assertions** (compte au journal du rejeu).

### v1.37.41 — securite : la valeur d'un override ne peut plus devenir une ligne de configuration

**Symptome.** `_SAFE_PARAM_RE` ne portait que sur le NOM d'un override. La valeur partait en
`f"{key}={value}\n"`, encodee en base64 et AJOUTEE au fichier de configuration de l'agent : une valeur
portant un saut de ligne produisait donc **une directive autonome**, que personne n'avait demandee par
aucun parametre nomme.

**Mesure du 2026-08-22 sur Test-Server-Debian (id 2, DEV), charge deliberement inoffensive.**

    POST /supervision/overrides/2  {"Timeout": "3\nLIGNE_INJECTEE=temoin"}
      -> {"success":true,"message":"Overrides sauvegardes"}
      -> la base retient  33 0A 4C49474E45...   (saut de ligne BRUT)

    POST /supervision/zabbix/reconfigure  {"machine_ids":[2]}
      -> fichier ecrit :   7  Timeout=3
                           8  LIGNE_INJECTEE_PAR_LA_MESURE=temoin   <- directive autonome

**Portee.** Sur un agent Zabbix reel, cette ligne peut etre un `UserParameter` — donc **l'execution d'une
commande arbitraire par l'agent**, sur la machine supervisee. La route d'ecriture porte
`@require_role(2)` + `@require_permission('can_manage_supervision')` : **un role 2 qui n'est PAS
administrateur du portail suffit**. Si personne ne l'a fait, c'est qu'**aucune interface n'ecrit dans
cette table** — le trou etait atteignable par l'API, pas par un ecran.

**Fix.** `_SAFE_VALUE_RE = ^[^\x00-\x1f\x7f]*$` : une valeur de configuration agent tient sur UNE
ligne, tout caractere de controle est refuse. **Applique DEUX FOIS** :
 - a l'**ecriture** (`save_overrides`), parce que c'est la porte d'entree ;
 - a la **relecture** (`_build_config_lines`), parce que la base peut deja contenir des lignes posees
   avant ce correctif — une validation qui ne garde que l'entree laisse le fichier a la merci de
   l'historique. Un refus a la relecture est journalise en `warning` avec la machine et la cle.

**UN REFUS SILENCIEUX N'EST PAS UN REFUS.** L'ancien code sautait les noms invalides sans rien dire :
l'appelant recevait « Overrides sauvegardes » et croyait avoir enregistre ce qu'il venait d'ecrire. La
reponse **NOMME** desormais les entrees refusees et chiffre les deux cotes. Mesure apres correctif :

    {"success":true,"saved":1,"message":"1 override(s) enregistre(s), 1 refuse(s).",
     "rejected":[{"param":"Timeout","raison":"valeur multiligne ou avec un caractere de controle"}]}

`ListenPort=10051`, legitime, passe : le correctif ne ferme pas la porte a tout.

**RESTE DECLARE ET NON CORRIGE, hors du perimetre autorise** : `POST /supervision/overrides/<id>` est la
**seule route du module touchant une machine sans `@require_machine_access`** — son `machine_id` vient du
chemin d'URL. Inerte au role 2 (`check_machine_access` rend vrai des ce niveau), mais absent. Voir E-85.

**Tests.** 11 tests neufs (`test_supervision_overrides.py`), **329 pytest** au total. Verification ciblee
des trois suites supervision les plus proches (onglets 14, config 17, ecriture 38) : conformes. Le LOT
complet n'a pas ete rejoue pour ce commit : le changement est borne a `supervision_overrides` (0 ligne en
base) et a `_build_config_lines`, appele par les seules routes de reconfiguration et de deploiement, ni
portees ni couvertes par une suite. Le rejeu complet accompagne le commit suivant, qui touche le portage.

### v1.37.40 — module `supervision/`, sous-lot V9 : l'ecriture distante, et le troisieme cas enfin dit

**Symptome.** Sur Centreon, Prometheus et Telegraf, le backend jetait les TROIS codes de retour et
annoncait « sauvegardee et agent redemarre » meme quand rien n'avait ete ecrit — mesure : un POST vers un
repertoire INEXISTANT rendait 200/success:true. Et cote client, le « restart echoue » que la route Zabbix
construisait exprès n'atteignait JAMAIS l'ecran. Detail des mesures en PARITE.md E-83.

**Arbitrage.** L'exploitant a tranche pour la correction des routes generiques.

**Fix backend.** `generic_config_save` et `generic_restore` verifient leurs codes de retour, restaurent la
sauvegarde si l'ecriture echoue, et distinguent le troisieme cas. Mesure sur l'appel qui mentait :

    avant : 200 {"success":true,  "Config telegraf sauvegardee et agent redemarre."}
    apres : 500 {"success":false, "Ecriture echouee: cannot create /etc/telegraf/telegraf.conf"}

`zabbix_restore` corrigee PAR COHERENCE, AU-DELA DE LA LETTRE DE L'AUTORISATION : elle portait le meme
defaut — code de retour du redemarrage jete, « agent redemarre » non verifie — et laisser la route
generique plus honnete que sa jumelle Zabbix aurait recree l'incoherence a l'envers. Choix de jugement,
dit comme tel pour pouvoir etre defait seul. **`restarted` est un booleen ajoute aux quatre routes** : un
client n'a pas a deviner l'issue en analysant une phrase francaise. Ajout purement ADDITIF.
**`_backup_agent_config` n'a PAS ete touche** : la correction du `A && B || C` n'etait pas dans
l'autorisation, et six routes en dependent, dont le deploiement. Le defaut reste declare.

**LE TROISIEME CAS EST DIT, et c'est toute la difference.** La machine de test n'a ni agent ni
`systemctl` : l'ecriture reussit, le redemarrage echoue. Mesure des DEUX cotes, sur le meme geste :

    legacy  : ✓ config_remote_saved     <- coche verte, cle cassee, pas un mot du redemarrage
    portage : Fichier ecrit, mais l'agent n'a PAS redemarre. La configuration est en place
              et le service ne tourne pas : verifiez-le avant de compter sur la supervision.

Le legacy ne cache pas l'avertissement par negligence d'affichage : LA DETTE i18n LE SUPPRIME. Son
`toast(__('config_remote_saved') || res.message, 'success')` n'atteint jamais `res.message`, une cle
absente etant rendue telle quelle donc non vide. Le portage lit le BOOLEEN, dit l'issue traduite, et ne
jette pas la sortie d'erreur brute de la commande a l'ecran — le test verifie son absence.

**DEUX DEFAUTS DE MON PROPRE PORTAGE DE V7, trouves en corrigeant un texte devenu faux.** Le bloc « pas
encore porte » annoncait encore « la lecture et l'ecriture arrivent avec les sous-lots suivants » alors
que la lecture etait portee depuis V7. En le corrigeant :

 1. **les quatre URL de l'editeur etaient FIGEES sur `/supervision/zabbix/...`** pendant que le chemin
    affiche suivait le selecteur de plateforme. Choisir Telegraf annoncait `/etc/telegraf/telegraf.conf`
    et lisait `/etc/zabbix/zabbix_agent2.conf` : EXACTEMENT le defaut E-79 que V7 reprochait au legacy,
    revenu par la ROUTE au lieu du CHEMIN. La base rouge le prouve — « centreon: route vise zabbix |
    prometheus: route vise zabbix | telegraf: route vise zabbix ». Et la suite de V7 ne pouvait pas le
    voir : elle n'exercait que Zabbix, la seule plateforme ou l'URL figee se trouvait etre la bonne.
    Chemins et routes viennent desormais de la MEME table serveur, indexee par la meme cle, et la
    propriete est mesuree SUR LES QUATRE PLATEFORMES, par interception, sans une seule session SSH ;
 2. **changer de serveur vidait la zone d'edition en silence.** Correct quand le champ etait en lecture
    seule ; depuis que V9 le rend modifiable, le meme geste efface ce que quelqu'un vient de taper — une
    PERTE DE TRAVAIL. Desormais annonce. Ce defaut est apparu parce que ma SUITE echouait a ouvrir le
    panneau : elle remplissait puis choisissait le serveur. Le portage avait raison, la suite avait tort.

**LE COUT S'ENONCE, ET LES TROIS EFFETS SONT ENUMERES** : la copie datee creee avant, le remplacement du
fichier, le redemarrage du service. « Enregistrer » cache deux effets sur trois. Le legacy n'annonce rien.

**LA RESTAURATION CESSE D'ETRE UN CLIC SANS FILET.** Cote legacy, liste dans une fenetre modale, un bouton
par ligne, un clic, la configuration est ecrasee et l'agent redemarre — ni `confirm()`, ni panneau, rien.
Ici le bouton OUVRE un panneau qui nomme la sauvegarde visee ET le fichier ecrase, et le test assert
qu'ouvrir n'emet aucune requete.

**POURQUOI CETTE SUITE PEUT CLIQUER, la ou celle de V8 devait avorter** : le geste porte sur UNE machine,
celle qu'on choisit — Test-Server-Debian (id 2, DEV). La production n'est jamais selectionnee, donc jamais
jointe. Le fichier ecrit et ses copies datees sont nettoyes dans un `finally`, et l'etat rendu est RELU
pour etre prouve plutot qu'affirme.

**CINQ EXONERATIONS MESUREES** : traversee de chemin refusee (`../../etc/passwd` → « Nom de backup
invalide »), chemin jamais choisi par le client, transport base64 fidele a l'octet (`od -c`), sauvegarde
faite AVANT l'ecriture et portant bien l'ancienne version, et les quatre gardes sur les quatre routes.

**UNE ASSERTION QUI PASSAIT POUR LA MAUVAISE RAISON, resserree** : le controle du message de restauration
lisait tout le panneau visible, et le message de l'ECRITURE, encore a l'ecran, le satisfaisait. Il lit
maintenant le porte-messages de la restauration et exige qu'il NOMME la sauvegarde.

**Trois cles fermees** : `config_remote_saved`, `backup_restored`, `btn_restore` (15e, 16e, 17e). L'onglet
de l'editeur est COMPLET : son bloc « pas encore porte » est retire, et la cle devenue inutile avec lui.
Le libelle du chemin dit « Fichier cible » et non « Fichier a lire » — l'editeur ecrit aussi.

**Tests.** `go-page-supervision-ecriture` : base rouge 5 PASS / 4 FAIL, puis **38 PASS sur le portage** et
**18 sur le legacy**. 10 tests backend neufs (`test_supervision_config_save.py`), **318 pytest** au total.
i18n : 25 cles FR + 25 EN dans le meme commit, une cle retiree des deux, **158 = 158**.

**Reference du LOT** : `go-page-supervision-ecriture` entre avec **18 PASS sur le legacy** et **38 sur le
portage**. Le LOT passe a **76 executions de suite** pour **1030 assertions** (compte au journal du rejeu, jamais reconduit).

### v1.37.39 — module `supervision/`, sous-lot V8 : le releve de parc devient une tache de fond

**Symptome.** Le releve de parc n'existait que dans le navigateur : un clic sur « Scanner tous les
agents » lancait `machines x 4 plateformes` requetes en parallele, chacune ouvrant sa session SSH,
chacune `@threaded_route` — donc chacune consommant un slot du pool PARTAGE par toutes les routes du
backend, celui dont le commentaire interdit precisement cet usage. Et le filtre de la table ne bornait
pas ce releve : une ligne visible, trois machines jointes, dont la production (E-80).

**Arbitrage.** L'exploitant a tranche pour la tache de fond, avec autorisation explicite d'ecrire la
route backend manquante. L'ecart signale — cette option joint la production en usage reel — a ete redit
avant de commencer, et la decision maintenue.

**Fix.** PREMIERE ROUTE PYTHON ECRITE PENDANT CETTE MIGRATION : `POST /supervision/scan-all`. Reponse
immediate `{queued, background, task_id}`, puis un unique thread demon qui balaie le parc
SEQUENTIELLEMENT. Le pool partage n'est plus touche du tout. Motif aligne sur `/ssh-audit/scan-all`
(v1.37.13), y compris le helper `_spawn_scan_all_thread` isole pour rester patchable sans stubber
`threading.Thread` globalement — le ThreadPoolExecutor de `@threaded_route` en depend pour creer ses
workers, et le stubber globalement interbloque le pool.

**UNE SEULE SESSION SSH PAR MACHINE, MESUREE AU JOURNAL PARAMIKO.** Les quatre lectures partagent la
session de la machine :

    INFO  Authentication (password) successful!
    DEBUG Secsh channel 0 opened.   zabbix_agent2 -V
    DEBUG Secsh channel 1 opened.   centreon-monitoring-agent --version
    DEBUG Secsh channel 2 opened.   node_exporter --version
    DEBUG Secsh channel 3 opened.   telegraf --version
    DEBUG EOF in transport thread

Un transport authentifie, quatre canaux : le parc passe de 12 sessions a 3. La mesure exonere au passage
l'echec `publickey` visible avant le mot de passe — `service_account_deployed = 0` pour cette machine,
la base dit vrai, c'est la negociation normale de paramiko.

**LE COUT S'ENONCE AVANT LE GESTE, ET LA PRODUCTION EST NOMMEE.** Le bouton n'envoie rien : il ouvre un
panneau de decision rendu par le SERVEUR — « 3 machine(s), 4 plateforme(s), 3 session(s) SSH — une par
machine, pas une par plateforme », puis « Machines de PRODUCTION concernees : srv-zabbix. » Nommer
plutot que compter est le point : « 3 machines » ne previent personne. **Le corps de la requete est
vide** : la portee vient du serveur, jamais d'une liste lue dans le tableau.

**COMMENT ON CLIQUE UN BOUTON QUI JOINDRAIT LA PRODUCTION.** La suite clique le vrai declencheur puis le
vrai bouton de confirmation, et la requete est INTERCEPTEE ET AVORTEE : le geste est exerce de bout en
bout, la requete est mesuree (methode, chemin, corps), aucune machine n'est jointe. Le contrat de mise en
file se mesure a part, sur une portee explicite (`machine_ids: [2]`, DEV) : 200 en 230 ms, la ou le legacy
tient la connexion pendant tout le balayage. Et le chemin « tout le parc », qu'aucun navigateur ne peut
declencher ici, est exerce par les tests backend avec le thread patche — on lit QUELLES machines auraient
ete balayees.

**UN GARDE SANS OBJET NE GARDE RIEN.** `@require_machine_access` lit `machine_id`/`machine_ids` dans le
corps et fail-close sur tout id refuse — mais un corps vide ne lui donne RIEN a refuser, et ici le corps
vide signifie « tout le parc ». Il aurait eu l'apparence d'un garde sans en etre un. Le parc implicite est
donc filtre dans le handler par `check_machine_access`, et un test le prouve. Ce filtre ne retire rien
aujourd'hui (role 2 requis) : c'est dit plutot que sous-entendu.

**AUCUNE NOTIFICATION, DELIBEREMENT.** `/ssh-audit/scan-all` appelle `notify_subscribed` par machine ; un
releve de version n'est ni une alerte ni un verdict. Un effet sortant ne se defait pas. **LE PRIVILEGE
N'A PAS ETE CHANGE** : la lecture passe par `execute_as_root` comme les routes par machine — E-78 reste
declare, un changement de droits ne se fait pas au detour d'un portage, et une lecture qui echouerait
sans root produirait un ecart avec les routes existantes.

**DEUX DEFAUTS DE MON PORTAGE, VUS A L'IMAGE.** Le cout s'affichait en vert de reussite
(`rw-confirmation`) dans un panneau a bordure rouge — le vert invite a cliquer alors que la phrase enonce
un COUT ; passe en encart neutre. Et le bouton etait a plus de mille pixels de la phrase qui l'explique :
la convention « action principale a droite » vaut pour un PIED DE FORMULAIRE, pas pour une action unique
attachee a une explication. Aucune assertion DOM ne voit ni l'un ni l'autre.

**UN DEFAUT DE MA SUITE, TROUVE PAR ELLE-MEME.** Son premier nettoyage supprimait les taches PAR TYPE :
il aurait efface l'historique d'un releve lance par un exploitant. Elle ne supprime plus que la tache
dont elle a retenu l'identifiant, et sa propriete de sortie est un DELTA, pas un zero.

**UN TEXTE QUI ALLAIT DEVENIR FAUX**, corrige dans le meme commit : le bloc « pas encore porte »
annoncait « le releve de tout le parc en une fois » parmi les gestes a venir.

**Tests.** `go-page-supervision-releve` : base rouge 3 PASS / 4 FAIL, puis **28 PASS sur le portage** et
**11 sur le legacy**. 12 tests backend neufs (`test_supervision_scan_all.py`), **308 pytest** au total.
i18n : 14 cles FR + 14 EN dans le meme commit, **135 = 135**.

**Reference du LOT** : `go-page-supervision-releve` entre avec **11 PASS sur le legacy** et **28 sur le
portage**. Le LOT passe a **74 executions de suite** (38 cote portage, 36 cote legacy), pour **974
assertions**.

**UN CHIFFRE HERITE N'EST PAS UNE MESURE.** Le suivi de chantier annoncait « 65 suites » depuis
plusieurs sous-lots ; le decompte reel avant V8 etait de **72**. Le nombre a donc ete COMPTE dans le
journal du rejeu plutot que deduit de l'ancien total — meme regle que pour les references de suite, qui
se mesurent au lieu de s'annoncer.

### mesure — module `supervision/`, sous-lot V8 : le releve de parc n'est pas porte, et c'est le resultat

*Aucun changement de comportement, aucune version : ce commit ne porte que la mesure et la declaration.*

**Symptome.** Le decoupage annoncait V8 comme « a reconcevoir en tache de fond ». La mesure montre que la
reconception ne repond pas a la vraie question : **le releve joint la PRODUCTION par construction.**

**CE QU'UN CLIC ENVOIE, COMPTE SANS CLIQUER.** `scanAllAgents` (`main.js:88`) itere
`#deploy-table-body tr[data-machine-id]` et boucle sur les quatre plateformes. La page charge toutes les
machines non archivees — `srv-zabbix` (id 1, PROD) comprise. Parc actuel : 3 machines, donc
**3 x 4 = 12 sessions SSH dans la meme boucle synchrone**, sans etalement ni plafond ni file. La mesure a
ete faite par LECTURE du code et OBSERVATION DU RESEAU : `requetes_envoyees: []`, prouve, le bouton n'a
pas ete touche.

**LE DEFAUT LE PLUS CONCRET : le filtre borne une action de masse et pas sa voisine.** Filtre saisi sur
`Test-Server`, onglet actif :

    lignes reellement visibles      : 1   (Test-Server-Debian)
    lignes visees par scanAllAgents : 3   (OpenCVE-Test-OnPrem, srv-zabbix, Test-Server-Debian)

`filterDeployTable` masque par `row.style.display`, que le selecteur du releve ne regarde pas — alors que
celui de « Tout cocher » le regarde (`tr:not([style*="display: none"])`). Meme tableau, meme barre
d'actions, deux perimetres opposes, et rien a l'ecran qui le dise.

**LE BACKEND CONDAMNE CE CHEMIN DANS SON PROPRE COMMENTAIRE** (`routes/helpers.py:24-30`) : les operations
longues de parc « doivent passer en tache de fond (centre de taches), **jamais monopoliser ce pool** ».
C'est ecrit parce que le sinistre a eu lieu : le fix v1.37.13 relate une boucle SSH de parc DANS la
requete HTTP, 504 en cascade sur toute l'interface. `ssh-audit/scan-all` a ete corrige dans cette vague ;
**`supervision/` ne l'a pas ete.** Et `threaded_route` bloque sur `future.result()` SANS timeout : au-dela
des 32 slots, les requetes ne tombent pas, elles s'empilent.

**IL N'EXISTE AUCUNE ROUTE DE PARC COTE BACKEND.** Les 30 routes du blueprint sont toutes par machine ; le
releve n'existe que dans le JS. Le « porter en tache de fond » serait donc ECRIRE UNE ROUTE QUI N'A JAMAIS
EXISTE — pas un portage.

**DEUX CLES i18n CASSEES, cause racine MIROIR de celle de V4.** `scan_all_running` et `scan_all_done`
existent — mais sous `supervision.*`, que `window._i18n` (peuple par `getJsTranslations('js.')`) ne
contient pas. Resolu dans la page : `__('scan_all_running')` rend **`"scan_all_running"`**. Comme `__()`
retourne la cle, le repli `|| 'Scan en cours...'` NE SE DECLENCHE JAMAIS. Treizieme et quatorzieme.
`select_machine`, elle, est bien dans `js.php` : **exoneree**.

**UN NEUVIEME FRANCAIS EN DUR, celui-la TOUJOURS affiche.** `updateAgentCounter` (`main.js:84`) construit
`count + '/' + total + ' avec ' + currentPlatform` — mesure a l'ecran : **`0/3 avec zabbix`**. Ce n'est pas
un repli inatteignable comme les huit precedents.

**DEUX EXONERATIONS, dites aussi nettement qu'une accusation.** Le compteur `startsWith(letter)` ne
confond aucune plateforme avec le jeu de badges actuel (Z/C/P/T distincts, aucun autre element arrondi
dans la cellule) — le selecteur reste fragile, il ne produit pas de faux compte. Et le `@threaded_route`
**imbriqué n'existe pas** : mesure avec le Werkzeug du conteneur, la regle statique
`/supervision/zabbix/version` gagne sur `/supervision/<platform>/version` **dans les deux ordres de
declaration**. Une lecture prend un slot, pas deux.

**MAIS HUIT BRANCHES MORTES ARMENT LE PIEGE (nouveau, E-81).** Les huit paires statique/generique du
module portent `@threaded_route` **des deux cotes**, et le `if platform == 'zabbix': return zabbix_xxx()`
de chaque handler generique est inatteignable par HTTP. La regle statique ressemble a un doublon : le jour
ou on la supprime, la branche devient vivante et chaque appel Zabbix prend DEUX slots du meme pool,
l'externe attendant l'interne. Un releve de 16 machines demanderait 128 slots pour 32 : le pool ne
ralentit pas, il se bloque. Ce point etait liste « a mesurer » depuis le debut du module ; il est
**referme** par une refutation ET un piege nomme.

**CE QUI ATTEND L'EXPLOITANT.** La decision n'est pas « comment porter » mais « faut-il un releve de
parc » : les trois options etudiees — ne pas porter, tache de fond, sequentiel borne — **joignent toutes
la production**, puisque le parc est « toutes les machines non archivees ». Reconcevoir change la charge,
pas la cible. Sous la regle en vigueur — `srv-zabbix` n'est jamais jointe, meme en lecture — seule la
premiere tient, et la detection PAR LIGNE de V6 la couvre deja. **Rien n'a ete porte sans arbitrage.**

**Reference du LOT** : inchangee. V8 n'ajoute aucune suite — il n'y a rien a caracteriser
tant que la cible n'est pas tranchee, et une suite qui ne peut pas echouer occuperait la place d'un test.

### v1.37.38 — module `supervision/`, sous-lot V7 : l'editeur distant en lecture

**Symptome.** La page de l'editeur nommait un fichier de configuration, et le portail en lisait un autre.

**Cause racine, MESUREE.** L'ecran affiche `CONFIG_PATHS[plateforme]`, **ecrit en dur cote client**
(`main.js:27-32`) : pour Zabbix, toujours `/etc/zabbix/zabbix_agent2.conf`. Le backend, lui, calcule
`_config_file_path(agent_type)` depuis `supervision_config.agent_type` EN BASE
(`supervision.py:281-287`) : `zabbix-agent` donne `/etc/zabbix/zabbix_agentd.conf`. Des que la
configuration globale designe l'agent historique, la page nomme un fichier et le portail en lit un autre.
Releve avec la fixture posee :

    legacy  : /etc/zabbix/zabbix_agent2.conf | /etc/zabbix/zabbix_agentd.conf   DEUX, dont un faux
    portage : /etc/zabbix/zabbix_agentd.conf                                    celui qui a ete lu

**Fix.** Le chemin vient du SERVEUR, donc de la meme source que celle que le backend lira. C'est un
doublon assume de `_config_file_path`, et LE TEST EN FAIT LA CONDITION : un doublon mesure vaut mieux
qu'une valeur en dur que rien ne confronte. La zone d'edition est en LECTURE SEULE — l'ecriture est V9,
et un champ modifiable dont l'enregistrement n'existe pas laisserait croire qu'on peut editer.

**LA PROPRIETE ASSERTEE EST NEGATIVE, et c'est ce qui la rend utile.** « Le chemin lu est affiche quelque
part » ne suffirait pas : le legacy le fait aussi, dans `#editor-path`. Ce qui le trahit, c'est que son
badge CONTINUE d'annoncer l'autre. La suite collecte donc TOUS les chemins visibles du panneau et assert
qu'aucun ne differe de celui de la fixture.

**LES DEUX COMMANDES DISTANTES ONT ETE LUES MOT POUR MOT AVANT LE MOINDRE CLIC** :
`cat <chemin> || echo 'FILE_NOT_FOUND'` et `LC_ALL=C ls -la <dir>/<fichier>.bak.* || echo 'NONE'`. Rien
n'ecrit, rien ne redemarre. `LC_ALL=C` fixe le format de `ls` — sans lui, la locale du serveur changerait
les colonnes que le backend analyse.

**TROIS EXONERATIONS, troisieme d'affilee dans ce module** : les deux routes portent `@require_api_key` +
`@require_role(2)` + `@require_permission` + `@require_machine_access` ; un fichier absent rend 404 EN
NOMMANT LE CHEMIN, donc le backend distingue « absent » d'« erreur interne » ; et `supervisionFetch` lit
`res.ok`, donc le refus n'est pas avale.

**CE QU'UN EDITEUR MONTRE LEGITIMEMENT — dit ainsi plutot qu'accuse.** Le fichier de fixture porte un
`TLSPSKIdentity` : un `.conf` d'agent PEUT contenir un secret, et un editeur existe pour montrer le
fichier qu'on edite. Le cacher le rendrait inutile. Ce qui se mesure est la SECONDE copie : au plus une
occurrence dans le source servi. Ce que la borne interdit, c'est l'ilot de donnees, l'attribut, le champ
cache.

**TROIS CAS SEPARES, la ou le legacy en mele deux.** Le portage distingue « le fichier n'existe pas »
(404 — une REPONSE, pas une panne), « la lecture a ete refusee (statut N) » et « la lecture n'a pas
abouti ». Le legacy jette `HTTP 404: {"success":false,…}` a l'ecran : lisible pour qui developpe, pas pour
qui exploite.

**`config_loaded` est desormais EXERCEE** : l'ecran du legacy rend `✓ config_loaded`. C'est un ecart
declare, donc l'assertion est reservee au portage — en faire une exigence des deux cotes ferait echouer
une suite qui mesure exactement ce qu'elle doit.

**DEUX DEFAUTS DE MON PROPRE PORTAGE, VUS A L'IMAGE ET CORRIGES.** Le panneau de l'editeur n'est pas dans
le `@foreach` des plateformes : y ecrire `$plateforme` reprenait la DERNIERE valeur laissee par la boucle
— donc Telegraf — et l'editeur annoncait le chemin d'une plateforme qu'on n'avait pas choisie ; Blade
laisse fuiter la variable sans broncher. Et la page disait « Fichier lu » AVANT toute lecture : deux
libelles desormais, « Fichier a lire » jusqu'au premier succes.

**Un huitieme francais en dur, releve au passage** : `saveRemoteConfig` (`main.js:539`) porte
`'Configuration vide'`. Il appartient au chemin de V9.

**`legacy/supervision/` N'EST PAS ARCHIVE** : V8 a V12 y vivent encore.

**Reference du LOT** : `go-page-supervision-editeur` entre avec **12 PASS sur le legacy** et **16 sur le
portage**.

### v1.37.37 — module `supervision/`, sous-lot V6 : la detection de version, premier SSH du module

**Symptome.** Le portage ne pouvait pas relever la version d'un agent. Cote legacy, le verdict de la
detection disparaissait avant que son effet soit constatable, et le bouton partageait sa barre d'outils
avec « Deployer », « Reconfigurer » et « Desinstaller ».

**Cause racine.** `toast()` s'effacé au bout de 4 s (`head.php:172`) alors qu'une session SSH en demande
9 : le message a TOUJOURS disparu au moment ou l'effet devient mesurable. Et la selection par cases a
cocher, partagee entre quatre actions dont trois modifient la machine, met « Tout cocher » — donc
`srv-zabbix`, en PRODUCTION — a un clic des gestes les plus lourds du module.

**Fix.** Le parc est rendu cote serveur avec ses agents releves, et **chaque ligne porte SON bouton de
detection** : il n'y a AUCUNE case a cocher, donc une action de masse est structurellement impossible —
on ne compte pas sur la prudence de qui clique. Le verdict s'ecrit dans la page ET Y RESTE. La detection
passe par la passerelle : c'est le backend qui ouvre le SSH, exception declaree du meme ordre que
K2/K3/K4.

**LA COMMANDE DISTANTE A ETE LUE MOT POUR MOT AVANT LE MOINDRE CLIC**, et c'est ce qui a autorise le
geste : `command -v zabbix_agent2 … && zabbix_agent2 -V | head -1 || … || echo 'NOT_INSTALLED'`. Rien
n'installe, rien n'ecrit a distance, rien ne redemarre.

**DEUX EXONERATIONS, ET UNE CORRECTION DE SUPPOSITION.** La route porte bien `@require_api_key` +
`@require_role(2)` (« Patch A01 ») + `@require_permission` + `@require_machine_access` — contrairement aux
quatre routes de profils (E-77), celles-ci ont recu le correctif. Et la detection ecrit
**`supervision_agents` SEULEMENT** : `machines.zabbix_agent_version` existe, la page la lit, personne ne
l'ecrit ici.

**LA PROPRIETE CENTRALE EST EXERCEE** : une detection qui ne trouve rien SUPPRIME l'agent enregistre
(`_remove_agent`). Fixture posee sur la machine de DEV, clic, ZERO ligne apres — l'inventaire suit donc
l'etat reel des machines, y compris quand un agent a ete desinstalle hors du portail.

**AUCUN APPEL DANGEREUX NE PART, et c'est mesure** : la suite collecte les requetes emises et assert
qu'aucune ne contient `deploy`, `uninstall` ni `reconfigure`. Une seule part.

**LE PORTAGE FERME CHEZ LUI LE TROU DECLARE EN E-72.** `RoutesBackend::ADMIN_SEULEMENT` etait le releve
fidele de `ADMIN_ONLY_PREFIXES` — il recopiait donc l'absence de `/supervision/`. La page exige `role:2`
des deux cotes : personne de legitime ne perd un acces, et un role 1 porteur de
`can_manage_supervision` cesse de pouvoir appeler `/api/gateway/supervision/profiles`, que le backend ne
garde par aucun `@require_role`. Le legacy garde son trou, et il reste declare.

**Un client qui ne lit pas `resp.status` avale tous les refus** : le portage lit le statut D'ABORD, et un
403 ne se confond pas avec « aucun agent installe ».

**DEUX MESURES FAUSSES DE LA SUITE, CORRIGEES.** La premiere lisait le DOM apres l'attente et declarait
« verdict non enonce » un verdict parfaitement affiche : un `MutationObserver` installe AVANT le clic
mesure desormais « le verdict a ete enonce ». La seconde lisait le NOEUD AJOUTE : `toast()` insere un
`<div>` puis y met deux `<span>`, si bien que l'observateur voyait passer l'ICONE seule (« ℹ ») avant que
le texte existe — et un motif assez lache faisait passer l'assertion pour une raison qui n'etait pas la
bonne. Elle relit le porte-messages entier, le motif exige le verdict, et LE FRAGMENT RETENU EST IMPRIME.

**Un jeton non substitue, evite de justesse** : les libelles du script partent avec TOUS leurs jetons
remplaces, y compris `:nom`. `__('x')` sans son argument laisse `:nom` en clair a l'ecran — le module
`ssh/` l'a paye (« 3 :count serveur(s) disponible(s) »), et aucun controle d'i18n ne le voit.

**Un texte devenu faux, vu A L'IMAGE** : le bloc « Pas encore porte » annoncait que « le tableau du parc
arrive avec les sous-lots suivants » alors que V6 vient de le porter. Il ne parle plus que de ce qui
reste.

**DEUX DEFAUTS DECLARES, NON CORRIGES — c'est du backend** : une LECTURE passe par `execute_as_root`
(relever un numero de version n'exige aucun privilege), et `agent_type` est calcule, renvoye au client,
puis JETE — aucune colonne ne le recoit.

**`legacy/supervision/` N'EST PAS ARCHIVE** : V7 a V12 y vivent encore.

**Reference du LOT** : `go-page-supervision-version` entre avec **12 PASS sur le legacy** et **14 sur le
portage**.

### v1.37.36 — module `supervision/`, sous-lot V5 : le CRUD des profils

**Symptome.** Le catalogue de profils affichait « Editer », « Supprimer » et « Nouveau profil » en
francais meme en anglais, ouvrait DEUX boites natives, et portait dix attributs `onclick` dont le plus
long faisait 671 caracteres.

**Cause racine.** `profiles.js` ecrit SEPT chaines francaises EN DUR — `Editer` (`:43`), `Supprimer`
(`:45`), `Nouveau profil` (`:60`), `Editer profil : ` (`:79`), `Le nom est obligatoire.` (`:96`), le texte
entier du `confirm` de suppression (`:111`), `Erreur reseau` (`:105`, `:118`). Aucun controle d'i18n ne
les voit : ils cherchent des identifiants `module.cle` et la parite des JEUX de cles, pas du francais
parfaitement lisible. Et le `confirm()` de suppression n'est **ni `confirm_deploy` ni
`confirm_uninstall`** : c'est une TROISIEME confirmation native, absente des douze cles cassees — pour
cause, elle n'utilise meme pas le catalogue.

**Fix.** Creation, modification et suppression en base, derriere la garde de la page. Zero boite native :
la suppression ouvre un panneau de decision SOUS SA LIGNE, qui **chiffre son cout** avant le geste.
« Modifier » est une ADRESSE — `?profil=<id>` — et le serveur pre-remplit le formulaire : l'enregistrement
n'est jamais dans la page deux fois, ni dans un attribut de gestionnaire, et il n'y a aucun gabarit
JavaScript. Tous les libelles viennent du meme catalogue FR/EN que la page.

**DEUX MESURES QUI DEDOUANENT LE CODE EXISTANT, et il faut le dire aussi clairement qu'une accusation.**
`upsert_profile` porte bien `WHERE id=%s AND platform=%s` (`supervision.py:1780`) : le defaut mesure en V4
n'est PAS generalise. Et la contrainte d'unicite EXISTE — `UNIQUE KEY uk_platform_name (platform, name)`,
lue au `SHOW CREATE TABLE` : le message d'erreur du backend doute de lui-meme (« nom deja pris ? ») mais
il a raison sur le fond. Le point d'interrogation etait une hesitation de redaction, pas un trou.

**TOUT EST MESURE AU CLIC, PAS PAR APPEL DE FONCTION — correction de methode.** La premiere version de la
suite declenchait `saveProfile()`, `editProfile()`, `deleteProfile()`. Cela prouve que la fonction marche ;
cela ne prouve pas que LE BOUTON L'ATTEINT. Un bouton non cable, cable au mauvais gestionnaire, ou
recouvert par un autre element est INVISIBLE a un appel de fonction — et cette famille a deja coute cher
ici : un bouton deplace faisait cliquer « Refuser et se deconnecter » au lieu d'« Accepter ». La suite
part du NOM AFFICHE dans le tableau, descend au bouton de SA ligne, et clique.

**LA CASCADE EST EXERCEE, PAS DEDUITE.** `machine_supervision_profile` est vide : la consequence la plus
lourde d'une suppression ne se mesurerait pas sans fixture. La suite pose une assignation sur la machine 2
(DEV, seule cible mutante autorisee), supprime, et constate ZERO assignation orpheline.

**L'ASSIGNATION N'EST PAS PORTEE, et c'est une decision, pas un oubli.** Son unique point d'entree est le
dropdown du tableau de deploiement, non porte. Cote legacy on choisit UN PROFIL POUR UNE MACHINE ;
assigner depuis le catalogue inverserait la relation, et comme la cle primaire est
`(machine_id, platform)`, une machine ne porte qu'un profil par plateforme : l'inversion RETIRERAIT la
machine de son profil precedent. Ce serait concevoir, pas migrer. La page dit ou se fait l'assignation.

**Deux mesures fausses de la suite, corrigees.** Le refus du doublon etait declare « non enonce » alors
qu'il l'etait : le legacy le passe a `alert()`, HORS du document, donc invisible a `innerText`. Et le geste
de modification tenait en un seul `page.evaluate` : cote portage « Modifier » NAVIGUE, et une navigation
detruit le contexte d'execution. Le geste se fait desormais en trois temps.

**Un defaut d'affichage vu A L'IMAGE** : le titre du formulaire se collait au dernier paragraphe du
catalogue. Separateur ajoute.

**CE QUI RESTE AU BACKEND** : les quatre routes de profils sans `@require_role` et l'absence de
`/supervision/` dans `$ADMIN_ONLY_PREFIXES`. Le portage ecrit en base derriere la garde de la page, donc
CHEZ LUI la permission garde enfin la requete.

**`legacy/supervision/` N'EST PAS ARCHIVE** : V6 a V12 y vivent encore.

**Reference du LOT** : `go-page-supervision-profils-crud` entre avec **16 PASS sur le legacy** et **19 sur
le portage**.

### v1.37.35 — module `supervision/`, sous-lot V4 : l'ecriture de la configuration globale

**Symptome.** Enregistrer la configuration Zabbix pouvait ecrire dans la ligne CENTREON : l'exploitant
voyait un succes, sa configuration Zabbix n'avait pas bouge, et celle de Centreon etait corrompue.

**Cause racine, MESUREE et plus seulement lue.** `backend/routes/supervision.py:508` fait
`SELECT id, tls_psk_value FROM supervision_config ORDER BY id DESC LIMIT 1` — **sans `WHERE platform`** —
puis `UPDATE ... WHERE id = %s`. Avec une ligne `centreon` plus recente qu'une ligne `zabbix`, la suite a
releve en base : ligne zabbix INCHANGEE, et la valeur tapee dans le formulaire Zabbix ecrite dans la
ligne centreon. Le meme effet se voit sur la colonne du secret — le nouveau blob `sodium:` atterrit dans
la ligne centreon.

**Fix.** Le portage ecrit en base avec `WHERE platform = ?` (decision S3/S4) et n'herite donc pas du
defaut. L'enregistrement est une SOUMISSION DE FORMULAIRE, pas un appel client : la propriete « cette
page n'appelle personne », assertee par les trois suites du module, reste vraie.

**LA COMPATIBILITE DU CHIFFREMENT A ETE MESUREE, PAS SUPPOSEE — et c'est ce qui a permis d'ecrire en
base.** La consigne etait : si l'interoperabilite PHP vers Python n'est pas demontrable, faire passer
l'ecriture du PSK par la passerelle. Aller-retour execute : un blob produit depuis le conteneur `laravel`
(HKDF-SHA256 `rootwarden-aes` + `secretbox`, prefixe `sodium:`) est dechiffre par
`Encryption().decrypt_password()` dans `rootwarden_python` et rend la chaine d'origine.
`App\Support\SecretSupervision` porte cette mesure en commentaire. L'etiquette HKDF n'est PAS celle du
TOTP (`rootwarden-totp`) : les usages sont separes des deux cotes. Et il n'y a **deliberement aucune
methode de dechiffrement** dans cette classe — V3 a pris soin de ne pas charger le PSK, un `dechiffre()`
l'offrirait a la premiere vue distraite.

**UNE DOUZIEME CLE CASSEE, non repertoriee, atteignable seulement ici.** `main.js:294` appelle
`__('supervision.zabbix_server')` — avec son prefixe de module — alors que `__()` prefixe DEJA par `js.`
et cherche dans `js.php`. Mesure faite en soumettant le formulaire avec un serveur vide : l'ecran rend
`supervision.zabbix_server` suivi du mot « requis », ecrit en dur en francais, et il reste francais quand
la page est demandee en anglais. `config_saved` est confirmee au passage.

**Le secret non retape est preserve des deux cotes, mais pas pour la meme raison.** Le legacy y arrive
parce que son backend reconnait son propre masque (`if psk_value == '********'`). Le portage n'a pas
besoin de cette gymnastique : son champ part TOUJOURS vide, et vide veut dire « ne change rien ». Le
legacy doit deviner l'intention, le portage la lit.

**Un PSK reellement saisi arrive chiffre** — mesure sur TOUTE la table et non sur la ligne visee : sur le
legacy l'ecriture atterrit dans la ligne d'a cote, donc une assertion visant la seule ligne zabbix
n'aurait rien vu.

**Une mesure fausse de la suite, corrigee.** Elle declarait le refus « non enonce » alors qu'il l'etait :
elle ne lisait que le bloc de configuration, or le legacy passe ce message a `toast()`, qui ecrit dans
`#toast-container`. Chercher dans le seul bloc concerne est la bonne regle quand on cherche CE QUE LE
BLOC AFFICHE ; ici on cherchait un MESSAGE, et c'est la cible qui decide ou elle le met.

**Un defaut de mon propre portage, vu A L'IMAGE et corrige.** La premiere version du formulaire rendait
`tls_connect` et `tls_accept` en champs de TEXTE LIBRE par-dessus des colonnes
`enum('unencrypted','psk','cert')` : une valeur hors liste aurait produit une erreur d'ecriture la ou
l'utilisateur attendait un enregistrement. Ce sont desormais des listes fermees, **revalidees cote
serveur** — un `<select>` empeche la faute a l'ecran, il n'empeche rien dans une requete forgee.

**Ce que le portage corrige au passage** : `savePlatformConfig()` (`main.js:186`) force
`hostname_pattern` et `extra_config` pour les trois plateformes non-Zabbix, quelles que soient les
valeurs a l'ecran — deux champs que l'utilisateur remplit et que l'enregistrement jette. Ici, ce qui est
affiche est ce qui est ecrit.

**Non porte, et dit tel quel** : l'ecriture du `telegraf_output_token`, qui vit dans une route a part du
backend. **Non corrige — c'est du backend** : le `WHERE platform` manquant de `:508` reste en place pour
tout appelant du legacy.

**`legacy/supervision/` N'EST PAS ARCHIVE** : V5 a V12 y vivent encore.

**Reference du LOT** : `go-page-supervision-config-ecriture` entre avec **11 PASS sur le legacy** et
**16 sur le portage**.

### v1.37.34 — module `supervision/`, sous-lot V3 : la configuration globale, en lecture

**Symptome.** L'onglet « Configuration globale » du portage n'affichait rien de la configuration reelle.
Et cote legacy, « la » configuration globale d'une plateforme n'est pas ce qu'elle annonce.

**Cause racine, mesuree.** `supervision_config` ne porte **aucune contrainte d'unicite** sur `platform` —
sa cle primaire est `id` seul. Or `_get_global_config()` (`supervision.py:132`) et la page legacy lisent
tous deux `ORDER BY id DESC LIMIT 1` : « la » configuration globale est en realite **la plus recemment
enregistree**, et rien n'empeche d'en accumuler. Ce n'est pas la meme chose.

**Fix.** Les quatre configurations sont peintes COTE SERVEUR, une par plateforme, en lecture seule : le
script n'en montre qu'une, donc changer de plateforme emet **zero appel**. Le legacy, lui, rend Zabbix
cote serveur et les TROIS AUTRES par un `GET /supervision/config/<plateforme>` declenche au changement —
deux chemins pour une meme donnee, et **3 requetes** mesurees a la bascule vers Centreon. La page NOMME
la regle de la ligne la plus recente plutot que de laisser croire a un enregistrement unique.

**LES DEUX SECRETS NE SONT MEME PAS LUS.** `configurationParPlateforme()` ne selectionne ni
`tls_psk_value` ni `telegraf_output_token` : elle rend deux BOOLEENS de presence. Masquer une valeur deja
chargee la laisse en memoire, dans la vue, et a portee du premier gabarit qui l'affichera par megarde ;
ne pas la lire ferme la question.

**Le secret ne fuyait PAS cote legacy — mesure, et il faut le dire tel quel.** La suspicion portee par le
suivi de chantier etait que `tls_psk_value` pouvait sortir en clair. Faux : le legacy rend `********`
dans son `<input type="password">`, et la valeur reelle posee en fixture n'apparait **nulle part dans le
source servi** — recherche faite dans le HTML complet, pas dans le texte visible, precisement parce qu'un
attribut peut porter autre chose que ce que l'oeil lit. Le backend est correct lui aussi : il refuse
d'ecrire `'********'` par-dessus le vrai PSK.

**LE DEFAUT QUE V4 DEVRA CORRIGER, maintenant localise.** `supervision.py:508` fait
`SELECT id, tls_psk_value FROM supervision_config ORDER BY id DESC LIMIT 1` — **sans filtre de
plateforme** — puis `UPDATE ... WHERE id = %s`. Enregistrer le formulaire Zabbix peut donc ecraser une
ligne **Centreon** si celle-ci est la plus recente. Localise par lecture, non exerce : V3 est en lecture.

**Un defaut latent, dit avec ses deux moities.** `GET /supervision/config` (`supervision.py:455`) masque
`tls_psk_value` mais **pas** `telegraf_output_token`, alors que sa voisine par plateforme masque les
deux. En pratique cette route ne lit que la ligne `zabbix`, ou la colonne du jeton est normalement NULL :
la fuite n'est pas vive, elle est a un enregistrement de l'etre. Seul appelant :
`legacy/adm/health_check.php`. Non corrige — c'est du backend.

**La fixture, et pourquoi elle est sure.** `supervision_config` est **VIDE** : un sous-lot de lecture sur
une table vide ne mesurerait qu'un ecran d'absence. La suite pose donc deux lignes Zabbix et une
Centreon, nettoie A L'ENTREE et dans un `finally`, et ANNONCE l'etat restaure. Verifie avant de l'ecrire :
`backend/scheduler.py` ne lit JAMAIS cette table — seuls un deploiement ou une reconfiguration la lisent,
et aucun des deux ne part sans un clic.

**Deux defauts d'affichage vus A L'IMAGE.** `.rw-tableau` ne stylait que les `th` du `thead` : un
`th scope="row"` retombait sur le defaut du navigateur — CENTRE — et sur une colonne de 690 px
l'etiquette se retrouvait au milieu du vide, a l'autre bout de la valeur qu'elle nomme. Puis, le
correctif applique, **a 390 px l'etiquette en `nowrap` prenait 215 des 350 px disponibles et repoussait
la VALEUR hors du cadre** : on gardait le mot et on perdait la donnee. Elle se replie desormais sous
700 px.

**Non affiche deliberement** : `updated_at` et `updated_by`. `updated_at` est ecrit par MySQL, donc dans
le fuseau du conteneur de base, et l'afficher ferait entrer dans cette page le decalage declare en
E-73. V3 montre la configuration, pas sa piste d'audit.

**`legacy/supervision/` N'EST PAS ARCHIVE** : V4 a V12 y vivent encore.

**Reference du LOT** : `go-page-supervision-config` entre avec **15 PASS sur le legacy** et **17 sur le
portage**.

### v1.37.33 — module `supervision/`, sous-lot V2 : le catalogue de profils, en lecture

**Symptome.** Le catalogue de profils affichait « Editer » et « Supprimer » en francais meme en anglais,
portait le profil ENTIER dans un attribut `onclick` de chaque ligne, et rejouait quatre requetes backend
a chaque changement de plateforme — dont deux identiques.

**Cause racine.** Trois causes distinctes, plus une decouverte par la mesure.
`profiles.js:43-46` ecrit ses deux libelles d'action EN DUR dans le HTML qu'il construit : ils echappent
donc a toute parite FR/EN, et aucun controle d'i18n ne les voit — ils cherchent des identifiants
`module.cle`, pas du francais. La meme ligne fait
`editProfile(${JSON.stringify(p)...})` : le document porte, dans un attribut de gestionnaire
d'evenement, toutes les colonnes de la ligne, `notes` comprise (652 et 671 caracteres mesures). Et la
route backend fait `SELECT *`, donc le navigateur recoit `notes`, `tls_connect`, `tls_accept`,
`created_at` et `updated_at` pour un tableau de cinq colonnes.
**Le quatrieme defaut n'etait pas repertorie** : changer de plateforme emet `config/<p>`,
`profiles?platform=<p>` **deux fois**, et `profiles/assignments?platform=<p>` — la meme requete jouee par
le `onchange` de la page ET par le crochet `DOMContentLoaded` de `profiles.js`.

**Fix.** Les quatre catalogues sont peints COTE SERVEUR, le script n'en montre qu'un : ouvrir l'onglet
et changer de plateforme emettent **zero appel**. C'est ce que V1 a rendu possible. Les colonnes sont
NOMMEES, jamais `SELECT *` : la page ne recoit que ce qu'elle affiche. Aucun gestionnaire en attribut.
Tous les libelles viennent du meme catalogue FR/EN que la page.

**LE SCHEMA A ETE MESURE AVANT D'ECRIRE LA REQUETE, et il a corrige deux suppositions.** La table
s'appelle `supervision_metadata_profiles`, pas `supervision_profiles`. Et le « nombre de machines » ne
vient d'aucune colonne de `machines` : il vient de `machine_supervision_profile`, cle primaire
`(machine_id, platform)` — une machine porte donc UN profil PAR PLATEFORME, et le compte se filtre par
plateforme. Deduire ces deux points de l'affichage aurait produit une requete fausse qui SEMBLAIT juste
sur ce parc. Verifie au passage, comme E-72 le demandait : `fk_msp_profile` porte bien un
`ON DELETE CASCADE`, donc la consequence de l'absence de `@require_role` sur
`DELETE /supervision/profiles/<id>` est confirmee.

**Une divergence assumee, et c'est une amelioration.** Le legacy ecrit `-` dans les colonnes Serveur et
Mandataire quand la valeur est NULL. `-` n'apprend rien ; NULL veut dire « la configuration globale
s'applique », et c'est ce que le portage ecrit. La suite ne cherche donc pas `-` : elle asserte
qu'aucune valeur absente n'est rendue par un MOT DE CODE (`null`, `undefined`, `NaN`,
`[object Object]`).

**Un defaut de la suite, corrige entre la mesure du legacy et le portage.** Elle comptait les lignes du
tableau SANS regarder si elles etaient visibles. Sur le legacy cela passait — il vide son `tbody` a
chaque bascule — mais un portage qui peint les quatre plateformes et en cache trois aurait fait mesurer
le catalogue de Zabbix en croyant mesurer celui de Centreon. `textContent` mesure la presence, pas la
visibilite. Corrigee puis re-mesuree sur le legacy : 14 PASS, inchange.

**Deux defauts d'affichage vus A L'IMAGE** : la description d'un profil, rendue en ligne, etirait la
colonne du nom a 780 px sur un ecran de 1920 et poussait les quatre autres a droite
(`.rw-cellule-note`) ; et l'astuce sur `{machine.name}` s'affichait meme sur une plateforme sans aucun
profil, ou elle decrivait un contenu absent.

**CE QUI RESTE AU BACKEND, et attend une decision** : les quatre routes de profils sans `@require_role`,
l'absence de `/supervision/` dans `$ADMIN_ONLY_PREFIXES`, le `SELECT *` de `list_profiles` et la requete
jouee en double. Aucune ligne de backend modifiee.

**`legacy/supervision/` N'EST PAS ARCHIVE** : V3 a V12 y vivent encore.

**Reference du LOT** : `go-page-supervision-profils` entre avec **14 PASS sur le legacy** et **18 sur le
portage**.

### v1.37.32 — module `supervision/`, sous-lot V1 : la page, ses quatre onglets, et une cle qui quitte l'ecran

**Symptome.** La page `supervision/` affichait `editor_select_server` en clair a ses exploitants, et
rechargeait son catalogue de profils par deux requetes backend a chaque bascule d'onglet.

**Cause racine.** Deux causes distinctes.

`head.php:76-78` charge `getJsTranslations('js.')` puis rend `_i18n['js.' + cle] || _i18n[cle] || cle` :
une cle absente est **retournee telle quelle**. Comme c'est une chaine NON VIDE, l'idiome
`__('x') || 'repli'` **ne declenche jamais son repli** — la panne est silencieuse. Onze cles du module
sont dans ce cas : presentes dans `supervision.php` en FR et en EN, absentes de `js.php`. Le portage
n'avait donc pas a traduire, il avait a **deplacer**.

Et la page peint son contenu depuis le client : deux `GET` des le chargement
(`/supervision/profiles`, `/supervision/profiles/assignments`), rejoues a chaque changement d'onglet.

**Fix.** Route `/supervision`, garde **reprise telle quelle** du legacy : `role:2` +
`perm:can_manage_supervision`. **Aucun ecart a declarer**, pour une fois : l'en-tete du fichier legacy
annonce « admin (2) + superadmin (3) + can_manage_supervision » et son code applique exactement cela.
La page est peinte cote serveur (decision S3/S4) et son script **ne parle a personne** : ni au
chargement, ni au changement d'onglet, ni au changement de plateforme. Les libelles du script partent du
MEME catalogue que la page, en donnees : le defaut d'i18n ne peut pas se reformer.

Ce que V1 ne porte pas encore le DIT — etat vide nomme, explication, et lien vers l'ancien portail avec
le marqueur des entrees non portees.

**LE DECOUPAGE ETAIT OPTIMISTE, et c'est la mesure qui l'a dit.** L'inventaire annoncait « V1 | aucune
route ». Il y en a **deux**, en lecture, des le chargement : la frontiere V1/V2 n'existe pas cote legacy.

**Neuf cles a deplacer, DEUX a remplacer.** `confirm_deploy` et `confirm_uninstall` sont consommees dans
des `confirm()` NATIFS, que la convention du portage interdit : elles seront remplacees par un panneau
de decision, en V11 et V12.

**Trois defauts vus A L'IMAGE, qu'aucune assertion DOM ne voit — corriges dans le socle :**
- `.rw-vide p { margin: 0 }` faisait recouvrir la derniere ligne d'un paragraphe par la hauteur de ligne
  du bouton place dessous, qui se lisait barree. L'action a desormais son bloc (`.rw-vide__action`) ;
- `.rw-etiquette-champ` est en `flex: 1` : sur 1920 px le menu des plateformes traversait la moitie de la
  page. Borner le `<select>` seul ne suffisait pas — l'enveloppe gardait la place et renvoyait le bouton
  voisin a l'autre bout de la carte. C'est l'enveloppe qui se borne (`--borne`), **et la regle doit rester
  APRES celle qu'elle surcharge** : a specificite egale, c'est l'ordre du fichier qui tranche, et la
  premiere version, ecrite 380 lignes plus haut, n'avait aucun effet ;
- un `<a class="rw-bouton">` est un element EN LIGNE : a 390 px son libelle passait a la ligne mais sa
  boite sortait du cadre par la droite, remplissage compris. `display: inline-block` la replie. **Ce
  correctif vaut pour toutes les pages** qui portent un bouton-lien.

**Un defaut de ma suite, corrige avant de l'inscrire.** L'assertion « aucune cle ne s'affiche en
identifiant » reussissait aussi pour un garde qui n'aurait RIEN affiche : ne rien dire, c'est ne dire
aucun identifiant. La suite mesure donc d'abord que le refus est **enonce a l'ecran**, en comparant au
texte que chaque cible declare comme son refus — cote portage lu dans l'ilot de donnees de la page, pour
ne pas recopier un catalogue de traduction dans un test.

**CE QUI RESTE AU BACKEND, et attend une decision.** Les quatre routes de profils (`1734`, `1760`,
`1801`, `1817`) portent `@require_api_key` + `@require_permission` et **aucun `@require_role`** ; la
cinquieme porte bien `@require_role(2)` — le correctif a ete applique a une route et pas a ses quatre
voisines. Et `/supervision/` est absent des 25 prefixes de `$ADMIN_ONLY_PREFIXES` du proxy legacy.

**`legacy/supervision/` N'EST PAS ARCHIVE** : V2 a V12 y vivent encore.

**Un defaut trouve PAR ce LOT, dans un autre module.** `go-page-cve-planification` est tombee a
15/16 sur le legacy a 03:07 : `next_run` est calcule par `croniter` dans `rootwarden_python`, qui tourne
en **UTC**, et stocke sans fuseau ; l'hote est en **CEST**. Le scheduler, dans le meme conteneur, compare
avec la meme horloge et **ne declenche donc rien trop tot** — mais tout lecteur qui compare cette valeur a
l'heure locale se trompe de deux heures, affichage des deux portails compris. **Non corrige** : le
corriger demande de choisir entre poser le fuseau, convertir a l'affichage ou aligner les horloges, sur
plusieurs modules. L'assertion, elle, est corrigee : elle comparait la valeur a l'horloge de l'HOTE, donc
elle mesurait la concordance des horloges et non la propriete, et echouait chaque nuit entre 03:00 et
05:00. Elle compare desormais a l'heure du conteneur qui a calcule la valeur, et **constate l'ecart en
clair** pour que le defaut reste visible. Voir `PARITE.md` E-73.

**Reference du LOT** : `go-page-supervision-onglets` entre avec **11 PASS sur le legacy** et **14 sur le
portage** (base rouge relevee avant portage : 6 PASS / 7 FAIL). `go-socle-navigation` passe de **44 a
46** : l'entree « Supervision » devient un lien interne, verifie pour chacun des deux comptes qui la
voient.

### v1.37.31 — module `ssh/`, sous-lot K3 : la lecture du journal de deploiement

**Symptome.** Le portage ne pouvait pas lire le journal du dernier deploiement. Cote legacy, trois
defauts s'y cachaient — dont une XSS STOCKEE — et un quatrieme non repertorie.

**Cause racine.** Le client ouvre le flux par un `EventSource`, qui **ne permet pas de lire un statut
HTTP** ; il compare le marqueur de fin `[Fin du flux de logs]` LITTERALEMENT ; et il fait
`logWindow.innerHTML += event.data` en pretendant « pas de donnees utilisateur non maitrisees », alors
que `configure_servers.py:112` injecte `machines.name` dans CHAQUE ligne sans validation.

**Correctif.**
- **Le marqueur de fin est pose en CONSTANTE dans le controleur, hors des fichiers de langue** : c'est
  un jeton de protocole, emis en dur par le backend. Le traduire ferait que le flux ne se termine
  JAMAIS — le bouton resterait fige et seul le chemin d'erreur le rendrait.
- **Le flux est lu par `fetch`**, dont le statut est lisible : un 403 est ANNONCE au lieu de tomber dans
  un `onerror` muet. `GET /logs` etant `@require_role(2)` et `POST /deploy` n'ayant ni role ni
  permission, un role 1 pouvait declencher le deploiement et conclure que tout s'etait bien passe.
- **Chaque ligne est posee par `textContent`**, jamais par `innerHTML`.
- **Un flux qui s'arrete sans son marqueur le DIT** au lieu de passer pour un succes.
- **Un seul chemin de sortie remet le bouton** : le legacy en avait deux, avec des libelles differents
  (« Deployer les cles » au succes, « Lancer le Deploiement » a l'erreur).

**Tests.** `tests/e2e/go-page-ssh-flux.mjs` — **8 PASS sur le legacy, 10 sur le portage**. Base rouge :
6 / 4. L'XSS est DEMONTREE PAR LA MESURE : la suite pose dans le journal une balise BENIGNE et compte les
elements correspondants — **1 cote legacy** (elle est devenue un noeud du document), **0 cote portage**,
qui affiche la chaine litterale. La propriete mesuree est « est-ce interprete », pas « peut-on
executer » : une charge executable n'aurait rien prouve de plus.
La fixture ecrit dans `deployment.log` via le conteneur et **le remet a zero dans un `finally`** —
verifie apres chaque execution (`journal restaure : 0 octet(s)`). Le fichier etait vide au depart, il est
ignore par git, et l'application le tronque de toute facon a chaque deploiement.
LOT complet rejoue. Captures regardees a 1400 et 390 px.

**Non mesurable, dit tel quel** : ce que le legacy fait du 403 sur SA page — un role 1 n'a pas
`can_deploy_keys`, donc il ne peut pas ouvrir `/ssh/` et n'atteint jamais le client. La route, elle,
refuse bien (verifie). Meme limite que D-5.

**Notes d'exploitation.** `legacy/ssh/` n'est PAS archive : K4 (le deploiement) y vit encore. La fuite
d'un mot de passe genere dans `deployment.log`, diffusee verbatim par ce flux, reste ouverte — elle
touche le backend, donc decision de l'exploitant. Aucune variable d'environnement, aucune migration.

---

### v1.37.30 — module `ssh/`, sous-lot K2 : le constat avant deploiement

**Symptome.** Cote legacy, il n'existait **aucun moyen de verifier les prerequis sans risquer de
deployer** : `preflight_check` et `deploy` vivent dans la MEME chaine `fetch`, et le deploiement part des
que le constat passe, sans reprise de main. Or deployer veut dire `apt-get install sudo`, `useradd`,
ecrasement d'`authorized_keys` et REVOCATION de cles, en root, sur chaque machine cochee.

**Cause racine.** `ssh/js/main.js:110-200` enchaine les deux appels dans la meme promesse, et
`.then(r => r.json())` ne regarde jamais `resp.ok` : un refus non-JSON tombe dans un `.catch` qui affiche
« Erreur pre-flight » sans jamais dire lequel.

**Correctif.**
- Bouton **« Verifier les prerequis »** dedie, qui n'appelle que `preflight_check` et n'enchaine RIEN.
- **Le statut est lu d'abord**, et le message du corps est affiche s'il en porte un.
- Le rapport est rendu **machine par machine**, en grille, au lieu d'une fenetre de texte monospace
  unique ou la ligne la plus importante du module se perdait.
- **Les acces qui seront REVOQUES sont distingues en rouge** : ce n'est pas une information de meme
  poids qu'une version d'OS ou un espace disque.
- `users_with_keys` a zero est ENONCE (« aucun compte actif ne porte de cle SSH — un deploiement ne
  deploierait rien ») plutot que rendu par un « 0 » au milieu d'un journal.
- Le prerequis manquant mene a l'endroit ou on le corrige, par un lien inter-portails marque `↗` —
  `adm/` n'etant pas porte — au lieu d'un `/adm/server_users.php` ecrit en dur.

**Non mesurable, et dit tel quel** : `preflight_check` n'a AUCUNE garde de role (seulement
`@require_api_key` + `@threaded_route`) alors qu'elle enumere les comptes UNIX distants, ce que
`/scan_server_users` reserve au role 2 ET place dans `ADMIN_ONLY_PREFIXES`. Aucun compte de role 1 ne
porte a la fois `can_deploy_keys` et un acces machine, donc le contournement n'est pas exercable.
Le fermer demande de MODIFIER LE BACKEND : decision de l'exploitant.

**Tests.** `tests/e2e/go-page-ssh-preflight.mjs` — **10 PASS sur le legacy, 15 sur le portage**. Base
rouge : 10 / 1. **AUCUNE session SSH n'est ouverte** : les deux portes bloquantes du preflight sont
atteintes par le parc reel (machine 2 jamais scannee, machine 3 avec un utilisateur en attente de
classification), et la machine 1 — la production — n'est jamais visee. Les preconditions sont verifiees
AVANT chaque sonde, qui est sautee si l'etat a change. Le bouton de deploiement n'est jamais clique.
LOT complet rejoue. Captures regardees a 1400 et 390 px — elles ont sorti un defaut qu'aucune assertion
ne voyait : les blocs du rapport portaient `.rw-carte`, plafonnee a 420 px, et restaient etroits sur une
page de 1400.

**Deux defauts de mes propres tests, catalogues et payes quand meme.** La precondition de la premiere
porte etait lue par un `COALESCE(..., '')` : `litEnBase` filtrant les chaines vides, la valeur arrivait a
`undefined` et la suite SAUTAIT la porte qu'elle venait mesurer — une sentinelle explicite regle cela. Et
la sonde relevant `users_with_keys` visait la machine 2 sans reprendre le garde de precondition applique
juste au-dessus ; elle vise desormais un identifiant valide mais inexistant.

**Notes d'exploitation.** `legacy/ssh/` n'est PAS archive : K3 (flux SSE) et K4 (deploiement) y vivent
encore. Aucune variable d'environnement, aucune migration ajoutee.

---

### v1.37.29 — module `ssh/` (« Cles SSH »), sous-lot K1 : la page nue

**Symptome.** L'entree « Cles SSH » — la PREMIERE du menu — renvoyait encore a l'ancien portail. Cote
legacy, trois defauts sur cette page : l'ecran affichait « 3 **:count** serveur(s) disponible(s) », le
bouton de deploiement etait actif sans qu'aucune machine ne soit cochee, et la liste des tags de filtrage
n'etait PAS cloisonnee.

**Cause racine.** Le gabarit ecrit `count($machines)` PUIS `t('ssh.servers_available')`, dont la valeur
est « :count serveur(s) disponible(s) » : le jeton n'est jamais substitue. Aucun controle ne le voyait —
`go-socle-i18n` cherche des identifiants `module.cle`, pas des jetons `:xxx`. Et `index.php:61` fait un
`SELECT DISTINCT tag FROM machine_tags` sans filtre, deux lignes au-dessus d'un `$allEnvs` qui, lui,
derive de la liste deja cloisonnee.

**Correctif.**
- Route `/cles-ssh`, garde **REPRISE TELLE QUELLE** du legacy : `role:1` + `perm:can_deploy_keys`.
- `App\Services\ParcSsh` derive les DEUX listes de filtrage du meme ensemble de machines visibles ; le
  filtre de cycle de vie est pose UNE FOIS, avant la branche de role (lecon E-46).
- Le compteur est substitue ; la suite mesure desormais TOUT jeton `:mot` visible a l'ecran.
- Le bouton de deploiement **nait desactive** et n'ouvre qu'une DECISION, qui NOMME les machines
  cochees et enonce ce qu'un deploiement engage : sur chaque serveur et en root, installation de `sudo`,
  creation de comptes, ECRASEMENT d'`authorized_keys`, politique sudoers, et REVOCATION des cles de tout
  compte ayant perdu son habilitation.
- **Une machine masquee par un filtre est decochee** : on ne deploie pas sur ce qu'on ne voit plus. Le
  legacy laissait la coche en place.
- K4 n'etant pas porte, l'action principale du panneau est un lien vers l'ancien portail, avec le
  marqueur des entrees non portees. Un panneau dont la seule issue serait « Annuler » ne serait pas une
  decision.
- Entree `Navigation` « Cles SSH » basculee sur `route` : une fleche de moins dans le menu.

**Non mesurable, et dit tel quel** : aucun compte de role 1 ne porte `can_deploy_keys`, donc aucun role 1
ne peut ouvrir cette page et la fuite du vocabulaire de tags n'est pas exercable. Elle est corrigee
quand meme — corriger un defaut non exercable reste correct, pretendre l'avoir mesure ne l'est pas.

**Ecart declare, non tranche** : l'en-tete de `ssh/index.php` annonce « Acces refuse pour les
utilisateurs standards (role_id = 1) », ce que son `checkAuth` n'applique pas. Consequence plus lourde
qu'E-36 : `POST /deploy` n'a NI role NI permission, donc un role 1 habilite pourrait declencher le
deploiement, et `GET /logs` etant `@require_role(2)` il ne pourrait pas en lire le resultat. Restreindre
serait un CHANGEMENT DE DROITS — a trancher avec D-1.

**Tests.** `tests/e2e/go-page-ssh-parc.mjs` — **11 PASS sur le legacy, 14 sur le portage**. Base rouge :
3 PASS / 5 FAIL. **Le bouton de deploiement n'est JAMAIS clique** : qu'il declenche immediatement cote
legacy se lit dans son `onclick`. LOT complet rejoue. Captures regardees a 1920, 1400 et 390 px — elles
ont sorti deux defauts qu'aucune assertion ne voyait : le nom de machine qui ramassait la pastille
d'environnement, et un `<a class="rw-bouton">` qui gardait son soulignement de lien (defaut deja present
sur « Exporter en CSV »).

**Notes d'exploitation.** `legacy/ssh/` n'est PAS archive : l'archivage se fait par MODULE et K2
(preflight), K3 (flux SSE) et K4 (deploiement) y vivent encore. Aucune variable d'environnement, aucune
migration ajoutee.

---

### v1.37.28 — module `security/`, sous-lot S7a : le declenchement d'un scan et ses refus

**Symptome.** Le portage affichait les resultats d'un scan sans jamais pouvoir en lancer un, et son etat
vide affirmait que « le declenchement d'un scan reste sur l'ancien portail ». Cote legacy, un scan
refuse etait **indiscernable de ne rien faire**.

**Cause racine.** `runScan` (legacy) fait `resp.body.getReader()` **sans jamais lire `resp.status`**. Le
corps d'un refus est un JSON sur une seule ligne, sans saut final : le lecteur le met dans son tampon,
`split()` rend un unique element que `pop()` y remet, et le tampon est abandonne a la sortie de la
boucle. Rien n'est parse. Second silence : un evenement d'erreur sans `machine_id` — le cas de « Aucun
serveur trouve » — part vers `results-undefined`, que `getElementById` ne trouve pas.

**Correctif.**
- Bouton de scan par machine, **avec ou sans scan precedent** ; l'etat vide ne ment plus.
- **Le statut est lu D'ABORD** ; le flux n'est ouvert que si la reponse est bonne. Le reste du tampon
  est traite en fin de boucle plutot que jete, et un flux qui se termine sans `done` ni `error` le DIT.
- Une erreur sans `machine_id` retombe sur l'annonce globale de la page.
- **Panneau de decision** qui nomme les quatre engagements d'un scan : session SSH et neuf commandes de
  LECTURE seule, plusieurs minutes, un resultat qui remplace le precedent, et **un rapport par
  courriel** — que le legacy n'annonce nulle part alors qu'il declenche au clic. Seuil CVSS et source
  des donnees vivent dans ce panneau, pas dans l'en-tete de la carte (lecon E-63).
- **Jauge d'avancement** : le flux emet un paquet courant sur un total ; sans zone pour les rendre, un
  scan de plusieurs minutes n'a aucun signe de vie.

**Defaut backend mesure, NON corrige** (E-68) : `_user_scan_throttle` et `_scan_lock` sont en memoire de
PROCESSUS et `hypercorn_config.py` declare `workers = 4`. La limite « 60 s entre deux scans » autorise
donc un scan PAR PROCESSUS, et le verrou « un seul scan a la fois » en autorise quatre — sur un
conteneur borne a 512 Mo et 1 CPU. Meme defaut que le scheduler, corrige en v1.37.5 par un `GET_LOCK`
en base. Decision de l'exploitant.

**Tests.** `tests/e2e/go-page-cve-scan-refus.mjs` — **12 PASS sur le legacy, 16 sur le portage**. Base
rouge relevee avant portage : 10 PASS / 3 FAIL. **Aucun scan n'est declenche** : les refus se mesurent
sur un identifiant de machine inexistant, le bouton reel n'est clique que la ou le clic est local puis
ANNULE, et l'absence d'appel est mesuree au reseau. L'absence de panneau cote legacy se lit dans le DOM
sans cliquer. Deux vrais scans avaient demarre avec une premiere version du garde-fou — interrompus
avant tout envoi, verifie (aucune ligne `cve_scans`, 1458 findings inchanges, aucune trace SMTP).
LOT complet rejoue. Captures regardees a 1920, 1400 et 390 px.

**Notes d'exploitation.** Le garde-fou de debit **traverse les suites** (pose par utilisateur, compte
partage) : la suite attend la fenetre, le delai etant lu dans le refus lui-meme. Aucune variable
d'environnement, aucune migration ajoutee.

---

### v1.37.27 — module `security/`, sous-lot S6 : l'enrichissement EPSS / KEV et la priorisation

**Symptôme.** Sur le portage, les cinq vulnérabilités du parc dont l'exploitation est **constatée**
(catalogue CISA KEV) étaient affichées en 104ᵉ position. Elles sont toutes de sévérité HIGH (CVSS 7,1 à
7,8), et le portage de S3 triait par sévérité puis par score : les 103 CRITICAL à 9,8 passaient devant,
sur une page qui montre cinquante lignes. Ni la pastille KEV, ni la probabilité d'exploitation EPSS, ni
le libellé de priorité n'étaient affichés.

**Cause racine.** `ScansCve::resultats()` ne sélectionnait que six colonnes et ignorait les colonnes
d'enrichissement de la migration 054. Le legacy, lui, trie correctement
(`backend/cve_scanner.py:1230-1241`) : **le défaut était dans le portage, pas dans le legacy**.

**Correctif.**
- Le tri devient `kev DESC, priority_score DESC, sévérité, CVSS DESC`, établi **une seule fois en SQL** —
  le script ne fait plus que filtrer, donc aucun geste ne peut le défaire.
- Pastille KEV, pourcentage EPSS (signalé au-delà de 50 %), libellé de priorité en infobulle, et une
  ligne au-dessus du tableau qui **explique** le tri : sans elle, un HIGH au-dessus d'un CRITICAL
  ressemble à un défaut.
- Filtre « KEV (n) », rendu seulement s'il y a de quoi filtrer.
- Re-priorisation précédée d'une **décision en ligne** nommant les 1458 lignes réécrites et l'absence de
  retour en arrière ; l'appel passe par la passerelle (deuxième et dernière exception du module après le
  ticket de S5, même motif : deux services externes).

**Trois défauts d'interface que seule la mesure a montrés** (E-63) : la cellule de sévérité se repliait
sur deux lignes (hauteur de ligne 54 → 63 px, sur 1458 lignes) ; `.rw-tableau` en `width: 100%` laissait
le tableau déborder de sa propre boîte en gardant `scrollWidth == clientWidth`, rendant la dernière
colonne **inatteignable** — ni visible, ni accessible par défilement — d'où le passage à `min-width` ;
et les deux nouvelles marques avaient rejeté hors du champ le bouton de ticket que S5 venait d'y ramener,
d'où l'effacement du résumé sous 1500 px. Sous 720 px la pastille KEV passe devant la sévérité : elle
était coupée en deux au bord du cadre.

**Défaut du legacy mesuré au style calculé** (E-62) : sa pastille KEV est peinte par `bg-rose-600`, une
classe Tailwind **absente du CSS compilé** (PurgeCSS). Fond transparent, texte blanc, contraste
**1,06:1** — invisible, alors que le HTML est correct et qu'aucune assertion sur le DOM ne pouvait le
voir. Le portage mesure **6,47:1**.

**Tests.** `tests/e2e/go-page-cve-priorite.mjs` — **8 PASS sur le legacy, 14 sur le portage**. Base rouge
relevée avant portage : 4 PASS / 5 FAIL. La suite ne déclenche **jamais** `/cve_reprioritize` : elle
interpose un compteur réseau et exige zéro appel, et le geste lui-même est conditionné à la cible, parce
que sur le legacy le bouton agit au premier clic. Captures regardées à 1920, 1400 et 390 px.

**Notes d'exploitation.** Le portage dépend désormais de la **migration 054** (colonnes `epss_score`,
`kev`, `kev_date_added`, `priority_score`, `priority_label`), dont le legacy dépendait déjà pour trier.
`min-width: 100%` sur `.rw-tableau` touche **tous** les tableaux du portage — LOT complet rejoué. Aucune
variable d'environnement, aucune migration ajoutée.

---

### v1.37.26 — module `security/`, sous-lot S5 : le suivi et le ticketing des CVE

`SuiviCve` + `SuiviCveController`, la sixieme colonne du tableau des vulnerabilites devenue
FONCTIONNELLE, et un fichier de langue `suivi` (**21 = 21** cles). Deux routes internes sous
`role:1` + `perm:can_scan_cve`.

E-57 — TROIS DEFAUTS D'UNE MEME COLONNE, tous mesures sur la pile reelle.

**L'etat stocke n'etait jamais affiche.** Le generateur du legacy ne pose aucune option `selected` et
son JS ne fait AUCUN `GET /cve_remediation` — sa seule occurrence est le POST. La cellule montrait donc
un tiret meme quand une remediation existait, et le choix qu'on venait de faire disparaissait au
rechargement alors qu'il etait bien enregistre.

**Un changement de statut effacait trois champs**, avec une remediation complete posee avant l'appel :

    avant            open        | 16   | 2026-12-31 | « note a preserver »
    apres, legacy    in_progress | VIDE | VIDE       | VIDE
    apres, portage   in_progress | 16   | 2026-12-31 | « note a preserver »

Le client n'envoie que `{cve_id, machine_id, status}` ; cote backend les trois autres colonnes
retombent a leur defaut et l'`ON DUPLICATE KEY UPDATE` reaffecte les CINQ. Deplacer une CVE de « a
traiter » a « en cours » effacait donc l'assignataire, l'echeance et la note — et defaisait en silence
l'auto-resolution du scanner. Le portage n'ecrit QUE la colonne demandee.

**Le statut n'etait controle par rien** : un ENUM sans liste blanche, donc un 500 avec une page HTML au
lieu d'un 400. Le portage refuse par un 400 qui NOMME le statut recu.
Choix a signaler : l'ENUM contient `resolved`, que l'interface ne PROPOSE pas — il est pose par le
scanner seul. Le portage l'AFFICHE en clair avec son explication, sans le mettre dans le selecteur :
proposer a quelqu'un de « resoudre » ce que le scanner constate brouillerait les deux gestes.

E-58 — LE TICKET PASSE PAR LA PASSERELLE, seule exception du module, et elle est fondee :
`POST /tickets` appelle un FOURNISSEUR ITSM EXTERNE quand il est configure, et le reimplementer
dupliquerait une integration et ses identifiants. La chaine de gardes y est deja en place.
Ce que le portage ajoute, c'est l'honnetete de l'ecran : la page exige `can_scan_cve`, le ticket exige
`can_admin_portal`, et un compte qui porte la premiere sans la seconde se voyait offrir un bouton
cliquable dont l'appel rend 403 — mesure. Le bouton est desormais DESACTIVE avec son explication, sans
que la regle soit deplacee cote navigateur : c'est toujours le backend qui refuse.

CE QUE S5 NE PORTE PAS, ET LE DIT.
**E-59 — la whitelist.** La table `cve_whitelist` n'a AUCUN lecteur : hors tests, deux requetes, son
listing et sa suppression. Le scanner ne la consulte jamais, `expires_at` n'est evalue nulle part.
Blanchir une CVE n'a donc aucun effet observable, et sa seule fonction d'appel cote legacy est du code
MORT. Decision de l'exploitant : ne pas la porter. Porter l'ecran livrerait un bouton qui enregistre une
ligne que rien ne lit — exactement ce que la v2.0 doit cesser de faire.
**E-60 — l'attribution d'un changement de statut.** `cve_remediation` n'a AUCUNE colonne d'auteur
(`assigned_to` est un assignataire, pas un auteur), le schema appartient au backend et la migration est
interdite au portage. Poser l'auteur dans `resolution_note` serait detourner une colonne de son sens :
la correction demande une migration SQL, donc une decision.

TROIS MESURES DE RENDU, et la colonne d'appoint a du ceder. Ajouter un selecteur et un bouton a la
sixieme colonne a elargi le tableau de 1048 px — le cadre exact obtenu en S3 — a 1102, puis a **1203**
quand j'ai empeche l'empilement, avec le bouton de ticket HORS DU CHAMP. La regle du projet a tranche :
le resume est passe de 46 a **28** caracteres de largeur maximale, son texte entier restant en
infobulle. Et la version a recu un `nowrap` : elle se coupait sur deux lignes, ce qui DOUBLAIT la
hauteur de chaque ligne (78 px au lieu de 41). Mesure finale : 1568 px pour un cadre de 1568 a 1920 px,
bouton dans le champ a 1400 px. A 390 px le defilement reste necessaire et c'est DIT : les quatre
colonnes restantes sont toutes decisionnelles, en cacher une retirerait des donnees necessaires pour
agir.

UN DEFAUT DE MA PROPRE CARACTERISATION, qui aurait pu faire condamner un portage correct. La premiere
version posait la remediation de fixture sur un identifiant INVENTE : il n'apparaissait dans aucune
ligne du tableau, et l'assertion « le suivi affiche l'etat stocke » lisait le selecteur d'une AUTRE
ligne — pour laquelle « vide » est la bonne reponse. Le test echouait sur le portage alors que le
portage avait raison. La fixture porte desormais sur la premiere CVE REELLEMENT AFFICHEE, reperee par le
texte de sa ligne, ce qui marche sur les deux portails.

**Reference du LOT** : `go-page-cve-suivi` entre avec **6 PASS sur le legacy** et **10 sur le portage**.

### Documents de migration

- `docs/migration/INVENTAIRE.md` — état chiffré du legacy avant portage
- `docs/migration/ARCHITECTURE-UI.md` — Filament écarté, Blade retenu, décision argumentée
- `docs/migration/PARITE.md` — écarts assumés entre legacy et portage (**E-01 à E-60**)
- `docs/migration/DEPRECIATION.md` — registre du retrait, partie par partie
- `docs/migration/METHODE-SOUS-LOT.md` — l'ordre de travail d'un sous-lot, et ce que chaque étape attrape
- `docs/migration/MODULE-UPDATE.md` — module `update/` : inventaire et découpage (**porté et archivé**)
- `docs/migration/MODULE-SECURITY.md` — module `security/` : 8 sous-lots (**S1, S2a, S2b, S2c, S3, S4, S5 portés**)
- `docs/migration/MODULE-AUTH.md` — module `auth/` : **condition de sortie de la v2.0**, rien de porté
- `docs/migration/MODULE-SSH.md` — module `ssh/` : inventaire, rien de porté
- `docs/migration/MODULE-SUPERVISION.md` — module `supervision/` : inventaire, rien de porté
- `docs/migration/MODULE-FILTRAGE.md` — `iptables/` et `fail2ban/` : inventaire, rien de porté

---

## [1.37.16] - 2026-08-12 — Sécurité : correctifs issus de l'audit de migration

Défauts relevés lors de l'inventaire préalable à la migration v2.0 (branche `laravel`).
Ils sont **antérieurs à ce chantier** et sont corrigés ici sur `main`, indépendamment de la
migration.

### Cloisonnement des données (IDOR)
- **`ssh-audit/index.php`** : le sélecteur de serveurs listait **tout le parc** (noms + IP) quel
  que soit le rôle. Un lecteur (rôle 1) voyait donc des machines qui ne lui sont pas attribuées.
  Cloisonnement aligné sur `security/index.php` : admin/superadmin voient tout, le lecteur passe
  par `user_machine_access`.
- **`security/cve_export.php`** : `machine_id` / `scan_id` viennent de l'URL et n'étaient pas
  contrôlés. Un lecteur pouvait exporter les CVE de **n'importe quelle** machine. Ajout d'un
  contrôle d'appartenance pour les rôles < admin, avec une réponse **404** (et non 403) pour ne
  pas divulguer l'existence de la machine.

### Authentification
- **`terms.php`** : le formulaire portait un `csrf_token` qui n'était **jamais vérifié** —
  l'acceptation des CGU était CSRF-able. Ajout de `checkCsrfToken()`.
- **`auth/confirm_2fa.php`** : la vérification TOTP n'avait **ni rate-limit, ni anti-rejeu, ni
  tolérance explicite**, offrant un chemin de brute-force (10⁶ combinaisons) contournant les
  protections de `verify_2fa.php`. Alignement sur le mécanisme de référence : rate-limit session
  (5/min) **et** IP (10/10 min via `login_attempts`, `step='2fa'`), anti-rejeu du dernier code,
  `verify($code, null, 1)`.
- **`php/php.ini`** : ajout de `session.use_strict_mode = 1`. Sans cette directive, PHP acceptait
  un identifiant de session non généré par lui (session fixation) ; les `session_regenerate_id(true)`
  du code limitaient le risque sans l'éliminer.

### Défense en profondeur
- **`auth/migrate_crypto.php`** et **`auth/migrate_totp.php`** : ces outils de migration sont
  désormais **strictement CLI** (403 sur toute requête HTTP, garde placée avant tout `require`
  pour n'ouvrir ni connexion BDD ni clé de chiffrement). `migrate_totp` déclenchait une écriture
  en masse sur `users` via un **simple GET sans CSRF**. Note : `www/auth/.htaccess` les refusait
  déjà en HTTP — la garde PHP double ce blocage et tient même si la configuration Apache change.
  Usage inchangé : `docker exec rootwarden_php php /var/www/html/auth/migrate_*.php`.
- **4 × `SELECT *` sur `machines`** remplacés par des listes de colonnes explicites
  (`adm/includes/manage_servers.php` ×2, `adm/includes/manage_servers_table.php`,
  `security/compliance_report.php`) : les credentials SSH chiffrés (`password`, `root_password`)
  ne sont plus chargés en mémoire ni transmis aux vues. Effet de bord positif : ils sortent du
  hash SHA-256 d'intégrité du rapport de conformité.

### Bug préexistant corrigé au passage
- `auth/confirm_2fa.php` utilisait `t()` sans jamais charger `includes/lang.php` (ni directement,
  ni transitivement) : le **premier message d'erreur produisait un fatal** « undefined function ».

### Tests
- E2E `tests/e2e/go-security-fixes.mjs` (nouveau) : **17/17** — login complet, acceptation des CGU
  toujours fonctionnelle, pages à requêtes modifiées rendues sans erreur PHP avec leurs données
  (`adm/admin_page`, `compliance_report`, `ssh-audit`), export CVE toujours autorisé au superadmin,
  scripts de migration en 403.
- Suites existantes rejouées : `01-login` (6/6), `02-admin-users` (4/4), `03-permissions` (3/3),
  `05-cve-scan` (6/6), `09-docker-idor` (4/4). Backend **pytest 285/285**. PHP lint OK sur les
  9 fichiers modifiés.

> Note de méthode : le rapport d'inventaire signalait aussi `update/functions/list_machines.php`
> comme IDOR. **Faux positif** : cette page exige déjà `ROLE_ADMIN`, et « un admin voit tout le
> parc » est le comportement voulu et documenté. Elle n'a pas été modifiée.

---

> ## ⚠️ AVERTISSEMENT — `main` v1.37.16, NON TESTÉ EN PRODUCTION
>
> La branche `main` intègre (merge depuis `beta`) toutes les fonctionnalités
> **v1.24 → v1.37** (drift, tâches, posture, EPSS/KEV, groupes & masse, fenêtres
> de maintenance, 4-eyes, journal de commandes, ChatOps, ticketing, recherche
> globale, restauration backup, veille Docker). **Validées en développement
> uniquement (Puppeteer), PAS en production.** À considérer comme **bêta** :
> tester en pré-production avant tout usage réel. Features sensibles OFF par
> défaut (`APPROVAL_ENABLED`, `CHATOPS_ENABLED`, `TICKETING_ENABLED`).
> Appliquer les **migrations 052 → 061** avant usage.

---

## [1.37.15] - 2026-08-11 — Fix : profils de supervision inassignables (feature à moitié branchée)

**Symptôme (prod)** : les profils Zabbix créés dans l'onglet Profils « ne
servaient à rien » — aucun moyen de les lier aux machines, et le déploiement
de l'agent appliquait toujours la configuration globale par défaut.

### Cause — le dropdown d'assignation n'a jamais été câblé
Toute la plomberie existait : table de liaison `machine_supervision_profile`,
route `POST /supervision/machines/<id>/profile`, fonction JS
`assignProfileToMachine()`, et le déploiement consulte bien le profil assigné
(`_get_machine_profile` → priorité overrides > profil > config globale). Mais
**`assignProfileToMachine()` n'était appelé nulle part** : aucune UI ne
permettait de faire l'assignation → table de liaison toujours vide → config
globale systématique. Le compteur « Machines » de l'onglet Profils restait à 0.

### Fix
- **Colonne « Profil » dans le tableau de déploiement** : un dropdown par
  machine (peuplé selon la plateforme active), présélectionné sur le profil
  assigné, `— aucun —` pour revenir à la config globale. Changement →
  assignation immédiate + toast « Cliquez "Reconfigurer" pour appliquer ».
  Chargé au démarrage, à l'ouverture de l'onglet Déploiement et au changement
  de plateforme.
- **Nouvel endpoint `GET /supervision/profiles/assignments?platform=…`** :
  map complète `machine_id → profile_id` en une requête (évite N appels).
- `assignProfileToMachine()` retourne désormais le succès réel (toast d'erreur
  sinon).
- 5 clés i18n ajoutées (FR/EN) : `supervision.th_profile`, `js.sup_profile_*`.

### Utilisation
1. Onglet **Profils** : créer le profil (HostMetadata, Server, proxy, TLS…).
2. Onglet **Déploiement** : choisir le profil dans la colonne « Profil » de
   chaque serveur.
3. Cliquer **Reconfigurer** (ou Déployer) : la conf générée applique le profil
   (priorité : overrides machine > profil > config globale).

### Tests
- `test_supervision.py` : +3 tests (map d'assignations, plateforme invalide
  refusée, défaut zabbix). Suite complète : **285 tests OK**.
- E2E Puppeteer `tests/e2e/go-supervision-profile-assign.mjs` (nouveau,
  auto-nettoyant) : **8/8 PASS** — un dropdown par machine, profil proposé,
  assignation via l'UI persistée en base, re-sélectionné après rechargement,
  0 erreur JS.

---

## [1.37.14] - 2026-08-11 — Fix : scans planifiés en boucle infinie + 10 000 tâches zombies « En cours » + noms de serveurs trop restrictifs

**Symptômes (prod)** :
1. Le Centre de tâches affichait **10 050 tâches « En cours »** : le scan CVE
   planifié (« Scan quotidien 3h ») se relançait en boucle **toutes les
   30-45 minutes** (= la durée d'un scan de parc), jour et nuit, sans jamais
   se terminer (0 réussite en 24 h).
2. L'ajout d'un serveur dans l'admin refusait les espaces et les caractères
   `+`, `.`, `()` dans le nom.

### Cause 1 — `next_run` persisté APRÈS l'exécution (boucle infinie)
Le scheduler ne mettait à jour `next_run` **qu'après** le scan. Un scan de
parc dure 30-45 min : si le worker meurt pendant (OOM, redémarrage,
déploiement, perte MySQL) ou si un autre worker reprend le verrou leader
entre-temps (fenêtre de course documentée dans le code), `next_run` restait
dans le passé → le scan **repartait immédiatement**, en boucle. Chaque tâche
interrompue restait « running » pour toujours (personne n'écrira jamais son
statut final) et `purge_old_tasks` ne supprime que les tâches **terminées** →
accumulation sans limite.

### Fix 1 (`backend/scheduler.py`)
- **`_advance_schedule()`** : `last_run`/`next_run` sont persistés **AVANT**
  d'exécuter la planification (CVE **et** audits SSH). Si la persistance
  échoue, l'exécution est **sautée** (fail-closed anti-boucle : au pire un
  cycle perdu, jamais dupliqué). Une expression cron invalide reporte à +24 h
  au lieu de re-boucler.
- **Watchdog `_expire_stale_tasks()`** : toute tâche encore « running » après
  `TASK_STALE_HOURS` (défaut **12 h**, 0 = désactivé) est marquée en erreur
  avec un détail explicite `[interrompue - watchdog >12h]`. Exécuté **dès la
  prise de leadership** (nettoie même en cas de crash-loop, où le bloc horaire
  ne tournait jamais) puis toutes les heures. **Les 10 050 zombies existants
  seront assainis automatiquement au premier démarrage après mise à jour.**

### Cause 2 — regex de nom de serveur trop stricte
`validateServerName` n'acceptait que `[a-zA-Z0-9-_]` (3 copies divergentes :
`manage_servers.php`, `server_actions.php`, `import_csv.php`).

### Fix 2
Règle unifiée sur les 3 copies : `^[a-zA-Z0-9][a-zA-Z0-9 ._+()-]{0,254}$` —
espaces, points, `+`, parenthèses autorisés (noms lisibles type « EAU ACTU
(backup) »). Les métacaractères shell/HTML (`;|&$\`"'<>/\`) restent interdits
(défense en profondeur : le nom circule dans des configs distantes et des
messages, déjà quoté/échappé en aval — `shlex.quote`, base64, `escHtml`).
L'import CSV **utilisateurs** reste strict (les noms deviennent des comptes
Linux). Champ mot de passe vérifié au passage : aucun caractère refusé
(trim + chiffrement uniquement).

### Configuration
- Nouvelle variable **`TASK_STALE_HOURS`** (défaut 12) documentée dans
  `srv-docker.env.example`.

### Tests
- `test_scheduler.py` : **+7 tests SPEC** — `_advance_schedule` (next_run futur
  persisté avant exécution, cron invalide → +24 h, échec de persistance →
  exécution sautée, table inconnue refusée) et `_expire_stale_tasks` (cible
  `running` + INTERVAL, délai configurable, désactivable à 0).
- Suite complète : **282 tests OK**. PHP lint OK sur les 3 fichiers.

---

## [1.37.13] - 2026-08-06 — Fix : 504/500 en cascade (scan SSH du parc synchrone + pool backend saturé)

**Symptômes (prod)** : en lançant l'audit SSH sur **tout le parc**, erreur 500
sur le scan lui-même, puis erreurs **504/500 en série sur les autres pages**
(/update/…) pendant toute la durée du scan.

### Causes
1. **`POST /ssh-audit/scan-all` était synchrone** : la route bouclait en SSH
   sur toutes les machines DANS la requête HTTP. Sur un parc réel (machines
   lentes/injoignables → timeouts SSH successifs), la connexion restait ouverte
   plusieurs minutes → n'importe quel proxy intermédiaire coupe (504) et la
   requête interrompue finit en erreur.
2. **Pool backend figé à 10 threads** : toutes les routes `@threaded_route`
   partagent un `ThreadPoolExecutor(max_workers=10)` et `future.result()` est
   **bloquant sans timeout**. La page /update/ tire plusieurs requêtes SSH par
   machine en parallèle : pendant un scan de parc, le pool saturait et toutes
   les requêtes s'empilaient → 504/500 en cascade sur toute l'UI.

### Fix
- **`/ssh-audit/scan-all` passe en tâche de fond** (pattern `groups.run`) :
  réponse immédiate `{queued, task_id, background: true}`, thread daemon
  `_run_scan_all_background` isolé du contexte de requête, **progression par
  machine dans le Centre de tâches** (`x/N — n OK, m erreur(s)`), statut final
  success/error. Helper `_spawn_scan_all_thread` isolé (patchable en test sans
  stubber `threading.Thread` global, dont dépendent les workers du pool).
- **Nouvel endpoint `GET /ssh-audit/fleet`** : dernier audit par machine (BDD
  uniquement, aucun SSH) — alimente la vue « parc » au chargement et pendant le
  polling. Documenté dans `openapi.yaml`.
- **UI SSH Audit** : « Tout scanner » affiche immédiatement « lancé en
  arrière-plan (N serveurs) », montre l'état courant du parc, puis rafraîchit
  la vue toutes les 5 s en suivant la tâche jusqu'au message de fin. 3 clés
  i18n ajoutées (FR/EN).
- **Pool backend dimensionné** : défaut **32 threads** (au lieu de 10),
  surchargeable via **`API_THREADPOOL_WORKERS`** (documenté dans
  `srv-docker.env.example`).

### Tests
- `backend/tests/test_ssh_audit_scan_all.py` (nouveau, 8 tests SPEC) : réponse
  immédiate + délégation au thread (helper patché — stubber `threading.Thread`
  global deadlockait le pool), 0 machine ⇒ pas de thread, RBAC role 1 refusé,
  `/fleet` DB-only, runner : progression + statut final success/error, thread
  daemon, pool ≥ 16.
- Blueprint `ssh_audit` enregistré dans le conftest (il n'était pas testable).
- Suite complète : **275 tests OK**.
- E2E Puppeteer `tests/e2e/go-ssh-audit-scanall.mjs` (nouveau) : **5/5 PASS** —
  réponse en **0,6 s** (avant : durée du scan complet), vue parc immédiate,
  fin de tâche reçue via Centre de tâches, résultats affichés, 0 erreur JS.

### Notes exploitation
- Le suivi du scan de parc se fait désormais dans le **Centre de tâches**
  (`/tasks/`) ; la page SSH Audit se met à jour toute seule.
- Les 504 résiduels sur /update/ pendant de futurs pics de charge peuvent se
  régler en augmentant `API_THREADPOOL_WORKERS`.

---

## [1.37.12] - 2026-08-06 — Fix : filtres de /update/ cassés (« Exception filtre : TypeError … reading 'forEach' »)

**Symptôme (prod)** : sur la page Mises à jour, cliquer « Filtrer » loggait
`Exception filtre : TypeError: Cannot read properties of undefined (reading
'forEach')` et le tableau n'était jamais filtré.

### Cause — clé JSON héritée de l'ancien endpoint PHP
`filterServers()` (`www/update/js/apiCalls.js`) lisait `data.servers`, la clé
renvoyée par l'ancien endpoint **PHP** `update/functions/filter_servers.php`
(`{"servers": [...]}`). Or l'appel a été migré vers l'API **Python**
`GET /filter_servers`, qui renvoie `{"machines": [...]}` (comme
`refreshMachineList`). `data.servers` valait donc `undefined` →
`populateMachineTable(undefined)` → `machines.forEach` → TypeError. Cassé
depuis la migration vers l'API Python (pas une régression récente).

### Fix
- `www/update/js/apiCalls.js` : lecture de `data.machines` (+ défaut `[]`),
  compteur du log « Filtre appliqué » aligné.
- `www/update/js/domManipulation.js` : garde défensive dans
  `populateMachineTable` — une liste non-Array est logguée en console et
  ignorée au lieu de crasher (et de vider le tableau).
- Vérifié : le SELECT du backend renvoie tous les champs consommés par le
  tableau (linux_version, last_checked, online_status, maj_secu_*,
  last_reboot, environment, criticality, network_type) — aucun changement
  backend nécessaire.

### Tests
- E2E Puppeteer `tests/e2e/go-update-filter.mjs` (nouveau, lecture seule,
  auto-validant) : **7/7 PASS** — filtre « tous » repeuple le tableau (2/2
  lignes, message « Filtre appliqué »), filtre `environment=PROD` restreint
  à 1 ligne, aucune « Exception filtre », aucune erreur JS.

---

## [1.37.11] - 2026-08-06 — Fix : deploy sudoers TOUJOURS annulé en mode legacy (« visudo -cf refuse la politique ») + ligne droits sudo absente sans refresh

**Symptômes (prod, EAU-ACTU)** :
1. Chaque déploiement de clé SSH loggait `[user] visudo -cf refuse la politique -
   deploy annulé` pour TOUS les utilisateurs → **aucun fichier sudoers installé**
   → « j'ai mis NOPASSWD mais sudo demande toujours le mot de passe ». (Le fix
   v1.37.8 corrigeait le conflit de nommage ; ce bug-ci l'empêchait carrément
   d'écrire le fichier sur les machines en mode legacy.)
2. Dans l'onglet Accès & Permissions, activer un accès n'affichait pas la ligne
   « droits sudo » (preset + NOPASSWD) : il fallait recharger la page.

### Cause 1 — écho du PTY interprété comme un échec visudo (backend, bloquant)
Sur les machines en bootstrap `su`/`sudo` (pas de compte de service), les
commandes root passent par le **mode legacy** de `execute_command_as_root` :
un shell interactif avec PTY, qui **échote la commande envoyée** dans la sortie
lue. Or la validation embarquait le marqueur d'échec **en clair** dans la
commande (`visudo -cf {tmp} 2>&1 || (rm -f {tmp}; echo __VISUDO_KO__)`) : le
test `'__VISUDO_KO__' in out` matchait l'écho de la commande elle-même →
**faux refus systématique**, même quand visudo validait la politique. Les
machines avec compte de service (`exec_command`, sans écho) n'étaient pas
touchées — d'où un bug visible uniquement sur une partie du parc.

Même famille : `user_exists()` testait `output.strip().isdigit()` — toujours
False avec écho+prompt → les utilisateurs déjà présents étaient revus comme
« à créer » à chaque déploiement (le `useradd` échouait ensuite en silence).

### Fix backend (`backend/configure_servers.py`)
- **Marqueurs assemblés par concaténation shell** (`echo "__VISUDO_""OK__"`) :
  la ligne échotée ne contient jamais le marqueur contigu ; seul l'écho
  réellement exécuté le produit.
- **Vérification positive fail-closed** : le déploiement n'a lieu que si le
  marqueur OK est vu ; sortie illisible/tronquée ⇒ abandon (un sudoers invalide
  peut casser sudo sur toute la machine) + **nettoyage du tmp** dans tous les
  cas d'abandon + sortie visudo incluse dans le log d'erreur.
- `user_exists()` : détection de l'UID par **ligne entièrement numérique**,
  robuste en mode exec comme en mode legacy.
- Périmètre audité : les autres marqueurs `|| echo XXX` du backend passent tous
  par des helpers `exec_command` (sans écho) — non concernés ; le check dpkg de
  `ensure_sudo_installed` utilise un marqueur positif — sain.

### Fix UI (`www/adm/includes/manage_access.php`)
- `toggleAccess()` **injecte dynamiquement la ligne « droits sudo »** (dropdown
  preset + NOPASSWD + lien avancé, identique au rendu PHP) dès l'activation de
  l'accès, et la retire (ligne + badge) à la révocation — plus besoin de
  recharger la page. Labels injectés via `textContent`/`json_encode` (pas de
  HTML dynamique non échappé).
- Fix badge dupliqué : l'ancien sélecteur `span.rounded` ne matchait pas le
  badge PHP (`rounded-full`) → doublons à chaque changement de preset. Classe
  dédiée `.sudo-badge` des deux côtés + parité dark mode.

### Tests
- `backend/tests/test_visudo_legacy_echo.py` (nouveau, 10 tests SPEC) :
  commande sans marqueur contigu, écho PTY sans faux refus, vrai refus ⇒
  abandon + nettoyage tmp, sortie illisible ⇒ fail-closed, user_exists
  paramétré exec/legacy.
- `backend/tests/test_sudoers_naming.py` : fixture réaliste (écho PTY + marqueur
  OK) — les 7 tests valident désormais aussi l'immunité à l'écho.
- Suite complète : **267 tests OK**.
- E2E Puppeteer `tests/e2e/go-access-toggle-refresh.mjs` (nouveau, auto-validant,
  restaure l'état) : **14/14 PASS** — activation ⇒ ligne sudo visible sans
  rechargement (marqueur JS intact), 7 presets, révocation ⇒ ligne + badge
  retirés, 0 erreur JS.

### Notes exploitation
- Après mise à jour des conteneurs, **relancer le déploiement de la clé SSH**
  sur les machines concernées : les fichiers `/etc/sudoers.d/rootwarden-<user>`
  seront cette fois réellement installés.
- Les tentatives échouées ont pu laisser des `/tmp/rootwarden-sudo-*.tmp`
  orphelins sur les serveurs cibles (inoffensifs, purgés au reboot).

---

## [1.37.10] - 2026-08-05 — Sécurité : bump `cryptography` 48.0.1 → 50.0.0 (3 CVE, CI pip-audit rouge)

**Contexte** : le job CI **SCA Python (pip-audit)** est passé au rouge (bloquant
l'auto-tag) après la publication de 3 avis de sécurité sur `cryptography 48.0.1`,
version épinglée dans `requirements.txt`. Aucune modification de code applicatif
n'était en cause — advisories publiées après le dernier run vert.

### CVE corrigées
| ID | Impact | Corrigé en |
|----|--------|-----------|
| PYSEC-2026-3552 | Oracle de Bleichenbacher sur `pkcs7_decrypt_*` (timing + longueur de clé divulguée) | 50.0.0 |
| PYSEC-2026-3553 | DoS : blowup exponentiel sur chaînes de certificats auto-signés dupliqués | 49.0.0 |
| PYSEC-2026-3554 | Contournement de `NameConstraints` : SAN wildcard trop large accepté | 49.0.0 |

### Fix
- `backend/requirements.in` : `cryptography>=48,<49` → `cryptography>=50,<51`.
- `backend/requirements.txt` (lock) : `cryptography==48.0.1` → `cryptography==50.0.0`.
- Vérifié localement : `pip-audit -r requirements.txt --strict` → *No known
  vulnerabilities found*. Compatible `paramiko==5.0.0` (exige `cryptography>=3.3`).

> **Note CI** : le job *SAST règles custom RootWarden (semgrep, advisory)* reste
> rouge mais est `continue-on-error: true` — dette connue (findings pré-existants
> `ssh_utils.py`, `crypto.php`, `machines.py`), non bloquant pour l'auto-tag.

---

## [1.37.9] - 2026-08-05 — Fix : diagramme « Tendances CVE (30 jours) » réduit à un seul point

**Symptôme (prod)** : sur le dashboard, le diagramme « Tendances CVE (30 jours) »
n'affichait qu'une seule barre (le dernier jour), sans historique.

### Cause 1 — rétention des scans CVE en NOMBRE au lieu d'une DURÉE
La purge périodique (`scheduler._purge_old_logs`, active quand
`LOG_RETENTION_DAYS > 0`) ne gardait que les **N derniers scans par machine**
(`CVE_SCAN_RETENTION`, défaut **10**), en comptant des **scans**. Or le diagramme
groupe par **jour** sur 30 jours. Dès que plusieurs scans tombaient le même jour
(planification horaire ou re-scans manuels en rafale), les 10 scans conservés
retombaient tous sur la même date → tout l'historique journalier était purgé →
un seul point affiché.

### Cause 2 — double-comptage intra-journée dans la requête de tendance
`GET /cve_trends` faisait `SUM(cve_count) … GROUP BY DATE(scan_date)` **sur la
table brute** : si une machine était scannée plusieurs fois le même jour, son
compte de CVE était additionné autant de fois qu'il y avait de scans → total
journalier gonflé (visible une fois l'historique rétabli par le fix ci-dessus).

### Fix
- **`backend/scheduler.py`** : purge CVE désormais **basée sur la durée**. Nouvelle
  variable `CVE_SCAN_RETENTION_DAYS` (défaut **90**, ≥ la fenêtre de 30 j du
  diagramme). Un scan n'est supprimé que s'il est **à la fois** hors des N plus
  récents de sa machine (`CVE_SCAN_RETENTION`, conservé comme **plancher** pour
  les machines scannées rarement + la comparaison des 2 derniers scans) **ET**
  plus vieux que `CVE_SCAN_RETENTION_DAYS`. Logique extraite dans
  `_purge_cve_scans()` (testable).
- **`backend/routes/monitoring.py`** (`/cve_trends`) : ne retient plus que le
  **dernier scan par (machine, jour)** (`ROW_NUMBER() … PARTITION BY machine_id,
  DATE(scan_date)`, `rn = 1`) avant de sommer entre machines → plus de
  double-comptage des scans multiples d'une même machine le même jour.

### Configuration
- Nouvelle variable **`CVE_SCAN_RETENTION_DAYS`** documentée dans
  `srv-docker.env.example` (récupérée automatiquement via `./maj.sh`). **Doit
  rester ≥ 30** sous peine de tronquer le diagramme.

### Tests
- `backend/tests/test_scheduler.py` : 4 tests SPEC (rétention par défaut en
  durée `(10, 90)`, fenêtre ≥ 30 j, suppression conditionnée aux **deux**
  critères, override par variables d'env).
- `backend/tests/test_cve_trends.py` (nouveau) : 4 tests SPEC (fenêtre 30 j
  préservée, déduplication `(machine, jour)`, SUM appliqué à la sous-requête
  dédupliquée et non à la table brute).
- Suite complète : **257 tests OK**.

### Frontend
Aucun changement : `www/index.php` construisait déjà correctement 30 barres
(jours manquants remplis à 0) ; le bug était entièrement côté données backend.

---

## [1.37.8] - 2026-08-05 — Fix : NOPASSWD ignoré après déploiement de clé SSH (fichiers sudoers dupliqués)

**Symptôme (prod)** : même avec le preset sudo en NOPASSWD, l'utilisateur devait
toujours saisir son mot de passe après un déploiement de clé SSH.

### Cause (régression de nommage, depuis v1.22.0)
Deux chemins de code écrivaient le sudoers d'un même utilisateur dans **deux
fichiers différents** :
- `configure_servers.add_to_sudoers` (déploiement de clé SSH) → `/etc/sudoers.d/<user>`
- `sudo_manager.deploy_policy` (page `/adm/server_user_policies.php`) → `/etc/sudoers.d/rootwarden-<user>`

`/etc/sudoers.d` est lu en **ordre lexical** et la **dernière** règle qui matche
gagne. Les deux fichiers pouvaient être désynchronisés (l'un NOPASSWD, l'autre non)
et le fichier lu en dernier (`<user>` vient après `rootwarden-<user>`) écrasait la
règle NOPASSWD → invite mot de passe. `remove_from_sudoers` n'effaçait par ailleurs
que `/etc/sudoers.d/<user>`, laissant `rootwarden-<user>` orphelin.

### Fix (`backend/configure_servers.py`)
- Nommage **unifié** : `add_to_sudoers` écrit désormais `/etc/sudoers.d/rootwarden-<user>`,
  **identique** à `sudo_manager` (`_target_path`). Un redéploiement depuis n'importe
  quel chemin ÉCRASE le même fichier au lieu d'accumuler des règles contradictoires.
- **Purge** de l'ancien fichier à nom nu `/etc/sudoers.d/<user>` (helper
  `_purge_legacy_sudoers`) à chaque add/remove.
- **Garde-fou** : le fichier du compte de service `/etc/sudoers.d/rootwarden`
  (géré par `routes/ssh.py`) n'est **jamais** touché (`username == 'rootwarden'` exclu).
- `remove_from_sudoers` supprime maintenant le fichier unifié **ET** le legacy.

### OWASP / sécurité
- A05/A08 (intégrité de configuration) : une seule source de vérité par utilisateur
  dans sudoers.d, plus de règle résiduelle contradictoire.
- Note de suivi : deux *stores* de desired-state cohabitent encore
  (`user_machine_access.sudo_preset` côté onglet Accès et `server_user_sudo_policies`
  côté page policies) — à unifier ultérieurement ; ce correctif règle le conflit de
  fichiers qui causait le symptôme.

### Vérifié
- pytest `test_sudoers_naming.py` (7/7) : chemin unifié = `sudo_manager._target_path`,
  purge legacy, compte de service protégé, contenu rendu contient `NOPASSWD`.
- Démonstration live sur le test-server (DEV) : fichier legacy sans NOPASSWD →
  `sudo -l` = `(ALL) ALL` (mdp requis) ; après fix (fichier unifié + purge) →
  `sudo -l` = `(root) NOPASSWD: ALL`. Suite complète 249/249.

---

## [1.37.7] - 2026-07-25 — Fix : contraintes requirements.in désynchronisées (risque de régression CVE)

Chasse active aux incohérences de configuration : `backend/requirements.in`
contraignait deux paquets **en-dessous** de la version verrouillée dans
`requirements.txt`, ce qui aurait fait **régresser une CVE** au prochain
`pip-compile` (le lock aurait été recalculé sur la borne haute du `.in`).

### Fix
- **paramiko** : `.in` `>=4,<5` → `>=5,<6` (le lock est `==5.0.0`, corrigeant
  **CVE-2026-44405**). Sans ce fix, un `pip-compile` serait redescendu en 4.x.
- **cryptography** : `.in` `>=47,<48` → `>=48,<49` (le lock est `==48.0.1`,
  corrigeant **GHSA-537c-gmf6-5ccf**, cf v1.37.3). Idem : `<48` aurait rétrogradé
  en 47.x.
- Détection systématique : les autres contraintes `>=x,<y` du `.in` sont
  cohérentes avec le lock (hypercorn 0.18 < 0.20, flask, werkzeug, etc.).

### Docs
- README : titre `v1.37.1` → `v1.37.7`, pied de page `v1.20.0 - 2026-05-05`
  → `v1.37.7 - 2026-07-25` (dérive de version corrigée).

### OWASP / sécurité
- A06 (Vulnerable and Outdated Components) : élimine un risque latent de
  réintroduction de deux CVE déjà corrigées lors d'une régénération du lock.

### Vérifié
- `pip-audit` reste vert (le lock installé est inchangé : paramiko 5.0.0,
  cryptography 48.0.1) ; seules les bornes du `.in` sont réalignées.

---

## [1.37.6] - 2026-07-25 — Sécurité : MAJ dépendances PHP (8 advisories dompdf + otphp)

Audit de dépendances complet (pip-audit + composer audit, 2026-07-25) :
- **Python : aucune vulnérabilité connue** (cryptography 48.0.1, paramiko 5.0.0,
  flask 3.1.3... déjà à jour).
- **PHP : 8 advisories sur 2 paquets**, corrigées par cette release.

### Fix
- **dompdf/dompdf `v2.0.8` → `v3.1.6`** (contrainte `^2.0` → `^3.1` dans
  `www/composer.json`) — corrige 6 CVE : CVE-2026-56722 (lecture de fichiers
  locaux via SVG), CVE-2026-59943 (fuite d'existence de fichiers via SVG),
  CVE-2026-59942 et CVE-2026-59941 (DoS par épuisement de ressources via images),
  CVE-2026-55555 (oracle d'existence de fichiers via font-face), CVE-2026-55554
  (bypass de validation chroot). Exposition réelle limitée (HTML du rapport
  généré côté serveur, `isRemoteEnabled=false` déjà en place), mais le job CI
  `sca-php` (strict sur main) serait rouge sans le bump.
- **spomky-labs/otphp `11.3.0` → `11.5.0`** — corrige GHSA-g7m4-839x-ch6v (HIGH :
  DivisionByZeroError via paramètre `digits` d'une URI de provisioning) et
  GHSA-2jx3-65f3-xr8r (MEDIUM : mass-assignment via `loadFromProvisioningUri`).
  Exposition réelle nulle : `loadFromProvisioningUri` n'est appelé nulle part
  dans `www/` (les TOTP sont créés via `createFromSecret` avec nos paramètres).

### OWASP / sécurité
- A06 (Vulnerable and Outdated Components) : `composer audit --locked` repasse à
  **0 advisory** ; API dompdf utilisée (`loadHtml`/`setPaper`/`render`/`stream`,
  constructeur options tableau) inchangée entre v2 et v3.

### Vérifié
- Smoke tests dans le conteneur php : génération + vérification TOTP OK
  (otphp 11.5.0), rendu PDF OK (`%PDF`, mêmes options que `compliance_report.php`).
- E2E Puppeteer `01-login.test.mjs` : **6/6 pass** (login + 2FA TOTP → dashboard)
  après restart du conteneur php.
- `composer audit --locked` : « No security vulnerability advisories found ».

---

## [1.37.5] - 2026-07-25 — Fix : jobs planifiés exécutés une fois PAR worker Hypercorn

Depuis le hotfix v1.37.4 (`hypercorn -c file:...`), la configuration est réellement
chargée et le backend tourne avec **4 workers**. Or `server.py` démarre le scheduler
à l'**import du module** : chaque worker lançait donc son propre thread scheduler,
sans aucun verrou. Conséquence : scans CVE / audits SSH planifiés, backups quotidiens,
purges et notifications pouvaient être exécutés **jusqu'à 4 fois en parallèle**
(`next_run` n'est mis à jour qu'APRÈS l'exécution → fenêtre de course de plusieurs
minutes). Avant v1.37.4, la config était ignorée (1 seul worker effectif) : le défaut
existait mais était masqué.

### Fix
- `backend/scheduler.py` : **verrou de leader MySQL** (`GET_LOCK('rootwarden_scheduler')`)
  porté par une **connexion dédiée gardée ouverte**. Un seul worker (le leader) exécute
  les jobs ; les autres candidatent à chaque itération (60 s) et reprennent
  automatiquement la main si le leader meurt (perte de session MySQL = libération
  automatique du verrou côté serveur).
- `ping(reconnect=False)` sur la connexion du verrou : une reconnexion transparente
  créerait une NOUVELLE session MySQL qui ne détiendrait plus le verrou (le leader
  doit re-candidater explicitement).

### OWASP / sécurité
- Pas de nouvelle surface d'attaque : verrou interne à la BDD, aucun input utilisateur,
  requête paramétrée. Améliore l'intégrité opérationnelle (A04/A08 : plus de doubles
  backups, doubles scans ni notifications dupliquées concurrentes).

### Vérifié
- Dev Docker, image rebuildée (4 workers effectifs) : 4 threads scheduler démarrés,
  **1 seul** « verrou leader acquis » dans les logs.
- Failover : `KILL` de la session MySQL du leader → `WARNING connexion du verrou
  leader perdue` puis ré-acquisition au cycle suivant (≤ 60 s), verrou re-détenu
  (`IS_USED_LOCK` non NULL).

---

## [1.37.4] - 2026-06-17 — Hotfix prod : entrypoint hypercorn (config Python)

Le conteneur `python` crashait en boucle au démarrage (`Restarting (1)`) après
un build neuf (prod), avec :
`tomllib.TOMLDecodeError: Invalid value` dans `hypercorn ... Config.from_toml`.

- **Cause** : `backend/entrypoint.sh` lançait `hypercorn -c hypercorn_config.py`.
  Depuis **hypercorn ≥ 0.15**, un chemin de config **sans préfixe est parsé en
  TOML** ; il tentait donc de lire le fichier **Python** comme du TOML → crash.
  (Invisible en dev : l'image n'avait pas été rebuildée avec ce nouvel entrypoint.)
- **Fix** : préfixe **`file:`** → `hypercorn -c file:hypercorn_config.py server:app`
  (force `Config.from_pyfile`). Validé : `from_pyfile` charge bien `bind=0.0.0.0:5000`.
- **Déploiement** : `./maj.sh` (rebuild de l'image → nouvel entrypoint).

---

## [1.37.3] - 2026-06-16 — Fix CI : CVE dépendance cryptography (pip-audit)

Le job CI **SCA Python (pip-audit)** était rouge (mode `--strict`) :
- **cryptography 47.0.0** → **GHSA-537c-gmf6-5ccf** : les wheels PyPI < 48.0.1
  embarquent une copie statique d'OpenSSL vulnérable (advisory OpenSSL 2026-06-09).
- **Correctif** : `backend/requirements.txt` `cryptography==47.0.0` → **`==48.0.1`**.
  Compatibilité vérifiée (import + AES-GCM + paramiko OK) ;
  `pip-audit -r requirements.txt --strict` → **« No known vulnerabilities found »**.

> Les jobs `ruff`, `bandit`, `semgrep`, `gitleaks`, `php -l`, `trivy`,
> `composer audit`, `build Docker` étaient déjà verts ; seul `pip-audit`
> bloquait (CVE upstream apparue après le pin).

---

## [1.37.2] - 2026-06-15 — Docs (README FR/EN) + correctifs CI

- **README.md / README.en.md** : titre porté à v1.37.1, section « 🆕 v1.24 → v1.37 »
  récapitulant les 12 features (avec mention **bêta / non testé en prod**), entrées
  ajoutées dans Fonctionnalités (EPSS/KEV, Docker, groupes, fenêtres de maintenance).
  Parité FR/EN respectée. Description du dépôt GitHub mise à jour.
- **CI — ruff** : 3 erreurs résiduelles corrigées (`mock-opencve/app.py` F401,
  `scripts/sync-obsidian-vault.py` F401/F541) → `ruff check .` repasse au vert.
- **CI — bandit** : recréation du fichier de config **`bandit.yml`** (référencé par
  `bandit -c bandit.yml` mais absent du repo → le job échouait au chargement). Skips
  documentés des faux positifs/décisions design : B608 (SQL paramétré), B110
  (best-effort), B601 (paramiko + shlex.quote), B507 (AutoAddPolicy — décision design),
  B108 (/tmp transitoire). `bandit -r . -ll -ii -c bandit.yml` → 0 finding au seuil.

---

## [1.37.1] - 2026-06-14 — Hardening : audit OWASP Top 10 des features v1.27→v1.37

Audit OWASP Top 10 ciblé sur les 11 features de la session (4 revues
adversariales en parallèle + vérification manuelle de chaque finding). **Aucune
faille critique ni bypass d'auth/injection** sur le socle (signatures ChatOps,
SSRF guards, requêtes paramétrées, 4-eyes serveur, path-traversal backup : OK).
6 corrections appliquées :

- **A01 — ChatOps approve/reject sans contrôle de rôle** (HIGH) : un compte mappé
  en rôle 1 pouvait débloquer des actions 4-eyes depuis le chat. Ajout du gate
  `role >= 2` dans `chatops.dispatch` (aligné sur l'UI web).
- **A10 — SSRF par redirection** (MEDIUM, x2) : `docker_registry` suivait les
  redirections du manifeste et du `realm` d'auth sans revalidation → passage par
  `_safe_get` (revalidation de chaque saut, comme le scanner CVE).
- **A01/IDOR — `docker/results` sans `machine_id`** (MEDIUM) : un opérateur (rôle 1)
  recevait l'inventaire Docker de TOUTE la flotte → filtrage sur
  `user_machine_access` pour les rôles < 2.
- **A03 — XSS d'attribut `href`** (MEDIUM) : `tickets.js` injectait `external_url`
  (réponse ITSM) dans un `href` via un échappeur qui n'échappe pas les `"` →
  `escAttr` + allowlist de schéma `http(s)`. Idem défensif sur `search.js`.
- **A10 — validation de l'hôte registre** (LOW) : regex stricte sur le host
  (bloque la confusion d'userinfo type `legit.io@169.254.169.254`).
- **Bug** : précédence du tuple de retour Jira (`ticketing._create_jira`) corrigée.

Findings résiduels acceptés/documentés : guard SSRF permissif sur le LAN RFC1918
(registre/OpenCVE interne — choix design), fail-open des fenêtres de maintenance
et de l'approbation sur erreur BDD (disponibilité), prefix-matching du proxy
(non exploitable, défense en profondeur).

---

## [1.37.0] - 2026-06-14 — Feature : inventaire & veille des conteneurs Docker

Sur demande : monitorer les conteneurs Docker des serveurs, détecter les mises à
jour disponibles côté **image** et côté **git**, avec le changelog.

### Détection (migration 061 + `backend/docker_monitor.py`)
- Via SSH (root) : `docker ps` + `docker inspect` (labels compose) +
  `docker image inspect` (digest local `RepoDigests`). Auto-détecte compose / run.
- **Git** : si une stack vient d'un dépôt cloné (working_dir compose = repo git),
  `git fetch` (best-effort, sans prompt, timeout) + nombre de commits en retard
  (`HEAD..origin`) + **changelog** (liste des commits). `safe.directory='*'` pour
  éviter l'erreur « dubious ownership » en root.

### Veille des images (`backend/docker_registry.py`)
- Compare le **digest local** au **digest distant** du même tag via la Registry
  HTTP API v2 : **Docker Hub**, **GHCR**, registres **génériques/internes**.
  Auth anonyme par défaut ; token Bearer optionnel par hôte
  (`DOCKER_REGISTRY_TOKENS`). Flux de challenge `WWW-Authenticate` géré.
- SSRF : guard `_url_is_safe_external` (autorise RFC1918 pour un registre interne,
  bloque loopback/link-local/metadata). Best-effort : digest distant inconnu →
  pas de mise à jour signalée (zéro faux positif).

### Routes & UI
- `routes/docker.py` : `POST /docker/scan` (machine, `require_machine_access`),
  `POST /docker/scan_all` (admin, streaming), `GET /docker/results`.
- Page `/docker/` (admin) : cartes de résumé + table (serveur, conteneur, image,
  état, **MAJ image** À jour/Dispo/Inconnu, **git N commits en retard** + changelog
  repliable). Scan par serveur ou global. Rendu sans `onclick` interpolé.
- Menu (opérationnel, admin) + tooltips, whitelist `api_proxy.php` (`/docker/`),
  i18n fr+en.

### Vérifié (live, vrai serveur srv-zabbix)
**19 conteneurs réels détectés**, digests résolus, **6 mises à jour d'image
réelles** signalées (ex glances, homepage), projets compose identifiés, détection
git correcte (0 stack git ici). Module registre testé contre Docker Hub (token +
digest réels). UI Puppeteer : 19 lignes, 4 cartes, badges MAJ/à jour, 0 erreur JS.

---

## [1.36.0] - 2026-06-14 — UX : séparation Sudo / SFTP + explications en clair

Suite à un retour utilisateur (« je sépare sudo et sftp, et dis ce que chaque
truc fait — je n'ai jamais vu chroot »), la gestion des droits par utilisateur
distant est rendue **compréhensible par un non-expert Linux**.

### Séparation en deux pages
- L'ancienne page unique à 3 onglets (`/adm/server_user_policies.php`) est scindée :
  - **`/adm/server_user_sudo.php`** — droits sudo (« ce que l'utilisateur peut faire en admin ») ;
  - **`/adm/server_user_sftp.php`** — accès SFTP/SSH (« comment l'utilisateur se connecte »).
- L'ancienne URL **redirige** vers la page sudo (compat liens/bookmarks). Menu : deux
  entrées distinctes (Droits sudo / Accès SFTP/SSH).
- JS factorisé dans `www/adm/js/server_user_policy.js` (config par page via `window.POL`).

### Explications en clair (le cœur du retour)
- Chaque page a un **encadré « À quoi sert cette page ? »**.
- Chaque **preset sudo** affiche une phrase concrète (ex : *read_logs* → « l'utilisateur
  peut seulement LIRE les journaux, il ne peut RIEN modifier »).
- Chaque **option SFTP** a un libellé humain + une explication sous le champ, sans jargon :
  - chroot → « Enfermer dans un dossier (« cage ») : l'utilisateur ne voit QUE ce dossier… » ;
  - sftp_only → « Transfert de fichiers uniquement (pas de terminal) » ;
  - password/tcp/agent/x11 forwarding → expliqués avec leur impact sécurité.
- Boutons Déployer/Auditer/Supprimer accompagnés de leur rôle.

### Vérifié (Puppeteer)
Page sudo : encadré intro + aide qui change selon le preset (apt_only → read_logs).
Page SFTP : intro + champ chroot + explication « cage » + « terminal » + libellés humains.
Ancienne URL → redirige vers sudo. 0 erreur JS. (Backend inchangé : routes `/policy/*`
et managers identiques.)

---

## [1.35.0] - 2026-06-14 — Feature : restauration de backup depuis l'UI

Douzième et dernière feature de la roadmap. Les backups (création + sha256)
existaient déjà ; la **restauration** et le **test de restauration** étaient manuels.

### Backend (`db_backup.py`)
- `verify_backup(filename)` — **test de restauration non destructif** : vérifie
  l'empreinte sha256, la lisibilité du gzip, compte tables/statements. N'applique rien.
- `restore_backup(filename)` — **restauration** (DROP TABLE → recréation) :
  - nom validé par regex (anti **path-traversal**), sha256 vérifié **avant** application ;
  - **backup de sécurité automatique** avant écrasement ;
  - `FOREIGN_KEY_CHECKS=0` pendant l'application ;
  - splitter SQL robuste (`_split_sql`) respectant chaînes quotées + échappement
    (un `;` dans une donnée ne casse pas le découpage).

### Routes (`routes/admin.py`)
- `POST /admin/backups/verify` (admin, role 2) ;
- `POST /admin/backups/restore` (**superadmin uniquement, role 3** — opération la
  plus destructive) ; journalisée dans le command log (context `db_restore`).

### Frontend (`/backups/`)
- Page : liste (fichier, taille, date), **Créer**, **Vérifier**, **Restaurer**
  (réservé superadmin, **double confirmation** par re-saisie du nom de fichier).
  Bannière d'avertissement. Rendu sans `onclick` interpolé.
- Menu (Admin) + tooltips, i18n fr+en. (`/admin/` déjà whitelisté + admin-only.)

### OWASP / sécurité
A01 restore = role 3 (superadmin), A03 nom validé + requêtes contrôlées,
A08 intégrité sha256 vérifiée avant restauration + backup de sécurité, A09 trail.

### Vérifié
Cycle complet : create (62 tables) → verify (valide, sha256 OK, 451 statements) →
restore (451 appliqués, backup de sécurité créé) → BDD intacte (superadmin role 3
préservé, 2 users, 62 tables). UI Puppeteer : liste + bouton restore (SA) + verify
API valide, 0 erreur JS.

---

## [1.34.0] - 2026-06-14 — Feature : recherche globale + audit log dans le menu

Onzième feature de la roadmap.

### Recherche globale (`routes/search.py` + `/search/`)
- Un seul endpoint `GET /search?q=` interroge **serveurs** (nom/IP),
  **utilisateurs** (nom/email), **CVE** (cve_id/paquet), **tickets** (résumé/réf)
  et **journal d'audit** (action). Résultats catégorisés + lien de navigation,
  plafonnés à 10 par catégorie.
- Page `/search/` : champ unique avec recherche **debouncée** (300 ms), rendu en
  cartes par catégorie. Rendu sans `onclick` interpolé → pas de DOM-XSS.
- Sécurité : `@require_role(2)` + `can_admin_portal` (traverse users + audit),
  LIKE 100 % paramétré, terme ≥ 2 caractères.

### Visualiseur d'audit log
- Le visualiseur existant (`/adm/audit_log.php` : filtres user/action/date,
  pagination, **export CSV**, **vérification de la chaîne HMAC** via
  `/adm/api/audit_verify.php`) est désormais **accessible depuis le menu** (section
  Admin) — il n'était atteignable que via la page d'administration.

### Divers
- Menu (Admin) : entrées « Recherche » + « Journal d'audit » + tooltips.
- Whitelist `api_proxy.php` (`/search`, admin-only), i18n fr+en.

### Vérifié
UI Puppeteer + API : `srv` → 1 serveur, `super` → 1 utilisateur, rendu en cartes
(srv-zabbix présent), 0 erreur JS.

---

## [1.33.0] - 2026-06-14 — Feature : ticketing ITSM (CVE → ticket)

Dixième feature de la roadmap. Transforme un finding (notamment CVE) en ticket
dans l'outil ITSM de l'équipe.

### Adaptateurs (migration 060 + `backend/ticketing.py`)
- Fournisseurs : **Jira** (REST v2), **ServiceNow** (table incident),
  **GLPI** (apirest.php), **generic** (webhook JSON). Sélection par config.
- SSRF : toute création distante passe par le guard (`_url_is_safe_external`)
  avant POST. Aucun secret journalisé.
- Si désactivé/échec → ticket **`local`** (tracé en base sans référence externe),
  rien n'est perdu. Table `tickets` avec **dédup** par (source, ref, machine_id).

### Routes & intégrations (`routes/tickets.py`)
- `POST /tickets` (manuel ou `source=cve`), `GET /tickets` (liste).
- `create_or_get_ticket()` réutilisable : dédup + fallback local.
- **CVE → ticket** : bouton 🎟 sur chaque finding de la page CVE (`/security/`).
- **Auto-KEV** (opt-in `TICKETING_AUTO_KEV`) : à chaque scan, un ticket est créé
  automatiquement pour les CVE activement exploitées (CISA KEV), dédupliqué.

### Frontend (`/tickets/`) + config
- Page admin : liste (source, fournisseur, référence cliquable) + création
  manuelle + indicateur de fournisseur. Rendu sans `onclick` interpolé.
- Config : `TICKETING_ENABLED`, `TICKETING_PROVIDER`, `TICKETING_URL`,
  `TICKETING_USER/TOKEN`, `TICKETING_PROJECT` (Jira), `TICKETING_APP_TOKEN` (GLPI),
  `TICKETING_AUTO_KEV`.
- Menu (Admin) + tooltips, whitelist `api_proxy.php` (`/tickets` admin-only), i18n fr+en.

### OWASP / sécurité
A01 `@require_role(2)` + `can_admin_portal`, A03 requêtes paramétrées + dédup
unique, A10 (SSRF) guard sur l'URL du fournisseur.

### Vérifié
create + dédup (même id) ; UI Puppeteer : création manuelle listée, CVE→ticket
(200, provider local) listé, indicateur « aucun fournisseur configuré », 0 erreur JS.

---

## [1.32.0] - 2026-06-14 — Feature : ChatOps bidirectionnel (Slack / Teams)

Neuvième feature de la roadmap. Les webhooks **sortants** existaient déjà ; cette
version ajoute le sens **entrant** : piloter RootWarden depuis le chat.

### Réception de commandes (migration 059 + `backend/chatops.py`)
- Endpoint `POST /chatops/command` (backend) exposé publiquement via le
  passthrough `www/chatops/webhook.php` (sans session — Slack/Teams ne peuvent
  pas s'authentifier par session).
- **Authentification** : signature Slack `v0` (HMAC-SHA256 sur `v0:{ts}:{body}`
  + anti-rejeu 5 min) **ou** jeton partagé constant-time (`X-ChatOps-Token`,
  pour Teams/générique). Aucune commande sans auth valide.
- **Mapping** `chatops_users` (chat_user_id → utilisateur RootWarden) : l'acteur
  est résolu via ce mapping ; sans mapping, les commandes mutantes sont refusées.
- Commandes (liste blanche) : `help`, `status` (résumé flotte), `approvals`
  (demandes en attente), `approve <id>` / `reject <id>` — **respecte la règle
  4-eyes** (refus d'approuver sa propre demande).

### Frontend (`/chatops/`) + config
- Page admin : gestion des mappings chat↔utilisateur + instructions de setup
  (URL du webhook, signing secret Slack, jeton Teams). Rendu sans `onclick` interpolé.
- Routes `/chatops/users` (GET/POST/DELETE, admin) via le proxy authentifié.
- Opt-in : `CHATOPS_ENABLED`, `CHATOPS_SLACK_SIGNING_SECRET`, `CHATOPS_TOKEN`.
- Menu (Admin) + tooltips, whitelist `api_proxy.php` (`/chatops/users` admin-only),
  i18n fr+en.

### OWASP / sécurité
A01/A07 : endpoint entrant authentifié par signature/jeton (jamais par session) ;
mapping CRUD réservé admin ; backend Python non exposé (atteint via le passthrough).
A03 commandes en liste blanche + requêtes paramétrées.

### Vérifié (curl live, token activé temporairement)
`status` → résumé flotte ; `approvals` → 2 demandes ; `approve 6` (demandeur tiers)
→ approuvée ; `approve 7` (sa propre demande) → refus 4-eyes ; mauvais jeton → 401 ;
commande sans mapping → refus d'identité ; `help` → liste des commandes.

---

## [1.31.1] - 2026-06-14 — Fix : le superadmin contourne l'approbation 4-eyes

Sur un déploiement avec un **seul administrateur**, la règle 4-eyes (approbation
par un 2e admin) ne pouvait jamais être satisfaite : le superadmin se serait
bloqué lui-même (impossible d'approuver sa propre demande, pas d'autre admin).
- `approvals.gate()` prend désormais le `role` et **contourne l'approbation pour
  le superadmin (rôle 3)** — contournement journalisé.
- Appelants mis à jour (`delete_remote_user`, `reboot_server`) pour transmettre
  le rôle. Doc + i18n (fr/en) précisent l'exemption superadmin.

---

## [1.31.0] - 2026-06-14 — Feature : journal des commandes (trail type bastion)

Huitième feature de la roadmap. Trace **ce que RootWarden exécute réellement**
sur les serveurs distants : un journal d'audit type bastion (qui, quoi, où,
quand, résultat).

### Modèle (migration 058 + `backend/command_logger.py`)
- Table `command_log` (machine_id, user_id, context, command, success, detail,
  created_at). Helper `log_command(...)` best-effort (connexion propre, jamais
  d'exception remontée — la journalisation ne casse jamais l'action suivie).

### Instrumentation des routes privilégiées
- `reboot_server` (context `reboot`), `delete_remote_user` (`delete_user`,
  succès réel d'après le check `id`), `update_server` (`full_update`),
  `apply_security_updates` (`security_update`), `custom_update` (`custom_update`).
  Chaque entrée capture la commande exacte + l'acteur + la machine.

### Consultation (`routes/commandlog.py` + `/commandlog/`)
- `GET /command_log` (filtres machine/context, limite ≤ 500) + `/command_log/contexts`.
- Page lecture seule : tableau filtrable (machine, contexte), pastille de
  résultat OK/échec. Rendu sans `onclick` interpolé → pas de DOM-XSS.
- Menu (Admin) + tooltips, whitelist `api_proxy.php` (`/command_log`, admin-only),
  i18n fr+en.

### OWASP / sécurité
A01 `@require_role(2)` + `can_admin_portal` (consultation d'un journal d'audit),
A03 requêtes paramétrées + filtres validés, A09 journal en lecture seule (pas
de suppression via l'API).

### Vérifié
`log_command` insère correctement (smoke-test). Viewer Puppeteer : 3 entrées
rendues (userdel / upgrade / reboot), filtre par contexte (delete_user → 1), 0
erreur JS. (Les actions mutantes ne sont pas déclenchées en live contre le
serveur de prod — instrumentation vérifiée par code + test du logger.)

---

## [1.30.0] - 2026-06-14 — Feature : workflow d'approbation 4-eyes

Septième feature de la roadmap. Au-delà du step-up 2FA (qui protège contre le
vol de session), impose une **double validation humaine** sur les actions les
plus destructives : un second administrateur doit approuver avant exécution.

### Modèle store-and-replay (migration 057 + `backend/approvals.py`)
- Table `approval_requests` (action_type, machine_id, target, payload, status,
  requested_by, approved_by, decision_reason, expires_at).
- `gate(action, machine_id, target, payload, user)` :
  1. 1re tentative → crée une demande `pending`, **n'exécute pas** (retour 202) ;
  2. un 2e admin approuve ;
  3. le demandeur rejoue → `gate` consomme l'approbation → l'action s'exécute.
  Pas de doublon (retentative = même demande). TTL d'expiration des `pending`.
- **Opt-in** (`APPROVAL_ENABLED=false` par défaut) pour ne pas bloquer un
  déploiement mono-admin. Liste d'actions configurable (`APPROVAL_ACTIONS`).
  **Fail-open** sur erreur BDD.

### Règle 4-eyes (`routes/approvals.py`)
- `GET /approvals`, `POST /approvals/<id>/approve|reject`, `/approvals/stats`.
- **Un admin ne peut pas approuver sa propre demande** (`approved_by != requested_by`),
  imposé côté backend (403) **et** UI (bouton désactivé sur ses propres demandes).
- Décisions horodatées + tracées (A09).

### Actions gatées
`delete_remote_user` (ssh) et `reboot_server` (monitoring) appellent `gate()`
après leurs validations ; hors approbation → HTTP **202** + `pending_approval`.
D'autres actions peuvent opter via `APPROVAL_ACTIONS`.

### Frontend (`/approvals/`) + divers
- Page de revue : onglets (en attente / approuvées / rejetées / toutes), boutons
  approuver/rejeter (motif), badge d'état. Rendu sans `onclick` interpolé.
- Menu (Admin) + tooltips, whitelist `api_proxy.php` (`/approvals`, admin-only),
  i18n fr+en, notification best-effort aux admins à la création d'une demande.

### Vérifié
gate() : created → pending (sans doublon) → approuvée → consommée → `executed`.
4-eyes : auto-approbation refusée (403 backend + bouton désactivé UI),
approbation d'un autre admin OK (200). Route : `reboot_server` → 202
`pending_approval` (aucun reboot réel). 0 erreur JS (hors 403 attendu du test négatif).

---

## [1.29.0] - 2026-06-14 — Feature : fenêtres de maintenance / calendrier de changements

Sixième feature de la roadmap. Encadre **quand** les actions mutantes peuvent
s'exécuter, pour éviter les patchs/reboots en pleine production.

### Modèle (migration 056 + `backend/maintenance.py`)
- Table `maintenance_windows` : plages horaires hebdomadaires (scope `global` ou
  `machine`, jours 0-6, `start_time`/`end_time`, `enabled`). Gère les fenêtres à
  cheval sur minuit (start > end).
- Helper `is_allowed(machine_id, role)` :
  - **superadmin (role 3) → bypass** (urgence patch), journalisé ;
  - aucune fenêtre active applicable → autorisé (défaut permissif) ;
  - sinon → autorisé seulement dans une fenêtre. **Fail-open** sur erreur BDD.

### Enforcement (actions mutantes gatées)
Vérification insérée dans : `update_server` (full upgrade), `apply_security_updates`,
`custom_update` (routes updates) et `reboot_server` (monitoring). Hors fenêtre →
HTTP **423** + message clair. Les endpoints lecture seule (`dry_run_update`) et le
callback cron (`update_security_exec`) ne sont **pas** gatés.

### Routes & frontend
- `routes/maintenance.py` : CRUD `/maintenance/windows` + `GET /maintenance/check`
  (utilisé par le frontend pour prévenir avant une action).
- Page `/maintenance/` : formulaire (scope, jours, horaires), liste avec badges de
  jours et indicateur **Ouverte / Fermée / Désactivée** calculé client-side.
  Rendu sans `onclick` interpolé → pas de DOM-XSS.
- Menu (Admin) + tooltips (`nav.maintenance` / `nav.tip_maintenance`).
- Whitelist `api_proxy.php` : `/maintenance/` autorisé, `/maintenance/windows`
  admin-only (le `/check` reste accessible aux opérateurs).

### OWASP / sécurité
A01 `@require_role(2)` + `can_admin_portal` (CRUD), A03 jours/heures validés
(regex HH:MM, jours 0-6) + requêtes paramétrées, A04 l'enforcement lui-même est
un contrôle d'autorisation temporel.

### Vérifié
Logique : fenêtre fermée (admin) → bloqué `outside-window` ; ouverte → `in-window` ;
superadmin → `superadmin-bypass` ; sans fenêtre → `no-window`. UI Puppeteer :
création + listing + `/maintenance/check`, 0 erreur JS.

---

## [1.28.0] - 2026-06-14 — Feature : groupes de machines + actions de masse

Cinquième feature de la roadmap. Permet de regrouper les serveurs et d'agir
sur tout un groupe d'un coup, plutôt que machine par machine.

### Groupes (backend `routes/groups.py` + migration 055)
- **Groupes dynamiques** : règle de filtre sur les attributs de `machines`
  (`environment`, `criticality`, `network_type`, `lifecycle_status`) + `tags`
  (`machine_tags`). Résolution **live** — un serveur qui matche la règle entre
  automatiquement dans le groupe (OR dans une catégorie, AND entre catégories).
- **Groupes statiques** : liste de membres explicite (`machine_group_members`).
- CRUD complet : `GET/POST /groups`, `PUT/DELETE /groups/<id>`,
  `GET /groups/<id>/members` (résolution + détail).
- Sécurité : filtres construits depuis une **whitelist** de colonnes + valeurs
  enum validées (A03), 100 % paramétré ; `@require_role(2)` + `can_admin_portal`.

### Actions de masse (`POST /groups/<id>/run`)
- Lance une opération sur tous les membres résolus, **en arrière-plan**, chaque
  machine étant tracée dans le **centre de tâches** (v1.25.0) :
  - `drift_scan` — scan de dérive (rapide, sans SSH) ;
  - `cve_scan` — scan CVE complet (réutilise tout le pipeline : SSH +
    enrichissement EPSS/KEV + persistance, via le générateur de streaming drainé).
- Réponse immédiate (`queued: N`) ; suivi dans `/tasks/`.

### Frontend (`/groups/`)
- Page de gestion : formulaire de création (dynamique avec cases à cocher par
  catégorie / statique avec checklist de serveurs), cartes de groupes avec
  compteur de membres, résumé de filtres, boutons « Voir membres / Scan dérive /
  Scan CVE / Supprimer ». Rendu sans `onclick` interpolé (addEventListener +
  `textContent`) → pas de DOM-XSS.
- Entrée menu (section Admin) + whitelist `api_proxy.php` (`/groups`, admin-only).
- i18n fr+en (`groups.*` + `js.groups.*` + `nav.groups`).

### Vérifié (Puppeteer live)
Groupe dynamique `environment=PROD` créé → 1 membre résolu (srv-zabbix) →
« Voir membres » OK → « Scan dérive » → tâche `drift_scan` créée dans le centre
de tâches. 0 erreur JS.

---

## [1.27.0] - 2026-06-14 — Feature : priorisation EPSS + CISA KEV des CVE

Quatrième feature de la roadmap. Le CVSS mesure la *sévérité théorique* d'une
CVE, pas la probabilité qu'elle soit réellement exploitée. Cette version enrichit
chaque finding avec deux signaux d'exploitabilité gratuits et complémentaires
pour **prioriser ce qu'il faut patcher en premier**.

### Enrichissement (backend)
- **EPSS** (FIRST.org) : probabilité d'exploitation à 30 jours (0..1), récupérée
  par batch de 80 CVE, cache mémoire 24h.
- **CISA KEV** : flag « activement exploitée in-the-wild », catalogue complet
  chargé puis caché 24h.
- Nouveau module `backend/cve_enrich.py` (`EPSSClient`, `KEVCatalog`,
  `compute_priority`, `enrich_findings`) réutilisant le guard SSRF (`_safe_get`)
  du scanner. **Best-effort** : API injoignable ⇒ le scan continue (priorisation
  sur le CVSS seul), jamais d'échec de scan.
- **Score de priorité consolidé** (0-100 + label `URGENT`/`HIGH`/`MEDIUM`/`LOW`) :
  KEV ⇒ 100/URGENT ; sinon moyenne pondérée 50 % CVSS + 50 % EPSS. Une CVSS 9.8
  jamais exploitée (EPSS 0.01) tombe sous une CVSS 6.5 activement exploitée.
- Enrichissement intégré à `scan_server` (avant persistance) + tri par KEV puis
  priorité. `_save_scan` + `get_last_scan_results` étendus aux 6 nouvelles colonnes.
- Nouvelle route **`POST /cve_reprioritize`** : ré-enrichit les findings du dernier
  scan **sans reconnexion SSH** (rapide) — cœur de la boucle de priorisation, à
  rejouer quotidiennement pour capter les nouvelles entrées KEV/EPSS.

### Boucle de remédiation patch
La vérification post-patch est assurée par l'auto-résolution déjà en place : à
chaque scan, les CVE non re-détectées passent en `resolved`. Le cycle complet =
scan → priorisation EPSS/KEV → remédiation → re-scan de vérification.

### Frontend (`/security/`)
- Pastille rouge **KEV** + **EPSS %** (rouge si ≥ 50 %) dans la colonne sévérité,
  centralisées via `sevCell(f)` (cohérent sur rendu/pagination/recherche/filtre).
- Tri par défaut : KEV en tête, puis score de priorité décroissant.
- Bouton de filtre **KEV** (si CVE exploitées) + bouton **↻ EPSS / KEV** (re-priorisation).
- Rechargement auto des données enrichies après un scan live.

### Migration / config / i18n
- Migration **054** (idempotente) : `epss_score`, `epss_percentile`, `kev`,
  `kev_date_added`, `priority_score`, `priority_label` + index `idx_cve_findings_kev`.
- Config : `CVE_ENRICH_ENABLED`, `EPSS_API_URL`, `KEV_CATALOG_URL`,
  `CVE_ENRICH_CACHE_TTL`, `KEV_CACHE_TTL` (+ `srv-docker.env.example`).
- i18n fr+en (`js.cve_kev_*`, `js.cve_epss_*`, `js.cve_reprio_*`, `cve.epss_legend`).

---

## [1.26.0] - 2026-06-10 — Feature : score de posture de conformité consolidé (CIS-like)

Troisième feature de la roadmap. Le rapport de conformité (`/security/compliance_report.php`)
exportait déjà CSV + PDF (dompdf) ; cette version ajoute un **score de posture
unique par serveur** agrégeant plusieurs signaux en une note A-F.

### Score de posture (0-100 + lettre, par serveur)
Calculé PHP-side à partir des données déjà en base :
- base = score du dernier audit sshd (`ssh_audit_results`), ou 50 si jamais audité ;
- −30 si CVE critique(s), −15 si CVE haute(s) (dernier scan) ;
- −15 si fail2ban absent (`fail2ban_status`) ;
- −10 par catégorie en dérive (`config_drift`, plafonné à −30).
Note : A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, sinon F. Moyenne de flotte affichée.

### Implémentation
- Nouvelle section « Posture de conformité par serveur » (tableau trié par score
  croissant + carte de moyenne) dans le rapport HTML.
- Posture intégrée aux exports **CSV** et **PDF** existants.
- Durcissement du PDF : purge des buffers de sortie avant `stream()` — un notice
  PHP (mode debug) pouvait corrompre le binaire en le préfixant de `<br />…`.
- i18n fr+en (`compliance.section_posture`, `posture_avg`, `th_score`, etc.).

### Vérifié
Page 200 + 0 erreur PHP/JS, section posture + moyenne affichées, export CSV
(section POSTURE présente), export PDF binaire valide (`%PDF-`, stable sur 3 appels).

---

## [1.25.0] - 2026-06-10 — Feature : centre de tâches (suivi de l'activité de fond)

Deuxième feature de la roadmap. Donne une visibilité opérationnelle sur les
tâches de fond de la plateforme (scans CVE/SSH/drift, backups) avec
statut/durée/historique — la base du « passage à l'échelle ».

### Implémentation
- Migration `053_tasks.sql` : table `tasks` (type, label, status
  pending/running/success/error, machine_id, progress, detail, horodatages).
- `backend/task_tracker.py` : helper autonome réutilisable — context manager
  `with track(type, label, machine_id):` (success/error auto) + `create_task`/
  `update_task`/`purge_old_tasks`. Best-effort (n'impacte jamais le job suivi),
  SQL paramétré, noms de colonnes whitelistés.
- Instrumentation du scheduler : scans CVE planifiés, audits SSH planifiés, scan
  de dérive, backup (si activé) sont désormais tracés. Purge des tâches terminées
  selon `LOG_RETENTION_DAYS`.
- Blueprint `backend/routes/tasks.py` : `/tasks/list` (filtrable status/type,
  paginé), `/tasks/stats` (compteurs 24h + en cours). `@require_role(2)`.
- Frontend `www/tasks/` : tableau live (badges de statut, type, durée, détail),
  cartes de résumé, filtre par statut, rafraîchissement auto (5s). Rendu sans
  `onclick` interpolé (textContent → pas de DOM-XSS).
- Menu (section Admin), i18n fr+en, whitelist + gate admin `api_proxy.php`.

### Note
Lecture seule pour l'instant (historique + statut live). Le **retry** et
l'instrumentation des déploiements interactifs viendront dans une itération
ultérieure (le helper `task_tracker` est prêt à être branché partout).

### Vérifié
Migration appliquée, backend clean, page 200 + 0 erreur PHP/JS, rendu des tâches
(drift_scan réussie + tâche en échec avec détail), cartes de résumé, filtre.

---

## [1.24.0] - 2026-06-10 — Feature : détection de dérive de configuration (drift)

Première feature de la roadmap produit post-audit. Détecte les écarts entre
l'**état désiré** (géré par RootWarden) et l'**état réel** des serveurs, à partir
des données déjà en base — **aucun nouvel appel SSH** (rapide, sans impact réseau).

### Catégories évaluées (par machine)
- **sudo** : nb de politiques désirées (`user_machine_access.sudo_preset` ≠ 'none')
  vs nb réellement déployées et actives (`server_user_sudo_policies.enabled`).
  Écart → « redéploiement requis ».
- **sshd** : grade du dernier audit SSH (`ssh_audit_results`). C/D/F → dérive.
- **fail2ban** : protection brute-force installée + active (`fail2ban_status`).

### Implémentation
- Migration `052_config_drift.sql` : table `config_drift` (upsert par
  (machine_id, category), FK cascade, statut ok/drift/unknown + détail + horodatage).
- Blueprint `backend/routes/drift.py` : `/drift/scan` (par machine), `/drift/scan_all`,
  `/drift/results`. Gardé par `@require_role(2)` + `@require_permission('can_view_compliance')`,
  requêtes 100 % paramétrées.
- Scheduler : scan de dérive de toute la flotte une fois par heure (cycle de purge),
  log si dérive détectée.
- Frontend `www/drift/` : tableau par serveur (badges sudo/sshd/fail2ban), cartes de
  résumé, boutons « Scanner tout » / « Re-scanner ». Rendu sans `onclick` interpolé
  (addEventListener + textContent → pas de DOM-XSS).
- Menu : entrée « Dérive de config » dans la section Conformité (`can_view_compliance`).
- i18n fr+en (`lang/{fr,en}/drift.php`), whitelist + gate admin dans `api_proxy.php`.

### Vérifié
Migration appliquée, backend redémarre clean, page 200 + 0 erreur PHP/JS, scan_all
fonctionnel (srv-zabbix : sudo OK, sshd non audité, fail2ban absent → dérive détectée).

---

## [1.23.3] - 2026-06-10 — Lot B : résiduel bas/moyen (fin de l'audit)

Derniers findings (bas/moyens) + bugs fonctionnels. Vérifié : 18/18 pages, 8/8
handlers, backend redémarre clean, login/profile OK.

### A05 — Misconfiguration
- **Mot de passe DB par défaut refusé hors debug** : `config.py` (backend) et
  `db.php` (PHP) lèvent/refusent si `DB_PASSWORD` vaut `rootwarden_password`
  (valeur triviale du dépôt) en mode non-debug.
- **db.php** : charset `utf8` → `utf8mb4` ; le `$hint` (suggestion `down -v`) et
  le message d'erreur SQL ne sont plus exposés qu'en `DEBUG_MODE`.
- **Cookie `lang`** : ajout de `SameSite=Lax` (forme tableau de `setcookie`).
- **`www/_ul`** : artefact (snapshot statique de la page login avec token CSRF en
  dur, non référencé) supprimé + mount retiré de `docker-compose.prod.yml`.

### A07 / A04 — Auth & Design
- **`profile.php`** : sous `force_password_change`, les modifications d'email et de
  clé SSH sont bloquées (seul le formulaire de mot de passe est traité) — avant,
  un compte en changement forcé pouvait changer ces vecteurs de prise de contrôle
  avant le mot de passe. (clé i18n `profile.must_change_password_first` fr+en)
- **`forgot_password.php`** : le message de succès était placé DANS `if ($user)` →
  un email inexistant n'affichait aucun message (énumération). Déplacé hors du if
  + travail bcrypt factice pour égaliser le timing.
- **`anonymize_user`** : step-up 2FA ajouté (action irréversible, comme `delete_user`).

### A09 — Logging / fuite d'info
- **Erreurs SQL génériques** côté client (détail en `error_log`) :
  `toggle_sudo`, `toggle_user`, `delete_user`, `server_actions` (add/update/delete).
- **PTY** : `execute_as_root_stream` ne se repose plus sur `replace(root_password)`
  (échouait si l'écho était scindé sur une frontière de chunk → fuite partielle) ;
  bufferisation jusqu'au premier `\n` pour jeter la ligne d'écho entière.

### A01 — Access Control
- **Notifications broadcast** (`user_id=0`) : un simple utilisateur ne peut plus
  les supprimer (réservé aux admins) — avant, le `OR user_id = 0` le permettait.
- **`openapi.php`** : aligné sur `docs.php` (superadmin uniquement ; la spec révèle
  toutes les routes).

### Bug fonctionnel
- **`server_id` validé comme port (1-65535)** : un serveur d'id > 65535 ne pouvait
  plus être édité/supprimé. Ajout d'un type de validation `id` (entier positif sans
  borne haute) dans `server_actions.php` et `manage_servers.php`.

### Note
- GeoIP (`fail2ban_manager`) reste en HTTP : ip-api.com en tier gratuit n'autorise
  que HTTP (HTTPS = payant) ; l'IP envoyée est déjà publique. Documenté.

---

## [1.23.2] - 2026-06-10 — Lot #2 : IDOR + cohérence d'accès (suite audit)

Findings de contrôle d'accès restants. Vérifié : 18/18 pages, 8/8 handlers,
fix CSRF iptables confirmé (load_from_db → 200 au lieu de 403), backend clean.

### A01 — Broken Access Control
- **IDOR iptables** : [iptables/index.php](www/iptables/index.php) — les handlers
  `load_from_db`/`save_to_db`/`restore` prenaient `$_POST['server_id']` sans
  revérifier l'accès (le dropdown était filtré, pas les handlers) → un role-1 avec
  `can_manage_iptables` pouvait lire/écrire/restaurer les règles de **n'importe
  quelle machine**. Revalidation `user_machine_access` ajoutée (admins exemptés).
- **IDOR supervision** : `require_role(2)` ajouté sur `machine_profile`,
  `zabbix/version` et `<platform>/version` (les autres routes supervision
  l'avaient déjà ; `require_machine_access` est un no-op sur le `mid` d'URL).
- **Exposition de colonnes** : `update/functions/filter.php` ne sélectionne plus
  `SELECT *` (qui renvoyait `password`/`root_password` chiffrés au navigateur) mais
  des colonnes explicites ; `checkPermission('can_update_linux')` ajouté sur
  `filter_servers.php` et `list_machines.php`.
- **Policy ↔ machine** : `_get_username_from_server_user_id` exige désormais que
  le `server_user_id` appartienne au `machine_id` ciblé (avant : résolution sans
  contrôle → déploiement possible d'un sudoers pour un user d'une autre machine).

### A03 — Injection
- `scheduler.py` : `shlex.quote` sur `home` (lu dans `/etc/passwd` distant) dans
  le scan hebdomadaire des clés (`cat {home}/.ssh/...`) — dernier site oublié.

### Bug fonctionnel
- **iptables « Sauvegarder/Charger BDD »** : les boutons `fetch("index.php")`
  n'envoyaient pas le token CSRF (le wrapper utils.js ne l'injecte que vers
  api_proxy.php) → 403 systématique. Token `csrf_token` ajouté au body.

### Note de conception (non modifié)
- Les routes mutantes *par-machine* (fail2ban ban/restart, services start/stop,
  iptables apply) restent gardées par `@require_machine_access` seul : un role=1
  inscrit dans `user_machine_access` est considéré **opérateur de ses machines**.
  Les actions *flotte entière* (`ban_all_servers`, `install_all`) exigent role 2.
  Modèle cohérent conservé ; à durcir en `require_role(2)` si role=1 doit être
  lecteur seul (décision de gouvernance).

---

## [1.23.1] - 2026-06-10 — Durcissement défense-en-profondeur (suite audit)

Traitement des findings restants (moyens/bas) de l'audit v1.23.0, plus hygiène.
Aucune escalade ; robustesse + défense en profondeur. Vérifié : 18/18 pages,
8/8 handlers, backend redémarre clean, bandit clean.

### Robustesse / fiabilité
- **Fuites de connexions MySQL** : `_resolve_ssh_creds` de `fail2ban.py`,
  `iptables.py`, `services.py`, `ssh_audit.py` passées en `with get_db_connection()`
  (la connexion fuyait sur exception → épuisement progressif du pool).
- **Flux SSE bornés** : `iptables_logs` et `stream_update_logs` avaient un
  `while True` sans fin → un thread/contexte mobilisé indéfiniment par connexion.
  Ajout d'une borne (10 min) + heartbeat (`: ping`) qui détecte la déconnexion client.
- **Robustesse des entrées** : `get_json(silent=True)` (iptables, pas de 500 sur
  body non-JSON), casts de ports bornés (wazuh), `int(hours)`/`value` gardés (admin).

### Sécurité (défense en profondeur)
- **`configure_servers` (déjà v1.23.0) + `bashrc.py`** : `home` (lu dans le
  `/etc/passwd` distant) validé par regex `^/[A-Za-z0-9._/-]+$` avant toute
  interpolation shell dans `_inspect_bashrc`/`_read_remote_bashrc`/`deploy`/backups
  (le seul `restore()` était déjà `shlex.quote`).
- **Presets sudo durcis** : `read_logs` retire `less` (permettait `!sh` = shell
  root) au profit de `cat`/`tail` (pas d'évasion) et force `journalctl --no-pager` ;
  `apt_only` documenté explicitement comme **équivalent root** (apt exécute des
  scripts mainteneur — pas de moyen sûr de « limiter à apt »).
- **Déchiffreur legacy supprimé** : `ssh_utils.decrypt_password` (~360 lignes
  d'heuristique best-effort) retirée définitivement ; tout passe par
  `encryption.decrypt_password` (AES-GCM AEAD).

### Bug fonctionnel
- **`update_security_exec`** : le callback cron renvoyait toujours 401 (ni clé
  API ni session role possible depuis un cron) → le suivi « dernière MAJ sécu »
  restait faux. Authentification machine-to-machine par **token HMAC** signé avec
  `SECRET_KEY` et borné au `machine_id` (header `X-Update-Token`, comparé en
  constant-time). Conserve la protection A01-NEW-01 (un user role=1 ne peut pas
  forger le token).

### Hygiène
- Secret TOTP dev retiré des fichiers e2e trackés (`go-policies.mjs`,
  `go-policies-visual.mjs`, `go-access-sudo-visual.mjs`, `helpers.mjs`) → lu via
  `E2E_TOTP_SECRET` uniquement (le base32 n'était pas détecté par gitleaks).

---

## [1.23.0] - 2026-06-10 — Audit sécurité de bout en bout + remédiations OWASP Top 10

Audit complet du code (backend Flask, frontend PHP, JS, infra Docker/CI) suivi
de la remédiation de l'ensemble des findings. Les escalades de privilège
identifiées étaient exploitables de bout en bout (proxy → backend) ; les autres
relèvent du durcissement défense-en-profondeur, de la robustesse et de bugs
fonctionnels. Tous les correctifs portent un commentaire `Patch <Axx>` au point
de modification.

### A01 — Broken Access Control (escalades corrigées)
- `routes/helpers.py::require_machine_access` : lisait uniquement `machine_id`
  /`server_id` (singulier) → **no-op** sur les routes à paramètre `machine_ids`
  (pluriel). Désormais collecte aussi `machine_ids`/`server_ids` (listes) et
  **fail-closed** si un id n'est pas autorisé.
- `routes/ssh.py` : ajout de `@require_role(2)` sur `deploy_platform_key`,
  `deploy_service_account` (déploiement compte root `NOPASSWD:ALL`),
  `remove_ssh_password`, `reenter_ssh_password`, `scan_server_users`,
  `remove_user_keys`, `delete_remote_user` — qui n'avaient aucun contrôle de rôle.
- `adm/includes/manage_users.php` + `import_csv.php` : un admin (role 2) pouvait
  créer un compte **superadmin** (role_id=3 accepté sans contrôle hiérarchique)
  puis prendre le contrôle via le magic-link. Désormais un créateur non-superadmin
  ne peut créer/assigner qu'un rôle **strictement inférieur** au sien. Un toast
  d'avertissement informe l'admin quand le rôle est ramené à « Utilisateur »
  (plus de clamp silencieux ; clés i18n `users.role_downgraded` fr+en).
- `adm/includes/manage_roles.php::change_role` : autorisait l'égalité de rôle
  (admin → admin) ; passé à strictement inférieur (superadmin excepté).
- `adm/api/update_server_access.php` (`update_sudo`) : aucune garde de rôle/anti-self
  → un admin posait `all_nopasswd` (root distant) sur tout user ; désormais
  **superadmin-only** (cohérent avec l'UI).
- `api_proxy.php` : gate de rôle défense-en-profondeur sur les préfixes admin
  (`/deploy_service_account`, `/policy/`, `/admin/`, …) en plus du backend.
- `routes/cve.py::cve_compare` : IDOR — les `scan1`/`scan2` fournis n'étaient pas
  liés au `machine_id` autorisé ; vérification d'appartenance ajoutée.
- `routes/helpers.py::_validate_api_key_from_db` : **fail-open** sur scope d'API
  key corrompu/non-liste (le commentaire promettait "denied", le code accordait) ;
  désormais fail-closed.

### A02 — Cryptographic Failures
- `routes/helpers.py` + `server_checks.py` : **retrait** du fallback déchiffreur
  legacy `ssh_utils.decrypt_password` (heuristique best-effort qui annulait la
  garantie d'intégrité AES-GCM/anti-padding-oracle) ; fail-closed sur échec.
- `encryption.py` : la boucle de déchiffrement GCM essaie désormais aussi la clé
  dérivée de `OLD_SECRET_KEY` (rotation) — évitait de retomber sur le fallback.
- `mail_utils.py` : STARTTLS/SMTPS avec contexte TLS vérifiant (chaîne+hostname) ;
  sans contexte, un MITM capturait les credentials SMTP.
- `includes/totp_crypto.php` : fallback non-sodium passé d'AES-256-**CBC** (non
  authentifié) à AES-256-**GCM** (AEAD) ; lecture rétrocompatible des anciens
  blobs `totp:aes:`.
- `adm/server_user_policies.php` : suppression de la clé API backend exposée en
  clair dans le DOM (`const API_KEY`).

### A03 — Injection / XSS
- DOM-XSS : helper `escJsAttr()` (hex-échappement) introduit dans 7 modules JS
  (`services`, `fail2ban`, `ssh-audit`, `bashrc`, `graylog`, `wazuh`,
  `supervision/profiles`). `escAttr` (entités HTML) dans un `onclick` était
  contournable : le parseur décode `&#39;` en `'` avant compilation JS → breakout.
- `json_encode` en contexte `<script>` : ajout des flags
  `JSON_HEX_TAG|APOS|QUOT|AMP` (`head.php`, `ssh/index.php`, `ssh-audit/index.php`).
- `notifications.php` : href de notification restreint aux chemins internes
  (bloque `javascript:`), aligné sur `menu.php`.
- `mail_utils.py` : `html.escape()` sur toutes les valeurs interpolées dans le
  rapport CVE + neutralisation d'injection d'en-tête SMTP (CR/LF dans le sujet).
- `configure_servers.py` : validation `_USERNAME_RE` (regex stricte) ajoutée sur
  `configure_user`/`deploy_user_config`/`manage_ssh_keys`/`add_to_sudoers`/
  `remove_from_sudoers`/`user_exists` — seul module sans cette défense.

### A04 — Insecure Design
- `api_proxy.php` : le check step-up 2FA utilisait une résolution de chemin
  divergente du forwarding (préfixe `api_proxy.php` non retiré) → step-up
  contournable si `PATH_INFO` absent. Chemin canonique calculé une seule fois.

### A07 — Authentication Failures
- `auth/reset_password.php` + `profile.php` : invalidation des `active_sessions`
  et `remember_tokens` après changement/reset de mot de passe (un attaquant gardait
  sa session après reset).
- `auth/login.php` : anti-énumération par timing (coût bcrypt équivalent brûlé
  pour les comptes inexistants) + re-hash bcrypt transparent si coût obsolète.
- `auth/step_up_verify.php` : anti-rejeu TOTP (le step-up n'en avait aucun).
- `auth/verify_2fa.php` : une 2FA réussie était comptée comme échec dans le
  rate-limit IP (DoS de comptes légitimes) ; double incrément du compteur session
  corrigé.

### A08 / A09 / A10
- A10 SSRF : `cve_scanner.py` et `webhooks.py` suivaient les redirections sans
  re-valider la cible → helper `_safe_get` (redirections désactivées + re-validation
  de chaque saut) ; webhooks `generic` signés HMAC-SHA256 (`WEBHOOK_SECRET`).
- A08 CI : bloc `permissions: contents: read` global (least-privilege GITHUB_TOKEN).
- A09 : messages d'erreur SQL génériques côté client (`policies.py`), détail en log.

### Bugs fonctionnels
- `scheduler.py` : les **audits SSH planifiés ne s'exécutaient jamais** (bloc dans
  une fonction `_scheduler_loop` jamais appelée) ; fusionné dans la boucle active
  + fuite de connexion MySQL corrigée (close en `finally`). Fonction morte supprimée.
- `adm/health_check.php` : la page diagnostic déclenchait des **actions
  destructives sur un serveur de prod** au chargement (stop cron, réécriture
  sshd_config, dpkg_repair…) ; routes mutantes basculées sur `machine_id=0` (no-op).
- `index.php` : carte « remédiations » lisait `$remStats` avant sa définition
  (toujours 0) + précédence d'opérateur `?? 0 > 0` corrigée.
- `db_backup.py` : écriture atomique (`.tmp`→rename) + sidecar `.sha256` (un dump
  tronqué par exception n'est plus pris pour un backup valide).

### Infra / déploiement
- `docker-compose.prod.yml` : retrait de `user:"1000:1000"` (incompatible avec
  `useradd -r` + `gosu` → crashloop backend en prod).
- `php/install.sh` : flag `.installed` et credentials écrits dans un volume
  persistant writable (`/var/www/sessions`) au lieu de `/var/www/html` (read_only)
  → évitait un crashloop et la régénération du mot de passe superadmin à chaque boot.
  Compat du flag legacy conservée.
- `backend/entrypoint.sh` : hypercorn lancé via `-c hypercorn_config.py`
  (`workers=4` était ignoré, 1 seul worker en prod).
- `.gitignore` : exclusion des scripts e2e `*-pentest.mjs` (credentials de test en dur).

### Limitations connues (non corrigées dans cette release)
- **CSP** : la politique réelle conserve `script-src 'unsafe-inline'` sans nonce.
  La migration (nonce sur chaque `<script>` inline + retrait de `'unsafe-inline'`)
  nécessite un test navigateur complet pour ne pas casser l'UI → à planifier.
  Commentaire trompeur de `csp_nonce.php` corrigé pour refléter l'état réel.
- **Vérification de clé d'hôte SSH** (`AutoAddPolicy`) : laissée en l'état
  (changer pour `RejectPolicy` sans flux d'enrôlement TOFU casserait tout SSH) —
  décision de design à trancher.
- **CI/images** : SHA-pinning des actions GitHub et digest-pinning des images de
  base recommandés (nécessitent une résolution réseau, non faite ici).

---

## [1.22.2] - 2026-05-31 — Pattern desired/actual state + UI grossie

### Architecture : resolution de la double source de verite

Feedback user 2026-05-31 apres v1.22.1 : "maintenant dit moi si c'est logique pour toi?".
Audit honnete : la v1.22.1 introduisait une double source de verite entre
`user_machine_access.sudo_preset` (configure depuis admin) et `server_user_sudo_policies`
(ecrit par la page server_user_policies.php) **sans pont entre les deux**.

**Resolution : pattern desired/actual state (infra-as-code classique)**

| Table | Role | Qui ecrit |
|---|---|---|
| `user_machine_access.sudo_preset` | **Desired state** (intention admin) | Dropdown onglet Acces |
| `server_user_sudo_policies` | **Actual state** (etat reel deploye) | configure_servers.py au deploy |
| `policy_deployments` | **Audit trail** | configure_servers.py au deploy |

#### Implementation
- `backend/ssh_utils.py::load_data_from_db()` : enrichi pour charger
  `sudo_preset/nopasswd/runas/custom_rules` depuis `user_machine_access`. Le dict
  user retourne maintenant `sudo_policies = { machine_id: {preset, nopasswd, runas, custom_rules} }`.
- `backend/configure_servers.py::add_to_sudoers()` : refactor pour accepter un
  `policy` dict. Rendu via `sudo_manager.render_policy()` + visudo -cf avant mv
  atomique (compatible canal SSH root via `execute_command_as_root`). Fallback
  historique NOPASSWD ALL si pas de policy fournie (retrocompat bool `users.sudo`).
- `configure_users()` : lit `user.sudo_policies.get(machine_id)` pour la machine
  en cours. Priorite : preset configure > bool legacy `users.sudo` > rien.

#### Comportement effectif
- Configurer dropdown 'apt_only' dans onglet Acces -> au prochain deploy SSH,
  le sudoers cible contient les bonnes lignes (visudo valide).
- Configurer 'none' -> le fichier sudoers est supprime au prochain deploy.
- Aucun preset configure + `users.sudo=1` (legacy) -> NOPASSWD ALL comme v1.21.x.

### Fix UX : interface grossie
Feedback user "je trouve ca petit pour info..." apres review v1.22.1 :
- Layout serveurs : `flex-wrap` horizontal -> `flex-col` vertical (1 serveur par ligne)
- Texte general : `text-[10px]` -> `text-xs` / `text-sm`
- Bloc sudo dropdown : conteneur avec bg + border + padding + icone cadenas
- Select sudo : `min-w-[220px]` au lieu de tres etroit
- Checkbox NOPASSWD : `h-4 w-4` + label gras (au lieu de h-3 w-3)
- Lien 'Avance' : avec icone fleche + push a droite (`ml-auto`)
- Badge sudo sur toggle serveur : `rounded-full` + `font-semibold`

---

## [1.22.1] - 2026-05-31 — Sudo par (user x serveur) integre dans onglet Acces

### Feat : choix du preset sudo lors de l'attribution serveur

Suite a la review v1.22.0 : la page `/adm/server_user_policies.php` etait separee du flow d'ajout. Demande user : "c'est la que j'attend les modif sudo" (= a cote du toggle d'attribution serveur).

#### Couche BDD (migration 051)
- `user_machine_access` enrichie : `sudo_preset`, `sudo_nopasswd`, `sudo_runas`, `sudo_custom_rules`
- Migration de compat auto : `users.sudo=1` -> `sudo_preset='all_nopasswd' + nopasswd=TRUE` sur toutes les attributions des users concernes (preserve le comportement existant)
- Le bool `users.sudo` reste pour retrocompat (deprecie mais non drop)

#### UI (admin_page.php -> onglet Acces & Permissions)
- Sous chaque toggle serveur attribue, dropdown inline preset sudo (7 valeurs : none / apt_only / restart_services / read_logs / systemctl_specific / all_nopasswd / custom) + checkbox NOPASSWD
- Badge couleur sur le toggle (rouge si all_nopasswd, ambre si custom, violet si autre)
- Lien "Avance →" qui ouvre `server_user_policies.php?server=X` pre-rempli pour les cas custom_rules, SFTP, audit, historique
- Visible uniquement pour superadmin (role_id=3)
- Toast feedback sur changement de preset

#### Endpoint backend
- `www/adm/api/update_server_access.php` : nouvelle action `update_sudo` qui accepte `{user_id, machine_id, sudo_preset, sudo_nopasswd, sudo_runas}`. Whitelist preset cote serveur + regex runas. UPDATE conditionnel sur ligne existante (refuse si l'access n'a pas ete cree d'abord). Audit_log trace.

#### TODO (commit separe)
- `backend/configure_servers.py` doit lire `user_machine_access.sudo_preset` au moment du deploy SSH et invoquer `sudo_manager.deploy_policy()` au lieu de l'actuel `echo '<user> ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/...`. Pour l'instant les modifications du preset sont stockees mais pas encore propagees au prochain deploy.

#### Audit OWASP
- A01 : `@checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` + dropdown visible superadmin only ; anti self-grant deja en place (patch A01-04)
- A03 : whitelist preset + regex runas `[a-z_][a-z0-9_-]{0,31}`
- A09 : audit_log via helper existant

---

## [1.22.0] - 2026-05-31 — Politiques sudo + SFTP par utilisateur distant

### Hardening complementaire (audit OWASP renforce)
- **Step-up 2FA** (A07) sur `/policy/(sudo|sftp)/(deploy|remove)` et `/policy/rollback` via `api_proxy.php`. Reuse du modal global `rwOpenStepUpModal()` deja en place (utils.js). Action `policy_action` valide 15 min.
- **Audit log chain HMAC** (A09) : helper `_audit_log()` dans `routes/policies.py` integre dans 5 actions critiques. Scrub auto si details > 200 chars (SHA-256 fingerprint sans leak des sudoers custom).
- **Whitelist proxy** corrigee : ajout `/policy/` dans `$ALLOWED_PROXY_PREFIXES` de `api_proxy.php` (etait oubliee - aurait bloque toutes les routes en prod).
- **Documentation API** : 9 routes ajoutees dans `openapi.yaml` (schemas, responses 200/400/403/404, tag Policies).
- **Diagnostic backend** : 2 entrees dans `/adm/health_check.php` (policy/list + policy/deployments).
- **Tests E2E Puppeteer** : `tests/e2e/go-policies.mjs` couvre 17 assertions : login + 2FA + CGU, acces page, 3 onglets, 6 presets, lecture backend, step-up 2FA effectif, historique, lien sidebar superadmin only.

### Feat majeure : administration fine des droits sudo et acces SFTP/SSH

Nouvelle page `/adm/server_user_policies.php` (superadmin only) qui permet de configurer, pour chaque (machine, server_user_inventory.id), une politique sudo et/ou une politique SFTP/SSH, deployees via SSH puis enregistrees dans un historique pour rollback 1-clic.

#### Couche BDD (migrations 048-050)
- `server_user_sudo_policies` : 5 presets metier + custom, nopasswd, runas, enabled
- `server_user_sftp_policies` : sftp_only/chroot/working/forwardings/x11
- `policy_deployments` : historique avec policy_snapshot JSON + previous_file_content pour rollback

#### Couche backend Python
- `backend/sudo_manager.py` : 5 renderers de preset + custom (visudo -cf au deploy)
- `backend/sftp_manager.py` : rendu du Match User block + sshd -t + reload sshd
- `backend/routes/policies.py` : Blueprint Flask avec 9 routes :
  - `POST /policy/sudo/deploy` `audit` `remove`
  - `POST /policy/sftp/deploy` `audit` `remove`
  - `POST /policy/rollback` (avec verification machine_id == deployment.machine_id)
  - `GET  /policy/deployments` (historique pagine, limit 50)
  - `GET  /policy/list` (toutes les politiques configurees, filtre par machine_id)

#### Couche UI
- `www/adm/server_user_policies.php` : 3 onglets (Sudo / SFTP / Historique)
- Sudo : dropdown 6 presets + textarea custom + liste services + nopasswd + runas
- SFTP : sftp_only, chroot_dir, working_dir, 4 toggles forwardings/x11
- Historique : liste deploiements avec status badge + bouton "Restaurer cette version"
- Audit cote serveur : bouton "Auditer" lit le fichier reel sur la machine
- Confirmation systematique avant remove ou rollback
- Lien sidebar (visible superadmin uniquement)

#### Defense en profondeur (audit OWASP Top 10)
- **A01** Broken Access Control : `@require_role(3)` (superadmin) sur les 9 routes backend ET `checkAuth([ROLE_SUPERADMIN])` sur la page PHP. Verification machine_id sur le rollback (un rollback cross-machine est refuse).
- **A02** Crypto : aucun nouveau hash/secret, pas de regression.
- **A03** Injection : managers valident username `[a-z_][a-z0-9_-]{0,31}`, path absolu sans `..`, services regex `[A-Za-z0-9@._-]+`. Heredoc avec marker aleatoire pour eviter collision avec contenu. SQL via prepared statements.
- **A04** Insecure Design : validation `visudo -cf` (sudoers) et `sshd -t` (sshd_config) SYSTEMATIQUE avant `mv` atomique. Backup en place `.rwbak` avant `systemctl reload sshd`. Si reload echoue, le backup est restaure automatiquement - evite de couper SSH du serveur cible.
- **A05** Misconfig : chemins cibles figes (`/etc/sudoers.d/rootwarden-*`, `/etc/ssh/sshd_config.d/rootwarden-*.conf`). chmod 0440 (sudoers) / 0644 (sshd) + chown root:root. Conforme conventions OpenSSH/visudo.
- **A09** Logging : table `policy_deployments` = trail audit complet (policy_snapshot JSON, contenu avant/apres, validation_output, actor user_id, timestamps). 4 statuts : applied / rolled_back / failed / superseded.

#### Internationalisation
- Parite FR + EN : `www/lang/fr/policies.php` + `www/lang/en/policies.php` (50+ cles)
- Tous les hints presets, warnings securite, status badges, confirmations en 2 langues

---

## [1.21.9] - 2026-05-27 — Durcissement toggle visibilite mdp (anti shoulder-surfing)

### Fix securite (defense en profondeur) : auto-hide du toggle 👁
- Contexte : le toggle 👁 ajoute en v1.21.8 exposait le mot de passe en DOM (`type=text`) jusqu'a ce que l'utilisateur reclique. Risque shoulder-surfing si l'user laisse la page ouverte ou alt-tab vers une autre app en oubliant de re-masquer.
- Fix : 3 mecanismes complementaires d'auto-masquage cote client :
  - **Timeout 8s** : apres clic sur 👁, le mdp se re-masque automatiquement apres 8 secondes (replace tout timer existant si reclic)
  - **visibilitychange** : mask immediat si l'onglet n'est plus visible (Tab change, minimisation)
  - **window.blur** : mask immediat si la fenetre perd le focus (alt-tab, autre app)
- Aucun impact serveur, le hash bcrypt reste inchange. Pas de regression OWASP.
- Nouvelle cle i18n : `reset.revealed_autohide` (annonce accessibility aria-label).

### Audit OWASP Top 10 du patch
- A01 Access Control : aucun changement de logique d'authn/authz
- A02 Crypto : bcrypt cost BCRYPT_COST (12) preserve
- A03 Injection : i18n via `json_encode()` (XSS-safe)
- A05 Misconfig : compatible CSP existante (`script-src 'self' 'unsafe-inline'`)
- A07 Auth : pas de regression sur le token TTL ni la policy serveur

---

## [1.21.8] - 2026-05-27 — UX reset password : indicateur match + toggle visibilite

### Feat : form reset password tolerant aux paste foireux
- Contexte : un user a rapporte qu'une passphrase de 38 chars (toutes les classes OK) etait rejetee a tort. Investigation : `passwordPolicyValidateAll` retournait `null` (aucune raison de rejeter) pour ce password sur l'user_id concerne. Le message affiche etait en realite `reset.error_mismatch` -> le copier-coller depuis Bitwarden/KeePass ajoute parfois un `\n` ou un espace en fin d'un des 2 champs, rendant les saisies differentes cote serveur.
- Fix UX (cf. `www/auth/reset_password.php`) :
  - Indicateur temps reel sous les 2 champs (vert "correspondent" / rouge "differents") avec bordure coloree
  - Toggle 👁 par champ pour reveler le mot de passe et le verifier visuellement
  - Trim auto au paste et au submit (`^\s+|\s+$`) pour gerer les newlines/spaces invisibles
  - Submit bloque cote client si mismatch apres trim -> evite un roundtrip serveur inutile
- Nouvelles cles i18n FR + EN : `reset.match_ok` / `match_ko` / `toggle_visibility` / `trim_warning`

### Fix : alignement hint UX sur la vraie policy serveur
- HTML `minlength="8"` -> `15` (sur password et password_confirm)
- Hint affiche `profile.password_policy_hint` (detaille les 4 classes) au lieu de `reset.min_chars` (qui disait "Minimum 8 caracteres")
- Update i18n `reset.min_chars` et `reset.error_short` FR/EN avec la vraie regle

---

## [1.21.7] - 2026-05-27 — Hotfixes pentest + reverse-proxy + UX

### Fix : reset password via reverse-proxy (HAProxy)
- Symptome (LAGOON) : email de reset mdp contient `https://cleopatre-ssh.magiline.fr:8443/auth/reset_password.php?...` mais l'HAProxy public ecoute sur **443**, pas 8443. L'utilisateur tombe sur `Could not connect to server` au TCP.
- Cause : `URL_HTTPS` servait pour le frontend JS (URL interne `lagoon:8443`) ET pour les emails (qui doivent referencer l'URL publique). Ces deux usages divergent des qu'il y a un reverse-proxy.
- Fix : nouvelle variable d'env optionnelle `URL_PUBLIC_HTTPS`. Si definie, `forgot_password.php` l'utilise pour construire le lien email. Fallback sur `URL_HTTPS` si absente (retrocompat).
- Deploiement : editer `srv-docker.env` -> `URL_PUBLIC_HTTPS=https://cleopatre-ssh.magiline.fr` (sans port si HAProxy ecoute en 443), puis `docker compose restart php`.

### Fix : unlock_user laissait le rate-limit IP actif
- Symptome : superadmin clique "Deverrouiller" sur un compte lock 120 min -> l'user retombe sur "Trop de tentatives, ressayer dans 10 minutes" sans pouvoir se logger.
- Cause : `unlock_user.php` resetait `users.failed_attempts` + `users.locked_until` mais ne touchait pas `login_attempts` (table separee qui sert au rate-limit IP-based 5 echecs / 10 min ajoute par patch A07-NEW-01).
- Fix : purge des tentatives echouees du username concerne (`DELETE FROM login_attempts WHERE username = ? AND success = 0`). On garde les attempts d'autres users sur la meme IP (NAT partage) intactes.

### Fix : toggle "Suivre" flicker sur /update/
- Symptome : checkbox 'Suivre' se decochait/recochait rapidement quand des logs arrivaient en continu.
- Cause : auto-scroll programmatique declenche un event `scroll` qui fait recalculer `nearBottom`. Pendant la frame de stabilisation du layout, le ratio scrollHeight/scrollTop/clientHeight peut momentanement ne plus correspondre -> toggle.checked = false -> frame suivante = true -> flicker.
- Fix : flag `_isProgrammaticScroll` set juste avant l'auto-scroll, reset apres 2 raf. Le scroll-listener bail out si flag actif. Scrolls user (wheel, touch, scrollbar drag) non affectes.

### Fix : /server_status retournait 400 apres patch A01-02
- Symptome : clic sur "Tester" un serveur dans l'admin -> 400 `machine_id requis`.
- Cause : 2 sites d'appel JS (`www/update/js/apiCalls.js`, `www/adm/includes/manage_servers.php`) envoyaient encore `{ip, port}` alors que le patch securite A01-02 a modifie `/server_status` pour exiger `machine_id` (anti LAN-scan).
- Fix : harmonisation JS sur `{machine_id}`. Audit des autres endpoints `@require_machine_access` : RAS.

### Fix : CI build PHP/Apache
- Symptome : `pecl install imagick` echoue `wget: not found` puis `Failed to extract PHP-Parser tarball`.
- Cause : imagick 3.8.1 (publie 2026-05-26) telecharge PHP-Parser via wget au build. L'image `php:8.4-apache` n'embarque pas wget.
- Fix : ajout `wget` aux deps apt-get install du Dockerfile.

---

## [1.21.6] - 2026-05-26 — Backend auto-bootstrap api_key

### Fix critique : 401 persistant apres maj.sh
- Symptome : sur LAGOON, malgre le hotfix v1.21.4/v1.21.5 dans `maj.sh`, le backend Python continuait a logger `API key refusee : DB indisponible ou table vide et API_KEY_BOOTSTRAP non active (fail-closed)`. Cause possible : `maj.sh` execute mais avec une version anterieure du script (etape 5c absente), ou container `rootwarden_db` down au moment du check.
- Fix : deplacement du bootstrap legacy api_key de `maj.sh` (etape shell) VERS le backend Python lui-meme (`backend/bootstrap_api_key.py`). A chaque demarrage du container `rootwarden_python`, on verifie qu'une cle active matche le SHA-256 de `Config.API_KEY` ; sinon on INSERT `proxy-internal-legacy-bootstrap-YYYYMMDD`.
- Avantages : plus de dependance shell, plus besoin du flag `API_KEY_BOOTSTRAP=1`, idempotent, best-effort (ne bloque pas le boot).
- L'etape 5c de `maj.sh` reste en ceinture-bretelle.

---

## [1.21.5] - 2026-05-26 — Hotfix bootstrap legacy (suite v1.21.4)

### Fix : bootstrap saute si la table contient deja des cles
- Symptome : sur certains serveurs, `maj.sh` etape 5c ne bootstrappait pas car la table `api_keys` contenait deja des cles (scopees, ou une legacy revoquee) -> 401 persistant.
- Cause : la condition `COUNT(*) = 0` (table vide) loupait le cas ou aucune cle ACTIVE ne matche le hash de l'env API_KEY.
- Fix : passage a `COUNT(*) WHERE key_hash = sha256(env) AND revoked_at IS NULL`. Insertion sous nom date `proxy-internal-legacy-bootstrap-YYYYMMDD` pour eviter collision UNIQUE avec une eventuelle ancienne legacy revoquee laissee en base pour audit.

---

## [1.21.4] - 2026-05-20 — Hotfix bootstrap legacy API key

### Fix critique : 401 sur toutes les routes apres upgrade prod
- Symptome : sur prod fraichement migree de pre-v1.21 vers v1.21.x, **toutes** les routes backend (deploy_platform_key, list_machines, etc.) retournent 401. Cause : la table `api_keys` est vide tant qu'un admin n'a pas cree sa 1ere cle via `/adm/api_keys.php` (qui auto-insere `proxy-internal-legacy`). Sans cette entree, le proxy PHP envoie `getenv('API_KEY')` que personne ne reconnait, et le fallback `Config.API_KEY` est opt-in (`API_KEY_BOOTSTRAP=1`).
- Fix : nouvelle etape `5c` dans `maj.sh` qui detecte `api_keys` vide + `API_KEY` env set et insere automatiquement `proxy-internal-legacy` (hash SHA256 de l'env, scope=NULL, auto_generated=1). Identique au comportement PHP `api_keys.php` mais sans dependre du clic UI. Idempotent (`INSERT IGNORE`).
- L'admin voit toujours la cle dans l'UI avec badge AUTO et peut la revoquer apres avoir rotate vers une cle scopee.

---

## [1.21.3] - 2026-05-20 — Hotfix onglets admin + dedup CSP

### Fix critique : onglets admin_page casses
- `validateServerName()` etait declaree dans deux fichiers (`manage_servers.php:22` sans guard et `import_csv.php:12` avec guard `function_exists`). Selon l'ordre d'inclusion, un fatal `Cannot redeclare function` cassait le render de `/adm/admin_page.php` apres l'onglet Utilisateurs -> les onglets Serveurs / Acces & Permissions etaient invisibles, tout le JS apres le point d'erreur (dont `switchTab()`) n'etait pas emis.
- Fix : ajout du guard `function_exists` aussi dans `manage_servers.php`. L'ordre d'inclusion n'a plus d'importance.

### Fix : double emission CSP (Apache + PHP)
- Apache (`apache-{ssl,http}.conf.tmpl`) et `verify.php` / `login.php` / `forgot_password.php` / `reset_password.php` emettaient **chacun** un header `Content-Security-Policy`. Quand les deux policies divergeaient (Apache : `object-src 'none'` ; PHP : `connect-src 'self'`), le navigateur appliquait l'intersection -> risque de regressions silencieuses sur features web modernes.
- Fix : la CSP n'est plus emise que par Apache (canonical). Le helper `csp_nonce.php` reste dispo pour usage futur (migration vers nonce explicites).

---

## [1.21.2] - 2026-05-20 — Patch UX cles API + rotation

### Cles API - refonte formulaire de creation
- **Modeles rapides** : 8 chips pre-remplissent nom + scope en 1 clic (Tout / Lecture seule / Scan CVE / Deploiement SSH / Maj APT / Audit SSH / Monitoring / Vider).
- **Checklist de 15 modules** (monitoring, cve, ssh, updates, iptables, fail2ban, services, ssh_audit, supervision, bashrc, graylog, wazuh, admin, reboot, logs) : cocher genere automatiquement les regex de scope.
- **Textarea avance** collapse sous `<details>` pour edition manuelle des regex (mode pro).
- Auto-suggestion du nom : `{preset}-YYYY-MM-DD` quand le champ est vide.

### Bouton "Cles API" dans la toolbar admin
- Visible entre "SSH Keypair" et "Backups" dans `/adm/admin_page.php` - acces direct au menu (auparavant orphelin).
- i18n FR/EN : `admin.btn_api_keys`, `admin.tip_api_keys`.

### Bouton "↻ Renouveler" sur les cles revoquees
- Recree une cle avec **meme scope + meme consumer_hint** sous un nouveau nom `{base}-rYYYYMMDD-HHMMSS` (strip d'un suffixe `-rXXX` precedent pour eviter les noms a rallonge).
- Garde-fous : refuse si la cle est encore active (anti-doublon), refuse les cles `auto_generated` (proxy-internal-legacy).
- Audit log : `Renouvellement cle API 'old' -> 'new'`.

### Champ `consumer_hint` (memo "ou est utilisee cette cle")
- Migration `047_api_keys_consumer_hint.sql` : colonne VARCHAR(200) nullable, idempotente.
- Champ texte libre a la creation : `srv-docker.env:API_KEY`, `GitLab CI variable PROD_API_KEY`, `ansible-vault secrets.yml`, etc. Pas de credential stocke, juste un memo.
- Recopie automatique au renouvellement.
- Bandeau vert post-creation affiche un rappel personnalise si hint fourni, sinon une checklist generique (srv-docker.env, jobs CI/CD, k8s secrets, ansible-vault).
- Colonne "Consommateur" dans la table (tronquee a 32 chars + title=full au hover).

### Banner anciennete (rotation guidee)
- **UI** : banner en haut de `/adm/api_keys.php` si des cles actives non-auto-generees datent de plus de 90j (jaune) ou 180j (rouge). Liste : age, nom, consumer_hint.
- **CLI** : etape 6 de `maj.sh` interroge la DB en silence et affiche un warning en fin de pipeline. Failsafe : skip silencieux si table/colonne absente (boot initial).
- Bonne pratique : rotater les credentials a long terme (90j warning, 180j alerte) limite l'impact d'une compromission.
- Source : `created_at` (pas `last_used_at`) - une cle compromise reste a risque meme utilisee tous les jours.

### Note importante
- **Pas de deploiement automatique** : la plateforme ne touche jamais aux secrets de deploiement (srv-docker.env, secrets k8s, vault). Le renouvellement cree juste une nouvelle valeur en DB. Le bandeau vert et le champ `consumer_hint` aident l'admin a savoir ou recoller manuellement.

---

## [1.21.1] - 2026-05-19 — Patch UX bashrc

### Bashrc - deploiement multi-serveurs
- **Checklist multi-select** des serveurs (remplace le dropdown mono-serveur).
- **Layout vertical** : tableau 1 ligne / serveur (nom, IP, env, dernier deploy).
- **Colonne "Dernier deploiement"** color-codee : vert <30j, jaune 30-90j, rouge >90j, italique gris si jamais. Donnees extraites de `user_logs` (action LIKE `[bashrc] deploy%machine_id=X%`, exclut dry_run=True). Dates formatees en fuseau navigateur via `fmtLocalDate()`.
- **Boutons "Deployer multi" / "Dry-run multi"** violets - actifs des qu'on coche >=2 serveurs. Iteration N serveurs, deploiement sur tous les non-system users, resultat aggrege avec `<details>` collapsibles par serveur.
- Header `<thead>` sticky au scroll pour les gros parcs.
- Modes 0 / 1 / N serveurs cibles geres : 0 = boutons disabled + message, 1 = comportement legacy (selection users fine), N = mode multi (deploy auto sur tous les non-system).

### Fix collateral CSP (regression de la v1.21.0)
- Rollback du nonce dans `csp_header_value()` : CSP3 ignore automatiquement `'unsafe-inline'` si un nonce est declare dans `script-src` -> tous les `<script>inline</script>` du repo etaient bloques silencieusement (bridge i18n, tabs, htmx, etc.). Retour a `'unsafe-inline'` pure en attendant la migration progressive des inline scripts.
- Doc procedure de reactivation dans `www/includes/csp_nonce.php`.

### Convention Tailwind purged respectee (cf [[feedback-tailwind-purged-classes]])
- `dark:bg-gray-900/30` (non compile) -> `dark:bg-gray-800/50` (compile)
- `bg-purple-700/300/400` (non compiles) -> inline styles hex avec `onmouseover/out`

### i18n
- 12 nouvelles cles FR/EN (`bashrc.servers`, `bashrc.all`, `bashrc.none`, `bashrc.btn_multi_deploy`, `bashrc.btn_multi_dryrun`, `bashrc.multi_deploy_info`, `bashrc.col_name`, `bashrc.col_ip`, `bashrc.col_env`, `bashrc.col_last_deploy`, `bashrc.never_deployed`, `bashrc.multi_in_progress`, etc.).

---

## [1.21.0] - 2026-05-19 — Security hardening OWASP Top 10

Audit OWASP Top 10 complet + 30 findings patchés sur 3 vagues. Merge `security/owasp-audit-2026-05` -> main. Voir [OPERATIONS.md](OPERATIONS.md) pour le déploiement.

### Critiques (vague 1)
- **A01-01 / A04-01** Backend Python re-vérifie role+permissions en DB (helpers.py). `X-User-Role` / `X-User-Permissions` headers désormais ignorés.
- **A02-01** Chiffrement passe à AES-256-GCM (AEAD). Préfixe `gcm:` pour les nouvelles écritures, lecture `aes:` legacy conservée.
- **A08-01** `audit_seal.php` ne réécrit plus les lignes scellées (anti-tamper même par superadmin compromis).
- **A04-03** `shlex.quote` sur les arguments shell (Wazuh registration_password + Graylog logger) → corrige RCE root distante.

### Hautes (vague 1 + 2)
- **A01-02/03/04** : `monitoring.py server_status` + machine_access ; `delete_user` strict `targetRole < currentRole` ; anti self-grant `update_server_access`.
- **A02-02/04** : decrypt strict (plus de `errors='ignore'`, plus de fallback null-byte). TOTP fail-closed si SECRET_KEY absente.
- **A04-02** : `api_proxy.php` whitelist explicite ~46 préfixes + rejet path traversal.
- **A06-01** : `requirements.txt` pinné en `==`.
- **A07-01/02** : rate-limit 2FA chainé `if/elseif/else`. Fallback `Config.API_KEY` désormais opt-in via `API_KEY_BOOTSTRAP=1`.
- **A08-02** : audit hash chain passe en HMAC-SHA256 avec `AUDIT_HMAC_KEY` dédiée (auto-générée par `env-merge.sh`). Rétrocompat SHA2 legacy pour vérif.
- **A09-04** : `_SecretScrubFilter` sur tous les handlers logging (server.log + deployment.log + iptables.log + update_servers.log).
- **A10-01/02** : blocklist IP (loopback, link-local, AWS metadata) sur création machine + URL externes via `_url_is_safe_external()`.

### Vague 2 — re-audit findings
- **A01-NEW-01/03/04** : `@require_role(2)` sur `/update_security_exec`, `/fail2ban/geoip`, SSE log streams.
- **A01-NEW-02** : `change_password.php` → `session_regenerate_id(true)` + purge `remember_tokens` + `active_sessions`.
- **A02-NEW-01** : bcrypt cost **12** (constante `BCRYPT_COST` configurable via env).
- **A02-NEW-02** : `change_password.php` applique la `passwordPolicyValidateAll()` (bypass corrigé).
- **A02-NEW-03** : `AUDIT_HMAC_KEY` dans `srv-docker.env.example` + warning runtime + **auto-gen `openssl rand -hex 32`** dans `env-merge.sh`.
- **A04-INSEC-N1** : refus cron schedule `< 10 min` (anti-DoS OpenCVE/SSH).
- **A04-INSEC-N2** : rate-limit CVE scan **60s par user**.
- **A07-NEW-01** : rate-limit 2FA **par IP** (login_attempts.step='2fa', max 10/10min). Migration 046.
- **A08-NEW-01** : `maj.sh` vérifie signature GPG `git verify-commit HEAD` (mode permissif par défaut, strict via `MAJ_REQUIRE_SIGNED=1`).
- **A09-NEW-01** : factorisation `backend/log_scrub.py` + `attach_scrub` + `install_scrub_on_root`.
- **A10-SSRF-N1** : NVDClient passe par `_url_is_safe_external` (oversight du patch A10-02).
- **A10-SSRF-N2** : webhook URL validé + `resp.text` plus loggé.
- **A10-SSRF-N4** : `connect_ssh()` Python a aussi un blocklist host.
- **CMD-INJ-02** : `shlex.quote` sur `home`/`uname`/`backup_path` dans `bashrc.py restore`.
- **XSS-02/03** : `htmlspecialchars` sur labels notif + `Number(cvss).toFixed(1)` en JS.

### Vague 3 — automation + UX
- **A04-INSEC-N4** : step-up 2FA implémenté côté backend (`/auth/step_up_verify.php`, helpers `step_up.php`) + **modal frontend automatique** via wrapper `window.fetch` qui catch les 403 `step_up_required` (utils.js).
- **A04-INSEC-N5** : kill-switch `/revoke_service_account` (superadmin) → `userdel rootwarden` + sudoers purge sur N machines.
- **A05-NEW-01/02/03** : hardening `docker-compose.prod.yml` (user non-root, `cap_drop ALL`, `read_only`, tmpfs).
- **A05-NEW-04** : CSP nonces (helper `csp_nonce.php`) + maintien `unsafe-inline` pour rétrocompat — CSP3 ignore `unsafe-inline` si nonce présent.
- **A05-NEW-05** : corrige commentaire Tailwind CDN (en fait local depuis longtemps).
- **A06-NEW-01** : `requirements.in` source pip-compile + doc.
- **A06-NEW-02** : `scripts/pin-docker-digests.sh` helper.
- **A09-NEW-03** : GELF handler optionnel via `GRAYLOG_HOST/PORT`.

### Conventions sécurité
- **`CONTRIBUTING-SECURITY.md`** : 11 sections + checklist code-review + workflow patch sécu.
- **`.semgrep/rules-rootwarden.yml`** : 10 règles custom CI (anti-régression).
- **Mémoires Claude Code** : conventions et règles persistées pour application automatique en future session.

### Migrations DB
- **045** : `cve_scan_schedules.scan_source` (`fast`/`hybrid`/`precise`).
- **046** : `login_attempts.step` (rate-limit 2FA par IP).

### Documentation
- **`OPERATIONS.md`** : guide d'exploitation complet (déploiement, maj, hardening, kill-switch, rate-limits, etc.).
- **`CONTRIBUTING-SECURITY.md`** : règles à respecter pour éviter régressions.

---

## [1.20.0] - 2026-05-05

### Bouton Redemarrer serveur (`/update/`)

Action manquante depuis la v1.0 alors que toutes les autres actions (apt update,
fail2ban restart, services systemd) etaient possibles. Maintenant :
- `POST /reboot_server` (role admin requis + `require_machine_access` + audit log)
- Bouton rouge **"Redemarrer"** dans la toolbar de `/update/index.php`
- Double confirmation utilisateur (action critique)
- Support `delay_minutes` (cap 24h) : `shutdown -r +N` programme avec broadcast aux users connectes
- Sans delay : `systemctl reboot` immediat (fallback `/sbin/shutdown -r now` si systemd absent)
- Webhook notification sur `server_reboot`
- i18n FR/EN parite : 7 cles

### Auto-fix sshd AllowUsers (suite v1.19)

`POST /sshd_allow_user` - endpoint manuel + bouton "Autoriser sshd" sur chaque
ligne user dans `/adm/server_users.php`. Patche `sshd_config` pour ajouter le
user a AllowUsers si absent. Idempotent (skip si AllowUsers absent ou user
deja autorise) + rollback complet (backup `.bak.rw` + `sshd -t` + restore si fail).

Et auto-fix dans `deploy_service_account` : si `paramiko.AuthenticationException`
sur le test SSH du compte rootwarden, trigger automatique de
`_ensure_sshd_allows_user(rootwarden)` puis retry. Resout les serveurs hardenes
type SRV-WEB qui bloquaient silencieusement.

### Documentation API enrichie

`/api/docs.php` (Swagger UI) etait coince en **v1.13.0**. Mis a jour vers
**v1.19.0** dans `info.version` du `openapi.yaml`. Nouvelles routes documentees :
- `/reboot_server` (Monitoring)
- `/server_user_keys` (SSH) - inventaire cles detaillees v1.19.0
- `/server_user_remove_key` (SSH) - suppression chirurgicale v1.19.0
- `/sshd_allow_user` (SSH) - patch AllowUsers v1.19.x
- `/wazuh/install_all` (Wazuh) - install batch v1.19.0
- `/wazuh/detect` (Wazuh) - detection agent existant v1.19.0

**Total** : 130 -> 136 paths documentes.

### Health check enrichi

`/adm/health_check.php` test maintenant 5 routes en plus :
`/reboot_server`, `/server_user_keys`, `/server_user_remove_key`,
`/sshd_allow_user`, `/wazuh/detect`, `/wazuh/install_all`.

### Memoire

- Nouvelle memoire `feedback_sshd_allowusers.md` documentant le piege AllowUsers
  sur serveurs hardenes (port custom + AllowUsers en place).

---

## [1.19.0] - 2026-04-29

### Inventaire detaille des cles SSH par utilisateur distant

`/adm/server_users.php` : le compteur de cles SSH d'un user devient cliquable
et ouvre un modal listant CHAQUE cle avec :
- type (`ssh-rsa`, `ssh-ed25519`, `ecdsa-*`, `sk-*`)
- fingerprint SHA256 (format identique a `ssh-keygen -lf`)
- comment (`user@hostname`)
- badge "plateforme" / nom proprietaire RootWarden / "proprietaire inconnu"
- date 1re vue (utile pour drift detection)

Backend :
- Migration 044 : nouvelle table `server_user_ssh_keys` (machine_id,
  username, key_type, fingerprint_sha256, comment, is_platform_key,
  first_seen_at, last_seen_at) avec UNIQUE et FK CASCADE.
- `scan_server_users` refactore : 1 seul `execute_as_root` qui dump tous
  les `authorized_keys` du serveur (root inclus) avec marqueurs
  `###USER:xxx###`. Avant : N appels SSH en simple user, silent fail sur
  `/root/*` et users a home protege.
- Nouvelle route `GET /server_user_keys?machine_id=X&username=Y` avec
  cross-reference sur `users.ssh_key` (ownership detection).
- Drift detection : cles disparues entre 2 scans -> DELETE auto.

### Suppression chirurgicale d'une cle SSH precise

Bouton ✗ par cle dans le modal. Confirmation utilisateur requise. SSH en
root sur le serveur, recalcule chaque fingerprint via `ssh-keygen -lf` et
filtre la ligne ciblee, conserve le reste, chmod 600.

- Nouvelle route `POST /server_user_remove_key` (role admin requis).
- Garde-fou : suppression de la cle plateforme RootWarden BLOQUEE par
  defaut (sinon RootWarden se locke hors du serveur). Override via flag
  `force=true` dans le payload.
- Audit log entry par suppression (fingerprint tronque + user + machine).

### Fixes prod (suite v1.18 deployment)

- `maj.sh` + `start.sh` : `chmod +x scripts/env-merge.sh` AVANT l'appel +
  invocation `bash <script>` (ne depend plus du bit exec apres `git pull`).
- `test_platform_key` : fallback `ip:port` quand `machines.name` est
  NULL/vide -> evite le toast "Connexion keypair OK sur " (nom vide).
- `Wazuh install` multi-OS : detection `/etc/os-release` + branche apt
  (Debian/Ubuntu) / yum-dnf (RHEL/Rocky/Alma/Fedora/Amazon/Oracle) /
  zypper (SUSE/openSUSE). Avant : apt-only -> fail silencieux sur
  RHEL family.
- Bit `+x` persistant (mode 100755) en git pour `maj.sh`, `start.sh`,
  `stop.sh`, `scripts/*.sh`, `scripts/sync-obsidian-vault.py`. Plus besoin
  de `chmod +x` apres `git clone` ou `git pull`.

### Migration

- 044 (`server_user_ssh_keys.sql`) : table + UNIQUE (machine_id, username,
  fingerprint_sha256) + FK CASCADE.

### Tests

- `tests/e2e/go-ssh-keys-inventory.mjs` : valide scan + endpoint
  `server_user_keys` + format reponse (fingerprint SHA256:..., owner_name,
  is_platform).
- `go-security.mjs` : regression OK.

---

## [1.18.0] - 2026-04-25

### Feature flags : modules ON/OFF via srv-docker.env

Les modules peuvent etre desactives entierement via une variable d'environnement
sans toucher au code. Premier toggle : `WAZUH_ENABLED=true|false`. Quand OFF :
- backend : blueprint Wazuh non enregistre, toutes les routes /wazuh/* retournent 404
- PHP : helper `feature_enabled('wazuh')` retourne false, sidebar/dashboard cachent
  l'entree, /wazuh/index.php abort en 404 (defense-in-depth)
- helper generique reutilisable : `feature_enabled('xxx')` lit `XXX_ENABLED`,
  default true (compatibilite ascendante)
- `www/api_proxy.php` : propage le HTTP status du backend sur GET (sinon 404
  Flask devenait 200 cote PHP)

### Hardening securite (suite audit complet)

**CI/CD** :
- Nouveau job `sast-semgrep` (bloquant PR + main) : config `p/owasp-top-ten`
  cross-langue PHP+JS+Python avec 6 rules FP-confirmees exclues.
- `actions/upload-artifact@v4` (was `@main`, mutable supply-chain).
- `gitleaks-action` + `trivy-action` pin SHA.
- `bandit` + `pip-audit` bloquants sur PR (etait `\|\| true`).

**Frontend** :
- `api_proxy.php` : `checkCsrfToken()` sur POST/PUT/DELETE/PATCH (defense-in-depth
  contre XSS same-origin sur l'endpoint le plus puissant).
- `www/js/utils.js` : wrapper fetch() qui auto-injecte `X-CSRF-TOKEN` sur les
  non-GET vers `/api_proxy.php` - aucun caller existant a modifier.

**Infra** :
- `docker-compose.prod.yml` : override qui retire les bind-mounts
  `./backend:/app` + `./www:/var/www/html` (defaisaient le hardening de l'image
  baked). Usage : `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d`.
- `test-server/Dockerfile` : refuse de demarrer (`set -e + exit 1`) sans
  `TEST_SERVER_ROOT_PASSWORD` / `TEST_SERVER_USER_PASSWORD`. Fallbacks
  `RootPass-Preprod` / `TestPass-Preprod` supprimes.

### E2E securite (tests/e2e/go-security.mjs)

Codifie les invariants pour qu'ils ne regressent jamais :
- POST `/api_proxy.php/*` sans X-CSRF-TOKEN -> 403
- POST avec CSRF -> 200
- GET non authentifie -> redirect login / 4xx
- XSS payload dans nom de schedule -> echappe dans le DOM, JS non execute
- audit_verify hash chain -> integrity OK

### Scripts d'orchestration : start.sh + stop.sh + maj.sh + env-merge.sh

- `scripts/env-merge.sh` : compare `srv-docker.env` vs `srv-docker.env.example`,
  ajoute les cles manquantes a la fin avec leur commentaire de preface.
  **Ne touche JAMAIS aux valeurs existantes** (secrets preserves). Backup auto
  `srv-docker.env.bak.YYYYMMDD_HHMMSS`. `--dry-run` pour lister sans ecrire.
- `start.sh` : appelle automatiquement `env-merge.sh` avant chmod / verif
  secrets / lancement docker compose. Plus besoin d'y penser apres `git pull`.
- `stop.sh` : wrapper docker compose down avec confirmation interactive sur
  `-v` (suppression volumes BDD destructive), auto-detection profile preprod.
- `maj.sh` : pipeline 5 etapes (git pull -> env-merge -> docker build ->
  migrations -> up -d). Migrations DB lancees in-place via docker exec si
  python tourne deja. `--no-pull / --no-build / --check`.

### Memoire + checklist

- Nouvelle memoire `feedback_security_checklist.md` : auth+role+CSRF+placeholders
  +escHtml a verifier sur chaque endpoint, lancer `go-security.mjs` apres modif.
- `feedback_ruff_f823_imports.md` : piege F823 quand un import global + local
  coexistent dans le meme module.
- `feedback_migration_sql_comments.md` : pas de commentaires `--` entre les
  statements (db_migrate.py concatene apres split sur `;`).

### Migration

- 043 (`ssh_audit_schedules_machines_target.sql`) : etend ENUM `target_type`
  pour 'machines' + `target_value` -> TEXT (multi-select v1.17 portait sur le
  scheduler mais le schema bloquait).

---

## [1.17.0] - 2026-04-25

### Multi-select serveurs sur les planifications de scans

Les schedules CVE et SSH audit acceptent desormais une selection libre de
serveurs (plus seulement "tous", "par tag" ou "un seul serveur"). UI :
nouvelle option "Plusieurs serveurs" qui deplie une grille de checkboxes
avec boutons Tout/Aucun + compteur live. Backend : `target_type='machines'`
+ `target_value` JSON array d'IDs. Parite stricte CVE/SSH audit.

- Migration `043_ssh_audit_schedules_machines_target.sql` :
  * `target_type` ENUM elargi a 'machines'.
  * `target_value` passe en TEXT (JSON array d'IDs au lieu de VARCHAR(100)).
- `backend/scheduler.py` : SSH audit gere `target_type='machines'`
  (parite avec CVE qui le supportait depuis v1.14.x).
- `www/security/index.php` + `www/ssh-audit/index.php` : section
  "Scans planifies" admin+ avec multi-select.
- E2E `tests/e2e/go-ssh-audit-schedules.mjs` : create all + create multi
  (2 IDs) + toggle + render UI + delete. CVE schedule existant inchange.

### Onboarding wizard : message felicitations 8/8

Quand toutes les etapes sont validees, le bandeau affiche un encart vert/bleu
"Felicitations, RootWarden est pret !" avec CTA "Masquer definitivement"
(au lieu de simplement disparaitre). 3 cles i18n.

### Banner de rotation cle API legacy

Sur `/adm/api_keys.php` : 2 niveaux de banner.
- Jaune (info) tant que seule la cle `proxy-internal-legacy` existe.
- Rouge (action requise) des qu'une cle scopee active coexiste avec la
  legacy : "Rotation requise, revoquer proxy-internal-legacy".

Sur le dashboard `/index.php`, rappel persistant compact tant que les
deux cles coexistent. Plus de risque d'oublier la rotation post-deploiement.

### Wazuh : detection d'agent existant

Nouveau bouton "Scanner" cyan dans l'onglet Deploiement. Endpoint
`POST /wazuh/detect` qui SSH le serveur, lit `/var/ossec/bin/wazuh-control
info`, `client.keys` et `systemctl is-active wazuh-agent` pour alimenter
la table `wazuh_agents` sans reinstaller. Cas d'usage : agent deja deploye
hors RootWarden et qu'on veut superviser depuis l'UI.

### Auto-classification serveurs : comptes `nologin`

`POST /scan_server_users` inclut desormais TOUS les comptes /etc/passwd
(le filtre awk excluait `nologin|false|sync|halt|shutdown`). Les comptes
sans login sont auto-classifies `excluded` avec note explicite. Ils restent
auditables sans polluer la liste des comptes geres.

### Bug `Tester` cle plateforme

`POST /test_platform_key` verifie `platform_key_deployed` AVANT de tenter
la connexion SSH. Sur un nouveau serveur : message clair *"Cle non deployee
sur X - clique Deployer d'abord"* au lieu de l'erreur paramiko brute.
`AuthenticationException` capturee separement (message friendlier).

### Centralisation `fmtLocalDate()` en JS global

Le helper de formatage de date locale (UTC -> timezone navigateur) etait
duplique dans `security/js/main.js` ; il vit maintenant dans `www/js/utils.js`
charge depuis `menu.php` (toutes pages). `ssh-audit/js/main.js` l'utilise via
`window.fmtLocalDate`.

### Vault Obsidian : graph.json restaure depuis template

Obsidian reecrit `.obsidian/graph.json` en permanence (scale, close, zoom),
donc on versionnait des changements parasites. Le fichier est maintenant
gitignore ; on versionne `graph.json.template` (avec les colorGroups par
couche) que `scripts/sync-obsidian-vault.py` recopie au premier checkout.

### Renommages mineurs

- `admin.btn_ssh_key` : "Cle SSH" -> "Cle SSH Keypair" (FR), "SSH Key" -> "SSH Keypair" (EN).

### CI

- Fix `import json` (F821) + suppression des `import json` locaux qui
  shadowent le global (F823) dans `backend/scheduler.py`.
- Pipeline GitHub Actions a 11 jobs reste vert.

---

## [1.16.1] - 2026-04-21

### Fix : auto-register de la cle legacy Config.API_KEY

Bug decouvert en prod : des qu'un admin creait sa premiere entree dans
`api_keys` via l'UI, le proxy PHP (qui envoie toujours `Config.API_KEY`
depuis `srv-docker.env`) se cassait silencieusement. Le fallback legacy de
`_validate_api_key_from_db` n'est actif que quand la table est vide (v1.14.4
design), donc tous les appels backend retournaient 401 "Non autorise" sans
aucune trace visible cote UI.

Symptomes observes : dashboard SSH audit vide, compliance report a 0
partout, /cve_trends refuse, etc.

Correctif :
- Migration `040_api_keys_auto_generated.sql` :
  * Ajoute colonne `auto_generated TINYINT(1)` sur `api_keys`.
  * Ajoute `UNIQUE KEY uk_api_keys_name` pour supporter INSERT IGNORE.
  * Backfill : tagge `proxy-internal-legacy` existante (patch manuel
    eventuel) en `auto_generated=1`.
- `www/adm/api_keys.php` (handler create) :
  * Apres chaque creation de cle utilisateur, `INSERT IGNORE` d'une entree
    `proxy-internal-legacy` (SHA256 de `Config.API_KEY`, scope=NULL,
    `auto_generated=1`). Idempotent, zero-downtime.
- UI `/adm/api_keys.php` :
  * Banniere jaune tant qu'une cle `auto_generated=1` active existe.
  * Badge `AUTO` sur la ligne concernee dans le tableau.

Test live : instance Docker locale - proxy PHP -> Python passe a nouveau
apres ajout de la cle auto-generee, GET /test retourne 200.

---

## [1.16.0] - 2026-04-21

### Feat : Profils de supervision (catalogue metadata)

Evite la saisie libre de HostMetadata/Server/ServerActive par machine. L'admin
cree un catalogue (LinuxInterne, LinuxExterne...) une fois, les autres admins
assignent chaque serveur via un dropdown.

- Migration `039_supervision_metadata_profiles.sql` :
  * Table `supervision_metadata_profiles(platform, name, description,
    host_metadata, zabbix_server, zabbix_server_active, zabbix_proxy,
    listen_port, tls_connect, tls_accept, notes)`.
  * Table `machine_supervision_profile(machine_id, platform, profile_id)`
    avec FK CASCADE pour decouplage propre.
  * Seed : 2 profils par defaut `LinuxInterne` / `LinuxExterne`.
- Routes Flask dans `backend/routes/supervision.py` :
  * `GET/POST /supervision/profiles` (permission `can_manage_supervision`).
  * `DELETE /supervision/profiles/<id>`.
  * `GET/POST/DELETE /supervision/machines/<mid>/profile` : assignation.
- `_build_config_lines()` refactore pour gerer la precedence
  `overrides > profil > global`.
- Substitution `{machine.name}` et `{machine.ip}` etendue a **tous** les
  overrides (plus seulement `Hostname`). Accepte aussi les cles d'override
  libres validees par `_SAFE_PARAM_RE`.
- UI : nouvel onglet "Profils" dans `www/supervision/index.php` + dialogue
  CRUD + lang FR/EN.
- Test E2E : `tests/e2e/go-supervision-profiles.mjs` couvre
  creation/edition/suppression + verification compte non-privilegie.

### Fix : Ubuntu/Debian support generique pour agent Zabbix

`backend/routes/supervision.py` detectait uniquement `ubuntu20.04` /
`ubuntu22.04`. Ubuntu 24.04 LTS tombait en fallback sur 20.04 (repo
inexistant → install silencieusement echouee).

- Debian : extraction du MAJOR, plancher 11, pas de plafond → supporte
  debian11+ y compris versions futures.
- Ubuntu : extraction `X.Y`, snap sur l'annee paire .04 la plus proche vers
  le bas (24.04, 26.04, etc.). Versions non-LTS retombent sur la LTS
  precedente, alignee avec la politique Zabbix.

### Fix : Documentation - lien repository

`/documentation.php#contribute` pointait toujours sur
`github.com/Timikana/Gestion_SSH_KEY`. Corrige en `github.com/Timikana/rootwarden`.

### Chore : purge em-dash U+2014

Caractere `-` em-dash remplace par le hyphen-minus dans **1712 fichiers**
(code, docs, lang, commentaires). Alignement stylistique, aucun impact
fonctionnel.

### Branches merged supprimees

- Local : `feature/bashrc-deploy`, `feature/brute-force-protection`,
  `feature/graylog-wazuh`, `refactor/rename-rootwarden`.
- Remote : `origin/feature/brute-force-protection`,
  `origin/feature/graylog-wazuh`, `origin/feature/supervision`.

---

## [1.15.1] - 2026-04-21

### CI : fix SAST bandit (config non chargee + skips ajustes)

Correction du job `sast-python` ajoute en v1.14.3 qui bloquait sur le merge
`graylog-wazuh` -> main.

Bugs :
- `backend/bandit.yml` n'etait PAS charge : la commande CI n'avait pas
  l'option `-c bandit.yml`. Seul `--exclude` etait pris en compte → tous
  les skips documentes etaient inertes.
- Les skips initiaux (B101, B404, B603, B607) ne couvraient pas les vrais
  patterns projet restants (paramiko, temp files distants, pycryptodome,
  f-strings SQL whitelistees).

Fixes :
- `.github/workflows/ci.yml` : ajoute `-c bandit.yml` a la commande.
- `backend/bandit.yml` : etend `skips:` avec justifications
  * B108 - temp files `/tmp/.rw_stream_*` CIBLENT les serveurs distants
    via SSH (pas le host backend), pas de lecture locale non-privilegiee
  * B601 - paramiko `exec_command`, pattern fondateur du projet, entrees
    validees en amont par shlex.quote + whitelists regex ; B602 (shell=True
    sur subprocess local) reste actif
  * B413 - `Crypto.Cipher.AES` : on utilise pycryptodome (drop-in du
    pyCrypto deprecated, meme namespace) ; bandit ne distingue pas les deux
  * B507 - paramiko `AutoAddPolicy` : TOFU assume sur la gestion de parc,
    host keys persistees via volume Docker `known_hosts`
  * B608 - f-strings SQL detectees ciblent uniquement des noms de tables
    et colonnes whitelistees cote app (ORDER BY dans liste fermee) ; toutes
    les VALEURS utilisent des prepared statements `%s` mysql-connector
- B602 (subprocess shell=True), B105/B106 (passwords hardcodes), B303-B306
  (cryptos faibles) restent actifs et bloquants.
- B103 ajoute aux skips : `chmod 0o755` sur `PLATFORM_SSH_DIR` est
  intentionnel (dossier traversable par le process container uid non-root).

### CI : fix gitleaks faux positif

La rule custom `rootwarden-example-secret` matchait "replacement" dans
la prose des docs via `replace[_-]?me` sans word boundary. Ajout de `\b`
autour + `backend/bandit.yml` ajoute a l'allowlist paths (fichier de
config scanner, pas du code applicatif).

Version 1.15.0 -> 1.15.1 (patch CI).

---

## [1.14.7] - 2026-04-20

### RGPD : export JSON des donnees personnelles + anonymisation admin

Reponse au gap #15 de l'audit DevSecOps. Conformite RGPD art. 15
(droit d'acces), art. 17 (effacement), art. 20 (portabilite).

Nouveau endpoint self-service /profile/export.php :
- Acces : n'importe quel user connecte, dump de SES donnees uniquement
- Format JSON UTF-8 telechargeable (Content-Disposition attachment)
- Contenu : user profile, permissions, user_machine_access, user_logs
  (avec 16 premiers chars du self_hash pour tracabilite), login_history,
  active_sessions (session_id masque), notification_preferences,
  password_history (metas changed_at seulement, PAS les hashes).
  Superadmin : inclut aussi les api_keys creees (sans le secret).
- Audit log [rgpd] de chaque demande d export
- Filename : rootwarden-export-user-{id}-{YYYYMMDD-HHMMSS}.json

Nouveau endpoint admin /adm/api/anonymize_user.php :
- Acces : superadmin uniquement, CSRF obligatoire
- Soft-delete preservant l'integrite des audit logs pour tracabilite
  legale (interet legitime de securite, RGPD art. 17.3.e)
- Effacement : name -> "deleted-{id}", email/company/ssh_key/totp_secret
  = NULL, password = NULL, active = 0, sudo = 0
- Revocation : active_sessions, remember_tokens, password_history,
  notification_preferences, permissions, user_machine_access
- Protections :
  * Pas d'auto-anonymisation (user ne peut s'anonymiser lui-meme)
  * Pas d'anonymisation du dernier superadmin actif
- Audit log [rgpd] avec original_name + id
- user_logs et login_history CONSERVES (tracabilite securite)

UI profile.php : nouvelle card "Donnees personnelles (RGPD)" avec
bouton d'export + note explicative.

i18n FR+EN parite 58=58 :
- profile.rgpd_title
- profile.rgpd_desc
- profile.btn_rgpd_export
- profile.rgpd_export_note

Version 1.14.6 -> 1.14.7.

---
## [1.14.6] - 2026-04-20

### Password history + HIBP k-anonymity check

Reponse au gap #14 de l'audit DevSecOps. La politique de complexite
(15 chars + 4 classes) existait deja mais rien n'empechait un user de
remettre son ancien password lors d'un changement force, ni de choisir
un mot de passe present dans les fuites publiques.

Migration 038 :
- Table password_history(user_id, password_hash, changed_at) + index user_changed + FK ON DELETE CASCADE

Nouveau helper www/auth/password_policy.php :
- passwordPolicyCheckComplexity() : 15 chars + 4 classes (existait, centralise)
- passwordPolicyCheckHistory() : refuse reutilisation des 5 derniers
  (verifie aussi vs le hash courant)
- passwordPolicyCheckHIBP() : k-anonymity via api.pwnedpasswords.com
  * Opt-in via env HIBP_ENABLED=true (off par defaut)
  * Seuil configurable via HIBP_THRESHOLD (defaut 10 fuites)
  * SHA1 + envoi des 5 premiers hex uniquement (privacy-preserving)
  * Timeout 3s, fail-open si API injoignable (pas de blocage user)
- passwordPolicyValidateAll() : pipeline en une passe
- passwordPolicyRecordOld() : archive l'ancien hash dans password_history
  + purge automatique a 10 entrees par user (rotation)

Integration :
- www/profile.php : le password change passe par la politique complete
- www/auth/reset_password.php : idem pour le flow forgot password (la
  check existante strlen<8 est remplacee par la politique complete,
  coherence FR/EN message)

i18n FR+EN parite 54=54 :
- profile.error_password_reuse
- profile.error_password_pwned

Tests manuels : un user qui tente de remettre son password courant est
refuse avec "deja utilise recemment". Si HIBP_ENABLED=true, un password
commun (ex: "Password123!") est refuse avec "apparait dans une fuite".

Version 1.14.5 -> 1.14.6.

---

## [1.14.5] - 2026-04-20

### Session revocation server-side + "Deconnecter les autres sessions"

Reponse au gap #9 de l'audit DevSecOps. Correction importante :
le profile.php avait DEJA un bouton "Revoquer" qui DELETE de active_sessions,
mais verify.php ne verifiait JAMAIS active_sessions → la revocation etait
sans effet cote serveur. L'utilisateur revoque restait connecte.

Changements :

www/auth/verify.php :
- Apres le check de timeout, AJOUT d'une verification DB :
  `SELECT 1 FROM active_sessions WHERE session_id = ? AND user_id = ?`
- Si absent → session_destroy + redirect login (session revoquee)
- Skip du check si 2fa_required actif (pour ne pas casser le flow login)
- Fail-open en cas d'erreur DB (log error, pas de lockout)

www/auth/functions.php (initializeUserSession) :
- Ajout REPLACE INTO active_sessions apres session_regenerate_id
- Garantit que le nouveau session_id est enregistre cote DB apres 2FA
- Sans ca, le check de verify.php aurait lockout l'utilisateur
  immediatement apres login

www/profile.php :
- Nouveau POST handler revoke_all_others : DELETE sauf session courante
- Bouton UI "🚪 Deconnecter les autres" visible si count(sessions) > 1
- Confirmation explicite
- Audit log via audit_log_raw() (hash chain 036)

i18n FR+EN parite 52=52 :
- profile.btn_revoke_all_others
- profile.confirm_revoke_all_others
- profile.all_others_revoked

Modele d'attaque couvert :
- Vol de cookie session → victime clique "Deconnecter les autres" dans
  profile → le cookie vole est invalide au prochain request
- Auparavant : le DELETE existait mais etait un no-op cote serveur

Version 1.14.4 -> 1.14.5.

---

## [1.14.4] - 2026-04-20

### API keys segmentees avec scope regex + last_used tracking

Reponse au gap #4 de l'audit DevSecOps : un seul API_KEY partage =
compromission = acces backend total sans revocation fine.

Migration 037 :
- Table api_keys(id, name UNIQUE, key_prefix, key_hash CHAR(64), scope_json,
  created_by, created_at, revoked_at, last_used_at, last_used_ip)
- Permission can_manage_api_keys (superadmin auto)

Backend (backend/routes/helpers.py) :
- require_api_key refactore : priorite table api_keys > fallback Config.API_KEY
- _validate_api_key_from_db(raw_key, route_path) :
  - Hash SHA-256 puis lookup
  - Check revoked_at
  - Scope JSON : liste de regex → la route doit matcher au moins 1
  - Update last_used_at + last_used_ip en best-effort (UPDATE separe)
- Mode fallback legacy : si table api_keys vide (premier boot), Config.API_KEY
  reste valide. Des la premiere cle creee, Config.API_KEY devient invalide
  automatiquement - transition zero-downtime.

UI (www/adm/api_keys.php, superadmin + can_manage_api_keys) :
- Creation : genere rw_live_XXXXXX_... (48 hex chars), affiche UNE SEULE FOIS
  le secret en clair + bouton Copier. Stocke le SHA-256.
- Scope : 1 regex par ligne (textarea), validation PHP preg_match avant save
- Revocation : soft-delete via revoked_at = NOW(). Cles revoquees visibles
  mais separees en bas de liste.
- Display : name, prefix (rw_live_XXXX…), scope resume (3 premieres regex),
  created_at, last_used_at + last_used_ip, statut Active/Revoquee

Tests E2E valides :
- Cle in-scope /list_machines → HTTP 200 ✓
- Cle out-of-scope /cve_trends → HTTP 401 ✓
- Cle legacy API_KEY env → HTTP 401 (car table non-vide) ✓
- last_used_at et last_used_ip mis a jour correctement ✓

Audit log : creation et revocation de cle loggees via audit_log() standard
(hash chain 036 → tracabilite forte).

Note compat : les api_proxy.php et consommateurs existants ne cassent pas
au deploy - tant qu'aucune cle n'est creee, la legacy API_KEY fonctionne.
Apres creation de la premiere cle, l'admin DOIT creer une cle nommee
"php-proxy" (ou equivalent) et la configurer dans srv-docker.env pour
remplacer l'ancienne API_KEY. Documente dans README.

Version 1.14.3 -> 1.14.4.

---

## [1.14.3] - 2026-04-20

### CI - SAST + SCA + secrets scan + Trivy filesystem

Reponse au gap #7 de l'audit DevSecOps. Note : Trivy image scan et
auto-tagging existaient deja dans `.github/workflows/ci.yml`. Ce qui
manquait (ajoute ici) : secrets commit scan, SAST Python, SCA Python + PHP,
et Trivy fs (scan repo en amont des images).

5 nouveaux jobs CI :
- **secrets-scan** (gitleaks) - scanne tous les commits (fetch-depth: 0)
  pour detecter clef AWS/GitHub/Stripe/Slack/SSH committee par accident.
  Bloquant sur PR et main.
- **sast-python** (bandit[toml]) - SAST Python avec config
  `backend/bandit.yml` (skip B101/B404/B603/B607 car patterns legitimes
  du projet, B608 conserve actif). Warning en PR, bloquant sur main.
- **sca-python** (pip-audit) - CVE check sur requirements.txt fige.
  Warning en PR, strict sur main.
- **sca-php** (composer audit --locked) - CVE check sur composer.lock.
  Warning en PR, strict sur main.
- **trivy-fs** (aquasecurity/trivy-action) - scan repo (requirements,
  composer.lock, Dockerfiles, docker-compose, secrets, misconfig IaC).
  Complement au `security-scan` existant qui ne scanne que les images
  apres build.

Configuration :
- `.gitleaks.toml` : baseline par defaut + allowlist des fichiers
  `.example`, README, CHANGELOG, helpers.mjs (TOTP de test documente),
  vendor/, backend/tests/. Regex pour filtrer les placeholders
  `change_me`, `replace_me`, etc.
- `backend/bandit.yml` : skips documentes des regles non-pertinentes
  pour ce projet (subprocess SSH legitime, assert en non-test).

Chainage :
- `auto-tag` depend desormais de `[build-docker, security-scan,
  secrets-scan, sast-python, sca-python, sca-php, trivy-fs]` → une
  fuite de secret, un CVE critique ou une vuln filesystem empeche le
  tag automatique.

Version 1.14.2 -> 1.14.3.

---

## [1.14.2] - 2026-04-20

### Audit log tamper-evident - hash chain SHA2-256

Reponse au gap #3 de l'audit DevSecOps (2026-04-20) : la table user_logs
etait alterable silencieusement en cas de compromission DB. Chaque ligne
est desormais scellee par une chaine de hash SHA2-256 detectable en cas
de modification.

Migration 036 :
- user_logs.prev_hash CHAR(64), user_logs.self_hash CHAR(64)
- Index idx_self_hash (id, self_hash) pour LAG rapide

Algo :
- self_hash = SHA2-256( prev_hash | user_id | action | unix_ts )
- prev_hash = self_hash de la ligne precedente (ORDER BY id DESC LIMIT 1)
- Premiere ligne : prev_hash = 'GENESIS' (constante)

Implementation app-level (pas de trigger MySQL - contrainte SUPER
privilege dans le container). Le hash est calcule par :
- PHP : nouveau helper audit_log_raw() dans www/adm/includes/audit_log.php
  + audit_log() existant refactore pour passer par audit_log_raw
- Refactoring de 4 INSERTs directs vers le helper :
  www/auth/login.php (connexion reussie, spraying, verrouillage) et
  www/adm/api/unlock_user.php (deverrouillage)

Endpoints :
- POST /adm/api/audit_seal.php : scelle les lignes orphelines (self_hash
  NULL venant d'INSERTs legacy) en continuant la chaine existante.
  GET = dry-run (compte sans modifier)
- GET /adm/api/audit_verify.php : walks toute la chaine, recompute chaque
  hash, signale la PREMIERE incoherence (MISMATCH ou PREV_BROKEN).
  Superadmin-only, read-only.

UI (www/adm/audit_log.php) - superadmin uniquement :
- Bouton "🔒 Verifier integrite" → affiche status chaine (OK / BROKEN)
  avec id + type de l'erreur
- Bouton "🖋 Sceller orphelines" → seal des lignes legacy

Modele d'attaque couvert :
- Modification action/user_id/created_at d'une ligne scellee → detection
  immediate au verify (hash ne matche plus)
- Suppression d'une ligne → detection (prev_hash de la suivante ne matche
  plus la nouvelle ORDER BY)
- Insertion d'une ligne au milieu → detection (prev_hash ne matche plus)

Limitations connues (documentees dans l'audit) :
- Un attaquant avec acces DB + lecture du code source peut recalculer la
  chaine entiere apres modification. Contre-mesure future : sceller le
  hash de tete dans un KMS externe (ou exporter WORM off-site).

i18n FR/EN parite 274=274 : nouvelles cles audit.btn_verify /
audit.btn_verify_tip / audit.btn_seal / audit.btn_seal_tip.

Tests manuels :
- Insert 3 lignes via helper → chain valide OK
- UPDATE action d'une ligne → verify detecte MISMATCH sur cette ligne
- DELETE d'une ligne → verify detecte PREV_BROKEN sur la suivante

Version 1.14.1 -> 1.14.2 (patch de securite).

---

## [1.14.1] - 2026-04-20

### Hardening auth : lockout per-user + backoff progressif + detection password spraying

Couche ajoutee au-dessus du rate limiting IP existant (`login_attempts`,
5/10min) pour couvrir les angles morts identifies dans l'audit DevSecOps
du 2026-04-20 (finding #1).

- **Per-user lockout** : colonnes `users.failed_attempts` + `users.locked_until`
  + `users.last_failed_login_at` (migration 035). Le compteur s'incremente a
  chaque echec et verrouille le compte avec un **backoff progressif** :
  3 echecs = 1min, 4 = 5min, 5 = 15min, 6 = 1h, 7+ = 4h. Reset a 0 au succes.
- **Password spraying detection** : `login_attempts.username` + `success`
  (migration 035) permettent de detecter une IP testant >= 5 usernames
  distincts en 10min. Audit log `[security]` prefix au superadmin.
- **Notification ecrit dans `user_logs`** au 5eme echec consecutif d'un user,
  avec IP source.
- **Oracle-safe** : password non verifie si `locked_until > NOW()` - evite
  d'exposer une difference de timing entre "password correct + verrou" et
  "password incorrect + verrou".
- **Admin UI** (superadmin only) :
  - Badge rouge `🔒 Verrouille X min` + badge orange `N ⚠` (3+ echecs) dans
    la liste des users (`adm/includes/manage_users.php`)
  - Bouton `🔓 Deverrouiller` cree la route `POST /adm/api/unlock_user.php`
    → reset `failed_attempts = 0, locked_until = NULL` + audit log
- **i18n FR/EN** parite 270=270 (admin) et 37=37 (login), nouvelles cles :
  `login.error_user_locked`, `users.badge_locked`, `users.btn_unlock`, etc.

Note : le rate limiting IP existant (`login_attempts`, 5/10min) est conserve
inchange - il agit en premiere ligne contre les attaques distribuees.

---

## [1.15.0] - 2026-04-20

### Module Graylog - forwarding rsyslog + templates editables

Approche rsyslog native (pas de sidecar Graylog) : plus simple, footprint
minimal, streams et extractors geres cote admin directement sur Graylog.

- **Nouveau blueprint Flask** `backend/routes/graylog.py` avec 9 routes :
  `GET/POST /graylog/config`, `GET /graylog/servers`, `POST /graylog/deploy|test|uninstall`,
  `GET /graylog/templates`, `GET/POST/DELETE /graylog/templates/<name>`.
- **Deploiement via SSH root** : installe rsyslog si absent (`apt install rsyslog`,
  `rsyslog-gnutls` si protocol=tls), ecrit `/etc/rsyslog.d/99-rootwarden-graylog-forward.conf`
  avec la regle `*.* @host:port` adaptee au protocole, valide syntaxe (`rsyslogd -N1`),
  redemarre `systemctl restart rsyslog`.
- **4 protocoles supportes** : UDP (default 514, lossy), TCP (514, reliable),
  TLS (6514, chiffre, CA configurable), RELP (20514, ACK applicatif via omrelp).
- **Rate limiting optionnel** : `$SystemLogRateLimitBurst` / `Interval`.
- **3 tables** : `graylog_config` (host, port, protocol, TLS CA, rate limit),
  `graylog_templates` (snippets rsyslog editables via UI, 4 seeds dont
  apache-access, mysql-slow, auth-log), `graylog_rsyslog` (etat par machine).
- **Templates** : chaque template est pousse dans
  `/etc/rsyslog.d/50-rootwarden-<name>.conf` au deploiement si `enabled=TRUE`.
- **Test de forwarding** : `logger -t rootwarden-test` depuis le serveur distant
  avec tag horodate a rechercher dans Graylog Search.
- **UI 4 onglets** : Configuration (host/port/proto/TLS), Deploiement
  (tableau serveurs + deploy/test/uninstall), Templates (liste + editeur +
  toggle enabled + save/delete), Historique.
- **Permission `can_manage_graylog`** (migration 033).

### Module Wazuh - agent SIEM + rules/decoders/CDB editables

- **Nouveau blueprint Flask** `backend/routes/wazuh.py` avec 11 routes :
  `GET/POST /wazuh/config`, `GET /wazuh/servers`, `POST /wazuh/install|uninstall|restart|group`,
  `GET/POST /wazuh/options`, `GET /wazuh/rules`, `GET/POST/DELETE /wazuh/rules/<name>`.
- **Installation agent via SSH** : repo Wazuh + `apt install wazuh-agent` avec
  `WAZUH_MANAGER` / `WAZUH_REGISTRATION_PASSWORD` / `WAZUH_AGENT_GROUP` en env.
- **4 tables** : `wazuh_config` (manager IP/port, password enrolement chiffre,
  default group, API manager), `wazuh_rules` (rules/decoders/CDB editables avec
  validation `xmllint` backend), `wazuh_agents` (etat agent par machine),
  `wazuh_machine_options` (FIM paths, active response, SCA, rootcheck, log_format,
  syscheck_frequency).
- **UI 5 onglets** : Configuration (manager + API), Deploiement (tableau agents
  avec badges statut + install/restart/uninstall/setgroup), Options (FIM paths
  par serveur + toggles SCA/rootcheck/active response), Rules & Decoders
  (editeur XML avec validation xmllint), Historique.
- **Permission `can_manage_wazuh`** (migration 034).

### Securite

- Zero trust : `@require_api_key` + `@require_role(2)` + `@require_permission`
  + `@require_machine_access` + `@threaded_route` sur toutes les routes
- Tous les passwords chiffres via `Encryption` (prefix `aes:`, label HKDF
  `rootwarden-aes`) - jamais renvoyes au client en clair
- Validation stricte : regex noms (`^[a-zA-Z0-9_-]{1,100}$`), IPs/FQDN, groupes
- Contenu configs/rules transmis exclusivement en base64 via SSH
- Validation `xmllint --noout` pour rules/decoders Wazuh
- Validation YAML best-effort pour collectors filebeat Graylog
- audit_log (prefix `[graylog]` / `[wazuh]`) sur chaque action

### Cohérence

- 2 nouvelles cards dans le dashboard (conditionnelles sur permissions)
- Entrees sidebar desktop + mobile + case manage_permissions
- API proxy allowlist mise a jour (2 nouvelles permissions)
- Version `1.14.0` → `1.15.0`

---

## [1.14.0] - 2026-04-20

### Module Bashrc - deploiement standardise du .bashrc par utilisateur + template editable

- **Template editable via UI** - Migration 032 cree la table
  `bashrc_templates(name, content, updated_by, updated_at)`. L'onglet "Template"
  devient un editeur textarea live : chargement GET, modification, bouton
  Sauvegarder (+ indicateur "modifie"), bouton "Annuler modifs". Routes
  `GET /bashrc/template` et `POST /bashrc/template`.
- **Fallback fichier** - Au premier boot, le contenu du fichier
  `backend/templates/bashrc_standard.sh` est auto-seed en BDD. Ensuite la
  BDD fait foi.
- **Cleanup legacy** - Suppression de `deploy_bashrc` (checkbox admin) et
  `zabbix_rsa_key` (champ formulaire + fallback PSK) devenus obsoletes avec
  les nouveaux modules `/bashrc/` et `supervision_config.tls_psk_value`.
  Colonnes DB laissees dormantes (pas de DROP pour preserver la compat prod).

### Module Bashrc - deploiement standardise du .bashrc par utilisateur

- **Nouveau blueprint Flask** - `backend/routes/bashrc.py`. 6 routes :
  `GET /bashrc/users`, `POST /bashrc/prerequisites`, `POST /bashrc/preview`,
  `POST /bashrc/deploy`, `POST /bashrc/restore`, `GET /bashrc/backups`.
  Decorateurs : `@require_api_key`, `@require_role(2)`, `@require_permission('can_manage_bashrc')`,
  `@require_machine_access`, `@threaded_route`.
- **Template versionne** - `backend/templates/bashrc_standard.sh` (v3.0).
  Banniere figlet, tableau sysinfo 3/4 lignes (auto HA keepalived), 10 alertes
  (disque, RAM, swap, MAJ securite, reboot requis, services failed, zombies,
  tentatives SSH, reboot recent, session root), prompt git-aware, 40+ alias,
  10 fonctions utilitaires, sourcage `~/.bashrc.local`.
- **Mode merge intelligent** - Detecte les blocs `# >>> USER CUSTOM >>>` dans
  l'ancien .bashrc et les reinjecte dans `~/.bashrc.local` (sourcee section 13).
- **Prerequis figlet** - Detection + installation `apt install -y figlet` via
  `execute_as_root` (meme chemin que le module `updates`).
- **Idempotence** - Pas de backup ni de reecriture si sha256 identique au template.
- **Securite** - Usernames valides `^[a-z_][a-z0-9_-]*$`, contenu transfere
  exclusivement en base64 (`printf '%s' '{b64}' | base64 -d > ~/.bashrc`),
  validation syntaxique `bash -n` post-deploiement, backup `.bashrc.bak.YYYYMMDD_HHMMSS`
  avec `chmod 600`.
- **Frontend** - `www/bashrc/index.php` avec 3 onglets (Deploiement / Historique /
  Template). Tableau utilisateurs : UID, home, shell, taille, sha8, status,
  badge custom detecte. Modal de preview avec diff colorise (unified diff).
- **Migration 031** - Colonne `can_manage_bashrc` dans `permissions`.
- **i18n FR + EN** - `www/lang/{fr,en}/bashrc.php` + cles nav + perms dans admin.php.
- **Audit log** - Chaque `install_figlet`, `deploy`, `restore` journalise dans `user_logs`.
- **Tests E2E** - `tests/e2e/go-bashrc.mjs` : login superadmin, select serveur,
  preview dry_run, deploy mode merge, verify backup via SSH (pas docker exec),
  restore, verification `bash -n` post-deploiement.

---

## [1.13.1] - 2026-04-12

### Preferences de notifications email par utilisateur

- **Table `notification_preferences`** - Migration 027. Chaque utilisateur peut etre
  abonne a 6 types d'evenements : scan CVE, audit SSH, alertes securite, conformite,
  backups, mises a jour. Canaux : email, in-app, ou les deux.
- **Admin > Acces & Permissions** - Nouvelle section "Notifications email" avec le meme
  pattern card accordeon que les droits fonctionnels. Grille de checkboxes par user,
  groupees par categorie (Securite / Rapports), toggle htmx, Tout activer/desactiver.
- **Notifications ciblees** - Les scans CVE et audits SSH envoient maintenant des
  notifications in-app uniquement aux users abonnes (via `notify_subscribed()`),
  avec filtrage par `machine_access` pour les users role=1.
- **Alertes securite automatiques** - CVE CRITICAL et grades SSH D/E/F declenchent
  une notification `security_alert` en plus de la notification standard.
- **Helper `get_subscribed_emails()`** - Retourne les emails des users abonnes a un
  type d'evenement, filtre par machine_access. Pret pour l'envoi SMTP cible.
- **i18n FR + EN** - Fichiers `lang/fr/notif_pref.php` et `lang/en/notif_pref.php`.

### Migration stack - PHP 8.4 / Python 3.13 / MySQL 9.2

- **PHP 8.2.30 → 8.4.20** - Image Docker `php:8.4-apache`. Aucun breaking change
  detecte dans le code (signatures nullable deja conformes `?Type`). Extensions
  inchangees : gd, imagick, pdo_mysql, mysqli, curl.
- **Python 3.12.13 → 3.13.13** - Image Docker `python:3.13-slim` (builder + runtime).
  Toutes les dependances pip installees sans erreur. 169 tests pytest passes.
- **MySQL 9.1.0 → 9.2.0** - Upgrade in-place automatique du data dictionary
  (v90000 → v90200) et du serveur (v90100 → v90200). Volume de donnees compatible.
- **CI/CD** - `python-version` 3.12 → 3.13, `php-version` 8.2 → 8.4 dans
  `.github/workflows/ci.yml`.

### Hardening securite post-migration

- **Apache TLS** - Force TLS 1.2+, cipher suite ECDHE+AESGCM/CHACHA20,
  `SSLCompression off`, `SSLHonorCipherOrder on`. Negocie TLS 1.3 + AES-256-GCM.
- **CSP** - `Content-Security-Policy` ajoute sur les 2 templates Apache (SSL + HTTP).
  `default-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`.
- **Permissions-Policy** - Desactive geolocation, camera, microphone, payment, USB.
- **ServerTokens Prod + ServerSignature Off** - Version Apache masquee dans les
  headers HTTP et les pages d'erreur.
- **php.ini** - `open_basedir` restreint a `/var/www/html:/var/www/sessions:/tmp`,
  `allow_url_include = Off` explicite, `E_STRICT` retire de `error_reporting` (supprime en 8.4).
- **Python deps pinnees** - flask>=3.0.0, werkzeug>=3.0.0, flask-cors>=4.0.0,
  marshmallow>=3.20.0, cryptography>=42.0.0, requests>=2.31.0.
- **MySQL 9.2 compat** - `ORDER BY` ajoute sur `GROUP BY status` dans cve_remediation
  (ordre non garanti en MySQL 9.2 sans ORDER BY explicite).
- **Docker** - `composer:latest` remplace par `composer:2` (image pinnee).

---

## [1.13.0] - 2026-04-12

### Planification SSH Audit + Tendances + Export PDF

- **Planification scans SSH Audit** - Table `ssh_audit_schedules` avec expressions cron.
  Le scheduler execute automatiquement les scans SSH sur le parc (par tag, env, ou all).
  Routes CRUD : `/ssh-audit/schedules` GET/POST/DELETE/toggle.
- **Tendances SSH Audit** - Route `/ssh-audit/trends` retourne les scores moyens sur
  30 jours (global ou par machine). Pret pour graphiques frontend.
- **Export PDF compliance** - Bouton "Export PDF" via dompdf, rapport A4 paysage avec
  toutes les sections : resume, CVE, utilisateurs, SSH audit, supervision, hash SHA-256.
- **Dashboard enrichi** - 6 cards (ajout SSH Audit score A-F + Agents deployes),
  raccourcis Supervision et SSH Audit dans les acces rapides.
- **Compliance report enrichi** - Sections SSH Audit (scores par serveur) et Supervision
  (badges multi-agent par serveur) ajoutees. Resume executif 6 cards.

### Audit securite global (68 failles corrigees)

- 11 CRITICAL, 22 HIGH, 35 MEDIUM corriges sur tout le projet
- Injection shell pubkey SSH, auth manquante, str(e) info leak, XSS onclick, SQL dynamique
- Voir commit `a282f4d` pour le detail complet

### Nouveau module Supervision multi-agent

**Extraction complete de Zabbix du module Updates** vers un module autonome `/supervision/`
qui supporte 4 plateformes de monitoring : Zabbix, Centreon, Prometheus Node Exporter et Telegraf.

#### Architecture

- **Backend `routes/supervision.py`** - Routes generiques multi-agent via `/{platform}/deploy`,
  `/{platform}/version`, `/{platform}/uninstall`, `/{platform}/reconfigure`,
  `/{platform}/config/read`, `/{platform}/config/save`, `/{platform}/backups`,
  `/{platform}/restore`. Registre d'agents (`AGENT_REGISTRY`) avec les specs de chaque
  plateforme (service, config path, commandes install/version/uninstall).
- **Table `supervision_agents`** - Tracking multi-agent par serveur (machine_id + platform).
  Un serveur peut avoir Zabbix ET Prometheus ET Telegraf en meme temps. Badges visuels
  dans le tableau (Z=violet, C=rouge, P=orange, T=bleu).
- **Table `supervision_config`** - Configuration globale par plateforme (colonne `platform`).
  Chaque agent a ses propres parametres : Zabbix (Server, TLS/PSK, metadata),
  Centreon (host gRPC, port 4317), Prometheus (listen address, collectors),
  Telegraf (InfluxDB v2 URL/token/org/bucket, inputs).
- **Table `supervision_overrides`** - Surcharge par serveur (Hostname, ServerActive, etc.).
- **Permission `can_manage_supervision`** - Admin + superadmin. Interface dans la page
  d'administration des permissions.

#### Frontend

- **Selecteur de plateforme** en haut a droite - switch instantane entre Zabbix/Centreon/
  Prometheus/Telegraf. Change dynamiquement le formulaire de config, les couleurs des
  boutons, le badge plateforme, le compteur d'agents et le chemin du fichier editeur.
- **3 onglets** - Configuration globale (formulaire specifique par agent), Deploiement
  agents (tableau 40+ serveurs avec badges multi-agent, filtre, scroll sticky, actions
  masse), Editeur de configuration distant (load/save/backup/restore).
- **Badges multi-agent** dans le tableau - Chaque serveur affiche tous ses agents
  installes avec version (ex: "Z 7.0.13 | P 1.8.2 | T 1.33.0").
- **Bouton "Scanner tous les agents"** - Detection des 4 plateformes en une passe.
- **Compteur** - "12/41 serveurs avec zabbix" adapte a la plateforme active.
- **UX 40+ serveurs** - Thead sticky, scroll smooth, filtre de recherche, compteur
  de selection, detection auto des versions apres deploiement.

#### Deploiement agents

- **Zabbix Agent 2** - Repo officiel, paquet + plugins, config INI, PSK chiffre en DB,
  streaming SSH temps reel. Supporte Debian 11/12/13 et Ubuntu 20.04/22.04.
- **Centreon Monitoring Agent** - Repo packages.centreon.com, config YAML, gRPC port 4317.
- **Prometheus Node Exporter** - Paquet apt standard, config flags systemd, pull-based.
- **Telegraf** - Repo InfluxData, config TOML, outputs InfluxDB v2 ou Prometheus format.

#### Technique

- **Migrations** - `022_supervision.sql` (tables config + overrides + permission),
  `023_supervision_multi_agent.sql` (colonne platform + colonnes Centreon/Prometheus/Telegraf),
  `024_supervision_agents.sql` (table supervision_agents + migration donnees Zabbix).
- **Retrocompat** - L'ancienne route `/update_zabbix` redirige (307) vers `/supervision/zabbix/deploy`.
- **i18n** - 107+ cles FR + EN dans `lang/fr|en/supervision.php`.
- **Menu sidebar** - Lien Supervision, raccourci clavier `g v`.
- **Health check** - 6 routes supervision testees dans le diagnostic.
- **Health check** - 6 nouvelles routes testees dans le diagnostic.

---

## [1.12.0] - 2026-04-11

### Rework complet authentification et controle d'acces

- **ZERO TRUST SESSION** - `checkAuth()` verifie desormais en DB que l'utilisateur
  existe, est actif (`active=1`), et synchronise le `role_id` session/DB a chaque requete.
  Un user desactive entre deux requetes est immediatement deconnecte.
- **`checkPermission()` verifie en DB** - Plus jamais de lecture `$_SESSION['permissions']`
  pour une decision de securite. Combine permissions permanentes + temporaires non expirees.
  Met a jour le cache session apres chaque check. Log les refus dans `user_logs`.
- **`api_proxy.php` securise** - Le `role_id` transmis au backend Python est verifie en DB
  (plus lu depuis la session). Nouveau header `X-User-Permissions` avec les permissions JSON.
- **Backend Python renforce** - Nouveau decorateur `@require_permission('can_xxx')` qui
  parse le header `X-User-Permissions`. Logging des refus d'acces (IP + user_id + route).
- **Superadmin toujours 13/13** - Les superadmins ont toutes les permissions par bypass.
  Leurs permissions sont affichees comme toujours cochees et non-editables dans l'interface.
  L'API rejette toute tentative de modification.
- **Anti-escalation renforcee** - Ajout de protections self-edit sur tous les endpoints
  admin : `update_permissions`, `toggle_sudo`, `toggle_user`, `update_user`, `update_user_status`.
  Protection dernier superadmin actif sur `toggle_user` et `delete_user`.
- **CSRF unifie** - `checkCsrfToken()` centralise supporte POST body, header `X-CSRF-TOKEN`,
  et body JSON (`php://input`). Tous les endpoints utilisent la fonction centralisee.
  Corrige une comparaison timing-unsafe (`!==`) dans `update_server_access.php`.
- **Pattern uniforme** - Toutes les pages utilisent `checkAuth([ROLE_*])` + `checkPermission()`.
  Constantes `ROLE_USER`, `ROLE_ADMIN`, `ROLE_SUPERADMIN` partout (plus de `[1,2,3]` ou `['1','2','3']`).
- **Login durci** - Verification `active=1` avant `password_verify()`. Verification DB
  apres TOTP reussi (user desactive entre login et 2FA = rejete).
- **Logout propre** - Suppression `active_sessions` en DB, cookie secure SameSite=Strict.
- **Remember-me durci** - Restauration force re-2FA + verification user actif en DB.
- **Fix htmx 2.0.4** - `hx-vals="js:{...}"` remplace par `hx-vals` statiques +
  `htmx:configRequest` listener (le prefixe `js:` est casse dans htmx 2.0).

### Fix SSH mode password (`_su_exec`)

- **Approche temp script** - `_su_exec()` ecrit la commande dans `/tmp/.rw_{uuid}.sh`
  et execute `su root -c 'sh /tmp/script.sh'`. Les pipes et redirections fonctionnent
  car `sh` les interprete, pas le PTY. Stdout propre via markers, vrai exit code.
- **`execute_as_root_stream()`** - Meme approche temp script pour le streaming
  (MAJ APT, MAJ SECU). Detection sudo via `sudo -S -p '' true` avec le vrai mot de
  passe (evite les faux positifs de `sudo -n`).
- **PATH complet** - `export PATH=/usr/local/sbin:...:/bin` en tete de chaque script
  (resout `iptables: not found`, `sshd: not found`).
- **Backups sshd_config** - `LC_ALL=C` sur `ls -la` pour forcer les dates en anglais
  (le parsing regex echouait avec les dates en francais "avril").

### CGU et Confidentialite

- **terms.php reecrit** - 8 sections professionnelles (objet, auth 2FA, responsabilites,
  activites interdites, tracabilite, limites, modifications, contact).
- **privacy.php reecrit** - 7 sections RGPD (donnees collectees, finalites, stockage/securite,
  conservation, partage self-hosted, droits, contact DPO) + exercice des droits en ligne.
- **118 cles i18n ajoutees** en parite FR/EN.

### Fichiers modifies

- 53 fichiers PHP/Python/JS modifies, 6 reecrits de zero.
- `backend/ssh_utils.py` : `_su_exec()` + `execute_as_root_stream()` fixes.
- `backend/ssh_audit.py` : `/usr/sbin/sshd -t`, `printf`, CRLF normalisation, `LC_ALL=C`.

---

## [1.11.0] - 2026-04-10

### Gestion des services systemd

- **Nouvelle page `/services/services_manager.php`** - Interface complete de gestion
  des services systemd sur les serveurs Linux distants (equivalent services.msc Windows)
- **Liste des services** - Affiche tous les services systemd avec statut (running/stopped/failed),
  etat au boot (enabled/disabled), description et categorie automatique
- **Actions** - Demarrer, arreter, redemarrer, activer/desactiver au boot depuis l'interface
- **Logs** - Consultation journalctl par service (50/100/200 lignes)
- **Detail service** - Modal avec PID, memoire, uptime, description complete
- **Categorisation automatique** - Web, Base de donnees, Mail, Securite, Monitoring, SSH,
  Systeme, Reseau, Conteneurs, FTP (10 categories)
- **Services proteges** - sshd, systemd-journald, dbus ne peuvent pas etre arretes (anti-lockout)
- **Filtres** - Par statut, par categorie, recherche texte
- **Stats** - Compteurs services actifs/arretes/en echec
- **8 routes API** - /services/list, /status, /start, /stop, /restart, /enable, /disable, /logs
- **Migration 020** - Permission can_manage_services
- **i18n** - 87 cles FR+EN (1148 total)

---

## [1.10.1] - 2026-04-10

### Durcissement securite (pentest interne)

- **force_password_change a l'install** - Le superadmin cree par `install.sh` a desormais
  `force_password_change = 1`. Meme si le mot de passe initial est compromis, l'attaquant
  est bloque sur la page profil et doit le changer (le vrai admin verra la compromission)
- **Masquage mot de passe Docker logs** - Le mot de passe initial n'est plus affiche en clair
  dans `docker logs`. Affichage masque (`sup***min`), mot de passe complet dans
  `/var/www/html/.first_run_credentials` (chmod 600, lisible uniquement depuis le conteneur)
- **start.sh** - Nouveau script de demarrage securise :
  - `chmod 600` automatique sur `srv-docker.env` et certificats
  - Detection des secrets par defaut (SECRET_KEY, API_KEY, DB_PASSWORD, MYSQL_ROOT_PASSWORD)
  - Warning rouge + confirmation avant demarrage si secrets non changes
- **Privileges MySQL restreints** - L'utilisateur applicatif `rootwarden_user` n'a plus
  `ALL PRIVILEGES`. Remplace par : SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX,
  CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE (principe du moindre privilege)
- **INIT_SUPERADMIN_PASSWORD vide par defaut** - Plus de mot de passe previsible
  dans `srv-docker.env`. Si vide, un mot de passe aleatoire 24 chars est genere

### Amelioration UX admin

- **Page Acces & Droits** - Badges (compteurs serveurs/droits) alignes inline avec le nom
  au lieu d'etre pousses a l'extreme droite. Labels clarifies :
  "Voit tout" → "Acces global", "Bypass all" → "Tous les droits",
  "Droits d'acces" → "Droits fonctionnels"
- **Descriptions sections** - Chaque section de la page admin a desormais une ligne
  explicative sous le titre (Attribution des serveurs, Droits fonctionnels)

### Fichiers modifies

- `php/install.sh` - force_password_change + masquage logs + fichier credentials
- `srv-docker.env` - INIT_SUPERADMIN_PASSWORD vide, INIT_ADMIN_PASSWORD supprime
- `srv-docker.env.example` - Warning securite en en-tete (6 points)
- `mysql/init.sql` - GRANT restreints pour rootwarden_user
- `start.sh` - Nouveau script demarrage securise
- `www/adm/includes/manage_access.php` - Alignement + descriptions
- `www/adm/includes/manage_permissions.php` - Alignement + descriptions + labels

---

## [1.10.0] - 2026-04-09

### Gestion Fail2ban

- **Nouvelle page `/fail2ban/fail2ban_manager.php`** - Interface complete de gestion Fail2ban
  sur tous les serveurs geres via SSH
- **Detection automatique des services** - SSH, FTP (vsftpd/proftpd/pure-ftpd), Apache,
  Nginx, Postfix, Dovecot. Affiche les jails disponibles par service detecte
- **Activation/desactivation de jails** - Modal de configuration (maxretry, bantime, findtime),
  ecriture dans `/etc/fail2ban/jail.local` et restart automatique
- **Monitoring IPs bannies** - Vue en temps reel par jail, nombre actuel et total
- **Ban/unban manuel** - Bannir ou debannir une IP depuis l'interface avec confirmation
- **Installation automatique** - Bouton "Installer Fail2ban" si absent sur le serveur
- **Historique d'audit** - Table `fail2ban_history` : chaque ban/unban logge avec auteur
- **Viewer jail.local** - Lecture du fichier de config en read-only
- **Dashboard** - Widget IPs bannies + alerte serveurs sans Fail2ban
- **Permission** - `can_manage_fail2ban` dans le systeme RBAC (11 fichiers)
- **11 routes API** - /fail2ban/status, /jail, /install, /ban, /unban, /restart,
  /config, /history, /services, /enable_jail, /disable_jail
- **Migration 019** - Permission, tables fail2ban_history et fail2ban_status

### Securite comptes utilisateurs

- **Changement de mot de passe obligatoire** - Flag `force_password_change` sur les users.
  Apres creation ou reset admin, l'utilisateur est force de changer son mdp
  a la premiere connexion (bandeau alerte, navigation bloquee)
- **Magic link d'activation** - Les nouveaux utilisateurs recoivent un email avec un lien
  d'activation (token 24h) au lieu d'un mot de passe temporaire en clair.
  L'email affiche les exigences du mot de passe (15+ chars, complexite)
- **Migration 018** - Colonne `force_password_change` sur la table users

### Corrections

- **CVE save en BDD** - `executemany` de mysql-connector ne gerait pas les apostrophes
  dans les summaries CVE. Remplace par `execute()` individuel. Ajout logging
  `_save_scan()` succes/echec
- **CVE datetime serialization** - `scan_date` converti en ISO string avant jsonify
- **CVE loadLastResults()** - Plus de catch vide : erreurs HTTP et JSON loguees en console
- **SMTP plain port 25** - Support relay Exchange Online Protection sans TLS/SSL
  (MAIL_SMTP_TLS=false + port != 465 → SMTP plain). Ajout `MAIL_DEBUG=true`
  pour diagnostiquer les connexions SMTP. Log config SMTP a chaque envoi
- **URL emails** - `forgot_password.php` utilise `URL_HTTPS` env au lieu de `HTTP_HOST`
  (qui retournait localhost:8443 dans Docker)
- **apt force-confold** - Toutes les commandes apt ajoutent
  `-o Dpkg::Options::='--force-confold' -o Dpkg::Options::='--force-confdef'`
  pour eviter les prompts interactifs dpkg sur les fichiers de config modifies
- **Detect apt lock + auto-repair** - Pre-check avant chaque MAJ : detecte si apt/dpkg
  est verrouille, kill les process bloques, supprime les locks, `dpkg --configure -a`
- **Bouton Repair dpkg** - Nouveau bouton rouge dans l'interface MAJ pour reparation manuelle
- **SSH keepalive 30s** - Empeche les timeouts sur les scans CVE longs (1900+ paquets)
- **Proxy timeout 30min** - `api_proxy.php` GET/POST passes de 300s/600s a 1800s

---

## [1.9.1] - 2026-04-08

### Corrections service account + compatibilite zero-password

- **Compte service rootwarden** - Corrections du deploiement :
  - Fix permissions keypair (`chmod 755` dossier, `chown` UID process Hypercorn)
  - Fallback `su -c` : ajout messages francais dans `_SUDO_UNAVAILABLE`
    (`commande introuvable`, `pas dans le fichier sudoers`)
  - Chemins absolus `/usr/sbin/useradd` et `/usr/sbin/visudo` pour `su -c` (PATH minimal)
  - Encodage base64 de `authorized_keys` pour eviter les problemes de quotes `su -c`
  - `chown rootwarden /home/rootwarden` apres `useradd` (su -c cree le home en root:root)
  - `ensure_sudo_installed()` integre au deploiement (installe sudo si absent)
  - `deploy_platform_key` deploie automatiquement le SA dans la foulee
  - `remove_ssh_password` supprime aussi `root_password` (plus besoin avec SA)
  - Bouton "Suppr. pwd" masque tant que SA non deploye
- **configure_servers.py** (deploiement cles SSH) :
  - Support service account : `ssh_connection(service_account=True)`
  - `execute_command_as_root` detecte SSHClient SA et utilise `sudo bash -c` NOPASSWD
  - Protection utilisateurs systeme (`nobody`, `daemon`, `sshd`, `rootwarden`, user SSH)
  - `source` → `.` pour compatibilite POSIX (sh)
  - `load_data_from_db` inclut `service_account_deployed`
- **Routes corrigees** (passwords vides acceptes si keypair/SA deploye) :
  - `iptables.py` : helper `_resolve_ssh_creds()` factorise les 4 routes
  - `cve.py`, `ssh.py preflight_check` : accepte password vide avec keypair
  - `helpers.py` : `server_decrypt_password` retourne `""` au lieu de `None`

### Scan CVE - progression temps reel + seuil par serveur

- **Progression temps reel** (cve_scanner.py) - Events enrichis avec `machine_id`,
  etapes `detect_os`/`packages`/`scan`, `current`/`total`/`percent` par paquet,
  compteur `total_cve_found` en cours de scan
- **Seuil CVSS par serveur** (cve.py) - Route `/cve_scan` accepte `per_machine_cvss`
  (dict `{machine_id: min_cvss}`). Seuil par machine prioritaire sur le global
- **Frontend** (cveScan.js) - Barre de progression avec nom du paquet et pourcentage,
  affichage des etapes initiales (detection OS, recuperation paquets). Dropdown seuil
  inline par serveur, synchro avec le seuil global, persistance localStorage
- **Fix findings invisibles** - Les events `finding` incluent maintenant `machine_id`
  (le JS les ignorait sinon). Corrige le bug "1421 CVE trouvees, 0 affichees"

### Corrections UX/UI

- **Freeze navigation** - `session_write_close()` dans `api_proxy.php` avant curl
  (le lock de session PHP bloquait toutes les requetes pendant les operations longues)
- **Cache JS** - Ajout `?v=filemtime()` sur tous les includes JS externes (cveScan.js,
  iptablesManager.js, sshManagement.js, apiCalls.js, domManipulation.js, admin.js)
  pour eviter les versions en cache apres mise a jour
- **Actualisation apres actions** - `location.reload()` ajoute sur `updateUserStatus`,
  `deleteUser` (doublon supprime dans manage_roles.php), `excludeUser`
- **admin_page.php** - Inclusion de `admin.js` (manquait)
- **Champ Zabbix RSA** - Rendu facultatif dans le formulaire d'ajout/edition serveur
- **Health check** - CVE scan en dry (`machine_id=0`) pour eviter le timeout 10s
- **"SA" renomme "Admin distant"** - Libelle plus clair dans l'UI platform_keys.php
- **Email bienvenue** - PHPMailer (remplace `mail()` natif) a la creation d'utilisateur

---

## [1.9.0] - 2026-04-07

### Suppression des mots de passe hardcodes (install.sh)

- **`php/install.sh`** - Nouveau script de premier demarrage. Genere les mots de passe
  admin/superadmin au premier lancement Docker (aleatoires ou via `INIT_SUPERADMIN_PASSWORD`).
  Hash bcrypt insere en BDD via PHP CLI. Mot de passe affiche dans les logs Docker.
  Flag `/var/www/html/.installed` empeche la re-execution
- **`mysql/init.sql`** - Les hash bcrypt hardcodes sont remplaces par `$PLACEHOLDER$`
  (invalide, aucun login possible sans install.sh). La `SECRET_KEY` peut desormais
  etre n'importe quelle valeur - plus de dependance a une cle de chiffrement fixe
- **`php/entrypoint.sh`** - Appel de install.sh apres Composer, avant la config SSL
- **`php/Dockerfile`** - COPY + chmod de install.sh
- **`srv-docker.env.example`** - Variables `INIT_SUPERADMIN_PASSWORD` et `INIT_ADMIN_PASSWORD`

### Reinitialisation de mot de passe par email

- **Migration 016** - Table `password_reset_tokens` (user_id, token_hash bcrypt,
  expires_at 1h, used_at, ip_address)
- **`www/auth/forgot_password.php`** - Page "Mot de passe oublie". Rate limit 3 demandes
  par IP par heure. Message identique que l'email existe ou non (anti-enumeration).
  Token 256 bits hache en bcrypt avant stockage
- **`www/auth/reset_password.php`** - Validation token (password_verify), nouveau mot de
  passe avec confirmation. Invalide tous les tokens du user apres changement
- **`www/includes/mail_helper.php`** - Wrapper PHPMailer. Lit les env vars SMTP existantes.
  Email HTML responsive avec branding RootWarden (header bleu, bouton CTA, footer)
- **`www/auth/login.php`** - Lien "Mot de passe oublie ?" apres le champ password
- **`www/composer.json`** - Ajout dependance `phpmailer/phpmailer ^6.9`
- **`backend/scheduler.py`** - Purge automatique des tokens expires dans `_purge_old_logs()`

### Compte de service rootwarden (NOPASSWD sudo)

- **Migration 017** - Colonnes `service_account_deployed` et `service_account_deployed_at`
  sur la table `machines`
- **Route `POST /deploy_service_account`** - Deploie un compte Linux `rootwarden` dedie
  sur les serveurs selectionnes : `useradd -r -m -s /bin/bash`, deploiement keypair
  Ed25519 dans `/home/rootwarden/.ssh/`, creation `/etc/sudoers.d/rootwarden` avec
  `NOPASSWD: ALL`, validation `visudo -cf`, test connexion + `sudo whoami`
- **`connect_ssh()`** - Nouveau parametre `service_account`. Si True, tente la connexion
  en tant que `rootwarden` via keypair avant le fallback user/password existant
- **`execute_as_root()` / `execute_as_root_stream()`** - Detectent `_rootwarden_auth_method
  == 'service_account'` et executent `sudo sh -c` sans envoyer de mot de passe
  (NOPASSWD). Pas de PTY, pas de filtrage password - sortie propre
- **24 appels `ssh_session()` mis a jour** - Tous les SELECT machines incluent
  `service_account_deployed`, passe a `ssh_session(service_account=...)`.
  Retrocompatible : le parametre default a `False`
- **`www/adm/platform_keys.php`** - Nouvelle colonne "Service Acc." avec badge indigo,
  stat card compteur, boutons "SA" par serveur et "Deployer SA" en masse

> **Flux de migration complet** : Deployer keypair → Deployer service account →
> Tester sudo → Supprimer password SSH + root_password de la BDD.
> Le compte `rootwarden` est autonome : plus besoin d'aucun mot de passe en BDD.

---

## [1.8.1] - 2026-04-07

### Correctif critique - erreur 500 sur installation neuve

- **`mysql/init.sql`** - Le schema initial pre-enregistrait les migrations 006-015
  dans `schema_migrations` sans creer les tables et colonnes correspondantes.
  Sur une installation neuve, `db_migrate.py` considerait ces migrations comme
  deja appliquees et ne les executait pas, provoquant des erreurs 500 sur
  `/ssh/ssh_management.php`, `/adm/server_users.php` et `/iptables/iptables_manager.php`
- **Tables ajoutees dans init.sql** : `machine_tags` (006), `cve_remediation` (009),
  `server_notes` (011)
- **Colonnes ajoutees dans `machines`** : `lifecycle_status`, `retire_date` (009),
  `platform_key_deployed`, `platform_key_deployed_at`, `ssh_password_required` (012)
- **Colonnes ajoutees dans `permissions`** : `can_manage_remote_users`,
  `can_manage_platform_key`, `can_view_compliance`, `can_manage_backups`,
  `can_schedule_cve` (013)
- **Migration 006 ajoutee** dans le bloc `INSERT INTO schema_migrations` (etait absente)
- **INSERT permissions superadmin** mis a jour pour inclure les 10 colonnes

> **Note de migration** : Les installations existantes affectees par ce bug doivent
> appliquer manuellement les SQL des migrations 006, 009, 011, 012 et 013 directement
> sur la base de donnees. Voir `mysql/migrations/` pour le contenu exact.

---

## [1.8.0] - 2026-04-04

### Pipeline CI/CD (GitHub Actions)

- **`.github/workflows/ci.yml`** - Pipeline 4 jobs declenchee sur push/PR vers main :
  lint Python (ruff), lint PHP (`php -l`), tests pytest (139 tests), build Docker images
- **`backend/ruff.toml`** - Configuration ruff (ignore E501/E402/F401 pour SQL et mocks)
- Job deploy staging commente, pret a activer avec secrets GitHub

### Suite de tests pytest (139 tests)

- **Infrastructure** - `conftest.py` avec fixtures : app Flask, client HTTP,
  mock MySQL (`mysql.connector.connect`), headers par role (user/admin/superadmin)
- **test_permissions.py** (17 tests) - Matrice API key (12 routes), check_machine_access,
  require_role, API key invalide/vide
- **test_monitoring.py** (15 tests) - /test, /list_machines (filtrage role),
  /server_status (online/offline), /linux_version, /last_reboot, /filter_servers
- **test_admin.py** (18 tests) - /admin/backups CRUD, /server_lifecycle (active/retiring/
  archived/invalid), /exclude_user, /admin/temp_permissions CRUD (grant/revoke/hours)
- **test_cve.py** (34 tests) - /cve_scan, /cve_results, /cve_history, /cve_compare,
  /cve_test_connection, /cve_schedules CRUD, /cve_whitelist CRUD, /cve_remediation + stats
- **test_ssh.py** (38 tests) - /platform_key, /regenerate, /deploy (machine access 403),
  /preflight_check, /deploy_platform_key, /test_platform_key, /remove_ssh_password
  (keypair not deployed 400), /reenter_ssh_password, /scan_server_users,
  /remove_user_keys, /delete_remote_user (root protege, user SSH protege)
- **test_iptables.py** (16 tests) - /iptables, /iptables-validate, /iptables-apply,
  /iptables-restore, /iptables-history, /iptables-rollback, /iptables-logs
- Couverture : 6 Blueprints, tous les codes retour (401/400/403/404/200)

### Integration htmx (zero build, 50 KB)

- **htmx 2.0.4** servi localement (`/js/htmx.min.js`) - CDN externe inaccessible
  depuis le conteneur Docker (certificat auto-signe)
- **CSRF auto-inject** - `htmx:configRequest` injecte `csrf_token` dans toutes les
  requetes htmx. Event `showToast` pour les toasts via header `HX-Trigger`
- **toggle_user.php / toggle_sudo.php** - Retournent un fragment HTML `<button>`
  quand `HX-Request` header present, JSON sinon (retrocompatible)
- **update_permissions.php** - Retourne un fragment HTML `<label>` avec checkbox
  htmx quand `HX-Request`, accepte form-urlencoded en plus de JSON
- **manage_users.php** - `onclick="toggleUserStatus()"` → `hx-post` + `hx-swap="outerHTML"`.
  ~60 lignes JS supprimees (toggleUserStatus, toggleSudo)
- **manage_permissions.php** - `onchange="updatePermission()"` → `hx-post` +
  `hx-trigger="change"` + `hx-target="closest label"`. ~25 lignes JS supprimees.
  `setAllPerms()` utilise `htmx.trigger()` au lieu de `updatePermission()`
- **Server access** conserve le JS (manipulation className trop complexe pour htmx v1)

### Corrections UX/UI

- **CGU** - Bouton "J'accepte" passe de `bg-orange-500` a `bg-blue-600` (design system)
- **Mises a jour Linux** - "MaJ Secu" et "Planifier Securite" passent de `bg-red-500`
  a `bg-amber-500` (rouge reserve aux actions destructives)
- **Profile** - 3 boutons bleus → 1 seul primaire ("Enregistrer" email),
  2 secondaires (`border border-gray-300`). Card password `rounded-xl shadow-sm`
- **CVE Export** - Erreurs brutes → reponses JSON (`Content-Type: application/json`)

---

## [1.7.0] - 2026-04-04

### Refonte systeme de permissions

- **5 failles AJAX corrigees** - checkAuth([3]) ajoute sur toggle_user, toggle_sudo,
  update_user, update_user_status, update_server_access. global_search filtre par role
- **3 routes SSE securisees** - @require_api_key ajoute sur /logs, /update-logs, /iptables-logs
- **Proxy securise** - api_proxy.php transmet X-User-ID et X-User-Role au backend Python.
  Helpers Python : get_current_user(), require_role(), check_machine_access()
- **5 nouvelles permissions** (migration 013) : can_manage_remote_users,
  can_manage_platform_key, can_view_compliance, can_manage_backups, can_schedule_cve
- **Ouverture par permission** - SSH, updates, iptables, conformite accessibles aux users
  avec la bonne permission (plus besoin d'etre admin). Sidebar affiche les liens par permission
- **Filtrage user_machine_access** - SSH management filtre les machines par user pour role=1
- **10 permissions** gerees dans l'admin (5 existantes + 5 nouvelles)

### Permissions temporaires

- **Table temporary_permissions** (migration 014) - Accorder un acces pour 1h a 30 jours
  a un utilisateur (ex: prestataire). Expiration automatique
- **checkPermission()** verifie les permissions temporaires en fallback si la perm
  permanente est refusee (query BDD)
- **API** : GET/POST/DELETE `/admin/temp_permissions`
- **UI admin** : formulaire d'attribution (user, permission, duree, raison) + liste
  des perms actives avec temps restant + bouton revoquer
- **Purge auto** : le scheduler supprime les permissions expirees a chaque cycle

### Gestion des utilisateurs distants

- **Page /adm/server_users.php** - Nouvelle page d'administration pour gerer les
  utilisateurs Linux presents sur chaque serveur distant :
  - Scan automatique au chargement (liste users avec shell valide)
  - Indicateurs visuels : cle plateforme (vert), cles presentes (jaune),
    aucune cle (gris), exclu de la synchronisation (violet)
  - Supprimer les cles RootWarden uniquement (`sed -i '/rootwarden/d'`)
  - Supprimer TOUTES les cles (`> authorized_keys`)
  - Supprimer l'utilisateur Linux (`userdel`, option `-r` pour le home)
  - Exclure de la synchronisation (table `user_exclusions`)
- **Routes API** - `POST /remove_user_keys` (mode all/rootwarden_only),
  `POST /delete_remote_user` (avec protection users systeme + user SSH)
- **Protections** - Users systeme (root, daemon, www-data) et user SSH de
  connexion non supprimables. Double confirmation pour userdel

### Reorganisation architecture

- **Flask Blueprints** - server.py (2786 lignes, 58 routes) decoupe en 6 modules :
  `routes/monitoring.py` (7 routes), `routes/iptables.py` (7), `routes/admin.py` (4),
  `routes/cve.py` (16), `routes/ssh.py` (10), `routes/updates.py` (12).
  Helpers partages dans `routes/helpers.py`
- **Fichiers morts supprimes** - 11 fichiers : redirects obsoletes (cve_scan.php, docs.php),
  utilitaires dev (test_decrypt.py, utils.py), scripts legacy (update_variables.sh,
  migrate_passwords.php, reset_zabbix_password.php), build Tailwind (frontend/),
  doublon (manage_servers_fonctionnel.php, update_permissions_ajax.php)
- **Endpoints AJAX reorganises** - www/adm/api/ cree, 9 endpoints deplaces
  (toggle_user, toggle_sudo, delete_user, update_user, update_user_status,
  update_server_access, update_permissions, change_password, global_search)
- **Includes renommes** - manage_ssh_key→manage_users, manage_droit_servers→manage_access,
  manage_portail_users→manage_roles. health_check deplace de security/ vers adm/
- **JS extrait** - 1461 lignes JS inline extraites en fichiers externes :
  iptables/js/iptablesManager.js (492L), ssh/js/sshManagement.js (237L),
  security/js/cveScan.js (732L)

### Refonte UX/UI

- **Sidebar verticale** - Navigation fixe a gauche (desktop) avec icones, sections
  categorisees (Navigation/Admin/Autre), recherche integree, avatar user en bas.
  Drawer mobile avec overlay. Remplace la barre horizontale surcharegee
- **Dashboard compact** - Header bienvenue reduit a 1 ligne + badge alertes.
  4 stat cards au lieu de 5. Raccourcis en grid uniforme. Widget remediation fusionne
- **Design system** - Boutons harmonises sur toutes les pages : 1 primaire bleu + reste en
  secondaire gris. Zero orange. Templates iptables en dropdown. 7 boutons MaJ Linux
  regroupes (5 consultation + separateur + 2 actions)
- **Footer compact** - Une ligne : copyright + logos mini + liens
- **Coherence globale** - Titres h1=text-2xl, h2=text-lg partout. Boutons login/2FA/SSH
  en bleu. Header tableau MaJ Linux en gris. Pubkey truncatee. Profil uniforme

### Migration SSH password → keypair Ed25519

- **Keypair plateforme Ed25519** - Generee automatiquement au demarrage du backend Python.
  Persistee dans un volume Docker nomme `platform_ssh_keys`. Pubkey affichee dans les logs
  et recuperable via `GET /platform_key`
- **Auth SSH keypair-first** - `connect_ssh()` essaie d'abord la keypair plateforme,
  fallback sur password si echec. Champ `_rootwarden_auth_method` sur le client SSH
- **Deploiement de la cle plateforme** - Route `POST /deploy_platform_key` : deploie la
  pubkey sur les serveurs selectionnes, teste la connexion, marque en BDD. Bouton
  "Deployer sur tous" dans l'UI admin
- **Test keypair** - Route `POST /test_platform_key` : verifie la connexion sans password
- **Suppression du password SSH** - Route `POST /remove_ssh_password` : supprime le password
  de la BDD apres validation keypair. Double confirmation dans l'UI
- **Regeneration de keypair** - Route `POST /regenerate_platform_key` : supprime et regenere
  la keypair. Marque tous les serveurs comme non-deployes. Double confirmation
- **Page admin "Securite SSH"** - Nouvelle page `/adm/platform_keys.php` avec :
  pubkey copiable, progression (deployes/en attente/password supprime), tableau des serveurs
  avec badges auth (keypair/keypair+pwd/password), boutons Tester/Suppr. pwd/Users
- **Scan des utilisateurs distants** - Route `POST /scan_server_users` : liste les users
  avec shell valide, compte les cles SSH, detecte la cle plateforme. Tableau de resultats
  dans la page admin
- **Alerte dashboard** - Alerte si des serveurs utilisent encore l'auth par password
  avec lien vers la page de migration
- **Barre de progression migration** - Barre visuelle tricolore (rouge/jaune/vert) dans la
  page Cle SSH avec message de statut contextuel
- **Suppression en masse des passwords** - Bouton orange "Suppr. passwords (N)" avec
  triple confirmation. Ne propose que les serveurs deja migres en keypair
- **Rollback password** - Bouton "Re-saisir pwd" pour restaurer un password SSH apres
  suppression. Route `POST /reenter_ssh_password` avec chiffrement automatique
- **Filtrage serveurs archives** - Les serveurs en lifecycle "archived" sont exclus des
  pages operationnelles (SSH, CVE, MaJ Linux) et du backend (list_machines, filter_servers)
- **Webhook keypair** - Notification Slack/Teams/Discord quand un serveur migre en keypair
- **Migration 012** - Colonnes `platform_key_deployed`, `platform_key_deployed_at`,
  `ssh_password_required` sur la table `machines`

## [1.6.0] - 2026-04-03

### Nouvelles fonctionnalites

- **Scans CVE planifies** - Planification automatique via expressions cron (ex: quotidien
  a 03h). CRUD complet (`/cve_schedules`), thread daemon, calcul next_run via `croniter`.
  Interface collapsible dans la page CVE pour creer/activer/supprimer des planifications
- **Dry-run APT** - Bouton "Dry-run" sur la page MaJ Linux. Simule `apt-get upgrade --dry-run`
  sans rien installer. Affiche les paquets qui seraient mis a jour (route `/dry_run_update`)
- **Pre-flight checks SSH** - Avant chaque deploiement de cles SSH, verification automatique :
  connectivite reseau, connexion SSH, version OS, espace disque, presence de cles SSH.
  Affichage du rapport dans les logs avant lancement du deploiement (`/preflight_check`)
- **Tendances CVE (dashboard)** - Graphique en barres sur 30 jours avec indicateur de tendance
  (hausse/baisse vs semaine precedente). Barres colorees par severite (rouge/orange/jaune)
  Route API `/cve_trends` pour l'agregation par jour
- **Historique iptables + rollback** - Sauvegarde automatique des regles avant chaque
  modification. Table `iptables_history` avec auteur et raison. Routes `/iptables-history`
  et `/iptables-rollback` pour consultation et restauration
- **Whitelist CVE** - Marquer des CVE comme faux positifs acceptes avec justification, auteur
  et date d'expiration. Table `cve_whitelist`, routes CRUD `/cve_whitelist`
- **Import CSV serveurs & utilisateurs** - Upload CSV depuis l'onglet admin pour creer
  des serveurs ou utilisateurs en masse. Validation par ligne, gestion doublons, tags,
  chiffrement automatique des mots de passe, rapport d'import avec erreurs detaillees
- **Historique de login + sessions actives** - Table `login_history` tracant chaque
  tentative (succes/echec, IP, user-agent). Table `active_sessions` avec revocation
  depuis la page Profil. Conformite ISO 27001 A.9.4.2
- **Politique d'expiration des mots de passe** - Configurable via `PASSWORD_EXPIRY_DAYS`
  (defaut: desactive). Banniere d'avertissement N jours avant expiration. Redirection
  forcee vers la page Profil quand le mot de passe est expire
- **Validation iptables (dry-run)** - Bouton "Valider" qui teste la syntaxe des regles
  via `iptables-restore --test` sans les appliquer. Route `/iptables-validate`
- **Retention & purge automatique des logs** - Configurable via `LOG_RETENTION_DAYS`.
  Purge periodique (1x/heure) des tables user_logs, login_history, login_attempts,
  active_sessions. Conservation des N derniers scans CVE par serveur (`CVE_SCAN_RETENTION`)
- **Suivi de remediation CVE** - Cycle de vie des vulnerabilites : Open → In Progress → Resolved.
  Assignation a un responsable, deadline, note de resolution. Table `cve_remediation` avec routes
  CRUD (`/cve_remediation`) et stats (`/cve_remediation/stats`). Auto-resolution prevu post-scan
- **Deploiement SSH par groupe/tag** - Filtres par tag et environnement dans la page de deploiement
  SSH. Bouton "Cocher filtres" pour selectionner uniquement les machines visibles
- **Templates iptables** - 5 presets chargeables en 1 clic : Serveur Web, Base de donnees,
  SSH uniquement, Deny All, Docker Host. Insere le template dans l'editeur IPv4
- **Backup BDD automatique** - mysqldump compresse planifie via le scheduler. Retention
  configurable (`BACKUP_RETENTION_DAYS`). Routes `/admin/backups` (GET pour lister, POST pour
  creer). Volume Docker `/app/backups` monte sur l'hote
- **Workflow decommissionnement serveur** - Statut lifecycle : Active → Retiring → Archived.
  Banniere visuelle dans les cartes serveurs admin. Boutons Retirer/Archiver/Reactiver.
  Route `/server_lifecycle`. Colonne `retire_date` pour la planification
- **Alertes SSH actionnables** - Les alertes "cles SSH > 90 jours" affichent desormais les
  noms des utilisateurs concernes avec un lien direct vers l'administration
- **Export CSV** - Bouton d'export sur chaque carte serveur dans le scan CVE
  (`/security/cve_export.php`) + export du journal d'audit (`/adm/audit_log.php?export=csv`)
- **Journal d'audit complet** - Nouvelle page `/adm/audit_log.php` avec filtres par
  utilisateur/action, pagination, export CSV. Actions loguees : connexion, toggle
  actif/sudo, creation/suppression utilisateur, modification cle SSH, permissions
- **Notifications webhook** - Support Slack, Teams, Discord et generic
  (`backend/webhook_utils.py`). Evenements : cve_critical, cve_high, deploy_complete,
  server_offline. Configuration via `WEBHOOK_URL`, `WEBHOOK_TYPE`, `WEBHOOK_EVENTS`
- **Session timeout** - Deconnexion automatique apres inactivite (defaut 30 min),
  configurable via `SESSION_TIMEOUT`. Message "session expiree" sur la page login
- **Alertes securite sur le dashboard** - 6 verifications automatiques : users sans
  2FA, users sans cle SSH, serveurs offline, CVE critiques, serveurs non verifies 30j+,
  cles SSH anciennes 90j+
- **Suivi d'age des cles SSH** - Colonne `ssh_key_updated_at` (migration 005), badge
  rouge "Cle SSH (Xj)" quand > 90 jours dans l'admin
- **OpenCVE v2 on-prem** - Support Bearer token, adaptation format reponse API v2
  (cve_id→id, description→summary, metrics nested), fallback search si vendor/product 404
- **Selection du role a la creation** - Dropdown user/admin/super-admin dans le
  formulaire d'ajout utilisateur
- **Champ email utilisateur** - Migration 004, champ dans le formulaire de creation,
  envoi mail de bienvenue (si SMTP configure), modifiable dans le profil
- **Test de connectivite serveur** - Bouton "Tester" dans chaque carte serveur admin
- **Resume global CVE** - Bandeau en haut de la page scan avec total CRITICAL/HIGH/MEDIUM

### Finitions UI (features round 3)

- **Widget remediation CVE (dashboard)** - Compteurs Open/En cours/Resolues/Acceptees
  avec indicateur de deadlines depassees sur la page d'accueil
- **UI historique iptables** - Section historique avec bouton Restaurer par version dans
  la page iptables. Chargement automatique apres recuperation des regles
- **Auto-resolution CVE** - Apres chaque scan, les remediations ouvertes dont la CVE
  n'est plus detectee passent automatiquement en "resolved" avec note horodatee
- **Gestion des backups (admin)** - Modal dans l'admin avec liste des sauvegardes,
  taille, date. Bouton "Creer un backup maintenant" pour dump manuel

### Finitions UI (features round 4)

- **Remediation CVE inline** - Dropdown de statut (Open/En cours/Accepte/Won't fix) directement
  dans le tableau de resultats CVE par serveur. Colonne "Suivi" ajoutee
- **Whitelist CVE inline** - Fonction JS `whitelistCve()` accessible depuis la page scan,
  avec saisie de la raison via prompt
- **Message lockout sur login** - Banniere rouge avec temps restant quand l'IP est bloquee
  apres 5 tentatives echouees. Message d'expiration de mot de passe
- **Expiration mot de passe** - `password_expires_at` mis a jour automatiquement apres chaque
  changement de mot de passe si `PASSWORD_EXPIRY_DAYS` est configure. Session flag efface
- **Rapport de conformite** - Nouvelle page `/security/compliance_report.php` : resume executif,
  CVE par serveur, remediation, authentification/cles SSH, pare-feu. Export CSV + impression PDF.
  Hash SHA-256 pour preuve d'integrite. Bouton raccourci sur le dashboard

### Finitions UI (features round 5)

- **Paquets en attente** - Bouton "Paquets" dans la page MaJ Linux. Affiche la liste des
  paquets upgradables (`apt list --upgradable`) sans rien toucher. Route `/pending_packages`
- **Notes sur les serveurs** - Champ de notes libres dans chaque carte serveur admin.
  Historique des notes avec auteur et date. Table `server_notes` (migration 011)
- **Timeline d'activite (profil)** - Section "Mon activite recente" avec icones colorees
  par type d'action (connexion, SSH, mot de passe, suppression, creation)
- **Recherche globale** - Barre de recherche dans le menu (cross-entites : serveurs, users, CVE).
  Resultats instantanes en dropdown avec debounce 250ms. Page `/adm/global_search.php`
- **Dashboard auto-refresh** - Les statuts serveurs se rafraichissent automatiquement toutes
  les 60 secondes sans recharger la page (appel `/list_machines` en arriere-plan)

### Finitions UI (features round 6)

- **Comparaison de scans CVE** - Bouton "Diff" par serveur dans la page CVE scan. Modal avec
  compteurs (corrigees / inchangees / nouvelles) et listes colorees. Route `/cve_compare`
- **Notification email expiration MdP** - Le scheduler verifie chaque heure si des mots de
  passe expirent dans les 7 prochains jours et envoie un email de rappel (si MAIL_ENABLED)
- **Indicateur reboot required** - Badge rouge "REBOOT" anime pulse a cote de la date de
  dernier boot quand `/var/run/reboot-required` est present sur le serveur
- **Raccourcis clavier** - `Ctrl+K` ou `/` = recherche, `g+h` = dashboard, `g+s` = SSH,
  `g+u` = MaJ, `g+c` = CVE, `g+a` = admin, `g+i` = iptables, `g+p` = profil, `?` = aide
- **Compteur lifecycle admin** - Le header admin affiche les serveurs "en retrait" et "archives"

### Ameliorations d'affichage CVE

- Cards serveur **collapsees par defaut** (1 ligne = resume par annee)
- **Filtres par annee** cliquables (reconstruisent le tableau depuis la memoire)
- **Recherche** dans les CVE par ID ou nom de paquet
- **Pagination** : 50 par page + "Voir plus"
- **Tri par annee** (plus recent d'abord) puis par CVSS
- Versions en `text-xs` (lisible)

### Corrections de bugs

- **`execute_as_root_stream`** - Fallback `su -c` quand sudo absent (serveurs Debian
  sans sudo), delai 1s pour l'invite "Mot de passe :"
- **`/linux_version`** et **`/last_reboot`** - Utilisent `client.exec_command` direct
  au lieu de `execute_as_root` (pas besoin de root pour `cat /etc/os-release` et `uptime -s`)
- **`import re` local** dans `last_reboot()` qui masquait le `re` global → supprime
- **Status Online/ONLINE** - JS harmonise en "ONLINE" pour correspondre a la BDD
- **Bouton "Reboot"** renomme en **"Dernier boot"** (evite la confusion "reboot le serveur")
- **`apiCalls.js`** - Apostrophe non echappee dans toast (`l'heure`) cassait tout le JS
- **CSP** - Ajout `unsafe-eval` pour Tailwind CDN
- **`configure_servers.py`** - `NoneType.strip()` sur user sans cle SSH (3 occurrences)
- **CVE doublons** - Deduplication paquets multiarch (dict `seen`)
- **`createMachineRow()`** - 3 colonnes manquantes (MaJ secu, derniere exec, dernier boot)
- **Modal `#schedule-modal`** manquant - Ajout du HTML
- **`checkLinuxVersion()`** - Met a jour le DOM immediatement (plus besoin de recharger)
- **Bouton "Dernier boot"** - Reference `$m` hors boucle PHP → itere `getSelectedMachineIds()`
- **`filterFindings()`** - Reconstruit le tableau depuis la memoire (filtres par annee fonctionnels)
- **`mysql/init.sql`** - Les comptes seedés `admin` et `superadmin` utilisent
  désormais des hashes cohérents avec les identifiants documentés
- **`php/entrypoint.sh`** - `composer install` automatique au démarrage si
  `www/vendor/autoload.php` absent (fix 2FA après `docker-compose up -d`)

### Documentation

- **`README.md`** - Réécriture complète pour v1.6.0 (features, stack, installation)
- **`ARCHITECTURE.md`** - Mise à jour avec nouveaux fichiers, tables, colonnes et flux
- **`documentation.php`** - Ajout sections webhooks, tags, audit, session timeout, export CSV

## [1.5.3] - 2026-04-01

### Refonte interface (design system unifie)

- **`ssh_management.php`** - Layout 2 colonnes (serveurs + terminal logs), bouton
  deploiement avec spinner/loading state, toast de succes a la fin du deploiement
- **`iptables_manager.php`** - Card-based layout, selecteur serveur + bouton principal,
  actions secondaires en hierarchy, panneaux regles en grille 2 colonnes
- **`linux_updates.php`** - Barre compacte filtres + actions inline, pills colorees
  par importance (versions bleu, statuts vert, MaJ orange, secu rouge), Zabbix inline
- **`admin_page.php`** - Systeme d'onglets (Utilisateurs, Serveurs, Acces & Droits,
  Exclusions) avec deep-links via URL hash, regroupement logique des sections
- **`verify_2fa.php` / `enable_2fa.php`** - Gradient bleu, branding white-label,
  champ code TOTP monospace 6 digits, bouton orange, QR code centre avec secret
  collapsible (details/summary)
- **`menu.php`** - Reecrit : icones SVG, lien actif surligne, badge user avec pill
  de role, hamburger mobile fonctionnel, toggle dark/light avec icones soleil/lune
- **`footer.php`** - Compact : logos technos discrets (40% opacity) + copyright en
  une ligne au lieu du gros bloc "A propos"
- **`index.php`** - Dashboard : 4 cartes statistiques + 6 raccourcis conditionnels
- **`profile.php`** - Carte identite (role, date creation, statut 2FA, sudo)

### Toast notifications

- **`head.php`** - Composant global toast() avec 4 types (success/error/warning/info),
  animation slide-in depuis la droite, auto-dismiss 4s
- Remplacement des 33 `alert()` par `toast()` dans 7 fichiers
- Toasts de succes sur les actions admin (toggle user, acces serveur, deploiement)

### Conventions visuelles

- Terminal logs : fond `#111827`, texte `#34d399` (vert), monospace 12px
- Cards : rounded-xl, shadow-sm, headers uppercase tracking-wide
- Boutons : primaires (plein), secondaires (outline), pills (petits colores)
- Dark mode : gradient gray-900 → gray-800 sur menu, dark:bg-gray-800 sur cards

---

## [1.5.2] - 2026-04-01

### Corrections de sécurité

- **`ssh_utils.py`** - Le mot de passe root était visible dans les logs de streaming
  SSH (`execute_as_root_stream`). Le PTY renvoyait le mot de passe en écho dans stdout.
  Corrigé : filtrage du mot de passe + nettoyage des séquences ANSI dans le flux.
- **`privacy.php`** - Action de suppression de compte sans validation CSRF.
  Ajout de `checkCsrfToken()`, champ hidden CSRF, confirmation JS et protection
  contre la suppression du dernier superadmin.
- **`delete_user.php`** - Un superadmin pouvait supprimer son propre compte et
  supprimer le dernier superadmin. Double protection ajoutée (self + count).

### Corrections de bugs

- **`login.php`** - CSP `script-src 'self'` bloquait le CDN Tailwind sur la page
  de connexion. Ajouté `https://cdn.tailwindcss.com` dans la directive.
- **`menu.php`** - Les conditions de navigation (`$role === 'superadmin'`)
  comparaient un entier avec une chaîne et ne fonctionnaient jamais. Corrigé
  avec `$roleLabel` mappé depuis `role_id`.
- **`manage_ssh_key.php`** - `htmlspecialchars(null)` sur la colonne `company`
  (PHP 8.2 deprecation warning visible). Ajouté `?? ''`.
- **`configure_servers.py`** - `ensure_sudo_installed()` appelé sans `root_password`
  (argument manquant). `ssh_connection()` yield un channel au lieu du client SSH
  (type mismatch). Corrigé avec tuple `(channel, client)`.
- **`domManipulation.js`** - Smart quotes Unicode (`'` `'`) dans le code exécutable
  cassaient le parsing JS. Remplacées par des apostrophes droites.
- **`profile.php`** - Classes CSS `light:` invalides (prefix inexistant dans Tailwind).

### Architecture (proxy API)

- **`api_proxy.php`** (nouveau) - Proxy PHP générique qui relaie toutes les requêtes
  JS vers le backend Python en interne Docker. Supporte GET JSON, GET SSE streaming,
  POST JSON et POST streaming. Élimine les problèmes CORS entre le navigateur et
  Hypercorn ASGI, et masque l'API_KEY côté serveur.
- **`head.php`** - `window.API_URL` pointe désormais vers `/api_proxy.php` au lieu
  de l'URL Python directe. Ce changement central corrige toutes les pages d'un coup.
- **`server.py`** - CORS géré manuellement (`@app.after_request`) au lieu de
  `flask_cors` (incompatible avec Hypercorn). Ajout de `handle_preflight()` pour OPTIONS.
- **`cve_scan.php`** - Test de connexion OpenCVE migré côté PHP (curl server-side)
  au lieu de JS → Python directe.

### Environnement preprod

- **`test-server/Dockerfile`** (nouveau) - Conteneur Debian Bookworm avec SSH, sudo
  et iptables pour tester les routes en local. Profile Docker `preprod`.
- **`mock-opencve/app.py`** (nouveau) - Mock API OpenCVE avec 13 CVE réalistes
  couvrant 10 packages Debian (apt, bash, libc6, sudo, openssh, curl, etc.).
- **`docker-compose.yml`** - Services `test-server` et `mock-opencve` sous le
  profile `preprod`. Port Python exposé pour le dev.

### Améliorations UX

- **`index.php`** - Dashboard avec 4 cartes statistiques (serveurs, en ligne,
  utilisateurs, CVE) et 6 raccourcis conditionnels selon les permissions.
- **`profile.php`** - Carte d'identité utilisateur (rôle, date de création,
  statut 2FA, sudo).
- **`menu.php`** - Affichage du nom de rôle (`superadmin`) au lieu du numéro (`3`).
- **`index.php`** - Rôle affiché en texte (`Super-administrateur`) au lieu de l'ID.
- **`health_check.php`** (nouveau) - Page diagnostic testant les 11 routes backend
  avec statut, temps de réponse et aperçu JSON. Accessible depuis Administration.

---

## [1.5.1] - 2026-03-31

### Corrections de bugs (review d'alignement frontend ↔ backend)

- **`apiCalls.js`** - `apiFetch()` n'envoyait jamais le header `X-API-KEY` → toutes les
  routes appelées via cette fonction retournaient HTTP 401. Header ajouté dans les defaults.
- **`iptables_manager.php`** - Template literal JavaScript (`` ` `` backtick) utilisé dans
  du code PHP → interprété comme `shell_exec()`. Remplacé par `getenv('API_URL') . '/...'`.
- **`iptables_manager.php`** - Les 3 appels `fetch()` vers `/iptables`, `/iptables-apply`,
  `/iptables-restore` n'envoyaient pas `X-API-KEY` → HTTP 401 systématique sur la page iptables.
- **`ssh_management.php`** - Appel `fetch()` vers `/deploy` sans `X-API-KEY` → HTTP 401
  lors de tout déploiement de clé SSH.
- **`apiCalls.js`** - `zabbixUpdateSingle()` utilisait `apiFetch()` (attend du JSON) sur
  `/update_zabbix` qui retourne du streaming `text/plain` → erreur de parsing JSON.
  Réécrit avec `fetch()` + `ReadableStream` reader.
- **`functions.php`** - `can_scan_cve` absent du tableau de fallback dans
  `initializeUserSession()` → comportement imprévisible pour les users sans ligne en BDD.
- **`crypto.php`** - Divergence de dérivation de clé AES entre PHP et Python :
  PHP passait la clé hex brute à `openssl_encrypt()`, Python faisait `bytes.fromhex()`.
  Nouveau helper `prepareKeyForAES()` aligné sur le comportement Python.
- **`config.py`** - `ENCRYPTION_KEY` marquée comme obligatoire (`_require_env`) alors
  qu'elle n'est pas utilisée par le backend Python → crash au démarrage si absente.
  Passée en optionnelle avec `os.getenv('ENCRYPTION_KEY', '')`.
- **`srv-docker.env.example`** - `DB_PORT` utilisé par `config.py` mais absent du template.
  Ajouté commenté avec valeur par défaut 3306.

### Documentation (couverture complète du projet)

- **Backend Python** (10 fichiers) - docstrings module-level + toutes les fonctions/classes :
  `server.py`, `config.py`, `encryption.py`, `ssh_utils.py`, `iptables_manager.py`,
  `cve_scanner.py`, `mail_utils.py`, `db_migrate.py`, `configure_servers.py`, `update_server.py`
- **PHP `www/`** (~35 fichiers) - blocs PHPDoc en-tête + PHPDoc sur toutes les fonctions :
  auth/, adm/includes/, adm/ (endpoints AJAX), security/, ssh/, iptables/, update/functions/,
  pages racine (index, head, menu, footer, db, profile, privacy, terms)
- **PHP `php/`** (8 fichiers) - commentaires sur Dockerfile, entrypoint.sh, templates Apache,
  php.ini (justification de chaque surcharge), scripts shell
- **JS** (3 fichiers) - JSDoc complet sur toutes les fonctions :
  `update/js/apiCalls.js`, `update/js/domManipulation.js`, `js/admin.js`
- **`ARCHITECTURE.md`** - Carte complète du projet (arbre ASCII, rôle de chaque fichier,
  tables MySQL, flux de données, conventions de développement)

---

## [1.5.0] - 2026-03-31

### Ajouté
- **Scan CVE** : intégration OpenCVE (cloud `opencve.io` ou instance on-prem)
  - Scan à la demande par serveur ou scan global de toute l'infrastructure
  - Filtrage par seuil CVSS configurable (`CVE_MIN_CVSS`) : 0 / 4 / 7 / 9+
  - Streaming temps réel des résultats (JSON-lines)
  - Persistance en base de données (historique des scans par serveur)
  - Page dédiée : `/security/cve_scan.php`
- **Notifications email** : rapport CVE HTML envoyé après chaque scan
  - Configuration SMTP complète via variables d'environnement
  - Support STARTTLS et SSL direct
  - Sujet automatiquement préfixé `[CRITICAL]` ou `[HIGH]` selon la sévérité
- **Système de migration DB** (`backend/db_migrate.py`)
  - Application automatique des migrations au démarrage du backend
  - Table `schema_migrations` pour le suivi des versions appliquées
  - CLI : `python db_migrate.py --status | --dry-run | --strict`
  - Idempotent : une migration déjà appliquée n'est jamais rejouée
- **Branding white-label**
  - `APP_NAME`, `APP_TAGLINE`, `APP_COMPANY` via variables d'environnement
  - Affichage dans le menu, la page de login, les titres de pages et le JS
- **Permission `can_scan_cve`**
  - Nouveau droit granulaire gérable depuis Administration → Droits d'accès
  - Les `user` ne voient que leurs serveurs attribués dans le scan CVE
  - Le `superadmin` a toujours accès sans vérification
- **Nouveau helper PHP `checkPermission()`** dans `verify.php`
  - Usage : `checkPermission('can_scan_cve')` ou `checkPermission('can_scan_cve', false)`

### Modifié
- **SSL dynamique** : mode `auto` / `custom` / `disabled` via `SSL_MODE`
  - Plus besoin de rebuilder l'image pour changer le certificat
  - `disabled` : idéal derrière un reverse proxy (Nginx, Traefik, Caddy)
  - `auto` : certificat auto-signé généré au premier démarrage (pas au build)
  - `custom` : apportez vos propres certificats (Let's Encrypt, entreprise)
- **Bug corrigé** : `${SERVER_NAME}` dans la config Apache n'était pas substitué
  - L'entrypoint injecte désormais les variables dans `/etc/apache2/envvars`
- **Sécurité réseau Docker** : backend Python et MySQL ne sont plus exposés
  sur l'hôte par défaut (communication interne uniquement)
- **`depends_on` fonctionnel** : healthcheck MySQL + `condition: service_healthy`
- **Composer** déplacé en `profiles: [tools]` (ne démarre plus avec `up`)
- **`verify.php`** : `can_scan_cve` ajouté aux permissions par défaut de session
- **`login.php`** : page de connexion redessinée avec support du branding

### Migrations DB requises (installation existante)
```bash
# Via le runner Python (recommandé)
docker exec rootwarden_python python /app/db_migrate.py

# Via MySQL directement
docker exec -i rootwarden_db mysql -u rootwarden_user -p rootwarden \
  < mysql/migrations/002_cve_tables.sql
docker exec -i rootwarden_db mysql -u rootwarden_user -p rootwarden \
  < mysql/migrations/003_add_can_scan_cve.sql
```

---

## [1.4.28] - 2025-xx-xx

### Modifié
- Amélioration de la gestion des mises à jour Linux
- Corrections diverses sur la gestion des clés SSH

---

## [1.4.x] - Historique antérieur

> Les versions antérieures à 1.4.28 n'ont pas de changelog détaillé.
> Consultez le log Git pour l'historique complet : `git log --oneline`

---

## Guide de mise à jour

### Processus standard

```bash
# 1. Sauvegarder la base de données
docker exec rootwarden_db \
  mysqldump -u root -p rootwarden > backup_$(date +%Y%m%d).sql

# 2. Récupérer la nouvelle version
git pull

# 3. Rebuilder les images
docker-compose build --no-cache

# 4. Redémarrer (les migrations s'appliquent automatiquement)
docker-compose up -d

# 5. Vérifier l'état des migrations
docker exec rootwarden_python python /app/db_migrate.py --status
```

### Vérification post-mise à jour

```bash
# Consulter les logs du backend (migrations + erreurs éventuelles)
docker logs rootwarden_python

# Tester la connectivité OpenCVE (si configurée)
curl -s -H "X-API-KEY: $API_KEY" https://localhost:8443/api/cve_test_connection
```

---

## Convention de nommage des migrations

Les fichiers de migration SQL sont dans `mysql/migrations/` :

```
NNN_description_courte.sql
│   └─ Snake_case, décrit le contenu
└── Numéro à 3 chiffres, séquentiel
```

Exemples :
- `001_initial_schema.sql`
- `002_cve_tables.sql`
- `003_add_can_scan_cve.sql`
- `004_add_audit_log_table.sql`   ← prochaine migration

**Règles impératives :**
- Toujours incrémenter le numéro
- Toujours idempotent (`CREATE TABLE IF NOT EXISTS`, `IF NOT EXISTS` sur les colonnes)
- Ajouter l'entrée correspondante dans le `INSERT IGNORE INTO schema_migrations` de `init.sql`
- Documenter dans ce CHANGELOG sous la section de version appropriée
