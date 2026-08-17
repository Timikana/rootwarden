---
name: rw-laravel
description: Conventions du portage RootWarden vers Laravel - schema partage sans migrations, pilotes fichier obligatoires, passerelle vers le backend Python, i18n FR/EN, composants Blade, contrats DOM des tests. A charger AVANT de toucher a laravel/.
---

# Portage RootWarden vers Laravel

Le frontend Laravel (`laravel/`, port 8444) tourne **en parallele** du legacy
(`legacy/`, port 8443) pendant toute la migration. Le legacy reste la reference
tant que la parite d'un module n'est pas prouvee.

Decisions et mesures : `docs/migration/{INVENTAIRE,ARCHITECTURE-UI,DEPRECIATION}.md`.

## Interdits absolus

- **Aucune migration Laravel.** Le schema (63 tables) appartient au backend
  Python et evolue par `mysql/migrations/*.sql`. Ni `migrate`, ni
  `migrate:fresh`, ni `db:seed`, ni `schema:dump`. Voir
  `laravel/database/migrations/README.md`.
- **Le backend Python ne se touche pas.** Laravel le joint par une passerelle,
  il ne le remplace pas.
- **Pas d'etape de construction.** CSS ecrit a la main, jetons + classes
  `.rw-*`. Filament et Tailwind ont ete evalues et ecartes sur mesure
  (`ARCHITECTURE-UI.md`).

## Pieges specifiques a ce portage

- **Les pilotes `database` sont des mines.** Laravel 13 propose par defaut
  `SESSION_DRIVER=database`, `QUEUE_CONNECTION=database`, `CACHE_STORE=database`.
  Ils exigent les tables `sessions`, `jobs`, `cache` — que ce projet ne cree
  pas. Laisses tels quels, ils cassent l'application a la PREMIERE requete,
  avec une erreur SQL et non un message clair. Rester sur `file` / `sync` /
  `file`.
- **`env()` hors de `config/` rend `null`** des le premier `config:cache`. Tout
  reglage se lit dans un fichier de `config/`, jamais ailleurs. Les
  identifiants de base sont lus en repli sur `MYSQL_*` dans
  `config/database.php` : ne pas les recopier sous `DB_*`, un mot de passe
  present a deux endroits finit par diverger.
- **Modeles Eloquent au fil de l'eau**, jamais en prealable. Sur 63 tables, **5
  seulement** portent `created_at` ET `updated_at` : la quasi-totalite des
  modeles demande un `public $timestamps = false;` explicite ou des colonnes
  nommees a la main. 23 tables n'ont aucun horodatage.
- **Sans `view:cache`, Blade recompile chaque gabarit a CHAQUE requete** : 2 a
  4,6 s par requete contre 0,21 s une fois compile. L'entrypoint le fait au
  demarrage. Ne PAS ajouter `config:cache` ni `route:cache` pendant la
  migration : ils figeraient des valeurs encore en mouvement.
- **Apres modification** : `config:clear` apres un changement de config,
  `view:clear` + `view:cache` apres un changement de vue.
- **Sur un hote Windows, le bind mount est ~258x plus lent que le systeme de
  fichiers du conteneur** : 9 300 ms contre 36 ms pour lire 1 500 fichiers PHP
  (mesure du 2026-08-17). Le legacy charge ~5 fichiers par page, Laravel
  plusieurs centaines : une premiere requete a froid depasse 6 s, puis retombe
  a 0,17 s une fois le cache du systeme chaud. Consequences :
  - la sonde du conteneur a un delai de 20 s, pas 5 s — avec 5 s elle echouait
    toujours et le conteneur restait « unhealthy » en permanence sans qu'aucun
    defaut applicatif n'existe ;
  - **toute mesure de latence faite sur cet hote est suspecte.** Comparer
    Laravel au legacy sur ce poste compare surtout leur nombre de fichiers
    charges. L'ecart releve precedemment sur la recherche (2,2 s contre 24 ms)
    doit etre re-mesure ailleurs avant d'etre traite comme un defaut.
- **`@json` multiligne casse le PHP compile.** Le garder sur une ligne.
- **Une cle de traduction absente rend son IDENTIFIANT a l'ecran**, sans
  erreur. Mesurer les cles MORTES : trois pieces justes peuvent donner un
  ecran inerte.

## i18n

Parite FR/EN **stricte**, dans le meme commit. Point de depart mesure au
2026-08-17 : 2 545 cles FR = 2 545 cles EN cote legacy.

Cote legacy le PHP appelle `t('module.cle')` et le JS `__('cle')` (injecte par
`head.php`) — ne pas confondre : une recherche de `__(` dans le PHP ne trouve
rien et le silence passe pour un zero.

## Tests

- Test de caracterisation **vert sur le legacy d'abord**, puis le MEME test
  vert sur Laravel. Divergence voulue -> CHANGELOG + attendu PAR CIBLE.
- **Suivre les liens DU MENU**, jamais une liste d'URL ecrite a la main : sept
  404 ont vecu dans le menu sans qu'aucune suite ne les voie.
- **Mesurer un booleen, pas une longueur.** La longueur du texte d'une page
  bouge seule d'une execution a l'autre (journal d'audit alimente par la
  connexion du test, tableaux asynchrones inacheves) : 2693 / 2690 / 2688
  releves sur la meme page sans aucun changement de code.
- **Verifier les droits avec les comptes dedies** `rw-test-user` (role 1, zero
  permission), `rw-test-admin` (role 2), `rw-test-super` (role 3). Une suite
  qui s'authentifie en superadmin ne mesure aucun cloisonnement — 21 vagues
  ont ete perdues a ecrire « non mesurable ».
- Conventions Puppeteer : voir la skill `rw-e2e`. Un contexte de navigateur
  NEUF par compte (`newPage()` partage les cookies), 30 s entre deux connexions
  du meme compte (fenetre TOTP).

## Environnement

- `laravel/.env` (ignore par git) part de `laravel/.env.example`. L'entrypoint
  genere `APP_KEY` au premier demarrage.
- Toute nouvelle variable va dans `srv-docker.env.example` : les exploitants la
  recuperent automatiquement via `./maj.sh`.
- `MSYS_NO_PATHCONV=1` devant tout `docker exec` portant un chemin absolu :
  Git Bash traduit `/var/www/html` en `C:/Program Files/Git/var/www/html`.

## Authentification — ce que le legacy fait vraiment

Mesure par `tests/e2e/go-socle-auth.mjs` (13 PASS / 1 ecart connu cote legacy) :

- **Aucun chemin sans second facteur.** `login.php` renvoie vers `enable_2fa.php`
  si le compte n'a pas de secret, vers `verify_2fa.php` sinon. Entre le mot de
  passe et le code, la session n'est PAS authentifiee : une page protegee reste
  refusee. Verifie sur les trois roles.
- **L'identifiant de session change** apres authentification complete.
- **Apres le second facteur**, passage par `/terms.php` — sauf
  `force_password_change`, qui renvoie vers `profile.php?force_change=1`.
- Limitation de debit du second facteur : 5 tentatives par session sur 60 s,
  ET un compteur par IP en base (`login_attempts`, `step='2fa'`, seuil 10 sur
  10 min). Une 2FA reussie repasse sa ligne a `success=1` — sans quoi une
  reussite comptait comme un echec.
- **Le garde anti-rejeu TOTP est INERTE** — voir `docs/migration/PARITE.md`
  E-01. `$_SESSION['last_totp_hash']` n'est pose que dans la branche de succes
  puis supprime dans la meme requete. Le portage doit porter ce garde par
  COMPTE, en base, jamais par session : un garde de session ne peut rien contre
  un rejeu venu d'une session neuve.
- Step-up : `stepUpVerify($action, 900)`, cle `_step_up_<action>` par ACTION,
  limitation a 5 tentatives, anti-rejeu `_step_up_last_totp`.

## Etat du portage

Rien n'est porte a ce jour. Le socle est en cours : squelette (fait),
caracterisation de l'authentification (faite), puis portage de
l'authentification, gabarit et navigation, passerelle, i18n.

Reference consultable sur la branche abandonnee `laravel` (22 vagues, 2 825
assertions vertes) : `git show laravel:docs/migration/{AUTH,GATEWAY,LAYOUT,DESIGN-SYSTEM,PORTAGE}.md`
et `git show laravel:laravel/resources/views/components/rw/<nom>.blade.php`
(7 composants). A consulter, jamais a recopier telle quelle.
