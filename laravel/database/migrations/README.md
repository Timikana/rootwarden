# Ce dossier reste vide — et ce n'est pas un oubli

Le schema de la base **n'appartient pas a Laravel**. Il est partage avec le backend
Python, qui le fait evoluer par ses propres fichiers (`mysql/migrations/*.sql`, joues par
`backend/db_migrate.py`). Au 2026-08-17 il compte **63 tables**.

## La regle

**Aucune migration Laravel, jamais.** Ni `php artisan migrate`, ni
`migrate:fresh`, ni `db:seed`, ni `schema:dump`. Le frontend Laravel *lit* et *ecrit* dans
un schema dont il n'est pas proprietaire.

Un besoin de colonne ou de table se traite cote Python, par une migration SQL, comme
n'importe quel autre changement de schema du projet.

## Ce qui a ete supprime, et pourquoi

Le squelette Laravel livre trois migrations par defaut :

- `0001_01_01_000000_create_users_table.php`
- `0001_01_01_000001_create_cache_table.php`
- `0001_01_01_000002_create_jobs_table.php`

La premiere est la plus dangereuse : `users` **existe deja**, avec ses colonnes
`role_id`, `totp_secret`, `failed_attempts`, `locked_until`, et une migration Laravel qui
la creerait echouerait — ou, pire, reussirait sur une base neuve et donnerait un schema
different de celui du backend.

Elles ont donc ete retirees des la creation du squelette.

## Le piege qui va avec

Supprimer les migrations ne suffit pas. Laravel 13 configure par defaut :

    SESSION_DRIVER=database
    QUEUE_CONNECTION=database
    CACHE_STORE=database

Ces trois pilotes ont besoin des tables `sessions`, `jobs` et `cache` — celles que l'on
vient justement de ne pas creer. Laisses tels quels, ils font echouer l'application a la
**premiere requete**, avec une erreur SQL de table absente plutot qu'un message
comprehensible.

`.env.example` les place donc sur `file` / `sync` / `file`. Ne pas les remettre sur
`database` sans avoir d'abord fait creer les tables correspondantes cote Python — ce qui
n'a aucun interet ici.

## Et les modeles Eloquent ?

Ecrits **au fil de l'eau**, quand une page portee en a besoin, jamais en prealable. Sur
les 63 tables, **5 seulement** portent `created_at` et `updated_at` : la quasi-totalite
des modeles demande donc un `public $timestamps = false;` explicite, ou des colonnes
d'horodatage nommees a la main. Voir `docs/migration/ARCHITECTURE-UI.md`.
