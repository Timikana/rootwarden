# ⚠ Le cache Blade : `git checkout` sur une vue ARME un 500

**Mesure du 2026-09-03. 28 pages d'erreur servies en sept minutes sur le socle,
donc sur toutes les pages du portage — avec un contenu identique a `HEAD`.**

## Le mecanisme, en trois proprietaires

    sources des vues     utilisateur:utilisateur  664
    repertoire du cache  www-data:www-data        755
    fichiers compiles    root:root                755   <- ecrits par `view:cache` (entrypoint)

Quand la source d'un gabarit devient **plus recente que son compile**, PHP
(www-data) recompile, puis appelle `touch()` sur un fichier **appartenant a
root** :

    local.ERROR: touch(): Utime failed: Operation not permitted
      (View: /var/www/html/resources/views/layouts/portail.blade.php)

L'exception remonte : **500 a chaque requete, indefiniment.** Le cache ne se
repare pas seul — *il echoue a se reparer, en boucle.*

## ✅ LA CAUSE RACINE — l'entrypoint, et une ligne la ferme

    laravel/docker-entrypoint.sh:25   chown -R www-data:www-data storage bootstrap/cache
                                :44   php artisan view:cache        <- EXECUTE EN ROOT

**La ligne 44 defait l'intention de la ligne 25 pour les fichiers qu'elle cree.**
L'entrypoint tourne en root, puis `apache2-foreground` fork des travailleurs `www-data`.

> **La cause est donc RECREEE A CHAQUE DEMARRAGE du conteneur.** *Un correctif manuel
> — `chown` a la main, ou `view:cache` relance — est annule au redemarrage suivant.*

**Ventilation mesuree le 2026-09-03, qui l'etablit :**

    root      07:48   111 fichiers   <- le view:cache de l'entrypoint, en root
    www-data  07:48     1 fichier
    www-data  08:44    39 fichiers   <- crees par des REQUETES, apres le demarrage

**Le correctif durable, apres la ligne 44 :**

    + # `view:cache` tourne en root : sans ce chown, les compiles appartiennent a
    + # root dans un repertoire www-data, et TOUTE modification d'une vue fait
    + # echouer la recompilation -> 500 sur toutes les pages.
    + chown -R www-data:www-data storage/framework/views 2>/dev/null || true

*Preferable a `su -c … www-data` : il ne change pas qui execute `artisan`, donc aucun
risque sur l'environnement de cette commande, et il est idempotent. Le depot fournit
deja ce motif a la ligne 25 — c'est la meme regle appliquee APRES la creation.*

### ⚠ Deux proprietes du repertoire, mesurees, qui decident du rattrapage

    repertoire  storage/framework/views   www-data:www-data  drwxr-xr-x (755)
                                          -> AUCUN bit collant
                                          (temoin : /tmp est drwxrwxrwt 1777)

    1. www-data CREE bien dans ce repertoire      -> les 39 fichiers de 08:44
    2. www-data n'ECRASE PAS un fichier root      -> les 28 echecs n'ont RIEN ecrit :
       le compile du socle est reste root:root et 07:48:46 pendant les 7 minutes

**Donc un `view:cache` lance en `www-data` ECHOUERAIT sur les compiles deja presents** —
il appellerait `put()` sur des fichiers root, exactement comme une requete web.
**Le rattrapage manuel exige `view:clear` D'ABORD** : sans bit collant, le proprietaire
du repertoire supprime n'importe quel fichier dedans, quel qu'en soit le proprietaire.

### Etat au 2026-09-03 : latent, pas actif

    compiles au total                      151   (111 root · 40 www-data)
    source plus recente que son compile      0   <- AUCUNE mine amorcee
    compiles a jour                        151   <- temoin inverse

Les 151 portent tous un pied de page `/**PATH … ENDPATH**/`, donc le mappage
source→compile est **complet** — c'est ce qui rend ce compte verifiable.

## Ce que cela implique pour tout le monde

> **`git checkout -- <vue>` n'est pas un defaire neutre.** Il restitue le
> CONTENU et arme une panne par la DATE. Sur du code interprete a chaque requete
> le `mtime` est neutre ; sur un gabarit **compile en cache**, la date est une
> entree du systeme.

Et ce n'est pas propre a un accident : **2 occurrences du 2026-09-01 a 15:30
CEST** suivent le commit `9422ab5` de 31 minutes. Toute session qui edite une vue
peut faire tomber le portage sans le savoir.

## La conduite

1. **Relever les dates AVANT d'ecrire.** Sans ce releve il n'y a aucune date a
   restituer, et la seule issue devient une reconstruction complete du cache —
   non bornee, elle pollue tout un banc en cours.

       stat -c '%y  %n' <chaque cible>

2. **Defaire en DEUX gestes.**

       git checkout -- <vue>
       touch -d '<date relevee AVANT>' <vue>

3. **Verifier au RESEAU, pas au contenu.** `git diff --quiet` disait « identique
   a HEAD » pendant que le portage rendait 500.

       curl -s -o /dev/null -w '%{http_code}' http://localhost:8444/connexion   # 200
       curl -s -o /dev/null -w '%{http_code}' http://localhost:8444/zzz         # 404 = temoin

4. **Balayer** apres coup : toute vue dont le `mtime` depasse la date de
   construction du cache arme la meme panne.

## ⚠ Deux pieges de mesure payes sur cet incident

- **Le journal est en UTC, l'hote en CEST.** J'ai lu les 28 lignes
  « 06:44:38 → 06:51:43 » comme *anterieures* a mon geste de 08:44, donc comme
  l'incident d'autrui, et publie un rapport disant « sans effet mesurable ».
  `06:44:38 UTC = 08:44:38 CEST`, soit **neuf secondes apres**. *Le fuseau non
  nomme n'a pas produit une erreur : il a produit une innocence.*

- **`grep` est ici une FONCTION enveloppant ripgrep, qui respecte
  `.gitignore`.** `laravel/storage/` est ignore : `grep -rl 'rw-' <cache>` rend
  **0** la ou la verite est **48**. La sonde rendait 0 **et le temoin aussi** —
  et zero des deux cotes veut dire *la mesure n'a pas eu lieu*, jamais *l'objet
  est absent*. `git check-ignore` ne sert PAS de garde-fou : il repond que le
  chemin n'est pas ignore par git, la regle est propre a l'outil.
  Formes qui voient un repertoire ignore : `--no-ignore`, ou une boucle shell
  sans `-r`.

## ⚠ UN TROISIEME CACHE : OPCACHE, ET IL N'A PAS LE MEME REGLAGE DANS LES DEUX CONTENEURS

Mesure du 2026-09-03, en lisant la configuration que le DEPOT compile dans chaque conteneur.

    directive                     portage (laravel/Dockerfile)   legacy (php/Dockerfile)
    php.ini                       AUCUN copie -> les DEFAUTS     COPY php/php.ini  (:100)
    opcache.enable                1 (defaut)                     1        (php.ini:246)
    opcache.validate_timestamps   1 (defaut)                     On       (php.ini:269)
    opcache.revalidate_freq       2 s (defaut)                   60 s     (php.ini:259)   <-- ⚠
    opcache.enable_cli            0 (defaut)                     1        (php.ini:265)

`laravel/Dockerfile:22` fait bien `docker-php-ext-install … opcache` : **le portage a OPcache
activé**, mais aucun `php.ini`, donc il tourne sur les défauts. `docker-compose.yml:11` associe
`php/Dockerfile` à `container_name: rootwarden_php` — **c'est le legacy qui porte le 60 s.**

> **« `laravel/**` et `legacy/**` sont relus a CHAQUE REQUETE » est vrai de la SOURCE et faux du
> BYTECODE cote legacy : un fichier PHP y reste non relu pendant jusqu'a 60 secondes.**

**Et rien ne purge le bytecode** : `opcache_reset` / `opcache_invalidate` → **0 fichier sur 3169
scannés** *(témoin positif : « opcache » dans 5 fichiers, dont `php/php.ini` et
`laravel/Dockerfile` ; témoin négatif : 0)*. Seuls le temps ou un redémarrage du conteneur
l'effacent.

**Pourquoi ça trompe** : un correctif appliqué au legacy et vérifié tout de suite peut paraître
**inerte pendant une minute** — et le legacy est la cible de RÉFÉRENCE des mesures de parité.
*Le délai est assez long pour tromper, assez court pour disparaître avant qu'on cherche.*

**⚠ Ceci est un cache DISTINCT de celui des gabarits Blade** décrit ci-dessus. Les 28 pages
d'erreur du 2026-09-03 venaient du `touch()` sur un compilé appartenant à root, **pas** d'OPcache.
Les confondre ferait chercher au mauvais endroit.

**Borne de cette mesure** : elle lit la configuration que le dépôt **compile**, pas celle des
conteneurs **en service** (`docker` refuse l'accès depuis l'hôte de cette session). Pour trancher
sur le serveur, il faut lire `opcache.revalidate_freq` **par une requête HTTP** dans
`rootwarden_php`, jamais par `docker exec` — la SAPI de service est la seule qui compte.

## ⚠ DEUX CLASSES D'INSTRUMENT FAUX, ET LA SECONDE NE SE TRAHIT PAS

Relevés le 2026-09-03, à une heure d'intervalle, par deux sessions.

    grep -rl 'rw-' <cache>        ->   0 fichier    la verite etait 48
    grep -l 'sudo_preset'         ->  11 fichiers   la verite etait  1 ECRIVAIN

**Le premier est un instrument AVEUGLE** : ripgpep respecte `.gitignore` (ci-dessus).
**Le second est un instrument qui MESURE AUTRE CHOSE QUE SA QUESTION** : il compte des
*mentions* là où la question portait sur des *écrivains*. Filtré sur `UPDATE|INSERT`, il rend 1.

> **Le second est le plus dangereux : il rend un nombre plausible, et il allait servir à
> contredire un pair.** *Le premier s'est trahi par un témoin à zéro ; le second n'aurait
> rien trahi.*

**How to apply :**

- un compte de `grep` porte le nom de la **chose**, pas le **geste**. Pour compter des
  écrivains, filtrer sur le verbe (`UPDATE`, `INSERT`, `DELETE`, `->execute`) ;
- même piège sur l'atteignabilité : *citer* une route n'est pas y *mener*. Un compte de
  mentions inclut les **auto-références** — `serveurs` en avait une centaine, presque
  toutes dans son propre gabarit. Ancrer sur `href=`/`action=` et **exclure le fichier de
  la page elle-même** ;
- **et énumérer par ROUTE, jamais par MODULE.** Un module peut être atteignable pendant
  qu'une de ses pages ne l'est pas : `notifications` est liée depuis le socle,
  `notifications.reglages` ne l'est de nulle part — le préfixe partagé rend la confusion
  invisible ;
- ⚠ **une sonde fondée sur `glob` + lecture n'a pas la cécité de `grep`.** Contre-épreuve :
  elle voit les 151 fichiers de `laravel/storage/framework/views`, que `grep -r` rend à 0.

## Ce que `banc-libre.sh` n'a pas vu

Il a rendu **« RIEN VU »** du debut a la fin, pendant que les 28 exceptions
partaient. Il surveille la charge, pas l'etat servi. **« RIEN VU » n'est pas
« le portage repond ».**
