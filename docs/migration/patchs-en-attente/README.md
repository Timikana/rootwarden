# Patchs préparés, vérifiés, **non appliqués**

Session 4. Persistés le **2026-09-03**, sur l'observation du Lead : *un patch vérifié qui ne vit que
dans un contexte de session n'attend pas une signature, il attend une compaction.*

> **Le journal n'est pas l'autorité — l'artefact l'est.** Ces fichiers sont hors `backend/`,
> `laravel/`, `legacy/` et `tests/e2e/` : **le gel du banc ne les couvre pas, et ils sont inertes.**

---

## Le régime de génération est ce qui les distingue

**Un patch ne se juge pas seulement sur ce qu'il change, mais sur l'arbre CONTRE lequel il a été
généré.** Deux de ces fichiers visent des arbres différents, et l'un doit **refuser** sur `HEAD`.

| | patch | régime | contrôle |
|---|---|---|---|
| 01 | `E-231-psk-illisible` | **HEAD** | `git apply --check` passe |
| 02 | `E-280-portee-scheduler` | **HEAD** | `git apply --check` passe |
| 03 | `telegraf-jeton-en-clair` | **HEAD** | `git apply --check` passe |
| 04 | `E-281-apres-fusion` | **`a345e65`** (après fusion de `security/backend-cve`) | `patch --dry-run` passe sur l'arbre post-fusion, **et `git apply --check` REFUSE sur `HEAD`** |

**Le refus du 04 sur `HEAD` est le contrôle, pas un défaut** : un apport destiné à l'après-fusion qui
s'appliquerait *aussi* sur `HEAD` viserait les mauvaises lignes — c'est-à-dire exactement le conflit
qu'on cherche à éviter.

## Ce que chacun ferme

**01 — `E-231`, la clé PSK illisible.** Le commentaire du code déclare l'étape « DECISIVE quand une
PSK est configurée », et la garde est `if psk_value:`. Or `psk_value` vaut `None` **et** quand aucune
PSK n'est configurée, **et** quand le déchiffrement a échoué — ce dernier n'étant qu'un
`logger.warning`. Le bloc est sauté, rien n'entre dans `echecs`, et `_conclut_geste` émet
`SUCCESS_MACHINE::`. **L'agent part sans sa clé et le portail annonce la réussite.** Le patch couvre
aussi le cas d'une PSK qui **déchiffre en vide**.

**02 — `E-280`, la portée vide du planificateur SSH.** Les branches restreintes portent leur test de
vacuité **dans la condition d'entrée** (`and target_value`) : un champ laissé blanc n'entre jamais
dans sa propre branche et sort par le `else` final — **tout le parc**, sur une cron. Le patch pose une
branche `all` **explicite** et un `else` qui **refuse**. *Ce n'est pas une énumération de cas : c'est
un repli inversé, et il couvre les cinq branches d'un coup.*

**03 — le jeton Telegraf stocké en clair.** Le commentaire dit « Chiffrer le token Telegraf si
fourni » et la fonction ne contient **aucun** appel de chiffrement. **Les deux moitiés sont
indissociables** : chiffrer sans déchiffrer en lecture déploierait `sodium:…` comme jeton dans la
configuration de l'agent — *aujourd'hui le jeton est en clair et il **fonctionne** ; après, il serait
chiffré et **cassé**, silencieusement.*

**04 — `E-281`, ce que la fusion ne ferme pas.** `a345e65` rend la cible `machines` fail-closed et
exclut les archivées, mais **ne pose ni branche `all` explicite ni `else` qui refuse** : son dernier
`else` prend encore tout le parc vivant. Et ce chemin reste atteignable **par le schéma** —
`cve_scan_schedules.target_type` est `NULLABLE`, et `.get('target_type','all')` rend `None` sur un
`null` JSON explicite.

## ⚠ QUARANTAINE — ne pas appliquer

`QUARANTAINE-perime-refait-par-a345e65.patch` **s'applique sur `HEAD`**, et c'est précisément le
danger : son contenu est **déjà écrit** dans `security/backend-cve`. L'appliquer rendrait
conflictuelle une fusion aujourd'hui propre, **sur le hunk le plus sensible du dépôt**.

Il est conservé, et non supprimé, pour que personne ne le réécrive une troisième fois. *Un correctif
périmé qui garde le nom d'un correctif est un piège posé pour la session suivante — celui-ci porte son
état dans son nom.*

## Deux patchs retirés de ce dossier, et pourquoi

- **`E-280-portee-entree`** : **appliqué** le 2026-09-02 (`v1.38.180`). Il refuse sur `HEAD` parce
  qu'il y est déjà ;
- **`e187-forme`** : **appliqué** aussi — son contenu est présent dans `backend/routes/ssh.py`,
  vérifié par témoin positif.

*Un patch qui refuse peut être périmé OU viser un autre arbre. Les deux se distinguent en cherchant
son contenu dans l'arbre, pas en relisant son nom.*

## Remesure

```bash
for p in docs/migration/patchs-en-attente/0*.patch; do
  git apply --check "$p" && echo "OK   $p" || echo "refuse $p"
done
# le 04 DOIT refuser ; les 01 a 03 DOIVENT passer
```


---

## ⚠ `02-E-280-portee-scheduler` — **APPLIQUÉ** le 2026-09-04

Posé avec le refus de `'all'` à l'entrée, sur autorisation nommée du DSI. **Le fichier est conservé
comme trace de ce qui a été appliqué**, pas comme candidat.

**Et il portait un défaut que trois contrôles n'ont pas vu** : il appelait `logger.error(…)` alors que
`scheduler.py` définit `_log` (`:28`). `git apply --check` passait, `ast.parse` passait, l'import du
module passait — **seul `ruff` l'a vu** (`F821 Undefined name 'logger'`).

> **Le défaut était sur la branche que le patch existe pour protéger** : un `NameError` sur le repli
> fail-closed, c'est-à-dire au moment exact où la planification doit être refusée. *Un correctif qui
> lève sur son propre chemin de refus ne refuse pas : il plante, et ce qui suit un plant n'est pas
> écrit.*

**Corrigé dans le code ET dans ce fichier**, pour que la prochaine session n'hérite pas du défaut.

*C'est la démonstration de la condition posée par le DSI : « `git apply` puis relis le résultat —
`--check` dit que ça s'applique, pas que c'est juste. » Ici il fallait aller au-delà de la relecture :
un nom absent ne se voit pas à l'œil dans un diff de 35 lignes.*

## ✅ 05 et 06 — APPLIQUÉS le 2026-09-06 à 19:39 (échange des ports)

**Ne pas les rejouer.** `git apply --check --reverse` passe sur les deux : la preuve qu'ils sont dans
l'arbre. Conservés ici comme trace de la manœuvre, pas comme travail en attente.

    05  laravel/docker-entrypoint.sh   repli LARAVEL_HTTPS_PORT  8446 -> 8443
    06  scripts/rejouer-lot.sh         les deux bases + le controle d'ETAT du portail

*Appliqués dans `fa1a409`, avec la recréation des conteneurs et le contrôle des quatre ports.*

---

## `07-retrait-du-service-php-NON-APPLIQUE.patch` — le dernier geste de l'extinction

**Généré le 2026-09-08 09:0x, contre `HEAD`. `git apply --check` PASSE.** *Non appliqué, et il
ne doit pas l'être par une session : l'appliquer exige une **recréation**, qui appartient à
l'exploitant.*

### CE QU'IL FAIT, ET RIEN D'AUTRE

```
0 ajout · 64 suppressions · un seul fichier : docker-compose.yml
retire   le bloc de service `php` (lignes 8-70)
retire   la declaration du volume `php_sessions` (elle n'avait qu'un usage)
```

**Vérifié — il ne touche PAS :**

```
./legacy/version.txt:/var/www/html/version.txt:ro   monte DANS le portage
./legacy:/app                                        monte par composer, x2
```

*Ces deux-là survivent au retrait du service, et c'est voulu : `version.txt` est la source
unique du numéro de version, lue par `laravel/app/Support/Version.php`.*

### CE QUI JUSTIFIE QU'IL SOIT PRÊT MAINTENANT

**Le legacy ne sert plus une seule page** — étapes ②→⑦ exécutées et vérifiées au réseau. Il
reste treize fichiers sous `legacy/`, **zéro `.php`** : des actifs statiques, `composer.*`,
`vendor/.htaccess`, `logs/.htaccess` et le `.htaccess` racine.

**Et le conteneur est `unhealthy`** depuis que sa sonde de vie vise `/auth/login.php`,
archivé à l'étape ⑤ : cinq échecs `exit=22`, `restarts=0`, et **rien ne dépend de `php` en
`service_healthy`** (graphe vérifié). *L'`unhealthy` est le symptôme d'un service qui n'a plus
d'objet — ce patch est ce qui le fait disparaître, et non une correction de la sonde.*

### VALIDATION FAITE

```
docker compose -f <modifie> config --quiet     code 0

⛔ **CETTE VALIDATION ETAIT VRAIE SUR SON OBJET ET MUETTE SUR CELUI QUI COMPTAIT.**
RECTIFICATION du 2026-09-08 14:35.

Je l'avais jouee sur la BASE SEULE. **`docker-compose.prod.yml` existe** — un
fichier d'override documente dans `README.md`, `OPERATIONS.md` et
`CONTRIBUTING-SECURITY.md`, invoque par `docker compose -f base -f prod`. Je ne
le savais pas quand j'ai prepare ce patch.

Son bloc `php:` **ne porte ni `image:` ni `build:`** : il ne surcharge que
`volumes`, `read_only`, `tmpfs`, `cap_drop`, `cap_add`. Donc en retirant `php` de
la base sans toucher l'override, le patch laissait un service defini par le seul
override — et la superposition devenait **invalide** :

    avant l'extension du patch, sur des copies :
      base seule                 -> code 0
      base + prod (documentee)   -> « service "php" has neither an image nor a
                                      build context specified: invalid compose
                                      project »

**Le patch aurait casse le chemin de deploiement de PRODUCTION**, en passant la
validation que j'avais choisie.

Le patch porte desormais DEUX hunks — un par fichier compose — et l'epreuve est
rejouee de bout en bout sur des copies neuves :

    apres application : `php` = 0 dans la base ET dans l'override
    base seule                 -> code 0
    base + prod                -> code 0
    services restants          -> db · laravel · python

*Code de sortie capture SANS tube : un code qui traverse un tube n'est pas celui
de la commande.*

⚠ Et le patch DERIVE : `Hunk #2 succeeded at 315 (offset 28 lines)` — les
modifications de `docker-compose.yml` du 2026-09-08 l'ont decale de 28 lignes.
Il s'applique encore ; une derive assez grande le ferait echouer. **A rejouer
avant signature, pas a supposer.**
services declares                              db · laravel · python
                                                (`php` absent, les autres intacts)
```

⚠ *Validé avec `srv-docker.env` LIÉ et non copié : ce fichier porte des secrets et n'a jamais
quitté le dépôt.*

### ⛔ TROIS DÉCISIONS L'ACCOMPAGNENT, ET AUCUNE N'EST DANS LE PATCH

**① `HTTP_PORT`, `HTTPS_PORT`, `URL_HTTP`, `URL_HTTPS` dans `srv-docker.env` perdent leur
objet.** *Ce sont les ports du service retiré.* **Et `URL_HTTPS` alimente la liste blanche
CORS du backend** — `backend/server.py:137`, `E-481` : elle ne contient aujourd'hui qu'une
seule origine distincte, celle du legacy. **Après ce patch, elle nommera un portail qui
n'existe plus.** *C'est le moment que `E-481` avait daté « à l'extinction ».*

**② La sonde de vie part avec le service.** *Ne pas la déplacer une troisième fois : elle
visait la racine, l'archivage de `index.php` l'a cassée — 21 h d'`UNHEALTHY` faux le
2026-09-05 — puis elle a été liée à l'écran de connexion, que l'étape ⑤ vient d'archiver.*
**Il n'existe plus de page du legacy dont la survie soit plus longue que celle du conteneur.**

**③ Les quatre `<FilesMatch "^(db|menu|head|footer)\.php$">` du `.htaccess` gardent désormais
des fichiers absents** — d'où un `403` là où un `404` serait juste. *Laissé en place
volontairement : le reste du fichier protège encore réellement, et un `403` sur un chemin
inexistant ne trompe personne sur une capacité.*

### ⚠ CE QUE CE PATCH NE PEUT PAS SAVOIR

**Si un consommateur externe — signet, clé d'API, script d'exploitation, supervision — vise
encore `:8444` ou `:8446`.** *La mesure porte sur le dépôt ; elle ne voit pas les usages.*
**Le journal d'accès dit qu'en une heure, les seules requêtes reçues étaient la sonde de vie
elle-même — mais une heure n'est pas une semaine.**

### ✅ LE RISQUE « CONSOMMATEUR EXTERNE » EST LEVÉ — 38 HEURES, ET VOICI SES LIMITES

*J'avais écrit : « une heure n'est pas une semaine ». Le journal du conteneur en couvre **38
heures**, du 2026-09-06 19:40 au 2026-09-08 09:18. Mesuré, pas supposé.*

```
4782 lignes · 4499 requetes de 127.0.0.1 (la sonde) · 274 de 172.18.0.1 (l'hote)
                                                     ·   4 de 192.168.0.245

agents : curl/8.14.1 4753 · "-" 15 · Chrome/131 7 · HeadlessChrome 2
```

**Les trois catégories non-sonde, identifiées une par une :**

```
7  Chrome NON headless   06/09 19:45:42 -> :47, UN SEUL passage de 5 secondes,
                         depuis l'HOTE : GET login.php 200 · POST login.php 302
                         · verify_2fa.php 200 · adm/admin_page.php 404
                         -> une authentification REUSSIE, il y a 38 heures
4  192.168.0.245         08/09 05:04-05:52, curl, dont `/reinitialiser` — une
                         route du PORTAGE : ce sont MES propres mesures de ce
                         matin, arrivees par l'IP LAN de l'hote
15 agent "-"             des octets de poignee TLS (\x16\x03\x01...) sur le port
                         HTTP : mes `curl -k https://...:8444`
```

> **Aucun consommateur humain externe en 38 heures.** *Le seul passage d'un vrai navigateur
> date du 06/09, depuis cette machine, et le flux qu'il a emprunté — connexion puis second
> facteur — est porté.*

⛔ **CE QUE CETTE MESURE NE COUVRE PAS, ET IL FAUT LE DIRE :**

```
38 heures, pas une semaine ni un mois
le journal ne voit que ce qui ATTEINT ce conteneur — un client qui a renonce il y
   a des mois, ou qui n'interroge qu'une fois par semaine, n'y figure pas
et il ne voit pas un signet non ouvert, une cle d'API non employee, un script
   planifie a une cadence plus longue que la fenetre
```

*C'est la seule inconnue qui reste, et elle est bornée : appliquer le patch ne détruit rien
— `_deprecated/` garde 214 fichiers, et le bloc retiré est un `git revert` de distance.*
