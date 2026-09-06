# DOSSIER 34 — ce qui vous attend

**Remesuré le 2026-09-06 à 11:36 CEST.** *Version précédente : 2026-09-05 à 23:40. Sept de ses
treize points sont tombés depuis — ils sont listés en bas, avec ce qui les a fermés.*

> **Chaque chiffre porte SA COMMANDE DE REMESURE.** *Un chiffre récité n'a plus de source : il a
> une habitude. Ce document a lui-même transporté « ~240 commits d'avance » pendant treize
> heures ; la valeur était 62.*

---

## ⑴ ⛔ LA FORME DE L'ÉCHANGE DES PORTS — c'est le seul blocage technique restant

**Tout le reste est prêt.** *Le prédicat de plateforme des 87 suites est posé (`a329876`), son
export l'est aussi (`3b8d093`), `LEGACY_URL` est en configuration. Les suites suivront la cible
quelle que soit l'adresse.*

**Mais l'échange n'est pas une substitution de chiffres :**

    portage   publie  ${LARAVEL_PORT}:80          HTTP SEUL
    legacy    publie  ${HTTP_PORT}:80  ET  ${HTTPS_PORT}:443

*Échanger les numéros donnerait du HTTP sur 8443 — un port conventionnellement TLS.*

    A. donner le TLS au portage    certificat, vhost, `a2enmod ssl`
                                   -> il prend vraiment 8080 ET 8443
    B. le portage prend 8080 seul  8443 reste au legacy
                                   -> ce n'est plus « prendre son adresse »

**Si vous ne tranchez pas, les ports restent en l'état — ce qui ne casse rien.**

    remesure : grep -n 'PORT}:' docker-compose.yml

---

## ⑵ ⛔ CE QUI EMPÊCHE D'ÉTEINDRE LE LEGACY — et ce ne sont pas des liens

    30 fichiers .php metier servis   (hors vendor, hors _deprecated)
    76 catalogues de langue          (des `return [...]`, aucun geste)

    remesure : python3 — rglob('*.php') moins '_deprecated' et 'vendor'

**Le portage ne dépend PLUS du legacy** : *les 4 contrôleurs posent `lienLegacy => null` sans
condition, les 8 lignes de vue sont sous un `@if` jamais vrai, `api_proxy` a 0 occurrence non
commentée, la passerelle est une route Laravel, l'authentification est propre.*

> **Mais ne pas LIER et pouvoir ÉTEINDRE sont deux propriétés distinctes.** *Seule la première
> est acquise.*

**Deux fichiers portent des capacités qu'aucun autre chemin n'atteint :**

    legacy/iptables/index.php   branche `restore` -> POST /iptables-restore
                                bloque sur l'arbitrage du PORT SSH
    legacy/security/index.php   /cve_scan (chemin compose) + /cve_whitelist
                                l'un bloque sur S7b

**Et trois autres pages restent pour leurs gestes d'écriture sous arbitrage** — *`bashrc`
(deploy, prerequisites, restore), `fail2ban` (install, restart), `ssh` (K4).*

> **Le legacy meurt le jour où vous tranchez ces gestes. Pas avant, et rien d'autre ne le
> retient.**

---

## ⑶ ⛔ L'ORACLE D'ÉNUMÉRATION — `DOSSIER-24`, toujours actif

    processus MAIL_MAILER   smtp      <- ce qui OPERE
    fichier .env            log       <- ce qu'on LIT en croyant verifier

    remesure : docker exec rootwarden_laravel sh -c 'echo $MAIL_MAILER'
               docker exec rootwarden_laravel grep '^MAIL_MAILER' /var/www/html/.env

**Un POST sur `/mot-de-passe-oublie` — page publique — envoie un courriel réel. Sous `mod_php`
sans `php-fpm`, la poignée TLS part PENDANT la requête et SEULEMENT dans la branche
« l'adresse existe ».**

    accepter en le sachant   gratuit, et c'est une DECISION
    poser `php-fpm`          le ferme PAR CONSTRUCTION
    desarmer                 editer `srv-docker.env` PUIS RECREER

⛔ **« Désarmer » a un faux remède** : *`.env` porte déjà `log` et PERD contre l'environnement du
processus.* **Qui l'ouvre pour vérifier y lit la valeur sûre et ne fait rien.**

---

## ⑷ TROIS CAPACITÉS MORTES SANS DÉCISION

    /policy/rollback      POST — ouvre une session SSH, ECRIT sur les machines
    /policy/deployments   GET  — lecture
    /policy/list          GET  — lecture

    remesure : grep -rl 'policy/<nom>' laravel/public/js laravel/resources   -> 0 chacune

*Leur interface vivait dans `_deprecated/`.* ⚠ **Et leur garde PASSE SES TESTS — un vert se lit
« saine ».** *Trois issues : leur rendre une interface · les retirer · les laisser en le
sachant. La troisième est légitime SI elle est écrite.*

---

## ⑸ 28 SUITES HORS DE TOUT LOT

    116 fichiers `go-*.mjs`  ·  88 enrolees  ·  28 HORS LOT

    remesure : python3 — les deux tableaux de rejouer-lot.sh contre les fichiers du disque

**Une suite hors lot ne rougit JAMAIS et garde ses effets de bord intacts.** *Deux d'entre elles
visaient la production ; les deux sont corrigées.* **Ce qui manque n'est pas une liste plus
longue : c'est que l'écart soit un CONTRÔLE — enrôlée, ou portant la raison de son exclusion,
et le runner refuse de démarrer sinon.**

---

## ⑹ LES GESTES CLASSIQUES, INCHANGÉS

    rotation du mot de passe SMTP    en clair dans l'environnement du conteneur
    `security/backend-cve`           6 commits jamais relus, jamais poussee
    `security/semgrep-regles-mortes` 32 commits, idem
    K4 sur la machine 3              portee arbitree `rootwarden` SEUL
    DOSSIER-32                       scan sortant, effets sur des tiers
    migrations 063/064/065           ecrites, non appliquees
    `laravel/.env:68`                `LEGACY_URL` MORT — l'environnement gagne.
                                     A retirer, sinon on l'editera sans effet.
    `docker-compose.prod.yml`        AUCUNE sonde de vie sur le service web

---

## ✅ CE QUI EST TOMBÉ DEPUIS LA VERSION DE 23:40

    conteneurs recrees          version 2.0.11 servie · inode 1998793 des DEUX cotes
    adresse de contact          gauderic.broussier@magiline.fr, en service
    durcissement Apache         `Server: Apache` — plus de version ni d'IP interne
    sonde de vie du legacy      visait la racine archivee — healthy en 10 s
    poussee                     Migration-Laravel a jour
    fusion                      main = origin/main = 3b0c50c, 305 commits
    step-up sur l'effacement    livre, atteste sur 7 criteres SCELLES avant lecture
    comptes 77 / 78             supprimes

    remesure de l'amont : git fetch && git rev-list --left-right --count 'origin/main...main'
