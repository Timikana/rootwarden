# DOSSIER 35 — les arbitrages, rendus

**Session 8 (DSI délégué), 2026-09-06 à 12:30 CEST.** *L'exploitant a demandé que je décide au
lieu de lui remonter. Ce document décide. Chaque décision porte sa mesure et son geste exact.*

> **Ce qui reste chez lui, à la fin, est nommé — et c'est court.**

---

## ⑴ 🔴 LE PORTAIL SERT L'AUTHENTIFICATION EN CLAIR — priorité absolue

**Trouvé en cherchant à trancher la forme de l'échange des ports. Ce n'est pas une question de
ports.**

    rootwarden_laravel   publie SEULEMENT 8444->80         AUCUN TLS
    https://localhost:8444                000  (echec de connexion)
    le formulaire de connexion            action="http://…:8444/connexion"
    cookies de session                    path=/ · samesite=lax · PAS de `Secure`
    TEMOIN — legacy https://…:8443        200

    remesure : docker ps --format '{{.Names}} {{.Ports}}'
               curl -sk -o /dev/null -w '%{http_code}' https://localhost:8444/connexion

**Mot de passe et code TOTP transitent en clair sur le réseau.** *Le prédécesseur avait du TLS ;
le successeur l'a perdu.* **Ce n'est pas un manque hérité — c'est une régression introduite par
la migration.**

⚠ **Et il n'y a AUCUN frontal** : *quatre services en production — `python`, `php`, `db`,
`laravel` — aucun `nginx`, `traefik` ni `caddy`.* **Les utilisateurs joignent le conteneur
directement.**

### DÉCISION — le portail reçoit le TLS, INDÉPENDAMMENT de l'échange des ports

    1. publier `443` sur le service `laravel`
    2. un vhost TLS, avec le meme certificat que le legacy (`a2enmod ssl`)
    3. `SESSION_SECURE_COOKIE=true` UNE FOIS le TLS en place — pas avant,
       sinon plus aucune session ne s'etablit
    4. redirection HTTP -> HTTPS, comme le legacy la porte deja

**Ordre imposé : 1-2, vérifier au réseau, PUIS 3.** *Poser `Secure` sans TLS coupe l'accès à
tout le monde — c'est la forme « la garde mord et refuse tout le monde » qu'une certification a
nommée ce matin.*

---

## ⑵ L'ÉCHANGE DES PORTS — APRÈS ⑴, et il devient trivial

**La question « le portail n'a pas de TLS » cessait de se poser dès qu'on la traitait.**

    le portage prend  8080:80  ET  8443:443
    le legacy passe   8081:80  et  8444:443

*Les 87 suites suivent `E2E_CIBLE`, posée par le runner (`a329876`, `3b8d093`) : elles ne lisent
plus le port.* **`LEGACY_URL` et `LARAVEL_URL` sont en configuration.**

⚠ **Reprendre les deux URL À LA MAIN** : *elles portent des valeurs littérales et non
interpolées. J'ai tenté la forme `${SERVER_NAME}:${PORT}` — elle rend `http://:` parce que dans
un `.env` une variable ne référence que ce qui est défini PLUS HAUT, et les deux URL précèdent
leurs dépendances.* **Restaurée dans la minute ; le service n'a rien vu.**

---

## ⑶ `DOSSIER-24` — L'ORACLE SE FERME PAR `php-fpm`

    image actuelle   php:8.4-apache   ·   mods : mpm_prefork + php.load  (mod_php)

**Sous `mod_php`, `Response::send()` ne peut pas terminer la requête : la poignée TLS vers le
fournisseur part PENDANT la requête, et SEULEMENT dans la branche « l'adresse existe ».**

### DÉCISION — poser `php-fpm`, et NON désarmer

**Les trois issues n'étaient pas équivalentes :**

    accepter        laisse un oracle d'enumeration sur une page PUBLIQUE
    desarmer        retire la reinitialisation a qui a perdu son mot de passe
                    -> payer une propriete avec la capacite qu'elle protege
    poser php-fpm   ferme PAR CONSTRUCTION, ne coute AUCUNE capacite

**Et ça se fait dans la même reconstruction que ⑴.** *Un seul redémarrage pour les deux.*

---

## ⑷ LES TROIS `/policy/` ORPHELINES — RETIRÉES

    /policy/rollback      POST — ouvre une session SSH, ECRIT sur les machines
    /policy/deployments   GET
    /policy/list          GET
    backend/routes/policies.py:11-13   ·   0 appelant chacune

    remesure : grep -rl 'policy/<nom>' laravel/public/js laravel/resources

**Leur interface vivait dans `_deprecated/`. Leur garde PASSE SES TESTS — un vert se lit
« saine ».**

### DÉCISION — les retirer, et retirer leur entrée de step-up avec

*Laisser une route destructrice qu'aucune interface n'atteint, gardée par une règle verte,
c'est laisser une porte dont personne ne sait qu'elle existe.* **Et ce matin a montré ce que ça
coûte : un POST de déploiement sudo vers la production n'était refusé QUE parce qu'un
vérificateur avait été archivé — pas par une décision.**

⚠ **Le retrait DOIT emporter l'entrée correspondante de `StepUp`** : *une marque qui n'ouvre
plus rien est un nom libre dans une liste fermée.*

---

## ⑸ LES 28 SUITES HORS LOT — LE RUNNER REFUSE DE DÉMARRER

    116 fichiers `go-*.mjs`  ·  88 enrolees  ·  28 hors lot
    l'instrument existe deja : tests/e2e/inventaire-hors-lot.mjs

**Une suite hors lot ne rougit JAMAIS et garde ses effets de bord intacts.** *Deux visaient la
production.*

### DÉCISION — l'écart devient un CONTRÔLE, pas une découverte

    un `go-*.mjs` est ENROLE, ou porte dans son en-tete la raison de son exclusion
    le runner REFUSE DE DEMARRER si un fichier ne satisfait ni l'un ni l'autre

*L'exclusion délibérée AVEC sa raison écrite est le bon régime — `go-ssh-audit-scanall` le fait
déjà.* **Ce qui manque n'est pas une liste plus longue, c'est que l'oubli soit impossible.**

---

## ⑹ CE QUI RESTE À L'EXPLOITANT, ET RIEN D'AUTRE

**Je ne décide pas ces quatre-là, et je dis pourquoi plutôt que de m'abriter derrière une
règle :**

    NOPASSWD: ALL (K4)          un choix de POSTURE sur son parc — combien de
                                pouvoir la plateforme detient en permanence
    S7b (le scan qui aboutit)   il ENVOIE un courriel a des tiers
    le port SSH d'`iptables`    joint des machines de son infrastructure
    la rotation du secret SMTP  il detient le compte

> **Ces quatre engagent SON infrastructure et SES tiers, pas la forme du produit.** *Un DSI
> délégué arbitre le produit ; il n'engage pas le parc de quelqu'un d'autre.*

**Et ces quatre sont les SEULES choses qui retiennent encore le legacy.** *Le portage n'en
dépend plus : 0 renvoi rendu, 0 `api_proxy`, authentification propre.*
