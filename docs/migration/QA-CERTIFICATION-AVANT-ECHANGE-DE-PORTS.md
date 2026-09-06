# QA — certification des chantiers avant l'échange de ports

**2026-09-06.** Ce que je certifie porte sur des **artefacts commités**. Un arbre en vol ne se
certifie pas : la mesure serait vraie d'un état que personne ne retrouvera.

---

## ✅ `c1` — `LEGACY_URL` : UNE définition, ZÉRO adresse en dur

    TEMOIN  fichiers laravel/ lus                                  331  (non nul)

    definitions `env('LEGACY_URL')`                                  1
      laravel/config/app.php:69   'url_legacy' => env('LEGACY_URL', 'https://localhost:8443')
    lectures `config('app.url_legacy')`                             12
      2 dans `LiensLegacy`, 2 dans `PortailController`, 8 dans des vues
    adresses du legacy ECRITES EN DUR (8080 · 8443 · .245)            0
      (les 2 occurrences du motif sont le defaut de config lui-meme et un commentaire)

**Le mécanisme survit à l'échange de ports** : aucun appelant ne connaît l'adresse.

⚠ **Mon premier relevé annonçait ZÉRO lecture** — parce que je cherchais `legacy_url` quand
la clé est `url_legacy`. *Un zéro produit par mon propre motif, et du côté qui alarme.*

### ⛔ MAIS LA VALEUR VIT DANS DEUX FICHIERS, ET C'EST LE MOINS ATTENDU QUI SERT

    /var/www/html/.env         LEGACY_URL=https://192.168.0.245:8443   <- CELUI QUI SERT
    environnement du PID 1     <absente>
    srv-docker.env:87          LEGACY_URL=https://192.168.0.245:8443   <- n'atteint PAS le service

`srv-docker.env` n'est pas suivi par git (config locale) et son injection par `env_file:` se
fait **au démarrage du conteneur** : la ligne n'a pas atteint celui qui tourne depuis 11 h.
La valeur servie vient donc du **fichier `.env`**, que `safeLoad()` charge *parce qu'aucune
variable d'environnement ne l'ombre*.

> **C'est l'image inversée du défaut `MAIL_MAILER` de cette nuit.** Là, l'environnement
> gagnait contre le fichier ; ici le fichier gagne parce que l'environnement est vide.
> **La même paire, et l'autorité bascule selon lequel des deux est renseigné.**

**Conséquence pour l'échange de ports, à traiter AVANT et non après :**

1. Modifier `srv-docker.env` **seul** ne change rien tant que le conteneur n'est pas recréé.
2. À la recréation, l'environnement **prend l'autorité** et l'emporte sur `.env`.
3. **Donc les deux fichiers doivent porter la MÊME nouvelle valeur**, sans quoi le portage
   renverra vers l'ancienne adresse — ou vers lui-même — *sans qu'aucun test ne rougisse*.

Et le défaut de `config/app.php:69` est `https://localhost:8443` : après l'échange, **ce port
sera celui du PORTAGE**. Un environnement où `LEGACY_URL` manque ferait pointer les douze
renvois legacy vers le portage lui-même. *Un repli qui devient faux le jour de la bascule.*

---

## ✅ `4f` — les renvois `lienLegacy` : NULS, et c'est justifié

**Précision de vocabulaire qui change la lecture** : ils ne sont pas *repointés*, ils sont
**mis à `null`**. 12 sites = **4 contrôleurs** qui passent `null` + **4 vues** qui font
`@if ($lienLegacy)` (deux lignes chacune).

Le motif est écrit, identique aux quatre sites — *« la cible est ARCHIVÉE et rend 404 »* — et
**je l'ai vérifié plutôt que de le croire** :

    legacy/_deprecated/groups            ⛔ ARCHIVE
    legacy/_deprecated/documentation.php ⛔ ARCHIVE
    legacy/_deprecated/wazuh             ⛔ ARCHIVE
    legacy/_deprecated/ssh-audit         ⛔ ARCHIVE
    CONTRE-EPREUVE  legacy/iptables/     ⚠ VIVANT  (l'instrument distingue)

Ces quatre pages **n'ont aucun lien legacy à casser** : l'échange de ports ne les touche pas.
Et `TableDesGardes` porte les redirections publiques `GET groups`, `GET ssh-audit`,
`GET documentation.php` — un utilisateur arrivant par l'ancienne URL est renvoyé au portage.
*Le circuit est cohérent dans les deux sens.*

---

## ✅ `94` — `b1ec180`, la sonde de vie

Le correctif est juste : la sonde visait `https://localhost:443/`, or `legacy/index.php` est
archivé depuis `de9669c` ; la racine rend 403, `curl -f` traite 403 comme une erreur.

⚠ **Et il n'est pas encore en effet** : `rootwarden_php` est toujours `unhealthy`, parce que le
conteneur n'a pas été recréé. *Même famille que `LEGACY_URL` — un correctif commité n'est pas
un correctif en service.* La recréation prévue pour l'échange de ports le résoudra ; **le dire
évite qu'on lise le `unhealthy` restant comme un second défaut.**

---

## ⛔ `ec` — `E2E_CIBLE` : NON CERTIFIABLE AUJOURD'HUI

    fichiers `tests/e2e/` modifies et NON COMMITES   87
    occurrences de `E2E_CIBLE` dans l'arbre           87
    occurrences dans `HEAD`                            0

**Rien n'est commité.** Je ne certifie pas un arbre en vol : la mesure porterait sur un état
que personne ne pourra retrouver, et 87 fichiers peuvent bouger entre ma lecture et le commit.

*Ce n'est pas un refus — c'est un « pas encore ». Qu'`ec` pousse et je mesure : le prédicat,
sa garde de cohérence, et surtout **qu'aucune suite ne change de cible en silence**.*
