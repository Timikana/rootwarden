# DOSSIER-52 — `APP_URL` envoie un jeton de réinitialisation en clair vers le portail qu'on démonte

**Écrit le 2026-09-08, ~05:1x.** ⛔ **Le seul défaut de la nuit qui SORTE DU BÂTIMENT.**
*Un courriel ne se rappelle pas.*

---

## LA CHAÎNE, MESURÉE BOUT À BOUT

```
laravel/.env:18                    APP_URL=http://192.168.0.245:8444
:8444 est servi par                rootwarden_php   ->  LE LEGACY
ReinitialisationController.php:69  $lien = route('reinit.formulaire', [...])
                            :94    Mail::raw( ... )

le lien produit, mesure par `artisan tinker` :
    http://192.168.0.245:8444/reinitialiser?uid=1&jeton=XXX
```

**Ce lien fait trois choses fausses à la fois :**

```
http://          un JETON DE REINITIALISATION en CLAIR
:8444            le portail qu'on demonte, pas celui qui sert la page
301 -> https://192.168.0.245:8444/reinitialiser   port non servi en HTTPS  = CASSE

le lien qui MARCHE : https://192.168.0.245:8443/reinitialiser   200
```

> **Le destinataire fuite son jeton en clair, puis atterrit nulle part.** *Et il ne peut pas
> le savoir : l'adresse ressemble à celle qu'il attendait.*

---

## POURQUOI PERSONNE NE L'AVAIT VU — TROIS RAISONS QUI SE CUMULENT

### ① C'est la TROISIÈME occurrence d'une espèce déjà payée deux fois

**L'échange du 2026-09-06 n'a pas changé les VALEURS : il a inversé leur ATTRIBUTION.**

```
1  docker-entrypoint.sh:86   LARAVEL_HTTPS_PORT:-8446   corrige avant ce tour
2  config/app.php:69         url_legacy => …:8443       corrige ce matin (38d366ef)
3  laravel/.env:18           APP_URL=…:8444             ⛔ NON CORRIGE
```

**`:8444` était le port HTTP du PORTAGE avant l'échange.** *La valeur était juste ; son sens
s'est inversé sous elle.* **Et c'est la seule des trois qui compose une URL destinée à
quitter la machine.**

### ② `APP_URL` N'EST GARDÉ PAR RIEN, ET PAS PAR NÉGLIGENCE

```
occurrences dans srv-docker.env           0
occurrences dans srv-docker.env.example   0
laravel/.env                              gitignore (laravel/.gitignore:3)
```

> ⛔ **Aucune garde fondée sur l'arbre ne peut lire ce fichier.** *Mon propre contrôle
> `ports-des-deux-portails.mjs`, écrit ce matin précisément pour cette classe de défaut,
> était structurellement incapable de le voir.*

**Et il échappe aussi à `env-merge.sh`** : ce mécanisme n'alimente que `srv-docker.env`, où
`APP_URL` n'existe pas. *Un fichier de configuration hors de l'arbre et hors du mécanisme de
propagation n'a aucun gardien.*

### ③ 92 SITES COMPOSENT UNE URL, ET UN SEUL LA FAIT SORTIR

```
route() / url() dans laravel/app/   92 sites
Mail:: (toutes formes)               1 site   -> ReinitialisationController.php:94
```

**Sur 91 des 92, un `APP_URL` faux est invisible** : ce sont des redirections internes, le
navigateur suit, personne ne lit l'hôte. **Le 92ᵉ le met dans un courriel.**

> **Un défaut de configuration partagé par 92 consommateurs dont un seul l'expose est plus
> difficile à voir qu'un défaut qui casse tout** : les 91 autres rendent le témoignage
> rassurant.

---

## ⛔ CE QUE ÇA CHANGE POUR L'ÉTAPE ⑤ DU DOSSIER-48

J'avais écrit que l'étape ⑤ tenait en **une variable** : `MAIL_MAILER=smtp`.

> ⛔ **ARMER SMTP MAINTENANT ENVERRAIT CES LIENS À DE VRAIES PERSONNES.** *Aujourd'hui
> `MAIL_MAILER` vaut `log` : le lien cassé s'écrit dans un fichier. C'est le seul motif pour
> lequel ce défaut n'a encore blessé personne.*

**L'ordre est donc contraint, et il ne l'était pas dans ce que j'ai écrit :**

```
1  corriger APP_URL     ->  https://192.168.0.245:8443
2  verifier le lien     ->  `artisan tinker` doit rendre :8443 et https
3  ALORS armer MAIL_MAILER=smtp
```

**Inverser 1 et 3 transforme un défaut journalisé en un défaut expédié.**

---

## ⚖ CE QUI EST À L'EXPLOITANT, ET POURQUOI JE N'Y TOUCHE PAS

```
laravel/.env    hors de l'arbre (gitignore) · appartenant a root dans le conteneur
                · configuration d'un service VIVANT
```

*Ce n'est pas un fichier de code : c'est l'état d'exploitation.* **Et la correction prend
effet différemment selon le régime** — `.env` est relu au démarrage du framework, donc un
`config:clear` ou un redémarrage est nécessaire ; il n'y a pas de `bootstrap/cache/config.php`
aujourd'hui, ce qui simplifie.

**Ce que je recommande, dans cet ordre :**

```
1  APP_URL=https://192.168.0.245:8443    dans laravel/.env
2  DECLARER APP_URL dans srv-docker.env.example, pour qu'`env-merge` le propage
   et qu'une garde de l'arbre puisse enfin le lire
3  etendre `ports-des-deux-portails.mjs` a APP_URL une fois (2) fait
```

*Le point 2 est le vrai correctif* : le point 1 répare la valeur, le point 2 répare
**l'absence de gardien**. **Sans le 2, la prochaine inversion sera aussi invisible que
celle-ci.**

---

## ⚠ ET MA PROPRE MESURE A FAILLI CACHER TOUT ÇA

**J'ai d'abord annoncé « le portage n'envoie AUCUN courriel ».** Ma sonde cherchait :

```
Mail::send · Mail::to · Mailable · ->notify( · Notification::
le code emploie   Mail::raw
```

> **J'ai énuméré les formes d'envoi au lieu de raisonner sur le mécanisme.** *Et l'énumération
> était celle des formes auxquelles j'ai pensé.*

**C'est textuellement la règle que je porte depuis des jours** — *fonder sur le MÉCANISME et
pas sur l'ÉNUMÉRATION* — et je l'ai enfreinte sur la mesure qui comptait le plus. **Sixième
fausse alarme de la nuit, et la seule dont la conclusion était RASSURANTE dans un sens et
ALARMANTE dans l'autre** : j'allais dire « la réinitialisation n'est pas portée » (faux) et
donc ne jamais regarder l'URL qu'elle compose (le vrai défaut).

*Ce qui m'a fait continuer n'est pas la mémoire de la règle : c'est que `/mot-de-passe-oublie`
rendait 2387 octets de page. **Une page qui existe pour une capacité que je venais de
déclarer absente est un reste inexpliqué.***
