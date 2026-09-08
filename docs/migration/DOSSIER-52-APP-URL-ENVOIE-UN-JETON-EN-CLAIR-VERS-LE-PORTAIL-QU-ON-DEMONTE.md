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

---

# AMENDEMENT — la forme dérivée ramène le piège qu'elle répare, et l'ordre des gestes le décide

**2026-09-08, ~05:2x, après `a179fa04` et `4aabbe1d`.** *Ma recommandation était moins bonne
que ce qui a été livré ; ce qui a été livré ramène un piège que le plan documente. Les deux
sont vrais.*

## ① CE QUE J'AI RECOMMANDÉ ÉTAIT PIRE

J'avais écrit : `APP_URL=https://192.168.0.245:8443`. **Une IP en dur dans un fichier
d'EXEMPLE que les déploiements copient.** *Fausse partout ailleurs qu'ici, et périssable au
premier changement de port — **le défaut même qu'on répare.***

**La forme livrée est la bonne pour le modèle :**

```
srv-docker.env.example:116   APP_URL=https://${SERVER_NAME}:${LARAVEL_HTTPS_PORT}
```

> **Le correctif d'une valeur périmée ne doit pas poser une valeur périssable.**

## ② ET LE GESTE N'EST PAS INERTE — J'AVAIS TORT SUR CE POINT AUSSI

J'avais réservé la valeur à l'exploitant et demandé « seulement la déclaration ». **La
déclaration EXÉCUTE la correction**, parce que `env_file: srv-docker.env` met la variable
dans l'environnement du conteneur, et **l'environnement l'emporte sur `laravel/.env`** :

```
docker exec -e APP_URL=https://EPREUVE.invalid:9999 …
  config('app.url')  ->  https://EPREUVE.invalid:9999    l'injection l'emporte
temoin, sans injection
  config('app.url')  ->  http://192.168.0.245:8444        laravel/.env
```

*Contre-épreuve refaite de mon côté, identique.* **Je décrivais comme une déclaration ce qui
est un correctif d'exploitation par un chemin détourné** — et la session l'a annoncé en
toutes lettres dans le fichier et au CHANGELOG plutôt que de le laisser passer pour inerte.

## 🔴 ③ MAIS LA FORME DÉRIVÉE RAMÈNE LE PIÈGE QUE LE PLAN A DÉJÀ PAYÉ

```
srv-docker.env:100      SERVER_NAME=localhost          <- le fichier VIVANT
srv-docker.env:375      LARAVEL_HTTPS_PORT=8443
=> APP_URL resolu       https://localhost:8443
```

**Dans un courriel, `localhost` désigne la machine du DESTINATAIRE.**

> **On échangerait un lien cassé contre un autre** : `http://…:8444` avait le mauvais port et
> pas de chiffrement, mais une IP **joignable**. `https://localhost:8443` a le bon port et le
> chiffrement, et n'est joignable par **personne**.

*C'est le piège n° 3 du §2 ter du plan, mot pour mot* — écrit à propos de `LARAVEL_URL` et
`LEGACY_URL` : **« remettre la forme dérivée aurait substitué `localhost` et cassé tout lien
vu depuis une autre machine ».** C'est exactement pour cela que ces deux-là sont **en dur
dans le fichier vivant.**

### Le motif est établi par les deux variables sœurs, et il faut le suivre

```
                MODELE (derive)                          VIVANT (en dur)
LARAVEL_URL     http://${SERVER_NAME}:${LARAVEL_PORT}    https://192.168.0.245:8443
LEGACY_URL      https://${SERVER_NAME}:${HTTPS_PORT}     https://192.168.0.245:8446
APP_URL         https://${SERVER_NAME}:${LARAVEL_HTTPS_PORT}   ⛔ ABSENT
```

### 🔴 Et le mécanisme qui propage le correctif est celui qui le casse

```
env-merge.sh:65   if ! echo "${existing_keys}" | grep -q "^${key}$"
                  -> n'ajoute QUE les cles MANQUANTES
```

**Donc `env-merge` déposerait la ligne DÉRIVÉE dans le fichier vivant**, où `SERVER_NAME`
vaut `localhost`. *Le remède arrive par le tuyau qui le dénature.*

## ⚖ CE QUE ÇA DONNE COMME ORDRE, ET L'ORDRE EST LA DÉCISION

```
1  ⛔ EXPLOITANT — ecrire A LA MAIN dans srv-docker.env :
       APP_URL=https://192.168.0.245:8443
   (ou le nom d'hote reellement joignable par les destinataires)

2  ALORS env-merge est un no-op sur cette cle : il n'ajoute que ce qui MANQUE,
   et la valeur ecrite a la main se protege elle-meme de la fusion

3  recreation du conteneur -> la valeur d'environnement l'emporte sur laravel/.env
4  verifier : `artisan tinker` doit rendre :8443 ET https ET un hote joignable
5  ALORS SEULEMENT armer MAIL_MAILER=smtp
```

> **L'ordre 1-avant-2 n'est pas une précaution : c'est ce qui fait que la valeur écrite à la
> main survit.** *`env-merge` ne l'écrasera pas, précisément parce qu'il ne complète que les
> absences.*

**Inverser 1 et 2 dépose `localhost` et le rend ensuite très difficile à distinguer d'un
choix.**

## ⚠ ET UNE DERNIÈRE, QUI N'EST PAS DE MOI MAIS QUI COMPTE

La session a d'abord cité au CHANGELOG `APP_URL=https://\${SERVER_NAME}…` — **des
échappements parasites venus de son heredoc, absents de l'artefact.** Corrigée en
**recopiant la ligne depuis le fichier** plutôt qu'en la retapant.

> **Un journal qui ne cite pas exactement l'artefact est la divergence que ce chantier vient
> de payer trois fois — et elle a été commise dans l'entrée qui la dénonce.**

*C'est la même mécanique que mes accents graves exécutés par le shell : un motif retapé n'est
pas le motif du fichier.* **La parade est identique dans les deux cas : lire depuis
l'artefact, jamais depuis sa mémoire.**

---

# ⛔⛔ RECTIFICATION MAJEURE — MON MÉCANISME ÉTAIT FAUX, ET LE DÉFAUT RÉEL EST PIRE

**2026-09-08, ~05:3x.** *Je corrige la thèse centrale de ce dossier. La conclusion
opérationnelle — **ne pas armer SMTP** — se renforce ; sa raison change entièrement.*

## ① CE QUE J'AI ÉCRIT DE FAUX

J'ai annoncé que le courriel de réinitialisation portait
`http://192.168.0.245:8444/reinitialiser?…` — le legacy, en clair.

**Cette valeur vient de `artisan tinker`, c'est-à-dire de HORS REQUÊTE.** Mesuré :

```
hors requete (tinker)        route('connexion')  ->  http://192.168.0.245:8444   APP_URL
dans une requete             la page emet        ->  https://localhost:8443      HOTE DE LA REQUETE
« :8444 » dans une page servie                   ->  0 occurrence
```

Et `ReinitialisationController.php:156` construit le lien **dans** `envoyer(Request $requete)` :

```php
$lien = route('reinit.formulaire', ['uid' => (int) $compte->id, 'jeton' => $clair]);
```

> **Donc le lien du courriel ne porte PAS `:8444`. Il porte l'hôte de la requête qui a
> soumis le formulaire.**

*J'ai mesuré avec l'instrument qui n'était pas dans le régime du code.* **Cinquième fois
cette nuit qu'arbre, service, base et page-vivante se confondent** — et cette fois j'ai
publié avant de vérifier le régime. [[feedback_arbre_ou_service]].

### Et `APP_URL` n'a AUCUNE conséquence vivante aujourd'hui

```
sites composant une URL, tous contextes        92
sites composant une URL HORS REQUETE            0
Mail:: (toutes formes)                          1, dans un CONTROLEUR donc en requete
Console/Commands · Jobs · planificateur        aucune composition d'URL
```

**`APP_URL` est faux et inerte.** *C'est un piège en sommeil pour le jour où quelque chose
composera une URL hors requête — un courriel mis en file, un rapport planifié — pas un
défaut vivant.* **Il faut toujours le corriger ; il ne fallait pas l'annoncer comme la
cause.**

## 🔴 ② CE QUE LE DÉFAUT EST RÉELLEMENT : L'HÔTE EST FOURNI PAR LE DEMANDEUR

```
curl -H "Host: attaquant.invalid" https://localhost:8443/connexion
  ->  200
  ->  la page emet   https://attaquant.invalid

gardes cherchees :  TrustHosts · trustedHosts · forceRootUrl   ->  AUCUNE
vhost Apache du portage :  ServerName localhost, sans rejet des autres hotes
```

**Conséquence sur le flux de réinitialisation :**

```
1  une requete POST /mot-de-passe-oublie avec l'adresse d'une VICTIME
   et un en-tete `Host` choisi par le demandeur
2  route() a la ligne 156 bâtit le lien sur CET hote
3  la victime recoit un courriel dont le lien de reinitialisation pointe
   vers l'hote du demandeur, JETON COMPRIS
4  si elle clique, le jeton part chez lui
```

> ⛔ **Ce n'est pas un lien cassé : c'est un lien dont l'adresse est choisie par celui qui
> déclenche l'envoi.** *La conclusion « ne pas armer SMTP » ne vaut plus par prudence
> d'hygiène — elle est la seule chose qui rend ce défaut latent.*

**Aujourd'hui `mail.default` vaut `log`** : le courriel s'écrit dans un fichier. **Le jour où
un transport réseau est armé, ce défaut devient vivant.**

*Le fichier lui-même porte cette phrase, écrite pour un autre défaut du même flux :* « il
devient vivant le jour où un transport RÉSEAU est configuré — et ce jour-là, personne ne
pensera à relire ce fichier ». **Elle s'applique deux fois.**

## ⚖ ③ CE QUE ÇA CHANGE DANS LA LISTE DES CORRECTIFS

```
AVANT (ce que j'avais ecrit)          APRES (mesure)
1  APP_URL, valeur                    devient SECONDAIRE — inerte, mais prerequis du 2
2  declarer dans l'exemple            garde son sens : rendre la variable lisible
⬅ 0  L'HOTE DE CONFIANCE              NOUVEAU, ET C'EST LE PREMIER
      TrustHosts, ou URL::forceRootUrl(config('app.url')) sur le chemin du
      courriel, ou le rejet des hotes inconnus par Apache
3  ne pas armer SMTP avant            INCHANGE, et c'est desormais un verrou de
   d'avoir verifie                    securite et non d'hygiene
```

**⚠ Et les deux se composent, dans cet ordre :** `forceRootUrl(config('app.url'))` **emploie
`APP_URL`**. *Forcer la racine sur une valeur fausse remplacerait un hôte choisi par le
demandeur par un hôte faux choisi par nous.* **Corriger `APP_URL` d'abord ; forcer ensuite.**

## ④ CE QUE JE RETIENS CONTRE MOI

**J'ai publié un dossier, puis son amendement, sur un mécanisme que je n'avais pas
mesuré dans le bon régime.** *Deux niveaux de correction sur ma propre thèse, et c'est un pair
qui m'a fait relire en me forçant à mesurer le rayon d'action.*

> **Ce qui m'a fait trouver le vrai défaut n'est pas un doute sur ma conclusion : c'est une
> question de PORTÉE — « combien de sites cette variable contamine-t-elle ? »** *La réponse
> (91 en requête, 1 en courriel, 0 hors requête) a rendu ma thèse intenable en une mesure.*

**Un chiffre de portée aurait dû précéder le dossier, pas le suivre.** *J'avais l'habitude de
le demander aux autres — « ton compte porte-t-il ses objets ? » — et je ne me l'étais pas
demandé.*

⛔ **AUCUN FORMULAIRE N'A ÉTÉ SOUMIS.** *Tout est mesuré par `curl` sur des pages de lecture,
par `artisan tinker`, et par lecture de code. Soumettre `/mot-de-passe-oublie` enverrait un
courriel à une personne réelle — et, ce défaut étant ce qu'il est, ce serait aussi la
démonstration qu'on refuse de faire.*
