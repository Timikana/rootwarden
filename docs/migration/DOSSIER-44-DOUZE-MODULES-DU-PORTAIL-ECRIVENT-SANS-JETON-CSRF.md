# DOSSIER-44 — ⛔ RETIRÉ : mon alarme était fausse, et le dépôt l'avait anticipée le 2026-08-18

> **CE DOSSIER EST RETIRÉ.** *Son constat de fait est exact — douze modules
> n'envoient aucun jeton — et la conséquence que j'en tirais est FAUSSE.*
> **Les POST du portail fonctionnent.**

## ⛔ LA RÉFUTATION, et les CORPS la portent mieux que les statuts

**Tirée des journaux conservés du LOT 4 par la session 7, sans aucun rejeu :**

```
go-fail2ban-f3   400   {"message":"lines doit etre un nombre","success":false}
go-services-s3   403   Service protege : sshd
LOT 3, legacy-go-fail2ban-f3   400, même corps
```

> **Un statut peut avoir plusieurs causes ; un corps porte la trace du chemin
> parcouru.** *`lines doit etre un nombre` est une validation APPLICATIVE, et
> `Service protege : sshd` une règle MÉTIER : la requête a traversé la couche
> CSRF, atteint la route, et été désérialisée.* **Une couche qui bloque rend 419
> et un corps générique, sans jamais avoir vu `lines` ni `sshd`.**

*Ces deux suites font leur POST SANS CONDITION — c'est ce qui les rend probantes,
là où `go-fail2ban-f4` a son POST derrière `if (! derniere)` et pouvait n'avoir
jamais évalué son assertion.*

## LE MÉCANISME, écrit dans le dépôt AVANT que je me trompe

**`laravel/bootstrap/app.php:16-29`, commentaire daté du 2026-08-18 :**

```
Laravel 13 place `PreventRequestForgery` dans le groupe `web` par defaut.
Ce middleware accepte une requete si l'UNE de ces conditions tient :
  methode de lecture · chemin exclu · ORIGINE valide (Sec-Fetch-Site: same-origin)
  · ou jeton correspondant

« Une mesure du 2026-08-18 a d'abord fait croire a une absence de controle :
  un `fetch` same-origin sans jeton passait. C'etait le comportement ATTENDU —
  une requete same-origin n'est pas une falsification. La propriete a verifier
  est qu'une requete CROSS-SITE sans jeton soit refusee, ce que fait
  tests/e2e/go-socle-passerelle.mjs. »
```

> **Quelqu'un a commis exactement mon erreur le 18 août, l'a comprise, et a
> écrit ce commentaire pour la prévenir.** *J'ai lu ce fichier deux fois
> aujourd'hui — `:56` pour la liste d'exceptions, `:16` pour repérer le
> commentaire — **sans lire le commentaire**.*

## ⚠ POURQUOI MA SONDE NE POUVAIT PAS VOIR LE CAS QUI PASSE

```
mon curl        POST /api/gateway/test  ->  419
mon TÉMOIN      POST /connexion         ->  419
```

*J'avais un témoin, et il ne discriminait rien : les deux rendent 419 sans
session.* **Ce qu'il me manquait n'était pas un témoin mais un en-tête :
`curl` n'envoie pas `Sec-Fetch-Site: same-origin`.** *Ma mesure était
structurellement incapable d'observer le cas qui passe — et un instrument aveugle
au cas favorable rend toujours l'alarme.*

## Ce qui reste VRAI et sans conséquence

*Les douze modules n'envoient effectivement aucun jeton, et `jetonCsrf` est
redéfini dans 18 fichiers plutôt qu'une fois.* **Ce n'est pas un défaut de
sécurité — c'est une inégalité de style.** *La propriété qui compte — une requête
CROSS-SITE sans jeton est refusée — est déjà tenue par le middleware et déjà
éprouvée par une suite.*

⚠ **BORNE DE LA RÉFUTATION, posée par la session 7 :** *deux points de mesure,
pas douze.* **« Les POST du portail sont inopérants » est faux comme énoncé
général — un contre-exemple suffit, et il y en a deux.** *Cela ne certifie pas
chacun des douze.*

---

*Ce qui suit est le dossier tel que publié, conservé pour la trace.*

# ~~DOSSIER-44 — douze modules du portail écrivent SANS jeton CSRF~~

**Session DSI, 2026-09-07 au soir. Trouvé par la session 5f** en portant la
liste blanche CVE ; **mesuré et étendu ici.** *Ce dossier passe devant
l'extinction.*

---

## ① LE FAIT, mesuré au réseau

```
POST /api/gateway/test   sans jeton   ->  419
GET  /api/gateway/test   (TÉMOIN)     ->  302   (redirection d'authentification)
```

**La seule exception CSRF du produit est `'chatops/webhook'`**
(`laravel/bootstrap/app.php:56`). *`/api/gateway/*` n'y est pas.* **Et le
docblock de `PasserelleController:26` l'annonce lui-même : « jeton CSRF sur les
méthodes mutantes (middleware web) ».**

---

## ② DOUZE MODULES POSTENT SANS JETON

```
acces-sftp · audit-ssh · bashrc · cle-plateforme · cles-ssh · comptes-distants
fail2ban · groupes · politiques · scan-cve · serveurs · services

  avec jeton                    20 fichiers
  SANS jeton mais MUTANTS       12
  sans jeton et lecture seule    5
```

**Chacun définit son propre helper**, et aucun n'ajoute l'en-tête :

```js
// bashrc.js
return fetch(PASSERELLE + chemin, options || {})
// fail2ban.js · politiques.js · comptes-distants.js
return fetch(PASSERELLE + chemin, { method: 'POST',
                                    headers: { 'Content-Type': 'application/json' } })
```

### ⚠ Aucun helper partagé ne les sauve — vérifié

*`jetonCsrf` n'est pas central : il est redéfini DANS CHACUN des 18 fichiers qui
l'emploient.* **Il n'existe aucun script commun chargé par le socle.** *Les
douze ne peuvent donc pas en hériter.*

---

## ③ ⛔ POURQUOI LE BANC NE L'A JAMAIS VU

> **Ces douze modules portent exactement les gestes que le banc a INTERDICTION
> d'exercer** — déployer, appliquer, révoquer, installer, redémarrer.

*Le LOT 4 a joué 85 suites hier avec zéro régression produit.* **Il ne pouvait
pas voir ce défaut : la règle qui protège le parc est la même qui rend le défaut
invisible.**

> **Une garde de sûreté et un angle mort de mesure sont ici LA MÊME RÈGLE.**

---

## ④ CE QUE JE N'ÉTABLIS PAS

⚠ **Je n'ai pas exercé une écriture réelle depuis une session authentifiée.**
*Ma preuve est un `POST` sans session : il rend 419, ce qui montre que la couche
CSRF mord AVANT l'authentification.* **Il reste concevable qu'un chemin
navigateur fournisse le jeton autrement** — un formulaire `@csrf`, un intercepteur
que ma lecture n'a pas trouvé.

**La contre-épreuve qui trancherait, et qu'il faut faire avant tout correctif :**
*ouvrir une session dans le navigateur et déclencher UN geste mutant non
destructeur parmi les douze* — par exemple une lecture-écriture inoffensive de
`services.js` — et lire le statut. **Si c'est 419, les douze sont confirmés.**

*La session 5f signale la même tension : `go-page-cve-planification.mjs` assère
un statut sur une création et son helper n'envoie pas de jeton non plus. Soit
cette suite ne l'exerce pas vraiment, soit quelque chose diffère.* **Non
tranché.**

---

## ⑤ CE QUI VOUS REVIENT, ET C'EST URGENT AVANT L'EXTINCTION

| | |
|---|---|
| **la contre-épreuve navigateur** | un geste mutant, une session réelle, un statut lu. *Sans elle, on corrige peut-être un défaut qui n'existe pas.* |
| **si confirmé : douze correctifs** | ajouter l'en-tête dans chacun des douze helpers |
| **la cause structurelle** | *`jetonCsrf` redéfini 18 fois plutôt qu'une.* **Un helper central l'aurait rendu impossible à oublier** — c'est la garde par construction, et son absence a produit douze oublis |

⛔ **Rien n'a été corrigé ni exercé.** *Et ce dossier passe devant les six
portages de l'extinction : si les douze sont confirmés, une partie de la surface
d'écriture du portail est inopérante en production, et l'archivage du legacy
retirerait le seul chemin qui fonctionne encore.*
