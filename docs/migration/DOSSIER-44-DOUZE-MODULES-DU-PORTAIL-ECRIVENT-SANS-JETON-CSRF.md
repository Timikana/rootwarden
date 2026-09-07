# DOSSIER-44 — 🔴 douze modules du portail écrivent SANS jeton CSRF, et le banc ne peut pas le voir

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
