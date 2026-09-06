# AUDIT — le catalogue `serveurs` apparié : la consigne ne tient pas sur ce module

**Session 5 (sécurité, lecture seule).** Relevé du **2026-09-05, 22:38 CEST**.
Aucune écriture hors `docs/` — la seconde fenêtre du LOT est ouverte. **Aucun
formulaire soumis** : le SMTP est armé depuis 22:18.

**Résultat : le catalogue est COMPLET — chaque route a un appelant, chaque
appelant a une route. Mais on ne pouvait pas l'établir par la méthode demandée.**

---

## 1. ⚠ « Apparie contre ce que son JS APPELLE » — la prémisse ne tient pas ici

`laravel/public/js/serveurs.js` fait **138 lignes** et **UN seul appel** :

```js
:114   fetch(PASSERELLE + '/server_status', …)
```

**Tout le reste est de la manipulation du DOM.** *Appliquée à la lettre, la
consigne trouverait **1 capacité sur 11** et conclurait que les dix autres sont
absentes.* **C'est un faux manque de la famille exacte que le DSI décrit — produit
par sa propre consigne.**

### 1.1 La couche réelle : DIX formulaires HTML

```
serveurs.blade.php   10 <form>   (temoin : comptes.blade.php en rend 2 — la sonde n'est pas aveugle)
```

Neuf citent une route nommée ; **le dixième compose son action à l'exécution** :

```js
:65   formulaire.setAttribute('action', gabarit.replace('__ID__', String(id)));
```

> **Ni un `fetch` composé, ni une route citée dans la vue : un ATTRIBUT `action`
> construit par remplacement de chaîne, à partir d'un gabarit posé par le serveur
> dans un `data-action`.** *Aucun relevé de `fetch`, aucun relevé de `route()`
> dans la vue ne relie ce geste à sa route.*

**Le DSI énumérait trois couches** — route backend, route de passerelle, appel
direct `DB::table()`. **En voici une quatrième : le formulaire HTML.** *Et une
cinquième forme à l'intérieur : l'action composée.*

---

## 2. L'appariement — complet

| geste | couche | route |
|---|---|---|
| consulter le parc | page | `GET /serveurs` |
| ajouter un serveur | formulaire | `POST /serveurs/ajouter` |
| importer un CSV | formulaire | `POST /serveurs/importer` |
| modifier un serveur | formulaire | `POST /serveurs/{id}/modifier` |
| **supprimer un serveur** | **formulaire à action COMPOSÉE** | `POST /serveurs/{id}/supprimer` |
| poser une étiquette | formulaire | `POST /serveurs/{id}/etiquettes` |
| retirer une étiquette | formulaire | `POST /serveurs/{id}/etiquettes/retirer` |
| poser une note | formulaire | `POST /serveurs/{id}/notes` |
| supprimer une note | formulaire | `POST /serveurs/{id}/notes/{note}/supprimer` |
| changer le cycle de vie | formulaire | `POST /serveurs/{id}/cycle` |
| **tester la connexion** | **`fetch` → passerelle** | `/server_status` |

**Aucune route orpheline, aucun appelant sans route.** Garde du module :
`role:2` + `perm:can_admin_portal`. Catalogue de libellés : **113 clés,
FR = EN, parité vérifiée.**

---

## 3. La méthode du DSI est bonne — c'est son ÉNONCÉ qui était trop étroit

**Sa règle générale porte** : *« cherche la COUCHE, pas seulement le nom »*. **Son
énoncé opérationnel ne portait pas** : *« apparie contre ce que son JS appelle »*.

> **Une méthode juste peut être transmise sous une forme qui ne l'est pas.** La
> règle survit au module ; l'instruction, non. *Et c'est l'instruction qu'on
> exécute.*

**Et le module précédent explique pourquoi elle a été énoncée ainsi** : sur
`security/` et `iptables`, les gestes **passent effectivement par le JS**, et la
consigne y était exacte. **Elle a été généralisée depuis deux cas qui la
vérifiaient.** *C'est l'énumération contre le mécanisme, une fois de plus — et
cette fois dans une consigne, pas dans un relevé.*

### 3.1 La forme qui survit

**Ne pas demander « ce que le JS appelle » mais « ce qui produit une requête » :**

    fetch / XHR             JS
    <form action=…>         gabarit
    action composee         JS qui ECRIT un attribut
    DB::table() direct      controleur, sans route backend
    lien <a href=…>         navigation

*Les cinq se relèvent séparément, et aucun vocabulaire ne les attrape tous.*

---

## 4. Le témoin positif, posé comme demandé

**Ma sonde de formulaires rend 2 sur `comptes.blade.php`** — elle n'est donc pas
aveugle, et le **10** de `serveurs.blade.php` est une mesure, pas un silence.

*Sans lui, « 10 formulaires » et « la sonde compte n'importe quoi » auraient été
indiscernables — et j'aurais fondé tout l'appariement dessus.*

---

## 5. Non mesuré, et dit

- **aucun formulaire soumis, aucune page ouverte** — le SMTP est armé, et je ne
  soumets rien sur ce banc ;
- je n'ai pas vérifié que les 113 clés de libellé sont **toutes employées** :
  l'appariement porte sur les gestes, pas sur les textes. *Une clé orpheline
  serait un résidu, pas un manque — et c'est le sens le moins coûteux.*
- **le cycle de vie et l'import CSV n'ont pas été touchés**, conformément à
  l'interdit : le premier est porté mais « Retirer du parc » ne se défait pas ;
  le second est bloqué sur trois arbitrages et écrit dans quatre tables.
