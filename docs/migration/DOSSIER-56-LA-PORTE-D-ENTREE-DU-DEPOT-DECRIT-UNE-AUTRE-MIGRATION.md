# DOSSIER-56 — La porte d'entrée du dépôt décrit une autre migration

**Mesuré le 2026-09-08 entre 15:30 et 15:35 CEST.** Aucune écriture hors ce
dossier.

> Le filon de ces derniers tours n'est plus dans le produit : il est dans **ce
> qui le décrit ou l'outille**. `README.md` est le document le plus lu du dépôt.
> **Il décrit une migration achevée à 40 %, nomme les mauvais ports, et appelle
> le legacy éteint « la référence ».**

---

## 1. La version annoncée contre la version réelle

```
version reelle (legacy/version.txt)   2.0.183
dernier tag                           v2.0.22

README.md          annonce  v1.37.47
README.en.md       annonce  v1.37.47
ARCHITECTURE.md    annonce  v1.37.47
OPERATIONS.md      annonce  v1.37.16
```

**Une version MAJEURE de retard**, dans les quatre documents qu'on lit avant le
code.

---

## 2. ⛔ LE TABLEAU DES PORTS EST INVERSÉ, ET C'EST LE PLUS COÛTEUX

`README.md:14-17` :

```
| | port | rôle |
|---|---|---|
| **portage Laravel** (`laravel/`) | **8444** | la cible — reçoit les pages une par une |
| **ancien portail** (`legacy/`)   | **8443** | la référence, dépréciée partie par partie |
```

**Mesure au réseau, maintenant :**

```
:8443  /connexion -> 200  ·  titre « Connexion · RootWarden »   <- le PORTAGE
:8446  /connexion -> 404                                         <- le legacy, eteint
```

**Les deux lignes sont fausses**, et l'une est un piège actif :

- le **portage** n'est pas sur 8444 — 8444 est la **redirection** http→https
- le **legacy** n'est pas sur 8443 : **8443 est le port du portage** depuis
  l'échange du 2026-09-06
- et le legacy n'est plus « la référence » : il sert **zéro** `.php`

> **Un exploitant suivant ce tableau pour comparer l'ancien et le nouveau
> taperait DEUX FOIS sur le portage** — 8443 pour « l'ancien », 8444 pour « le
> nouveau » qui n'est qu'une redirection vers 8443. Il conclurait que les deux
> portails sont identiques.

*C'est la forme la plus coûteuse d'une doc périmée : elle ne se contente pas de
ne rien dire, elle mène une mesure au mauvais endroit et la rend cohérente.*

---

## 3. Une mesure datée, présentée comme l'état

`README.md:19-21` :

> *« **État mesuré au 2026-08-23** : **14 entrées de menu portées sur 33**, **9
> parties du legacy archivées**, deux modules entièrement dépréciés. »*

**Seize jours. Et l'état réel :** la migration est **achevée** — zéro `.php`
servi hors archive, **214** fichiers sous `legacy/_deprecated/`, aucun lien
composé vers le legacy par le portage.

⚠ **La phrase porte sa date, et c'est ce qui la sauve à moitié** : elle ne
prétend pas être actuelle. Mais elle est au premier écran, et *une mesure datée
placée là où on cherche l'état se lit comme l'état.*

---

## 4. Ce qui n'est PAS un défaut, et j'ai failli le dire

`README.md:336-346` explique, en dépannage, de faire `rm -f legacy/.installed`
après un `down -v`.

**J'allais signaler que le README demande de supprimer un fichier employé par du
code vivant** : `git grep '\.installed'` rend `backend/routes/fail2ban.py`,
`laravel/app/Services/Fail2ban.php`, `laravel/public/js/fail2ban.js`.

**C'est faux.** Ces correspondances portent sur une **colonne de base**
(`f.installed`) et un **champ JSON** (`d.installed`) — *textuellement identiques
à un nom de fichier terminant par `.installed`*. Le vrai fichier est
`php/install.sh:27` : `LEGACY_FLAG="${APP_DIR}/.installed"  # compat installs
anterieures`, un drapeau du service **php**, éteint.

> **Un nom de fichier et un accès de propriété peuvent être le même texte.**
> `\.installed` échappe bien le point, et il apparie quand même `f.installed`.

La section est donc **périmée, pas nuisible** : elle dit de supprimer un fichier
qui ne compte plus. Elle part avec `patch 07`.

---

## 5. Ce que je ne corrige pas, et pourquoi

**`README.md` n'est ni `DECISIONS-DSI.md` ni un `DOSSIER-*.md`.** C'est la face
publique du dépôt, lue par l'exploitant et par sept sessions ; l'éditer
unilatéralement est plus conséquent qu'un dossier.

**Le geste le plus urgent tient en deux lignes** : le tableau `README.md:16-17`.
Corriger les ports et retirer « la référence ». *C'est le seul des quatre points
qui fasse mesurer faux.*

Les trois autres sont de la mise à jour : la version dans quatre documents, la
mesure du 2026-08-23, et la section de dépannage qui part avec `patch 07`.


---

# 6. ⛔ LE RUNBOOK EST PIRE QUE LE README : il fait TAPER des commandes mortes

**Mesuré le 2026-09-08 15:55.** `OPERATIONS.md` — le document qui te fait
**agir** — annonce `v1.37.16` et porte **le même tableau de ports inversé** :

```
:14  | rootwarden_laravel | 8444 | le portage, la cible |
:15  | rootwarden_php     | 8443 | l'ancien portail, deprecie partie par partie |
```

## Trois commandes, trois 404

```
:183  curl -k -b cookies.txt https://localhost:8443/adm/api/audit_verify.php
:200  curl … -X POST https://localhost:8443/api_proxy.php/revoke_service_account
:209  curl … -X POST https://localhost:8443/api_proxy.php/regenerate_platform_key
:224  « si tu appelles /adm/api/delete_user.php sans step-up, tu reçois : »
```

**Les quatre points d'entrée sont ARCHIVÉS**, mesuré fichier par fichier :

```
adm/api/audit_verify.php    vivant 0  ·  archive 1
api_proxy.php               vivant 0  ·  archive 1
adm/api/delete_user.php     vivant 0  ·  archive 1

au reseau, sur :8443 (le PORTAGE) :
  /adm/api/audit_verify.php               -> 404
  /api_proxy.php/revoke_service_account   -> 404
```

*⛔ Les deux POST n'ont pas été envoyés : `revoke` et `regenerate` sont
destructeurs. Seuls les GET ont été mesurés.*

## ⚠ ET LES TROIS CAPACITÉS FONCTIONNENT

C'est ce qui rend ce défaut plus grave que celui du README :

```
① verifier un sceau d'audit
     /journal-audit                  web.php:1200
     journal-audit/verifier          TableDesGardes:112, role:3 + can_admin_portal
② revoquer un compte de service
     backend/routes/ssh.py:988       @bp.route('/revoke_service_account', POST)
     page du portage : /comptes-distants        web.php:1171
③ regenerer la cle de plateforme
     backend/routes/ssh.py:14 · ssh_key_manager.py:192
     page du portage : /cle-plateforme          web.php:1018
```

> **Le runbook fait taper trois commandes qui rendent 404, pour trois capacités
> qui MARCHENT — atteintes par un autre chemin.** C'est l'inverse d'une
> documentation qui sous-promet : **celle-ci fait paraître cassé un système qui
> fonctionne.** Un exploitant qui la suit conclut que la migration a perdu la
> vérification de sceau, la révocation de compte de service et la régénération de
> clé de plateforme.

## Ce que je n'écris PAS, et pourquoi

**Je ne fabrique pas les commandes de remplacement.** Les deux gestes d'API
passent désormais par la passerelle, dont l'accès porte session **et** jeton CSRF
— donc un code TOTP. Écrire un `curl` sans avoir mesuré cette chaîne
reproduirait exactement le défaut que ce dossier signale : *une commande fausse
dans un runbook se tape.*

**Ce qui est vérifié et suffit à corriger** : les trois **pages** du portage
(`/journal-audit`, `/comptes-distants`, `/cle-plateforme`) et le fait que les
deux points d'API vivent côté backend, atteints par la passerelle.

## Priorité, revue

Le geste le plus court de ce dossier n'est plus `README.md:16-17` seul :

```
1. OPERATIONS.md:183 :200 :209 :224   -> quatre commandes/renvois MORTS
                                          sur des capacites VIVANTES
2. OPERATIONS.md:14-15 + README.md:16-17  -> le meme tableau inverse, DEUX fois
3. la version annoncee dans quatre documents
4. README.md:19, la mesure du 2026-08-23
```
