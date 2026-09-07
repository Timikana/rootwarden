# DOSSIER-47 — Deux portes pour le même geste, une seule laisse une trace

**Mesuré le 2026-09-07 entre 22:33 et 22:40 (hôte, CEST).** Branche `Migration-Laravel`.
Signalé par la session sécurité comme *« un défaut de TRACE du portage ACTUEL, qui ne
demande ni I5, ni l'extinction, ni le port SSH »*. Vérifié ici avant d'être tranché.

---

## 1. Le fait

`backend/routes/iptables.py` porte **deux routes qui appliquent des règles de pare-feu sur
une machine**, avec le même effet distant et les mêmes gardes. **Une seule archive.**

```
A   POST /iptables         action="apply"   :29   apply_iptables_rules(...)          RIEN
B   POST /iptables-apply   action="apply"   :90   INSERT INTO iptables_history (:148)
                                                  puis apply_iptables_rules(...)
```

Les gardes sont **identiques, à la ligne près** :

```
@require_api_key · @require_permission('can_manage_iptables') · @require_machine_access
@threaded_route
```

**Rien, vu du dehors, ne distingue les deux portes.** Même verbe dans le corps, même
permission, même effet sur la machine. *La seule différence est que l'une inscrit
l'état précédent dans `iptables_history` et l'autre non.*

## 2. Ce que la trace manquante coûte, précisément

Ce n'est pas seulement « on ne sait pas qui a fait quoi ». **C'est que l'archive devient
non contiguë**, et rien ne le dit :

```
etat 0  --A-->  etat 1        A n'archive pas : l'etat 0 est PERDU
etat 1  --B-->  etat 2        B archive l'etat 1

/iptables-rollback depuis l'etat 2  ->  restaure l'etat 1
                                        et NON l'etat 0, qui n'existe plus nulle part
```

**L'opérateur qui déroule l'historique croit remonter le fil des changements. Il remonte
le fil des changements *tracés*.** *Une archive avec un trou est plus dangereuse qu'une
archive absente : l'absence se voit, le trou se lit comme une continuité.*

Et `/iptables-rollback` **applique** ce qu'il restaure. Le trou n'est donc pas
documentaire : il est actionnable.

## 3. ⚠ MAIS LE DÉFAUT EST DORMANT, et c'est ce qui décide de sa forme

**Personne n'emprunte la porte A.** Balayage complet des fichiers suivis, hors documentation
et hors le fichier de routes lui-même :

```
sites posant `action: "apply"`                    3
  legacy/iptables/js/main.js:139     -> vers /iptables-apply  (:135), donc la porte B
  PareFeuController.php:25           -> une PROSE de docbloc
  tests/e2e/go-page-pare-feu.mjs:145 -> une PROSE de commentaire

appels a POST /iptables dans le portage           1
  pare-feu.js:307   appelle('/iptables', { action: 'get' })   <- LECTURE seulement
```

**Aucun client, legacy ou portage, n'envoie `action="apply"` vers `/iptables`.** Le legacy
lui-même, qui a écrit les deux routes, n'utilise que celle qui archive.

> **C'est un élargissement DORMANT : zéro appelant aujourd'hui, effectif au premier qui
> l'emprunte.** *La même forme que l'octroi de permission sans compte concerné — la
> mesure d'usage rend zéro, et le zéro ne dit rien de ce que le code permet.*

**Elle est atteignable.** `RoutesBackend.php:114` porte `'/iptables', '/iptables-'`, et
`:446` compare par `str_starts_with` : la passerelle du portage relaie donc `/iptables`
comme le reste. Une requête forgée par un porteur de `can_manage_iptables` ayant l'accès à
la machine passe les deux gardes — **et ce sont exactement les mêmes gardes que la porte
qui trace.**

## 4. L'arbitrage que je rends

*Question produit : `POST /iptables` doit-il conserver un verbe `apply` en v2.0 ?*

### ⛔ Ce que je NE retiens pas : supprimer le verbe

C'est la garde par construction — un verbe qui n'existe pas ne s'appelle pas — et j'ai
d'abord penché pour elle. **Elle est mauvaise ici, pour une raison mesurable :**

```
laravel/app/Services/ClesApi.php:60   'iptables' => ['^/iptables']
```

**Les clés d'API portent une portée par module, et celle d'`iptables` est un préfixe.**
Un détenteur de clé externe peut donc appeler `POST /iptables` aujourd'hui, légitimement.
*Retirer le verbe casserait un consommateur que je ne peux pas énumérer* — le backend
survit à la migration, et sa surface n'est pas un objet de portage.

> **« Le legacy l'expose déjà » ne fonde aucun choix de portage — mais « le backend
> l'expose aujourd'hui » fonde une obligation de compatibilité.** *Ce ne sont pas les
> mêmes objets : le legacy meurt, le backend reste.*

### ⚠ AMENDEMENT 22:50 — ma prémisse était vraie et trop forte, et un second garde la borne

*Vérifié par la session sécurité, qui a cherché à se contredire.* **« Les clés d'API ont une
portée à préfixe sur `^/iptables` » se relit trop facilement en « une clé d'API peut
appliquer des règles ». Ce n'est pas vrai.**

```
get_current_user()   lit X-User-ID, puis RECHARGE role_id EN BASE
                     echoue en FERMETURE : en-tete absent · compte inactif
                     · base injoignable  ->  (0, 0)
=> require_permission('can_manage_iptables') refuse : 403
```

**La portée de clé est un SECOND filtre trop large, pas un chemin indépendant.** *Il faut
encore fournir un `X-User-ID` nommant un compte ACTIF porteur de la permission.* Le
docblock de la fonction documente la faille qui a produit cette conception : le backend
lisait `X-User-Role` **en en-tête**, et tout porteur de clé pouvait forger `role=3`.
Refermé.

**Mon arbitrage ne bouge pas** — converger plutôt que retirer reste juste, et pour la même
raison : *un consommateur légitime, porteur d'une clé ET d'un compte habilité, appelle
`POST /iptables` aujourd'hui sans que je puisse l'énumérer.*

### ⚠ Et une exception de convention, que la vérification a mise au jour

```
portees de type espace-de-noms, toutes terminees par un SEPARATEUR :
  ^/fail2ban/  ^/services/  ^/ssh-audit/  ^/supervision/  ^/bashrc/
  ^/graylog/   ^/wazuh/     ^/admin/      ^/cve_  ^/apt_  ^/schedule_  ^/server_user_
l'exception :
  ^/iptables        ni `$`, ni separateur — couvre les SEPT routes du module
```

**La convention est suivie douze fois et manquante sur le seul module qui contient un geste
capable de couper RootWarden d'une machine définitivement.**

*Ce n'est pas une faille — le second garde tient. C'est une portée qui **ne sait pas dire
« lecture seule »** là où ça vaudrait le plus la peine : une clé destinée à lire le
pare-feu porte aussi `apply`, `restore` et `rollback` dans sa portée, alors que la
granularité existe douze fois ailleurs dans la même table.*

> **Même classe que l'interrupteur `*_ENABLED` manquant sur la géolocalisation : le
> mécanisme existe dans le dépôt, et il manque à l'endroit qui compte.** *Une convention
> tenue partout sauf au point sensible n'est pas une convention — c'est une habitude.*

### ✅ CE QUE JE RETIENS : faire converger les deux portes

**`action="apply"` sur `/iptables` doit archiver, en DÉLÉGUANT au chemin de
`/iptables-apply` — pas en recopiant son bloc.**

| | |
|---|---|
| capacité | **inchangée** — aucun consommateur ne casse |
| trace | **acquise** — l'archive redevient contiguë |
| forme | **délégation**, jamais duplication |

*Le second point n'est pas un détail de style : ce dépôt a payé **trois copies** du garde
SSRF et **trois** compteurs 2FA. Une deuxième copie du bloc d'archivage divergerait, et
elle divergerait silencieusement — les deux portes continueraient de « marcher ».*

**Corollaire, à écrire dans le code et pas seulement ici :** si les deux portes doivent
rester, **la duplication du verbe est le défaut**, pas la trace manquante. Le remède
durable est qu'il n'existe qu'**un seul** chemin d'application, que les deux routes
appellent. *La trace manquante était le symptôme ; deux implémentations du même geste
irréversible est la cause.*

## 5. Ce qui n'est pas de moi

**L'écriture.** `backend/routes/iptables.py` est du code de service, hors de mon périmètre
d'écriture (`docs/migration/DECISIONS-DSI.md` et `DOSSIER-*.md`). *La session sécurité me
l'a signalé et le tient ; je rends la décision, elle rend le code.*

⛔ **Et rien de ceci n'autorise à exercer quoi que ce soit.** *Aucune règle appliquée,
aucune machine jointe, aucune requête émise vers `/iptables` ni `/iptables-apply` pendant
cette mesure.* Le relevé est entièrement statique.

## 6. Ce que ce dossier a failli être

**Ma première formulation était « `action:"apply"` applique sans archiver, donc il faut le
retirer ».** Deux mesures l'ont retournée, dans les deux sens :

```
« il faut le retirer »      -> ClesApi.php:60 : une cle d'API peut l'appeler.
                               Le retrait casse un consommateur non enumerable.
« c'est un trou beant »     -> 0 appelant, mesure avec temoin.
                               C'est un elargissement DORMANT, pas une fuite.
```

**Les deux corrections vont dans des directions opposées, et elles se seraient annulées si
je n'avais mesuré qu'une seule.** *Mesurer l'exposition sans mesurer l'usage donne une
alarme ; mesurer l'usage sans mesurer l'exposition donne un dédouanement. Il fallait les
deux pour que le remède — converger plutôt que retirer — devienne visible.*

---

**Voir aussi** DOSSIER-40 (les quatre gestes `iptables`, et `/iptables-logs` qui ne se
porte pas) · `E-463` (l'arbitrage I5, rendu par l'exploitant, Q1–Q4 obligatoires) ·
`SPEC-MESURE-Q2-REFUS-AVANT-ENVOI.md` (Q2 est un garde d'INTERFACE, pas une impossibilité).

---

# ⚠ ADDENDUM 23:50 — ELLES SONT QUATRE, ET DEUX RESTENT SANS TRACE

**La convergence est faite** (`be5a30ef`) : `_archive_puis_applique()` porte le bloc, il n'a
pas été recopié, et il ne reste qu'**un** `INSERT INTO iptables_history` dans le fichier.
Vérifié.

**Mais mon dossier ne parlait que de deux portes. Il y en a quatre.**

```
/iptables            :132   ✅ archive
/iptables-apply      :192   ✅ archive
/iptables-restore    :224   ⛔ APPLIQUE SANS ARCHIVER
/iptables-rollback   :284   ⛔ APPLIQUE SANS ARCHIVER
```

*J'ai mesuré les deux routes qui portaient le même verbe `apply` et j'ai cru avoir mesuré
les chemins d'application.* **`restore` et `rollback` appliquent aussi — par d'autres verbes,
donc mon motif ne les a pas vues.** C'est la forme que je corrige chez les autres depuis
deux jours : *le grain de la mesure doit égaler la question.* La question était « quels
chemins appliquent », pas « quelles routes portent `action=apply` ».

## ✅ L'ARBITRAGE : les quatre archivent, par le MÊME chemin

**Et `rollback` est le cas qui décide, parce qu'il se présente comme réversible.**

```
etat courant  --rollback--> etat archive N
              l'etat courant n'est conserve NULLE PART
=> on peut revenir en arriere, jamais revenir EN AVANT
```

> **Une porte à sens unique habillée en porte réversible est pire qu'une porte à sens
> unique** — l'opérateur clique parce que le nom promet qu'il pourra défaire.

*L'iso-périmètre ne l'exige pas : le legacy n'archive pas davantage sur ces deux chemins.*
**Mais la règle de l'exploitant dit « ou debug », et c'en est un** : la capacité annonce une
réversibilité qu'elle n'a pas. Ce n'est pas une fonctionnalité manquante, c'est une promesse
fausse.

⚠ **Contrainte de conception, à écrire avec le geste :** l'archive doit enregistrer l'état
**QUITTÉ**, jamais l'état restauré. *Enregistrer l'état restauré dupliquerait une entrée déjà
présente et rendrait la chaîne illisible — on ne saurait plus distinguer « voici où j'étais »
de « voici où je vais ».*

## ⚠ ET LE FAIT LE PLUS INSTRUCTIF DU LOT N'EST PAS L'ARCHIVE

**Le premier jet du refactor levait `NameError` sur LES DEUX portes. La suite est restée
entièrement verte — 672 tests.**

```
seize tests couvrent `iptables`   les gardes · les parametres absents
le chemin nominal `apply` avec des regles valides   JOUE PAR PERSONNE
```

> **Une suite qui couvre les gardes et les paramètres absents peut être verte sur une route
> dont le chemin nominal ne s'exécute pas.**

**C'est exactement la forme du défaut `user_id` de ce soir** — invisible au rôle 2 parce que
la jointure est sautée au-dessus. *Dans les deux cas la couverture ne manquait pas : elle
regardait ailleurs.* **Et dans les deux cas, ce qui manquait était le cas le plus banal.**

## ⛔ Ce qui reste dû

**Les trois tests écrits avec ce lot sont une vérification d'AUTEUR, pas une certification.**
*La règle de flotte vaut contre son auteur comme contre tout le monde : qui écrit un
correctif ne certifie pas qu'il est là.* Une attestation indépendante reste due sur
`be5a30ef`.

**Et le service exécute encore l'ancien code** : `pytest` lit le disque, donc les 675 verts
portent sur le fichier. La recréation appartient à l'exploitant.

