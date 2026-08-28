# `health_check.php` — quelle machine un diagnostic doit-il viser ?

Session 4, **2026-08-28**. Proposition demandée avant écriture. **Rien n'est écrit**, et
`legacy/adm/` n'est pas mon périmètre.

---

## 1. ⚠ D'ABORD : LE COMPTE DE « DIX-SEPT LECTURES DISTANTES » EST FAUX DEUX FOIS

Mesuré par arbre syntaxique, valeurs des variables résolues, appels suivis :

| ce que fait réellement l'entrée | n |
|---|---|
| **ne joint aucune machine** — lecture en base seule | **6** |
| joint la machine, commande en lecture | **10** |
| ⚠ **joint la machine et la MODIFIE** | **1** |

Les six qui ne joignent rien — `/server_status`, `/server_user_keys`, `/policy/deployments`,
`/iptables-history`, `/fail2ban/history`, `/fail2ban/stats`, `/supervision/overrides` — **ne sont pas
concernées par le choix de la cible.** Quelle que soit la machine, elles lisent une table.

### ⚠ Et la dix-septième n'est pas une lecture

```
/pending_packages  ->  apt-get update -qq 2>/dev/null; apt list --upgradable …
```

**`apt-get update` réécrit les listes de paquets, en root.** Cette entrée vise `$machineId`, donc
`srv-zabbix`, **à chaque chargement de la page**.

> **E-227 a corrigé « les sept routes mutantes ». Il en restait une huitième, classée parmi les
> lectures.** Et le commentaire qui documente E-227, dans ce même fichier, dit exactement pourquoi ça
> compte : *« un correctif appliqué à certains porteurs et pas à tous laisse le défaut intact là où il
> coûte le plus, ET fait croire qu'il est fermé. »*

**C'est le premier point à traiter, et il ne dépend d'aucun arbitrage** : `/pending_packages` doit
passer sur `$mutId` comme ses sept voisines. Le reste de ce document porte sur les dix qui restent.

---

## 2. La question, et pourquoi elle n'a pas la réponse évidente

*« Un diagnostic qui ne regarde jamais la production ne diagnostique pas la production. »* C'est juste,
et ça mélange deux outils :

| | ce qu'on veut savoir | cible pertinente |
|---|---|---|
| **diagnostiquer le PORTAIL** | les routes répondent-elles ? le backend est-il joignable ? | **n'importe laquelle** — et la moins chère |
| **diagnostiquer le PARC** | `srv-zabbix` est-elle saine ? | la production, forcément |

**`health_check.php` fait le premier.** Il boucle sur une liste de routes et affiche un code HTTP et
une durée. Il ne rend aucun verdict sur l'état d'un serveur. **Une route qui répond « machine
introuvable » y est verte** — c'est le principe déjà retenu pour `$mutId = 0`.

Donc : le choix de la cible ne doit pas être guidé par « il faut surveiller la prod ». Il doit l'être
par **« quelle machine peut-on joindre dix fois par chargement de page sans conséquence ».**

---

## 3. Ce que je propose : une cible **déclarée**, jamais devinée

```
HEALTH_CHECK_MACHINE_ID=   (vide par défaut  ->  0)
```

**Trois raisons, dans cet ordre :**

1. **Vide vaut 0, et 0 est déjà le repli éprouvé de ce fichier.** Le backend répond « machine
   introuvable », le test reste vert, **aucune machine n'est jointe**. La page fonctionne — elle
   diagnostique les routes, ce qui est son objet — **sans qu'aucune valeur par défaut ne désigne une
   victime**. *Un défaut de configuration ne doit pas choisir une machine à notre place* ;
2. **viser la production redevient une DÉCISION.** L'exploitant qui veut que son diagnostic touche
   `srv-zabbix` écrit `1` et l'assume. Aujourd'hui il l'obtient **par un ordre de tri**. *Un
   diagnostic peut viser la production ; ça doit être une décision, pas un accident de `LIMIT 1`* ;
3. **c'est le motif de configuration du produit** — 80 variables dans `srv-docker.env.example`, et
   toute nouvelle variable y est documentée puis récupérée automatiquement. Aucune mécanique nouvelle
   à inventer.

### Ce que j'écarte, et pourquoi

**`WHERE environment <> 'PROD'` ou `criticality <> 'CRITIQUE'`.** La colonne existe et elle est juste
aujourd'hui (`srv-zabbix` = `PROD` / `CRITIQUE`, les deux autres = `DEV`). **Mais rien ne garantit
qu'elle soit tenue à jour**, et une machine nouvellement ajoutée sans étiquette deviendrait la cible
silencieusement. C'est le même raisonnement que pour E-224 : *une étiquette d'inventaire n'est pas une
autorisation*, et ici elle ne doit pas non plus tenir lieu de garde-fou.

**Coder `2` en dur.** Ça marche sur ce déploiement et nulle part ailleurs. Le banc n'existe pas chez
tout le monde.

**Garder `LIMIT 1` en ajoutant `ORDER BY id DESC`.** Ça déplace l'accident sans le supprimer : la
cible resterait choisie par un ordre de tri, et changerait le jour où une machine est ajoutée.

---

## 4. Ce qui reste à décider, et qui ne m'appartient pas

**La valeur par défaut est le seul vrai arbitrage.** Je propose « vide », donc *aucune machine jointe
tant que personne ne l'a demandé*. Un exploitant peut légitimement préférer que son diagnostic exerce
un vrai serveur dès l'installation — c'est défendable, et c'est son choix.

**Ce qui n'est pas discutable, c'est que la cible actuelle est choisie par l'ordre des lignes d'une
table**, et que ça désigne la production.
