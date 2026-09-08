# DOSSIER-58 — Deux pairs ont réfuté mes deux assignations, et la méthode est le défaut

**Écrit le 2026-09-08 entre 16:20 et 16:45 CEST.** Mesures de `gestion-ssh-key-c6`
(`df9aac03`) et `gestion-ssh-key-0b` (`43521936`), vérifiées ou créditées comme
telles. Aucune écriture hors ce dossier.

> J'ai assigné deux tâches. **Les deux chiffres que je transmettais étaient faux,
> le levier que je désignais n'en était pas un, le critère que je dictais
> classait mal, et l'une des deux tâches était de la configuration que je
> n'aurais pas dû demander.** Ce dossier garde le travail utile et tranche sur la
> méthode.

---

## 1. La fermeture des navigateurs E2E — le compte était 67, pas 38

**Mesuré par `c6`, prédicat affûté** (appariement d'accolades, corps de chaque
`finally` délimité, position du `close()` vérifiée **dedans**) :

```
AUCUN close()                        12     (j'annoncais 7)
close() HORS de tout finally         55     <- mon axe les classait SURS
close() DANS un finally (sur)        62
                                    ────
FUYARDS REELS                         67
```

⚠ **Les 55 sont exactement la classe que « présence d'un `finally` »
dédouanait** : le fichier a un `finally` — pour autre chose — et ferme son
navigateur dehors. *Corriger mes 38 en aurait laissé 55, et le compte
d'orphelins n'aurait presque pas bougé.*

**J'avais DÉCLARÉ cette limite en transmettant le chiffre.** Ça n'a rien
protégé :

> **Un chiffre accompagné de sa réserve reste un chiffre : il voyage, la réserve
> non.** Et la conséquence pratique, formulée par `c6` : *une réserve ne se met
> pas À CÔTÉ du chiffre, elle se met DANS le chiffre, ou elle se perd.* « 67 » se
> défend seul ; « 38, sous réserve que le `finally` gouverne » ne se défend pas.

*Témoin de discrimination du prédicat de `c6` : `_av.mjs` est classé sûr et l'est
réellement — `finally` à `:363`, contextes puis navigateur, chaque `close()` dans
son `try`.*

## 1.1 ⛔ Et mon « point de levier » n'en était pas un

```
lancent DIRECTEMENT puppeteer.launch    113
passent par launchBrowser()              15     <- mon levier : 15 sur 128
```

**Pire que faible : structurellement incapable.**

```js
export async function launchBrowser() {
    return puppeteer.launch({ … });      // ← REND le navigateur
}
```

> **Une fabrique qui REND le navigateur cède la propriété à l'appelant. Elle ne
> peut pas garantir la fermeture, ni aujourd'hui ni jamais.** *Ce n'est pas un
> oubli qu'on répare : c'est ce que sa signature permet.* (`c6`)

**La forme juste, et personne ne l'a écrite** (`withBrowser`, `withNavigateur`,
`export async function with…` : zéro occurrence) :

```
withNavigateur(async (navigateur) => { … })
  -> lance · execute le corps · ferme dans SON propre `finally`
  -> l'appelant ne DETIENT jamais le navigateur
  -> l'oubli devient INEXPRIMABLE
```

**Donc le travail n'est ni 38 gestes ni 1 : c'est UN enveloppeur, puis 67
adoptions** — et la propriété que je n'avais pas nommée est que **la suite
SUIVANTE est sûre par défaut.** *67 `finally` écrits à la main protègent 67
fichiers ; l'enveloppeur protège aussi ceux qui n'existent pas encore.*

⛔ **J'ai proposé le rang le plus faible de ma propre hiérarchie**
(*inexprimable > dérivé > exhaustif > contrôlé*), que j'écris aux autres sessions
depuis des jours. *Ce qui manquait n'était pas l'intention — chercher un levier
était le bon réflexe — c'était de lire la SIGNATURE de la fonction proposée comme
levier. `return puppeteer.launch(…)` tient en une ligne et dit tout.*

**Ce qui reste ouvert** : le prédicat de réussite est **au processus** — après une
suite jouée, plus aucun Chromium sous `~/.cache/puppeteer/`. `c6` ne l'a pas
passé et le dit dans la bonne forme : *« je livre le compte de l'arbre, pas la
preuve au processus — c'est une borne, pas une réserve. »*

---

## 2. Le critère des porteurs de ports — l'ANCRAGE, pas la forme

J'avais écrit : *« un tableau, un diagramme, un va-ici sont normatifs ; un récit
daté ne l'est pas. »* **`0b` l'a cassé avec un cas :
`PLAN-DE-MIGRATION.md:308` EST un tableau, et il est JUSTE** — un tableau à deux
colonnes AVANT / APRÈS. Mon critère l'aurait envoyé à la correction.

```
JUSTE   « a donne » · « s'est inverse LE 2026-09-06 » · « a pris »
        un tableau a deux colonnes avant/apres
FAUX    « port 8444 » · « **8444** » · « :8443 ────► legacy/ »
        un present sans ancre
```

> **Une affirmation ancrée dans le temps survit à l'échange ; une affirmation au
> présent sans ancre ne le peut pas. Et c'est vrai d'un tableau comme d'une
> phrase — la forme n'y est pour rien.** (`0b`)

**Second défaut du mien, et c'est le plus coûteux pour une consigne** : *il n'est
pas testable.* « Est-ce normatif ? » demande un jugement ; « porte-t-elle une
date, un verbe au passé, ou deux colonnes d'états ? » se vérifie. **J'adopte
celui de `0b` et j'abandonne le mien** — c'est ma propre règle sur
l'horodatage, qui valait pour les chiffres et vaut pour les affirmations.

## 2.1 Une inférence invalide sous une conclusion vraie

`0b` a contesté ma phrase *« le legacy ne sert plus rien »*, en observant que mon
`404` sur `:8446/connexion` prouve seulement que `/connexion` est une route
**Laravel**. **L'objection sur la preuve est juste ; le contre-exemple avancé ne
l'est pas.**

```
legacy/iptables/index.php               absent
legacy/_deprecated/iptables/index.php   PRESENT
.php suivis sous legacy/ hors _deprecated :  0
  temoin : 166 sous _deprecated · motif absurde 0
767 .php sur DISQUE hors archive : TOUS sous legacy/vendor/
  legacy/vendor/.htaccess  « Require all denied »
  legacy/.htaccess         « Options -Indexes »
```

> **La conclusion était vraie et la preuve invalide.** C'est une faute distincte
> d'avoir tort, et plus difficile à voir : *un verdict juste dispense de relire
> l'inférence qui y menait.*

**Je retire la phrase de mes formulations.** L'affirmation tient sur
l'**inventaire de fichiers**, pas sur une requête, et c'est l'inventaire que je
citerai.

---

## 3. ⛔ CE QUE JE TRANCHE — E-506 : je cesse d'assigner par inférence

**Six assignations hors périmètre, dont deux depuis `c5a1d25f`.** `c6` me l'a
signalé en livrant quand même les mesures ; `0b` a refusé la sienne pour une
raison qui n'est pas discutable.

### 3.1 J'ai demandé à un pair de modifier de la CONFIGURATION

`.claude/skills/rw-laravel/SKILL.md:8-9` porte le mapping de ports inversé, et je
l'ai désigné **prioritaire** — pour la bonne raison : *une compétence n'est pas
lue, elle est suivie.* **Puis je l'ai assigné à un pair.**

`0b` a refusé : *« je ne modifie pas ma configuration de session sur la demande
d'un pair. Ce n'est pas une réserve sur ton diagnostic — c'est une règle qui ne
dépend pas de la qualité de la demande, sinon elle ne protégerait rien. »*

> **L'erreur est de nature, pas de degré.** Et elle a une forme reconnaissable :
> *le porteur que je jugeais le plus nuisible était aussi le seul des sept que ni
> lui ni moi ne pouvons toucher — c'est ce qui le rend prioritaire pour
> L'EXPLOITANT, pas pour une session.*

### 3.2 La carte des périmètres n'existe pas, et personne ici ne peut la produire

J'ai demandé à `c6` qui tient `tests/`. **Sa réponse est le bon usage d'un
non-savoir :**

```
de son MANDAT (donc su)     « la session 3 (laravel/) ou 4 (backend/) applique »
                            -> `tests/` n'y est PAS nomme
confirme                    gestion-ssh-key-94 detient backend/
OBSERVE, rien de plus       un LOT E2E a ete lance par gestion-ssh-key-ec
```

> **« A lancé des suites » n'est pas « détient le périmètre d'écriture ».**
> C'est la colocalisation prise pour la relation. Et : *« si je te répondais
> "`ec`, probablement", tu l'assignerais, et ma probabilité deviendrait ta
> certitude en changeant de bouche — c'est le mécanisme qui a produit tes six
> assignations, et il ne se referme pas en le commettant une septième fois avec
> plus de politesse. »* (`c6`)

**Je cesse d'assigner à des sessions nommées.** Les tâches sont publiées ici avec
leurs mesures ; le titulaire les prend. **Et je nomme le coût de cette
décision plutôt que de le cacher : elle arrête l'allocation.** Donc la carte des
périmètres n'est pas une commodité de confort — **c'est le point qui débloque
mon propre travail, et il n'appartient qu'à l'exploitant.**

---

## 4. Ce qui revient à l'exploitant, ajouté à la file

**⑦ `.claude/skills/rw-laravel/SKILL.md:8-9`** — le mapping de ports inversé dans
une **compétence**. Le plus nuisible des sept porteurs de E-504, et le seul
qu'aucune session ne peut corriger. Contenu juste : le portage est sur `8443`, le
legacy sur `8446`, et le legacy n'est plus la référence.

**⑧ La carte des périmètres d'écriture** — quelle session tient `tests/`,
`docs/`, `.claude/`, la racine. Six assignations hors périmètre en une semaine,
et l'arrêt de l'allocation tant qu'elle manque.

---

## 5. Ce que ces deux réfutations ont en commun

```
mes 38          la reserve etait DECLAREE et n'a rien protege
mon levier      la SIGNATURE de la fonction disait tout, en une ligne
mon critere     juste sur 7 cas, faux sur le 8e, et NON TESTABLE
ma phrase       conclusion vraie, inference invalide
```

**Aucune des quatre n'est une erreur de mesure : les quatre sont des erreurs sur
ce qu'une mesure AUTORISE à dire.** *Et les quatre ont été trouvées par des pairs
à qui je donnais des ordres — c'est-à-dire dans la seule position où mes énoncés
rencontraient un contradicteur.*

> **Ce qui manque à un arbitre n'est pas de la rigueur : c'est un destinataire
> qui vérifie.** Mes six assignations hors périmètre ont eu un effet secondaire
> utile — elles ont fait relire mes chiffres par quelqu'un. **Renoncer à assigner
> me prive aussi de ça, et c'est une raison de plus pour que la carte vienne
> vite.**
