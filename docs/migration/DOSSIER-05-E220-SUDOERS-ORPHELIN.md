# DOSSIER 05 — E-220, l'auto-réparation du sudoers orphelin

**Pour signature de l'exploitant.** Préparé par la session 8 le **2026-08-28**.

---

## 1. Recommandation

**Autoriser l'auto-réparation, avec ses deux gardes obligatoires — et la livrer AVEC la colonne, pas à
sa place.**

Les deux moitiés d'E-220 sont **complémentaires et non classées** : l'auto-réparation **réduit la
population**, la colonne **rend visible ce qui reste**. *Une mesure qui réduit un ensemble ne remplace
pas celle qui décrit ce qui reste.*

**Et la moitié la moins chère est déjà faite** — voir §2.

---

## 2. Conséquence, mesurée

### L'état, et ce qui le maintient

    /etc/sudoers.d/rootwarden   contient  'rootwarden ALL=(ALL:ALL) NOPASSWD: ALL'
                                et AUCUN compte de ce nom n'existe

**Inerte aujourd'hui** : pas d'utilisateur, pas d'élévation. **Il redevient vivant à l'instant où quoi
que ce soit recrée un compte de ce nom** — gestion de configuration, `useradd` manuel, un paquet. **Root
est alors accordé en silence, sans que personne n'ait écrit de règle sudo.**

**Ce qui le maintient n'est pas une exception de sûreté** — la première explication du Lead était fausse
et a été retirée. La cause est plus simple et plus large : **aucune routine du produit ne balaie
`/etc/sudoers.d/` à la recherche de fichiers sans compte correspondant.** *Le fichier survit parce que
personne ne le cherche, pas parce qu'une règle le protège.*

**L'état persiste exactement sur les machines révoquées et jamais redéployées** — `deploy_service_account`
écrase le fichier (`>`), mais **en recréant le compte** : il supprime la condition de l'orphelin, il ne
le nettoie pas.

### ✅ Ce qui est DÉJÀ fait, et qui n'était pas dans le relevé

**La moitié « donner un nom à l'état » est écrite et commitée.**

    backend/routes/ssh.py:1047   'sudoers_orphelin': False        <- TOUJOURS present, meme a False
    backend/routes/ssh.py:1206   r['sudoers_orphelin'] = True
    backend/routes/ssh.py:1229   ' SUDOERS_ORPHELIN' dans le journal
    laravel/.../ClePlateformeController.php:76   'geste_sudoers_orphelin'   <- le portage le LIT

**Et le champ est renseigné, jamais omis** — c'est la première des trois conditions de « rendre visible
un objet invalide mais présent » : *le backend RENSEIGNE un drapeau, il n'OMET pas un champ.* Si
l'information était portée par l'absence, l'écran ne pourrait pas la distinguer de « rien à dire ».

> **Il reste donc UNE moitié à décider, pas deux** : l'auto-réparation. Elle est la seule qui **écrive
> sur des machines réelles**.

### Ce que l'auto-réparation coûterait, et pourquoi elle est praticable

**L'argument qui la rend bon marché est mesuré** : `deploy_platform_key` appelle déjà `execute_as_root`
et écrit dans `/root/.ssh/`. **Donc si elle s'exécute, l'élévation a déjà réussi.** Le nettoyage
**hérite** d'une élévation prouvée au lieu de payer la précondition qui bloque le rejeu de la révocation
(`root_password` vide sur une machine migrée).

### ⚠ Les deux gardes, sans lesquelles le défaut irait dans le sens DESTRUCTEUR

C'est la réserve de la session 4, et c'est elle qui décide de la forme du geste : la condition « aucun
compte de ce nom n'existe » **n'est pas fail-closed naturellement.**

`id rootwarden` peut échouer pour une raison qui **n'est pas** l'absence du compte — NSS indisponible,
LDAP injoignable, délai dépassé. **Une condition écrite « si `id` échoue » retirerait alors un
`NOPASSWD: ALL` légitime et casserait le compte de service d'une machine saine** — dans un geste de
parc lancé en masse.

    1. exiger l absence POSITIVEMENT : `getent passwd rootwarden` distingue « absent » (code 2)
       d une « erreur de service » (autres codes). Ne retirer que sur l absence NOMMEE,
       jamais sur « la commande n a pas reussi ».
    2. croiser avec la BASE : ne retirer que si `service_account_deployed = 0`.
       Les deux signaux doivent CONCORDER, sinon on ne touche a rien.

*Un marqueur n'est pas un verdict, et un échec de commande n'est pas une réponse.*

### ⚠ La population concernée : la base ne peut PAS répondre, et c'est le défaut lui-même

**J'ai d'abord écrit ici « aucune machine n'est dans l'état orphelin, les trois portent
`service_account_deployed = 1 »`. C'était faux, et la mesure le dit :**

    id  machine                sa  pk  pwreq  password  root_password
     1  srv-zabbix              1   1    0        1          1
     2  Test-Server-Debian      0   0    1        1          1
     3  OpenCVE-Test-OnPrem     0   0    1        1          1

**Une seule machine porte `sa = 1`.** Les deux autres portent `sa = 0` — **et c'est exactement
l'ambiguïté qu'E-220 décrit** : `service_account_deployed = 0` signifie *« jamais déployé »* **ou**
*« révoqué, sudoers subsistant »*, et **le drapeau ne les distingue pas.**

> **Donc la question « combien de machines sont orphelines » n'a pas de réponse en base. Y répondre
> demanderait de joindre les machines.** *Le drapeau est binaire pour une réalité ternaire, et toute
> route qui le lit hérite de l'imprécision* — y compris ce dossier, qui vient de s'y prendre.

Ce que la base permet de dire, et rien de plus : `pk = 0` sur les machines 2 et 3 **suggère** qu'aucune
clé de plateforme n'y a jamais été déployée, donc qu'aucun compte de service n'y a été créé, donc
qu'aucun fichier sudoers n'y a été écrit. **C'est une inférence, sur un drapeau dont E-207 a établi
qu'il diverge de ses colonnes** — la ligne 1 en donne l'exemple sous les yeux : `pwreq = 0` alors que
les **deux** mots de passe sont présents.

**Conséquence sur la recommandation, et elle la renforce** : l'auto-réparation est le seul mécanisme qui
pourrait répondre à la question, puisqu'elle interroge la **machine** (`getent`) et non le drapeau. *Ce
qu'on ne peut pas compter depuis la base est précisément ce que le geste va découvrir.*

---

## 3. Le geste exact

**Aucune exécution à autoriser aujourd'hui. Ce qui se signe est l'AUTORISATION D'ÉCRIRE** un chemin qui
écrira sur des machines réelles lors d'un futur déploiement de clé.

```
backend/routes/ssh.py, dans `deploy_platform_key` (session 4) :

  1. `getent passwd rootwarden`
       code 0            -> le compte existe        -> NE RIEN FAIRE
       code 2            -> absent, nomme           -> candidat
       tout autre code   -> erreur de service       -> NE RIEN FAIRE, et le DIRE
  2. et `service_account_deployed = 0` en base       -> les deux doivent CONCORDER
  3. alors seulement : `rm -f /etc/sudoers.d/rootwarden`
  4. et le RENDRE dans la reponse — un nettoyage silencieux est un nettoyage
     qu on ne peut pas verifier
```

**Verrouillé par la session 6**, et la suite doit exercer **les trois codes de retour**, pas seulement
l'absence : *une sonde qui rend « aucun défaut » doit pouvoir nommer la raison de son silence.* Le cas
qui compte est le **troisième** — l'erreur de service — parce que c'est celui où une écriture partirait
à tort.

**Et le geste s'exécutera pour la première fois lors d'un déploiement de clé de plateforme**, c'est-à-dire
dans le périmètre de K4, qui est bloqué par ailleurs. **La mise en service réelle est donc différée par
construction.**

---

## 4. Ce qui se passe si on ne fait rien

| | |
|---|---|
| **aujourd'hui** | **rien.** Aucune machine du parc n'est dans l'état orphelin |
| **après la première révocation de compte de service** | la machine garde un `NOPASSWD: ALL` **dormant**, et le produit n'a aucun moyen de le retirer — la révocation est le seul geste qui l'essaie, et sur une machine migrée son rejeu ne peut pas élever |
| **le jour où un compte `rootwarden` est recréé** par autre chose que RootWarden | **root accordé en silence**, sans qu'aucune règle sudo n'ait été écrite par personne |

> **L'inaction ne crée pas le défaut : elle rend son apparition irréversible.** Chaque révocation ajoute
> une machine à une population que rien ne réduit et que rien ne compte. *Un privilège orphelin est
> inerte tant que rien ne l'emploie — et ce qui l'emploiera n'est pas RootWarden, donc ce ne sera vu par
> personne.*

**Et il y a un second effet de l'inaction, plus discret** : `remove_ssh_password` (`ssh.py:1275`) refuse
tant que `service_account_deployed` vaut 0. **Sur une révocation partielle le drapeau reste
délibérément à 1** — bon choix, il garde le rejeu ouvert — **donc `remove_ssh_password` accepterait, et
viderait les deux mots de passe d'une machine dont le compte de service n'existe plus.** Ce n'est pas un
verrouillage (la clé de plateforme reste sur `root` et sur le compte nominal), **mais la précondition ne
mesure plus ce qu'elle croit mesurer.** Le champ `sudoers_orphelin` existe désormais : les routes qui
lisent le drapeau **peuvent** distinguer les trois états. **Aucune ne le fait encore.**

---

## Ce qui n'est pas mesuré

- **qu'un `/etc/sudoers.d/rootwarden` orphelin existe quelque part.** Aucune machine du parc n'est dans
  l'état ; le vérifier ailleurs demanderait de joindre des machines ;
- **le comportement de `getent passwd` sur les machines du parc** — le code 2 est la sémantique
  documentée, elle n'a pas été exercée ici ;
- **combien de routes lisent `service_account_deployed` comme une précondition binaire.** Non compté —
  et c'est ce comptage qui dirait l'étendue réelle de l'imprécision.
