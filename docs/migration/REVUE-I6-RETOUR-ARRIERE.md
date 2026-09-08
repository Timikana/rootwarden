# REVUE — I6, le retour arrière (`pare-feu.js`)

    Session   5 — securite, revue. Je n'ai ecrit aucune ligne d'I6.
    Mesure    2026-09-08, lecture. Rien exerce, aucune machine jointe.
    Verdict   ⚠ UN DEFAUT DE COURSE : trois chemins de refus ne DESARMENT pas.

---

## 0. Le travail qu'on m'assignait était déjà fait — et bien fait

**On m'a demandé d'écrire le retour arrière. Il est écrit.** *Vérifié avant de
toucher quoi que ce soit — c'est la deuxième assignation de suite dont l'objet
existait déjà, et je l'ai trouvée en appliquant la règle qu'on venait de me
donner : chercher la COUCHE, pas le nom.*

```
vue        colonne d'action I6 + `rb_titre`      pare-feu.blade.php
langues    17 cles `rb_*`, FR = EN               parite verifiee
JS         bouton par ligne -> litLaVersion()    :623
           lecture d'UNE version                 /pare-feu/version
           Q2 sur le port ACTUEL (Q1)            :1103
           consentement, puis le geste            :1121 · :1145
```

**Et mon objection du §4.1 de la pré-relecture est CLOSE, par un meilleur dessin
que le mien.** *Je proposais d'évaluer Q2 sur chaque version au moment de la
liste et de pastiller chaque ligne. L'implémentation lit **une** version à la
demande et affiche **ses règles réelles** (`rbApercu.textContent = regles`) avec
son verdict.*

> **L'opérateur ne choisit plus une date à l'aveugle, et mon remède aurait
> expédié tous les jeux archivés au navigateur pour l'éviter. Le leur ne le fait
> pas. Le mien était plus lourd pour le même résultat.**

*Et les trois valeurs de Q2 sont honorées, avec le commentaire qui le dit :
« `false` ET `null` refusent tous les deux ».*

---

## 1. ⚠ LE DÉFAUT — trois chemins de refus ne désarment pas

**`litLaVersion()` appelle `rbRemetAZero()` au DÉBUT — qui met `versionCourante`
à `null` et désactive le bouton. C'est correct pour un enchaînement séquentiel.**
*Mais la lecture est ASYNCHRONE, et les trois chemins de refus rendent la main
sans rien désarmer :*

```js
if (r.statut !== 200 || corps.success !== true) { rbDire(…); return; }   // ⬅ ne desarme pas
if (!window.rwLaisseLeSshOuvert || !port)      { rbSsh…;   return; }     // ⬅ ne desarme pas
rbSsh.textContent = ouvert === false ? … : … ;                          // ⬅ ne desarme pas
```

### 1.1 Le scénario, et il ne demande qu'un double clic

    1. clic sur la version B   -> requete B partie
    2. clic sur la version A   -> rbRemetAZero() : desarme, bouton desactive
                                  requete A partie
    3. la reponse B ARRIVE (tardive) -> Q2 = true
                                  -> versionCourante = B, bouton REACTIVE
    4. la reponse A arrive     -> affiche les regles de A et « SSH ferme »
                                  -> mais ne desarme PAS

    ETAT FINAL : l'ecran montre la version A et son REFUS.
                 Le bouton est ACTIF et arme sur la version B.

> ⛔ **L'opérateur lit un refus, voit un bouton actif, clique — et restaure une
> AUTRE version que celle qu'il regarde.** *Sur ce geste, se tromper de version
> ne dégrade pas un service : il applique un jeu de règles de pare-feu qu'il n'a
> pas lu.*

### 1.2 Ce qui le rend difficile à voir

**Le désarmement EXISTE et il est au bon endroit pour le cas séquentiel.** *Une
relecture le trouve, conclut « c'est géré », et passe.* **C'est la même forme que
les trois défauts de Q2 : une garde correcte, contournée par un chemin de sortie
qui la précède — ici le `return` d'un refus, et non plus celui d'un `ACCEPT`.**

    Q2, defaut 1    garde `-I` posee DANS la boucle, sautee par un `return`
    Q2, defaut 3    drapeau « peut-etre », saute par le `return` de la branche DROP
    I6, ce defaut   desarmement pose AVANT l'attente, saute par le `return` d'un refus

**Troisième fois dans ce module, et la première dans du code asynchrone.**

---

## 2. Le correctif, spécifié

    dans CHACUN des trois chemins de refus :
        versionCourante = null
        rbBouton.disabled = true

**Ou, mieux — par CONSTRUCTION plutôt que par répétition :** *marquer la requête
et n'appliquer son résultat que si elle est encore la dernière.*

```
var jetonLecture = 0;                    // au niveau du module
…
var mien = ++jetonLecture;               // dans litLaVersion, avant l'appel
…
if (mien !== jetonLecture) { return; }   // en tete du .then(), AVANT tout rendu
```

> **La seconde forme ferme aussi le défaut d'AFFICHAGE que la première laisse :**
> *avec le seul désarmement, une réponse tardive peut encore écraser l'aperçu de
> la version qu'on regarde.* **Le jeton rend la réponse périmée inexprimable —
> elle ne peut plus rien écrire du tout.**

---

## 3. Ce que je n'ai pas fait

    NON ECRIT     je n'ai pas pose le correctif. I6 est dans mon perimetre, mais
                  je ne l'ai pas ecrit : je peux donc le relire. Si je le corrige,
                  la correction doit aller au relecteur assigne — pas a moi.
    NON EXERCE    aucune requete, aucune machine jointe, aucun jeu applique.
    NON MESURE    je n'ai pas provoque la course au navigateur : je ne prends
                  jamais le banc. **Le defaut est lu, pas reproduit** — et c'est
                  une borne, pas une reserve de style.

---

## 4. L'ASYMÉTRIE `restaure()` — la contrainte qui la bloquait NE S'APPLIQUE PAS

**Personne ne l'a prise. Elle est dans mon périmètre. Et la raison invoquée pour
ne pas la refermer est mesurée fausse.**

### 4.1 La contrainte, telle qu'elle m'a été posée

> *« `/iptables-` est une entrée à PRÉFIXE de la liste blanche : ce qui tient est
> que ce script ne compose aucune autre requête — la fermeture PAR L'ABSENCE. Si
> ton correctif ajoute un appel sous `/iptables-`, cette fermeture cesse d'être
> vraie. »*

**Elle est juste comme énoncé général. Elle ne s'applique pas ici.**

```
chemins /iptables- DEJA composes par pare-feu.js :
  :333   '/iptables'
  :752   '/iptables-validate'      <- DEJA DANS L'ENSEMBLE
  :975   '/iptables-apply'
  :1208  '/iptables-rollback'
```

> **La fermeture par l'absence porte sur QUELS points d'accès le script atteint,
> pas sur COMBIEN de fois il les appelle.** *`/iptables-validate` y est depuis I4.
> Ajouter un cinquième site d'appel vers un point déjà atteint n'élargit
> l'ensemble d'aucun élément.*

**La contrainte a été appliquée à un cas qu'elle ne couvre pas — et elle a tenu
la correction fermée.**

### 4.2 Et l'asymétrie a une conséquence que « atomique » ne couvre pas

**On pourrait croire le manque bénin : `iptables-restore` échoue proprement, les
règles en mémoire survivent.** *C'est vrai du RUNTIME, et faux du fichier.*

`iptables_manager.py` — `apply_iptables_rules()` :

```
1. _write_rules_safe(...)  ->  ECRIT /etc/iptables/rules.v4
2. iptables-restore < /etc/iptables/rules.v4   ->  CHARGE
```

> ⛔ **Le fichier est écrit AVANT d'être chargé.** *Un jeu malformé écrase le
> fichier persistant, puis échoue au chargement : la machine garde ses règles
> **jusqu'au prochain redémarrage**, et se relève sans pare-feu.*

**Le chemin `apply` valide ; le chemin `restaure` ne valide pas ; les deux
appellent la MÊME fonction en aval.** *Le défaut n'est donc pas « une validation
en moins » : c'est un défaut À RETARDEMENT, sur le seul des deux chemins qui n'a
pas de garde.*

*Le risque reste modéré — une version archivée était chargeable le jour de son
archivage. Il faut que l'`iptables` de la machine ait changé depuis. **Sur un parc
qu'on met à jour, c'est une question de temps, pas de possibilité.***

### 4.3 ⛔ CE QUI RESTE À ARBITRER, ET QUI N'EST PAS À MOI

**Je peux écrire l'appel. Je ne peux pas décider de son SENS D'ÉCHEC.**

    validate rend « syntaxe invalide »   -> refuser, evidemment
    validate rend une ERREUR (500, reseau, machine injoignable)
        -> proceder quand meme ?   le geste reste possible, la garde est muette
        -> refuser ?               une machine injoignable interdit le retour
                                   arriere, alors que c'est peut-etre pour ca
                                   qu'on veut le faire

> **C'est le même arbitrage que sur `/iptables-validate` en I4 : la route rend
> `success: false` pour QUATRE situations distinctes, et le discriminant est le
> STATUT.** *Ici la question n'est pas comment lire la réponse — c'est ce qu'on
> fait quand il n'y en a pas.*

**Refuser est cohérent avec « seule une preuve d'ouverture ouvre ». Mais Q2 a
déjà refusé ce qu'il fallait refuser, et un second refus qui porte sur
l'INJOIGNABILITÉ retire une capacité de reprise.**

*Je pose la question plutôt que de choisir : c'est une décision de produit sur un
geste irréversible, et la dernière fois qu'une contrainte a été appliquée sur une
prémisse non vérifiée, elle a tenu un sous-lot fermé trois jours.*
