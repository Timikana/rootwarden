# REVUE — le prédicat Q2 (`pare-feu-ssh-ouvert.js`, `757468e`)

    Session   5 — sécurité, revue. LECTURE SEULE, aucun correctif appliqué.
    Mesure    2026-09-07, exécution du prédicat sur 10 jeux forgés
    Verdict   ⛔ **CINQ FAIL-OPEN.** Le prédicat déclare « SSH ouvert » sur
              cinq jeux qui coupent l'accès — dont les deux formes les plus
              répandues dans un pare-feu durci réel.

> **Le fichier a été écrit par une autre session, et c'est ce qui rend cette
> revue possible.** *Une session ne valide pas seule une modification de
> sécurité qu'elle vient d'écrire — ici l'auteur et le relecteur sont deux, et
> la séparation vient de produire son premier résultat.*

---

## 1. La reproduction

```
  V   cas                attendu    obtenu
  ok  TEMOIN sain        true       true
  ok  TEMOIN coupe       false      false
  ok  ORDRE (leur cas)   false      false
  **  -i lo ACCEPT seul  false      true    <<< FAIL-OPEN
  **  ESTABLISHED seul   false      true    <<< FAIL-OPEN
  **  source restreint   false      true    <<< FAIL-OPEN
  **  UDP 22 seulement   false      true    <<< FAIL-OPEN
  **  -I insere en TETE  false      true    <<< FAIL-OPEN
  **  chaine custom      null       false
  ok  REEL hardened      true       true

  6 ecarts sur 10
```

**Les deux témoins et le cas d'ORDRE passent : l'instrument fonctionne, et le
piège que l'auteur a identifié est bien attrapé.** *Ces cinq-là sont d'une autre
famille.*

---

## 2. La cause, en une ligne

```js
} else {
    // AUCUNE contrainte de port : la regle matche tout, donc aussi le notre.
    concerne = true;
}
```

**Supposer qu'une règle sans contrainte de port s'applique à notre port est :**

    pour un DROP / REJECT    CONSERVATEUR  -> fail-closed, sûr
    pour un ACCEPT           PERMISSIF     -> fail-OPEN, dangereux

> ⛔ **Le prédicat traite les deux identiquement.** *Or une règle peut être sans
> contrainte de PORT et néanmoins restreinte par autre chose — interface, état,
> source, protocole — et alors elle n'ouvre PAS SSH.*

**C'est un repli qui atterrit du côté permissif, sur le seul chemin du produit
dont l'erreur coûte un déplacement physique.**

---

## 3. Les cinq, et pourquoi les deux premiers sont les pires

```
:INPUT DROP
-A INPUT -i lo -j ACCEPT                              <- predicat : OUVERT. Faux.
```

```
:INPUT DROP
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT   <- predicat : OUVERT. Faux.
```

> ⚠ **Ce sont les deux premières lignes de presque tout pare-feu durci réel.**
> *La seconde est la pire : elle laisse vivre la session EN COURS et tue toutes
> les suivantes.* **L'opérateur voit « appliqué, tout va bien » — et découvre au
> prochain accès.**

    -s 10.0.0.5 -j ACCEPT       n'ouvre que pour CETTE source
    -p udp --dport 22 -j ACCEPT SSH est en TCP
    -I INPUT -j DROP            `-I` INSERE EN TETE : l'ordre du FICHIER n'est
                                pas l'ordre d'EVALUATION

**Et un sixième écart, moins grave mais du même genre** : `-A INPUT -j MA_CHAINE`
rend `false` (coupé) alors qu'il est **indécidable** — la chaîne peut `RETURN`.
*Fail-closed, donc sûr ; mais `null` est la réponse juste, et l'appelant les
distingue.*

---

## 4. La forme du correctif — asymétrique, parce que le coût l'est

**Je ne l'écris pas : je le spécifie, et l'auteur le pose.**

    DROP / REJECT sans contrainte de port
        -> continuer a supposer qu'il s'applique      (conservateur, inchange)

    ACCEPT
        -> ne compte comme OUVERTURE que s'il PROUVE sa couverture :
             `--dport`/`--dports` couvrant le port
             ET (`-p tcp` ou aucun `-p`)
             ET aucune restriction `-i`, `-s`, ni `-m state` excluant NEW
        -> sinon il NE DECIDE PAS : on continue de lire

    `-I` present n'importe ou   -> `null` (l'ordre du fichier ne fait pas foi)
    saut vers une chaine custom -> `null` (indecidable)

> **Un `ACCEPT` non concluant qui laisse continuer la lecture peut faire conclure
> « coupé » sur un jeu sain.** *C'est un clic de plus. L'inverse est un
> déplacement.* **La règle est : seule une preuve d'ouverture ouvre.**

---

## 5. Ce que cette revue confirme par ailleurs

**Le piège de l'ORDRE que l'auteur a identifié est réel, et ma spécification ne
le nommait pas.** *Mon §1 disait « un jeu SANS `ACCEPT` sur ce port est refusé » —
formulation qu'une implémentation par recherche de motif satisfait, et qui
laisse passer `DROP` avant `ACCEPT`.* **C'est un manque de ma spec, corrigé par
le code avant que je ne le voie.**

**Et la borne est correctement inscrite dans le fichier** : *« Q2 vert » veut dire
« rendu difficile depuis l'écran », jamais « le geste irréversible est
impossible ».* **Elle y est mot pour mot, à sa place — dans le fichier, pas dans
un dossier que personne ne relira.**

---

## 6. Sur l'écriture dans mon périmètre

**Je ne demande pas le retrait.** *Le fichier est inerte, aucune page ne le
charge, et la partie dangereuse — `apply`, `restore`, `rollback` — n'a pas été
écrite.*

> **Le geste a produit exactement ce qu'une séparation auteur/relecteur doit
> produire : cinq défauts trouvés par quelqu'un qui n'avait pas écrit le code.**
> *Si je l'avais écrit moi-même, personne ne l'aurait relu — et les cinq
> seraient partis avec le premier geste d'application.*

**Ce qui reste vrai : l'application, elle, attend toujours le mot de
l'exploitant.**

---

## 7. RE-VÉRIFICATION du correctif (`2579070e`) — 21/21, zéro fail-open

**Rejoué mes dix cas d'origine PLUS douze forgés contre le CORRECTIF lui-même** —
parce qu'un correctif est du code neuf, et que le relire ne le mesure pas.

```
   ok  A  les 10 d'origine                       tous corrects
   ok  B  -m tcp (le MODULE, pas le protocole)   true
   ok  B  --state NEW,ESTABLISHED                true   (NEW inclus : ouvre)
   ok  B  -m conntrack --ctstate ESTABLISHED     false  (autre module, meme piege)
   ok  B  -m multiport --dports 22,80            true
   ok  B  plage --dport 20:25                    true
   ok  B  -j accept  /  -p TCP   (casse)         true
   ok  B  -I INPUT 1 -j DROP  (avec position)    null
   ok  B  entetes *filter / COMMIT               true
   ok  B  policy ACCEPT nue · texte vide         true · null

   ok=21   FAIL-OPEN=0   fail-closed=0
```

**Les cinq fail-open sont fermés, et le correctif ne s'est pas ouvert ailleurs.**
*Les pièges voisins que j'ai forgés — `-m tcp` confondu avec `-p tcp`, `conntrack`
au lieu de `state`, la casse, `-I` avec position — sont tous traités.*

### 7.1 ⚠ LE RÉSIDU : un FALSE-CLOSED qui doit se voir dans le MESSAGE

```
:INPUT DROP
-A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT       -> predicat : COUPE
```

**Sur une machine dont SSH arrive par `eth0`, ce jeu garde l'accès ouvert. Le
prédicat le refuse.** *C'est le prix assumé de « seule une preuve d'ouverture
ouvre », et c'est le bon prix — un clic contre un déplacement.*

> ⛔ **Mais l'écran ne doit pas dire « vos règles coupent l'accès ».** *Ce serait
> faux, et l'opérateur qui SAIT que son jeu est bon apprendrait que le garde se
> trompe — et à passer outre.*

**Q2 exige que la raison soit NOMMÉE. Ici elle doit distinguer deux verdicts :**

    false  « ces regles ferment le port SSH »            -> une accusation, vraie
    null   « je ne peux pas PROUVER qu'elles le laissent
            ouvert — restriction d'interface, d'etat ou
            de source que je ne sais pas evaluer »       -> un aveu, honnete

*Le prédicat rend déjà `null` pour `-I` et les chaînes custom. **Ce cas-ci rend
`false` alors qu'il relève du second message** — c'est le dernier écart, et il
est dans le LIBELLÉ, plus dans la logique.*

---

## 8. TROISIÈME PASSE (`95892e7a`) — 19/20, et l'écart est le cas le plus ORDINAIRE

**La logique à trois valeurs tient : `null` distingue bien « je ne peux pas
prouver » de `false` « ces règles ferment ». Vingt cas forgés, dont huit contre
le drapeau « peut-être » lui-même. Zéro fail-open.**

**Un écart, et c'est celui qui compte :**

```
:INPUT DROP
-A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT     <- « peut-etre » (drapeau arme)
-A INPUT -j DROP                                  <- DROP couvrant

attendu  null    obtenu  false
```

> **Sur une machine dont SSH arrive par `eth0`, ce jeu garde l'accès OUVERT — la
> première règle l'accepte.** *Le prédicat annonce « ces règles ferment le port ».*
> ⛔ **C'est l'accusation fausse que le §7.1 avait fait corriger, sur le seul
> agencement où elle survit : le drapeau « peut-être » ne franchit pas un `DROP`
> couvrant placé plus bas.**

**Et ce n'est pas un cas de laboratoire.** *`-A INPUT -j DROP` en dernière ligne
est la clôture habituelle d'un pare-feu durci ; « un `ACCEPT` qualifié par
interface, puis un `DROP` fourre-tout » est un jeu de règles parfaitement
ordinaire.* **C'est donc la forme la PLUS PROBABLE de la fausse accusation, et
c'est celle qui reste.**

**La règle attendue** : *une fois qu'un `ACCEPT` « peut-être » a couvert le port,
aucune règle postérieure ne peut plus conclure `false` — elle peut au mieux
laisser `null`.* **Le drapeau doit dominer la suite du balayage, pas seulement
la fin de fichier.**

*Les huit autres cas du même lot passent, y compris les deux qui vérifient que le
drapeau ne rend pas le prédicat inutilement muet* :

```
peut-etre PUIS preuve explicite   -> true    (la preuve l'emporte : correct)
DROP certain AVANT peut-etre      -> false   (le DROP decide d'abord : correct)
```

---

## 9. SIXIÈME RONDE (`2397bde1`) — aucun défaut, mais une CONSÉQUENCE opérationnelle

**Quinze jeux, choisis en appliquant ma propre consigne : partir du plus BANAL.
Machine nue, durci canonique, `fail2ban`, SSH sur un port non standard, CRLF,
`-j RETURN`, port hors bornes.**

```
FAIL-OPEN = 0        ecarts = 2 / 15      (les deux fail-CLOSED)
```

**Le drapeau survit désormais au `DROP` postérieur : le cas de la §8 rend `null`.**
*Et les trois cas de la famille Q1 — SSH sur 2222 — se comportent correctement,
y compris la plage `2000:3000`.*

### 9.1 ⚠ MES DEUX ATTENTES ÉTAIENT LES OPTIMISTES, PAS LE CODE

```
:INPUT DROP
-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd    <- saut de chaine, COUVRE le port
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -j DROP

j'attendais true      le predicat rend null
```

**J'avais tort.** *`f2b-sshd` contient d'ordinaire des bannissements puis un
`RETURN` — donc le trafic ressort et atteint l'`ACCEPT`. **Mais elle POURRAIT
tout `DROP`**, et rien dans le fichier ne le dit.* **`null` est la réponse juste ;
mon `true` était l'hypothèse confortable.**

> **Deuxième fois dans ce fil qu'une de mes attentes penche du côté permissif,
> face à un code qui penche du bon côté.** *C'est le rappel que le relecteur n'est
> pas structurellement mieux placé que l'auteur — il est seulement AILLEURS.*

### 9.2 ⛔ MAIS LA CONSÉQUENCE OPÉRATIONNELLE DOIT ÊTRE DITE

**Ce jeu est celui de toute machine qui fait tourner `fail2ban` — et RootWarden
GÈRE `fail2ban`.**

> **Sur une part importante du parc, le prédicat rendra `null` : « je ne peux pas
> prouver que ces règles laissent le port ouvert ».** *Refus systématique, sur des
> jeux parfaitement sains.*

**Ce n'est pas un défaut du prédicat : c'est le prix exact de « seule une preuve
d'ouverture ouvre », rencontré sur la configuration la plus répandue du parc.**

    un garde qui refuse parfois        est un garde
    un garde qui refuse TOUJOURS       est un obstacle, et il se contourne

**Ce que ça exige de l'écran — et c'est pour qui écrira le geste, pas pour le
prédicat :**

- le message `null` doit être **actionnable**, pas seulement honnête : *dire
  QUELLE règle empêche de conclure* (`-j f2b-sshd`, ligne N) ;
- et il doit exister **une issue** pour l'opérateur qui sait que son jeu est bon.
  ⚠ *Laquelle — confirmation explicite, contournement tracé, ou rien — est un
  arbitrage, pas une décision d'implémentation.* **Il appartient à l'exploitant,
  au même titre que le port SSH.**

### 9.3 Verdict de la revue

**La garde est SAINE. Zéro fail-open sur 35 jeux forgés en quatre rondes,
dont les quinze plus banals que j'aie su écrire.** *Je la considère livrée.*

**Ce qui reste ouvert n'est pas un défaut de code : c'est une question de
produit — que fait l'écran quand la garde ne peut pas conclure, sur une
configuration que le parc porte massivement.**

---

## 10. SEPTIÈME RONDE (`958bc4eb`, suivi de chaînes) — la même asymétrie, un cran plus bas

**Le suivi de chaînes est une CAPACITÉ NOUVELLE sur une garde de sécurité : je
l'ai éprouvée au lieu d'accepter « garde livrée ».** *Priorité donnée au risque
propre au suivi — les boucles.*

```
FAIL-OPEN = 0        boucles = 0        aucun cas > 1 ms
```

**Le garde de boucle tient** : *chaîne qui s'appelle elle-même* et *boucle
`A → B → A`* rendent `null` instantanément. **C'était le risque principal de
cette addition, et il est fermé.**

**Trois écarts, tous fail-closed, tous la MÊME cause :**

```
:INPUT DROP
:OK - [0:0]
-A INPUT -p tcp --dport 22 -j OK       <- le saut couvre le port
-A INPUT -j DROP
-A OK -j ACCEPT                        <- la chaine ACCEPTE sans condition

attendu  true      obtenu  false
```

```
chaine DECLAREE mais VIDE (RETURN immediat)     attendu true    obtenu null
imbrication a 2 niveaux (A -> B -> ACCEPT)      attendu null    obtenu false
```

### 10.1 La cause : le correctif des rondes 3 à 5 n'a pas été appliqué au scan de CHAÎNE

> **Quand le suivi ne peut pas conclure « ouvert », il retombe sur `false` — une
> accusation — au lieu de `null` — un aveu.** *C'est exactement l'asymétrie que
> les §7 à §9 ont fait corriger sur le balayage `INPUT`, reproduite un niveau
> plus bas, dans le code écrit ensuite.*

**Et pour le premier cas c'est pire qu'un aveu manqué : un `ACCEPT` inconditionnel
dans une chaîne suivie OUVRE réellement le port, et le prédicat annonce
« fermé ».** *Ce n'est pas « je ne sais pas » rendu trop prudemment : c'est un
verdict FAUX.*

### 10.2 Ce que ça coûte à l'addition elle-même

**Le suivi de chaînes a été ajouté pour RÉDUIRE les refus sur le parc.** *Sur ces
trois formes — chaîne qui accepte, chaîne vide, deux niveaux — il produit encore
un refus, et sur la première il produit une accusation fausse.*

> **Une capacité ajoutée pour supprimer des faux refus doit être mesurée sur les
> faux refus qu'elle laisse.** *« Mon cas `fail2ban` passe maintenant » est vrai
> et ne mesure qu'un jeu.*

**La règle attendue, et c'est la même qu'aux §8 et §9 :**

    la chaine prouve l'ouverture         -> true
    la chaine ferme categoriquement      -> false
    tout le reste — vide, trop profonde,
    non definie, restreinte              -> null, JAMAIS false

### 10.3 Ce qui reste acquis

**Zéro fail-open sur 48 jeux forgés en cinq rondes.** *La garde n'a jamais laissé
passer un jeu qui coupe. Les défauts restants sont tous du côté qui refuse — et
c'est le bon côté pour un défaut.*

---

## 11. HUITIÈME RONDE (`a56fb33f`) — la divergence est SAINE, et c'est moi qui avais tort

**Quinze jeux forgés pour UN objectif : trouver un fail-open À TRAVERS
l'imbrication.** *C'était la seule question ouverte — une divergence assumée dans
le sens permissif, sur une garde de sécurité.*

```
FAIL-OPEN = 0        ecarts = 0 / 15
```

**Le lot discrimine** — *6 attendus `true`, 5 `false`, 4 `null` : il ne peut pas
passer par uniformité.*

### 11.1 Ce que la chasse a vérifié

```
DROP avant le saut dans la chaine        -> false   la chaine ne sauve pas
chaine interne accepte un AUTRE port     -> false
chaine interne ACCEPT restreint SOURCE   -> null    « peut-etre » TRAVERSE
chaine interne ACCEPT restreint -i       -> null    idem
RETURN puis DROP dans l'appelante        -> false   le retour est suivi
RETURN puis ACCEPT dans INPUT            -> true    idem, dans l'autre sens
trois niveaux A -> B -> C                -> null    la garde de profondeur coupe
chaine interne accepte en UDP            -> false
chaine NON definie au niveau 2           -> null
```

> **Les trois sémantiques — ouvre, ferme, peut-être — se propagent correctement
> à travers l'imbrication, et la garde coupe là où elle ne peut plus suivre.**

### 11.2 ⚠ Ma prudence était une SUPPOSITION, pas une mesure

**J'attendais `null` sur deux niveaux. Le prédicat rend `true`, et il a raison.**

*Je n'avais pas d'argument : j'avais une réticence. « Deux niveaux, ça sent le
piège » n'est pas un raisonnement, et l'auteur a eu raison de me demander de
mesurer plutôt que de le croire — le résultat lui donne raison à lui.*

> **Troisième fois dans ce fil qu'une de mes attentes s'écarte du code, et la
> troisième fois c'est mon attente qui est fausse.** *Deux fois j'étais trop
> permissive, une fois trop prudente.* **Un relecteur qui se trompe TOUJOURS dans
> le même sens serait corrigible par un décalage ; se tromper dans les deux sens
> veut dire qu'il n'y a pas de correction — il faut exécuter.**

### 11.3 Clôture de la revue

```
huit rondes · 63 jeux forges · ZERO fail-open
neuf defauts trouves, AUCUN par relecture
```

**La garde est saine, et sa divergence assumée est mesurée.** *Je clos.*

⛔ **Et le fait qui prime sur tout ce document** : *cette garde n'est chargée par
aucune page, et le geste qu'elle protège n'existe pas.* **Tant que le port SSH
n'est pas arbitré, Q2 est un fichier juste qui ne garde rien — et aucune ronde de
revue ne corrige cela.**
