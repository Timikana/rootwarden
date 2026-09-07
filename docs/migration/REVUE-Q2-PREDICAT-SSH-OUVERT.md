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
