# MESURE — les navigateurs orphelins des suites E2E

    Session   5 — securite, LECTURE SEULE. `tests/` n'est pas mon perimetre.
    Mesure    2026-09-08, arbre courant. Aucune suite jouee, aucun processus arrete.
    Objet     repondre aux DEUX questions posees avant d'ouvrir un fichier.

---

## 1. Le compte : 67 fuyards, pas 38 — l'axe était le mauvais

**Le relevé transmis comptait les fichiers SANS aucun `finally`, et son auteur
avait déclaré la limite : *« `grep -c finally` dit qu'un `finally` EXISTE, pas que
le `close()` soit dedans »*.**

**Prédicat affûté — appariement de accolades, le corps de chaque `finally` est
délimité, et on vérifie que la position du `close()` tombe DEDANS :**

```
AUCUN close()                          12    (le releve en annoncait 7)
close() HORS de tout finally           55    ← non mesure par l'axe precedent
close() DANS un finally  (sur)         62
                                      ───
FUYARDS REELS                          67
```

> **Les 55 sont exactement la classe que l'axe « présence d'un `finally` »
> classait sûre.** *Le fichier a un `finally` — pour autre chose — et ferme son
> navigateur en dehors. Corriger les 38 en aurait laissé 55.*

**Témoin de discrimination** : *`_av.mjs` est classé sûr, et il l'est —
`finally` à `:363`, `close()` des contextes puis du navigateur, chaque `close()`
dans son `try`.* **La sonde distingue donc bien les deux cas.**

---

## 2. Le levier : `helpers.mjs` couvre 15 suites sur 128

```
lancent DIRECTEMENT puppeteer.launch   113
passent par launchBrowser()             15
ni l'un ni l'autre                      18
```

**Ce n'est PAS un point de levier unique.** *La question posée — « si le lancement
est centralisé, un correctif couvre beaucoup de suites » — a une réponse
mesurée : **non**, 113 suites lancent en direct.*

### 2.1 ⛔ ET LA RAISON EST STRUCTURELLE, PAS HISTORIQUE

```js
export async function launchBrowser() {
    return puppeteer.launch({ … });      // ← REND le navigateur
}
```

> **Une fabrique qui REND le navigateur cède la propriété à l'appelant. Elle ne
> peut PAS garantir la fermeture, aujourd'hui ni jamais.** *Corriger
> `helpers.mjs` ne fermerait donc rien, même pour ses 15 usagers.*

**La forme qui ferme par CONSTRUCTION est un enveloppeur qui possède les DEUX
bouts :**

    withNavigateur(async (navigateur) => { … })
      -> lance, execute le corps, ferme dans son propre `finally`
      -> l'appelant ne DETIENT jamais le navigateur, donc il ne peut pas
         oublier de le fermer : l'oubli devient INEXPRIMABLE

**Aucun enveloppeur de ce genre n'existe** (mesuré : `withBrowser`,
`withNavigateur`, `export async function with…` → zéro occurrence). *Et
`_av.mjs` en montre déjà la forme, à la main.*

> **Le travail n'est donc ni 38 gestes ni 1 : c'est UN enveloppeur, puis 67
> adoptions.** *Chaque adoption est triviale, et la suite suivante est sûre par
> défaut — ce que 67 `finally` écrits à la main ne donnent pas.*

---

## 3. Le prédicat de réussite est au PROCESSUS — et je ne peux pas le passer

    compter les Chromium sous ~/.cache/puppeteer/ AVANT et APRES une suite,
    dans la MEME commande

**Je ne joue aucune suite** : *`banc-libre.sh` rend « RIEN VU », ce qui n'est pas
« libre », et je ne prends jamais le banc.* **Donc je livre le compte de l'arbre
et pas la preuve au processus — c'est une borne, pas une réserve.**

⛔ **Et je n'arrête aucun processus** : *8 des Chromium présents sont les fenêtres
de la session graphique de l'exploitant.* **Un `pkill` les fermerait avec les
orphelins.**

---

## 4. Ce que ça vaut, sans le survendre

**Le gain mémoire est 0,32 Gio** — *le chiffre a été corrigé par son auteur, qui
avait d'abord annoncé 2,9 Gio en remontant la chaîne de parenté entière au lieu du
parent immédiat.*

> **La valeur réelle est la LISIBILITÉ de l'arbre de processus.** *C'est son
> illisibilité qui a produit une accusation fausse de 2,9 Gio — donc le correctif
> paie en mesures justes, pas en mémoire.*


---

## 5. ⛔ RECTIFICATION — « fuyards » est le mauvais mot, et le mécanisme le dit

**Ce document appelle les 67 des « fuyards ». Sur un arrêt PROPRE, ils ne fuient
pas.**

`@puppeteer/browsers` installe ses propres répartiteurs de sortie — mesuré
(`lib/cjs/launch.js:91`, `src/launch.ts:219`) :

```
evenements couverts   exit · SIGINT · SIGHUP · SIGTERM
mecanisme             detached: true  +  onProcessExit  +  process.kill
desactives ?          aucune suite ne passe handleSIGINT/TERM/HUP  ->  0 occurrence
  temoin : la sonde voit 359 `timeout:`, 117 `headless:`, 116 `args:` — elle lit bien
```

    chemin de sortie      puppeteer   finally   enveloppeur
    sortie propre             ✅          ✅          ✅
    process.exit()            ✅          ❌          ✅
    SIGINT/TERM/HUP           ✅          ❌          ✅
    SIGKILL (OOM)             ❌          ❌          ❌   ← par definition du signal

> **Les 15 orphelins réparentés à `init`, d'un SEUL événement à 2,8 jours, avec le
> swap plein à 120 Ki près, sont un SIGKILL. Et SIGKILL est le seul chemin
> qu'aucun gestionnaire ne peut couvrir.**

### 5.1 La causalité était inversée, et le correctif reste bon

**Ce n'est pas le défaut des 67 qui a produit la pression mémoire : c'est la
pression mémoire qui a produit les orphelins.**

> **Donc l'enveloppeur ne nettoie pas après l'OOM — il rend l'OOM MOINS
> PROBABLE**, en ne gardant pas un navigateur ouvert pendant qu'une suite échoue.
> *Il agit sur la cause mesurée, pas sur le symptôme — et il n'a aucun chemin par
> lequel il réduirait un compte d'orphelins.*

**Le mot juste n'est donc pas « fuyard » mais « qui garde un navigateur ouvert
plus longtemps que nécessaire ».** *Ça se corrige par la même chose et ça ne fait
pas chercher une fuite qui n'existe pas.*

### 5.2 ⚠ Et mon propre angle mort, qui a failli réfuter le vrai

**Ma première sonde a cherché les gestionnaires dans `puppeteer-core` et rendu
ZÉRO.** *J'ai failli écrire « puppeteer ne pose aucun gestionnaire ».*

**Ils sont dans `@puppeteer/browsers`.** *Mon `find` avait atterri sur le premier
répertoire portant le nom, et **j'ai laissé la portée de ma sonde être décidée par
où il était tombé**.*

> **C'est le témoin qui m'a sauvée** : il montrait 7 fichiers avec `process.on`
> dans l'arbre, donc la sonde LISAIT. **Le zéro venait de son périmètre, pas d'une
> absence — et sans témoin les deux sont la même sortie.**


---

## 6. ⛔ MON 67 ÉTAIT CONTAMINÉ — et le désaccord qui reste n'est PAS celui qu'on croit

**Mon relevé ne dépouillait pas les commentaires. C'est ma propre règle — « cité »
n'est pas « appelé » — enfreinte pour la troisième fois aujourd'hui, dans un dépôt
dont la prose parle abondamment de ses propres défauts.**

*Mesuré : **47 % des occurrences de `finally`** des suites vivent dans des
commentaires.*

### 6.1 Ce que je mesure APRÈS dépouillement

```
population (fichiers lançant un navigateur, hors commentaires)   132
défaut (a) — fermeture non gouvernée par un finally               68
défaut (b) — process.exit() interposé                             42
```

**Variables isolées, une à la fois — portée `plat`/`récursif` × motif
`navigateur seul`/`tout .close()` : les QUATRE variantes rendent `132 / 68`.**
*Donc ni la portée ni le motif de fermeture n'expliquent quoi que ce soit : mon
instrument est stable.*

### 6.2 ⚠ ET JE NE REPRODUIS PAS LE `110 / 62 / 37` ANNONCÉ

    moi, apres depouillement    132 population · 68 (a) · 42 (b)
    annonce par ailleurs        110 population · 62 (a) · 37 (b)

> **L'écart est de 22 fichiers sur la POPULATION, et il ne vient pas du
> dépouillement — mon dépouillement fait MONTER mon compte, pas descendre.**

**Le désaccord porte donc sur la DÉFINITION de la population, et aucun des deux
prédicats n'a été énoncé assez précisément pour que l'autre le rejoue.** *C'est la
règle du grain de la mesure : un instrument qui nomme une FAMILLE ne peut pas en
compter les membres tant que la famille n'est pas définie.*

**Mon prédicat, énoncé pour être réfuté** : *`tests/e2e/**/*.mjs` hors
`node_modules` · texte dépouillé des `//` et `/* */` en respectant chaînes et
gabarits · retenu si `puppeteer.launch` OU `launchBrowser(` subsiste · défaut (a)
si aucune `.close(` ne tombe dans le corps d'un `finally` délimité par
appariement d'accolades.*

### 6.3 ⛔ ET LA CONSÉQUENCE EST SUR LE CLIQUET, PAS SUR LE CHIFFRE

**Un cliquet statique a été posé à `62`. Si le compte réel est `68`, il n'est pas
« un peu bas » : il est calibré sur une population qui EXCLUT 22 fichiers.**

> **Un cliquet mord dès la première régression — c'est sa vertu. Mais un cliquet
> calibré sous la vérité déclare acquis ce qui ne l'est pas, et sa vertu joue
> alors CONTRE : il autorise 6 régressions avant de mordre.**

**Aucun de nous ne devrait publier ce nombre avant que les deux prédicats soient
rapprochés.** *Ce n'est pas une querelle de chiffre : c'est le seuil d'un
mécanisme qui décide, et je ne sais pas lequel des deux est juste.*


---

## 7. ✅ RAPPROCHÉ — `125 / 70`, et mes DEUX termes étaient faux

**Les prédicats ont été échangés sous forme réfutable. J'ai rejoué le leur sur ma
portée : `population 125 · (a) 70` — l'accord est exact.**

### 7.1 L'écart de population : 6 fichiers, le lancement n'est QUE dans une chaîne

```
ma retention   (commentaires seuls depouilles)   132
leur retention (commentaires ET litteraux)       126
ecart : 6 fichiers ou `puppeteer.launch` ne subsiste que dans une CHAINE
  go-fail2ban-f7 · go-page-groupes · go-page-pare-feu · go-page-wazuh
  lib-navigateur.epreuve · lib-navigateur.invariant
puis 126 − 1 (lib-navigateur.mjs)                125   ✓
```

> **Je dépouillais les commentaires et PAS les littéraux.** *« Cité » n'est pas
> « appelé » — et une chaîne est une citation autant qu'un commentaire. J'avais
> corrigé la moitié de ma faute en croyant l'avoir corrigée entière.*

### 7.2 ⛔ ET SUR LE DÉFAUT, MON MOTIF DÉDOUANAIT

**Mon motif acceptait n'importe quel `.close(`. Recensement des receveurs, dérivé
de la source dépouillée :**

```
ctx 151 · navigateur 121 · browser 30 · c 28 · page 11 · ctxEn 4 · context 1
```

> ⛔ **`ctx`, `c`, `ctxEn`, `context` sont des CONTEXTES et `page` une PAGE. Une
> suite qui ferme proprement ses contextes dans un `finally` et n'a JAMAIS fermé
> le navigateur était classée SAINE par ma sonde.**

**C'est pourquoi je comptais 68 et non 70 : mon erreur était du côté PERMISSIF.**
*Deux suites réellement en défaut sortaient de ma liste — et c'est la classe de
faute que je répète depuis deux jours qu'un pair ne relit pas.* **Celui-ci l'a
relue.**

### 7.3 Ce que ça règle, et ce que ça vaut

    le compte arrete       population 125 · defaut (a) 70 · defaut (b) 37
    le cliquet             recalibre a 70, et il refuse desormais tout
                           receveur de `.close(` INCONNU a l'execution

**Mon §6 disait « je ne sais pas lequel des deux est juste ». Réponse : ni l'un ni
l'autre — le leur après correction de sa population, le mien jamais.** *Et la
seule raison pour laquelle un seuil faux n'a pas été scellé sur `main` est qu'un
chiffre a refusé d'être reproduit.*


---

## 8. ⛔ LE §7 ÉTAIT FAUX AUSSI — `129 / 67 / 41`, et deux erreurs s'annulaient

**Ma « chaîne fantôme » n'était pas une propriété des fichiers : c'était mon
INSTRUMENT. Reproduit chez moi, mesuré :**

```
go-page-pare-feu.mjs:231
  return m ? m[1].replace(/\\'/g, "'").replace(/\\\\/g, '\\') : null;

mon depouilleur : le `/` est un caractere ORDINAIRE
  -> l'apostrophe de /\\'/g OUVRE une chaine fantome
  -> 4175 des 4200 caracteres suivants BLANCHIS
  -> `puppeteer.launch` ligne 262 : present dans le brut, ZERO apres mon strip
  -> la ligne 262 est ENTIEREMENT avalee
```

**Les quatre fichiers appellent le lancement en CODE NU** — `go-fail2ban-f7:223`,
`go-page-groupes:330`, `go-page-pare-feu:262`, `go-page-wazuh:244`, tous
`const navigateur = await puppeteer.launch({`. *Mon §7.1 décrivait fidèlement le
comportement de mon lexeur cassé, et nous l'avons pris tous les deux pour une
propriété du dépôt.*

### 8.1 Le compte, confirmé par un lexeur qui connaît les regex

```
population 129  ·  (a) 67  ·  (b) 41       <- ma mesure independante
                                              accord exact avec l'annonce

temoins du lexeur, les trois :
  apostrophe dans une regex   -> le launch SURVIT          ✔
  division qui n'est pas une regex -> le code survit       ✔
  launch dans une CHAINE seule -> hors population          ✔
```

*Règle du `/` : il ouvre une regex quand le dernier jeton significatif n'est pas
une valeur (identifiant, nombre, `)`, `]`), ou quand c'est un mot-clé — `return`,
`await`, `typeof`, `new`, `throw`, `case`, `of`, `in`…*

### 8.2 ⚠⚠ ET VOICI CE QUI COMPTE : `67 / 41` SONT NOS CHIFFRES DU DÉPART

```
avant tout depouillement   67  ·  41
apres depouillement (faux) 62/70 · 37
apres correction du lexeur 67  ·  41      <- identiques au depart
```

> ⛔ **Deux erreurs de signes opposés s'annulaient : la PROSE gonflait les
> comptes, la CHAÎNE FANTÔME les dégonflait.**

**Donc retomber sur un chiffre antérieur n'est PAS une preuve de justesse.** *Et
c'est cette coïncidence qui aurait fait clore le sujet si l'un de nous s'était
arrêté à la première correction — nous aurions eu le bon nombre pour deux mauvaises
raisons, sans le savoir.*

**La seule chose qui nous a fait continuer est que nos deux valeurs FAUSSES
divergeaient entre elles.** *Un désaccord entre deux mesures fausses est plus
informatif qu'un accord entre une mesure fausse et un souvenir.*

### 8.3 ⛔ LA RÈGLE, ET ELLE EST NEUVE

> **Un témoin qui vérifie ce qu'on CLASSE ne vérifie pas ce qu'on LIT.**

**Nos six et huit témoins forgés portaient tous sur `(a)` et `(b)` — le
classement. Aucun ne demandait « ce fichier est-il ENTIÈREMENT lu ? »** *Le
dépouillement était traité comme une plomberie, pas comme une mesure — et une
plomberie ne porte pas de témoin.*

**Le témoin manquant tient en une ligne** : *après dépouillement, un jeton connu
pour être présent en code nu doit subsister.* **Trois d'entre eux existent
maintenant, et les deux premiers sont exactement ceux qui manquaient à nos DEUX
instruments.**


---

## 9. ✅ LE DÉFAUT (b) ÉTAIT UN MIRAGE — `129 / 67 / 0`, et ma vérification a produit sa propre fausse alarme

**Confirmé indépendamment, avec le prédicat JUSTE :**

```
predicat JUSTE : un `exit` apres le lancement, AUCUNE fermeture AVANT lui
  -> cas reels : 0
```

**Les 41 « défauts » textuels fermaient le navigateur AVANT de sortir. C'est
l'idiome du répertoire, et le prédicat l'accusait.**

> **La position TEXTUELLE d'un `exit` n'est pas son ordre d'exécution — et une
> fermeture qui le PRÉCÈDE le rend inoffensif.** *Le critère retenait tout `exit`
> situé avant la DERNIÈRE fermeture du fichier, donc il comptait comme fautif le
> geste le plus banal du répertoire.*

### 9.1 ⚠ ET MA PROPRE VÉRIFICATION A ACCUSÉ TROIS FICHIERS SAINS

**J'ai vérifié l'exculpation — c'est la classe que personne ne relit — et j'ai
trouvé 3 cas restants. Ils étaient faux.**

```
go-page-chatops       close:337  exit:341   ecart 4 lignes
go-page-graylog-g2    close:389  exit:392   ecart 3
go-page-maintenance   close:467  exit:471   ecart 4
```

**J'avais posé une fenêtre de « ≤ 2 lignes » — un nombre MAGIQUE, que je n'ai
dérivé de rien.** *Les trois fermaient bien avant leur `exit` ; il y avait une
ligne de message entre les deux.*

> ⛔ **Et mon erreur était du côté qui ALARME, comme les trois précédentes sur ce
> même compte.** *Quatre erreurs d'alarme sur un seul défaut, réparties sur deux
> sessions.*

### 9.2 La cause commune des QUATRE

**Chacune a substitué un SUBSTITUT à la propriété :**

    la propriete           « une fermeture est-elle ATTEINTE avant l'exit ? »
    substitut 1            la position textuelle de l'exit
    substitut 2            « avant la DERNIERE fermeture du fichier »
    substitut 3 (le mien)  l'ECART EN LIGNES entre les deux

> **Un substitut se trompe toujours dans un sens, et il est stable : il ne se
> signale pas.** *Les trois substituts se trompaient du côté de l'accusation —
> parce qu'un substitut de proximité échoue quand le code est aéré, et le code
> aéré est le code soigné.*

**Le témoin qui manquait est celui-là, et il coûte une ligne** : *un fichier qui
ferme puis sort sur deux lignes consécutives ne doit PAS être un défaut.*

### 9.3 Le compte final, et ce qu'il vaut

    REFERENCE   110/62/37 -> 125/70/37 -> 129/67/41 -> 129/67/0

**`(a) = 67` est le seul défaut réel. Et mon 67 du premier message était juste par
ACCIDENT — deux erreurs de signes opposés — alors qu'il l'est maintenant par
mesure.** *La différence ne se voit pas dans le chiffre ; elle se voit dans ce
qu'on peut en faire.*

⚠ **Et une classe de défaut d'outil, à garder** : *un module d'invariant
s'exécutait À L'IMPORT et posait `process.exitCode`.* **Un module qui expose des
fonctions ET agit au chargement ne peut pas être importé — et il fait échouer le
programme APPELANT.** *Trouvé en réutilisant son lexeur depuis une autre sonde :
les deux sorties se sont mêlées.*
