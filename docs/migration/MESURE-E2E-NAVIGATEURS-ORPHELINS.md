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
