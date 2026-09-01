# QA — E-270 : ce qui, du RENDU, se mesure sans devenir un test de pixels

> **Instruction, pas chiffrage.** Trois questions posées : quelles propriétés tiennent,
> sur quelles pages d'abord, et ce qu'une telle suite **ne couvrira pas**. La troisième
> est écrite aussi fort que les deux autres, et elle est en tête parce que c'est celle
> qu'on saute.

---

## 0. Le critère qui trie tout le reste

Le Lead a fourni ce matin, sans le chercher, le test de conception de cette suite. Sa
commande de remesure comptait des lignes de titre au lieu d'écarts, et :

> **L'erreur grandissait avec la qualité du registre.** Chaque fois qu'un écart était clos
> ou amendé proprement, il recevait un second titre et le compteur s'éloignait.
> *L'instrument punissait la bonne tenue.*

D'où la question à poser à **chaque** assertion de rendu avant de l'écrire :

> ### Que fait cette assertion quand la page S'AMÉLIORE ?

Une assertion qui rougit quand le travail est bien fait ne survit pas trois jours — elle
sera désactivée par quelqu'un qui a raison de le faire sur le moment. C'est la même mort
que le faux rouge et que le préflight trop large : **elle use le crédit du garde.**

Ce critère suffit à trancher la quasi-totalité des cas ci-dessous, et il explique pourquoi
la ligne de partage ne passe pas entre « visuel » et « fonctionnel » mais entre
**grandeur absolue** et **relation mesurée**.

---

## 1. Ce qui tient — quatre propriétés, toutes des RELATIONS

### 1.1 Le contraste CALCULÉ — la plus solide des quatre

    getComputedStyle(el).color  vs  la couleur de fond EFFECTIVE (remontée
    jusqu'au premier ancêtre non transparent)  ->  ratio WCAG  ->  seuil

**Pourquoi elle tient** : un ratio est indépendant de la mise en page. Changer le gabarit,
déplacer le bloc, ajouter une colonne ne le bougent pas. Elle rougit quand une **couleur**
change, ce qui est exactement l'événement à surveiller.

**Ce qu'elle a déjà attrapé** — et personne d'autre ne pouvait : la pastille KEV à
**1,06:1**. Le HTML était **parfaitement juste**. Aucune assertion DOM ne la voyait, et
c'est la **troisième** occurrence de classes Tailwind purgées.

**À l'amélioration** : le ratio monte, l'assertion reste verte. ✔

**La condition qui la rend juste** : ne jamais comparer à une valeur hexadécimale attendue
— ce serait une grandeur absolue. On asserte le **ratio**, jamais la couleur.

### 1.2 Le débordement horizontal — binaire, sans nombre magique

    document.body.scrollWidth > document.body.clientWidth        -> la page
    el.scrollWidth > el.clientWidth + 1                          -> l'élément

**Pourquoi elle tient** : elle compare un élément **à lui-même**. Aucune largeur attendue,
aucun point de rupture codé en dur, donc rien qui se périme quand le gabarit change.

**Ce qu'elle attrape**, et les deux cas sont mesurés sur ce chantier : « Version inconnue »
**tronqué au bord droit dans les deux largeurs**, et le sélecteur de langue qui **perd
`FR` en 390**.

**À l'amélioration** : un texte qui cesse de déborder passe au vert. ✔
**Le piège** : un libellé plus long — donc meilleur — peut nouvellement tronquer. Ce n'est
pas l'instrument qui punit le progrès, c'est un vrai défaut : *un libellé qu'on ne peut pas
lire en entier n'est pas un meilleur libellé.*

### 1.3 Qui reçoit ce clic — `elementFromPoint`

    r = el.getBoundingClientRect()
    recu = document.elementFromPoint(r.x + r.width/2, r.y + r.height/2)
    -> `recu` doit être `el` ou l'un de ses descendants

**Pourquoi elle tient** : elle ne mesure aucune coordonnée attendue, seulement l'identité
de ce qui occupe le point. Elle survit à tout déplacement.

**Ce qu'elle a déjà tranché** : E-241, en 40 secondes. La séquence faisait défiler la page
de 480 px, le bouton d'onglet remontait à `y = -7` sous l'en-tête collant, et
`elementFromPoint` a **nommé** `rw-entete` comme recevant le clic. Le clic par `evaluate`
réussissait au même instant que celui par coordonnées échouait.

⚠ **`null` n'est pas un échec de mesure : c'est une réponse.** Le point est hors fenêtre,
donc il faut défiler. Une sonde qui traite son `null` comme « je n'ai pas pu mesurer »
**jette exactement le cas qu'elle cherchait**.

### 1.4 Un conteneur censé porter du texte en porte

    el.getBoundingClientRect().height > 0   ET   son compte d'entrées > 0

**Pourquoi elle tient** : deux seuils à zéro, aucune valeur attendue.

⚠ **Et surtout : jamais sur le TEXTE.** `innerText` sur un élément **non rendu** retombe
sur `textContent`. Une assertion « le conteneur est vide au repos » a rougi **sur une page
saine** parce qu'un conteneur `hidden` portait un texte d'attente invisible à l'écran :
**elle mesurait l'instrument, pas la page.** La propriété juste est *« il n'est pas affiché
et ne porte aucune entrée »* — visibilité **et** comptage.

---

## 2. Ce qu'il faut ABANDONNER, et pourquoi

| à abandonner | ce que ça fait quand la page s'améliore |
|---|---|
| une hauteur, une largeur, une position **en pixels** | **rouge** — c'est le cas `scroll-padding-top: 64px` posé sur un en-tête « ~44 px lus dans le CSS et non mesurés », dont la hauteur rendue vaut **65** |
| une couleur hexadécimale attendue | **rouge** au premier ajustement de palette, alors que le contraste peut s'être amélioré |
| une taille de police, un espacement, un rayon | **rouge** à chaque passe de design |
| une **comparaison d'images** (diff de captures) | **rouge partout**, et c'est la forme la plus coûteuse à maintenir du lot |
| un **compte d'éléments** (« la page porte 9 indicateurs ») | **rouge quand la page en gagne un** : l'instrument punit l'ajout de valeur |
| un point de rupture codé en dur | **rouge** au premier changement de grille |

**La règle générale, et elle suffit** :

> **N'asserte jamais une grandeur ; asserte une RELATION entre deux grandeurs mesurées au
> même instant.** `hauteur_rendue_de_l_en_tete <= marge_de_defilement_effective` est juste
> et le restera ; `marge == 64` était faux d'un pixel le jour où il a été écrit, et
> personne ne remesure un nombre qui a l'air juste.

---

## 3. Sur quelles pages, et dans quel ordre — trois critères, pas un goût

### Priorité 1 — LE SOCLE, avant toute page

`layouts/portail.blade.php` et `public/css/rw.css` **touchent les 158 exécutions**. Une
mesure de rendu sur le socle — en-tête collant, débordement du `body`, contraste des
composants partagés (pastilles, annonces, boutons) — couvre plus que vingt-sept suites de
page, et à un coût sans commune mesure.

C'est aussi là que vit la relation en-tête / défilement, donc E-241 et son pixel.

### Priorité 2 — LES TROIS PAGES OÙ UN DÉFAUT DE RENDU EST DÉJÀ MESURÉ

Pas par affinité : parce qu'un défaut mesuré une fois est le seul endroit où l'on sait que
la classe existe.

| page | défaut mesuré | propriété qui l'attrape |
|---|---|---|
| CVE | pastille KEV à **1,06:1** | contraste calculé |
| `graylog` | onglet recouvert par l'en-tête après défilement | `elementFromPoint` |
| accueil | « Version inconnue » tronqué ; `FR` perdu en 390 | débordement d'élément |

### Priorité 3 — LES PAGES OÙ LA COULEUR PORTE L'INFORMATION

Partout où une **décision** se lit sur une pastille ou un badge — criticité CVE, statut
d'agent, verdict de conformité, sévérité — **le contraste n'est pas cosmétique : il EST
l'information**. Une pastille illisible ne dégrade pas l'esthétique, elle supprime la
donnée. C'est le seul critère de cette liste qui justifie de mesurer une page qui n'a
jamais rien montré d'anormal.

**Ce qui vient en dernier, et l'assumer** : les pages de formulaire sans code couleur et
sans tableau large. Le rendu y échoue moins, et il échoue de façon visible.

---

## 4. ⚠ CE QU'UNE TELLE SUITE NE COUVRIRA PAS

**À lire avant de se réjouir d'un vert.** Sept défauts ont été trouvés à l'œil ; les
propriétés du §1 en auraient attrapé **trois** — les deux troncatures et le contraste. Les
quatre autres, non. Une suite de rendu verte ne dit **pas** que la page est bonne.

1. **Elle ne voit pas ce qu'un humain voit.** Aucune assertion ne dit qu'une hiérarchie
   visuelle trompe, qu'un libellé est mauvais, qu'un alignement est laid, qu'un écran est
   illisible pour une raison qu'aucun seuil ne nomme. **Elle mesure des défauts d'une
   classe connue, pas la qualité.**

2. **Elle mesure UNE largeur à la fois.** Le `FR` perdu en 390 le prouve : la largeur fait
   partie de la mesure, pas du décor. Une suite jouée à une seule largeur est **muette** sur
   toutes les autres, et son vert ne s'y étend pas.

3. **Elle mesure L'INSTANT où elle mesure.** E-241 n'apparaissait **pas au chargement** :
   il apparaissait *après* un enregistrement refusé. Une sonde qui mesure la page à
   l'ouverture est structurellement aveugle à tout défaut produit par une **séquence** —
   et c'est le cas le plus fréquent des quatre défauts non couverts.

4. **Un vert ne dit pas « bâti correctement ».** L'artefact CSS peut être **à jour** et le
   rendu faux, si la classe n'a jamais été vue par le purge. La fraîcheur du bâti est un
   **indice**, jamais la mesure — seul le style calculé tranche.

5. **Elle ne distingue pas « rien à signaler » de « je n'ai pas pu regarder »** — sauf si
   chaque assertion porte sa **fenêtre d'observation**. Sans cela, une page qui ne charge
   pas rend un filet **entièrement vert** : mesuré ici même, deux PASS décernés à une suite
   dont aucun navigateur n'avait été ouvert. Forme obligatoire : `SANS OBJET`, ni PASS ni
   FAIL.

6. **Elle ne couvre pas ce qu'elle n'a pas visité.** Les défauts de rendu se logent dans
   les états rares — table vide, libellé le plus long, rôle le plus pauvre, message
   d'erreur. *« La suite ne descend pas assez bas » et « il n'y a pas de suite » ne se
   corrigent pas de la même façon* : la seconde s'avoue.

---

## 5. Ce que ce document ne tranche pas

Il ne dit pas **combien** cela coûte : c'est un chiffrage, et il n'a pas été demandé.

Il ne dit pas **qui l'écrit**. Le banc appartient à la session qui le tient, et une
propriété de rendu se pose là où vivent les sondes — pas dans les suites hermétiques, qui
n'ont ni navigateur ni style calculé et ne peuvent donc mesurer aucune de ces quatre
propriétés. **Ce document instruit ; il n'attribue pas.**
