# Porter un sous-lot — la méthode

Écrit après sept sous-lots du module `update/` (U1 à U6b) et huit archivages. Ce n'est pas une
proposition : c'est ce qui a fonctionné, avec les défauts que chaque étape a réellement attrapés.

Les écarts mesurés vivent dans [PARITE.md](PARITE.md), la recette d'archivage dans
[DEPRECIATION.md](DEPRECIATION.md), les pièges du codebase dans le skill `rw-pieges`. Ce document
ne les répète pas — il dit **dans quel ordre travailler**.

---

## 1. Inventorier avant de toucher à quoi que ce soit

Deux agents en parallèle, sur des fichiers disjoints.

**Un agent `Explore` — l'inventaire du module.** Pour chaque route backend :

- les décorateurs exacts, dans l'ordre ;
- les clés JSON attendues, et les validations (regex de liste blanche, bornes) ;
- **la ou les commandes shell exactes**, recopiées littéralement ;
- passe-t-elle par une fenêtre de maintenance ? une approbation ?
- `jsonify` ou `Response(generate())` — **un flux ne se porte pas comme un JSON** ;
- écrit-elle en base ? journalise-t-elle **avant ou après** l'exécution SSH ?

Puis, côté frontend legacy :

- quelle fonction JS appelle chaque route, depuis quel bouton (`onclick` exact) ;
- **le corps envoyé correspond-il aux clés lues ?** Cas trouvé : le JS envoyait
  `{date, time, repeat}` à une route qui lisait `interval_minutes` — 400 systématique, depuis
  toujours (E-18) ;
- y a-t-il des `confirm()` natifs, et **dans quel catalogue vit leur clé** ? Cas trouvé : les deux
  confirmations du redémarrage affichaient l'identifiant technique (E-20) ;
- les fonctions lisent-elles des éléments du DOM **qui n'existent pas** ? Cas trouvé trois fois
  dans le seul module `update/` (E-18, E-21, E-22).

**Un agent `general-purpose` — la relecture du fichier porté**, qui grossit à chaque sous-lot :
déclarations en double, écouteurs non gardés, clés i18n absentes, code mort, erreurs avalées. Sur
`mises-a-jour.js` (1 047 lignes, sept sous-lots), il a sorti **quatre défauts qu'aucun test ne
montrait**, dont un panneau oublié dans une liste et trois masquages de portée.

> **Vérifier qu'une capacité est ATTEIGNABLE avant de la porter.** Chercher l'appelant de la
> fonction, croiser chaque `getElementById` avec la page. Porter une capacité que personne ne
> pouvait demander, ce n'est plus migrer, c'est concevoir — et cela mérite une décision.

## 2. Lire le backend, et écrire ce qu'on a lu

Ne jamais cliquer un bouton dont on n'a pas lu l'effet. Recopier la commande shell dans l'en-tête
du test : c'est ce qui a fait découvrir que « les constats sans effet » lançaient `apt-get update`,
qui **réécrit l'index local des paquets**. Le sous-lot a été renommé.

## 3. La caractérisation, verte sur le legacy d'abord

Un seul fichier vise les deux cibles :

```js
const BASE  = process.env.E2E_BASE || 'http://localhost:8444';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE  = CIBLE === 'laravel' ? '/mises-a-jour' : '/update/';
```

Trois fonctions d'assertion, jamais plus :

```js
function verifie(libelle, ok, detail) { ... }   // exigible des DEUX côtés
function constate(libelle, valeur)    { ... }   // une mesure, sans jugement
function verifiePortage(libelle, ok, detail) {  // exigible du portage seul
    if (CIBLE === 'laravel') return verifie(libelle, ok, detail);
    constate(libelle, `non exigible du legacy — ${detail}`);
}
```

Le **détail** d'une attente décrit ce qu'on a *mesuré*, jamais ce qu'on aurait dit en cas d'échec.

## 4. Le harnais Puppeteer

```js
const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});

async function connecte(nom, secret) {
    const ctx  = await navigateur.createBrowserContext();  // UN contexte par compte
    const page = await ctx.newPage();
    page.on('dialog', d => d.dismiss().catch(() => {}));   // sans quoi un dialogue BLOQUE
    // identifiant + mot de passe → second facteur → CGU éventuelles
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);  // fenêtre TOTP de 30 s
}
```

Remettre les compteurs à zéro **avant chaque connexion**, sinon le compte se verrouille.

Sur Linux, Chromium **refuse de tourner en root** sans `--no-sandbox` : lancer les suites sous un
compte ordinaire plutôt que de dégrader le bac à sable.

## 5. Les attentes — là où tout se paie

**Jamais de délai fixe.** La règle s'est payée quatre fois, sous une forme neuve à chaque fois.

```js
// FAUX — s'arrête dès que le journal cesse de changer. Or il ne bouge pas
// pendant que la commande travaille : on s'arrête AVANT la première ligne.
if (texte === precedent) break;

// JUSTE — viser LE CONTENU attendu.
async function attendLaSortie(motif, maxMs) {
    const limite = Date.now() + maxMs;
    let texte = await journalEntier(page);
    while (Date.now() < limite && !motif.test(texte)) {
        await dors(1000);
        texte = await journalEntier(page);
    }
    return texte;
}
```

Autres formes de la même règle : attendre que **le bouton redevienne actif**, que **la liste soit
relue**, que **la ligne cite le terme**. Et **repartir d'un état connu avant chaque mesure** — une
action qui re-rend le tableau *décoche la sélection*.

## 6. Mesurer la fonction, pas ses effets visibles

Un écran qui ne change pas ne prouve pas qu'aucun appel n'est parti :

```js
const appels = [];
page.on('request', r => {
    if (/pending_packages/.test(r.url())) appels.push({ url: r.url(), corps: r.postData() });
});
// ... clic ...
verifie("sans machine cochee, aucun appel n'est emis", appels.length === avant);
verifie('la machine 1, en production, n est jamais designee',
        !appels.some(a => /"machine_id"\s*:\s*1\b/.test(a.corps)));
```

**Prouver qu'une action destructive n'a PAS eu lieu** : chercher la trace que le backend n'écrit
qu'*après* l'exécution — pour `/reboot_server`, `command_log` de contexte `reboot` — et la compter
avant et après. La preuve vient du système, pas de l'écran.

**Vérifier qu'un secret n'apparaît pas** sans le manipuler : envoyer le texte encodé en base64 à un
script exécuté *dans* le conteneur du backend, qui déchiffre et ne répond que `ABSENT` ou
`PRESENT` — pour le mot entier **et** pour tout fragment de six caractères.

## 7. Le portage

Contrôleur, vue, JS, route avec `role:` et `perm:` **repris du legacy**, i18n FR+EN dans le **même**
commit. Extraire plutôt que recopier. Contrat DOM : `data-rw="<nom>"`, jamais « le premier bouton
submit ». Garder les identifiants d'élément du legacy pour qu'un seul test vise les deux cibles.

Une action destructive prend un **panneau de décision en ligne**, jamais un `confirm()` natif : il
nomme les machines, dit les conséquences, dit la réserve **avant** le geste, et son bouton naît
`disabled` jusqu'à la recopie d'un mot ou d'un nombre. Deux « OK » d'affilée sont un réflexe, pas
deux décisions.

Vérifier la parité des catalogues, pas seulement leur nombre :

```bash
docker exec rootwarden_laravel php -r '
  $fr = require "lang/fr/x.php"; $en = require "lang/en/x.php";
  $a = array_keys($fr); $b = array_keys($en); sort($a); sort($b);
  echo count($a), " ", count($b), " ", ($a === $b ? "oui" : "NON"), "\n";'
```

## 8. Les captures — les regarder, pas les prendre

```bash
node go-captures-socle.mjs rw-test-super
```

Trois largeurs : 1920, 1400, 390. Puis **ouvrir les PNG**. Une capture s'arrête au pli : amener la
section dans le champ avant de photographier, avec `block: 'center'` — `'start'` la glisse sous
l'en-tête collant.

Ce que **seules** les captures ont montré : deux panneaux de décision ouverts en même temps
(`[hidden]` perd contre `display: flex`, et le test lisait l'*attribut*), une colonne d'actions
entièrement hors du champ, des libellés de formulaire rendus en pastilles bleues (E-12), quatre
boutons rouges qui ne signalaient plus rien.

## 9. Vérifier en cliquant, rejouer, committer

Une vérification **en direct** sur la machine de test : un script jetable dans `tests/e2e/`, qui
clique, attend le résultat *réel*, imprime ce qu'il voit et photographie. Supprimé après usage.

Rejouer le **lot entier** — toucher au gabarit casse une suite antérieure. Pas plus de trois suites
par commande.

Puis dérouler `rw-pre-commit`, documenter dans `CHANGELOG.md` et `docs/migration/`, et committer.
Un chantier, un commit.

---

## Ce qui ne tient pas dans une liste

**Ne jamais asserter sur un mot qu'on vient soi-même de changer.**

**Quand une assertion passe, se demander ce qu'elle mesure vraiment.** Trois cas payés :

- `[].every()` rend `true` — « tous les éléments vérifient X » est vert sur un tableau **vide** ;
- un `href` qui *cite* la bonne route ne prouve pas que le lien **mène** quelque part : les huit
  entrées de menu redirigées pointaient vers un port en clair par une URL `https://`, et huit
  suites vertes déclaraient le menu réparé ;
- `mysqladmin ping` répond **avant** que le mot de passe root ne soit appliqué.

Les trois donnaient des tests verts qui ne mesuraient rien.
