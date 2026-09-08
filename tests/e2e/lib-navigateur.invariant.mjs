/**
 * Cliquet sur la propriete du navigateur — statique, sans banc, sans reseau.
 *
 * DEUX DEFAUTS SONT MESURES, tous deux sur la source DEPOUILLEE :
 *   (a) une suite lance un navigateur et sa fermeture n'est gouvernee par
 *       AUCUN bloc `finally`
 *   (b) un `process.exit()` est interpose entre le lancement et la derniere
 *       fermeture — il termine immediatement et n'execute aucun `finally`
 *
 * ⛔ POURQUOI LE DEPOUILLEMENT N'EST PAS UN DETAIL. Les deux premiers releves
 * de ces comptes ont donne 67 et 41. Aucun ne retirait les commentaires, et
 * dans ces suites **79 des 167 occurrences de `finally` vivent dans de la
 * prose** (47 %), ainsi que 41 des 182 `process.exit`. La population elle-meme
 * etait fausse : 114 fichiers annonces, 110 reels — quatre ne portaient
 * `puppeteer.launch` qu'en commentaire.
 *
 * *Un motif trouve dans un commentaire compte comme du code jusqu'a ce qu'on
 * depouille, et la prose de ce depot parle abondamment de ses propres defauts.
 * C'est la forme la plus discrete de mesure fausse : elle est stable,
 * reproductible, et fausse de la meme quantite a chaque execution.*
 *
 * CE FICHIER EST UN CLIQUET, PAS UNE PORTE. Les comptes de reference ci-dessous
 * sont l'etat MESURE au 2026-09-08. Le controle echoue si un compte CROIT — une
 * suite neuve qui rouvre le defaut — et il signale sans echouer quand un compte
 * baisse, en demandant de descendre la reference. *Une porte qui refuse a 62
 * serait rouge en permanence et on l'eteindrait ; un cliquet mord des la
 * premiere regression.*
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, basename, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

/* Etat mesure le 2026-09-08 par cet instrument. A DESCENDRE en meme temps que
 * les adoptions, jamais a monter. */
export const REFERENCE = { population: 129, defautA: 67, defautB: 0 };

/*
 * ⛔ CETTE REFERENCE A ETE FAUSSE TROIS FOIS.
 *
 *   110 / 62 / 37   population trop etroite (launchBrowser ignore) ET prose
 *                   comptee comme du code
 *   125 / 70 / 37   population elargie, mais une chaine fantome avalait encore
 *                   quatre suites
 *   129 / 67 / 41   lexeur correct — et (b) etait a 97 % de FAUX POSITIFS
 *   129 / 67 /  0   predicat (b) affute : 40 des 41 fermaient sur la ligne
 *                   PRECEDANT leur `exit`, et la 41e a ete corrigee
 *
 * ⛔ ET LA PREMIERE ERREUR ETAIT DANS LE SENS QUI DEDOUANE.
 * Premiere version : { population: 110, defautA: 62, defautB: 37 } — calibree
 * sur un predicat qui ne retenait que `puppeteer.launch` et manquait donc les
 * 15 suites qui lancent par `launchBrowser()`. **Une regression chez elles
 * aurait ete invisible : le cliquet n'aurait rien dit.** Un cliquet dont la
 * POPULATION est trop etroite ne se signale pas d'elle-meme, et son vert
 * rassure plus qu'une absence de cliquet. Releve par `gestion-ssh-key-c6`.
 */

/* Les fichiers de l'enveloppeur lui-meme : ils citent `puppeteer.launch` et
 * pollueraient la population qu'ils mesurent. */
const EXCLUS = new Set([
    'lib-navigateur.mjs',
    'lib-navigateur.epreuve.mjs',
    'lib-navigateur.invariant.mjs',
]);

/*
 * Apres ces mots-cles, un `/` ouvre une REGEX et non une division, meme si le
 * caractere precedent est alphanumerique.
 */
const MOTS_CLES = new Set(['return', 'typeof', 'instanceof', 'in', 'of', 'new',
    'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await']);

/**
 * Remplace commentaires et litteraux par des espaces, en PRESERVANT les
 * offsets — les classements ne dependent que de positions relatives.
 */
export function depouille(src) {
    let out = '';
    let i = 0;
    const n = src.length;
    /*
     * Le dernier jeton significatif decide si un `/` ouvre une EXPRESSION
     * REGULIERE ou une division. Sans cette distinction, une apostrophe a
     * l'interieur d'une regex ouvre une chaine FANTOME.
     */
    let dernier = '';       // dernier caractere significatif emis
    let motCourant = '';    // identifiant en cours d'emission
    let dernierMot = '';    // dernier identifiant complet emis
    const emet = (c) => {
        out += c;
        if (/\s/.test(c)) return;
        dernier = c;
        if (/[A-Za-z0-9_$]/.test(c)) { motCourant += c; dernierMot = motCourant; }
        else { motCourant = ''; dernierMot = ''; }
    };
    while (i < n) {
        const c = src[i];
        if (c === '/' && src[i + 1] === '*') {
            const j = src.indexOf('*/', i + 2);
            const fin = j >= 0 ? j + 2 : n;
            out += ' '.repeat(fin - i); i = fin; motCourant = ''; continue;
        }
        if (c === '/' && src[i + 1] === '/') {
            const j = src.indexOf('\n', i);
            const fin = j >= 0 ? j : n;
            out += ' '.repeat(fin - i); i = fin; motCourant = ''; continue;
        }
        if (c === '/') {
            const apresValeur = /[A-Za-z0-9_$)\]]/.test(dernier) && !MOTS_CLES.has(dernierMot);
            if (!apresValeur) {
                const deb = i; let k = i + 1; let classe = false; let ferme = false;
                while (k < n) {
                    const ch = src[k];
                    if (ch === '\\') { k += 2; continue; }
                    if (ch === '\n') break;            // une regex ne traverse pas la ligne
                    if (ch === '[') classe = true;
                    else if (ch === ']') classe = false;
                    else if (ch === '/' && !classe) { k += 1; ferme = true; break; }
                    k += 1;
                }
                if (ferme) {
                    while (k < n && /[a-z]/.test(src[k])) k += 1;   // drapeaux
                    out += ' '.repeat(k - deb); i = k;
                    dernier = '/'; motCourant = ''; dernierMot = ''; continue;
                }
            }
            emet('/'); i += 1; continue;                 // division
        }
        if (c === '"' || c === "'" || c === '`') {
            const q = c; const deb = i; i += 1;
            while (i < n) {
                if (src[i] === '\\') { i += 2; continue; }
                if (src[i] === q) { i += 1; break; }
                i += 1;
            }
            out += ' '.repeat(i - deb);
            dernier = '"'; motCourant = ''; dernierMot = ''; continue;
        }
        emet(c); i += 1;
    }
    return out;
}

/** Intervalles des CORPS de blocs `finally`, par appariement d'accolades. */
export function corpsFinally(d) {
    const spans = [];
    for (const m of d.matchAll(/\bfinally\b/g)) {
        const debutMot = m.index + m[0].length;
        const j = d.indexOf('{', debutMot);
        // Un `finally` suivi de plus de 12 caracteres avant son `{` n'est pas
        // une clause : on ne devine pas.
        if (j < 0 || j - debutMot > 12) continue;
        let prof = 0;
        for (let k = j; k < d.length; k += 1) {
            if (d[k] === '{') prof += 1;
            else if (d[k] === '}') {
                prof -= 1;
                if (prof === 0) { spans.push([j, k]); break; }
            }
        }
    }
    return spans;
}

/** Classe une source. Rend `null` si elle ne lance pas de navigateur. */
export function classe(src) {
    const d = depouille(src);
    /*
     * ⛔ LA POPULATION INCLUT LA FABRIQUE, et l'avoir oubliee a calibre une
     * premiere version de ce cliquet sur 15 suites INVISIBLES. Une suite qui
     * lance par `launchBrowser()` detient un navigateur exactement comme celle
     * qui appelle `puppeteer.launch` : une regression chez elle ne devait pas
     * passer sous le radar. Releve par `gestion-ssh-key-c6`.
     */
    const parDirect = d.indexOf('puppeteer.launch');
    const parFabrique = d.search(/launchBrowser\s*\(/);
    const lan = parDirect >= 0 ? parDirect : parFabrique;
    if (lan < 0) return null;
    const spans = corpsFinally(d);
    /*
     * ⚠ CE MOTIF EST DERIVE, PAS DEVINE. Recensement des receveurs de
     * `.close(` sur la source depouillee de tout `tests/e2e/` :
     *
     *   ctx 151 · navigateur 121 · browser 30 · c 28 · page 11
     *   ctxEn 4 · context 1
     *
     * `ctx`, `c`, `ctxEn`, `context` sont des CONTEXTES de navigateur et
     * `page` une page : les compter comme une fermeture de navigateur
     * EXONERERAIT une suite qui ferme ses contextes dans un `finally` et
     * n'a jamais ferme le navigateur. Seuls `navigateur` et `browser` en
     * designent un. *Une version anterieure listait aussi `nav` et `b` : ils
     * n'apparaissent NULLE PART dans le recensement — inoffensifs, mais
     * inventes.*
     */
    const nav = [...d.matchAll(/\b(navigateur|browser)\s*\.\s*close\s*\(/g)].map((m) => m.index);
    const exits = [...d.matchAll(/process\.exit\s*\(/g)].map((m) => m.index);
    const gouvernees = nav.filter((p) => spans.some(([a, z]) => a < p && p < z));
    const dernier = nav.length ? Math.max(...nav) : null;
    /*
     * ⛔ CE PREDICAT ETAIT A 97 % DE FAUX POSITIFS, ET PUBLIE TROIS FOIS.
     * Sa premiere forme retenait tout `process.exit()` situe entre le
     * lancement et la DERNIERE fermeture — un critere purement TEXTUEL. Or
     * l'idiome du repertoire est `await navigateur.close(); process.exit(...)`
     * sur deux lignes consecutives : mesure, 40 des 41 suites signalees
     * fermaient sur la ligne PRECEDANT immediatement leur `exit`.
     *
     * *La position textuelle n'est pas l'ordre d'execution, et une fermeture
     * qui PRECEDE l'exit rend l'exit inoffensif.* Le predicat juste exige donc
     * qu'AUCUNE fermeture de navigateur ne precede l'exit — c'est-a-dire que
     * le navigateur soit encore ouvert quand le processus se termine.
     */
    const interposes = dernier === null ? []
        : exits.filter((e) => e > lan && e < dernier
            && !nav.some((c) => c > lan && c < e));
    return {
        fermetures: nav.length,
        blocsFinally: spans.length,
        gouvernees: gouvernees.length,
        exits: exits.length,
        interposes: interposes.length,
        defautA: nav.length === 0 || gouvernees.length === 0,
        defautB: interposes.length > 0,
    };
}

// ── temoins forges : l'instrument doit les classer, sinon il ne mesure rien ──
const TEMOINS = [
    ['BON — fermeture dans un finally',
        'try { const navigateur = await puppeteer.launch({}); }'
        + ' finally { await navigateur.close(); }\nprocess.exit(0);',
        { defautA: false, defautB: false }],
    ['MAUVAIS — le finally n\'existe QUE dans un commentaire',
        '/* finally { await navigateur.close(); } — et ce commentaire MENT */\n'
        + 'const navigateur = await puppeteer.launch({});\nawait navigateur.close();',
        { defautA: true, defautB: false }],
    ['MAUVAIS — un exit interpose',
        'try { const navigateur = await puppeteer.launch({}); process.exit(1); }'
        + ' finally { await navigateur.close(); }',
        { defautA: false, defautB: true }],
    ['HORS POPULATION — puppeteer.launch seulement en commentaire',
        '// const navigateur = await puppeteer.launch({});\nconsole.log(1);',
        null],
    ['DANS LA POPULATION par la FABRIQUE — launchBrowser() sans fermeture',
        'const navigateur = await launchBrowser();\nawait navigateur.newPage();',
        { defautA: true, defautB: false }],
    ['UNE APOSTROPHE DANS UNE REGEX N\'OUVRE PAS UNE CHAINE',
        'const m = s.replace(/\\\\\'/g, "\'");\n'
        + 'const navigateur = await puppeteer.launch({});\nawait navigateur.close();',
        { defautA: true, defautB: false }],
    ['UNE DIVISION N\'EST PAS UNE REGEX',
        'const r = a / b; const q = c / d;\n'
        + 'const navigateur = await puppeteer.launch({});\nawait navigateur.close();',
        { defautA: true, defautB: false }],
    ['UN CONTEXTE FERME NE VAUT PAS UN NAVIGATEUR FERME',
        'const navigateur = await puppeteer.launch({});\n'
        + 'try { const ctx = await navigateur.createBrowserContext(); }'
        + ' finally { await ctx.close(); }',
        { defautA: true, defautB: false }],
];

function fichiers(racine) {
    const trouves = [];
    for (const e of readdirSync(racine)) {
        const p = join(racine, e);
        if (statSync(p).isDirectory()) { trouves.push(...fichiers(p)); continue; }
        if (e.endsWith('.mjs') && !EXCLUS.has(e)) trouves.push(p);
    }
    return trouves;
}

/*
 * ⚠ CE MODULE S'EXECUTAIT A L'IMPORT. Ses fonctions (`depouille`, `classe`,
 * `recense`) sont exportees pour etre reutilisables — mais tout le controle
 * vivait au niveau superieur, donc `import { depouille } from ...` lancait le
 * cliquet entier. Constate en voulant reutiliser le lexeur depuis une autre
 * sonde : la sortie du cliquet s'est melee a la mienne.
 *
 * **Un module qui expose des fonctions ET agit au chargement ne peut pas etre
 * importe.** La partie executable est desormais gardee par une comparaison
 * entre `import.meta.url` et le fichier reellement lance.
 */
const LANCE_DIRECTEMENT = process.argv[1]
    && import.meta.url === pathToFileURL(process.argv[1]).href;

let echecs = 0;
const note = (s) => { if (LANCE_DIRECTEMENT) process.stdout.write(`${s}\n`); };
function verifie(quoi, ok, detail) {
    if (ok) { note(`PASS  ${quoi}`); return; }
    echecs += 1;
    note(`FAIL  ${quoi}${detail ? `\n        ${detail}` : ''}`);
}

note('══ cliquet withNavigateur — statique, source depouillee ══\n');

for (const [nom, src, attendu] of TEMOINS) {
    const r = classe(src);
    if (attendu === null) {
        verifie(`TEMOIN ${nom}`, r === null, `classe() a rendu ${JSON.stringify(r)} au lieu de null`);
        continue;
    }
    const ok = r !== null && r.defautA === attendu.defautA && r.defautB === attendu.defautB;
    verifie(`TEMOIN ${nom}`, ok,
        `obtenu ${JSON.stringify(r && { defautA: r.defautA, defautB: r.defautB })}, attendu ${JSON.stringify(attendu)}`);
}
note('');

/*
 * ⚠ UN MOTIF DERIVE DE LA SOURCE D'AUJOURD'HUI NE COUVRE PAS LE CODE DE DEMAIN.
 * Une suite neuve pourrait nommer son navigateur autrement et passer sous le
 * radar sans que rien ne le signale. On RECENSE donc les receveurs a chaque
 * execution et on REFUSE tout nom inconnu : la classification devient une
 * decision explicite au lieu d'un oubli silencieux.
 */
export const RECEVEURS_CONNUS = {
    navigateur: 'navigateur',
    browser: 'navigateur',
    ctx: 'contexte',
    c: 'contexte',
    ctxEn: 'contexte',
    context: 'contexte',
    page: 'page',
};

export function recense(sources) {
    const compte = new Map();
    for (const src of sources) {
        const d = depouille(src);
        for (const m of d.matchAll(/([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*close\s*\(/g)) {
            compte.set(m[1], (compte.get(m[1]) || 0) + 1);
        }
    }
    return compte;
}

const racine = join(dirname(fileURLToPath(import.meta.url)));
const pop = [];
for (const f of fichiers(racine)) {
    const r = classe(readFileSync(f, 'utf8'));
    if (r) pop.push([basename(f), r]);
}

/*
 * ⚠ LE TEMOIN QUI MANQUAIT A DEUX INSTRUMENTS, et il coute trois lignes.
 *
 * Nos huit temoins portaient tous sur ce qu'on CLASSE — (a) et (b). Aucun ne
 * demandait « ce fichier est-il ENTIEREMENT lu ? ». Le depouillement etait
 * traite comme une plomberie, et une plomberie ne porte pas de temoin. Une
 * chaine fantome ouverte par l'apostrophe de `/\\'/g` a ainsi blanchi 3800
 * caracteres et fait tomber QUATRE suites hors population, sans qu'aucun vert
 * ne bouge.
 *
 * **Un temoin qui verifie ce qu'on CLASSE ne verifie pas ce qu'on LIT.**
 * (formulation de `gestion-ssh-key-c6`)
 *
 * Forme generale : tout fichier dont la source BRUTE porte le jeton de
 * lancement doit soit le conserver apres depouillement, soit figurer dans la
 * liste ci-dessous avec sa raison. Une entree NOUVELLE fait echouer le
 * controle — c'est le seul moyen qu'une perte de lecture se signale.
 */
const PERTE_LEGITIME = {
    'lib-navigateur.epreuve.mjs': 'le jeton vit dans la source d\'un processus fils (chaine), et le fichier est exclu',
    'lib-navigateur.invariant.mjs': 'le jeton vit dans les temoins forges (chaines), et le fichier est exclu',
};

{
    const perdus = [];
    for (const f of fichiers(racine)) {
        const brut = readFileSync(f, 'utf8');
        if (!brut.includes('puppeteer.launch')) continue;
        if (depouille(brut).includes('puppeteer.launch')) continue;
        perdus.push(basename(f));
    }
    const inattendus = perdus.filter((n2) => !(n2 in PERTE_LEGITIME));
    verifie('aucun fichier ne PERD son jeton de lancement au depouillement',
        inattendus.length === 0,
        `${inattendus.join(' ')} — la source brute porte « puppeteer.launch » et le `
        + 'depouillement le mange. Soit le lexeur casse (chaine fantome, regex mal '
        + 'lue), soit le jeton n\'est vraiment qu\'en commentaire/chaine : LIRE le '
        + 'fichier, puis corriger le lexeur ou inscrire la raison dans PERTE_LEGITIME.');
    if (perdus.length) {
        note(`      (pertes declarees : ${perdus.map((n2) => `${n2}`).join(', ')})`);
    }
}
note('');

// ── le recensement, AVANT les comptes : un nom inconnu invalide les comptes ──
const cens = recense(fichiers(racine).map((f) => readFileSync(f, 'utf8')));
const inconnus = [...cens.entries()].filter(([nom]) => !(nom in RECEVEURS_CONNUS));
note('  recensement des receveurs de .close( :');
note(`      ${[...cens.entries()].sort((x, y) => y[1] - x[1])
    .map(([n, v]) => `${n} ${v}`).join(' · ')}`);
verifie('aucun receveur de .close( inconnu',
    inconnus.length === 0,
    `${inconnus.map(([n, v]) => `${n} (${v} fois)`).join(', ')} — `
    + 'classer chaque nom dans RECEVEURS_CONNUS (navigateur / contexte / page) '
    + 'AVANT de lire les comptes : un navigateur nomme autrement est invisible.');
note('');

const a = pop.filter(([, r]) => r.defautA);
const b = pop.filter(([, r]) => r.defautB);
note(`  population : ${pop.length} suites lancant un navigateur`);
note(`    (a) fermeture non gouvernee par un finally   ${a.length}   (reference ${REFERENCE.defautA})`);
note(`    (b) process.exit() interpose                 ${b.length}   (reference ${REFERENCE.defautB})`);
note('');

verifie('la population n\'a pas grandi sans etre mesuree',
    pop.length <= REFERENCE.population,
    `${pop.length} suites contre ${REFERENCE.population} en reference — `
    + 'des suites neuves ont ete ajoutees : remesurer et descendre la reference.');

verifie('(a) ne CROIT pas',
    a.length <= REFERENCE.defautA,
    `${a.length} > ${REFERENCE.defautA}. Suites concernees :\n        `
    + a.map(([n]) => n).join(' '));

verifie('(b) ne CROIT pas',
    b.length <= REFERENCE.defautB,
    `${b.length} > ${REFERENCE.defautB}. Suites concernees :\n        `
    + b.map(([n]) => n).join(' '));

// Une baisse n'est pas un echec — mais elle doit etre consignee, sinon la
// reference derive et le cliquet cesse de mordre au bon cran.
if (a.length < REFERENCE.defautA || b.length < REFERENCE.defautB
    || pop.length !== REFERENCE.population) {
    note(`\n  ⚠ La reference est PERIMEE (dans le bon sens pour a/b). A poser :`);
    note(`      REFERENCE = { population: ${pop.length}, defautA: ${a.length}, defautB: ${b.length} }`);
}

note(`\n${echecs === 0 ? '=== TOUT OK ===' : `=== ${echecs} ECHEC(S) ===`}`);
/*
 * Le code de sortie n'est pose QUE si ce fichier est lance directement : un
 * import qui rendrait `exitCode = 1` ferait echouer le programme APPELANT sur
 * un controle qui ne le concerne pas. Le travail lui-meme tourne encore a
 * l'import — inutile, mais inoffensif, et je prefere une garde d'une ligne a
 * une restructuration de la portee des `const`.
 */
if (LANCE_DIRECTEMENT) process.exitCode = echecs === 0 ? 0 : 1;
