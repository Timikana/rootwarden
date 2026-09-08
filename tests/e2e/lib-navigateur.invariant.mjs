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
import { fileURLToPath } from 'node:url';

/* Etat mesure le 2026-09-08 par cet instrument. A DESCENDRE en meme temps que
 * les adoptions, jamais a monter. */
export const REFERENCE = { population: 110, defautA: 62, defautB: 37 };

/* Les fichiers de l'enveloppeur lui-meme : ils citent `puppeteer.launch` et
 * pollueraient la population qu'ils mesurent. */
const EXCLUS = new Set([
    'lib-navigateur.mjs',
    'lib-navigateur.epreuve.mjs',
    'lib-navigateur.invariant.mjs',
]);

/**
 * Remplace commentaires et litteraux par des espaces, en PRESERVANT les
 * offsets — les classements ne dependent que de positions relatives.
 */
export function depouille(src) {
    let out = '';
    let i = 0;
    const n = src.length;
    while (i < n) {
        const c = src[i];
        if (c === '/' && src[i + 1] === '*') {
            const j = src.indexOf('*/', i + 2);
            const fin = j >= 0 ? j + 2 : n;
            out += ' '.repeat(fin - i); i = fin; continue;
        }
        if (c === '/' && src[i + 1] === '/') {
            const j = src.indexOf('\n', i);
            const fin = j >= 0 ? j : n;
            out += ' '.repeat(fin - i); i = fin; continue;
        }
        if (c === '"' || c === "'" || c === '`') {
            const q = c; const deb = i; i += 1;
            while (i < n) {
                if (src[i] === '\\') { i += 2; continue; }
                if (src[i] === q) { i += 1; break; }
                i += 1;
            }
            out += ' '.repeat(i - deb); continue;
        }
        out += c; i += 1;
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
    const lan = d.indexOf('puppeteer.launch');
    if (lan < 0) return null;
    const spans = corpsFinally(d);
    const nav = [...d.matchAll(/\b(navigateur|browser|nav|b)\s*\.\s*close\s*\(/g)].map((m) => m.index);
    const exits = [...d.matchAll(/process\.exit\s*\(/g)].map((m) => m.index);
    const gouvernees = nav.filter((p) => spans.some(([a, z]) => a < p && p < z));
    const dernier = nav.length ? Math.max(...nav) : null;
    const interposes = dernier === null ? []
        : exits.filter((e) => e > lan && e < dernier);
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
        'try { const b = await puppeteer.launch({}); } finally { await b.close(); }\nprocess.exit(0);',
        { defautA: false, defautB: false }],
    ['MAUVAIS — le finally n\'existe QUE dans un commentaire',
        '/* finally { await b.close(); } — et ce commentaire MENT */\n'
        + 'const b = await puppeteer.launch({});\nawait b.close();',
        { defautA: true, defautB: false }],
    ['MAUVAIS — un exit interpose',
        'try { const b = await puppeteer.launch({}); process.exit(1); }'
        + ' finally { await b.close(); }',
        { defautA: false, defautB: true }],
    ['HORS POPULATION — puppeteer.launch seulement en commentaire',
        '// const b = await puppeteer.launch({});\nconsole.log(1);',
        null],
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

let echecs = 0;
const note = (s) => process.stdout.write(`${s}\n`);
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

const racine = join(dirname(fileURLToPath(import.meta.url)));
const pop = [];
for (const f of fichiers(racine)) {
    const r = classe(readFileSync(f, 'utf8'));
    if (r) pop.push([basename(f), r]);
}

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
process.exitCode = echecs === 0 ? 0 : 1;
