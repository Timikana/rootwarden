/*
 * ÉPREUVE Q3 — AUCUNE ENTRÉE NE PRODUIT LE SILENCE
 *
 * Elle ne relit pas le module : elle le passe sur un espace d'entrées engendré,
 * et exige de CHACUNE un message. *Une propriété de totalité ne se vérifie pas
 * en lisant les branches — elle se vérifie en ne trouvant pas de trou.*
 *
 *     node laravel/tests/Outils/q3-retour-visible.mjs
 *     node laravel/tests/Outils/q3-retour-visible.mjs --mutation
 *
 * ⛔ Aucune requête, aucune machine jointe, aucun DOM.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const JS = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'public', 'js');
const FICHIER = join(JS, 'pare-feu-retour-visible.js');

function charge(mutation) {
    const bac = {};
    let src = readFileSync(FICHIER, 'utf8');
    if (mutation) {
        /*
         * MUTATION : le CAS SANS NOM redevient un repli silencieux — la forme
         * exacte trouvée dans le menu du legacy. Elle doit faire rougir tous les
         * cas qui l'atteignent, et EUX SEULS.
         */
        const avant = src;
        src = src.replace(
            "    return { ton: TONS.INABOUTI, titre: 'ipt_retour_contrat_inconnu', detail: '', sur: false };",
            '    return null;   // MUTATION : le repli silencieux');
        if (src === avant) {
            console.error("  ⛔ la mutation n'a rien remplace — l'ancre a bouge, l'epreuve ne prouve RIEN");
            process.exit(2);
        }
    }
    new Function('globalThis', src).call(bac, bac);
    if (typeof bac.rwRetourPareFeu !== 'function') {
        console.error('  ⛔ le module n\'expose pas rwRetourPareFeu'); process.exit(2);
    }
    return bac;
}

/*
 * ⚠ `sansNom: true` MARQUE LES CAS QUI ATTEIGNENT LE CAS SANS NOM.
 *
 * La prédiction de mutation est scellée sur leur IDENTITÉ, pas sur leur nombre :
 * elle est DÉRIVÉE de cette liste au lieu d'être recomptée à la main. *J'ai
 * donné quatre comptes faux cette nuit, tous parce que je ne dénombrais pas la
 * liste que je venais d'écrire — un nombre écrit deux fois est un nombre qui
 * peut divergier.*
 */
const CAS = [
    // ── l'appel n'a pas abouti ────────────────────────────────────────────
    { nom: 'rien du tout',            arg: [undefined, undefined, undefined] },
    { nom: 'exception reseau',        arg: [null, null, new Error('ECONNREFUSED')] },
    { nom: 'statut non numerique',    arg: [{ success: true }, 'oui', null] },
    { nom: 'statut hors plage',       arg: [{ success: true }, 42, null] },
    { nom: 'statut NaN',              arg: [{ success: true }, NaN, null] },
    // ── statut != 200 ─────────────────────────────────────────────────────
    { nom: '400 identifiants',        arg: [{ success: false }, 400, null] },
    { nom: '500 interne',             arg: [{ success: false }, 500, null] },
    { nom: '204 sans corps',          arg: [null, 204, null] },
    { nom: '302 redirection',         arg: [{}, 302, null] },
    // ── 200, corps inexploitable ──────────────────────────────────────────
    { nom: '200 corps null',          arg: [null, 200, null] },
    { nom: '200 corps chaine',        arg: ['<html>', 200, null] },
    { nom: '200 corps nombre',        arg: [7, 200, null] },
    // ── 200, doute sur le marqueur ────────────────────────────────────────
    { nom: 'doute (fr)',              arg: [{ marqueur_incertain: true, output: 'x' }, 200, null] },
    { nom: 'doute (en)',              arg: [{ marker_uncertain: true, sortie: 'y' }, 200, null] },
    { nom: 'doute PRIME sur success', arg: [{ success: true, marqueur_incertain: true }, 200, null] },
    // ── 200, verdict fonde ────────────────────────────────────────────────
    { nom: 'succes',                  arg: [{ success: true, output: 'ok' }, 200, null] },
    { nom: 'echec regles',            arg: [{ success: false, output: 'bad rule' }, 200, null] },
    { nom: 'succes sans sortie',      arg: [{ success: true }, 200, null] },
    // ── LE CAS SANS NOM ───────────────────────────────────────────────────
    { nom: 'success absent',          arg: [{ output: 'z' }, 200, null],          sansNom: true },
    { nom: 'success = 1 (verite JS)', arg: [{ success: 1 }, 200, null],           sansNom: true },
    { nom: 'success = "true"',        arg: [{ success: 'true' }, 200, null],      sansNom: true },
    { nom: 'success = null',          arg: [{ success: null }, 200, null],        sansNom: true },
    { nom: 'objet vide',              arg: [{}, 200, null],                       sansNom: true },
    { nom: 'tableau vide',            arg: [[], 200, null],                       sansNom: true },
];

const mutation = process.argv.includes('--mutation');
const { rwRetourPareFeu, rwRetourTons } = charge(mutation);
const TONS = rwRetourTons();

const rouges = [];
let ok = 0;
for (const c of CAS) {
    const r = rwRetourPareFeu(...c.arg);
    // Le SILENCE est le seul echec possible : un objet, un ton connu, un titre.
    const muet = !r || typeof r !== 'object'
        || typeof r.titre !== 'string' || r.titre.trim() === ''
        || !TONS.includes(r.ton) || typeof r.sur !== 'boolean';
    if (muet) { rouges.push(c.nom); } else { ok++; }
    if (!mutation) {
        console.log(`  ${muet ? 'FAIL' : 'ok  '} ${c.nom.padEnd(24)} ${muet ? 'SILENCE' : r.ton.padEnd(9) + ' sur=' + r.sur}`);
    }
}

/* ⚠ TEMOINS — sur le module NON MUTE, toujours. */
const propre = charge(false);
const t1 = propre.rwRetourPareFeu({ success: true, output: 'ok' }, 200, null);
const t2 = propre.rwRetourPareFeu({ success: false, output: 'bad' }, 200, null);
const t3 = propre.rwRetourPareFeu({ success: false, output: 'bad' }, 500, null);
let ko = 0;
if (t1.ton !== 'succes' || t1.detail !== 'ok') { ko++; }          // le detail suit le succes
if (t2.ton !== 'echec'  || t2.detail !== 'bad') { ko++; }          // et l'echec, chacun le SIEN
if (t3.detail !== '' || t3.sur !== false) { ko++; }                // un inabouti ne porte PAS de detail
if (ko) {
    console.log(`\n  ⛔ ${ko} temoin(s) en echec — l'epreuve ne mesure pas ce qu'elle annonce`);
    process.exit(2);
}

if (mutation) {
    /*
     * PRÉDICTION SCELLÉE, et DÉRIVÉE de la liste : exactement les cas marqués
     * `sansNom` rougissent, et aucun autre. C'est une identité, pas un compte —
     * « 6 rouges » serait vrai si six AUTRES cas cassaient.
     */
    const attendus = CAS.filter((c) => c.sansNom).map((c) => c.nom).sort();
    const obtenus = [...rouges].sort();
    const identique = attendus.length === obtenus.length && attendus.every((n, i) => n === obtenus[i]);
    console.log(`  MUTATION (le cas sans nom redevient un repli silencieux)`);
    console.log(`    attendus rouges : ${attendus.length} — ${attendus.join(' · ')}`);
    console.log(`    obtenus  rouges : ${obtenus.length} — ${obtenus.join(' · ') || '(aucun)'}`);
    if (identique && attendus.length > 0) {
        console.log('  ✅ l\'epreuve MORD, et exactement sur les cas prevus');
        process.exit(0);
    }
    console.log('  ⛔ la mutation ou ma comprehension est fausse');
    process.exit(1);
}

console.log(`\n  ${ok} ok · ${rouges.length} SILENCE(S)`);
if (rouges.length) { for (const n of rouges) { console.log(`      ⛔ ${n}`); } }
else { console.log('  → rejouer avec --mutation pour verifier que cette epreuve MORD'); }
process.exit(rouges.length === 0 ? 0 : 1);
