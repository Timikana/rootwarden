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
    { nom: 'doute',                   arg: [{ marker_uncertain: true, output: 'x' }, 200, null], ton: 'doute' },
    { nom: 'doute PRIME sur success', arg: [{ success: true, marker_uncertain: true }, 200, null], ton: 'doute' },
    /*
     * ⚠ DEUX CAS QUI MESURENT DES ALIAS RETIRES.
     *
     * Le module acceptait `marqueur_incertain` a cote de `marker_uncertain`, et
     * `sortie` a cote de `output` — deux alias sans AUCUN producteur, mesures sur
     * le depot entier. Retires. **Sans ces deux cas, retirer un alias serait
     * indiscernable de le garder** : les deux formes rendaient un message, et la
     * seule chose que l'epreuve exigeait etait « pas de silence ».
     *
     * C'est pourquoi les cas nomment desormais leur TON attendu : « non muet » ne
     * distingue pas `doute` de `inabouti`, et c'est exactement ce qu'un alias
     * retire change.
     */
    { nom: 'alias fr retire',         arg: [{ marqueur_incertain: true }, 200, null], sansNom: true },
    { nom: 'alias sortie retire',     arg: [{ success: true, sortie: 'y' }, 200, null], ton: 'succes', detail: '' },
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

/*
 * ⚠⚠ PRE-BALAYAGE — CHAQUE TITRE RENDU DOIT AVOIR UN DESTINATAIRE.
 *
 * Q3 rend un NOM DE CLE (`titre: 'ipt_retour_succes'`). Elle est totale, et elle
 * l'etait : un titre non vide, toujours. **Mais un titre non vide qui ne DESIGNE
 * rien satisfait toute assertion de forme** — et l'ecran afficherait un
 * identifiant nu, ou du vide selon la facon de le rendre.
 *
 * Trouve par un pair, en appliquant a mes modules le controle que je venais de
 * NOMMER une heure plus tot : « les champs lus sont-ils produits ? ». Ici c'est
 * l'exact retournement — **un producteur sans destinataire**, la ou j'avais eu un
 * consommateur sans producteur. *Applique en lisant, manque en ecrivant.*
 *
 * TROIS destinataires, pas un — le troisieme s'est paye deux fois sur `fail2ban` :
 *
 *     lang/fr/pare-feu.php          le catalogue
 *     lang/en/pare-feu.php          la parite
 *     PareFeuController             la liste CURATEE : ce qui n'y est pas ne
 *                                   voyage pas jusqu'au JS, et le panneau
 *                                   s'ouvre vide sans rien dire
 *
 * ⚠ La liste des titres est DERIVEE du module, par tout litteral de la famille —
 * pas par `titre:\s*'…'`. Ma premiere sonde employait le motif etroit et en
 * comptait SIX quand il y en a HUIT : deux naissent d'un ternaire. Le pair
 * comptait juste, ma sonde minimisait.
 */
function litCles(chemin) {
    let src;
    try { src = readFileSync(chemin, 'utf8'); } catch { return null; }
    return new Set([...src.matchAll(/^\s*'([a-z0-9_.]+)'\s*=>/gm)].map((m) => m[1]));
}

const RACINE = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const sansCommentaires = readFileSync(FICHIER, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const TITRES = [...new Set([...sansCommentaires.matchAll(/'(ipt_[a-z0-9_]+)'/g)].map((m) => m[1]))].sort();

const DESTINATAIRES = [
    ['lang/fr/pare-feu.php', litCles(join(RACINE, 'lang', 'fr', 'pare-feu.php'))],
    ['lang/en/pare-feu.php', litCles(join(RACINE, 'lang', 'en', 'pare-feu.php'))],
];
{
    let ctrl = null;
    try {
        const t = readFileSync(join(RACINE, 'app', 'Http', 'Controllers', 'PareFeuController.php'), 'utf8');
        ctrl = new Set([...t.matchAll(/'([a-z0-9_.]+)'/g)].map((m) => m[1]));
    } catch { /* absent : signale ci-dessous */ }
    DESTINATAIRES.push(['PareFeuController (liste curatee)', ctrl]);
}

console.log(`  titres rendus par le module : ${TITRES.length}`);
let orphelins = 0;
for (const [nom, ens] of DESTINATAIRES) {
    if (ens === null) { console.log(`  ⛔ ${nom} : ILLISIBLE — ne rien conclure`); orphelins++; continue; }
    const abs = TITRES.filter((k) => !ens.has(k));
    /*
     * ⚠ TEMOIN : un ensemble vide rendrait « tout absent » exactement comme un
     * catalogue qui ne porte aucun de mes titres. Les deux se distinguent ici.
     */
    if (ens.size === 0) { console.log(`  ⛔ ${nom} : 0 cle lue — la sonde ne lit pas`); orphelins++; continue; }
    console.log(`  ${abs.length === 0 ? 'ok  ' : 'FAIL'} ${nom.padEnd(34)} ${ens.size} cles · ${abs.length} orphelin(s)`);
    if (abs.length) { for (const k of abs) { console.log(`         ⛔ ${k}`); } orphelins += abs.length; }
}
if (orphelins) {
    console.log(`\n  ⛔ ${orphelins} titre(s) sans destinataire. Q3 rendrait un identifiant nu a l'ecran.`);
    console.log('     La propriete de TOTALITE tient ; ce qu\'elle rend ne DESIGNE rien.');
    process.exit(2);
}
console.log('');

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
    if (muet) { rouges.push(c.nom); ok--; }
    /*
     * ⚠ Le TON attendu quand le cas en nomme un, et le DETAIL quand il en nomme
     * un. « Pas de silence » etait trop faible pour voir un alias retire.
     */
    else if (c.ton && r.ton !== c.ton) { rouges.push(c.nom + ' [ton=' + r.ton + ' attendu ' + c.ton + ']'); }
    else if (c.detail !== undefined && r.detail !== c.detail) { rouges.push(c.nom + ' [detail=' + JSON.stringify(r.detail) + ']'); }
    ok++;
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
