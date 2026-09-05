/*
 * ═══ L'ECART ENTRE CE QUI EXISTE ET CE QUI EST JOUE ═══════════════════════
 *
 * Le 2026-09-06 a 01 h, la session 94 a trouve `go-ssh-audit-schedules.mjs` en
 * lisant le fichier pour autre chose. Elle armait une planification de scan SSH
 * sur TOUT LE PARC, puis une seconde sur `machines.slice(0, 2)` — c'est-a-dire
 * `srv-zabbix`, 192.168.0.244, la PRODUCTION.
 *
 * **Aucun lot ne pouvait la reveler : elle n'est dans aucune liste du runner.**
 *
 *     ce que le runner exerce   = la definition de FAIT de « ce qui est teste »
 *     ce qui existe dans tests/ = autre chose, et personne ne mesurait l'ecart
 *
 * Le releve du soir : 116 suites presentes, 88 connues du runner, **28 hors
 * liste**, dont DIX portant des gestes non-GET et ZERO filet d'avortement.
 * Quatre etaient armees (`go-security`, `go-ssh-audit-schedules`,
 * `go-cve-schedules`, `go-wazuh`) ; six restent a instruire.
 *
 * ══ POURQUOI CET OUTIL EXISTE PLUTOT QU'UNE CONSIGNE ══════════════════════
 *
 * La session 6 a nomme la difference entre nos deux bancs, et elle est
 * structurelle :
 *
 *     son `phpunit.xml` enrole par RACINE   <directory>tests/Feature</directory>
 *     `rejouer-lot.sh` enrole par LISTE     SUITES_LARAVEL=( ... )
 *
 * **Une liste doit etre maintenue ; une racine se maintient toute seule.** Les
 * 28 hors liste ne sont pas une negligence : c'est le mode de defaillance de
 * l'enumeration. On ne le corrige pas en demandant plus d'attention.
 *
 * Le remede propre serait d'enroler par racine. `scripts/rejouer-lot.sh` n'est
 * pas mon perimetre, et changer la population d'un LOT est un arbitrage qui
 * deplace une ligne de base. **Alors a defaut de supprimer l'ecart, cet outil le
 * MESURE et le rend bruyant** — et il ne rend pas un constat : il rend un CODE
 * DE SORTIE, parce qu'un controle qui ne commande rien finit par ne plus etre lu.
 *
 * ══ CE QU'IL NE FAIT PAS ══════════════════════════════════════════════════
 *
 * Il ne dit pas si une suite hors liste est DANGEREUSE — il dit qu'elle porte
 * des gestes non-GET sans filet, ce qui est un motif de RELECTURE, pas un
 * verdict. Une suite peut ecrire legitimement dans une fixture qu'elle nettoie.
 *
 * Il ne voit pas non plus une classe enrolee qui n'exerce rien : le meme angle
 * mort que la session 6 nomme chez elle — la racine garantit qu'on CHARGE, pas
 * qu'on MESURE.
 *
 *   usage :  node tests/e2e/inventaire-hors-lot.mjs
 *   sortie :  0 = aucune suite hors liste ne porte de geste arme
 *             1 = au moins une en porte  ->  a instruire
 *             2 = l'instrument n'a pas pu mesurer  ->  NE RIEN CONCLURE
 */
import { readFileSync, readdirSync } from 'node:fs';

const RACINE = new URL('../../', import.meta.url).pathname;
const RUNNER = RACINE + 'scripts/rejouer-lot.sh';
const E2E = RACINE + 'tests/e2e/';

/*
 * ⚠ LIRE LA LISTE PAR JETON, JAMAIS PAR DEBUT DE LIGNE.
 *
 * Mesure du 2026-09-06 : trois motifs sur la meme source ont rendu TROIS
 * nombres. `grep -oE '^go-[a-z0-9-]+'` rendait 0 (les noms ne sont pas en tete
 * de ligne), le decoupage par espaces rendait 80, et le runner a joue 82.
 * **L'autorite est ce qu'un outil EXECUTE, pas ce qu'on lit de sa source** —
 * mais faute de pouvoir l'executer ici, on prend la lecture la plus large et on
 * DIT que c'en est une.
 */
function listesDuRunner() {
    let texte;
    try {
        texte = readFileSync(RUNNER, 'utf8');
    } catch (e) {
        return null;
    }
    const noms = new Set();
    for (const nom of ['SUITES_LARAVEL', 'SUITES_LEGACY']) {
        const m = texte.match(new RegExp(`^${nom}=\\(([\\s\\S]*?)\\)`, 'm'));
        if (!m) return null;
        for (const jeton of m[1].split(/\s+/)) {
            if (/^go-[a-z0-9.-]+$/.test(jeton)) noms.add(jeton);
        }
    }

    return noms;
}

/** Le code, sans les commentaires : ma propre prose cite les motifs qu'elle decrit. */
function codeSeul(source) {
    return source
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/^\s*\/\/.*$/gm, '')
        .replace(/^\s*\*.*$/gm, '');
}

function inspecte(fichier) {
    const brut = readFileSync(E2E + fichier, 'utf8');
    const code = codeSeul(brut);

    return {
        nonGet: (code.match(/method: *'(POST|PUT|DELETE|PATCH)'/g) || []).length,
        filet: /setRequestInterception/.test(code),
        production: (code.match(/machine_id: *1[^0-9]|192\.168\.0\.244/g) || []).length,
        portee: /target_type: *'all'/.test(code),
        gestes: [...new Set((code.match(/deploy|scan-all|scan_all|rotate|revoke|purge|schedules/g) || []))],
    };
}

const enrolees = listesDuRunner();
if (enrolees === null || enrolees.size === 0) {
    console.log('INSTRUMENT INDISPONIBLE — les listes du runner sont illisibles.');
    console.log('NE RIEN CONCLURE : une liste vide et une liste illisible se ressemblent.');
    process.exit(2);
}

const presentes = readdirSync(E2E).filter((f) => /^go-.*\.mjs$/.test(f))
    .map((f) => f.replace(/\.mjs$/, '')).sort();
const horsListe = presentes.filter((s) => !enrolees.has(s));

console.log(`suites presentes dans tests/e2e/ : ${presentes.length}`);
console.log(`enrolees par le runner           : ${enrolees.size}`);
console.log(`HORS LISTE                       : ${horsListe.length}`);

/*
 * TEMOIN — sans lui, « 0 suite armee » et « l'instrument ne voit rien » sont la
 * MEME sortie. On verifie que l'inspection rend le POSITIF sur une suite dont
 * on sait qu'elle porte des non-GET.
 */
const temoinNom = presentes.find((s) => inspecte(`${s}.mjs`).nonGet > 0);
if (!temoinNom) {
    console.log('\nTEMOIN MUET — aucune suite du depot ne porte de non-GET detectable.');
    console.log('C\'est invraisemblable : l\'inspection ne mesure probablement rien.');
    process.exit(2);
}
console.log(`temoin : ${temoinNom} porte des non-GET, l'inspection rend le positif`);

const armees = [];
console.log('');
for (const s of horsListe) {
    const i = inspecte(`${s}.mjs`);
    if (i.nonGet === 0) continue;
    armees.push(s);
    const alertes = [];
    if (!i.filet) alertes.push('AUCUN FILET');
    if (i.production) alertes.push('⚠ VISE LA PRODUCTION');
    if (i.portee) alertes.push('⚠ PORTEE `all`');
    console.log(`  ${s.padEnd(32)} ${String(i.nonGet).padStart(2)} non-GET  `
        + `${i.gestes.join(' ').padEnd(22)} ${alertes.join(' · ')}`);
}

console.log('');
if (armees.length === 0) {
    console.log('AUCUNE suite hors liste ne porte de geste non-GET.');
    process.exit(0);
}
console.log(`${armees.length} suite(s) hors liste portent un geste non-GET.`);
console.log('Ce n\'est pas un verdict de danger : c\'est un motif de RELECTURE.');
console.log('Une suite hors liste ne rougit jamais, et garde ses effets de bord.');
process.exit(1);
