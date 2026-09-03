/**
 * absence.mjs - ETABLIR UNE ABSENCE, ce qui est plus difficile qu'une presence.
 *
 * Enumere PAR ARBRE SYNTAXIQUE toutes les chaines litterales des fichiers
 * JavaScript du portage, puis dit si un chemin donne y figure — en excluant les
 * commentaires, que `grep` compte, et en voyant les concatenations, que `grep`
 * manque.
 *
 * L'absence doit etre etablie sur DEUX couches : le JavaScript et le PHP qui lui
 * injecte des URL. `/cve_scan` en est la preuve — invisible en JS, injecte par
 * `ScanCveController`.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';
const acorn = createRequire(import.meta.url)('acorn');

const dossier = process.argv[2];
const cherches = process.argv.slice(3);

const litteraux = new Map();   // chaine -> [fichiers]
let concats = 0;

for (const nom of readdirSync(dossier).filter((f) => f.endsWith('.js'))) {
    const code = readFileSync(join(dossier, nom), 'utf8');
    let arbre;
    try { arbre = acorn.parse(code, { ecmaVersion: 2022, sourceType: 'script' }); }
    catch (e) { console.error(`ILLISIBLE ${nom} : ${e.message}`); process.exit(3); }
    const voir = (n) => {
        if (!n || typeof n.type !== 'string') return;
        if (n.type === 'Literal' && typeof n.value === 'string') {
            if (!litteraux.has(n.value)) litteraux.set(n.value, []);
            litteraux.get(n.value).push(nom);
        }
        // Une concatenation de deux litteraux : `'/iptables' + '-logs'`
        if (n.type === 'BinaryExpression' && n.operator === '+'
            && n.left?.type === 'Literal' && n.right?.type === 'Literal') concats++;
        for (const k of Object.keys(n)) {
            const v = n[k];
            if (Array.isArray(v)) v.forEach(voir);
            else if (v && typeof v.type === 'string') voir(v);
        }
    };
    voir(arbre);
}

console.log(`${litteraux.size} chaines litterales distinctes, ${concats} concatenations de deux litteraux`);
for (const c of cherches) {
    const trouve = [...litteraux.entries()].filter(([s]) => s.includes(c));
    console.log(`  ${c.padEnd(20)} ${trouve.length ? 'PRESENT : ' + JSON.stringify(trouve) : 'ABSENT des litteraux JS'}`);
}
