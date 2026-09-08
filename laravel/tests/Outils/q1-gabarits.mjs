/*
 * ÉPREUVE Q1 — CHAQUE GABARIT, POUR CHAQUE PORT, DOIT SATISFAIRE Q2.
 *
 * Elle ne relit pas les gabarits : elle les PASSE AU GARDE que l'application
 * leur opposera. *Un gabarit qu'on relit et juge correct reste un jugement ; un
 * gabarit que Q2 accepte est une propriété.*
 *
 * Les deux fichiers SERVIS sont chargés, jamais recopiés :
 *     laravel/public/js/pare-feu-gabarits.js
 *     laravel/public/js/pare-feu-ssh-ouvert.js
 *
 * Usage :
 *     node laravel/tests/Outils/q1-gabarits.mjs
 *     node laravel/tests/Outils/q1-gabarits.mjs --mutation
 *
 * ⛔ Aucune requête, aucune machine jointe. On fabrique du texte et on le juge.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ICI = dirname(fileURLToPath(import.meta.url));
const JS = join(ICI, '..', '..', 'public', 'js');

function charge(mutation) {
    const bac = {};
    let gab = readFileSync(join(JS, 'pare-feu-gabarits.js'), 'utf8');

    if (mutation) {
        /*
         * MUTATION : le port redevient `22` en dur — l'état du legacy.
         * Elle doit faire rougir TOUT gabarit rendu pour un port ≠ 22, et AUCUN
         * rendu pour 22. C'est ce dernier point qui rend la mutation probante :
         * un gabarit correct par coïncidence reste vert, et c'est exactement
         * pourquoi le défaut a survécu au legacy.
         */
        const avant = gab;
        gab = gab.replace(
            "            '-A INPUT -p tcp --dport ' + port + ' -j ACCEPT',",
            "            '-A INPUT -p tcp --dport 22 -j ACCEPT',   // MUTATION"
        );
        if (gab === avant) {
            console.error("  ⛔ la mutation n'a rien remplace — l'ancre a bouge, l'epreuve ne prouve RIEN");
            process.exit(2);
        }
    }

    new Function('globalThis', readFileSync(join(JS, 'pare-feu-ssh-ouvert.js'), 'utf8')).call(bac, bac);
    new Function('globalThis', gab).call(bac, bac);

    if (typeof bac.rwGabaritPareFeu !== 'function' || typeof bac.rwLaisseLeSshOuvert !== 'function') {
        console.error('  ⛔ un des deux fichiers n\'expose pas ce qu\'on attend');
        process.exit(2);
    }

    return bac;
}

/*
 * Les ports éprouvés. 22 est le cas du parc AUJOURD'HUI — donc celui où le
 * défaut est invisible ; les autres sont ceux d'un `sshd` durci.
 * 80 et 443 sont là exprès : le gabarit `web` les ouvre déjà pour HTTP, donc
 * ils vérifient qu'on ne conclut pas « ouvert » par la mauvaise ligne.
 */
const PORTS = [22, 2222, 22022, 2200, 1022, 80, 443];

const mutation = process.argv.includes('--mutation');
const { rwGabaritPareFeu, rwGabaritsPareFeu, rwLaisseLeSshOuvert } = charge(mutation);

const NOMS = rwGabaritsPareFeu();
console.log(`  gabarits : ${NOMS.length} · ports : ${PORTS.length} · cas : ${NOMS.length * PORTS.length}\n`);

let ok = 0;
let echecs = 0;
const rouges = [];

for (const nom of NOMS) {
    const verdicts = [];
    for (const port of PORTS) {
        const texte = rwGabaritPareFeu(nom, port);
        if (texte === null) {
            echecs++; rouges.push([nom, port, 'gabarit null']);
            verdicts.push('null!');
            continue;
        }
        const v = rwLaisseLeSshOuvert(texte, port);
        if (v === true) { ok++; verdicts.push(String(port)); }
        else { echecs++; rouges.push([nom, port, `Q2 rend ${v}`]); verdicts.push(`${port}:${v}`); }
    }
    const bon = verdicts.every((x) => /^\d+$/.test(x));
    console.log(`  ${bon ? 'ok  ' : 'FAIL'} ${nom.padEnd(14)} ${verdicts.join(' · ')}`);
}

/*
 * ⚠ TÉMOINS — sans eux, « tout est vert » ne dit pas que l'épreuve regarde.
 *
 * ⛔ ET ILS SONT JOUES SUR LES FICHIERS **NON MUTES**, TOUJOURS.
 *
 * Premier jet : ils tournaient sur les fichiers chargés plus haut, donc mutés en
 * mode `--mutation`. Le témoin positif « un gabarit pour 2222, jugé sur 22, doit
 * rendre `false` » devenait alors `true` — puisque le gabarit muté EST figé sur
 * 22 — et ma garde de témoin arrêtait l'épreuve avant qu'elle ne rende son
 * compte de mutation.
 *
 * **Un témoin que la mutation modifie ne peut pas valider la course mutée.** Il
 * doit vivre en dehors de ce qu'on mute — sinon il mesure la mutation au lieu de
 * mesurer l'instrument.
 *
 * *Trouvé par la garde elle-même, sur son propre test : elle a refusé de rendre
 * un verdict qu'elle ne pouvait plus fonder.*
 */
console.log('');
const propre = charge(false);
const t1 = propre.rwGabaritPareFeu('zzz-inexistant', 22);
const t2 = propre.rwGabaritPareFeu('web', 0);
const t3 = propre.rwLaisseLeSshOuvert(propre.rwGabaritPareFeu('tout_fermer', 2222), 22);
console.log(`  [TEMOIN-] un nom inconnu           -> ${t1}   (null attendu)`);
console.log(`  [TEMOIN-] un port invalide         -> ${t2}   (null attendu)`);
console.log(`  [TEMOIN+] gabarit pour 2222, juge sur 22 -> ${t3}   (false attendu : Q2 SAIT refuser)`);

let temoinsKo = 0;
if (t1 !== null) { temoinsKo++; }
if (t2 !== null) { temoinsKo++; }
if (t3 !== false) { temoinsKo++; }
if (temoinsKo) {
    console.log(`\n  ⛔ ${temoinsKo} temoin(s) en echec — l'epreuve ne mesure pas ce qu'elle annonce`);
    process.exit(2);
}

console.log('');

if (mutation) {
    /*
     * PRÉDICTION SCELLÉE, écrite avant d'avoir joué : la mutation remet `22` en
     * dur, donc elle doit faire rougir CHAQUE gabarit pour CHAQUE port ≠ 22.
     *
     *     5 gabarits × 6 ports differents de 22           30
     *     moins `web` sur 80 et 443, `docker` sur 80 et 443  -4
     *     ────────────────────────────────────────────────────
     *                                                        26
     *
     * ⚠ MA PREMIERE PREDICTION DISAIT 30, ET ELLE ETAIT FAUSSE. Je laisse la
     * trace. `web` et `docker` portent `--dport 80` et `--dport 443` pour HTTP :
     * une machine dont `sshd` ecoute sur 80 a donc son port OUVERT par une autre
     * ligne, meme avec le gabarit fige a 22. **Q2 a raison de rendre `true` : le
     * port EST ouvert.**
     *
     * *Et j'avais mis 80 et 443 dans la liste POUR CETTE RAISON — « ils
     * verifient qu'on ne conclut pas ouvert par la mauvaise ligne » — puis je ne
     * les ai pas comptes dans ma prediction.* **Troisieme fois cette nuit que je
     * ne relis pas la liste que je viens d'ecrire.**
     *
     * ⚠ Et pas 35 non plus : les cinq cas « port = 22 » restent VERTS, parce que
     * le gabarit mute est correct pour eux. **C'est le cœur du defaut du legacy —
     * juste par coincidence sur le parc actuel** — et une mutation qui rougirait
     * partout prouverait que mes ports d'epreuve ne contiennent pas le cas ou le
     * defaut se cache.
     */
    const attendu = 26;
    console.log(`  MUTATION (port fige a 22) : ${echecs} ROUGE (prediction scellee : ${attendu})`);
    if (echecs === attendu) {
        console.log('  ✅ l\'epreuve MORD, et les cinq cas « port = 22 » restent verts — comme prevu');
        process.exit(0);
    }
    console.log('  ⛔ la mutation ou ma comprehension est fausse');
    for (const [n, p, r] of rouges.slice(0, 6)) { console.log(`      ${n} port=${p} : ${r}`); }
    process.exit(1);
}

console.log(`  ${ok} ok · ${echecs} FAIL`);
if (echecs) {
    for (const [n, p, r] of rouges) { console.log(`      ⛔ ${n} port=${p} : ${r}`); }
} else {
    console.log('  → rejouer avec --mutation pour verifier que cette epreuve MORD');
}
process.exit(echecs === 0 ? 0 : 1);
