/*
 * EPREUVE DE LA PROPRIETE Q2 — et elle doit MORDRE.
 *
 * Elle lit `laravel/public/js/pare-feu-ssh-ouvert.js`, LE FICHIER SERVI, plutot
 * que d'en recopier la logique. Une seconde copie divergerait, et divergerait
 * en silence — les deux continueraient de « passer ».
 *
 * Usage :
 *     node laravel/tests/Outils/q2-ssh-ouvert.mjs
 *     node laravel/tests/Outils/q2-ssh-ouvert.mjs --mutation   (prouve qu'elle mord)
 *
 * ⚠ CE QUE CETTE EPREUVE N'EST PAS : elle n'emet aucune requete et ne joint
 * aucune machine. Elle juge un predicat sur des textes. La propriete « aucune
 * requete ne part » se mesure au RESEAU, dans une suite de navigateur, avec un
 * temoin positif — c'est une autre epreuve, et elle reste a ecrire.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ICI = dirname(fileURLToPath(import.meta.url));
const SOURCE = join(ICI, '..', '..', 'public', 'js', 'pare-feu-ssh-ouvert.js');

function chargeLePredicat(mutation) {
    let code = readFileSync(SOURCE, 'utf8');

    if (mutation) {
        // MUTATION : on retire le `return` qui fait decider la PREMIERE regle
        // applicable, et on laisse la boucle continuer. Le predicat devient
        // « le texte contient-il un ACCEPT sur le port ? » — l'erreur meme que
        // ce fichier existe pour ne pas commettre.
        const avant = code;
        code = code.replace(
            "            return cible === 'ACCEPT';   // LA PREMIERE QUI PEUT S'APPLIQUER DECIDE",
            "            if (cible === 'ACCEPT') { return true; }   // MUTATION"
        );
        if (code === avant) {
            console.error("  ⛔ la mutation n'a rien remplace — l'ancre a bouge, l'epreuve ne prouve RIEN");
            process.exit(2);
        }
    }

    const bac = {};
    new Function('globalThis', code).call(bac, bac);
    if (typeof bac.rwLaisseLeSshOuvert !== 'function') {
        console.error('  ⛔ le fichier n\'expose pas `rwLaisseLeSshOuvert`');
        process.exit(2);
    }

    return bac.rwLaisseLeSshOuvert;
}

/* Chaque cas porte la RAISON pour laquelle il existe. */
const CAS = [
    ['ACCEPT explicite avant DROP',
     ':INPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j DROP', 22, true],

    ['⚠ LE CAS QUI DECIDE — DROP place AVANT l\'ACCEPT',
     ':INPUT ACCEPT\n-A INPUT -j DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT', 22, false],

    ['politique DROP et rien d\'autre',        ':INPUT DROP [0:0]', 22, false],
    ['politique ACCEPT et rien d\'autre',      ':INPUT ACCEPT [0:0]', 22, true],

    ['un AUTRE port est ouvert, pas le notre',
     ':INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT', 2222, false],

    ['une PLAGE qui couvre le port',
     ':INPUT DROP\n-A INPUT -p tcp --dport 2200:2300 -j ACCEPT', 2222, true],

    ['multiport qui couvre le port',
     ':INPUT DROP\n-A INPUT -p tcp -m multiport --dports 80,443,2222 -j ACCEPT', 2222, true],

    ['negation : `! --dport 22` ne couvre PAS 22',
     ':INPUT DROP\n-A INPUT -p tcp ! --dport 22 -j ACCEPT', 22, false],

    ['REJECT global avant l\'ACCEPT',
     ':INPUT ACCEPT\n-A INPUT -j REJECT\n-A INPUT --dport 22 -j ACCEPT', 22, false],

    ['une cible NON terminale ne decide pas',
     ':INPUT DROP\n-A INPUT -j LOG\n-A INPUT -p tcp --dport 22 -j ACCEPT', 22, true],

    ['un commentaire est ignore',
     '# rien\n:INPUT DROP\n-A INPUT --dport 22 -j ACCEPT', 22, true],

    ['FAIL-CLOSED — texte vide',                '', 22, null],
    ['FAIL-CLOSED — port invalide',             ':INPUT ACCEPT', 0, null],
    ['FAIL-CLOSED — regles sans politique',     '-A INPUT -p tcp --dport 80 -j ACCEPT', 22, false],
];

const mutation = process.argv.includes('--mutation');
const predicat = chargeLePredicat(mutation);

let ok = 0;
let echecs = 0;

for (const [nom, texte, port, attendu] of CAS) {
    const obtenu = predicat(texte, port);
    const bon = obtenu === attendu;
    bon ? ok++ : echecs++;
    console.log(`  ${bon ? 'ok  ' : 'FAIL'} ${nom.padEnd(46)} attendu=${String(attendu).padEnd(5)} obtenu=${obtenu}`);
}

console.log('');

if (mutation) {
    /*
     * ⚠ PREDICTION SCELLEE — ET ELLE ETAIT FAUSSE. Je laisse la trace.
     *
     *     ce que j'avais scelle avant de jouer :  1 rouge
     *     ce que la mutation a rendu            :  2 rouges
     *
     * J'avais predit le seul cas « DROP place AVANT l'ACCEPT ». Mais
     * « REJECT global avant l'ACCEPT » est LE MEME CAS — un ACCEPT sur le port,
     * rendu inatteignable par une regle terminale placee plus haut. **J'ai
     * ecrit deux cas de la meme famille et n'en ai compte qu'un.**
     *
     * C'est exactement le controle qui ne demande aucune connaissance du sujet :
     * compter la liste qu'on vient d'ecrire. La mutation n'a rien revele sur le
     * code — elle a revele que je n'avais pas relu mes propres cas.
     *
     * **La prediction corrigee est donc 2, et elle porte sa raison** : deux cas
     * exercent la propriete d'ORDRE, et la mutation retire precisement l'ordre.
     * Si un troisieme cas d'ordre est ajoute plus tard, ce nombre doit monter a
     * 3 — et s'il ne monte pas, c'est le cas neuf qui est mal ecrit.
     */
    const attendu = 2;
    console.log(`  MUTATION : ${echecs} cas ROUGE (prediction scellee : ${attendu})`);
    if (echecs === attendu) {
        console.log('  ✅ l\'epreuve MORD, et elle mord a l\'endroit prevu');
        process.exit(0);
    }
    console.log(`  ⛔ ${echecs} rouges au lieu de ${attendu} : la mutation ou ma comprehension est fausse`);
    process.exit(1);
}

console.log(`  ${ok} ok · ${echecs} FAIL`);
if (echecs === 0) {
    console.log('  → rejouer avec --mutation pour verifier que cette epreuve MORD');
}
process.exit(echecs === 0 ? 0 : 1);
