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
        // MUTATION : on retire L'ASYMETRIE — un `ACCEPT` redevient decisif des
        // qu'il ne s'agit pas d'un autre port, comme un `DROP`. C'est
        // exactement l'etat du 2026-09-07 avant la revue, celui qui declarait
        // OUVERTS les deux premieres lignes de tout pare-feu durci.
        const avant = code;
        code = code.replace(
            "                if (ouvre === true) { return true; }",
            "                if (portCouvert !== false) { return true; }   // MUTATION"
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

    /* ══ LES DIX DE LA REVUE — cinq d'entre eux etaient FAIL-OPEN ══════════
     * Releves par une seconde session sur le fichier que je venais d'ecrire.
     * Les deux premiers sont les DEUX PREMIERES LIGNES de presque tout
     * pare-feu durci reel : c'est ce qui rend le defaut grave et non theorique.
     */
    ['⚠ FAIL-OPEN 1/5 — `-i lo` ACCEPT seul',
     ':INPUT DROP\n-A INPUT -i lo -j ACCEPT', 22, false],

    ['⚠ FAIL-OPEN 2/5 — ESTABLISHED seul (le pire : tue les session SUIVANTES)',
     ':INPUT DROP\n-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT', 22, false],

    ['⚠ FAIL-OPEN 3/5 — source restreinte',
     ':INPUT DROP\n-A INPUT -s 10.0.0.5 -j ACCEPT', 22, false],

    ['⚠ FAIL-OPEN 4/5 — UDP 22, pas TCP',
     ':INPUT DROP\n-A INPUT -p udp --dport 22 -j ACCEPT', 22, false],

    ['⚠ FAIL-OPEN 5/5 — `-I` insere en TETE : l\'ordre du fichier ment',
     ':INPUT ACCEPT\n-A INPUT --dport 22 -j ACCEPT\n-I INPUT -j DROP', 22, null],

    ['saut vers une chaine personnalisee — indecidable',
     ':INPUT DROP\n-A INPUT -j MACHAINE', 22, null],

    /* ══ L'AVEU CONTRE L'ACCUSATION — releve en 2e revue ══════════════════
     * `false` accuse (« ces regles ferment »), `null` avoue (« je ne peux pas
     * prouver »). Les deux se traitent en REFUS ; seul le MESSAGE differe.
     * Un garde qui accuse a tort s'use plus vite qu'un garde absent.
     */
    ['AVEU — `-i eth0` : indecidable, PAS une accusation',
     ':INPUT DROP\n-A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT', 22, null],

    ['AVEU — source restreinte sur le bon port : indecidable',
     ':INPUT DROP\n-A INPUT -s 10.0.0.5 -p tcp --dport 22 -j ACCEPT', 22, null],

    ['ACCUSATION VRAIE — ESTABLISHED sur le bon port : on SAIT qu il n ouvre pas',
     ':INPUT DROP\n-A INPUT -m state --state ESTABLISHED --dport 22 -j ACCEPT', 22, false],

    /* ══ LA FORME LA PLUS ORDINAIRE, ET C'EST ELLE QUI RESTAIT FAUSSE ═════
     * « Un ACCEPT qualifie, puis un DROP de cloture » est la forme canonique
     * d'un pare-feu durci. Mes cas forges etaient exotiques ; celui-ci est le
     * cas reel, et il a survecu a trois rondes de correction.
     *
     * > Quand on forge des cas, partir du jeu de regles le plus BANAL qu'on
     * > puisse ecrire, pas du plus retors. Un correctif qui traite le cas
     * > d'ecole avant le cas reel a une couverture inversee par rapport a la
     * > frequence.                                    (formulation de la revue)
     */
    ['LE CAS REEL — ACCEPT qualifie puis DROP de cloture',
     ':INPUT DROP\n-A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT\n-A INPUT -j DROP', 22, null],

    ['BORNE — un peut-etre PUIS une preuve : la preuve l\'emporte',
     ':INPUT DROP\n-A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT', 22, true],

    ['BORNE — un DROP certain AVANT le peut-etre : le DROP decide',
     ':INPUT ACCEPT\n-A INPUT -j DROP\n-A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT', 22, false],

    ['ACCUSATION VRAIE — aucun peut-etre, DROP de cloture',
     ':INPUT DROP\n-A INPUT -p tcp --dport 80 -j ACCEPT\n-A INPUT -j DROP', 22, false],

    /* ══ LE SUIVI DE CHAINE — le cas du PARC ═══════════════════════════════
     * `fail2ban` saute vers `f2b-sshd` sur le port SSH. Sans suivre la chaine,
     * le predicat rendait `null` sur TOUTE machine faisant tourner fail2ban —
     * et RootWarden gere fail2ban. Un garde qui refuse toujours se contourne :
     * c'est un argument de SURETE, pas de confort.
     */
    ['PARC — fail2ban ordinaire : la chaine RETURN, l\'ACCEPT suit',
     '*filter\n:INPUT DROP [0:0]\n:f2b-sshd - [0:0]\n-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j DROP\n-A f2b-sshd -s 203.0.113.7 -j REJECT\n-A f2b-sshd -j RETURN\nCOMMIT', 22, true],

    ['CHAINE — elle bloque tout le monde : accusation VRAIE',
     '*filter\n:INPUT DROP\n:mur - [0:0]\n-A INPUT -p tcp --dport 22 -j mur\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A mur -j DROP\nCOMMIT', 22, false],

    ['CHAINE — non definie dans le fichier : indecidable',
     ':INPUT DROP\n-A INPUT -p tcp --dport 22 -j inconnue\n-A INPUT -p tcp --dport 22 -j ACCEPT', 22, null],

    ['CHAINE — elle ne concerne pas notre port',
     ':INPUT DROP\n:web - [0:0]\n-A INPUT -p tcp --dport 80 -j web\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A web -j DROP', 22, true],

    ['CHAINE — imbriquee de deux niveaux : on ne pretend pas suivre',
     ':INPUT DROP\n:a - [0:0]\n:b - [0:0]\n-A INPUT -p tcp --dport 22 -j a\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A a -j b\n-A b -j c\n-A c -j RETURN', 22, null],

    /* ══ LE SUIVI CONCLUT « OUVERT », ET NE RETOMBE PLUS SUR `false` ══════
     * Ecarts de la 7e revue : quand le suivi ne pouvait pas conclure, il
     * laissait le balayage retomber sur le DROP de cloture — donc sur une
     * ACCUSATION. C'est l'asymetrie des rondes 3 a 5, reproduite un cran plus
     * bas, DANS LE CODE ECRIT ENSUITE.
     */
    ['CHAINE — elle ACCEPTE sans condition : elle OUVRE',
     ':INPUT DROP\n:OK - [0:0]\n-A INPUT -p tcp --dport 22 -j OK\n-A INPUT -j DROP\n-A OK -j ACCEPT', 22, true],

    ['CHAINE — declaree mais VIDE : elle RETURN, le trafic traverse',
     ':INPUT DROP\n:OK - [0:0]\n-A INPUT -p tcp --dport 22 -j OK\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j DROP', 22, true],

    ['CHAINE — imbrication A->B->ACCEPT : suivie et conclue',
     ':INPUT DROP\n:A - [0:0]\n:B - [0:0]\n-A INPUT -p tcp --dport 22 -j A\n-A INPUT -j DROP\n-A A -j B\n-A B -j ACCEPT', 22, true],

    ['BOUCLE — A->B->A : la garde de profondeur ferme',
     ':INPUT DROP\n:A - [0:0]\n:B - [0:0]\n-A INPUT -p tcp --dport 22 -j A\n-A A -j B\n-A B -j A', 22, null],

    ['BOUCLE — une chaine qui s\'appelle ELLE-MEME',
     ':INPUT DROP\n:A - [0:0]\n-A INPUT -p tcp --dport 22 -j A\n-A A -j A', 22, null],

    ['REEL — pare-feu durci complet, et il est SUR',
     ':INPUT DROP\n-A INPUT -i lo -j ACCEPT\n-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT', 22, true],
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
    /*
     * ══ PREDICTION MISE A JOUR APRES LA REVUE : 4 ═══════════════════════════
     *
     * La mutation retire desormais L'ASYMETRIE. Elle doit faire rougir les
     * QUATRE cas ou un `ACCEPT` ne prouve pas son ouverture :
     *
     *     `-i lo` seul · ESTABLISHED seul · source restreinte · UDP 22
     *
     * **Et PAS le cinquieme (`-I` en tete)** : celui-la est attrape par le
     * PRE-BALAYAGE, que cette mutation ne touche pas. *Deux defauts de la meme
     * revue, deux mecanismes differents — une seule mutation ne peut pas les
     * exercer tous les deux, et le dire evite de croire qu'elle le fait.*
     *
     * Historique de cette valeur, garde volontairement :
     *     1  scelle avant la 1re mutation — FAUX, j'avais deux cas d'ORDRE
     *     2  corrige apres mesure
     *     4  apres la 1re revue, qui a ajoute quatre cas d'ASYMETRIE
     *     7  apres la 2e revue : les quatre ci-dessus PLUS les trois cas
     *        « aveu contre accusation », qui exercent la meme branche
     *     8  apres la 3e revue : + « LE CAS REEL ». Les trois autres cas
     *        ajoutes n'en sont pas — deux BORNES qui restent justes sous la
     *        mutation, et une accusation vraie sans drapeau arme.
     *
     * PREDICTION SCELLEE pour 7, ecrite avant de jouer : les quatre cas ou un
     * ACCEPT sans contrainte de port ne prouve rien (`-i lo`, ESTABLISHED,
     * source, UDP) et les trois ou il couvre le port sans conclure (`-i eth0`,
     * `-s` + dport, ESTABLISHED + dport). PAS `-I` ni la chaine custom : ils
     * passent par le pre-balayage et par la garde de cible, que la mutation ne
     * touche ni l'un ni l'autre.
     */
    const attendu = 8;
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
