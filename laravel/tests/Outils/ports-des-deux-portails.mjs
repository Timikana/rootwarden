/*
 * LES DEUX PORTAILS N'ONT PAS LE MEME PORT, ET AUCUN DEFAUT NE DOIT NOMMER L'AUTRE
 *
 * ══ CE QUE CE CONTROLE EXISTE POUR ATTRAPER ══════════════════════════════
 *
 * L'echange du 2026-09-06 a donne au PORTAGE les ports du portail historique et
 * relegue le legacy sur ceux que le portage abandonnait. **Les valeurs sont
 * inchangees ; c'est leur ATTRIBUTION qui a bascule.**
 *
 *     portage   8080 / 8443
 *     legacy    8444 / 8446
 *
 * Un defaut ecrit avant l'echange reste donc SYNTAXIQUEMENT valide et devient
 * SEMANTIQUEMENT faux. Mesure du 2026-09-08 : `config/app.php` portait
 * `env('LEGACY_URL', 'https://localhost:8443')` — la cle nomme le legacy, le
 * port nommait le portage, et sept lecteurs concatenent cette valeur avec un
 * chemin du legacy.
 *
 * > **Ce n'est pas une panne : c'est un lien qui porte le nom d'un portail et
 * > l'adresse de l'autre.** Rien ne le signale — ni une erreur de syntaxe, ni un
 * > 500, ni un test de forme. L'ecran ressemble a celui qu'on attendait.
 *
 * ⚠ ET LE MEME PIEGE A DEJA ETE ARME AILLEURS. Le plan de migration avertit que
 * `laravel/docker-entrypoint.sh` portait `LARAVEL_HTTPS_PORT:-8446` — le port que
 * le legacy occupe desormais — ce qui aurait bati la redirection HTTP -> HTTPS du
 * PORTAGE vers le LEGACY. Corrige depuis ; ce controle le tient.
 *
 * ══ LA SOURCE EST LE COMPOSE, JAMAIS UNE SECONDE LISTE ═══════════════════
 *
 * Les attributions sont LUES dans `docker-compose.yml`. Ecrire ici « legacy =
 * 8446 » creerait une seconde liste a faire divergier — et c'est exactement
 * l'espece de defaut qu'on mesure.
 *
 *     node laravel/tests/Outils/ports-des-deux-portails.mjs
 *     node laravel/tests/Outils/ports-des-deux-portails.mjs --mutation
 *
 * sortie   0 = aucun defaut ne nomme le mauvais portail
 *          1 = au moins un le fait
 *          2 = l'instrument n'a pas pu mesurer -> NE RIEN CONCLURE
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const RACINE = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const mutation = process.argv.includes('--mutation');

function lit(rel) {
    try { return readFileSync(join(RACINE, rel), 'utf8'); }
    catch { return null; }
}

/*
 * ── LES ATTRIBUTIONS, DERIVEES DU COMPOSE ────────────────────────────────
 *
 * On lit les defauts d'interpolation `${NOM:-VALEUR}` des lignes `ports:`. Le
 * bloc `php` est le legacy, le bloc `laravel` est le portage — et c'est le seul
 * endroit ou cette correspondance est ecrite.
 */
function attributions() {
    const brut = lit('docker-compose.yml');
    if (brut === null) { return null; }
    /*
     * ⚠ LES COMMENTAIRES YAML SONT RETIRES AVANT DE MESURER, ET C'EST OBLIGATOIRE.
     *
     * `docker-compose.yml` CITE en prose, pour expliquer le risque de l'echange,
     * la forme perimee `LARAVEL_HTTPS_PORT="${LARAVEL_HTTPS_PORT:-8446}"`. Elle
     * apparait AVANT la vraie declaration, et `String.match` rend la PREMIERE
     * occurrence : la sonde lisait donc l'ancienne valeur dans un commentaire qui
     * expliquait pourquoi elle etait dangereuse.
     *
     * *Cinquieme fois dans la meme session qu'une prose satisfait le motif que je
     * verifie — apres `/* * /`, `//`, `{{-- --}}` et un docblock. La parade n'est
     * pas de connaitre les syntaxes : c'est de depouiller AVANT de mesurer, a
     * chaque fois, sans se demander si ce fichier-la en contient.*
     *
     * Limite declaree : un `#` a l'interieur d'une chaine entre guillemets serait
     * retire a tort. Les lignes `ports:` n'en portent pas, et le temoin de
     * discrimination ci-dessous attrape le cas ou ce depouillage casserait tout.
     */
    const y = brut.replace(/^\s*#.*$/gm, '').replace(/\s#.*$/gm, '');
    const out = {};
    let manquants = [];
    for (const [service, cle] of [['legacy', 'HTTPS_PORT'], ['portage', 'LARAVEL_HTTPS_PORT']]) {
        const m = y.match(new RegExp('\\$\\{' + cle + ':-(\\d+)\\}'));
        if (!m) { manquants.push(service); continue; }
        out[service] = Number(m[1]);
    }
    /*
     * ── TROIS ETATS, ET L'ANCIENNE FORME LES CONFONDAIT EN DEUX ───────────────
     *
     * `patch 07` a retire le service `php` du compose le 2026-09-08. `HTTPS_PORT`
     * n'y apparait donc plus, et cette fonction rendait `null` — c'est-a-dire
     * « NE RIEN CONCLURE », c'est-a-dire un REFUS PERMANENT.
     *
     * Or ce refus est le SUCCES de ce que la sonde surveillait : il n'y a plus
     * deux portails a comparer. Une porte qui ne peut plus s'ouvrir bloque la
     * sequence d'extinction pour toujours, et son rouge ressemble a un defaut.
     *
     *   legacy ET portage lisibles   -> comparer, c'est la question d'origine
     *   legacy absent, portage lu    -> ETAT TERMINAL, il n'y a qu'un portail
     *   portage absent aussi         -> l'instrument n'a rien lu, exit 2
     *
     * ⚠ Le TEMOIN est ce qui separe le deuxieme du troisieme : « legacy absent »
     * et « fichier illisible » rendent la meme sortie si on ne verifie pas
     * qu'on a lu QUELQUE CHOSE. C'est pourquoi l'etat terminal exige que
     * `portage` soit non seulement present mais NUMERIQUE.
     */
    if (manquants.length === 2) { return null; }
    if (manquants.length === 1) {
        return { manquants, ...out };
    }
    return out;
}

const PORTS = attributions();
if (PORTS === null) {
    console.log('  ⛔ docker-compose.yml illisible : AUCUN des deux defauts de port lu.');
    console.log('     « les deux absents » et « fichier illisible » sont la meme sortie.');
    console.log('     NE RIEN CONCLURE.');
    process.exit(2);
}
if (PORTS.manquants) {
    /*
     * L'ETAT TERMINAL. Un seul portail est declare : la question « les deux
     * portails se marchent-ils sur les pieds » n'a plus d'objet.
     */
    if (PORTS.manquants.includes('portage')) {
        console.log('  ⛔ le defaut de port du PORTAGE est absent, celui du legacy present.');
        console.log('     C\'est l\'inverse de l\'extinction : le portage devrait rester.');
        process.exit(1);
    }
    const restant = PORTS.portage;
    if (!Number.isInteger(restant) || restant <= 0 || restant > 65535) {
        console.log(`  ⛔ le port du portage est lu mais invalide : ${restant}`);
        console.log('     NE RIEN CONCLURE.');
        process.exit(2);
    }
    console.log('  ✅ ETAT TERMINAL — un seul portail est declare dans le compose.');
    console.log(`     le legacy (\${HTTPS_PORT:-...}) a disparu du compose : 0 occurrence`);
    console.log(`     le portage repond sur :${restant}, lu hors commentaires`);
    console.log('     TEMOIN : ce vert n\'est pas « rien lu » — une valeur NUMERIQUE');
    console.log('     a ete extraite du fichier. Sans elle, ce chemin sortirait en 2.');
    console.log('     La comparaison des deux portails n\'a plus d\'objet.');
    process.exit(0);
}
if (PORTS.legacy === PORTS.portage) {
    console.log(`  ⛔ les deux portails lisent le meme port (${PORTS.legacy}) — la sonde ne discrimine pas.`);
    process.exit(2);
}
console.log(`  attributions lues dans le compose : legacy=${PORTS.legacy} · portage=${PORTS.portage}\n`);

/*
 * ── LES DEFAUTS A EPROUVER ───────────────────────────────────────────────
 *
 * `portail` dit QUEL portail ce defaut est cense nommer. C'est la seule chose
 * qu'on affirme ici ; le port attendu en est DEDUIT.
 */
const DEFAUTS = [
    {
        nom: 'config/app.php  url_legacy',
        fichier: 'laravel/config/app.php',
        motif: /env\(\s*'LEGACY_URL'\s*,\s*'[^']*?:(\d+)'\s*\)/,
        portail: 'legacy',
    },
    {
        nom: 'docker-entrypoint.sh  LARAVEL_HTTPS_PORT',
        fichier: 'laravel/docker-entrypoint.sh',
        motif: /LARAVEL_HTTPS_PORT="\$\{LARAVEL_HTTPS_PORT:-(\d+)\}"/,
        portail: 'portage',
    },
];

let echecs = 0;
let lus = 0;
for (const d of DEFAUTS) {
    let src = lit(d.fichier);
    if (src === null) { console.log(`  ⛔ ${d.nom} : ${d.fichier} ILLISIBLE`); echecs++; continue; }

    if (mutation) {
        /*
         * MUTATION : on echange les deux ports dans la source lue — la faute
         * exacte que l'echange du 2026-09-06 pouvait produire. Elle doit faire
         * rougir CHAQUE defaut, sinon ce controle ne regarde rien.
         */
        src = src.replace(
            new RegExp('(:|-)' + PORTS[d.portail] + '(?=[^\\d])', 'g'),
            (_, p) => p + PORTS[d.portail === 'legacy' ? 'portage' : 'legacy']);
    }

    const m = src.match(d.motif);
    if (!m) { console.log(`  ⛔ ${d.nom} : ANCRE ABSENTE — non mesure`); echecs++; continue; }
    lus++;
    const trouve = Number(m[1]);
    const attendu = PORTS[d.portail];
    const bon = trouve === attendu;
    if (!bon) { echecs++; }
    console.log(`  ${bon ? 'ok  ' : 'FAIL'} ${d.nom.padEnd(38)} ${trouve}`
        + (bon ? `  (${d.portail})` : `  ⛔ nomme ${d.portail} mais porte le port de `
            + (trouve === PORTS[d.portail === 'legacy' ? 'portage' : 'legacy'] ? 'L AUTRE PORTAIL' : 'personne')
            + ` — attendu ${attendu}`));
}

/*
 * ⚠ TEMOIN — sans lui, « 0 defaut » et « je n'ai lu aucune ancre » sont la meme
 * sortie. On exige d'avoir LU chaque defaut declare.
 */
if (lus !== DEFAUTS.length) {
    console.log(`\n  ⛔ ${lus}/${DEFAUTS.length} defaut(s) lu(s) — l'instrument n'a pas mesure ce qu'il annonce.`);
    console.log('     NE RIEN CONCLURE.');
    process.exit(2);
}

if (mutation) {
    const attendu = DEFAUTS.length;
    console.log(`\n  MUTATION (les deux ports echanges dans chaque source)`);
    console.log(`    prediction scellee : ${attendu} rouge(s) — un par defaut declare`);
    console.log(`    obtenus            : ${echecs}`);
    if (echecs === attendu) { console.log('  ✅ le controle MORD sur chaque defaut'); process.exit(0); }
    console.log('  ⛔ la mutation ou ma comprehension est fausse');
    process.exit(1);
}

console.log(`\n  ${DEFAUTS.length - echecs} ok · ${echecs} FAIL`);
if (echecs === 0) { console.log('  → rejouer avec --mutation pour verifier que ce controle MORD'); }
process.exit(echecs === 0 ? 0 : 1);
