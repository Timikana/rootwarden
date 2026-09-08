/*
 * ═══ LES JETONS INTERDITS — UNE DECLARATION D'ETAT QUI SE TIENT SEULE ═════
 *
 * HORS-LOT: controle statique, sans navigateur ni session. Il se joue seul ou
 * depuis un crochet, pas dans une moitie du LOT.
 *
 * ══ LE DEFAUT QU'IL REMPLACE ══════════════════════════════════════════════
 *
 * Une declaration du type « `socle_…` a disparu » est vraie le jour
 * ou on la mesure, et **redevient fausse sans qu'aucun commit ne la touche** —
 * il suffit qu'un pair reintroduise la chaine. La consigne demande donc de la
 * remesurer a chaque tour.
 *
 * Mesure du 2026-09-07 : **le meme vrai negatif remesure DOUZE fois**, et redige
 * douze fois dans `DECISIONS-DSI.md`. Chaque remesure etait justifiee prise
 * seule ; l'agregat est du travail pur perdu, et 100 % de documentation.
 *
 * **Ce fichier rend la verification gratuite et permanente.** La reponse a « ou
 * en est cette declaration » devient « cette suite la porte, elle est verte » —
 * et ce vert tient ENTRE les tours, ce qu'aucune remesure ne fait.
 *
 * ══ TROIS PROPRIETES, ET LA TROISIEME EST CELLE QUI DECIDE ════════════════
 *
 * 1. LA PORTEE EST DECLAREE et imprimee dans le verdict. Un lecteur ne doit pas
 *    pouvoir prendre ce vert pour un vert du DEPOT : il ne vaut que pour les
 *    repertoires nommes.
 *
 * 2. LE TEMOIN POSITIF, sans quoi le controle est vert a vide. **« 0 occurrence »
 *    et « je n'ai lu aucun fichier » sont la meme sortie.** On exige donc que le
 *    balayage ait lu > 0 fichiers ET qu'il retrouve un jeton qui DOIT etre la.
 *    *Mesure du 2026-09-07 : un `grep` a rendu 0 sur `laravel/storage/` la ou
 *    python rendait 15 — `grep` est ici une fonction enveloppant `ugrep`.* Ce
 *    balayage lit donc les fichiers lui-meme, sans sous-processus.
 *
 * 3. IL DOIT MORDRE, et ca se prouve : on forge la chaine dans un fichier du
 *    perimetre, la suite passe au ROUGE, on retire, elle repasse au VERT.
 *    **Une assertion dont personne n'a vu le rouge est une assertion dont
 *    personne ne sait si elle regarde.**
 *
 * ══ CE QU'IL NE FAIT PAS ══════════════════════════════════════════════════
 *
 * Il ne dit pas qu'un jeton est absent du DEPOT — seulement des repertoires
 * declares. Et il ne juge pas la PROSE : une occurrence dans un commentaire ou
 * une documentation compte comme une occurrence. *C'est deliberé pour un nom de
 * cle i18n, dont la reapparition dans un commentaire est deja un signal ; ca ne
 * conviendrait pas a un jeton dont la prose parle legitimement.*
 *
 *   usage :  node tests/e2e/jetons-interdits.mjs
 *   sortie :  0 = aucun jeton interdit trouve, et le balayage a bien eu lieu
 *             1 = au moins un jeton interdit est present
 *             2 = l'instrument n'a pas pu mesurer -> NE RIEN CONCLURE
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const RACINE = new URL('../../', import.meta.url).pathname;
/* Ce fichier lui-meme : il porte les chaines qu'il cherche. */
const MOI = new URL(import.meta.url).pathname;

/*
 * ⚠ LA LISTE EST DONNEE AVEC SA PORTEE, jamais seule. Un jeton sans portee
 * produirait un verdict dont on ne saurait pas de quoi il parle.
 *
 * `temoin` est la chaine qui DOIT etre trouvee dans la meme portee : c'est elle
 * qui distingue « rien trouve » de « rien lu ».
 */
const INTERDITS = [
    {
        /*
         * ⚠ LE JETON SE CONSTRUIT, IL NE S'ECRIT PAS — et ce n'est pas une
         * coquetterie. Premier jet : la chaine etait ecrite en clair ici et
         * dans la prose de l'en-tete. **Le controle s'est trouve LUI-MEME**,
         * a rendu rouge, et nommait `jetons-interdits.mjs:9`.
         *
         * Le remede evident etait d'exclure ce fichier du balayage. Je l'ai
         * ecarte : **une exclusion est un trou permanent qu'on ouvre pour un
         * cas, et qui reste ouvert pour tous les suivants.** En construisant
         * le jeton, le fichier ne le CONTIENT pas — la portee reste totale et
         * rien n'a besoin d'etre excepte.
         */
        jeton: ['socle', 'avertissement'].join('_'),
        portee: ['laravel/lang', 'laravel/resources/views', 'tests/e2e'],
        temoin: 'etape_identifiants',
        raison: 'Cle i18n retiree le 2026-09-07 ; sa reapparition defait la decision.',
    },
];

/* Ce qu'on ne lit jamais : ni etat d'execution, ni dependance, ni binaire. */
const IGNORES = [/\/node_modules\//, /\/vendor\//, /\/\.git\//, /\/storage\/framework\//,
                 /\/screenshots\//, /\.(png|jpg|jpeg|gif|ico|pdf|zip|woff2?)$/i];

function fichiers(depart) {
    const out = [];
    const pile = [depart];
    while (pile.length) {
        const d = pile.pop();
        let entrees;
        try { entrees = readdirSync(d, { withFileTypes: true }); } catch { continue; }
        for (const e of entrees) {
            const p = join(d, e.name);
            if (IGNORES.some((m) => m.test(p))) continue;
            if (e.isDirectory()) { pile.push(p); continue; }
            try { if (statSync(p).size > 2_000_000) continue; } catch { continue; }
            out.push(p);
        }
    }

    return out;
}

let echecs = 0;
let indispo = false;

for (const regle of INTERDITS) {
    console.log(`\n══ jeton interdit : ${regle.jeton}`);
    console.log(`   raison : ${regle.raison}`);
    console.log(`   PORTEE DECLAREE : ${regle.portee.join(' · ')}`);

    const lus = [];
    for (const p of regle.portee) lus.push(...fichiers(join(RACINE, p)));

    /*
     * TEMOIN 1 — le balayage a-t-il seulement eu lieu ? Une portee mal ecrite,
     * un repertoire renomme, un filtre trop large : tous rendent zero fichier,
     * et zero fichier rend zero occurrence.
     */
    if (lus.length === 0) {
        console.log(`   ⛔ AUCUN FICHIER LU dans la portee declaree.`);
        console.log(`      « 0 occurrence » et « je n'ai rien lu » sont la meme sortie.`);
        console.log(`      NE RIEN CONCLURE : verifier que les chemins existent.`);
        indispo = true;
        continue;
    }

    let trouves = [];
    let temoinVu = 0;
    for (const f of lus) {
        let t;
        try { t = readFileSync(f, 'utf8'); } catch { continue; }
        if (t.includes(regle.jeton)) {
            const n = t.slice(0, t.indexOf(regle.jeton)).split('\n').length;
            trouves.push(`${f.replace(RACINE, '')}:${n}`);
        }
        /*
         * ⚠ LE TEMOIN NE SE COMPTE PAS LUI-MEME, et c'est ce fichier qui a
         * failli rendre le garde inerte.
         *
         * `regle.temoin` est ECRIT ici, en clair — il le faut bien. Ce fichier
         * etant dans la portee `tests/e2e`, il porte donc TOUJOURS la chaine, et
         * `temoinVu` valait au moins 1 quoi qu'il arrive. **Le garde cense
         * detecter un temoin muet ne pouvait jamais se declencher.**
         *
         * Mesure du 2026-09-07 : temoin remplace par `zzz-temoin-introuvable`,
         * une chaine qui n'existe nulle part — le controle a rendu
         * « temoin present dans 1 fichier » et code 0. **Il se citait lui-meme.**
         *
         * Contrairement au JETON, qu'on a rendu inexprimable en le construisant,
         * le temoin doit rester litteral pour etre cherche. On l'exclut donc du
         * COMPTE — et de ce compte seulement : la recherche du jeton interdit,
         * elle, reste totale.
         */
        if (f !== MOI && t.includes(regle.temoin)) temoinVu++;
    }

    console.log(`   fichiers lus : ${lus.length}`);

    /*
     * TEMOIN 2 — le balayage LIT-IL VRAIMENT le contenu ? Un fichier ouvert mais
     * mal decode, un encodage inattendu, une lecture qui echoue en silence : le
     * compte de fichiers serait bon et le contenu vide.
     */
    console.log(`   temoin « ${regle.temoin} » : ${temoinVu} fichier(s)`);
    if (temoinVu === 0) {
        console.log(`   ⛔ TEMOIN MUET — la chaine qui DOIT etre presente est introuvable.`);
        console.log(`      Le balayage compte des fichiers mais ne lit pas leur contenu,`);
        console.log(`      ou la portee ne couvre plus le fichier qui la porte.`);
        console.log(`      NE RIEN CONCLURE.`);
        indispo = true;
        continue;
    }

    if (trouves.length) {
        console.log(`   ⛔ PRESENT dans ${trouves.length} fichier(s) :`);
        for (const t of trouves) console.log(`        ${t}`);
        console.log(`      Ce jeton a ete retire par decision. Sa reapparition la defait.`);
        echecs++;
    } else {
        console.log(`   ✓ ABSENT de la portee declaree — ${lus.length} fichiers lus,`
            + ` temoin present dans ${temoinVu}.`);
    }
}

console.log('');
if (indispo) {
    console.log('INSTRUMENT INDISPONIBLE — au moins une regle n\'a pas pu etre mesuree.');
    process.exit(2);
}
if (echecs) {
    console.log(`${echecs} jeton(s) interdit(s) PRESENT(S). Ce n'est pas une regression de code :`);
    console.log('c\'est une decision defaite, et elle se defait sans qu\'aucun test ne rougisse');
    console.log('ailleurs. C\'est pour ca que ce controle existe.');
    process.exit(1);
}
console.log('Aucun jeton interdit dans les portees declarees, et le balayage a eu lieu.');
process.exit(0);
