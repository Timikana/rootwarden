/*
 * ═══ TOUT REPERTOIRE PHP SERVI DOIT ETRE COUVERT PAR `sca-php` ════════════
 *
 * HORS-LOT: controle statique du depot, sans navigateur, sans session, sans
 * requete. A jouer avant une fusion, ou depuis la CI.
 *
 * ══ LE DEFAUT QU'IL EMPECHE ════════════════════════════════════════════════
 *
 * Le 2026-09-09, `sca-php` est passe de `for d in laravel legacy` a
 * `for d in laravel` dans le commit qui archivait le legacy. La decision etait
 * juste — plus rien du legacy n'est servi — mais **898 fichiers de dependances
 * tierces ont cesse d'etre audites, et rien dans le depot ne le dit.**
 *
 * > Un job vert ne dit pas ce qu'il a CESSE de couvrir.
 *
 * Le jour ou quelqu'un remet `legacy/` en service, il herite de ces 898
 * fichiers sans qu'aucun controle les regarde. Ce fichier est le gardien de
 * cette consequence.
 *
 * ══ IL DERIVE, IL NE RECITE PAS ════════════════════════════════════════════
 *
 * On pourrait comparer `sca-php` a une liste ecrite a la main des repertoires a
 * scanner. **Elle se perimerait comme tout inventaire recite** — et c'est
 * exactement ainsi que le trou s'est ouvert : une liste (`for d in …`) a ete
 * modifiee sans que sa raison d'etre soit verifiee.
 *
 * L'ensemble SERVI est donc derive de ses sources :
 *
 *     montages hote des `docker-compose*.yml`     - ./x:/dans/le/conteneur
 *     sources des `COPY` des Dockerfile
 *
 * puis on remonte de chaque chemin servi vers sa RACINE COMPOSER (le repertoire
 * lui-meme ou un ancetre portant un `composer.json`). L'ensemble SCANNE est
 * derive du `for d in …` de `ci.yml`.
 *
 *     la garde echoue quand une racine composer SERVIE n'est pas SCANNEE
 *
 * ⚠ Consequence voulue de la derivation : les dix `composer.json` sous
 * `.claude/skills/php-modern/fixtures/` ne sont NI montes NI copies, donc jamais
 * comptes comme servis. Une liste ecrite a la main aurait eu a les excepter un
 * par un, et chaque exception aurait ete un trou permanent ouvert pour un cas.
 *
 * ⚠ ET `legacy/_deprecated/composer.json` EST SUIVI PAR GIT. C'est ce qui rend
 * la decision reversible dans les deux sens — et ce qui rend cette garde utile :
 * remettre le legacy en service est un geste possible, pas hypothetique.
 *
 * ══ LE DOMAINE DE CETTE GARDE, NOMME PLUTOT QUE SUPPOSE ═══════════════════
 *
 * **Un gage se juge sur son PUITS et son DOMAINE, pas sur sa qualite.** Celui-ci
 * ne dit RIEN de :
 *
 *   · la qualite de `sca-php` sur ce qu'il scanne — un scanner casse resterait
 *     vert ici, puisqu'on ne mesure que la COUVERTURE ;
 *   · les dependances servies autrement qu'en montage ou en `COPY` (une image
 *     construite ailleurs, un artefact telecharge au demarrage) ;
 *   · les ecosystemes non-PHP.
 *
 * Ces limites sont imprimees dans le verdict, pas seulement ici : un lecteur
 * n'ouvre pas le fichier avant de croire une ligne de sortie.
 *
 * ⚠ ET LA LECTURE DES YAML EST LIGNE A LIGNE, pas un vrai analyseur. Un montage
 * ecrit en forme longue (`type: bind` / `source:`) lui echapperait. Le controle
 * exige donc de TROUVER des montages : zero montage vu rend une abstention, pas
 * un vert — sans quoi un changement de forme desarmerait la garde en silence.
 *
 *   usage :  node tests/e2e/sca-couvre-le-servi.mjs
 *   sortie :  0 = tout ce qui est servi est scanne
 *             1 = une racine composer servie n'est pas scannee
 *             2 = l'instrument n'a pas pu mesurer -> NE RIEN CONCLURE
 */
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';

const RACINE = new URL('../../', import.meta.url).pathname.replace(/\/$/, '');

/*
 * ⚠ SURCHARGE ANNONCEE, pour la contre-epreuve seulement. Muter les vrais
 * `docker-compose*.yml` pour eprouver cette garde reviendrait a ecrire dans le
 * socle d'autres sessions ; on travaille sur une copie, et le verdict PORTE la
 * mention — un vert obtenu sur une copie se lirait sinon comme un vert du depot.
 */
const SURCHARGE = process.env.RW_SCA_RACINE;
const BASE = SURCHARGE ? SURCHARGE.replace(/\/$/, '') : RACINE;
if (SURCHARGE) {
    console.log('');
    console.log('⚠⚠ RACINE SURCHARGEE — ce verdict NE PORTE PAS sur le depot :');
    console.log(`      ${BASE}`);
    console.log('   Cette surcharge sert a eprouver la garde, jamais a la conclure.');
}

const lis = (p) => { try { return readFileSync(p, 'utf8'); } catch { return null; } };

/* ── ① L'ENSEMBLE SERVI, derive des montages et des COPY ─────────────────── */

const composes = readdirSync(BASE).filter((f) => /^docker-compose.*\.ya?ml$/.test(f));
const cheminsServis = new Map();   /* chemin relatif -> d'ou on le tient */
let montagesVus = 0;

for (const f of composes) {
    const t = lis(join(BASE, f));
    if (t === null) continue;
    for (const ligne of t.split('\n')) {
        if (/^\s*#/.test(ligne)) continue;
        /* forme courte : `- ./hote:/conteneur[:ro]` */
        const m = ligne.match(/^\s*-\s+(\.\/[^:\s]+)\s*:/);
        if (! m) continue;
        montagesVus++;
        cheminsServis.set(m[1].replace(/^\.\//, ''), `${f} (montage)`);
    }
}

/*
 * ⚠ LES DOCKERFILE SONT DERIVES DES `build:` DES COMPOSE, PAS BALAYES.
 *
 * Premier jet : je cherchais `Dockerfile*` dans l'arbre. Deux faux positifs, et
 * les deux disaient la meme chose :
 *
 *   .claude/skills/php-modern  <- backend/Dockerfile, `COPY ./ /app`
 *   legacy/_deprecated         <- legacy/_deprecated/php/Dockerfile
 *
 * ① **Une source de `COPY` est relative au CONTEXTE DE BUILD, pas a la racine
 *    du depot.** `build: ./backend` donne un contexte `backend/`, donc `COPY ./`
 *    designe `backend/` — et non l'arbre entier. Resolue depuis la racine, elle
 *    ramassait tous les `composer.json` du depot, fixtures comprises.
 *
 * ② **Un Dockerfile que personne ne bati ne sert rien.** Celui sous
 *    `legacy/_deprecated/php/` est dans l'archive : le trouver revenait a
 *    declarer servi ce qu'on venait d'archiver.
 *
 * > Un fichier de construction n'est pas une preuve de service : ce qui sert est
 * > ce qu'un compose BATIT, avec le contexte qu'il DECLARE. Balayer l'arbre
 * > confond « present » et « employe ».
 *
 * Les deux faux positifs alarmaient — donc ils se sont fait voir. Le meme defaut
 * dans l'autre sens (un contexte plus large que declare) aurait DEDOUANE, et
 * rien ne l'aurait signale.
 */
const construits = [];   /* { contexte, dockerfile } */
for (const f of composes) {
    const t = lis(join(BASE, f));
    if (t === null) continue;
    const lg = t.split('\n');
    for (let i = 0; i < lg.length; i++) {
        const l = lg[i];
        if (/^\s*#/.test(l)) continue;
        /* forme scalaire : `build: ./backend` */
        const scal = l.match(/^\s*build\s*:\s*(\S+)\s*$/);
        if (scal) {
            const ctx = scal[1].replace(/^\.\//, '').replace(/\/$/, '') || '.';
            construits.push({ contexte: ctx, dockerfile: join(ctx === '.' ? '' : ctx, 'Dockerfile') });
            continue;
        }
        /* forme mapping : `build:` puis `context:` / `dockerfile:` */
        if (! /^\s*build\s*:\s*$/.test(l)) continue;
        const ind = (l.match(/^(\s*)/) || ['', ''])[1].length;
        let ctx = '.', df = null;
        for (let j = i + 1; j < lg.length; j++) {
            const k = (lg[j].match(/^(\s*)/) || ['', ''])[1].length;
            if (lg[j].trim() === '') continue;
            if (k <= ind) break;
            const mc = lg[j].match(/^\s*context\s*:\s*(\S+)/);
            const md = lg[j].match(/^\s*dockerfile\s*:\s*(\S+)/);
            if (mc) ctx = mc[1].replace(/^\.\//, '').replace(/\/$/, '') || '.';
            if (md) df = md[1].replace(/^\.\//, '');
        }
        construits.push({ contexte: ctx, dockerfile: df ?? join(ctx === '.' ? '' : ctx, 'Dockerfile') });
    }
}

let copiesVues = 0;
for (const { contexte, dockerfile } of construits) {
    const t = lis(join(BASE, dockerfile));
    if (t === null) continue;
    for (const ligne of t.split('\n')) {
        const m = ligne.match(/^\s*COPY\s+(?:--[^\s]+\s+)*([^\s]+)\s+[^\s]+\s*$/);
        if (! m) continue;
        const src = m[1];
        /* `--from=` copie depuis une ETAPE, pas depuis le contexte : hors sujet. */
        if (/--from=/.test(ligne)) continue;
        if (src.startsWith('/')) continue;
        const rel = join(contexte === '.' ? '' : contexte, src.replace(/^\.\//, '')) || '.';
        copiesVues++;
        cheminsServis.set(rel.replace(/\/$/, '') || '.', `${dockerfile} (COPY, contexte ${contexte})`);
    }
}

/* ── ② REMONTER DE CHAQUE CHEMIN SERVI VERS SA RACINE COMPOSER ───────────── */

/*
 * ⚠ LES DEUX SENS, ET LE PREMIER JET N'EN AVAIT QU'UN.
 *
 * Ce resolveur ne remontait que vers l'ANCETRE portant un `composer.json`.
 * Contre-epreuve jouee sur une copie : en remettant `- ./legacy:/var/www/legacy`
 * dans un compose, la garde a rendu **code 0**.
 *
 * Cause : `legacy/composer.json` n'existe pas — la racine composer est un cran
 * PLUS BAS, a `legacy/_deprecated/composer.json`. Le chemin servi ne DESCEND pas
 * d'une racine, il en CONTIENT une.
 *
 * > Monter un repertoire sert tout ce qu'il contient. Une derivation qui ne
 * > remonte que vers les ancetres rate exactement le cas qu'on garde : la remise
 * > en service d'un repertoire ENTIER.
 *
 * **Sans la contre-epreuve, cette garde aurait rendu vert sur le seul scenario
 * pour lequel elle a ete ecrite.** C'est le cas ou une garde est pire que rien :
 * elle occupe la place d'un controle et rassure a sa place.
 *
 * On collecte donc les racines composer A OU AU-DESSUS **et** A OU EN DESSOUS du
 * chemin servi.
 */
const racinesComposer = (rel) => {
    const trouvees = new Set();

    /* sens 1 — vers les ANCETRES : le chemin servi descend d'une racine. */
    let d = rel;
    while (d && d !== '.' && d !== '/') {
        if (existsSync(join(BASE, d, 'composer.json'))) { trouvees.add(d); break; }
        const parent = dirname(d);
        if (parent === d) break;
        d = parent;
    }

    /* sens 2 — vers les DESCENDANTS : le chemin servi contient des racines. */
    (function descend(sous, prof) {
        if (prof > 4) return;
        const abs = join(BASE, sous);
        let e;
        try {
            if (! statSync(abs).isDirectory()) return;
            e = readdirSync(abs, { withFileTypes: true });
        } catch { return; }
        for (const x of e) {
            /* `vendor/` est le RESULTAT d'une installation, pas une racine a
             * scanner : y descendre rendrait une racine par dependance. */
            if (['node_modules', 'vendor', '.git'].includes(x.name)) continue;
            if (x.name === 'composer.json' && ! x.isDirectory()) trouvees.add(sous);
            if (x.isDirectory()) descend(join(sous, x.name), prof + 1);
        }
    })(rel, 0);

    return [...trouvees];
};

const serviesAvecComposer = new Map();
for (const [rel, source] of cheminsServis) {
    for (const r of racinesComposer(rel)) serviesAvecComposer.set(r, source);
}

/* ── ③ L'ENSEMBLE SCANNE, derive du `for d in …` de ci.yml ───────────────── */

const CI = join(BASE, '.github/workflows/ci.yml');
const ci = lis(CI);
if (ci === null) {
    console.log(`\n⛔ ${CI.replace(`${BASE}/`, '')} illisible. NE RIEN CONCLURE.`);
    process.exit(2);
}
const lignesCi = ci.split('\n');
const iSca = lignesCi.findIndex((l) => /^\s*sca-php\s*:/.test(l));
if (iSca < 0) {
    console.log('\n⛔ job `sca-php` introuvable dans ci.yml — renomme ou retire ?');
    console.log('   Une garde qui ne trouve plus son objet ne rend pas un vert.');
    console.log('   NE RIEN CONCLURE.');
    process.exit(2);
}
/* borne du job : la prochaine cle de meme indentation */
const indent = (lignesCi[iSca].match(/^(\s*)/) || ['', ''])[1].length;
let fSca = lignesCi.length;
for (let i = iSca + 1; i < lignesCi.length; i++) {
    const l = lignesCi[i];
    if (l.trim() === '' || /^\s*#/.test(l)) continue;
    const k = (l.match(/^(\s*)/) || ['', ''])[1].length;
    if (k <= indent && /:\s*$/.test(l.trim())) { fSca = i; break; }
}
const corpsSca = lignesCi.slice(iSca, fSca).join('\n');
const mFor = corpsSca.match(/for\s+\w+\s+in\s+([^;\n]+)[;\n]/);
const scannees = mFor
    ? mFor[1].trim().split(/\s+/).filter((x) => x && ! x.startsWith('$'))
    : [];

console.log(`\nPORTEE : depot ${BASE.replace(process.env.HOME ?? '~', '~')}`);
console.log(`  compose lus      : ${composes.length}  [${composes.join(' ')}]`);
console.log(`  montages hote    : ${montagesVus}`);
console.log(`  images BATIES par les compose : ${construits.length}   COPY retenus : ${copiesVues}`);
console.log(`  job sca-php      : lignes ${iSca + 1}..${fSca}`);
console.log('  repertoires scannes (derives du for..in) : ' + (scannees.join(' ') || '(aucun)'));

/*
 * TEMOINS — zero sur la sonde ET zero sur le temoin veut dire « la mesure n'a
 * pas eu lieu », jamais « l'objet est absent ». Chacun de ces trois ensembles
 * DOIT etre non vide : un depot sans montage, sans racine composer servie ou
 * sans repertoire scanne est un depot qu'on ne sait pas mesurer.
 */
const muets = [];
if (construits.length === 0) muets.push('aucun `build:` trouve dans les compose');
if (montagesVus === 0) muets.push('aucun montage hote trouve dans les compose (forme longue `type: bind` ?)');
if (scannees.length === 0) muets.push('aucun repertoire dans le `for d in …` de sca-php');
if (serviesAvecComposer.size === 0) muets.push('aucune racine composer SERVIE trouvee');
if (muets.length) {
    console.log('\n⛔ INSTRUMENT MUET :');
    for (const m of muets) console.log(`   ${m}`);
    console.log('   Un zero sur la sonde ET sur le temoin signifie que la mesure n\'a pas');
    console.log('   eu lieu. NE RIEN CONCLURE.');
    process.exit(2);
}

console.log(`\nRACINES COMPOSER SERVIES : ${serviesAvecComposer.size}`);
for (const [r, source] of [...serviesAvecComposer].sort()) {
    const couvert = scannees.includes(r);
    console.log(`  ${couvert ? '✓' : '⛔'} ${r.padEnd(28)} ${couvert ? 'scannee' : 'NON SCANNEE'}   <- ${source}`);
}

/* Les racines composer du depot qui ne sont PAS servies : information, pas verdict. */
const toutes = [];
(function cherche(d, prof) {
    if (prof > 4) return;
    let e;
    try { e = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const x of e) {
        if (['node_modules', 'vendor', '.git'].includes(x.name)) continue;
        const p = join(d, x.name);
        if (x.isDirectory()) { cherche(p, prof + 1); continue; }
        if (x.name === 'composer.json') toutes.push(dirname(p).replace(`${BASE}/`, '') || '.');
    }
})(BASE, 0);
const nonServies = toutes.filter((r) => ! serviesAvecComposer.has(r));
if (nonServies.length) {
    console.log(`\nRACINES COMPOSER NON SERVIES : ${nonServies.length}  (information, pas verdict)`);
    for (const r of nonServies.slice(0, 6)) console.log(`    ${r}`);
    if (nonServies.length > 6) console.log(`    … et ${nonServies.length - 6} autres`);
    console.log('  Elles ne sont ni montees ni copiees, donc hors du domaine de cette');
    console.log('  garde. C\'est la DERIVATION qui les ecarte, pas une exception ecrite.');
}

const decouvertes = [...serviesAvecComposer].filter(([r]) => ! scannees.includes(r));

console.log('');
console.log('DOMAINE DE CETTE GARDE — ce qu\'elle ne dit PAS :');
console.log('  · rien sur la QUALITE de sca-php sur ce qu\'il scanne (un scanner casse');
console.log('    resterait vert ici : on ne mesure que la COUVERTURE) ;');
console.log('  · rien sur des dependances servies autrement qu\'en montage ou en COPY ;');
console.log('  · rien sur les ecosystemes non-PHP.');

console.log('');
if (decouvertes.length) {
    console.log(`⛔ ${decouvertes.length} RACINE(S) COMPOSER SERVIE(S) ET NON SCANNEE(S) :`);
    for (const [r, source] of decouvertes) {
        const n = existsSync(join(BASE, r, 'composer.lock')) ? 'avec composer.lock' : 'sans composer.lock';
        console.log(`    ${r}   (${n})   servie par ${source}`);
    }
    console.log('');
    console.log('  Ajouter ces repertoires au `for d in …` du job `sca-php`, ou cesser de');
    console.log('  les servir. Un job vert ne dit pas ce qu\'il a cesse de couvrir.');
    process.exit(1);
}
console.log(`Tout ce qui est servi est scanne — ${serviesAvecComposer.size} racine(s) servie(s),`
    + ` toutes dans [${scannees.join(' ')}].`);
process.exit(0);
