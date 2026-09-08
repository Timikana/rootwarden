/*
 * ═══ AUCUN FICHIER LEGACY SERVI NE POINTE VERS UNE CIBLE ARCHIVEE ═════════
 *
 * HORS-LOT: controle statique, sans navigateur ni session. Il se joue seul ou
 * depuis un crochet, pas dans une moitie du LOT.
 *
 * ══ LE DEFAUT QU'IL REMPLACE ══════════════════════════════════════════════
 *
 * Le 2026-09-08, `legacy/menu.php` portait 38 liens vers le legacy dont
 * **TRENTE-QUATRE visaient une cible archivee**. Le fichier enonçait la regle
 * qu'il enfreignait, cinq lignes au-dessus du premier lien mort :
 *
 *     « un menu qui mene nulle part est le defaut qu'on corrige,
 *       pas celui qu'on installe »
 *
 * La correction a ete un `git diff` relu ligne a ligne. **Ca ne tient pas entre
 * les tours** — et chaque archivage suivant recree le meme risque chez ceux qui
 * restent.
 *
 * ══ TROIS EXIGENCES, ET LA TROISIEME EST CELLE QUI DECIDE ═════════════════
 *
 * 1. PLUSIEURS FORMES DE LIEN. Une seule rend un zero qui ne veut rien dire :
 *    une treizieme entree manquante d'une table de redirection a ete trouvee
 *    parce qu'elle vivait sur un `href` la ou le balayage ne lisait que les
 *    `sideLink`. On lit ici `sideLink('/x')`, `href="/x"`, `window.location`
 *    et `fetch('/x')`.
 *
 * 2. « ARCHIVEE » N'EST PAS « N'A JAMAIS EXISTE ». Le disque ne distingue pas :
 *    un chemin absent l'est des deux façons. La presence sous
 *    `legacy/_deprecated/<chemin>` repond a la premiere, et c'est la seule qui
 *    fait un lien MORT par archivage. Un chemin inconnu des deux cotes est
 *    rapporte a part, sans etre compte comme mort : il peut etre servi par une
 *    regle de reecriture que ce controle ne lit pas.
 *
 * 3. ⚠ LE TEMOIN POSITIF. Sans lui, « zero lien mort » et « ma sonde ne lit
 *    rien » sont la MEME sortie. On exige donc que la sonde voie des liens
 *    VIVANTS — il en reste trois au moment ou ceci est ecrit : `/iptables/` et
 *    `/auth/logout.php` deux fois.
 *
 * ══ CE QU'IL NE FAIT PAS, ET LA LIMITE EST DITE PLUTOT QUE CACHEE ═════════
 *
 * Il ne lit ni `require`/`include`, ni les liens construits par concatenation
 * (`'/adm/' + f`), ni ceux qui vivent dans un fichier JS d'un module. **Une
 * sonde d'une autre session a rendu « 0 lien mort » pendant que les 34
 * existaient, parce qu'elle ne lisait que les `require`.** Elle DECLARAIT son
 * angle mort et l'imprimait a chaque execution.
 *
 * **Declarer une espece aveugle evite le FAUX VERDICT, pas le DEFAUT.** La
 * declaration protege le lecteur ; elle ne protege pas le parc. Ce controle
 * imprime donc ses formes lues a chaque execution, pour qu'un vert ne se lise
 * jamais comme « aucun lien mort » mais comme « aucun, dans ces formes-la ».
 *
 *   usage :  node tests/e2e/liens-morts-legacy.mjs
 *   sortie :  0 = aucun lien vers une cible archivee, et la sonde a bien lu
 *             1 = au moins un lien mort
 *             2 = l'instrument n'a pas pu mesurer -> NE RIEN CONCLURE
 */
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';

const RACINE = new URL('../../', import.meta.url).pathname;
/*
 * ⚠ LA PORTEE EST FIXE, ET CE N'EST PAS UNE COMMODITE MANQUANTE.
 *
 * En restreignant `LEGACY` pour eprouver le controle, une classification a
 * DIFFERE du mode complet : `lang/fr/tips.php:7 -> /profile.php` est rendu
 * ARCHIVE sur la portee entiere et VIVANT sur la portee restreinte. Les deux
 * verifications d'existence sont pourtant absolues depuis le correctif
 * ci-dessous, et je n'ai PAS explique l'ecart.
 *
 * **Je retire donc le mode que je n'ai pas su verifier plutot que de le laisser
 * disponible.** Un controle dont un mode se comporte autrement sans qu'on sache
 * pourquoi rend un verdict dont la valeur depend de la façon dont on l'a lance —
 * et personne ne relit un lanceur.
 *
 * Le controle porte sur `legacy/` en entier, ou il est eprouve : rouge sur cas
 * reel, abstention sur temoin muet, abstention sur portee vide.
 */
const LEGACY = join(RACINE, 'legacy');
/*
 * ⚠ L'ARCHIVE EST ABSOLUE, PAS DERIVEE DE LA PORTEE — et c'est une epreuve qui
 * l'a montre. Premier jet : `join(LEGACY, '_deprecated')`. En restreignant la
 * portee a `legacy/lang/fr` pour eprouver le controle, `ARCHIVE` est devenu
 * `legacy/lang/fr/_deprecated`, qui n'existe pas. **`etat()` n'a plus jamais
 * rendu ARCHIVE** : les quatre liens morts de `tips.php` sont passes en
 * INCONNU, qui n'est pas compte, et le verdict est passe au VERT.
 *
 * Une portee plus etroite rendait donc un resultat plus PROPRE, ce qui est le
 * sens exactement inverse de ce qu'on attend. **Un referentiel derive de la
 * portee se deplace avec elle, et le controle mesure alors autre chose sans
 * rien signaler.**
 */
const ARCHIVE = join(RACINE, 'legacy/_deprecated');
const MOI = new URL(import.meta.url).pathname;

/* Les formes de lien reconnues. Imprimees dans le verdict : un vert ne vaut
 * que pour elles. */
const FORMES = [
    { nom: "sideLink('/x')",  motif: /sideLink\(\s*['"](\/[^'"]*)['"]/g },
    { nom: 'href="/x"',       motif: /href\s*=\s*["'](\/[^"']*)["']/g },
    /*
     * ⚠ ELARGI LE 2026-09-08. Ce motif s'appelait `window.location` et exigeait
     * ce prefixe litteral. Mesure : il RATE `location.href = '/x'` (nu),
     * `document.location`, `top.location`, et `.replace('/x')`.
     *
     * Un second motif `location = "/x"` avait ete ajoute puis retire comme
     * « deja couvert par window.location ». **Il ne l'etait pas** : il couvrait
     * un ensemble STRICTEMENT PLUS LARGE. La conclusion tenait — le parc n'a
     * aucune forme nue hors `vendor/`, deja ignore — mais la RAISON etait fausse,
     * et une raison fausse ne se perime pas au meme rythme que son parc.
     *
     * > Deux motifs qui rendent zero sur le parc ne sont pas pour autant
     * > redondants : l'un peut rendre zero parce qu'il est couvert, l'autre
     * > parce que la forme est absente aujourd'hui.
     *
     * Un seul motif dont le grain EST l'objet, plutot que deux dont l'un
     * dedouane l'autre.
     */
    { nom: 'location = "/x"',
      motif: /(?:^|[^\w$.])(?:\w+\.)?location(?:\.href)?\s*(?:=\s*|\.(?:replace|assign)\(\s*)['"](\/[^'"]*)['"]/g },
    { nom: "fetch('/x')",     motif: /fetch\(\s*['"`](\/[^'"`?]*)/g },
    /*
     * ⚠ AJOUTEES LE 2026-09-08, APRES UN DEDOUANEMENT.
     *
     * Cette suite rendait 13 liens morts ; il y en avait 21. Les 8 manquants
     * vivaient dans une TABLE DE ROUTES de raccourcis clavier :
     *
     *     const routes = {c: '/security/', a: '/adm/admin_page.php', ...};
     *     if (routes[e.key]) { window.location.href = routes[e.key]; }
     *
     * La destination atteint bien `location.href` — mais A L'EXECUTION, jamais
     * lexicalement comme `href="..."`. **Le grain de la sonde etait le LITTERAL
     * `href=`, l'objet est la DESTINATION** : huit liens navigables ont donc ete
     * declares propres par un instrument qui fonctionnait.
     *
     * Et l'autre sonde, qui les voyait, en a rate deux autres de la meme ligne :
     * elle excluait la ligne ENTIERE des qu'elle contenait `LARAVEL_URL`, alors
     * qu'une ligne porte un lien rebase ET deux liens morts. **Les deux
     * instruments etaient aveugles aux memes liens, pour deux raisons
     * differentes** — et aucun des deux ne le disait.
     *
     * > Une declaration d'angle mort protege le lecteur ; deux instruments qui
     * > declarent chacun le leur ne couvrent pas pour autant leur union.
     */
    { nom: 'table {k: "/x"}',  motif: /[A-Za-z_$][\w$]*\s*:\s*['"](\/[A-Za-z0-9_.\/-]+)['"]/g },
    /*
     * ⚠ J'AI AJOUTE ICI UN MOTIF `location = "/x"` PUIS JE L'AI RETIRE.
     *
     * `window.location` (ci-dessus) le couvrait deja. Je l'avais ajoute sans lire
     * la liste a laquelle je l'ajoutais — et ma mesure d'extraction avait reproduit
     * MES TROIS motifs a moi en les nommant « les formes de la suite », donc elle
     * ne pouvait pas me montrer les cinq qui existaient.
     *
     * > Reproduire un instrument pour le mesurer mesure la reproduction.
     *
     * Le zero qu'il rendait n'etait donc pas « cette forme est absente du parc » :
     * c'etait « cette forme est deja lue par sa voisine ».
     */
];

const IGNORES = [/\/_deprecated\//, /\/node_modules\//, /\/vendor\//, /\/\.git\//];

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
            if (! /\.(php|js|html)$/.test(p)) continue;
            try { if (statSync(p).size > 2_000_000) continue; } catch { continue; }
            out.push(p);
        }
    }

    return out;
}

/*
 * L'ETAT D'UNE CIBLE, et les trois valeurs sont distinctes — c'est tout l'objet
 * de l'exigence 2. Un `/x/` se resout comme `/x/index.php`, un `/x.php` comme
 * lui-meme.
 */
function etat(chemin) {
    const c = chemin.split('?')[0].split('#')[0].replace(/^\//, '');
    if (! c) return 'RACINE';
    const cible = c.endsWith('.php') ? c : join(c, 'index.php');
    if (existsSync(join(LEGACY, cible))) return 'VIVANT';
    if (existsSync(join(ARCHIVE, cible))) return 'ARCHIVE';

    return 'INCONNU';
}

const lus = fichiers(LEGACY).filter((f) => f !== MOI);
/*
 * ⚠ CHAQUE FORME DOIT PROUVER QU'ELLE MORD, SUR UN ECHANTILLON FORGE.
 *
 * Ajoute le 2026-09-08 : les deux formes venues d'un dedouanement ont ete
 * mesurees juste apres leur ecriture. `table {k: "/x"}` extrayait 1 lien du parc
 * — donc elle mord. **`location = "/x"` en extrayait ZERO.**
 *
 * Zero n'y prouvait rien : la forme du parc est `location.href = routes[e.key]`,
 * une VARIABLE, pas un litteral. Le motif visait donc une forme qui n'existe
 * nulle part aujourd'hui — legitime en prevention, **mais inverifiable**, et une
 * sonde inerte annoncee comme couverture est exactement l'espece qui DEDOUANE.
 *
 * > Un motif qui ne matche rien dans le parc n'est pas faux ; il est NON MESURE.
 * > Et « non mesure » se lit comme « couvert » des qu'on l'imprime dans la liste
 * > des formes lues.
 *
 * D'ou cet echantillon : il ne mesure pas le parc, il mesure L'INSTRUMENT. Une
 * forme qui n'extrait rien d'ici est cassee, et la suite s'arrete a 2 au lieu de
 * rendre un vert que personne ne peut fonder.
 */
const ECHANTILLON = {
    'href="/x"':        '<a href="/temoin-forge.php">x</a>',
    "fetch('/x')":      "fetch('/temoin-forge.php?q=1')",
    'action="/x"':      '<form action="/temoin-forge.php">',
    'table {k: "/x"}':  "const r = {t: '/temoin-forge.php'};",
    "sideLink('/x')":   "sideLink('/temoin-forge.php', 'x')",
    /*
     * ⚠ L'ECHANTILLON EST LA FORME NUE, PAS `window.location.href`.
     *
     * Un echantillon qui n'exerce que le cas facile ne prouve pas l'elargissement :
     * si quelqu'un restreint un jour le motif a `window.`, un echantillon prefixe
     * resterait VERT et l'elargissement serait perdu en silence. Celui-ci echoue.
     */
    'location = "/x"':  "location.href = '/temoin-forge.php';",
};
const inertes = [];
for (const forme of FORMES) {
    const source = ECHANTILLON[forme.nom];
    if (source === undefined) { inertes.push(`${forme.nom} : aucun echantillon forge`); continue; }
    forme.motif.lastIndex = 0;
    const vus = [...source.matchAll(forme.motif)].map((m) => m[1]);
    if (! vus.includes('/temoin-forge.php')) {
        inertes.push(`${forme.nom} : n'extrait pas son propre echantillon (${JSON.stringify(vus)})`);
    }
}
if (inertes.length) {
    console.log('\n⛔ FORME(S) QUI NE MORDENT PAS — l\'instrument ne mesure pas ce qu\'il annonce :');
    for (const i of inertes) { console.log(`   ${i}`); }
    console.log('   NE RIEN CONCLURE.');
    process.exit(2);
}

console.log(`PORTEE DECLAREE : legacy/ (hors _deprecated) — ${lus.length} fichiers lus`);
console.log(`FORMES LUES     : ${FORMES.map((f) => f.nom).join(' · ')}`);
console.log('  un vert ne dit pas « aucun lien mort » : il dit « aucun, dans ces formes-la ».');

if (lus.length === 0) {
    console.log('\n⛔ AUCUN FICHIER LU. « 0 lien mort » et « je n\'ai rien lu » sont la meme');
    console.log('   sortie. NE RIEN CONCLURE.');
    process.exit(2);
}

const morts = [];
const inconnus = [];
let vivants = 0;
for (const f of lus) {
    let t;
    try { t = readFileSync(f, 'utf8'); } catch { continue; }
    for (const forme of FORMES) {
        forme.motif.lastIndex = 0;
        let m;
        while ((m = forme.motif.exec(t)) !== null) {
            const e = etat(m[1]);
            const ligne = t.slice(0, m.index).split('\n').length;
            const ou = `${f.replace(RACINE, '')}:${ligne}`;
            if (e === 'VIVANT' || e === 'RACINE') vivants++;
            else if (e === 'ARCHIVE') morts.push(`${ou}  ->  ${m[1]}  [${forme.nom}]`);
            else inconnus.push(`${ou}  ->  ${m[1]}`);
        }
    }
}

/*
 * ⚠ LE TEMOIN POSITIF, et il vient AVANT le verdict. Une sonde qui ne trouve
 * aucun lien vivant ne mesure rien : ses motifs ne mordent pas, ou la portee a
 * change sous elle. Son « zero lien mort » serait alors vrai a vide.
 */
console.log(`\nTEMOIN POSITIF  : ${vivants} lien(s) vers une cible VIVANTE`);
if (vivants === 0) {
    console.log('⛔ TEMOIN MUET — la sonde ne voit AUCUN lien vivant, alors qu\'il en existe.');
    console.log('   Ses motifs ne mordent pas, ou la portee a change. NE RIEN CONCLURE.');
    process.exit(2);
}

if (inconnus.length) {
    console.log(`\nCIBLES INCONNUES (ni servies, ni archivees) : ${inconnus.length}`);
    console.log('  Elles ne sont PAS comptees comme mortes : une reecriture peut les servir,');
    console.log('  et ce controle ne lit pas les regles de reecriture.');
    for (const i of inconnus.slice(0, 10)) console.log(`    ${i}`);
    if (inconnus.length > 10) console.log(`    … et ${inconnus.length - 10} autres`);
}

console.log('');
if (morts.length) {
    console.log(`⛔ ${morts.length} LIEN(S) VERS UNE CIBLE ARCHIVEE :`);
    for (const m of morts) console.log(`    ${m}`);
    console.log('');
    console.log('Un menu qui mene nulle part est le defaut qu\'on corrige, pas celui qu\'on');
    console.log('installe. Chaque archivage recree ce risque chez ceux qui restent.');
    process.exit(1);
}
console.log(`Aucun lien vers une cible archivee — ${lus.length} fichiers lus,`
    + ` ${vivants} liens vivants vus.`);
process.exit(0);
