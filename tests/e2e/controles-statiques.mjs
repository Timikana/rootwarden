/*
 * ═══ LE LANCEUR DES CONTROLES STATIQUES ═══════════════════════════════════
 *
 * HORS-LOT: lance les controles en LECTURE SEULE du depot. Aucun navigateur,
 * aucune requete, aucune machine jointe, aucune ecriture.
 *
 * ══ LE DEFAUT QU'IL EMPECHE ════════════════════════════════════════════════
 *
 * Sept controles statiques existent dans `tests/e2e/`, chacun invocable par son
 * nom. Mesure du 2026-09-09 : **quatre d'entre eux sont cites par AUCUN autre
 * fichier du depot.** Ils existent, ils sont verts, et personne ne les joue.
 *
 *     releve-chemins-passerelle   cite par 0 fichier
 *     vues-compilees-en-root      cite par 0 fichier
 *     sca-couvre-le-servi         cite par 0 fichier
 *     go-cron-validation-forgee   cite par 0 fichier
 *
 * C'est le meme defaut que celui que `sca-couvre-le-servi` garde, applique au
 * corpus qui le contient : **un controle que rien n'appelle est une decoration,
 * et rien dans le depot ne dit qu'il existe.**
 *
 * ══ ⚠ POURQUOI LA LISTE EST ECRITE ET NON DERIVEE ══════════════════════════
 *
 * Partout ailleurs aujourd'hui la regle a ete : **deriver plutot que reciter.**
 * Ici elle ne s'applique pas, et la raison est mesurable.
 *
 * Premier jet : deriver l'ensemble « sans effet » par « ne contient ni `fetch(`
 * ni `docker` ni `execFileSync` ». Resultat sur le code DEPOUILLE de ses
 * commentaires :
 *
 *     liens-morts-legacy.mjs        -> « effets: reseau »   FAUX
 *     releve-chemins-passerelle.mjs -> « effets: reseau »   FAUX
 *
 * Les deux sont des lecteurs de fichiers purs. Ils sont signales parce que leur
 * code CHERCHE la chaine `fetch(` — c'est leur objet meme. Le premier porte
 * `motif: /fetch\(\s*['"\`](\/[^'"\`?]*)/g`, le second `chemins(t, 'fetch(PASSERELLE +')`.
 *
 * > Un analyseur d'appels reseau est plein des mots qu'il cherche. Depouiller
 * > les commentaires ne suffit pas : le motif est dans le CODE, en donnee.
 *
 * Un vrai discriminant demanderait un analyseur syntaxique — `fetch(` dans un
 * litteral de chaine n'est pas un noeud d'appel — et Node n'en embarque pas.
 * **Une liste ecrite dont on sait pourquoi elle est ecrite vaut mieux qu'une
 * derivation dont on ne sait pas ce qu'elle rate.**
 *
 * ══ CE QUI REMPLACE LA DERIVATION : UNE PARTITION QUI PEUT ROUGIR ══════════
 *
 * La liste ecrite se perimerait en silence — c'est ce qu'on lui reproche
 * partout ailleurs. On l'accompagne donc d'un invariant : **tout fichier
 * `HORS-LOT:` de `tests/e2e/` doit etre dans L'UNE des deux listes.** Un
 * controle ajoute demain sans etre classe fait ROUGIR ce lanceur.
 *
 * L'oubli produit alors un echec bruyant, jamais un controle discretement non
 * joue — et c'est le sens sur.
 *
 *   usage :  node tests/e2e/controles-statiques.mjs
 *   sortie :  0 = tous les controles passent, et la partition couvre tout
 *             1 = un controle a echoue, ou la partition est incomplete
 *             2 = un controle s'est ABSTENU -> NE RIEN CONCLURE de celui-la
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const RACINE = new URL('../../', import.meta.url).pathname.replace(/\/$/, '');
const D = 'tests/e2e';

/*
 * ⚠ CE QUE CE LANCEUR JOUE : lecture seule, sans exception.
 *
 * Chaque entree porte ce que le controle garde. Ajouter un controle ici est un
 * geste DELIBERE — et ne pas l'y ajouter le laisse hors partition, donc rouge.
 */
const LECTURE_SEULE = [
    ['jetons-interdits',          'un jeton retire par decision ne reapparait pas'],
    ['liens-morts-legacy',        'aucun fichier legacy servi ne pointe vers une cible archivee'],
    ['inventaire-hors-lot',       'toute suite hors lot porte une raison declaree'],
    ['releve-chemins-passerelle', 'quels chemins de passerelle sont reellement appeles'],
    ['vues-compilees-en-root',    'aucune vue compilee en root n\'arme un 500'],
    ['sca-couvre-le-servi',       'tout repertoire PHP servi est scanne par sca-php'],
    ['go-cron-validation-forgee', 'la validation cron.d refuse le forge et accepte le nominal'],
];

/*
 * ⚠ ET CE QU'IL NE JOUE JAMAIS, avec le motif du refus. Ces fichiers portent
 * `HORS-LOT:` comme les autres — **l'absence de navigateur ne vaut pas absence
 * d'effet**, et c'est l'erreur que ce lanceur a failli commettre : un premier
 * predicat « pas de puppeteer + HORS-LOT » les selectionnait tous.
 */
const JAMAIS = [
    ['go-audit-ssh-scan-machine3', 'ouvre une session SSH et ecrit en base ; autorisation nominative'],
    ['go-ssh-audit-scanall',       'joint la PRODUCTION'],
    ['go-cve-schedules',           'PLANIFICATION — interdite jusqu\'a arbitrage'],
    ['go-ssh-audit-schedules',     'PLANIFICATION — interdite jusqu\'a arbitrage'],
    ['go-page-audit-ssh-planif',   'PLANIFICATION — interdite jusqu\'a arbitrage'],
    ['go-security',                'emet des scans ; portee nulle mais effet reseau'],
    ['test-full-deploy',           'DEPLOIE un agent ; cible nominative obligatoire'],
    ['open-supervision',           'ouvre un navigateur VISIBLE, sans assertion'],
    ['go-policies',                'suite de page, navigateur'],
    ['go-wazuh',                   'suite de page, navigateur'],
    ['go-page-notifications-portee', 'suite de page, navigateur'],
    ['go-page-profil-rgpd',        'suite de page, navigateur'],
    ['go',                         'balayage legacy, navigateur ; objet archive'],
];

/* ── ① LA PARTITION COUVRE-T-ELLE TOUS LES `HORS-LOT:` ? ─────────────────── */

const horsLot = readdirSync(`${RACINE}/${D}`)
    .filter((f) => f.endsWith('.mjs'))
    .filter((f) => {
        try { return /HORS-LOT:/.test(readFileSync(`${RACINE}/${D}/${f}`, 'utf8')); }
        catch { return false; }
    })
    .map((f) => f.replace(/\.mjs$/, ''))
    .filter((n) => n !== 'controles-statiques');

const classes = new Set([...LECTURE_SEULE.map(([n]) => n), ...JAMAIS.map(([n]) => n)]);
const nonClasses = horsLot.filter((n) => ! classes.has(n));
const fantomes = [...classes].filter((n) => ! existsSync(`${RACINE}/${D}/${n}.mjs`));

console.log(`PARTITION : ${horsLot.length} fichier(s) HORS-LOT dans ${D}/`);
console.log(`  lecture seule declaree : ${LECTURE_SEULE.length}`);
console.log(`  jamais joues ici       : ${JAMAIS.length}`);

/*
 * TEMOIN — un depot sans fichier HORS-LOT est un depot qu'on ne sait pas
 * mesurer, pas un depot sain. Zero sur la sonde ET sur le temoin veut dire que
 * la mesure n'a pas eu lieu.
 */
if (horsLot.length === 0) {
    console.log('\n⛔ AUCUN fichier HORS-LOT trouve — le marqueur a-t-il change de forme ?');
    console.log('   NE RIEN CONCLURE.');
    process.exit(2);
}

let partitionCassee = false;
if (nonClasses.length) {
    console.log(`\n⛔ ${nonClasses.length} FICHIER(S) HORS-LOT NON CLASSE(S) :`);
    for (const n of nonClasses) console.log(`     ${n}`);
    console.log('   Classer chacun dans LECTURE_SEULE (avec ce qu\'il garde) ou dans');
    console.log('   JAMAIS (avec le motif du refus). Un controle non classe n\'est pas');
    console.log('   joue, et rien ne le dirait sans cette assertion.');
    partitionCassee = true;
}
if (fantomes.length) {
    console.log(`\n⛔ ${fantomes.length} ENTREE(S) SANS FICHIER :`);
    for (const n of fantomes) console.log(`     ${n}  (renomme ou supprime ?)`);
    console.log('   Une liste qui nomme un fichier absent donne une couverture apparente.');
    partitionCassee = true;
}

/* ── ② LES CONTROLES ─────────────────────────────────────────────────────── */

console.log('');
const resultats = [];
for (const [nom, garde] of LECTURE_SEULE) {
    let code, sortie = '';
    try {
        sortie = execFileSync('node', [`${D}/${nom}.mjs`],
            { cwd: RACINE, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
        code = 0;
    } catch (e) {
        code = typeof e.status === 'number' ? e.status : -1;
        sortie = `${e.stdout ?? ''}${e.stderr ?? ''}`;
    }
    /* La derniere ligne non vide : c'est le verdict que le controle a redige. */
    const verdict = sortie.split('\n').filter((l) => l.trim()).pop() ?? '(aucune sortie)';
    const etat = code === 0 ? 'OK ' : (code === 2 ? 'ABST' : 'ECHEC');
    resultats.push({ nom, code, garde, verdict });
    console.log(`  ${etat.padEnd(6)}[${code}] ${nom}`);
    console.log(`         garde : ${garde}`);
    console.log(`         ${verdict.slice(0, 108)}`);
}

const echoues = resultats.filter((r) => r.code === 1 || r.code === -1);
const abstenus = resultats.filter((r) => r.code === 2);

console.log('');
console.log(`${resultats.length} controle(s) joues — ${resultats.length - echoues.length - abstenus.length} OK,`
    + ` ${echoues.length} en echec, ${abstenus.length} abstention(s).`);
console.log('');
console.log('DOMAINE DE CE LANCEUR — ce qu\'il ne dit PAS :');
console.log('  · rien sur les suites a navigateur, qui ne sont pas jouees ici ;');
console.log('  · rien sur la JUSTESSE de chaque controle — il rapporte leur verdict,');
console.log('    il ne le verifie pas ; un controle vert a tort reste vert ici ;');
console.log('  · la liste LECTURE_SEULE est ECRITE, pas derivee — voir l\'en-tete :');
console.log('    un analyseur d\'appels reseau est plein des mots qu\'il cherche.');

console.log('');
if (partitionCassee) {
    console.log('PARTITION INCOMPLETE — des controles existent sans etre classes, donc');
    console.log('sans etre joues. C\'est le defaut que ce lanceur existe pour empecher.');
    process.exit(1);
}
if (abstenus.length) {
    console.log(`${abstenus.length} controle(s) se sont ABSTENUS : NE RIEN CONCLURE de ceux-la.`);
    for (const r of abstenus) console.log(`   ${r.nom}`);
    process.exit(2);
}
if (echoues.length) {
    console.log(`${echoues.length} controle(s) en ECHEC :`);
    for (const r of echoues) console.log(`   ${r.nom} (code ${r.code}) — ${r.garde}`);
    process.exit(1);
}
console.log('Tous les controles statiques passent, et la partition couvre tous les HORS-LOT.');
process.exit(0);
