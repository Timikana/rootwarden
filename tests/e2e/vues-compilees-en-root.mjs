/*
 * ═══ UNE VUE COMPILEE EN ROOT ARME UN 500 QUE PERSONNE NE RELIERA A SA CAUSE ══
 *
 * HORS-LOT: controle statique du cache Blade, sans navigateur ni session ni
 * requete. A jouer AVANT un lot, pas dedans.
 *
 * ══ LE DEFAUT ══════════════════════════════════════════════════════════════
 *
 * Laravel compile ses vues dans `storage/framework/views` et rafraichit un
 * compile par comparaison de `mtime`, via un `touch()`. Si le compile
 * appartient a `root` et que le processus PHP tourne en `www-data`, ce `touch()`
 * echoue — et la page rend 500.
 *
 * `docker-entrypoint.sh:44` lance `php artisan view:cache` EN ROOT, puis la l.59
 * repare avec `chown -R www-data:www-data storage/framework/views`. **Mais ce
 * chown ne tourne qu'au DEMARRAGE.** Tout `artisan` lance en root ensuite —
 * a la main, dans un script, depuis un `docker exec` — recree des compiles root
 * qu'aucun chown ne rattrape.
 *
 * Mesure du 2026-09-08 : 7 compiles sur 65 appartiennent a `root:root`, dates du
 * 2026-09-07 22:29, soit ~25 h APRES le demarrage du conteneur.
 *
 * ══ POURQUOI CE CONTROLE PLUTOT QU'UN CHOWN ════════════════════════════════
 *
 * Un `chown` repare l'etat ; il ne dit pas qu'il y avait quelque chose a
 * reparer, et il demande des droits que ce harnais n'a pas a prendre. Ce
 * controle CONSTATE, et il nomme la cause — parce que le cout reel du defaut
 * n'est pas le 500, c'est le temps passe a le chercher ailleurs.
 *
 * `PIEGE-CACHE-BLADE.md` documente l'incident du 2026-09-03 : 111 compiles sur
 * 151 en root, **28 pages d'erreur en sept minutes**, et la cause dans un chown
 * d'entrypoint vieux de deux jours.
 *
 * > Un 500 dont la cause est un proprietaire de fichier ne ressemble pas a un
 * > probleme de droits : il ressemble a une regression de la page.
 *
 * ══ DEUX ETATS, ET C'EST LA DISTINCTION QUI COMPTE ═════════════════════════
 *
 *     ARME    le compile root est PLUS VIEUX que sa source
 *             -> la prochaine requete tente le touch(), echoue, rend 500
 *     LATENT  le compile root est PLUS NEUF que sa source
 *             -> aucun 500 aujourd'hui, mais la premiere modification de la
 *                source l'arme
 *
 * ⚠ Un verdict qui ne distinguerait pas les deux serait inutilisable : rouge en
 * permanence sur un parc sain, donc ignore. **Un garde-fou qui se declenche a
 * tort ne protege plus : il empeche.**
 *
 *   usage :  node tests/e2e/vues-compilees-en-root.mjs
 *   sortie :  0 = aucun compile arme  (les LATENTS sont signales, pas fatals)
 *             1 = au moins un 500 est ARME
 *             2 = l'instrument n'a pas pu mesurer -> NE RIEN CONCLURE
 */
import { readdirSync, statSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const RACINE = new URL('../../', import.meta.url).pathname;
const VUES = join(RACINE, 'laravel/storage/framework/views');
const SOURCES = join(RACINE, 'laravel');

/*
 * ⚠ LE PROPRIETAIRE ATTENDU EST DERIVE DU REPERTOIRE, JAMAIS ECRIT EN DUR.
 *
 * Ecrire `33` (www-data sur Debian) ou le nom `www-data` supposerait l'image.
 * Le repertoire `views/` appartient a l'utilisateur qui doit posseder son
 * contenu : on lit SA valeur, et tout fichier qui s'en ecarte est suspect.
 *
 * Une liste rendue depuis sa source ne se perime pas quand l'image change.
 */
let attendu;
let fichiers;
try {
    attendu = statSync(VUES).uid;
    fichiers = readdirSync(VUES).filter((f) => f.endsWith('.php'));
} catch (e) {
    console.log(`⛔ ${VUES.replace(RACINE, '')} illisible : ${e.code || e.message}`);
    console.log('   Le conteneur a-t-il demarre au moins une fois ? NE RIEN CONCLURE.');
    process.exit(2);
}

console.log(`PORTEE : laravel/storage/framework/views — ${fichiers.length} compile(s)`);
console.log(`PROPRIETAIRE ATTENDU : uid ${attendu}, lu sur le repertoire lui-meme`);

/*
 * TEMOIN 1 — « aucun compile en retard » et « je n'ai lu aucun fichier » sont la
 * meme sortie. Une boucle qui n'imprime rien se lit comme un parc sain.
 */
if (fichiers.length === 0) {
    console.log('\n⛔ AUCUN COMPILE LU. Ce n\'est pas « le cache est sain » : c\'est');
    console.log('   « le cache est vide ou illisible ». NE RIEN CONCLURE.');
    process.exit(2);
}

/* Le PATH que Laravel inscrit en pied de chaque compile. */
const source = (chemin) => {
    let t;
    try { t = readFileSync(chemin, 'utf8'); } catch { return null; }
    const m = t.match(/PATH\s+(\S+?)\s+ENDPATH/) || t.match(/PATH\s+(\S+)/);
    if (! m) return null;

    return m[1].replace(/^\/var\/www\/html\//, '');
};

const armes = [];
const latents = [];
const sansSource = [];
let conformes = 0;
let sourcesResolues = 0;

for (const f of fichiers) {
    const p = join(VUES, f);
    let st;
    try { st = statSync(p); } catch { continue; }
    const rel = source(p);
    if (rel !== null && existsSync(join(SOURCES, rel))) sourcesResolues++;
    if (st.uid === attendu) { conformes++; continue; }

    /* A partir d'ici : le compile n'appartient PAS a l'utilisateur attendu. */
    if (rel === null) { sansSource.push(`${f}  (uid ${st.uid}, source non declaree)`); continue; }
    const abs = join(SOURCES, rel);
    if (! existsSync(abs)) { sansSource.push(`${rel}  (uid ${st.uid}, source absente)`); continue; }
    const mtimeSource = statSync(abs).mtimeMs;
    const ligne = `${rel}  (uid ${st.uid})`;
    if (mtimeSource > st.mtimeMs) armes.push(ligne);
    else latents.push(ligne);
}

/*
 * TEMOIN 2 — l'uid attendu est-il celui de QUELQUE CHOSE ? Si aucun fichier ne
 * lui correspond, la valeur lue sur le repertoire ne decrit pas son contenu, et
 * « 7 fichiers suspects » pourrait etre « 65 fichiers suspects » mal comptes.
 */
console.log(`  conformes a l'uid attendu : ${conformes}`);
if (conformes === 0) {
    console.log('\n⛔ AUCUN compile n\'appartient a l\'uid du repertoire.');
    console.log('   La reference est donc fausse, et tout paraitrait suspect.');
    console.log('   NE RIEN CONCLURE.');
    process.exit(2);
}

/*
 * TEMOIN 3 — le pied `PATH` est-il lisible ? Sans lui, aucun compile ne se
 * relie a une source, et tout tomberait en « source non declaree » : le
 * controle rendrait vert faute de pouvoir comparer quoi que ce soit.
 */
console.log(`  compiles relies a une source existante : ${sourcesResolues}`);
if (sourcesResolues === 0) {
    console.log('\n⛔ AUCUN compile ne se relie a une source. Le pied « PATH … » a-t-il');
    console.log('   change de forme ? Sans lui, rien ne peut etre compare. NE RIEN CONCLURE.');
    process.exit(2);
}

if (sansSource.length) {
    console.log(`\nCOMPILES SUSPECTS SANS SOURCE RESOLUE : ${sansSource.length}`);
    console.log('  Ils ne sont PAS comptes comme armes — on ne sait pas les comparer.');
    for (const s of sansSource) console.log(`    ${s}`);
}

if (latents.length) {
    console.log(`\n⚠ ${latents.length} COMPILE(S) EN ROOT, PAS ENCORE ARME(S) :`);
    for (const l of latents) console.log(`    ${l}`);
    console.log('  Le compile est plus neuf que sa source, donc aucun 500 aujourd\'hui.');
    console.log('  **La premiere modification d\'une de ces vues l\'arme**, et si la vue');
    console.log('  est un composant du socle, toutes les pages qui l\'incluent rendent 500.');
}

console.log('');
if (armes.length) {
    console.log(`⛔ ${armes.length} 500 ARME(S) — le compile est PLUS VIEUX que sa source :`);
    for (const a of armes) console.log(`    ${a}`);
    console.log('');
    console.log('  La prochaine requete tentera un touch() qui echouera. Ce n\'est pas une');
    console.log('  regression de la page : c\'est un proprietaire de fichier.');
    console.log('');
    console.log('  Remede (hors de ce harnais, demande des droits) :');
    console.log('    sudo chown -R www-data:www-data laravel/storage/framework/views');
    process.exit(1);
}
console.log(`Aucun 500 arme — ${fichiers.length} compile(s) lus, ${conformes} conformes,`
    + ` ${latents.length} latent(s).`);
process.exit(0);
