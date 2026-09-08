/*
 * ═══ QUELS CHEMINS DE PASSERELLE SONT REELLEMENT APPELES ══════════════════
 *
 * HORS-LOT: releve statique du portage, sans navigateur ni session. Il ne joue
 * aucune page et n'emet aucune requete.
 *
 * ══ A QUOI IL SERT ════════════════════════════════════════════════════════
 *
 * `laravel/app/Support/RoutesBackend.php` autorise la passerelle par PREFIXE.
 * Son propre commentaire le dit : `/groups` autorise `/groupsecret`. Resserrer
 * demande de savoir quels sous-chemins sont VRAIMENT appeles — sinon un ancrage
 * exact coupe des gestes qui marchent.
 *
 * **Une liste rendue DEPUIS sa source vaut mieux qu'une seconde liste a
 * maintenir** : celle-ci se recalcule, elle ne se met pas a jour.
 *
 * ══ TROIS CHOSES QU'UN RELEVE NAIF RATE, LES TROIS MESUREES ═══════════════
 *
 * 1. **LES NOMS DE HELPERS NE SONT PAS UNIFORMES.** 13 noms distincts
 *    (`appelle` `lis` `lit` `litGet` `litDistant` `agit` `agitParc` `ecris`
 *    `supprime` `verseLeFlux` `verseLeJson` `appellePortage` `resout`). Suivre
 *    les trois de `groupes.js` en raterait dix.
 *
 *    ⚠ Et l'inverse rate aussi : relever les `fetch` trouve les DEFINITIONS des
 *    helpers, pas les gestes qu'ils portent. Une session a conclu « un seul site
 *    d'appel pour un module entier » sur ce releve-la ; les appels de `groupes.js`
 *    sont a 341, 391, 431, 478, 521, 575, 619, 773. **Les deux bouts menent a la
 *    meme conclusion fausse.**
 *
 * 2. **CERTAINS FICHIERS APPELLENT `fetch(PASSERELLE + '<litteral>')` SANS
 *    HELPER** — `cle-plateforme.js` cinq fois, `serveurs.js`, `docker.js:235`,
 *    `audit-ssh.js:180`, `recherche-menu.js:138`, `distants-cles.js:81`.
 *
 * 3. **⚠ ET LE PHP INJECTE DES URL DANS LES VUES.** 9 chemins passent par
 *    `url('/api/gateway/…')` dans `laravel/app/`, et HUIT sont absents du releve
 *    JS — dont `/supervision/scan-all` et `/cve_scan`. Un resserrage fonde sur le
 *    seul JS couperait ces huit. Ce releve fait donc l'UNION des deux sources.
 *
 * ══ CE QU'IL NE VOIT PAS ══════════════════════════════════════════════════
 *
 * Un chemin construit ENTIEREMENT a l'execution, sans aucun segment litteral.
 * Le releve rend alors le prefixe seul, ou rien. Declare plutot que mal corrige.
 *
 *   usage :  node tests/e2e/releve-chemins-passerelle.mjs [/prefixe]
 *   sortie :  0 = releve rendu · 2 = l'instrument n'a pas pu mesurer
 */
import { readFileSync, readdirSync } from 'node:fs';
const JS = 'laravel/public/js/';

/*
 * ⚠ LES NOMS DE HELPERS SONT DECOUVERTS, PAS SUPPOSES. Mesure : 41 definitions
 * et 14 noms distincts. Suivre les trois de `groupes.js` en raterait 38.
 */
const fichiers = readdirSync(JS).filter((f) => f.endsWith('.js'));

/*
 * ⚠ LE NOM NE SUFFIT PAS : IL FAUT QUE LE CORPS CITE `PASSERELLE` — et le
 * discriminant est par FICHIER, pas par nom.
 *
 * Premier jet : toute fonction prenant un parametre `chemin` etait tenue pour un
 * helper de passerelle. Quatorze noms, dont QUATRE qui ne touchent pas la
 * passerelle : `appellePortage` (les routes du portage lui-meme), `resout` (la
 * resolution de liens legacy), `verseLeJson`, et `appelle` DANS CERTAINS
 * FICHIERS SEULEMENT.
 *
 * Le releve rendait donc `/pare-feu/copie`, `/pare-feu/historique`,
 * `/pare-feu/version` et `/profil/step-up` comme des chemins de PASSERELLE.
 * **Ce sont des routes NATIVES du portage** — le nom `appellePortage` le dit.
 *
 * ⚠ ET LE MEME NOM EST LES DEUX SELON LE FICHIER : `appelle` cite `PASSERELLE`
 * dans une dizaine de modules et ne la cite pas ailleurs. Un ensemble global de
 * noms ne peut donc pas trancher — la question « ce nom est-il un helper de
 * passerelle » n'a pas de reponse hors d'un fichier.
 *
 * > Un helper ne se reconnait pas a son nom ni a la forme de ses parametres,
 * > mais a ce qu'il APPELLE. Et deux fichiers peuvent donner le meme nom a deux
 * > gestes differents sans que rien ne s'en plaigne.
 *
 * Direction de l'erreur : elle SURESTIMAIT les chemins de passerelle, donc elle
 * aurait fait GARDER des prefixes inutiles — le sens inoffensif. Elle n'aurait
 * pas fait couper. Ca ne la rend pas juste : les 41 prefixes annonces n'etaient
 * pas 41 prefixes de passerelle.
 */
function helpersDe(t) {
    const out = new Set();
    for (const m of t.matchAll(/function\s+([A-Za-zéèà]+)\s*\(\s*chemin/g)) {
        const deb = m.index + m[0].length;
        const suivante = t.indexOf('\n    function ', deb);
        const corps = t.slice(deb, suivante > 0 ? suivante : deb + 1200);
        if (corps.includes('PASSERELLE')) out.add(m[1]);
    }

    return out;
}
const noms = new Set();
for (const f of fichiers) {
    const t = readFileSync(JS + f, 'utf8');
    if (! t.includes('/api/gateway')) continue;
    for (const n of helpersDe(t)) noms.add(n);
}

/*
 * ⚠ ET ON GARDE TOUS LES SEGMENTS LITTERAUX D'UNE CONCATENATION, pas le premier.
 * `'/groups/' + encodeURIComponent(id) + '/members'` vaut `/groups/{}/members`,
 * jamais `/groups/`. Un releve qui perd le suffixe classe deux gestes comme un.
 */
function chemins(t, quoi, motEntier) {
    const out = [];
    const ouvre = motEntier ? `${quoi}(` : quoi;
    const positions = [];
    if (motEntier) {
        for (const m of t.matchAll(new RegExp(`(?<![\\w$])${quoi}\\s*\\(`, 'g'))) {
            positions.push(m.index + m[0].length - 1);
        }
    } else {
        let k = 0;
        while ((k = t.indexOf(ouvre, k)) !== -1) { positions.push(k + ouvre.length - 1); k += ouvre.length; }
    }
    for (const p of positions) {
        const i = p;
        let j = i + 1, prof = 1, arg = '';
        while (j < t.length && prof > 0) {
            const c = t[j];
            if (c === '(') prof++;
            else if (c === ')') { prof--; if (prof === 0) break; }
            else if (c === ',' && prof === 1) break;
            arg += c; j++;
        }
        const segs = [...arg.matchAll(/['"`]([^'"`]*)['"`]/g)].map((m) => m[1]);
        const dyn = /[A-Za-z_$][\w$]*\s*(\(|\.)|\+\s*[A-Za-z_$]/.test(arg);
        if (segs.length && segs[0].startsWith('/')) {
            /*
             * ⚠ UN SEUL SEGMENT SUIVI D'UNE PARTIE DYNAMIQUE se rendait comme un
             * littéral pur : `supprime('/groups/' + encodeURIComponent(id))`
             * donnait `/groups/`, indiscernable d'un chemin fixe. Le `{}` final
             * doit etre AJOUTE, pas seulement intercale — sinon le geste DELETE
             * par identifiant disparait du releve.
             */
            let rendu = segs.join('{}');
            const finitParLitteral = /['"`]\s*\)?\s*$/.test(arg.trimEnd());
            if (dyn && ! finitParLitteral) rendu += '{}';
            out.push(rendu);
        }
    }

    return out;
}

const parPrefixe = new Map();
let sitesVus = 0;
for (const f of fichiers) {
    const t = readFileSync(JS + f, 'utf8');
    if (! t.includes('/api/gateway')) continue;
    /*
     * ⚠ LES HELPERS SONT CEUX DE CE FICHIER, et l'appel est cherche avec une
     * FRONTIERE DE MOT. `indexOf('lis(')` matchait `remplis(`, `etablis(` ;
     * `lit(` matchait `remplit(` et `traduit(` — donc des lectures i18n prises
     * pour des appels de passerelle. Elles ne ressortaient pas dans le verdict
     * parce que leurs arguments ne commencent pas par `/`, mais elles gonflaient
     * le COMPTE de sites.
     */
    const trouves = [];
    for (const n of helpersDe(t)) trouves.push(...chemins(t, n, true));
    trouves.push(...chemins(t, 'fetch(PASSERELLE +', false));  /* les fetch DIRECTS */
    for (const c of trouves) {
        sitesVus++;
        const pref = '/' + c.replace(/^\//, '').split(/[/?{]/)[0];
        if (! parPrefixe.has(pref)) parPrefixe.set(pref, new Set());
        parPrefixe.get(pref).add(`${c}   (${f})`);
    }
}

/*
 * ⚠ LA SECONDE SOURCE : les URL que le PHP injecte dans les vues. Elles ne
 * passent par aucun helper JS, donc par aucun motif ci-dessus.
 */
const APP = 'laravel/app/';
function phpRecursif(d) {
    const out = [];
    for (const e of readdirSync(d, { withFileTypes: true })) {
        const p = d + e.name;
        if (e.isDirectory()) { out.push(...phpRecursif(p + '/')); continue; }
        if (e.name.endsWith('.php')) out.push(p);
    }

    return out;
}
let sitesPhp = 0;
for (const f of phpRecursif(APP)) {
    const t = readFileSync(f, 'utf8');
    for (const m of t.matchAll(/url\(\s*['"]\/api\/gateway(\/[^'"]*)['"]\s*\)/g)) {
        sitesPhp++;
        const c = m[1];
        const pref = '/' + c.replace(/^\//, '').split(/[/?{]/)[0];
        if (! parPrefixe.has(pref)) parPrefixe.set(pref, new Set());
        parPrefixe.get(pref).add(`${c}   (${f.replace(APP, 'app/')}, injecte par PHP)`);
    }
}

/*
 * TEMOIN — un releve vide et un instrument casse sont la meme sortie. On exige
 * les deux sources : le JS seul a deja produit une conclusion fausse une fois.
 */
if (sitesVus === 0 || sitesPhp === 0 || noms.size === 0) {
    console.log('⛔ RELEVE INCOMPLET — au moins une source rend zero :');
    console.log(`   helpers decouverts : ${noms.size}`);
    console.log(`   sites JS           : ${sitesVus}`);
    console.log(`   sites PHP injectes : ${sitesPhp}`);
    console.log('   Un releve partiel donne pour complet fait resserrer une liste');
    console.log('   blanche sur des chemins manquants. NE RIEN CONCLURE.');
    process.exit(2);
}

console.log(`sites PHP injectes         : ${sitesPhp}`);
console.log(`noms de helpers decouverts : ${noms.size}  [${[...noms].join(' ')}]`);
console.log(`sites de chemin releves    : ${sitesVus}`);
console.log(`prefixes distincts         : ${parPrefixe.size}\n`);
const cible = process.argv[2];
for (const [p, s] of [...parPrefixe].sort()) {
    if (cible && p !== cible) continue;
    console.log(`══ ${p}   (${s.size} chemin(s))`);
    for (const c of [...s].sort()) console.log(`     ${c}`);
}
