/**
 * analyse-appelants.mjs — QUI, DANS LE PORTAGE, APPELLE LE BACKEND, ET TESTE-T-IL
 * LE VERDICT QU'IL REND ?
 *
 * QA-005. Ne dit rien de la garde d'une route — c'est le travail de
 * `InventaireDesGardesTest`. Dit ce que chaque APPELANT SUPPOSE.
 *
 * ── POURQUOI UN ANALYSEUR ET PAS UNE EXPRESSION REGULIERE ────────────────────
 *
 * Un appelant peut consulter `success` de trois facons au moins :
 *   d.success === true            acces par membre
 *   const { success } = await …   destructuration
 *   if (!r.success) …             negation
 *
 * Un motif sur `data.success` manquerait les deux dernieres, et la premiere
 * est justement celle qu'un helper bien ecrit n'emploie pas. Une entree libre de
 * motif se trompe DANS LES DEUX SENS : elle accuse un appelant correct et
 * dedouane un appelant fautif.
 *
 * Ce fichier lit donc le JavaScript avec `acorn`, le meme analyseur que Node.
 * *Compter une structure, c'est la faire lire par son propre langage.*
 *
 * ── CE QU'IL MESURE, ET CE QU'IL NE MESURE PAS ───────────────────────────────
 *
 * Pour chaque appel a `fetch(...)` : la fonction qui l'englobe consulte-t-elle
 * `success` ? consulte-t-elle `.ok` ? Il ne suit PAS la valeur de retour a
 * travers les fonctions — un appelant qui delegue son controle a un helper est
 * donc juge sur le helper, ce qui est le comportement voulu : c'est bien le
 * helper qui decide.
 *
 * Son verdict n'est pas un jugement : `success: false` sur une route de LECTURE
 * pure n'est pas un defaut. Le document QA le tranche cas par cas.
 *
 * Usage : NODE_PATH=/usr/share/nodejs node analyse-appelants.mjs [dossier]
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join, basename } from 'node:path';
import { createRequire } from 'node:module';

const require_ = createRequire(import.meta.url);
let acorn;
try {
    acorn = require_('acorn');
} catch {
    // ECHOUER FORT PLUTOT QUE RENDRE UN RESULTAT VIDE. Un analyseur qui ne
    // trouve pas son analyseur doit le DIRE : un relevé vide se lit comme
    // « aucun appelant fautif », qui est la conclusion la plus dangereuse.
    console.error("acorn introuvable. NODE_PATH=/usr/share/nodejs, ou `npm i acorn`.");
    process.exit(2);
}

const dossier = process.argv[2] || 'laravel/public/js';

/** Parcourt un arbre acorn en appelant `visite(noeud, parents)`. */
function parcours(noeud, visite, parents = []) {
    if (!noeud || typeof noeud.type !== 'string') return;
    visite(noeud, parents);
    const suite = [...parents, noeud];
    for (const cle of Object.keys(noeud)) {
        if (cle === 'type' || cle === 'start' || cle === 'end' || cle === 'loc') continue;
        const valeur = noeud[cle];
        if (Array.isArray(valeur)) valeur.forEach((v) => parcours(v, visite, suite));
        else if (valeur && typeof valeur.type === 'string') parcours(valeur, visite, suite);
    }
}

const EST_FONCTION = new Set([
    'FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression',
]);

/** Le nom lisible de la fonction englobante la plus proche. */
function nomDeFonction(parents) {
    for (let i = parents.length - 1; i >= 0; i--) {
        const n = parents[i];
        if (!EST_FONCTION.has(n.type)) continue;
        if (n.id?.name) return n.id.name;
        const p = parents[i - 1];
        if (p?.type === 'VariableDeclarator' && p.id?.name) return p.id.name;
        if (p?.type === 'Property' && p.key?.name) return p.key.name;
        return '(anonyme)';
    }
    return '(module)';
}

/** La fonction englobante la plus proche, ou le programme. */
function fonctionEnglobante(parents, programme) {
    for (let i = parents.length - 1; i >= 0; i--) {
        if (EST_FONCTION.has(parents[i].type)) return parents[i];
    }
    return programme;
}

/** `success` est-il consulte quelque part sous ce noeud ? */
function consulte(noeud, nom) {
    let vu = false;
    parcours(noeud, (n) => {
        if (vu) return;
        // r.success
        if (n.type === 'MemberExpression' && !n.computed && n.property?.name === nom) vu = true;
        // r['success']
        if (n.type === 'MemberExpression' && n.computed && n.property?.value === nom) vu = true;
        // const { success } = ...
        if (n.type === 'Property' && n.key?.name === nom
            && (n.value?.type === 'Identifier' || n.value?.type === 'AssignmentPattern')) vu = true;
        // 'success' in r
        if (n.type === 'BinaryExpression' && n.operator === 'in' && n.left?.value === nom) vu = true;
    });
    return vu;
}

/**
 * La fonction REND-ELLE le corps analyse a son appelant ?
 *
 * Distinction decisive, et la premiere version ne la faisait pas : un helper qui
 * transmet le corps ne « manque » pas le controle de `success`, il le DELEGUE.
 * Le compter comme fautif serait la faute que ce chantier paie le plus souvent —
 * un motif plus LARGE que la propriete, qui accuse un appelant correct.
 *
 * ── ET LA PREMIERE VERSION DE CETTE FONCTION ETAIT DEJA TROP ETROITE ─────────
 *
 * Elle cherchait un `return` contenant litteralement un appel `.json()`. Or
 * `approbations.js` fait :
 *
 *     let corpsJson = null;
 *     try { corpsJson = await r.json(); } catch (e) {}
 *     return { ok: r.ok, statut: r.status, corps: corpsJson };
 *
 * — le corps est bien transmis, par une VARIABLE. Le motif etroit rendait donc
 * « ignore » sur un helper correct : une accusation. Corrige en suivant les noms
 * lies a `.json()` jusqu'aux `return`. *Un motif qui suppose une forme d'ecriture
 * ne mesure que cette forme.*
 */
function rendLeCorps(fonction) {
    // 1. les noms lies au corps analyse
    //
    // LA BRANCHE JUMELLE, et elle a ete oubliee au premier passage. `litUnFlux`
    // venait d'apprendre a reconnaitre `JSON.parse` ; celle-ci ne le savait pas,
    // si bien que `pare-feu.js` passait de « flux » a « ignore » — d'un faux
    // dedouanement a une fausse accusation, sans jamais etre juste.
    // *Chercher la branche jumelle est une regle de ce chantier.*
    const noms = new Set();
    parcours(fonction, (n) => {
        const estJson = (e) => {
            let vu = false;
            parcours(e, (m) => {
                if (m.type !== 'CallExpression' || m.callee?.type !== 'MemberExpression') return;
                if (m.callee.property?.name === 'json') vu = true;
                if (m.callee.object?.name === 'JSON' && m.callee.property?.name === 'parse') vu = true;
            });
            return vu;
        };
        if (n.type === 'VariableDeclarator' && n.id?.type === 'Identifier'
            && n.init && estJson(n.init)) noms.add(n.id.name);
        if (n.type === 'AssignmentExpression' && n.left?.type === 'Identifier'
            && estJson(n.right)) noms.add(n.left.name);
    });

    // 2. un `return` qui transmet, soit le corps directement, soit l'un de ces noms
    let vu = false;
    parcours(fonction, (n) => {
        if (vu || n.type !== 'ReturnStatement' || !n.argument) return;
        parcours(n.argument, (m) => {
            if (m.type === 'CallExpression' && m.callee?.type === 'MemberExpression') {
                if (m.callee.property?.name === 'json') vu = true;
                if (m.callee.object?.name === 'JSON' && m.callee.property?.name === 'parse') vu = true;
            }
            if (m.type === 'Identifier' && noms.has(m.name)) vu = true;
        });
    });
    return vu;
}

/**
 * La reponse est-elle lue comme un FLUX de texte plutot que comme du JSON ?
 *
 * Troisieme resserrement de cet analyseur, et le troisieme faux positif qu'il
 * ecarte. Plusieurs routes du backend rendent `text/plain` tenu ouvert pendant
 * que la commande tourne : desinstallation, reconfiguration, deploiement,
 * mises a jour, journal de deploiement. `success` n'y existe pas — le verdict
 * se lit DANS le flux, puis se verifie sur la machine (c'est le correctif
 * d'E-90, « une reussite verifiee, pas annoncee »).
 *
 * Les compter comme « ne lit pas le verdict » serait accuser precisement le
 * code qui a ete ecrit pour ne plus croire une annonce.
 *
 * ── ET CE RESSERREMENT A D'ABORD ETE TROP LARGE ──────────────────────────────
 *
 * Sa premiere version cherchait un appel a `.text()` n'importe ou dans la
 * fonction. Or `cles-ssh.js` lit `rep.text()` dans sa branche d'ERREUR, pour
 * afficher le message d'un refus — la reponse normale, elle, est du JSON. Le
 * preflight de deploiement de cles etait donc classe « flux », c'est-a-dire
 * DEDOUANE, alors qu'il est justement le cas le plus interessant du relevé.
 *
 * Le premier motif accusait des appelants corrects ; celui-ci en dedouanait un
 * fautif. **Un motif trop large se trompe dans les deux sens, et la seconde
 * erreur est la plus couteuse : un vert ne se relit pas.**
 *
 * ── ET UNE TROISIEME FORME, QUE NI L'UN NI L'AUTRE NE VOYAIT ─────────────────
 *
 * Un flux se lit aussi — et surtout — par `reponse.body.getReader()`. Deux
 * appelants le font, et ils lisent en plus du JSON dans leur branche d'ERREUR
 * (un 423 hors fenetre de maintenance, par exemple). Ni « du texte et jamais de
 * JSON » ni « du JSON » ne les classait juste.
 *
 * ── ET UNE QUATRIEME FORME, TROUVEE LE 2026-08-27 PAR LE DECLENCHEUR ────────
 *
 * `pare-feu.js` lit `r.text()` puis `JSON.parse(brut)` — deliberement, pour
 * distinguer « la reponse n'est pas du JSON » de « elle l'est ». Ce n'est PAS un
 * flux : c'est une lecture JSON par un autre chemin. La regle « du texte et
 * jamais de `.json()` » le classait donc `flux`, c'est-a-dire DEDOUANE.
 *
 * **Deuxieme faux NEGATIF de cette fonction, et le plus instructif** : il n'est
 * pas venu d'une relecture mais du declencheur, qui a signale un fichier neuf et
 * m'a fait regarder. Un instrument se corrige par ce qu'il rencontre, pas par ce
 * qu'on imagine.
 *
 * Regle finale, et elle se lit dans cet ordre :
 *   1. un `getReader()`               -> c'est un flux, quoi que fasse la branche d'erreur ;
 *   2. sinon, un `.json()` OU un `JSON.parse` -> ce n'est PAS un flux ;
 *   3. sinon, du texte -> c'est un flux ;
 *   4. sinon -> ce n'est pas un flux.
 */
function litUnFlux(fonction) {
    let texte = false;
    let json = false;
    let lecteur = false;
    parcours(fonction, (n) => {
        if (n.type !== 'CallExpression') return;
        // `JSON.parse(...)` : une lecture JSON qui ne passe pas par `.json()`.
        if (n.callee?.type === 'MemberExpression'
            && n.callee.object?.name === 'JSON'
            && n.callee.property?.name === 'parse') json = true;
        if (n.callee?.type !== 'MemberExpression') return;
        const nom = n.callee.property?.name;
        if (nom === 'text') texte = true;
        if (nom === 'json') json = true;
        if (nom === 'getReader') lecteur = true;
    });
    return lecteur || (texte && !json);
}

/** Le texte source d'un noeud, tronque. */
function source(code, noeud, max = 70) {
    const t = code.slice(noeud.start, noeud.end).replace(/\s+/g, ' ');
    return t.length > max ? t.slice(0, max - 1) + '…' : t;
}

const appels = [];
const fichiers = readdirSync(dossier).filter((f) => f.endsWith('.js')).sort();

for (const nom of fichiers) {
    const chemin = join(dossier, nom);
    const code = readFileSync(chemin, 'utf8');
    let arbre;
    try {
        arbre = acorn.parse(code, { ecmaVersion: 2022, locations: true, sourceType: 'script' });
    } catch (e) {
        // ── UN FICHIER ILLISIBLE SE DIT — ET IL NE SE DISAIT PAS ────────────
        //
        // Ce commentaire affirmait deja cette propriete, et elle etait FAUSSE :
        // l'entree partait sans `verdict`, donc elle n'entrait ni dans
        // `a_examiner` ni dans aucun total. Un fichier qui cesse d'etre analysable
        // voyait donc TOUS ses appelants disparaitre du releve en silence —
        // c'est-a-dire etre EXONERES.
        //
        // Une affirmation de commentaire n'est pas une propriete. Celle-ci en est
        // une maintenant : le verdict `illisible` entre dans la liste a examiner,
        // donc il fait rougir le declencheur PHPUnit, qui la fige.
        //
        // Trouve le 2026-08-28 en appliquant a mon propre instrument la question
        // que la session 7 s'est posee sur le sien : *avais-je mute ce qu'il
        // attrape, ou aussi ce qu'il laisse passer ?*
        appels.push({ fichier: nom, ligne: 0, fonction: '(ILLISIBLE)', cible: e.message,
                      success: false, ok: false, verdict: 'illisible' });
        continue;
    }

    parcours(arbre, (n, parents) => {
        const estFetch = n.type === 'CallExpression'
            && ((n.callee.type === 'Identifier' && n.callee.name === 'fetch')
                || (n.callee.type === 'MemberExpression' && n.callee.property?.name === 'fetch'));
        if (!estFetch) return;

        const englobante = fonctionEnglobante(parents, arbre);
        const verifie = consulte(englobante, 'success');
        const flux = !verifie && litUnFlux(englobante);
        const delegue = !verifie && !flux && rendLeCorps(englobante);
        appels.push({
            fichier: nom,
            ligne: n.loc.start.line,
            fonction: nomDeFonction(parents),
            cible: n.arguments[0] ? source(code, n.arguments[0]) : '(sans argument)',
            success: verifie,
            ok: consulte(englobante, 'ok'),
            // `verifie`  : cette fonction lit le verdict elle-meme
            // `delegue`  : elle rend le corps analyse, son appelant decidera
            // `ignore`   : ni l'un ni l'autre — personne ne lit le verdict ici
            verdict: verifie ? 'verifie' : (flux ? 'flux' : (delegue ? 'delegue' : 'ignore')),
        });
    });
}

// Un fichier qui ne prononce JAMAIS `success` ne peut pas avoir delegue a
// quelqu'un qui le lit : la delegation y est une impasse. On le mesure a part.
const consultePar = {};
for (const nom of fichiers) {
    const code = readFileSync(join(dossier, nom), 'utf8');
    try {
        const arbre = acorn.parse(code, { ecmaVersion: 2022, sourceType: 'script' });
        consultePar[nom] = consulte(arbre, 'success');
    } catch { consultePar[nom] = false; }
}
for (const a of appels) {
    a.fichier_consulte_success = !!consultePar[a.fichier];
    if (a.verdict === 'delegue' && !a.fichier_consulte_success) a.verdict = 'delegue_sans_lecteur';
}

const parVerdict = (v) => appels.filter((a) => a.verdict === v);

// ── LE PLANCHER : en dessous, c'est l'INSTRUMENT qui est casse ──────────────
//
// Une enumeration qui rend le vide satisfait toutes les proprietes universelles.
// Si l'analyseur ne trouve presque plus d'appels — chemin change, acorn absent,
// `glob` qui ne voit plus rien — il doit ECHOUER, pas rendre un releve rassurant.
//
// La valeur est un PLANCHER, pas un compte : elle ne se remesure pas a chaque
// portage. Elle vaut environ la moitie de ce qui est mesure aujourd'hui, de sorte
// qu'une baisse legitime ne la touche jamais et qu'une panne la traverse.
const PLANCHER_APPELS = 30;
if (appels.length < PLANCHER_APPELS) {
    console.error(`analyse-appelants : ${appels.length} appels trouves, sous le `
        + `plancher de ${PLANCHER_APPELS}. L'analyseur ne voit plus le portage — `
        + `ce n'est pas un releve, c'est une panne.`);
    process.exit(3);
}
const sortie = {
    fichiers: fichiers.length,
    appels: appels.length,
    verifie: parVerdict('verifie').length,
    flux: parVerdict('flux').length,
    delegue: parVerdict('delegue').length,
    delegue_sans_lecteur: parVerdict('delegue_sans_lecteur').length,
    ignore: parVerdict('ignore').length,
    detail: appels,
};

// ── L'INSTANTANE ────────────────────────────────────────────────────────────
//
// Ecrit ce que l'analyseur a compris, PLUS l'empreinte de chaque fichier lu.
// C'est cette empreinte que le test PHPUnit compare : PHP ne sait pas analyser
// du JavaScript, et lui faire deviner la syntaxe reviendrait a reecrire un
// analyseur — la faute meme que ce fichier existe pour eviter.
//
// Le test ne dit donc jamais « cet appelant est fautif ». Il dit « ce fichier a
// change depuis le dernier examen » et nomme la commande a rejouer. Le verdict
// vient de l'analyseur ; le test n'est qu'un declencheur d'examen.
if (process.argv.includes('--instantane')) {
    const { createHash } = await import('node:crypto');
    const empreintes = {};
    for (const nom of fichiers) {
        empreintes[nom] = createHash('sha256')
            .update(readFileSync(join(dossier, nom))).digest('hex').slice(0, 16);
    }
    console.log(JSON.stringify({
        genere_par: 'laravel/tests/Outils/analyse-appelants.mjs --instantane',
        dossier,
        totaux: {
            fichiers: sortie.fichiers, appels: sortie.appels,
            verifie: sortie.verifie, flux: sortie.flux, delegue: sortie.delegue,
            delegue_sans_lecteur: sortie.delegue_sans_lecteur, ignore: sortie.ignore,
            illisible: parVerdict('illisible').length,
        },
        empreintes,
        // `illisible` en fait partie : un fichier qu'on ne sait plus lire est le
        // cas le plus urgent a regarder, pas le plus discret.
        a_examiner: appels.filter((a) => a.verdict === 'ignore'
                                      || a.verdict === 'delegue_sans_lecteur'
                                      || a.verdict === 'illisible'),
    }, null, 2));
} else if (process.argv.includes('--json')) {
    console.log(JSON.stringify(sortie, null, 2));
} else {
    console.log(`${fichiers.length} fichiers, ${appels.length} appels a fetch`);
    console.log(`  verifie              ${sortie.verifie}  (lit le verdict lui-meme)`);
    console.log(`  flux                 ${sortie.flux}  (reponse text/plain : \`success\` n'y existe pas)`);
    console.log(`  delegue              ${sortie.delegue}  (rend le corps, un appelant du fichier lit \`success\`)`);
    console.log(`  delegue_sans_lecteur ${sortie.delegue_sans_lecteur}  (rend le corps, et PERSONNE dans le fichier ne lit \`success\`)`);
    console.log(`  ignore               ${sortie.ignore}  (ne lit ni le verdict ni ne le transmet)\n`);
    for (const a of appels) {
        console.log(`[${a.verdict.padEnd(20)}] ${a.fichier}:${a.ligne} ${a.fonction}() -> ${a.cible}`);
    }
}
