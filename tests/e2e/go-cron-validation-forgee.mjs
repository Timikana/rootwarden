/*
 * ═══ LA VALIDATION `cron.d` REFUSE LE FORGE ET ACCEPTE LE NOMINAL ═════════
 *
 * HORS-LOT: controle statique et en-processus. Aucun navigateur, aucune session,
 * AUCUNE REQUETE RESEAU, et surtout AUCUNE PLANIFICATION.
 *
 * ══ CE QU'ON EPROUVE ══════════════════════════════════════════════════════
 *
 * `time` et `date` viennent de `request.json` et atteignaient une ligne de
 * `/etc/cron.d/auto_update_advanced`, ecrite puis suivie d'un
 * `systemctl restart cron`. **Cron execute en root.**
 *
 * `_cron_heure_minute` et `_cron_annee_mois_jour` (backend/routes/updates.py)
 * ferment ce chemin. Cette suite mesure les DEUX SENS :
 *
 *     valeur forgee    ne doit JAMAIS ressortir sous forme de chaine
 *     valeur nominale  `14:30` DOIT etre acceptee
 *
 * > Un garde dont seuls les refus sont verts peut refuser TOUT, la valeur
 * > legitime comprise, et le vert des refus ne le montrerait pas.
 *
 * ══ ⚠ LA PROPRIETE N'EST PAS « REFUSE LES SAUTS DE LIGNE » ════════════════
 *
 * C'est l'assertion que j'allais ecrire, et elle est FAUSSE. Mesure :
 *
 *     '14:30'            -> ACCEPTE (14, 30)
 *     '14:30\n'          -> ACCEPTE (14, 30)      <- un saut de ligne PASSE
 *     '14:30\ncurl evil' -> REFUSE
 *
 * `int()` ignore les blancs de bord, donc `int('30\n')` vaut 30. Une suite qui
 * exigerait le refus de tout saut de ligne **rougirait sur une implementation
 * correcte** — et on l'aurait « corrigee » en durcissant un garde qui n'avait
 * pas besoin de l'etre.
 *
 * La neutralisation ici n'est pas un ECHAPPEMENT mais un TYPAGE : la fonction
 * rend des ENTIERS BORNES, jamais la chaine recue. **Le danger n'est donc pas
 * qu'une chaine contienne un metacaractere, c'est qu'une chaine SORTE.**
 *
 *     ce qu'on assert   la sortie est faite d'entiers dans les bornes
 *     jamais            « l'entree ressemblait a quelque chose de sur »
 *
 * ══ POURQUOI PAS UNE REQUETE HTTP ═════════════════════════════════════════
 *
 * Envoyer une valeur forgee a `POST /schedule_advanced_update` pour voir un 400
 * **n'est sans danger que si la validation fonctionne** — c'est-a-dire si ce
 * qu'on veut mesurer est deja vrai. Si elle est absente ou mal placee, la
 * requete poursuit jusqu'a l'ecriture du fichier `cron.d` et au redemarrage de
 * cron : la sonde EXECUTE l'injection qu'elle pretend detecter.
 *
 * > On ne teste pas une garde en l'attaquant, quand l'echec du test EST le
 * > dommage. L'epreuve se prend en amont du geste, sur la fonction elle-meme.
 *
 * ⚠ ET LE SENS NOMINAL PAR HTTP RESTE NON PROUVE, declare comme tel : un
 * `14:30` accepte poursuit vers l'ecriture reelle. Separer « accepte par la
 * validation » de « le geste a eu lieu » demanderait une cible qui ne resout
 * pas — mais `@require_machine_access` repondrait alors 403 AVANT la validation,
 * et on ne mesurerait plus rien. **Je rends ce sens comme non mesure plutot que
 * de planifier quoi que ce soit.**
 *
 * ══ CE QU'IL FAUT ENCORE, ET QUE CETTE SUITE COUVRE ═══════════════════════
 *
 * Une fonction juste qui n'est PAS APPELEE ne protege rien. Le second volet
 * verifie donc que la route appelle les deux validateurs, et qu'elle les appelle
 * AVANT tout `execute_as_root` — une garde ne vaut que si elle domine les
 * gestes qui la suivent.
 *
 *   usage :  node tests/e2e/go-cron-validation-forgee.mjs
 *   sortie :  0 = les deux sens tiennent, et le garde domine
 *             1 = une propriete est fausse
 *             2 = l'instrument n'a pas pu mesurer -> NE RIEN CONCLURE
 */
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const RACINE = new URL('../../', import.meta.url).pathname;
/*
 * ⚠ LA SOURCE EST SURCHARGEABLE, ET LA SURCHARGE S'ANNONCE.
 *
 * Elle n'existe que pour EPROUVER cette suite : muter les validateurs demande
 * une copie, et `backend/routes/updates.py` est ecrit par une autre session —
 * le muter meme brievement ecraserait son travail. Rendre le banc ne suffit
 * pas : l'arbre est partage lui aussi.
 *
 * Un drapeau silencieux sur un controle de securite change ce qu'on mesure sans
 * le dire. Celui-ci l'imprime a chaque execution, et le verdict porte alors la
 * mention — sans quoi un vert obtenu sur une copie se lirait comme un vert
 * obtenu sur le socle.
 */
const SURCHARGE = process.env.RW_SOURCE_CRON;
const SOURCE = SURCHARGE || `${RACINE}backend/routes/updates.py`;
if (SURCHARGE) {
    console.log('');
    console.log('⚠⚠ SOURCE SURCHARGEE — ce verdict NE PORTE PAS sur le socle :');
    console.log(`      ${SURCHARGE}`);
    console.log('   Cette surcharge sert a eprouver la suite, jamais a la conclure.');
}
const VALIDATEURS = ['_cron_heure_minute', '_cron_annee_mois_jour'];
const ROUTE = 'schedule_advanced_update';

let echecs = 0;
let indispo = false;
const dit = (ok, quoi, detail) => {
    /* Le detail ne vaut que pour UN verdict : il se conditionne a ce verdict. */
    console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${quoi}${detail ? `  — ${detail}` : ''}`);
    if (! ok) echecs++;
};

/*
 * ⚠ LE CODE EST LU DEPUIS LE FICHIER, JAMAIS RETAPE. Les deux fonctions sont
 * autonomes (mesure : aucun nom libre), donc on peut les exercer sans importer
 * le module — `flask` n'est pas installe sur ce banc, et un import qui echoue
 * rendrait l'abstention indiscernable d'un refus.
 *
 * Reproduire un validateur pour le mesurer mesurerait la reproduction.
 */
const PY_EXTRAIT = `
import ast, json, sys
src = open(${JSON.stringify(SOURCE)}, encoding='utf8').read()
arbre = ast.parse(src)
corps = {}
for n in ast.walk(arbre):
    if isinstance(n, ast.FunctionDef) and n.name in ${JSON.stringify(VALIDATEURS)}:
        corps[n.name] = ast.get_source_segment(src, n)
if len(corps) != ${VALIDATEURS.length}:
    print(json.dumps({'erreur': 'validateurs introuvables', 'vus': sorted(corps)}))
    sys.exit(0)
g = {}
exec('\\n\\n'.join(corps.values()), g)

def essaie(fn, valeur):
    try:
        r = g[fn](valeur)
    except Exception as e:
        return {'refuse': True, 'exc': type(e).__name__}
    return {'refuse': False, 'rendu': [repr(x) for x in r],
            'types': [type(x).__name__ for x in r]}

cas = json.loads(sys.stdin.read())
print(json.dumps({'resultats': [essaie(f, v) for f, v in cas]}))
`;

/*
 * Les cas. `attendu` dit ce qu'on exige, jamais « ce que ca fait aujourd'hui » :
 *   'refus'   -> la fonction doit lever
 *   'entiers' -> elle peut accepter, mais ne doit rendre QUE des entiers bornes
 * Aucun cas n'exige « accepte tel quel » : rien de l'entree n'a le droit de
 * ressortir.
 */
const CAS = [
    // ── le sens NOMINAL, celui qui prouve que le garde ne refuse pas tout ──
    ['_cron_heure_minute',    '14:30',                'entiers', 'nominal'],
    ['_cron_annee_mois_jour', '2026-09-09',           'entiers', 'nominal'],
    ['_cron_heure_minute',    '00:00',                'entiers', 'bord bas'],
    ['_cron_heure_minute',    '23:59',                'entiers', 'bord haut'],
    // ── le sens FORGE : une queue derriere la valeur ──
    ['_cron_heure_minute',    '14:30\ncurl http://x', 'refus',   'saut de ligne + commande'],
    ['_cron_heure_minute',    '14:30; id',            'refus',   'point-virgule'],
    ['_cron_heure_minute',    '14:30 && id',          'refus',   'chainage'],
    ['_cron_heure_minute',    '14:30`id`',            'refus',   'accent grave'],
    ['_cron_heure_minute',    '14:30$(id)',           'refus',   'substitution'],
    ['_cron_annee_mois_jour', '2026-09-09\nMAILTO=x', 'refus',   'ligne cron injectee'],
    ['_cron_annee_mois_jour', '2026-09-09; id',       'refus',   'point-virgule'],
    // ── les bornes, qui ne sont pas du forge mais du hors-domaine ──
    ['_cron_heure_minute',    '25:00',                'refus',   'heure hors bornes'],
    ['_cron_heure_minute',    '14:60',                'refus',   'minute hors bornes'],
    ['_cron_heure_minute',    '-1:00',                'refus',   'heure negative'],
    ['_cron_heure_minute',    '1430',                 'refus',   'separateur absent'],
    ['_cron_annee_mois_jour', '2026-13-01',           'refus',   'mois inexistant'],
    ['_cron_annee_mois_jour', '2026-02-30',           'refus',   'jour inexistant'],
    /*
     * ⚠ CE CAS DOIT PASSER, ET C'EST CONTRE-INTUITIF. `int()` ignore les blancs
     * de bord : `'14:30\n'` rend (14, 30). C'est CORRECT — seuls des entiers
     * sortent. L'inscrire ici empeche qu'on « corrige » un jour ce comportement
     * en croyant fermer un trou.
     */
    ['_cron_heure_minute',    '14:30\n',              'entiers', 'saut de ligne SEUL — legitime'],
];

let sortie;
try {
    sortie = execFileSync('python3', ['-c', PY_EXTRAIT], {
        input: JSON.stringify(CAS.map(([f, v]) => [f, v])),
        encoding: 'utf8',
    });
} catch (e) {
    console.log('⛔ python3 n\'a pas pu jouer l\'extraction :');
    console.log(`   ${String(e.message).split('\n')[0]}`);
    console.log('   NE RIEN CONCLURE.');
    process.exit(2);
}

let charge;
try { charge = JSON.parse(sortie); } catch {
    console.log('⛔ sortie python illisible — NE RIEN CONCLURE.');
    console.log(sortie.slice(0, 400));
    process.exit(2);
}
if (charge.erreur) {
    console.log(`⛔ ${charge.erreur} — vus : ${JSON.stringify(charge.vus)}`);
    console.log(`   Les deux validateurs ont-ils ete renommes dans ${SOURCE.replace(RACINE, '')} ?`);
    console.log('   NE RIEN CONCLURE.');
    process.exit(2);
}

console.log('\n=== ① les deux sens, sur les fonctions LUES depuis la source\n');
let nominauxOk = 0;
charge.resultats.forEach((r, i) => {
    const [fn, valeur, attendu, libelle] = CAS[i];
    const nom = `${fn.replace('_cron_', '')} · ${libelle} · ${JSON.stringify(valeur)}`;
    if (attendu === 'refus') {
        dit(r.refuse, `REFUSE : ${nom}`,
            r.refuse ? undefined : `ACCEPTE et rend ${JSON.stringify(r.rendu)}`);

        return;
    }
    /* attendu === 'entiers' */
    if (r.refuse) {
        dit(false, `ACCEPTE : ${nom}`, `refuse (${r.exc}) — le garde refuse une valeur LEGITIME`);

        return;
    }
    const quEntiers = r.types.every((t) => t === 'int');
    dit(quEntiers, `ACCEPTE et ne rend QUE des entiers : ${nom}`,
        quEntiers ? undefined : `rend ${JSON.stringify(r.types)} — une chaine SORT`);
    if (quEntiers) nominauxOk++;
});

/*
 * TEMOIN — sans lui, « aucun refus manquant » et « aucun cas joue » sont la
 * meme sortie. On exige qu'au moins un cas NOMINAL soit passe : c'est lui qui
 * distingue un garde qui trie d'un garde qui refuse tout.
 */
console.log('');
if (nominauxOk === 0) {
    console.log('⛔ TEMOIN MUET — aucune valeur nominale n\'a ete acceptee.');
    console.log('   Un garde qui refuse TOUT rendrait tous les refus verts. NE RIEN CONCLURE.');
    indispo = true;
}

console.log('\n=== ② la fonction est-elle APPELEE, et AVANT le geste ?\n');
/*
 * Une fonction juste qui n'est pas appelee ne protege rien, et une garde
 * appelee APRES le geste ne garde que le verdict.
 */
let texte;
try { texte = readFileSync(SOURCE, 'utf8'); } catch {
    console.log('⛔ source illisible — NE RIEN CONCLURE.');
    process.exit(2);
}
const lignes = texte.split('\n');
const debut = lignes.findIndex((l) => new RegExp(`^def ${ROUTE}\\s*\\(`).test(l));
if (debut < 0) {
    console.log(`⛔ fonction ${ROUTE} introuvable — renommee ? NE RIEN CONCLURE.`);
    process.exit(2);
}
let fin = lignes.length;
for (let i = debut + 1; i < lignes.length; i++) {
    if (/^(def |@)/.test(lignes[i])) { fin = i; break; }
}
const corps = lignes.slice(debut, fin);
const numero = (motif) => {
    const i = corps.findIndex((l) => ! /^\s*#/.test(l) && motif.test(l));

    return i < 0 ? null : debut + i + 1;
};

const geste = numero(/execute_as_root\s*\(/);
console.log(`  corps de ${ROUTE} : lignes ${debut + 1}..${fin}`);
console.log(`  premier execute_as_root : ${geste ?? '(aucun dans ce corps)'}`);
for (const v of VALIDATEURS) {
    const appel = numero(new RegExp(`${v}\\s*\\(`));
    if (appel === null) {
        dit(false, `${v} est APPELE par la route`,
            'aucun appel — une fonction juste et jamais appelee ne protege rien');
        continue;
    }
    dit(true, `${v} est APPELE par la route`, `ligne ${appel}`);
    if (geste === null) {
        console.log(`  INFO  ${v} : aucun execute_as_root dans ce corps, domination sans objet ici`);
        continue;
    }
    dit(appel < geste, `${v} precede le premier execute_as_root`,
        appel < geste ? `${appel} < ${geste}` : `${appel} >= ${geste} — la garde suit le geste`);
}

console.log('\n=== ③ ce que cette suite NE prouve PAS\n');
console.log('  Le sens nominal PAR HTTP : NON PROUVE, et volontairement.');
console.log('  Un `14:30` accepte par POST /schedule_advanced_update poursuit vers');
console.log('  l\'ecriture de /etc/cron.d/auto_update_advanced et le redemarrage de');
console.log('  cron. C\'est un geste SORTANT ; il n\'est pas a moi de le declencher.');
console.log('');
console.log('  Et le sens FORGE par HTTP n\'est pas joue non plus : il ne serait sans');
console.log('  danger que si la validation fonctionne deja — donc la sonde executerait');
console.log('  l\'injection qu\'elle pretend detecter, le jour ou elle serait utile.');

console.log('');
if (indispo) {
    console.log('INSTRUMENT INDISPONIBLE — ne rien conclure de cette execution.');
    process.exit(2);
}
if (echecs) {
    console.log(`${echecs} propriete(s) FAUSSE(S) sur la validation d'une ligne cron.d`);
    console.log('executee en root. Ce n\'est pas un test de confort : sans ces bornes,');
    console.log('une chaine de `request.json` atteint un fichier que cron lit en root.');
    process.exit(1);
}
console.log(`Les deux sens tiennent — ${nominauxOk} valeur(s) nominale(s) acceptee(s),`);
console.log('aucune chaine ne ressort, et les deux gardes precedent le geste.');
process.exit(0);
