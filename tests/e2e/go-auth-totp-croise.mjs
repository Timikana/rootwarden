/**
 * go-auth-totp-croise.mjs - `auth/` sous-lot ENROLEMENT : l'execution CROISEE
 * des secrets TOTP entre les deux implementations.
 *
 * ══ POURQUOI CE TEST EXISTE, ET POURQUOI IL PASSE EN PREMIER ════════════════
 *
 * L'enrolement est le seul geste de toute la migration qui **ECRIT** un secret
 * TOTP. Les deux portails partagent la base : un blob ecrit par l'un doit etre
 * lisible par l'autre. Et un format divergent d'un octet ne produit **aucun
 * message d'erreur** — il rend simplement le compte inaccessible d'un cote, ce
 * qu'on ne decouvre qu'au moment ou quelqu'un n'arrive plus a se connecter.
 *
 * `MODULE-AUTH.md` §7 place donc l'enrolement en dernier, et designe ce test
 * comme le premier a ecrire. La lecture comparee des deux fichiers avait ete
 * faite ; l'execution croisee, non — or deux implementations qui se ressemblent
 * a la lecture peuvent diverger a l'execution (une etiquette HKDF, un ordre de
 * concatenation, un `hex2bin` qui echoue en silence).
 *
 * ══ PAS DE NAVIGATEUR, ET C'EST LE MOTIF ═══════════════════════════════════
 *
 * La convention du projet veut que les tests soient pilotes par des CLICS. Elle
 * porte sur la logique qui a une INTERFACE : cliquer le bouton plutot qu'appeler
 * la fonction. Ici la propriete mesuree est un format de donnees partage entre
 * deux processus PHP ; elle n'a aucune surface a cliquer, et la mesurer par
 * l'interface reviendrait a enroler un vrai compte pour lire un octet. Le test
 * fait donc executer les DEUX implementations reelles, chacune dans SON
 * conteneur — pas une reimplementation en JavaScript, qui ne prouverait que ma
 * comprehension du format.
 *
 * ══ CE QU'IL MESURE ════════════════════════════════════════════════════════
 *
 *   portage chiffre  -> legacy dechiffre   (le sens NEUF : c'est l'enrolement)
 *   legacy chiffre   -> portage dechiffre  (le sens deja vivant)
 *   chacun se relit lui-meme
 *   le blob porte le prefixe attendu, et n'est jamais le secret en clair
 *   un blob altere d'UN octet est refuse, et refuse par le VIDE (fail-closed)
 *
 * Aucune ecriture en base : les blobs vivent dans la sortie standard des deux
 * conteneurs. Aucun compte n'est touche.
 *
 * Usage :
 *   cd tests/e2e && node go-auth-totp-croise.mjs
 */
import { execFileSync } from 'node:child_process';

/** Le secret d'epreuve. Base32 valide, jamais celui d'un compte reel. */
const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
function verifie(l, ok, d) { note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { note(`INFO  ${l} : ${v}`); }

/**
 * Execute du PHP dans un conteneur et rend sa sortie.
 *
 * Le code part par l'ARGUMENT `-r` et les donnees par des ARGUMENTS positionnels
 * (`$argv`), jamais par interpolation : un blob base64 contient `+` et `/`, et
 * une valeur interpolee dans du code PHP serait une injection de code — dans un
 * test comme ailleurs.
 */
function php(conteneur, code, ...arguments_) {
    return execFileSync('sudo', [
        '-n', 'docker', 'exec', conteneur, 'php', '-r', code, '--', ...arguments_,
    ], { encoding: 'utf8', timeout: 30000 }).trim();
}

/** Le legacy : ses deux fonctions vivent dans un fichier a inclure. */
const PRELUDE_LEGACY = 'require "/var/www/html/includes/totp_crypto.php";';

function chiffreLegacy(secret) {
    return php('rootwarden_php', `${PRELUDE_LEGACY} echo encryptTotpSecret($argv[1]);`, secret);
}
function dechiffreLegacy(blob) {
    return php('rootwarden_php', `${PRELUDE_LEGACY} echo decryptTotpSecret($argv[1]);`, blob);
}

/**
 * Le portage : il faut amorcer le cadre, parce que `TotpCrypto` lit la cle par
 * `config('rootwarden.secret_key')` — et non par `getenv()`, precisement pour
 * qu'un `config:cache` ne la vide pas.
 */
const PRELUDE_PORTAGE = 'require "/var/www/html/vendor/autoload.php";'
    + '$app = require "/var/www/html/bootstrap/app.php";'
    + '$app->make(Illuminate\\Contracts\\Console\\Kernel::class)->bootstrap();';

function chiffrePortage(secret) {
    return php('rootwarden_laravel',
        `${PRELUDE_PORTAGE} echo App\\Support\\TotpCrypto::chiffre($argv[1]);`, secret);
}
function dechiffrePortage(blob) {
    return php('rootwarden_laravel',
        `${PRELUDE_PORTAGE} echo App\\Support\\TotpCrypto::dechiffre($argv[1]);`, blob);
}

/** Chaque etape isolee : une exception ne doit pas emporter le journal entier. */
let etapes = 0;
function etape(titre, fn) {
    etapes += 1;
    try {
        fn();
    } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

/**
 * Altere UN octet du corps base64 d'un blob, en gardant son prefixe.
 * On change le caractere du MILIEU pour tomber dans le chiffre et non dans le
 * nonce : c'est l'authentification qu'on veut mettre en defaut.
 */
function altere(blob) {
    const coupe = blob.lastIndexOf(':') + 1;
    const corps = blob.slice(coupe);
    const i = Math.floor(corps.length / 2);
    const autre = corps[i] === 'A' ? 'B' : 'A';

    return blob.slice(0, coupe) + corps.slice(0, i) + autre + corps.slice(i + 1);
}

let blobPortage = '';
let blobLegacy  = '';

etape('le portage chiffre', () => {
    blobPortage = chiffrePortage(SECRET);
    constate('blob ecrit par le portage', `${blobPortage.slice(0, 12)}… (${blobPortage.length} car.)`);
    verifie('le portage produit un blob prefixe', /^totp:(sodium|gcm):/.test(blobPortage),
        blobPortage.slice(0, 12));
    /* LE SECRET NE DOIT PAS APPARAITRE. Un chiffrement qui echoue en silence et
     * rend la valeur telle quelle passerait tous les tests de va-et-vient. */
    verifie('le blob ne contient pas le secret en clair', ! blobPortage.includes(SECRET));
});

etape('le legacy chiffre', () => {
    blobLegacy = chiffreLegacy(SECRET);
    constate('blob ecrit par le legacy', `${blobLegacy.slice(0, 12)}… (${blobLegacy.length} car.)`);
    verifie('le legacy produit un blob prefixe', /^totp:(sodium|gcm):/.test(blobLegacy),
        blobLegacy.slice(0, 12));
    verifie('les deux choisissent le MEME moteur',
        blobPortage.split(':')[1] === blobLegacy.split(':')[1],
        `portage ${blobPortage.split(':')[1]} / legacy ${blobLegacy.split(':')[1]}`);
});

etape('deux chiffrements du meme secret different', () => {
    const second = chiffrePortage(SECRET);
    /* Le nonce est aleatoire : deux blobs identiques signaleraient un nonce fixe,
     * qui casse la confidentialite de secretbox comme de GCM. */
    verifie('deux chiffrements du meme secret donnent deux blobs differents',
        second !== blobPortage && second !== '', `${second.slice(0, 20)}…`);
});

etape('LE SENS NEUF : portage -> legacy', () => {
    const lu = dechiffreLegacy(blobPortage);
    verifie('le legacy relit ce que le portage a ecrit', lu === SECRET,
        lu === SECRET ? 'identique' : `lu « ${lu.slice(0, 24)}… »`);
});

etape('LE SENS DEJA VIVANT : legacy -> portage', () => {
    const lu = dechiffrePortage(blobLegacy);
    verifie('le portage relit ce que le legacy a ecrit', lu === SECRET,
        lu === SECRET ? 'identique' : `lu « ${lu.slice(0, 24)}… »`);
});

etape('chacun se relit lui-meme', () => {
    verifie('le portage relit son propre blob', dechiffrePortage(blobPortage) === SECRET);
    verifie('le legacy relit son propre blob', dechiffreLegacy(blobLegacy) === SECRET);
});

etape('un blob altere est refuse, des DEUX cotes', () => {
    const abime = altere(blobPortage);
    verifie('l\'alteration a bien change le blob', abime !== blobPortage);
    const cotePortage = dechiffrePortage(abime);
    const coteLegacy  = dechiffreLegacy(abime);
    /* FAIL-CLOSED : le refus doit rendre le VIDE, jamais le blob brut. Rendre le
     * blob ferait echouer la verification TOTP « pour une autre raison », et le
     * defaut se lirait comme un mauvais code. */
    verifie('le portage refuse un blob altere, et rend le vide', cotePortage === '',
        `rendu « ${cotePortage.slice(0, 24)} »`);
    verifie('le legacy refuse un blob altere, et rend le vide', coteLegacy === '',
        `rendu « ${coteLegacy.slice(0, 24)} »`);
});

etape('un prefixe inconnu est refuse', () => {
    const inconnu = 'totp:inventé:' + blobPortage.split(':').pop();
    verifie('le portage refuse un prefixe inconnu', dechiffrePortage(inconnu) === '');
});

etape('une valeur sans prefixe est rendue telle quelle', () => {
    /* Retrocompatibilite explicite : des secrets d'avant le chiffrement existent
     * encore. Les deux cotes doivent se comporter PAREIL, sans quoi un vieux
     * compte marcherait sur un portail et pas sur l'autre. */
    verifie('le portage rend un secret historique tel quel', dechiffrePortage(SECRET) === SECRET);
    verifie('le legacy rend un secret historique tel quel', dechiffreLegacy(SECRET) === SECRET);
});

note('');
const pass = lignes.filter((l) => l.startsWith('PASS')).length;
note(`${pass} PASS / ${echecs} FAIL — ${etapes} etapes, execution croisee`);
process.exit(echecs === 0 ? 0 : 1);
