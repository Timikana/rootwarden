/*
 * ═══ L'EXPORT RGPD DU PROFIL — `a48df2c` (v1.39.2) ════════════════════════
 *
 * Ce que cette suite prouve, et pourquoi chaque assertion existe.
 *
 * ══ 1. LA PORTABILITE EST UN DROIT, PAS UN PRIVILEGE ══════════════════════
 *
 * `web.php:669` pose la route SANS `role:` ni `perm:`, et le commentaire le
 * declare volontaire. Une absence de garde ne se verifie pas en relisant la
 * route — elle se verifie en l'EXERCANT depuis un compte qui n'est pas
 * administrateur. `rw-test-admin` (role 2) doit obtenir SON export.
 *
 * ⚠ CE QUE JE N'EXERCE PAS, ET LA RAISON : le role 1. `rw-test-user` (id 14)
 * est en lecture seule par consigne, et l'export ecrit une ligne d'audit
 * ATTRIBUEE au compte exporte. La propriete « aucune garde de role » est donc
 * mesuree entre le role 2 et le role 3, et le role 1 reste DECLARE non mesure
 * plutot que suppose vert.
 *
 * ══ 2. AUCUNE ENTREE LIBRE — C'EST LE COEUR ═══════════════════════════════
 *
 * L'identifiant vient de la SESSION et la route n'offre aucun parametre. Une
 * route sans parametre ne se prouve pas par la lecture : elle se prouve en en
 * FORGEANT un. On demande donc l'export avec `?user_id=`, `?id=` et `?user=`
 * pointant un AUTRE compte, et on exige que le sujet de l'export n'ait pas
 * bouge. Une entree libre absente ne se contourne pas ; une entree libre
 * validee, si.
 *
 * ══ 3. CE QU'UN EXPORT NE DOIT JAMAIS CONTENIR ════════════════════════════
 *
 * Un export RGPD remet a la personne ses donnees. Un hachage de mot de passe
 * et un secret TOTP n'en sont pas : ce sont les deux facteurs d'authentification.
 * Les remettre dans un fichier telecharge — donc copie, sauvegarde, transmis —
 * transforme un droit d'acces en fuite de second facteur.
 *
 * On ne mesure PAS cette propriete sur le code du service : un `SELECT` relu ne
 * dit pas ce que le fichier porte. On la mesure sur l'ARTEFACT, en parcourant
 * le JSON rendu, cle par cle, valeur par valeur.
 *
 * ══ CE QUE CETTE SUITE NE PEUT PAS MESURER, ET QUI EST REEL ═══════════════
 *
 * Le groupe de routes porte `mot.de.passe.a.changer`. Un compte marque
 * `force_password_change` est donc renvoye vers son profil et NE PEUT PAS
 * exporter — parite declaree avec le legacy, et population reelle (8 comptes
 * actifs sur 12 au 2026-09-03, dont 6 sans adresse pour lever le drapeau
 * seuls). Mesurer ce chemin exigerait de POSER le drapeau sur un compte
 * partage : c'est une ecriture en BASE, invisible au garde de fenetre, et de la
 * classe qui a fait tomber ~61 suites le 2026-09-01. Non mesure, et DIT.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { mkdirSync, readFileSync } from 'fs';
import { litEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = (() => {
    /*
     * ══ LA CIBLE VIENT DE L'ENVIRONNEMENT, L'URL N'EST QU'UN REPLI ════════
     *
     * `/8444|laravel/i.test(BASE)` deduit la cible d'un NUMERO DE PORT. Tant que
     * le portage vit sur 8444 c'est juste ; **le jour ou les ports s'echangent,
     * ce predicat rend 87 suites MENTEUSES et non rouges** — elles appliqueraient
     * les attentes du legacy au portage, et rendraient du VERT.
     *
     * `E2E_CIBLE` devient donc l'autorite, et `rejouer-lot.sh` l'exporte pour
     * chaque moitie. Le motif d'URL ne sert plus qu'aux lancements a la main.
     *
     * ⚠ ET IL N'Y A PAS DE GARDE DE COHERENCE ENTRE LES DEUX — c'est deliberé,
     * et l'inverse a ete demande puis ecarte apres mesure :
     *
     *     E2E_CIBLE=laravel + BASE=…:8443
     *       AVANT l'echange  incoherent   (a refuser)
     *       APRES l'echange  CORRECT      (a accepter)
     *
     * **Une garde « l'environnement doit concorder avec le motif d'URL »
     * refuserait exactement la configuration que cet elargissement existe pour
     * permettre.** Le motif d'URL n'est pas un invariant : c'est la chose meme
     * qu'on rend caduque. On ne garde pas une valeur contre une heuristique
     * qu'on sait perimee.
     *
     * CE QUI EST INVARIANT, ET SUR QUOI LA GARDE SE POSE : la cible appartient a
     * une LISTE FERMEE. Une valeur hors liste est refusee bruyamment, au
     * chargement, avant qu'une seule assertion ne s'execute — une faute de frappe
     * ne doit pas se lire comme « legacy » par repli silencieux.
     */
    const CIBLES = ['laravel', 'legacy'];
    const declaree = process.env.E2E_CIBLE;
    if (declaree !== undefined && declaree !== '') {
        if (! CIBLES.includes(declaree)) {
            throw new Error(
                `E2E_CIBLE=${JSON.stringify(declaree)} n'est pas une cible connue `
                + `(${CIBLES.join(' | ')}). Rien n'est joue : une cible inconnue `
                + `retomberait sur « legacy » et la suite mesurerait le mauvais portail.`);
        }

        return declaree;
    }

    return /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
})();
const PAGE = CIBLE === 'laravel' ? '/profil/donnees-personnelles' : '/profile/export.php';
/*
 * ⚠ `/profile/index.php` N'EXISTE PAS : la page de profil du legacy est
 * `/profile.php`, et `profile/` ne contient QUE `export.php`. Mon premier jet
 * visait le mauvais chemin — voir l'assertion ci-dessous, qui est passee au
 * VERT sur la page « Not Found » du serveur.
 */
const PROFIL = CIBLE === 'laravel' ? '/profil' : '/profile.php';

/*
 * Les secrets sont RELEVES dans les suites existantes, jamais inventes :
 * `rw-test-super` figure dans 60 fichiers de `tests/e2e/`, `rw-test-admin` dans
 * 66 (compte du 2026-09-04). Un secret invente rendrait un echec de connexion
 * indiscernable d'un defaut de la page.
 */
const COMPTES = {
    'rw-test-admin': { id: 15, role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX' },
    'rw-test-super': { id: 16, role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW' },
};
/* Le sujet qu'on tentera de se faire servir en forgeant un parametre. */
const AUTRUI = 14;

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,''))b+=a.indexOf(c).toString(2).padStart(5,'0');const o=[];for(let i=0;i+8<=b.length;i+=8)o.push(parseInt(b.slice(i,i+8),2));return Buffer.from(o)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[19]&0xf;return String(((h.readUInt32BE(o)&0x7fffffff)%1000000)).padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
const avortees = [];

function verifie(libelle, ok, detail, __quatrieme) {
    /*
     * INF-002 — ce fichier suit la convention a TROIS arguments : le detail
     * s'affiche sur un PASS COMME sur un FAIL. Un quatrieme argument ecrit pour
     * l'autre convention serait ignore en silence, et son explication d'echec
     * imprimee sur une ligne VERTE.
     */
    if (__quatrieme !== undefined) {
        throw new Error(
            'INF-002 : `verifie` de ce fichier prend TROIS arguments. Pour une '
            + 'explication qui ne doit paraitre qu\'en cas d\'echec, ecrire le '
            + 'troisieme ainsi : `ok ? <ce qu\'on a mesure> : <ce qui explique l\'echec>`.');
    }
    lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${libelle}${detail ? '  — ' + detail : ''}`);
    if (!ok) echecs++;
}
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }
function verifiePortage(libelle, ok, detail) {
    if (CIBLE === 'laravel') return verifie(libelle, ok, detail);
    constate(libelle, `non exigible du legacy — ${detail}`);
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 90000,
});

/*
 * ══ FILET — CETTE SUITE NE FAIT QUE LIRE ══════════════════════════════════
 *
 * Le seul non-GET dont elle a besoin est sa propre connexion. Tout autre est
 * AVORTE : `/profil` porte des formulaires (mot de passe, cle SSH), et un clic
 * mal ancre ne doit pas pouvoir en soumettre un.
 *
 * ⚠ ET LE PREMIER JET DE CE FILET ETAIT UNE LISTE BLANCHE D'URL, TROP ETROITE.
 *
 *     /(connexion|login\.php|auth\/)/     <- ne contient PAS `/second-facteur`
 *
 * Le second facteur etait donc avorte, la connexion n'aboutissait jamais, et
 * TOUT le reste mesurait la page de connexion : `/profil` redirigeait, et
 * l'export rendait du HTML en 200. **Neuf assertions rouges qui ne disaient
 * rien de l'export.** Une liste blanche trop etroite ne se signale pas : elle
 * produit un resultat plausible et faux.
 *
 * LE REMEDE N'EST PAS D'AJOUTER `/second-facteur` A LA LISTE — ce serait se
 * preparer a rater l'etape suivante (les CGU, un ecran d'enrolement). C'est de
 * remplacer la liste par un ETAT : le non-GET est permis PENDANT la phase de
 * connexion, et interdit des qu'elle est finie. Cette phase est fermee par
 * construction, elle ne peut pas oublier une etape qu'elle contient.
 */
let enConnexion = false;

function installeFilet(page) {
    page.setRequestInterception(true);
    page.on('request', (r) => {
        const m = r.method();
        if (m !== 'GET' && !enConnexion) {
            avortees.push(`${m} ${r.url().replace(BASE, '')}`);
            return r.abort('blockedbyclient').catch(() => {});
        }
        r.continue().catch(() => {});
    });
}

async function connecte(nom) {
    enConnexion = true;
    const compte = COMPTES[nom];
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    page.on('dialog', d => d.dismiss().catch(() => {}));
    installeFilet(page);

    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };

    await page.goto(`${BASE}${chemins.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    // Le garde anti-rejeu TOTP est par COMPTE et PERSISTANT : on ne presente
    // jamais un code ne dans une fenetre qui va se refermer.
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    await page.type('input[name="2fa_code"]', totp(compte.secret), { delay: 8 });
    nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (chemins.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$('[data-rw="cgu-accepter"]') || await page.$('button[name="accept_terms"]');
        if (b) await b.evaluate(x => x.click());
        try { await nav; } catch {}
    }
    // La phase est CLOSE : a partir d'ici, tout non-GET est avorte.
    enConnexion = false;

    return { ctx, page };
}

/*
 * Demande l'export depuis la PAGE, donc avec ses cookies. La valeur variable
 * est passee en ARGUMENT du rappel : le rappel s'execute dans le navigateur, ou
 * les constantes de ce fichier n'existent pas. Une constante lue cote Node y
 * vaudrait `undefined`, et `undefined` dans une URL ne leve rien — il produit
 * une requete differente de celle qu'on croit mesurer.
 */
async function exporte(page, requete) {
    return page.evaluate(async (url) => {
        const r = await fetch(url, { credentials: 'same-origin' });
        const corps = await r.text();
        return {
            statut: r.status,
            type: r.headers.get('content-type') || '',
            disposition: r.headers.get('content-disposition') || '',
            corps,
        };
    }, `${BASE}${PAGE}${requete || ''}`);
}

/** Parcourt le JSON et rend chaque couple (chemin, cle, valeur) atteignable. */
function* parcourt(noeud, chemin = '') {
    if (noeud === null || typeof noeud !== 'object') return;
    for (const [cle, val] of Object.entries(noeud)) {
        const ici = chemin ? `${chemin}.${cle}` : cle;
        yield { chemin: ici, cle, val };
        yield* parcourt(val, ici);
    }
}

try {
    const { ctx, page } = await connecte('rw-test-super');
    const MOI = COMPTES['rw-test-super'].id;

    // ══ 1. L'ANCRE, ET LE CLIC ════════════════════════════════════════════
    /*
     * ══ MESURER LE STATUT, PAS SEULEMENT L'URL ════════════════════════════
     *
     * Premier jet : `!/\/connexion|login\.php/.test(page.url())`. Il demandait
     * « la barre d'adresse ne montre pas la page de connexion », ce qu'une page
     * d'erreur satisfait parfaitement. Sur le legacy, `PROFIL` pointait un
     * chemin inexistant : le serveur a rendu « Not Found », l'URL n'etait pas
     * celle de la connexion, et **l'assertion est passee au VERT sur un 404**.
     * La capture l'a montre ; aucune assertion ne l'a vu.
     *
     * On exige donc les DEUX : un statut 200 ET une URL qui n'est pas celle de
     * la connexion. Le premier attrape la page absente, le second la
     * redirection — ce sont deux pannes differentes, et l'une des deux ne
     * couvre jamais l'autre.
     */
    const reponseProfil = await page.goto(`${BASE}${PROFIL}`, { waitUntil: 'networkidle2' });
    const statutProfil = reponseProfil ? reponseProfil.status() : 0;
    verifie('la page de profil repond 200, et n\'est pas la connexion',
        statutProfil === 200 && !/\/connexion|login\.php/.test(page.url()),
        `statut ${statutProfil}, URL finale ${page.url().replace(BASE, '')}`);

    const ancre = await page.$('[data-rw="rgpd-telecharger"]');
    verifiePortage('le profil porte l\'ancre de telechargement RGPD', ancre !== null,
        ancre ? 'presente' : 'ancre [data-rw="rgpd-telecharger"] absente de la page');

    if (ancre) {
        const href = await ancre.evaluate((a) => a.getAttribute('href'));
        verifie('l\'ancre pointe la route d\'export, pas une autre page',
            typeof href === 'string' && href.includes(PAGE),
            href ? `href="${href}"` : 'aucun attribut href');

        // Un CLIC REEL. La reponse est une piece jointe : le navigateur la
        // telecharge et NE NAVIGUE PAS. Rester sur le profil est donc le
        // resultat attendu — et c'est une propriete du RESULTAT, pas du clic.
        const avant = page.url();
        await ancre.click();
        await dors(1200);
        verifie('le clic telecharge sans quitter le profil',
            page.url() === avant,
            page.url() === avant ? 'la page n\'a pas navigue' : `a navigue vers ${page.url()}`);
    }

    // ══ 2. LA REPONSE ═════════════════════════════════════════════════════
    const exp = await exporte(page, '');
    verifie('l\'export repond 200', exp.statut === 200, `statut ${exp.statut}`);
    verifie('le type annonce du JSON', /application\/json/i.test(exp.type),
        `content-type « ${exp.type} »`);
    verifie('le fichier est propose en telechargement, et il est NOMME',
        /attachment/i.test(exp.disposition) && /filename="[^"]+\.json"/i.test(exp.disposition),
        `content-disposition « ${exp.disposition} »`);

    let donnees = null;
    try { donnees = JSON.parse(exp.corps); } catch (e) { donnees = null; }
    verifie('le corps est du JSON valide', donnees !== null,
        donnees !== null ? `${exp.corps.length} octet(s)` : `illisible : ${exp.corps.slice(0, 80)}`);

    if (donnees) {
        // ══ 3. LES BLOCS DECLARES ═════════════════════════════════════════
        const ATTENDUS = ['_metadata', 'user', 'permissions', 'user_machine_access',
                          'user_logs', 'login_history', 'active_sessions',
                          'notification_preferences', 'password_history'];
        const manquants = ATTENDUS.filter((k) => !(k in donnees));
        verifiePortage('les neuf blocs declares sont tous presents',
            manquants.length === 0,
            manquants.length === 0 ? `${ATTENDUS.length} blocs` : `manquants : ${manquants.join(', ')}`);

        // ══ 4. LE SUJET DE L'EXPORT ═══════════════════════════════════════
        verifiePortage('l\'export porte l\'identifiant du compte CONNECTE',
            donnees._metadata && donnees._metadata.user_id === MOI,
            `_metadata.user_id = ${donnees._metadata && donnees._metadata.user_id} (attendu ${MOI})`);

        verifiePortage('l\'export dit la version du produit',
            !!(donnees._metadata && donnees._metadata.rootwarden_version),
            `rootwarden_version = ${JSON.stringify(donnees._metadata && donnees._metadata.rootwarden_version)}`);

        if (CIBLE === 'laravel' && donnees._metadata) {
            // La version a UNE source : `legacy/version.txt`, monte en lecture
            // seule dans le conteneur. On la relit sur le disque plutot que de
            // la recopier : une constante recopiee ne mesure que ma frappe.
            let surDisque = null;
            try {
                surDisque = readFileSync(
                    new URL('../../legacy/version.txt', import.meta.url).pathname, 'utf8').trim();
            } catch { surDisque = null; }
            verifie('la version exportee est celle du fichier de version',
                surDisque !== null && donnees._metadata.rootwarden_version === surDisque,
                surDisque === null ? 'legacy/version.txt illisible'
                    : `export « ${donnees._metadata.rootwarden_version} » contre disque « ${surDisque} »`);
        }

        // ══ 5. AUCUN SECRET DANS LE FICHIER ═══════════════════════════════
        //
        // Mesure sur l'ARTEFACT. Un `SELECT` relu ne dit pas ce que le fichier
        // porte : c'est le fichier qu'on remet a la personne.
        const CLES_INTERDITES = /^(password|mot_de_passe|totp_secret|remember_token|secret|password_hash)$/i;
        const clesFuitees = [...parcourt(donnees)]
            .filter((n) => CLES_INTERDITES.test(n.cle)
                        && n.val !== null && n.val !== '' && typeof n.val !== 'object')
            .map((n) => n.chemin);
        verifiePortage('aucune cle de secret ne porte de valeur dans l\'export',
            clesFuitees.length === 0,
            clesFuitees.length === 0 ? 'aucune' : `fuite : ${clesFuitees.slice(0, 5).join(', ')}`);

        // Et les VALEURS, independamment du nom de leur cle : un hachage change
        // de nom de colonne, sa forme ne change pas.
        const FORME_HACHAGE = /^\$(2[aby]|argon2[a-z]*|6)\$/;
        const FORME_TOTP = /^[A-Z2-7]{32,}$/;
        const valeursFuitees = [...parcourt(donnees)]
            .filter((n) => typeof n.val === 'string'
                        && (FORME_HACHAGE.test(n.val) || FORME_TOTP.test(n.val)))
            .map((n) => `${n.chemin} (${FORME_HACHAGE.test(n.val) ? 'hachage' : 'base32 long'})`);
        verifiePortage('aucune valeur n\'a la FORME d\'un hachage ou d\'un secret TOTP',
            valeursFuitees.length === 0,
            valeursFuitees.length === 0 ? 'aucune' : valeursFuitees.slice(0, 5).join(', '));

        // ══ 6. LES SESSIONS ACTIVES SONT MASQUEES ═════════════════════════
        //
        // `ExportRgpd` fait passer ce bloc par `masqueJetons()`. Un jeton de
        // session en clair dans un fichier telecharge est un vol de session
        // remis a qui obtient le fichier.
        const sessions = JSON.stringify(donnees.active_sessions ?? null);
        const jetonsEnClair = (sessions.match(/"[A-Za-z0-9_-]{32,}"/g) || [])
            .filter((j) => !/\*|…|\.\.\./.test(j));
        verifiePortage('aucun jeton de session en clair dans le bloc des sessions',
            jetonsEnClair.length === 0,
            jetonsEnClair.length === 0 ? 'aucun'
                : `${jetonsEnClair.length} chaine(s) longue(s) non masquee(s)`);

        // ══ 7. LES BORNES SONT DECLAREES ══════════════════════════════════
        for (const bloc of ['user_logs', 'login_history']) {
            const b = donnees[bloc];
            verifiePortage(`le bloc ${bloc} declare sa borne et sa troncature`,
                !!b && typeof b === 'object' && '_total' in b && '_tronque' in b && '_borne' in b,
                b && typeof b === 'object'
                    ? `_total=${b._total} _exportees=${b._exportees} _tronque=${b._tronque}`
                    : 'bloc absent ou non structure');
        }
    }

    // ══ 8. AUCUNE ENTREE LIBRE ════════════════════════════════════════════
    //
    // La route n'offre aucun parametre. On en FORGE trois. Le sujet doit rester
    // le compte connecte — un export qui obeirait a `?user_id=` remettrait les
    // donnees d'autrui a qui les demande.
    for (const p of [`?user_id=${AUTRUI}`, `?id=${AUTRUI}`, `?user=${AUTRUI}`]) {
        const forge = await exporte(page, p);
        let sujet = null;
        try { sujet = JSON.parse(forge.corps)._metadata.user_id; } catch { sujet = null; }
        verifiePortage(`le parametre forge ${p} ne change pas le sujet de l'export`,
            forge.statut === 200 && sujet === MOI,
            `statut ${forge.statut}, sujet ${sujet} (attendu ${MOI}, jamais ${AUTRUI})`);
    }

    // ══ 9. LA TRACE ═══════════════════════════════════════════════════════
    //
    // L'export est journalise. On lit la BASE, pas l'ecran : ce que la page
    // affiche d'un journal n'est pas ce que le journal contient.
    if (CIBLE === 'laravel') {
        /*
         * ⚠ CET INSTRUMENT PEUT ETRE INDISPONIBLE, ET C'EST UN TROISIEME
         * VERDICT — NI VERT NI ROUGE.
         *
         * `lib-base` passe par `docker exec`, refuse quand le compte qui lance
         * la suite n'est pas dans le groupe `docker`. Laisser l'exception
         * remonter avait un cout mesure : elle a emporte les captures ET la
         * verification du role 2, qui n'avaient aucun rapport. **Un instrument
         * indisponible ne doit pas eteindre les mesures voisines**, et il ne
         * doit pas non plus se rendre en PASS : « je n'ai pas pu regarder »
         * n'est pas « rien a signaler ».
         */
        let traces = null;
        let motif = '';
        try {
            traces = litEnBase(
                `SELECT COUNT(*) FROM rootwarden.user_logs WHERE user_id = ${MOI} `
                + `AND action LIKE '%rgpd%' AND created_at >= NOW() - INTERVAL 5 MINUTE`);
        } catch (e) {
            motif = String(e.message || e).split('\n')[0];
        }
        const n = traces === null ? NaN : parseInt(traces[0], 10);
        if (Number.isFinite(n)) {
            verifie('l\'export laisse une trace d\'audit sur le compte', n > 0,
                `${n} ligne(s) [rgpd] dans les 5 dernieres minutes`);
        } else {
            constate('trace d\'audit de l\'export',
                `NON MESURE — la lecture en base est indisponible depuis ce shell. ${motif}`);
        }
    }

    // ══ 10. CAPTURES ══════════════════════════════════════════════════════
    const dossier = new URL(`./screenshots/profil-rgpd/${CIBLE}`, import.meta.url).pathname;
    mkdirSync(dossier, { recursive: true });
    await page.goto(`${BASE}${PROFIL}`, { waitUntil: 'networkidle2' });
    for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                     { n: 'mobile', w: 390, h: 844 }]) {
        await page.setViewport({ width: f.w, height: f.h });
        await dors(400);
        await page.screenshot({ path: `${dossier}/profil-${f.n}.png`, fullPage: true });
    }
    constate('captures ecrites', dossier);

    await ctx.close();

    // ══ 11. LE ROLE 2 A LE MEME DROIT ═════════════════════════════════════
    //
    // La propriete est « la portabilite n'est pas un privilege d'administration ».
    // Elle ne se lit pas sur la route : elle s'exerce depuis un compte qui n'est
    // pas superadministrateur.
    const b = await connecte('rw-test-admin');
    const SON_ID = COMPTES['rw-test-admin'].id;
    const sien = await exporte(b.page, '');
    let sujetAdmin = null;
    try { sujetAdmin = JSON.parse(sien.corps)._metadata.user_id; } catch { sujetAdmin = null; }
    verifiePortage('un compte de role 2 obtient SON export, sans permission d\'administration',
        sien.statut === 200 && sujetAdmin === SON_ID,
        `statut ${sien.statut}, sujet ${sujetAdmin} (attendu ${SON_ID})`);
    await b.ctx.close();

    // ══ CE QUI RESTE HORS DE PORTEE ═══════════════════════════════════════
    constate('role 1 (rw-test-user, id 14)',
        'NON MESURE — compte en lecture seule par consigne, et l\'export ecrit une '
        + 'ligne d\'audit attribuee au compte exporte.');
    constate('chemin force_password_change',
        'NON MESURE — exigerait de poser le drapeau sur un compte partage : ecriture '
        + 'en BASE, invisible au garde de fenetre, classe de l\'incident du 2026-09-01.');
} catch (e) {
    lignes.push('EXCEPTION ' + String(e.message || e).split('\n')[0]);
    echecs++;
} finally {
    constate('requetes AVORTEES par le filet',
        avortees.length ? avortees.join(' | ') : '(aucune)');
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
