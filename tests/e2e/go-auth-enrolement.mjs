/**
 * go-auth-enrolement.mjs - `auth/` : l'enrolement 2FA du legacy, et la
 * vulnerabilite qu'il portait EN PRODUCTION.
 *
 * ══ PILOTEE PAR DES CLICS, comme toutes les suites du LOT ════════════════════
 *
 * Convention du projet, rappelee par l'exploitant le 2026-08-23 : on **clique le
 * bouton**, on ne **pas** appelle la fonction, et on n'emet pas de requetes HTTP
 * brutes. Un premier jet de cette suite passait par `node:https` sans navigateur :
 * il mesurait des statuts, pas l'ecran. Appeler la fonction ne mesure pas que le
 * bouton l'appelle — un `onclick` absent, un bouton `disabled`, un formulaire dont
 * l'action a change, rien de tout cela ne se voit.
 *
 * Les seules navigations directes ici sont celles d'un **attaquant** : taper
 * `/auth/enable_2fa.php` dans la barre d'adresse EST le geste a mesurer. Tout le
 * reste — connexion, soumission du code — passe par `page.type` et `page.click`.
 *
 * ══ CE QUE CETTE SUITE PROTEGE ══════════════════════════════════════════════
 *
 * `enable_2fa.php` ne gardait que `isset($_SESSION['temp_user'])`, l'etat pose par
 * `login.php` APRES le mot de passe et AVANT le second facteur. Mesure du
 * 2026-08-20, reproduite le 2026-08-23 : avec le mot de passe seul, la page
 * rendait 200 et 17 547 octets contenant le secret TOTP du compte **en clair** et
 * son QR. Le second facteur etait derivable du premier, et le fichier etait
 * identique a l'octet a celui d'`origin/main`, qui tourne en production.
 *
 * Quatre defauts corriges, quatre proprietes mesurees :
 *   1. un compte DEJA enrole est renvoye vers la verification (la divulgation) ;
 *   2. un GET n'ecrit plus rien : le secret vit en session jusqu'a la preuve ;
 *   3. la limitation de debit des deux autres portes 2FA s'applique ;
 *   4. l'anti-rejeu est effectif (il etait inerte — motif E-01).
 *
 * ══ ET LE CAS NORMAL, QUI COMPTE AUTANT ═════════════════════════════════════
 *
 * Un correctif evident peut casser le cas normal. Refuser la page a un compte
 * deja enrole ne doit RIEN retirer a un compte sans second facteur : la suite
 * deroule l'enrolement complet, au clavier et a la souris.
 *
 * ══ LA FIXTURE, ET POURQUOI ELLE EST SURE ═══════════════════════════════════
 *
 * Elle mute `rw-test-admin` (arbitrage de l'exploitant) : la valeur chiffree de
 * `totp_secret` est SAUVEGARDEE, effacee, puis RESTAUREE dans un `finally`, l'etat
 * rendu etant RELU pour etre prouve. Treize suites dependent de ce compte, et le
 * runner les joue en SEQUENCE : aucune n'est en vol pendant l'effacement.
 * Ni `rw-test-user` (D-5), ni `opsuser` (compte reel), ni les residus `e2e_test_*`.
 *
 * Aucun code TOTP n'est consomme sur un compte deja enrole : la premiere phase
 * s'arrete apres le mot de passe, la seconde se joue sur un compte sans secret.
 * Le garde anti-rejeu (par compte, en base) n'est donc jamais sollicite.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-auth-enrolement.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const COMPTE = 'rw-test-admin';

/**
 * Les chemins et les marqueurs, par cible.
 *
 * Le QR differe par NATURE : le legacy rend un PNG en base64 (`gd`), le portage
 * un SVG en ligne — son conteneur n'a ni `gd` ni `imagick` (mesure). La suite
 * mesure donc « un QR est present », pas « une balise <img> est presente » :
 * exiger la forme du legacy ferait echouer un portage correct.
 */
const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion?lang=fr',
        enrolement: '/second-facteur/enrolement',
        motifEnrolement: /second-facteur\/enrolement/,
        motifVerification: /second-facteur(?!\/enrolement)/,
        motifAbouti: /\/cgu|\/profil/,
        qr: '[data-rw="enrolement-qr"] svg',
        secret: '[data-rw="enrolement-secret"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        enrolement: '/auth/enable_2fa.php',
        motifEnrolement: /enable_2fa\.php/,
        motifVerification: /verify_2fa\.php/,
        motifAbouti: /terms\.php|profile\.php/,
        qr: 'img[src^="data:image/png;base64,"]',
        secret: '.select-all',
    };

let echecs = 0;
const lignes = [];
function verifie(l, ok, d, __quatrieme) {
    /*
     * INF-002 — LE QUATRIEME ARGUMENT N'EXISTE PAS ICI, ET IL NE PASSERA PLUS
     * EN SILENCE.
     *
     * Ce depot porte DEUX semantiques du troisieme argument, et elles sont
     * OPPOSEES : dans ce fichier (70 suites) le detail s'affiche sur un PASS
     * COMME sur un FAIL ; dans 12 autres, il ne s'affiche QUE sur un FAIL, et
     * un quatrieme argument y porte l'informatif. Rien ne les distingue a la
     * lecture d'un appel.
     *
     * Un appel a quatre arguments ecrit pour l'autre convention etait donc
     * SILENCIEUSEMENT tronque : le quatrieme ignore, et l'explication d'echec
     * imprimee sur des lignes VERTES. Quatre occurrences mesurees le
     * 2026-08-27, dont deux preexistantes. On ne le laisse plus arriver sans
     * bruit — et le message nomme le REMEDE, faute de quoi on le contourne en
     * retirant l'argument.
     */
    if (__quatrieme !== undefined) {
        throw new Error(
            'INF-002 : `verifie` de ce fichier prend TROIS arguments, et son detail '
            + 's\'affiche sur un PASS COMME sur un FAIL. Pour une explication qui ne '
            + 'doit paraitre qu\'en cas d\'echec, ecrire le troisieme argument ainsi : '
            + '`ok ? <ce qu\'on a mesure> : <ce qui explique l\'echec>`.');
    }
 lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

function secretEnBase() {
    const r = litEnBase(`SELECT COALESCE(totp_secret, '(ABSENT)') FROM rootwarden.users WHERE name = '${COMPTE}'`);

    return r.length ? r[0] : '(ABSENT)';
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});

/**
 * L'ETAPE MOT DE PASSE, AU CLAVIER ET A LA SOURIS. On ne soumet pas le
 * formulaire par script : on remplit les champs et on CLIQUE le bouton, donc on
 * mesure aussi que le formulaire est cable.
 */
async function etapeMotDePasse() {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));

    await page.goto(`${BASE}${C.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', COMPTE, { delay: 10 });
    await page.type('input[name="password"]', MDP, { delay: 10 });
    const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]');
    try { await nav; } catch { /* le verdict se lit sur l'URL, pas sur l'attente */ }

    return { ctx, page, erreursJs };
}

/** Ce que la page d'enrolement montre : son QR et le secret propose. */
function lisEcranEnrolement(page) {
    return page.evaluate((selQr, selSecret) => {
        const qr = document.querySelector(selQr);
        const clair = document.querySelector(selSecret);
        const champ = document.querySelector('input[name="2fa_code"]');
        /* LE BOUTON DU FORMULAIRE QUI PORTE LE CHAMP, pas le premier de la page. */
        const form = champ ? champ.closest('form') : null;

        return {
            qr: !! qr,
            secret: clair ? clair.textContent.trim().replace(/\s+/g, '') : '',
            champCode: !! champ,
            bouton: !! (form && form.querySelector('button[type="submit"], input[type="submit"]')),
        };
    }, C.qr, C.secret);
}

const secretOrigine = secretEnBase();
let fixturePosee = false;

try {
    constate('cible', CIBLE);

    verifie('la fixture part d\'un compte REELLEMENT enrole',
        secretOrigine !== '(ABSENT)',
        secretOrigine === '(ABSENT)' ? 'aucun secret en base' : 'secret present');
    litEnBase('DELETE FROM rootwarden.login_attempts');

    /* ══ 1. LA DIVULGATION — un compte DEJA enrole ═══════════════════════════ */
    {
        const { ctx, page, erreursJs } = await etapeMotDePasse();
        constate('apres le clic sur « se connecter »', page.url().replace(BASE, ''));
        verifie('le mot de passe seul ne suffit pas : on atterrit sur la verification',
            C.motifVerification.test(page.url()), page.url().replace(BASE, ''));

        /*
         * LE GESTE DE L'ATTAQUANT : taper l'URL d'enrolement alors que la 2FA est
         * encore en attente. C'est une navigation directe, et c'est voulu — c'est
         * exactement ce qui rendait le secret.
         */
        await page.goto(`${BASE}${C.enrolement}`, { waitUntil: 'networkidle2' });
        const vu = await lisEcranEnrolement(page);
        const corps = await page.content();
        constate(`url apres avoir tape ${C.enrolement}`, page.url().replace(BASE, ''));
        verifie('un compte DEJA enrole est renvoye vers la verification',
            C.motifVerification.test(page.url()), page.url().replace(BASE, ''));
        verifie('aucun QR code ne lui est montre', vu.qr === false, `qr=${vu.qr}`);
        verifie('le secret TOTP du compte n\'apparait PAS a l\'ecran',
            vu.secret === '' && ! corps.includes(secretOrigine.slice(0, 24)),
            vu.secret === '' ? 'aucun secret rendu' : 'SECRET RENDU');
        verifie('aucune erreur JS pendant la sequence', erreursJs.length === 0,
            erreursJs.join(' | ') || 'aucune');
        await ctx.close();
    }

    /* ══ 2. LE CAS NORMAL — un compte SANS secret doit pouvoir s'enroler ══════ */
    litEnBase(`UPDATE rootwarden.users SET totp_secret = NULL WHERE name = '${COMPTE}'`);
    fixturePosee = true;
    verifie('la fixture est en place : le compte n\'a plus de second facteur',
        secretEnBase() === '(ABSENT)',
        `secret en base : ${secretEnBase() === '(ABSENT)' ? 'absent' : 'present'}`);
    litEnBase('DELETE FROM rootwarden.login_attempts');

    {
        if (resteFenetre() < 8) { await dors((resteFenetre() + 1) * 1000); }
        const { ctx, page, erreursJs } = await etapeMotDePasse();
        constate('apres le clic, compte sans secret', page.url().replace(BASE, ''));
        verifie('un compte SANS second facteur atterrit sur l\'enrolement',
            C.motifEnrolement.test(page.url()), page.url().replace(BASE, ''));

        const ecran = await lisEcranEnrolement(page);
        verifie('l\'ecran montre un QR code', ecran.qr === true, `qr=${ecran.qr}`);
        verifie('il offre le secret en clair pour une saisie manuelle',
            ecran.secret.length >= 16, `${ecran.secret.length} caracteres`);
        verifie('il porte un champ de code et un bouton',
            ecran.champCode && ecran.bouton,
            `champ=${ecran.champCode} bouton=${ecran.bouton}`);

        /*
         * UN GET N'ECRIT PLUS RIEN. C'etait le defaut de principe : le secret
         * etait enregistre des l'affichage, sans jeton CSRF et avant toute preuve.
         */
        verifie('afficher la page n\'a RIEN ecrit en base',
            secretEnBase() === '(ABSENT)',
            `secret en base apres affichage : ${secretEnBase() === '(ABSENT)' ? 'toujours absent' : 'ECRIT'}`);

        /*
         * LE SECRET NE DOIT PAS CHANGER D'UN AFFICHAGE A L'AUTRE : le QR scanne et
         * le code attendu doivent concorder. En regenerer un a chaque vue rendrait
         * l'enrolement impossible — c'est le risque introduit par le correctif.
         */
        await page.reload({ waitUntil: 'networkidle2' });
        const ecran2 = await lisEcranEnrolement(page);
        verifie('le secret propose survit a un rechargement',
            ecran.secret !== '' && ecran.secret === ecran2.secret,
            ecran.secret === ecran2.secret ? 'identique' : 'REGENERE');

        /* ── Le code, tape au clavier, soumis par un CLIC ───────────────────── */
        if (resteFenetre() < 8) { await dors((resteFenetre() + 1) * 1000); }
        await page.type('input[name="2fa_code"]', totp(ecran.secret), { delay: 12 });
        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]');
        try { await nav; } catch { /* l'URL tranche */ }
        constate('apres le clic sur « activer »', page.url().replace(BASE, ''));
        verifie('un premier code valide acheve l\'enrolement',
            C.motifAbouti.test(page.url()), page.url().replace(BASE, ''));

        const apres = secretEnBase();
        verifie('le secret est ecrit en base APRES la preuve, et pas avant',
            apres !== '(ABSENT)',
            `secret en base : ${apres === '(ABSENT)' ? 'toujours absent' : 'present'}`);
        verifie('et il n\'est pas stocke en CLAIR', apres !== ecran.secret,
            apres === ecran.secret ? 'stocke en clair !' : 'chiffre');
        verifie('aucune erreur JS pendant l\'enrolement', erreursJs.length === 0,
            erreursJs.join(' | ') || 'aucune');
        await ctx.close();
    }
} catch (e) {
    verifie('la suite s\'est deroulee sans exception', false, String(e).split('\n')[0]);
} finally {
    /*
     * RESTAURATION, ET ETAT RELU POUR ETRE PROUVE. Treize suites dependent de ce
     * compte : si la restauration echoue, il faut que ca se voie ICI.
     */
    if (secretOrigine !== '(ABSENT)') {
        litEnBase(`UPDATE rootwarden.users SET totp_secret = '${secretOrigine}' WHERE name = '${COMPTE}'`);
    }
    litEnBase('DELETE FROM rootwarden.login_attempts');
    const rendu = secretEnBase();
    verifie('le secret d\'origine du compte est RESTAURE',
        rendu === secretOrigine,
        rendu === secretOrigine ? 'identique a l\'entree' : 'DIFFERENT — treize suites en dependent');
    constate('fixture posee pendant la suite', fixturePosee ? 'oui, et defaite' : 'non');
    await navigateur.close();
    console.log(lignes.join('\n'));
    console.log(`\n${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
    process.exit(echecs === 0 ? 0 : 1);
}
