/**
 * go-auth-step-up.mjs - `auth/` sous-lot A5 : LA RE-AUTHENTIFICATION PONCTUELLE.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443   `auth/step_up.php` + `auth/step_up_verify.php`
 *   laravel  http://localhost:8444    le contrat que le portage doit tenir
 *
 * ══ POURQUOI CE SOUS-LOT ════════════════════════════════════════════════════
 *
 * Une session valide ne doit pas suffire a declencher un geste destructeur. Le
 * legacy l'exige sur quatre chemins ; le portage, lui, **REFUSE** les routes
 * concernees au lieu de les transmettre (`PasserelleController`, 403 +
 * `portage: non_porte`). Ce n'est pas un trou — accorder root sans le second
 * controle serait un recul — mais c'est une capacite manquante : apres une
 * bascule directe, personne ne pourrait plus deployer ni annuler une politique
 * sudo depuis le portail.
 *
 * ══ CE QUE LA SUITE MESURE, ET POURQUOI C'EST SUR ═══════════════════════════
 *
 * **Tout se mesure sur le CHEMIN DE REFUS.** Aucun geste root n'est jamais
 * emis : pas un deploiement, pas une revocation, pas une suppression de compte.
 * Les quatre chemins gardes rendent 403 **avant** de lire leur corps, donc les
 * sonder ne produit aucun effet.
 *
 * La seule cible re-jouee apres un step-up accorde est
 * `adm/api/update_permissions.php` **avec un corps VIDE** : le fichier valide la
 * presence des champs (`:71`) et sort sur « Donnees manquantes » **avant toute
 * ecriture**. C'est ce qui rend le modal pilotable par de vrais clics sans rien
 * detruire — verifie en lisant le fichier AVANT de faire cliquer, jamais apres.
 *
 * ══ LES QUATRE DEFAUTS QUE LE PORTAGE NE DOIT PAS REPRENDRE ═════════════════
 *
 * Mesures par cette suite, chacun sur le chemin de refus :
 *
 *  1. **l'anti-rejeu est par SESSION** (`$_SESSION['_step_up_last_totp']`) : le
 *     meme code, rejoue depuis une session NEUVE, est accepte. Meme famille que
 *     E-01. Le portage doit le porter **par COMPTE et EN BASE** ;
 *  2. **l'anti-rejeu ne couvre pas la connexion** : la cle du legacy est propre
 *     au step-up, si bien qu'un code observe a la CONNEXION reste utilisable
 *     pour obtenir un step-up — l'escalade meme que le step-up existe pour
 *     empecher. Le portage partage un compteur de fenetre MONOTONE par compte
 *     entre les deux : un code ne sert qu'UNE FOIS, pour quoi que ce soit ;
 *  3. **le debit n'est pas remis a zero sur succes** : `:53` empile la tentative
 *     avant toute verification et rien ne vide le tableau apres un succes. Cinq
 *     step-up reussis en une minute rendent **429** ;
 *  4. **`api_proxy.php:63` fusionne TROIS routes root sous un seul nom d'action**
 *     (`policy_action`). Un step-up consenti pour annuler une politique autorise
 *     donc un DEPLOIEMENT sudo pendant quinze minutes. Mesure sans rien deployer :
 *     les trois refus annoncent le MEME `action`.
 *
 * ══ PILOTEE PAR DES CLICS ═══════════════════════════════════════════════════
 *
 * Le modal du legacy est pilote au clavier et a la souris (`page.type` sur
 * `#rw-stepup-code`, `page.click` sur `#rw-stepup-ok`), et la requete d'origine
 * est bien re-jouee par le greffon de `window.fetch`.
 *
 * Les proprietes qui n'ont AUCUNE interface — un 405, le nom d'action porte par
 * un corps JSON, un anti-rejeu, une limite de debit — sont mesurees par des
 * requetes forgees **emises depuis la page**. Motif ecrit, comme l'exige la
 * convention. Elles passent par `XMLHttpRequest` et **non** par `fetch` : le
 * greffon de `utils.js` intercepte tout 403 portant `step_up_required` et ouvre
 * le modal, qui attendrait alors une saisie que personne ne fera — la requete
 * forgee n'aurait jamais rendu et la suite aurait expire sans rien mesurer.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-auth-step-up.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';

/**
 * Les chemins, par cible. Cote portage c'est un CONTRAT : la suite le declare
 * avant qu'il existe, et sa base rouge mesure ce qui manque.
 */
const C = CIBLE === 'laravel'
    ? {
        verifier: '/profil/step-up',
        /** Le portage doit nommer CHAQUE route, pas les fusionner. */
        gardees: [
            ['/api/gateway/policy/sudo/deploy', 'policy_sudo_deploy'],
            ['/api/gateway/policy/sftp/deploy', 'policy_sftp_deploy'],
            ['/api/gateway/policy/rollback', 'policy_rollback'],
        ],
        /** Cible de rejeu sure : le portage ne porte pas `adm/`. */
        revocation: '/profil/step-up/revoquer',
        /*
         * CIBLE DE REJEU SURE, VERIFIEE EN LISANT LE BACKEND.
         * `backend/routes/policies.py:220-225` : `sudo_deploy` resout d'abord
         * les identifiants SSH, et `_resolve_ssh_creds` (`:44-47`) rend
         * « machine_id requis. » en 400 des que le corps n'en porte pas —
         * AVANT tout `ssh_session`. Un corps vide ne deploie donc rien.
         */
        rejeu: '/api/gateway/policy/sudo/deploy',
        attenduRejeu: /machine_id/i,
        /*
         * PAS DE PANNEAU SUR LE PORTAGE, ET C'EST DELIBERE : aucune page portee
         * n'appelle une route gardee par un step-up. Les pages qui le feront —
         * `ssh/` (K4) et `adm/` — ne sont pas portees. Un panneau pose dans le
         * gabarit sans flux pour l'exercer ne serait mesurable par aucun clic, et
         * une piece non mesuree dans le gabarit met en risque les quatorze pages
         * deja portees. Voir PARITE.md E-96.
         */
        aPanneau: false,
        action: 'policy_sudo_deploy',
        action2: 'policy_rollback',
        panneau: '[data-rw="step-up-panneau"]',
        champ: '[data-rw="step-up-code"]',
        valider: '[data-rw="step-up-valider"]',
        annuler: '[data-rw="step-up-annuler"]',
    }
    : {
        verifier: '/auth/step_up_verify.php',
        gardees: [
            ['/adm/api/update_permissions.php', 'update_permissions'],
            ['/adm/api/delete_user.php', 'delete_user'],
            ['/adm/api/anonymize_user.php', 'anonymize_user'],
            ['/api_proxy.php/policy/sudo/deploy', 'policy_action'],
            ['/api_proxy.php/policy/sftp/deploy', 'policy_action'],
            ['/api_proxy.php/policy/rollback', 'policy_action'],
        ],
        revocation: null,
        rejeu: '/adm/api/update_permissions.php',
        attenduRejeu: /donn[eé]es manquantes/i,
        aPanneau: true,
        action: 'update_permissions',
        action2: 'delete_user',
        panneau: '#rw-stepup-overlay',
        champ: '#rw-stepup-code',
        valider: '#rw-stepup-ok',
        annuler: '#rw-stepup-cancel',
    };

/** Les trois routes root, celles dont le nom d'action doit differer. */
const ROOT = C.gardees.filter(([chemin]) => /policy/.test(chemin));

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
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
 note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { note(`INFO  ${l} : ${v}`); }
/**
 * Une propriete que le PORTAGE doit tenir et que le legacy ne tient pas.
 *
 * Sur le portage c'est une assertion. Le detail n'est imprime QUE sur un echec :
 * il explique le defaut du legacy, et l'imprimer sur un PASS ferait lire au
 * journal l'inverse de ce qui vient d'etre mesure — un detail est imprime au
 * PASS comme au FAIL, il doit donc dire ce qu'on a TROUVE.
 */
function verifiePortage(l, ok, d, __quatrieme) {
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

    if (CIBLE === 'laravel') return verifie(l, ok, ok ? '' : d);
    constate(l, `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

/**
 * UN CODE JAMAIS ENCORE EMPLOYE PAR CE SCRIPT.
 *
 * Le portage partage un compteur de fenetre MONOTONE par compte entre la
 * connexion et le step-up : un code ne sert qu'UNE FOIS, pour quoi que ce soit.
 * Deux connexions tombant dans la meme fenetre de 30 s emploieraient donc le
 * meme code, et la seconde serait refusee comme un rejeu — la suite echouerait
 * sur une propriete qu'elle ne cherchait pas a mesurer.
 *
 * Attend aussi qu'il reste assez de fenetre pour que le code survive a l'aller.
 */
let derniereFenetre = -1;
async function codeFrais() {
    for (;;) {
        const f = Math.floor(Date.now() / 1000 / 30);
        if (f > derniereFenetre && resteFenetre() >= 6) {
            derniereFenetre = f;

            return totp(SECRET);
        }
        await dors(1500);
    }
}

/** Un code a six chiffres qui n'est PAS le code courant, ni celui d'a cote. */
function codeFaux() {
    const interdits = new Set([totp(SECRET)]);
    for (let n = 100000; n < 100050; n += 1) {
        const c = String(n);
        if (! interdits.has(c)) return c;
    }

    return '100000';
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});
const contextes = [];
/** Une page encore ouverte, pour rendre les privileges dans le `finally`. */
let pageVivante = null;

/** Connexion complete, AU CLAVIER ET A LA SOURIS. */
async function connecte() {
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(40000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]' }
        : { connexion: '/auth/login.php', cgu: /terms\.php/, accepte: 'button[name="accept_terms"]' };

    await page.goto(`${BASE}${chemins.connexion}?lang=fr`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', COMPTE, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    for (let essai = 0; essai < 2; essai += 1) {
        const champ = await page.$('input[name="2fa_code"]');
        if (! champ) break;
        await champ.click({ clickCount: 3 });
        await champ.type(await codeFrais(), { delay: 8 });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
    }
    if (chemins.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$(chemins.accepte);
        if (b) await b.evaluate((x) => x.click());
        try { await nav; } catch {}
    }

    pageVivante = page;

    return { ctx, page, erreursJs };
}

/**
 * Une requete forgee EMISE DEPUIS LA PAGE, par `XMLHttpRequest`.
 *
 * Motif : ces proprietes n'ont aucune interface, et `fetch` est greffe par
 * `utils.js` — un 403 portant `step_up_required` y ouvre le modal, qui
 * attendrait une saisie. La requete n'aurait jamais rendu.
 */
function forge(page, chemin, corps, methode = 'POST') {
    return page.evaluate(async (chemin, corps, methode) => {
        const jeton = document.querySelector('meta[name="csrf-token"]')?.content
            || document.querySelector('input[name="csrf_token"]')?.value || '';
        const charge = corps === null ? null : JSON.stringify({ ...corps, csrf_token: jeton });

        return new Promise((resolve) => {
            const x = new XMLHttpRequest();
            x.open(methode, chemin, true);
            if (charge !== null) x.setRequestHeader('Content-Type', 'application/json');
            x.setRequestHeader('X-CSRF-TOKEN', jeton);
            x.onloadend = () => resolve({ statut: x.status, texte: (x.responseText || '').slice(0, 400) });
            x.onerror = () => resolve({ statut: -1, texte: '(erreur reseau)' });
            x.send(charge);
        });
    }, chemin, corps, methode);
}

/** Le corps JSON d'une reponse forgee, ou un objet vide. */
function json(r) { try { return JSON.parse(r.texte) || {}; } catch { return {}; } }
/**
 * Le message d'une reponse, LU DANS LE CORPS ANALYSE.
 *
 * Un premier jet cherchait « Donnees manquantes » dans le texte BRUT : le PHP
 * echappe les non-ASCII, si bien que la reponse porte `Donn\u00e9es manquantes`
 * et qu'aucune expression reguliere cherchant un `e` accentue ne pouvait
 * correspondre. Deux assertions echouaient sur une reponse pourtant JUSTE — ce
 * n'etait pas le legacy qui avait tort, c'etait la suite.
 */
function message(texte) {
    try { return String(JSON.parse(texte)?.message ?? ''); } catch { return String(texte); }
}

/**
 * REND LES PRIVILEGES DU COMPTE.
 *
 * Appele a l'ENTREE et dans le `finally`. Sans cela la suite n'etait pas
 * idempotente, et ce n'etait pas theorique : une marque posee par une execution
 * survivait quinze minutes et l'execution SUIVANTE trouvait sa premiere sonde
 * TRANSMISE au backend au lieu d'etre refusee. Seul un `machine_id` absent a
 * empeche un deploiement sudo reel — de la chance, pas une precaution.
 *
 * Le legacy n'offre aucun equivalent : sa marque vit quinze minutes et rien ne
 * permet de l'abreger. La suite ne peut donc nettoyer que du cote portage.
 */
async function rendPrivileges(page) {
    if (! C.revocation) return null;
    const r = await forge(page, C.revocation, {});

    return json(r);
}

/** Un step-up demande par requete forgee. */
async function demandeStepUp(page, action, code) {
    const r = await forge(page, C.verifier, { action, totp_code: code, code });

    return { ...r, corps: json(r) };
}

let etapes = 0;
/** Chaque etape isolee : une exception ne doit pas emporter le journal entier. */
async function etape(titre, fn) {
    etapes += 1;
    try {
        await fn();
    } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e).split('\n')[0]);
    }
}

try {
    /*
     * ══ LE SUJET DE CETTE SUITE N'EXISTE PLUS COTE LEGACY ═════════════════
     *
     * Une suite de parite dont la moitie legacy a ete archivee ne doit pas
     * ECHOUER : un rouge permanent finit par ne plus etre lu. Elle CONSTATE.
     *
     * LE CONSTAT VIENT AVANT LA CONNEXION : la sonde n'ouvre pas de navigateur,
     * et se connecter d'abord consommerait un code TOTP — garde anti-rejeu par
     * COMPTE et persistant — pour mesurer une page qui n'existe plus.
     */
    if (CIBLE === 'legacy') {
        /*
         * Le sujet n'est pas une PAGE mais deux points d'API d'administration.
         * On constate sur l'un et on fait verifier l'autre en `fichiers` : le
         * geste mesure portait sur les DEUX, en constater un seul laisserait
         * croire que l'autre repond encore.
         */
        const archivee = await constateArchivage({
            base: BASE, chemin: '/adm/api/delete_user.php',
            fichiers: ['/adm/api/anonymize_user.php'], verifie, constate,
        });
        if (archivee) throw new Error('__archivee__');
    }

    // ══ PARTIE A — le garde refuse, et NOMME l'action ═══════════════════════
    const s1 = await connecte();
    pageVivante = s1.page;
    constate('cible', `${CIBLE} — ${BASE}`);
    constate('compte', `${COMPTE} (role 3)`);
    const entree = await rendPrivileges(s1.page);
    constate('privileges rendus a l\'entree', entree
        ? `${entree.revoquees} marque(s) effacee(s)` : 'sans objet sur cette cible');

    const noms = new Map();
    for (const [chemin, attendu] of C.gardees) {
        await etape(`refus de ${chemin}`, async () => {
            const r = await forge(s1.page, chemin, {});
            const c = json(r);
            /* LE CORPS SUR ECHEC. Un « HTTP 400 » seul ne dit pas LEQUEL des
             * refus a parle : la passerelle en rend deux (aucune route, chemin
             * invalide) avant meme d'arriver au step-up. */
            verifie(`${chemin} est refuse sans step-up`, r.statut === 403,
                r.statut === 403 ? `HTTP ${r.statut}`
                    : `HTTP ${r.statut} — ${r.texte.slice(0, 200)} — page ${await s1.page.url()}`);
            verifie(`${chemin} annonce step_up_required`, c.step_up_required === true,
                `step_up_required = ${JSON.stringify(c.step_up_required)}`);
            verifie(`${chemin} nomme l'action « ${attendu} »`, c.action === attendu,
                `action = ${JSON.stringify(c.action)}`);
            noms.set(chemin, c.action);
        });
    }

    await etape('les trois routes root portent des noms DISTINCTS', async () => {
        const vus = ROOT.map(([chemin]) => noms.get(chemin));
        const distincts = new Set(vus.filter(Boolean)).size;
        constate('noms d\'action des trois routes root', vus.join(' / '));
        verifiePortage('les trois routes root portent des noms d\'action distincts',
            distincts === ROOT.length,
            `${distincts} nom(s) pour ${ROOT.length} routes — un step-up consenti pour l'une `
            + 'autorise les autres pendant quinze minutes');
    });

    await etape('la methode est contrainte', async () => {
        const r = await forge(s1.page, C.verifier, null, 'GET');
        verifie('le point de verification refuse GET', r.statut === 405, `HTTP ${r.statut}`);
    });

    // ══ PARTIE B — les regles du point de verification ══════════════════════
    await etape('un code mal forme est refuse', async () => {
        const r = await demandeStepUp(s1.page, C.action, '12345');
        verifie('un code de cinq chiffres est refuse', r.corps.success === false,
            `message = ${JSON.stringify(r.corps.message)}`);
    });

    await etape('une action absente est refusee', async () => {
        const r = await demandeStepUp(s1.page, '', codeFaux());
        verifie('une action vide est refusee', r.corps.success === false,
            `message = ${JSON.stringify(r.corps.message)}`);
    });

    await etape('un code faux est refuse', async () => {
        const r = await demandeStepUp(s1.page, C.action, codeFaux());
        verifie('un code a six chiffres mais faux est refuse', r.corps.success === false,
            `message = ${JSON.stringify(r.corps.message)}`);
    });

    /* Le code de reference de la partie B, jamais employe avant lui. */
    const codeB = await codeFrais();

    await etape('un code valide accorde le step-up', async () => {
        const r = await demandeStepUp(s1.page, C.action, codeB);
        verifie('un code valide accorde le step-up', r.corps.success === true,
            `message = ${JSON.stringify(r.corps.message)}`);
        /* Le legacy nomme le champ `valid_until` (un instant), le portage
         * `expire_dans` (une duree). On accepte les deux et on imprime CELUI
         * QU'ON A TROUVE : imprimer seulement le nom du legacy faisait lire
         * « valid_until = undefined » sur un PASS. */
        const echeance = ['valid_until', 'expire_dans']
            .filter((n) => typeof r.corps[n] === 'number')
            .map((n) => `${n} = ${r.corps[n]}`);
        verifie('la reponse annonce une echeance', echeance.length > 0,
            echeance.join(', ') || 'aucun champ d\'echeance');
    });

    await etape('le meme code ne se rejoue pas dans la meme session', async () => {
        const r = await demandeStepUp(s1.page, C.action, codeB);
        verifie('le meme code est refuse au second usage', r.corps.success === false,
            `message = ${JSON.stringify(r.corps.message)}`);
    });

    /*
     * UN CODE NE SERT QU'UNE FOIS, MEME POUR UNE AUTRE ACTION.
     *
     * Un premier jet de cette suite exigeait l'inverse — qu'un second step-up
     * pour une AUTRE action reste possible dans la meme fenetre de 30 s — au
     * motif que le refus du legacy gene un geste legitime. C'etait une exigence
     * DANGEREUSE : elle aurait autorise le rejeu d'un code observe a la
     * connexion pour obtenir un step-up, c'est-a-dire exactement l'escalade que
     * le step-up existe pour empecher. Le refus est la bonne reponse ; ce qui
     * cloche chez le legacy n'est pas qu'il refuse, c'est qu'il refuse depuis la
     * SESSION, donc de façon contournable (partie suivante).
     */
    await etape('un code ne sert qu\'une fois, meme pour une autre action', async () => {
        const r = await demandeStepUp(s1.page, C.action2, codeB);
        constate('second step-up, action differente, meme code',
            `success = ${JSON.stringify(r.corps.success)} — ${JSON.stringify(r.corps.message)}`);
        verifie('un code deja consomme est refuse meme pour une autre action',
            r.corps.success === false, JSON.stringify(r.corps.message));
    });

    if (C.rejeu) {
        await etape('le step-up accorde laisse passer, et rien n\'est ecrit', async () => {
            const r = await forge(s1.page, C.rejeu, {});
            const c = json(r);
            verifie('le chemin garde n\'est plus refuse pour absence de step-up',
                c.step_up_required !== true, `step_up_required = ${JSON.stringify(c.step_up_required)}`);
            const m = message(r.texte);
            verifie('le refus porte sur le CORPS, donc le step-up a laisse passer',
                C.attenduRejeu.test(m), m);
        });
    }

    // ══ PARTIE C — le modal, PAR DES CLICS ═════════════════════════════════
    if (C.aPanneau) {
        const s2 = await connecte();

        await etape('le modal s\'ouvre sur un refus de step-up', async () => {
            /* On lance la requete SANS l'attendre : c'est le greffon de `fetch`
             * qui doit ouvrir le modal. La promesse est mise de cote pour etre
             * relue apres le clic. */
            await s2.page.evaluate((chemin) => {
                const jeton = document.querySelector('meta[name="csrf-token"]')?.content || '';
                window.__rwEssai = fetch(chemin, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': jeton },
                    body: JSON.stringify({ csrf_token: jeton }),
                }).then((r) => r.text());
            }, C.rejeu);
            await s2.page.waitForSelector(C.panneau, { visible: true, timeout: 15000 });
            verifie('le refus ouvre le panneau de re-authentification', true, C.panneau);
        });

        await etape('le panneau nomme l\'action et porte ses trois pieces', async () => {
            const vu = await s2.page.evaluate((champ, valider, annuler, panneau) => {
                const p = document.querySelector(panneau);

                return {
                    champ: !! document.querySelector(champ),
                    valider: !! document.querySelector(valider),
                    annuler: !! document.querySelector(annuler),
                    texte: p ? (p.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 220) : '',
                };
            }, C.champ, C.valider, C.annuler, C.panneau);
            verifie('le panneau porte un champ de code', vu.champ);
            verifie('le panneau porte un bouton de validation', vu.valider);
            verifie('le panneau porte un bouton d\'annulation', vu.annuler);
            constate('texte du panneau', vu.texte);
            verifie('le panneau nomme l\'action concernee', /update_permissions/.test(vu.texte),
                vu.texte.slice(0, 80));
            verifiePortage('le panneau vouvoie', ! /\bton\b|\bEntre le code\b/.test(vu.texte),
                'le modal du legacy tutoie, et son texte est en francais EN DUR — hors parite FR/EN');
        });

        await etape('un code mal forme est refuse SANS quitter le panneau', async () => {
            await s2.page.type(C.champ, '123', { delay: 20 });
            await s2.page.click(C.valider);
            await dors(600);
            const ouvert = await s2.page.evaluate((p) => {
                const e = document.querySelector(p);

                return !! e && getComputedStyle(e).display !== 'none';
            }, C.panneau);
            verifie('le panneau reste ouvert apres un code mal forme', ouvert);
        });

        await etape('le code valide fait re-jouer la requete d\'origine, PAR UN CLIC', async () => {
            if (resteFenetre() < 8) await dors((resteFenetre() + 1) * 1000);
            const champ = await s2.page.$(C.champ);
            await champ.click({ clickCount: 3 });
            await champ.type(totp(SECRET), { delay: 20 });
            await s2.page.click(C.valider);
            const texte = await s2.page.evaluate(() => window.__rwEssai);
            const m = message(texte);
            constate('reponse de la requete re-jouee', m);
            verifie('la requete d\'origine a bien ete re-jouee apres le step-up',
                /donn[eé]es manquantes/i.test(m),
                'le refus porte sur le CORPS, donc le step-up a ete accorde et rien n\'a ete ecrit');
        });

        await etape('aucune erreur JS pendant le pilotage du panneau', async () => {
            verifie('aucune erreur JS', s2.erreursJs.length === 0, s2.erreursJs.join(' | ') || 'aucune');
        });
    }

    // ══ PARTIE D — l'anti-rejeu traverse-t-il les sessions ? ════════════════
    await etape('l\'anti-rejeu traverse-t-il une session NEUVE ?', async () => {
        /* Les DEUX sessions sont ouvertes AVANT d'employer le code : le rejeu
         * suit le premier usage de quelques millisecondes, et non du temps
         * qu'aurait pris une connexion. Sans cela le code serait hors fenetre
         * et l'assertion echouerait pour une mauvaise raison. */
        const a = await connecte();
        const b = await connecte();
        const code = await codeFrais();
        const r1 = await demandeStepUp(a.page, C.action, code);
        const r2 = await demandeStepUp(b.page, C.action, code);
        constate('premier usage du code (session A)', JSON.stringify(r1.corps.success));
        constate('rejeu du MEME code (session B)', `${JSON.stringify(r2.corps.success)} — `
            + JSON.stringify(r2.corps.message));
        verifie('le premier usage est accorde', r1.corps.success === true,
            JSON.stringify(r1.corps.message));
        verifiePortage('le rejeu depuis une session NEUVE est refuse', r2.corps.success === false,
            'l\'anti-rejeu est pose en SESSION : une session neuve le contourne, comme E-01');
    });

    // ══ PARTIE E — la limite de debit, en DERNIER (elle brule la session) ═══
    await etape('la limite de debit, et ce qu\'elle compte', async () => {
        const d = await connecte();
        const faux = codeFaux();
        const statuts = [];
        for (let i = 0; i < 6; i += 1) {
            const r = await demandeStepUp(d.page, C.action, faux);
            statuts.push(r.statut);
        }
        /*
         * LE QUOTA DU PORTAGE EST PAR COMPTE, PAS PAR SESSION : il traverse donc
         * les parties de cette suite, la ou celui du legacy repartait de zero a
         * chaque session neuve. Les deux series de statuts ne sont pas
         * directement comparables d'une cible a l'autre, et c'est voulu — le but
         * est de brider le COMPTE, pas le navigateur.
         */
        constate('six tentatives fausses de suite', statuts.join(' ')
            + (CIBLE === 'laravel' ? ' (quota par COMPTE : il traverse les parties)' : ''));
        verifie('la limite de debit finit par rendre 429', statuts.includes(429),
            statuts.join(' '));

        /* Un SUCCES compte-t-il dans la limite ?
         *
         * La mesure ci-dessus fixe le quota : cinq tentatives passent, la
         * SIXIEME rend 429 (`count >= 5` est evalue AVANT l'empilement). Un
         * premier jet faisait un succes puis QUATRE tentatives — cinq en tout,
         * donc aucune ne pouvait etre refusee : l'assertion passait sans rien
         * pouvoir distinguer. Il faut CINQ tentatives apres le succes : si la
         * derniere rend 429, le succes a bien consomme un jeton. */
        const e = await connecte();
        const ok = await demandeStepUp(e.page, C.action, await codeFrais());
        constate('succes initial', JSON.stringify(ok.corps.success));
        const apres = [];
        for (let i = 0; i < 5; i += 1) {
            const r = await demandeStepUp(e.page, C.action, faux);
            apres.push(r.statut);
        }
        constate('cinq tentatives apres le succes', apres.join(' '));
        /*
         * CONDITIONNEE AU SUCCES PREALABLE. Sans cette garde, l'assertion
         * passait sur le portage *parce que* le point de verification repondait
         * 404 : cinq 404 ne contiennent aucun 429, donc « le quota n'est pas
         * consomme » — un PASS dont la raison etait l'ABSENCE de la
         * fonctionnalite. Un pass dont on ne sait pas pourquoi il passe ne vaut
         * rien : il faut d'abord qu'un step-up ait REUSSI.
         */
        verifiePortage('un step-up REUSSI ne consomme pas le quota',
            ok.corps.success === true && apres[4] !== 429,
            ok.corps.success === true
                ? 'la tentative est empilee avant toute verification et rien ne vide le tableau '
                  + 'sur succes : cinq step-up legitimes en une minute rendent 429'
                : `non mesurable : aucun step-up n'a reussi (statuts ${apres.join(' ')})`);
    });
} catch (e) {
    // `__archivee__` est la sortie NORMALE d'un sujet archive, pas une panne.
    if (String(e && e.message || e).includes('__archivee__')) { /* le constat a tout dit */ } else {
    verifie('deroulement de la suite', false, String(e).split('\n')[0]);
    }
} finally {
    /* LES PRIVILEGES AVANT LES FERMETURES : la revocation a besoin d'une page
     * vivante et de sa session. */
    if (pageVivante) {
        try {
            const sortie = await rendPrivileges(pageVivante);
            if (sortie) constate('privileges rendus a la sortie',
                `${sortie.revoquees} marque(s) effacee(s)`);
        } catch (e) {
            note(`FAIL  restitution des privileges  — ${String(e).split('\n')[0]}`);
            echecs++;
        }
    }
    for (const ctx of contextes) {
        try { await ctx.close(); } catch {}
    }
    try { await navigateur.close(); } catch {}
}

note('');
const pass = lignes.filter((l) => l.startsWith('PASS')).length;
note(`${pass} PASS / ${echecs} FAIL — ${etapes} etapes, cible ${CIBLE}`);
process.exit(echecs === 0 ? 0 : 1);
