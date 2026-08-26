/**
 * go-adm-cles-api.mjs - Sous-lot D7 de `adm/` : les cles d'API.
 *
 * `legacy/adm/api_keys.php` (535 l.). CRUD en base, aucun appel backend.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/adm/api_keys.php
 *   laravel  http://localhost:8444/cles-api   (pas encore porte)
 *
 * ══ CONTRAINTE PERMANENTE : CETTE SUITE N'IMPRIME JAMAIS UNE CLE ══════════
 *
 * La clé n'existe en clair qu'une fois, dans la reponse de sa creation — la
 * table ne stocke que `key_prefix` et `key_hash`. Tout ce qui la concerne se
 * mesure donc en BOOLEENS et en LONGUEURS, jamais en valeur, et les captures
 * sont prises APRES rechargement, quand la page ne l'affiche plus.
 *
 * ══ TROIS DEFAUTS, TOUS MESURES ══════════════════════════════════════════
 *
 * 1. LA VALIDATION ET L'APPLICATION N'EMPLOIENT PAS LE MEME MOTEUR.
 *    `api_keys.php:47` valide chaque motif de portee en PCRE
 *    (`preg_match('#…#')`) ; `backend/routes/helpers.py:88` l'applique en
 *    Python (`re.search`). Mesure du 2026-08-26 : PHP accepte les six motifs
 *    d'epreuve, Python en refuse deux — `(?<nom>…)` et `(?R)`.
 *    Une portee acceptee a l'ecriture peut donc etre incompilable a la lecture.
 *
 * 2. LA PORTEE N'EST PAS ANCREE. `re.search` cherche n'importe ou : un motif
 *    `/deploy` couvre `/x/deploy_platform_key`, et `/cve_scan` couvre
 *    `/admin/cve_scan_all`. Une portee se lit plus etroite qu'elle n'est —
 *    meme classe qu'E-02, sur une autre surface.
 *
 * 3. CREER UNE CLE ENREGISTRE UNE SECONDE FOIS LA CLE D'ENVIRONNEMENT.
 *    `api_keys.php:80-89` insere `proxy-internal-legacy` par `INSERT IGNORE`,
 *    qui ne se protege que par l'unicite du NOM. Or `bootstrap_api_key.py` a
 *    deja enregistre le meme secret sous `proxy-internal-legacy-bootstrap-…`,
 *    et `key_hash` n'est PAS unique. Deux lignes actives pour un meme secret.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 *   - la page est purement en base : aucun effet distant, aucun courriel ;
 *   - toutes les cles creees portent un nom d'epreuve et sont SUPPRIMEES ;
 *   - le doublon `proxy-internal-legacy` eventuellement cree par le geste est
 *     borne par un identifiant releve a l'entree, et supprime lui aussi ;
 *   - la cle d'environnement deja enregistree (id 1) n'est ni lue, ni citee,
 *     ni touchee : la suite verifie seulement qu'elle est INTACTE.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-adm-cles-api
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
/** Role 2 : la page est reservee au role 3, il doit etre refuse. */
const COMPTE_ROLE = 'rw-test-admin';
const SECRET_ROLE = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

const CLE_EPREUVE = 'epreuve-d7-cle';
const CLE_PCRE = 'epreuve-d7-pcre';
/** Motif valide en PCRE, INCOMPILABLE en Python : groupe nomme a la PCRE. */
const MOTIF_PCRE_SEUL = '(?<zone>/cve_.*)';

const DOSSIER_CAPTURES = new URL('./screenshots/adm', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/cles-api',
        form: '[data-rw="cle-api-form"]',
        champNom: '[data-rw="cle-api-nom"]',
        // LE PORTAGE N'A PAS DE CHAMP LIBRE : la portee se coche dans une liste
        // FERMEE. C'est la decision du sous-lot, prise sur E-135 et E-136 — ce
        // qui est valide ici doit etre compilable la-bas, et ce portage ne
        // compile pas du Python.
        champPortee: null,
        modulePortee: '[data-rw="cle-api-module"][data-module="cve"]',
        valeur: '[data-rw="cle-api-valeur"]',
        revoquer: '[data-rw="cle-api-revoquer"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/adm/api_keys.php',
        form: '#apikey-form',
        champNom: '#ak-name',
        champPortee: '#ak-scope',
        modulePortee: null,
        valeur: '#new-key-value',
        revoquer: 'form:has(input[name="action"][value="revoke"]) button[type="submit"]',
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
function verifie(l, ok, d) { note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs += 1; }
function constate(l, v) { note(`INFO  ${l} : ${v}`); }
function verifiePortage(l, ok, d) {
    if (CIBLE === 'laravel') return verifie(l, ok, ok ? '' : d);
    constate(l, `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

/** Identifiant maximal releve a l'entree : borne tout le nettoyage. */
let borne = 0;
function retireLesCles() {
    litEnBase(`DELETE FROM rootwarden.api_keys WHERE name LIKE 'epreuve-d7-%'`);
    // Le doublon que la creation aurait pose. BORNE PAR L'IDENTIFIANT : on ne
    // touche jamais une ligne anterieure a l'execution.
    if (borne > 0) {
        litEnBase(`DELETE FROM rootwarden.api_keys WHERE id > ${borne} AND name = 'proxy-internal-legacy'`);
    }
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(40000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => { try { await d.accept(); } catch {} });

    await page.goto(`${BASE}${C.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    for (let essai = 0; essai < 2; essai += 1) {
        const champ = await page.$('input[name="2fa_code"]');
        if (! champ) break;
        if (essai > 0) await dors((resteFenetre() + 1) * 1000);
        await champ.click({ clickCount: 3 });
        await champ.type(totp(secret), { delay: 8 });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
    }
    if (C.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$(C.accepte);
        if (b) await b.evaluate((x) => x.click());
        try { await nav; } catch {}
    }

    return { ctx, page, erreursJs };
}

/**
 * Cree une cle PAR LE FORMULAIRE, et rend des MESURES — jamais la valeur.
 *
 * On remonte du formulaire a ses champs et a son bouton : la page en porte
 * plusieurs (creation, renouvellement, revocation par ligne), et « le premier
 * bouton submit » viserait le mauvais.
 */
async function creeParLeFormulaire(page, nom, portee) {
    // SIXIEME OCCURRENCE DU MEME PIEGE, et sous sa forme la plus retorse : le
    // champ de portee vit dans un `<details>` IMBRIQUE dans le `<details>` du
    // formulaire (« Avance : editer les regex manuellement »). Deplier un seul
    // niveau ne suffit pas — il faut remonter toute la chaine. Sans cela, le
    // nom se saisit, la cle se cree, et la PORTEE est perdue en silence : le
    // geste reussit, l'assertion echoue, et rien ne dit pourquoi.
    const deplie = await page.evaluate((sels) => {
        const etat = {};
        for (const [cle, sel] of Object.entries(sels)) {
            const e = document.querySelector(sel);
            if (! e) { etat[cle] = 'absent'; continue; }
            for (let n = e; n; n = n.parentElement) if (n.tagName === 'DETAILS') n.open = true;
            etat[cle] = e.getBoundingClientRect().height > 0 ? 'ouvert' : 'REPLIE';
        }

        return etat;
    }, { nom: C.champNom, portee: C.champPortee || C.modulePortee });
    constate('etat des champs apres depliage', JSON.stringify(deplie));

    const form = await page.$(C.form);
    if (! form) return { emis: false, motif: 'formulaire absent' };

    const champNom = await form.$(C.champNom) || await page.$(C.champNom);
    if (! champNom) return { emis: false, motif: 'champ de nom absent' };
    await champNom.click({ clickCount: 3 });
    await champNom.type(nom, { delay: 8 });

    if (portee !== null) {
        if (C.champPortee) {
            const champPortee = await form.$(C.champPortee) || await page.$(C.champPortee);
            if (champPortee) {
                await champPortee.click({ clickCount: 3 });
                await champPortee.type(portee, { delay: 6 });
            }
        } else if (C.modulePortee) {
            // Sur le portage, la portee est une CASE. On la coche par un vrai
            // clic sur son etiquette, qui englobe la case et son texte.
            const module = await page.$(C.modulePortee);
            if (module) await module.click();
        }
    }

    // ON RELIT CE QU'ON VIENT DE SAISIR. Une frappe qui n'atterrit pas ne leve
    // rien : c'est la seule facon de le savoir avant de soumettre.
    const saisi = await page.evaluate((sels) => {
        const e = sels.portee ? document.querySelector(sels.portee) : null;

        return {
            nom: (document.querySelector(sels.nom) || {}).value || '',
            portee: e === null ? '(sans champ libre)'
                : (e.type === 'checkbox' ? (e.checked ? 'module coche' : 'module NON coche') : (e.value || '')),
        };
    }, { nom: C.champNom, portee: C.champPortee || C.modulePortee });
    constate('valeurs relues avant soumission', `nom=${saisi.nom} portee=${saisi.portee || '(vide)'}`);

    const bouton = await form.$('button[type="submit"]');
    if (! bouton) return { emis: false, motif: 'bouton absent' };

    const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 25000 });
    await bouton.click();
    try { await nav; } catch { /* certaines cibles redirigent */ }
    await dors(700);

    // LE MESSAGE D'ERREUR EST UNE MESURE. « 0 ligne creee » a plusieurs causes ;
    // le bandeau dit laquelle. Lecon de D6b, appliquee des le premier jet ici.
    const message = await page.evaluate(() => {
        const e = document.querySelector('[class*="red"], [class*="rw-annonce"], .rw-erreur');

        return e ? (e.textContent || '').trim().slice(0, 120) : '';
    });

    return { emis: true, motif: '', message };
}

/**
 * Mesure l'affichage de la cle SANS jamais la rendre.
 *
 * Rend la longueur et un booleen de forme. Une longueur ne reconstitue pas un
 * secret ; une valeur, si. C'est la seule facon de tester « la cle est bien
 * affichee une fois » sans la faire entrer dans un journal.
 */
async function mesureAffichage(page) {
    return page.evaluate((sel) => {
        const e = document.querySelector(sel);
        if (! e) return { present: false, longueur: 0, formeAttendue: false };
        const v = (e.textContent || '').trim();

        return {
            present: v.length > 0,
            longueur: v.length,
            formeAttendue: /^rw_live_[0-9a-f]{6}_[0-9a-f]+$/.test(v),
        };
    }, C.valeur);
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

const session = {};
try {
    borne = compteEnBase('SELECT IFNULL(MAX(id), 0) FROM rootwarden.api_keys');
    constate('borne d\'identifiant a l\'entree', String(borne));
    retireLesCles();

    // ══ 1. LA GARDE : la page est reservee au role 3 ═══════════════════════
    await etape('un role 2 atteint-il la page ?', async () => {
        const s = await connecte(COMPTE_ROLE, SECRET_ROLE);
        try {
            const rep = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            constate('statut au role 2', String(rep.status()));
            verifie('le role 2 est refuse sur la page des cles', rep.status() === 403,
                `statut ${rep.status()} — \`checkAuth([ROLE_SUPERADMIN])\``);
        } finally {
            await s.ctx.close();
        }
    });
    await dors((resteFenetre() + 1) * 1000);

    session.s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = session.s;

    await etape('ouverture', async () => {
        const rep = await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('le role 3 atteint la page', rep.status() === 200, `statut ${rep.status()}`);
    });

    // ══ 2. CREER UNE CLE, PAR LE FORMULAIRE ════════════════════════════════
    await etape('creer une cle par le formulaire', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const r = await creeParLeFormulaire(page, CLE_EPREUVE, '^/cve_');
        constate('formulaire de creation', r.emis ? 'soumis' : `NON soumis (${r.motif})`);
        constate('message rendu apres creation', r.message || '(aucun)');
        verifiePortage('le formulaire de creation existe et se soumet', r.emis, r.motif);
        if (! r.emis) return;

        // EN BASE : on mesure la FORME de ce qui est stocke, pas le secret.
        const stocke = litEnBase(
            `SELECT CONCAT(LEFT(key_prefix,8),'|',LENGTH(key_hash),'|',IFNULL(scope_json,'(nul)'))
             FROM rootwarden.api_keys WHERE name = '${CLE_EPREUVE}'`);
        constate('forme stockee (prefixe|longueur du hash|portee)', stocke[0] || '(absente)');
        // La portee est comparee par ses PARTIES, pas par une chaine assemblee :
        // `json_encode` echappe les barres obliques (`["^\\/cve_"]`), et une
        // egalite ecrite a la main sur cette forme se trompe une fois sur deux.
        const parts = (stocke[0] || '').split('|');
        verifie('la cle est enregistree et hachee',
            parts[0] === 'rw_live_' && parts[1] === '64', stocke[0] || '(absente)');
        verifie('la portee saisie est retenue',
            (parts[2] || '').includes('cve_'), parts[2] || '(nulle)');

        // A L'ECRAN : presente une fois, et de la bonne forme. JAMAIS SA VALEUR.
        const vue = await mesureAffichage(page);
        constate('cle affichee apres creation', `presente=${vue.present} longueur=${vue.longueur} forme=${vue.formeAttendue}`);
        verifie('la cle est affichee une fois, dans la forme attendue',
            vue.present && vue.formeAttendue, `presente=${vue.present} forme=${vue.formeAttendue}`);
    });

    // ══ 3. ELLE NE DOIT PLUS JAMAIS PARAITRE ═══════════════════════════════
    await etape('la cle reparait-elle au rechargement ?', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const vue = await mesureAffichage(page);
        constate('cle affichee apres rechargement', `presente=${vue.present} longueur=${vue.longueur}`);
        // LA PROPRIETE CENTRALE DE CETTE PAGE. La table ne stocke qu'un hachage :
        // si la cle reparaissait, c'est qu'elle serait conservee ailleurs.
        verifie('la cle n\'est plus affichee apres rechargement', ! vue.present,
            vue.present ? `longueur ${vue.longueur} — la cle serait conservee quelque part` : '');
    });

    // ══ 4. LE DOUBLON D'ENREGISTREMENT DE LA CLE D'ENVIRONNEMENT ═══════════
    await etape('la creation enregistre-t-elle une seconde fois la cle d\'environnement ?', async () => {
        const doublons = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.api_keys WHERE id > ${borne} AND name = 'proxy-internal-legacy'`);
        constate('lignes `proxy-internal-legacy` creees par le geste', String(doublons));

        // Le meme secret enregistre deux fois, sous deux noms, sans que `key_hash`
        // soit unique : `_validate_api_key_from_db` fait `WHERE key_hash = %s
        // LIMIT 1` SANS `ORDER BY`. Revoquer l'une des deux rend donc
        // l'authentification NON DETERMINISTE.
        const memeSecret = compteEnBase(
            `SELECT COUNT(DISTINCT key_hash) FROM rootwarden.api_keys
             WHERE name LIKE 'proxy-internal-legacy%'`);
        constate('secrets distincts parmi les lignes `proxy-internal-legacy%`', String(memeSecret));

        verifiePortage('creer une cle n\'enregistre pas une seconde fois la cle d\'environnement',
            doublons === 0,
            `${doublons} ligne(s) — \`api_keys.php:86\` fait \`INSERT IGNORE\` sur le nom fixe `
            + '`proxy-internal-legacy`, alors que `bootstrap_api_key.py` a enregistre le meme secret '
            + 'sous `proxy-internal-legacy-bootstrap-…`. `key_hash` n\'est pas unique : deux lignes '
            + 'actives pour un seul secret, et la validation fait `LIMIT 1` sans `ORDER BY`');
    });

    // ══ 5. UN MOTIF VALIDE EN PCRE, INCOMPILABLE EN PYTHON ═════════════════
    await etape('un motif de portee PCRE-seul est-il accepte ?', async () => {
        if (! C.champPortee) {
            // LA PROPRIETE EST L'ABSENCE. Elle s'asserte : un champ libre
            // reapparu passerait inapercu autrement.
            const libre = await page.$('textarea[name="scope"], [data-rw="cle-api-portee"]');
            constate('champ libre de portee', libre === null ? 'absent' : 'PRESENT');
            verifie('le portage n\'offre aucun champ libre de portee', libre === null,
                libre === null ? '' : 'un champ libre est reapparu — E-135 et E-136 redeviendraient atteignables');

            return;
        }
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const r = await creeParLeFormulaire(page, CLE_PCRE, MOTIF_PCRE_SEUL);
        if (! r.emis) { constate('creation avec motif PCRE', `non soumise (${r.motif})`); return; }
        constate('message rendu apres creation PCRE', r.message || '(aucun)');

        const creee = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.api_keys WHERE name = '${CLE_PCRE}'`);
        constate('cle a portee PCRE-seule creee', String(creee));
        // La validation compile en PCRE, l'application compile en Python. Une
        // portee acceptee ici sera incompilable a l'usage — et le journal du
        // backend annoncera « API key DB lookup failed », donc une panne de
        // base, pour un motif qu'on vient de saisir.
        verifiePortage('un motif que le moteur d\'APPLICATION ne compile pas est refuse',
            creee === 0,
            `motif « ${MOTIF_PCRE_SEUL} » accepte — valide en PCRE par preg_match, refuse par `
            + 'Python `re` qui l\'applique. La validation ne prouve rien sur le moteur qui decide');
    });

    // ══ 6. REVOQUER, PAR UN CLIC ═══════════════════════════════════════════
    await etape('revoquer une cle par un clic', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });

        // Le bouton de CETTE cle, repere par le contenu de sa ligne — jamais
        // « le premier bouton de revocation » : la page en porte un par cle, et
        // la premiere ligne est la cle d'environnement, qu'on ne touche pas.
        const bouton = await page.evaluateHandle((sel, nom) => {
            for (const b of document.querySelectorAll(sel)) {
                const ligne = b.closest('tr') || b.closest('li') || b.parentElement;
                if (ligne && (ligne.textContent || '').includes(nom)) return b;
            }

            return null;
        }, C.revoquer, CLE_EPREUVE);

        const element = bouton.asElement();
        verifie('le bouton de revocation de CETTE cle est trouve', element !== null);
        if (! element) return;

        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await element.click();
        try { await nav; } catch { /* redirection ou confirm */ }
        await dors(700);

        const revoquee = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.api_keys WHERE name = '${CLE_EPREUVE}' AND revoked_at IS NOT NULL`);
        verifie('la cle est revoquee', revoquee === 1, `${revoquee} ligne(s) revoquee(s)`);
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            // RECHARGEMENT AVANT CHAQUE CAPTURE, et ce n'est pas un detail :
            // la page qui suit une creation AFFICHE la cle en clair. Une
            // capture prise la deposerait un secret vivant dans un fichier
            // que personne ne surveille.
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            const reste = await mesureAffichage(page);
            if (reste.present) {
                verifie('aucune cle en clair sur la capture', false, 'la page affiche encore une cle');

                return;
            }
            await dors(400);
            await page.screenshot({ path: `${dossier}/cles-api-${nom}.png` });
        }
        verifie('les trois captures sont ecrites, sans cle en clair', true);
    });

    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    verifiePortage('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 2).join(' | '));

} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    try {
        retireLesCles();
        const reste = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.api_keys WHERE name LIKE 'epreuve-d7-%'
             OR (id > ${borne} AND name = 'proxy-internal-legacy')`);
        verifie('aucune cle d\'epreuve ne subsiste', reste === 0, `${reste} ligne(s)`);
    } catch (e) { note(`FAIL  retrait : ${e.message}`); echecs += 1; }
    try {
        // La cle d'environnement enregistree au bootstrap : ni lue, ni citee,
        // ni touchee. On verifie seulement qu'elle est intacte et active.
        const socle = litEnBase(
            "SELECT CONCAT(name,'|',IFNULL(revoked_at,'active')) FROM rootwarden.api_keys WHERE id = 1");
        verifie('la cle d\'environnement du socle est intacte et active',
            socle.length === 1 && socle[0].endsWith('|active'), socle[0] || '(absente)');
    } catch (e) { note(`FAIL  controle du socle : ${e.message}`); echecs += 1; }
    try { for (const c of contextes) await c.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
    try { await navigateur.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
