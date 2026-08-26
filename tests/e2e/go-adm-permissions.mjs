/**
 * go-adm-permissions.mjs - Sous-lot D5 de `adm/` : permissions fonctionnelles.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/adm/admin_page.php  (onglet Acces & permissions)
 *   laravel  http://localhost:8444/permissions          (pas encore porte)
 *
 * Perimetre : `includes/manage_permissions.php` (273 l.),
 * `api/update_permissions.php` (184 l.). L'attribution des ACCES MACHINES
 * (`manage_access.php`, `update_server_access.php`) suit dans le meme sous-lot.
 *
 * ══ TROIS VOCABULAIRES POUR LES MEMES DROITS, ET DEUX TROUS ════════════════
 *
 * Mesure du 2026-08-26, en croisant le schema, le formulaire de creation et la
 * liste blanche du point d'API :
 *
 *   colonnes de `permissions`            18
 *   posables A LA CREATION               14   (`manage_users.php:116`)
 *   basculables ENSUITE                  16   (`update_permissions.php:101`)
 *
 * D'ou deux trous, de natures differentes :
 *
 *   `can_manage_fail2ban`   creable, JAMAIS basculable — on peut l'accorder et
 *                           on ne peut plus la retirer par l'interface. Elle
 *                           garde `fail2ban/` et son entree de menu SUR LES DEUX
 *                           PORTAILS.
 *   `can_manage_api_keys`   ni creable ni basculable — inatteignable dans les
 *                           deux sens. Elle garde `adm/api_keys.php`, qui n'est
 *                           donc joignable que par le role 3, lequel contourne
 *                           toute permission. Ce n'est pas une decision : c'est
 *                           un oubli de liste.
 *
 * Deux comptes portent aujourd'hui `can_manage_fail2ban` et un porte
 * `can_manage_api_keys` : ils les ont recues a la creation ou par import CSV.
 * Le trou n'est donc pas theorique — il y a bien des droits accordes que
 * l'interface ne sait pas reprendre.
 *
 * ══ LA GARDE STEP-UP, ET LE TRANSPORT QUI NE LA VOIT PAS ═══════════════════
 *
 * `update_permissions.php:60` porte `stepUpRequire('update_permissions')`. Le
 * modal du legacy est une surcouche de `window.fetch` (`js/utils.js:38-49`), et
 * la case est declenchee par **htmx**, qui n'emploie que `XMLHttpRequest`. La
 * lecture concluait donc que la bascule ne fait RIEN, sans message. Cette suite
 * le mesure au CLIC — c'est la seule maniere de conclure.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * La suite bascule des permissions. Le faire sur `rw-test-admin` changerait ce
 * que TREIZE autres suites mesurent. Elle cree donc son propre compte, par de
 * vrais clics, et le retire — `permissions.user_id` etant en CASCADE, la ligne
 * part avec lui.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-adm-permissions
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
/** Role 2 SANS `can_admin_portal` — le seul compte qui mesure cette garde. */
const COMPTE_ROLE = 'rw-test-admin';
const SECRET_ROLE = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';
/** Page gardee par `can_admin_portal` sur les deux portails. */
const PAGE_GARDEE = CIBLE === 'laravel' ? '/comptes' : '/adm/admin_page.php';

const EPREUVE = 'epreuve-e2e-d5';
/** Une permission BASCULABLE, pour mesurer le geste nominal. */
const PERM = 'can_scan_cve';
/** Les deux trous mesures : creable non basculable, et ni l'un ni l'autre. */
const PERM_NON_BASCULABLE = 'can_manage_fail2ban';
const PERM_INATTEIGNABLE = 'can_manage_api_keys';

const DOSSIER_CAPTURES = new URL('./screenshots/adm', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/permissions',
        champNom: null,
        case: (id, perm) => `[data-rw="perm-${perm}-${id}"]`,
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/adm/admin_page.php',
        champNom: 'form:has(input[name="action"][value="add_user"]) input[name="name"]',
        case: (id, perm) => `input[type="checkbox"][data-user-id="${id}"][data-permission="${perm}"]`,
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

let borne = 0;
function idEpreuve() {
    const v = litEnBase(`SELECT id FROM rootwarden.users WHERE name = '${EPREUVE}'`);

    return v.length ? parseInt(v[0], 10) : 0;
}
function permEnBase(id, perm) {
    if (id <= 0) return null;
    const v = litEnBase(`SELECT ${perm} FROM rootwarden.permissions WHERE user_id = ${id}`);

    return v.length ? parseInt(v[0], 10) : null;
}
function retireLEpreuve() {
    // `permissions.user_id` est en CASCADE : la ligne part avec le compte.
    if (borne > 0) litEnBase(`DELETE FROM rootwarden.users WHERE id > ${borne} AND name = '${EPREUVE}'`);
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

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

const session = {};
try {
    retireLEpreuve();
    borne = compteEnBase('SELECT IFNULL(MAX(id), 0) FROM rootwarden.users');

    // ══ 1. Les trois vocabulaires, mesures ═════════════════════════════════
    await etape('trois listes pour les memes droits', async () => {
        const colonnes = compteEnBase(
            "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='rootwarden' "
            + "AND TABLE_NAME='permissions' AND COLUMN_NAME LIKE 'can\\\\_%'");
        constate('colonnes de `permissions`', String(colonnes));
        // Les deux trous, mesures en base : des comptes PORTENT ces droits, donc
        // ils ont bien ete accordes — par la creation ou par un import.
        const f2b = compteEnBase(`SELECT COUNT(*) FROM rootwarden.permissions WHERE ${PERM_NON_BASCULABLE} = 1`);
        const api = compteEnBase(`SELECT COUNT(*) FROM rootwarden.permissions WHERE ${PERM_INATTEIGNABLE} = 1`);
        constate(`comptes portant ${PERM_NON_BASCULABLE}`, String(f2b));
        constate(`comptes portant ${PERM_INATTEIGNABLE}`, String(api));
        verifie('le schema porte bien dix-huit permissions', colonnes === 18, `${colonnes}`);
    });

    session.s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = session.s;

    await etape('ouverture', async () => {
        const rep = await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('le role 3 atteint la page des permissions', rep.status() === 200, `statut ${rep.status()}`);
    });

    // ══ 1bis. LES TROIS CONFIRMATIONS D'E-114 S'ANALYSENT-ELLES ? ══════════
    //
    // E-114 accusait l'APOSTROPHE de casser le litteral JavaScript de
    // `onclick="return confirm('…')"`, et concluait « seulement en francais » et
    // « le troisieme bouton fonctionne ». Le sous-lot D6a a mesure le meme
    // montage sur `manage_servers.php` : ce qui coupe est le GUILLEMET DOUBLE de
    // la traduction, qui ferme l'ATTRIBUT HTML — un niveau au-dessus — et il est
    // present dans les deux catalogues.
    //
    // Cette etape fait ce qui manquait a E-114 : la mesure AU NAVIGATEUR sur
    // cette page-ci. On ne compte pas des caracteres, on demande au moteur si
    // l'attribut s'ANALYSE — `new Function(code)` compile sans executer. Un
    // decompte d'apostrophes se laisserait tromper par un `\'` ; le compilateur
    // non.
    await etape('les confirmations de manage_roles s\'analysent-elles ?', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const verdicts = await page.evaluate(() => {
            const sortie = [];
            document.querySelectorAll('button[onclick]').forEach((b) => {
                const code = b.getAttribute('onclick') || '';
                if (! /confirm\(/.test(code)) return;
                let analyse = true;
                let erreur = '';
                try {
                    // COMPILE, N'EXECUTE PAS : aucune boite ne s'ouvre, aucun
                    // formulaire ne part. C'est la propriete « ce code est-il
                    // seulement valide » qu'on mesure, rien d'autre.
                    new Function(code);
                } catch (e) {
                    analyse = false;
                    erreur = String(e.message || e);
                }

                return sortie.push({
                    nom: b.getAttribute('name') || '(sans name)',
                    type: b.getAttribute('type') || '(sans type)',
                    dansUnFormulaire: b.closest('form') !== null,
                    code: code.slice(0, 60),
                    analyse,
                    erreur,
                });
            });

            return sortie;
        });

        // ONZE COMPTES x TROIS BOUTONS = 33 LIGNES IDENTIQUES. On regroupe : un
        // journal qu'on ne relit pas ne sert a rien, et trente-trois repetitions
        // se relisent moins bien qu'une ligne par CAS.
        constate('boutons a `confirm()` trouves', String(verdicts.length));
        const parCas = new Map();
        for (const v of verdicts) {
            const cle = `${v.nom} [${v.type}, ${v.dansUnFormulaire ? 'dans un form' : 'hors form'}] `
                + `${v.analyse ? 'analysable' : `NON ANALYSABLE — ${v.erreur} — « ${v.code} »`}`;
            parCas.set(cle, (parCas.get(cle) || 0) + 1);
        }
        for (const [cas, n] of parCas) constate(`  x${n}`, cas);

        // Le legacy en porte ; le portage n'en porte AUCUN, et c'est la reponse
        // correcte : ses confirmations sont des panneaux, pas des attributs.
        const casses = verdicts.filter((v) => ! v.analyse);
        const dangereux = casses.filter((v) => v.type === 'submit' && v.dansUnFormulaire);
        constate('confirmations qui ne s\'analysent pas', `${casses.length} sur ${verdicts.length}`);
        constate('dont un `submit` DANS un formulaire (le geste part quand meme)', String(dangereux.length));

        verifiePortage('toute confirmation presente s\'analyse',
            casses.length === 0,
            `${casses.length} attribut(s) tronque(s) — le guillemet double de la traduction ferme `
            + `l'attribut HTML ; ${dangereux.length} d'entre eux sont des \`submit\` dans un `
            + 'formulaire, donc le geste part SANS confirmation (E-114 corrige par E-121)');
    });

    // ══ 2. Le compte d'epreuve ═════════════════════════════════════════════
    await etape('creation du compte d\'epreuve', async () => {
        if (! C.champNom) {
            // Sur le portage, la creation vit sur `/comptes` (sous-lot D3).
            await page.goto(`${BASE}/comptes`, { waitUntil: 'networkidle2' });
        }
        const sel = C.champNom || 'form input[name="name"]';
        await page.evaluate((s) => {
            const c = document.querySelector(s);
            const d = c ? c.closest('details') : null;
            if (d) d.open = true;
        }, sel);
        const champ = await page.$(sel);
        if (! champ) throw new Error('champ de nom absent');
        await champ.click({ clickCount: 3 });
        await champ.type(EPREUVE, { delay: 8 });
        const bouton = await page.evaluateHandle((s) => {
            const c = document.querySelector(s);
            const f = c ? c.closest('form') : null;

            return f ? f.querySelector('button[type="submit"]') : null;
        }, sel);
        const b = bouton.asElement();
        if (! b) throw new Error('aucun bouton de creation');
        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 25000 });
        await b.click();
        try { await nav; } catch {}
        verifie('le compte d\'epreuve est cree', idEpreuve() > borne, `id ${idEpreuve()}`);
    });

    const idEpr = idEpreuve();

    // ══ 3. LA BASCULE : le clic fait-il quelque chose ? ════════════════════
    await etape('bascule d\'une permission, par un vrai clic', async () => {
        if (idEpr <= 0) throw new Error('pas de compte d\'epreuve');
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        // DEUX couches a ouvrir, pas une. Les permissions vivent dans l'onglet
        // « Acces & permissions » de `admin_page.php`, masque tant qu'on ne
        // clique pas dessus ; et chaque compte y est une carte `<details>`
        // repliee. `page.$()` trouve la case dans les deux cas, et le clic
        // echoue sur « not clickable » — quatrieme fois que ce piege coute un
        // tour. On ouvre les deux, puis on ASSERTE la boite.
        await page.evaluate((sel) => {
            const onglet = document.querySelector('.tab-btn[data-tab="access"]');
            if (onglet) onglet.click();
            const c = document.querySelector(sel);
            const d = c ? c.closest('details') : null;
            if (d) d.open = true;
        }, C.case(idEpr, PERM));
        await dors(400);

        const emises = [];
        const reponses = [];
        const surRequete = (r) => {
            if (/update_permissions|permissions\/\d+/.test(r.url()) && r.method() !== 'GET') {
                emises.push(`${r.method()} ${r.url().split('/').pop()}`);
            }
        };
        const surReponse = async (r) => {
            if (! /update_permissions|permissions\/\d+/.test(r.url())) return;
            let corps = '';
            try { corps = (await r.text()).slice(0, 120); } catch {}
            reponses.push(`${r.status()} ${corps}`);
        };
        page.on('request', surRequete);
        page.on('response', surReponse);

        const avant = permEnBase(idEpr, PERM);
        const caseCible = await page.$(C.case(idEpr, PERM));
        verifie('la case de permission est presente', !! caseCible, C.case(idEpr, PERM));
        if (! caseCible) { page.off('request', surRequete); page.off('response', surReponse); return; }
        const visible = await page.evaluate((s) => {
            const e = document.querySelector(s);

            return e ? e.getClientRects().length > 0 : false;
        }, C.case(idEpr, PERM));
        verifie('la case a une boite avant le clic', visible);
        if (! visible) { page.off('request', surRequete); page.off('response', surReponse); return; }

        await caseCible.click();
        for (let i = 0; i < 24 && reponses.length === 0; i += 1) await dors(250);
        page.off('request', surRequete);
        page.off('response', surReponse);

        const apres = permEnBase(idEpr, PERM);
        constate('requetes emises par le clic', emises.join(' | ') || '(aucune)');
        constate('reponses recues', reponses.join(' | ').slice(0, 220) || '(aucune)');
        constate(`${PERM} avant / apres`, `${avant} / ${apres}`);

        const refuse = reponses.some((r) => /step_up_required/.test(r));
        constate('une re-authentification est-elle exigee ?', refuse ? 'OUI' : 'non');

        verifie('le clic emet bien une requete', emises.length >= 1, `${emises.length}`);
        // LA QUESTION DU SOUS-LOT : le clic aboutit-il ? La lecture concluait
        // que non — modal sur `window.fetch`, case declenchee par htmx (XHR).
        // Sur le legacy le geste s'arrete ici, faute de chemin pour repondre au
        // refus. Sur le portage, un panneau s'ouvre : on le suit jusqu'au bout,
        // sans quoi la piece ecrite pour lever E-119 ne serait mesuree par rien.
        if (CIBLE !== 'laravel') {
            constate('la bascule change-t-elle la permission ?',
                avant !== apres ? 'oui' : 'NON — le refus n\'ouvre aucun modal, '
                + 'htmx n\'emploie que XMLHttpRequest et la surcouche ne voit que `fetch`');

            return;
        }

        const panneau = await page.evaluate(() => {
            const p = document.querySelector('[data-rw="perms-panneau-stepup"]');

            return p ? p.getClientRects().length > 0 : false;
        });
        verifie('le panneau de re-authentification s\'ouvre en page', panneau,
            panneau ? '' : 'le refus 403 n\'a pas ouvert le panneau');
        if (! panneau) return;

        // Fenetre TOTP NEUVE : le code de la connexion vient d'etre consomme,
        // et le garde anti-rejeu est par compte et en base.
        await dors((resteFenetre() + 1) * 1000);
        const code = await page.$('[data-rw="perms-stepup-code"]');
        await code.click({ clickCount: 3 });
        await code.type(totp(SECRET), { delay: 8 });
        await page.click('[data-rw="perms-stepup-valider"]');
        // On attend la CONSEQUENCE en base, pas un evenement d'interface.
        for (let i = 0; i < 40 && permEnBase(idEpr, PERM) === avant; i += 1) await dors(250);

        const final = permEnBase(idEpr, PERM);
        constate(`${PERM} apres re-authentification`, String(final));
        verifie('la bascule aboutit une fois le second facteur fourni', final !== avant,
            `${avant} avant, ${final} apres`);
    });

    // ══ LES PERMISSIONS TEMPORAIRES OUVRENT-ELLES LA PAGE ? ═══════════════
    //
    // `checkPermissionFromDB()` du legacy consulte TROIS sources : le repli
    // superadministrateur, la table `permissions`, et `temporary_permissions`
    // non expirees. Le portage n'en lisait que la deuxieme — un octroi
    // temporaire ouvrait la page sur l'ancien portail et rendait 403 ici
    // (PARITE E-134). C'est une assertion de PARITE : elle vaut sur les deux
    // cibles, aucune n'a le droit d'echouer.
    //
    // La fixture est posee EN BASE parce qu'aucune interface du portage n'octroie
    // encore une permission temporaire — c'est le sous-lot D5b, pas celui-ci.
    // L'octroi passe cote legacy par `POST /admin/temp_permissions`, dont le
    // formulaire vit dans `manage_permissions.php` et n'a pas ete porte.
    await etape('un octroi temporaire ouvre-t-il la page gardee ?', async () => {
        const idRole = litEnBase(`SELECT id FROM rootwarden.users WHERE name = '${COMPTE_ROLE}'`);
        if (idRole.length !== 1) { verifie('le compte de role 2 est trouve', false); return; }
        const uid = parseInt(idRole[0], 10);

        // FAIL-CLOSED : si le compte portait deja la permission en permanent,
        // la mesure ne prouverait rien — elle passerait sans l'octroi.
        const permanente = compteEnBase(
            `SELECT IFNULL(SUM(can_admin_portal), 0) FROM rootwarden.permissions WHERE user_id = ${uid}`);
        verifie('le compte de role 2 n\'a PAS la permission en permanent', permanente === 0,
            `can_admin_portal = ${permanente} — l'octroi temporaire ne serait pas mesurable`);
        if (permanente !== 0) return;

        litEnBase(`DELETE FROM rootwarden.temporary_permissions WHERE user_id = ${uid}`);

        await dors((resteFenetre() + 1) * 1000);
        const s2 = await connecte(COMPTE_ROLE, SECRET_ROLE);
        try {
            const avant = await s2.page.goto(`${BASE}${PAGE_GARDEE}`, { waitUntil: 'networkidle2' });
            constate('statut sans octroi', String(avant.status()));
            verifie('sans octroi, la page gardee est refusee', avant.status() === 403,
                `statut ${avant.status()}`);

            litEnBase(
                "INSERT INTO rootwarden.temporary_permissions (user_id, permission, granted_by, reason, expires_at) "
                + `VALUES (${uid}, 'can_admin_portal', 1, 'epreuve E-134', DATE_ADD(NOW(), INTERVAL 1 HOUR))`);

            const apres = await s2.page.goto(`${BASE}${PAGE_GARDEE}`, { waitUntil: 'networkidle2' });
            constate('statut avec octroi temporaire', String(apres.status()));
            // PARITE STRICTE : le legacy honore l'octroi, le portage doit
            // l'honorer aussi. Un `verifie`, pas un `verifiePortage`.
            verifie('un octroi temporaire non expire ouvre la page', apres.status() === 200,
                `statut ${apres.status()} — le portage ne lisait que la table \`permissions\``);

            litEnBase(`DELETE FROM rootwarden.temporary_permissions WHERE user_id = ${uid}`);
            const revoque = await s2.page.goto(`${BASE}${PAGE_GARDEE}`, { waitUntil: 'networkidle2' });
            constate('statut apres revocation', String(revoque.status()));
            // LES DROITS SONT RELUS A CHAQUE REQUETE : une revocation doit
            // refermer la page sans attendre une reconnexion.
            verifie('la revocation referme la page sans reconnexion', revoque.status() === 403,
                `statut ${revoque.status()}`);
        } finally {
            litEnBase(`DELETE FROM rootwarden.temporary_permissions WHERE user_id = ${uid}`);
            await s2.ctx.close();
        }
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            await page.screenshot({ path: `${dossier}/permissions-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    verifiePortage('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 2).join(' | '));

} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    try {
        // NETTOYER CE QUE LE TEST A ACCORDE. La marque de step-up vit quinze
        // minutes dans le cache et SURVIT a l'execution : sans cette revocation,
        // l'execution suivante herite de la marque et mesure un 200 la ou elle
        // attend un 403. Paye en D4, pas deux fois.
        const s = session.s;
        if (s && s.page) {
            await s.page.evaluate(async () => {
                const m = document.querySelector('meta[name="csrf-token"]');
                await fetch('/profil/step-up/revoquer', {
                    method: 'POST', credentials: 'same-origin',
                    headers: { 'X-CSRF-TOKEN': m ? m.content : '', 'Content-Type': 'application/json' },
                }).catch(() => null);
            }).catch(() => null);
        }
    } catch (e) { note(`INFO  revocation du step-up : ${e.message}`); }
    try {
        litEnBase("DELETE FROM rootwarden.temporary_permissions WHERE reason = 'epreuve E-134'");
        const restes = compteEnBase(
            "SELECT COUNT(*) FROM rootwarden.temporary_permissions WHERE reason = 'epreuve E-134'");
        verifie('aucun octroi temporaire d\'epreuve ne subsiste', restes === 0, `${restes} ligne(s)`);
    } catch (e) { note(`FAIL  retrait des octrois : ${e.message}`); echecs += 1; }
    try {
        retireLEpreuve();
        verifie('le compte d\'epreuve est retire',
            compteEnBase(`SELECT COUNT(*) FROM rootwarden.users WHERE name = '${EPREUVE}'`) === 0);
    } catch (e) { note(`FAIL  retrait : ${e.message}`); echecs += 1; }
    try {
        const intacts = compteEnBase(
            "SELECT COUNT(*) FROM rootwarden.users WHERE name IN "
            + "('rw-test-user','rw-test-admin','rw-test-super') AND active = 1");
        verifie('les trois comptes de test sont intacts', intacts === 3, `${intacts}/3`);
        const supervision = compteEnBase(
            "SELECT IFNULL(MAX(p.can_manage_supervision),0) FROM rootwarden.permissions p "
            + "JOIN rootwarden.users u ON u.id = p.user_id WHERE u.name = 'rw-test-admin'");
        verifie('rw-test-admin garde can_manage_supervision', supervision === 1,
            `${supervision} — treize suites en dependent`);
    } catch (e) { note(`FAIL  controle des comptes de test : ${e.message}`); echecs += 1; }
    try { for (const c of contextes) await c.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
    try { await navigateur.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
