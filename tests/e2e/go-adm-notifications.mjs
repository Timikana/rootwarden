/**
 * go-adm-notifications.mjs - Sous-lot D2 de `adm/` : les notifications.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/notifications.php
 *   laravel  http://localhost:8444/notifications          (pas encore porte)
 *
 * Perimetre du sous-lot, et il DEBORDE de `adm/` — c'est le premier du module
 * dans ce cas :
 *   adm/api/notifications.php · adm/api/update_notification_prefs.php
 *   adm/includes/manage_notifications.php  ....................  376 lignes
 *   notifications.php (RACINE du legacy, la page elle-meme)  ..  165 lignes
 *   la pastille de `menu.php`, donc TOUTES les pages legacy restantes
 *
 * ══ CE QUE LA LECTURE A ETABLI, ET QUE CETTE SUITE MESURE ═══════════════════
 *
 * 1. UNE HYPOTHESE DE LECTURE, INFIRMEE PAR LE CLIC — et elle reste ecrite
 *    ici parce que c'est la lecon du sous-lot. La case de preference porte
 *    `hx-vals='{"user_id":…,"event_type":…}'` sans `value`, et AUCUN attribut
 *    `name` (`manage_notifications.php:94-98`) ; le point d'API exige pourtant
 *    `isset($data['user_id'], $data['event_type'], $data['value'])`
 *    (`update_notification_prefs.php:32`). J'en avais conclu que chaque clic
 *    rendrait « Donnees manquantes ».
 *    LA MESURE DIT LE CONTRAIRE. Le corps reellement emis est
 *    `user_id=16&event_type=backup_status&csrf_token=…&value=1` : htmx serialise
 *    la case declenchante meme sans `name`, et la preference passe bien de
 *    (absente) a 1. La case FONCTIONNE. Comparer les deux cotes du contrat
 *    reste la bonne discipline — mais elle se conclut au CLIC, pas a la lecture
 *    d'une minification.
 *
 * 2. « MARQUER LU » NE MARQUE RIEN — mais l'ecran dit le contraire. Le bouton
 *    porte `onclick="… this.remove();"` (`notifications.php:141`), qui le retire
 *    du DOM PENDANT l'evenement de clic. htmx n'emet alors AUCUNE requete
 *    (mesure : « aucune requete POST »), tandis que le surlignage est efface et
 *    le bouton disparait. L'affichage optimiste annonce une lecture que la base
 *    ignore, et un rechargement la fait revenir.
 *
 * 3. UN GET ECRIT, ET SANS JETON. `checkCsrfToken()` n'est appele que si la
 *    methode est POST (`notifications.php:26-27`), alors que `$action` est lu
 *    dans `$_GET` en premier (`:23`). `GET ?action=read_all` marque donc tout
 *    comme lu sans aucun jeton. C'est la regle « un GET ne doit rien ecrire »,
 *    prise en defaut.
 *
 * 4. LE DEFAUT DE DIFFUSION N'EST CORRIGE QUE SUR `delete`. Le commentaire du
 *    `case 'delete'` nomme precisement le probleme — « un simple utilisateur ne
 *    peut supprimer QUE ses propres notifications » — et scinde sur le role.
 *    Ses JUMEAUX `read` et `read_all` gardent `OR user_id = 0` pour tout le
 *    monde, alors qu'un role 1 ne VOIT meme pas ces lignes (`$whereUser` ne les
 *    lui rend pas). Ecriture aveugle sur des lignes invisibles.
 *
 * 5. QUATRE VOCABULAIRES POUR LA COLONNE `type`, ET DEUX NE SE CROISENT PAS.
 *    Les preferences connaissent {cve_scan, ssh_audit, compliance_report,
 *    security_alert, backup_status, update_status} ; la page connait
 *    {cve_critical, server_offline, perm_granted, perm_expired,
 *    password_expiry, info}. INTERSECTION VIDE, mesuree. Toute notification
 *    reellement produite retombe donc sur le repli « Autre », en gris.
 *
 * ══ LA FIXTURE, ET CE QU'ELLE ENGAGE ════════════════════════════════════════
 *
 * `notifications` ne portait que DEUX lignes au 2026-08-26, toutes deux a
 * l'utilisateur 1, toutes deux lues, et AUCUNE diffusion. La suite pose donc
 * les siennes et les retire, BORNEES PAR UN DELTA d'identifiant : un nettoyage
 * qui supprimerait par type ou par utilisateur en retirerait plus qu'il n'en a
 * pose.
 *
 * La ligne de DIFFUSION (`user_id = 0`) est le seul moyen d'exercer le point 4.
 * Elle est visible des roles >= 2 le temps de l'execution ; elle porte un titre
 * qui la nomme comme une epreuve, et elle est retiree dans le `finally`.
 *
 * Les preferences sont RELUES avant d'etre touchees et RESTAUREES ensuite :
 * `notification_preferences` porte de vraies lignes pour six types.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-adm-notifications
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

/** Role 3 : le seul qui puisse editer une preference (`role_id >= 3`). */
const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
const ID_SUPER = 16;
/** Role 1 — il ne VOIT pas les diffusions, et c'est tout le sujet du point 3. */
const COMPTE_BAS = 'rw-test-user';
const SECRET_BAS = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';
const ID_BAS = 14;

/** Ce que la fixture pose. Le titre NOMME l'epreuve : rien ne s'y trompe. */
const MARQUE = 'epreuve-e2e-notifications';
/** Le type que les PREFERENCES connaissent — et que la page ne sait pas nommer. */
const TYPE_REEL = 'cve_scan';
/** La preference qu'on bascule, puis qu'on restaure. */
const PREF = 'backup_status';

const DOSSIER_CAPTURES = new URL('./screenshots/adm', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/notifications',
        pastille: '[data-rw="notif-pastille"]',
        corps: '[data-rw="notif-corps"]',
        toutLire: '[data-rw="notif-tout-lire"]',
        lire: (id) => `[data-rw="notif-lire-${id}"]`,
        pastilleType: (id) => `[data-rw="notif-type-${id}"]`,
        routeCompte: '/notifications/compte',
        routeToutLire: '/notifications/tout-lire',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/notifications.php',
        pastille: '#notif-badge',
        corps: 'main',
        toutLire: null,
        lire: (id) => `button[hx-vals*='"id":${id}']`,
        // Le legacy n'expose aucun crochet : la pastille est le PREMIER `span`
        // de la ligne. On la vise par la ligne, pas par « le premier span de la
        // page » — c'est la meme discipline que remonter d'un champ a son form.
        pastilleType: null,
        routeCompte: '/adm/api/notifications.php?action=count',
        routeToutLire: '/adm/api/notifications.php?action=read_all',
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

/* ── La fixture, bornee par un DELTA d'identifiant ──────────────────────── */

let borne = 0;
function poseLaFixture() {
    borne = compteEnBase('SELECT IFNULL(MAX(id), 0) FROM rootwarden.notifications');
    litEnBase(
        "INSERT INTO rootwarden.notifications (user_id, type, title, message, link, read_at) VALUES "
        + `(${ID_SUPER}, '${TYPE_REEL}', '${MARQUE} non lue', 'message', NULL, NULL), `
        + `(${ID_SUPER}, 'security_alert', '${MARQUE} deja lue', 'message', NULL, NOW()), `
        + `(0, '${TYPE_REEL}', '${MARQUE} diffusion', 'message', NULL, NULL)`);

    return {
        nonLue: compteEnBase(`SELECT MIN(id) FROM rootwarden.notifications WHERE id > ${borne} AND user_id = ${ID_SUPER} AND read_at IS NULL`),
        diffusion: compteEnBase(`SELECT id FROM rootwarden.notifications WHERE id > ${borne} AND user_id = 0`),
    };
}
/** Ne retire QUE ce que la fixture a pose. Un nettoyage par type en retirerait plus. */
function retireLaFixture() {
    if (borne > 0) litEnBase(`DELETE FROM rootwarden.notifications WHERE id > ${borne}`);
}
function nonLuesDe(userId) {
    const clause = userId >= 15 ? `(user_id = ${userId} OR user_id = 0)` : `user_id = ${userId}`;

    return compteEnBase(`SELECT COUNT(*) FROM rootwarden.notifications WHERE ${clause} AND read_at IS NULL`);
}
function estLue(id) {
    return compteEnBase(`SELECT COUNT(*) FROM rootwarden.notifications WHERE id = ${id} AND read_at IS NOT NULL`) === 1;
}
function prefEnBase() {
    const v = litEnBase(
        `SELECT enabled FROM rootwarden.notification_preferences WHERE user_id = ${ID_SUPER} AND event_type = '${PREF}'`);

    return v.length ? parseInt(v[0], 10) : null;
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
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    page.on('dialog', async (d) => { try { await d.accept(); } catch { /* deja fermee */ } });

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

/** Attend qu'une condition mesuree EN BASE devienne vraie. Jamais d'attente fixe. */
async function attendEnBase(mesure, veut, limiteMs = 15000) {
    const fin = Date.now() + limiteMs;
    let vu = mesure();
    while (vu !== veut && Date.now() < fin) {
        await dors(300);
        vu = mesure();
    }

    return vu;
}

let fixture = { nonLue: 0, diffusion: 0 };
let prefInitiale = null;
const session = {};

try {
    retireLaFixture();
    prefInitiale = prefEnBase();
    fixture = poseLaFixture();
    constate('fixture posee', `non lue #${fixture.nonLue}, diffusion #${fixture.diffusion}, borne ${borne}`);
    constate('preference initiale', `${PREF} = ${prefInitiale === null ? '(absente)' : prefInitiale}`);

    // ══ 1. La page, au role 3 ═══════════════════════════════════════════════
    session.s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = session.s;

    let nonLuesAvant = 0;
    await etape('ouverture', async () => {
        const rep = await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('le role 3 atteint la page des notifications', rep.status() === 200, `statut ${rep.status()}`);
        nonLuesAvant = nonLuesDe(ID_SUPER);
        constate('non lues en base pour le role 3', String(nonLuesAvant));
    });

    await etape('la pastille du menu', async () => {
        // La pastille est peuplee par un `fetch` au chargement : attendre le
        // CONTENU attendu, jamais une duree.
        const vu = await page.waitForFunction((sel, attendu) => {
            const el = document.querySelector(sel);

            return el && el.textContent.trim() === String(attendu) ? el.textContent.trim() : false;
        }, { timeout: 20000 }, C.pastille, nonLuesAvant).then((h) => h.jsonValue()).catch(() => null);
        verifie('la pastille du menu annonce le compte de non-lues', vu === String(nonLuesAvant),
            `pastille « ${vu} », base ${nonLuesAvant}`);
    });

    await etape('les lignes de l\'epreuve sont rendues', async () => {
        const texte = await page.evaluate(() => document.body.innerText);
        verifie('la notification non lue de l\'epreuve est affichee', texte.includes(`${MARQUE} non lue`));
        verifie('la diffusion est visible du role 3', texte.includes(`${MARQUE} diffusion`),
            'le role >= 2 voit les lignes user_id = 0');
    });

    // ══ 2. Quatre vocabulaires, deux qui ne se croisent pas ════════════════
    await etape('le type reel est-il nommable par la page ?', async () => {
        // LA PASTILLE DE LA LIGNE, pas « les spans du plus proche ancetre » : le
        // premier jet remontait jusqu'a la barre de navigation et rendait le menu
        // entier. L'assertion passait alors parce que le mot « Autre » n'est pas
        // dans le menu — un vert qu'on ne sait pas expliquer ne vaut rien.
        const etiquette = await page.evaluate((marque, sel) => {
            if (sel) {
                const e = document.querySelector(sel);

                return e ? (e.textContent || '').trim() : null;
            }
            // Legacy : la LIGNE est le div dont un ENFANT DIRECT est la pastille
            // de type (`notifications.php:118`). Ni le plus lointain ancetre (on
            // remontait au menu), ni le plus proche (on tombait sur le titre) :
            // celui qui porte la pastille en enfant direct, et lui seul.
            const ligne = Array.from(document.querySelectorAll('div'))
                .find((e) => (e.textContent || '').includes(marque + ' non lue')
                    && e.querySelector(':scope > span[class*="rounded-full"]'));
            if (! ligne) return null;
            const p = ligne.querySelector(':scope > span[class*="rounded-full"]');

            return p ? (p.textContent || '').trim() : null;
        }, MARQUE, C.pastilleType ? C.pastilleType(fixture.nonLue) : null);
        constate(`pastille de type rendue pour « ${TYPE_REEL} »`, etiquette || '(aucune)');
        verifie('la ligne porte une pastille de type', !! etiquette, String(etiquette));
        // Les preferences connaissent 6 types, la page en connait 6 AUTRES :
        // intersection vide, mesuree. Toute notification reellement produite
        // retombe donc sur le repli.
        verifiePortage('le type de la notification est nomme, pas replie sur « Autre »',
            !!etiquette && ! /Autre/.test(etiquette),
            'le vocabulaire des preferences et celui de la page ne se croisent en AUCUN type');
    });

    // ══ 3. Marquer UNE notification lue, par un vrai clic ══════════════════
    await etape('clic sur « marquer lue »', async () => {
        const bouton = await page.$(C.lire(fixture.nonLue));
        verifie('le bouton « marquer lue » existe pour la ligne de l\'epreuve', !! bouton,
            C.lire(fixture.nonLue));
        if (! bouton) return;

        // On RELEVE la reponse plutot que de deviner : un clic qui n'aboutit
        // pas et un clic qui aboutit sur un refus se ressemblent en base.
        const reponses = [];
        const ecoute = async (r) => {
            if (! /notifications/.test(r.url()) || r.request().method() !== 'POST') return;
            let corps = '';
            try { corps = (await r.text()).slice(0, 120); } catch { /* corps consomme */ }
            reponses.push(`${r.status()} ${corps}`);
        };
        page.on('response', ecoute);
        await bouton.click();
        const lue = await attendEnBase(() => estLue(fixture.nonLue), true);
        page.off('response', ecoute);

        // Ce que l'ECRAN a fait, et ce que le SERVEUR a entendu : les deux se
        // mesurent, parce que le legacy les fait diverger.
        const boutonParti = await page.evaluate((sel) => ! document.querySelector(sel), C.lire(fixture.nonLue));
        const htmxPresent = await page.evaluate(() => typeof window.htmx !== 'undefined');
        constate('htmx est-il charge sur la page ?', htmxPresent ? 'oui' : 'NON');
        constate('reponse au clic « marquer lue »', reponses.join(' | ') || '(aucune requete POST)');
        constate('le bouton a-t-il disparu de l\'ecran ?', boutonParti ? 'OUI' : 'non');

        // LE DEFAUT : le `onclick` du legacy fait `this.remove()` DANS l'evenement
        // de clic (`notifications.php:141`). L'element quitte le DOM avant que
        // htmx n'emette, donc rien ne part — mais le surlignage est retire et le
        // bouton disparait. L'ecran annonce une lecture que la base ignore, et
        // un simple rechargement la fait revenir.
        verifie('le clic modifie bien l\'ecran', boutonParti === true,
            'le bouton disparait, donc l\'utilisateur croit l\'action faite');
        verifiePortage('la notification cliquee passe LUE en base', lue === true,
            `id ${fixture.nonLue} : l'ecran a change, `
            + `${reponses.length ? 'la reponse etait ' + reponses.join(' | ') : 'AUCUNE requete n\'est partie'} `
            + '— l\'affichage optimiste ment');
    });

    // ══ 4. UN GET ECRIT, ET SANS JETON ═════════════════════════════════════
    // REQUETE FORGEE, et le motif est ecrit : la propriete mesuree est « une
    // requete en LECTURE modifie l'etat », et aucun element de l'interface ne
    // peut l'exprimer — le seul bouton de la page POSTe. Le `fetch` part DEPUIS
    // la page, donc avec la session reelle, et SANS en-tete CSRF : c'est
    // precisement ce qu'on veut prouver.
    await etape('un GET sans jeton marque-t-il tout comme lu ?', async () => {
        // On repose une ligne non lue pour avoir quelque chose a observer.
        litEnBase(`UPDATE rootwarden.notifications SET read_at = NULL WHERE id = ${fixture.nonLue}`);
        const avant = nonLuesDe(ID_SUPER);
        const d = await page.evaluate(async (route) => {
            const r = await fetch(route, { credentials: 'same-origin' });

            return { statut: r.status, texte: (await r.text()).slice(0, 120) };
        }, C.routeToutLire);
        const apres = await attendEnBase(() => nonLuesDe(ID_SUPER), 0);
        constate('reponse du GET', `${d.statut} — ${d.texte}`);
        constate('non lues avant / apres le GET', `${avant} / ${apres}`);
        // Cote legacy la propriete est mesuree et rendue en INFO : c'est
        // l'ecart, pas une regression. Le portage doit REFUSER.
        verifiePortage('un GET ne modifie rien', apres === avant,
            `${avant} non lues avant, ${apres} apres — le GET a ecrit, sans aucun jeton`);
    });

    // ══ 5. La preference : le clic envoie-t-il ce que la route lit ? ═══════
    await etape('la case de preference', async () => {
        const avant = prefEnBase();
        const emises = [];
        const ecoute = (r) => {
            if (/update_notification_prefs|preferences/.test(r.url()) && r.method() === 'POST') {
                emises.push({ url: r.url(), corps: r.postData() || '' });
            }
        };
        page.on('request', ecoute);

        await page.goto(`${BASE}${CIBLE === 'laravel' ? '/notifications/preferences' : '/adm/admin_page.php#access'}`,
            { waitUntil: 'networkidle2' });
        // UN BLOC REPLIE NE RECOIT PAS LES FRAPPES : ouvrir l'onglet puis la
        // carte, et l'ASSERTER avant de cliquer.
        await page.evaluate(() => {
            const onglet = document.querySelector('.tab-btn[data-tab="access"]');
            if (onglet) onglet.click();
            document.querySelectorAll('details.notif-card, .notif-card details, details')
                .forEach((d) => { d.open = true; });
        });
        await dors(400);
        const cible = `input[type="checkbox"][data-user-id="${ID_SUPER}"][data-event-type="${PREF}"]`;
        const visible = await page.evaluate((sel) => {
            const e = document.querySelector(sel);

            return e ? e.getClientRects().length > 0 : false;
        }, cible);
        verifie('la case de preference est visible avant le clic', visible, cible);
        if (! visible) { page.off('request', ecoute); return; }

        await page.click(cible);
        await dors(1500);
        page.off('request', ecoute);

        constate('requetes de preference emises', String(emises.length));
        if (emises.length) constate('corps emis', emises[0].corps.slice(0, 160) || '(vide)');
        verifie('le clic emet bien une requete', emises.length >= 1, `${emises.length}`);

        // LES DEUX COTES DU CONTRAT : le corps envoye porte-t-il la cle que la
        // route LIT ? `update_notification_prefs.php:32` exige `value`.
        const porteValue = emises.length > 0 && /(^|[&{"])value/.test(emises[0].corps);
        constate('le corps porte-t-il « value » ?', porteValue ? 'oui' : 'NON');

        const apres = prefEnBase();
        constate('preference avant / apres le clic', `${avant} / ${apres}`);
        // Mesure du 2026-08-26 : le legacy ECRIT bien. Ce n'est donc pas un
        // ecart mais une propriete que les DEUX cibles doivent tenir.
        verifie('le clic change bien la preference en base', avant !== apres,
            `avant ${avant}, apres ${apres}`);
        verifie('le corps emis porte la cle que la route lit', porteValue,
            emises.length ? emises[0].corps.slice(0, 80) : '(aucune requete)');

        const remplace = await page.evaluate((sel) => {
            const e = document.querySelector(sel);
            if (! e) return document.body.innerText.includes('Donnees manquantes')
                ? 'etiquette remplacee par le message d\'erreur' : 'case disparue';

            return 'case toujours la';
        }, cible);
        constate('etat de l\'etiquette apres le clic', remplace);
    });

    // ══ 6. La diffusion, et la moitie non corrigee du defaut ══════════════
    await etape('un role 1 peut-il marquer une DIFFUSION comme lue ?', async () => {
        litEnBase(`UPDATE rootwarden.notifications SET read_at = NULL WHERE id = ${fixture.diffusion}`);
        await dors((resteFenetre() + 1) * 1000);
        const bas = await connecte(COMPTE_BAS, SECRET_BAS);
        try {
            await bas.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            const texte = await bas.page.evaluate(() => document.body.innerText);
            verifie('le role 1 ne VOIT pas la diffusion', ! texte.includes(`${MARQUE} diffusion`),
                'la lecture filtre bien sur user_id = <lui>');

            // REQUETE FORGEE, motif ecrit : la propriete est « il ECRIT sur une
            // ligne qu'il ne voit pas ». Aucun clic ne peut l'exprimer, puisque
            // la ligne n'est pas rendue pour lui.
            const d = await bas.page.evaluate(async () => {
                const m = document.querySelector('meta[name="csrf-token"]');
                const jeton = m ? m.content
                    : (document.querySelector('input[name="csrf_token"]') || {}).value || '';
                const r = await fetch('/adm/api/notifications.php', {
                    method: 'POST', credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': jeton },
                    body: JSON.stringify({ action: 'read_all', csrf_token: jeton }),
                });

                return { statut: r.status, texte: (await r.text()).slice(0, 100) };
            });
            constate('reponse du read_all en role 1', `${d.statut} — ${d.texte}`);
            const diffusionLue = await attendEnBase(() => estLue(fixture.diffusion), true, 8000);
            constate('la diffusion est-elle passee lue ?', diffusionLue ? 'OUI' : 'non');
            verifiePortage('un role 1 ne touche pas une ligne de diffusion', ! diffusionLue,
                'le correctif A01 ne couvre que `delete` ; `read` et `read_all` gardent '
                + '`OR user_id = 0` pour tout le monde');
        } finally {
            await bas.ctx.close();
        }
    });

    // ══ 7. Les captures, aux trois largeurs ════════════════════════════════
    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            await page.screenshot({ path: `${dossier}/notifications-${nom}.png` });
        }
        constate('captures deposees', dossier);
        verifie('les trois captures sont ecrites', true);
    });

    verifie('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 3).join(' | '));

} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    // CHAQUE etape dans son propre `try` : une exception ici emporterait le
    // journal entier, et treize suites dependent de ces comptes.
    try {
        retireLaFixture();
        const reste = compteEnBase(`SELECT COUNT(*) FROM rootwarden.notifications WHERE id > ${borne}`);
        verifie('la fixture est retiree', reste === 0, `${reste} ligne(s) restantes`);
    } catch (e) { note(`FAIL  retrait de la fixture : ${e.message}`); echecs += 1; }
    try {
        if (prefInitiale === null) {
            litEnBase(`DELETE FROM rootwarden.notification_preferences WHERE user_id = ${ID_SUPER} AND event_type = '${PREF}'`);
        } else {
            litEnBase(`UPDATE rootwarden.notification_preferences SET enabled = ${prefInitiale} `
                + `WHERE user_id = ${ID_SUPER} AND event_type = '${PREF}'`);
        }
        verifie('la preference est restauree', prefEnBase() === prefInitiale,
            `attendu ${prefInitiale}, relu ${prefEnBase()}`);
    } catch (e) { note(`FAIL  restauration de la preference : ${e.message}`); echecs += 1; }
    try { for (const c of contextes) await c.close(); } catch (e) { note(`INFO  fermeture des contextes : ${e.message}`); }
    try { await navigateur.close(); } catch (e) { note(`INFO  fermeture du navigateur : ${e.message}`); }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
