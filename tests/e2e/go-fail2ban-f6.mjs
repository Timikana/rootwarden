/**
 * go-fail2ban-f6.mjs - Sous-lot F6 de `fail2ban/` : les gestes sur TOUT LE PARC.
 *
 * `POST /fail2ban/ban_all_servers` (fail2ban.py:505) et `/fail2ban/install_all`
 * (:645). Frontend : `banIpAllServers` (main.js:491), `installAllFail2ban`
 * (:509).
 *
 * ══ AUCUN DE CES DEUX GESTES N'EST LAISSE PARTIR. JAMAIS. ═════════════════
 *
 * Ce sont les deux seules routes du module qui ne prennent **aucun**
 * `machine_id` : elles choisissent elles-memes leurs cibles en base, et elles
 * les joignent TOUTES — `srv-zabbix` comprise. Le filet les avorte sans
 * exception, et une assertion de surete le verifie a la fin.
 *
 * Ce qui reste mesurable, et c'est l'essentiel :
 *   — ce que le bouton ENVERRAIT, lu sur la requete avortee ;
 *   — ce que la confirmation NOMME ;
 *   — et surtout **la PORTEE**, calculee en base avec le SQL exact des deux
 *     routes. C'est une lecture : elle ne joint personne.
 *
 * ══ CE QUE LA PORTEE REVELE ═══════════════════════════════════════════════
 *
 * `install_all` selectionne :
 *
 *     LEFT JOIN rootwarden.fail2ban_status f ON m.id = f.server_id
 *     WHERE f.installed IS NULL OR f.installed = 0
 *
 * Une machine **jamais relevee** n'a pas de ligne dans le cache : le `LEFT JOIN`
 * rend `NULL`, et `NULL` passe le `WHERE`. **Ne l'avoir jamais regardee suffit a
 * la faire installer.**
 *
 * `ban_all_servers` selectionne l'inverse — `INNER JOIN ... WHERE f.running = 1`
 * — donc les machines que le CACHE dit actives. Un cache vieux de deux semaines
 * decide donc du parc atteint : une machine dont fail2ban est tombe depuis est
 * ignoree, une machine installee depuis l'est aussi.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-fail2ban-f6
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

const MACHINE_ID = 2;
const MACHINE_PRODUCTION = 1;
const JAIL = 'sshd';
const ADRESSE = '203.0.113.7';

/** Les deux gestes de parc — AVORTES sans exception. */
const PARC = /\/fail2ban\/(ban_all_servers|install_all)(\?|$)/;
const STATUT = /\/fail2ban\/status(\?|$)/;
const SERVICES = /\/fail2ban\/services(\?|$)/;
/*
 * SERVI, ET SANS LUI RIEN NE S'OUVRE.
 *
 * Le bouton « Ban global » vit DANS le detail d'une jail. Une premiere redaction
 * avortait `/fail2ban/jail` — donc `loadJailDetail` echouait, le panneau restait
 * ferme, le bouton n'etait pas visible, et TROIS assertions passaient « parce
 * que le geste n'est pas offert »… sur le legacy, ou il l'est. Onzieme faux PASS
 * de ce module, et le premier cause par le filet lui-meme.
 */
const DETAIL_JAIL = /\/fail2ban\/jail(\?|$)/;
const BLANCHE = /\/fail2ban\/whitelist(\?|$)/;
const BASE_SEULE = /\/fail2ban\/(history|stats)(\?|$)/;
const ROUTES_MODULE = /\/fail2ban\/(status|jail|services|history|stats|config|logs|ban|unban|ban_all_servers|unban_all|install|install_all|restart|enable_jail|disable_jail|whitelist|geoip)(\?|$)/;
/*
 * LES DEUX GESTES DE F6, POUR RECONNAITRE UN GESTE DE PARC QUI PASSERAIT AILLEURS.
 *
 * `PARC` (plus haut) les capte deja sur leur chemin attendu et les avorte : ce
 * motif-ci ne sert QU'A qualifier une requete qui aurait echappe a
 * `ROUTES_MODULE` — donc a nommer le pire cas plutot qu'a le compter avec le
 * reste.
 *
 * MA PREMIERE REDACTION AVAIT SUR-DIAGNOSTIQUE, ET IL FAUT LE DIRE : j'avais
 * ecrit « aucun `quoi` du fichier ne vaut jamais parc ». Faux — `avortees` en
 * porte deux depuis toujours (`bannir-tout-le-parc`, `installer-tout-le-parc`).
 * Ce qui etait vrai, et qui suffisait : `abouties` ne peut contenir que `base`,
 * donc les deux assertions posees sur LUI ne pouvaient pas echouer. J'avais
 * ajoute une seconde branche d'avortement : elle etait INATTEIGNABLE, `PARC`
 * mordant trente lignes plus haut. Retiree.
 */
const GESTES_PARC = /\/fail2ban\/(ban_all_servers|install_all)(\?|$)/;
/* Ce qui vise le BACKEND, quel que soit le portail : passerelle ou proxy. */
const VERS_BACKEND = /\/(api\/gateway|api_proxy\.php)\//;

const DOSSIER_CAPTURES = new URL('./screenshots/fail2ban', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion', page: '/fail2ban',
        serveur: '[data-rw="f2b-serveur"]', relever: '[data-rw="f2b-relever"]',
        carteJail: `[data-rw="f2b-jail-${JAIL}"]`,
        champIp: '[data-rw="f2b-ban-ip"]',
        bannirParc: '[data-rw="f2b-bannir-parc"]',
        installerParc: '[data-rw="f2b-installer-parc"]',
        portee: '[data-rw="f2b-portee"]',
        confirmation: '[data-rw="f2b-confirmation"]', confirmer: '[data-rw="f2b-confirmer"]',
        journal: '[data-rw="f2b-journal"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr', page: '/fail2ban/',
        serveur: '#server', relever: 'button[onclick="loadStatus()"]',
        carteJail: '#jails-grid > div',
        champIp: '#ban-ip-input',
        bannirParc: 'button[onclick="banIpAllServers()"]',
        installerParc: '#btn-install-all',
        portee: null,
        confirmation: null, confirmer: null,
        journal: '#logs-container',
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
function verifie(l, ok, d, toujours) {
    const suffixe = toujours || (! ok && d) || '';
    note(`${ok ? 'PASS' : 'FAIL'}  ${l}${suffixe ? '  — ' + suffixe : ''}`);
    if (! ok) echecs += 1;
}
function constate(l, v) { note(`INFO  ${l} : ${v}`); }
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
    constate(l, ok ? 'verifie sur le legacy aussi' : `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

/*
 * LA PORTEE SE CALCULE EN BASE, AVEC LE SQL EXACT DES DEUX ROUTES.
 *
 * C'est une LECTURE : elle ne joint aucune machine. C'est la seule facon de
 * savoir ce que le bouton toucherait sans le laisser toucher.
 */
function porteeInstallerTout() {
    return litEnBase(
        "SELECT CONCAT(m.name, ' (', IFNULL(m.environment,'?'), ')') FROM rootwarden.machines m "
        + 'LEFT JOIN rootwarden.fail2ban_status f ON m.id = f.server_id '
        + 'WHERE f.installed IS NULL OR f.installed = 0');
}
function porteeBannirTout() {
    return litEnBase(
        "SELECT CONCAT(m.name, ' (', IFNULL(m.environment,'?'), ')') FROM rootwarden.machines m "
        + 'INNER JOIN rootwarden.fail2ban_status f ON m.id = f.server_id WHERE f.running = 1');
}
function ancienneteDuCache() {
    const r = litEnBase('SELECT IFNULL(MAX(last_checked), \'(jamais)\') FROM rootwarden.fail2ban_status');

    return r[0] || '(jamais)';
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});
const contextes = [];
const abouties = [];
const avortees = [];
const servies = [];
const boites = [];
let accepteLaBoite = false;
/** Ce que le statut servi annonce. `false` fait paraitre « installer sur tout ». */
let statutInstalle = true;

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(60000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => {
        boites.push({ type: d.type(), message: (d.message() || '').slice(0, 200) });
        try { await (accepteLaBoite ? d.accept() : d.dismiss()); } catch {}
    });

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        const url = r.url();
        const chemin = url.replace(/^https?:\/\/[^/]+/, '');

        // LES DEUX GESTES DE PARC, D'ABORD ET SANS EXCEPTION.
        if (PARC.test(url)) {
            avortees.push({
                route: chemin,
                quoi: /ban_all/.test(url) ? 'bannir-tout-le-parc' : 'installer-tout-le-parc',
                corps: (() => { try { return (r.postData() || '').slice(0, 200); } catch { return ''; } })(),
            });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (! ROUTES_MODULE.test(url)) {
            /*
             * LE TROU QUE CE FILET AVAIT.
             *
             * Tout ce que `ROUTES_MODULE` ne reconnait pas passait ici SANS etre
             * enregistre. Une route du backend nommee autrement — un renommage,
             * un alias, une casse differente — partait donc pour de vrai, et
             * aucune assertion ne pouvait le voir. On laisse toujours passer les
             * ressources de la page (feuilles, scripts, images), mais tout ce qui
             * vise le BACKEND est desormais compte, avec la nature qu'on lui
             * reconnait — pour que « seules des lectures ont abouti » puisse
             * enfin etre FAUSSE.
             */
            if (VERS_BACKEND.test(url)) {
                abouties.push({ route: chemin, methode: r.method(),
                    quoi: GESTES_PARC.test(url) ? 'parc-NON-RECONNU' : 'backend-non-reconnu' });
            }
            r.continue().catch(() => {});

            return;
        }


        if (STATUT.test(url)) {
            servies.push({ route: chemin, quoi: 'statut' });
            r.respond({ status: 200, contentType: 'application/json',
                body: JSON.stringify({ success: true,
                    installed: statutInstalle, running: statutInstalle,
                    jails: statutInstalle
                        ? [{ name: JAIL, currently_banned: 0, total_banned: 0 }] : [] }) }).catch(() => {});

            return;
        }
        if (DETAIL_JAIL.test(url)) {
            servies.push({ route: chemin, quoi: 'detail-jail' });
            r.respond({ status: 200, contentType: 'application/json',
                body: JSON.stringify({ success: true, banned_ips: [],
                    config: { maxretry: 5, bantime: 3600, findtime: 600 } }) }).catch(() => {});

            return;
        }
        if (SERVICES.test(url) || BLANCHE.test(url)) {
            servies.push({ route: chemin, quoi: SERVICES.test(url) ? 'services' : 'blanche' });
            r.respond({ status: 200, contentType: 'application/json',
                body: JSON.stringify(SERVICES.test(url)
                    ? { success: true, services: [{ service: 'sshd', installed: true,
                        jails: [{ name: JAIL, available: true, enabled: true }] }] }
                    : { success: true, ips: ['127.0.0.1/8', '::1'], lue: false }) }).catch(() => {});

            return;
        }
        if (BASE_SEULE.test(url)) {
            abouties.push({ route: chemin, methode: r.method(), quoi: 'base' });
            r.continue().catch(() => {});

            return;
        }
        avortees.push({ route: chemin, quoi: 'hors de F6', corps: '' });
        r.abort('blockedbyclient').catch(() => {});
    });

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

    return { ctx, page, erreursJs, surConnexion: /connexion|login\.php/.test(page.url()) };
}

async function choisitMachine(page, id) {
    const valeur = await page.evaluate((sel, cible) => {
        const s = document.querySelector(sel);
        if (! s) return null;
        for (const o of s.options) {
            if (! o.value) continue;
            if (o.value === String(cible)) return o.value;
            try { if (JSON.parse(o.value)?.id === cible) return o.value; } catch { /* pas du JSON */ }
        }

        return null;
    }, C.serveur, id);
    if (valeur === null) throw new Error(`aucune option ne designe la machine ${id}`);
    await page.select(C.serveur, valeur);
    await dors(250);
}

async function cliqueEtAttend(page, selecteur, ms) {
    const avant = abouties.length + avortees.length + servies.length;
    await page.click(selecteur);
    for (let i = 0; i < 80; i += 1) {
        if (abouties.length + avortees.length + servies.length > avant) break;
        await dors(200);
    }
    await dors(ms || 1500);
}

/** Visible = la place REELLEMENT occupee. `offsetParent` est null en `fixed`. */
async function visible(page, sel) {
    if (! sel) return false;

    return page.evaluate((s) => {
        const e = document.querySelector(s);
        if (! e || e.hidden) return false;
        const st = getComputedStyle(e);
        if (st.display === 'none' || st.visibility === 'hidden') return false;

        return e.getBoundingClientRect().height > 0;
    }, sel);
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

let session = null;

try {
    // ── LA PORTEE, AVANT TOUTE NAVIGATION ────────────────────────────────
    const installables = porteeInstallerTout();
    const bannissables = porteeBannirTout();
    constate('anciennete du cache `fail2ban_status`', ancienneteDuCache());
    constate('« installer sur tout le parc » toucherait', installables.join(' · ') || '(aucune)');
    constate('« bannir sur tout le parc » toucherait', bannissables.join(' · ') || '(aucune)');

    session = await connecte(COMPTE, SECRET);
    verifie('la session a tenu', ! session.surConnexion, session.page.url());
    if (session.surConnexion) throw new Error('session non etablie');
    const page = session.page;

    await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
    await dors(400);
    await choisitMachine(page, MACHINE_ID);
    await cliqueEtAttend(page, C.relever, 2000);

    // ═══ 1. LA PORTEE EST-ELLE DITE A L'ECRAN ? ══════════════════════════
    await etape('la portee des gestes de parc', async () => {
        /*
         * ══ NE JAMAIS AVOIR REGARDE UNE MACHINE SUFFIT A LA FAIRE INSTALLER ══
         *
         * `install_all` fait `LEFT JOIN fail2ban_status ... WHERE f.installed IS
         * NULL OR f.installed = 0`. Une machine jamais relevee n'a pas de ligne :
         * le `LEFT JOIN` rend `NULL`, et `NULL` passe le `WHERE`.
         *
         * `ban_all_servers` fait l'inverse — `INNER JOIN ... WHERE f.running = 1`
         * — donc les machines que le CACHE dit actives. Le parc atteint est
         * decide par un releve qui peut avoir des semaines.
         */
        /*
         * `Array.isArray(litEnBase(...))` est TOUJOURS vrai : la propriete ne
         * pouvait pas echouer. Ce qui peut l'etre, et qui compte ici, c'est que
         * la portee LUE soit la portee ENTIERE : `litEnBase` trime puis filtre,
         * donc une machine au nom vide DISPARAIT de la liste — et la portee
         * annoncee serait plus petite que celle que le backend joindrait.
         * On recompte par un autre moyen, sur le meme predicat.
         */
        const porteeComptee = compteEnBase(
            'SELECT COUNT(*) FROM rootwarden.machines m '
            + 'LEFT JOIN rootwarden.fail2ban_status f ON m.id = f.server_id '
            + 'WHERE f.installed IS NULL OR f.installed = 0');
        verifie('la portee lue est la portee ENTIERE',
            installables.length === porteeComptee,
            `${installables.length} nom(s) lus pour ${porteeComptee} machine(s) comptees — `
            + 'une ligne a disparu de la lecture, la portee annoncee serait trop petite',
            `${installables.length} = ${porteeComptee}`);
        const production = installables.filter((n) => /PROD|prod/.test(n));
        constate('machines de PRODUCTION dans la portee d\'une installation de masse',
            production.join(' · ') || '(aucune)');

        /*
         * ON CHERCHE L'ANNONCE LA OU LE GESTE VIT, PAS N'IMPORTE OU DANS LA PAGE.
         *
         * Une premiere redaction cherchait les noms de machines dans
         * `document.body.innerText` — et les trouvait, parce qu'ils sont dans le
         * SELECTEUR de machine. Elle repondait donc « l'ecran enumere les
         * machines touchees : OUI » alors que rien n'annonce la portee.
         * Dixieme motif plus large que la propriete sur ce module.
         *
         * La portee doit etre dite dans une zone qui lui est dediee — c'est ce
         * que `f2b-portee` designe cote portage — ou, a defaut, dans la
         * confirmation du geste. Le selecteur de machine ne l'annonce pas.
         */
        const texte = C.portee
            ? await page.evaluate((s) => {
                const e = document.querySelector(s);

                return e ? (e.innerText || '') : '';
            }, C.portee)
            : '';
        const enumere = installables.length > 0 && texte.trim().length > 0
            && installables.every((n) => texte.includes(String(n).split(' (')[0]));
        constate('l\'ecran enumere-t-il les machines qui seraient touchees ?', enumere ? 'OUI' : 'non');
        verifiePortage('l\'ecran DIT quelles machines un geste de parc toucherait',
            enumere,
            `« installer sur tout le parc » toucherait ${installables.length} machine(s) — `
            + `${installables.join(', ')} — et la page n'en nomme aucune. La selection vient d'un `
            + 'cache ou « jamais relevee » compte comme « fail2ban absent »');
    });

    // ═══ 2. BANNIR SUR TOUT LE PARC ══════════════════════════════════════
    await etape('bannir sur tout le parc', async () => {
        // LE GESTE VIT DANS LE DETAIL D'UNE JAIL : il faut l'ouvrir d'abord.
        // Une premiere redaction cherchait le bouton avant, le trouvait dans un
        // panneau CACHE, et Puppeteer levait « Node is either not clickable ».
        const carte = await page.$(C.carteJail);
        if (carte) { await cliqueEtAttend(page, C.carteJail, 1800); }

        const offert = await visible(page, C.bannirParc);
        constate('le geste « bannir sur tout le parc » est-il offert ?',
            offert ? 'OUI' : 'non — il n\'est pas rendu');
        if (! offert) {
            verifiePortage('la confirmation d\'un geste de parc NOMME l\'adresse', true, '');
            verifiePortage('la confirmation d\'un geste de parc DIT combien de machines', true, '');

            return;
        }
        const champ = await page.$(C.champIp);
        if (champ) {
            await page.click(C.champIp, { clickCount: 3 });
            await page.type(C.champIp, ADRESSE, { delay: 10 });
        }

        const avantBoites = boites.length;
        accepteLaBoite = true;
        await cliqueEtAttend(page, C.bannirParc, 2500);
        accepteLaBoite = false;

        const nouvelles = boites.slice(avantBoites);
        const panneau = C.confirmation && await visible(page, C.confirmation)
            ? await page.evaluate((s) => (document.querySelector(s).innerText || '')
                .replace(/\s+/g, ' ').trim(), C.confirmation)
            : '';
        const texteConf = nouvelles.map((b) => b.message).join(' ') + ' ' + panneau;
        constate('ce que la confirmation dit', texteConf.trim().slice(0, 150) || '(aucune)');

        verifie('un geste de parc demande confirmation', texteConf.trim().length > 0,
            'aucune confirmation');
        /*
         * `banIpAllServers` passe `{ip, jail}` a la traduction, et le catalogue
         * les ignore : la boite dit « Bannir cette IP sur TOUS les serveurs ? ».
         * Cinquieme occurrence du motif d'E-163 — et celle dont l'enjeu est le
         * plus grand : on accepte de bannir sur tout le parc sans savoir QUOI.
         */
        verifiePortage('la confirmation d\'un geste de parc NOMME l\'adresse',
            texteConf.includes(ADRESSE),
            `elle dit « ${texteConf.trim().slice(0, 60)} » — l'adresse lui est pourtant passee`);
        verifiePortage('la confirmation d\'un geste de parc DIT combien de machines',
            /\b\d+\b/.test(texteConf.replace(ADRESSE, '')),
            'elle dit « TOUS les serveurs » sans en donner le nombre ni les nommer');
    });

    // ═══ 3. INSTALLER SUR TOUT LE PARC ═══════════════════════════════════
    await etape('installer sur tout le parc', async () => {
        /*
         * CE BOUTON N'APPARAIT QUE SI FAIL2BAN EST ABSENT. `loadStatus` cache
         * `btn-install-all` des que la machine a fail2ban — or les etapes
         * precedentes servent `installed: true` pour faire exister les jails.
         * On sert donc ici un statut « pas installe », et on releve a nouveau :
         * c'est le seul etat ou le geste est atteignable.
         */
        statutInstalle = false;
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await dors(400);
        await choisitMachine(page, MACHINE_ID);
        await cliqueEtAttend(page, C.relever, 2000);

        const offert = await visible(page, C.installerParc);
        constate('le geste « installer sur tout le parc » est-il offert ?',
            offert ? 'OUI' : 'non — il n\'est pas rendu ou pas visible');
        if (! offert) {
            verifiePortage('la confirmation d\'une installation de masse NOMME les machines', true, '');

            return;
        }
        const avantBoites = boites.length;
        accepteLaBoite = true;
        await cliqueEtAttend(page, C.installerParc, 2500);
        accepteLaBoite = false;

        const nouvelles = boites.slice(avantBoites);
        const panneau = C.confirmation && await visible(page, C.confirmation)
            ? await page.evaluate((s) => (document.querySelector(s).innerText || '')
                .replace(/\s+/g, ' ').trim(), C.confirmation)
            : '';
        const texteConf = nouvelles.map((b) => b.message).join(' ') + ' ' + panneau;
        constate('ce que la confirmation dit', texteConf.trim().slice(0, 150) || '(aucune)');
        verifie('une installation de masse demande confirmation', texteConf.trim().length > 0,
            'aucune confirmation');

        const nomme = installables.length > 0
            && installables.some((n) => texteConf.includes(String(n).split(' (')[0]));
        verifiePortage('la confirmation d\'une installation de masse NOMME les machines',
            nomme,
            `elle dit « ${texteConf.trim().slice(0, 70) }» — sans nommer aucune des `
            + `${installables.length} machines qu'elle toucherait, dont `
            + `${installables.filter((n) => /PROD/i.test(n)).length} en production`);
    });

    // ═══ 4. SURETE ══════════════════════════════════════════════════════
    await etape('surete', async () => {
        const gestesParc = avortees.filter((a) => /parc/.test(a.quoi));
        constate('gestes de parc AVORTES', gestesParc.map((a) => a.quoi).join(' ') || '(aucun)');
        gestesParc.forEach((a) => constate(`corps de « ${a.quoi} »`, a.corps || '(vide)'));
        constate('requetes SERVIES', servies.map((s) => s.quoi).join(' ') || '(aucune)');
        constate('requetes abouties', abouties.map((a) => a.quoi).join(' ') || '(aucune)');
        // Une route non reconnue se CORRIGE par son chemin, pas par son etiquette.
        abouties.filter((a) => a.quoi !== 'base')
            .forEach((a) => constate('  route LAISSEE PASSER, non reconnue', a.route));

        /* LA PROPRIETE DE SURETE DE CE LOT, ET LA SEULE QUI COMPTE. */
        verifie('AUCUN geste de parc n\'a abouti',
            ! abouties.some((a) => /parc/.test(a.quoi)), 'un geste de parc est parti');
        /*
         * MA PREMIERE REDACTION ETAIT TROP LARGE, et le banc l'a montre du
         * premier coup : elle exigeait `quoi === 'base'` de TOUTE requete
         * laissee passer, alors que « base » ne nomme que les lectures de
         * fail2ban. La page legacy tire aussi `/api_proxy.php/cve_trends` — une
         * lecture d'un AUTRE module, parfaitement inoffensive — et l'assertion
         * la comptait comme un manquement a la surete. Un FAIL qui accuse une
         * page saine vaut a peine mieux qu'un PASS creux.
         *
         * Ce qui compte n'est pas « rien d'etranger n'est passe » mais « rien de
         * ce qui est passe ne peut MUTER ». On juge donc sur la METHODE, et on
         * garde le module a part.
         */
        const duModule = abouties.filter((a) => a.quoi !== 'backend-non-reconnu');
        verifie('seules des lectures en base ont abouti, cote fail2ban',
            duModule.length > 0 && duModule.every((a) => a.quoi === 'base'),
            duModule.length === 0
                ? 'AUCUNE lecture du module laissee passer — `[].every()` rend `true`, '
                  + 'donc cette propriete se serait verifiee sur rien'
                : duModule.map((a) => `${a.quoi} ${a.route}`).join(' | '),
            `${duModule.length} lecture(s) du module`);

        /*
         * LE TROU QUE LE FILET AVAIT, ET QU'AUCUNE ASSERTION NE VOYAIT : une
         * route du backend que `ROUTES_MODULE` ne reconnait pas part POUR DE
         * VRAI. Inoffensif tant qu'elle ne fait que lire ; un `POST` ou un
         * `DELETE` laisse passer serait, lui, un geste non mesure.
         */
        const mutantes = abouties.filter((a) => a.quoi === 'parc-NON-RECONNU'
            || (a.quoi === 'backend-non-reconnu' && a.methode !== 'GET'));
        verifie('aucune requete laissee passer ne peut MUTER',
            mutantes.length === 0,
            mutantes.map((a) => `${a.methode} ${a.route}`).join(' | '),
            `${abouties.filter((a) => a.quoi === 'backend-non-reconnu').length} etrangere(s), toutes en lecture`);
        verifie('aucune erreur JavaScript', session.erreursJs.length === 0,
            session.erreursJs.join(' | '));
    });

    // ═══ 5. CAPTURES ════════════════════════════════════════════════════
    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                         { n: 'mobile', w: 390, h: 844 }]) {
            await page.setViewport({ width: f.w, height: f.h });
            await dors(350);
            await page.screenshot({ path: `${dossier}/f6-${f.n}.png`, fullPage: true });
        }
        verifie('les trois captures sont ecrites', true, '', `${dossier}/f6-*.png`);
    });
} catch (e) {
    verifie('deroulement sans exception', false, String(e.message || e).split('\n')[0]);
} finally {
    try {
        for (const ctx of contextes) { try { await ctx.close(); } catch {} }
        await navigateur.close();
    } catch { /* deja ferme */ }
}

note(`${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
process.exit(echecs === 0 ? 0 : 1);
