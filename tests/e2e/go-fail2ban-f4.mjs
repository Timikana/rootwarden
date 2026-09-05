/**
 * go-fail2ban-f4.mjs - Sous-lot F4 de `fail2ban/` : bannir et debannir.
 *
 * `POST /fail2ban/jail` (fail2ban.py:146, LECTURE), `/fail2ban/ban` (:195),
 * `/fail2ban/unban` (:224) et `/fail2ban/unban_all` (:441) — les trois derniers
 * MODIFIENT la machine distante.
 *
 * ══ PREMIER SOUS-LOT DE `fail2ban/` QUI ECRIT ═════════════════════════════
 *
 * Les commandes sont composees sans risque — `_validate_jail` et `_validate_ip`
 * filtrent, aucune valeur du client n'est interpolee brute :
 *
 *     fail2ban-client set <jail> banip <ip>
 *     fail2ban-client set <jail> unbanip <ip>
 *     fail2ban-client set <jail> unbanip --all
 *
 * SURETE, et chaque point est une decision :
 *   — `srv-zabbix` (id 1) n'est JAMAIS jointe. Le filet avorte toute requete
 *     qui la vise, meme une lecture ;
 *   — l'adresse bannie est `203.0.113.7`, dans TEST-NET-3 (RFC 5737), reservee
 *     a la documentation. Elle n'appartient a personne, et surtout pas au
 *     portail : bannir l'adresse du portail couperait son propre acces ;
 *   — `/fail2ban/ban_all_servers` est AVORTEE. Elle bannit sur TOUTES les
 *     machines, production comprise, et appartient a F6. Son bouton est
 *     pourtant a un centimetre de celui qu'on clique — voir l'etape 3 ;
 *   — la machine d'essai n'a PAS fail2ban : les commandes echouent donc, et
 *     rien n'est reellement banni. C'est ce qui rend ce sous-lot mesurable
 *     sans danger — et c'est aussi ce qui revele le defaut principal.
 *
 * ══ CE QU'ON MESURE ═══════════════════════════════════════════════════════
 *
 * `fail2ban_ban` recoit `rc` et **ne le teste jamais** :
 *
 *     out, stderr, rc = ban_ip(client, root_pass, jail, target_ip)
 *     _log_ban_action(mid, jail, target_ip, 'ban', ...)          # inconditionnel
 *     return jsonify({'success': True, 'message': f'{target_ip} banni ...'})
 *
 * Sur une machine sans fail2ban, la commande echoue, la page annonce « banni »,
 * et une ligne d'audit affirme que le ban a eu lieu. **La table d'audit
 * enregistre un fait qui ne s'est pas produit.**
 *
 * La preuve se lit SUR LA PAGE, sans rien savoir du backend : `banIp` recharge
 * le detail du jail juste apres, et la liste des IP bannies qu'il affiche **ne
 * contient pas** l'adresse que la page vient de declarer bannie. Deux verites
 * sur le meme ecran, a une ligne d'intervalle.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-fail2ban-f4
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';
import { constateArchivage } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';

const MACHINE_ID = 2;
const MACHINE_PRODUCTION = 1;
const JAIL = 'sshd';
/** TEST-NET-3 (RFC 5737) : reservee a la documentation, n'appartient a personne. */
const ADRESSE = '203.0.113.7';
/*
 * E-174 — l'identifiant de PORTEE IPv6, celui qui suit un `%`.
 *
 * L'ancienne validation appelait `ipaddress.ip_address(ip)` pour son seul effet
 * de bord, jetait l'objet et rendait la chaine RECUE : la portee repartait
 * verbatim dans un f-string vers `fail2ban-client`, puis dans un `sh -c`
 * distant. Execution de commande arbitraire en root.
 *
 * LA CHARGE EST INOFFENSIVE ET C'EST DELIBERE : `%eth0` est un nom d'interface
 * ordinaire, pas une commande. Demontrer la faille en envoyant `%$(id)`
 * reviendrait A LA COMMETTRE sur la machine d'essai. Ce qu'on mesure est le
 * VERDICT du garde — refuse-t-il la FORME ? —, jamais son contournement.
 */
const ADRESSE_PORTEE = 'fe80::1%eth0';

/** Ce que F4 laisse aboutir, et seulement vers la machine 2. */
const GESTES_F4 = /\/fail2ban\/(jail|ban|unban|unban_all)(\?|$)/;
/** Servi : sans lui, aucune carte de jail n'existe sur un banc sans fail2ban. */
const STATUT = /\/fail2ban\/status(\?|$)/;
/** Lu en base, sans effet distant. */
const BASE_SEULE = /\/fail2ban\/(history|stats)(\?|$)/;
/** F5 et F6 — dont `ban_all_servers`, qui atteint la PRODUCTION. */
const HORS_LOT = /\/fail2ban\/(ban_all_servers|install|install_all|restart|enable_jail|disable_jail|whitelist|geoip|config|logs|services)(\?|$)/;
const ROUTES_MODULE = /\/fail2ban\/(status|jail|services|history|stats|config|logs|ban|unban|ban_all_servers|unban_all|install|install_all|restart|enable_jail|disable_jail|whitelist|geoip)(\?|$)/;

const DOSSIER_CAPTURES = new URL('./screenshots/fail2ban', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion', page: '/fail2ban',
        serveur: '[data-rw="f2b-serveur"]', relever: '[data-rw="f2b-relever"]',
        carteJail: `[data-rw="f2b-jail-${JAIL}"]`,
        panneau: '[data-rw="f2b-jail-detail"]',
        champIp: '[data-rw="f2b-ban-ip"]',
        bannir: '[data-rw="f2b-bannir"]',
        bannirParc: '[data-rw="f2b-bannir-parc"]',
        toutDebannir: '[data-rw="f2b-tout-debannir"]',
        listeBannies: '[data-rw="f2b-bannies-corps"]',
        journal: '[data-rw="f2b-journal"]',
        confirmation: '[data-rw="f2b-confirmation"]',
        confirmer: '[data-rw="f2b-confirmer"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr', page: '/fail2ban/',
        serveur: '#server', relever: 'button[onclick="loadStatus()"]',
        carteJail: '#jails-grid > div',
        panneau: '#jail-detail',
        champIp: '#ban-ip-input',
        bannir: 'button[onclick="banIpFromForm()"]',
        bannirParc: 'button[onclick="banIpAllServers()"]',
        toutDebannir: 'button[onclick="unbanAllIps()"]',
        listeBannies: '#banned-ips-table',
        journal: '#logs-container',
        // Le legacy n'a pas de panneau de decision : il ouvre un `confirm()`.
        confirmation: null, confirmer: null,
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

function cacheEnBase() {
    const r = litEnBase("SELECT CONCAT_WS('|', installed, running, total_banned, "
        + "IFNULL(jails_json,''), last_checked) FROM rootwarden.fail2ban_status "
        + `WHERE server_id = ${MACHINE_ID}`);

    return r[0] || '(absent)';
}
function borneHistorique() {
    return compteEnBase('SELECT IFNULL(MAX(id),0) FROM rootwarden.fail2ban_history');
}

function machineVisee(requete) {
    try {
        const corps = requete.postData();
        if (corps) {
            const b = /"(machine_id|server_id)"\s*:\s*"?(\d+)"?/.exec(corps);
            if (b) return Number(b[2]);
        }
    } catch { /* corps illisible */ }
    const m = /[?&](machine_id|server_id)=(\d+)/.exec(requete.url());

    return m ? Number(m[2]) : null;
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});
const contextes = [];
const abouties = [];
const reponses = [];
const avortees = [];
const servies = [];
const boites = [];

/** Ce que la prochaine boite native doit recevoir. Par defaut : REFUS. */
let accepteLaBoite = false;

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(60000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    /*
     * LES BOITES NATIVES SE REFUSENT PAR DEFAUT.
     *
     * Une confirmation acceptee par reflexe est une action destructrice
     * declenchee sans decision. Le drapeau n'est leve que par l'etape qui veut
     * VRAIMENT le geste, et il retombe aussitot.
     */
    page.on('dialog', async (d) => {
        boites.push({ type: d.type(), message: (d.message() || '').slice(0, 160),
            accepte: accepteLaBoite });
        try { await (accepteLaBoite ? d.accept() : d.dismiss()); } catch {}
    });

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        const url = r.url();
        const chemin = url.replace(/^https?:\/\/[^/]+/, '');
        if (! ROUTES_MODULE.test(url)) { r.continue().catch(() => {}); return; }
        const cible = machineVisee(r);

        if (STATUT.test(url)) {
            servies.push({ route: chemin, machine: cible });
            r.respond({ status: 200, contentType: 'application/json',
                body: JSON.stringify({
                    success: true, installed: true, running: true,
                    jails: [{ name: JAIL, currently_banned: 0, total_banned: 0 }],
                }) }).catch(() => {});

            return;
        }
        // FAIL-CLOSED : hors lot, ou hors de la machine d'essai -> avorte.
        if (! HORS_LOT.test(url) && (GESTES_F4.test(url) || BASE_SEULE.test(url))
            && cible === MACHINE_ID) {
            abouties.push({ route: chemin, machine: cible });
            r.continue().catch(() => {});

            return;
        }
        avortees.push({
            route: chemin,
            machine: cible === null ? '(indetermine)' : String(cible),
            motif: HORS_LOT.test(url) ? 'appartient a F5 ou F6' : 'machine hors perimetre',
        });
        r.abort('blockedbyclient').catch(() => {});
    });

    /*
     * LES REPONSES — f4 n'en collectait aucune.
     *
     * `abouties` est peuple dans `page.on('request')` : il dit qu'une requete
     * est PARTIE, jamais ce que le serveur en a fait. Pour E-174 la propriete
     * porte precisement sur le VERDICT du backend (400), donc sur la reponse.
     */
    page.on('response', async (r) => {
        const u = r.url();
        if (! /\/fail2ban\//.test(u)) return;
        let message = '';
        try {
            const t = await r.text();
            try { message = String(JSON.parse(t).message || ''); } catch { message = t.slice(0, 120); }
        } catch { /* corps illisible ou deja consomme */ }
        reponses.push({ route: u.replace(/^https?:\/\/[^/]+/, ''), statut: r.status(), message });
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
    const avant = abouties.length + avortees.length;
    await page.click(selecteur);
    for (let i = 0; i < 80; i += 1) {
        if (abouties.length + avortees.length > avant) break;
        await dors(200);
    }
    await dors(ms || 1500);
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

const CACHE_ORIGINE = cacheEnBase();
const BORNE = borneHistorique();
let session = null;

try {
    /*
     * ══ LE SUJET DE CETTE SUITE N'EXISTE PLUS COTE LEGACY ═════════════════
     *
     * Une suite de parite dont la moitie legacy a ete archivee ne doit pas
     * ECHOUER : un rouge permanent finit par ne plus etre lu, et il occupe la
     * place ou l'on aurait cherche une vraie regression. Elle CONSTATE, et sa
     * moitie portage continue de s'exercer.
     *
     * LE CONSTAT VIENT AVANT LA CONNEXION, et ce n'est pas un detail : la sonde
     * de `archive.mjs` n'ouvre pas de navigateur (Apache rend 404 pour un chemin
     * absent AVANT toute redirection de connexion). Se connecter d'abord ferait
     * consommer un code TOTP — dont le garde anti-rejeu est par COMPTE et
     * PERSISTANT — pour aller mesurer une page qui n'existe plus.
     *
     * ⚠ ET LE CONSTAT EXIGE UN 404, PAS UNE ABSENCE DE PAGE. Le 2026-09-05 ces
     * repertoires rendaient 403 : le `git mv` avait emporte les `.php` et laisse
     * le JavaScript, si bien que le dossier existait encore. `constateArchivage`
     * traite tout statut != 404 comme « encore servie » et rend `false` : le
     * constat aurait ete FAUX et la suite rouge quand meme. L'archivage a ete
     * acheve (`7588e71`) avant que cette ligne soit ecrite.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: C.page, fichiers: [], verifie, constate,
        });
        if (archivee) throw new Error('__archivee__');
    }

    constate('cache `fail2ban_status` a l\'entree', CACHE_ORIGINE);
    constate('borne de `fail2ban_history` a l\'entree', `id > ${BORNE}`);
    session = await connecte(COMPTE, SECRET);
    verifie('la session a tenu', ! session.surConnexion, session.page.url());
    if (session.surConnexion) throw new Error('session non etablie');
    const page = session.page;

    await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
    await dors(400);

    // ═══ 1. OUVRIR LE DETAIL D'UNE JAIL ══════════════════════════════════
    await etape('ouvrir le detail d\'une jail', async () => {
        await choisitMachine(page, MACHINE_ID);
        await cliqueEtAttend(page, C.relever, 1200);
        const carte = await page.$(C.carteJail);
        verifie('la carte de la jail est rendue', carte !== null, C.carteJail);
        if (! carte) throw new Error('aucune carte de jail');
        await cliqueEtAttend(page, C.carteJail, 2500);

        const vu = await page.evaluate((sels) => {
            const p = document.querySelector(sels.panneau);

            return {
                ouvert: p ? (p.offsetParent !== null && ! p.hidden) : false,
                champ: document.querySelector(sels.champIp) !== null,
            };
        }, C);
        constate('panneau de detail ouvert', `${vu.ouvert}`);
        verifie('le detail de la jail s\'ouvre', vu.ouvert && vu.champ,
            `ouvert=${vu.ouvert} champ=${vu.champ}`);
        verifie('la lecture du detail est partie vers la machine d\'essai',
            abouties.some((a) => /\/jail(\?|$)/.test(a.route) && a.machine === MACHINE_ID),
            abouties.map((a) => a.route).join(' '));
    });

    // ═══ 2. TROIS BOUTONS DESTRUCTEURS, UN SEUL CHAMP ════════════════════
    await etape('les trois boutons et le champ qu\'ils partagent', async () => {
        /*
         * LE BOUTON QUI ATTEINT LA PRODUCTION EST AU MILIEU.
         *
         * `banIpFromForm()` bannit sur LA machine choisie. `banIpAllServers()`
         * bannit sur TOUTES, production comprise. `unbanAllIps()` vide la jail.
         * Les trois sont cote a cote, alimentes par le MEME champ, et ne se
         * distinguent que par une nuance : `bg-red-600`, `bg-red-800`,
         * `bg-orange-600`.
         *
         * On mesure les couleurs RENDUES — pas les classes : une classe purgee
         * les rendrait identiques sans qu'aucune assertion DOM ne le voie.
         */
        const vu = await page.evaluate((sels) => {
            const lire = (s) => {
                const b = document.querySelector(s);
                if (! b) return null;
                const r = b.getBoundingClientRect();

                return {
                    texte: (b.textContent || '').trim(),
                    fond: getComputedStyle(b).backgroundColor,
                    x: Math.round(r.left), y: Math.round(r.top), l: Math.round(r.width),
                };
            };

            return {
                bannir: lire(sels.bannir),
                parc: lire(sels.bannirParc),
                tout: lire(sels.toutDebannir),
                champPartage: document.querySelectorAll(sels.champIp).length,
            };
        }, C);
        constate('bannir (cette machine)', vu.bannir ? `« ${vu.bannir.texte} » ${vu.bannir.fond}` : '(absent)');
        constate('bannir (TOUT LE PARC)', vu.parc ? `« ${vu.parc.texte} » ${vu.parc.fond}` : '(absent)');
        constate('tout debannir', vu.tout ? `« ${vu.tout.texte} » ${vu.tout.fond}` : '(absent)');
        /*
         * UN GESTE QUI N'EST PAS OFFERT NE PEUT PAS ETRE CLIQUE PAR ERREUR.
         *
         * Le portage ne rend pas le ban de parc : il appartient a F6, et le
         * panneau « pas encore porte » le dit. Son absence satisfait donc la
         * propriete tout autant que sa separation — mais il faut le DIRE, sans
         * quoi l'assertion passerait en silence.
         */
        if (! vu.parc) {
            verifiePortage('le geste qui atteint TOUT LE PARC se distingue du geste local',
                true, '');
            constate('le ban de parc est-il offert sur cette page ?', 'non — il n\'est pas rendu');
        }
        if (vu.bannir && vu.parc) {
            const ecart = Math.abs(vu.parc.x - (vu.bannir.x + vu.bannir.l));
            constate('espace entre « bannir » et « bannir tout le parc »', `${ecart}px`);
            /*
             * La PROPRIETE : le geste qui atteint TOUT LE PARC ne se distingue
             * pas du geste local par la seule couleur, ni par sa seule position.
             * Un ecart de quelques pixels entre deux boutons de meme forme, dont
             * l'un touche la production, est un piege a clic.
             */
            const distingue = ecart >= 24
                || /parc|tous|all|flotte|fleet/i.test(vu.parc.texte)
                    !== /parc|tous|all|flotte|fleet/i.test(vu.bannir.texte);
            verifiePortage('le geste qui atteint TOUT LE PARC se distingue du geste local',
                distingue && ecart >= 24,
                `« ${vu.bannir.texte} » et « ${vu.parc.texte} » sont a ${ecart}px l'un de l'autre, `
                + 'de meme forme et de meme taille, et ne different que par une nuance de rouge '
                + `(${vu.bannir.fond} contre ${vu.parc.fond}) — celui du milieu bannit sur TOUTES `
                + 'les machines, production comprise');
        }
        verifie('un seul champ d\'adresse existe', vu.champPartage === 1, `${vu.champPartage}`);

        /*
         * ══ LES DEUX GESTES LES PLUS DESTRUCTEURS ONT PERDU LEUR COULEUR ═══
         *
         * Mesure du 2026-08-27, sur le style CALCULE :
         *   « Ban »            rgb(220, 38, 38)   — `bg-red-600` survit
         *   « Ban global »     rgba(0, 0, 0, 0)   — `bg-red-800` PURGEE
         *   « Debannir tout »  rgba(0, 0, 0, 0)   — `bg-orange-600` PURGEE
         *
         * Le seul bouton qui garde sa couleur d'alerte est le MOINS dangereux
         * des trois. Celui qui bannit sur toutes les machines de production, et
         * celui qui vide une jail entiere, sont rendus sans fond.
         *
         * Cinquieme occurrence de la famille « classe purgee » sur ce chantier,
         * et la premiere ou elle retire un signal de DANGER. Aucune assertion
         * sur le DOM ne peut le voir : le HTML porte bien `bg-red-800`.
         */
        const peint = (b) => b && ! /rgba?\([^)]*,\s*0\s*\)/.test(b.fond) && b.fond !== 'transparent';
        const sansCouleur = [
            ['bannir (cette machine)', vu.bannir],
            ['bannir tout le parc', vu.parc],
            ['tout debannir', vu.tout],
        ].filter(([, b]) => b && ! peint(b)).map(([n]) => n);
        constate('gestes destructeurs SANS fond peint', sansCouleur.join(' \u00b7 ') || '(aucun)');
        verifiePortage('chaque geste destructeur porte une couleur d\'alerte RENDUE',
            sansCouleur.length === 0,
            `${sansCouleur.join(' et ')} n'ont aucun fond peint (${vu.parc ? vu.parc.fond : '?'}) `
            + 'alors que leur HTML porte bien la classe : `bg-red-800` et `bg-orange-600` sont '
            + 'purgees. Le seul bouton qui garde sa couleur est le MOINS dangereux des trois');
    });

    // ═══ 3. BANNIR — ET CE QUE LA PAGE EN DIT ════════════════════════════
    await etape('bannir une adresse', async () => {
        await page.click(C.champIp, { clickCount: 3 });
        await page.type(C.champIp, ADRESSE, { delay: 10 });
        const avantBoites = boites.length;

        /*
         * DEUX FAÇONS DE CONFIRMER, ET LE PROJET EN PREFERE UNE.
         *
         * Le legacy ouvre un `confirm()` natif. La convention du portage veut un
         * PANNEAU EN PAGE, qui dit ce que l'action engage — un `confirm()` tient
         * en une ligne, s'accepte au reflexe, et ne peut rien montrer.
         *
         * La propriete est « le geste destructeur demande une confirmation qui
         * NOMME sa cible ». Les deux formes la satisfont ; on mesure laquelle.
         */
        accepteLaBoite = true;
        await cliqueEtAttend(page, C.bannir, 2500);
        accepteLaBoite = false;

        const nouvelles = boites.slice(avantBoites);
        constate('boites natives ouvertes', nouvelles.length
            ? nouvelles.map((b) => `${b.type} « ${b.message} »`).join(' | ') : '(aucune)');

        const panneau = C.confirmation ? await page.evaluate((sels) => {
            const p = document.querySelector(sels.confirmation);
            if (! p) return null;

            return {
                ouvert: p.offsetParent !== null && ! p.hidden,
                texte: (p.innerText || '').replace(/\s+/g, ' ').trim(),
            };
        }, C) : null;
        if (panneau) {
            constate('panneau de decision en page', panneau.ouvert
                ? `« ${panneau.texte.slice(0, 130)} »` : '(ferme)');
        }

        const texteConfirmation = nouvelles.map((b) => b.message).join(' ')
            + ' ' + (panneau && panneau.ouvert ? panneau.texte : '');
        verifie('le geste destructeur a demande confirmation',
            nouvelles.length > 0 || (panneau && panneau.ouvert),
            'ni boite native ni panneau de decision');
        /*
         * UNE CONFIRMATION QUI NE NOMME PAS SA CIBLE NE CONFIRME RIEN.
         *
         * `banIp` passe pourtant `{ip, jail, server: _currentServer.name}` a la
         * traduction — et le catalogue les ignore tous les trois : la boite dit
         * « Bannir cette IP ? ». Quatrieme occurrence du motif d'E-163, et ici
         * elle n'est pas cosmetique : on confirme un geste destructeur sans
         * savoir sur QUELLE adresse ni sur QUELLE machine — alors que F4 vient
         * de montrer que la machine peut differer de celle qu'affiche le
         * selecteur (E-162).
         */
        constate('ce que la confirmation nomme', texteConfirmation.replace(/\s+/g, ' ').trim().slice(0, 140) || '(vide)');
        verifiePortage('la confirmation NOMME l\'adresse et la machine',
            texteConfirmation.includes(ADRESSE)
            && /Test-Server|essai|10\.10\.10\.10/i.test(texteConfirmation),
            `elle dit « ${texteConfirmation.replace(/\s+/g, ' ').trim().slice(0, 60)} » — `
            + 'ni l\'adresse, ni la jail, ni la machine, alors que les trois lui sont passees');
        // La convention du portage : pas de boite native.
        verifiePortage('la confirmation se fait EN PAGE, pas par une boite native',
            nouvelles.length === 0,
            `${nouvelles.length} boite(s) native(s) — un \`confirm()\` tient en une ligne, `
            + 's\'accepte au reflexe, et ne peut pas montrer ce que l\'action engage');

        // Sur le portage, le geste ne part qu'apres le second clic.
        if (panneau && panneau.ouvert && C.confirmer) {
            await cliqueEtAttend(page, C.confirmer, 3000);
        }

        verifie('le ban est parti vers la machine d\'essai',
            abouties.some((a) => /\/ban(\?|$)/.test(a.route) && a.machine === MACHINE_ID),
            abouties.map((a) => `${a.route}→${a.machine}`).join(' '));
        verifie('aucun ban n\'a vise la production',
            ! abouties.some((a) => /\/ban(\?|$)/.test(a.route) && a.machine === MACHINE_PRODUCTION),
            'un ban a vise `srv-zabbix`');

        const vu = await page.evaluate((sels, adr) => {
            const j = document.querySelector(sels.journal);
            const liste = document.querySelector(sels.listeBannies);

            return {
                journal: j ? (j.innerText || '').replace(/\s+/g, ' ').trim().slice(-260) : '',
                bannies: liste ? (liste.innerText || '') : '',
                presente: liste ? (liste.innerText || '').includes(adr) : false,
            };
        }, C, ADRESSE);
        constate('ce que le journal de la page dit', vu.journal.slice(-140) || '(vide)');
        constate('l\'adresse figure-t-elle dans la liste des bannies ?', vu.presente ? 'OUI' : 'non');

        /*
         * UN MOTIF QUI TROUVE LA NEGATION DE CE QU'IL CHERCHE.
         *
         * Une premiere redaction cherchait « <adresse> ... banni ». Une fois le
         * backend corrige, la page dit « 203.0.113.7 n'a PAS ete banni » — et le
         * motif y trouvait « banni ». Elle repondait donc « la page annonce un
         * ban reussi : OUI » sur un message d'ECHEC. Meme faute que « ban » dans
         * « fail2ban » : un motif plus large que la propriete.
         *
         * Une annonce de reussite, c'est le message SANS marque d'echec.
         */
        const phrases = vu.journal.split(/(?=Erreur|Error|\u2022|\|)/);
        const annonceSucces = phrases.some((ligne) =>
            ligne.includes(ADRESSE)
            && /banni|banned/i.test(ligne)
            && ! /erreur|error|n'a pas|n\u2019a pas|not been|echec|\u00e9chec|fail/i.test(ligne));
        constate('la page annonce-t-elle un ban reussi ?', annonceSucces ? 'OUI' : 'non');

        /*
         * ══ UNE REUSSITE ANNONCEE N'EST PAS UNE REUSSITE VERIFIEE ══════════
         *
         * `fail2ban_ban` recoit `rc` et ne le teste jamais. La machine d'essai
         * n'ayant pas fail2ban, la commande echoue — et la page annonce
         * pourtant « banni ». `banIp` recharge le detail juste apres : la liste
         * des IP bannies qu'il affiche ne contient donc PAS l'adresse. Deux
         * verites sur le meme ecran, a une ligne d'intervalle.
         */
        verifiePortage('une reussite annoncee est confirmee par ce que la page affiche ensuite',
            ! annonceSucces || vu.presente,
            `la page annonce « ${ADRESSE} banni » et sa propre liste d'adresses bannies, `
            + 'rechargee juste apres, ne le contient pas — `rc` est recu et jamais teste');

        // ── LA TABLE D'AUDIT ──────────────────────────────────────────────
        const posees = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.fail2ban_history WHERE id > ${BORNE}`);
        const detail = litEnBase("SELECT CONCAT_WS('|', action, ip_address, performed_by) "
            + `FROM rootwarden.fail2ban_history WHERE id > ${BORNE} ORDER BY id`);
        constate('lignes d\'audit creees par le geste', `${posees}`);
        constate('detail', detail.join(' · ') || '(aucune)');
        verifiePortage('la table d\'audit n\'enregistre que des faits qui ont eu lieu',
            posees === 0 || vu.presente,
            `${posees} ligne(s) affirment qu'un ban a eu lieu sur une machine qui n'a pas `
            + 'fail2ban : `_log_ban_action` est appele avant tout controle de `rc`');
    });

    // ═══ 3bis. LES PARAMETRES DE TRADUCTION ═════════════════════════════
    // ═══ 3b. E-174 — UNE ADRESSE A IDENTIFIANT DE PORTEE EST-ELLE REFUSEE ? ══
    await etape('une adresse a identifiant de portee est refusee', async () => {
        const avant = reponses.length;
        await page.click(C.champIp, { clickCount: 3 });
        await page.type(C.champIp, ADRESSE_PORTEE, { delay: 10 });

        accepteLaBoite = true;
        await cliqueEtAttend(page, C.bannir, 2500);
        accepteLaBoite = false;
        // Sur le portage le geste ne part qu'apres le second clic.
        const ouvert = C.confirmation ? await page.evaluate((sels) => {
            const p = document.querySelector(sels.confirmation);

            return p ? (p.offsetParent !== null && ! p.hidden) : false;
        }, C) : false;
        if (ouvert && C.confirmer) await cliqueEtAttend(page, C.confirmer, 3000);

        const neuves = reponses.slice(avant).filter((x) => /\/ban(\?|$)/.test(x.route));
        const derniere = neuves[neuves.length - 1];
        constate('reponses au ban a portee', neuves.length
            ? neuves.map((x) => `HTTP ${x.statut} « ${x.message.slice(0, 70)} »`).join(' | ')
            : '(aucune)');

        /*
         * SI LA REQUETE N'EST PAS PARTIE, LA PROPRIETE N'EST PAS SATISFAITE :
         * elle est NON MESUREE. Une garde du navigateur deplace le refus, elle
         * ne le supprime pas — et c'est le SERVEUR qu'on veut eprouver ici. On
         * le dit par un FAIL explicite plutot que par un silence, et la requete
         * FORGEE depuis la page (l'une des deux exceptions du §3.7, motif ecrit)
         * etablit alors le verdict serveur.
         */
        if (! derniere) {
            constate('aucune requete de ban emise', 'le champ ou la page a retenu la saisie');
            const forge = await page.evaluate(async (chemin, ip, jail, mid) => {
                try {
                    const rep = await fetch(chemin, {
                        method: 'POST', credentials: 'same-origin',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ ip, jail, machine_id: mid, server_id: mid }),
                    });

                    return { statut: rep.status, corps: (await rep.text()).slice(0, 160) };
                } catch (e) { return { statut: 0, corps: String(e.message || e) }; }
            }, CIBLE === 'laravel' ? '/api/gateway/fail2ban/ban' : '/api_proxy.php/fail2ban/ban',
               ADRESSE_PORTEE, JAIL, MACHINE_ID);
            constate('requete FORGEE depuis la page', `HTTP ${forge.statut} — ${forge.corps}`);
            verifie('le backend REFUSE une adresse a identifiant de portee (E-174)',
                forge.statut === 400,
                `HTTP ${forge.statut} — attendu 400. Un 200 signifie que la portee est passee `
                + 'jusqu\'a la composition de la commande distante',
                `HTTP ${forge.statut}`);

            return;
        }

        verifie('le backend REFUSE une adresse a identifiant de portee (E-174)',
            derniere.statut === 400,
            `HTTP ${derniere.statut} — attendu 400. Un 200 signifie que la portee est passee `
            + 'jusqu\'a la composition de la commande distante',
            `HTTP ${derniere.statut}`);
    });

    await etape('aucun parametre de traduction a l\'ecran', async () => {
        // Meme controle qu'en F3, sur un autre ecran : le panneau de detail
        // affiche « Jail :name » — troisieme occurrence du motif.
        const vu = await page.evaluate(() => {
            const t = document.body.innerText || '';

            return { trouves: [...new Set((t.match(/(?:^|\s):[a-z][a-z0-9_]{2,}\b/g) || [])
                .map((x) => x.trim()))] };
        });
        constate('parametres non substitues trouves', vu.trouves.join(' ') || '(aucun)');
        verifiePortage('aucun parametre de traduction n\'apparait a l\'ecran',
            vu.trouves.length === 0,
            `${vu.trouves.join(' ')} — meme famille qu'E-163, sur le panneau de detail d'une jail`);
    });

    // ═══ 4. SURETE ══════════════════════════════════════════════════════
    await etape('surete', async () => {
        constate('gestes aboutis', abouties.map((a) => `${a.route}→${a.machine}`).join(' ') || '(aucun)');
        constate('requetes avortees', avortees.length
            ? avortees.map((a) => `${a.route}→${a.machine} (${a.motif})`).join(' ') : '(aucune)');
        verifie('aucune requete n\'a joint la production',
            ! abouties.some((a) => Number(a.machine) === MACHINE_PRODUCTION),
            abouties.filter((a) => Number(a.machine) === MACHINE_PRODUCTION).map((a) => a.route).join(' '));
        verifie('le ban sur TOUT LE PARC n\'a jamais ete emis',
            ! abouties.some((a) => /ban_all_servers/.test(a.route)),
            'une requete de ban global a abouti');
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
            await page.screenshot({ path: `${dossier}/f4-${f.n}.png`, fullPage: true });
        }
        verifie('les trois captures sont ecrites', true, '', `${dossier}/f4-*.png`);
    });
} catch (e) {
    // `__archivee__` n'est pas une panne : c'est la sortie NORMALE quand le
    // sujet legacy a ete archive. Le constat a deja tout dit.
    if (String(e && e.message || e).includes('__archivee__')) { /* rien a ajouter */ } else {
    verifie('deroulement sans exception', false, String(e.message || e).split('\n')[0]);
    }
} finally {
    try {
        for (const ctx of contextes) { try { await ctx.close(); } catch {} }
        await navigateur.close();
    } catch { /* deja ferme */ }
    try {
        litEnBase(`DELETE FROM rootwarden.fail2ban_history WHERE id > ${BORNE}`);
        const reste = compteEnBase(`SELECT COUNT(*) FROM rootwarden.fail2ban_history WHERE id > ${BORNE}`);
        verifie('les lignes d\'audit creees par la suite sont retirees', reste === 0,
            `${reste} ligne(s) restante(s)`);
    } catch (e) {
        verifie('retrait des lignes d\'audit', false, String(e.message || e).split('\n')[0]);
    }
    try {
        const apres = cacheEnBase();
        verifie('le cache `fail2ban_status` est intact', apres === CACHE_ORIGINE,
            `avant=${CACHE_ORIGINE} apres=${apres}`);
    } catch (e) {
        verifie('relecture du cache', false, String(e.message || e).split('\n')[0]);
    }
}

note(`${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
process.exit(echecs === 0 ? 0 : 1);
