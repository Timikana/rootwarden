/**
 * go-fail2ban-f3.mjs - Sous-lot F3 de `fail2ban/` : configuration, journaux et
 * services detectes.
 *
 * `POST /fail2ban/config` (fail2ban.py:276), `/fail2ban/logs` (:530) et
 * `/fail2ban/services` (:330). Frontend : `loadConfig` (main.js:265),
 * `loadF2bLogs` (:524), `loadServices` (:318).
 *
 * ══ LES TROIS SONT DES LECTURES ══════════════════════════════════════════
 *
 * Elles sont en POST — parce qu'elles portent des identifiants SSH dans leur
 * corps — mais leurs commandes distantes ne modifient rien :
 *
 *     cat /etc/fail2ban/jail.local 2>/dev/null || echo "[FICHIER ABSENT]"
 *     tail -n <n> /var/log/fail2ban.log 2>/dev/null || echo "[LOG ABSENT]"
 *     fail2ban-client status 2>/dev/null   puis un `check_cmd` par service
 *
 * Aucune valeur venant du client n'est interpolee : `check_cmd` vient d'une
 * table du serveur, et `lines` est borne par
 * `max(10, min(500, int(lines)))` (`fail2ban_manager.py:253`).
 *
 * ══ LE STATUT EST SERVI — SANS LUI, AUCUN BOUTON N'EXISTE ════════════════
 *
 * `loadStatus` ne devoile `btn-config` et `btn-logs` que si la machine a
 * fail2ban INSTALLE, et n'appelle `loadServices` que dans ce cas. Le banc etant
 * un conteneur SANS fail2ban, **aucun des trois gestes de F3 n'est atteignable
 * par un clic** : la page cache ses boutons, et une suite qui s'arreterait la
 * mesurerait une page morte.
 *
 * Le filet REPOND donc au seul `/fail2ban/status`, avec `installed: true`, et
 * **laisse partir les trois lectures pour de vrai** — elles joignent la machine
 * 2 en SSH et rapportent ce qu'elle a vraiment : rien. C'est precisement ce
 * qu'on veut mesurer : ce que la page fait d'un « [FICHIER ABSENT] ».
 *
 * Consequence voulue : `_update_status_cache` ne tourne pas, le cache
 * `fail2ban_status` n'est pas ecrit. Une assertion le prouve, avant et apres.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * Toutes les routes de F4, F5 et F6 sont avortees. `srv-zabbix` (id 1) n'est
 * JAMAIS jointe — et l'etape qui mesure le desaccord de machine le fait dans le
 * sens SUR : releve sur la machine 2, selecteur bascule sur la production, donc
 * la requete part vers **2**. Le sens inverse joindrait la production, et il
 * n'est pas exerce.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-fail2ban-f3
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';

const MACHINE_ID = 2;
const MACHINE_PRODUCTION = 1;

/** Les trois lectures de F3 — elles partent pour de vrai, vers la machine 2. */
const LECTURES = /\/fail2ban\/(config|logs|services)(\?|$)/;
/** Servi, jamais transmis : sans lui, aucun bouton de F3 n'existe. */
const STATUT = /\/fail2ban\/status(\?|$)/;
/** Lu en base, sans effet distant : laisse passer. */
const BASE_SEULE = /\/fail2ban\/(history|stats)(\?|$)/;
/**
 * Le motif vise le SEGMENT qui suit `/fail2ban/`, jamais une sous-chaine :
 * « ban » se trouve DANS « fail2ban », et un motif large accusait
 * `/fail2ban/history` d'etre un geste de F4 (faute payee en F2).
 */
const ROUTES_MODULE = /\/fail2ban\/(status|jail|services|history|stats|config|logs|ban|unban|ban_all_servers|unban_all|install|install_all|restart|enable_jail|disable_jail|whitelist|geoip)(\?|$)/;

const DOSSIER_CAPTURES = new URL('./screenshots/fail2ban', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion', page: '/fail2ban',
        serveur: '[data-rw="f2b-serveur"]', relever: '[data-rw="f2b-relever"]',
        boutonConfig: '[data-rw="f2b-voir-config"]', boutonLogs: '[data-rw="f2b-voir-logs"]',
        config: '[data-rw="f2b-config-contenu"]', logs: '[data-rw="f2b-logs-contenu"]',
        blocConfig: '[data-rw="f2b-config"]', blocLogs: '[data-rw="f2b-logs"]',
        services: '[data-rw="f2b-services"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr', page: '/fail2ban/',
        serveur: '#server', relever: 'button[onclick="loadStatus()"]',
        boutonConfig: '#btn-config', boutonLogs: '#btn-logs',
        config: '#jail-config-content', logs: '#f2b-logs-content',
        blocConfig: '#config-viewer', blocLogs: '#f2b-logs-viewer',
        services: '#services-grid',
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
function verifiePortage(l, ok, d) {
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
const avortees = [];
const servies = [];

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(60000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => { try { await d.dismiss(); } catch {} });

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
                    jails: [{ name: 'sshd', currently_banned: 0, total_banned: 0 }],
                }) }).catch(() => {});

            return;
        }
        // FAIL-CLOSED SUR LA MACHINE : une lecture qui viserait la PRODUCTION
        // est avortee, meme si elle est inoffensive. On ne joint pas `srv-zabbix`.
        if ((LECTURES.test(url) || BASE_SEULE.test(url)) && cible === MACHINE_ID) {
            abouties.push({ route: chemin, machine: cible });
            r.continue().catch(() => {});

            return;
        }
        avortees.push({
            route: chemin,
            machine: cible === null ? '(indetermine)' : String(cible),
            motif: LECTURES.test(url) || BASE_SEULE.test(url)
                ? 'machine hors perimetre' : 'appartient a F4, F5 ou F6',
        });
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

/** Le legacy met un OBJET JSON dans `option.value` ; le portage l'identifiant. */
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

/** Cliquer, puis attendre qu'une requete de F3 soit partie (ou renoncer). */
async function cliqueEtAttend(page, selecteur, motif) {
    const avant = abouties.length + avortees.length;
    await page.click(selecteur);
    for (let i = 0; i < 80; i += 1) {
        if (abouties.length + avortees.length > avant) break;
        await dors(200);
    }
    await dors(motif ? 2500 : 1200);

    return (abouties.length + avortees.length) - avant;
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

const CACHE_ORIGINE = cacheEnBase();
let session = null;

try {
    constate('cache `fail2ban_status` a l\'entree', CACHE_ORIGINE);
    session = await connecte(COMPTE, SECRET);
    verifie('la session a tenu', ! session.surConnexion, session.page.url());
    if (session.surConnexion) throw new Error('session non etablie');
    const page = session.page;

    await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
    await dors(400);

    // ═══ 1. LES BOUTONS DE F3 N'EXISTENT QU'APRES UN RELEVE ══════════════
    await etape('les gestes de F3 apparaissent apres le releve', async () => {
        const visible = async (sel) => page.evaluate((s) => {
            const e = document.querySelector(s);

            return e ? (e.offsetParent !== null && ! e.hidden) : false;
        }, sel);

        const avantConfig = await visible(C.boutonConfig);
        const avantLogs = await visible(C.boutonLogs);
        constate('avant le releve — config / logs', `${avantConfig} / ${avantLogs}`);

        await choisitMachine(page, MACHINE_ID);
        await cliqueEtAttend(page, C.relever, false);

        const apresConfig = await visible(C.boutonConfig);
        const apresLogs = await visible(C.boutonLogs);
        constate('apres le releve — config / logs', `${apresConfig} / ${apresLogs}`);
        verifie('les deux gestes de lecture sont atteignables apres un releve',
            apresConfig && apresLogs, `config=${apresConfig} logs=${apresLogs}`);
        constate('statuts SERVIS', `${servies.length}`);
    });

    // ═══ 2. LA CONFIGURATION, LUE POUR DE VRAI ═══════════════════════════
    await etape('lire la configuration', async () => {
        const n = await cliqueEtAttend(page, C.boutonConfig, true);
        constate('requetes emises par le clic', `${n}`);
        const vu = await page.evaluate((sels) => {
            const bloc = document.querySelector(sels.blocConfig);
            const contenu = document.querySelector(sels.config);

            return {
                visible: bloc ? (bloc.offsetParent !== null && ! bloc.hidden) : false,
                texte: contenu ? (contenu.textContent || '').trim() : '',
                texteSection: bloc ? (bloc.innerText || '').trim() : '',
            };
        }, C);
        verifie('la lecture de configuration est partie vers la machine d\'essai',
            abouties.some((a) => /config/.test(a.route) && a.machine === MACHINE_ID),
            abouties.map((a) => a.route).join(' '));
        constate('bloc de configuration visible', `${vu.visible}`);
        constate('contenu rendu', (vu.texte || '(vide)').slice(0, 90));

        /*
         * UN FICHIER ABSENT N'EST PAS UNE CONFIGURATION VIDE.
         *
         * La commande distante est `cat ... || echo "[FICHIER ABSENT]"`. Le
         * legacy pose ce retour dans le MEME `<pre>` vert sur noir qu'une vraie
         * configuration : « [FICHIER ABSENT] » s'y lit comme le contenu du
         * fichier. Rien ne distingue « voici la configuration » de « il n'y en a
         * pas ».
         */
        const marqueur = /\[FICHIER ABSENT\]|\[FILE MISSING\]/i.test(vu.texte);
        constate('la machine a-t-elle rendu le marqueur d\'absence ?', marqueur ? 'OUI' : 'non');
        if (marqueur) {
            const explique = /absent|introuvable|aucune configuration|not installed|no configuration|manquant/i
                .test(vu.texteSection.replace(vu.texte, ''));
            verifiePortage('un fichier ABSENT est annonce, pas affiche comme un contenu',
                explique,
                '« [FICHIER ABSENT] » est pose dans le meme bloc de code qu\'une vraie '
                + 'configuration : le marqueur du shell devient le contenu du fichier');
        } else {
            verifie('le marqueur d\'absence a pu etre mesure', false,
                `la machine a rendu autre chose : « ${vu.texte.slice(0, 60)} »`);
        }
    });

    // ═══ 3. LES JOURNAUX ════════════════════════════════════════════════
    await etape('lire les journaux', async () => {
        const n = await cliqueEtAttend(page, C.boutonLogs, true);
        constate('requetes emises par le clic', `${n}`);
        const vu = await page.evaluate((sels) => {
            const bloc = document.querySelector(sels.blocLogs);
            const contenu = document.querySelector(sels.logs);

            return {
                visible: bloc ? (bloc.offsetParent !== null && ! bloc.hidden) : false,
                texte: contenu ? (contenu.textContent || '').trim() : '',
                texteSection: bloc ? (bloc.innerText || '').trim() : '',
            };
        }, C);
        verifie('la lecture des journaux est partie vers la machine d\'essai',
            abouties.some((a) => /logs/.test(a.route) && a.machine === MACHINE_ID),
            abouties.map((a) => a.route).join(' '));
        constate('contenu rendu', (vu.texte || '(vide)').slice(0, 90));

        const marqueur = /\[LOG ABSENT\]|\[LOG MISSING\]/i.test(vu.texte);
        constate('la machine a-t-elle rendu le marqueur d\'absence ?', marqueur ? 'OUI' : 'non');
        if (marqueur) {
            const explique = /absent|introuvable|aucun journal|no log|manquant|jamais/i
                .test(vu.texteSection.replace(vu.texte, ''));
            verifiePortage('un journal ABSENT est annonce, pas affiche comme un contenu',
                explique,
                '« [LOG ABSENT] » est pose dans le meme bloc que de vraies lignes de '
                + 'journal : le marqueur du shell devient le journal');
        } else {
            verifie('le marqueur d\'absence a pu etre mesure', false,
                `la machine a rendu autre chose : « ${vu.texte.slice(0, 60)} »`);
        }
    });

    // ═══ 3bis. LES SERVICES DETECTES ════════════════════════════════════
    await etape('les services detectes', async () => {
        const vu = await page.evaluate((sels) => {
            const grille = document.querySelector(sels.services);
            const cartes = grille ? [...grille.children] : [];

            return {
                visible: grille ? (grille.offsetParent !== null) : false,
                nb: cartes.length,
                texte: grille ? (grille.innerText || '').replace(/\s+/g, ' ').trim() : '',
                // Un service NON installe est rendu a `opacity-50` : on mesure
                // l'opacite CALCULEE, pas la classe — une classe purgee laisse
                // les deux etats identiques a l'ecran (piege paye en F2).
                opacites: cartes.map((c) => getComputedStyle(c).opacity),
            };
        }, C);
        verifie('la detection des services est partie vers la machine d\'essai',
            abouties.some((a) => /services/.test(a.route) && a.machine === MACHINE_ID),
            abouties.map((a) => a.route).join(' '));
        constate('grille des services visible', `${vu.visible}`);
        constate('services rendus', `${vu.nb}`);
        constate('opacites calculees', [...new Set(vu.opacites)].join(' \u00b7 ') || '(aucune)');
        constate('contenu', vu.texte.slice(0, 110) || '(vide)');
        verifie('la grille des services est rendue', vu.visible && vu.nb > 0,
            `visible=${vu.visible} cartes=${vu.nb}`);
        // Le banc n'a pas fail2ban : les services doivent se distinguer les uns
        // des autres, sans quoi « installe » et « absent » se ressemblent.
        verifiePortage('un service absent se distingue VISUELLEMENT d\'un service installe',
            new Set(vu.opacites).size > 1 || /absent|non install|missing|not install/i.test(vu.texte),
            'toutes les cartes ont la meme opacite calculee et aucun mot ne dit '
            + 'lesquelles correspondent a un service absent');
    });

    // ═══ 4. LE DESACCORD DE MACHINE ═════════════════════════════════════
    await etape('quelle machine le bouton vise-t-il ?', async () => {
        /*
         * ══ DEUX NOTIONS DE « LA MACHINE » DANS LA MEME PAGE ══════════════
         *
         * `loadConfig` (main.js:266) lit `getServer()` — la machine du
         * SELECTEUR. **Tous les autres gestes du module** — logs, services,
         * detail d'une jail, bannir, debannir, activer et desactiver une jail,
         * liste blanche, tout debannir — lisent `_currentServer`, pose au
         * dernier releve REUSSI (`:60`). Douze appels contre un.
         *
         * Consequence : relever sur A, changer le selecteur pour B, et tout agit
         * sur **A** pendant que l'ecran montre **B**.
         *
         * LE SENS DE LA MESURE EST CHOISI POUR NE RIEN RISQUER : on releve sur
         * la machine d'essai, puis on bascule le selecteur sur la PRODUCTION.
         * Si le defaut existe, la requete part vers la machine d'ESSAI — la
         * bonne direction. Le sens inverse joindrait `srv-zabbix`, et il n'est
         * pas exerce.
         */
        await choisitMachine(page, MACHINE_PRODUCTION);
        const choisie = await page.evaluate((sel) => {
            const s = document.querySelector(sel);
            const o = s ? s.options[s.selectedIndex] : null;

            return o ? (o.textContent || '').trim() : '';
        }, C.serveur);
        constate('machine affichee par le selecteur', choisie);

        /*
         * DEUX TABLEAUX, DEUX BORNES.
         *
         * Une premiere redaction faisait `[...abouties, ...avortees].slice(n)`
         * avec `n = abouties.length + avortees.length`. Decouper la CONCATENATION
         * par un compte qui couvre les deux tableaux ne rend pas les entrees
         * neuves : une ligne ajoutee au premier se retrouve **au milieu** de la
         * concatenation, jamais apres la borne. La mesure rendait donc une liste
         * vide, `viseeReelle` valait `null`, et l'assertion passait **faute
         * d'objet** — sixieme faux PASS de la meme famille sur ce module.
         */
        const avantA = abouties.length;
        const avantB = avortees.length;
        await cliqueEtAttend(page, C.boutonLogs, true);
        const emises = [...abouties.slice(avantA), ...avortees.slice(avantB)];
        const versLogs = emises.filter((e) => /logs/.test(e.route));
        constate('requetes emises', emises.map((e) => `${e.route}→${e.machine}`).join(' ') || '(aucune)');

        verifie('le clic n\'a joint AUCUNE machine de production',
            ! versLogs.some((e) => Number(e.machine) === MACHINE_PRODUCTION),
            versLogs.map((e) => e.machine).join(' '));

        const viseeReelle = versLogs.length ? Number(versLogs[0].machine) : null;
        constate('machine reellement visee', viseeReelle === null ? '(aucune requete)' : String(viseeReelle));
        /* L'INSTRUMENT D'ABORD : sans requete, la propriete n'a pas d'objet et
         * ne peut pas etre « satisfaite ». On le dit par un FAIL, pas par un
         * silence. */
        verifie('le clic a bien emis une lecture de journaux', viseeReelle !== null,
            emises.map((e) => e.route).join(' ') || '(aucune requete)');
        verifiePortage('le bouton vise la machine que le selecteur AFFICHE',
            viseeReelle === MACHINE_PRODUCTION,
            `le selecteur affiche « ${choisie} » et la requete part vers la machine `
            + `${viseeReelle} — \`_currentServer\` l'emporte sur \`getServer()\`, et douze `
            + 'gestes du module sur treize lisent `_currentServer`');
    });

    // ═══ 4bis. LES PARAMETRES DE TRADUCTION SONT-ILS SUBSTITUES ? ═══════
    await etape('aucun parametre de traduction a l\'ecran', async () => {
        /*
         * VU A L'IMAGE, PAS PAR UNE ASSERTION — et c'est pour cela qu'on
         * l'assertionne maintenant.
         *
         * Le journal de la page affiche « :count jail(s) trouves » et
         * « :count service(s) detecte(s) ». Les catalogues ecrivent `:count`
         * (`legacy/lang/{fr,en}/js.php`), le script passe `{jails, ips}` et
         * `{installed, enabled}` (`main.js:117` et `:372`) : **le nom ne
         * correspond a aucun parametre**, la substitution n'a jamais lieu, et
         * quatre valeurs sont calculees pour etre jetees.
         *
         * On cherche un `:mot` isole — jamais dans une URL (`https://`), jamais
         * dans une heure (`12:30`), jamais dans un `key: value`. Le motif exige
         * donc un deux-points precede d'un espace ou d'un debut, et suivi d'une
         * lettre minuscule.
         */
        const vu = await page.evaluate(() => {
            const texte = document.body.innerText || '';
            const trouves = texte.match(/(?:^|\s):[a-z][a-z0-9_]{2,}\b/g) || [];

            return { trouves: [...new Set(trouves.map((t) => t.trim()))] };
        });
        constate('parametres non substitues trouves', vu.trouves.join(' ') || '(aucun)');
        verifiePortage('aucun parametre de traduction n\'apparait a l\'ecran',
            vu.trouves.length === 0,
            `${vu.trouves.join(' ')} — les catalogues ecrivent \`:count\`, le script passe `
            + '`{jails, ips}` et `{installed, enabled}` : la substitution n\'a jamais lieu, '
            + 'dans les deux langues');
    });

    // ═══ 4ter. UN `lines` NON NUMERIQUE ═════════════════════════════════
    await etape('un nombre de lignes non numerique', async () => {
        /*
         * ══ REQUETE FORGEE, ET VOICI POURQUOI ═════════════════════════════
         *
         * `loadF2bLogs` envoie `lines: 100`, en dur. **Aucune interface de cette
         * page ne peut produire un `lines` non numerique** : il n'y a pas de
         * champ. La propriete ne peut donc s'atteindre par aucun clic.
         *
         * Elle est emise DEPUIS LA PAGE, par `fetch`, donc avec la session et
         * les en-tetes reels — jamais depuis Node.
         *
         * ET ELLE NE JOINT AUCUNE MACHINE : la route fait
         * `lines = int(data.get('lines', 50))` **avant** `_resolve_ssh_creds`
         * (`fail2ban.py:537`). Le cast echoue donc avant qu'une session SSH soit
         * seulement envisagee. Ce qui est mesure, c'est ce que le backend REND :
         * un refus explicite, ou une erreur interne ?
         */
        const vu = await page.evaluate(async (chemin) => {
            try {
                const r = await fetch(chemin, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ machine_id: 2, lines: 'beaucoup' }),
                });
                const t = await r.text();

                return { statut: r.status, corps: t.slice(0, 120) };
            } catch (e) {
                return { statut: -1, corps: String(e).slice(0, 120) };
            }
        }, CIBLE === 'laravel' ? '/api/gateway/fail2ban/logs' : '/api_proxy.php/fail2ban/logs');
        constate('statut rendu pour `lines: "beaucoup"`', `${vu.statut}`);
        constate('corps rendu', vu.corps.replace(/\s+/g, ' ').slice(0, 100));
        /*
         * La PROPRIETE : une valeur invalide se REFUSE, elle ne casse pas. Un
         * 400 dit « votre requete est mauvaise » ; un 500 dit « le serveur a un
         * defaut » — et c'est le second qui est vrai ici, alors que la faute est
         * dans la requete. Le manager borne pourtant deja la valeur
         * (`max(10, min(500, int(lines)))`, `fail2ban_manager.py:253`) : c'est le
         * cast de la ROUTE, place hors de son `try`, qui leve.
         */
        verifiePortage('une valeur invalide est REFUSEE, elle ne provoque pas d\'erreur interne',
            vu.statut === 400 || vu.statut === 422,
            `le backend rend ${vu.statut} — \`int(data.get('lines', 50))\` est hors du \`try\` `
            + 'de la route : une valeur non numerique y leve une `ValueError`, et la faute de '
            + 'la requete est rendue comme un defaut du serveur');
    });

    // ═══ 5. SURETE ══════════════════════════════════════════════════════
    await etape('surete', async () => {
        constate('lectures abouties', abouties.map((a) => `${a.route}→${a.machine}`).join(' ') || '(aucune)');
        constate('requetes avortees', avortees.length
            ? avortees.map((a) => `${a.route}→${a.machine} (${a.motif})`).join(' ') : '(aucune)');
        const GESTES = /\/fail2ban\/(ban|unban|ban_all_servers|unban_all|install|install_all|restart|enable_jail|disable_jail|whitelist)(\?|$)/;
        verifie('aucun geste de F4, F5 ou F6 n\'a abouti',
            ! abouties.some((a) => GESTES.test(a.route)),
            abouties.filter((a) => GESTES.test(a.route)).map((a) => a.route).join(' '));
        verifie('aucune requete n\'a joint la production',
            ! abouties.some((a) => Number(a.machine) === MACHINE_PRODUCTION),
            abouties.filter((a) => Number(a.machine) === MACHINE_PRODUCTION).map((a) => a.route).join(' '));
        verifie('aucune erreur JavaScript', session.erreursJs.length === 0,
            session.erreursJs.join(' | '));
    });

    // ═══ 6. CAPTURES ════════════════════════════════════════════════════
    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        await choisitMachine(page, MACHINE_ID);
        for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                         { n: 'mobile', w: 390, h: 844 }]) {
            await page.setViewport({ width: f.w, height: f.h });
            await dors(350);
            await page.screenshot({ path: `${dossier}/f3-${f.n}.png`, fullPage: true });
        }
        verifie('les trois captures sont ecrites', true, '', `${dossier}/f3-*.png`);
    });
} catch (e) {
    verifie('deroulement sans exception', false, String(e.message || e).split('\n')[0]);
} finally {
    try {
        for (const ctx of contextes) { try { await ctx.close(); } catch {} }
        await navigateur.close();
    } catch { /* deja ferme */ }
    try {
        // Le statut etant SERVI, `_update_status_cache` n'a jamais tourne.
        const apres = cacheEnBase();
        verifie('le cache `fail2ban_status` est intact', apres === CACHE_ORIGINE,
            `avant=${CACHE_ORIGINE} apres=${apres}`);
    } catch (e) {
        verifie('relecture du cache', false, String(e.message || e).split('\n')[0]);
    }
}

note(`${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
process.exit(echecs === 0 ? 0 : 1);
