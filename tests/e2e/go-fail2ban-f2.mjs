/**
 * go-fail2ban-f2.mjs - Sous-lot F2 de `fail2ban/` : historique et frise.
 *
 * `GET /fail2ban/history` (fail2ban.py:296) et `GET /fail2ban/stats` (:554).
 * Frontend : `loadHistory` (main.js:284) et `loadStats` (:556).
 *
 * ══ F2 NE JOINT AUCUNE MACHINE ═════════════════════════════════════════════
 *
 * Les deux routes sont des LECTURES EN BASE pures : un `SELECT` sur
 * `fail2ban_history`, aucun SSH, aucune commande distante. C'est ce qui fait de
 * F2 un sous-lot sur — a la difference de F4, F5 et F6, qui bannissent,
 * redemarrent et reecrivent des fichiers de configuration.
 *
 * ══ POURQUOI LE STATUT EST *SERVI* ════════════════════════════════════════
 *
 * `loadStatus` (main.js:57) charge l'historique et la frise **a la fin de son
 * propre succes** :
 *
 *     const d = await apiPost('/fail2ban/status', ...);
 *     if (!d.success) { appendLog(...); return; }      // <-- ici
 *     ...
 *     loadHistory(srv.id);  loadStats(srv.id);
 *
 * Le releve de statut est donc une PRECONDITION dependant de la machine, alors
 * que ce qu'on mesure n'en depend pas. Le banc etant un conteneur sans systemd,
 * laisser partir ce releve rendrait F2 dependant d'une session SSH dont il n'a
 * aucun besoin — et le ferait echouer pour une raison etrangere a son objet.
 *
 * Le filet REPOND donc a `/fail2ban/status`, et **laisse passer `/history` et
 * `/stats`** : ce qui est mesure traverse le vrai chemin, jusqu'a la base.
 * Consequence voulue : `_update_status_cache` ne tourne pas, donc le cache
 * `fail2ban_status` n'est pas ecrit. Une assertion le prouve, avant et apres.
 *
 * Et cette servitude devient elle-meme une MESURE : une etape sert un ECHEC de
 * statut, pour montrer qu'une machine injoignable masque son propre historique.
 *
 * ══ LA DONNEE D'EPREUVE, ET POURQUOI ELLE S'ECRIT EN BASE ═════════════════
 *
 * `fail2ban_history` est **vide** sur le banc (mesure du 2026-08-27 : 0 ligne).
 * Sans donnee, les deux sections restent cachees et tout le chemin de rendu est
 * invisible — le banc vide de `services/` S2, qui avait cache deux defauts
 * vivants pendant un sous-lot entier.
 *
 * Les gestes qui PEUPLENT cette table (`/fail2ban/ban`) appartiennent a F4 et
 * bannissent une adresse sur une machine reelle. Ecrire les lignes directement
 * est donc le seul moyen de caracteriser la LECTURE sans commettre l'ECRITURE.
 * Seules les deux routes de F2 lisent cette table — verifie par recherche
 * exhaustive, contrairement a `iptables_history` que le rapport de conformite
 * lit deja. Nettoyage borne par un DELTA d'`id`, jamais par un `DELETE` large.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * `srv-zabbix` (id 1) n'est jamais choisie. Toutes les routes de F4, F5 et F6
 * sont avortees. Aucune ecriture ne part vers une machine.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-fail2ban-f2
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
/** L'identifiant de `rw-test-super` en base : ce que le backend ecrirait. */
const UTILISATEUR_ID = 16;

const MACHINE_ID = 2;
const MACHINE_PRODUCTION = 1;

/** Ce que F2 laisse aboutir : les deux LECTURES EN BASE, et rien d'autre. */
const LECTURES = /\/fail2ban\/(history|stats)(\?|$)/;
/** Servi, jamais transmis — voir l'en-tete. */
const STATUT = /\/fail2ban\/status(\?|$)/;
/**
 * Les routes de l'API du module — et **rien d'autre**. Le motif exige une fin
 * de chemin sans extension : `/\/fail2ban\/[a-z_]+/` attraperait
 * `/fail2ban/js/main.js`, le script de la page, et la suite passerait au vert
 * en mesurant une page morte (piege paye en F1).
 */
const ROUTES_MODULE = /\/fail2ban\/(status|jail|services|history|stats|ban|unban|ban_all_servers|unban_all|install|install_all|restart|enable_jail|disable_jail|whitelist|config|logs|geoip)(\?|$)/;

const DOSSIER_CAPTURES = new URL('./screenshots/fail2ban', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion', page: '/fail2ban',
        serveur: '[data-rw="f2b-serveur"]', relever: '[data-rw="f2b-relever"]',
        sectionHisto: '[data-rw="f2b-historique"]', corpsHisto: '[data-rw="f2b-historique-corps"]',
        sectionFrise: '[data-rw="f2b-frise"]', frise: '[data-rw="f2b-frise-barres"]',
        barre: '[data-rw^="f2b-barre-"]',
        // LE CORPS DE LA BARRE, pas son conteneur : celui du portage englobe
        // l'etiquette du nombre, ce qui ajoutait 14 px a chaque mesure.
        corpsBarre: '.rw-frise__corps',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
        valeurOption: (o) => o.value,
    }
    : {
        connexion: '/auth/login.php?lang=fr', page: '/fail2ban/',
        serveur: '#server', relever: 'button[onclick="loadStatus()"]',
        sectionHisto: '#history-section', corpsHisto: '#history-table',
        sectionFrise: '#stats-section', frise: '#stats-chart',
        barre: '#stats-chart > div',
        corpsBarre: null,
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
        // Le legacy met un OBJET JSON dans la valeur de chaque `<option>` :
        // `getServer()` fait `JSON.parse(sel.value)`. Un `page.select(sel, '2')`
        // ne trouverait aucune option.
        valeurOption: (o) => o.value,
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

/** Le cache de statut, en une chaine comparable — F2 ne doit PAS le toucher. */
function cacheEnBase() {
    const r = litEnBase("SELECT CONCAT_WS('|', installed, running, total_banned, "
        + "IFNULL(jails_json,''), last_checked) FROM rootwarden.fail2ban_status "
        + `WHERE server_id = ${MACHINE_ID}`);

    return r[0] || '(absent)';
}
function borneHistorique() {
    return compteEnBase('SELECT IFNULL(MAX(id),0) FROM rootwarden.fail2ban_history');
}

/*
 * ══ LA DONNEE D'EPREUVE ═══════════════════════════════════════════════════
 *
 * Trois jours, et chacun est choisi pour ce qu'il REVELE :
 *
 *   J-3 :  0 ban, 6 unban   — un jour sans aucun ban, mais qui n'est PAS vide.
 *                             Le legacy calcule la hauteur sur `counts.ban`
 *                             seul : ce jour tombe au plancher de 4 % et se
 *                             peint en VERT, comme s'il ne s'y etait rien passe.
 *   J-2 : 40 ban, 0 unban   — le maximum, qui fixe l'echelle.
 *   J-1 :  5 ban, 9 unban   — 14 evenements rendus a 5/40 = 12,5 % de hauteur,
 *                             alors que l'echelle, elle, est calculee sur
 *                             `ban + unban`. La hauteur et l'echelle ne mesurent
 *                             donc PAS la meme grandeur.
 *
 * 60 lignes au total, pour 50 que la route rend (`LIMIT 50`) : c'est ce qui
 * permet de mesurer si l'ecran DIT qu'il tronque.
 */
const JOURS = [
    { decalage: 3, bans: 0,  unbans: 6 },
    { decalage: 2, bans: 40, unbans: 0 },
    { decalage: 1, bans: 5,  unbans: 9 },
];
const TOTAL_POSE = JOURS.reduce((a, j) => a + j.bans + j.unbans, 0);
const LIMITE_ROUTE = 50;

function poseHistorique() {
    const valeurs = [];
    let n = 0;
    for (const j of JOURS) {
        for (let i = 0; i < j.bans + j.unbans; i += 1) {
            const action = i < j.bans ? 'ban' : 'unban';
            // Une ligne sur dix porte le repli LITTERAL `'admin'` du backend
            // (`_log_ban_action(..., user='admin')`) ; les autres portent
            // l'identifiant NUMERIQUE que `X-User-ID` y depose reellement.
            const par = (n % 10 === 0) ? "'admin'" : `'${UTILISATEUR_ID}'`;
            const ip = `203.0.113.${(n % 200) + 1}`;
            valeurs.push(`(${MACHINE_ID}, 'sshd', '${ip}', '${action}', ${par}, `
                + `DATE_SUB(NOW(), INTERVAL ${j.decalage} DAY))`);
            n += 1;
        }
    }
    litEnBase('INSERT INTO rootwarden.fail2ban_history '
        + '(server_id, jail, ip_address, action, performed_by, created_at) VALUES '
        + valeurs.join(', '));
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

/** Ce que le filet sert au prochain releve. `null` = un ECHEC de statut. */
let statutServi = { success: true, installed: false, running: false, jails: [] };

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
        // LE GARDE VISE LES NOMS DE ROUTES : `/fail2ban/` est aussi le chemin de
        // LA PAGE, et l'avorter tuerait la suite.
        if (! ROUTES_MODULE.test(url)) { r.continue().catch(() => {}); return; }

        if (STATUT.test(url)) {
            servies.push(chemin);
            const charge = statutServi === null
                ? { success: false, message: 'machine injoignable' }
                : statutServi;
            r.respond({ status: 200, contentType: 'application/json',
                body: JSON.stringify(charge) }).catch(() => {});

            return;
        }
        if (LECTURES.test(url)) {
            abouties.push(chemin);
            r.continue().catch(() => {});

            return;
        }
        avortees.push({ route: chemin, motif: 'appartient a F4, F5 ou F6' });
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

/**
 * CHOISIR LA MACHINE PAR CLIC, malgre deux formes de valeur d'option.
 *
 * Le legacy met un OBJET JSON dans `option.value` (`getServer()` fait
 * `JSON.parse`) ; le portage y met l'identifiant. On cherche donc l'option dont
 * la valeur DESIGNE la machine 2, quelle que soit sa forme, et on la choisit par
 * `page.select` — qui emet un vrai evenement `change` sur l'element reel.
 */
async function choisitMachine(page) {
    const valeur = await page.evaluate((sel, id) => {
        const s = document.querySelector(sel);
        if (! s) return null;
        for (const o of s.options) {
            if (! o.value) continue;
            if (o.value === String(id)) return o.value;
            try { if (JSON.parse(o.value)?.id === id) return o.value; } catch { /* pas du JSON */ }
        }

        return null;
    }, C.serveur, MACHINE_ID);
    if (valeur === null) throw new Error(`aucune option ne designe la machine ${MACHINE_ID}`);
    await page.select(C.serveur, valeur);

    return valeur;
}

/** Cliquer le releve, puis attendre que la lecture de l'historique soit partie. */
async function releve(page) {
    const avant = abouties.length;
    await page.click(C.relever);
    for (let i = 0; i < 60; i += 1) {
        if (abouties.length > avant) break;
        await dors(200);
    }
    await dors(700);
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
let titreFr = '';

try {
    constate('cache `fail2ban_status` a l\'entree', CACHE_ORIGINE);
    constate('borne de `fail2ban_history` a l\'entree', `id > ${BORNE}`);
    verifie('la table d\'historique est bien celle qu\'on croit',
        compteEnBase(`SELECT COUNT(*) FROM rootwarden.fail2ban_history WHERE id > ${BORNE}`) === 0,
        'des lignes trainent au-dessus de la borne');

    session = await connecte(COMPTE, SECRET);
    verifie('la session a tenu', ! session.surConnexion, session.page.url());
    if (session.surConnexion) throw new Error('session non etablie');
    const page = session.page;

    await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
    await dors(400);

    // ═══ 1. L'HISTORIQUE VIDE ════════════════════════════════════════════
    await etape('un historique vide', async () => {
        await choisitMachine(page);
        await releve(page);
        const vu = await page.evaluate((sels) => {
            const vis = (s) => {
                const e = document.querySelector(s);
                if (! e) return null;

                return e.offsetParent !== null && getComputedStyle(e).display !== 'none';
            };

            return {
                histoVisible: vis(sels.sectionHisto),
                friseVisible: vis(sels.sectionFrise),
                texte: (document.body.innerText || '').toLowerCase(),
            };
        }, C);
        constate('section historique visible', `${vu.histoVisible}`);
        constate('section frise visible', `${vu.friseVisible}`);
        verifie('la lecture de l\'historique est bien partie',
            abouties.some((c) => /history/.test(c)), abouties.join(' '));
        // La PROPRIETE : l'ecran DIT qu'il n'y a rien, plutot que de se taire.
        const annonce = /aucun|jamais|no ban|nothing|vide|empty/.test(vu.texte);
        verifiePortage('un historique vide est ANNONCE, pas simplement cache',
            vu.histoVisible === true && annonce,
            'les deux sections restent `hidden` et rien ne nomme l\'absence : '
            + '« aucun ban enregistre » et « la lecture a echoue » se ressemblent a l\'ecran');
    });

    // ═══ 2. LA DONNEE D'EPREUVE, PUIS UN NOUVEAU RELEVE ══════════════════
    await etape('l\'historique peuple', async () => {
        poseHistorique();
        const pose = compteEnBase(`SELECT COUNT(*) FROM rootwarden.fail2ban_history WHERE id > ${BORNE}`);
        verifie('la donnee d\'epreuve est posee', pose === TOTAL_POSE, `${pose} / ${TOTAL_POSE}`);

        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await dors(300);
        await choisitMachine(page);
        await releve(page);

        const vu = await page.evaluate((sels) => {
            const corps = document.querySelector(sels.corpsHisto);
            const rangs = corps ? [...corps.querySelectorAll('tr')] : [];
            const section = document.querySelector(sels.sectionHisto);

            return {
                visible: section ? (section.offsetParent !== null) : false,
                rangs: rangs.length,
                premiere: rangs[0] ? [...rangs[0].querySelectorAll('td')].map((c) => c.textContent.trim()) : [],
                auteurs: [...new Set(rangs.map((r) => {
                    const c = r.querySelectorAll('td');

                    return c.length ? c[c.length - 1].textContent.trim() : '';
                }))],
                texteSection: section ? (section.innerText || '') : '',
                titre: section ? (section.querySelector('h2')?.textContent || '').trim() : '',
            };
        }, C);
        verifie('la section d\'historique est visible', vu.visible);
        titreFr = vu.titre;
        constate('intitule de la section, en francais', titreFr || '(vide)');
        constate('lignes rendues', `${vu.rangs} pour ${TOTAL_POSE} en base`);
        constate('premiere ligne', vu.premiere.join(' | '));
        constate('valeurs distinctes de la colonne « Par »', vu.auteurs.join(' · '));

        // ── LA TRONCATURE ────────────────────────────────────────────────
        // La route rend 50 lignes au plus. 60 existent. L'ecran le dit-il ?
        /*
         * ON CHERCHE DES MOTS, DANS LA SECTION, PAS UN NOMBRE DANS LA PAGE.
         *
         * Une premiere redaction cherchait le nombre `60` n'importe ou dans le
         * texte de la page — et le trouvait dans l'adresse `203.0.113.60` de la
         * premiere ligne. Elle declarait donc le legacy conforme. **Un faux
         * PASS**, et il vient toujours d'un motif plus large que la propriete.
         */
        const annonceTroncature = /tronqu|plus anciennes|derni[e\u00e8]res|limit|only the|latest/i
            .test(vu.texteSection);
        constate('une troncature est-elle annoncee ?', annonceTroncature ? 'OUI' : 'non');
        verifiePortage('un tableau tronque DIT qu\'il l\'est',
            annonceTroncature,
            `la route rend ${LIMITE_ROUTE} lignes au plus, ${TOTAL_POSE} existent, `
            + 'et rien a l\'ecran ne distingue « tout l\'historique » de « les 50 derniers »');

        // ── L'AUTEUR ─────────────────────────────────────────────────────
        // `_log_ban_action` recoit `request.headers.get('X-User-ID', 'admin')` :
        // la colonne affiche un NUMERO, ou la chaine litterale `admin`.
        const numerique = vu.auteurs.some((a) => /^\d+$/.test(a));
        verifiePortage('la colonne « Par » nomme une personne, pas un numero',
            ! numerique,
            `elle affiche « ${vu.auteurs.filter((x) => /^\d+$/.test(x)).join(', ')} » — `
            + 'corrige dans `iptables`, pas ici : deuxieme moitie d\'un « a moitie corrige »');
    });

    // ═══ 3. LA FRISE ═════════════════════════════════════════════════════
    await etape('la frise des bans', async () => {
        const vu = await page.evaluate((sels) => {
            const section = document.querySelector(sels.sectionFrise);
            const cadre = document.querySelector(sels.frise);
            const barres = [...document.querySelectorAll(sels.barre)];

            return {
                visible: section ? (section.offsetParent !== null) : false,
                nb: barres.length,
                /*
                 * LA HAUTEUR RENDUE, EN PIXELS — pas celle qui est DECLAREE.
                 *
                 * Une premiere redaction ne lisait que `b.style.height`, donc
                 * « 100% », et concluait que la barre etait haute. La capture a
                 * montre une carte « Statistics » VIDE : le conteneur du legacy
                 * porte `h-32`, une classe Tailwind, et une hauteur en
                 * POURCENTAGE se resout contre la hauteur du parent. Si celle-ci
                 * vaut zero, toutes les barres valent zero — en declarant 100 %.
                 *
                 * Quatrieme piege du meme genre dans ce projet : une pastille
                 * KEV a 1,06:1 etait invisible alors que le HTML etait juste.
                 * **Mesurer le rendu, jamais l'intention.**
                 */
                cadreHautPx: Math.round(cadre ? cadre.getBoundingClientRect().height : -1),
                barres: barres.map((b) => ({
                    hauteur: b.style.height || getComputedStyle(b).height,
                    hautPx: Math.round(((sels.corpsBarre && b.querySelector(sels.corpsBarre)) || b)
                        .getBoundingClientRect().height),
                    largePx: Math.round(b.getBoundingClientRect().width),
                    fondRendu: getComputedStyle(((sels.corpsBarre && b.querySelector(sels.corpsBarre)) || b))
                        .backgroundColor,
                    fond: b.style.background || getComputedStyle(b).backgroundColor,
                    titre: b.title || b.getAttribute('aria-label') || '',
                    texte: (b.textContent || '').trim(),
                })),
                reperes: (section ? section.innerText || '' : '').trim(),
            };
        }, C);
        verifie('la frise est visible', vu.visible);
        constate('barres rendues', `${vu.nb} pour ${JOURS.length} jours en base`);
        vu.barres.forEach((b, i) => constate(`barre ${i + 1}`,
            `declaree=${b.hauteur} rendue=${b.hautPx}x${b.largePx}px fond=${b.fondRendu} `
            + `intitule="${b.titre || b.texte}"`));
        constate('hauteur RENDUE du cadre de la frise', `${vu.cadreHautPx}px`);
        verifie('une barre par jour', vu.nb === JOURS.length, `${vu.nb} / ${JOURS.length}`);

        /*
         * UNE FRISE DECLAREE N'EST PAS UNE FRISE RENDUE. La propriete est que
         * la barre la plus haute occupe reellement de la place a l'ecran.
         */
        const plusHaute = Math.max(0, ...vu.barres.map((b) => b.hautPx || 0));
        verifiePortage('la frise occupe reellement de la hauteur a l\'ecran',
            plusHaute >= 40,
            `la plus haute barre est rendue a ${plusHaute}px (cadre : ${vu.cadreHautPx}px) `
            + 'alors qu\'elle declare 100 % : une hauteur en pourcentage se resout contre un '
            + 'parent de hauteur nulle, et la carte « Statistiques » s\'affiche VIDE');

        /*
         * LA HAUTEUR ET L'ECHELLE DOIVENT MESURER LA MEME GRANDEUR.
         *
         * `maxVal` est calcule sur `ban + unban`, la hauteur sur `ban` seul :
         *   const maxVal = Math.max(1, ...Object.values(days).map(d => d.ban + d.unban));
         *   const h = Math.max(4, (counts.ban / maxVal) * 100);
         *
         * On mesure la PROPRIETE, pas la formule : la barre du jour le plus
         * charge doit etre la plus haute. J-3 (6 unbans) et J-1 (14 evenements)
         * doivent donc depasser le plancher.
         */
        /*
         * ON NORMALISE AVANT DE COMPARER — pixels et pourcentages ne se
         * soustraient pas.
         *
         * Le legacy declare ses hauteurs en POURCENTAGE, le portage en PIXELS.
         * Une premiere redaction comparait `parseFloat('34px')` a « 15 % » et
         * annonçait 44 points d'ecart sur une frise juste. Meme faute que
         * comparer `LENGTH` a `CHAR_LENGTH` : deux nombres de la meme forme dans
         * deux unites differentes.
         *
         * On ramene donc chaque serie a sa propre plus haute barre. C'est
         * exactement ce que la propriete demande : une PROPORTION.
         */
        const brutes = vu.barres.map((b) => b.hautPx || 0);
        const maxBrute = Math.max(1, ...brutes);
        const pc = brutes.map((v) => (v / maxBrute) * 100);
        const attendus = JOURS.map((j) => j.bans + j.unbans);
        /*
         * ON MESURE UNE PROPORTION, PAS UN CLASSEMENT.
         *
         * Une premiere redaction comparait l'ORDRE des barres a l'ordre des
         * totaux. Les deux classements coincident (4 % / 100 % / 12,5 % contre
         * 6 / 40 / 14 evenements) : l'assertion passait au vert **sur le defaut
         * qu'elle etait ecrite pour trouver**. Troisieme faux PASS de la suite,
         * et le troisieme vient d'une mesure plus GROSSIERE que la propriete.
         *
         * La propriete est la proportionnalite : une barre qui vaut 14/40 des
         * evenements doit occuper 35 % de la hauteur, pas 12,5 %.
         */
        const maxAttendu = Math.max(...attendus);
        const attendusPc = attendus.map((v) => (v / maxAttendu) * 100);
        const ecarts = pc.map((v, i) => Math.abs(v - attendusPc[i]));
        const pire = Math.round(Math.max(...ecarts) * 10) / 10;
        constate('evenements par jour, en base', attendus.join(' \u00b7 '));
        constate('hauteurs rendues, normalisees', pc.map((v) => Math.round(v * 10) / 10 + '%').join(' \u00b7 '));
        constate('hauteurs attendues', attendusPc.map((v) => Math.round(v * 10) / 10 + '%').join(' \u00b7 '));
        constate('pire ecart', `${pire} points`);
        verifiePortage('la hauteur d\'une barre est PROPORTIONNELLE aux evenements du jour',
            pire <= 5,
            `pire ecart ${pire} points — l'echelle compte les bans ET les unbans `
            + '(`maxVal = d.ban + d.unban`), la hauteur seulement les bans '
            + '(`(counts.ban / maxVal) * 100`) : les deux ne mesurent pas la meme grandeur');

        // Un jour de 6 unbans et 0 ban tombe au plancher, en VERT : il se lit
        // comme un jour ou il ne s'est rien passe.
        verifiePortage('un jour sans ban mais avec des unbans se distingue d\'un jour vide',
            pc[0] > 5,
            `la premiere barre est a ${Math.round(pc[0] * 10) / 10} % de la plus haute — le plancher — `
            + 'alors que 6 evenements y sont enregistres');

        // Une frise sans repere de date ne se lit pas : les dates ne vivent que
        // dans l'attribut `title`, donc au survol, donc jamais au doigt.
        const reperes = /\d{4}-\d{2}-\d{2}|\d{2}\/\d{2}/.test(vu.reperes);
        constate('des dates sont-elles VISIBLES sur la frise ?', reperes ? 'OUI' : 'non');
        verifiePortage('la frise porte des reperes de date visibles',
            reperes,
            'les dates ne vivent que dans l\'attribut `title` : invisibles au doigt, '
            + 'invisibles a un lecteur d\'ecran, invisibles sur une capture');
    });

    // ═══ 4. UNE MACHINE INJOIGNABLE MASQUE-T-ELLE SON HISTORIQUE ? ═══════
    await etape('un releve de statut en echec', async () => {
        statutServi = null;
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await dors(300);
        await choisitMachine(page);
        const avant = abouties.length;
        await page.click(C.relever);
        await dors(2500);
        const lectures = abouties.length - avant;
        const vu = await page.evaluate((sels) => {
            const s = document.querySelector(sels.sectionHisto);

            return { visible: s ? (s.offsetParent !== null) : false };
        }, C);
        constate('lectures d\'historique parties malgre l\'echec', `${lectures}`);
        constate('section d\'historique visible', `${vu.visible}`);
        /*
         * L'historique est EN BASE : il ne depend d'aucune machine. Le legacy le
         * charge pourtant a la fin du succes de `loadStatus` — une machine
         * injoignable masque donc son propre historique, precisement au moment
         * ou on le consulte.
         */
        verifiePortage('l\'historique reste consultable quand la machine est injoignable',
            lectures > 0,
            '`loadStatus` sort par `return` avant `loadHistory` : une lecture EN BASE '
            + 'est rendue dependante d\'une session SSH dont elle n\'a aucun besoin');
        statutServi = { success: true, installed: false, running: false, jails: [] };
    });

    // ═══ 5. LA LANGUE, ET CE QUE LA PAGE EN DIT ════════════════
    await etape('la langue et la date', async () => {
        await page.goto(`${BASE}${C.page}?lang=en`, { waitUntil: 'networkidle2' });
        await dors(400);
        await choisitMachine(page);
        await releve(page);
        const vu = await page.evaluate((sels) => {
            const section = document.querySelector(sels.sectionHisto);
            const corps = document.querySelector(sels.corpsHisto);
            const r = corps ? corps.querySelector('tr') : null;
            const c = r ? r.querySelector('td') : null;

            return {
                attribut: document.documentElement.getAttribute('lang') || '(absent)',
                titre: section ? (section.querySelector('h2')?.textContent || '').trim() : '',
                date: c ? c.textContent.trim() : '',
            };
        }, C);
        constate('intitule de la section, apres `?lang=en`', vu.titre || '(vide)');
        constate('attribut `lang` de la page', vu.attribut);
        constate('premiere date rendue', vu.date || '(vide)');

        /*
         * L'INSTRUMENT D'ABORD : la bascule a-t-elle seulement pris ?
         *
         * Une premiere redaction lisait `document.documentElement.lang` pour
         * savoir en quelle langue etait la page. Or `legacy/fail2ban/index.php:24`
         * ecrit `<html lang="fr">` EN DUR : l'attribut disait « fr » quelle que
         * soit la langue reelle, et l'assertion sur la date passait au vert
         * faute d'objet. **Quatrieme faux PASS de la suite.**
         *
         * On compare donc l'intitule a celui releve en francais : c'est du
         * contenu traduit, il ne peut pas mentir sur sa propre langue.
         */
        const aBascule = titreFr !== '' && vu.titre !== '' && vu.titre !== titreFr;
        verifie('la bascule de langue prend effet sur cette page', aBascule,
            `« ${titreFr} » puis « ${vu.titre} »`);

        // L'attribut `lang` sert aux lecteurs d'ecran : un contenu anglais
        // annonce « fr » se prononce avec la phonetique francaise.
        verifiePortage('l\'attribut `lang` de la page suit la langue de l\'interface',
            vu.attribut.startsWith('en'),
            `la page est en anglais et declare lang="${vu.attribut}" — `
            + '`index.php:24` l\'ecrit en dur');

        // `toLocaleString('fr-FR')` est ecrit en dur (main.js:298).
        if (aBascule) {
            const formatFrancais = /^\d{2}\/\d{2}\/\d{4}/.test(vu.date);
            verifiePortage('la date suit la langue de l\'interface',
                ! formatFrancais,
                `l'interface est en anglais et la date s'affiche « ${vu.date} » — `
                + '`toLocaleString(\'fr-FR\')` est ecrit en dur');
        } else {
            verifie('la date a pu etre mesuree dans la langue voulue', false,
                'la bascule n\'a pas pris : la mesure de la date n\'a pas d\'objet');
        }
    });

    // ═══ 6. SURETE ══════════════════════════════════════════════════════
    await etape('surete', async () => {
        constate('statuts SERVIS (jamais transmis)', `${servies.length}`);
        constate('lectures abouties', abouties.join(' ') || '(aucune)');
        constate('requetes avortees', avortees.length
            ? avortees.map((a) => `${a.route} (${a.motif})`).join(' · ') : '(aucune)');
        verifie('aucune requete n\'a vise la production',
            ! [...abouties, ...servies].some((c) => new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(c)),
            [...abouties, ...servies].join(' '));
        /*
         * LE MOTIF VISE LE SEGMENT, PAS LA SOUS-CHAINE.
         *
         * Une premiere redaction cherchait `(ban|unban|install|...)` n'importe
         * ou dans l'URL — et « ban » se trouve DANS « fail2ban ». Elle accusait
         * donc `/fail2ban/history` d'etre un geste de F4. Meme faute que le
         * filtre d'archivage qui acceptait `/supervision/` parce qu'il contient
         * `/supervision` : on compare des SEGMENTS, jamais des sous-chaines.
         */
        const GESTES = /\/fail2ban\/(ban|unban|ban_all_servers|unban_all|install|install_all|restart|enable_jail|disable_jail|whitelist)(\?|$)/;
        verifie('aucun geste de F4, F5 ou F6 n\'a abouti',
            ! abouties.some((c) => GESTES.test(c)),
            abouties.filter((c) => GESTES.test(c)).join(' '));
        verifie('aucune erreur JavaScript', session.erreursJs.length === 0,
            session.erreursJs.join(' | '));
    });

    // ═══ 7. CAPTURES ════════════════════════════════════════════════════
    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await dors(300);
        await choisitMachine(page);
        await releve(page);
        for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                         { n: 'mobile', w: 390, h: 844 }]) {
            await page.setViewport({ width: f.w, height: f.h });
            await dors(350);
            await page.screenshot({ path: `${dossier}/f2-${f.n}.png`, fullPage: true });
        }
        verifie('les trois captures sont ecrites', true, '', `${dossier}/f2-*.png`);
    });
} catch (e) {
    verifie('deroulement sans exception', false, String(e.message || e).split('\n')[0]);
} finally {
    /*
     * CHAQUE ETAPE DANS SON PROPRE `try`. Une exception ici emporterait tout le
     * verdict, et la suite rendrait « 0 PASS / 0 FAIL » sans dire si la donnee
     * d'epreuve a ete retiree — treize suites en dependent (piege paye en A2).
     */
    try {
        for (const ctx of contextes) { try { await ctx.close(); } catch {} }
        await navigateur.close();
    } catch { /* deja ferme */ }

    try {
        // BORNE PAR UN DELTA, jamais par un `DELETE` large : la table est un
        // journal d'audit, et une autre session peut y ecrire.
        litEnBase(`DELETE FROM rootwarden.fail2ban_history WHERE id > ${BORNE}`);
        const reste = compteEnBase(`SELECT COUNT(*) FROM rootwarden.fail2ban_history WHERE id > ${BORNE}`);
        verifie('la donnee d\'epreuve est retiree', reste === 0, `${reste} ligne(s) restante(s)`);
    } catch (e) {
        verifie('retrait de la donnee d\'epreuve', false, String(e.message || e).split('\n')[0]);
    }

    try {
        const apres = cacheEnBase();
        // Le statut etant SERVI, `_update_status_cache` n'a jamais tourne.
        verifie('le cache `fail2ban_status` est intact', apres === CACHE_ORIGINE,
            `avant=${CACHE_ORIGINE} apres=${apres}`);
    } catch (e) {
        verifie('relecture du cache', false, String(e.message || e).split('\n')[0]);
    }
}

note(`${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
process.exit(echecs === 0 ? 0 : 1);
