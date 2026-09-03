/**
 * go-adm-cycle-connexion.mjs - Sous-lot D6d de `adm/` : cycle de vie et test de
 * connexion d'une machine.
 *
 * SOUS-LOT NE DE LA CORRECTION D'UN DECOUPAGE. L'inventaire avait scinde D6 par
 * FICHIER ; or ces deux capacites de la carte serveur ne vivent dans aucun
 * fichier de `adm/` — elles appellent le BACKEND :
 *
 *   `setLifecycle()`          -> `POST {API_URL}/server_lifecycle`  (admin.py:93)
 *   `testServerConnection()`  -> `POST {API_URL}/server_status`     (monitoring.py:57)
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/adm/admin_page.php  (onglet Serveurs)
 *   laravel  http://localhost:8444/serveurs
 *
 * ══ CE QUE CHAQUE ROUTE FAIT VRAIMENT, MESURE ═════════════════════════════
 *
 * `/server_status` n'ouvre PAS de session SSH : c'est un `socket.connect_ex`
 * avec 5 s de delai. Il ECRIT `machines.online_status`, et peut emettre une
 * notification `server_offline` — qui est un `INSERT` en base, sans courriel.
 * Sa protection ne vient PAS de son decorateur `@require_machine_access` mais
 * de son CORPS : refus d'un `machine_id` absent, puis resolution de l'IP EN
 * BASE au lieu d'accepter une IP brute (patch A01-02).
 *
 * `/server_lifecycle` ecrit `lifecycle_status` et `retire_date`. Sa liste
 * fermee `('active','retiring','archived')` tient, et un `machine_id` falsy est
 * refuse au meme endroit.
 *
 * ══ LE DEFAUT : `updated` RECOUVRE DEUX SITUATIONS OPPOSEES ═══════════════
 *
 * `admin.py:110` rend `{'success': True, 'updated': cur.rowcount > 0}` SANS
 * aucun `SELECT` prealable. Or `rowcount` vaut 0 aussi bien quand on reecrit la
 * valeur deja en place que quand la machine n'existe pas. `updated: false`
 * recouvre donc « il n'y avait rien a faire » et « la machine n'existe pas ».
 *
 * Une interface qui affiche « echec » sur `updated: false` ment dans le premier
 * cas ; une qui affiche « fait » ment dans le second. Voir PARITE E-133.
 *
 * ══ CE QUI N'EST PAS UN DEFAUT, ET IL FAUT LE DIRE ═══════════════════════
 *
 * `/server_lifecycle` n'a pas `@require_machine_access` la ou `/server_status`
 * le porte. Une premiere redaction y a vu un IDOR : **c'etait faux**.
 * `check_machine_access()` commence par `if role_id >= 2: return True`, donc sur
 * une route gardee par `@require_role(2)` le decorateur est REDONDANT. Mesure
 * sur tout le depot : 114 routes le portent, il est sans effet sur 57. L'ecart
 * entre les deux routes est COSMETIQUE.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 *   - la machine visee est `Test-Server-Debian` (id 2), jamais `srv-zabbix` ;
 *   - `online_status`, `lifecycle_status` et `retire_date` sont RELEVES a
 *     l'entree et RESTAURES a la sortie, quoi qu'il arrive ;
 *   - le cycle de vie ne passe jamais par `archived` : cette valeur retire la
 *     machine de `Machines::pourMisesAJour()`, donc du champ de vision d'autres
 *     suites. `retiring` suffit a mesurer le geste ;
 *   - aucune session SSH n'est ouverte : `/server_status` est une sonde TCP.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-adm-cycle-connexion
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

/** Machine d'essai du parc — jamais `srv-zabbix` (id 1, PRODUCTION). */
const MACHINE_ID = 2;
const MACHINE_NOM = 'Test-Server-Debian';

const DOSSIER_CAPTURES = new URL('./screenshots/adm', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/serveurs',
        onglet: null,
        carte: '[data-rw="serveur-carte"]',
        tester: '[data-rw="serveur-tester"]',
        cycle: (etat) => `[data-rw="serveur-cycle"][data-etat="${etat}"]`,
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/adm/admin_page.php',
        onglet: '.tab-btn[data-tab="servers"]',
        carte: 'details.server-card',
        tester: 'button[onclick^="testServerConnection"]',
        cycle: (etat) => `button[onclick*="setLifecycle"][onclick*="'${etat}'"]`,
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

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
 note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs += 1; }
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
    constate(l, `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

/** Etat releve a l'entree, restaure a la sortie quoi qu'il arrive. */
let etatInitial = null;
function releveEtat() {
    const l = litEnBase(
        `SELECT CONCAT(IFNULL(online_status,''),'|',IFNULL(lifecycle_status,''),'|',IFNULL(retire_date,''))
         FROM rootwarden.machines WHERE id = ${MACHINE_ID}`);

    return l.length ? l[0] : null;
}
function restaureEtat() {
    if (etatInitial === null) return;
    const [enLigne, cycle, date] = etatInitial.split('|');
    litEnBase(
        `UPDATE rootwarden.machines SET
           online_status = ${enLigne === '' ? 'NULL' : `'${enLigne}'`},
           lifecycle_status = ${cycle === '' ? 'NULL' : `'${cycle}'`},
           retire_date = ${date === '' ? 'NULL' : `'${date}'`}
         WHERE id = ${MACHINE_ID}`);
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

async function ouvreOnglet(page) {
    if (! C.onglet) return;
    await page.evaluate((sel) => { const o = document.querySelector(sel); if (o) o.click(); }, C.onglet);
    await dors(400);
}

/** La carte d'une machine, REPEREE PAR SON CONTENU — jamais « la premiere ». */
async function carteDe(page, nom) {
    for (const h of await page.$$(C.carte)) {
        const t = await h.evaluate((e) => e.textContent || '');
        if (t.includes(nom)) return h;
    }

    return null;
}

/** Deplie la carte et prouve que son CORPS a une boite, pas le `<details>`. */
async function deplie(carte) {
    return carte.evaluate((e) => {
        for (let n = e; n; n = n.parentElement) if (n.tagName === 'DETAILS') n.open = true;
        const corps = Array.from(e.children).find((c) => c.tagName !== 'SUMMARY');

        return corps !== undefined && corps.getBoundingClientRect().height > 0;
    });
}

/**
 * Ecoute les reponses des DEUX routes de ce sous-lot.
 *
 * LE VERDICT SE LIT DANS LA REPONSE. « La colonne n'a pas change » a plusieurs
 * causes qu'un comptage en base ne distingue pas — lecon de D6b, repayee une
 * fois de trop.
 */
function ecoute(page) {
    const vues = [];
    const f = async (r) => {
        if (! /server_status|server_lifecycle/.test(r.url())) return;
        let corps = '';
        try { corps = (await r.text()).slice(0, 140); } catch { corps = '(illisible)'; }
        vues.push(`${r.status()} ${corps.replace(/\s+/g, ' ')}`);
    };
    page.on('response', f);

    return { vues, arrete: () => page.off('response', f) };
}

/** Clique un bouton DE CETTE CARTE, et attend que le reseau retombe. */
async function clique(page, carte, selecteur) {
    const b = await carte.$(selecteur);
    if (! b) return { fait: false, reponses: [] };
    const oreille = ecoute(page);
    await b.click();
    await dors(7000); // la sonde TCP a 5 s de delai cote backend
    oreille.arrete();

    return { fait: true, reponses: oreille.vues };
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
    etatInitial = releveEtat();
    constate('etat releve a l\'entree (en ligne|cycle|date)', etatInitial || '(machine absente)');

    await etape('la machine d\'essai est-elle bien la 2 ?', async () => {
        const n = litEnBase(`SELECT name FROM rootwarden.machines WHERE id = ${MACHINE_ID}`);
        // FAIL-CLOSED : si l'identifiant 2 ne designait plus la machine d'essai,
        // tous les gestes de cette suite viseraient une machine inconnue.
        verifie('l\'identifiant 2 designe bien la machine d\'essai',
            n.length === 1 && n[0] === MACHINE_NOM, n[0] || '(absente)');
    });

    session.s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = session.s;

    await etape('ouverture', async () => {
        const rep = await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('le role 3 atteint la page', rep.status() === 200, `statut ${rep.status()}`);
    });

    // ══ 1. LE TEST DE CONNEXION, PAR UN CLIC ═══════════════════════════════
    await etape('tester la connexion par un clic', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await ouvreOnglet(page);
        const carte = await carteDe(page, MACHINE_NOM);
        verifie('la carte de la machine d\'essai est trouvee', carte !== null, MACHINE_NOM);
        if (! carte) return;
        verifie('la carte est depliee et son corps a une boite', await deplie(carte));
        await dors(300);

        litEnBase(`UPDATE rootwarden.machines SET online_status = 'AVANT' WHERE id = ${MACHINE_ID}`);
        const r = await clique(page, carte, C.tester);
        constate('reponses de /server_status', r.reponses.length ? r.reponses.join(' || ') : '(aucune)');

        const apres = litEnBase(`SELECT online_status FROM rootwarden.machines WHERE id = ${MACHINE_ID}`);
        constate('online_status apres le clic', apres[0] || '(nul)');
        // LA PROPRIETE EST « LE GESTE A ABOUTI », pas « la machine repond ».
        // 10.10.10.10 peut etre injoignable : ONLINE comme OFFLINE sont des
        // reussites du geste ; seul `AVANT` dirait que rien ne s'est passe.
        verifie('le clic declenche la sonde et ecrit le resultat',
            r.fait && apres.length === 1 && apres[0] !== 'AVANT',
            r.fait ? `online_status = ${apres[0]}` : 'bouton absent');
    });

    // ══ 2. LE CYCLE DE VIE, PAR UN CLIC ════════════════════════════════════
    await etape('passer la machine en retrait, par un clic', async () => {
        litEnBase(`UPDATE rootwarden.machines SET lifecycle_status = 'active' WHERE id = ${MACHINE_ID}`);
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await ouvreOnglet(page);
        const carte = await carteDe(page, MACHINE_NOM);
        if (! carte) { verifie('la carte est retrouvee', false); return; }
        await deplie(carte);
        await dors(300);

        // JAMAIS `archived` : cette valeur retire la machine de la vue des
        // autres suites. `retiring` mesure le meme geste sans effet de bord.
        const r = await clique(page, carte, C.cycle('retiring'));
        constate('reponses de /server_lifecycle', r.reponses.length ? r.reponses.join(' || ') : '(aucune)');

        const apres = litEnBase(`SELECT lifecycle_status FROM rootwarden.machines WHERE id = ${MACHINE_ID}`);
        verifie('le clic passe la machine en retrait', r.fait && apres[0] === 'retiring',
            r.fait ? (apres[0] || '(nul)') : 'bouton absent');
    });

    // ══ 3. L'AMBIGUITE DE `updated` ════════════════════════════════════════
    //
    // AUCUN CLIC NE PEUT PRODUIRE CE CAS, et c'est une bonne propriete de
    // l'interface : elle n'offre jamais le bouton de l'etat COURANT. Machine
    // `active` -> bouton « retirer » ; machine `retiring` -> boutons
    // « archiver » et « reactiver ». Reposer la valeur en place est donc
    // inatteignable au clic.
    //
    // La premiere redaction de cette etape l'ignorait : elle cherchait le
    // bouton `retiring` sur une machine deja en `retiring`, ne le trouvait pas,
    // ne declenchait aucune requete — et son assertion passait sur une chaine
    // VIDE. Un test qui ne peut pas echouer, revele par le seul `(aucune)` du
    // journal.
    //
    // D'ou une REQUETE FORGEE, avec son motif : exercer ce qu'aucun clic ne
    // peut atteindre. Elle part DEPUIS LA PAGE, donc avec la session, les
    // en-tetes et l'enrobage `fetch` reels.
    await etape('reposer la valeur deja en place : que dit la reponse ?', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await ouvreOnglet(page);
        const carte = await carteDe(page, MACHINE_NOM);
        if (! carte) { verifie('la carte est retrouvee', false); return; }
        await deplie(carte);
        await dors(300);

        // La machine est en `retiring` depuis l'etape 2. On PROUVE d'abord que
        // l'interface ne propose pas ce meme etat : c'est la propriete qui rend
        // la requete forgee necessaire, et elle vaut d'etre asserte.
        const boutonCourant = await carte.$(C.cycle('retiring'));
        verifie('l\'interface n\'offre pas le bouton de l\'etat COURANT',
            boutonCourant === null, 'le bouton `retiring` est propose sur une machine deja `retiring`');

        // LES DEUX CIBLES NE SE FORGENT PAS PAREIL. Le legacy poste du JSON vers
        // la passerelle du backend ; le portage a une route de formulaire, qui
        // repond par une redirection et un message. On mesure donc, de chaque
        // cote, ce qui FAIT OFFICE DE REPONSE — et la propriete comparee reste
        // la meme : la reponse dit-elle quelque chose de vrai ?
        let brut;
        if (CIBLE === 'laravel') {
            // On construit et on soumet un VRAI formulaire, avec le jeton lu
            // sur la page : c'est le mecanisme reel, simplement declenche sur
            // un etat que l'interface ne propose pas.
            const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
            await page.evaluate((mid) => {
                const jeton = document.querySelector('input[name="_token"]');
                const f = document.createElement('form');
                f.method = 'POST';
                f.action = `/serveurs/${mid}/cycle`;
                f.innerHTML = `<input name="_token" value="${jeton ? jeton.value : ''}">`
                    + '<input name="etat" value="retiring">';
                document.body.appendChild(f);
                f.submit();
            }, MACHINE_ID);
            try { await nav; } catch { /* redirection */ }
            await dors(600);
            brut = await page.evaluate(() => {
                const e = document.querySelector('[data-rw="serveurs-annonce"]');

                return e ? (e.textContent || '').trim() : '';
            });
        } else {
            brut = await page.evaluate(async (mid) => {
                const base = window.API_URL || '/api_proxy.php';
                try {
                    const r = await fetch(`${base}/server_lifecycle`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ machine_id: mid, lifecycle_status: 'retiring' }),
                    });

                    return `${r.status} ${(await r.text()).slice(0, 140)}`;
                } catch (e) {
                    return `(echec reseau) ${String(e.message || e)}`;
                }
            }, MACHINE_ID);
        }
        constate('reponse a une reecriture sans effet', brut.replace(/\s+/g, ' ') || '(vide)');

        // FAIL-CLOSED SUR L'ABSENCE DE REPONSE : une chaine vide ferait passer
        // l'assertion pour la mauvaise raison — c'est exactement ce qui est
        // arrive au premier jet de cette etape. On exige d'avoir MESURE quelque
        // chose avant de conclure.
        const mesuree = CIBLE === 'laravel' ? brut.length > 0 : /"success"/.test(brut);
        verifie('la requete forgee a bien recu une reponse', mesuree, brut.slice(0, 80) || '(vide)');
        if (! mesuree) return;

        // Cote legacy, `updated: false` est le symptome. Cote portage, la
        // propriete est que le message NOMME la situation — « rien n'a change »
        // — au lieu de la confondre avec une machine absente.
        const ambigu = CIBLE === 'laravel'
            ? ! /rien n'a chang|nothing changed/i.test(brut)
            : /"updated"\s*:\s*false/.test(brut);
        verifiePortage('la reponse distingue « rien a changer » de « machine absente »',
            ! ambigu,
            CIBLE === 'laravel'
                ? `message rendu : « ${brut.slice(0, 90)} »`
                : '`updated: false` — le backend rend `cur.rowcount > 0` sans `SELECT` prealable, '
                  + 'donc reecrire la valeur en place et viser une machine inexistante rendent tous '
                  + 'deux 0. Deux situations opposees sous une seule reponse');
    });

    // ══ 4. LE RETOUR A `active`, PAR UN CLIC ═══════════════════════════════
    await etape('reactiver la machine, par un clic', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await ouvreOnglet(page);
        const carte = await carteDe(page, MACHINE_NOM);
        if (! carte) { verifie('la carte est retrouvee', false); return; }
        await deplie(carte);
        await dors(300);

        const r = await clique(page, carte, C.cycle('active'));
        const apres = litEnBase(`SELECT lifecycle_status FROM rootwarden.machines WHERE id = ${MACHINE_ID}`);
        verifie('le clic reactive la machine', r.fait && apres[0] === 'active',
            r.fait ? (apres[0] || '(nul)') : 'bouton absent');
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            await ouvreOnglet(page);
            const carte = await carteDe(page, MACHINE_NOM);
            if (carte) {
                await deplie(carte);
                await carte.evaluate((e) => e.scrollIntoView({ block: 'center' }));
            }
            await dors(500);
            await page.screenshot({ path: `${dossier}/cycle-connexion-${nom}.png` });
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
        restaureEtat();
        const remis = releveEtat();
        verifie('l\'etat de la machine d\'essai est restaure', remis === etatInitial,
            `${remis} attendu ${etatInitial}`);
    } catch (e) { note(`FAIL  restauration : ${e.message}`); echecs += 1; }
    try {
        const zabbix = litEnBase(
            "SELECT CONCAT(name,'|',ip,'|',IFNULL(online_status,''),'|',IFNULL(lifecycle_status,'')) FROM rootwarden.machines WHERE id = 1");
        verifie('srv-zabbix est intacte', zabbix.length === 1 && zabbix[0] === 'srv-zabbix|192.168.0.244|ONLINE|active',
            zabbix[0] || '(absente)');
    } catch (e) { note(`FAIL  controle de srv-zabbix : ${e.message}`); echecs += 1; }
    try { for (const c of contextes) await c.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
    try { await navigateur.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
