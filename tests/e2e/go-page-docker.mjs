/**
 * go-page-docker.mjs - La page `docker/` : inventaire et veille des conteneurs.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/docker/index.php
 *   laravel  http://localhost:8444/docker
 *
 * ══ POURQUOI LES DEUX BOUTONS DE SCAN NE SONT JAMAIS EMIS ═══════════════════
 *
 * Lecture faite AVANT d'ecrire un seul clic, comme l'exige la regle du projet.
 * Un « scan » Docker n'est PAS en lecture seule :
 *
 *   - `backend/docker_monitor.py:116` lance un **`git fetch`** dans le depot de
 *     chaque projet compose de la machine. Ca ecrit dans `.git/` et ca fait
 *     sortir la MACHINE sur le reseau ;
 *   - `backend/docker_registry.py` interroge le registre distant
 *     (`registry-1.docker.io` par defaut) pour comparer les empreintes.
 *
 * Et surtout : **`/docker/scan_all` frappe TOUTES les machines**, donc
 * `srv-zabbix` (id 1), la PRODUCTION, que la regle permanente interdit de
 * joindre. Ce n'est pas un risque theorique — la machine est bien dans le
 * selecteur de la page.
 *
 * Les deux boutons sont donc **interceptes et avortes** : on mesure que le clic
 * emet la BONNE requete, avec la bonne charge, vers la bonne route — et rien ne
 * part. C'est le motif « joint la production par construction -> interception +
 * avortement ». Aucune machine n'est jointe par cette suite.
 *
 * ══ CE QUI EST MESURE POUR DE VRAI ══════════════════════════════════════════
 *
 * Le chargement (`GET /docker/results`), les sept colonnes, les quatre tuiles de
 * synthese, le selecteur de machines, l'etat de chargement remplace, et la
 * GARDE : un role 1 ne doit pas voir la page.
 *
 * Usage :
 *   cd tests/e2e && node go-page-docker.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

/** Rôle 2 : la page est gardee par le ROLE, pas par une permission. */
const COMPTE = 'rw-test-admin';
const SECRET = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';
/** Rôle 1, zero permission — sert UNIQUEMENT a mesurer le refus. D-5 : lecture seule. */
const COMPTE_BAS = 'rw-test-user';
const SECRET_BAS = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion?lang=fr',
        page: '/docker',
        selecteur: '[data-rw="docker-machine"]',
        scanUn: '[data-rw="docker-scan-un"]',
        scanTout: '[data-rw="docker-scan-tout"]',
        synthese: '[data-rw="docker-synthese"]',
        corps: '[data-rw="docker-corps"]',
        prefixe: '/api/gateway',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/docker/index.php',
        selecteur: '#scan-machine',
        scanUn: '#scan-one-btn',
        scanTout: '#scan-all-btn',
        synthese: '#docker-summary',
        corps: '#docker-tbody',
        prefixe: '/api_proxy.php',
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
 note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { note(`INFO  ${l} : ${v}`); }
/** Une propriete que le PORTAGE doit tenir et que le legacy ne tient pas. */
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

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];

/**
 * Connexion complete, AU CLAVIER ET A LA SOURIS, avec l'interception armee
 * AVANT toute navigation.
 *
 * `emises` recueille les requetes de scan, qui sont AVORTEES : elles ne sortent
 * jamais. Tout le reste passe.
 */
async function connecte(nom, secret) {
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(40000);
    const erreursJs = [];
    const emises = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        const u = r.url();
        if (/\/docker\/scan(_all)?$/.test(u)) {
            emises.push({ url: u, methode: r.method(), corps: r.postData() || '' });
            /* AVORTE. La requete n'atteint ni la passerelle, ni le backend, ni
             * la moindre machine. */
            r.abort('failed').catch(() => {});

            return;
        }
        r.continue().catch(() => {});
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

    return { ctx, page, erreursJs, emises };
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

/** Le corps du tableau a-t-il cesse d'annoncer « chargement » ? */
async function attendChargement(page) {
    for (let i = 0; i < 40; i += 1) {
        const pret = await page.evaluate((sel) => {
            const tb = document.querySelector(sel);
            if (! tb) return false;
            const t = (tb.textContent || '').toLowerCase();

            return ! /chargement|loading/.test(t);
        }, C.corps);
        if (pret) return true;
        await dors(250);
    }

    return false;
}

try {
    constate('cible', `${CIBLE} — ${BASE}`);

    /*
     * LE CONSTAT D'ARCHIVAGE, EN TETE.
     *
     * Une partie archivee ne doit pas laisser une suite ROUGE derriere elle :
     * plus personne ne lit les rouges. Tant que la partie est servie, ce bloc
     * est inerte et la suite se joue normalement.
     *
     * Les noms de fichiers sont ceux qui EXISTENT dans
     * `legacy/_deprecated/docker/` — sonder un chemin qui n'a jamais existe rend
     * 404 et ferait passer l'assertion pour rien.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE,
            chemin: '/docker/',
            fichiers: ['/docker/index.php', '/docker/js/main.js'],
            verifie, constate,
        });
        if (archivee) {
            const s = await connecte(COMPTE, SECRET);
            await verifieMenuLegacy(s.page, '/docker', verifie);
            note('');
            note(`${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
            for (const ctx of contextes) { try { await ctx.close(); } catch {} }
            await navigateur.close();
            process.exit(echecs > 0 ? 1 : 0);
        }
    }

    const s = await connecte(COMPTE, SECRET);

    await etape('la page est servie au role 2', async () => {
        await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('la page docker est servie a un compte de role 2',
            ! /login|connexion|403/.test(s.page.url()), s.page.url().replace(BASE, ''));
    });

    await etape('le selecteur de machines', async () => {
        const vu = await s.page.evaluate((sel) => {
            const e = document.querySelector(sel);
            if (! e) return null;

            return {
                nombre: e.options ? e.options.length : 0,
                noms: e.options ? Array.from(e.options).map((o) => o.textContent.trim()) : [],
            };
        }, C.selecteur);
        verifie('le selecteur de machines existe', vu !== null);
        if (! vu) return;
        constate('machines proposees', `${vu.nombre} — ${vu.noms.join(', ')}`);
        verifie('il propose au moins une machine', vu.nombre >= 1, `${vu.nombre}`);
        /* CONSTAT DE SURETE, PAS UN DEFAUT : la production figure bien dans la
         * liste. C'est pourquoi aucun scan n'est emis par cette suite. */
        constate('srv-zabbix (production) figure dans le selecteur',
            vu.noms.some((n) => /zabbix/i.test(n)) ? 'OUI' : 'non');
    });

    await etape('les deux boutons de scan', async () => {
        const vu = await s.page.evaluate((un, tout) => ({
            un: !! document.querySelector(un),
            tout: !! document.querySelector(tout),
        }), C.scanUn, C.scanTout);
        verifie('le bouton « scanner cette machine » existe', vu.un);
        verifie('le bouton « scanner toutes les machines » existe', vu.tout);
    });

    await etape('le tableau et ses colonnes', async () => {
        const pret = await attendChargement(s.page);
        verifie('l\'etat de chargement est remplace', pret,
            pret ? 'le tableau a rendu' : 'toujours « chargement »');
        const colonnes = await s.page.evaluate(() =>
            Array.from(document.querySelectorAll('thead th')).map((t) => t.textContent.trim()));
        constate('colonnes', `${colonnes.length} — ${colonnes.join(' | ')}`);
        verifie('le tableau porte SEPT colonnes', colonnes.length === 7, `${colonnes.length}`);
    });

    await etape('les quatre tuiles de synthese', async () => {
        const n = await s.page.evaluate((sel) => {
            const e = document.querySelector(sel);

            return e ? e.children.length : -1;
        }, C.synthese);
        constate('tuiles de synthese', `${n}`);
        verifie('la synthese porte QUATRE tuiles', n === 4, `${n}`);
    });

    /* ══ LES DEUX SCANS : LA REQUETE EST MESUREE, ELLE N'EST PAS EMISE ══════ */
    await etape('le scan d\'une machine emet la bonne requete, et rien ne part', async () => {
        s.emises.length = 0;
        s.erreursJs.length = 0;
        const valeur = await s.page.$eval(C.selecteur, (e) => e.value);
        await s.page.click(C.scanUn);
        await dors(1200);
        verifie('un clic sur « scanner » emet UNE requete', s.emises.length === 1,
            `${s.emises.length} requete(s)`);
        const r = s.emises[0];
        if (! r) return;
        constate('requete interceptee', `${r.methode} ${r.url.replace(BASE, '')} ${r.corps}`);
        verifie('elle vise /docker/scan en POST',
            r.methode === 'POST' && r.url.endsWith(`${C.prefixe}/docker/scan`),
            `${r.methode} ${r.url.replace(BASE, '')}`);
        verifie('elle porte la machine choisie dans le selecteur',
            r.corps.includes(`"machine_id":${valeur}`) || r.corps.includes(`"machine_id": ${valeur}`),
            `selecteur=${valeur} corps=${r.corps}`);

        /*
         * UNE PANNE RESEAU DOIT SE VOIR, PAS SE PERDRE.
         *
         * L'avortement est exactement ce qu'un backend injoignable produirait.
         * Cote legacy, `docker/js/main.js:14` fait `await fetch(...)` SANS
         * `try`, dans `api()` : le rejet remonte hors du gestionnaire de clic,
         * la promesse n'est jamais rattrapee, et le message d'erreur prevu
         * (`docker.err_scan`) n'est JAMAIS affiche. L'exploitant clique, et rien
         * ne se passe — ni resultat, ni explication.
         *
         * `scanAll`, lui, enveloppe son `fetch` (`:106`) et affiche le message.
         * L'asymetrie est l'oubli, pas une intention.
         */
        await dors(400);
        constate('erreurs JS apres le scan d\'une machine',
            s.erreursJs.join(' | ') || 'aucune');
        verifiePortage('un scan de machine qui echoue ne laisse pas d\'erreur non capturee',
            s.erreursJs.length === 0,
            'le `fetch` de `api()` n\'est pas enveloppe : le rejet remonte et le message '
            + 'd\'erreur prevu n\'apparait jamais');
    });

    await etape('le scan global emet la bonne requete, et rien ne part', async () => {
        s.emises.length = 0;
        s.erreursJs.length = 0;
        await s.page.click(C.scanTout);
        await dors(1200);
        verifie('un clic sur « tout scanner » emet UNE requete', s.emises.length === 1,
            `${s.emises.length} requete(s)`);
        const r = s.emises[0];
        if (! r) return;
        constate('requete interceptee', `${r.methode} ${r.url.replace(BASE, '')}`);
        verifie('elle vise /docker/scan_all en POST',
            r.methode === 'POST' && r.url.endsWith(`${C.prefixe}/docker/scan_all`),
            `${r.methode} ${r.url.replace(BASE, '')}`);

        /* Celui-la, le legacy le tient : son `fetch` est enveloppe. */
        await dors(400);
        constate('erreurs JS apres le scan global', s.erreursJs.join(' | ') || 'aucune');
        verifie('un scan global qui echoue ne laisse pas d\'erreur non capturee',
            s.erreursJs.length === 0, s.erreursJs.join(' | ') || 'aucune');
    });

    /* ══ LA GARDE ══════════════════════════════════════════════════════════ */
    await etape('un role 1 n\'accede pas a la page', async () => {
        const bas = await connecte(COMPTE_BAS, SECRET_BAS);
        /*
         * LE STATUT, PAS LE TEXTE. Un premier jet reniflait le corps rendu a la
         * recherche de « acces refuse » : sur la base rouge, la page n'existait
         * pas encore et rendait « 404 Not Found » — que le renifleur comptait
         * comme un NON-refus. La propriete est le CODE, et il doit valoir 403 :
         * un 404 dirait « cette page n'existe pas », ce qui n'est pas la meme
         * chose que « vous n'y avez pas droit ».
         */
        const reponse = await bas.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const statut = reponse ? reponse.status() : 0;
        const corps = (await bas.page.evaluate(() => document.body.innerText)).slice(0, 200);
        constate('statut rendu au role 1', `HTTP ${statut}`);
        constate('debut du corps rendu au role 1', corps.replace(/\s+/g, ' ').slice(0, 120));

        /* LA PROPRIETE PARTAGEE : l'acces est refuse, d'une façon ou d'une autre. */
        const refuse = statut === 403
            || /acc[eè]s refus|refus|interdit|forbidden/i.test(corps);
        verifie('la page docker est refusee a un compte de role 1', refuse,
            `HTTP ${statut} — ${corps.replace(/\s+/g, ' ').slice(0, 60)}`);

        /*
         * LE REFUS PORTE UN CODE, DES DEUX COTES — ET LE LEGACY EST DEDOUANE.
         *
         * J'avais suppose qu'il rendait sa page « Acces refuse » en HTTP 200,
         * et ecrit l'ecart en consequence. La mesure dit l'inverse : il rend un
         * vrai **403**. L'ecart etait donc une accusation sans fondement, et
         * quand la mesure dedouane il faut le dire aussi clairement que quand
         * elle accuse. C'est une assertion partagee, pas une divergence.
         */
        verifie('le refus porte le code 403, et pas un 200 habille', statut === 403,
            `HTTP ${statut}`);
    });
} catch (e) {
    verifie('deroulement de la suite', false, String(e).split('\n')[0]);
} finally {
    for (const ctx of contextes) { try { await ctx.close(); } catch {} }
    try { await navigateur.close(); } catch {}
}

note('');
note(`${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — ${etapes} etapes, cible ${CIBLE}`);
process.exit(echecs === 0 ? 0 : 1);
