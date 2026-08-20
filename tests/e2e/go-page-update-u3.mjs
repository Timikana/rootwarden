/**
 * go-page-update-u3.mjs - Module `update/`, sous-lot U3 : les constats.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/update/
 *   laravel  http://localhost:8444/mises-a-jour
 *
 * PERIMETRE U3 — « paquets en attente » (`/pending_packages`). LU DANS
 * `backend/routes/updates.py` AVANT TOUT CLIC : la route ouvre une session SSH
 * et lance en root
 *     apt-get update -qq 2>/dev/null; apt list --upgradable
 * puis DECOUPE la sortie elle-meme et ne renvoie que des noms et des versions.
 * Elle n'installe rien ; elle REECRIT en revanche l'index local des paquets.
 *
 * LA SIMULATION (`/dry_run_update`) etait restee au legacy tant que son flux
 * portait le mot de passe root. Le correctif du 2026-08-19 leve cette raison :
 * elle a rejoint le portage avec le sous-lot U6a. Ce test verifie seulement que
 * le constat des paquets ne l'appelle pas — ce sont deux actions distinctes.
 *
 * MACHINE 1 EN PRODUCTION : jamais cochee. Le test verifie qu'aucune requete
 * ne la designe.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-update-u3.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-update-u3.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/mises-a-jour' : '/update/';

const MACHINE_TEST = 2;
const NOM_TEST = 'Test-Server-Debian';
const MACHINE_PROD = 1;

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
function verifie(libelle, ok, detail) {
    lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${libelle}${detail ? '  — ' + detail : ''}`);
    if (!ok) echecs++;
}
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }

/** Exigence qui ne vaut que pour le portage ; cote legacy, simple constat. */
function verifiePortage(libelle, ok, detail) {
    if (CIBLE === 'laravel') return verifie(libelle, ok, detail);
    constate(libelle, `non exigible du legacy — ${detail}`);
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});

async function connecte(nom, secret) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    page.on('dialog', d => d.dismiss().catch(() => {}));

    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };

    await page.goto(`${BASE}${chemins.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    await page.type('input[name="2fa_code"]', totp(secret), { delay: 8 });
    nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (chemins.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$('[data-rw="cgu-accepter"]') || await page.$('button[name="accept_terms"]');
        if (b) await b.evaluate(x => x.click());
        try { await nav; } catch {}
    }
    return { ctx, page };
}

/** Le bouton du constat, sur l'une ou l'autre cible. */
const SEL_PAQUETS = '[data-rw="paquets-en-attente"], button[onclick*="checkPendingPackages"]';
const SEL_SIMULATION = '[data-rw="simulation"], button[onclick*="dryRunUpdate"]';

/** Lignes du panneau de journal d'un serveur donne. */
async function panneau(page, serveur) {
    return page.evaluate((nom) => {
        const conteneur = document.getElementById('logs-container');
        if (!conteneur) return null;
        for (const el of conteneur.querySelectorAll('[data-server-name]')) {
            if (el.getAttribute('data-server-name') === nom) {
                return {
                    lignes: [...el.querySelectorAll('.log-line')].map(p => p.textContent.trim()),
                    texte: el.innerText,
                };
            }
        }
        return null;
    }, serveur);
}

async function attendJusqua(page, lit, predicat, maxMs = 90000) {
    const limite = Date.now() + maxMs;
    let dernier = await lit();
    while (Date.now() < limite && !predicat(dernier)) {
        await dors(400);
        dernier = await lit();
    }
    return dernier;
}

console.log(`\n=== Module update/, sous-lot U3 — constat « paquets en attente » (${CIBLE}) ===\n`);
constate('cible', `${BASE}${PAGE}`);
constate('ce que fait la route, lu dans backend/routes/updates.py',
    "apt-get update -qq ; apt list --upgradable, en root — n'installe rien, reecrit l'index local");

/*
 * MODULE ARCHIVE ? Cote legacy, `update/` a ete porte en sept sous-lots puis
 * deplace dans `legacy/_deprecated/`. Ses URL rendent 404 : ce n'est pas un
 * echec, c'est l'aboutissement du portage. Le test le CONSTATE — et verifie
 * surtout que le menu du legacy mene desormais au portage, sans quoi on aurait
 * installe soi-meme un 404 dans un menu.
 *
 * Tant que le module est servi, ce bloc est inerte et la suite se joue.
 */
if (CIBLE === 'legacy') {
    const archivee = await constateArchivage({
        base: BASE,
        chemin: '/update/',
        fichiers: [
        '/update/index.php',
        '/update/js/apiCalls.js',
        '/update/js/domManipulation.js',
        '/update/functions/list_machines.php',
        '/update/functions/filter_servers.php',
        ],
        verifie, constate,
    });
    if (archivee) {
        const { ctx, page } = await connecte('rw-test-admin', SECRET_ADMIN);
        await verifieMenuLegacy(page, '/mises-a-jour', verifie);
        await ctx.close();
        console.log(lignes.join('\n'));
        console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
        await navigateur.close();
        process.exit(echecs > 0 ? 1 : 0);
    }
}

const { ctx, page } = await connecte('rw-test-admin', SECRET_ADMIN);

// Toutes les requetes du navigateur, pour MESURER LA FONCTION et pas seulement
// son effet visible : combien d'appels, vers quoi, pour quelle machine.
const appels = [];
page.on('request', (r) => {
    const url = r.url();
    if (!/pending_packages|dry_run_update/.test(url)) return;
    appels.push({ url, corps: r.postData() || '' });
});

await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });

// Le tableau se remplit par script : attendre les lignes, pas un delai.
const nbLignes = await attendJusqua(page,
    () => page.evaluate(() => document.querySelectorAll('#server-table-body tr[data-machine-id]').length),
    (n) => n > 0, 30000);
verifie('le parc est rendu', nbLignes > 0, `${nbLignes} ligne(s)`);

const aPaquets = await page.$(SEL_PAQUETS);
verifie("l'action « paquets en attente » est presente", Boolean(aPaquets));

const aSimulation = await page.$(SEL_SIMULATION);
if (CIBLE === 'legacy') {
    constate('la simulation existe cote legacy', aSimulation ? 'oui' : 'non');
} else {
    // La simulation est restee au legacy tant que son flux portait le mot de
    // passe root. Le correctif du 2026-08-19 leve cette raison : elle a rejoint
    // le portage avec le sous-lot U6a, qui la couvre.
    verifie('la simulation est desormais portee', Boolean(aSimulation),
        'la fuite qui la retenait au legacy est corrigee (CHANGELOG v1.37.17)');
}

// ── Sans machine cochee : le constat ne part pas ────────────────────────────
//
// On REPART D'UN ETAT CONNU : aucune case cochee. Et on mesure en REQUETES,
// parce qu'un ecran qui ne change pas ne prouve pas qu'aucun appel n'est parti.
await page.evaluate(() => {
    for (const c of document.querySelectorAll('input[name="selected_machines[]"]')) c.checked = false;
});
const avantVide = appels.length;
await aPaquets.evaluate(b => b.click());
await dors(1500);
verifie("sans machine cochee, aucun appel n'est emis",
    appels.length === avantVide, `${appels.length - avantVide} appel(s)`);

const compteurVide = await page.evaluate(() =>
    document.querySelector('[data-rw="compteur-selection"]')?.textContent.trim() || '');
verifiePortage("la page dit qu'il manque une machine, avant le geste",
    /cochez|tick/i.test(compteurVide), `compteur : « ${compteurVide} »`);

const annonceVide = await page.evaluate(() =>
    document.querySelector('[data-rw="annonce"]')?.textContent.trim() || '');
verifiePortage('le clic a vide est explique',
    /aucune machine|no machine/i.test(annonceVide), `annonce : « ${annonceVide} »`);

// ── Machine 2 seule ─────────────────────────────────────────────────────────
const coche = await page.$(`input[name="selected_machines[]"][value="${MACHINE_TEST}"]`);
verifie(`la machine ${MACHINE_TEST} est cochable`, Boolean(coche));
await coche.evaluate(c => { c.checked = true; c.dispatchEvent(new Event('change', { bubbles: true })); });

const compteurUn = await page.evaluate(() =>
    document.querySelector('[data-rw="compteur-selection"]')?.textContent.trim() || '');
verifiePortage('le compteur suit la selection', /\b1\b/.test(compteurUn), `compteur : « ${compteurUn} »`);

const avant = appels.length;
await aPaquets.evaluate(b => b.click());

// Attendre LE CONTENU attendu : une ligne dans le panneau du serveur. Le
// constat ouvre une session SSH et lance apt — il ne repond pas tout de suite.
const p = await attendJusqua(page, () => panneau(page, NOM_TEST),
    (x) => x && x.lignes.length > 0, 90000);

verifie('le resultat s\'affiche dans le panneau du serveur',
    Boolean(p) && p.lignes.length > 0, p ? `${p.lignes.length} ligne(s)` : 'aucun panneau');

const emis = appels.slice(avant);
verifie('un seul appel, pour la machine cochee',
    emis.length === 1 && /pending_packages/.test(emis[0].url) &&
    /"machine_id"\s*:\s*2\b/.test(emis[0].corps),
    `${emis.length} appel(s)`);

verifie(`la machine ${MACHINE_PROD}, en production, n'est jamais designee`,
    !appels.some(a => /"machine_id"\s*:\s*1\b/.test(a.corps)),
    `${appels.length} appel(s) inspecte(s)`);

verifie("le constat des paquets n'appelle pas la simulation",
    !appels.some(a => /dry_run_update/.test(a.url)),
    'les deux actions restent distinctes');

const texte = p ? p.texte : '';
verifie('le panneau nomme le resultat du constat',
    /paquet|package/i.test(texte), `« ${(p?.lignes[0] || '').slice(0, 70)} »`);

verifiePortage("l'etat vide ne promet pas que la machine est a jour",
    /index local|local index/i.test(texte),
    "le backend jette la stderr d'apt-get update et ignore son echec");

const reactif = await attendJusqua(page,
    () => page.evaluate((s) => { const b = document.querySelector(s); return b ? !b.disabled : true; }, SEL_PAQUETS),
    (v) => v === true, 20000);
verifiePortage('le bouton redevient actif quand le constat est fini', reactif === true,
    "il est desactive pendant l'appel");

await ctx.close();
await navigateur.close();

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL\n`);
process.exit(echecs ? 1 : 0);
