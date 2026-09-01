/**
 * go-ssh-audit-scanall.mjs - Regression v1.37.13 : "Tout scanner" (SSH Audit)
 * doit repondre IMMEDIATEMENT (tache de fond + centre de taches) au lieu de
 * garder la requete HTTP ouverte pendant tout le scan du parc (504 des proxys,
 * saturation backend -> 500/504 en cascade sur /update/).
 *
 * Auto-validant (headless, exit 0/1). L'audit SSH est en lecture seule sur les
 * cibles (lecture sshd_config) - aucune action mutante.
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  ⚠ NE PAS AJOUTER AU LOT. Cette suite JOINT LA PRODUCTION.               ║
 * ║                                                                          ║
 * ║  « Tout scanner » porte sur LE PARC ENTIER : `srv-zabbix` (machine 1,    ║
 * ║  production) est jointe par SSH a chaque execution.                      ║
 * ║                                                                          ║
 * ║  La phrase ci-dessus — « aucune action mutante » — est VRAIE et ne suffit ║
 * ║  pas : elle ecarte la MUTATION, pas la PORTEE. Une lecture distante reste ║
 * ║  une connexion sortante vers des machines reelles, et un LOT la rejouerait ║
 * ║  a chaque passage. **Une condition formulee sur ce qui est typique plutot ║
 * ║  que sur ce qui rend le geste grave laisse ouvert le cas qu'elle voulait  ║
 * ║  fermer.**                                                               ║
 * ║                                                                          ║
 * ║  `rejouer-lot.sh` ne mentionne PAS cette suite : rien, aujourd'hui,      ║
 * ║  n'empeche quelqu'un de « completer » le LOT avec les 24 suites qui n'y   ║
 * ║  sont pas. Ce cadre est la pour que la lecture de ce fichier suffise a    ║
 * ║  l'en dissuader — c'est le seul endroit que lira forcement celui qui      ║
 * ║  voudra l'ajouter.                                                       ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { mkdirSync } from 'fs';

const BASE = 'https://localhost:8443';
const USER = process.env.E2E_USER || 'superadmin';
const PASS = process.env.E2E_PASS || 'RootWarden@2026-Sec!';
const SECRET = process.env.E2E_TOTP_SECRET || ''; // secret 2FA via env (audit v1.23)
const SHOTS = './screenshots/ssh-audit-scanall';
mkdirSync(SHOTS, { recursive: true });

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function sleep(ms){return new Promise(r=>setTimeout(r,ms))}

let failures = 0;
function check(label, ok) {
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
    if (!ok) failures++;
}

const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
});
const page = (await browser.pages())[0];
page.setDefaultTimeout(30000);
const jsErrors = [];
page.on('pageerror', e => jsErrors.push(String(e)));

try {
    // ── Login (+ TOTP + CGU) ────────────────────────────────────────────────
    await page.goto(`${BASE}/auth/login.php`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', USER, { delay: 10 });
    await page.type('input[name="password"]', PASS, { delay: 10 });
    const n1 = page.waitForNavigation({ waitUntil: 'networkidle2' });
    await page.click('button[type="submit"]'); await n1;
    if (page.url().includes('verify_2fa')) {
        const rem = 30 - (Math.floor(Date.now()/1000) % 30);
        if (rem < 6) await sleep(rem*1000+500);
        await page.type('input[name="2fa_code"]', totp(SECRET), { delay: 10 });
        const n2 = page.waitForNavigation({ waitUntil: 'networkidle2' });
        await page.click('button[type="submit"]'); await n2;
    }
    if (page.url().includes('terms')) {
        const btn = await page.$('button[name="accept_terms"]');
        if (btn) { const nT = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 8000 }); await btn.click(); try { await nT; } catch {} }
    }

    // ── Page SSH Audit ──────────────────────────────────────────────────────
    await page.goto(`${BASE}/ssh-audit/`, { waitUntil: 'networkidle2' });
    await sleep(800);

    // ── Lancer le scan du parc : la reponse doit etre IMMEDIATE ─────────────
    const t0 = Date.now();
    await page.evaluate(() => scanAll());
    // La confirmation "lance en arriere-plan" doit apparaitre en quelques
    // secondes (avant : la requete durait tout le scan -> minutes/504).
    let queuedSeen = false;
    for (let i = 0; i < 16 && !queuedSeen; i++) {
        await sleep(500);
        queuedSeen = await page.evaluate(() =>
            document.body.textContent.includes('arriere-plan') ||
            document.body.textContent.includes('background'));
    }
    const elapsed = (Date.now() - t0) / 1000;
    console.log(`Reponse scan-all en ~${elapsed.toFixed(1)}s`);
    check('reponse immediate (<8s) avec message "arriere-plan"', queuedSeen && elapsed < 8);

    const fleetVisible = await page.evaluate(() => {
        const f = document.getElementById('fleet-container');
        return !!f && !f.classList.contains('hidden');
    });
    check('vue parc affichee immediatement', fleetVisible);
    await page.screenshot({ path: `${SHOTS}/01_queued.png` });

    // ── Attendre la fin de la tache (polling UI toutes les 5s) ─────────────
    let doneSeen = false;
    for (let i = 0; i < 36 && !doneSeen; i++) {   // jusqu'a ~3 min
        await sleep(5000);
        doneSeen = await page.evaluate(() =>
            document.body.textContent.includes('Audit du parc termine') ||
            document.body.textContent.includes('Fleet audit finished'));
    }
    check('tache terminee (message de fin recu du centre de taches)', doneSeen);

    const fleetRows = await page.evaluate(() =>
        document.querySelectorAll('#fleet-tbody tr').length);
    console.log(`Lignes vue parc : ${fleetRows}`);
    check('la vue parc contient au moins 1 resultat', fleetRows >= 1);
    await page.screenshot({ path: `${SHOTS}/02_done.png` });

    check('aucune erreur JS', jsErrors.length === 0);
    if (jsErrors.length) console.log('  erreurs JS :', jsErrors.join(' | '));
} catch (e) {
    console.error('ERREUR SCRIPT :', e);
    failures++;
} finally {
    await browser.close();
}

console.log(failures === 0 ? '\n=== TOUT OK ===' : `\n=== ${failures} ECHEC(S) ===`);
process.exit(failures === 0 ? 0 : 1);
