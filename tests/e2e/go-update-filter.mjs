/**
 * go-update-filter.mjs - Regression v1.37.12 : le bouton "Filtrer" de /update/
 * doit repeupler le tableau (cle JSON "machines" de l'API Python) au lieu de
 * lever "Exception filtre : TypeError ... reading 'forEach'" (ancienne cle
 * "servers" heritee de l'endpoint PHP legacy).
 *
 * Auto-validant (headless, exit 0/1). Lecture seule : ne modifie rien.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { mkdirSync } from 'fs';

const BASE = 'https://localhost:8443';
const USER = process.env.E2E_USER || 'superadmin';
const PASS = process.env.E2E_PASS || 'RootWarden@2026-Sec!';
const SECRET = process.env.E2E_TOTP_SECRET || ''; // secret 2FA via env (audit v1.23)
const SHOTS = './screenshots/update-filter';
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

async function readState() {
    return page.evaluate(() => {
        const rows = document.querySelectorAll('#server-table-body tr[data-machine-id]').length;
        const logs = (document.getElementById('logs')?.textContent
                   || document.querySelector('#log-container, .logs, textarea')?.value
                   || document.body.textContent || '');
        return {
            rows,
            hasException: logs.includes('Exception filtre'),
            hasApplied: /Filtre appliqu/.test(logs),
        };
    });
}

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

    // ── Page /update/ ───────────────────────────────────────────────────────
    await page.goto(`${BASE}/update/`, { waitUntil: 'networkidle2' });
    await sleep(800);
    const initialRows = await page.evaluate(() =>
        document.querySelectorAll('#server-table-body tr[data-machine-id]').length);
    console.log(`Lignes initiales (rendu PHP) : ${initialRows}`);
    check('la page charge avec au moins 1 machine', initialRows >= 1);

    // ── Filtre "tous" (aucun critere) : doit repeupler le tableau ───────────
    await page.evaluate(() => filterServers());
    await sleep(1500);
    await page.screenshot({ path: `${SHOTS}/01_filtre_tous.png` });
    let st = await readState();
    console.log(`Apres filtre "tous" : ${st.rows} ligne(s)`);
    check('aucune "Exception filtre" apres filtre sans critere', !st.hasException);
    check('message "Filtre applique" present', st.hasApplied);
    check('le tableau est repeuple (>=1 ligne)', st.rows >= 1);
    check('autant de lignes que le rendu initial', st.rows === initialRows);

    // ── Filtre restrictif (environment=PROD) : pas d'exception non plus ─────
    await page.select('#environment', 'PROD').catch(() => {});
    await page.evaluate(() => filterServers());
    await sleep(1500);
    await page.screenshot({ path: `${SHOTS}/02_filtre_prod.png` });
    st = await readState();
    console.log(`Apres filtre PROD : ${st.rows} ligne(s)`);
    check('aucune "Exception filtre" apres filtre PROD', !st.hasException);

    check('aucune erreur JS non geree', jsErrors.length === 0);
    if (jsErrors.length) console.log('  erreurs JS :', jsErrors.join(' | '));
} catch (e) {
    console.error('ERREUR SCRIPT :', e);
    failures++;
} finally {
    await browser.close();
}

console.log(failures === 0 ? '\n=== TOUT OK ===' : `\n=== ${failures} ECHEC(S) ===`);
process.exit(failures === 0 ? 0 : 1);
