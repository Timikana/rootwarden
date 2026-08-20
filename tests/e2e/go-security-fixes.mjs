/**
 * go-security-fixes.mjs - Non-regression des correctifs de securite v1.37.16.
 *
 * Verifie que les pages dont les requetes SQL / gardes d'acces ont ete modifiees
 * rendent toujours correctement (pas d'erreur PHP, contenu attendu present),
 * et que les scripts de migration restent refuses en HTTP.
 *
 * Auto-validant (headless, exit 0/1). Lecture seule.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';

const BASE = process.env.E2E_URL || 'https://localhost:8443';
const USER = process.env.E2E_USER || 'superadmin';
const PASS = process.env.E2E_PASS || 'RootWarden@2026-Sec!';
const SECRET = process.env.E2E_TOTP_SECRET || '';

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function sleep(ms){return new Promise(r=>setTimeout(r,ms))}

let failures = 0;
function check(label, ok) { console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`); if (!ok) failures++; }

const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
});
const page = (await browser.pages())[0];
page.setDefaultTimeout(30000);
const jsErrors = [];
page.on('pageerror', e => jsErrors.push(String(e)));

// Une page est saine si elle rend sans trace d'erreur PHP.
async function visit(url) {
    const resp = await page.goto(url, { waitUntil: 'networkidle2' });
    const body = await page.evaluate(() => document.body.innerText);
    return {
        status: resp?.status(),
        phpError: /Fatal error|Parse error|Warning:|Notice:|Undefined (variable|index|array key)/.test(body),
        body,
    };
}

try {
    // ── Login ───────────────────────────────────────────────────────────────
    await page.goto(`${BASE}/auth/login.php`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', USER, { delay: 10 });
    await page.type('input[name="password"]', PASS, { delay: 10 });
    { const n = page.waitForNavigation({ waitUntil: 'networkidle2' }); await page.click('button[type="submit"]'); await n; }
    if (page.url().includes('verify_2fa')) {
        const rem = 30 - (Math.floor(Date.now()/1000) % 30);
        if (rem < 6) await sleep(rem*1000+500);
        await page.type('input[name="2fa_code"]', totp(SECRET), { delay: 10 });
        const n = page.waitForNavigation({ waitUntil: 'networkidle2' }); await page.click('button[type="submit"]'); await n;
    }
    // L'ecran CGU porte desormais une verification CSRF : il doit toujours s'accepter.
    if (page.url().includes('terms')) {
        const btn = await page.$('button[name="accept_terms"]');
        check('[terms] CSRF ajoute : acceptation des CGU toujours fonctionnelle', !!btn);
        if (btn) { const n = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 8000 }); await btn.click(); try { await n; } catch {} }
        check('[terms] redirection apres acceptation', !page.url().includes('terms'));
    } else {
        console.log('INFO  CGU deja acceptees pour cette session (test terms ignore)');
    }
    check('login complet aboutit au dashboard', /index\.php|:8443\/$/.test(page.url()));

    // ── Pages dont les requetes SQL ont change (SELECT * -> colonnes explicites)
    let r = await visit(`${BASE}/adm/admin_page.php`);
    check('[adm] admin_page rend en 200', r.status === 200);
    check('[adm] aucune erreur PHP (colonnes explicites OK)', !r.phpError);
    // La liste des serveurs doit toujours etre peuplee (colonnes name/ip presentes).
    // NB : on lit le HTML et non innerText — l'onglet "Serveurs" n'est pas actif
    // par defaut et innerText ignore le texte des elements masques.
    const admServers = await page.evaluate(() => {
        const html = document.documentElement.innerHTML;
        return {
            hasName: /test-server|srv-/.test(html),
            rows: document.querySelectorAll('tbody tr').length,
        };
    });
    check('[adm] les noms de serveurs sont toujours rendus', admServers.hasName);
    check('[adm] le tableau contient des lignes', admServers.rows > 0);

    r = await visit(`${BASE}/security/compliance_report.php`);
    check('[compliance] rend en 200', r.status === 200);
    check('[compliance] aucune erreur PHP', !r.phpError);

    r = await visit(`${BASE}/ssh-audit/`);
    check('[ssh-audit] rend en 200', r.status === 200);
    check('[ssh-audit] aucune erreur PHP (cloisonnement ajoute)', !r.phpError);
    // Superadmin : le selecteur doit lister les machines
    const auditOptions = await page.evaluate(() =>
        document.querySelectorAll('#server option').length);
    check('[ssh-audit] selecteur de serveurs peuple pour un superadmin', auditOptions > 1);

    // `update/` a ete porte sur Laravel puis archive le 2026-08-20. Le controle
    // de non-regression devient le TEMOIN de cet archivage : la page ne doit
    // plus repondre du tout.
    r = await visit(`${BASE}/update/`);
    check('[update] archive : ne repond plus (404)', r.status === 404);

    // ── Export CVE : le superadmin doit toujours pouvoir exporter ───────────
    const exportStatus = await page.evaluate(async (base) => {
        const resp = await fetch(`${base}/security/cve_export.php?machine_id=2`, { credentials: 'same-origin' });
        return { status: resp.status, ct: resp.headers.get('content-type') || '' };
    }, BASE);
    check('[cve_export] superadmin : export toujours autorise (200 ou 404 si pas de scan)',
        exportStatus.status === 200 || exportStatus.status === 404);

    // ── Scripts de migration : refuses en HTTP ──────────────────────────────
    for (const s of ['migrate_crypto', 'migrate_totp']) {
        const st = await page.evaluate(async (base, name) => {
            const resp = await fetch(`${base}/auth/${name}.php`, { credentials: 'same-origin' });
            return resp.status;
        }, BASE, s);
        check(`[${s}] refuse en HTTP (403)`, st === 403);
    }

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
