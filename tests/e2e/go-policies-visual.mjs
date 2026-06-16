/**
 * go-policies-visual.mjs - Variante visuelle de go-policies.mjs avec screenshots.
 * Navigateur visible, screenshots a chaque etape, reste ouvert a la fin.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { mkdirSync } from 'fs';

const BASE = 'https://localhost:8443';
const USER = process.env.E2E_USER || 'superadmin';
const PASS = process.env.E2E_PASS || 'RootWarden@2026-Sec!';
const SECRET = process.env.E2E_TOTP_SECRET || ''; // audit v1.23 : secret 2FA via env, plus de secret en dur
const SHOTS = './screenshots/policies';
mkdirSync(SHOTS, { recursive: true });

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function sleep(ms){return new Promise(r=>setTimeout(r,ms))}

let step = 0;
async function shot(page, name) {
    step++;
    const path = `${SHOTS}/${String(step).padStart(2,'0')}_${name}.png`;
    await page.screenshot({ path, fullPage: false });
    console.log(`  shot -> ${path}`);
}

const browser = await puppeteer.launch({
    headless: false, defaultViewport: null,
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    protocolTimeout: 60000,
});
const page = (await browser.pages())[0];
page.setDefaultTimeout(30000);

console.log('=== Test VISUEL - per-user policies v1.22.0 ===\n');

// 1. LOGIN
await page.goto(`${BASE}/auth/login.php`, { waitUntil: 'networkidle2' });
await shot(page, 'login');
await page.type('input[name="username"]', USER, { delay: 20 });
await page.type('input[name="password"]', PASS, { delay: 20 });
const n1 = page.waitForNavigation({ waitUntil: 'networkidle2' });
await page.click('button[type="submit"]');
await n1;

// 2FA
if (page.url().includes('verify_2fa')) {
    const rem = 30 - (Math.floor(Date.now()/1000) % 30);
    if (rem < 6) await sleep(rem*1000 + 500);
    await page.type('input[name="2fa_code"]', totp(SECRET), { delay: 20 });
    const n2 = page.waitForNavigation({ waitUntil: 'networkidle2' });
    await page.click('button[type="submit"]');
    await n2;
}

// CGU
if (page.url().includes('terms')) {
    const btn = await page.$('button[name="accept_terms"]');
    if (btn) {
        const nT = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 8000 });
        await btn.click();
        try { await nT; } catch {}
    }
}

await shot(page, 'logged_in');

// 2. ACCES page policies
console.log('\n--- Page server_user_policies ---');
await page.goto(`${BASE}/adm/server_user_policies.php`, { waitUntil: 'networkidle2' });
await sleep(500);
await shot(page, 'policies_sudo_tab');

// 3. Onglet SFTP
console.log('\n--- Switch onglet SFTP ---');
await page.click('#tab-sftp');
await sleep(500);
await shot(page, 'policies_sftp_tab');

// 4. Onglet Historique
console.log('\n--- Switch onglet Historique ---');
await page.click('#tab-history');
await sleep(1000);  // pour laisser loadHistory() finir
await shot(page, 'policies_history_tab');

// 5. Test step-up via clic deploy (sans complete TOTP modal)
console.log('\n--- Click deploy (declenche step-up modal) ---');
await page.click('#tab-sudo');
await sleep(300);
await page.click('button[onclick="deployPolicy(\'sudo\')"]');
await sleep(2500);  // laisse le modal s'afficher
await shot(page, 'policies_stepup_modal');

// 6. Annule le modal
console.log('\n--- Cancel modal step-up ---');
const cancelBtn = await page.$('#rw-stepup-cancel');
if (cancelBtn) await cancelBtn.click();
await sleep(800);
await shot(page, 'policies_after_cancel');

// 7. Audit (lit le serveur) - declenche pas step-up car GET-like
console.log('\n--- Audit policy (lit /etc/sudoers.d/...) ---');
await page.click('button[onclick="auditPolicy(\'sudo\')"]');
await sleep(1500);
await shot(page, 'policies_audit_output_with_toast');

// 7b. Verifier qu'un toast est apparu
const toastVisible = await page.evaluate(() => {
    const toasts = document.querySelectorAll('#toast-container .toast');
    return Array.from(toasts).map(t => ({ text: t.textContent.trim(), classes: t.className }));
});
console.log('  Toasts detectes :', JSON.stringify(toastVisible));

console.log('\n=== Navigateur reste ouvert. Ctrl+C pour fermer. ===\n');
console.log(`Screenshots dans : ${SHOTS}\n`);

await new Promise(() => {});
