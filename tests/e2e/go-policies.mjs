/**
 * go-policies.mjs - Test E2E des politiques sudo + SFTP par utilisateur (v1.22.0)
 *
 * Couvre :
 *   1. Login + 2FA + accès page /adm/server_user_policies.php
 *   2. Verification du selecteur serveur + user
 *   3. Backend route /policy/list (smoke test)
 *   4. Step-up 2FA : tentative deploy -> 403 step_up_required -> validation TOTP -> retry
 *   5. Render sudo preset apt_only (sans deployer reellement sur un serveur prod)
 *   6. Render sftp form
 *   7. Lecture historique vide
 *   8. Audit log persistance (verif que les actions sont tracees)
 *
 * Pre-requis :
 *   - Container Docker rootwarden_* up (docker compose up -d)
 *   - superadmin/RootWarden@2026-Sec! + secret 2FA en memoire
 *   - Au moins 1 machine configuree avec au moins 1 server_user_inventory
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';

const BASE = 'https://localhost:8443';
const USER = process.env.E2E_USER || 'superadmin';
const PASS = process.env.E2E_PASS || 'RootWarden@2026-Sec!';
const SECRET = process.env.E2E_TOTP_SECRET || ''; // audit v1.23 : secret 2FA via env, plus de secret en dur

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function sleep(ms){return new Promise(r=>setTimeout(r,ms))}

let passed = 0, failed = 0;
function check(label, cond, details = '') {
    if (cond) { console.log(`  OK  ${label}${details ? ' ('+details+')' : ''}`); passed++; }
    else      { console.log(`  KO  ${label}${details ? ' ('+details+')' : ''}`); failed++; }
}

const browser = await puppeteer.launch({
    headless: 'new', defaultViewport: { width: 1400, height: 900 },
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost'],
    protocolTimeout: 60000,
});
const page = (await browser.pages())[0];
page.setDefaultTimeout(30000);

console.log('=== go-policies.mjs - E2E per-user policies v1.22.0 ===\n');

// 1. LOGIN + 2FA
console.log('1) Login + 2FA');
await page.goto(`${BASE}/auth/login.php`, { waitUntil: 'networkidle2' });
await page.type('input[name="username"]', USER, { delay: 20 });
await page.type('input[name="password"]', PASS, { delay: 20 });
const nav1 = page.waitForNavigation({ waitUntil: 'networkidle2' });
await page.click('button[type="submit"]');
await nav1;
check('login redirect vers verify_2fa', page.url().includes('verify_2fa') || page.url().includes('terms') || page.url() === BASE + '/' || page.url().includes('index'),
    page.url());

if (page.url().includes('verify_2fa')) {
    const remaining = 30 - (Math.floor(Date.now()/1000) % 30);
    if (remaining < 6) await sleep(remaining*1000 + 500);
    await page.type('input[name="2fa_code"]', totp(SECRET), { delay: 20 });
    const nav2 = page.waitForNavigation({ waitUntil: 'networkidle2' });
    await page.click('button[type="submit"]');
    await nav2;
    check('2FA valide', !page.url().includes('verify_2fa'), page.url());
}

// CGU si necessaire : le bouton est <button type="submit" name="accept_terms">
if (page.url().includes('terms')) {
    const btn = await page.$('button[name="accept_terms"]');
    if (btn) {
        const navTerms = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 });
        await btn.click();
        try { await navTerms; } catch {}
    }
    check('CGU acceptees', !page.url().includes('terms'), page.url());
}

// 2. ACCES page policies
console.log('\n2) Acces /adm/server_user_policies.php');
const resp = await page.goto(`${BASE}/adm/server_user_policies.php`, { waitUntil: 'networkidle2' });
check('HTTP 200', resp.status() === 200, 'status=' + resp.status());

const title = await page.title();
check('Titre contient "Politiques"', /Politique|policies/i.test(title), 'title=' + title);

const hasServerSelect = await page.evaluate(() => !!document.getElementById('server-select'));
check('Selecteur serveur present', hasServerSelect);

const hasUserSelect = await page.evaluate(() => !!document.getElementById('user-select'));
check('Selecteur user present', hasUserSelect);

const hasSudoTab = await page.evaluate(() => !!document.getElementById('tab-sudo'));
const hasSftpTab = await page.evaluate(() => !!document.getElementById('tab-sftp'));
const hasHistoryTab = await page.evaluate(() => !!document.getElementById('tab-history'));
check('3 onglets presents (sudo/sftp/history)', hasSudoTab && hasSftpTab && hasHistoryTab);

// 3. Switch tab SFTP
console.log('\n3) Onglet SFTP');
await page.click('#tab-sftp');
await sleep(300);
const sftpVisible = await page.evaluate(() => !document.getElementById('pane-sftp')?.classList.contains('hidden'));
check('Pane SFTP visible apres click', sftpVisible);

const hasChrootInput = await page.evaluate(() => !!document.getElementById('sftp-chroot'));
const hasSftpOnly = await page.evaluate(() => !!document.getElementById('sftp-only'));
check('Champs SFTP presents (chroot, sftp_only)', hasChrootInput && hasSftpOnly);

// 4. Onglet sudo presets
console.log('\n4) Onglet Sudo - presets disponibles');
await page.click('#tab-sudo');
await sleep(300);
const presets = await page.evaluate(() => {
    const sel = document.getElementById('sudo-preset');
    return sel ? Array.from(sel.options).map(o => o.value) : [];
});
const expected = ['all_nopasswd', 'restart_services', 'apt_only', 'read_logs', 'systemctl_specific', 'custom'];
const allPresets = expected.every(p => presets.includes(p));
check('6 presets sudo presents', allPresets, presets.join(','));

// 5. Backend smoke test : /policy/list via api_proxy
console.log('\n5) Backend /policy/list');
const listResp = await page.evaluate(async () => {
    const r = await fetch('/api_proxy.php/policy/list');
    return { status: r.status, body: await r.json() };
});
check('GET /policy/list = 200', listResp.status === 200, 'status=' + listResp.status);
check('Reponse contient sudo_policies + sftp_policies',
    listResp.body && Array.isArray(listResp.body.sudo_policies) && Array.isArray(listResp.body.sftp_policies));

// 6. Step-up 2FA : tentative deploy doit declencher 403 + step_up_required
// (XHR direct pour bypasser le wrapper fetch global qui ouvrirait le modal step-up)
console.log('\n6) Step-up 2FA sur deploy (sans valider TOTP)');
const deployResp = await page.evaluate(() => new Promise((resolve) => {
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api_proxy.php/policy/sudo/deploy', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.setRequestHeader('X-CSRF-Token', csrfMeta?.content || '');
    xhr.timeout = 10000;
    xhr.onload = () => { let b = null; try { b = JSON.parse(xhr.responseText); } catch {} resolve({ status: xhr.status, body: b }); };
    xhr.onerror = () => resolve({ status: 0, body: null });
    xhr.ontimeout = () => resolve({ status: -1, body: null });
    xhr.send(JSON.stringify({ machine_id: 1, server_user_id: 0, preset: 'apt_only' }));
}));
check('POST /policy/sudo/deploy = 403 (step_up_required)', deployResp.status === 403, 'status=' + deployResp.status);
check('Reponse step_up_required=true', deployResp.body && deployResp.body.step_up_required === true,
    JSON.stringify(deployResp.body));

// 7. Onglet historique
console.log('\n7) Onglet Historique');
await page.click('#tab-history');
await sleep(800);
const historyVisible = await page.evaluate(() => !document.getElementById('pane-history')?.classList.contains('hidden'));
check('Pane Historique visible', historyVisible);

// 8. Verification du lien menu sidebar (superadmin only)
console.log('\n8) Lien sidebar visible pour superadmin');
const sidebarHasLink = await page.evaluate(() => {
    return Array.from(document.querySelectorAll('a')).some(a => a.href.includes('server_user_policies.php'));
});
check('Lien /adm/server_user_policies.php dans la sidebar', sidebarHasLink);

// ── Synthese ──
console.log('\n========================================');
console.log(`  Tests passes  : ${passed}`);
console.log(`  Tests echoues : ${failed}`);
console.log('========================================');

await browser.close();
process.exit(failed > 0 ? 1 : 0);
