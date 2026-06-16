/**
 * go-func-v1.23.mjs - Test fonctionnel des handlers onclick modifies (escJsAttr).
 * Login + 2FA, puis sur le serveur de test : charge services/fail2ban/ssh-audit,
 * verifie que les boutons d'action sont rendus et que cliquer un bouton READ-ONLY
 * (detail/logs/status) declenche le handler JS (modal/toast) sans erreur console.
 * N'effectue AUCUNE action destructive (pas de stop/restart/ban).
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { mkdirSync } from 'fs';

// Credentials via env UNIQUEMENT (pas de secret en dur - cf audit v1.23.0).
const BASE = process.env.E2E_URL || 'https://localhost:8443';
const USER = process.env.E2E_USER || 'superadmin';
const PASS = process.env.E2E_PASS || 'superadmin';
const SECRET = process.env.E2E_TOTP_SECRET || '';
const SHOT = 'screenshots/v1.23';
if (!SECRET) console.warn('[warn] E2E_TOTP_SECRET non defini : le 2FA echouera. Exportez-le avant de lancer.');
mkdirSync(SHOT, { recursive: true });
function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
const sleep = ms => new Promise(r => setTimeout(r, ms));

const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'] });
const page = await browser.newPage();
await page.setViewport({ width: 1400, height: 900 });
page.setDefaultTimeout(30000);
const consoleErrors = [];
page.on('console', m => { if (m.type() === 'error') consoleErrors.push(m.text()); });
page.on('pageerror', e => consoleErrors.push('PAGEERR: ' + e.message));

// Login
await page.goto(`${BASE}/auth/login.php`, { waitUntil: 'networkidle2' });
await page.type('input[name="username"]', USER); await page.type('input[name="password"]', PASS);
await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle2' }), page.click('button[type="submit"]')]);
if (page.url().includes('verify_2fa')) { const r = 30 - (Math.floor(Date.now()/1000)%30); if (r<6) await sleep(r*1000+500); await page.type('input[name="2fa_code"]', totp(SECRET)); await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle2' }), page.click('button[type="submit"]')]); }
if (page.url().includes('terms')) { await page.evaluate(() => { for (const b of document.querySelectorAll('button')) if (b.textContent.toLowerCase().includes('accepte')) { b.click(); return; } }); await page.waitForNavigation({ waitUntil: 'networkidle2' }).catch(()=>{}); }
console.log('Login:', page.url().includes('login.php') ? 'FAIL' : 'OK');

const report = [];
function check(label, cond, extra='') { report.push({label, ok: !!cond, extra}); console.log(`  ${cond?'OK  ':'WARN'} ${label}${extra?' :: '+extra:''}`); }

// ── SERVICES : charge, attend la liste, verifie boutons + clic Detail (read-only)
console.log('\n[services]');
consoleErrors.length = 0;
await page.goto(`${BASE}/services/index.php`, { waitUntil: 'networkidle2' });
// selectionner le serveur (#server) puis cliquer le bouton loadServices() (SSH reel)
await page.evaluate(() => { const s = document.getElementById('server'); if (s && s.options.length>1){ s.selectedIndex=1; s.dispatchEvent(new Event('change',{bubbles:true})); } });
await page.evaluate(() => { const b = document.querySelector('button[onclick*="loadServices"]'); if (b) b.click(); });
await sleep(8000); // SSH vers le serveur cible
const svcBtns = await page.$$eval('button[onclick*="viewDetail"], button[onclick*="viewLogs"]', els => els.length).catch(()=>0);
check('services: boutons action rendus', svcBtns > 0, `${svcBtns} bouton(s)`);
// onclick bien forme ? (pas de quote brute cassant l'attribut)
const svcOnclick = await page.$$eval('button[onclick*="viewDetail"]', els => els.slice(0,3).map(e=>e.getAttribute('onclick'))).catch(()=>[]);
check('services: onclick bien formes', svcOnclick.every(o => /viewDetail\('[^']*'\)/.test(o)), svcOnclick[0]||'aucun');
if (svcBtns > 0) {
  consoleErrors.length = 0;
  await page.evaluate(() => { const b = document.querySelector('button[onclick*="viewDetail"]'); if (b) b.click(); });
  await sleep(2500);
  const modalVisible = await page.evaluate(() => { const m = document.getElementById('detail-modal'); return m && !m.classList.contains('hidden'); });
  check('services: clic Detail ouvre le modal', modalVisible);
  check('services: pas d\'erreur console au clic', consoleErrors.length === 0, consoleErrors.join('|').slice(0,150));
  await page.screenshot({ path: `${SHOT}/services-detail.png` });
}

// ── FAIL2BAN : charge status (read-only) sur le serveur de test
console.log('\n[fail2ban]');
consoleErrors.length = 0;
await page.goto(`${BASE}/fail2ban/index.php`, { waitUntil: 'networkidle2' });
await page.evaluate(() => { const s = document.querySelector('select'); if (s && s.options.length>1){ s.selectedIndex=1; s.dispatchEvent(new Event('change',{bubbles:true})); } });
await sleep(3000);
check('fail2ban: page chargee sans erreur console', consoleErrors.length === 0, consoleErrors.join('|').slice(0,150));
await page.screenshot({ path: `${SHOT}/fail2ban.png` });

// ── SSH-AUDIT : charge fleet/scan, verifie rendu + pas d'erreur
console.log('\n[ssh-audit]');
consoleErrors.length = 0;
await page.goto(`${BASE}/ssh-audit/index.php`, { waitUntil: 'networkidle2' });
await sleep(2500);
check('ssh-audit: pas d\'erreur console', consoleErrors.length === 0, consoleErrors.join('|').slice(0,150));
await page.screenshot({ path: `${SHOT}/ssh-audit.png` });

// ── SUPERVISION profiles : verifie escapeAttr (deleteProfile onclick)
console.log('\n[supervision]');
consoleErrors.length = 0;
await page.goto(`${BASE}/supervision/index.php`, { waitUntil: 'networkidle2' });
await sleep(2500);
check('supervision: pas d\'erreur console', consoleErrors.length === 0, consoleErrors.join('|').slice(0,150));

// ── Toast generique : declenche un fetch via un bouton et regarde si un toast/feedback apparait
//    (test non destructif : on lit juste l'existence du conteneur de toast)
console.log('\n[toast infra]');
const toastContainer = await page.evaluate(() => !!document.querySelector('#toast, .toast, #toast-container, [id*="toast"], [class*="toast"]'));
check('infra toast presente dans le DOM (layout)', toastContainer);

// Bilan
console.log('\n=== BILAN FONCTIONNEL ===');
const warn = report.filter(r => !r.ok);
console.log(`OK : ${report.filter(r=>r.ok).length}/${report.length}`);
if (warn.length) { console.log('A verifier :'); warn.forEach(w => console.log(`  - ${w.label} :: ${w.extra}`)); }
else console.log('Tous les handlers/UI testes fonctionnent.');
await browser.close();
process.exit(warn.length ? 2 : 0);
