/**
 * go-sec-v1.23.mjs - Regression post-audit securite v1.23.0.
 * Login + 2FA, puis parcourt toutes les pages touchees par les correctifs en
 * capturant : status HTTP, erreurs PHP (Fatal/Warning/Notice) dans le body,
 * erreurs console JS. Screenshots des pages cles.
 * Credentials via env (E2E_PASS / E2E_TOTP_SECRET) sinon valeurs dev locales.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { mkdirSync } from 'fs';

// Credentials via env UNIQUEMENT (pas de secret en dur - cf audit v1.23.0).
//   E2E_USER (defaut superadmin), E2E_PASS, E2E_TOTP_SECRET
// Ex: E2E_PASS='...' E2E_TOTP_SECRET='...' node go-sec-v1.23.mjs
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

// Marqueurs PHP non ambigus (evite les faux positifs type `warning:` dans du JS).
const PHP_ERR = /(Fatal error:|Parse error:|Uncaught [A-Za-z]*Error|on line \d+|Stack trace:|call to a member function|Undefined (variable|array key|property))/;

const browser = await puppeteer.launch({
  headless: true,
  args: ['--no-sandbox', '--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
});
const page = await browser.newPage();
await page.setViewport({ width: 1400, height: 900 });
page.setDefaultTimeout(30000);

const consoleErrors = [];
page.on('console', m => { if (m.type() === 'error') consoleErrors.push(m.text()); });
page.on('pageerror', e => consoleErrors.push('PAGEERROR: ' + e.message));

const results = [];
let curLabel = '';
async function visit(label, path, shot = false) {
  curLabel = label;
  consoleErrors.length = 0;
  let status = 'ERR', phpErr = false, body = '';
  try {
    const resp = await page.goto(BASE + path, { waitUntil: 'networkidle2' });
    status = resp ? resp.status() : 'noresp';
    body = await page.content();
    phpErr = PHP_ERR.test(body.replace(/<[^>]+>/g, ' '));
    if (shot) await page.screenshot({ path: `${SHOT}/${label}.png`, fullPage: false });
  } catch (e) { status = 'EXC:' + e.message.slice(0, 60); }
  const jsErr = [...consoleErrors];
  const ok = (status === 200) && !phpErr && jsErr.length === 0;
  results.push({ label, path, status, phpErr, jsErr, ok });
  console.log(`  ${ok ? 'OK  ' : 'WARN'} [${status}] ${label}${phpErr ? ' PHP-ERR' : ''}${jsErr.length ? ' JS:' + jsErr.length : ''}`);
  return body;
}

console.log('=== Regression securite v1.23.0 ===\n');

// 1. Login + 2FA
console.log('1) Login + 2FA');
await page.goto(`${BASE}/auth/login.php`, { waitUntil: 'networkidle2' });
await page.type('input[name="username"]', USER, { delay: 20 });
await page.type('input[name="password"]', PASS, { delay: 20 });
await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle2' }), page.click('button[type="submit"]')]);
console.log('   ->', page.url());
if (page.url().includes('verify_2fa')) {
  const rem = 30 - (Math.floor(Date.now() / 1000) % 30);
  if (rem < 6) { await sleep(rem * 1000 + 500); }
  await page.type('input[name="2fa_code"]', totp(SECRET), { delay: 20 });
  await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle2' }), page.click('button[type="submit"]')]);
  console.log('   -> 2FA ->', page.url());
}
if (page.url().includes('terms')) {
  await page.evaluate(() => { for (const b of document.querySelectorAll('button')) if (b.textContent.toLowerCase().includes('accepte')) { b.click(); return; } });
  await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {});
  console.log('   -> CGU ->', page.url());
}
const loggedIn = !page.url().includes('login.php');
console.log('   Login:', loggedIn ? 'OK' : 'FAIL');
if (!loggedIn) { await browser.close(); process.exit(1); }

// 2. Pages touchees par les correctifs
console.log('\n2) Pages modifiees (200 + 0 erreur PHP/JS attendu)');
await visit('dashboard', '/index.php', true);            // remStats fix
await visit('notifications', '/notifications.php');       // href fix
await visit('profile', '/profile.php');                   // session invalidation
await visit('admin', '/adm/admin_page.php', true);        // manage_users/roles/access
await visit('health_check', '/adm/health_check.php', true); // routes mutantes -> machine_id=0
await visit('server_user_policies', '/adm/server_user_policies.php', true); // API_KEY retiree
await visit('ssh', '/ssh/index.php', true);               // json_encode flags
await visit('ssh_audit', '/ssh-audit/index.php', true);   // json_encode + escJsAttr
await visit('fail2ban', '/fail2ban/index.php', true);     // escJsAttr
await visit('services', '/services/index.php', true);     // escJsAttr (name)
await visit('iptables', '/iptables/index.php');
await visit('supervision', '/supervision/index.php', true); // profiles escapeAttr
await visit('graylog', '/graylog/index.php');             // escJsAttr
await visit('wazuh', '/wazuh/index.php');                 // escJsAttr
await visit('bashrc', '/bashrc/index.php');               // escJsAttr
await visit('cve', '/security/index.php');                // cve_compare
await visit('update', '/update/index.php');
await visit('documentation', '/documentation.php');       // sous-section v1.23.0+

// 3. Inspection ciblee : API_KEY ne doit PAS etre dans le DOM de policies
console.log('\n3) Verifs ciblees');
const polBody = await page.goto(`${BASE}/adm/server_user_policies.php`, { waitUntil: 'networkidle2' }).then(() => page.content());
const apiKeyLeak = /const\s+API_KEY\s*=/.test(polBody);
console.log(`   ${!apiKeyLeak ? 'OK  ' : 'FAIL'} API_KEY absente du DOM (server_user_policies)`);

// 4. health_check : recuperer le tableau de statuts rendu (les routes mutantes
//    sur machine_id=0 doivent renvoyer <500, pas casser la page)
const hcBody = await page.goto(`${BASE}/adm/health_check.php`, { waitUntil: 'networkidle2' }).then(() => page.content());
const has500 = /\b50[0-9]\b/.test(await page.evaluate(() => {
  // recupere les codes affiches dans les badges de statut s'ils existent
  return Array.from(document.querySelectorAll('td,span,div')).map(e => e.textContent).join(' ');
}));
console.log(`   ${!has500 ? 'OK  ' : 'INFO'} health_check : pas de 5xx visible dans les badges`);

// Bilan
console.log('\n=== BILAN ===');
const warn = results.filter(r => !r.ok);
console.log(`Pages OK : ${results.filter(r => r.ok).length}/${results.length}`);
if (warn.length) {
  console.log('Anomalies :');
  for (const w of warn) {
    console.log(`  - ${w.label} [${w.status}]${w.phpErr ? ' PHP-ERR' : ''}${w.jsErr.length ? ' JS=' + JSON.stringify(w.jsErr).slice(0, 200) : ''}`);
  }
} else {
  console.log('Aucune anomalie (HTTP/PHP/JS) sur les pages modifiees.');
}
console.log(`Verifs : API_KEY-leak=${apiKeyLeak ? 'FAIL' : 'OK'}, health_check-5xx=${has500 ? 'INFO' : 'OK'}`);
console.log(`Screenshots : tests/e2e/${SHOT}/`);

await browser.close();
process.exit(warn.length || apiKeyLeak ? 2 : 0);
