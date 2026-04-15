/**
 * go-quick.mjs — Login + 2FA + password change + go to admin
 * Navigateur visible, reste ouvert sur admin_page.php
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';

const BASE = 'https://localhost:8443';
const USER = 'superadmin';
const PASS = 'superadmin';
const NEW_PASS = 'RootWarden@2026-Sec!';

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function sleep(ms){return new Promise(r=>setTimeout(r,ms))}

const browser = await puppeteer.launch({
  headless:false, defaultViewport:null,
  args:['--ignore-certificate-errors','--allow-insecure-localhost','--window-size=1440,900'],
});
const page = (await browser.pages())[0];
page.setDefaultTimeout(30000);

// 1. LOGIN
console.log('Login...');
await page.goto(`${BASE}/auth/login.php`, {waitUntil:'networkidle2'});
await page.type('input[name="username"]', USER, {delay:30});
await page.type('input[name="password"]', PASS, {delay:30});
const nav1 = page.waitForNavigation({waitUntil:'networkidle2'});
await page.click('button[type="submit"]');
await nav1;
console.log('  ->', page.url());

// 2. 2FA ENROLLMENT
if (page.url().includes('enable_2fa')) {
  console.log('2FA enrollment...');
  await sleep(1000);
  await page.evaluate(() => { const d = document.querySelector('details'); if(d) d.open=true; });
  await sleep(300);
  const secret = await page.evaluate(() => {
    for (const e of document.querySelectorAll('.font-mono')) {
      const t = e.textContent.trim().replace(/\s/g,'');
      if (/^[A-Z2-7]{32,}$/.test(t)) return t;
    }
    return null;
  });
  if (secret) {
    const remaining = 30 - (Math.floor(Date.now()/1000) % 30);
    if (remaining < 6) { console.log(`  Attente ${remaining}s...`); await sleep(remaining*1000+500); }
    const code = totp(secret);
    console.log(`  Code: ${code}`);
    await page.evaluate(c => { document.querySelector('input[name="2fa_code"]').value = c; }, code);
    const nav2 = page.waitForNavigation({waitUntil:'networkidle2'});
    await page.click('button[type="submit"]');
    await nav2;
    console.log('  ->', page.url());
  } else { console.log('  SECRET NON TROUVE'); }
}

// 3. CGU
if (page.url().includes('terms')) {
  console.log('CGU...');
  await page.evaluate(() => { for(const b of document.querySelectorAll('button')) if(b.textContent.includes('accepte')){b.click();return;} });
  try { await page.waitForNavigation({waitUntil:'networkidle2',timeout:10000}); } catch{}
}

// 4. PASSWORD CHANGE
if (page.url().includes('force_change') || page.url().includes('profile.php')) {
  console.log('Changement mot de passe...');
  await sleep(500);
  await page.type('input[name="current_password"]', PASS, {delay:30});
  await page.type('input[name="new_password"]', NEW_PASS, {delay:30});
  await page.type('input[name="confirm_password"]', NEW_PASS, {delay:30});
  await sleep(300);
  const btn = await page.evaluateHandle(() => {
    for(const f of document.querySelectorAll('form')){
      if(f.querySelector('input[name="current_password"]')) return f.querySelector('button[type="submit"]');
    }
    return null;
  });
  if (btn?.asElement()) {
    await btn.asElement().click();
    try { await page.waitForNavigation({waitUntil:'networkidle2',timeout:15000}); } catch{}
  }
  await sleep(500);
  console.log('  ->', page.url());
  console.log(`  Nouveau mdp: ${NEW_PASS}`);
}

// 5. GO TO ADMIN
console.log('Navigation vers admin...');
await page.goto(`${BASE}/adm/admin_page.php`, {waitUntil:'networkidle2'});
console.log('  ->', page.url());
console.log('\n=== Navigateur ouvert sur admin. Ctrl+C pour fermer. ===\n');

await new Promise(() => {});
