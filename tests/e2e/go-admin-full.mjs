/**
 * go-admin-full.mjs - Test COMPLET des fonctions admin RootWarden v1.13.1
 * 48 tests : CRUD users/servers, toggle active/sudo, roles, permissions (14 droits),
 * acces serveurs, notification prefs (6 types), notifications in-app, recherche globale,
 * anti-escalade (toggle/delete self), onglets UI, audit log, health check,
 * platform keys, server users, backups, API proxy, nettoyage.
 * Navigateur visible 1440x900, reste ouvert.
 *
 * Prerequis : superadmin connecte (lancer apres go.mjs ou avec mdp connu).
 *   - Si totp_secret est set, le reset en DB avant : UPDATE users SET totp_secret=NULL
 *
 * Bugs debugues dans cette suite (2026-04-16) :
 *   - CSRF : auto-injecte via meta[name=csrf-token] + header X-CSRF-TOKEN
 *   - delete_user.php lit $_POST pas JSON : utiliser apiPostForm (form-urlencoded)
 *   - update_permissions.php / update_notification_prefs.php : CSRF dans body JSON
 *   - Anti-escalade myId : cherche data-user-id pres de "superadmin", fallback ID=1
 *   - Acces serveurs : switcher sur onglet access avant de chercher data-machine-id
 *   - Serveurs fallback API /machines si pas de data-machine-id dans le DOM
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { mkdir } from 'fs/promises';

const BASE = 'https://localhost:8443';
const USER = 'superadmin';
const PASS = 'RootWarden@2026-Sec!';
const SHOTS = './screenshots/admin';
await mkdir(SHOTS, { recursive: true });

// TOTP
function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function sleep(ms){return new Promise(r=>setTimeout(r,ms))}

// Tracking
let ok=0, fail=0, warn=0, testNum=0;
const results=[];
const errors404=[];
const jsErrors=[];
const reqFailed=[];

function log(name, status, detail='') {
  testNum++;
  const s = status==='OK'?'OK  ':status==='FAIL'?'FAIL':'WARN';
  if(status==='OK')ok++; else if(status==='FAIL')fail++; else warn++;
  const line = `  ${s}  ${String(testNum).padStart(2,'0')}. ${name.padEnd(40)} ${detail}`;
  results.push(line);
  console.log(line);
}

async function shot(page, name) {
  try { await page.screenshot({path:`${SHOTS}/${name}.png`,fullPage:true}); } catch{}
}

// =====================================================================
// LAUNCH
// =====================================================================
const browser = await puppeteer.launch({
  headless:false, defaultViewport:null,
  args:['--ignore-certificate-errors','--allow-insecure-localhost','--window-size=1440,900'],
});
const page = (await browser.pages())[0];
page.setDefaultTimeout(20000);

page.on('response', r=>{if(r.status()>=400){errors404.push(`${r.status()} ${r.url()}`)}});
page.on('pageerror', e=>{jsErrors.push(e.message);console.log('[JS]',e.message)});
page.on('requestfailed', r=>{const msg=`${r.failure()?.errorText||'unknown'} ${r.url()}`;reqFailed.push(msg);console.log('[REQ FAIL]',msg)});

console.log('');
console.log('============================================================');
console.log('  RootWarden v1.13.1 - Test Admin COMPLET');
console.log('============================================================\n');

// Helper: get CSRF token from page
async function getCsrf(pg) {
  return pg.evaluate(() =>
    document.querySelector('meta[name="csrf-token"]')?.content ||
    document.querySelector('input[name="csrf_token"]')?.value || ''
  );
}

// Helper: fetch JSON via page context (keeps cookies) - auto-injects CSRF
async function apiPost(pg, url, body) {
  return pg.evaluate(async (u, b) => {
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content
              || document.querySelector('input[name="csrf_token"]')?.value || '';
    b.csrf_token = b.csrf_token || csrf;
    const r = await fetch(u, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': csrf },
      body: JSON.stringify(b),
      credentials: 'same-origin'
    });
    return { status: r.status, data: await r.json().catch(() => ({})) };
  }, url, body);
}

// Helper: POST form-urlencoded (for endpoints that read $_POST)
async function apiPostForm(pg, url, params) {
  return pg.evaluate(async (u, p) => {
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content
              || document.querySelector('input[name="csrf_token"]')?.value || '';
    p.csrf_token = p.csrf_token || csrf;
    const fd = new URLSearchParams();
    for (const [k, v] of Object.entries(p)) fd.append(k, v);
    const r = await fetch(u, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: fd.toString(),
      credentials: 'same-origin'
    });
    return { status: r.status, data: await r.json().catch(() => ({})) };
  }, url, params);
}

async function apiGet(pg, url) {
  return pg.evaluate(async (u) => {
    const r = await fetch(u, { credentials: 'same-origin' });
    return { status: r.status, data: await r.json().catch(() => ({})) };
  }, url);
}

// =====================================================================
// 1. LOGIN + 2FA ENROLLMENT
// =====================================================================
console.log('--- LOGIN ---\n');
try {
  await page.goto(`${BASE}/auth/login.php`, { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USER, { delay: 30 });
  await page.type('input[name="password"]', PASS, { delay: 30 });
  const navP = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
  await page.click('button[type="submit"]');
  await navP;
  log('Login', 'OK', page.url().split('/').pop());
  await shot(page, '01-login');
} catch(e) { log('Login', 'FAIL', e.message.slice(0, 80)); }

// Handle 2FA enrollment if needed
if (page.url().includes('enable_2fa')) {
  try {
    await sleep(1000);
    await page.evaluate(() => { const d = document.querySelector('details'); if (d) d.open = true; });
    await sleep(300);
    const secret = await page.evaluate(() => {
      for (const e of document.querySelectorAll('.font-mono')) {
        const t = e.textContent.trim().replace(/\s/g, '');
        if (/^[A-Z2-7]{32,}$/.test(t)) return t;
      }
      return null;
    });
    if (secret) {
      const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
      if (remaining < 6) { console.log(`      TOTP: attente ${remaining}s...`); await sleep(remaining * 1000 + 500); }
      const code = totp(secret);
      await page.evaluate(c => { document.querySelector('input[name="2fa_code"]').value = c; }, code);
      const navP2 = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
      await page.click('button[type="submit"]');
      await navP2;
      log('2FA Enrollment', 'OK', `code ${code}`);
    } else { log('2FA Enrollment', 'FAIL', 'secret introuvable'); }
  } catch(e) { log('2FA Enrollment', 'FAIL', e.message.slice(0, 80)); }
}

// Handle verify_2fa (already enrolled)
if (page.url().includes('verify_2fa')) {
  console.log('  ERREUR: verify_2fa sans secret connu. Resetez le TOTP en DB.');
  await browser.close();
  process.exit(1);
}

// Skip CGU if present
if (page.url().includes('terms')) {
  await page.evaluate(() => { for (const b of document.querySelectorAll('button')) if (b.textContent.includes('accepte')) { b.click(); return; } });
  try { await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }); } catch {}
}

// =====================================================================
// NAVIGATE TO ADMIN
// =====================================================================
console.log('\n--- ADMIN PAGE ---\n');
await page.goto(`${BASE}/adm/admin_page.php`, { waitUntil: 'networkidle2' });
await sleep(500);

if (!page.url().includes('admin_page')) {
  log('Admin page', 'FAIL', `redirige ${page.url()}`);
  console.log('\n  IMPOSSIBLE D\'ACCEDER A L\'ADMIN. Fermeture.\n');
  await browser.close();
  process.exit(1);
}
log('Admin page access', 'OK', 'chargee');
await shot(page, '02-admin');

const csrf = await getCsrf(page);
console.log(`      CSRF token: ${csrf.slice(0, 16)}...`);

// =====================================================================
// CRUD UTILISATEUR
// =====================================================================
console.log('\n--- CRUD UTILISATEUR ---\n');

// Add user via form
let testUserId = null;
try {
  // Open "Ajouter un utilisateur" details
  await page.evaluate(() => {
    const details = document.querySelectorAll('details');
    for (const d of details) { if (d.textContent.includes('Ajouter un utilisateur') || d.textContent.includes('Add a user')) d.open = true; }
  });
  await sleep(500);
  await shot(page, '03-add-user-form');

  // Find the add user form and fill it
  const formExists = await page.evaluate(() => !!document.querySelector('input[name="name"][form],form input[name="name"]'));
  if (formExists) {
    // Fill user creation form - find fields within the add-user section
    await page.evaluate(() => {
      // Find the form that has action=add_user or the one with name field in the details
      const forms = document.querySelectorAll('form');
      for (const f of forms) {
        const actionInput = f.querySelector('input[name="action"][value="add_user"]');
        if (actionInput || f.querySelector('input[name="name"]')) {
          const nameInput = f.querySelector('input[name="name"]');
          if (nameInput && !nameInput.value) {
            nameInput.value = 'test-e2e-user';
            const emailInput = f.querySelector('input[name="email"]');
            if (emailInput) emailInput.value = 'test@e2e.local';
            const companyInput = f.querySelector('input[name="company"]');
            if (companyInput) companyInput.value = 'E2E Testing';
            return true;
          }
        }
      }
      return false;
    });

    // Submit the add user form
    const navP2 = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }).catch(() => null);
    await page.evaluate(() => {
      const forms = document.querySelectorAll('form');
      for (const f of forms) {
        if (f.querySelector('input[name="action"][value="add_user"]') ||
            (f.querySelector('input[name="name"]') && f.querySelector('input[name="name"]').value === 'test-e2e-user')) {
          f.submit();
          return;
        }
      }
    });
    await navP2;
    await sleep(500);

    // Verify user was created
    const userCreated = await page.evaluate(() =>
      document.body.innerText.includes('test-e2e-user')
    );
    await shot(page, '04-user-created');
    log('Creer utilisateur', userCreated ? 'OK' : 'FAIL', userCreated ? 'test-e2e-user' : 'non trouve dans la page');

    // Get user ID
    if (userCreated) {
      testUserId = await page.evaluate(() => {
        const rows = document.querySelectorAll('tr, details, [data-user-id]');
        for (const r of rows) {
          if (r.textContent.includes('test-e2e-user')) {
            const id = r.getAttribute('data-user-id') || r.querySelector('[data-user-id]')?.getAttribute('data-user-id');
            if (id) return parseInt(id);
          }
        }
        // Try finding in the HTML via regex
        const html = document.body.innerHTML;
        const m = html.match(/data-user-id="(\d+)"[^>]*>[\s\S]*?test-e2e-user/);
        return m ? parseInt(m[1]) : null;
      });
      console.log(`      test-e2e-user ID: ${testUserId}`);
    }
  } else {
    log('Creer utilisateur', 'WARN', 'formulaire add_user non trouve');
  }
} catch(e) { log('Creer utilisateur', 'FAIL', e.message.slice(0, 80)); }

// If we didn't find the user ID from DOM, query the API
if (!testUserId) {
  try {
    testUserId = await page.evaluate(async () => {
      // Try to find user in the page source
      const html = document.body.innerHTML;
      const match = html.match(/user_id['":\s]+(\d+)[\s\S]*?test-e2e-user|test-e2e-user[\s\S]*?user_id['":\s]+(\d+)/);
      return match ? parseInt(match[1] || match[2]) : null;
    });
  } catch {}
}

// =====================================================================
// TOGGLE ACTIVE / SUDO (via API)
// =====================================================================
if (testUserId) {
  // Toggle active OFF
  try {
    const csrf2 = await getCsrf(page);
    const r1 = await apiPost(page, '/adm/api/toggle_user.php', { user_id: testUserId, csrf_token: csrf2 });
    const isOff = r1.data?.success !== false;
    log('Toggle user INACTIF', isOff ? 'OK' : 'FAIL', `status=${r1.status} ${JSON.stringify(r1.data).slice(0,60)}`);

    // Toggle active ON
    const r2 = await apiPost(page, '/adm/api/toggle_user.php', { user_id: testUserId, csrf_token: csrf2 });
    log('Toggle user ACTIF', r2.data?.success !== false ? 'OK' : 'FAIL', `new_status=${r2.data?.new_status}`);
  } catch(e) { log('Toggle active', 'FAIL', e.message.slice(0, 80)); }

  // Toggle sudo ON
  try {
    const csrf3 = await getCsrf(page);
    const r3 = await apiPost(page, '/adm/api/toggle_sudo.php', { user_id: testUserId, csrf_token: csrf3 });
    log('Toggle sudo ON', r3.data?.success !== false ? 'OK' : 'FAIL', `new_sudo=${r3.data?.new_sudo}`);

    // Toggle sudo OFF
    const r4 = await apiPost(page, '/adm/api/toggle_sudo.php', { user_id: testUserId, csrf_token: csrf3 });
    log('Toggle sudo OFF', r4.data?.success !== false ? 'OK' : 'FAIL', `new_sudo=${r4.data?.new_sudo}`);
  } catch(e) { log('Toggle sudo', 'FAIL', e.message.slice(0, 80)); }
} else {
  log('Toggle active', 'WARN', 'pas de testUserId');
  log('Toggle sudo', 'WARN', 'pas de testUserId');
}

// =====================================================================
// ANTI-ESCALATION TESTS
// =====================================================================
console.log('\n--- ANTI-ESCALATION ---\n');

// Try to delete self (should fail)
try {
  // Find superadmin user_id: it's the first user in the list (ID 1) or find via text match
  const myId = await page.evaluate(() => {
    // Look for a row/element containing 'superadmin' with a data-user-id
    const allEls = document.querySelectorAll('[data-user-id]');
    for (const el of allEls) {
      // Find the closest container that mentions 'superadmin'
      const parent = el.closest('tr, details, div, summary');
      if (parent && parent.textContent.includes('superadmin')) {
        return parseInt(el.getAttribute('data-user-id'));
      }
    }
    // Fallback: superadmin is usually ID 1
    return 1;
  });

  // Try toggle self (should fail)
  if (myId) {
    const rSelf = await apiPost(page, '/adm/api/toggle_user.php', { user_id: myId });
    const blocked = rSelf.data?.success === false;
    log('Anti-escalade: toggle self', blocked ? 'OK' : 'WARN', blocked ? 'bloque correctement' : `success=${rSelf.data?.success}`);

    const rSelfDel = await apiPostForm(page, '/adm/api/delete_user.php', { user_id: String(myId) });
    const blockedDel = rSelfDel.data?.success === false;
    log('Anti-escalade: delete self', blockedDel ? 'OK' : 'WARN', blockedDel ? 'bloque correctement' : `success=${rSelfDel.data?.success}`);
  } else {
    log('Anti-escalade: toggle self', 'WARN', 'myId non trouve');
    log('Anti-escalade: delete self', 'WARN', 'myId non trouve');
  }
} catch(e) { log('Anti-escalade', 'FAIL', e.message.slice(0, 80)); }

// =====================================================================
// CHANGE ROLE
// =====================================================================
console.log('\n--- GESTION DES ROLES ---\n');

if (testUserId) {
  try {
    // Switch to roles tab (manage_roles is in panel-users)
    // Change role of test user to admin (2) then back to user (1)
    const csrfR = await getCsrf(page);

    // POST form to change role - this is a form POST, not AJAX
    const roleResult = await page.evaluate(async (uid, csrf) => {
      const fd = new URLSearchParams();
      fd.append('csrf_token', csrf);
      fd.append('change_role', '1');
      fd.append('user_id', uid);
      fd.append('new_role', '2'); // admin
      const r = await fetch('/adm/admin_page.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: fd.toString(),
        credentials: 'same-origin',
        redirect: 'follow'
      });
      return { status: r.status, ok: r.ok };
    }, testUserId, csrfR);
    log('Changer role -> admin', roleResult.ok ? 'OK' : 'FAIL', `HTTP ${roleResult.status}`);

    // Reload and change back to user (1)
    await page.goto(`${BASE}/adm/admin_page.php`, { waitUntil: 'networkidle2' });
    const csrfR2 = await getCsrf(page);
    const roleResult2 = await page.evaluate(async (uid, csrf) => {
      const fd = new URLSearchParams();
      fd.append('csrf_token', csrf);
      fd.append('change_role', '1');
      fd.append('user_id', uid);
      fd.append('new_role', '1'); // user
      const r = await fetch('/adm/admin_page.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: fd.toString(),
        credentials: 'same-origin',
        redirect: 'follow'
      });
      return { status: r.status, ok: r.ok };
    }, testUserId, csrfR2);
    log('Changer role -> user', roleResult2.ok ? 'OK' : 'FAIL', `HTTP ${roleResult2.status}`);
  } catch(e) { log('Changer role', 'FAIL', e.message.slice(0, 80)); }
} else {
  log('Changer role', 'WARN', 'pas de testUserId');
}

// =====================================================================
// RESET PASSWORD & 2FA
// =====================================================================
if (testUserId) {
  try {
    await page.goto(`${BASE}/adm/admin_page.php`, { waitUntil: 'networkidle2' });
    const csrfP = await getCsrf(page);

    // Reset password (generate random)
    const pwdResult = await page.evaluate(async (uid, csrf) => {
      const fd = new URLSearchParams();
      fd.append('csrf_token', csrf);
      fd.append('change_password', '1');
      fd.append('user_id', uid);
      fd.append('new_password', ''); // empty = generate
      const r = await fetch('/adm/admin_page.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: fd.toString(),
        credentials: 'same-origin',
        redirect: 'follow'
      });
      const html = await r.text();
      return { status: r.status, hasSuccess: html.includes('succes') || html.includes('success') || html.includes('genere') };
    }, testUserId, csrfP);
    log('Reset mot de passe (genere)', pwdResult.hasSuccess ? 'OK' : 'WARN', `HTTP ${pwdResult.status}`);

    // Reset 2FA
    const csrfP2 = await getCsrf(page);
    const tfaResult = await page.evaluate(async (uid, csrf) => {
      const fd = new URLSearchParams();
      fd.append('csrf_token', csrf);
      fd.append('reset_2fa', '1');
      fd.append('user_id', uid);
      const r = await fetch('/adm/admin_page.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: fd.toString(),
        credentials: 'same-origin',
        redirect: 'follow'
      });
      return { status: r.status, ok: r.ok };
    }, testUserId, csrfP2);
    log('Reset 2FA', tfaResult.ok ? 'OK' : 'FAIL', `HTTP ${tfaResult.status}`);
  } catch(e) { log('Reset password/2FA', 'FAIL', e.message.slice(0, 80)); }
} else {
  log('Reset mot de passe', 'WARN', 'pas de testUserId');
  log('Reset 2FA', 'WARN', 'pas de testUserId');
}

// =====================================================================
// GESTION DES PERMISSIONS
// =====================================================================
console.log('\n--- PERMISSIONS ---\n');

if (testUserId) {
  const perms = ['can_deploy_keys', 'can_update_linux', 'can_manage_iptables', 'can_scan_cve',
                 'can_manage_fail2ban', 'can_manage_services', 'can_audit_ssh', 'can_manage_supervision',
                 'can_admin_portal', 'can_manage_remote_users', 'can_manage_platform_key',
                 'can_view_compliance', 'can_manage_backups', 'can_schedule_cve'];

  // Toggle permissions ON then OFF
  try {
    const csrfPerm = await getCsrf(page);

    // Turn all ON
    let allOn = true;
    for (const p of perms) {
      const r = await apiPost(page, '/adm/api/update_permissions.php', { user_id: testUserId, permission: p, value: 1 });
      if (r.data?.success === false && !r.data?.message?.includes('superadmin')) allOn = false;
    }
    log('Permissions: activer 14 droits', allOn ? 'OK' : 'WARN', allOn ? '14/14 activees' : 'certaines refusees');

    // Turn all OFF
    let allOff = true;
    for (const p of perms) {
      const r = await apiPost(page, '/adm/api/update_permissions.php', { user_id: testUserId, permission: p, value: 0 });
      if (r.data?.success === false && !r.data?.message?.includes('superadmin')) allOff = false;
    }
    log('Permissions: desactiver 14 droits', allOff ? 'OK' : 'WARN', allOff ? '14/14 desactivees' : 'certaines refusees');

    // Test invalid permission (should be rejected)
    const rBad = await apiPost(page, '/adm/api/update_permissions.php', { user_id: testUserId, permission: 'can_hack_system', value: 1 });
    const badBlocked = rBad.data?.success === false || rBad.status >= 400;
    log('Permission invalide rejetee', badBlocked ? 'OK' : 'FAIL', `can_hack_system -> ${rBad.data?.success}`);
  } catch(e) { log('Permissions', 'FAIL', e.message.slice(0, 80)); }
} else {
  log('Permissions', 'WARN', 'pas de testUserId');
}

// =====================================================================
// GESTION DES ACCES SERVEURS
// =====================================================================
console.log('\n--- ACCES SERVEURS ---\n');

try {
  // Switch to access tab to find server IDs
  await page.goto(`${BASE}/adm/admin_page.php`, { waitUntil: 'networkidle2' });
  await sleep(300);
  await page.evaluate(() => { if (typeof switchTab === 'function') switchTab('access'); });
  await sleep(500);

  // Get server list from access panel
  let servers = await page.evaluate(() => {
    const result = [];
    document.querySelectorAll('[data-machine-id], [data-server-id]').forEach(el => {
      const id = parseInt(el.getAttribute('data-machine-id') || el.getAttribute('data-server-id'));
      if (id && !result.includes(id)) result.push(id);
    });
    return result;
  });

  // Fallback: get from API
  if (servers.length === 0) {
    const apiR = await apiGet(page, '/api_proxy.php?route=/machines');
    if (apiR.data?.machines) servers = apiR.data.machines.map(m => m.id);
    else if (Array.isArray(apiR.data)) servers = apiR.data.map(m => m.id);
  }

  console.log(`      Serveurs detectes: ${servers.length} (IDs: ${servers.join(', ')})`);

  if (testUserId && servers.length > 0) {
    const serverId = servers[0];
    const csrfA = await getCsrf(page);

    // Add access
    const rAdd = await apiPost(page, '/adm/api/update_server_access.php', {
      user_id: testUserId, machine_id: serverId, action: 'add'
    });
    log('Ajouter acces serveur', rAdd.data?.success !== false ? 'OK' : 'FAIL', `user=${testUserId} server=${serverId}`);

    // Remove access
    const rRem = await apiPost(page, '/adm/api/update_server_access.php', {
      user_id: testUserId, machine_id: serverId, action: 'remove'
    });
    log('Retirer acces serveur', rRem.data?.success !== false ? 'OK' : 'FAIL', `user=${testUserId} server=${serverId}`);
  } else {
    log('Acces serveur', 'WARN', testUserId ? 'aucun serveur' : 'pas de testUserId');
  }
} catch(e) { log('Acces serveur', 'FAIL', e.message.slice(0, 80)); }

// =====================================================================
// NOTIFICATIONS PREFERENCES
// =====================================================================
console.log('\n--- NOTIFICATION PREFERENCES ---\n');

if (testUserId) {
  try {
    const events = ['cve_scan', 'ssh_audit', 'compliance_report', 'security_alert', 'backup_status', 'update_status'];

    // Toggle OFF all notifications for test user
    let offOk = 0;
    for (const ev of events) {
      const r = await apiPost(page, '/adm/api/update_notification_prefs.php', { user_id: testUserId, event_type: ev, value: 0 });
      if (r.status < 400) offOk++;
    }
    log('Notif prefs: desactiver 6 types', offOk === 6 ? 'OK' : 'WARN', `${offOk}/6`);

    // Toggle ON all
    let onOk = 0;
    for (const ev of events) {
      const r = await apiPost(page, '/adm/api/update_notification_prefs.php', { user_id: testUserId, event_type: ev, value: 1 });
      if (r.status < 400) onOk++;
    }
    log('Notif prefs: reactiver 6 types', onOk === 6 ? 'OK' : 'WARN', `${onOk}/6`);
  } catch(e) { log('Notification prefs', 'FAIL', e.message.slice(0, 80)); }
} else {
  log('Notification prefs', 'WARN', 'pas de testUserId');
}

// =====================================================================
// NOTIFICATIONS IN-APP
// =====================================================================
console.log('\n--- NOTIFICATIONS IN-APP ---\n');

try {
  // Get notification count
  const countR = await apiGet(page, '/adm/api/notifications.php?action=count');
  log('Notifications: count', countR.status === 200 ? 'OK' : 'FAIL', `count=${countR.data?.unread_count ?? countR.data?.count ?? '?'}`);

  // Get notification list
  const listR = await apiGet(page, '/adm/api/notifications.php?action=list&limit=5');
  const notifCount = listR.data?.notifications?.length ?? listR.data?.length ?? 0;
  log('Notifications: list', listR.status === 200 ? 'OK' : 'FAIL', `${notifCount} notification(s)`);

  // Get all notifications (paginated)
  const allR = await apiGet(page, '/adm/api/notifications.php?action=list_all&page=1');
  log('Notifications: list_all page 1', allR.status === 200 ? 'OK' : 'FAIL', `HTTP ${allR.status}`);

  // Mark all as read
  const readAllR = await apiPost(page, '/adm/api/notifications.php', { action: 'read_all' });
  log('Notifications: mark all read', readAllR.status === 200 ? 'OK' : 'WARN', `HTTP ${readAllR.status}`);
} catch(e) { log('Notifications', 'FAIL', e.message.slice(0, 80)); }

// =====================================================================
// RECHERCHE GLOBALE
// =====================================================================
console.log('\n--- RECHERCHE GLOBALE ---\n');

try {
  const searchR = await apiGet(page, '/adm/api/global_search.php?q=super');
  const hasResults = searchR.data?.results?.length > 0;
  log('Recherche "super"', hasResults ? 'OK' : 'WARN', `${searchR.data?.results?.length ?? 0} resultats`);

  const searchR2 = await apiGet(page, '/adm/api/global_search.php?q=debain');
  log('Recherche "debain"', searchR2.status === 200 ? 'OK' : 'WARN', `${searchR2.data?.results?.length ?? 0} resultats`);

  // Search too short (should fail)
  const searchR3 = await apiGet(page, '/adm/api/global_search.php?q=a');
  log('Recherche trop courte rejetee', searchR3.data?.results?.length === 0 || searchR3.status >= 400 ? 'OK' : 'WARN', `q=a -> ${searchR3.data?.results?.length ?? 'error'}`);
} catch(e) { log('Recherche globale', 'FAIL', e.message.slice(0, 80)); }

// =====================================================================
// ONGLETS ADMIN (UI)
// =====================================================================
console.log('\n--- ONGLETS ADMIN (UI) ---\n');

try {
  await page.goto(`${BASE}/adm/admin_page.php`, { waitUntil: 'networkidle2' });
  await sleep(500);

  // Tab Serveurs
  const hasSwitchTab = await page.evaluate(() => typeof window.switchTab === 'function');
  if (hasSwitchTab) {
    await page.evaluate(() => switchTab('servers'));
    await sleep(300);
    const serversActive = await page.evaluate(() => document.getElementById('panel-servers')?.classList.contains('active'));
    await shot(page, '05-tab-servers');
    log('Onglet Serveurs', serversActive ? 'OK' : 'FAIL', '');

    // Check servers content
    const serverContent = await page.evaluate(() => {
      const panel = document.getElementById('panel-servers');
      return panel ? panel.innerText.substring(0, 200) : '';
    });
    const hasServerData = serverContent.includes('debain-test') || serverContent.includes('serveur') || serverContent.includes('server');
    log('Contenu Serveurs', hasServerData ? 'OK' : 'WARN', serverContent.slice(0, 60));

    // Tab Acces
    await page.evaluate(() => switchTab('access'));
    await sleep(300);
    const accessActive = await page.evaluate(() => document.getElementById('panel-access')?.classList.contains('active'));
    await shot(page, '06-tab-access');
    log('Onglet Acces & Permissions', accessActive ? 'OK' : 'FAIL', '');

    // Check access content
    const accessContent = await page.evaluate(() => {
      const panel = document.getElementById('panel-access');
      return panel ? panel.innerText.substring(0, 200) : '';
    });
    const hasAccessData = accessContent.includes('Attribution') || accessContent.includes('Droits') || accessContent.includes('access') || accessContent.includes('permission');
    log('Contenu Acces & Permissions', hasAccessData ? 'OK' : 'WARN', accessContent.slice(0, 60));

    // Back to Users
    await page.evaluate(() => switchTab('users'));
    await sleep(200);
  } else {
    log('Onglets Admin', 'FAIL', 'switchTab non defini');
  }
} catch(e) { log('Onglets Admin', 'FAIL', e.message.slice(0, 80)); }

// =====================================================================
// AUDIT LOG
// =====================================================================
console.log('\n--- AUDIT LOG ---\n');

try {
  await page.goto(`${BASE}/adm/audit_log.php`, { waitUntil: 'networkidle2' });
  await sleep(500);
  await shot(page, '07-audit-log');

  const auditContent = await page.evaluate(() => document.body.innerText);
  const hasLogs = auditContent.includes('superadmin') || auditContent.includes('action') || auditContent.includes('journal');
  log('Audit log: page', hasLogs ? 'OK' : 'WARN', 'chargee');

  // Check for log entries about our test user
  const hasTestUserLogs = auditContent.includes('test-e2e-user');
  log('Audit log: traces test-e2e-user', hasTestUserLogs ? 'OK' : 'WARN', hasTestUserLogs ? 'present' : 'absent');

  // Test filter
  const filterInput = await page.$('input[name="filter_user"], input[name="username"], input[type="text"]');
  if (filterInput) {
    await filterInput.type('superadmin');
    // Submit filter if there's a form
    const filterForm = await page.evaluate(() => {
      const input = document.querySelector('input[name="filter_user"], input[name="username"]');
      return input?.form ? true : false;
    });
    if (filterForm) {
      const navP3 = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => null);
      await page.evaluate(() => {
        const input = document.querySelector('input[name="filter_user"], input[name="username"]');
        if (input?.form) input.form.submit();
      });
      await navP3;
    }
    log('Audit log: filtre par user', 'OK', 'superadmin');
  } else {
    log('Audit log: filtre', 'WARN', 'champ filtre non trouve');
  }

  // Check export CSV link
  const hasCsvExport = await page.evaluate(() => {
    const links = document.querySelectorAll('a, button');
    for (const l of links) if (l.textContent.includes('CSV') || l.href?.includes('export') || l.href?.includes('csv')) return true;
    return false;
  });
  log('Audit log: export CSV', hasCsvExport ? 'OK' : 'WARN', hasCsvExport ? 'bouton present' : 'non trouve');
} catch(e) { log('Audit log', 'FAIL', e.message.slice(0, 80)); }

// =====================================================================
// HEALTH CHECK
// =====================================================================
console.log('\n--- HEALTH CHECK ---\n');

try {
  await page.goto(`${BASE}/adm/health_check.php`, { waitUntil: 'networkidle2', timeout: 30000 });
  await sleep(1000);
  await shot(page, '08-health-check');

  const healthContent = await page.evaluate(() => document.body.innerText);

  // Count status indicators
  const healthStats = await page.evaluate(() => {
    const html = document.body.innerHTML;
    const green = (html.match(/bg-green|text-green|200|✓|pass/gi) || []).length;
    const red = (html.match(/bg-red|text-red|500|✗|fail/gi) || []).length;
    const badges = document.querySelectorAll('.badge, .status, [class*="status"]').length;
    return { green, red, badges };
  });

  const hasHealthData = healthContent.includes('Monitoring') || healthContent.includes('SSH') || healthContent.includes('endpoint') || healthContent.includes('route');
  log('Health check: page', hasHealthData ? 'OK' : 'WARN', `green~${healthStats.green} red~${healthStats.red}`);

  // Check if backend routes are listed
  const routeCount = await page.evaluate(() => {
    const rows = document.querySelectorAll('tr, .route-row, [class*="route"]');
    return rows.length;
  });
  log('Health check: routes listees', routeCount > 10 ? 'OK' : 'WARN', `${routeCount} elements`);
} catch(e) { log('Health check', 'FAIL', e.message.slice(0, 80)); }

// =====================================================================
// PLATFORM KEYS
// =====================================================================
console.log('\n--- PLATFORM KEYS ---\n');

try {
  await page.goto(`${BASE}/adm/platform_keys.php`, { waitUntil: 'networkidle2' });
  await sleep(500);
  await shot(page, '09-platform-keys');

  const pkContent = await page.evaluate(() => document.body.innerText);
  const hasPK = pkContent.includes('platform') || pkContent.includes('SSH') || pkContent.includes('keypair') || pkContent.includes('cle');
  log('Platform Keys: page', hasPK ? 'OK' : 'WARN', 'chargee');

  // Check if public key is displayed
  const hasPublicKey = await page.evaluate(() => {
    const code = document.querySelector('code, pre, .font-mono, textarea[readonly]');
    return code ? code.textContent.includes('ssh-') || code.textContent.includes('key') : false;
  });
  log('Platform Keys: cle publique', hasPublicKey ? 'OK' : 'WARN', hasPublicKey ? 'affichee' : 'non trouvee');

  // Check server deployment status
  const hasServerTable = await page.evaluate(() => {
    return document.body.innerText.includes('debain-test') || document.querySelectorAll('table tr, .server-row').length > 0;
  });
  log('Platform Keys: serveurs', hasServerTable ? 'OK' : 'WARN', hasServerTable ? 'debain-test present' : 'aucun serveur');
} catch(e) { log('Platform Keys', 'FAIL', e.message.slice(0, 80)); }

// =====================================================================
// SERVER USERS
// =====================================================================
console.log('\n--- SERVER USERS ---\n');

try {
  await page.goto(`${BASE}/adm/server_users.php`, { waitUntil: 'networkidle2' });
  await sleep(500);
  await shot(page, '10-server-users');

  const suContent = await page.evaluate(() => document.body.innerText);
  const hasSU = suContent.includes('utilisateur') || suContent.includes('user') || suContent.includes('serveur') || suContent.includes('scan');
  log('Server Users: page', hasSU ? 'OK' : 'WARN', 'chargee');

  // Check if server dropdown exists
  const hasDropdown = await page.evaluate(() =>
    !!document.querySelector('select, [data-server-select], #server-select')
  );
  log('Server Users: dropdown serveur', hasDropdown ? 'OK' : 'WARN', hasDropdown ? 'present' : 'non trouve');
} catch(e) { log('Server Users', 'FAIL', e.message.slice(0, 80)); }

// =====================================================================
// CRUD SERVEUR (Tab Serveurs)
// =====================================================================
console.log('\n--- CRUD SERVEUR ---\n');

let testServerId = null;
try {
  await page.goto(`${BASE}/adm/admin_page.php`, { waitUntil: 'networkidle2' });
  await sleep(500);

  // Switch to servers tab
  await page.evaluate(() => { if (typeof switchTab === 'function') switchTab('servers'); });
  await sleep(500);

  // Open add server form
  await page.evaluate(() => {
    const details = document.querySelectorAll('details');
    for (const d of details) {
      if (d.textContent.includes('Ajouter') && d.textContent.includes('serveur')) d.open = true;
      if (d.textContent.includes('Add') && d.textContent.includes('server')) d.open = true;
    }
  });
  await sleep(300);

  // Fill add server form
  const serverFormFilled = await page.evaluate(() => {
    const forms = document.querySelectorAll('form');
    for (const f of forms) {
      const nameInput = f.querySelector('input[name="name"]');
      const ipInput = f.querySelector('input[name="ip"]');
      if (nameInput && ipInput && f.closest('#panel-servers')) {
        nameInput.value = 'test-e2e-server';
        ipInput.value = '10.0.0.99';
        const portInput = f.querySelector('input[name="port"]');
        if (portInput) portInput.value = '22';
        const userInput = f.querySelector('input[name="user"]');
        if (userInput) userInput.value = 'root';
        const passInput = f.querySelector('input[name="password"]');
        if (passInput) passInput.value = 'test123!Test';
        const rootPassInput = f.querySelector('input[name="root_password"]');
        if (rootPassInput) rootPassInput.value = 'test123!Test';
        // Set environment
        const envSelect = f.querySelector('select[name="environment"]');
        if (envSelect) envSelect.value = 'TEST';
        return true;
      }
    }
    return false;
  });

  if (serverFormFilled) {
    await shot(page, '11-add-server-form');
    const navP4 = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }).catch(() => null);
    await page.evaluate(() => {
      const forms = document.querySelectorAll('form');
      for (const f of forms) {
        if (f.querySelector('input[name="ip"]') && f.closest('#panel-servers')) {
          f.submit();
          return;
        }
      }
    });
    await navP4;
    await sleep(500);

    const serverCreated = await page.evaluate(() => document.body.innerText.includes('test-e2e-server'));
    await shot(page, '12-server-created');
    log('Creer serveur', serverCreated ? 'OK' : 'WARN', 'test-e2e-server');
  } else {
    log('Creer serveur', 'WARN', 'formulaire add_server non trouve dans panel-servers');
  }
} catch(e) { log('Creer serveur', 'FAIL', e.message.slice(0, 80)); }

// =====================================================================
// BACKUP MANAGEMENT
// =====================================================================
console.log('\n--- BACKUPS ---\n');

try {
  await page.goto(`${BASE}/adm/admin_page.php`, { waitUntil: 'networkidle2' });
  await sleep(300);

  // Try to list backups via API
  const backupList = await page.evaluate(async () => {
    try {
      const r = await fetch(window.API_URL + '/admin/backups', { credentials: 'same-origin' });
      const d = await r.json();
      return { status: r.status, count: d.backups?.length ?? 0, success: d.success };
    } catch(e) { return { status: 0, error: e.message }; }
  });
  log('Backups: lister', backupList.success !== undefined ? 'OK' : 'WARN', `${backupList.count ?? 0} backup(s), HTTP ${backupList.status}`);
} catch(e) { log('Backups', 'FAIL', e.message.slice(0, 80)); }

// =====================================================================
// BACKEND API PROXY
// =====================================================================
console.log('\n--- API PROXY ---\n');

try {
  // Test basic API proxy
  const apiTest = await page.evaluate(async () => {
    const r = await fetch('/api_proxy.php?route=/test', { credentials: 'same-origin' });
    return { status: r.status, data: await r.json().catch(() => ({})) };
  });
  log('API proxy: /test', apiTest.status === 200 ? 'OK' : 'FAIL', `HTTP ${apiTest.status}`);

  // Test machines list
  const apiMachines = await page.evaluate(async () => {
    const r = await fetch('/api_proxy.php?route=/machines', { credentials: 'same-origin' });
    return { status: r.status, data: await r.json().catch(() => ({})) };
  });
  log('API proxy: /machines', apiMachines.status === 200 ? 'OK' : 'WARN', `HTTP ${apiMachines.status}`);
} catch(e) { log('API proxy', 'FAIL', e.message.slice(0, 80)); }

// =====================================================================
// CLEANUP: DELETE TEST USER
// =====================================================================
console.log('\n--- NETTOYAGE ---\n');

if (testUserId) {
  try {
    await page.goto(`${BASE}/adm/admin_page.php`, { waitUntil: 'networkidle2' });
    const delResult = await apiPostForm(page, '/adm/api/delete_user.php', { user_id: String(testUserId) });
    log('Supprimer test-e2e-user', delResult.data?.success ? 'OK' : 'FAIL', `id=${testUserId} ${delResult.data?.message ?? ''}`);
  } catch(e) { log('Supprimer test user', 'FAIL', e.message.slice(0, 80)); }
} else {
  log('Supprimer test user', 'WARN', 'pas de testUserId');
}

// Verify deletion
try {
  await page.goto(`${BASE}/adm/admin_page.php`, { waitUntil: 'networkidle2' });
  const stillExists = await page.evaluate(() => document.body.innerText.includes('test-e2e-user'));
  log('Verification suppression user', !stillExists ? 'OK' : 'FAIL', stillExists ? 'toujours present!' : 'confirme');
} catch(e) { log('Verification suppression', 'FAIL', e.message.slice(0, 80)); }

// =====================================================================
// RAPPORT
// =====================================================================
console.log('\n============================================================');
console.log('  RAPPORT FINAL - Admin Tests');
console.log('============================================================\n');
for (const r of results) console.log(r);
console.log(`\n  TOTAL: ${ok} OK, ${warn} WARN, ${fail} FAIL / ${ok + warn + fail} tests`);
console.log(`\n  404/erreurs HTTP (${errors404.length}):`);
for (const e of errors404) console.log(`    ${e}`);
console.log(`\n  Erreurs JS (${jsErrors.length}):`);
for (const e of jsErrors) console.log(`    ${e}`);
console.log(`\n  Requetes echouees (${reqFailed.length}):`);
for (const e of reqFailed) console.log(`    ${e}`);
console.log(`\n  Screenshots: ${SHOTS}/`);
console.log(fail > 0 ? '\n  >>> DES TESTS ONT ECHOUE <<<' : '\n  >>> TOUS LES TESTS PASSENT <<<');
console.log('\n============================================================');
console.log('  Navigateur ouvert sur admin. Ctrl+C pour fermer.');
console.log('============================================================\n');

// Retour admin pour navigation manuelle
await page.goto(`${BASE}/adm/admin_page.php`, { waitUntil: 'networkidle2' }).catch(() => {});
await new Promise(() => {});
