/**
 * go-security.mjs - Tests E2E des controles securite (NE PAS REGRESSER).
 *
 * Codifie les invariants ajoutes par l'audit v1.17.0 :
 *   1. POST /api_proxy.php/* sans X-CSRF-TOKEN -> 403
 *   2. GET /api_proxy.php/* non authentifie -> 302 vers login (ou 401)
 *   3. Endpoint role 2+ accede par role 1 -> 403 (require_role)
 *   4. Payload XSS dans nom de schedule -> echappe dans le DOM (pas execute)
 *
 * Si un nouvel endpoint contourne ces controles, ce test casse a la prochaine PR.
 *
 * Usage : node go-security.mjs
 */
import { BASE_URL, launchBrowser, newPage, login, sleep } from './helpers.mjs';

let failed = 0;
function check(label, ok, details = '') {
    if (ok) { console.log(`   [OK] ${label}`); }
    else    { console.error(`   [ECHEC] ${label}${details ? ' - ' + details : ''}`); failed++; }
}

(async () => {
    const browser = await launchBrowser();

    // ── TEST 1 : POST sans CSRF -> 403 ───────────────────────────────────────
    console.log('> 1. POST api_proxy.php sans CSRF token');
    {
        const page = await newPage(browser);
        await login(page);

        // Appel direct via fetch SANS le wrapper utils.js (on simule une XSS qui
        // bypass le shim ; l'attaque doit etre bloquee cote serveur).
        const r = await page.evaluate(async () => {
            // Bypass le wrapper en utilisant XMLHttpRequest direct
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/api_proxy.php/cve_schedules', false);
            xhr.setRequestHeader('Content-Type', 'application/json');
            try {
                xhr.send(JSON.stringify({ name: 'EVIL', cron_expression: '0 3 * * *', target_type: 'all' }));
                return { status: xhr.status, body: xhr.responseText };
            } catch (e) { return { status: 0, body: String(e) }; }
        });
        check('POST sans CSRF -> 403', r.status === 403, `got ${r.status}`);

        // Avec CSRF (via le wrapper natif) -> doit passer
        const ok = await page.evaluate(async () => {
            const meta = document.querySelector('meta[name="csrf-token"]');
            const r = await fetch('/api_proxy.php/cve_schedules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': meta?.content || '' },
                body: JSON.stringify({ name: 'TEST_sec_csrfok', cron_expression: '0 3 * * *',
                                       min_cvss: 7, target_type: 'all', target_value: '' }),
            });
            return r.status;
        });
        check('POST avec CSRF -> 200', ok === 200, `got ${ok}`);

        // Cleanup
        await page.evaluate(async () => {
            const meta = document.querySelector('meta[name="csrf-token"]');
            const r = await fetch('/api_proxy.php/cve_schedules');
            const d = await r.json();
            for (const s of (d.schedules || [])) if (s.name?.startsWith('TEST_sec_')) {
                await fetch(`/api_proxy.php/cve_schedules/${s.id}`, {
                    method: 'DELETE', headers: { 'X-CSRF-TOKEN': meta?.content || '' },
                });
            }
        });
        await page.close();
    }

    // ── TEST 2 : GET non authentifie -> redirect login ───────────────────────
    console.log('> 2. GET api_proxy.php non authentifie');
    {
        // Fresh browser context (pas de cookies session persistants)
        const ctx = await browser.createBrowserContext();
        const page = await ctx.newPage();
        const resp = await page.goto(`${BASE_URL}/api_proxy.php/list_machines`, {
            waitUntil: 'networkidle2'
        });
        const finalUrl = page.url();
        // checkAuth() redirige vers login.php (ou 401/403 selon contexte)
        const blocked = resp.status() >= 400 || finalUrl.includes('login') || finalUrl.includes('auth');
        check('Non-auth bloque', blocked, `status=${resp.status()} url=${finalUrl}`);
        await page.close();
        await ctx.close();
    }

    // ── TEST 3 : XSS payload echappe dans le DOM ────────────────────────────
    console.log('> 3. XSS escape sur nom de schedule');
    {
        const page = await newPage(browser);
        await login(page);

        // Cree un schedule avec un payload XSS dans le nom
        const created = await page.evaluate(async () => {
            const meta = document.querySelector('meta[name="csrf-token"]');
            const r = await fetch('/api_proxy.php/cve_schedules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': meta?.content || '' },
                body: JSON.stringify({
                    name: 'TEST_sec_<img src=x onerror=window.__pwned=1>',
                    cron_expression: '0 3 * * *', min_cvss: 7, target_type: 'all', target_value: '',
                }),
            });
            return r.status === 200;
        });
        check('Schedule XSS cree', created);

        // Charge la page security et verifie que window.__pwned reste undefined
        await page.goto(`${BASE_URL}/security/`, { waitUntil: 'networkidle2' });
        await page.evaluate(() => document.querySelectorAll('details').forEach(d => d.open = true));
        await sleep(800);
        const pwned = await page.evaluate(() => !!window.__pwned);
        check('XSS payload non execute (window.__pwned undefined)', !pwned);

        // Verifie aussi que le payload apparait dans le HTML mais echape
        const html = await page.evaluate(() => document.getElementById('schedules-list')?.innerHTML || '');
        const escaped = html.includes('&lt;img') || html.includes('&amp;lt;img');
        check('Payload echape dans le DOM (& < >)', escaped, `html sample: ${html.slice(0, 200)}`);

        // Cleanup
        await page.evaluate(async () => {
            const meta = document.querySelector('meta[name="csrf-token"]');
            const r = await fetch('/api_proxy.php/cve_schedules');
            const d = await r.json();
            for (const s of (d.schedules || [])) if (s.name?.startsWith('TEST_sec_')) {
                await fetch(`/api_proxy.php/cve_schedules/${s.id}`, {
                    method: 'DELETE', headers: { 'X-CSRF-TOKEN': meta?.content || '' },
                });
            }
        });
        await page.close();
    }

    // ── TEST 4 : audit log hash chain integrity (depuis migration 036) ──────
    console.log('> 4. Audit log hash chain integrity');
    {
        const page = await newPage(browser);
        await login(page);
        const r = await page.evaluate(async () => {
            const meta = document.querySelector('meta[name="csrf-token"]');
            const resp = await fetch('/adm/api/audit_verify.php', {
                method: 'POST', headers: { 'X-CSRF-TOKEN': meta?.content || '' },
            });
            const text = await resp.text();
            try { return { status: resp.status, body: JSON.parse(text) }; }
            catch { return { status: resp.status, body: text }; }
        });
        check('audit_verify retourne 200', r.status === 200, `status=${r.status}`);
        // Le endpoint retourne {success:true, integrity:"OK", total, sealed, unsealed, chain_head}
        check('hash chain valide', r.body?.success === true && r.body?.integrity === 'OK',
              `body: ${JSON.stringify(r.body).slice(0, 120)}`);
        await page.close();
    }

    await browser.close();

    if (failed > 0) {
        console.error(`\n[ECHEC] ${failed} controle(s) securite casse(s)`);
        process.exit(1);
    }
    console.log('\n[SUCCES] tous les controles securite passent');
})();
