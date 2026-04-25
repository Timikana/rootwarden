/**
 * smoke-v1.17.mjs - Smoke test visuel des nouveautes v1.17.0.
 *
 * Capture le rendu :
 *   1. /security/ avec schedule multi cree (CVE) - section + multi list ouverte
 *   2. /ssh-audit/ avec schedule multi cree (SSH audit) - meme deal
 *   3. /index.php pour voir le banner rotation legacy si applicable
 *
 * Cleanup : tous les TEST_smoke_* sont supprimes en fin de run.
 */
import { BASE_URL, launchBrowser, newPage, login, sleep } from './helpers.mjs';
import fs from 'fs';

const OUTDIR = './screenshots/v1.17';
fs.mkdirSync(OUTDIR, { recursive: true });

async function apiFetch(page, path, init = {}) {
    return page.evaluate(async (p, i) => {
        const r = await fetch((window.API_URL || '/api_proxy.php') + p, i);
        const text = await r.text();
        let body = null; try { body = JSON.parse(text); } catch (_) {}
        return { status: r.status, body, text };
    }, path, init);
}

async function listMachines(page) {
    const d = await apiFetch(page, '/list_machines');
    return d.body?.machines || [];
}

async function cleanupCve(page) {
    const d = await apiFetch(page, '/cve_schedules');
    for (const s of (d.body?.schedules || [])) {
        if ((s.name || '').startsWith('TEST_smoke_')) {
            await apiFetch(page, `/cve_schedules/${s.id}`, { method: 'DELETE' });
        }
    }
}
async function cleanupSsh(page) {
    const d = await apiFetch(page, '/ssh-audit/schedules');
    for (const s of (d.body?.schedules || [])) {
        if ((s.name || '').startsWith('TEST_smoke_')) {
            await apiFetch(page, `/ssh-audit/schedules/${s.id}`, { method: 'DELETE' });
        }
    }
}

(async () => {
    const browser = await launchBrowser();
    const page = await newPage(browser);
    page.on('dialog', d => d.accept().catch(() => {}));
    let failed = null;

    try {
        console.log('> Login superadmin...');
        await login(page);
        await cleanupCve(page); await cleanupSsh(page);

        const machines = await listMachines(page);
        const ids = machines.slice(0, 3).map(m => m.id).filter(Boolean);
        console.log(`   ${machines.length} serveur(s) dispo, multi-select sur ${ids.length}`);

        // ── 1. CVE multi-schedule ───────────────────────────────────
        console.log('> Cree CVE schedule multi...');
        const cveCreate = await apiFetch(page, '/cve_schedules', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: 'TEST_smoke_cve_multi', cron_expression: '0 3 * * *',
                min_cvss: 7.0, target_type: 'machines',
                target_value: JSON.stringify(ids),
            }),
        });
        console.log(`   create=${cveCreate.body?.success ? 'OK' : 'FAIL'} id=${cveCreate.body?.id || '?'}`);

        await page.goto(`${BASE_URL}/security/`, { waitUntil: 'networkidle2' });
        // Ouvre le <details> "Scans planifies" pour qu'il soit visible
        await page.evaluate(() => document.querySelectorAll('details').forEach(d => d.open = true));
        await sleep(800);
        await page.screenshot({ path: `${OUTDIR}/01-cve-schedules-with-multi.png`, fullPage: true });
        console.log('   [SAVED] 01-cve-schedules-with-multi.png');

        // Capture le formulaire avec sched-multi-list visible
        await page.evaluate(() => {
            const sel = document.getElementById('sched-target');
            if (sel) { sel.value = 'multi'; sel.dispatchEvent(new Event('change')); }
            // Coche les 2 premieres checkboxes pour le compteur
            document.querySelectorAll('.sched-multi-cb').forEach((cb, i) => { if (i < 2) { cb.checked = true; cb.dispatchEvent(new Event('change', { bubbles: true })); }});
        });
        await sleep(500);
        await page.screenshot({ path: `${OUTDIR}/02-cve-form-multi-open.png`, fullPage: true });
        console.log('   [SAVED] 02-cve-form-multi-open.png');

        // ── 2. SSH audit multi-schedule ─────────────────────────────
        console.log('> Cree SSH audit schedule multi...');
        const sshCreate = await apiFetch(page, '/ssh-audit/schedules', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: 'TEST_smoke_ssh_multi', cron_expression: '0 4 * * *',
                target_type: 'machines',
                target_value: JSON.stringify(ids),
            }),
        });
        console.log(`   create=${sshCreate.body?.success ? 'OK' : 'FAIL'}`);

        await page.goto(`${BASE_URL}/ssh-audit/`, { waitUntil: 'networkidle2' });
        await page.evaluate(() => document.querySelectorAll('details').forEach(d => d.open = true));
        await sleep(800);
        await page.screenshot({ path: `${OUTDIR}/03-ssh-audit-schedules-with-multi.png`, fullPage: true });
        console.log('   [SAVED] 03-ssh-audit-schedules-with-multi.png');

        await page.evaluate(() => {
            const sel = document.getElementById('ssh-sched-target');
            if (sel) { sel.value = 'multi'; sel.dispatchEvent(new Event('change')); }
            document.querySelectorAll('.ssh-sched-multi-cb').forEach((cb, i) => { if (i < 2) { cb.checked = true; cb.dispatchEvent(new Event('change', { bubbles: true })); }});
        });
        await sleep(500);
        await page.screenshot({ path: `${OUTDIR}/04-ssh-audit-form-multi-open.png`, fullPage: true });
        console.log('   [SAVED] 04-ssh-audit-form-multi-open.png');

        // ── 3. Dashboard (banner rotation si applicable) ────────────
        console.log('> Capture dashboard...');
        await page.goto(`${BASE_URL}/`, { waitUntil: 'networkidle2' });
        await sleep(600);
        await page.screenshot({ path: `${OUTDIR}/05-dashboard.png`, fullPage: true });
        console.log('   [SAVED] 05-dashboard.png');

        // ── 4. API keys page (banner rotation 2 niveaux) ────────────
        console.log('> Capture API keys page...');
        await page.goto(`${BASE_URL}/adm/api_keys.php`, { waitUntil: 'networkidle2' });
        await sleep(600);
        await page.screenshot({ path: `${OUTDIR}/06-api-keys.png`, fullPage: true });
        console.log('   [SAVED] 06-api-keys.png');

    } catch (e) {
        failed = e;
    } finally {
        await cleanupCve(page).catch(() => {});
        await cleanupSsh(page).catch(() => {});
        await page.close();
        await browser.close();
    }

    if (failed) { console.error('[ECHEC]', failed.message); process.exit(1); }
    console.log(`\n[SUCCES] 6 screenshots dans ${OUTDIR}/`);
})();
