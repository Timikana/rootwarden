/**
 * go-ssh-audit-schedules.mjs - E2E sur la planification des audits SSH.
 *
 * Couvre la nouvelle UI multi-select admin+ ajoutee en v1.16.x :
 *   1. Login superadmin
 *   2. CREATE schedule via API (target_type=all)
 *   3. CREATE schedule target_type=machines avec un array d'IDs (multi-select)
 *   4. TOGGLE on/off (verifier persistence)
 *   5. DELETE
 *   6. Cleanup : tous les TEST_* sont effaces
 */
import { BASE_URL, launchBrowser, newPage, login, sleep } from './helpers.mjs';

const TEST_NAME_ALL = 'TEST_ssh_all';
const TEST_NAME_MULTI = 'TEST_ssh_multi';

async function apiFetch(page, path, init = {}) {
    return page.evaluate(async (p, i) => {
        const r = await fetch((window.API_URL || '/api_proxy.php') + p, i);
        const text = await r.text();
        let body = null; try { body = JSON.parse(text); } catch (_) {}
        return { status: r.status, body, text };
    }, path, init);
}

async function findSchedule(page, name) {
    const d = await apiFetch(page, '/ssh-audit/schedules');
    if (!d.body?.success) return null;
    return (d.body.schedules || []).find(s => s.name === name) || null;
}

async function cleanup(page) {
    const d = await apiFetch(page, '/ssh-audit/schedules');
    if (!d.body?.schedules) return;
    for (const s of d.body.schedules) {
        if ((s.name || '').startsWith('TEST_')) {
            await apiFetch(page, `/ssh-audit/schedules/${s.id}`, { method: 'DELETE' });
        }
    }
}

async function listMachines(page) {
    const d = await apiFetch(page, '/list_machines');
    return d.body?.machines || d.body?.servers || [];
}

(async () => {
    const browser = await launchBrowser();
    const page = await newPage(browser);
    page.on('dialog', d => d.accept().catch(() => {}));
    let failed = null;

    try {
        console.log('> Login superadmin...');
        await login(page);

        console.log('> Cleanup eventuel...');
        await cleanup(page);

        console.log('> CREATE schedule target=all via API...');
        const cr1 = await apiFetch(page, '/ssh-audit/schedules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: TEST_NAME_ALL,
                cron_expression: '0 4 * * *',
                target_type: 'all',
                target_value: null,
            }),
        });
        if (cr1.status !== 200 || !cr1.body?.success) throw new Error(`FAIL create all: ${cr1.text}`);
        const s1 = await findSchedule(page, TEST_NAME_ALL);
        if (!s1) throw new Error('FAIL: schedule_all non visible apres POST');
        console.log(`   [OK] schedule_all id=${s1.id}, target=${s1.target_type}`);

        console.log('> CREATE schedule target=machines (multi) via API...');
        const machines = await listMachines(page);
        const ids = machines.slice(0, 2).map(m => m.id).filter(Boolean);
        if (ids.length === 0) {
            console.log('   [SKIP] pas de serveurs disponibles, skip multi');
        } else {
            const cr2 = await apiFetch(page, '/ssh-audit/schedules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: TEST_NAME_MULTI,
                    cron_expression: '30 5 * * *',
                    target_type: 'machines',
                    target_value: JSON.stringify(ids),
                }),
            });
            if (cr2.status !== 200 || !cr2.body?.success) throw new Error(`FAIL create multi: ${cr2.text}`);
            const s2 = await findSchedule(page, TEST_NAME_MULTI);
            if (!s2) throw new Error('FAIL: schedule_multi non visible apres POST');
            const parsed = JSON.parse(s2.target_value || '[]');
            if (parsed.length !== ids.length) throw new Error(`FAIL: target_value=${s2.target_value} attendu ${ids.length} ids`);
            console.log(`   [OK] schedule_multi id=${s2.id}, ${parsed.length} machines`);

            console.log('> TOGGLE OFF/ON sur le multi...');
            const tg1 = await apiFetch(page, `/ssh-audit/schedules/${s2.id}/toggle`, { method: 'POST' });
            if (tg1.status !== 200) throw new Error(`FAIL toggle: ${tg1.text}`);
            const s2off = await findSchedule(page, TEST_NAME_MULTI);
            console.log(`   [OK] toggle 1, enabled=${s2off?.enabled}`);
            await apiFetch(page, `/ssh-audit/schedules/${s2.id}/toggle`, { method: 'POST' });

            console.log('> Verifier UI rendu (admin+ section "Scans planifies")...');
            await page.goto(`${BASE_URL}/ssh-audit/`, { waitUntil: 'networkidle2' });
            await sleep(800);
            const seen = await page.evaluate((name) => {
                const list = document.getElementById('ssh-schedules-list');
                return list ? list.innerHTML.includes(name) : false;
            }, TEST_NAME_MULTI);
            if (!seen) throw new Error('FAIL: TEST_ssh_multi pas affiche dans la section UI');
            console.log('   [OK] schedule visible dans l\'UI');
        }

        console.log('> DELETE TEST_ssh_all...');
        const del = await apiFetch(page, `/ssh-audit/schedules/${s1.id}`, { method: 'DELETE' });
        if (del.status !== 200 || !del.body?.success) throw new Error(`FAIL delete: ${del.text}`);
        const s1after = await findSchedule(page, TEST_NAME_ALL);
        if (s1after !== null) throw new Error('FAIL: schedule still present apres DELETE');
        console.log('   [OK] schedule supprime');

    } catch (e) {
        failed = e;
    } finally {
        await cleanup(page).catch(() => {});
        await page.close();
        await browser.close();
    }

    if (failed) { console.error('[ECHEC]', failed.message); process.exit(1); }
    console.log('[SUCCES] tous les tests SSH audit schedules OK');
})();
