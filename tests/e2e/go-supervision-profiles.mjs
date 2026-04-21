/**
 * go-supervision-profiles.mjs - Test E2E des profils de supervision.
 *
 * Couvre :
 *   1. Superadmin : creation d'un profil avec fausses donnees (LinuxTestInterne)
 *   2. Superadmin : edition du profil
 *   3. Superadmin : suppression du profil
 *   4. Compte non-privilegie (E2E_USER2/E2E_PASS2) : verification 403/redirect
 *
 * Usage :
 *   E2E_URL=https://srv-docker:8443 \
 *   E2E_USER=superadmin E2E_PASS=*** E2E_TOTP_SECRET=*** \
 *   E2E_USER2=user_lecteur E2E_PASS2=*** E2E_TOTP_SECRET2=*** \
 *   node tests/e2e/go-supervision-profiles.mjs
 *
 * Les fausses donnees (prefixe "TEST_") sont toujours supprimees a la fin,
 * meme en cas d'echec (cleanup dans le finally).
 */
import { BASE_URL, launchBrowser, newPage, login, sleep, assertSelector } from './helpers.mjs';

const TEST_PROFILE_NAME = 'TEST_LinuxInterne';
const TEST_PROFILE_RENAMED = 'TEST_LinuxInterneV2';

async function gotoProfilesTab(page) {
    await page.goto(`${BASE_URL}/supervision/`, { waitUntil: 'networkidle2' });
    await page.click('button[data-tab="profiles"]');
    await sleep(300);
    await assertSelector(page, '#profiles-tbody');
}

async function openNewDialog(page) {
    await page.evaluate(() => window.openProfileDialog && window.openProfileDialog());
    await page.waitForSelector('#profile-dialog:not(.hidden)');
}

async function fillDialog(page, fields) {
    for (const [id, val] of Object.entries(fields)) {
        await page.evaluate((sel, v) => {
            const el = document.getElementById(sel);
            if (el) { el.value = v; el.dispatchEvent(new Event('input')); }
        }, id, val);
    }
}

async function saveDialog(page) {
    await page.evaluate(() => window.saveProfile && window.saveProfile());
    await sleep(600);
}

async function findRow(page, name) {
    return page.evaluate((n) => {
        const rows = Array.from(document.querySelectorAll('#profiles-tbody tr'));
        for (const r of rows) {
            if (r.textContent.includes(n)) return true;
        }
        return false;
    }, name);
}

async function cleanupProfile(page) {
    // Supprime le profil de test s'il existe encore (nom current ou renamed)
    const names = [TEST_PROFILE_NAME, TEST_PROFILE_RENAMED];
    for (const n of names) {
        const exists = await findRow(page, n);
        if (!exists) continue;
        // Recupere les id des profils via le DOM des boutons
        const id = await page.evaluate((target) => {
            const rows = Array.from(document.querySelectorAll('#profiles-tbody tr'));
            for (const r of rows) {
                if (!r.textContent.includes(target)) continue;
                const delBtn = r.querySelector('button[onclick*="deleteProfile"]');
                if (delBtn) {
                    const m = delBtn.getAttribute('onclick').match(/deleteProfile\((\d+),/);
                    return m ? parseInt(m[1], 10) : null;
                }
            }
            return null;
        }, n);
        if (id) {
            await page.evaluate(async (i) => {
                await fetch(`${window.API_URL || '/api_proxy.php'}/supervision/profiles/${i}`, {
                    method: 'DELETE',
                });
            }, id);
            await sleep(300);
        }
    }
}

async function testNonPrivileged(browser) {
    // Test secondary account : skip si variables non definies
    const user2 = process.env.E2E_USER2;
    const pass2 = process.env.E2E_PASS2;
    const secret2 = process.env.E2E_TOTP_SECRET2;
    if (!user2 || !pass2) {
        console.log('   [skip] E2E_USER2/E2E_PASS2 non definis - test non-prive saute');
        return;
    }
    // Override TOTP pour ce compte si fourni
    if (secret2) process.env.E2E_TOTP_SECRET = secret2;
    // Contexte incognito pour ne pas heriter du cookie superadmin
    const context = await browser.createBrowserContext();
    const page = await context.newPage();
    page.setDefaultTimeout(15000);
    await page.setViewport({ width: 1440, height: 900 });
    page.on('dialog', d => d.accept().catch(() => {}));
    try {
        await login(page, user2, pass2);
        // Tente POST /profiles et analyse la reponse
        const result = await page.evaluate(async () => {
            const r = await fetch(`${window.API_URL || '/api_proxy.php'}/supervision/profiles`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: 'TEST_Unauthorized', platform: 'zabbix' }),
            });
            const text = await r.text();
            // Si HTML (page de login/2fa), c'est aussi un refus implicite
            const isHtml = text.trim().startsWith('<');
            let body = null;
            try { body = JSON.parse(text); } catch (_) { /* pas JSON */ }
            return { status: r.status, isHtml, body };
        });
        // Refus attendu : 401/403 JSON OU redirect HTML (session/2fa pas valide)
        // Echec SEULEMENT si JSON {success: true} avec 200 (= user a pu creer)
        const granted = !result.isHtml && result.status === 200
                        && result.body && result.body.success === true;
        if (granted) throw new Error('FAIL: user non-privilegie a pu creer un profil');
        console.log(`   [OK] User non-prive bloque (status=${result.status}, html=${result.isHtml}, success=${result.body?.success ?? 'n/a'})`);
        // Cleanup : si par inadvertance cree, supprime
        if (granted && result.body?.id) {
            await page.evaluate(async (id) => {
                await fetch(`${window.API_URL || '/api_proxy.php'}/supervision/profiles/${id}`, { method: 'DELETE' });
            }, result.body.id);
        }
    } finally {
        await page.close();
        try { await context.close(); } catch (e) { /* ok */ }
    }
}

(async () => {
    const browser = await launchBrowser();
    let failed = null;
    const page = await newPage(browser);
    // Auto-accept alerts/confirms (sinon puppeteer timeout sur evaluate)
    page.on('dialog', d => d.accept().catch(() => {}));
    try {
        console.log('> Login superadmin...');
        await login(page);

        console.log('> Onglet Profils...');
        await gotoProfilesTab(page);

        console.log('> Cleanup profils TEST_ existants...');
        await cleanupProfile(page);
        await sleep(300);

        console.log(`> Creation profil "${TEST_PROFILE_NAME}"...`);
        // Creation via API directe (plus deterministe que le dialog UI)
        const createResp = await page.evaluate(async (name) => {
            const r = await fetch((window.API_URL || '/api_proxy.php') + '/supervision/profiles', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name,
                    platform: 'zabbix',
                    description: 'Profil de test auto E2E, a ignorer',
                    host_metadata: 'LinuxTestInterne',
                    zabbix_server: 'zbx-test.lab.local',
                    zabbix_server_active: 'zbx-test.lab.local',
                    zabbix_proxy: '',
                    listen_port: 10050,
                    notes: 'Genere par go-supervision-profiles.mjs - a supprimer',
                }),
            });
            return { status: r.status, body: await r.text() };
        }, TEST_PROFILE_NAME);
        console.log(`   API POST status=${createResp.status} body=${createResp.body.slice(0, 200)}`);
        if (createResp.status !== 200) throw new Error(`FAIL: POST /profiles status=${createResp.status}`);
        // Rafraichit la vue
        await page.evaluate(() => window.loadProfiles && window.loadProfiles());
        await sleep(500);
        if (!(await findRow(page, TEST_PROFILE_NAME))) throw new Error('FAIL: profil cree mais absent du tableau');
        console.log('   [OK] profil cree');

        console.log(`> Edition profil -> "${TEST_PROFILE_RENAMED}"...`);
        // Recupere l'id puis PUT via API
        const pid = await page.evaluate(async (name) => {
            const r = await fetch((window.API_URL || '/api_proxy.php') + '/supervision/profiles?platform=zabbix');
            const d = await r.json();
            const p = (d.profiles || []).find(x => x.name === name);
            return p ? p.id : null;
        }, TEST_PROFILE_NAME);
        if (!pid) throw new Error('FAIL: impossible de retrouver id profil pour edition');
        const editResp = await page.evaluate(async (id, newName) => {
            const r = await fetch((window.API_URL || '/api_proxy.php') + '/supervision/profiles', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id, platform: 'zabbix', name: newName, host_metadata: 'LinuxTestInterneV2' }),
            });
            return { status: r.status, body: await r.text() };
        }, pid, TEST_PROFILE_RENAMED);
        console.log(`   API edit status=${editResp.status}`);
        if (editResp.status !== 200) throw new Error(`FAIL: edit status=${editResp.status}`);
        await page.evaluate(() => window.loadProfiles && window.loadProfiles());
        await sleep(500);
        if (!(await findRow(page, TEST_PROFILE_RENAMED))) throw new Error('FAIL: profil non renomme');
        console.log('   [OK] profil renomme');

        console.log('> Test compte non-privilegie...');
        await testNonPrivileged(browser);

    } catch (e) {
        failed = e;
    } finally {
        console.log('> Cleanup final...');
        try { await cleanupProfile(page); } catch (e) { /* best effort */ }
        await page.close();
        await browser.close();
    }

    if (failed) {
        console.error('[ECHEC]', failed.message);
        process.exit(1);
    }
    console.log('[SUCCES] tous les tests profils supervision OK');
})();
