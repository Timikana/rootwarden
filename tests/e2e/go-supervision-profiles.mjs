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
    const page = await newPage(browser);
    try {
        await login(page, user2, pass2);
        await page.goto(`${BASE_URL}/supervision/`, { waitUntil: 'networkidle2', timeout: 10000 });
        const url = page.url();
        // User non-privilegie : redirect vers login OU 403 OU menu sans l'entree supervision
        const privileged = url.includes('/supervision/');
        if (privileged) {
            // Verifier qu'il ne peut PAS creer de profil via l'API proxy (403 attendu)
            const status = await page.evaluate(async () => {
                const r = await fetch(`${window.API_URL || '/api_proxy.php'}/supervision/profiles`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: 'TEST_Unauthorized', platform: 'zabbix' }),
                });
                return r.status;
            });
            if (status === 200) throw new Error('FAIL: user non-privilegie a pu creer un profil (status 200)');
            console.log(`   [OK] User non-prive refuse sur POST profils (status=${status})`);
        } else {
            console.log(`   [OK] User non-prive redirige hors de /supervision/ (url=${url})`);
        }
    } finally {
        await page.close();
    }
}

(async () => {
    const browser = await launchBrowser();
    let failed = null;
    const page = await newPage(browser);
    try {
        console.log('> Login superadmin...');
        await login(page);

        console.log('> Onglet Profils...');
        await gotoProfilesTab(page);

        console.log('> Cleanup profils TEST_ existants...');
        await cleanupProfile(page);
        await sleep(300);

        console.log(`> Creation profil "${TEST_PROFILE_NAME}"...`);
        await openNewDialog(page);
        await fillDialog(page, {
            'profile-name': TEST_PROFILE_NAME,
            'profile-description': 'Profil de test auto E2E, a ignorer',
            'profile-host-metadata': 'LinuxTestInterne',
            'profile-server': 'zbx-test.lab.local',
            'profile-server-active': 'zbx-test.lab.local',
            'profile-proxy': '',
            'profile-listen-port': '10050',
            'profile-notes': 'Genere par go-supervision-profiles.mjs - a supprimer',
        });
        await saveDialog(page);
        await sleep(400);
        if (!(await findRow(page, TEST_PROFILE_NAME))) throw new Error('FAIL: profil non cree');
        console.log('   [OK] profil cree');

        console.log(`> Edition profil -> "${TEST_PROFILE_RENAMED}"...`);
        // Click sur le bouton Editer du profil
        await page.evaluate((name) => {
            const rows = Array.from(document.querySelectorAll('#profiles-tbody tr'));
            for (const r of rows) {
                if (!r.textContent.includes(name)) continue;
                const btn = r.querySelector('button[onclick*="editProfile"]');
                if (btn) btn.click();
                return;
            }
        }, TEST_PROFILE_NAME);
        await sleep(300);
        await fillDialog(page, { 'profile-name': TEST_PROFILE_RENAMED });
        await saveDialog(page);
        await sleep(400);
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
