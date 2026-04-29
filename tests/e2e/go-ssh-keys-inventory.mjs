/**
 * go-ssh-keys-inventory.mjs - Smoke test inventaire SSH keys (v1.18.x).
 *
 * 1. Login superadmin
 * 2. Lance un scan_server_users sur la 1ere machine
 * 3. Appelle /server_user_keys?machine_id=X&username=Y
 * 4. Verifie format de la reponse (keys list, fingerprint SHA256, etc.)
 */
import { BASE_URL, launchBrowser, newPage, login, sleep } from './helpers.mjs';

let failed = 0;
function check(label, ok, details = '') {
    if (ok) console.log(`   [OK] ${label}`);
    else { console.error(`   [ECHEC] ${label}${details ? ' - ' + details : ''}`); failed++; }
}

async function apiFetch(page, path, init = {}) {
    return page.evaluate(async (p, i) => {
        const r = await fetch((window.API_URL || '/api_proxy.php') + p, i);
        const text = await r.text();
        let body = null; try { body = JSON.parse(text); } catch (_) {}
        return { status: r.status, body, text };
    }, path, init);
}

(async () => {
    const browser = await launchBrowser();
    const page = await newPage(browser);
    page.on('dialog', d => d.accept().catch(() => {}));

    try {
        await login(page);

        const machines = await apiFetch(page, '/list_machines');
        const m = (machines.body?.machines || [])[0];
        if (!m) { console.log('[SKIP] aucune machine en base'); return; }
        console.log(`> Machine cible : ${m.name} (id=${m.id})`);

        console.log('> Scan users...');
        const scan = await page.evaluate(async (mid) => {
            const meta = document.querySelector('meta[name="csrf-token"]');
            const r = await fetch('/api_proxy.php/scan_server_users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': meta?.content || '' },
                body: JSON.stringify({ machine_id: mid }),
            });
            return r.json();
        }, m.id);
        check('scan_server_users success', scan.success === true,
              `msg: ${scan.message || ''}`);

        const userWithKey = (scan.users || []).find(u => u.keys_count > 0);
        if (!userWithKey) {
            console.log('   [SKIP] aucun user avec authorized_keys sur cette machine');
            return;
        }
        console.log(`> User avec ${userWithKey.keys_count} cles : ${userWithKey.username}`);

        console.log('> GET /server_user_keys...');
        const keysResp = await apiFetch(page, `/server_user_keys?machine_id=${m.id}&username=${encodeURIComponent(userWithKey.username)}`);
        check('endpoint retourne 200', keysResp.status === 200, `got ${keysResp.status}`);
        check('reponse success=true', keysResp.body?.success === true);
        check('keys est un tableau', Array.isArray(keysResp.body?.keys));
        if (Array.isArray(keysResp.body?.keys) && keysResp.body.keys.length > 0) {
            const k = keysResp.body.keys[0];
            check('cle a un type', typeof k.type === 'string' && k.type.length > 0);
            check('fingerprint commence par SHA256:',
                  typeof k.fingerprint === 'string' && k.fingerprint.startsWith('SHA256:'),
                  `got: ${k.fingerprint}`);
            check('owner_name est string ou null',
                  k.owner_name === null || typeof k.owner_name === 'string');
            console.log(`   [INFO] type=${k.type} fp=${k.fingerprint?.slice(0, 30)}... owner=${k.owner_name || 'inconnu'} platform=${k.is_platform}`);
        }
    } finally {
        await page.close();
        await browser.close();
    }

    if (failed > 0) { console.error(`\n[ECHEC] ${failed} verification(s) cassee(s)`); process.exit(1); }
    console.log('\n[SUCCES] inventaire SSH keys fonctionne');
})();
