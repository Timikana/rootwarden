/**
 * go-wazuh-toggle.mjs - Verifie le feature flag WAZUH_ENABLED.
 *
 * Test "vivant" qui s'execute UNIQUEMENT sur l'etat actuel des containers
 * (lit la valeur de WAZUH_ENABLED via le DOM/backend, et asserte la coherence).
 *
 * Test du toggle complet (ON/OFF/ON) : voir scripts/test-wazuh-toggle.sh.
 */
import { BASE_URL, launchBrowser, newPage, login, sleep } from './helpers.mjs';

let failed = 0;
function check(label, ok, details = '') {
    if (ok) console.log(`   [OK] ${label}`);
    else { console.error(`   [ECHEC] ${label}${details ? ' - ' + details : ''}`); failed++; }
}

(async () => {
    const browser = await launchBrowser();
    const page = await newPage(browser);
    page.on('dialog', d => d.accept().catch(() => {}));

    try {
        await login(page);

        // 1. Verifier coherence menu sidebar vs backend
        await page.goto(`${BASE_URL}/`, { waitUntil: 'networkidle2' });
        const menuHasWazuh = await page.evaluate(() =>
            !!document.querySelector('a[href="/wazuh/"]')
        );

        // 2. Backend : check si /wazuh/servers retourne 404 (OFF) ou autre (ON)
        const backendStatus = await page.evaluate(async () => {
            const r = await fetch('/api_proxy.php/wazuh/servers');
            return r.status;
        });

        // Si menu a Wazuh -> backend doit accepter (status != 404)
        // Si menu n'a pas Wazuh -> backend doit retourner 404
        if (menuHasWazuh) {
            check('Menu sidebar : Wazuh visible', true);
            check('Backend : /wazuh/servers accessible (status != 404)',
                  backendStatus !== 404, `got ${backendStatus}`);
            const pageStatus = await page.evaluate(async () => {
                const r = await fetch('/wazuh/', { credentials: 'include' });
                return r.status;
            });
            check('Page /wazuh/ retourne 200', pageStatus === 200, `got ${pageStatus}`);
        } else {
            check('Menu sidebar : Wazuh cache (WAZUH_ENABLED=false)', true);
            // 404 (route absente) ou 405 (Flask catchall OPTIONS-only matche
            // mais GET non autorise) - les deux indiquent "blueprint disable".
            check('Backend : /wazuh/servers bloque (404 ou 405)',
                  backendStatus === 404 || backendStatus === 405, `got ${backendStatus}`);
            const pageStatus = await page.evaluate(async () => {
                const r = await fetch('/wazuh/', { credentials: 'include' });
                return r.status;
            });
            check('Page /wazuh/ retourne 404', pageStatus === 404, `got ${pageStatus}`);
        }

        console.log(`\n>> Etat detecte : Wazuh = ${menuHasWazuh ? 'ON' : 'OFF'}`);
    } finally {
        await page.close();
        await browser.close();
    }

    if (failed > 0) { console.error(`\n[ECHEC] ${failed} verification(s) cassee(s)`); process.exit(1); }
    console.log('\n[SUCCES] feature flag WAZUH coherent entre frontend et backend');
})();
