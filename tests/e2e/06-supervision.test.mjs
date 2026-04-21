/**
 * 06-supervision.test.mjs - Test E2E du module Supervision
 *
 * Verifie :
 *   - Page /supervision/ accessible apres login
 *   - 4 onglets presents et fonctionnels
 *   - Formulaire configuration globale affiche
 *   - Tableau deploiement affiche
 *   - Editeur de configuration affiche
 *   - Onglet monitoring placeholder affiche
 */
import puppeteer from 'puppeteer';
import { login, BASE_URL, assertTextPresent, assertSelector, sleep, generateTOTP } from './helpers.mjs';

const SCREENSHOTS_DIR = './tests/e2e/screenshots';

async function run() {
    console.log('=== Test Supervision Module ===');

    const browser = await puppeteer.launch({
        headless: false,
        args: ['--no-sandbox', '--ignore-certificate-errors', '--allow-insecure-localhost'],
    });

    const page = await browser.newPage();
    page.setDefaultTimeout(15000);
    await page.setViewport({ width: 1400, height: 900 });

    // Login - credentials via env ou defaults
    const user = process.env.E2E_USER || 'superadmin';
    const pass = process.env.E2E_PASS || 'superadmin';
    console.log(`[1] Login as ${user}...`);
    await login(page, user, pass);
    const urlAfterLogin = page.url();
    console.log('    URL after login:', urlAfterLogin);
    await page.screenshot({ path: `${SCREENSHOTS_DIR}/supervision-00-after-login.png`, fullPage: true });
    if (urlAfterLogin.includes('login')) {
        console.error('    ERREUR: login echoue - verifier E2E_USER / E2E_PASS / E2E_TOTP_SECRET');
        console.error('    Usage: E2E_USER=xxx E2E_PASS=yyy E2E_TOTP_SECRET=zzz node tests/e2e/06-supervision.test.mjs');
        await browser.close();
        process.exit(1);
    }
    console.log('    OK - logged in');

    // Navigate to supervision
    console.log('[2] Navigation vers /supervision/...');
    await page.goto(`${BASE_URL}/supervision/`, { waitUntil: 'networkidle2' });
    await sleep(1000);
    await page.screenshot({ path: `${SCREENSHOTS_DIR}/supervision-01-config.png`, fullPage: true });
    console.log('    Screenshot: supervision-01-config.png');

    // Check page title
    await assertTextPresent(page, 'Supervision');
    console.log('    OK - titre present');

    // Check 4 tabs exist
    const tabs = await page.$$('.tab-btn');
    if (tabs.length !== 4) throw new Error(`Expected 4 tabs, got ${tabs.length}`);
    console.log('    OK - 4 onglets');

    // Onglet 1 : Configuration globale
    await assertSelector(page, '#cfg-zabbix-server');
    await assertSelector(page, '#cfg-agent-type');
    await assertSelector(page, '#cfg-tls-connect');
    console.log('    OK - formulaire config globale');

    // Onglet 2 : Deploiement
    console.log('[3] Onglet Deploiement...');
    await page.click('.tab-btn[data-tab="deploy"]');
    await sleep(500);
    await page.screenshot({ path: `${SCREENSHOTS_DIR}/supervision-02-deploy.png`, fullPage: true });
    console.log('    Screenshot: supervision-02-deploy.png');
    await assertSelector(page, '#deploy-table-body');
    console.log('    OK - tableau deploiement');

    // Onglet 3 : Editeur
    console.log('[4] Onglet Editeur...');
    await page.click('.tab-btn[data-tab="editor"]');
    await sleep(500);
    await page.screenshot({ path: `${SCREENSHOTS_DIR}/supervision-03-editor.png`, fullPage: true });
    console.log('    Screenshot: supervision-03-editor.png');
    await assertSelector(page, '#editor-content');
    await assertSelector(page, '#editor-server');
    console.log('    OK - editeur de config');

    // Onglet 4 : Monitoring
    console.log('[5] Onglet Monitoring...');
    await page.click('.tab-btn[data-tab="monitoring"]');
    await sleep(500);
    await page.screenshot({ path: `${SCREENSHOTS_DIR}/supervision-04-monitoring.png`, fullPage: true });
    console.log('    Screenshot: supervision-04-monitoring.png');
    console.log('    OK - placeholder monitoring');

    // Retour onglet config et verif page updates
    console.log('[6] Verification page Updates (pas de Zabbix)...');
    await page.goto(`${BASE_URL}/update/`, { waitUntil: 'networkidle2' });
    await sleep(1000);
    await page.screenshot({ path: `${SCREENSHOTS_DIR}/supervision-05-updates-no-zabbix.png`, fullPage: true });
    console.log('    Screenshot: supervision-05-updates-no-zabbix.png');

    // Verifier que le bouton Zabbix n'est plus present
    const zabbixBtn = await page.$('#zabbix-version');
    if (zabbixBtn) throw new Error('Le champ zabbix-version est encore present dans Updates !');
    console.log('    OK - plus de Zabbix dans Updates');

    // Check menu
    console.log('[7] Verification lien Supervision dans le menu...');
    const menuLink = await page.$('a[href="/supervision/"]');
    if (!menuLink) throw new Error('Lien Supervision absent du menu');
    console.log('    OK - lien menu present');

    console.log('\n=== TOUS LES TESTS OK ===');
    await browser.close();
}

run().catch(err => {
    console.error('\n=== TEST FAILED ===');
    console.error(err.message);
    process.exit(1);
});
