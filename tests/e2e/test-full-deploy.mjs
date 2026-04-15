import puppeteer from 'puppeteer';
import { login, BASE_URL, sleep } from './helpers.mjs';

const SCREENSHOTS = './screenshots';

const browser = await puppeteer.launch({
    headless: false,
    args: ['--no-sandbox', '--ignore-certificate-errors', '--allow-insecure-localhost', '--start-maximized'],
    defaultViewport: { width: 1400, height: 900 }
});

const page = await browser.newPage();
await page.setViewport({ width: 1400, height: 900 });

// Login
console.log('[1] Login...');
await login(page);
console.log('    URL:', page.url());

// Onglet Config Globale
console.log('[2] Config globale...');
await page.goto(`${BASE_URL}/supervision/`, { waitUntil: 'networkidle2' });
await sleep(500);

// Remplir le formulaire
await page.select('#cfg-agent-type', 'zabbix-agent2');
await page.select('#cfg-agent-version', '7.0');
await page.evaluate(() => { document.getElementById('cfg-zabbix-server').value = '192.168.0.2'; });
await page.evaluate(() => { document.getElementById('cfg-listen-port').value = '10050'; });
await page.evaluate(() => { document.getElementById('cfg-hostname-pattern').value = '{machine.name}'; });
await page.select('#cfg-tls-connect', 'unencrypted');
await page.select('#cfg-tls-accept', 'unencrypted');
await page.evaluate(() => { document.getElementById('cfg-host-metadata').value = 'LinuxInterne'; });

// Sauvegarder
console.log('[3] Sauvegarde config...');
await page.evaluate(() => { saveGlobalConfig(); });
await sleep(2000);
await page.screenshot({ path: `${SCREENSHOTS}/full-01-config-saved.png`, fullPage: true });
console.log('    Screenshot: full-01-config-saved.png');

// Onglet Deploy
console.log('[4] Onglet Deploiement...');
await page.click('.tab-btn[data-tab="deploy"]');
await sleep(500);

// Cocher debian-test
const checkbox = await page.$('input[name="deploy_machines[]"]');
if (checkbox) await checkbox.click();
await sleep(300);
await page.screenshot({ path: `${SCREENSHOTS}/full-02-server-selected.png`, fullPage: true });
console.log('    Screenshot: full-02-server-selected.png');

// Deployer
console.log('[5] Deploiement en cours...');
// Click deploy et accept confirm
page.on('dialog', async dialog => { await dialog.accept(); });
await page.evaluate(() => { deploySingle(1); });

// Attendre que les logs apparaissent (max 120s)
console.log('    Attente des logs de deploiement (max 120s)...');
for (let i = 0; i < 60; i++) {
    await sleep(2000);
    const logText = await page.evaluate(() => {
        const container = document.getElementById('deploy-logs-container');
        return container ? container.textContent : '';
    });
    if (logText.includes('SUCCESS_MACHINE') || logText.includes('reussi') || logText.includes('Deploiement reussi')) {
        console.log('    Deploiement reussi !');
        break;
    }
    if (logText.includes('ERROR_MACHINE') || logText.includes('Exception')) {
        console.log('    ERREUR deploiement detectee');
        break;
    }
    if (i % 5 === 0) {
        const lines = logText.split('\n').filter(l => l.trim()).length;
        console.log(`    ... ${lines} lignes de logs (${(i+1)*2}s)`);
    }
}

await page.screenshot({ path: `${SCREENSHOTS}/full-03-deploy-result.png`, fullPage: true });
console.log('    Screenshot: full-03-deploy-result.png');

// Detection version
console.log('[6] Detection version...');
await page.evaluate(() => { detectVersion(1); });
await sleep(3000);
await page.screenshot({ path: `${SCREENSHOTS}/full-04-version-detected.png`, fullPage: true });
console.log('    Screenshot: full-04-version-detected.png');

console.log('\n=== Test complet termine — navigateur ouvert pour debug ===');
console.log('Ctrl+C pour fermer.');
await new Promise(() => {});
