import { BASE_URL, launchBrowser, newPage, login, sleep } from './helpers.mjs';

const browser = await launchBrowser();
const page = await newPage(browser);
page.on('dialog', d => d.accept().catch(() => {}));

await login(page);
await page.goto(`${BASE_URL}/security/`, { waitUntil: 'networkidle2' });
// Ouvre le details "Scans planifies"
await page.evaluate(() => {
    document.querySelectorAll('details').forEach(d => d.open = true);
});
await sleep(1200);

await page.screenshot({ path: 'security-page.png', fullPage: true });
console.log('saved security-page.png');

// Screenshot ciblé sur la section des scans planifiés
const el = await page.$('details');
if (el) {
    const box = await el.boundingBox();
    await page.screenshot({
        path: 'security-schedules.png',
        clip: { x: 0, y: Math.max(0, box.y - 20), width: 1440, height: Math.min(900, box.height + 40) },
    });
    console.log('saved security-schedules.png');
}

// Ouvre aussi le modal preset pour le capturer
await page.evaluate(() => window.openCronPresets && window.openCronPresets());
await sleep(500);
await page.screenshot({ path: 'security-presets-modal.png' });
console.log('saved security-presets-modal.png');

await browser.close();
