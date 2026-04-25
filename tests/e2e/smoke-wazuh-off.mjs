// Petite capture comparative ON vs OFF
import { BASE_URL, launchBrowser, newPage, login, sleep } from './helpers.mjs';
const browser = await launchBrowser();
const page = await newPage(browser);
await login(page);
await page.goto(BASE_URL + '/', { waitUntil: 'networkidle2' });
await sleep(500);
await page.screenshot({ path: './screenshots/v1.17/wazuh-off-dashboard.png', fullPage: true });
console.log('saved wazuh-off-dashboard.png');
await browser.close();
