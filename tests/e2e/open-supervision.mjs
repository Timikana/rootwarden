import puppeteer from 'puppeteer';
import { login, BASE_URL } from './helpers.mjs';

const browser = await puppeteer.launch({
    headless: false,
    args: ['--no-sandbox', '--ignore-certificate-errors', '--allow-insecure-localhost', '--start-maximized'],
    defaultViewport: { width: 1400, height: 900 }
});

const page = await browser.newPage();
await page.setViewport({ width: 1400, height: 900 });

console.log('Login...');
await login(page);
console.log('URL:', page.url());

console.log('Navigation vers /supervision/...');
await page.goto(`${BASE_URL}/supervision/`, { waitUntil: 'networkidle2' });
console.log('Page ouverte - navigateur visible. Ctrl+C pour fermer.');

await new Promise(() => {});
