/**
 * go-graylog.mjs - Tests E2E module Graylog.
 * Flux : login, config save, list servers, collectors CRUD.
 */
import puppeteer from 'puppeteer';
import { BASE_URL, login, sleep } from './helpers.mjs';
import fs from 'fs';
import path from 'path';

const SHOT_DIR = 'tests/e2e/screenshots/graylog';
fs.mkdirSync(SHOT_DIR, { recursive: true });
const shot = (page, name) => page.screenshot({
    path: path.join(SHOT_DIR, `${String(Date.now()).slice(-6)}-${name}.png`), fullPage: true,
});

async function call(page, p, opts = {}) {
    return page.evaluate(async (url, o) => {
        const meta = document.querySelector('meta[name="csrf-token"]');
        const headers = Object.assign({ 'Content-Type': 'application/json' }, o.headers || {},
            meta ? { 'X-CSRF-TOKEN': meta.getAttribute('content') } : {});
        const r = await fetch(url, Object.assign({ headers }, o));
        const t = await r.text();
        try { return JSON.parse(t); } catch { return { success: false, message: t.slice(0, 200) }; }
    }, p, opts);
}

const browser = await puppeteer.launch({
    headless: false,
    defaultViewport: { width: 1400, height: 900 },
    args: ['--no-sandbox', '--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
});
const page = await browser.newPage();
page.setDefaultTimeout(20000);
await page.setViewport({ width: 1400, height: 900 });

let fail = 0;
const a = (c, m) => { console.log((c ? '  ✓ ' : '  ✗ ') + m); if (!c) fail++; };

try {
    console.log('== Graylog E2E ==');
    await login(page);
    await page.goto(`${BASE_URL}/graylog/`, { waitUntil: 'networkidle2' });
    await shot(page, 'landing');

    console.log('1. GET /graylog/config');
    const cfg = await call(page, '/api_proxy.php/graylog/config');
    a(cfg.success === true, 'config load OK');

    console.log('2. POST /graylog/config (invalid url)');
    const bad = await call(page, '/api_proxy.php/graylog/config', {
        method: 'POST', body: JSON.stringify({ server_url: 'not-a-url' })
    });
    a(bad.success === false, 'URL invalide rejetee');

    console.log('3. POST /graylog/config (valid)');
    const ok = await call(page, '/api_proxy.php/graylog/config', {
        method: 'POST',
        body: JSON.stringify({
            server_url: 'https://graylog.test:9000',
            api_token: 'test-token-1234567890',
            tls_verify: false, sidecar_version: 'latest'
        })
    });
    a(ok.success === true, 'config saved');

    console.log('4. GET /graylog/servers');
    const srv = await call(page, '/api_proxy.php/graylog/servers');
    a(srv.success === true, `servers loaded (${(srv.servers || []).length})`);

    console.log('5. POST /graylog/collectors (invalid name)');
    const bi = await call(page, '/api_proxy.php/graylog/collectors', {
        method: 'POST', body: JSON.stringify({ name: 'bad name!', content: '' })
    });
    a(bi.success === false, 'name invalide rejetee');

    console.log('6. POST /graylog/collectors (valid + YAML)');
    const ci = await call(page, '/api_proxy.php/graylog/collectors', {
        method: 'POST', body: JSON.stringify({
            name: 'e2e-test', collector_type: 'filebeat',
            content: "filebeat.inputs:\n  - type: log\n    paths: ['/var/log/syslog']\n",
            tags: 'test,e2e'
        })
    });
    a(ci.success === true, `collector cree (sha=${ci.sha8})`);

    console.log('7. GET /graylog/collectors');
    const cl = await call(page, '/api_proxy.php/graylog/collectors');
    a((cl.collectors || []).some(c => c.name === 'e2e-test'), 'collector dans la liste');

    console.log('8. DELETE collector');
    const d = await call(page, '/api_proxy.php/graylog/collectors/e2e-test', { method: 'DELETE' });
    a(d.success === true, 'collector supprime');

    // Switch UI tabs pour screenshots
    for (const t of ['deploy', 'collectors', 'history']) {
        await page.evaluate((tn) => {
            const b = Array.from(document.querySelectorAll('.tab-btn')).find(x => x.dataset.tab === tn);
            if (b) b.click();
        }, t);
        await sleep(700);
        await shot(page, 'tab-' + t);
    }

    console.log('\n' + (fail === 0 ? '== ✓ ALL PASS ==' : `== ✗ ${fail} FAIL ==`));
} catch (e) {
    console.error('FAIL:', e.message);
    await shot(page, 'error');
    fail++;
} finally {
    await sleep(2000);
    await browser.close();
    process.exit(fail === 0 ? 0 : 1);
}
