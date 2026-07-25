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

    // Modele actuel : forwarding rsyslog (server_host + server_port + protocol),
    // et "templates" (plus "collectors"). L'ancien modele sidecar (server_url/
    // api_token/collectors) a ete remplace.
    console.log('2. POST /graylog/config (host invalide)');
    const bad = await call(page, '/api_proxy.php/graylog/config', {
        method: 'POST', body: JSON.stringify({ server_host: 'a b c', server_port: 514, protocol: 'udp' })
    });
    a(bad.success === false, 'host invalide rejete');

    console.log('3. POST /graylog/config (valid)');
    const ok = await call(page, '/api_proxy.php/graylog/config', {
        method: 'POST',
        body: JSON.stringify({
            server_host: 'graylog.test', server_port: 1514, protocol: 'tcp',
            ratelimit_burst: 0, ratelimit_interval: 0
        })
    });
    a(ok.success === true, 'config saved');

    console.log('4. GET /graylog/servers');
    const srv = await call(page, '/api_proxy.php/graylog/servers');
    a(srv.success === true, `servers loaded (${(srv.servers || []).length})`);

    console.log('5. POST /graylog/templates (name invalide)');
    const bi = await call(page, '/api_proxy.php/graylog/templates', {
        method: 'POST', body: JSON.stringify({ name: 'bad name!', content: '' })
    });
    a(bi.success === false, 'name invalide rejete');

    console.log('6. POST /graylog/templates (valide)');
    const ci = await call(page, '/api_proxy.php/graylog/templates', {
        method: 'POST', body: JSON.stringify({
            name: 'e2e-test', description: 'template e2e',
            content: "*.* @@graylog.test:1514;RSYSLOG_SyslogProtocol23Format\n",
            enabled: true
        })
    });
    a(ci.success === true, `template cree (sha=${ci.sha8})`);

    console.log('7. GET /graylog/templates');
    const cl = await call(page, '/api_proxy.php/graylog/templates');
    a((cl.templates || []).some(c => c.name === 'e2e-test'), 'template dans la liste');

    console.log('8. DELETE template');
    const d = await call(page, '/api_proxy.php/graylog/templates/e2e-test', { method: 'DELETE' });
    a(d.success === true, 'template supprime');

    // Switch UI tabs pour screenshots
    for (const t of ['deploy', 'templates', 'history']) {
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
