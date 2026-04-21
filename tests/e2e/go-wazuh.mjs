/**
 * go-wazuh.mjs - Tests E2E module Wazuh.
 * Flux : login, config save, options save, rules CRUD (incl. xmllint).
 */
import puppeteer from 'puppeteer';
import { BASE_URL, login, sleep } from './helpers.mjs';
import fs from 'fs';
import path from 'path';

const SHOT_DIR = 'tests/e2e/screenshots/wazuh';
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
    console.log('== Wazuh E2E ==');
    await login(page);
    await page.goto(`${BASE_URL}/wazuh/`, { waitUntil: 'networkidle2' });
    await shot(page, 'landing');

    console.log('1. GET /wazuh/config');
    const cfg = await call(page, '/api_proxy.php/wazuh/config');
    a(cfg.success === true, 'config load');

    console.log('2. POST /wazuh/config (invalid manager)');
    const bad = await call(page, '/api_proxy.php/wazuh/config', {
        method: 'POST', body: JSON.stringify({ manager_ip: 'a b c' })
    });
    a(bad.success === false, 'manager invalide rejete');

    console.log('3. POST /wazuh/config (valid)');
    const ok = await call(page, '/api_proxy.php/wazuh/config', {
        method: 'POST',
        body: JSON.stringify({
            manager_ip: 'wazuh.test.local', manager_port: 1514, registration_port: 1515,
            registration_password: 'TestPwd1234!', default_group: 'default',
            agent_version: 'latest', enable_active_response: false
        })
    });
    a(ok.success === true, 'config saved');

    console.log('4. GET /wazuh/servers');
    const srv = await call(page, '/api_proxy.php/wazuh/servers');
    a(srv.success === true, `servers (${(srv.servers || []).length})`);

    console.log('5. POST /wazuh/rules (XML invalide)');
    const bx = await call(page, '/api_proxy.php/wazuh/rules', {
        method: 'POST', body: JSON.stringify({
            name: 'e2e-bad', rule_type: 'rules',
            content: '<group name="test"><rule id="1001"><level>5</level>'  // pas fermee
        })
    });
    a(bx.success === false, 'XML invalide rejete');

    console.log('6. POST /wazuh/rules (XML valide)');
    const gx = await call(page, '/api_proxy.php/wazuh/rules', {
        method: 'POST', body: JSON.stringify({
            name: 'e2e-test', rule_type: 'rules',
            content: '<group name="e2e,test,">\n  <rule id="100001" level="5">\n    <match>test</match>\n    <description>Test E2E</description>\n  </rule>\n</group>'
        })
    });
    a(gx.success === true, `rule cree (sha=${gx.sha8})`);

    console.log('7. GET /wazuh/rules/e2e-test');
    const gr = await call(page, '/api_proxy.php/wazuh/rules/e2e-test');
    a(gr.success === true && gr.rule?.name === 'e2e-test', 'rule readable');

    console.log('8. Options save (invalid FIM path)');
    const bp = await call(page, '/api_proxy.php/wazuh/options', {
        method: 'POST', body: JSON.stringify({
            machine_id: 1, fim_paths: ['/etc; rm -rf /']
        })
    });
    a(bp.success === false, 'FIM path avec shell chars rejete');

    console.log('9. DELETE rule');
    const d = await call(page, '/api_proxy.php/wazuh/rules/e2e-test', { method: 'DELETE' });
    a(d.success === true, 'rule supprimee');

    // Screenshots onglets
    for (const t of ['deploy', 'options', 'rules', 'history']) {
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
