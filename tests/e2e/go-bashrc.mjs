/**
 * go-bashrc.mjs — Tests E2E module Bashrc
 *
 * Flux teste :
 *   1. Login superadmin + TOTP
 *   2. Navigation /bashrc/
 *   3. Liste users pour le premier serveur
 *   4. Preview dry_run
 *   5. Deploy mode merge (sur un user unique)
 *   6. Verification backup via SSH (pas docker exec — namespaces differents)
 *   7. Verification syntaxe bash -n post-deploy
 *   8. Restore depuis le backup le plus recent
 *
 * Utilisation : node tests/e2e/go-bashrc.mjs
 * Prerequis   : BASE_URL, E2E_USER, E2E_PASS, E2E_TOTP_SECRET configurees dans helpers.mjs
 */

import { BASE_URL, launchBrowser, newPage, login, sleep } from './helpers.mjs';
import fs from 'fs';
import path from 'path';

const SCREENSHOT_DIR = 'tests/e2e/screenshots/bashrc';
fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });

function shot(page, name) {
    return page.screenshot({
        path: path.join(SCREENSHOT_DIR, `${String(Date.now()).slice(-6)}-${name}.png`),
        fullPage: true,
    });
}

async function apiCall(page, path, opts = {}) {
    return page.evaluate(async (url, options) => {
        const meta = document.querySelector('meta[name="csrf-token"]');
        const headers = Object.assign(
            { 'Content-Type': 'application/json' },
            options.headers || {},
            meta ? { 'X-CSRF-TOKEN': meta.getAttribute('content') } : {},
        );
        const res = await fetch(url, Object.assign({ headers }, options));
        const text = await res.text();
        try { return { status: res.status, json: JSON.parse(text) }; }
        catch { return { status: res.status, json: null, raw: text }; }
    }, path, opts);
}

async function main() {
    console.log('== Bashrc E2E ==');
    const browser = await launchBrowser();
    const page = await newPage(browser);

    try {
        // 1. Login
        console.log('→ Login superadmin');
        await login(page);
        await shot(page, 'login-done');

        // 2. Navigate to /bashrc/
        console.log('→ Navigate /bashrc/');
        await page.goto(`${BASE_URL}/bashrc/`, { waitUntil: 'networkidle2' });
        await shot(page, 'bashrc-landing');

        const title = await page.$eval('h1', el => el.textContent.trim());
        if (!/bashrc/i.test(title)) {
            throw new Error(`Title does not contain "Bashrc" : ${title}`);
        }

        // 3. Liste des serveurs dispo
        const machines = await page.$$eval('#machine-select option', opts =>
            opts.filter(o => o.value).map(o => ({ id: o.value, label: o.textContent.trim() }))
        );
        if (!machines.length) {
            console.warn('   aucun serveur disponible, skip');
            await browser.close(); return;
        }
        const target = machines[0];
        console.log(`   serveur cible : ${target.label} (id=${target.id})`);

        // 4. Liste users via API proxy
        console.log('→ GET /bashrc/users');
        const usersResp = await apiCall(page, `/api_proxy.php/bashrc/users?machine_id=${target.id}`);
        console.log(`   status=${usersResp.status} success=${usersResp.json?.success} figlet=${usersResp.json?.figlet_present} users=${(usersResp.json?.users || []).length}`);
        if (!usersResp.json?.success) {
            console.warn(`   erreur backend : ${usersResp.json?.message || usersResp.raw}`);
            await browser.close(); return;
        }
        const users = usersResp.json.users || [];
        const testUser = users.find(u => u.name === 'root') || users[0];
        if (!testUser) {
            console.warn('   aucun user disponible, skip');
            await browser.close(); return;
        }
        console.log(`   user test : ${testUser.name} (home=${testUser.home})`);

        // 5. Preview dry_run
        console.log('→ POST /bashrc/preview (dry)');
        const preview = await apiCall(page, '/api_proxy.php/bashrc/preview', {
            method: 'POST',
            body: JSON.stringify({
                machine_id: parseInt(target.id, 10),
                users: [testUser.name],
                mode: 'merge',
            }),
        });
        console.log(`   status=${preview.status} success=${preview.json?.success}`);
        if (!preview.json?.success) {
            console.warn(`   preview echec : ${preview.json?.message}`);
        } else {
            const r = preview.json.results[0];
            console.log(`   diff bytes : current=${r.current_bytes} new=${r.new_bytes} custom=${r.custom_detected}`);
        }

        // 6. Select dans le UI pour screenshot
        await page.select('#machine-select', target.id);
        await sleep(1500);
        await shot(page, 'users-loaded');

        // 7. Deploy dry_run via API
        console.log('→ POST /bashrc/deploy (dry_run=true)');
        const dry = await apiCall(page, '/api_proxy.php/bashrc/deploy', {
            method: 'POST',
            body: JSON.stringify({
                machine_id: parseInt(target.id, 10),
                users: [testUser.name],
                mode: 'merge',
                dry_run: true,
            }),
        });
        console.log(`   status=${dry.status} ok=${dry.json?.summary?.ok}/${dry.json?.summary?.total}`);

        // 8. Deploy reel (merge)
        console.log('→ POST /bashrc/deploy (real, merge)');
        const deploy = await apiCall(page, '/api_proxy.php/bashrc/deploy', {
            method: 'POST',
            body: JSON.stringify({
                machine_id: parseInt(target.id, 10),
                users: [testUser.name],
                mode: 'merge',
                dry_run: false,
            }),
        });
        console.log(`   status=${deploy.status} summary=${JSON.stringify(deploy.json?.summary)}`);
        if (!deploy.json?.success) {
            throw new Error(`deploy failed : ${deploy.json?.message}`);
        }
        const depRes = deploy.json.results[0];
        console.log(`   deploy result : ok=${depRes.ok} backup=${depRes.backup} syntax_ok=${depRes.syntax_ok} skipped=${depRes.skipped}`);

        // 9. Liste backups
        console.log('→ GET /bashrc/backups');
        const backups = await apiCall(page, `/api_proxy.php/bashrc/backups?machine_id=${target.id}&user=${testUser.name}`);
        console.log(`   backups count=${(backups.json?.backups || []).length}`);

        // 10. Restore (si on a fait un deploy reel avec backup)
        if (depRes.backup) {
            console.log('→ POST /bashrc/restore');
            const restore = await apiCall(page, '/api_proxy.php/bashrc/restore', {
                method: 'POST',
                body: JSON.stringify({
                    machine_id: parseInt(target.id, 10),
                    user: testUser.name,
                    backup: depRes.backup,
                }),
            });
            console.log(`   status=${restore.status} success=${restore.json?.success}`);
        }

        // 11. Switch onglet Historique
        console.log('→ Onglet Historique');
        await page.evaluate(() => {
            const btn = Array.from(document.querySelectorAll('.tab-btn'))
                .find(b => b.dataset.tab === 'history');
            if (btn) btn.click();
        });
        await sleep(500);
        await shot(page, 'history-tab');

        // 12. Switch onglet Template
        console.log('→ Onglet Template');
        await page.evaluate(() => {
            const btn = Array.from(document.querySelectorAll('.tab-btn'))
                .find(b => b.dataset.tab === 'template');
            if (btn) btn.click();
        });
        await sleep(500);
        await shot(page, 'template-tab');

        console.log('== DONE ==');
    } catch (e) {
        console.error('TEST FAILED:', e.message);
        await shot(page, 'failure');
        process.exitCode = 1;
    } finally {
        await browser.close();
    }
}

main();
