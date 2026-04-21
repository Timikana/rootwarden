/**
 * 04-ssh-preflight.test.mjs - E2E : SSH preflight check
 *
 * Valide :
 *  - Page Cles SSH accessible
 *  - Serveurs listes avec checkboxes
 *  - Selectionner un serveur
 *  - Le bouton "Deployer les cles" est present
 *  - (Optionnel) La zone de logs existe
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { launchBrowser, newPage, login, BASE_URL } from './helpers.mjs';

let browser, page;

describe('04 - SSH Preflight', () => {
    before(async () => {
        browser = await launchBrowser();
        page = await newPage(browser);
        await login(page);
    });

    after(async () => {
        await browser?.close();
    });

    it('should navigate to SSH management page', async () => {
        await page.goto(`${BASE_URL}/ssh/`, { waitUntil: 'networkidle2' });
        const content = await page.content();
        assert.ok(content.includes('Deploiement des cles SSH'), 'Expected SSH deployment heading');
    });

    it('should list servers with checkboxes', async () => {
        const serverCount = await page.evaluate(() => {
            return document.querySelectorAll('input[type="checkbox"]').length;
        });
        assert.ok(serverCount > 0, `Expected at least 1 server checkbox, got ${serverCount}`);
    });

    it('should show deploy button', async () => {
        const deployBtn = await page.evaluate(() => {
            const btns = document.querySelectorAll('button');
            for (const b of btns) {
                if (b.textContent.includes('Deployer')) return b.textContent.trim();
            }
            return null;
        });
        assert.ok(deployBtn, 'Expected "Deployer les cles" button');
    });

    it('should have a log zone', async () => {
        const content = await page.content();
        assert.ok(
            content.includes('LOGS DE DEPLOIEMENT') || content.includes('logs') || content.includes('En attente'),
            'Expected log zone on SSH page'
        );
    });

    it('should select a server', async () => {
        // Cocher le premier serveur
        await page.evaluate(() => {
            const cb = document.querySelector('input[type="checkbox"]');
            if (cb && !cb.checked) cb.click();
        });

        const checked = await page.evaluate(() => {
            const cb = document.querySelector('input[type="checkbox"]');
            return cb?.checked ?? false;
        });
        assert.ok(checked, 'Expected first server to be checked');
    });
});
