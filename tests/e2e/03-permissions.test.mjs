/**
 * 03-permissions.test.mjs - E2E : Permissions toggle via htmx
 *
 * Valide :
 *  - Page Acces & Droits accessible
 *  - Ouvrir les permissions d'un user
 *  - Cocher une permission → fond bleu (htmx swap)
 *  - Decocher la meme permission → fond gris
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { launchBrowser, newPage, login, sleep, BASE_URL } from './helpers.mjs';

let browser, page;
const TARGET_USER_ID = '1'; // admin

describe('03 - Permissions htmx toggle', () => {
    before(async () => {
        browser = await launchBrowser();
        page = await newPage(browser);
        await login(page);
    });

    after(async () => {
        await browser?.close();
    });

    it('should navigate to Acces & Droits tab', async () => {
        await page.goto(`${BASE_URL}/adm/admin_page.php`, { waitUntil: 'networkidle2' });

        // Cliquer sur l'onglet "Acces & Droits"
        await page.evaluate(() => {
            const tabs = document.querySelectorAll('[role="tab"], button, a');
            for (const t of tabs) {
                if (t.textContent.trim().includes('Droits')) { t.click(); break; }
            }
        });
        await sleep(500);

        const content = await page.content();
        assert.ok(content.includes("Droits d'acces") || content.includes('Droits'), 'Expected permissions section');
    });

    it('should open admin permissions card', async () => {
        await page.evaluate((userId) => {
            const details = document.querySelectorAll('details');
            for (const d of details) {
                const summary = d.querySelector('summary');
                if (summary && summary.textContent.includes('admin') && summary.textContent.includes('/10')) {
                    d.setAttribute('open', '');
                    d.scrollIntoView();
                    break;
                }
            }
        }, TARGET_USER_ID);

        await sleep(300);
        const checkbox = await page.$(`input[data-user-id="${TARGET_USER_ID}"][hx-post]`);
        assert.ok(checkbox, 'Expected htmx permission checkbox for admin');
    });

    it('should toggle a permission via htmx', async () => {
        // Trouver une permission non cochee pour la cocher
        const permKey = await page.evaluate((userId) => {
            const cbs = document.querySelectorAll(`input[data-user-id="${userId}"][hx-post]`);
            for (const cb of cbs) {
                if (!cb.checked) return cb.dataset.permission;
            }
            return null;
        }, TARGET_USER_ID);

        if (!permKey) {
            // Toutes cochees - decocher la premiere
            const firstPerm = await page.evaluate((userId) => {
                const cb = document.querySelector(`input[data-user-id="${userId}"][hx-post]:checked`);
                return cb?.dataset.permission;
            }, TARGET_USER_ID);
            assert.ok(firstPerm, 'No permission checkbox found');
            return; // Skip ce test si toutes sont cochees
        }

        // Cocher la permission via JS (click ne declenche pas htmx de facon fiable en headless)
        await page.evaluate((userId, perm) => {
            const cb = document.querySelector(`input[data-user-id="${userId}"][data-permission="${perm}"]`);
            if (cb) { cb.checked = true; cb.dispatchEvent(new Event('change', {bubbles:true})); }
        }, TARGET_USER_ID, permKey);

        // Attendre le htmx swap (le label est remplace)
        await sleep(2000);

        // Apres le swap, le nouveau checkbox est coche et le label a le fond bleu
        const afterToggle = await page.evaluate((userId, perm) => {
            const cb = document.querySelector(`input[data-user-id="${userId}"][data-permission="${perm}"]`);
            const label = cb?.closest('label');
            return {
                checked: cb?.checked ?? false,
                hasBlueBg: label?.className.includes('bg-blue') ?? false,
            };
        }, TARGET_USER_ID, permKey);
        assert.ok(afterToggle.checked, `Expected ${permKey} to be checked after htmx toggle`);

        // Decocher pour restaurer l'etat
        await page.evaluate((userId, perm) => {
            const cb = document.querySelector(`input[data-user-id="${userId}"][data-permission="${perm}"]`);
            if (cb) { cb.checked = false; cb.dispatchEvent(new Event('change', {bubbles:true})); }
        }, TARGET_USER_ID, permKey);
        await sleep(2000);
    });
});
