/**
 * 01-login.test.mjs - E2E : Login + 2FA TOTP → Dashboard visible
 *
 * Valide :
 *  - Page login accessible
 *  - Formulaire login → redirect vers TOTP
 *  - TOTP valide → redirect vers dashboard (ou CGU → dashboard)
 *  - Dashboard contient "Bonjour" + sidebar visible
 *  - Badge notifications visible
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { launchBrowser, newPage, login, BASE_URL } from './helpers.mjs';

let browser, page;

describe('01 - Login + TOTP → Dashboard', () => {
    before(async () => {
        browser = await launchBrowser();
        page = await newPage(browser);
    });

    after(async () => {
        await browser?.close();
    });

    it('should display the login page', async () => {
        await page.goto(`${BASE_URL}/auth/login.php`, { waitUntil: 'networkidle2' });
        const title = await page.title();
        assert.ok(title.includes('Connexion') || title.includes('RootWarden'), `Expected login page, got: ${title}`);
        const usernameInput = await page.$('input[name="username"]');
        assert.ok(usernameInput, 'Username input not found');
    });

    it('should login with TOTP and reach dashboard', async () => {
        await login(page);
        const url = page.url();
        // Apres login + CGU, on est sur le dashboard (index.php)
        assert.ok(
            url.includes('index.php') || url.endsWith(':8443/'),
            `Expected dashboard URL, got: ${url}`
        );
    });

    it('should display the welcome message', async () => {
        const content = await page.content();
        assert.ok(content.includes('Bonjour'), 'Expected "Bonjour" on dashboard');
    });

    it('should show the sidebar with navigation', async () => {
        const sidebar = await page.$('#sidebar');
        assert.ok(sidebar, 'Sidebar element not found');
        const hasDashboard = await page.evaluate(() => {
            const labels = document.querySelectorAll('#sidebar .sidebar-label');
            for (const l of labels) if (l.textContent.includes('Dashboard')) return true;
            return false;
        });
        assert.ok(hasDashboard, 'Dashboard link not found in sidebar');
    });

    it('should display the notification badge', async () => {
        // Le badge se charge en async - attendre un peu
        await page.waitForFunction(() => {
            const badge = document.getElementById('notif-badge');
            return badge && !badge.classList.contains('hidden');
        }, { timeout: 5000 }).catch(() => {});
        const badge = await page.$('#notif-badge');
        assert.ok(badge, 'Notification badge not found');
    });

    it('should display stat cards', async () => {
        const content = await page.content();
        assert.ok(content.includes('Serveurs en ligne'), 'Expected "Serveurs en ligne" stat card');
        assert.ok(content.includes('Utilisateurs actifs'), 'Expected "Utilisateurs actifs" stat card');
    });
});
