/**
 * helpers.mjs — Fonctions partagees pour les tests E2E RootWarden
 *
 * Fournit : TOTP generation, login flow, browser setup, assertions.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';

// ── Config ──────────────────────────────────────────────────────
export const BASE_URL = process.env.E2E_URL || 'https://localhost:8443';
export const SUPERADMIN_USER = process.env.E2E_USER || 'superadmin';
export const SUPERADMIN_PASS = process.env.E2E_PASS || 'superadmin';
export const TOTP_SECRET = process.env.E2E_TOTP_SECRET || 'QMLH2AFHTN6LVD6QTGFXYCX6RONTQS23CDTHE4YMBYY2XBLRGO3GLMW72CPGTQR7A6XOLWZ4YNDM5D2CER47EQSFWSMIUKWQHLLGCQQ';

const TIMEOUT = 15_000;

// ── TOTP ────────────────────────────────────────────────────────
function base32Decode(str) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (const c of str.toUpperCase().replace(/=+$/, '')) {
        const val = alphabet.indexOf(c);
        if (val === -1) continue;
        bits += val.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return Buffer.from(bytes);
}

export function generateTOTP(secret = TOTP_SECRET) {
    const key = base32Decode(secret);
    const counter = Math.floor(Date.now() / 1000 / 30);
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(BigInt(counter));
    const hmac = createHmac('sha1', key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
    return code.toString().padStart(6, '0');
}

// ── Browser ─────────────────────────────────────────────────────
export async function launchBrowser() {
    return puppeteer.launch({
        headless: true,
        args: [
            '--no-sandbox',
            '--ignore-certificate-errors',
            '--allow-insecure-localhost',
        ],
    });
}

export async function newPage(browser) {
    const page = await browser.newPage();
    page.setDefaultTimeout(TIMEOUT);
    await page.setViewport({ width: 1440, height: 900 });
    return page;
}

// ── Login flow complet (login + TOTP + accept CGU si present) ───
export async function login(page, user = SUPERADMIN_USER, pass = SUPERADMIN_PASS) {
    await page.goto(`${BASE_URL}/auth/login.php`, { waitUntil: 'networkidle2' });

    // Remplir login (evaluate pour etre sur de clear les champs)
    await page.evaluate((u, p) => {
        document.querySelector('input[name="username"]').value = u;
        document.querySelector('input[name="password"]').value = p;
    }, user, pass);
    await Promise.all([
        page.evaluate(() => document.querySelector('form').submit()),
        page.waitForNavigation({ waitUntil: 'networkidle2' }),
    ]);

    // TOTP si demande (le champ s'appelle "2fa_code")
    const totpInput = await page.$('input[name="2fa_code"]');
    if (totpInput) {
        const code = generateTOTP();
        await page.evaluate((c) => {
            document.querySelector('input[name="2fa_code"]').value = c;
        }, code);
        await Promise.all([
            page.evaluate(() => document.querySelector('form').submit()),
            page.waitForNavigation({ waitUntil: 'networkidle2' }),
        ]);
    }

    // CGU si affichee — bouton "J'accepte les conditions"
    const acceptBtn = await page.evaluateHandle(() => {
        const btns = document.querySelectorAll('button');
        for (const b of btns) if (b.textContent.includes('accepte')) return b;
        return null;
    });
    if (acceptBtn && acceptBtn.asElement()) {
        await Promise.all([
            acceptBtn.asElement().click(),
            page.waitForNavigation({ waitUntil: 'networkidle2' }),
        ]);
    }

    return page;
}

// ── Assertions ──────────────────────────────────────────────────
export async function assertTextPresent(page, text) {
    const content = await page.content();
    if (!content.includes(text)) {
        throw new Error(`Expected "${text}" to be present on page ${page.url()}`);
    }
}

export async function assertSelector(page, selector) {
    const el = await page.$(selector);
    if (!el) {
        throw new Error(`Expected selector "${selector}" to exist on page ${page.url()}`);
    }
    return el;
}

export async function waitAndClick(page, selector) {
    await page.waitForSelector(selector, { timeout: TIMEOUT });
    await page.click(selector);
}

export function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export async function getText(page, selector) {
    await page.waitForSelector(selector, { timeout: TIMEOUT });
    return page.$eval(selector, el => el.textContent.trim());
}
