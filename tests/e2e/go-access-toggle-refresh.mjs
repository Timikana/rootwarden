/**
 * go-access-toggle-refresh.mjs - Regression v1.37.11 : activer un acces dans
 * l'onglet Acces & Permissions doit afficher la ligne "droits sudo" (preset +
 * NOPASSWD + lien avance) IMMEDIATEMENT, sans recharger la page ; la revoquer
 * doit retirer la ligne et le badge.
 *
 * Auto-validant (headless, exit 0/1), restaure l'etat initial (add puis remove
 * sur un couple user/machine initialement inactif).
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { mkdirSync } from 'fs';

/*
 * ══ LA BASE NE PEUT PLUS ETRE DEVINEE — ELLE SE DECLARE ═══════════════════
 *
 * Cette suite codait `https://localhost:8443` en dur. **Le 2026-09-06 a 19:39,
 * les deux portails ont echange leurs ports** : `:8443` sert desormais le
 * PORTAGE, et le legacy est passe sur `:8446`.
 *
 * Une suite ecrite pour le legacy y aurait trouve des ancres, des formulaires,
 * une session — le portage accepte les MEMES identifiants et rend des pages qui
 * RESSEMBLENT. **Elle n'aurait pas echoue : elle aurait rendu du vert sur le
 * mauvais objet.** C'est la forme la plus couteuse d'un defaut de banc, parce
 * qu'aucun signal ne la distingue d'une mesure juste.
 *
 * ⚠ ET UN REPLI CORRIGE SE REPERIMERAIT AU PROCHAIN ECHANGE. Ecrire
 * `:8446` ici ne ferait que deplacer la date de peremption. **La base cesse donc
 * d'etre exprimable autrement que declaree** : pas de valeur par defaut, pas de
 * repli, une erreur au chargement.
 *
 * C'est plus severe que l'annonce bruyante retenue pour les suites qui LISENT
 * l'environnement, et c'est voulu : celles-la ont un repli qu'un runner
 * surcharge, celle-ci n'en avait aucun. **Rendre le champ inexprimable plutot
 * que sa valeur inoffensive** — quand c'est possible, c'est la garde la plus
 * forte.
 */
const BASE = (() => {
    const declaree = process.env.E2E_BASE;
    if (! declaree) {
        throw new Error(
            'E2E_BASE n\'est pas declaree, et cette suite n\'a plus de base par defaut.\n'
            + '  Les deux portails ont ECHANGE leurs ports le 2026-09-06 : une valeur\n'
            + '  ecrite en dur mesurerait l\'AUTRE portail en rendant du vert.\n'
            + '  Verifiez lequel repond avant de choisir — l\'ETAT, jamais le numero :\n'
            + '    curl -sk https://<hote>:<port>/up   200 = portage · 404 = legacy\n'
            + '  puis :  E2E_BASE=https://<hote>:<port> node tests/e2e/<suite>.mjs');
    }

    return declaree;
})();
const USER = process.env.E2E_USER || 'superadmin';
const PASS = process.env.E2E_PASS || 'RootWarden@2026-Sec!';
const SECRET = process.env.E2E_TOTP_SECRET || ''; // secret 2FA via env (audit v1.23)
const SHOTS = './screenshots/access-toggle';
mkdirSync(SHOTS, { recursive: true });

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function sleep(ms){return new Promise(r=>setTimeout(r,ms))}

let failures = 0;
function check(label, ok) {
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
    if (!ok) failures++;
}

const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
});
const page = (await browser.pages())[0];
page.setDefaultTimeout(30000);
const jsErrors = [];
page.on('pageerror', e => jsErrors.push(String(e)));

try {
    // ── Login (+ TOTP + CGU) ────────────────────────────────────────────────
    await page.goto(`${BASE}/auth/login.php`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', USER, { delay: 10 });
    await page.type('input[name="password"]', PASS, { delay: 10 });
    const n1 = page.waitForNavigation({ waitUntil: 'networkidle2' });
    await page.click('button[type="submit"]'); await n1;
    if (page.url().includes('verify_2fa')) {
        const rem = 30 - (Math.floor(Date.now()/1000) % 30);
        if (rem < 6) await sleep(rem*1000+500);
        await page.type('input[name="2fa_code"]', totp(SECRET), { delay: 10 });
        const n2 = page.waitForNavigation({ waitUntil: 'networkidle2' });
        await page.click('button[type="submit"]'); await n2;
    }
    if (page.url().includes('terms')) {
        const btn = await page.$('button[name="accept_terms"]');
        if (btn) { const nT = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 8000 }); await btn.click(); try { await nT; } catch {} }
    }

    // ── Onglet Acces & Permissions ──────────────────────────────────────────
    await page.goto(`${BASE}/adm/admin_page.php`, { waitUntil: 'networkidle2' });
    await sleep(600);
    await page.evaluate(() => {
        for (const t of document.querySelectorAll('button, a, [role="tab"]')) {
            const txt = (t.textContent || '').toLowerCase();
            if (txt.includes('accès') || txt.includes('access') || txt.includes('permission')) { t.click(); return; }
        }
    });
    await sleep(900);
    await page.evaluate(() => document.querySelectorAll('details.access-card').forEach(d => { d.open = true; }));
    await sleep(300);

    // Marqueur anti-reload : doit survivre a tout le scenario.
    await page.evaluate(() => { window.__no_reload_marker = 42; });

    // ── Cible : premier couple (user, machine) SANS acces ───────────────────
    const target = await page.evaluate(() => {
        const btn = document.querySelector('.access-btn[data-active="0"]');
        if (!btn) return null;
        return { user: btn.dataset.user, machine: btn.dataset.machine };
    });
    if (!target) {
        console.log('SKIP  aucun couple user/machine inactif disponible dans ce jeu de donnees');
        await browser.close();
        process.exit(1);
    }
    console.log(`Cible : user=${target.user} machine=${target.machine}`);
    const cardSel = `.server-card[data-user="${target.user}"][data-machine="${target.machine}"]`;

    const before = await page.evaluate(sel => ({
        row: !!document.querySelector(sel + ' .sudo-row'),
    }), cardSel);
    check('etat initial : pas de ligne sudo', before.row === false);

    // ── ACTIVER l'acces : la ligne sudo doit apparaitre SANS reload ─────────
    await page.evaluate(sel => document.querySelector(sel + ' .access-btn').click(), cardSel);
    await sleep(1200);
    await page.screenshot({ path: `${SHOTS}/01_apres_activation.png` });

    const after = await page.evaluate(sel => {
        const card = document.querySelector(sel);
        const row = card?.querySelector('.sudo-row');
        return {
            marker: window.__no_reload_marker === 42,
            active: card?.querySelector('.access-btn')?.dataset.active === '1',
            row: !!row,
            select: !!row?.querySelector('select.sudo-preset'),
            selectVal: row?.querySelector('select.sudo-preset')?.value || null,
            nopasswd: !!row?.querySelector('input.sudo-nopasswd'),
            advanced: !!row?.querySelector('a[href*="server_user_policies.php"]'),
            options: row ? row.querySelectorAll('select.sudo-preset option').length : 0,
        };
    }, cardSel);
    check('aucun rechargement de page (marqueur JS intact)', after.marker);
    check('acces active cote UI', after.active);
    check('ligne "droits sudo" visible SANS refresh', after.row);
    check('dropdown preset present', after.select);
    check('preset par defaut = none', after.selectVal === 'none');
    check('checkbox NOPASSWD presente', after.nopasswd);
    check('lien "avance" vers server_user_policies present', after.advanced);
    check('les 7 presets sont proposes', after.options === 7);

    // ── REVOQUER l'acces : ligne + badge retires, etat initial restaure ─────
    await page.evaluate(sel => document.querySelector(sel + ' .access-btn').click(), cardSel);
    await sleep(1200);
    await page.screenshot({ path: `${SHOTS}/02_apres_revocation.png` });

    const reverted = await page.evaluate(sel => {
        const card = document.querySelector(sel);
        return {
            marker: window.__no_reload_marker === 42,
            active: card?.querySelector('.access-btn')?.dataset.active === '1',
            row: !!card?.querySelector('.sudo-row'),
            badge: !!card?.querySelector('.sudo-badge'),
        };
    }, cardSel);
    check('toujours aucun rechargement', reverted.marker);
    check('acces revoque (etat initial restaure)', reverted.active === false);
    check('ligne sudo retiree a la revocation', reverted.row === false);
    check('badge sudo retire a la revocation', reverted.badge === false);

    check('aucune erreur JS pendant le scenario', jsErrors.length === 0);
    if (jsErrors.length) console.log('  erreurs JS :', jsErrors.join(' | '));
} catch (e) {
    console.error('ERREUR SCRIPT :', e);
    failures++;
} finally {
    await browser.close();
}

console.log(failures === 0 ? '\n=== TOUT OK ===' : `\n=== ${failures} ECHEC(S) ===`);
process.exit(failures === 0 ? 0 : 1);
