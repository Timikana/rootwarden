/**
 * go-access-sudo-visual.mjs - Verification visuelle de l'integration sudo preset
 * dans l'onglet Acces & Permissions (admin_page.php).
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
const SECRET = process.env.E2E_TOTP_SECRET || ''; // audit v1.23 : secret 2FA via env, plus de secret en dur
const SHOTS = './screenshots/access-sudo';
mkdirSync(SHOTS, { recursive: true });

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function sleep(ms){return new Promise(r=>setTimeout(r,ms))}

let step = 0;
async function shot(page, name) {
    step++; const p = `${SHOTS}/${String(step).padStart(2,'0')}_${name}.png`;
    await page.screenshot({ path: p, fullPage: false });
    console.log(`  shot -> ${p}`);
}

const browser = await puppeteer.launch({
    headless: false, defaultViewport: null,
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
});
const page = (await browser.pages())[0];
page.setDefaultTimeout(30000);

await page.goto(`${BASE}/auth/login.php`, { waitUntil: 'networkidle2' });
await page.type('input[name="username"]', USER, { delay: 20 });
await page.type('input[name="password"]', PASS, { delay: 20 });
const n1 = page.waitForNavigation({ waitUntil: 'networkidle2' });
await page.click('button[type="submit"]'); await n1;

if (page.url().includes('verify_2fa')) {
    const rem = 30 - (Math.floor(Date.now()/1000) % 30);
    if (rem < 6) await sleep(rem*1000+500);
    await page.type('input[name="2fa_code"]', totp(SECRET), { delay: 20 });
    const n2 = page.waitForNavigation({ waitUntil: 'networkidle2' });
    await page.click('button[type="submit"]'); await n2;
}
if (page.url().includes('terms')) {
    const btn = await page.$('button[name="accept_terms"]');
    if (btn) { const nT = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 8000 }); await btn.click(); try { await nT; } catch {} }
}

console.log('Navigation vers Administration -> Acces & Permissions...');
await page.goto(`${BASE}/adm/admin_page.php`, { waitUntil: 'networkidle2' });
await sleep(800);
await shot(page, 'admin_page_default');

// Cliquer sur l'onglet "Acces & Permissions"
console.log('Click onglet Acces...');
await page.evaluate(() => {
    const tabs = Array.from(document.querySelectorAll('button, a, [role="tab"]'));
    for (const t of tabs) {
        const txt = (t.textContent || '').toLowerCase();
        if (txt.includes('accès') || txt.includes('access') || txt.includes('permission')) {
            t.click(); return;
        }
    }
});
await sleep(1000);
await shot(page, 'tab_access');

// Ouvrir TOUTES les cartes user (pour voir opsuser)
console.log('Ouvrir TOUTES les cartes user...');
await page.evaluate(() => {
    document.querySelectorAll('details.access-card').forEach(d => { d.open = true; });
});
await sleep(600);
await shot(page, 'card_user_expanded');

// Scroll jusqu'a la carte opsuser
console.log('Focus opsuser...');
await page.evaluate(() => {
    const cards = document.querySelectorAll('details.access-card');
    for (const c of cards) {
        if (c.dataset.name === 'opsuser') { c.scrollIntoView({ block: 'center' }); break; }
    }
});
await sleep(500);
await shot(page, 'opsuser_card');

// Zoom in sur le dropdown sudo pour bien le voir
const sudoSelectExists = await page.evaluate(() => !!document.querySelector('.sudo-preset'));
console.log('Dropdown sudo present :', sudoSelectExists);
if (sudoSelectExists) {
    const sel = await page.$('.sudo-preset');
    const box = await sel.boundingBox();
    console.log('Dropdown bounding :', JSON.stringify(box));
    await shot(page, 'sudo_dropdown_visible');
}

console.log('\n=== Navigateur reste ouvert. Ctrl+C pour fermer. ===\n');
await new Promise(() => {});
