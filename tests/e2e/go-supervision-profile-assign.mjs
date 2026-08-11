/**
 * go-supervision-profile-assign.mjs - Regression v1.37.14 : les profils de
 * supervision doivent etre ASSIGNABLES aux machines depuis le tableau de
 * deploiement (dropdown "Profil" par serveur). Avant : CRUD des profils OK
 * mais assignProfileToMachine() jamais appele -> profils inutilisables, la
 * config deployee retombait toujours sur la globale.
 *
 * Auto-validant (headless, exit 0/1). Nettoie le profil de test cree.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { mkdirSync } from 'fs';

const BASE = 'https://localhost:8443';
const USER = process.env.E2E_USER || 'superadmin';
const PASS = process.env.E2E_PASS || 'RootWarden@2026-Sec!';
const SECRET = process.env.E2E_TOTP_SECRET || '';
const SHOTS = './screenshots/supervision-profile-assign';
mkdirSync(SHOTS, { recursive: true });
const PROFILE_NAME = 'E2E_AssignTest';

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

async function api(path, opts) {
    return page.evaluate(async (p, o) => {
        const r = await fetch((window.API_URL || '/api_proxy.php') + p, o ? JSON.parse(o) : undefined);
        return r.json();
    }, path, opts ? JSON.stringify(opts) : null);
}

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

    // ── Page Supervision : creer un profil de test via l'API de la page ─────
    await page.goto(`${BASE}/supervision/`, { waitUntil: 'networkidle2' });
    await sleep(800);
    const created = await api('/supervision/profiles', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ platform: 'zabbix', name: PROFILE_NAME,
                               host_metadata: 'E2ETest', zabbix_server: '10.9.9.9' }),
    });
    check('profil de test cree', created.success === true);
    const profileId = created.id;

    // ── Recharger : les dropdowns doivent lister le profil ──────────────────
    await page.reload({ waitUntil: 'networkidle2' });
    await sleep(1500);
    const state = await page.evaluate(() => {
        const sels = document.querySelectorAll('#deploy-table-body .profile-cell select.profile-select');
        return {
            selects: sels.length,
            rows: document.querySelectorAll('#deploy-table-body tr[data-machine-id]').length,
            firstOptions: sels.length ? [...sels[0].options].map(o => o.textContent) : [],
        };
    });
    console.log(`Dropdowns : ${state.selects}/${state.rows} lignes`);
    check('un dropdown "Profil" par machine', state.selects >= 1 && state.selects === state.rows);
    check('le profil cree est propose dans le dropdown',
          state.firstOptions.includes(PROFILE_NAME));
    await page.screenshot({ path: `${SHOTS}/01_dropdowns.png` });

    // ── Assigner via le dropdown (machine 2 = test-server) ──────────────────
    const assigned = await page.evaluate(async (pid) => {
        const cell = document.querySelector('#deploy-table-body .profile-cell[data-machine="2"]')
                  || document.querySelector('#deploy-table-body .profile-cell');
        const sel = cell.querySelector('select');
        sel.value = String(pid);
        sel.dispatchEvent(new Event('change'));
        await new Promise(r => setTimeout(r, 1200));
        return { machine: cell.dataset.machine, value: sel.value };
    }, profileId);
    check('assignation declenchee via le dropdown', assigned.value === String(profileId));

    // ── Persistance : la map d'assignations doit refleter le choix ──────────
    const map = await api('/supervision/profiles/assignments?platform=zabbix');
    check('assignation persistee en base',
          map.success === true && String(map.assignments[assigned.machine]) === String(profileId));

    // ── Rechargement : le dropdown re-selectionne le profil ─────────────────
    await page.reload({ waitUntil: 'networkidle2' });
    await sleep(1500);
    const after = await page.evaluate((m) => {
        const sel = document.querySelector(`#deploy-table-body .profile-cell[data-machine="${m}"] select`);
        return sel ? sel.selectedOptions[0]?.textContent : null;
    }, assigned.machine);
    check('le profil reste selectionne apres rechargement', after === PROFILE_NAME);
    await page.screenshot({ path: `${SHOTS}/02_persisted.png` });

    // ── Nettoyage : desassigner + supprimer le profil de test ───────────────
    await api(`/supervision/machines/${assigned.machine}/profile?platform=zabbix`, { method: 'DELETE' });
    const del = await api(`/supervision/profiles/${profileId}`, { method: 'DELETE' });
    check('nettoyage (profil de test supprime)', del.success === true);

    check('aucune erreur JS', jsErrors.length === 0);
    if (jsErrors.length) console.log('  erreurs JS :', jsErrors.join(' | '));
} catch (e) {
    console.error('ERREUR SCRIPT :', e);
    failures++;
} finally {
    await browser.close();
}

console.log(failures === 0 ? '\n=== TOUT OK ===' : `\n=== ${failures} ECHEC(S) ===`);
process.exit(failures === 0 ? 0 : 1);
