/**
 * go-vague0-legacy.mjs - Test de caracterisation du deplacement de www/ vers legacy/.
 *
 * Ce que le deplacement d'une racine documentaire casse en silence, ce n'est pas
 * le code HTTP de la page : c'est le chargement des SOUS-RESSOURCES (feuilles de
 * style, scripts, images) et les chemins d'inclusion cote serveur. Un montage
 * Docker mal repris rend une page 200 parfaitement nue.
 *
 * Le script suit donc les liens DU MENU (jamais une liste d'URL ecrite a la main :
 * sept 404 ont vecu dans le menu sans qu'aucune suite ne les voie) et, sur chaque
 * page, il compte les sous-ressources en echec.
 *
 * Sortie : rapport trie et deterministe sur stdout, destine a etre compare
 * AVANT et APRES le deplacement. Toute difference est une regression.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_TOTP_SECRET='...' node go-vague0-legacy.mjs > /tmp/vague0-avant.txt
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';

const BASE = 'https://localhost:8443';
const USER = process.env.E2E_USER || 'superadmin';
const PASS = process.env.E2E_PASS || 'RootWarden@2026-Sec!';
const SECRET = process.env.E2E_TOTP_SECRET || '';

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function sleep(ms){return new Promise(r=>setTimeout(r,ms))}

const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
});
const page = (await browser.pages())[0];
page.setDefaultTimeout(30000);

// Collecte des sous-ressources en echec, par page visitee.
let echecs = [];
page.on('response', r => {
    const s = r.status();
    if (s >= 400) echecs.push(`${s} ${new URL(r.url()).pathname}`);
});
let erreursJs = [];
page.on('pageerror', e => erreursJs.push(String(e).split('\n')[0]));
// Un dialogue natif bloque Puppeteer et laisse le bouton de souris enfonce.
page.on('dialog', d => d.dismiss().catch(() => {}));

const lignes = [];
let echecsTotal = 0;

try {
    // ── Connexion (+ TOTP + CGU) ────────────────────────────────────────────
    await page.goto(`${BASE}/auth/login.php`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', USER, { delay: 10 });
    await page.type('input[name="password"]', PASS, { delay: 10 });
    const n1 = page.waitForNavigation({ waitUntil: 'networkidle2' });
    await page.click('button[type="submit"]'); await n1;
    if (page.url().includes('verify_2fa')) {
        const rem = 30 - (Math.floor(Date.now() / 1000) % 30);
        if (rem < 6) await sleep(rem * 1000 + 500);
        await page.type('input[name="2fa_code"]', totp(SECRET), { delay: 10 });
        const n2 = page.waitForNavigation({ waitUntil: 'networkidle2' });
        await page.click('button[type="submit"]'); await n2;
    }
    if (page.url().includes('terms')) {
        const btn = await page.$('button[name="accept_terms"]');
        if (btn) {
            const nT = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 8000 });
            await btn.click();
            try { await nT; } catch {}
        }
    }
    if (page.url().includes('login') || page.url().includes('verify_2fa')) {
        console.log('ECHEC connexion impossible, url=' + page.url());
        await browser.close();
        process.exit(1);
    }

    // ── Les cibles viennent DU MENU, pas d'une liste ecrite a la main ───────
    await page.goto(`${BASE}/index.php`, { waitUntil: 'networkidle2' });
    const cibles = await page.evaluate(() => {
        const vus = new Set();
        const out = [];
        for (const a of document.querySelectorAll('a[href]')) {
            const brut = a.getAttribute('href') || '';
            // Liens internes uniquement : premier caractere '/', deuxieme different de '/'.
            if (brut.charAt(0) !== '/' || brut.charAt(1) === '/') continue;
            if (/logout|deconnexion/i.test(brut)) continue;
            const chemin = brut.split('#')[0];
            if (!chemin || vus.has(chemin)) continue;
            vus.add(chemin);
            out.push(chemin);
        }
        return out.sort();
    });
    lignes.push(`liens de menu collectes : ${cibles.length}`);

    // ── Visite de chaque cible ──────────────────────────────────────────────
    for (const chemin of cibles) {
        echecs = [];
        erreursJs = [];
        let statut = 0;
        try {
            const rep = await page.goto(`${BASE}${chemin}`, { waitUntil: 'networkidle2', timeout: 25000 });
            statut = rep ? rep.status() : 0;
        } catch (e) {
            statut = -1;
        }
        await sleep(200);

        const info = await page.evaluate(() => ({
            titre: (document.title || '').trim(),
            h1: (document.querySelector('h1')?.textContent || '').trim().slice(0, 60),
            feuilles: document.querySelectorAll('link[rel="stylesheet"]').length,
            scripts: document.querySelectorAll('script[src]').length,
            images: document.querySelectorAll('img').length,
            // Une page servie mais vide est le symptome exact d'une racine
            // documentaire deplacee sans que les actifs suivent.
            //
            // On rend un BOOLEEN, pas une longueur : la longueur du texte varie
            // d'une execution a l'autre sans qu'aucun code ne change (journal
            // d'audit alimente par la connexion du test, tableaux charges en
            // asynchrone qui n'ont pas tous fini). Trois executions consecutives
            // du 2026-08-17 donnaient 2693 / 2690 / 2688 sur admin_page.php et
            // 987 / 987 / 3786 sur server_users.php. Une mesure qui bouge seule
            // ne mesure rien : elle ne peut que produire de fausses alertes.
            garni: (document.body ? document.body.innerText.trim().length : 0) > 200,
        }));

        // Les sous-ressources en echec sont dedupliquees et triees : le rapport
        // doit etre comparable d'une execution a l'autre.
        const sousEchecs = [...new Set(echecs)].sort();
        echecsTotal += sousEchecs.length;

        lignes.push(
            `${chemin}\t${statut}\tcss=${info.feuilles}\tjs=${info.scripts}\timg=${info.images}` +
            `\tgarni=${info.garni ? 'oui' : 'NON'}\tsousechecs=${sousEchecs.length}` +
            (sousEchecs.length ? `\t[${sousEchecs.join(' ')}]` : '') +
            (erreursJs.length ? `\tJS:[${[...new Set(erreursJs)].sort().join(' | ')}]` : '')
        );
    }
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecsTotal++;
}

console.log(lignes.join('\n'));
console.log(`\nTOTAL sous-ressources en echec : ${echecsTotal}`);
await browser.close();
process.exit(0);
