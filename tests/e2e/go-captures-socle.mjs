/**
 * go-captures-socle.mjs - Captures du socle porte, a REGARDER.
 *
 * Une assertion DOM ne voit pas qu'un bouton est mal place, qu'une colonne est
 * vide ou qu'un ecran respire mal. Ce script ne verifie rien : il produit des
 * images destinees a etre ouvertes et jugees.
 *
 * Trois largeurs, parce qu'un gabarit se juge a ses extremes :
 *   1920x1080  grand ecran — c'est la que le gaspillage de largeur se voit
 *   1400x900   ecran courant
 *    390x844   mobile — c'est la que le tiroir et les debordements se voient
 *
 * Usage :
 *   cd tests/e2e
 *   node go-captures-socle.mjs [compte]      (defaut : rw-test-super)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { mkdirSync } from 'fs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const SORTIE = './screenshots/socle';

const COMPTES = {
    'rw-test-user':  'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW',
    'rw-test-admin': 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX',
    'rw-test-super': 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW',
};

const LARGEURS = [
    { nom: 'grand',  width: 1920, height: 1080 },
    { nom: 'moyen',  width: 1400, height: 900 },
    { nom: 'mobile', width: 390,  height: 844 },
];

const nomCompte = process.argv[2] || 'rw-test-super';
const secret = COMPTES[nomCompte];
if (! secret) { console.log('compte inconnu : ' + nomCompte); process.exit(1); }

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

mkdirSync(SORTIE, { recursive: true });

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost'],
});

const prises = [];

for (const format of LARGEURS) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    await page.setViewport({ width: format.width, height: format.height });
    page.setDefaultTimeout(30000);
    page.on('dialog', d => d.dismiss().catch(() => {}));

    /*
     * Une page qui remplit son tableau par un appel reseau met un temps
     * variable. Dormir une duree fixe capture « Chargement… » et donne une
     * image qui ne montre pas ce qu'on voulait juger.
     */
    const attendTableau = async (maxMs = 12000) => {
        const limite = Date.now() + maxMs;
        while (Date.now() < limite) {
            const encoreEnCharge = await page.evaluate(() => {
                const c = document.querySelector('#cmdlog-tbody, #appr-tbody, #drift-tbody, #backup-tbody, #task-tbody, #tickets-tbody');
                return c ? /Chargement|Loading/i.test(c.textContent) : false;
            });
            if (!encoreEnCharge) return;
            await dors(300);
        }
    };

    const prend = async (etiquette) => {
        const chemin = `${SORTIE}/${format.nom}-${etiquette}.png`;
        await page.screenshot({ path: chemin });
        prises.push(chemin);
    };

    // 1. Connexion
    await page.goto(`${BASE}/connexion`, { waitUntil: 'networkidle2' });
    await dors(200);
    await prend('01-connexion');

    // 2. Second facteur
    await page.type('input[name="username"]', nomCompte, { delay: 6 });
    await page.type('input[name="password"]', MDP, { delay: 6 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]');
    try { await nav; } catch {}
    await dors(200);
    await prend('02-second-facteur');

    // 3. Conditions d'utilisation
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    await page.type('input[name="2fa_code"]', totp(secret), { delay: 6 });
    nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]');
    try { await nav; } catch {}
    await dors(200);
    await prend('03-cgu');

    // 4. Accueil du portail
    if (/\/cgu/.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        // Ancrage sur le CONTRAT DOM, pas sur « le premier bouton submit » :
        // la page CGU en porte deux, et refuser vient avant accepter.
        await page.click('[data-rw="cgu-accepter"]');
        try { await nav; } catch {}
    }
    await dors(300);
    await prend('04-accueil');

    // 5. Profil
    await page.goto(`${BASE}/profil`, { waitUntil: 'networkidle2' });
    await dors(200);
    await prend('05-profil');

    // 6. Journal des commandes — premiere page metier portee
    await page.goto(`${BASE}/journal-commandes`, { waitUntil: 'networkidle2' });
    await attendTableau();
    await prend('06-journal-commandes');

    // 7. Approbations a quatre yeux
    await page.goto(`${BASE}/approbations`, { waitUntil: 'networkidle2' });
    await attendTableau();
    await prend('07-approbations');

    // 8. Derive de configuration
    await page.goto(`${BASE}/derive-config`, { waitUntil: 'networkidle2' });
    await attendTableau();
    await prend('08-derive-config');

    // 9. Sauvegardes de la base
    await page.goto(`${BASE}/sauvegardes`, { waitUntil: 'networkidle2' });
    await attendTableau();
    await prend('09-sauvegardes');

    // 10. Centre de taches
    await page.goto(`${BASE}/taches`, { waitUntil: 'networkidle2' });
    await attendTableau();
    await prend('10-taches');

    // 11. Tickets ITSM, formulaire ouvert
    await page.goto(`${BASE}/tickets`, { waitUntil: 'networkidle2' });
    await attendTableau();
    await page.evaluate(() => document.getElementById('new-ticket-btn')?.click());
    await dors(400);
    await prend('11-tickets');

    // 6. Tiroir ouvert — n'a de sens qu'en mobile
    if (format.nom === 'mobile') {
        await page.goto(`${BASE}/accueil`, { waitUntil: 'networkidle2' });
        await page.evaluate(() => { document.getElementById('rw-tiroir').checked = true; });
        await dors(300);
        await prend('08-tiroir');
    }

    await ctx.close();
    // Fenetre TOTP suivante avant la connexion du format suivant : meme compte.
    await dors((resteFenetre() + 1) * 1000);
}

console.log(prises.join('\n'));
console.log(`\n${prises.length} captures dans ${SORTIE}`);
await navigateur.close();
process.exit(0);
