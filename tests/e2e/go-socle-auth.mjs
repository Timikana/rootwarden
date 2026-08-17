/**
 * go-socle-auth.mjs - Test de caracterisation de la chaine d'authentification.
 *
 * Joue d'abord sur le LEGACY (https://localhost:8443), puis le MEME test devra
 * passer sur le portage Laravel. Il ne decrit pas ce qu'on croit que
 * l'authentification fait : il mesure ce qu'elle fait.
 *
 * Invariants verifies, avec les TROIS comptes de test dedies :
 *   A. une page protegee sans session renvoie vers la connexion ;
 *   B. un mot de passe correct SEUL n'authentifie pas — il n'existe aucun
 *      chemin sans second facteur ;
 *   C. un mauvais mot de passe n'authentifie pas et incremente le compteur ;
 *   D. REJEU TOTP : le meme code, dans une session NEUVE, a l'interieur de la
 *      meme fenetre de 30 s — accepte ou refuse ? (mesure, pas hypothese) ;
 *   E. l'identifiant de session change apres authentification complete ;
 *   F. apres le second facteur, on passe par les conditions d'utilisation.
 *
 * Cible : E2E_BASE (defaut https://localhost:8443).
 *
 * Usage :
 *   cd tests/e2e
 *   node go-socle-auth.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTES = [
    { nom: 'rw-test-user',  role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW' },
    { nom: 'rw-test-admin', role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX' },
    { nom: 'rw-test-super', role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW' },
];

// Pages protegees : une par famille de garde (role 1, admin, superadmin).
const PAGES_PROTEGEES = ['/index.php', '/profile.php', '/adm/admin_page.php'];

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
/** Secondes restantes dans la fenetre TOTP courante. */
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

/**
 * Cible courante. Certaines attentes different volontairement entre le legacy
 * et le portage : le portage CORRIGE des defauts. Une divergence voulue est un
 * ECART CONNU cote legacy, jamais un echec — et une exigence cote Laravel.
 */
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';

let echecs = 0;
let ecarts = 0;
const lignes = [];
function verifie(libelle, ok, detail) {
    lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${libelle}${detail ? '  — ' + detail : ''}`);
    if (!ok) echecs++;
}
/**
 * Attente qui ne vaut que pour le portage. Sur le legacy, un echec est un ecart
 * connu et documente (docs/migration/PARITE.md), pas une regression.
 */
function verifiePortage(libelle, ok, detail) {
    if (ok) { lignes.push(`PASS  ${libelle}${detail ? '  — ' + detail : ''}`); return; }
    if (CIBLE === 'legacy') {
        lignes.push(`ECART CONNU (legacy)  ${libelle}${detail ? '  — ' + detail : ''}`);
        ecarts++;
    } else {
        lignes.push(`FAIL  ${libelle}${detail ? '  — ' + detail : ''}`);
        echecs++;
    }
}
function constate(libelle, valeur) {
    lignes.push(`INFO  ${libelle} : ${valeur}`);
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
});

/** Un contexte NEUF par compte : newPage() partagerait les cookies. */
async function nouvelOnglet() {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    page.on('dialog', d => d.dismiss().catch(() => {}));
    return { ctx, page };
}

/** Etape mot de passe seule. Rend l'URL atteinte. */
async function etapeMotDePasse(page, nom, mdp) {
    await page.goto(`${BASE}/auth/login.php`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', mdp, { delay: 8 });
    const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]');
    try { await nav; } catch { /* la page peut se re-rendre sans naviguer */ }
    return page.url();
}

/** Etape second facteur. Rend l'URL atteinte. */
async function etapeSecondFacteur(page, code) {
    const champ = await page.$('input[name="2fa_code"]');
    if (!champ) return page.url();
    await champ.type(code, { delay: 8 });
    const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]');
    try { await nav; } catch { /* idem */ }
    return page.url();
}

/** Identifiant de session courant (PHPSESSID ou equivalent Laravel). */
async function jetonSession(page) {
    const cookies = await page.cookies(BASE);
    const c = cookies.find(x => /PHPSESSID|laravel[_-]?session|session/i.test(x.name));
    return c ? c.value : null;
}

try {
    // ── A. Page protegee sans session ───────────────────────────────────────
    {
        const { ctx, page } = await nouvelOnglet();
        for (const chemin of PAGES_PROTEGEES) {
            const rep = await page.goto(`${BASE}${chemin}`, { waitUntil: 'networkidle2' });
            const url = page.url();
            const renvoyee = /login|auth/i.test(url);
            verifie(`A. sans session, ${chemin} renvoie vers la connexion`,
                    renvoyee, `statut=${rep ? rep.status() : '?'} url=${url.replace(BASE, '')}`);
        }
        await ctx.close();
    }

    // ── B. Mot de passe correct SEUL n'authentifie pas ──────────────────────
    for (const c of COMPTES) {
        const { ctx, page } = await nouvelOnglet();
        const apres = await etapeMotDePasse(page, c.nom, MDP);
        const surSecondFacteur = /verify_2fa|enable_2fa|2fa|two-factor/i.test(apres);
        verifie(`B. ${c.nom} : mot de passe seul -> second facteur exige`,
                surSecondFacteur, apres.replace(BASE, ''));

        // A ce stade la session n'est PAS authentifiee : une page protegee
        // doit encore etre refusee.
        await page.goto(`${BASE}/index.php`, { waitUntil: 'networkidle2' });
        const urlProtegee = page.url();
        verifie(`B. ${c.nom} : entre le mot de passe et le second facteur, /index.php reste refuse`,
                !/index\.php$/.test(urlProtegee) || /login|2fa/i.test(urlProtegee),
                urlProtegee.replace(BASE, ''));
        await ctx.close();
    }

    // ── C. Mauvais mot de passe ─────────────────────────────────────────────
    {
        const c = COMPTES[0];
        const { ctx, page } = await nouvelOnglet();
        const apres = await etapeMotDePasse(page, c.nom, 'mot-de-passe-manifestement-faux-42');
        verifie(`C. ${c.nom} : mauvais mot de passe n'authentifie pas`,
                /login/i.test(apres), apres.replace(BASE, ''));
        await ctx.close();
    }

    // ── D. REJEU TOTP entre deux sessions, dans la MEME fenetre ─────────────
    // Le garde du legacy est porte par la SESSION (`last_totp_hash`) : il ne
    // peut donc rien contre un rejeu venu d'une session neuve. On mesure.
    {
        const c = COMPTES[2]; // le compte le plus privilegie : l'enjeu y est maximal

        // Se placer en debut de fenetre pour avoir le temps de deux connexions.
        if (resteFenetre() < 20) await dors((resteFenetre() + 1) * 1000);
        const code = totp(c.secret);
        const fenetre = Math.floor(Date.now() / 1000 / 30);

        // Premiere connexion, complete.
        const a = await nouvelOnglet();
        await etapeMotDePasse(a.page, c.nom, MDP);
        const url1 = await etapeSecondFacteur(a.page, code);
        const premiereOk = !/verify_2fa|login/i.test(url1);
        verifie(`D. ${c.nom} : premiere utilisation du code acceptee`, premiereOk, url1.replace(BASE, ''));
        await a.ctx.close();

        // Seconde connexion, session NEUVE, MEME code, MEME fenetre.
        const memeFenetre = Math.floor(Date.now() / 1000 / 30) === fenetre;
        constate('D. la seconde tentative est dans la meme fenetre TOTP', memeFenetre ? 'oui' : 'NON (mesure invalide)');

        if (memeFenetre) {
            const b = await nouvelOnglet();
            await etapeMotDePasse(b.page, c.nom, MDP);
            const url2 = await etapeSecondFacteur(b.page, code);
            const rejeuAccepte = !/verify_2fa|login/i.test(url2);
            constate('D. rejeu du meme code depuis une session neuve', rejeuAccepte ? 'ACCEPTE' : 'refuse');
            // Le garde du legacy (`last_totp_hash`) est pose UNIQUEMENT dans la
            // branche de succes de verify_2fa.php ligne 96, puis supprime onze
            // lignes plus bas (126) dans la MEME requete. Il n'est jamais pose
            // sur un echec. Il ne peut donc jamais se declencher — et, porte par
            // la session, il ne pourrait de toute facon rien contre un rejeu
            // venu d'une session neuve, qui est precisement le scenario.
            // Le portage doit porter ce garde par COMPTE, en base.
            verifiePortage('D. le rejeu du meme code doit etre REFUSE',
                    !rejeuAccepte, url2.replace(BASE, ''));
            await b.ctx.close();
        }
    }

    // ── E + F. Session regeneree, puis passage par les CGU ──────────────────
    {
        const c = COMPTES[1];
        // Fenetre TOTP distincte de celle du bloc D.
        await dors((resteFenetre() + 1) * 1000);

        const { ctx, page } = await nouvelOnglet();
        await page.goto(`${BASE}/auth/login.php`, { waitUntil: 'networkidle2' });
        const avant = await jetonSession(page);

        await etapeMotDePasse(page, c.nom, MDP);
        const url = await etapeSecondFacteur(page, totp(c.secret));
        const apres = await jetonSession(page);

        verifie(`E. ${c.nom} : l'identifiant de session change apres authentification`,
                Boolean(avant) && Boolean(apres) && avant !== apres,
                `avant=${avant ? avant.slice(0, 6) + '…' : 'absent'} apres=${apres ? apres.slice(0, 6) + '…' : 'absent'}`);

        verifie(`F. ${c.nom} : apres le second facteur, passage par les conditions d'utilisation`,
                /terms|cgu|conditions/i.test(url), url.replace(BASE, ''));
        await ctx.close();
    }
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL / ${ecarts} ecart(s) connu(s)`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
