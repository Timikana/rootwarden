/**
 * go-socle-navigation.mjs - Le menu du portail porte.
 *
 * Ce que ce test regarde, et pourquoi :
 *
 *  - IL SUIT LES LIENS. Sur la tentative precedente, sept entrees de menu
 *    rendaient 404 pendant des semaines parce qu'aucune suite ne cliquait
 *    dessus. On ne teste que ce qu'on regarde.
 *  - IL COMPARE LES ROLES. Une suite qui s'authentifie en superadmin ne mesure
 *    aucun cloisonnement. Les trois comptes dedies sont utilises, et le menu
 *    doit STRICTEMENT croitre avec les droits.
 *  - IL CHERCHE LES CLES MORTES. Une cle de traduction absente n'echoue pas :
 *    elle affiche son identifiant. `nav.` visible a l'ecran est un defaut.
 *  - IL VERIFIE LE MARQUEUR DES PAGES NON PORTEES. Un lien qui change de
 *    portail sans le dire trahit l'utilisateur.
 *
 * Cible : Laravel uniquement (le legacy n'a pas ce menu porte).
 *
 * Usage :
 *   cd tests/e2e
 *   node go-socle-navigation.mjs
 */
import puppeteer from 'puppeteer';
import { execFileSync } from 'child_process';
import { createHmac } from 'crypto';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
/**
 * La base du legacy, LUE DANS LA CONFIGURATION DU PORTAGE et non ecrite en dur.
 *
 * L'ancienne valeur figee `https://localhost:8443` faisait echouer trois
 * assertions des que `LEGACY_URL` pointait ailleurs — par exemple sur l'adresse
 * de la VM, ce qu'il FAUT poser pour ouvrir les deux portails depuis un autre
 * poste : un lien « ancien portail » en localhost mene au localhost DU VISITEUR.
 *
 * Le test mesurait donc une VALEUR de deploiement la ou la propriete a verifier
 * est « l'entree vise le portail legacy, quelle que soit son adresse ». Il lit
 * desormais la meme source que la page — il ne peut plus la contredire.
 * `E2E_LEGACY` reste prioritaire pour forcer la main.
 */
function baseLegacyConfiguree() {
    if (process.env.E2E_LEGACY) return process.env.E2E_LEGACY;
    try {
        const sortie = execFileSync('docker',
            ['exec', 'rootwarden_laravel', 'php', 'artisan', 'config:show', 'app'],
            { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
        const ligne = sortie.split('\n').find(l => /^\s+url_legacy\s/.test(l));
        const url = ligne && ligne.match(/(https?:\/\/\S+)/);
        if (url) return url[1].replace(/\/+$/, '');
    } catch { /* le relais docker peut manquer : on retombe sur le defaut */ }
    return 'https://localhost:8443';
}
const LEGACY = baseLegacyConfiguree();
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTES = [
    { nom: 'rw-test-user',  role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW' },
    { nom: 'rw-test-admin', role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX' },
    { nom: 'rw-test-super', role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW' },
];

/** Nombre total d'entrees declarees dans App\Support\Navigation. */
const TOTAL_ENTREES = 33;

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
function verifie(libelle, ok, detail) {
    lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${libelle}${detail ? '  — ' + detail : ''}`);
    if (!ok) echecs++;
}
function constate(libelle, valeur) { lignes.push(`INFO  ${libelle} : ${valeur}`); }

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
});

/** Ouvre une session complete et rend le menu observe. */
async function connecte(compte) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    page.on('dialog', d => d.dismiss().catch(() => {}));

    await page.goto(`${BASE}/connexion`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', compte.nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]');
    try { await nav; } catch {}

    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    await page.type('input[name="2fa_code"]', totp(compte.secret), { delay: 8 });
    nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]');
    try { await nav; } catch {}

    // On arrive sur les conditions d'utilisation : on les accepte pour entrer.
    if (/\/cgu/.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        // Ancrage sur le CONTRAT DOM : la page CGU porte deux boutons submit,
        // et refuser vient avant accepter.
        await page.click('[data-rw="cgu-accepter"]');
        try { await nav; } catch {}
    }

    return { ctx, page };
}

/** Releve le menu tel qu'il est RENDU, barre laterale et tiroir separement. */
async function releveMenu(page) {
    return page.evaluate(() => {
        const lire = (racine) => [...racine.querySelectorAll('.rw-menu__lien')].map(a => {
            const libelle = a.querySelector('.rw-menu__libelle');
            const marqueur = a.querySelector('.rw-menu__marqueur');
            return {
                libelle: (libelle?.textContent || '').trim(),
                href: a.getAttribute('href') || '',
                externe: a.classList.contains('rw-menu__lien--externe'),
                marqueur: (marqueur?.textContent || '').trim(),
                cible: a.getAttribute('target') || '',
                // Geometrie reelle : un marqueur declare mais large de zero ne
                // previent personne, et un libelle tronque a l'ecran ne se voit
                // pas dans le HTML. On mesure ce qui est RENDU.
                largeurMarqueur: marqueur ? Math.round(marqueur.getBoundingClientRect().width) : -1,
                libelleTronque: libelle ? libelle.scrollWidth > libelle.clientWidth + 1 : false,
                debordeLien: a.scrollWidth > a.clientWidth + 1,
            };
        });
        const laterale = document.querySelector('.rw-laterale .rw-menu');
        const tiroir = document.querySelector('.rw-tiroir__panneau');

        return {
            laterale: laterale ? lire(laterale) : [],
            tiroir: tiroir ? lire(tiroir) : [],
            sections: [...document.querySelectorAll('.rw-laterale .rw-menu__section')].map(s => s.textContent.trim()),
            texteEntier: document.body.innerText,
        };
    });
}

try {
    const vus = [];

    for (const compte of COMPTES) {
        // Fenetre TOTP distincte entre deux comptes n'est pas necessaire (les
        // comptes different), mais on evite de coller deux connexions.
        const { ctx, page } = await connecte(compte);

        if (! /\/accueil/.test(page.url())) {
            verifie(`${compte.nom} : arrive sur l'accueil`, false, page.url().replace(BASE, ''));
            await ctx.close();
            continue;
        }

        const menu = await releveMenu(page);
        vus.push({ compte, menu });

        // ── Le menu est rendu DEUX FOIS mais depuis UNE SEULE source ────────
        // On compare les ENTREES, pas leur geometrie : le tiroir est ferme
        // (display:none), donc de largeur nulle. Comparer la geometrie, ce
        // serait faire dependre l'assertion d'une forme qui n'est pas son objet.
        const sansGeometrie = liste => liste.map(e =>
            [e.libelle, e.href, e.externe, e.marqueur, e.cible].join('|'));
        const memeMenu = JSON.stringify(sansGeometrie(menu.laterale))
                      === JSON.stringify(sansGeometrie(menu.tiroir));
        verifie(`${compte.nom} : barre laterale et tiroir rendent les MEMES entrees`,
                memeMenu, `laterale=${menu.laterale.length} tiroir=${menu.tiroir.length}`);

        // ── Aucune cle de traduction morte ──────────────────────────────────
        const clesMortes = menu.laterale.filter(e => /^(nav|auth)\./.test(e.libelle)).map(e => e.libelle);
        verifie(`${compte.nom} : aucune cle de traduction morte dans le menu`,
                clesMortes.length === 0, clesMortes.join(', ') || 'aucune');
        verifie(`${compte.nom} : aucune cle morte ailleurs dans la page`,
                ! /\b(nav|auth)\.[a-z_]{3,}/.test(menu.texteEntier));

        // ── Les liens non portes le DISENT ──────────────────────────────────
        const externes = menu.laterale.filter(e => e.externe);
        const mal = externes.filter(e => ! e.href.startsWith(LEGACY) || e.cible !== '_blank' || e.marqueur === '');
        verifie(`${compte.nom} : chaque entree non portee vise le legacy, en nouvel onglet, avec son marqueur`,
                mal.length === 0, `${externes.length} externes, ${mal.length} incorrectes`);

        // Le marqueur doit etre VISIBLE, pas seulement present dans le HTML.
        const marqueursEcrases = externes.filter(e => e.largeurMarqueur <= 0);
        verifie(`${compte.nom} : le marqueur « non porte » est visible a l'ecran`,
                marqueursEcrases.length === 0,
                `${marqueursEcrases.length} ecrase(s) sur ${externes.length}`);

        // Aucun lien ne doit deborder de sa colonne.
        const debordent = menu.laterale.filter(e => e.debordeLien).map(e => e.libelle);
        verifie(`${compte.nom} : aucune entree ne deborde de la barre laterale`,
                debordent.length === 0, debordent.join(', ') || 'aucune');

        const tronques = menu.laterale.filter(e => e.libelleTronque).map(e => e.libelle);
        if (tronques.length) constate(`${compte.nom} : libelles tronques (title present)`, tronques.join(', '));

        // ── Les liens portes RESOLVENT (le piege des sept 404) ──────────────
        const internes = menu.laterale.filter(e => ! e.externe);
        for (const e of internes) {
            const rep = await page.goto(e.href, { waitUntil: 'networkidle2' });
            const statut = rep ? rep.status() : 0;
            verifie(`${compte.nom} : le lien porte « ${e.libelle} » resout`,
                    statut === 200 && ! /\/connexion/.test(page.url()),
                    `${statut} ${page.url().replace(BASE, '')}`);
        }

        constate(`${compte.nom} (role ${compte.role})`,
                 `${menu.laterale.length} entrees · ${internes.length} portees · ${externes.length} vers le legacy · sections : ${menu.sections.join(', ') || 'aucune'}`);

        await ctx.close();
    }

    // ── Le menu croit STRICTEMENT avec les droits ───────────────────────────
    if (vus.length === 3) {
        const [u, a, s] = vus.map(v => v.menu.laterale.length);
        verifie('le menu croit strictement avec les droits (role 1 < role 2 < role 3)',
                u < a && a < s, `${u} < ${a} < ${s}`);

        verifie('le superadmin voit toutes les entrees declarees',
                s === TOTAL_ENTREES, `${s} sur ${TOTAL_ENTREES}`);

        // Un role sans permission ne doit voir AUCUNE entree d'administration.
        const sectionsRole1 = vus[0].menu.sections.map(x => x.toLowerCase());
        verifie('un role sans permission ne voit pas la section administration',
                ! sectionsRole1.some(x => /admin/.test(x)), sectionsRole1.join(', ') || 'aucune section');

        // Ce que le role 1 voit doit etre un SOUS-ENSEMBLE de ce que voit le role 3.
        const libelles = v => new Set(v.menu.laterale.map(e => e.libelle));
        const sousEnsemble = [...libelles(vus[0])].every(l => libelles(vus[2]).has(l));
        verifie('ce que voit le role 1 est un sous-ensemble de ce que voit le superadmin', sousEnsemble);
    }
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
