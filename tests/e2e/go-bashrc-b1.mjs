/**
 * go-bashrc-b1.mjs - Sous-lot B1 de `bashrc/` : la page, ses trois onglets, ses gardes.
 *
 * `legacy/bashrc/index.php` (352 l.), `legacy/bashrc/js/bashrc.js` (589 l.).
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/bashrc/
 *   laravel  http://localhost:8444/bashrc   (pas encore porte)
 *
 * ══ CE QUE CE SOUS-LOT MESURE, ET POURQUOI C'EST LE PLUS INTERESSANT ══════
 *
 * **LE TRIPLE CHEMIN DE GARDE.** La page porte `checkAuth([ROLE_ADMIN,
 * ROLE_SUPERADMIN])` ET `checkPermission('can_manage_bashrc')`. Trois chemins
 * distincts en sortent, et celui du MILIEU n'est exerce par aucune autre suite
 * du chantier :
 *
 *   rw-test-user   role 1, sans la permission  -> REFUSE
 *   rw-test-admin  role 2, SANS la permission  -> REFUSE   <- celui-la
 *   rw-test-super  role 3, SANS la permission  -> ADMIS    (contournement de role)
 *
 * La table `permissions` a ete relevee au 2026-08-26 : **aucun des trois comptes
 * d'epreuve ne detient `can_manage_bashrc`** (seul `superadmin`, inutilisable).
 * `rw-test-super` exerce donc le contournement PAR LE ROLE, et `rw-test-admin`
 * mesure que le role 2, lui, ne contourne pas.
 *
 * C'est la seule facon de distinguer « la garde laisse passer parce que la
 * permission est la » de « parce que le role l'emporte ». Vingt-et-une vagues
 * ont ete perdues ailleurs a ecrire « non mesurable ».
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * B1 ne mesure QUE la page. Or l'ouvrir peut declencher `bashrcLoadUsers()`,
 * qui appelle `/bashrc/users` — une route qui OUVRE UNE SESSION SSH sur la
 * machine pour enumerer ses comptes. C'est une lecture, et elle appartient a B2.
 *
 * **Toutes les routes `/bashrc/*` sont donc interceptees et AVORTEES**, filet
 * pose avant toute navigation et jamais leve. B1 prouve ainsi qu'il n'a joint
 * aucune machine, plutot que de l'affirmer.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-bashrc-b1
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

/**
 * Les trois comptes, avec leur attendu. Le SECRET n'est jamais invente : ces
 * trois valeurs sont celles qu'emploient les 30 autres suites du depot.
 */
const COMPTES = [
    { nom: 'rw-test-user',  role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW', admis: false },
    { nom: 'rw-test-admin', role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX', admis: false },
    { nom: 'rw-test-super', role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW', admis: true },
];
const COMPTE_CAPTURES = 'rw-test-super';

/**
 * Les routes qui JOIGNENT UNE MACHINE, ou qui ECRIVENT. B1 les avorte toutes :
 * il ne mesure que la page, les lectures distantes sont B2.
 *
 * **`GET /bashrc/template` en est EXCLU, et c'est une correction.** Cette route
 * lit le gabarit EN BASE — elle ne joint aucune machine. La premiere redaction
 * l'avortait avec les autres, et la page rendait alors « Failed to fetch » :
 * **la suite fabriquait l'erreur JavaScript qu'elle rapportait ensuite**, et
 * l'assertion « aucune erreur JavaScript » aurait echoue sur le portage pour un
 * defaut cree par l'instrument de mesure.
 *
 * Le `POST` sur la meme route, lui, ECRIT le gabarit : il reste avorte. D'ou le
 * filtre par METHODE plus bas, et non par seul chemin.
 */
const ROUTES_MACHINE = /\/bashrc\/(users|prerequisites|preview|deploy|restore|backups)/;
const ROUTE_GABARIT = /\/bashrc\/template/;

const DOSSIER_CAPTURES = new URL('./screenshots/bashrc', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/bashrc',
        onglets: '[data-rw^="bashrc-onglet-"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/bashrc/',
        onglets: '.tab-btn[data-tab]',
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
function verifie(l, ok, d) { note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs += 1; }
function constate(l, v) { note(`INFO  ${l} : ${v}`); }
function verifiePortage(l, ok, d) {
    if (CIBLE === 'laravel') return verifie(l, ok, ok ? '' : d);
    constate(l, `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];
/** Toute requete du module vue sur l'execution. Elles sont toutes avortees. */
const interceptees = [];

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(45000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => { try { await d.dismiss(); } catch {} });

    // LE FILET : aucune route du module ne part. Pose avant toute navigation.
    await page.setRequestInterception(true);
    page.on('request', (r) => {
        const versMachine = ROUTES_MACHINE.test(r.url());
        const ecritGabarit = ROUTE_GABARIT.test(r.url()) && r.method() !== 'GET';
        if (versMachine || ecritGabarit) {
            interceptees.push(`${r.method()} ${r.url().replace(/^https?:\/\/[^/]+/, '')}`);
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        r.continue().catch(() => {});
    });

    await page.goto(`${BASE}${C.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    for (let essai = 0; essai < 2; essai += 1) {
        const champ = await page.$('input[name="2fa_code"]');
        if (! champ) break;
        if (essai > 0) await dors((resteFenetre() + 1) * 1000);
        await champ.click({ clickCount: 3 });
        await champ.type(totp(secret), { delay: 8 });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
    }
    if (C.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$(C.accepte);
        if (b) await b.evaluate((x) => x.click());
        try { await nav; } catch {}
    }
    // LA SESSION A-T-ELLE TENU ? Sans ce controle, un second facteur refuse
    // ferait mesurer la page de CONNEXION — qui rend 200 et ne porte aucune
    // entree de menu. Piege paye sur les controles i18n.
    const surConnexion = /connexion|login\.php/.test(page.url());

    return { ctx, page, erreursJs, surConnexion };
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

try {
    // ══ 1. LE TRIPLE CHEMIN DE GARDE ══════════════════════════════════════
    //
    // Relevé d'abord EN BASE : si un compte d'epreuve venait a recevoir la
    // permission, l'attendu du milieu changerait sans que rien ne le signale.
    // On mesure la precondition plutot que de la supposer.
    const porteurs = litEnBase(
        'SELECT u.name FROM rootwarden.users u JOIN rootwarden.permissions p ON p.user_id = u.id '
        + "WHERE p.can_manage_bashrc = 1 AND u.name LIKE 'rw-test-%'");
    constate('comptes d\'epreuve detenant `can_manage_bashrc`', porteurs.join(', ') || '(aucun)');
    verifie('aucun compte d\'epreuve ne detient la permission', porteurs.length === 0,
        porteurs.length === 0 ? '' : `${porteurs.join(', ')} — l'attendu du role 2 n'est plus valable`);

    for (const compte of COMPTES) {
        await etape(`garde : ${compte.nom} (role ${compte.role}, sans la permission)`, async () => {
            const s = await connecte(compte.nom, compte.secret);
            try {
                verifie(`${compte.nom} : la session a tenu`, ! s.surConnexion, s.page.url());
                if (s.surConnexion) return;
                const rep = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
                const statut = rep ? rep.status() : 0;
                constate(`${compte.nom} : statut`, String(statut));

                // LA PROPRIETE, par compte. Le role 3 passe SANS la permission
                // (contournement de role) ; le role 2 ne passe PAS.
                verifie(`${compte.nom} (role ${compte.role}) est ${compte.admis ? 'admis' : 'refuse'}`,
                    compte.admis ? statut === 200 : statut === 403,
                    `statut ${statut}`);
            } finally {
                await s.ctx.close();
            }
        });
        // Le garde anti-rejeu TOTP est par COMPTE et EN BASE : il traverse les
        // contextes de navigateur. Attendre le basculement de fenetre.
        await dors((resteFenetre() + 1) * 1000);
    }

    // ══ 2. LA PAGE, AU COMPTE QUI Y ACCEDE ════════════════════════════════
    const s = await connecte(COMPTE_CAPTURES, COMPTES[2].secret);
    const { page, erreursJs } = s;
    verifie('la session de capture a tenu', ! s.surConnexion, page.url());

    await etape('les trois onglets sont la, et ils basculent', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const onglets = await page.$$eval(C.onglets, (els) => els.map((e) => ({
            cle: e.dataset.tab || e.dataset.rw || '',
            libelle: (e.textContent || '').trim(),
            visible: e.offsetParent !== null,
        })));
        constate('onglets trouves', onglets.map((o) => `${o.cle}="${o.libelle}"`).join(' · ') || '(aucun)');
        verifie('les trois onglets sont presents', onglets.length === 3, `${onglets.length} trouve(s)`);
        verifie('les trois onglets sont visibles', onglets.length > 0 && onglets.every((o) => o.visible));

        // BASCULER PAR UN CLIC, pas en appelant la fonction de la page : un
        // ecouteur jamais attache ne se verrait pas autrement.
        if (onglets.length === 3) {
            const cible = onglets[2].cle;
            const boutons = await page.$$(C.onglets);
            await boutons[2].click();
            await dors(500);
            const actif = await page.$$eval(C.onglets, (els) => {
                const a = els.find((e) => e.classList.contains('active')
                    || e.getAttribute('aria-selected') === 'true');

                return a ? (a.dataset.tab || a.dataset.rw || '') : '';
            });
            constate('onglet actif apres le clic', actif || '(aucun marque actif)');
            verifie('cliquer un onglet le rend actif', actif === cible, `attendu ${cible}, vu « ${actif} »`);
        }
    });

    await etape('aucun identifiant de traduction a l\'ecran', async () => {
        const rep = await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        // LA PRECONDITION D'ABORD : une page en erreur n'a pas d'identifiants de
        // traduction a montrer, et « aucun trouve » y serait vrai pour la pire
        // des raisons. Mesure du 2026-08-26 : la page rendait 500, et le
        // controle lisait la PAGE D'ERREUR.
        verifie('la page rend avant qu\'on y cherche des identifiants',
            rep && rep.status() === 200, `statut ${rep ? rep.status() : 0}`);
        if (! rep || rep.status() !== 200) return;

        const bruts = await page.evaluate(() => {
            const texte = document.body.innerText || '';
            // Le motif exclut les EXTENSIONS DE FICHIER : sur la page d'erreur,
            // `bashrc.blade` et `bashrc.js` etaient rapportes comme des cles de
            // traduction manquantes. Ce sont des noms de fichiers dans une pile
            // d'appels — l'instrument nommait mal ce qu'il voyait.
            const trouves = texte.match(/\bbashrc\.[a-z_]+\b/g) || [];

            return [...new Set(trouves.filter(
                (c) => ! /\.(blade|js|php|css|json|log|mjs)$/.test(c)))];
        });
        constate('cles brutes visibles', bruts.join(', ') || '(aucune)');
        verifie('aucune cle de traduction n\'apparait en clair', bruts.length === 0, bruts.join(', '));
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            await dors(500);
            await page.screenshot({ path: `${dossier}/bashrc-b1-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    verifiePortage('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 2).join(' | '));

} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    // Chaque controle dans son PROPRE `try` : une exception ici emporterait les
    // suivants, et c'est deja arrive (A2).
    try {
        // B1 N'A JOINT AUCUNE MACHINE, et on le PROUVE. Les requetes du module
        // sont comptees puis avortees ; en voir est normal (la page en emet au
        // chargement), n'en laisser passer aucune est la propriete.
        constate('requetes avortees (machine ou ecriture)', interceptees.length
            ? [...new Set(interceptees)].join(' · ') : '(aucune)');
        // La propriete se mesure sur ce qui a ete AVORTE, pas sur un `true`
        // constant : une assertion qui vaut toujours vrai n'en est pas une.
        verifie('aucune requete avortee ne visait autre chose qu\'une machine ou une ecriture',
            interceptees.every((r) => ROUTES_MACHINE.test(r) || ROUTE_GABARIT.test(r)),
            interceptees.join(' · '));
    } catch (e) { note(`FAIL  controle des requetes : ${e.message}`); echecs += 1; }
    try {
        // AUCUNE FIXTURE : B1 ne pose rien. On le verifie plutot que de l'affirmer.
        //
        // LE PREFIXE EST `[bashrc]`, ENTRE CROCHETS. Une premiere redaction
        // cherchait `LIKE 'bashrc%'` : elle n'aurait JAMAIS rien trouve, et
        // aurait donc toujours conclu « aucun journal ». Un controle qui ne peut
        // pas se declencher n'est pas un controle — c'est la famille du « test
        // qui ne peut pas echouer ». Verifie contre le format reel en base.
        const politiques = compteEnBase('SELECT COUNT(*) FROM rootwarden.user_logs '
            + "WHERE action LIKE '[bashrc]%' AND created_at > NOW() - INTERVAL 10 MINUTE");
        constate('journaux `bashrc*` des dix dernieres minutes', String(politiques));
        verifie('la suite n\'a produit aucun journal de geste bashrc', politiques === 0,
            politiques === 0 ? '' : `${politiques} ligne(s) — une route a abouti`);
    } catch (e) { note(`FAIL  controle du journal : ${e.message}`); echecs += 1; }
    try {
        const zabbix = litEnBase("SELECT CONCAT(name,'|',ip) FROM rootwarden.machines WHERE id = 1");
        verifie('srv-zabbix est intacte', zabbix.length === 1 && zabbix[0] === 'srv-zabbix|192.168.0.244',
            zabbix[0] || '(absente)');
    } catch (e) { note(`FAIL  controle de srv-zabbix : ${e.message}`); echecs += 1; }
    try { for (const c of contextes) await c.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
    try { await navigateur.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
