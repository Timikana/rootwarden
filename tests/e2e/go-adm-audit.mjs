/**
 * go-adm-audit.mjs - Sous-lot D1 de `adm/` : le journal d'audit.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/adm/audit_log.php
 *   laravel  http://localhost:8444/journal-audit          (pas encore porte)
 *
 * Perimetre du sous-lot, tel que `MODULE-ADM.md` le decoupe :
 *   adm/audit_log.php · adm/api/audit_verify.php · adm/api/audit_seal.php
 *   adm/includes/audit_log.php                                  — 711 lignes.
 *
 * ══ POURQUOI D1 VIENT EN PREMIER, ET CE QU'IL FAUT QUAND MEME PROTEGER ══════
 *
 * C'est le seul sous-lot de `adm/` qui ne joint aucune machine : tout se joue
 * en base. Mais il porte **une** ecriture, et elle n'est pas anodine — le bouton
 * « Sceller les orphelines » ecrit `prev_hash` et `self_hash` sur toutes les
 * lignes non scellees de `user_logs`, et **rien ne le defait** : remettre des
 * NULL serait fabriquer un autre etat, pas restaurer celui d'avant.
 *
 * Or le plan porte ces lignes non scellees en §7 comme un constat **mesure et
 * non corrige**, en attente d'arbitrage. Une suite qui cliquerait le bouton
 * trancherait donc a la place de l'exploitant, en silence, et le compteur qu'il
 * suit changerait sans qu'aucun commit ne le dise.
 *
 * D'ou les deux motifs employes ici, chacun avec sa raison :
 *
 *   1. **interception + avortement** sur le bouton « Sceller » — on clique le
 *      VRAI bouton, on mesure la requete emise (methode, chemin, en-tete CSRF)
 *      et elle est **abattue avant de partir**. C'est le motif de V8. La
 *      propriete mesuree est « le bouton emet bien la requete attendue », pas
 *      « le scellement fonctionne » ;
 *
 *   2. **requete FORGEE depuis la page** pour la simulation. MOTIF ECRIT, comme
 *      la convention l'exige : `audit_seal.php:42` porte un mode simulation
 *      (`$dryRun = methode !== 'POST'`), mais **aucun element de l'interface ne
 *      l'offre** — le seul bouton POSTe. Il n'existe donc aucun clic capable
 *      d'atteindre cette branche. Le `fetch` part depuis la page, avec sa
 *      session et ses en-tetes reels.
 *
 * Le bouton « Verifier l'integrite » est, lui, clique pour de vrai : son
 * endpoint est en LECTURE seule (`audit_verify.php`, aucun UPDATE).
 *
 * ══ CE QUE LA LECTURE A FAIT ATTENDRE, ET QUI SE MESURE ICI ═════════════════
 *
 * `audit_verify.php` et `audit_seal.php` ne parcourent PAS la chaine de la meme
 * facon devant une ligne orpheline :
 *
 *   - verify (`:44-51`) la **saute** sans avancer `$expectedPrev` ;
 *   - seal   (`:79-84`) **calcule** son hash et avance `$lastHash`.
 *
 * Mesure en base au 2026-08-25 : 4171 lignes, 3305 scellees, 866 orphelines, et
 * les orphelines sont **entrelacees** (la premiere porte l'id 2, et 3304 lignes
 * scellees viennent apres elle). Les deux lectures de la chaine ne peuvent donc
 * pas rendre le meme verdict. La suite ne suppose rien : elle clique, elle lit,
 * et elle CONSTATE le verdict rendu.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-adm-audit
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

/** Role 3 : le seul qui voie les deux boutons d'integrite. */
const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
/** Role 2 SANS `can_admin_portal` (mesure en base) — chemin « permission ». */
const COMPTE_ROLE = 'rw-test-admin';
const SECRET_ROLE = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';
/** Role 1 — chemin « role ». D-5 : lecture seule, jamais modifie. */
const COMPTE_BAS = 'rw-test-user';
const SECRET_BAS = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';

/** Les captures vont dans le depot, jamais dans un scratchpad : ailleurs, elles
 *  sont invisibles. */
const DOSSIER_CAPTURES = new URL('./screenshots/adm', import.meta.url).pathname;

/** Le legacy pagine a 50 (`audit_log.php:19`). */
const PAR_PAGE = 50;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/journal-audit',
        total: '[data-rw="audit-total"]',
        corps: '[data-rw="audit-corps"]',
        champUtilisateur: '[data-rw="audit-filtre-utilisateur"]',
        champAction: '[data-rw="audit-filtre-action"]',
        champDu: '[data-rw="audit-filtre-du"]',
        boutonFiltrer: '[data-rw="audit-filtrer"]',
        lienCsv: '[data-rw="audit-export-csv"]',
        boutonVerifier: '[data-rw="audit-verifier"]',
        boutonSceller: '[data-rw="audit-sceller"]',
        resultat: '[data-rw="audit-resultat"]',
        confirmerEnPage: '[data-rw="audit-confirmer"]',
        routeVerifier: '/journal-audit/verifier',
        // Le portage SEPARE la simulation du scellement : `?simulation=1` rend
        // ce que l'ecriture produirait, sans rien ecrire.
        routeSimulation: ['/journal-audit/sceller?simulation=1', 'POST'],
        motifSceller: /\/journal-audit\/sceller/,
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/adm/audit_log.php',
        total: null,
        corps: 'tbody',
        champUtilisateur: 'input[name="user"]',
        champAction: 'input[name="action"]',
        champDu: 'input[name="from"]',
        boutonFiltrer: null,
        lienCsv: 'a[href*="export=csv"]',
        boutonVerifier: '#btn-verify-audit',
        boutonSceller: '#btn-seal-audit',
        resultat: '#audit-verify-result',
        confirmerEnPage: null,
        routeVerifier: '/adm/api/audit_verify.php',
        // Cote legacy la simulation est la branche NON-POST du meme fichier.
        routeSimulation: ['/adm/api/audit_seal.php', 'GET'],
        motifSceller: /audit_seal/,
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

/** Compteurs de la chaine, relus a chaque fois : rien n'est reconduit. */
function compteLignes()      { return compteEnBase('SELECT COUNT(*) FROM rootwarden.user_logs'); }
function compteOrphelines()  { return compteEnBase('SELECT COUNT(*) FROM rootwarden.user_logs WHERE self_hash IS NULL'); }
function compteScellees()    { return compteEnBase('SELECT COUNT(*) FROM rootwarden.user_logs WHERE self_hash IS NOT NULL'); }

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];

async function connecte(nom, secret) {
    // Le compteur de tentatives traverse les suites : le vider avant CHAQUE
    // connexion, sans quoi une suite precedente peut verrouiller celle-ci.
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* table vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(40000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const boitesNatives = [];
    page.on('dialog', async (d) => {
        boitesNatives.push(d.message());
        try { await d.accept(); } catch { /* deja fermee */ }
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
    return { ctx, page, erreursJs, boitesNatives };
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

/** Nombre de lignes du tableau, et le texte de la premiere. Forme CONSTANTE. */
function litTableau(page) {
    return page.evaluate((sel) => {
        const corps = document.querySelector(sel);
        if (! corps) return { porte: false, lignes: 0, textes: [] };
        const trs = Array.from(corps.querySelectorAll('tr'));
        return {
            porte: true,
            lignes: trs.length,
            textes: trs.map((tr) => (tr.textContent || '').replace(/\s+/g, ' ').trim()),
        };
    }, C.corps);
}

/**
 * Soumet le formulaire de filtrage en REMONTANT du champ a son `form`.
 * Jamais « le premier bouton submit de la page » : `audit_log.php` porte aussi
 * le formulaire de recherche globale du menu, et il vient AVANT dans le DOM.
 */
async function soumetFiltre(page, selecteurChamp) {
    const bouton = await page.evaluateHandle((s) => {
        const champ = document.querySelector(s);
        const form = champ ? champ.closest('form') : null;
        return form ? form.querySelector('button[type="submit"], input[type="submit"]') : null;
    }, selecteurChamp);
    const el = bouton.asElement();
    if (! el) throw new Error(`aucun bouton de soumission dans le form de ${selecteurChamp}`);
    const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await el.click();
    try { await nav; } catch {}
}

const session = {};
try {
    // ══ 1. La garde, aux trois roles ════════════════════════════════════════
    // Mesurer le STATUT, pas le texte : un 404 dirait « cette page n'existe
    // pas », pas « vous n'y avez pas droit ».
    await etape('garde role 1', async () => {
        const s = await connecte(COMPTE_BAS, SECRET_BAS);
        const rep = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('role 1 refuse sur le journal d\'audit', rep.status() === 403, `statut ${rep.status()}`);
        await s.ctx.close();
    });

    // Le basculement de fenetre TOTP separe deux connexions du MEME lot : le
    // garde anti-rejeu est par COMPTE et EN BASE, il traverse les contextes.
    await dors((resteFenetre() + 1) * 1000);

    await etape('garde role 2 sans la permission', async () => {
        const s = await connecte(COMPTE_ROLE, SECRET_ROLE);
        const rep = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('role 2 sans can_admin_portal refuse', rep.status() === 403, `statut ${rep.status()}`);
        await s.ctx.close();
    });

    await dors((resteFenetre() + 1) * 1000);

    // ══ 2. La page, au role 3 ═══════════════════════════════════════════════
    session.s = await connecte(COMPTE, SECRET);
    const { page, erreursJs, boitesNatives } = session.s;

    let reponse;
    await etape('ouverture', async () => {
        reponse = await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('role 3 atteint la page', reponse.status() === 200, `statut ${reponse.status()}`);
    });

    const totalBase = compteLignes();
    const orphelinesAvant = compteOrphelines();
    const scelleesAvant = compteScellees();
    constate('lignes en base', `${totalBase} dont ${scelleesAvant} scellees et ${orphelinesAvant} orphelines`);

    await etape('le total affiche', async () => {
        const texte = await page.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
        // Le legacy formate avec une espace comme separateur de milliers.
        const attendu = new Intl.NumberFormat('fr-FR').format(totalBase).replace(/ | /g, ' ');
        verifie('le total annonce correspond a la base', texte.includes(attendu),
            `cherche « ${attendu} » dans la page`);
    });

    await etape('le tableau', async () => {
        const t = await litTableau(page);
        verifie('le tableau des entrees est rendu', t.porte, `porte=${t.porte}`);
        verifie(`la page en rend au plus ${PAR_PAGE}`, t.lignes > 0 && t.lignes <= PAR_PAGE,
            `${t.lignes} lignes`);
    });

    await etape('les deux boutons d\'integrite', async () => {
        const v = await page.$(C.boutonVerifier);
        const s = await page.$(C.boutonSceller);
        verifie('le role 3 voit « Verifier l\'integrite »', !! v);
        verifie('le role 3 voit « Sceller les orphelines »', !! s);
    });

    // ══ 3. Les filtres, par des clics ═══════════════════════════════════════
    await etape('filtre par utilisateur', async () => {
        // `litEnBase` rend un TABLEAU de lignes : prendre la premiere.
        const [nom] = litEnBase(
            "SELECT u.name FROM rootwarden.user_logs l JOIN rootwarden.users u ON l.user_id = u.id "
            + "GROUP BY u.name ORDER BY COUNT(*) DESC LIMIT 1");
        // La fixture se choisit DANS les donnees rendues, jamais inventee.
        constate('utilisateur le plus present au journal', nom);
        const champ = await page.$(C.champUtilisateur);
        if (! champ) throw new Error('champ de filtre utilisateur absent');
        await champ.click({ clickCount: 3 });
        await champ.type(nom, { delay: 8 });
        await soumetFiltre(page, C.champUtilisateur);

        const t = await litTableau(page);
        const toutes = t.textes.length > 0 && t.textes.every((x) => x.includes(nom));
        verifie('toutes les lignes rendues portent l\'utilisateur filtre', toutes,
            `${t.lignes} lignes`);
        const attendu = compteEnBase(
            "SELECT COUNT(*) FROM rootwarden.user_logs l JOIN rootwarden.users u ON l.user_id = u.id "
            + `WHERE u.name LIKE '%${nom.replace(/'/g, "''")}%'`);
        const texte = await page.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
        const attenduFmt = new Intl.NumberFormat('fr-FR').format(attendu).replace(/ | /g, ' ');
        verifie('le total filtre correspond au compte en base', texte.includes(attenduFmt),
            `attendu ${attenduFmt}`);
    });

    await etape('filtre par action', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const champ = await page.$(C.champAction);
        if (! champ) throw new Error('champ de filtre action absent');
        const [motif] = litEnBase(
            "SELECT SUBSTRING_INDEX(action, ' ', 1) FROM rootwarden.user_logs "
            + "GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 1");
        constate('motif d\'action le plus frequent', motif);
        await champ.click({ clickCount: 3 });
        await champ.type(motif, { delay: 8 });
        await soumetFiltre(page, C.champAction);
        const t = await litTableau(page);
        const toutes = t.textes.length > 0
            && t.textes.every((x) => x.toLowerCase().includes(motif.toLowerCase()));
        verifie('toutes les lignes rendues portent le motif d\'action', toutes, `${t.lignes} lignes`);
    });

    await etape('filtre par date', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const champ = await page.$(C.champDu);
        if (! champ) throw new Error('champ de date absent');
        const d = new Date();
        const iso = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
        // Un `input[type=date]` est un COMPOSITE de segments : le clic peut poser
        // le caret sur le mois. On revient au premier segment par des fleches,
        // puis on ASSERTE la valeur obtenue — une frappe qui rate ne doit pas
        // se transformer en mesure silencieusement fausse.
        await champ.click();
        for (let i = 0; i < 3; i += 1) await page.keyboard.press('ArrowLeft');
        await page.keyboard.type(`${String(d.getDate()).padStart(2, '0')}${String(d.getMonth() + 1).padStart(2, '0')}${d.getFullYear()}`, { delay: 30 });
        const saisi = await page.$eval(C.champDu, (e) => e.value);
        verifie('la date saisie est bien celle voulue', saisi === iso, `saisi « ${saisi} », voulu « ${iso} »`);
        if (saisi !== iso) return;

        await soumetFiltre(page, C.champDu);
        const attendu = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.user_logs WHERE created_at >= '${iso} 00:00:00'`);
        const texte = await page.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
        const attenduFmt = new Intl.NumberFormat('fr-FR').format(attendu).replace(/ | /g, ' ');
        verifie('le total du filtre de date correspond a la base', texte.includes(attenduFmt),
            `attendu ${attenduFmt} entrees depuis ${iso}`);
        verifie('le filtre de date se retrouve dans l\'adresse', page.url().includes(`from=${iso}`),
            page.url().split('?')[1] || '(aucun parametre)');
    });

    // ══ 4. L'export CSV : le lien, pas le telechargement ════════════════════
    await etape('le lien d\'export CSV', async () => {
        await page.goto(`${BASE}${C.page}?user=rw-test&page=2`, { waitUntil: 'networkidle2' });
        const href = await page.$eval(C.lienCsv, (a) => a.getAttribute('href'));
        constate('lien d\'export rendu', href);
        verifie('l\'export porte le filtre courant', /user=rw-test/.test(href), href);
        // `audit_log.php:157` retire `page` : l'export porte TOUS les resultats
        // filtres, pas les 50 de la page affichee. C'est un bug corrige, et il
        // doit le rester.
        verifie('l\'export ne se limite pas a la page affichee', ! /[?&]page=/.test(href), href);
    });

    // ══ 5. Verifier l'integrite — clic REEL, endpoint en lecture seule ══════
    await etape('clic sur « Verifier l\'integrite »', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await page.click(C.boutonVerifier);
        // ATTENDRE LE BOUTON, pas la premiere annonce : la region porte d'abord
        // un message de travail. Les deux cibles reactivent leur bouton dans le
        // MEME bloc synchrone que l'ecriture du verdict, ce qui rend ce signal
        // independant de la cible ET de la langue.
        await page.waitForFunction((sr, sb) => {
            const el = document.querySelector(sr);
            const b = document.querySelector(sb);
            return el && b && ! b.disabled && (el.textContent || '').trim().length > 20;
        }, { timeout: 30000 }, C.resultat, C.boutonVerifier);
        const rendu = await page.$eval(C.resultat, (e) => (e.textContent || '').replace(/\s+/g, ' ').trim());
        constate('verdict rendu par la page', rendu);
        verifie('le porte-messages rend un verdict', rendu.length > 20, rendu.slice(0, 80));

        // Le verdict doit nommer les compteurs de la BASE, pas des siens.
        const scelleesMaintenant = compteScellees();
        const orphelinesMaintenant = compteOrphelines();
        const chiffres = (rendu.match(/\d+/g) || []).map(Number);
        const intacte = /intacte/i.test(rendu);
        if (intacte) {
            verifie('le verdict annonce le compte de lignes scellees mesure',
                chiffres.includes(scelleesMaintenant), `base : ${scelleesMaintenant} scellees`);
            verifie('le verdict annonce le compte d\'orphelines mesure',
                chiffres.includes(orphelinesMaintenant), `base : ${orphelinesMaintenant} orphelines`);
        } else {
            // Chemin INCOHERENCE : le verdict nomme une ligne. On mesure qu'il
            // designe une ligne qui EXISTE — un verdict qui pointe dans le vide
            // ne serait pas exploitable.
            const id = chiffres.find((n) => n > 0);
            const existe = id ? compteEnBase(`SELECT COUNT(*) FROM rootwarden.user_logs WHERE id = ${id}`) : 0;
            constate('la chaine est annoncee rompue, sur la ligne', String(id));
            verifie('la ligne designee par le verdict existe en base', existe === 1,
                `id ${id}, ${existe} ligne(s)`);
        }
    });

    // ══ 6. Sceller — le VRAI bouton, la requete AVORTEE ═════════════════════
    // Motif : « chemin destructeur -> simuler d'abord ». Le scellement ne se
    // defait pas, et le compteur d'orphelines est suivi par l'exploitant en §7.
    await etape('clic sur « Sceller » : la requete est emise puis abattue', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const emises = [];
        await page.setRequestInterception(true);
        const filtre = (r) => {
            if (C.motifSceller.test(r.url())) {
                emises.push({
                    methode: r.method(),
                    url: r.url(),
                    csrf: r.headers()['x-csrf-token'] || '',
                    corps: r.postData() || '',
                });
                return r.abort();
            }
            return r.continue();
        };
        page.on('request', filtre);

        const boitesAvant = boitesNatives.length;
        await page.click(C.boutonSceller);
        for (let i = 0; i < 40 && emises.length === 0; i += 1) await dors(250);

        // Couper l'interception AVANT de retirer l'ecouteur : tant qu'elle est
        // active, toute requete non traitee resterait suspendue.
        await page.setRequestInterception(false);
        page.off('request', filtre);

        verifie('le clic emet exactement une requete de scellement', emises.length === 1,
            `${emises.length} requete(s)`);
        if (emises.length) {
            verifie('elle est emise en POST', emises[0].methode === 'POST', emises[0].methode);
            // La propriete est « la requete porte un jeton », pas « elle le porte
            // a tel endroit ». Le legacy le met dans l'en-tete ET dans le corps ;
            // le portage s'en tient a l'en-tete, que `PreventRequestForgery`
            // lit — le dupliquer n'ajouterait rien. On mesure le jeton, et on
            // CONSTATE par ou il voyage.
            const dansLeCorps = /csrf_token/.test(emises[0].corps);
            verifie('elle porte un jeton CSRF', emises[0].csrf.length > 0 || dansLeCorps,
                emises[0].csrf ? `en-tete, ${emises[0].csrf.length} caracteres`
                               : (dansLeCorps ? 'dans le corps seulement' : '(aucun)'));
            constate('ou voyage le jeton',
                `${emises[0].csrf ? 'en-tete' : '—'}${dansLeCorps ? ' + corps' : ''}`);
        }
        // Le legacy garde son `confirm()` natif ; le portage devra un panneau.
        const boiteVue = boitesNatives.length > boitesAvant;
        constate('boite native presentee par le legacy', boiteVue ? boitesNatives[boitesNatives.length - 1] : '(aucune)');
        verifiePortage('le scellement demande confirmation dans un panneau en page',
            !! (C.confirmerEnPage && await page.$(C.confirmerEnPage)),
            'le legacy emploie un confirm() natif, en francais code en dur');

        // La propriete « rien n'a ete ecrit » se mesure EN BASE.
        verifie('aucune ligne n\'a ete scellee par ce clic',
            compteOrphelines() === orphelinesAvant,
            `${orphelinesAvant} avant, ${compteOrphelines()} apres`);
    });

    // ══ 7. La simulation : requete FORGEE, et le motif est ecrit ════════════
    // `audit_seal.php:42` fait de toute methode autre que POST une simulation.
    // AUCUN element de l'interface ne l'emet : le seul bouton POSTe. Il n'existe
    // donc pas de clic capable d'atteindre cette branche. Le `fetch` part DEPUIS
    // la page, donc avec la session et les en-tetes reels.
    await etape('la simulation integree, par requete forgee', async () => {
        const d = await page.evaluate(async ([chemin, methode]) => {
            const options = { credentials: 'same-origin', headers: {} };
            if (methode !== 'GET') {
                options.method = methode;
                const m = document.querySelector('meta[name="csrf-token"]');
                if (m) options.headers['X-CSRF-TOKEN'] = m.content;
            }
            const r = await fetch(chemin, options);
            return { statut: r.status, corps: await r.json() };
        }, C.routeSimulation);
        constate('simulation', JSON.stringify(d.corps).slice(0, 260));
        verifie('la simulation repond 200', d.statut === 200, `statut ${d.statut}`);
        const enSimulation = CIBLE === 'laravel' ? d.corps.simulation : d.corps.dry_run;
        const scellees = CIBLE === 'laravel' ? d.corps.scellees : d.corps.sealed;
        const vues = CIBLE === 'laravel' ? d.corps.total : d.corps.total_rows;
        verifie('elle se declare bien en simulation', enSimulation === true, String(enSimulation));
        verifie('elle n\'a rien scelle', scellees === 0, String(scellees));
        verifie('elle voit le meme nombre total de lignes que la base',
            vues === totalBase, `annonce ${vues}, base ${totalBase}`);
        verifie('la base est intacte apres la simulation',
            compteOrphelines() === orphelinesAvant && compteScellees() === scelleesAvant,
            `${compteOrphelines()} orphelines, ${compteScellees()} scellees`);
    });

    // ══ 8. LE DEFAUT DE D1 : les deux points d'API se contredisent ══════════
    //
    // Mesure du 2026-08-25, et elle ne suppose rien : la MEME base, au MEME
    // instant, obtient deux verdicts opposes.
    //
    //   « Verifier »          -> Chaine intacte
    //   « Sceller » (simule)  -> Desynchronisation ligne 3, investigation requise
    //
    // La raison tient en une ligne. Devant une ligne ORPHELINE :
    //   `audit_verify.php:44-51` la SAUTE sans avancer la tete de chaine ;
    //   `audit_seal.php:79-84`  calcule son hash et AVANCE la tete.
    // Or la chaine reellement inscrite en base saute les orphelines : la ligne 3
    // porte `prev_hash` = `self_hash` de la ligne 1, pas de la ligne 2.
    //
    // Consequence, et c'est elle qui coute : `stopped_at_tamper` verrouille le
    // bloc d'UPDATE (`audit_seal.php:105`). Le bouton « Sceller les orphelines »
    // ne pourra donc JAMAIS sceller une seule ligne — et pendant ce temps le
    // compteur d'orphelines grossit a chaque connexion.
    await etape('les deux points d\'API rendent-ils le meme verdict ?', async () => {
        const d = await page.evaluate(async ([routeV, sim]) => {
            const options = { credentials: 'same-origin', headers: {} };
            if (sim[1] !== 'GET') {
                options.method = sim[1];
                const m = document.querySelector('meta[name="csrf-token"]');
                if (m) options.headers['X-CSRF-TOKEN'] = m.content;
            }
            const [v, s] = await Promise.all([
                fetch(routeV, { credentials: 'same-origin' }).then((r) => r.json()),
                fetch(sim[0], options).then((r) => r.json()),
            ]);
            return { verify: v, seal: s };
        }, [C.routeVerifier, C.routeSimulation]);

        // Les deux cibles ne nomment pas leurs champs de la meme facon. On lit
        // le SENS, pas la cle : « la verification declare-t-elle la chaine
        // saine ? » et « le scellement s'arrete-t-il sur une incoherence ? »
        const verifIntegre = CIBLE === 'laravel' ? d.verify.integre === true
                                                 : d.verify.integrity === 'OK';
        const sealArrete = CIBLE === 'laravel' ? d.seal.arret_sur_incoherence === true
                                               : d.seal.stopped_at_tamper === true;
        const sealScellees = CIBLE === 'laravel' ? d.seal.scellees : d.seal.sealed;
        constate('verdict de « Verifier »', verifIntegre ? 'chaine saine' : 'chaine rompue');
        constate('verdict de « Sceller » simule',
            sealArrete ? 'ARRET sur incoherence' : 'poursuite normale');
        verifie('la simulation n\'a rien scelle', sealScellees === 0, String(sealScellees));

        // Deuxieme mesure, par un AUTRE moyen : la sous-chaine des lignes
        // SCELLEES se tient-elle, maillon par maillon ? C'est la question que
        // « Verifier » tranche, et le SQL la tranche independamment de lui.
        const ruptures = compteEnBase(
            'WITH s AS (SELECT id, prev_hash, self_hash, '
            + 'LAG(self_hash) OVER (ORDER BY id) AS precedente '
            + 'FROM rootwarden.user_logs WHERE self_hash IS NOT NULL) '
            + 'SELECT COUNT(*) FROM s WHERE precedente IS NOT NULL AND prev_hash <> precedente');
        constate('ruptures dans la sous-chaine scellee, mesurees en SQL', String(ruptures));
        verifie('la sous-chaine scellee est coherente, maillon par maillon', ruptures === 0,
            `${ruptures} rupture(s)`);

        // Le legacy CONTREDIT cette mesure par un de ses deux points d'API. Le
        // portage doit rendre UN verdict, pas deux.
        const accord = verifIntegre === (sealArrete === false);
        verifiePortage('les deux lectures de la chaine s\'accordent', accord,
            `« Verifier » dit ${verifIntegre ? 'SAINE' : 'ROMPUE'} et « Sceller » dit `
            + `${sealArrete ? 'INCOHERENTE' : 'coherente'} — `
            + 'le bouton de scellement est donc inerte, et il crie au loup');
        if (! accord) {
            constate('consequence mesuree', 'le bouton « Sceller » ne peut sceller aucune ligne : '
                + `stopped_at_tamper verrouille l'UPDATE, et ${orphelinesAvant} orphelines restent`);
        }
    });

    // ══ 9. Les captures, aux trois largeurs ════════════════════════════════
    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            await page.screenshot({ path: `${dossier}/journal-audit-${nom}.png`, fullPage: false });
        }
        // Et l'etat que l'exploitant voit reellement apres avoir clique
        // « Verifier » : c'est celui qui porte le verdict.
        await page.setViewport({ width: 1400, height: 900 });
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await page.click(C.boutonVerifier);
        await page.waitForFunction((sl) => {
            const el = document.querySelector(sl);
            return el && ! el.classList.contains('hidden') && ! /en cours/i.test(el.textContent || '');
        }, { timeout: 30000 }, C.resultat);
        await page.screenshot({ path: `${dossier}/journal-audit-verdict-1400x900.png` });
        constate('captures deposees', dossier);
        verifie('les quatre captures sont ecrites', true);
    });

    // ══ 10. Zero erreur JavaScript sur tout le parcours ═════════════════════
    verifie('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 3).join(' | '));

} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    // Chaque etape du nettoyage dans son propre `try` : une exception ici
    // emporterait le journal entier.
    try { for (const c of contextes) await c.close(); } catch (e) { note(`INFO  fermeture des contextes : ${e.message}`); }
    try { await navigateur.close(); } catch (e) { note(`INFO  fermeture du navigateur : ${e.message}`); }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
