/**
 * go-adm-comptes.mjs - Sous-lot D3 de `adm/` : comptes, roles, mots de passe.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/adm/admin_page.php   (onglet Utilisateurs)
 *   laravel  http://localhost:8444/comptes               (pas encore porte)
 *
 * ══ POURQUOI CETTE SUITE NE TOUCHE AUCUN COMPTE EXISTANT ═══════════════════
 *
 * D3 ecrit dans `users` : mot de passe, `active`, `sudo`, role. Or treize suites
 * du LOT dependent de `rw-test-admin`, et `rw-test-user` est marque D-5. Changer
 * le mot de passe d'un compte de test casserait toutes les autres suites, en
 * silence et pour de bon — la suite ne saurait meme pas dire pourquoi.
 *
 * Elle CREE donc son propre compte, par de vrais clics sur le formulaire de la
 * page, et le retire dans le `finally`, BORNE PAR UN DELTA d'identifiant. Un
 * nettoyage par nom ou par role en retirerait plus qu'il n'en a pose.
 *
 * `sudo` n'est PAS bascule. `users.sudo = 1` est la precondition du repli
 * `NOPASSWD: ALL` de `ssh/` (K4), et le plan mesure qu'AUCUN compte actif de
 * role 1 ne le porte aujourd'hui. Poser ce drapeau, meme le temps d'une
 * execution, rendrait ce trou exploitable — et un `finally` qui ne s'execute pas
 * le laisserait pose.
 *
 * ══ CE QUE LA LECTURE A ETABLI, ET QUE LES CLICS MESURENT ══════════════════
 *
 * 1. LA POLITIQUE DE MOT DE PASSE EST CONTOURNEE PAR LE SEUL CHEMIN QUI FIXE LE
 *    MOT DE PASSE D'AUTRUI. Tous les autres chemins appellent
 *    `passwordPolicyValidateAll` ; l'administrateur, non.
 *
 *      exigence            | libre-service        | administrateur
 *      longueur            | >= 15                | >= 8
 *      classes de car.     | 4 exigees            | aucune
 *      non reutilise       | oui (historique)     | non
 *      absent de HIBP      | oui                  | non
 *      ecrit l'historique  | oui                  | non
 *
 *    Mesure des sources : `profile.php:174-184` contre
 *    `manage_roles.php:65-88`, et `validateInputUsers(…, 'password')`
 *    (`manage_roles.php:48`) n'exige que `strlen >= 8`.
 *
 * 2. LE MOT DE PASSE GENERE EST RENDU EN CLAIR DANS LE HTML
 *    (`manage_roles.php:93`). Il finit dans l'historique du navigateur et dans
 *    tout cache intermediaire.
 *
 * 3. LE COUT DU HACHAGE — et ici LA MESURE DEDOUANE, ce qui se dit aussi
 *    nettement qu'une accusation. `manage_roles.php:85` emploie
 *    `PASSWORD_DEFAULT` la ou tout le reste emploie `BCRYPT_COST`. Mesure sur ce
 *    PHP : les deux rendent `$2y$12$`. Le hachage n'est donc PAS plus faible
 *    aujourd'hui. Ce qui reste vrai : `BCRYPT_COST` se lit dans une variable
 *    d'environnement (`password_policy.php:28`), donc l'exploitant peut la
 *    relever — et ce chemin-la ne suivrait pas.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-adm-comptes
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
const COMPTE_ROLE = 'rw-test-admin';
const SECRET_ROLE = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';
const COMPTE_BAS = 'rw-test-user';
const SECRET_BAS = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';

/** Le compte d'epreuve. Son nom le NOMME : rien ne s'y trompe. */
const EPREUVE = 'epreuve-e2e-d3';
/**
 * Un mot de passe que la POLITIQUE refuse sur trois chefs — moins de 15
 * caracteres, aucune majuscule, aucun symbole — et que le chemin administrateur
 * accepte (il n'exige que huit caracteres).
 */
const MDP_REFUSE_PAR_LA_POLITIQUE = 'password123';

const DOSSIER_CAPTURES = new URL('./screenshots/adm', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/comptes',
        champNom: '[data-rw="compte-nom"]',
        champMdp: '[data-rw="compte-mdp"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/adm/admin_page.php',
        // LE champ du formulaire de creation, pas « le premier `name` de la
        // page » : `admin_page.php` en porte QUATRE (creation de compte, et
        // trois cotes serveurs). On vise par le formulaire qui porte
        // `action=add_user`.
        champNom: 'form:has(input[name="action"][value="add_user"]) input[name="name"]',
        champMdp: 'input[name="new_password"]',
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

let borne = 0;
function idEpreuve() {
    const v = litEnBase(`SELECT id FROM rootwarden.users WHERE name = '${EPREUVE}'`);

    return v.length ? parseInt(v[0], 10) : 0;
}
function hachageEpreuve() {
    const v = litEnBase(`SELECT IFNULL(password,'(nul)') FROM rootwarden.users WHERE name = '${EPREUVE}'`);

    return v.length ? v[0] : '';
}
function historiqueDe(id) {
    return id > 0 ? compteEnBase(`SELECT COUNT(*) FROM rootwarden.password_history WHERE user_id = ${id}`) : 0;
}
/** Ne retire QUE ce que la suite a pose. Borne par un DELTA d'identifiant. */
function retireLEpreuve() {
    if (borne <= 0) return;
    litEnBase(`DELETE FROM rootwarden.password_history WHERE user_id > ${borne}`);
    litEnBase(`DELETE FROM rootwarden.permissions WHERE user_id > ${borne}`);
    litEnBase(`DELETE FROM rootwarden.user_logs WHERE user_id > ${borne}`);
    litEnBase(`DELETE FROM rootwarden.users WHERE id > ${borne} AND name = '${EPREUVE}'`);
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(40000);
    const erreursJs = [];
    // On garde la PILE, pas seulement le message : « SyntaxError » sans source
    // ne se diagnostique pas, et deviner a deja coute un tour.
    page.on('pageerror', (e) => erreursJs.push(
        String(e.message || e).split('\n')[0]
        + (e.stack ? ' @ ' + String(e.stack).split('\n').slice(1, 3).join(' / ') : '')));
    page.on('dialog', async (d) => { try { await d.accept(); } catch { /* deja fermee */ } });

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

    return { ctx, page, erreursJs };
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

/** Soumet en remontant du CHAMP a son `form` — jamais « le premier submit ». */
async function soumetDepuis(page, selecteurChamp, nomDuBouton) {
    const bouton = await page.evaluateHandle((s, n) => {
        const champ = document.querySelector(s);
        const form = champ ? champ.closest('form') : null;
        if (! form) return null;

        return n ? form.querySelector(`button[name="${n}"]`) : form.querySelector('button[type="submit"]');
    }, selecteurChamp, nomDuBouton || null);
    const el = bouton.asElement();
    if (! el) throw new Error(`aucun bouton dans le form de ${selecteurChamp}`);
    const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 25000 });
    await el.click();
    try { await nav; } catch {}
}

const session = {};
try {
    retireLEpreuve();
    borne = compteEnBase('SELECT IFNULL(MAX(id), 0) FROM rootwarden.users');
    constate('borne d\'identifiant avant l\'epreuve', String(borne));

    // ══ 1. La garde, aux trois roles ═══════════════════════════════════════
    await etape('garde role 1', async () => {
        const s = await connecte(COMPTE_BAS, SECRET_BAS);
        const rep = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('role 1 refuse sur la page des comptes', rep.status() === 403, `statut ${rep.status()}`);
        await s.ctx.close();
    });
    await dors((resteFenetre() + 1) * 1000);

    await etape('garde role 2 sans la permission', async () => {
        const s = await connecte(COMPTE_ROLE, SECRET_ROLE);
        const rep = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('role 2 sans can_admin_portal refuse', rep.status() === 403, `statut ${rep.status()}`);
        await s.ctx.close();
    });
    await dors((resteFenetre() + 1) * 1000);

    // ══ 2. Le compte d'epreuve, cree par de VRAIS clics ════════════════════
    session.s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = session.s;

    await etape('ouverture', async () => {
        const rep = await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('le role 3 atteint la page des comptes', rep.status() === 200, `statut ${rep.status()}`);
    });

    await etape('creation du compte d\'epreuve', async () => {
        // UN BLOC REPLIE NE RECOIT PAS LES FRAPPES : le formulaire vit dans un
        // `<details>` ferme (`manage_users.php:297`). `page.$()` le trouve,
        // `type()` ne leve pas — et rien ne se passe. Deplier D'ABORD, et
        // l'ASSERTER avant de frapper.
        await page.evaluate((sel) => {
            const champ = document.querySelector(sel);
            const bloc = champ ? champ.closest('details') : null;
            if (bloc) bloc.open = true;
        }, C.champNom);
        const visible = await page.evaluate((sel) => {
            const e = document.querySelector(sel);

            return e ? e.getClientRects().length > 0 : false;
        }, C.champNom);
        verifie('le formulaire de creation est deplie avant la frappe', visible, C.champNom);
        if (! visible) return;

        const champ = await page.$(C.champNom);
        if (! champ) throw new Error('champ de nom absent');
        await champ.click({ clickCount: 3 });
        await champ.type(EPREUVE, { delay: 8 });
        const saisi = await page.$eval(C.champNom, (e) => e.value);
        verifie('le nom est bien saisi dans le champ', saisi === EPREUVE, `saisi « ${saisi} »`);
        await soumetDepuis(page, C.champNom);

        const id = idEpreuve();
        constate('identifiant du compte d\'epreuve', String(id));
        verifie('le compte d\'epreuve est cree', id > borne, `id ${id}, borne ${borne}`);
    });

    const idEpr = idEpreuve();

    // ══ 3. La politique est-elle appliquee au chemin administrateur ? ══════
    await etape('reinitialisation avec un mot de passe que la politique refuse', async () => {
        if (idEpr <= 0) throw new Error('pas de compte d\'epreuve');
        const avantHash = hachageEpreuve();
        const avantHisto = historiqueDe(idEpr);

        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        // Le champ de LA LIGNE du compte d'epreuve, pas « le premier de la page » :
        // la page en porte un par compte.
        const champ = await page.evaluateHandle((nom, sel) => {
            const ligne = Array.from(document.querySelectorAll('tr'))
                .find((tr) => (tr.textContent || '').includes(nom));

            return ligne ? ligne.querySelector(sel) : null;
        }, EPREUVE, C.champMdp);
        const el = champ.asElement();
        verifie('la ligne du compte d\'epreuve porte un champ de mot de passe', !! el);
        if (! el) return;

        await el.click({ clickCount: 3 });
        await el.type(MDP_REFUSE_PAR_LA_POLITIQUE, { delay: 8 });
        const bouton = await el.evaluateHandle((champElem) => {
            const form = champElem.closest('form');

            return form ? form.querySelector('button[name="change_password"], button[type="submit"]') : null;
        });
        const b = bouton.asElement();
        if (! b) throw new Error('aucun bouton de reinitialisation dans le form');
        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 25000 });
        await b.click();
        try { await nav; } catch {}

        const apresHash = hachageEpreuve();
        const apresHisto = historiqueDe(idEpr);
        constate('le hachage a-t-il change ?', avantHash === apresHash ? 'non' : 'oui');
        constate('prefixe du hachage ecrit', apresHash.slice(0, 7) || '(vide)');
        constate('lignes d\'historique avant / apres', `${avantHisto} / ${apresHisto}`);

        // Le legacy ACCEPTE : c'est le defaut. Le portage doit REFUSER.
        verifiePortage('un mot de passe refuse par la politique est refuse a l\'administrateur aussi',
            avantHash === apresHash,
            `« ${MDP_REFUSE_PAR_LA_POLITIQUE} » : 11 caracteres, sans majuscule ni symbole — `
            + 'refuse a l\'utilisateur pour lui-meme, accepte a l\'administrateur pour autrui');
        verifiePortage('le changement est inscrit dans password_history',
            apresHisto > avantHisto,
            `${avantHisto} ligne(s) avant, ${apresHisto} apres — l'historique garde un trou, `
            + 'donc le mot de passe pose par un administrateur peut etre repose aussitot');
        // LA MESURE DEDOUANE sur le cout : `PASSWORD_DEFAULT` rend `$2y$12$`,
        // comme `BCRYPT_COST`. On le CONSTATE, on ne l'accuse pas.
        verifie('le hachage ecrit est un bcrypt', /^\$2y\$/.test(apresHash), apresHash.slice(0, 7));
    });

    // ══ 4. Le mot de passe GENERE s'affiche-t-il en clair ? ════════════════
    await etape('generation d\'un mot de passe, champ laisse vide', async () => {
        if (idEpr <= 0) throw new Error('pas de compte d\'epreuve');
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const champ = await page.evaluateHandle((nom, sel) => {
            const ligne = Array.from(document.querySelectorAll('tr'))
                .find((tr) => (tr.textContent || '').includes(nom));

            return ligne ? ligne.querySelector(sel) : null;
        }, EPREUVE, C.champMdp);
        const el = champ.asElement();
        if (! el) throw new Error('champ de mot de passe introuvable');

        const bouton = await el.evaluateHandle((c) => {
            const form = c.closest('form');

            return form ? form.querySelector('button[name="change_password"], button[type="submit"]') : null;
        });
        const b = bouton.asElement();
        if (! b) throw new Error('aucun bouton de reinitialisation');
        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 25000 });
        await b.click();
        try { await nav; } catch {}

        // Un mot de passe genere qui s'affiche est une chaine longue et melangee
        // dans le HTML rendu. On mesure la PROPRIETE, pas un libelle : un bloc
        // `<strong>` dont le contenu ressemble a un secret.
        const enClair = await page.evaluate(() => {
            const forts = Array.from(document.querySelectorAll('strong, code'))
                .map((e) => (e.textContent || '').trim())
                .filter((t) => t.length >= 10 && /[a-z]/.test(t) && /[A-Z0-9]/.test(t) && ! /\s/.test(t));

            return forts.length ? forts[0] : null;
        });
        constate('chaine ressemblant a un secret dans le HTML', enClair ? `${enClair.length} caracteres` : '(aucune)');
        verifiePortage('le mot de passe genere n\'apparait pas dans le HTML', ! enClair,
            'le legacy le rend en clair dans la page — il finit dans l\'historique du navigateur '
            + 'et dans tout cache intermediaire');
    });

    // ══ 5. Les captures ════════════════════════════════════════════════════
    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            await page.screenshot({ path: `${dossier}/comptes-${nom}.png` });
        }
        constate('captures deposees', dossier);
        verifie('les trois captures sont ecrites', true);
    });

    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ') : '(aucune)');
    // Le legacy en porte ; le portage ne doit pas.
    verifiePortage('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 2).join(' | '));

} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    try {
        retireLEpreuve();
        const reste = compteEnBase(`SELECT COUNT(*) FROM rootwarden.users WHERE name = '${EPREUVE}'`);
        verifie('le compte d\'epreuve est retire', reste === 0, `${reste} restant(s)`);
    } catch (e) { note(`FAIL  retrait du compte d'epreuve : ${e.message}`); echecs += 1; }
    try {
        // Preuve que rien n'a debordé sur les comptes de test.
        const sudo = compteEnBase("SELECT COUNT(*) FROM rootwarden.users WHERE name LIKE 'rw-test-%' AND sudo = 1");
        verifie('aucun compte de test ne porte le drapeau sudo', sudo === 0, `${sudo}`);
        const inactifs = compteEnBase("SELECT COUNT(*) FROM rootwarden.users WHERE name LIKE 'rw-test-%' AND active <> 1");
        verifie('les trois comptes de test sont toujours actifs', inactifs === 0, `${inactifs} inactif(s)`);
    } catch (e) { note(`FAIL  controle des comptes de test : ${e.message}`); echecs += 1; }
    try { for (const c of contextes) await c.close(); } catch (e) { note(`INFO  fermeture des contextes : ${e.message}`); }
    try { await navigateur.close(); } catch (e) { note(`INFO  fermeture du navigateur : ${e.message}`); }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
