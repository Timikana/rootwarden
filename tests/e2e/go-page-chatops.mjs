/**
 * go-page-chatops.mjs - La page `chatops/` : mapping identifiant chat -> compte.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/chatops/index.php
 *   laravel  http://localhost:8444/chatops
 *
 * ══ CE QUE LE MODULE FAIT VRAIMENT, LU AVANT D'ECRIRE UN CLIC ═══════════════
 *
 * `chatops/` a DEUX pieces de nature differente :
 *
 *   - `index.php` + `js/main.js` : la page de configuration. Elle liste et
 *     modifie les correspondances « identifiant Slack -> compte RootWarden »,
 *     par trois routes du backend (`GET`, `POST`, `DELETE /chatops/users`).
 *     Gardee par le role 2 **ET** la permission `can_admin_portal` ;
 *   - `webhook.php` : un passthrough **PUBLIC et SANS authentification de
 *     session**, que Slack appelle. Il relaie le corps brut et les en-tetes de
 *     signature vers `/chatops/command`. Ce n'est pas une page et il n'est pas
 *     dans le menu.
 *
 * ══ LA FONCTIONNALITE EST DORMANTE, ET C'EST MESURE ════════════════════════
 *
 * Aucune variable `CHATOPS_*` dans `srv-docker.env` (seul l'exemple en porte,
 * a `false`), et **zero correspondance** dans `chatops_users`. Cote backend,
 * `/chatops/command` rend **403 « ChatOps desactive »** avant tout examen de
 * signature — fail-closed verifie en lisant `backend/routes/chatops.py:34`.
 *
 * Consequence pour cette suite : elle ne fait sortir AUCUNE requete vers Slack,
 * et il n'y a aucun trafic entrant a simuler. Les seuls effets sont deux ecritures
 * en base sur une table vide, posees puis retirees.
 *
 * ══ LA FIXTURE ═════════════════════════════════════════════════════════════
 *
 * La suite AJOUTE une correspondance par l'interface, verifie qu'elle apparait,
 * puis la SUPPRIME par l'interface. Le `finally` retire ce qui porterait
 * l'identifiant d'epreuve, et RELIT la table pour le prouver. La table part de
 * zero ligne : le nettoyage est donc borne par une valeur qui n'appartient a
 * personne, jamais par un `DELETE` de type.
 *
 * Sur le legacy, la suppression passe par un `confirm()` NATIF, qui bloque
 * Puppeteer. On l'accepte explicitement (`page.on('dialog')`) — le portage, lui,
 * doit offrir un panneau de decision EN PAGE, la boite native etant proscrite.
 *
 * Usage :
 *   cd tests/e2e && node go-page-chatops.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

/** Role 3 AVEC `can_admin_portal` : le seul qui atteint la page. */
const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
/** Role 2 SANS la permission — mesure le chemin « permission » de la garde. */
const COMPTE_ROLE = 'rw-test-admin';
const SECRET_ROLE = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';
/** Role 1 — mesure le chemin « role » de la garde. D-5 : lecture seule. */
const COMPTE_BAS = 'rw-test-user';
const SECRET_BAS = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';

/** L'identifiant d'epreuve. N'appartient a aucun espace de nommage reel. */
const CHAT_ID = 'UE2ETEST0000';
const ETIQUETTE = 'epreuve-e2e';

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion?lang=fr',
        page: '/chatops',
        etat: '[data-rw="chatops-etat"]',
        webhook: '[data-rw="chatops-webhook"]',
        plateforme: '[data-rw="chatops-plateforme"]',
        chatid: '[data-rw="chatops-chatid"]',
        utilisateur: '[data-rw="chatops-utilisateur"]',
        etiquette: '[data-rw="chatops-etiquette"]',
        ajouter: '[data-rw="chatops-ajouter"]',
        corps: '[data-rw="chatops-corps"]',
        supprimer: '[data-rw="chatops-supprimer"]',
        /** Le portage confirme EN PAGE : pas de boite native. */
        confirmerEnPage: '[data-rw="chatops-confirmer"]',
        webhookPost: '/chatops/webhook',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/chatops/index.php',
        etat: '#chatops-status',
        webhook: 'code',
        plateforme: '#m-platform',
        chatid: '#m-chatid',
        utilisateur: '#m-user',
        etiquette: '#m-label',
        ajouter: '#m-add',
        corps: '#chatops-tbody',
        supprimer: null,
        confirmerEnPage: null,
        webhookPost: '/chatops/webhook.php',
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
function verifie(l, ok, d) { note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { note(`INFO  ${l} : ${v}`); }
function verifiePortage(l, ok, d) {
    if (CIBLE === 'laravel') return verifie(l, ok, ok ? '' : d);
    constate(l, `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

/** Combien de correspondances portent l'identifiant d'epreuve ? */
function correspondancesEpreuve() {
    return compteEnBase(
        `SELECT COUNT(*) FROM rootwarden.chatops_users WHERE chat_user_id = '${CHAT_ID}'`);
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];

async function connecte(nom, secret) {
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(40000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    /* La boite native du legacy bloque Puppeteer : on l'accepte. Le portage n'en
     * pose pas — un `dialog` qui arriverait la serait donc un defaut. */
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

/** Le tableau a-t-il cesse d'annoncer « chargement » ? */
async function attendChargement(page) {
    for (let i = 0; i < 40; i += 1) {
        const pret = await page.evaluate((sel) => {
            const tb = document.querySelector(sel);
            if (! tb) return false;

            return ! /chargement|loading/i.test(tb.textContent || '');
        }, C.corps);
        if (pret) return true;
        await dors(250);
    }

    return false;
}

/** Le texte du tableau, pour y chercher l'identifiant d'epreuve. */
function texteTableau(page) {
    return page.evaluate((sel) => {
        const tb = document.querySelector(sel);

        return tb ? (tb.textContent || '').replace(/\s+/g, ' ') : '';
    }, C.corps);
}

/*
 * ══ LE CONSTAT D'ARCHIVAGE, AVANT TOUT LE RESTE ═════════════════════════════
 *
 * Une partie archivee ne doit pas laisser une suite ROUGE derriere elle : plus
 * personne ne lit les rouges. Tant que la partie est servie, ce bloc est inerte
 * et la suite se joue normalement.
 *
 * Le bloc vit AVANT le `try` et sort par `process.exit` : le `finally` de la
 * suite nettoie une fixture qui, ici, n'a jamais ete posee. L'y faire passer
 * n'ajouterait rien et melerait deux chemins.
 *
 * LES QUATRE CHEMINS SONDES EXISTENT VRAIMENT — mesure du 2026-08-25, AVANT le
 * deplacement, precisement pour que les assertions ne soient pas creuses :
 *   /chatops/            302     (redirection de connexion)
 *   /chatops/index.php   302
 *   /chatops/webhook.php 403     (« ChatOps desactive », le refus du backend)
 *   /chatops/js/main.js  200
 * Aucun ne rendait 404. Apres archivage, les quatre doivent le rendre.
 *
 * `webhook.php` merite d'etre nomme : c'est le point d'entree PUBLIC que Slack
 * appelle. Son 404 est VOULU — le portage expose `/chatops/webhook` — mais il
 * change une adresse exterieure, ce que `DEPRECIATION.md` consigne.
 */
if (CIBLE === 'legacy') {
    const archivee = await constateArchivage({
        base: BASE,
        chemin: '/chatops/',
        fichiers: ['/chatops/index.php', '/chatops/webhook.php', '/chatops/js/main.js'],
        verifie, constate,
    });
    if (archivee) {
        litEnBase('DELETE FROM rootwarden.login_attempts');
        const s = await connecte(COMPTE, SECRET);
        await verifieMenuLegacy(s.page, '/chatops', verifie);
        for (const ctx of contextes) { try { await ctx.close(); } catch {} }
        try { await navigateur.close(); } catch {}
        litEnBase('DELETE FROM rootwarden.login_attempts');
        note('');
        note(`${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
        process.exit(echecs > 0 ? 1 : 0);
    }
}

const auDepart = correspondancesEpreuve();

try {
    constate('cible', `${CIBLE} — ${BASE}`);
    verifie('la table part SANS correspondance d\'epreuve', auDepart === 0, `${auDepart}`);
    litEnBase('DELETE FROM rootwarden.login_attempts');

    const s = await connecte(COMPTE, SECRET);

    await etape('la page est servie au role 3 avec la permission', async () => {
        const r = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        constate('statut de la page', `HTTP ${r ? r.status() : 0}`);
        verifie('la page chatops est servie', r && r.status() === 200,
            `HTTP ${r ? r.status() : 0} — ${s.page.url().replace(BASE, '')}`);
    });

    await etape('l\'etat de la fonctionnalite est ANNONCE', async () => {
        await attendChargement(s.page);
        const texte = await s.page.evaluate((sel) => {
            const e = document.querySelector(sel);

            return e ? (e.textContent || '').trim() : '(absent)';
        }, C.etat);
        constate('badge d\'etat', texte);
        /* CHATOPS_ENABLED est absent de l'environnement : la page doit dire
         * « desactive ». Un badge muet laisserait croire que ca marche. */
        verifie('la page annonce que ChatOps est desactive',
            /desactiv|désactiv|disabled/i.test(texte), texte);
    });

    await etape('l\'URL du webhook est affichee', async () => {
        const texte = await s.page.evaluate((sel) => {
            for (const e of document.querySelectorAll(sel)) {
                const t = (e.textContent || '').trim();
                if (/webhook/i.test(t)) return t;
            }

            return '(aucune)';
        }, C.webhook);
        constate('URL du webhook affichee', texte);
        verifie('la page affiche l\'URL a configurer cote Slack',
            /^https?:\/\/.+webhook/i.test(texte), texte);
    });

    await etape('le choix de plateforme est une LISTE FERMEE', async () => {
        const vu = await s.page.evaluate((sel) => {
            const e = document.querySelector(sel);
            if (! e) return null;

            return {
                balise: e.tagName.toLowerCase(),
                valeurs: e.options ? Array.from(e.options).map((o) => o.value) : [],
            };
        }, C.plateforme);
        verifie('le champ plateforme existe', vu !== null);
        if (! vu) return;
        constate('plateformes proposees', `${vu.balise} — ${vu.valeurs.join(', ')}`);
        /* PAS D'ENTREE LIBRE. Une plateforme est un identifiant que le backend
         * range en base et relit ensuite : la laisser saisir librement ouvrirait
         * une valeur que rien n'attend. Le legacy fait bien une liste fermee. */
        verifie('la plateforme se choisit dans une liste, pas au clavier',
            vu.balise === 'select' && vu.valeurs.length >= 2, `${vu.balise}`);
    });

    await etape('le formulaire porte ses quatre champs et son bouton', async () => {
        const vu = await s.page.evaluate((c, u, e, a) => ({
            chatid: !! document.querySelector(c),
            utilisateur: !! document.querySelector(u),
            etiquette: !! document.querySelector(e),
            ajouter: !! document.querySelector(a),
        }), C.chatid, C.utilisateur, C.etiquette, C.ajouter);
        verifie('le champ d\'identifiant chat existe', vu.chatid);
        verifie('le choix du compte existe', vu.utilisateur);
        verifie('le champ d\'etiquette existe', vu.etiquette);
        verifie('le bouton d\'ajout existe', vu.ajouter);
    });

    await etape('un identifiant vide est refuse SANS ecrire', async () => {
        const avant = correspondancesEpreuve();
        await s.page.click(C.ajouter);
        await dors(900);
        verifie('un ajout sans identifiant n\'ecrit rien',
            correspondancesEpreuve() === avant, `${correspondancesEpreuve()} vs ${avant}`);
    });

    await etape('AJOUT : au clavier et a la souris', async () => {
        const champId = await s.page.$(C.chatid);
        await champId.click({ clickCount: 3 });
        await champId.type(CHAT_ID, { delay: 10 });
        const champEt = await s.page.$(C.etiquette);
        await champEt.click({ clickCount: 3 });
        await champEt.type(ETIQUETTE, { delay: 10 });
        await s.page.click(C.ajouter);
        await dors(1500);
        const enBase = correspondancesEpreuve();
        constate('correspondances d\'epreuve en base', `${enBase}`);
        verifie('l\'ajout ecrit UNE correspondance', enBase === 1, `${enBase}`);
        const texte = await texteTableau(s.page);
        verifie('la correspondance apparait dans le tableau',
            texte.includes(CHAT_ID), texte.slice(0, 140));
    });

    await etape('SUPPRESSION : par un clic, et elle disparait vraiment', async () => {
        if (CIBLE === 'legacy') {
            /* La boite native est acceptee par le gestionnaire de `dialog`. */
            const boutons = await s.page.$$(`${C.corps} button`);
            constate('boutons de suppression dans le tableau', `${boutons.length}`);
            if (boutons.length) await boutons[boutons.length - 1].click();
        } else {
            await s.page.click(C.supprimer);
            /* LE PORTAGE CONFIRME EN PAGE : le panneau doit s'ouvrir, et c'est
             * lui qu'on clique. Une boite native bloquerait Puppeteer et
             * recouvrirait la ligne sur laquelle on decide. */
            await s.page.waitForSelector(C.confirmerEnPage, { visible: true, timeout: 8000 });

            /* ══ LE PANNEAU OCCUPE-T-IL BIEN TOUTE LA LIGNE ? ═══════════════
             *
             * `.rw-panneau-decision` porte `display: flex`. Posee SUR le `<td>`,
             * elle ecrase `display: table-cell` : la cellule sort du modele de
             * tableau et son `colspan` est IGNORE. Le panneau s'arrete alors a
             * la largeur de la premiere colonne, le reste de la ligne restant
             * blanc — sur un ecran de 1920, 745 px utilises sur 1600.
             *
             * AUCUNE ASSERTION DOM NE L'ATTRAPE : `colSpan` vaut bien la bonne
             * valeur, c'est le RENDU qui ment. Il faut mesurer la LARGEUR
             * CALCULEE, et la comparer a celle de la ligne. Defaut releve a
             * l'image sur un portage voisin le 2026-08-26, present ici aussi.
             */
            const largeurs = await s.page.evaluate((sel) => {
                const b = document.querySelector(sel);
                if (! b) return null;
                const panneau = b.closest('.rw-panneau-decision');
                const ligne = b.closest('tr');
                if (! panneau || ! ligne) return null;

                return {
                    panneau: Math.round(panneau.getBoundingClientRect().width),
                    ligne: Math.round(ligne.getBoundingClientRect().width),
                };
            }, C.confirmerEnPage);
            if (largeurs === null) {
                constate('largeur du panneau', 'non mesurable (hors tableau)');
            } else {
                constate('largeur panneau / ligne', `${largeurs.panneau} / ${largeurs.ligne} px`);
                /* 92 % : le panneau porte des marges internes, il ne peut pas
                 * atteindre 100 %. En dessous, c'est le `colspan` qui est perdu. */
                const tient = largeurs.panneau >= largeurs.ligne * 0.92;
                verifie('le panneau de decision occupe la ligne entiere', tient,
                    tient ? `${largeurs.panneau} px sur ${largeurs.ligne}`
                        : `${largeurs.panneau} px sur ${largeurs.ligne} — le colspan est perdu, `
                          + '`display: flex` ayant ecrase `table-cell` sur la cellule');
            }

            await s.page.click(C.confirmerEnPage);
        }
        await dors(1500);
        const enBase = correspondancesEpreuve();
        verifie('la suppression retire la correspondance de la base', enBase === 0, `${enBase}`);
        const texte = await texteTableau(s.page);
        verifie('elle disparait aussi du tableau', ! texte.includes(CHAT_ID),
            texte.slice(0, 140));
    });

    await etape('la boite native, et ce que le portage doit faire a la place', async () => {
        constate('boites natives rencontrees', s.boitesNatives.length
            ? s.boitesNatives.join(' | ') : 'aucune');
        verifiePortage('aucune boite native : la decision se prend EN PAGE',
            s.boitesNatives.length === 0,
            'le legacy pose un `confirm()` natif — il recouvre la ligne sur laquelle on '
            + 'decide, ne se style pas, et BLOQUE Puppeteer');
    });

    await etape('aucune erreur JS', async () => {
        verifie('aucune erreur JS pendant la sequence', s.erreursJs.length === 0,
            s.erreursJs.join(' | ') || 'aucune');
    });

    /* ══ LE POINT D'ENTREE PUBLIC : IL DOIT REFUSER ═══════════════════════ */
    await etape('le webhook public refuse une commande non signee', async () => {
        /*
         * REQUETE FORGEE, ET LE MOTIF EST ECRIT : le webhook est un point
         * d'entree SERVEUR A SERVEUR. Il n'a aucune interface a cliquer, et
         * c'est precisement pour ca qu'il faut le mesurer — c'est le seul chemin
         * public du portage qui accepte un POST.
         *
         * On l'emet DEPUIS LA PAGE, sans jeton CSRF et sans signature Slack.
         * Deux proprietes a distinguer :
         *   - il ne doit PAS rendre 419 : un webhook qui exige un jeton CSRF ne
         *     peut pas fonctionner, Slack n'en presente aucun ;
         *   - il ne doit PAS rendre 200 : sans signature, la commande doit etre
         *     refusee. Ici ChatOps est desactive, donc le backend refuse d'emblee
         *     — c'est bien un refus, et c'est ce qu'on mesure.
         *
         * Aucun trafic ne part vers Slack : le relais va vers le backend interne.
         */
        const r = await s.page.evaluate(async (chemin) => {
            const rep = await fetch(chemin, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'text=status&user_id=UPIRATE0000',
            });

            return { statut: rep.status, texte: (await rep.text()).slice(0, 200) };
        }, C.webhookPost);
        constate('webhook sans signature', `HTTP ${r.statut} — ${r.texte.replace(/\s+/g, ' ')}`);
        verifie('le webhook n\'exige PAS de jeton CSRF', r.statut !== 419, `HTTP ${r.statut}`);
        verifie('une commande non signee est REFUSEE', r.statut !== 200,
            `HTTP ${r.statut} — ${r.texte.replace(/\s+/g, ' ').slice(0, 90)}`);
    });

    /* ══ LES DEUX CHEMINS DE LA GARDE ══════════════════════════════════════ */
    await etape('un role 2 SANS la permission est refuse', async () => {
        const r2 = await connecte(COMPTE_ROLE, SECRET_ROLE);
        const r = await r2.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const corps = (await r2.page.evaluate(() => document.body.innerText)).slice(0, 160);
        constate('role 2 sans can_admin_portal', `HTTP ${r ? r.status() : 0} — ${corps.replace(/\s+/g, ' ').slice(0, 70)}`);
        verifie('le role seul ne suffit pas : la permission est exigee',
            (r && r.status() === 403) || /refus|interdit|forbidden/i.test(corps),
            `HTTP ${r ? r.status() : 0}`);
    });

    await etape('un role 1 est refuse', async () => {
        const r1 = await connecte(COMPTE_BAS, SECRET_BAS);
        const r = await r1.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const corps = (await r1.page.evaluate(() => document.body.innerText)).slice(0, 160);
        constate('role 1', `HTTP ${r ? r.status() : 0} — ${corps.replace(/\s+/g, ' ').slice(0, 70)}`);
        verifie('un compte de role 1 est refuse',
            (r && r.status() === 403) || /refus|interdit|forbidden/i.test(corps),
            `HTTP ${r ? r.status() : 0}`);
    });
} catch (e) {
    verifie('deroulement de la suite', false, String(e).split('\n')[0]);
} finally {
    for (const ctx of contextes) { try { await ctx.close(); } catch {} }
    try { await navigateur.close(); } catch {}
    /*
     * NETTOYAGE BORNE PAR L'IDENTIFIANT D'EPREUVE, jamais par type : un
     * `DELETE FROM chatops_users` emporterait des correspondances legitimes le
     * jour ou la fonctionnalite sera employee. Etat RELU pour etre prouve.
     */
    try {
        litEnBase(`DELETE FROM rootwarden.chatops_users WHERE chat_user_id = '${CHAT_ID}'`);
        litEnBase('DELETE FROM rootwarden.login_attempts');
    } catch (e) {
        note(`FAIL  nettoyage de la fixture  — ${String(e.message || e).split('\n')[0]}`);
        echecs++;
    }
    const reste = correspondancesEpreuve();
    verifie('aucune correspondance d\'epreuve ne subsiste', reste === 0, `${reste}`);
}

note('');
note(`${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — ${etapes} etapes, cible ${CIBLE}`);
process.exit(echecs === 0 ? 0 : 1);
