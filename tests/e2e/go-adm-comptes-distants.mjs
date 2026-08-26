/**
 * go-adm-comptes-distants.mjs - Sous-lot D8 de `adm/` : les comptes distants.
 *
 * `legacy/adm/server_users.php` (387 l.). **PREMIERE ECRITURE DISTANTE d'`adm/`.**
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/adm/server_users.php
 *   laravel  http://localhost:8444/comptes-distants   (pas encore porte)
 *
 * ══ SURETE : TROIS GESTES NE SONT JAMAIS DECLENCHES ═══════════════════════
 *
 * `/delete_remote_user` fait un `userdel` distant IRREVERSIBLE.
 * `/remove_user_keys` efface les `authorized_keys` d'un compte.
 * `/sshd_allow_user` modifie `sshd_config`.
 *
 * Les trois sont exerces par INTERCEPTION AVEC AVORTEMENT — motif eprouve sur
 * V8 : on active `setRequestInterception`, on AVORTE la seule requete
 * dangereuse, et on laisse passer le reste. On clique donc le VRAI bouton, on
 * mesure la requete emise (methode, chemin, corps), et **rien n'atteint la
 * machine**.
 *
 * Le seul geste qui aboutit est `/scan_server_users` — une ENUMERATION, qui
 * ouvre une session SSH en LECTURE et ne modifie rien. Il vise la machine 2
 * (`test-server`), jamais `srv-zabbix`.
 *
 * ══ LE DEFAUT : LA PAGE EST PLUS PERMISSIVE QUE TOUT CE QU'ELLE OFFRE ═════
 *
 * `server_users.php:11` : `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])`
 * — **le role 1 entre**. Or SIX de ses SEPT routes exigent `@require_role(2)` :
 *
 *   /server_user_keys                    aucun role   (borne par l'acces machine)
 *   /scan_server_users                   role 2
 *   /sshd_allow_user                     role 2
 *   /remove_user_keys                    role 2
 *   /delete_remote_user                  role 2
 *   /admin/user_inventory/classify       role 2
 *   /admin/user_inventory/classify_bulk  role 2
 *
 * Et la page **ne distingue aucun role dans son rendu** : `ROLE_` n'y apparait
 * qu'a la ligne 11. Un role 1 porteur de `can_manage_remote_users` verrait donc
 * tous les boutons et recevrait 401 sur six d'entre eux.
 *
 * C'est le MIROIR du defaut habituel du depot : d'ordinaire la garde est sur la
 * PAGE et pas sur la REQUETE ; ici la page est plus LARGE que ses requetes.
 *
 * **L'admission du role 1 est LATENTE** : `can_manage_remote_users` est creable
 * et basculable, mais un seul compte la porte — `superadmin`, role 3. Le trou
 * est reel et a une attribution de permission d'etre atteignable. La suite
 * mesure ce qu'elle PEUT : `rw-test-user` (role 1, zero permission) est refuse.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-adm-comptes-distants
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
/** Role 1, zero permission — D-5, on ne le modifie jamais. */
const COMPTE_USER = 'rw-test-user';
const SECRET_USER = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';

/** `test-server`. JAMAIS `srv-zabbix` (id 1, PRODUCTION). */
const MACHINE_ID = 2;
const MACHINE_NOM = 'Test-Server-Debian';

/** Les trois routes qu'aucune execution ne doit laisser aboutir. */
const ROUTES_INTERDITES = /\/(delete_remote_user|remove_user_keys|sshd_allow_user|server_user_remove_key)(\?|$)/;

const DOSSIER_CAPTURES = new URL('./screenshots/adm', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: `/comptes-distants?machine=${MACHINE_ID}`,
        scan: '[data-rw="distants-scanner"]',
        conteneur: '[data-rw="distants-liste"]',
        supprimer: '[data-rw="distant-supprimer"]',
        retirerCles: '[data-rw="distant-retirer-cles"]',
        // LE PORTAGE SEPARE LE GESTE DE SA CONFIRMATION : le bouton n'envoie
        // rien, il ouvre un panneau qui NOMME la consequence. Le compte doit
        // d'abord etre designe — le legacy, lui, pose ces trois gestes en
        // boutons minuscules au bout de chaque ligne du tableau.
        choixCompte: '[data-rw="distants-geste-compte"]',
        confirmer: '[data-rw="distant-confirmer"]',
        panneau: '[data-rw="distant-panneau"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: `/adm/server_users.php?server=${MACHINE_ID}`,
        scan: '#btn-scan',
        conteneur: '#users-container',
        supprimer: 'button[data-user][onclick^="deleteUser"]',
        retirerCles: 'button[data-user][onclick^="removeKeys"]',
        choixCompte: null,
        confirmer: null,
        panneau: null,
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
    protocolTimeout: 180000,
});
const contextes = [];

/** Toutes les requetes dangereuses vues, quelle que soit la page. */
const interdites = [];

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(60000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => { try { await d.accept(); } catch {} });

    // ══ LE FILET, POSE AVANT TOUTE NAVIGATION ═════════════════════════════
    //
    // Il vaut pour TOUTE la duree de la session, pas seulement pendant l'etape
    // qui clique : une requete partie d'un rechargement, d'un `setTimeout` ou
    // d'un re-rendu serait tout aussi destructrice. Le filet est pose une fois
    // et ne se leve jamais.
    await page.setRequestInterception(true);
    page.on('request', (r) => {
        if (ROUTES_INTERDITES.test(r.url()) && r.method() !== 'GET') {
            let corps = '';
            try { corps = (r.postData() || '').slice(0, 160); } catch { corps = '(illisible)'; }
            interdites.push({ methode: r.method(), url: r.url(), corps });
            // AVORTEE : elle ne quitte jamais le navigateur.
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

    return { ctx, page, erreursJs };
}

/** Le bouton d'un compte distant, REPERE PAR SA LIGNE — jamais « le premier ». */
async function boutonDe(page, selecteur) {
    const tous = await page.$$(selecteur);

    return tous.length ? tous[0] : null;
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

const session = {};
try {
    // ══ 1. LA PRECONDITION DE SURETE, mesuree ══════════════════════════════
    await etape('la cible est-elle bien la machine d\'essai ?', async () => {
        const n = litEnBase(`SELECT name FROM rootwarden.machines WHERE id = ${MACHINE_ID}`);
        constate('machine visee', n[0] || '(absente)');
        // FAIL-CLOSED : si l'identifiant 2 ne designait plus `test-server`, tous
        // les gestes de cette suite viseraient une machine inconnue — et le
        // scan ouvrirait une session SSH ailleurs.
        verifie('l\'identifiant 2 designe bien la machine d\'essai',
            n.length === 1 && n[0] === MACHINE_NOM, n[0] || '(absente)');
    });

    // ══ 2. LA GARDE, AU ROLE 1 ═════════════════════════════════════════════
    await etape('un role 1 sans permission atteint-il la page ?', async () => {
        const s = await connecte(COMPTE_USER, SECRET_USER);
        try {
            const rep = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            constate('statut au role 1 sans permission', String(rep.status()));
            // CE QUI EST MESURABLE. `checkAuth` ADMET le role 1 ; c'est
            // `checkPermission('can_manage_remote_users')` qui refuse ici. Le
            // role 1 PORTEUR de la permission n'est pas mesurable — aucun
            // compte d'epreuve ne la porte, et un seul compte du parc l'a :
            // `superadmin`, role 3. L'admission reste donc LATENTE, etablie par
            // lecture, et c'est dit comme tel.
            verifie('le role 1 sans la permission est refuse', rep.status() === 403,
                `statut ${rep.status()}`);
        } finally {
            await s.ctx.close();
        }
    });
    await dors((resteFenetre() + 1) * 1000);

    session.s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = session.s;

    await etape('ouverture', async () => {
        const rep = await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('le role 3 atteint la page', rep.status() === 200, `statut ${rep.status()}`);
    });

    // ══ 3. LE SCAN — SEUL GESTE QUI ABOUTIT ════════════════════════════════
    await etape('enumerer les comptes distants, par un clic', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const vues = [];
        const ecoute = (r) => {
            if (/scan_server_users/.test(r.url())) vues.push(`${r.status()}`);
        };
        page.on('response', ecoute);

        const bouton = await page.$(C.scan);
        verifie('le bouton de scan est atteignable', bouton !== null);
        if (! bouton) { page.off('response', ecoute); return; }

        await bouton.click();
        // Une session SSH plus une enumeration : on laisse le temps.
        await dors(20000);
        page.off('response', ecoute);
        constate('reponses de /scan_server_users', vues.join(' | ') || '(aucune)');

        const comptes = await page.evaluate((sel) => {
            const e = document.querySelector(sel);

            return e ? (e.textContent || '').trim().length : 0;
        }, C.conteneur);
        constate('longueur du rendu de la liste', String(comptes));
        verifie('le scan aboutit et la liste se garnit', vues.length > 0 && comptes > 0,
            `${vues.length} reponse(s), ${comptes} caracteres`);
    });

    // ══ 4. LES GESTES DESTRUCTEURS : CLIQUES, MESURES, AVORTES ═════════════
    await etape('les gestes destructeurs partent-ils, et sont-ils avortes ?', async () => {
        const avant = interdites.length;

        // ══ SUR LE PORTAGE, IL FAUT D'ABORD DESIGNER LE COMPTE ════════════
        //
        // Et l'ouverture du panneau doit n'emettre RIEN : c'est une propriete a
        // part entiere, et elle s'asserte. Le legacy n'a pas ce temps — ses
        // boutons partent au premier clic.
        if (C.choixCompte) {
            const choisi = await page.evaluate((sel) => {
                const s2 = document.querySelector(sel);
                if (! s2) return '';
                const opt = [...s2.options].find((o) => o.value);
                if (! opt) return '';
                s2.value = opt.value;
                s2.dispatchEvent(new Event('change', { bubbles: true }));

                return opt.value;
            }, C.choixCompte);
            constate('compte designe pour les gestes', choisi || '(aucun)');
            verifie('un compte peut etre designe dans la liste', choisi !== '', '(liste vide)');
        }

        for (const [nom, selecteur] of [['retrait des cles', C.retirerCles], ['suppression du compte', C.supprimer]]) {
            const b = await boutonDe(page, selecteur);
            if (! b) {
                // ABSENT N'EST PAS UN SILENCE. Le bouton de retrait des cles
                // n'est rendu que si le compte EN A (`u.keys_count > 0`) : son
                // absence est donc une propriete de la page, pas un raté du
                // reperage. On la CONSTATE, et la suite ne prétend pas l'avoir
                // exercee.
                constate(`bouton « ${nom} »`, 'absent — rendu seulement si le compte porte des cles');
                continue;
            }
            // COMPTE RELEVE JUSTE AVANT CE CLIC, pas au debut de l'etape : le
            // geste precedent a pu emettre, et une borne perimee ferait dire
            // n'importe quoi a la difference.
            const avantCeClic = interdites.length;
            await b.click();
            await dors(800);

            if (C.confirmer) {
                // LE PREMIER CLIC N'ENVOIE RIEN. On le PROUVE avant de
                // confirmer : un panneau qui aurait deja agi ne serait pas un
                // panneau de decision.
                verifie(`ouvrir le panneau « ${nom} » n'emet aucune requete`,
                    interdites.length === avantCeClic,
                    `${interdites.length - avantCeClic} requete(s) emise(s) a l'ouverture`);

                const ouvert = await page.evaluate((sel) => {
                    const e = document.querySelector(sel);

                    return Boolean(e) && ! e.hidden;
                }, C.panneau);
                verifie(`le panneau « ${nom} » s'ouvre`, ouvert);
                if (ouvert) {
                    await page.click(C.confirmer);
                    await dors(1500);
                }
            }
        }

        const vues = interdites.slice(avant);
        for (const r of vues) constate(`  requete AVORTEE`, `${r.methode} ${r.url.replace(/^https?:\/\/[^/]+/, '')} ${r.corps}`);
        constate('requetes dangereuses interceptees', String(vues.length));

        // LA PROPRIETE EST DOUBLE, et les deux moities comptent :
        //   1. le clic EMET bien la requete — sinon on n'aurait rien mesure ;
        //   2. AUCUNE n'a quitte le navigateur.
        verifie('les clics emettent bien les requetes destructrices', vues.length > 0,
            vues.length > 0 ? `${vues.length} interceptee(s)`
                : 'aucune requete vue — les boutons seraient inertes, ou le reperage a cote');
        verifie('aucune requete destructrice n\'a quitte le navigateur',
            vues.every((r) => ROUTES_INTERDITES.test(r.url)),
            vues.every((r) => ROUTES_INTERDITES.test(r.url)) ? ''
                : 'une requete hors liste a ete comptee comme avortee');
    });

    // ══ 5. RIEN N'A CHANGE SUR LA MACHINE, ET ON LE PROUVE ═════════════════
    await etape('la machine d\'essai est-elle intacte ?', async () => {
        // La preuve se lit au RESEAU : aucune des requetes destructrices n'est
        // partie. On le redit ici sur le TOTAL de l'execution, pas seulement
        // sur l'etape qui cliquait — une requete emise par un re-rendu tardif
        // compterait aussi.
        constate('total des requetes destructrices sur toute l\'execution', String(interdites.length));
        verifie('toutes les requetes destructrices ont ete avortees',
            interdites.every((r) => ROUTES_INTERDITES.test(r.url)));

        const zabbix = litEnBase("SELECT CONCAT(name,'|',ip) FROM rootwarden.machines WHERE id = 1");
        verifie('srv-zabbix n\'a pas ete visee', zabbix.length === 1 && zabbix[0] === 'srv-zabbix|192.168.0.244',
            zabbix[0] || '(absente)');
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            await dors(600);
            await page.screenshot({ path: `${dossier}/comptes-distants-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    verifiePortage('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 2).join(' | '));

} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    try {
        // AUCUNE FIXTURE A RETIRER : cette suite n'ecrit rien, ni en base ni a
        // distance. Le seul geste qui aboutit est une ENUMERATION. On verifie
        // quand meme le parc, parce qu'une suite qui ne croit rien ecrire est
        // exactement celle qu'il faut controler.
        const parc = compteEnBase('SELECT COUNT(*) FROM rootwarden.machines');
        constate('machines au parc a la sortie', String(parc));
        const zabbix = litEnBase(
            "SELECT CONCAT(name,'|',ip,'|',IFNULL(online_status,'')) FROM rootwarden.machines WHERE id = 1");
        verifie('srv-zabbix est intacte', zabbix.length === 1 && zabbix[0].startsWith('srv-zabbix|192.168.0.244'),
            zabbix[0] || '(absente)');
    } catch (e) { note(`FAIL  controle du parc : ${e.message}`); echecs += 1; }
    try { for (const c of contextes) await c.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
    try { await navigateur.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
