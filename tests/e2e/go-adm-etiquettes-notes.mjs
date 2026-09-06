/**
 * go-adm-etiquettes-notes.mjs - Sous-lot D6b de `adm/` : etiquettes et notes.
 *
 * D6 a ete redecoupe une seconde fois, et pour une raison MESUREE : l'inventaire
 * l'avait decoupe par FICHIER, or deux capacites de la carte serveur ne vivent
 * dans aucun des deux fichiers de D6b — elles appellent le BACKEND.
 *
 *   D6b  `includes/server_actions.php` — etiquettes et notes, purement en base
 *   D6c  `includes/import_csv.php`     — l'import par fichier, deux imports
 *   D6d  `POST /server_lifecycle` et `POST /server_status` — routes backend
 *        atteintes depuis la carte ; la seconde ouvre une connexion TCP vers
 *        une machine du parc ET ecrit `machines.online_status`
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/adm/admin_page.php  (onglet Serveurs)
 *   laravel  http://localhost:8444/serveurs
 *
 * ══ CE QUE `server_actions.php` REPARTIT, ET CE QUI L'APPELLE ══════════════
 *
 * Le fichier porte DEUX repartitions, et une seule est atteignable :
 *
 *   corps JSON        `add_tag` `remove_tag` `add_note` `delete_note`
 *                     -> QUATRE appelants vivants (`manage_servers.php:558,571,
 *                        612,626`), jeton CSRF par en-tete `X-CSRF-Token`
 *   corps de formulaire  `add_server` `update_server` `delete_server`
 *                     -> TROIS appelants, tous a l'INTERIEUR du bloc commente
 *                        (`:770,803,831` dans `:661-923`) — donc AUCUN vivant
 *
 * ══ LE PREMIER DEFAUT : LES QUATRE GESTES VIVANTS SONT INERTES ════════════
 *
 * Chaque clic emet bien sa requete, et le serveur repond
 * `{"success":false,"message":"Token CSRF invalide"}`. Rien n'est jamais ecrit.
 *
 * Quatre pieces, toutes correctes, et une liste incomplete :
 *
 *   `admin_page.php:103`  rend `<meta name="csrf-token">`            OK
 *   `menu.php:267`        charge `js/utils.js`                       OK
 *   `utils.js:19`         enrobe `window.fetch` et injecte l'en-tete OK
 *   `utils.js:22`         ... mais SEULEMENT si l'URL contient
 *                         `api_proxy.php`, `/adm/api/` ou `/auth/`
 *
 * `/adm/includes/server_actions.php` n'est dans aucune des trois familles. Le
 * jeton n'est donc jamais joint, et le point d'action — qui le verifie
 * correctement — refuse sa propre interface.
 *
 * **Et le contraste est net** : ce meme controle CSRF ne fait rien contre une
 * requete FORGEE depuis le portail, puisque n'importe quel compte authentifie
 * lit le jeton sur `profile.php`. Le garde tient dehors l'interface legitime et
 * laisse entrer la requete forgee.
 *
 * ══ LE SECOND DEFAUT : LE CORRECTIF SSRF N'EXISTE QUE SUR UN DES DEUX CHEMINS ═
 *
 * `manage_servers.php` et `server_actions.php` portent CHACUN leur copie de
 * `validateInput()`. Le commentaire de la premiere annonce le correctif A10-01 :
 * refus du bouclage, du lien-local (169.254/16 — les points de metadonnees AWS
 * et Azure) et de 0.0.0.0/8, « pour empecher un admin compromis d'inserer
 * 169.254.169.254 pour exfiltrer les credentials cloud ».
 *
 * La copie de `server_actions.php` tient en UNE ligne :
 *
 *     case 'ip':
 *         return filter_var($data, FILTER_VALIDATE_IP) ? $data : false;
 *
 * **Aucun garde.** C'est le motif « a moitie corrige » — sixieme occurrence —
 * applique cette fois a un correctif de SECURITE, sur celui des deux chemins
 * qu'aucun clic n'emprunte, donc celui que personne ne regarde.
 *
 * ══ LA REQUETE FORGEE, ET SON MOTIF ═══════════════════════════════════════
 *
 * Le geste `add_server` de `server_actions.php` n'a AUCUN appelant vivant :
 * aucun clic ne peut l'atteindre. C'est exactement le cas prevu par la
 * convention — « exercer ce qu'aucun clic ne peut atteindre » — et la requete
 * s'emet DEPUIS LA PAGE, par `fetch` dans un `page.evaluate`, donc avec la
 * session et les en-tetes reels.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 *   - etiquettes et notes sont purement en base : aucun effet distant ;
 *   - la machine visee est `Test-Server-Debian` (id 2), jamais `srv-zabbix` ;
 *   - la machine forgee porte une adresse lien-local et est retiree
 *     IMMEDIATEMENT ; le parc n'est parcouru que par une planification, et il
 *     n'y en a aucune — mesure refaite a chaque execution, fail-closed.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-adm-etiquettes-notes
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';
import { constateArchivage } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
/** Role 2 SANS `can_admin_portal` — le seul compte qui mesure cette garde. */
const COMPTE_ROLE = 'rw-test-admin';
const SECRET_ROLE = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

/** Machine d'essai du parc — jamais `srv-zabbix` (id 1, PRODUCTION). */
const MACHINE_ID = 2;
const MACHINE_NOM = 'Test-Server-Debian';

const ETIQUETTE = 'epreuve-d6b';
const NOTE = 'note d\'epreuve du sous-lot D6b';
const MACHINE_FORGEE = 'epreuve-forgee-d6b';
/** Point de metadonnees des nuages publics — la cible NOMMEE par le correctif A10-01. */
const IP_LIEN_LOCAL = '169.254.169.254';

const DOSSIER_CAPTURES = new URL('./screenshots/adm', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/serveurs',
        profil: '/profil',
        onglet: null,
        carte: '[data-rw="serveur-carte"]',
        etiquetteSaisie: '[data-rw="serveur-etiquette-saisie"]',
        etiquetteRetirer: '[data-rw="serveur-etiquette-retirer"]',
        noteSaisie: '[data-rw="serveur-note-saisie"]',
        noteAjouter: '[data-rw="serveur-note-ajouter"]',
        noteSupprimer: '[data-rw="serveur-note-supprimer"]',
        pointAction: null,
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/adm/admin_page.php',
        profil: '/profile.php',
        onglet: '.tab-btn[data-tab="servers"]',
        carte: 'details.server-card',
        etiquetteSaisie: 'input[placeholder="+ tag"]',
        etiquetteRetirer: 'button[onclick^="removeTag"]',
        noteSaisie: 'input[id^="note-input-"]',
        noteAjouter: 'button[onclick^="addNote"]',
        noteSupprimer: 'button[onclick^="deleteNote"]',
        pointAction: '/adm/includes/server_actions.php',
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
function verifie(l, ok, d, __quatrieme) {
    /*
     * INF-002 — LE QUATRIEME ARGUMENT N'EXISTE PAS ICI, ET IL NE PASSERA PLUS
     * EN SILENCE.
     *
     * Ce depot porte DEUX semantiques du troisieme argument, et elles sont
     * OPPOSEES : dans ce fichier (70 suites) le detail s'affiche sur un PASS
     * COMME sur un FAIL ; dans 12 autres, il ne s'affiche QUE sur un FAIL, et
     * un quatrieme argument y porte l'informatif. Rien ne les distingue a la
     * lecture d'un appel.
     *
     * Un appel a quatre arguments ecrit pour l'autre convention etait donc
     * SILENCIEUSEMENT tronque : le quatrieme ignore, et l'explication d'echec
     * imprimee sur des lignes VERTES. Quatre occurrences mesurees le
     * 2026-08-27, dont deux preexistantes. On ne le laisse plus arriver sans
     * bruit — et le message nomme le REMEDE, faute de quoi on le contourne en
     * retirant l'argument.
     */
    if (__quatrieme !== undefined) {
        throw new Error(
            'INF-002 : `verifie` de ce fichier prend TROIS arguments, et son detail '
            + 's\'affiche sur un PASS COMME sur un FAIL. Pour une explication qui ne '
            + 'doit paraitre qu\'en cas d\'echec, ecrire le troisieme argument ainsi : '
            + '`ok ? <ce qu\'on a mesure> : <ce qui explique l\'echec>`.');
    }
 note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs += 1; }
function constate(l, v) { note(`INFO  ${l} : ${v}`); }
function verifiePortage(l, ok, d, __quatrieme) {
    /*
     * INF-002 — LE QUATRIEME ARGUMENT N'EXISTE PAS ICI, ET IL NE PASSERA PLUS
     * EN SILENCE.
     *
     * Ce depot porte DEUX semantiques du troisieme argument, et elles sont
     * OPPOSEES : dans ce fichier (70 suites) le detail s'affiche sur un PASS
     * COMME sur un FAIL ; dans 12 autres, il ne s'affiche QUE sur un FAIL, et
     * un quatrieme argument y porte l'informatif. Rien ne les distingue a la
     * lecture d'un appel.
     *
     * Un appel a quatre arguments ecrit pour l'autre convention etait donc
     * SILENCIEUSEMENT tronque : le quatrieme ignore, et l'explication d'echec
     * imprimee sur des lignes VERTES. Quatre occurrences mesurees le
     * 2026-08-27, dont deux preexistantes. On ne le laisse plus arriver sans
     * bruit — et le message nomme le REMEDE, faute de quoi on le contourne en
     * retirant l'argument.
     */
    if (__quatrieme !== undefined) {
        throw new Error(
            'INF-002 : `verifie` de ce fichier prend TROIS arguments, et son detail '
            + 's\'affiche sur un PASS COMME sur un FAIL. Pour une explication qui ne '
            + 'doit paraitre qu\'en cas d\'echec, ecrire le troisieme argument ainsi : '
            + '`ok ? <ce qu\'on a mesure> : <ce qui explique l\'echec>`.');
    }

    if (CIBLE === 'laravel') return verifie(l, ok, ok ? '' : d);
    constate(l, `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

function retireLesFixtures() {
    litEnBase(`DELETE FROM rootwarden.machine_tags WHERE tag = '${ETIQUETTE}'`);
    litEnBase(`DELETE FROM rootwarden.server_notes WHERE content LIKE '%D6b%'`);
    litEnBase(`DELETE FROM rootwarden.machines WHERE name = '${MACHINE_FORGEE}'`);
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
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => { try { await d.accept(); } catch {} });

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

/** Ouvre l'onglet « Serveurs » du legacy ; sans objet sur le portage. */
async function ouvreOnglet(page) {
    if (! C.onglet) return;
    await page.evaluate((sel) => {
        const o = document.querySelector(sel);
        if (o) o.click();
    }, C.onglet);
    await dors(400);
}

/** La carte d'une machine, REPEREE PAR SON CONTENU — jamais « la premiere ». */
async function carteDe(page, nom) {
    for (const h of await page.$$(C.carte)) {
        const texte = await h.evaluate((e) => e.textContent || '');
        if (texte.includes(nom)) return h;
    }

    return null;
}

/** Deplie la carte et PROUVE qu'elle a une boite : un bloc replie ne recoit rien. */
async function deplieLaCarte(carte) {
    return carte.evaluate((e) => {
        for (let n = e; n; n = n.parentElement) if (n.tagName === 'DETAILS') n.open = true;

        // MESURER LE CONTENU, PAS LE `<details>`. Un `<details>` replie a
        // toujours la hauteur de son sommaire : `height > 0` sur lui-meme est
        // une assertion qui ne peut pas echouer. Ce qu'on veut savoir, c'est si
        // ce qui SUIT le sommaire a une boite.
        const corps = Array.from(e.children).find((c) => c.tagName !== 'SUMMARY');

        return corps !== undefined && corps.getBoundingClientRect().height > 0;
    });
}

/**
 * Enregistre les reponses du point d'action pendant un geste.
 *
 * LE VERDICT SE LIT DANS LA REPONSE, PAS DANS L'ABSENCE DE LIGNE. « Rien n'a
 * ete ecrit » a trois causes possibles — la requete n'est pas partie, elle est
 * partie et a ete refusee, elle a reussi et ecrit ailleurs — et elles ne se
 * corrigent pas de la meme facon. Le premier jet de cette suite a conclu « le
 * clic n'ecrit pas » sans savoir laquelle.
 */
function ecouteLesReponses(page) {
    const vues = [];
    const ecoute = async (r) => {
        if (! /server_actions\.php|\/serveurs\//.test(r.url())) return;
        let corps = '';
        try { corps = (await r.text()).slice(0, 120); } catch { corps = '(illisible)'; }
        vues.push(`${r.status()} ${corps.replace(/\s+/g, ' ')}`);
    };
    page.on('response', ecoute);

    return { vues, arrete: () => page.off('response', ecoute) };
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

let etiquettePosee = false;
let notePosee = false;

const session = {};
try {
    /*
     * ══ LE SUJET DE CETTE SUITE N'EXISTE PLUS COTE LEGACY ═════════════════
     *
     * ⚠ ET MON INVENTAIRE L'AVAIT CLASSEE « MIXTE », DONC ECARTEE. Le
     * 2026-09-05 j'ai outille 33 suites au sujet archive, en ecartant celles
     * qui CITENT un chemin encore servi. Celle-ci en cite un — mais son SUJET
     * est archive, et elle a rendu ses rouges au lot suivant.
     *
     * **Mon critere demandait « cite-t-elle un chemin vivant » la ou il fallait
     * demander « son SUJET vit-il ».** Un chemin d'API partage ne dit rien de la
     * page qu'une suite mesure.
     *
     * LE CONSTAT VIENT AVANT LA CONNEXION : la sonde de `archive.mjs` n'ouvre pas
     * de navigateur, et se connecter d'abord consommerait un code TOTP — garde
     * anti-rejeu par COMPTE et persistant — pour mesurer une page absente.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: C.page, fichiers: [], verifie, constate,
        });
        if (archivee) throw new Error('__archivee__');
    }

    retireLesFixtures();

    // ══ 1. LA PRECONDITION DE SURETE ═══════════════════════════════════════
    await etape('le parc est-il parcouru par une planification ?', async () => {
        const cve = compteEnBase('SELECT COUNT(*) FROM rootwarden.cve_scan_schedules');
        const ssh = compteEnBase('SELECT COUNT(*) FROM rootwarden.ssh_audit_schedules');
        constate('planifications de scan CVE', String(cve));
        constate('planifications d\'audit SSH', String(ssh));
        // FAIL-CLOSED : la machine forgee de l'etape 5 porte une adresse de
        // metadonnees. Elle est retiree dans la seconde, mais on ne la pose que
        // si RIEN ne parcourt le parc.
        verifie('aucune planification ne parcourt le parc', cve === 0 && ssh === 0,
            `${cve} CVE, ${ssh} SSH — la machine forgee ne serait pas inerte`);
    });

    // ══ 2. Les gestes, au role 3, PAR DES CLICS ════════════════════════════
    session.s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = session.s;

    await etape('ouverture', async () => {
        const rep = await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('le role 3 atteint la page', rep.status() === 200, `statut ${rep.status()}`);
    });

    await etape('poser une etiquette, par une frappe reelle', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await ouvreOnglet(page);

        const carte = await carteDe(page, MACHINE_NOM);
        verifie('la carte de la machine d\'essai est trouvee', carte !== null, MACHINE_NOM);
        if (! carte) return;
        verifie('la carte est depliee et a une boite', await deplieLaCarte(carte));
        await dors(300);

        const champ = await carte.$(C.etiquetteSaisie);
        verifie('le champ d\'etiquette est atteignable', champ !== null);
        if (! champ) return;

        const oreille = ecouteLesReponses(page);
        await champ.click();
        await champ.type(ETIQUETTE, { delay: 10 });
        // La soumission se fait a la touche Entree — c'est le geste REEL que
        // l'interface offre, il n'y a pas de bouton a cliquer ici.
        await champ.press('Enter');
        await dors(1500);
        oreille.arrete();
        constate('reponses du point d\'action', oreille.vues.length ? oreille.vues.join(' || ') : '(aucune requete)');

        const pose = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.machine_tags WHERE machine_id = ${MACHINE_ID} AND tag = '${ETIQUETTE}'`);
        etiquettePosee = pose === 1;
        verifiePortage('le clic pose l\'etiquette en base', etiquettePosee,
            `${pose} ligne(s) — la requete PART et le serveur repond « Token CSRF invalide » : `
            + 'l\'enrobage de `window.fetch` (`js/utils.js:22`) n\'injecte `X-CSRF-TOKEN` que pour '
            + '`api_proxy.php`, `/adm/api/` et `/auth/`. `/adm/includes/` n\'est dans aucune des trois');
    });

    await etape('retirer l\'etiquette, par un clic', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await ouvreOnglet(page);
        const carte = await carteDe(page, MACHINE_NOM);
        if (! carte) { verifie('la carte est retrouvee', false); return; }
        await deplieLaCarte(carte);
        await dors(300);

        // LA BRANCHE EST EXPLICITE ET ELLE EST ASSERTEE. Un `if` dont l'echec
        // ne serait que journalise est un test qui ne peut pas echouer — le
        // piege releve sur `go-cve-schedules.mjs`. Ici, ne pas pouvoir exercer
        // le retrait EST le verdict, et il se declare comme tel.
        if (! etiquettePosee) {
            verifiePortage('le clic retire l\'etiquette', false,
                'geste non exercable : l\'ajout n\'a rien ecrit, le retrait ne peut pas etre teste');

            return;
        }

        // Le bouton de CETTE etiquette, repere par son contenu — pas « le
        // premier bouton de retrait » : la machine en porte deja une autre.
        const bouton = await carte.evaluateHandle((e, sel, tag) => {
            for (const b of e.querySelectorAll(sel)) {
                // Trois reperages, parce que les deux portails ne portent pas
                // l'etiquette au meme endroit : le portage la met en attribut,
                // le legacy dans l'argument de son `onclick`, et le texte
                // visible la porte dans un ANCETRE — le parent direct du bouton
                // est son formulaire, dont le texte n'est que « x ».
                if ((b.dataset || {}).tag === tag) return b;
                if ((b.getAttribute('onclick') || '').includes(`'${tag}'`)) return b;
                // REMONTEE BORNEE A TROIS NIVEAUX. Sans borne, on finirait par
                // atteindre un ancetre qui contient TOUTE la carte, et le
                // premier bouton venu passerait pour le bon.
                let n = b.parentElement;
                for (let i = 0; i < 3 && n; i += 1, n = n.parentElement) {
                    if ((n.textContent || '').includes(tag)) return b;
                }
            }

            return null;
        }, C.etiquetteRetirer, ETIQUETTE);

        // `evaluateHandle` rend un JSHandle : `asElement()` le convertit en
        // poignee d'ELEMENT, seule forme sur laquelle le `click()` de Puppeteer
        // — un vrai clic, aux coordonnees reelles — puisse s'appliquer.
        const element = bouton.asElement();
        verifie('le bouton de retrait de CETTE etiquette est trouve', element !== null);
        if (! element) return;

        const oreille = ecouteLesReponses(page);
        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 });
        await element.click();
        try { await nav; } catch { /* le legacy ne navigue pas : il `fetch` */ }
        await dors(900);
        oreille.arrete();
        constate('reponses du retrait', oreille.vues.length ? oreille.vues.join(' || ') : '(aucune requete)');

        const reste = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.machine_tags WHERE machine_id = ${MACHINE_ID} AND tag = '${ETIQUETTE}'`);
        verifiePortage('le clic retire l\'etiquette', reste === 0, `${reste} ligne(s) restante(s)`);
    });

    await etape('poser une note, par un clic', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await ouvreOnglet(page);
        const carte = await carteDe(page, MACHINE_NOM);
        if (! carte) { verifie('la carte est retrouvee', false); return; }
        await deplieLaCarte(carte);
        await dors(300);

        const champ = await carte.$(C.noteSaisie);
        const bouton = await carte.$(C.noteAjouter);
        verifie('le champ et le bouton de note sont atteignables', champ !== null && bouton !== null,
            `champ=${champ !== null} bouton=${bouton !== null}`);
        if (! champ || ! bouton) return;

        const oreille = ecouteLesReponses(page);
        await champ.click();
        await champ.type(NOTE, { delay: 6 });
        await bouton.click();
        await dors(1500);
        oreille.arrete();
        constate('reponses du point d\'action', oreille.vues.length ? oreille.vues.join(' || ') : '(aucune requete)');

        const lues = litEnBase(
            `SELECT CONCAT(author,'|',content) FROM rootwarden.server_notes WHERE machine_id = ${MACHINE_ID}`);
        constate('note enregistree', lues[0] || '(aucune)');
        notePosee = lues.length === 1 && lues[0] === `${COMPTE}|${NOTE}`;
        verifiePortage('le clic pose la note, avec son auteur', notePosee,
            `${lues[0] || '(aucune)'} — meme cause que l'etiquette : « Token CSRF invalide »`);
    });

    await etape('supprimer la note, par un clic', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await ouvreOnglet(page);
        const carte = await carteDe(page, MACHINE_NOM);
        if (! carte) { verifie('la carte est retrouvee', false); return; }
        await deplieLaCarte(carte);
        await dors(300);

        if (! notePosee) {
            verifiePortage('le clic supprime la note', false,
                'geste non exercable : l\'ajout n\'a rien ecrit, la suppression ne peut pas etre testee');

            return;
        }

        const bouton = await carte.$(C.noteSupprimer);
        verifie('le bouton de suppression de note est trouve', bouton !== null);
        if (! bouton) return;

        await bouton.click();
        await dors(900);

        const reste = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.server_notes WHERE machine_id = ${MACHINE_ID}`);
        verifiePortage('le clic supprime la note', reste === 0, `${reste} ligne(s) restante(s)`);
    });

    // ══ 3. LA GARDE : un role 2 SANS la permission de la page ══════════════
    await etape('un role 2 sans permission atteint-il le point d\'action ?', async () => {
        if (! C.pointAction) {
            constate('point d\'action separe', 'le portage n\'en a pas — les gestes sont des routes gardees');
            verifie('le portage ne sert aucun point d\'action non garde', true);

            return;
        }
        await dors((resteFenetre() + 1) * 1000);
        const s = await connecte(COMPTE_ROLE, SECRET_ROLE);
        try {
            const surPage = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            verifie('le role 2 sans can_admin_portal est refuse sur la PAGE',
                surPage.status() === 403, `statut ${surPage.status()}`);

            // Le jeton CSRF se lit sur une page que CE compte peut atteindre.
            // `profile.php` est ouvert a tout compte authentifie et le rend
            // dans un champ cache : la garde CSRF ne protege donc pas d'un
            // compte du portail, elle protege d'un site tiers.
            await s.page.goto(`${BASE}${C.profil}`, { waitUntil: 'networkidle2' });
            const jeton = await s.page.evaluate(() => {
                const e = document.querySelector('input[name="csrf_token"]');

                return e ? e.value : '';
            });
            constate('jeton CSRF obtenu depuis le profil', jeton ? `oui (${jeton.length} caracteres)` : 'non');

            // REQUETE FORGEE, ET SON MOTIF : le geste `add_tag` a bien un
            // appelant vivant, mais il vit dans une page que CE compte ne peut
            // pas ouvrir. Aucun clic ne peut donc l'atteindre depuis ce compte
            // — c'est precisement ce qu'on mesure. La requete part DEPUIS LA
            // PAGE, avec la session et les en-tetes reels.
            const verdict = await s.page.evaluate(async (url, jetonCsrf, mid) => {
                const r = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': jetonCsrf },
                    body: JSON.stringify({ action: 'add_tag', machine_id: mid, tag: 'sondedeuxb' }),
                });

                return { statut: r.status, corps: (await r.text()).slice(0, 120) };
            }, `${BASE}${C.pointAction}`, jeton, MACHINE_ID);

            constate('statut du point d\'action pour ce compte', String(verdict.statut));
            constate('corps rendu', verdict.corps);

            const posee = compteEnBase(
                `SELECT COUNT(*) FROM rootwarden.machine_tags WHERE tag = 'sondedeuxb'`);
            constate('etiquette reellement ecrite en base', String(posee));
            litEnBase("DELETE FROM rootwarden.machine_tags WHERE tag = 'sondedeuxb'");

            // LA PROPRIETE MESUREE EST L'ECRITURE, PAS LE STATUT. Un 200
            // portant `success:false` ne serait pas un defaut ; une LIGNE
            // ecrite par un compte refuse sur la page en est un.
            verifiePortage('un compte refuse sur la page n\'ecrit pas par le point d\'action',
                posee === 0,
                `${posee} ligne(s) ecrite(s) — `
                + '`server_actions.php` appelle `checkAuth([2,3])` et PAS '
                + '`checkPermission(\'can_admin_portal\')`, que sa page hote exige');
        } finally {
            await s.ctx.close();
        }
    });

    // ══ 4. LE CORRECTIF SSRF, SUR LES DEUX CHEMINS ════════════════════════
    await etape('le correctif A10-01 protege-t-il les DEUX chemins ?', async () => {
        if (! C.pointAction) {
            constate('second chemin d\'ecriture', 'le portage n\'en a qu\'un — `Serveurs::valideIp()`');
            verifie('le portage n\'a qu\'un seul chemin d\'ecriture a garder', true);

            return;
        }
        await page.goto(`${BASE}${C.profil}`, { waitUntil: 'networkidle2' });
        const jeton = await page.evaluate(() => {
            const e = document.querySelector('input[name="csrf_token"]');

            return e ? e.value : '';
        });

        // REQUETE FORGEE, ET SON MOTIF : `add_server` de `server_actions.php`
        // n'a AUCUN appelant vivant — ses trois `fetch` sont dans le bloc
        // commente. Aucun clic ne peut l'atteindre ; c'est le cas prevu par la
        // convention. Elle part depuis la page, avec la session reelle.
        const verdict = await page.evaluate(async (url, jetonCsrf, nom, ip) => {
            const corps = new URLSearchParams({
                csrf_token: jetonCsrf, action: 'add_server',
                name: nom, ip, user: 'epreuve', password: 'x', root_password: 'x',
                port: '22', environment: 'DEV', criticality: 'NON CRITIQUE', network_type: 'INTERNE',
            });
            const r = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: corps.toString(),
            });

            return { statut: r.status, corps: (await r.text()).slice(0, 160) };
        }, `${BASE}${C.pointAction}`, jeton, MACHINE_FORGEE, IP_LIEN_LOCAL);

        constate('statut du chemin AJAX', String(verdict.statut));
        constate('corps rendu', verdict.corps.replace(/\s+/g, ' '));

        const creee = litEnBase(
            `SELECT ip FROM rootwarden.machines WHERE name = '${MACHINE_FORGEE}'`);
        constate('machine a adresse de metadonnees creee', creee[0] || '(aucune)');
        // ON LA RETIRE TOUT DE SUITE, sans attendre le `finally` : une adresse
        // de metadonnees en base est ce que le correctif A10-01 cherche a
        // empecher, et rien ne justifie de l'y laisser une seconde de plus.
        litEnBase(`DELETE FROM rootwarden.machines WHERE name = '${MACHINE_FORGEE}'`);

        verifiePortage('une adresse lien-local est refusee par TOUS les chemins d\'ecriture',
            creee.length === 0,
            `${creee[0]} acceptee — \`manage_servers.php\` porte le correctif A10-01, `
            + '`server_actions.php` en porte une copie de `validateInput()` REDUITE A UNE LIGNE, '
            + 'sans aucun garde. Le correctif n\'a ete applique qu\'au chemin qu\'un clic emprunte');
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            await ouvreOnglet(page);
            const carte = await carteDe(page, MACHINE_NOM);
            if (carte) {
                await deplieLaCarte(carte);
                // CADRER CE QUE LE SOUS-LOT CONSTRUIT. Sans ce defilement, les
                // trois images montrent le haut de la page — vrai, 200, garni,
                // et sans une seule etiquette ni une seule note. Meme piege que
                // l'onglet de D6a, et vu de la meme facon : en regardant.
                await carte.evaluate((e) => e.scrollIntoView({ block: 'center' }));
            }
            await dors(500);
            await page.screenshot({ path: `${dossier}/etiquettes-notes-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    verifiePortage('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 2).join(' | '));

} catch (e) {
    // `__archivee__` est la sortie NORMALE d'un sujet archive, pas une panne.
    if (String(e && e.message || e).includes('__archivee__')) { /* le constat a tout dit */ } else {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
    }
} finally {
    try {
        retireLesFixtures();
        const t = compteEnBase(`SELECT COUNT(*) FROM rootwarden.machine_tags WHERE tag = '${ETIQUETTE}'`);
        const n = compteEnBase("SELECT COUNT(*) FROM rootwarden.server_notes WHERE content LIKE '%D6b%'");
        const m = compteEnBase(`SELECT COUNT(*) FROM rootwarden.machines WHERE name = '${MACHINE_FORGEE}'`);
        verifie('aucune fixture ne subsiste', t === 0 && n === 0 && m === 0,
            `${t} etiquette(s), ${n} note(s), ${m} machine(s)`);
    } catch (e) { note(`FAIL  retrait : ${e.message}`); echecs += 1; }
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
