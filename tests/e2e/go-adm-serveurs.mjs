/**
 * go-adm-serveurs.mjs - Sous-lot D6a de `adm/` : le tableau des serveurs.
 *
 * D6 PESAIT 1 746 LIGNES ET A ETE REDECOUPE. C'est un document de migration, pas
 * une promesse : `S2` l'avait deja ete pour 579 lignes.
 *
 *   D6a  `includes/manage_servers.php` (939 l.) + `manage_servers_table.php` (352 l.)
 *   D6b  `includes/server_actions.php` (267 l.) + `includes/import_csv.php` (189 l.)
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/adm/admin_page.php  (onglet Serveurs)
 *   laravel  http://localhost:8444/serveurs             (porte par D6a)
 *
 * ══ LE DEFAUT : UN FRAGMENT MORT QUI REPOND ENCORE, ET SANS PERMISSION ═════
 *
 * `manage_servers_table.php` n'a qu'UNE reference dans tout le depot — le
 * `fetch()` de `manage_servers.php:709` — et elle est **a l'interieur d'un bloc
 * commente** (`:661-923`, 263 lignes sur 939). Le fichier est donc mort par
 * navigation.
 *
 * Il reste pourtant servi par Apache, et sa garde est CONDITIONNELLE :
 *
 *     if (!function_exists('checkAuth')) {
 *         … checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
 *     }
 *
 * Le reflexe est bon — inclus depuis la page, la garde du parent suffit ; appele
 * en direct, il se garde lui-meme. Mais il appelle `checkAuth` et **PAS**
 * `checkPermission('can_admin_portal')`, que sa page hote exige. Un compte de
 * role 2 SANS cette permission est donc refuse sur `admin_page.php` et obtient
 * le tableau des serveurs en visant le fragment.
 *
 * C'est « la garde est sur la PAGE, pas sur la REQUETE » — sur du code mort qui
 * repond encore.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * La suite cree une machine d'epreuve. Deux precautions, toutes deux mesurees :
 *
 *   - son adresse est dans `192.0.2.0/24` (RFC 5737, TEST-NET-1), reservee a la
 *     documentation : meme une connexion accidentelle n'aboutit nulle part ;
 *   - le parc n'est parcouru que par une PLANIFICATION, et il n'y en a AUCUNE —
 *     mesure du 2026-08-26 : `cve_scan_schedules` et `ssh_audit_schedules` sont
 *     vides. Une machine ajoutee est donc inerte.
 *
 * `srv-zabbix` (id 1) n'est ni lue, ni citee, ni jointe.
 *
 * ══ LE SECOND DEFAUT : UNE CONFIRMATION QUI NE S'EXECUTE PAS ══════════════
 *
 * `manage_servers.php:495` rend le bouton de suppression avec
 * `onclick="return confirm('<?= t('servers.confirm_delete', [...]) ?>')"`. La
 * traduction vaut « Supprimer le serveur "X" ? Cette action est irreversible. »
 * — avec des GUILLEMETS DOUBLES, dans un attribut HTML delimite par des
 * guillemets doubles. Le premier ferme l'attribut.
 *
 * Le navigateur ne recoit donc que `return confirm('Supprimer le serveur `,
 * chaine non terminee : le gestionnaire ne s'attache pas et le formulaire part
 * SANS confirmation. Mesure du 2026-08-26 : l'attribut fait 99 caracteres, il
 * est coupe au 46e.
 *
 * `addslashes` est bien applique — au NOM. C'est le motif « a moitie corrige »
 * du depot, cinquieme occurrence relevee.
 *
 * ══ LES TROIS GESTES SE FONT PAR DES CLICS ════════════════════════════════
 *
 * Ajout, modification et retrait sont pilotes par `type()` et `click()` sur les
 * elements REELS, et le verdict se lit EN BASE — jamais dans un message. Le
 * legacy affiche le sien par un `toast()`, que rien ne relie a une ecriture.
 *
 * Une difference de forme, assumee et mesuree : le legacy pose un `confirm()`
 * natif avant de supprimer, le portage ouvre un panneau qui NOMME la
 * consequence. La suite exerce les deux, et verifie en plus, cote portage, que
 * l'ouverture du panneau n'ecrit rien.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-adm-serveurs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';
import { constateArchivage } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = (() => {
    /*
     * ══ LA CIBLE VIENT DE L'ENVIRONNEMENT, L'URL N'EST QU'UN REPLI ════════
     *
     * `/8444|laravel/i.test(BASE)` deduit la cible d'un NUMERO DE PORT. Tant que
     * le portage vit sur 8444 c'est juste ; **le jour ou les ports s'echangent,
     * ce predicat rend 87 suites MENTEUSES et non rouges** — elles appliqueraient
     * les attentes du legacy au portage, et rendraient du VERT.
     *
     * `E2E_CIBLE` devient donc l'autorite, et `rejouer-lot.sh` l'exporte pour
     * chaque moitie. Le motif d'URL ne sert plus qu'aux lancements a la main.
     *
     * ⚠ ET IL N'Y A PAS DE GARDE DE COHERENCE ENTRE LES DEUX — c'est deliberé,
     * et l'inverse a ete demande puis ecarte apres mesure :
     *
     *     E2E_CIBLE=laravel + BASE=…:8443
     *       AVANT l'echange  incoherent   (a refuser)
     *       APRES l'echange  CORRECT      (a accepter)
     *
     * **Une garde « l'environnement doit concorder avec le motif d'URL »
     * refuserait exactement la configuration que cet elargissement existe pour
     * permettre.** Le motif d'URL n'est pas un invariant : c'est la chose meme
     * qu'on rend caduque. On ne garde pas une valeur contre une heuristique
     * qu'on sait perimee.
     *
     * CE QUI EST INVARIANT, ET SUR QUOI LA GARDE SE POSE : la cible appartient a
     * une LISTE FERMEE. Une valeur hors liste est refusee bruyamment, au
     * chargement, avant qu'une seule assertion ne s'execute — une faute de frappe
     * ne doit pas se lire comme « legacy » par repli silencieux.
     */
    const CIBLES = ['laravel', 'legacy'];
    const declaree = process.env.E2E_CIBLE;
    if (declaree !== undefined && declaree !== '') {
        if (! CIBLES.includes(declaree)) {
            throw new Error(
                `E2E_CIBLE=${JSON.stringify(declaree)} n'est pas une cible connue `
                + `(${CIBLES.join(' | ')}). Rien n'est joue : une cible inconnue `
                + `retomberait sur « legacy » et la suite mesurerait le mauvais portail.`);
        }

        return declaree;
    }

    return /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
})();
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
/** Role 2 SANS `can_admin_portal` — le seul compte qui mesure cette garde. */
const COMPTE_ROLE = 'rw-test-admin';
const SECRET_ROLE = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

const EPREUVE = 'epreuve-e2e-d6a';
/** RFC 5737 TEST-NET-1 : reservee a la documentation, ne route nulle part. */
const IP_EPREUVE = '192.0.2.77';

const DOSSIER_CAPTURES = new URL('./screenshots/adm', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/serveurs',
        fragment: null,
        corps: '[data-rw="serveurs-corps"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
        onglet: null,
        ajout: {
            nom: '[data-rw="serveur-nom"]', ip: '[data-rw="serveur-ip"]',
            port: '[data-rw="serveur-port"]', user: '[data-rw="serveur-utilisateur"]',
            mdp: '[data-rw="serveur-mdp"]', mdpRoot: '[data-rw="serveur-mdp-root"]',
            valide: '[data-rw="serveur-ajouter"]',
        },
        carte: '[data-rw="serveur-carte"]',
        editIp: '[data-rw="serveur-edit-ip"]',
        editValide: '[data-rw="serveur-enregistrer"]',
        supprime: '[data-rw="serveur-supprimer"]',
        // Le portage NOMME la consequence dans un panneau ; le legacy pose un
        // `confirm()` natif, que l'ecouteur de dialogue accepte.
        supprimeConfirme: '[data-rw="serveur-suppr-confirmer"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/adm/admin_page.php',
        // Le fragment MORT, toujours servi.
        fragment: '/adm/includes/manage_servers_table.php',
        corps: 'table',
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
        onglet: '.tab-btn[data-tab="servers"]',
        ajout: {
            nom: '#add-server-form input[name="name"]', ip: '#add-server-form input[name="ip"]',
            port: '#add-server-form input[name="port"]', user: '#add-server-form input[name="user"]',
            mdp: '#add-server-form input[name="password"]',
            mdpRoot: '#add-server-form input[name="root_password"]',
            valide: '#add-server-form button[name="add_server"]',
        },
        carte: 'details.server-card',
        editIp: 'input[name="ip"]',
        editValide: 'button[name="update_server"]',
        supprime: 'button[name="delete_server"]',
        supprimeConfirme: null,
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

let borne = 0;
function idEpreuve() {
    const v = litEnBase(`SELECT id FROM rootwarden.machines WHERE name = '${EPREUVE}'`);

    return v.length ? parseInt(v[0], 10) : 0;
}
function retireLEpreuve() {
    if (borne > 0) litEnBase(`DELETE FROM rootwarden.machines WHERE id > ${borne} AND name = '${EPREUVE}'`);
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

/**
 * Ouvre l'onglet « Serveurs » du legacy. Sans objet sur le portage, ou la page
 * EST celle des serveurs.
 *
 * Chaque POST du legacy recharge `admin_page.php`, qui revient sur l'onglet des
 * comptes : il faut donc le rouvrir apres CHAQUE geste. Sans cela on mesurerait
 * un onglet qui n'est pas celui qu'on croit — la page repond 200 et rend du
 * contenu, simplement pas le bon.
 */
async function ouvreOnglet(page) {
    if (! C.onglet) return;
    await page.evaluate((sel) => {
        const o = document.querySelector(sel);
        if (o) o.click();
    }, C.onglet);
    await dors(400);
}

/**
 * Deplie le `<details>` qui CONTIENT un element, et prouve qu'il a une boite.
 *
 * Un bloc replie ne recoit pas les frappes : `page.$()` le trouve, `type()` ne
 * leve pas, et rien ne se passe — la suite meurt vingt lignes plus loin sur
 * « Node is either not clickable ». Cinq occurrences payees sur ce module.
 *
 * @returns {Promise<boolean>} l'element a-t-il une hauteur non nulle ?
 */
async function deplie(page, selecteur) {
    return page.evaluate((sel) => {
        const e = document.querySelector(sel);
        if (! e) return false;
        for (let n = e; n; n = n.parentElement) {
            if (n.tagName === 'DETAILS') n.open = true;
        }

        return e.getBoundingClientRect().height > 0
            && getComputedStyle(e).display !== 'none';
    }, selecteur);
}

/** Remplit un champ par des frappes reelles, apres l'avoir vide. */
async function saisis(page, selecteur, valeur) {
    const champ = await page.$(selecteur);
    if (! champ) throw new Error(`champ absent : ${selecteur}`);
    await champ.click({ clickCount: 3 });
    await champ.press('Backspace');
    await champ.type(String(valeur), { delay: 8 });
}

/**
 * Rend le handle de la carte de la machine d'epreuve, REPEREE PAR SON CONTENU.
 *
 * Jamais « la premiere carte » : les deux portails ne les ordonnent pas
 * pareil, et le legacy en rend trois de plus.
 */
async function carteEpreuve(page) {
    const handles = await page.$$(C.carte);
    for (const h of handles) {
        const texte = await h.evaluate((e) => e.textContent || '');
        if (texte.includes(EPREUVE)) return h;
    }

    return null;
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
    /*
     * ══ LE SUJET DE CETTE SUITE N'EXISTE PLUS COTE LEGACY ═════════════════
     *
     * Une suite de parite dont la moitie legacy a ete archivee ne doit pas
     * ECHOUER : un rouge permanent finit par ne plus etre lu, et il occupe la
     * place ou l'on aurait cherche une vraie regression. Elle CONSTATE, et sa
     * moitie portage continue de s'exercer.
     *
     * LE CONSTAT VIENT AVANT LA CONNEXION, et ce n'est pas un detail : la sonde
     * de `archive.mjs` n'ouvre pas de navigateur (Apache rend 404 pour un chemin
     * absent AVANT toute redirection de connexion). Se connecter d'abord ferait
     * consommer un code TOTP — dont le garde anti-rejeu est par COMPTE et
     * PERSISTANT — pour aller mesurer une page qui n'existe plus.
     *
     * ⚠ ET LE CONSTAT EXIGE UN 404, PAS UNE ABSENCE DE PAGE. Le 2026-09-05 ces
     * repertoires rendaient 403 : le `git mv` avait emporte les `.php` et laisse
     * le JavaScript, si bien que le dossier existait encore. `constateArchivage`
     * traite tout statut != 404 comme « encore servie » et rend `false` : le
     * constat aurait ete FAUX et la suite rouge quand meme. L'archivage a ete
     * acheve (`7588e71`) avant que cette ligne soit ecrite.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: C.page, fichiers: [], verifie, constate,
        });
        if (archivee) throw new Error('__archivee__');
    }

    retireLEpreuve();
    borne = compteEnBase('SELECT IFNULL(MAX(id), 0) FROM rootwarden.machines');

    // ══ 1. LA PRECONDITION DE SURETE, mesuree ══════════════════════════════
    await etape('le parc est-il parcouru par une planification ?', async () => {
        const cve = compteEnBase('SELECT COUNT(*) FROM rootwarden.cve_scan_schedules');
        const ssh = compteEnBase('SELECT COUNT(*) FROM rootwarden.ssh_audit_schedules');
        constate('planifications de scan CVE', String(cve));
        constate('planifications d\'audit SSH', String(ssh));
        // FAIL-CLOSED : une planification « toutes machines » enrolerait la
        // machine d'epreuve dans un scan REEL — session SSH, et courriel a la
        // fin. On ne pose la fixture que si le parc est inerte.
        verifie('aucune planification ne parcourt le parc', cve === 0 && ssh === 0,
            `${cve} CVE, ${ssh} SSH — la fixture ne serait pas inerte`);
    });

    // ══ 2. LA GARDE DU FRAGMENT MORT ═══════════════════════════════════════
    await etape('un role 2 sans permission atteint-il le fragment ?', async () => {
        if (! C.fragment) {
            constate('fragment', 'le portage n\'en a pas — la page rend son tableau elle-meme');
            verifie('le portage ne sert aucun fragment separe', true);

            return;
        }
        const s = await connecte(COMPTE_ROLE, SECRET_ROLE);
        try {
            const surPage = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            verifie('le role 2 sans can_admin_portal est refuse sur la PAGE',
                surPage.status() === 403, `statut ${surPage.status()}`);

            const surFragment = await s.page.goto(`${BASE}${C.fragment}`, { waitUntil: 'networkidle2' });
            const corps = await s.page.evaluate(() => document.body.innerText.slice(0, 200));
            constate('statut du fragment pour ce compte', String(surFragment.status()));
            constate('debut du corps rendu', corps.replace(/\s+/g, ' ').slice(0, 120) || '(vide)');
            // MESURER LE STATUT, pas le texte : un 404 dirait « cette page
            // n'existe pas », pas « vous n'y avez pas droit ».
            // CE QU'IL EXPOSE, ET CE QU'IL N'EXPOSE PAS. La distinction decide de
            // la gravite : un inventaire de machines n'est pas un secret de
            // machine. Mesure : les colonnes de mot de passe sont des `<input
            // type=password>` VIDES, portant « laisser vide pour ne pas
            // modifier » — aucune valeur stockee n'est imprimee.
            const fuite = await s.page.evaluate(() => {
                const champs = Array.from(document.querySelectorAll('input[type="password"]'));

                return {
                    champs: champs.length,
                    remplis: champs.filter((e) => (e.value || '') !== '').length,
                };
            });
            constate('champs de mot de passe rendus', `${fuite.champs}, dont ${fuite.remplis} remplis`);
            verifie('aucun mot de passe stocke n\'est imprime dans le fragment',
                fuite.remplis === 0, `${fuite.remplis} champ(s) rempli(s)`);
            verifiePortage('le fragment refuse un compte sans la permission de la page',
                surFragment.status() === 403,
                `statut ${surFragment.status()} — le fragment appelle `
                + '`checkAuth([2,3])` et PAS `checkPermission`, que sa page hote exige. '
                + 'Il rend l\'INVENTAIRE (noms, adresses, ports, comptes SSH), pas les secrets');
        } finally {
            await s.ctx.close();
        }
    });
    await dors((resteFenetre() + 1) * 1000);

    // ══ 3. La page, au role 3 ══════════════════════════════════════════════
    session.s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = session.s;

    await etape('ouverture', async () => {
        const rep = await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('le role 3 atteint la page', rep.status() === 200, `statut ${rep.status()}`);
    });

    // ══ 4. Le tableau est-il rendu par le SERVEUR ou par un appel ? ════════
    await etape('le tableau des serveurs est rendu sans appel', async () => {
        const appels = [];
        const ecoute = (r) => {
            if (/manage_servers_table|serveurs\/tableau/.test(r.url())) appels.push(r.url());
        };
        page.on('request', ecoute);
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        // L'onglet « Serveurs » n'est pas celui par defaut : sans ce clic, la
        // page ne montre pas son tableau et l'assertion mesurerait l'onglet des
        // comptes. Cinquieme forme du meme piege — ici ce n'est pas un
        // `<details>` mais un onglet, et le symptome est plus sournois : la page
        // repond 200 et rend du contenu, simplement pas celui qu'on croit.
        await page.evaluate(() => {
            const o = document.querySelector('.tab-btn[data-tab="servers"]');
            if (o) o.click();
        });
        await dors(1200);
        page.off('request', ecoute);

        const machines = compteEnBase('SELECT COUNT(*) FROM rootwarden.machines');
        const texte = await page.evaluate(() => document.body.innerText);
        constate('appels vers le fragment de tableau', String(appels.length));
        constate('machines en base', String(machines));
        // Le fetch qui chargeait ce fragment vit DANS le bloc commente : la page
        // rend donc son tableau cote serveur, et le fragment n'est appele par
        // personne.
        verifie('aucun appel vers le fragment de tableau', appels.length === 0,
            appels.join(' | '));
        const nomVu = litEnBase('SELECT name FROM rootwarden.machines ORDER BY id LIMIT 1');
        const rendu = await page.evaluate(() => document.body.innerText);
        verifie('le tableau rend bien les machines du parc',
            nomVu.length > 0 && rendu.includes(nomVu[0]), nomVu[0] || '(aucune machine)');
        void texte;
    });

    // ══ 5. UNE ADRESSE MAPPEE EST-ELLE REFUSEE ? ══════════════════════════
    //
    // Le garde A10-01 du legacy compare des PREFIXES DE CHAINE
    // (`strpos($ip, '169.254.') === 0`). `::ffff:169.254.169.254` designe la
    // MEME adresse — le point de metadonnees des nuages publics, nomme par le
    // commentaire du correctif — et ne commence par aucun des prefixes testes.
    //
    // Le premier jet du portage avait recopie cette regle, angle mort compris.
    // Releve par une relecture croisee le 2026-08-26, pas par cette suite :
    // d'ou cette etape. Le portage compare desormais sur la forme BINAIRE.
    //
    // CETTE ETAPE VIENT AVANT LA CREATION LEGITIME, et ce n'est pas un detail :
    // posee apres, elle porterait le MEME nom qu'une machine deja creee, serait
    // refusee pour cause de DOUBLON, et passerait pour une bonne nouvelle. Une
    // assertion qui reussit pour la mauvaise raison ne se relit jamais.
    //
    // GESTE REEL : on tape l'adresse dans le formulaire et on clique. Pas de
    // requete forgee — le formulaire d'ajout existe sur les deux cibles, et
    // c'est justement le chemin « durci » qu'on veut mettre a l'epreuve.
    await etape('une adresse mappee IPv4-en-IPv6 est-elle refusee ?', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await ouvreOnglet(page);
        await deplie(page, C.ajout.nom);

        await saisis(page, C.ajout.nom, EPREUVE);
        await saisis(page, C.ajout.ip, '::ffff:169.254.169.254');
        await saisis(page, C.ajout.port, '22');
        await saisis(page, C.ajout.user, 'epreuve');
        await saisis(page, C.ajout.mdp, 'epreuve-sans-valeur-1!');
        await saisis(page, C.ajout.mdpRoot, 'epreuve-sans-valeur-2!');

        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click(C.ajout.valide);
        try { await nav; } catch { /* redirection */ }
        await dors(600);

        const creee = litEnBase(`SELECT ip FROM rootwarden.machines WHERE name = '${EPREUVE}'`);
        constate('machine creee avec une adresse mappee', creee[0] || '(aucune)');
        // RETIREE TOUT DE SUITE, sans attendre le `finally` : une adresse de
        // metadonnees en base est exactement ce que le correctif empeche.
        retireLEpreuve();

        verifiePortage('une adresse de metadonnees ecrite en IPv6 mappe est refusee',
            creee.length === 0,
            `${creee[0]} acceptee — le garde compare des PREFIXES DE CHAINE, et `
            + '`::ffff:169.254.169.254` ne commence par aucun d\'eux. La copie « durcie » '
            + 'de `manage_servers.php` tombe donc aussi, pas seulement celle de `server_actions.php`');
    });

    // ══ 6. AJOUTER une machine, PAR LE FORMULAIRE ══════════════════════════
    await etape('ajouter une machine par le formulaire', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await ouvreOnglet(page);

        const ouvert = await deplie(page, C.ajout.nom);
        verifie('le formulaire d\'ajout est deplie et a une boite', ouvert,
            'replie : les frappes ne seraient pas recues');

        await saisis(page, C.ajout.nom, EPREUVE);
        await saisis(page, C.ajout.ip, IP_EPREUVE);
        await saisis(page, C.ajout.port, '22');
        await saisis(page, C.ajout.user, 'epreuve');
        await saisis(page, C.ajout.mdp, 'epreuve-sans-valeur-1!');
        await saisis(page, C.ajout.mdpRoot, 'epreuve-sans-valeur-2!');

        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click(C.ajout.valide);
        try { await nav; } catch { /* le portage repond par une redirection */ }
        await dors(600);

        // LA MESURE EST EN BASE, pas a l'ecran : un message de succes n'est
        // qu'un message. Le legacy en affiche un par `toast()`, que rien ne
        // relie a une ecriture reelle.
        const cree = litEnBase(`SELECT CONCAT(ip,'|',port,'|',user) FROM rootwarden.machines WHERE name = '${EPREUVE}'`);
        constate('la machine d\'epreuve en base', cree[0] || '(absente)');
        verifie('la machine est creee avec les valeurs saisies',
            cree.length === 1 && cree[0] === `${IP_EPREUVE}|22|epreuve`,
            cree[0] || '(absente)');

        // ET LES SECRETS SONT CHIFFRES. Un mot de passe de machine stocke en
        // clair serait lisible par toute lecture de la table ; le backend
        // Python attend de son cote un blob `sodium:`.
        const secrets = litEnBase(`SELECT CONCAT(LEFT(password,7),'|',LEFT(root_password,7)) FROM rootwarden.machines WHERE name = '${EPREUVE}'`);
        constate('prefixe des deux secrets stockes', secrets[0] || '(absent)');
        verifie('les deux mots de passe sont chiffres, jamais en clair',
            secrets.length === 1 && secrets[0] === 'sodium:|sodium:',
            secrets[0] || '(absent)');
    });

    // ══ 7. MODIFIER la machine, PAR LE FORMULAIRE ══════════════════════════
    await etape('modifier la machine par le formulaire', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await ouvreOnglet(page);

        const carte = await carteEpreuve(page);
        verifie('la carte de la machine d\'epreuve est trouvee', carte !== null);
        if (! carte) return;

        await carte.evaluate((e) => { e.open = true; });
        await dors(300);

        // On remonte du CHAMP a SON formulaire : le portage porte plusieurs
        // formulaires sur la page, et « le premier bouton submit » en viserait
        // un autre. Six assertions de A2 sont passees pour cette raison.
        const champ = await carte.$(C.editIp);
        verifie('le champ d\'adresse de la carte est atteignable', champ !== null);
        if (! champ) return;

        await champ.click({ clickCount: 3 });
        await champ.press('Backspace');
        await champ.type('192.0.2.78', { delay: 8 });

        const bouton = await carte.$(C.editValide);
        verifie('le bouton d\'enregistrement de CETTE carte est trouve', bouton !== null);
        if (! bouton) return;

        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await bouton.click();
        try { await nav; } catch { /* redirection */ }
        await dors(600);

        const apres = litEnBase(`SELECT ip FROM rootwarden.machines WHERE name = '${EPREUVE}'`);
        verifie('la modification est enregistree', apres.length === 1 && apres[0] === '192.0.2.78',
            apres[0] || '(absente)');
    });

    // ══ 8. RETIRER la machine, PAR LE FORMULAIRE ═══════════════════════════
    await etape('retirer la machine par le formulaire', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await ouvreOnglet(page);

        const carte = await carteEpreuve(page);
        verifie('la carte est retrouvee avant le retrait', carte !== null);
        if (! carte) return;

        await carte.evaluate((e) => { e.open = true; });
        await dors(300);

        const bouton = await carte.$(C.supprime);
        if (! bouton) { verifie('le bouton de retrait est trouve', false); return; }

        // ══ LA CONFIRMATION EST-ELLE SEULEMENT EXECUTABLE ? ════════════════
        //
        // Le legacy rend :
        //     onclick="return confirm('<?= t('servers.confirm_delete',
        //              ['name' => htmlspecialchars(addslashes($server['name']))]) ?>')"
        //
        // `addslashes` protege l'apostrophe du NOM. Rien ne protege les
        // GUILLEMETS DOUBLES que porte la traduction elle-meme :
        // « Supprimer le serveur "X" ? ». Le premier d'entre eux FERME
        // l'attribut HTML, et le navigateur ne recoit que
        // `return confirm('Supprimer le serveur ` — une chaine non terminee.
        //
        // Consequence : le gestionnaire ne s'attache pas, `confirm()` n'est
        // jamais appele, et le formulaire part SANS confirmation. C'est le
        // motif « a moitie corrige » du depot : l'auteur a vu le risque
        // d'injection et n'en a garde qu'une moitie.
        //
        // On mesure la PROPRIETE — la confirmation est-elle exploitable — et
        // non la presence de l'attribut : un `onclick` present mais tronque
        // passerait tous les controles de presence.
        const onclick = await bouton.evaluate((e) => e.getAttribute('onclick'));
        constate('attribut onclick du bouton de retrait', onclick === null ? '(aucun)' : onclick);
        const confirmationTient = onclick === null
            ? C.supprimeConfirme !== null            // le portage : un panneau, pas un `confirm()`
            : /^return confirm\('.*'\)$/.test(onclick);
        verifiePortage('le retrait est precede d\'une confirmation exploitable',
            confirmationTient,
            onclick === null ? '(aucun onclick et aucun panneau)'
                : 'l\'attribut est tronque par le guillemet de la traduction : '
                  + '`confirm()` n\'est jamais appele, la machine part sans confirmation');

        if (C.supprimeConfirme) {
            // LE PORTAGE SEPARE LE GESTE DE SA CONFIRMATION. Le premier clic
            // n'ecrit rien : il OUVRE un panneau qui nomme la consequence — et
            // surtout ce qu'elle n'est pas, la machine n'etant pas touchee.
            await bouton.click();
            await dors(400);
            const avant = compteEnBase(`SELECT COUNT(*) FROM rootwarden.machines WHERE name = '${EPREUVE}'`);
            verifie('ouvrir le panneau de retrait n\'ecrit rien', avant === 1,
                `${avant} ligne(s) — le panneau aurait deja supprime`);

            const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
            await page.click(C.supprimeConfirme);
            try { await nav; } catch { /* redirection */ }
        } else {
            const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
            await bouton.click();
            try { await nav; } catch { /* le `confirm()` natif est accepte par l'ecouteur */ }
        }
        await dors(600);

        const reste = compteEnBase(`SELECT COUNT(*) FROM rootwarden.machines WHERE name = '${EPREUVE}'`);
        verifie('la machine est retiree du parc', reste === 0, `${reste} ligne(s) restante(s)`);
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            // SANS CE CLIC, LA CAPTURE DU LEGACY MONTRE L'ONGLET DES COMPTES.
            // Releve en REGARDANT l'image, pas en lisant le code : la page
            // repond 200, rend du contenu, et ce contenu n'est pas le sujet.
            // Une capture qui montre autre chose que ce qu'on croit est pire
            // qu'une capture absente — elle sert de preuve a un examen qui n'a
            // pas eu lieu.
            await ouvreOnglet(page);
            await page.screenshot({ path: `${dossier}/serveurs-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    verifiePortage('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 2).join(' | '));

} catch (e) {
    // `__archivee__` n'est pas une panne : c'est la sortie NORMALE quand le
    // sujet legacy a ete archive. Le constat a deja tout dit.
    if (String(e && e.message || e).includes('__archivee__')) { /* rien a ajouter */ } else {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
    }
} finally {
    try {
        retireLEpreuve();
        verifie('aucune machine d\'epreuve ne subsiste',
            compteEnBase(`SELECT COUNT(*) FROM rootwarden.machines WHERE name = '${EPREUVE}'`) === 0);
    } catch (e) { note(`FAIL  retrait : ${e.message}`); echecs += 1; }
    try {
        // `srv-zabbix` (id 1) n'a pas ete touchee : on le PROUVE.
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
