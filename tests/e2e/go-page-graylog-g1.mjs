/**
 * go-page-graylog-g1.mjs - `graylog/` sous-lot G1 : configuration, gabarits,
 * onglets et gardes. Les gestes qui MUTENT une machine sont hors de ce sous-lot.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/graylog/index.php
 *   laravel  http://localhost:8444/graylog
 *
 * ══ POURQUOI G1 S'ARRETE AVANT LES BOUTONS DE DEPLOIEMENT ═══════════════════
 *
 * Releve en lisant `backend/routes/graylog.py` et `legacy/graylog/js/graylog.js`
 * AVANT d'ecrire un clic. La page porte deux surfaces de nature differente :
 *
 *   1. la CONFIGURATION et les GABARITS : lectures et ecritures en base, aucune
 *      machine jointe. C'est G1, et c'est ce fichier ;
 *   2. DEPLOY / TEST / UNINSTALL : chacun ouvre une session SSH REELLE et
 *      execute en root (`apt-get install -y rsyslog`, ecriture dans
 *      `/etc/rsyslog.d/`, `logger`, `systemctl restart rsyslog`). C'est G2.
 *
 * Les melanger ferait d'une suite de lecture une suite qui installe des paquets.
 * « Faire moins mais completement » veut dire ceci : G1 mesure entierement sa
 * surface, et ne touche pas l'autre.
 *
 * ══ ⚠ CE QUE G1 NE CLIQUE JAMAIS, ET POURQUOI C'EST ECRIT ICI ══════════════
 *
 * Le tableau de l'onglet « deploy » liste TOUTES les machines non archivees —
 * `srv-zabbix` (id 1, PRODUCTION) comprise — et pose trois boutons par ligne.
 * Deux appellent `confirm()` avant d'agir (`glDeploy` js:90, `glUninstall`
 * js:107). **`glTest` (js:100) n'en a AUCUN** : un seul clic ouvre une session
 * SSH sur la machine de la ligne.
 *
 * Cette suite ouvre donc l'onglet « deploy » — c'est un clic d'onglet, il ne
 * mute rien — mais ne clique AUCUN bouton de ligne. Elle verifie seulement que
 * le tableau se remplit. Un test qui « verrait ce que fait le bouton » sur la
 * ligne de `srv-zabbix` la joindrait pour de vrai.
 *
 * ══ LES DEUX FIXTURES, ET CE QU'ELLES PEUVENT CASSER ═══════════════════════
 *
 *   - la CONFIGURATION est un reglage de FLOTTE : ce qui y est ecrit decide du
 *     comportement de tous les deploiements suivants. La ligne existante est
 *     donc SAUVEGARDEE, modifiee, puis RESTAUREE dans un `finally`, et l'etat
 *     rendu est RELU pour etre prouve ;
 *   - le GABARIT d'epreuve est borne par son NOM. Un `DELETE FROM
 *     graylog_templates` emporterait les quatre gabarits reels.
 *
 * Usage :
 *   cd tests/e2e && node go-page-graylog-g1.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
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

/** Role 3 : il contourne `checkPermission`, donc il atteint la page. */
const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
/** Role 2 SANS `can_manage_graylog` — chemin « permission ». */
const COMPTE_ROLE = 'rw-test-admin';
const SECRET_ROLE = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';
/** Role 1 — chemin « role ». D-5 : lecture seule. */
const COMPTE_BAS = 'rw-test-user';
const SECRET_BAS = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';

/** Le nom d'epreuve borne le nettoyage. Aucun gabarit reel ne le porte. */
const GABARIT = 'epreuve-e2e-g1';
/** L'hote d'epreuve : il ne resout pas, et c'est voulu. */
const HOTE_EPREUVE = 'epreuve-e2e.invalid';

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion?lang=fr',
        page: '/graylog',
        onglet: (n) => `[data-rw="graylog-onglet-${n}"]`,
        panneau: (n) => `[data-rw="graylog-panneau-${n}"]`,
        hote: '[data-rw="graylog-hote"]',
        port: '[data-rw="graylog-port"]',
        protocole: '[data-rw="graylog-protocole"]',
        enregistrerConfig: '[data-rw="graylog-config-enregistrer"]',
        etatConfig: '[data-rw="graylog-config-etat"]',
        serveurs: '[data-rw="graylog-serveurs"]',
        gabaritNom: '[data-rw="graylog-gabarit-nom"]',
        gabaritContenu: '[data-rw="graylog-gabarit-contenu"]',
        gabaritActive: '[data-rw="graylog-gabarit-active"]',
        gabaritEnregistrer: '[data-rw="graylog-gabarit-enregistrer"]',
        gabaritSupprimer: '[data-rw="graylog-gabarit-supprimer"]',
        gabaritConfirmer: '[data-rw="graylog-gabarit-confirmer"]',
        listeGabarits: '[data-rw="graylog-gabarits"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/graylog/index.php',
        onglet: (n) => `.tab-btn[data-tab="${n}"]`,
        panneau: (n) => `.tab-panel[data-panel="${n}"]`,
        hote: '#gl-host',
        port: '#gl-port',
        protocole: '#gl-proto',
        enregistrerConfig: 'button[onclick="glSaveConfig()"]',
        etatConfig: '#gl-config-status',
        serveurs: '#gl-servers-container',
        gabaritNom: '#gl-tpl-name',
        gabaritContenu: '#gl-tpl-editor',
        gabaritActive: '#gl-tpl-enabled',
        gabaritEnregistrer: 'button[onclick="glSaveTemplate()"]',
        gabaritSupprimer: 'button[onclick="glDeleteTemplate()"]',
        gabaritConfirmer: null,
        listeGabarits: '#gl-templates-list',
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
 note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
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

/* ── Etat en base, lu et non suppose ──────────────────────────────────────── */

function configEnBase() {
    const r = litEnBase("SELECT CONCAT(server_host,'|',server_port,'|',protocol) "
        + 'FROM rootwarden.graylog_config WHERE id = 1');

    return r[0] || '(absente)';
}
function compteGabaritEpreuve() {
    return compteEnBase(
        `SELECT COUNT(*) FROM rootwarden.graylog_templates WHERE name = '${GABARIT}'`);
}
function compteGabaritsReels() {
    return compteEnBase(
        `SELECT COUNT(*) FROM rootwarden.graylog_templates WHERE name <> '${GABARIT}'`);
}
function supprimeGabaritEpreuve() {
    litEnBase(`DELETE FROM rootwarden.graylog_templates WHERE name = '${GABARIT}'`);
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
    const boitesNatives = [];
    page.on('dialog', async (d) => {
        boitesNatives.push(`${d.type()}: ${d.message().slice(0, 60)}`);
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

/** Le panneau est-il VISIBLE ? On mesure le rendu, jamais l'attribut. */
function panneauVisible(page, nom) {
    return page.evaluate((sel) => {
        const e = document.querySelector(sel);
        if (! e) return null;
        const s = getComputedStyle(e);

        return s.display !== 'none' && s.visibility !== 'hidden' && e.offsetHeight > 0;
    }, C.panneau(nom));
}

/*
 * ══ OUVRIR UN ONGLET, ET S'ASSURER QU'IL EST OUVERT ══════════════════════
 *
 * Une attente FIXE apres un clic d'onglet tient quand la suite tourne seule et
 * lache autrement. Mesure du LOT du 2026-08-28 : deux etapes GABARIT en
 * « Node is either not clickable » — l'onglet n'etait pas ouvert, donc le champ
 * existait sans etre atteignable.
 *
 * CE QUI A ETE ECARTE PAR LA MESURE, et qu'il faut savoir pour ne pas y revenir :
 *   - la charge — la suite echoue AUSSI machine au repos ;
 *   - le pied de page neuf — mesure `position: static`, y=1317, il ne recouvre rien ;
 *   - une erreur JS — aucune ;
 *   - le contrat DOM — `data-rw` ET `data-onglet` poses, panneau `id` correspondant ;
 *   - la page elle-meme — sonde isolee : le clic fait passer `hidden` a `false`,
 *     le champ prend 45 px. **La page est SAINE.**
 * L'ouverture echoue seulement APRES l'enregistrement de configuration.
 *
 * On n'attend donc pas une DUREE mais la PROPRIETE — le panneau est visible —
 * et l'on RE-CLIQUE tant qu'elle n'est pas obtenue : c'est le GESTE qui peut
 * avoir ete perdu, pas seulement son effet. Et l'ouverture devient une
 * assertion a part entiere : un onglet qui ne s'ouvre pas doit se voir comme
 * tel, jamais se deguiser en « element non cliquable » vingt lignes plus loin.
 */
async function ouvreOnglet(page, nom, borneMs = 8000) {
    const limite = Date.now() + borneMs;
    let visible = await panneauVisible(page, nom);
    while (! visible && Date.now() < limite) {
        /*
         * ══ AMENER LE BOUTON AU CENTRE AVANT DE CLIQUER ══════════════════
         *
         * E-241 est clos, et ce n'etait NI le JS de la page NI un enchainement :
         * **la sequence fait defiler la page de 480 px**, le bouton d'onglet
         * remonte a `y = -7`, et **l'EN-TETE COLLANT intercepte le clic**.
         * `elementFromPoint` a nomme le coupable :
         *
         *     AVANT  rect.y = 473  scroll =   0  recu = « templates »
         *     APRES  rect.y =  -7  scroll = 480  recu = « **rw-entete** »
         *
         * Le clic par `evaluate` reussissait — il n'emprunte pas les
         * coordonnees ; celui par coordonnees echouait. C'est ce qui a separe
         * « le gestionnaire est perdu » de « le clic n'arrive pas ».
         *
         * Le defilement automatique de Puppeteer ne suffit pas : il amene
         * l'element au bord (`block: 'start'`), donc **sous** l'en-tete. C'est
         * exactement le piege des captures deja paye — *`'start'` glisse la
         * section sous l'en-tete collant, `'center'` non.*
         *
         * ⚠ ET LE DEFAUT D'INTERFACE RESTE, LUI : un exploitant qui a defile
         * voit la barre d'onglets passer sous l'en-tete, et son clic atteint
         * l'en-tete. Il s'en sort en remontant ; la suite, elle, ne le voyait
         * pas. **Corriger la mesure ne corrige pas la page** — signale a part.
         */
        try {
            await page.evaluate((sel) => {
                const b = document.querySelector(sel);
                if (b) b.scrollIntoView({ block: 'center', behavior: 'instant' });
            }, C.onglet(nom));
            await dors(120);
            await page.click(C.onglet(nom));
        } catch { /* pas encore cliquable : on retentera */ }
        await dors(250);
        visible = await panneauVisible(page, nom);
    }

    return visible === true;
}

/** Attendre qu'un conteneur cesse d'afficher « chargement » ET se stabilise. */
async function attendCharge(page, selecteur) {
    let precedent = null;
    for (let i = 0; i < 40; i += 1) {
        const t = await page.evaluate((s) => {
            const e = document.querySelector(s);

            return e ? (e.textContent || '').replace(/\s+/g, ' ').trim() : null;
        }, selecteur);
        if (t !== null && ! /chargement|loading/i.test(t) && t === precedent) return t;
        precedent = t;
        await dors(250);
    }

    return precedent;
}

const configOrigine = configEnBase();
const gabaritsReelsAuDepart = compteGabaritsReels();
const gabaritEpreuveAuDepart = compteGabaritEpreuve();

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

    constate('cible', `${CIBLE} — ${BASE}`);
    constate('configuration en base au depart', configOrigine);
    constate('gabarits reels au depart', `${gabaritsReelsAuDepart}`);
    verifie('la configuration existe — sinon la page n\'a rien a montrer',
        configOrigine !== '(absente)', configOrigine);
    verifie('aucun gabarit d\'epreuve ne traine', gabaritEpreuveAuDepart === 0,
        `${gabaritEpreuveAuDepart}`);
    litEnBase('DELETE FROM rootwarden.login_attempts');

    const s = await connecte(COMPTE, SECRET);

    await etape('la page est servie au role 3', async () => {
        const r = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        constate('statut', `HTTP ${r ? r.status() : 0}`);
        verifie('la page graylog est servie', r && r.status() === 200,
            `HTTP ${r ? r.status() : 0} — ${s.page.url().replace(BASE, '')}`);
    });

    await etape('LA CONFIGURATION EST PRE-REMPLIE depuis la base', async () => {
        /*
         * Le champ doit porter la valeur REELLE, pas son gabarit vide : une page
         * qui affiche un formulaire vierge ferait croire qu'aucun transfert n'est
         * configure, et le premier enregistrement effacerait la configuration de
         * la flotte sans que personne l'ait voulu.
         */
        await dors(1200);
        const lu = await s.page.evaluate((h, p, pr) => ({
            hote: (document.querySelector(h) || {}).value,
            port: (document.querySelector(p) || {}).value,
            protocole: (document.querySelector(pr) || {}).value,
        }), C.hote, C.port, C.protocole);
        constate('champs rendus', `${lu.hote} : ${lu.port} / ${lu.protocole}`);
        const attendu = configOrigine.split('|');
        verifie('l\'hote affiche est celui de la base', lu.hote === attendu[0],
            `affiche « ${lu.hote} », base « ${attendu[0]} »`);
        verifie('le port affiche est celui de la base', String(lu.port) === attendu[1],
            `affiche « ${lu.port} », base « ${attendu[1]} »`);
        verifie('le protocole affiche est celui de la base', lu.protocole === attendu[2],
            `affiche « ${lu.protocole} », base « ${attendu[2]} »`);
    });

    await etape('LES QUATRE ONGLETS BASCULENT AU CLIC', async () => {
        for (const nom of ['deploy', 'templates', 'history', 'config']) {
            await s.page.click(C.onglet(nom));
            await dors(600);
            const visible = await panneauVisible(s.page, nom);
            verifie(`l'onglet « ${nom} » ouvre son panneau`, visible === true,
                `visible=${visible}`);
        }
    });

    await etape('LE TABLEAU DES MACHINES SE REMPLIT — sans cliquer une seule ligne', async () => {
        /*
         * ⚠ On ouvre l'onglet et on lit. On ne clique AUCUN bouton de ligne :
         * `glTest` n'a pas de `confirm()` et ouvrirait une session SSH sur la
         * machine de la ligne — `srv-zabbix` figure dans ce tableau.
         */
        await s.page.click(C.onglet('deploy'));
        const texte = await attendCharge(s.page, C.serveurs);
        constate('tableau des machines', (texte || '').slice(0, 120));
        verifie('le tableau nomme les machines du parc',
            !! texte && /test-server|Test-Server/i.test(texte), (texte || '').slice(0, 120));
        /* La machine de production DOIT y figurer : c'est le legacy tel qu'il
         * est, et c'est justement pourquoi aucun bouton de ligne n'est clique. */
        constate('srv-zabbix est bien dans le tableau',
            /srv-zabbix/i.test(texte || '') ? 'oui — aucun bouton de sa ligne n\'est touche' : 'non');
    });

    await etape('ECRITURE DE LA CONFIGURATION : au clavier, puis verifiee EN BASE', async () => {
        await s.page.click(C.onglet('config'));
        await dors(500);
        const champ = await s.page.$(C.hote);
        await champ.click({ clickCount: 3 });
        await champ.type(HOTE_EPREUVE, { delay: 20 });
        await s.page.click(C.enregistrerConfig);
        await dors(1500);

        const apres = configEnBase();
        constate('configuration apres enregistrement', apres);
        verifie('l\'hote saisi est ECRIT en base', apres.split('|')[0] === HOTE_EPREUVE,
            `base « ${apres.split('|')[0] }», saisi « ${HOTE_EPREUVE} »`);
        verifie('le port et le protocole ne sont pas emportes',
            apres.split('|')[1] === configOrigine.split('|')[1]
            && apres.split('|')[2] === configOrigine.split('|')[2],
            `${apres} contre ${configOrigine}`);
    });

    await etape('UN HOTE VIDE est refuse SANS ecrire', async () => {
        /*
         * La propriete mesuree est « rien n'a change en base », pas « un message
         * est apparu » : un refus qui ecrit quand meme serait un defaut que le
         * message masquerait.
         */
        const avant = configEnBase();
        const champ = await s.page.$(C.hote);
        await champ.click({ clickCount: 3 });
        await s.page.keyboard.press('Backspace');
        await s.page.click(C.enregistrerConfig);
        await dors(1200);
        const apres = configEnBase();
        constate('etat de la configuration', `${avant} -> ${apres}`);
        verifie('un hote vide n\'ecrit rien', apres === avant, `${avant} -> ${apres}`);
    });

    await etape('GABARIT : creation par clics, puis verifiee EN BASE', async () => {
        verifie('l\'onglet des gabarits s\'ouvre', await ouvreOnglet(s.page, 'templates'),
            'le panneau des gabarits ne s\'affiche pas — tout clic suivant echouerait '
            + 'en « not clickable », vingt lignes plus loin et sans dire pourquoi');
        const nom = await s.page.$(C.gabaritNom);
        await nom.click({ clickCount: 3 });
        await nom.type(GABARIT, { delay: 15 });
        const contenu = await s.page.$(C.gabaritContenu);
        await contenu.click();
        await contenu.type('# gabarit d\'epreuve e2e\n*.info @@127.0.0.1:1514\n', { delay: 5 });
        await s.page.click(C.gabaritEnregistrer);
        await dors(1500);

        const n = compteGabaritEpreuve();
        constate('gabarits d\'epreuve en base', `${n}`);
        verifie('la creation ecrit UN gabarit', n === 1, `${n}`);
        verifie('les gabarits reels ne sont pas touches',
            compteGabaritsReels() === gabaritsReelsAuDepart,
            `${gabaritsReelsAuDepart} -> ${compteGabaritsReels()}`);

        const liste = await attendCharge(s.page, C.listeGabarits);
        verifie('il apparait dans la liste', !! liste && liste.includes(GABARIT),
            (liste || '').slice(0, 120));
    });

    await etape('GABARIT : suppression par clics, et il disparait vraiment', async () => {
        /*
         * Le bouton vit DANS le panneau des gabarits : si l'onglet s'est referme
         * entre-temps, le clic echoue en « not clickable » — et l'echec de cette
         * etape n'etait qu'une CONSEQUENCE de celui de la creation. On reouvre
         * par la propriete plutot que de supposer l'etat laisse par l'etape
         * precedente : **une suite ne doit pas dependre d'un etat qu'elle n'a
         * pas verifie.**
         */
        verifie('l\'onglet des gabarits est encore ouvert', await ouvreOnglet(s.page, 'templates'),
            'le panneau s\'est referme depuis la creation');
        if (CIBLE === 'laravel') {
            await s.page.click(C.gabaritSupprimer);
            await s.page.waitForSelector(C.gabaritConfirmer, { visible: true, timeout: 8000 });
            await s.page.click(C.gabaritConfirmer);
        } else {
            /* Le legacy pose un `confirm()` : le gestionnaire de dialogue
             * l'accepte, et c'est justement l'ecart mesure plus bas. */
            await s.page.click(C.gabaritSupprimer);
        }
        await dors(1600);
        const reste = compteGabaritEpreuve();
        verifie('la suppression retire le gabarit de la base', reste === 0, `${reste}`);
        verifie('et elle n\'emporte aucun gabarit reel',
            compteGabaritsReels() === gabaritsReelsAuDepart,
            `${gabaritsReelsAuDepart} -> ${compteGabaritsReels()}`);
    });

    await etape('LES BOITES NATIVES, et ce que le portage doit faire a la place', async () => {
        constate('boites natives rencontrees', s.boitesNatives.length
            ? s.boitesNatives.join(' | ') : 'aucune');
        verifiePortage('aucune boite native : la decision se prend EN PAGE',
            s.boitesNatives.length === 0,
            'le legacy pose `confirm()` pour supprimer un gabarit, et `alert()` pour '
            + 'rendre le resultat — la boite recouvre la ligne, ne se style pas, et BLOQUE Puppeteer');
    });

    /*
     * LA PROPRIETE DE LA MARGE DE DEFILEMENT A ETE DEPLACEE VERS
     * `go-socle-navigation`. Elle mesure `.rw-entete` et `html`, qui sont
     * GLOBAUX : la loger ici etait un accident de decouverte — E-241 l'a
     * revelee sur cette page — pas un choix. **Une assertion appartient a la
     * couche qu'elle mesure, pas a celle ou on l'a trouvee.**
     *
     * Et elle y est moins fragile : `graylog/` peut etre archive, et cette suite
     * ne rendrait plus que son constat d'archivage — c'est arrive a `services/`,
     * dont les trois suites sont passees de 19/14/18 a 5 sans qu'aucun rouge ne
     * le signale. Aucun emplacement n'est permanent ; une suite du socle est
     * seulement beaucoup moins susceptible de disparaitre.
     */
    await etape('aucune erreur JS', async () => {
        verifie('aucune erreur JS pendant la sequence', s.erreursJs.length === 0,
            s.erreursJs.join(' | ') || 'aucune');
    });

    /* ══ LES DEUX CHEMINS DE LA GARDE ══════════════════════════════════════ */
    await etape('un role 2 SANS la permission est refuse', async () => {
        const r2 = await connecte(COMPTE_ROLE, SECRET_ROLE);
        const r = await r2.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const statut = r ? r.status() : 0;
        constate('role 2 sans can_manage_graylog', `HTTP ${statut}`);
        verifie('le role seul ne suffit pas : la permission est exigee', statut === 403,
            `HTTP ${statut}`);
    });

    await etape('un role 1 est refuse', async () => {
        const r1 = await connecte(COMPTE_BAS, SECRET_BAS);
        const r = await r1.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const statut = r ? r.status() : 0;
        constate('role 1', `HTTP ${statut}`);
        verifie('un compte de role 1 est refuse', statut === 403, `HTTP ${statut}`);
    });
} catch (e) {
    // `__archivee__` n'est pas une panne : c'est la sortie NORMALE quand le
    // sujet legacy a ete archive. Le constat a deja tout dit.
    if (String(e && e.message || e).includes('__archivee__')) { /* rien a ajouter */ } else {
    verifie('deroulement de la suite', false, String(e).split('\n')[0]);
    }
} finally {
    for (const ctx of contextes) { try { await ctx.close(); } catch {} }
    try { await navigateur.close(); } catch {}
    /*
     * RESTAURATION, PUIS RELECTURE POUR PREUVE.
     *
     * La configuration est un reglage de FLOTTE : la laisser sur
     * `epreuve-e2e.invalid` ferait ecrire cette valeur dans les confs rsyslog du
     * prochain deploiement. Le gabarit d'epreuve, lui, serait POUSSE sur les
     * machines au prochain deploiement s'il restait active.
     */
    try {
        const [h, p, pr] = configOrigine.split('|');
        if (configOrigine !== '(absente)') {
            litEnBase('UPDATE rootwarden.graylog_config SET '
                + `server_host = '${h}', server_port = ${parseInt(p, 10)}, protocol = '${pr}' `
                + 'WHERE id = 1');
        }
        supprimeGabaritEpreuve();
        litEnBase('DELETE FROM rootwarden.login_attempts');
    } catch (e) {
        note(`FAIL  nettoyage de la fixture  — ${String(e.message || e).split('\n')[0]}`);
        echecs++;
    }
    const rendu = configEnBase();
    verifie('la configuration de flotte est RESTAUREE', rendu === configOrigine,
        rendu === configOrigine ? 'identique a l\'entree'
            : `DIFFERENTE — « ${rendu} » au lieu de « ${configOrigine} »`);
    verifie('aucun gabarit d\'epreuve ne subsiste', compteGabaritEpreuve() === 0,
        `${compteGabaritEpreuve()}`);
    verifie('les gabarits reels sont intacts', compteGabaritsReels() === gabaritsReelsAuDepart,
        `${gabaritsReelsAuDepart} a l'entree, ${compteGabaritsReels()} a la sortie`);
}

note('');
note(`${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — ${etapes} etapes, cible ${CIBLE}`);
process.exit(echecs === 0 ? 0 : 1);
