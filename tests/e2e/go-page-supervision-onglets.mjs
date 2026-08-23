/**
 * go-page-supervision-onglets.mjs - Module `supervision/`, sous-lot V1 : la page
 * et ses quatre onglets.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/supervision/
 *   laravel  http://localhost:8444/supervision
 *
 * V1 NE MODIFIE RIEN et ne joint aucune machine. Mais — mesure du 2026-08-22 —
 * **il n'est PAS « aucune route » sur le legacy** : la page emet DEUX requetes
 * backend des le chargement, `GET /supervision/profiles?platform=zabbix` et
 * `GET /supervision/profiles/assignments?platform=zabbix`. Le catalogue de profils
 * est donc charge d'emblee, pas a l'ouverture de son onglet, et le decoupage de
 * l'inventaire (« V1 | aucune route ») etait optimiste. Les deux routes sont en
 * LECTURE, donc V1 reste inoffensif — mais le portage, lui, lit la base
 * directement (decision S3/S4) et n'a donc besoin d'AUCUN appel client.
 *
 * CE QUE V1 FERME : UN IDENTIFIANT TECHNIQUE AFFICHE A L'ECRAN.
 *
 * `head.php:76-78` charge `getJsTranslations('js.')` puis fait
 * `_i18n['js.' + key] || _i18n[key] || key`. Une cle absente est donc **retournee
 * telle quelle** — et comme une cle est une chaine NON VIDE, l'idiome
 * `__('x') || 'repli'` **ne declenche jamais son repli**. La panne est silencieuse.
 *
 * Onze cles du module sont dans ce cas. **Une seule est atteignable sans action
 * distante** : `editor_select_server`, le garde qui refuse de lire une config
 * quand aucun serveur n'est choisi. Les dix autres demandent un scan, une lecture
 * SSH, une ecriture ou une action destructrice — leur defaut se LIT dans les
 * catalogues, il ne se declenche pas ici. La suite mesure donc :
 *   - que la cle atteignable ne s'affiche PAS en identifiant (assertion) ;
 *   - qu'AUCUNE des onze n'apparait dans le corps de la page (assertion) ;
 *   - la liste des jetons de forme `mot_avec_underscores` visibles, EN CLAIR dans
 *     le journal (constat), pour qu'une NOUVELLE fuite se remarque a la lecture.
 *
 * Un point que l'inventaire ne dit pas : `confirm_deploy` et `confirm_uninstall`
 * sont passees a `confirm()` NATIF. La convention du portage l'interdit — ces deux
 * cles ne seront donc pas « deplacees » mais **remplacees** par un panneau de
 * decision, en V11 et V12.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-supervision-onglets.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/supervision' : '/supervision/';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';
const SECRET_USER = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';
const SECRET_SUPER = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';

/** Les quatre onglets, dans l'ordre du legacy. */
const ONGLETS = ['config', 'profiles', 'deploy', 'editor'];
/** Les quatre plateformes du bloc de configuration. */
const PLATEFORMES = ['zabbix', 'centreon', 'prometheus', 'telegraf'];
/** Les onze cles absentes du catalogue que le JS charge : aucune ne doit s'afficher. */
const CLES_CASSEES = [
    'backup_restored', 'btn_restore', 'config_loaded', 'config_remote_saved',
    'config_saved', 'confirm_deploy', 'confirm_uninstall', 'editor_select_server',
    'no_backups', 'scan_all_done', 'scan_all_running',
];

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
function verifie(l, ok, d) { lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }
function verifiePortage(l, ok, d) {
    if (CIBLE === 'laravel') return verifie(l, ok, d);
    constate(l, `ecart assume du legacy — ${d}`);
}

/** L'etat du parc : le compte habilite existe-t-il vraiment ? */
const ADMIN_HABILITE = compteEnBase(
    'SELECT COUNT(*) FROM rootwarden.users u JOIN rootwarden.permissions p ON p.user_id = u.id '
    + "WHERE u.active = 1 AND u.name = 'rw-test-admin' AND p.can_manage_supervision = 1");

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});

async function connecte(nom, secret) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };
    await page.goto(`${BASE}${chemins.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    const champ = await page.$('input[name="2fa_code"]');
    if (champ) {
        await champ.type(totp(secret), { delay: 8 });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
    }
    if (chemins.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$('[data-rw="cgu-accepter"]') || await page.$('button[name="accept_terms"]');
        if (b) await b.evaluate(x => x.click());
        try { await nav; } catch {}
    }
    return { ctx, page };
}

try {
    constate('cible', `${CIBLE} — ${PAGE}`);
    verifie('un compte de test porte bien can_manage_supervision',
        ADMIN_HABILITE === 1,
        `rw-test-admin : ${ADMIN_HABILITE === 1 ? 'habilite' : 'NON habilite'}`);

    // ── Un role 1 sans la permission est refuse ─────────────────────────────
    const u = await connecte('rw-test-user', SECRET_USER);
    const refus = await u.page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    constate('role 1 sans can_manage_supervision', `statut ${refus?.status()}`);
    verifie('un role 1 est refuse par un 403 EXACT',
        (refus?.status() ?? 0) === 403, `statut ${refus?.status()}`);
    await u.ctx.close();
    await dors((resteFenetre() + 1) * 1000);

    /* ── UN ROLE 3 PASSE SANS AVOIR LA PERMISSION ────────────────────────────
     * La regle du projet est qu'une permission vaut « cette permission OU
     * superadmin (role 3) ». Elle etait appliquee ici par la garde `perm:` de la
     * route, mais AUCUNE des douze suites du module ne l'exercait : elles se
     * connectent toutes en `rw-test-admin`, qui a la permission.
     *
     * Or `rw-test-super` est role 3 et n'a PAS `can_manage_supervision` (mesure
     * en base). C'est donc le seul compte qui puisse distinguer « la garde laisse
     * passer parce que la permission est la » de « la garde laisse passer parce
     * que le role l'emporte ». Sans lui, un durcissement qui casserait le second
     * chemin passerait inapercu.
     */
    const sup = await connecte('rw-test-super', SECRET_SUPER);
    const acces = await sup.page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    constate('role 3 SANS can_manage_supervision', `statut ${acces?.status()}`);
    verifie('un role 3 passe MEME sans la permission : le role l\'emporte',
        (acces?.status() ?? 0) === 200, `statut ${acces?.status()}`);
    const pageSuper = await sup.page.evaluate(() =>
        document.querySelectorAll('[data-rw="panneau-config"], #tab-config').length > 0);
    verifie('et il obtient bien la PAGE, pas une coquille vide', pageSuper);
    await sup.ctx.close();
    await dors((resteFenetre() + 1) * 1000);

    // ── La page, sous un role 2 habilite ────────────────────────────────────
    const { ctx, page } = await connecte('rw-test-admin', SECRET_ADMIN);
    const erreursJs = [];
    page.on('pageerror', e => erreursJs.push(String(e).split('\n')[0]));
    // Les boites natives sont refusees : la convention du portage les interdit,
    // et elles bloqueraient la suite.
    const dialogues = [];
    page.on('dialog', d => { dialogues.push(d.type()); d.dismiss().catch(() => {}); });
    const appels = [];
    page.on('request', (r) => {
        if (/api_proxy\.php\/|\/api\/gateway\//.test(r.url())) {
            appels.push(r.method() + ' ' + r.url().replace(BASE, '').slice(0, 60));
        }
    });

    const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie a un role 2 habilite',
        (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(3000);

    // COMBIEN D'APPELS AU CHARGEMENT ? Le legacy en fait deux ; le portage lit la
    // base directement (decision S3/S4) et n'en a besoin d'aucun.
    constate('appels backend au chargement',
        appels.length ? `${appels.length} — ${appels.join(' | ')}` : 'aucun');
    verifiePortage('la page se peint sans appel client au backend',
        appels.length === 0,
        `${appels.length} appel(s) : le catalogue de profils est charge d'emblee, `
        + "pas a l'ouverture de son onglet");

    // ── Les quatre onglets ──────────────────────────────────────────────────
    const etat = await page.evaluate(() => ({
        boutons: [...document.querySelectorAll('.tab-btn, [data-rw^="onglet-"]')]
            .map((b) => b.dataset.tab || (b.dataset.rw || '').replace('onglet-', '')),
        actifs: [...document.querySelectorAll('.tab-panel.active, [data-rw^="panneau-"]:not([hidden])')]
            .map((p) => p.id),
    }));
    constate('onglets rendus', `${etat.boutons.join(', ')} · actif : ${etat.actifs.join(', ')}`);
    verifie('les quatre onglets sont rendus, dans l\'ordre',
        etat.boutons.join(',') === ONGLETS.join(','),
        `« ${etat.boutons.join(', ')} » contre « ${ONGLETS.join(', ')} »`);
    verifie('un seul panneau est actif a l\'arrivee',
        etat.actifs.length === 1, `${etat.actifs.length} panneau(x) actif(s)`);

    // Chaque onglet doit basculer, et le portage ne doit RIEN demander pour cela.
    const bascules = [];
    for (const onglet of ONGLETS.slice(1)) {
        appels.length = 0;
        await page.evaluate((t) => {
            (document.querySelector(`.tab-btn[data-tab="${t}"]`)
                || document.querySelector(`[data-rw="onglet-${t}"]`))?.click();
        }, onglet);
        await dors(2000);
        const actifs = await page.evaluate(() =>
            [...document.querySelectorAll('.tab-panel.active, [data-rw^="panneau-"]:not([hidden])')]
                .map((p) => p.id));
        bascules.push({ onglet, actifs, appels: appels.length });
    }
    constate('bascule des onglets',
        bascules.map((b) => `${b.onglet}→${b.actifs.join('+') || 'RIEN'} (${b.appels} appel)`).join(' · '));
    verifie('chaque onglet bascule et laisse un seul panneau actif',
        bascules.every((b) => b.actifs.length === 1),
        bascules.map((b) => `${b.onglet}:${b.actifs.length}`).join(' '));
    verifiePortage('changer d\'onglet n\'emet aucun appel au backend',
        bascules.every((b) => b.appels === 0),
        bascules.filter((b) => b.appels > 0).map((b) => `${b.onglet}:${b.appels}`).join(' ')
            + ' — le legacy recharge le catalogue a chaque bascule');

    // ── Les quatre plateformes : une seule visible ───────────────────────────
    await page.evaluate(() => {
        (document.querySelector('.tab-btn[data-tab="config"]')
            || document.querySelector('[data-rw="onglet-config"]'))?.click();
    });
    await dors(800);
    const plateformes = await page.evaluate((noms) => noms.map((n) => {
        const e = document.getElementById('config-' + n);
        return { nom: n, present: e !== null, visible: e ? e.offsetParent !== null : false };
    }), PLATEFORMES);
    constate('blocs de plateforme',
        plateformes.map((p) => `${p.nom}:${p.present ? (p.visible ? 'visible' : 'masque') : 'ABSENT'}`).join(' · '));
    verifie('les quatre plateformes ont leur bloc, et une seule est visible',
        plateformes.every((p) => p.present) && plateformes.filter((p) => p.visible).length === 1,
        `${plateformes.filter((p) => p.present).length}/4 presents, `
        + `${plateformes.filter((p) => p.visible).length} visible(s)`);

    // ── LE GARDE DE L'EDITEUR : local, et il doit parler francais ────────────
    await page.evaluate(() => {
        (document.querySelector('.tab-btn[data-tab="editor"]')
            || document.querySelector('[data-rw="onglet-editor"]'))?.click();
    });
    await dors(800);
    appels.length = 0;
    const pilote = await page.evaluate(() => {
        if (typeof window.loadRemoteConfig === 'function') { window.loadRemoteConfig(); return 'loadRemoteConfig'; }
        const b = document.querySelector('[data-rw="superv-lire-config"]');
        if (b) { b.click(); return 'bouton du portage'; }
        return null;
    });
    await dors(1800);
    constate('garde « aucun serveur choisi » pilote', pilote || 'aucun point d\'entree');
    verifie('le garde « aucun serveur choisi » n\'emet AUCUN appel distant',
        appels.length === 0, appels.join(' | ') || 'aucun appel');

    /*
     * LE REFUS EST-IL ENONCE ? Sans cette mesure, l'assertion suivante — « aucune
     * cle en identifiant » — passerait aussi pour un garde qui ne dit RIEN : ne
     * rien afficher, c'est n'afficher aucun identifiant. Un test qui ne peut pas
     * echouer occupe la place d'un test.
     *
     * La propriete est la meme des deux cotes, le porteur differe : le legacy la
     * passe a `toast()` (4 s), le portage l'ecrit dans la page. On compare au
     * texte que CHAQUE cible declare comme son refus — cote portage il est lu
     * dans l'ilot de donnees de la page, pour ne pas recopier un catalogue de
     * traduction dans un test.
     */
    const refusEnonce = await page.evaluate((cible) => {
        const attendu = cible === 'laravel'
            ? (JSON.parse(document.getElementById('superv-libelles')?.textContent || '{}')
                .editeur_sans_serveur || '')
            : 'editor_select_server';
        if (attendu === '') return { attendu, vu: false };
        const vu = [...document.querySelectorAll('body *')]
            .some((e) => e.children.length === 0
                && e.offsetParent !== null
                && e.textContent.includes(attendu));
        return { attendu, vu };
    }, CIBLE);
    constate('refus affiche a l\'ecran',
        `${refusEnonce.vu ? 'oui' : 'NON'} — attendu « ${refusEnonce.attendu.slice(0, 60)} »`);
    verifie('le refus « aucun serveur choisi » est ENONCE a l\'ecran',
        refusEnonce.vu, refusEnonce.attendu ? `attendu « ${refusEnonce.attendu.slice(0, 40)} »` : 'aucun texte declare');

    const corps = await page.evaluate(() => document.body.innerText);
    const visibles = CLES_CASSEES.filter((c) => corps.includes(c));
    const jetons = [...new Set(corps.match(/\b[a-z][a-z0-9]*(?:_[a-z0-9]+){1,}\b/g) || [])];
    constate('jetons de forme mot_avec_underscores visibles', jetons.join(', ') || 'aucun');
    constate('cles cassees visibles', visibles.join(', ') || 'aucune');
    verifiePortage('aucune cle de traduction ne s\'affiche en identifiant',
        Boolean(pilote) && visibles.length === 0,
        `${visibles.length} visible(s) : ${visibles.join(', ')} — une cle absente est RETOURNEE, `
        + 'donc non vide, donc `__(x) || repli` ne replie jamais');

    verifie('aucune boite native n\'a ete ouverte',
        dialogues.length === 0, dialogues.join(', ') || 'aucune');
    verifie('aucune erreur JS pendant toute la sequence', erreursJs.length === 0,
        erreursJs.slice(0, 3).join(' · ') || 'aucune');
    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
