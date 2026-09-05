/**
 * go-page-supervision-editeur.mjs - Module `supervision/`, sous-lot V7 :
 * l'editeur de configuration distant, EN LECTURE. Deuxieme sous-lot SSH.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/supervision/   (onglet « Editeur de configuration »)
 *   laravel  http://localhost:8444/supervision     (panneau `panneau-editor`)
 *
 * ══ CE QUE LA LECTURE DU CODE A ETABLI AVANT LE MOINDRE CLIC ══
 *
 *  1. **LES DEUX COMMANDES DISTANTES SONT DES LECTURES PURES** :
 *       cat <chemin> 2>/dev/null || echo 'FILE_NOT_FOUND'          (config/read)
 *       LC_ALL=C ls -la <dir>/<fichier>.bak.* 2>/dev/null || echo 'NONE'  (backups)
 *     Rien n'ecrit, rien ne redemarre. `LC_ALL=C` fixe le format de `ls` — sans
 *     lui, la locale du serveur changerait les colonnes que le backend analyse.
 *
 *  2. **LES DEUX ROUTES SONT BIEN GARDEES** — troisieme exoneration d'affilee
 *     dans ce module : `@require_api_key` + `@require_role(2)` +
 *     `@require_permission('can_manage_supervision')` + `@require_machine_access`.
 *
 *  3. **UN FICHIER ABSENT REND 404, ET LE MESSAGE NOMME LE CHEMIN.** Le backend
 *     distingue donc bien « absent » d'« erreur interne » (500). Et
 *     `supervisionFetch` lit `res.ok` : le refus n'est pas avale.
 *
 * ══ LA DECOUVERTE CENTRALE : LE CHEMIN AFFICHE N'EST PAS LE CHEMIN LU ══
 *
 * L'ecran affiche `CONFIG_PATHS[plateforme]`, **ecrit en dur cote client**
 * (`main.js:27-32`) : pour Zabbix, toujours `/etc/zabbix/zabbix_agent2.conf`.
 * Le backend, lui, calcule `_config_file_path(agent_type)` a partir de
 * `supervision_config.agent_type` **en base** (`supervision.py:281-287`) :
 *   agent_type = 'zabbix-agent'  ->  /etc/zabbix/zabbix_agentd.conf
 *   sinon                        ->  /etc/zabbix/zabbix_agent2.conf
 *
 * Donc des que la configuration globale designe l'agent historique, **la page
 * nomme un fichier et le portail en lit un autre**. Un exploitant croit editer
 * `zabbix_agent2.conf` et voit le contenu de `zabbix_agentd.conf`. La meme
 * derive vaut pour la liste des sauvegardes, qui derive du meme chemin.
 *
 * La suite le mesure de la facon la plus directe : elle pose `agent_type =
 * 'zabbix-agent'` en base ET le fichier `zabbix_agentd.conf` sur la machine de
 * test, puis compare **le chemin affiche** au **chemin rendu par la lecture**.
 *
 * ══ CE QU'UN EDITEUR MONTRE LEGITIMEMENT ══
 *
 * Le fichier de fixture porte un `TLSPSKIdentity` et une cle : un `.conf` d'agent
 * PEUT contenir un secret. **Ce n'est pas une fuite** — un editeur existe pour
 * montrer le fichier qu'on edite, et le cacher le rendrait inutile. Il faut le
 * dire ainsi plutot que d'accuser. Ce qui se mesure, c'est que le portage ne
 * recopie PAS ce contenu ailleurs : ni dans un ilot de donnees, ni dans un
 * attribut, ni dans un journal — seulement dans la zone d'edition.
 *
 * ══ SURETE ══
 *
 * Cible : **Test-Server-Debian (id 2**, DEV). **`srv-zabbix` (id 1) est en
 * PRODUCTION et n'est jamais jointe.** Deux fixtures, toutes deux nettoyees dans
 * un `finally` avec l'etat restaure ANNONCE : une ligne `supervision_config` en
 * base, et deux fichiers dans le conteneur `rootwarden_test_server`. Verifie en
 * V3 : le scheduler ne lit AUCUNE table de supervision.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-supervision-editeur.mjs
 */
import puppeteer from 'puppeteer';
import { execFileSync } from 'child_process';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/supervision' : '/supervision/';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

const MACHINE_DEV = 2;
const MARQUE = 'rw-e2e-v7';
/** Le conteneur qui joue Test-Server-Debian. */
const CONTENEUR = 'rootwarden_test_server';
/**
 * LE CHEMIN QUE LE BACKEND LIRA, une fois `agent_type = 'zabbix-agent'` pose.
 * Le client, lui, affichera toujours `zabbix_agent2.conf` : c'est tout le sujet.
 */
const CHEMIN_LU = '/etc/zabbix/zabbix_agentd.conf';
const CHEMIN_AFFICHE = '/etc/zabbix/zabbix_agent2.conf';
/** Une ligne reconnaissable du fichier, et un secret que l'editeur MONTRE. */
const LIGNE_REPERE = `Hostname=${MARQUE}-repere`;
const IDENTITE_PSK = `${MARQUE}-psk-identity`;

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
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
 lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }
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

    if (CIBLE === 'laravel') return verifie(l, ok, d);
    constate(l, `ecart assume du legacy — ${d}`);
}

/**
 * Une commande dans le conteneur de test.
 *
 * `execFileSync` recoit un TABLEAU : le contenu du fichier porte des `=` et des
 * guillemets, et un shell intermediaire les interpreterait. Pas de `sudo` ici —
 * les suites appellent `docker` directement, comme `lib-base.mjs`.
 */
function dansLeConteneur(...args) {
    return execFileSync('docker', ['exec', CONTENEUR, ...args], { encoding: 'utf-8' });
}

function poseLesFichiers() {
    dansLeConteneur('mkdir', '-p', '/etc/zabbix');
    dansLeConteneur('sh', '-c',
        `printf '%s\\n' '# fixture ${MARQUE}' '${LIGNE_REPERE}' `
        + `'TLSPSKIdentity=${IDENTITE_PSK}' 'TLSPSKFile=/etc/zabbix/psk.key' > ${CHEMIN_LU}`);
    // Une sauvegarde, pour que la liste ne soit pas vide : le backend cherche
    // `<fichier>.bak.*` dans le meme repertoire.
    dansLeConteneur('sh', '-c', `printf '%s\\n' '# sauvegarde ${MARQUE}' > ${CHEMIN_LU}.bak.20260101_000000`);
}

function retireLesFichiers() {
    try {
        const restants = dansLeConteneur('sh', '-c',
            `ls -1 ${CHEMIN_LU} ${CHEMIN_LU}.bak.* 2>/dev/null | wc -l`).trim();
        dansLeConteneur('sh', '-c', `rm -f ${CHEMIN_LU} ${CHEMIN_LU}.bak.*`);
        return restants;
    } catch {
        return 'conteneur injoignable';
    }
}

function nettoieBase() {
    const n = compteEnBase(
        `SELECT COUNT(*) FROM rootwarden.supervision_config WHERE zabbix_server LIKE '${MARQUE}%'`);
    litEnBase(`DELETE FROM rootwarden.supervision_config WHERE zabbix_server LIKE '${MARQUE}%'`);
    return n;
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});

async function connecte(langue) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };
    await page.goto(`${BASE}${chemins.connexion}?lang=${langue}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', 'rw-test-admin', { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    const champ = await page.$('input[name="2fa_code"]');
    if (champ) {
        await champ.type(totp(SECRET_ADMIN), { delay: 8 });
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

async function ouvreEditeur(page) {
    await page.evaluate(() => {
        (document.querySelector('.tab-btn[data-tab="editor"]')
            || document.querySelector('[data-rw="onglet-editor"]'))?.click();
    });
    await dors(1500);
}

/**
 * L'OBSERVATEUR DES MESSAGES, installe AVANT le geste — lecon de V6 : `toast()`
 * dure 4 s et une session SSH en demande davantage, donc le message a disparu
 * quand son effet devient constatable. On relit le porte-messages ENTIER, jamais
 * le noeud ajoute : l'icone y arrive avant le texte.
 */
async function observeLesMessages(page) {
    await page.evaluate(() => {
        window.__rwMessages = [];
        const collecte = () => {
            for (const sel of ['#toast-container', '[data-rw="superv-editeur-message"]']) {
                const e = document.querySelector(sel);
                const t = (e?.innerText || '').trim();
                if (t) { window.__rwMessages.push(t.slice(0, 300)); }
            }
        };
        new MutationObserver(collecte)
            .observe(document.body, { childList: true, subtree: true, characterData: true });
    });
}

try {
    /*
     * MODULE ARCHIVE ? Cote legacy, `supervision/` a ete porte en douze
     * sous-lots (V1 a V12) puis deplace dans `legacy/_deprecated/`. Ses URL
     * rendent 404 : ce n'est pas un echec, c'est l'aboutissement du portage. Le
     * test le CONSTATE — et verifie surtout que le menu du legacy mene desormais
     * au portage, sans quoi on aurait installe soi-meme un 404 dans un menu.
     *
     * Le constat vient AVANT toute fixture : rien n'est pose, donc rien n'est a
     * defaire, et `process.exit()` peut court-circuiter le `finally`.
     *
     * Les TROIS fichiers du module sont sondes, pas un echantillon. Et ce sont
     * les fichiers REELS : sonder un chemin qui n'a jamais existe rend 404 et
     * fait passer l'assertion pour rien.
     *
     * Tant que le module est servi, ce bloc est inerte et la suite se joue.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE,
            chemin: '/supervision/',
            fichiers: [
                '/supervision/index.php',
                '/supervision/js/main.js',
                '/supervision/js/profiles.js',
            ],
            verifie, constate,
        });
        if (archivee) {
            const { ctx, page } = await connecte('fr');
            await verifieMenuLegacy(page, '/supervision', verifie, constate);
            await ctx.close();
            console.log(lignes.join('\n'));
            console.log(`\n${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
            await navigateur.close();
            process.exit(echecs > 0 ? 1 : 0);
        }
    }

    constate('cible', `${CIBLE} — ${PAGE}`);
    constate('fixtures nettoyees a l\'entree',
        `base : ${nettoieBase()} ligne(s), conteneur : ${retireLesFichiers()} fichier(s)`);

    /*
     * LA FIXTURE EN DEUX MOITIES, et l'ordre compte : la ligne de base decide
     * QUEL fichier le backend lira, le fichier decide de ce qu'il trouvera.
     * `agent_type = 'zabbix-agent'` fait viser `zabbix_agentd.conf`, alors que
     * l'ecran du legacy affichera toujours `zabbix_agent2.conf`.
     */
    litEnBase(
        'INSERT INTO rootwarden.supervision_config '
        + '(platform, agent_type, agent_version, zabbix_server, listen_port, hostname_pattern) '
        + `VALUES ('zabbix', 'zabbix-agent', '7.0', '${MARQUE}-serveur.example', 10050, '{machine.name}')`);
    poseLesFichiers();
    const posees = dansLeConteneur('sh', '-c',
        `ls -1 ${CHEMIN_LU} ${CHEMIN_LU}.bak.* 2>/dev/null | wc -l`).trim();
    constate('fixture posee', `agent_type=zabbix-agent, ${posees} fichier(s) dans le conteneur`);
    verifie('la fixture est en place — sans elle, ni la lecture ni la derive de '
        + 'chemin ne se mesurent',
        Number(posees) === 2, `${posees} fichier(s) attendus 2`);

    const { ctx, page } = await connecte('fr');
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const dialogues = [];
    page.on('dialog', (d) => { dialogues.push(`${d.type()}: ${d.message().slice(0, 60)}`); d.dismiss().catch(() => {}); });
    const appels = [];
    page.on('request', (r) => {
        if (/api_proxy\.php\/|\/api\/gateway\//.test(r.url())) {
            appels.push(r.method() + ' ' + r.url().replace(BASE, '').slice(0, 70));
        }
    });

    const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie', (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(2000);
    await ouvreEditeur(page);

    // ── Le chemin AFFICHE, avant tout geste ─────────────────────────────────
    const cheminAffiche = await page.evaluate(() => {
        const e = document.getElementById('editor-file-path-badge')
            || document.querySelector('[data-rw="superv-editeur-chemin"]');
        return (e?.innerText || '').trim();
    });
    constate('chemin affiche par la page', cheminAffiche || 'aucun');
    verifie('la page annonce un chemin de fichier', cheminAffiche !== '', cheminAffiche || 'aucun');

    // ── LE GESTE : choisir la machine de DEV, puis lire ──────────────────────
    await observeLesMessages(page);
    appels.length = 0;
    const geste = await page.evaluate((idDev) => {
        const selecteur = document.getElementById('editor-server')
            || document.querySelector('[data-rw="superv-serveur"]');
        if (! selecteur) return null;
        selecteur.value = String(idDev);
        selecteur.dispatchEvent(new Event('change', { bubbles: true }));
        const bouton = document.querySelector('[data-rw="superv-lire-config"]')
            || document.querySelector('[onclick*="loadRemoteConfig"]');
        if (! bouton) return { choisi: true, declenche: null };
        bouton.click();
        return { choisi: true, declenche: 'clic sur le bouton de lecture' };
    }, MACHINE_DEV);
    constate('geste', geste ? (geste.declenche ?? 'bouton introuvable') : 'selecteur introuvable');
    verifie('la lecture a un point d\'entree atteignable au clic',
        Boolean(geste?.declenche), geste?.declenche ?? 'aucun');

    await dors(9000);
    const appelsLecture = appels.slice();
    constate('appels emis par la lecture',
        appelsLecture.length ? appelsLecture.join(' | ') : 'aucun');
    /*
     * AUCUNE ECRITURE N'A PU PARTIR. `config/save` est la route voisine, et c'est
     * elle qui ecrit sur la machine puis redemarre l'agent : mesurer qu'elle n'a
     * pas ete appelee vaut mieux que de le supposer.
     */
    const ecritures = appelsLecture.filter((a) => /save|restore|uninstall|deploy|reconfigure/i.test(a));
    verifie('AUCUN appel d\'ecriture, de restauration ni de deploiement n\'est parti',
        ecritures.length === 0, ecritures.join(' | ') || 'aucun');
    verifie('l\'appel de lecture est bien parti',
        appelsLecture.some((a) => /config\/read/i.test(a)),
        appelsLecture.join(' | ') || 'aucun appel');

    // ── LE CONTENU EST-IL LA, ET D'OU VIENT-IL ? ────────────────────────────
    const etat = await page.evaluate(() => {
        const zone = document.getElementById('editor-content')
            || document.querySelector('[data-rw="superv-editeur-contenu"]');
        const chemin = document.getElementById('editor-path')
            || document.querySelector('[data-rw="superv-editeur-chemin-lu"]');
        return {
            contenu: (zone?.value ?? zone?.innerText ?? ''),
            cheminLu: (chemin?.innerText || '').trim(),
            messages: window.__rwMessages || [],
        };
    });
    constate('chemin rendu par la lecture', etat.cheminLu || 'aucun');
    constate('contenu rapatrie', etat.contenu ? `${etat.contenu.length} caractere(s)` : 'aucun');
    verifie('le contenu du fichier distant est rapatrie',
        etat.contenu.includes(LIGNE_REPERE),
        `« ${LIGNE_REPERE} » attendu dans la zone d'edition`);

    /*
     * LA DECOUVERTE CENTRALE, et la propriete est negative : APRES la lecture, la
     * page ne doit nommer AUCUN chemin autre que celui qui a ete lu.
     *
     * Mesurer « le chemin lu est affiche quelque part » ne suffirait pas — le
     * legacy le fait aussi, dans `#editor-path`. Ce qui le trahit, c'est que son
     * BADGE continue d'annoncer `zabbix_agent2.conf` alors que le portail a lu
     * `zabbix_agentd.conf` : deux chemins a l'ecran, dont un faux. On collecte
     * donc TOUS les chemins visibles dans le panneau et on compare a celui de la
     * fixture, qui est le seul que le backend pouvait lire.
     */
    const cheminsAffiches = await page.evaluate(() => {
        const bloc = [...document.querySelectorAll('#tab-editor, [data-rw="panneau-editor"]')]
            .find((e) => e.offsetParent !== null);
        if (! bloc) return [];
        const trouves = bloc.innerText.match(/\/etc\/[\w./-]+/g) || [];

        return [...new Set(trouves)];
    });
    const cheminsFaux = cheminsAffiches.filter((c) => c !== CHEMIN_LU);
    constate('chemins nommes par le panneau apres la lecture',
        cheminsAffiches.join(' | ') || 'aucun');
    verifie('le chemin qui a ete LU est nomme a l\'ecran',
        cheminsAffiches.includes(CHEMIN_LU), `« ${CHEMIN_LU} » attendu`);
    verifiePortage('la page ne nomme AUCUN autre chemin que celui qui a ete lu',
        cheminsFaux.length === 0,
        `${cheminsFaux.join(', ')} — le badge du legacy est ecrit en dur dans `
        + 'main.js:27-32 alors que le backend calcule _config_file_path(agent_type) '
        + 'depuis la base : deux chemins a l\'ecran, dont un faux');

    /*
     * CE QU'UN EDITEUR MONTRE LEGITIMEMENT. Le fichier porte un
     * `TLSPSKIdentity` : un editeur existe pour montrer le fichier qu'on edite,
     * donc l'y voir n'est PAS une fuite. Ce qui se mesure, c'est qu'il ne soit
     * recopie NULLE PART AILLEURS — ni ilot de donnees, ni attribut.
     */
    const source = await page.content();
    const occurrences = (source.match(new RegExp(IDENTITE_PSK, 'g')) || []).length;
    const dansLaZone = etat.contenu.includes(IDENTITE_PSK);
    /*
     * POURQUOI LA BORNE EST « AU PLUS UNE ». Cote legacy le contenu arrive par
     * JavaScript dans la `value` d'un `<textarea>` : il n'apparait donc PAS dans
     * le source serialise, et l'on mesure zero. Cote portage, un rendu serveur
     * l'y met UNE fois — ce qui est normal. Ce que la borne interdit, c'est la
     * SECONDE copie : un ilot de donnees, un attribut, un champ cache.
     */
    constate('identite PSK du fichier',
        `${occurrences} occurrence(s) dans le source servi, `
        + `${dansLaZone ? 'presente dans' : 'absente de'} la zone d'edition`);
    verifie('le contenu du fichier n\'est recopie qu\'a UN seul endroit',
        occurrences <= 1,
        `${occurrences} occurrence(s) — un editeur montre le fichier qu'il edite, `
        + 'mais il n\'a aucune raison de le recopier ailleurs');

    // ── Le verdict est ENONCE, et sans trace technique ──────────────────────
    const tout = [etat.messages.join('\n'), dialogues.join('\n')].join('\n');
    const MOTIF = /(charg|loaded|lu|read)/i;
    const retenu = etat.messages.find((m) => MOTIF.test(m));
    constate('messages apparus pendant la lecture',
        etat.messages.slice(0, 3).map((m) => m.replace(/\n/g, ' ')).join(' | ') || 'aucun');
    verifie('la lecture annonce son resultat',
        Boolean(retenu) || etat.contenu !== '',
        retenu ? `« ${retenu.replace(/\n/g, ' ').slice(0, 60)} »` : 'aucun message, mais contenu present');
    /*
     * UN MESSAGE D'EXPLOITATION N'EST PAS UNE TRACE TECHNIQUE. Le legacy jette
     * `HTTP <code>: <json>` a l'ecran quand la route refuse : c'est lisible pour
     * qui developpe, pas pour qui exploite.
     */
    const traceTechnique = /HTTP \d{3}|\{"success"|Traceback/.test(tout);
    constate('trace technique dans les messages', traceTechnique ? 'oui' : 'aucune');
    verifiePortage('aucun message ne jette de trace technique a l\'ecran',
        ! traceTechnique, 'le legacy affiche « HTTP <code>: <json> » tel quel');

    /*
     * `config_loaded` EST L'UNE DES ONZE CLES CASSEES, et c'est V4 qui l'avait
     * reperee dans le catalogue : ici elle est EXERCEE — l'ecran rend
     * « ✓ config_loaded ». C'est donc un ecart DECLARE du legacy, pas une
     * regression : l'assertion est reservee au portage. En faire une exigence des
     * deux cotes ferait echouer une suite qui mesure exactement ce qu'elle doit.
     */
    const clesVisibles = ['config_loaded', 'no_backups', 'btn_restore', 'backup_restored',
        'editor_select_server']
        .filter((c) => (tout + etat.contenu).includes(c));
    constate('cles rendues en identifiant', clesVisibles.join(', ') || 'aucune');
    verifiePortage('aucune cle de traduction ne s\'affiche en identifiant',
        clesVisibles.length === 0,
        `${clesVisibles.join(', ')} — absentes de js.php, donc retournees telles quelles`);

    verifiePortage('aucune boite native ne s\'ouvre',
        dialogues.length === 0, dialogues.join(', ') || 'aucune');
    verifie('aucune erreur JS pendant toute la sequence',
        erreursJs.length === 0, erreursJs.slice(0, 3).join(' · ') || 'aucune');
    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
} finally {
    const restesBase = nettoieBase();
    const restesFichiers = retireLesFichiers();
    lignes.push(`INFO  fixtures supprimees en sortie : base ${restesBase} ligne(s), `
        + `conteneur ${restesFichiers} fichier(s)`);
    const configRestante = compteEnBase('SELECT COUNT(*) FROM rootwarden.supervision_config');
    let fichiersRestants = 'inconnu';
    try {
        fichiersRestants = dansLeConteneur('sh', '-c',
            `ls -1 ${CHEMIN_LU} ${CHEMIN_LU}.bak.* 2>/dev/null | wc -l`).trim();
    } catch { /* le conteneur peut etre arrete : on le dit plutot que d'echouer en silence */ }
    const propre = configRestante === 0 && fichiersRestants === '0';
    lignes.push(`${propre ? 'PASS' : 'FAIL'}  la base ET la machine de test sont rendues a leur `
        + `etat initial  — ${configRestante} ligne(s), ${fichiersRestants} fichier(s)`);
    if (! propre) echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
