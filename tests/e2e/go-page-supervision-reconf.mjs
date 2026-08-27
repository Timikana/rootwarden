/**
 * go-page-supervision-reconf.mjs - Module `supervision/`, sous-lot V10 : la
 * RECONFIGURATION d'un agent (flux `text/plain`, MODIFIE la machine).
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/supervision/   (« Reconfigurer », SANS confirmation)
 *   laravel  http://localhost:8444/supervision     (panneau de decision, quatre effets)
 *
 * ══ POURQUOI CETTE SUITE PEUT CLIQUER DES DEUX COTES ════════════════════════
 *
 * Le geste porte sur UNE machine, celle de la ligne : **Test-Server-Debian
 * (id 2, DEV)**. `srv-zabbix` n'est jamais visee. Ce que le geste ecrit et rien
 * de plus : `/etc/zabbix/zabbix_agent2.conf` et ses copies datees. Fixtures — une
 * ligne `supervision_config` (0 a l'entree) et les fichiers — nettoyees a
 * l'entree et dans un `finally`, etat RELU pour etre PROUVE.
 *
 * ══ CE QUI EST DEJA MESURE, ET QUE CETTE SUITE VERROUILLE (PARITE E-85) ═════
 *
 *  1. **LE MARQUEUR TERMINAL DU FLUX MENT.** Mesure sur la machine de test, qui
 *     n'a pas de `systemctl` :
 *
 *         Exécution terminée (code 127).
 *         SUCCESS_MACHINE::2::Reconfiguration reussie pour Test-Server-Debian.
 *
 *     Le redemarrage a echoue et le marqueur conclut a la reussite. L'information
 *     est dans le flux DEUX LIGNES plus haut. Le portage doit dire ce que le flux
 *     a MONTRE, pas ce que son dernier marqueur affirme — c'est la propriete
 *     centrale de ce sous-lot ;
 *
 *  2. **QUATRE EFFETS, pas trois** : sauvegarde datee, ecriture CLE PAR CLE,
 *     ecriture d'une CLE PSK si la configuration globale en porte une, puis
 *     redemarrage. Le legacy n'annonce RIEN : `reconfigureSingle` part au premier
 *     clic, la ou `deploy` et `uninstall` ouvrent au moins un `confirm()` ;
 *
 *  3. **L'ECRITURE FUSIONNE, elle ne remplace pas** : `sed` de purge puis ajout,
 *     donc les lignes inconnues du portail SURVIVENT — a l'inverse de l'editeur
 *     (V9) qui tronque. Deux gestes voisins, deux semantiques opposees, et cette
 *     suite le MESURE en posant une ligne etrangere avant le geste ;
 *
 *  4. **`zabbix_reconfigure` REFUSE (400) sans configuration globale**, et la
 *     table en a zero. Une regle appliquee par le backend se rend visible : le
 *     bouton du portage est DESACTIVE, avec l'explication en infobulle.
 *
 * ══ LA PASSERELLE BUFFERISE, ET C'EST ASSUME ════════════════════════════════
 *
 * `/supervision/` n'est pas dans `EN_FLUX`. Mesure : une reconfiguration d'UNE
 * machine dure **1,4 s**. Tenir la connexion ouverte pour la rendre « vivante »
 * n'apporterait rien a ce prix — le geste est par ligne, pas sur le parc.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-supervision-reconf.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';
import { execFileSync } from 'child_process';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/supervision' : '/supervision/';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

const MACHINE_DEV = 2;
const CONTENEUR = 'rootwarden_test_server';
const REPERTOIRE = '/etc/zabbix';
const FICHIER = `${REPERTOIRE}/zabbix_agent2.conf`;
/** Le serveur que la fixture de configuration globale designe. */
const SERVEUR_FIXTURE = '10.0.0.251';
/** Une ligne que le portail ne gere PAS : elle doit SURVIVRE a la fusion. */
const LIGNE_ETRANGERE = 'Timeout=42';

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

function surLaMachine(...args) {
    try {
        return execFileSync('docker', ['exec', CONTENEUR, ...args],
            { encoding: 'utf8', timeout: 20000 });
    } catch (e) {
        return `(echec: ${String(e.message || e).split('\n')[0]})`;
    }
}

function etatDuRepertoire() {
    return (surLaMachine('sh', '-c', `ls -1 ${REPERTOIRE} 2>/dev/null | tr '\\n' ' '`)).trim() || '(vide)';
}

function contenuDuFichier() {
    return surLaMachine('sh', '-c', `cat ${FICHIER} 2>/dev/null || echo '(ABSENT)'`).trim();
}

function configsEnBase() {
    return compteEnBase(
        `SELECT COUNT(*) FROM rootwarden.supervision_config WHERE zabbix_server = '${SERVEUR_FIXTURE}'`);
}

function nettoie() {
    const avant = `${etatDuRepertoire()} | ${configsEnBase()} config(s) de fixture`;
    surLaMachine('sh', '-c', `rm -f ${FICHIER} ${REPERTOIRE}/zabbix_agent2.conf.bak.*`);
    litEnBase(`DELETE FROM rootwarden.supervision_config WHERE zabbix_server = '${SERVEUR_FIXTURE}'`);
    return avant;
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});

async function connecte(langue) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(40000);
    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };
    await page.goto(`${BASE}${chemins.connexion}?lang=${langue}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', 'rw-test-admin', { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    for (let essai = 0; essai < 2; essai += 1) {
        const champ = await page.$('input[name="2fa_code"]');
        if (! champ) break;
        if (essai > 0) await dors((resteFenetre() + 1) * 1000);
        await champ.click({ clickCount: 3 });
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

async function ouvreDeploiement(page) {
    for (let essai = 0; essai < 20; essai += 1) {
        const visible = await page.evaluate(() => {
            const onglet = document.querySelector('.tab-btn[data-tab="deploy"]')
                || document.querySelector('[data-rw="onglet-deploy"]');
            const panneau = document.querySelector('#tab-deploy, [data-rw="panneau-deploy"]');
            if (panneau && panneau.offsetParent !== null) return true;
            onglet?.click();

            return false;
        });
        if (visible) return true;
        await dors(400);
    }

    return false;
}

/** Le geste de reconfiguration de la LIGNE de la machine DEV, des deux cotes. */
async function cliqueReconfigurer(page, mid) {
    return page.evaluate((id) => {
        const portage = document.querySelector(
            `[data-rw="superv-reconfigurer"][data-machine="${id}"]`);
        if (portage) {
            if (portage.disabled) return 'desactive';
            portage.click();

            return 'clique';
        }
        const leg = [...document.querySelectorAll('button')].find((b) =>
            (b.getAttribute('onclick') || '').includes(`reconfigureSingle(${id})`));
        if (! leg) return 'absent';
        leg.click();

        return 'clique';
    }, mid);
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
            await verifieMenuLegacy(page, '/supervision', verifie);
            await ctx.close();
            console.log(lignes.join('\n'));
            console.log(`\n${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
            await navigateur.close();
            process.exit(echecs > 0 ? 1 : 0);
        }
    }

    constate('cible', `${CIBLE} — ${PAGE}`);
    constate('machine visee', `id ${MACHINE_DEV} (DEV) — srv-zabbix jamais visee`);
    constate('etat a l\'entree', nettoie());

    const { ctx, page } = await connecte('fr');
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const dialogues = [];
    page.on('dialog', (d) => { dialogues.push(`${d.type()}: ${d.message().slice(0, 70)}`); d.dismiss().catch(() => {}); });
    let appels = [];
    page.on('request', (r) => {
        const u = r.url();
        if (/api_proxy\.php\/|\/api\/gateway\//.test(u)) {
            appels.push(r.method() + ' ' + u.replace(BASE, '').slice(0, 70));
        }
    });

    const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie', (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(1800);
    verifie('l\'onglet du parc s\'ouvre', await ouvreDeploiement(page));

    /* ══ 1. SANS CONFIGURATION GLOBALE, LA REGLE DU BACKEND EST VISIBLE ═════
     * `zabbix_reconfigure` rend 400 « Aucune configuration globale ». Un bouton
     * cliquable pour se faire refuser fait decider dans le vide. */
    const sansConfig = await page.evaluate((id) => {
        const b = document.querySelector(`[data-rw="superv-reconfigurer"][data-machine="${id}"]`);
        const vide = document.querySelector('[data-rw="superv-reconf-indisponible"]');

        return {
            existe: b !== null,
            desactive: b ? b.disabled : null,
            infobulle: b ? (b.getAttribute('title') || '') : '',
            annonce: vide ? vide.innerText.replace(/\s+/g, ' ').trim() : '',
        };
    }, MACHINE_DEV);
    constate('geste de reconfiguration, sans configuration globale',
        sansConfig.existe ? `desactive=${sansConfig.desactive} « ${sansConfig.infobulle} »` : 'absent');
    verifiePortage('sans configuration globale, le geste est DESACTIVE et dit pourquoi',
        sansConfig.desactive === true && sansConfig.infobulle !== '',
        sansConfig.infobulle || 'aucune infobulle');
    verifiePortage('et la page l\'ANNONCE, plutot que de laisser deviner',
        sansConfig.annonce.length > 30, sansConfig.annonce.slice(0, 90) || 'rien');

    /* ══ 2. LA FIXTURE : une configuration globale, et une ligne ETRANGERE ══
     * La ligne etrangere sert a mesurer que l'ecriture FUSIONNE. */
    litEnBase('INSERT INTO rootwarden.supervision_config (platform, zabbix_server) '
        + `VALUES ('zabbix', '${SERVEUR_FIXTURE}')`);
    surLaMachine('sh', '-c',
        `printf '%s\\n' '${LIGNE_ETRANGERE}' 'Server=1.1.1.1' > ${FICHIER}`);
    constate('fixture posee', `config globale + ${FICHIER} portant « ${LIGNE_ETRANGERE} »`);

    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await dors(1500);
    await ouvreDeploiement(page);

    /* ══ 3. LE GESTE EST PRESENT, ET IL EST PAR LIGNE ══════════════════════ */
    const parLigne = await page.evaluate(() => ({
        portage: document.querySelectorAll('[data-rw="superv-reconfigurer"]').length,
        cases: document.querySelectorAll('input[name="deploy_machines[]"]').length,
        surSelection: [...document.querySelectorAll('button')].filter((b) =>
            /reconfigureSelected/.test(b.getAttribute('onclick') || '')).length,
    }));
    constate('gestes de reconfiguration', `par ligne : ${parLigne.portage} · `
        + `sur selection : ${parLigne.surSelection} · cases a cocher : ${parLigne.cases}`);
    verifiePortage('aucun geste de reconfiguration SUR SELECTION',
        parLigne.surSelection === 0 && parLigne.cases === 0,
        `${parLigne.surSelection} geste(s) de masse, ${parLigne.cases} case(s)`);

    /* ══ 4. OUVRIR N'ENVOIE RIEN — le legacy, lui, part au premier clic ═════ */
    appels = [];
    const geste = await cliqueReconfigurer(page, MACHINE_DEV);
    constate('resultat du clic', geste);
    verifie('le geste est atteignable une fois la configuration globale posee',
        geste === 'clique', geste);
    await dors(900);

    if (CIBLE === 'laravel') {
        const ouvert = await page.evaluate(() =>
            document.querySelector('[data-rw="superv-panneau-reconf"]')?.offsetParent !== null);
        verifie('le geste OUVRE un panneau de decision', ouvert);
        verifie('ouvrir le panneau n\'envoie AUCUNE requete',
            appels.length === 0, appels.join(' | ') || 'aucune');
        verifie('aucune boite native ne s\'ouvre a la place',
            dialogues.length === 0, dialogues.join(', ') || 'aucune');

        /* ══ 5. LE PANNEAU NOMME LA MACHINE, LE CHEMIN, ET ENUMERE LES EFFETS */
        const panneau = await page.evaluate(() => ({
            cout: document.querySelector('[data-rw="superv-reconf-cout"]')?.textContent.trim() || '',
            effets: [...document.querySelectorAll('[data-rw="superv-reconf-effets"] li')]
                .filter((e) => e.offsetParent !== null).map((e) => e.textContent.trim()),
            pskCache: document.querySelector('[data-rw="superv-reconf-effet-psk"]')?.hidden,
        }));
        verifie('le panneau NOMME la machine et le chemin',
            /Test-Server-Debian/.test(panneau.cout) && /zabbix_agent2\.conf/.test(panneau.cout),
            `« ${panneau.cout.slice(0, 100)} »`);
        constate('effets enumeres', panneau.effets.length);
        verifie('les effets sont ENUMERES, pas noyes dans une phrase',
            panneau.effets.length >= 3, `${panneau.effets.length} effet(s)`);
        verifie('ils nomment la sauvegarde, la FUSION et le redemarrage',
            panneau.effets.some((e) => /copie|sauvegarde/i.test(e))
            && panneau.effets.some((e) => /SURVIVENT|survive/i.test(e))
            && panneau.effets.some((e) => /redemarr|restart/i.test(e)),
            panneau.effets.join(' | ').slice(0, 130));
        /*
         * LE QUATRIEME EFFET EST CONDITIONNEL, et sa condition est mesuree : la
         * fixture ne pose AUCUN PSK, donc la ligne doit etre CACHEE. Annoncer un
         * effet qui n'aura pas lieu est aussi faux que d'en taire un.
         */
        verifie('l\'effet PSK est CACHE quand la configuration n\'en porte pas',
            panneau.pskCache === true, `hidden=${panneau.pskCache}`);

        /* ══ 6. ANNULER N'ENVOIE RIEN ══════════════════════════════════════ */
        appels = [];
        await page.click('[data-rw="superv-reconf-annuler"]');
        await dors(600);
        verifie('annuler referme le panneau', await page.evaluate(() =>
            document.querySelector('[data-rw="superv-panneau-reconf"]')?.offsetParent === null));
        verifie('annuler n\'envoie AUCUNE requete',
            appels.length === 0, appels.join(' | ') || 'aucune');

        /* ══ 7. LE GESTE REEL, ET LA PROPRIETE CENTRALE DE V10 ═════════════ */
        await cliqueReconfigurer(page, MACHINE_DEV);
        await dors(500);
        await page.click('[data-rw="superv-reconf-confirmer"]');
    }
    // Le flux dure ~1,4 s cote backend ; on attend la PROPRIETE, pas une duree.
    for (let i = 0; i < 40 && ! contenuDuFichier().includes(SERVEUR_FIXTURE); i += 1) await dors(1000);
    await dors(1500);

    const ecrit = contenuDuFichier();
    verifie('la configuration a REELLEMENT ete poussee sur la machine',
        ecrit.includes(`Server=${SERVEUR_FIXTURE}`), ecrit.replace(/\n/g, ' ').slice(0, 80));
    /*
     * L'ECRITURE FUSIONNE. La ligne etrangere, que le portail ne gere pas, doit
     * AVOIR SURVECU — c'est ce qui distingue la reconfiguration de l'editeur,
     * qui tronque le fichier.
     */
    verifie('la ligne ETRANGERE a survecu : l\'ecriture fusionne, elle ne tronque pas',
        ecrit.includes(LIGNE_ETRANGERE), ecrit.replace(/\n/g, ' ').slice(0, 90));
    verifie('une sauvegarde datee a ete creee avant l\'ecriture',
        Number(String(surLaMachine('sh', '-c',
            `ls -1 ${REPERTOIRE}/zabbix_agent2.conf.bak.* 2>/dev/null | wc -l`)).trim()) >= 1);

    const ecran = await page.evaluate(() => {
        const bloc = [...document.querySelectorAll('#tab-deploy, [data-rw="panneau-deploy"]')]
            .find((e) => e.offsetParent !== null);
        const morceaux = bloc ? [bloc.innerText] : [];
        for (const sel of ['#toast-container', '[data-rw="superv-reconf-message"]',
                           '#deploy-logs-container', '#deploy-logs']) {
            const e = document.querySelector(sel);
            if (e) morceaux.push(e.innerText);
        }

        return morceaux.join('\n');
    });

    /*
     * LA PROPRIETE CENTRALE. Le redemarrage a echoue (code 127, pas de
     * `systemctl` sur la machine de test) et le marqueur terminal du backend dit
     * « Reconfiguration reussie ». Le portage doit dire l'ECHEC DE LA COMMANDE.
     */
    verifiePortage('le portage dit ce que le FLUX a montre, pas ce que son marqueur affirme',
        /ECHOUE|FAILED/i.test(ecran) && /127/.test(ecran),
        (ecran.match(/[^\n]*(ECHOUE|FAILED)[^\n]*/i) || ['rien qui signale un echec'])[0].slice(0, 130));
    /*
     * LE DETAIL EST IMPRIME AU PASS COMME AU FAIL : il doit dire ce qu'on a
     * TROUVE. Un premier jet rendait « PASS ... — journal absent ou vide », qui
     * se lit comme une contradiction.
     */
    const journal = await page.evaluate(() =>
        document.querySelector('[data-rw="superv-reconf-journal"]')?.textContent || '');
    const preuve = (journal.match(/[^\n]*(SUCCESS_MACHINE::|code 127)[^\n]*/g) || []);
    verifiePortage('le journal du flux est MONTRE, pour pouvoir verifier ce verdict',
        preuve.length > 0,
        preuve.length ? `${journal.split('\n').length} lignes, dont « ${preuve[0].trim()} »`
                      : 'journal absent ou vide');

    const journalLegacy = await page.evaluate(() =>
        (document.querySelector('#deploy-logs-container')?.innerText
            || document.querySelector('#deploy-logs')?.innerText || '').slice(0, 200));
    if (CIBLE === 'legacy') {
        constate('ce que le legacy montre', journalLegacy.replace(/\n/g, ' ').slice(0, 140) || 'rien');
        verifie('le legacy n\'a demande AUCUNE confirmation avant d\'agir',
            dialogues.length === 0 && ecrit.includes(SERVEUR_FIXTURE),
            dialogues.join(', ') || 'aucune boite, et le fichier a ete ecrit');
    }

    verifie('aucune erreur JS pendant toute la sequence',
        erreursJs.length === 0, erreursJs.slice(0, 3).join(' · ') || 'aucune');

    const texte = await page.evaluate(() => document.body.innerText);
    verifie('aucun identifiant de traduction a l\'ecran (fr)',
        ! /superv\.[a-z_]+/.test(texte),
        (texte.match(/superv\.[a-z_]+/g) || []).slice(0, 3).join(', '));
    await ctx.close();

    /* ══ 8. LA PASSE ANGLAISE ══════════════════════════════════════════════ */
    await dors((resteFenetre() + 1) * 1000);
    const { ctx: ctxEn, page: pageEn } = await connecte('en');
    await pageEn.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await dors(1500);
    verifie('la seconde session (en) est bien authentifiee',
        ! /connexion|login/.test(pageEn.url()), pageEn.url().replace(BASE, ''));
    verifie('l\'onglet du parc s\'ouvre (en)', await ouvreDeploiement(pageEn));
    const texteEn = await pageEn.evaluate(() => document.body.innerText);
    verifie('aucun identifiant de traduction a l\'ecran (en)',
        ! /superv\.[a-z_]+/.test(texteEn),
        (texteEn.match(/superv\.[a-z_]+/g) || []).slice(0, 3).join(', '));
    /*
     * UN MOTIF TROP LARGE ATTRAPE LE FRANCAIS. « Reconfigure » est un PREFIXE de
     * « Reconfigurer » : le motif passait sur la page francaise. On vise des
     * phrases anglaises entieres, qui ne peuvent pas etre un prefixe du francais.
     */
    const anglais = (texteEn.match(/Reconfigure and restart|Reconfigure a server's agent/g) || []);
    verifiePortage('le geste de reconfiguration est traduit en anglais',
        anglais.length > 0, anglais.length ? `trouve : ${anglais[0]}` : 'aucun libelle anglais');
    await ctxEn.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
} finally {
    const avant = nettoie();
    lignes.push(`INFO  etat avant nettoyage de sortie : ${avant}`);
    const apres = etatDuRepertoire();
    const configs = configsEnBase();
    lignes.push(`${apres === '(vide)' && configs === 0 ? 'PASS' : 'FAIL'}  l'etat est rendu a `
        + `l'identique  — repertoire ${apres}, ${configs} config(s) de fixture`);
    if (apres !== '(vide)' || configs !== 0) echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
