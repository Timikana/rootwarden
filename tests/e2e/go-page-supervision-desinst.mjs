/**
 * go-page-supervision-desinst.mjs - Module `supervision/`, sous-lot V11 : la
 * DESINSTALLATION d'un agent (flux `text/plain`, DETRUIT).
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/supervision/   (`confirm()` natif)
 *   laravel  http://localhost:8444/supervision     (panneau + VERIFICATION apres coup)
 *
 * ══ POURQUOI CETTE SUITE PEUT CLIQUER UN GESTE DESTRUCTEUR ══════════════════
 *
 * Le geste porte sur UNE machine, celle de la ligne : **Test-Server-Debian
 * (id 2, DEV)**. `srv-zabbix` n'est jamais visee. Et le perimetre a ete MESURE
 * AVANT d'etre paye : `apt-get autoremove --dry-run` y rend « 0 to remove », et
 * `autoremove` a de toute facon ete retire des quatre commandes (v1.37.44). La
 * purge, elle, ne porte que sur ce que `dpkg-query` trouve installe — donc rien
 * ici.
 *
 * ══ LA FIXTURE QUI REND LA PROPRIETE CENTRALE MESURABLE ═════════════════════
 *
 * Le portage VERIFIE apres coup en relisant la version. Pour exercer la branche
 * qui compte — « la commande a rendu un succes, mais un agent est TOUJOURS
 * detecte » — la suite pose un FAUX binaire `zabbix_agent2` sur la machine :
 *
 *   - `dpkg-query` ne le voit pas (ce n'est pas un paquet) -> la commande rend
 *     `RIEN_A_PURGER` et un code 0 : elle « reussit » ;
 *   - `command -v zabbix_agent2` le trouve -> la detection de version le voit.
 *
 * La commande dit donc oui, et la verification dit non. C'est exactement le cas
 * pour lequel ce portage verifie, et il ne serait pas atteignable autrement : on
 * ne peut pas installer un vrai agent sur le banc d'essai. Le faux binaire est
 * un script inoffensif qui n'imprime qu'une version, et il est retire dans un
 * `finally` avec l'etat RELU pour etre prouve.
 *
 * ══ CE QUI EST DEJA MESURE (PARITE E-88) ════════════════════════════════════
 *
 *  - **`confirm_uninstall` est absente des deux `js.php`** : le `confirm()` natif
 *    du legacy affiche donc la chaine `confirm_uninstall`. On demande de
 *    confirmer une DESTRUCTION avec un identifiant a l'ecran. 18e cle cassee ;
 *  - le backend ne peut plus mentir (v1.37.44) : la commande ne purge que ce qui
 *    est installe, son code remonte, et l'inventaire n'est vide que si ce code
 *    vaut 0.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-supervision-desinst.mjs
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
/** Le faux binaire : inoffensif, il n'imprime qu'une version. */
const FAUX_AGENT = '/usr/local/bin/zabbix_agent2';
const VERSION_FIXTURE = '7.0.99-faux-v11';
/*
 * CE QUE L'ECRAN AFFICHE N'EST PAS CE QUE LE BINAIRE IMPRIME. La route de
 * version extrait le NUMERO par `(\d+\.\d+[\.\d]*)` : de
 * « zabbix_agent2 (Zabbix) 7.0.99-faux-v11 » elle ne garde que `7.0.99`. Un
 * premier jet assertait la chaine brute et echouait — la suite avait tort, pas
 * le portage.
 */
const VERSION_AFFICHEE = '7.0.99';

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
            { encoding: 'utf8', timeout: 25000 });
    } catch (e) {
        return `(echec: ${String(e.message || e).split('\n')[0]})`;
    }
}

/** Le faux agent est-il present et vu par `command -v` ? */
function agentDetecte() {
    return surLaMachine('sh', '-c',
        'command -v zabbix_agent2 >/dev/null 2>&1 && echo OUI || echo NON').trim();
}

function inventaire() {
    return compteEnBase(
        `SELECT COUNT(*) FROM rootwarden.supervision_agents WHERE machine_id = ${MACHINE_DEV}`);
}

function nettoie() {
    const avant = `agent detecte=${agentDetecte()} inventaire=${inventaire()}`;
    surLaMachine('sh', '-c', `rm -f ${FAUX_AGENT}`);
    litEnBase(`DELETE FROM rootwarden.supervision_agents WHERE machine_id = ${MACHINE_DEV}`);

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

async function cliqueDesinstaller(page, mid) {
    return page.evaluate((id) => {
        const portage = document.querySelector(
            `[data-rw="superv-desinstaller"][data-machine="${id}"]`);
        if (portage) { portage.click(); return 'clique'; }
        const leg = [...document.querySelectorAll('button')].find((b) =>
            (b.getAttribute('onclick') || '').includes(`uninstallAgent(${id})`));
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
    constate('perimetre du geste, mesure AVANT de le payer',
        surLaMachine('sh', '-c', 'apt-get autoremove --dry-run 2>/dev/null | tail -1').trim());

    /*
     * LA FIXTURE QUI REND LA PROPRIETE CENTRALE MESURABLE. Un faux binaire que
     * `dpkg-query` ne voit pas (ce n'est pas un paquet) mais que `command -v`
     * trouve : la commande « reussit » sans rien purger, et la verification
     * apres coup la contredit.
     */
    surLaMachine('sh', '-c',
        `printf '#!/bin/sh\\necho "zabbix_agent2 (Zabbix) ${VERSION_FIXTURE}"\\n' > ${FAUX_AGENT}`
        + ` && chmod +x ${FAUX_AGENT}`);
    litEnBase('INSERT INTO rootwarden.supervision_agents (machine_id, platform, agent_version) '
        + `VALUES (${MACHINE_DEV}, 'zabbix', '${VERSION_FIXTURE}')`);
    verifie('la fixture est en place : un agent est detectable sur la machine',
        agentDetecte() === 'OUI', `command -v -> ${agentDetecte()}`);
    constate('inventaire apres fixture', inventaire());

    const { ctx, page } = await connecte('fr');
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const dialogues = [];
    page.on('dialog', (d) => {
        dialogues.push(`${d.type()}: ${d.message().slice(0, 80)}`);
        // Cote legacy on ACCEPTE : c'est le seul moyen de mesurer ce qui suit.
        d.accept().catch(() => {});
    });
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

    /* ══ 1. LE GESTE EST PAR LIGNE, SANS ACTION DE MASSE ════════════════════ */
    const gestes = await page.evaluate(() => ({
        parLigne: document.querySelectorAll('[data-rw="superv-desinstaller"]').length,
        cases: document.querySelectorAll('input[name="deploy_machines[]"]').length,
        legacy: [...document.querySelectorAll('button')].filter((b) =>
            /uninstallAgent\(/.test(b.getAttribute('onclick') || '')).length,
    }));
    constate('gestes de desinstallation',
        `portage par ligne : ${gestes.parLigne} · legacy par ligne : ${gestes.legacy} · `
        + `cases : ${gestes.cases}`);
    verifie('un geste de desinstallation existe par ligne',
        gestes.parLigne + gestes.legacy > 0);
    verifiePortage('aucune case a cocher ne subsiste',
        gestes.cases === 0, `${gestes.cases} case(s)`);

    /* ══ 2. OUVRIR N'ENVOIE RIEN — le legacy ouvre une BOITE NATIVE ═════════ */
    appels = [];
    const geste = await cliqueDesinstaller(page, MACHINE_DEV);
    verifie('le geste est atteignable', geste === 'clique', geste);
    await dors(1200);

    if (CIBLE === 'legacy') {
        /*
         * LA CLE CASSEE, MESUREE LA OU ELLE FAIT LE PLUS DE MAL. `__()` rend la
         * cle absente TELLE QUELLE : la boite qui demande de confirmer une
         * DESTRUCTION affiche donc « confirm_uninstall ».
         */
        constate('boite native ouverte par le legacy', dialogues.join(' | ') || 'aucune');
        verifie('le legacy ouvre bien une boite native', dialogues.length > 0);
        verifie('et cette boite affiche la CLE, pas une phrase',
            dialogues.some((d) => d.includes('confirm_uninstall')),
            dialogues.join(' | ') || 'aucune');
    } else {
        const ouvert = await page.evaluate(() =>
            document.querySelector('[data-rw="superv-panneau-desinst"]')?.offsetParent !== null);
        verifie('le geste OUVRE un panneau de decision', ouvert);
        verifie('ouvrir le panneau n\'envoie AUCUNE requete',
            appels.length === 0, appels.join(' | ') || 'aucune');
        verifie('AUCUNE boite native ne s\'ouvre',
            dialogues.length === 0, dialogues.join(', ') || 'aucune');

        /* ══ 3. LE PANNEAU NOMME CE QUI SERA DETRUIT ═══════════════════════ */
        const panneau = await page.evaluate(() => ({
            cout: document.querySelector('[data-rw="superv-desinst-cout"]')?.textContent.trim() || '',
            effets: [...document.querySelectorAll('[data-rw="superv-desinst-effets"] li')]
                .filter((e) => e.offsetParent !== null).map((e) => e.textContent.trim()),
        }));
        verifie('le panneau NOMME la machine et le chemin',
            /Test-Server-Debian/.test(panneau.cout) && /zabbix_agent2\.conf/.test(panneau.cout),
            `« ${panneau.cout.slice(0, 100)} »`);
        verifie('les effets sont ENUMERES : service, purge, inventaire',
            panneau.effets.length >= 3
            && panneau.effets.some((e) => /service/i.test(e))
            && panneau.effets.some((e) => /purg/i.test(e))
            && panneau.effets.some((e) => /inventaire/i.test(e)),
            panneau.effets.join(' | ').slice(0, 130));
        /*
         * L'INVENTAIRE N'EST RETIRE QUE SI LA COMMANDE A REUSSI, et le panneau
         * le DIT : c'est la contrepartie du correctif backend, et la taire
         * laisserait croire que l'inventaire ment encore.
         */
        /*
         * NOMMER LA PRODUCTION, SUR LE GESTE QUI DETRUIT. Le panneau ouvert sur
         * la machine DEV ne doit PAS crier a la production ; celui ouvert sur
         * `srv-zabbix` doit le faire. La propriete se mesure donc dans les deux
         * sens — un avertissement toujours affiche ne previent de rien.
         */
        const prodSurDev = await page.evaluate(() =>
            document.querySelector('[data-rw="superv-desinst-prod"]')?.hidden);
        verifie('aucun avertissement de production sur une machine DEV',
            prodSurDev === true, `hidden=${prodSurDev}`);

        verifie('le panneau dit que l\'inventaire ne bouge QUE si la commande reussit',
            panneau.effets.some((e) => /SEULEMENT|ONLY/i.test(e)),
            panneau.effets.find((e) => /inventaire|inventory/i.test(e)) || 'rien');

        /* ══ 3bis. LE MEME PANNEAU, OUVERT SUR LA PRODUCTION ═══════════════
         * On OUVRE seulement — ouvrir n'envoie rien, c'est deja mesure. Jamais de
         * confirmation ici : `srv-zabbix` est en production et ne doit pas etre
         * jointe. Ce que l'on mesure est l'AVERTISSEMENT, pas le geste. */
        await page.click('[data-rw="superv-desinst-annuler"]');
        await dors(400);
        appels = [];
        await cliqueDesinstaller(page, 1);
        await dors(700);
        const surProd = await page.evaluate(() => {
            const p = document.querySelector('[data-rw="superv-desinst-prod"]');

            return { cache: p?.hidden, texte: p?.textContent.trim() || '' };
        });
        constate('panneau ouvert sur srv-zabbix (PROD)',
            surProd.cache === false ? `« ${surProd.texte.slice(0, 90)} »` : 'aucun avertissement');
        verifie('la PRODUCTION est NOMMEE quand le geste la viserait',
            surProd.cache === false && /PRODUCTION/.test(surProd.texte)
            && surProd.texte.includes('srv-zabbix'),
            surProd.texte.slice(0, 100) || 'rien');
        verifie('et ouvrir ce panneau n\'a rien envoye a la production',
            appels.length === 0, appels.join(' | ') || 'aucune requete');
        await page.click('[data-rw="superv-desinst-annuler"]');
        await dors(400);
        await cliqueDesinstaller(page, MACHINE_DEV);
        await dors(500);

        /* ══ 4. ANNULER N'ENVOIE RIEN ══════════════════════════════════════ */
        appels = [];
        await page.click('[data-rw="superv-desinst-annuler"]');
        await dors(600);
        verifie('annuler referme le panneau', await page.evaluate(() =>
            document.querySelector('[data-rw="superv-panneau-desinst"]')?.offsetParent === null));
        verifie('annuler n\'envoie AUCUNE requete',
            appels.length === 0, appels.join(' | ') || 'aucune');

        /* ══ 5. LE GESTE REEL ══════════════════════════════════════════════ */
        await cliqueDesinstaller(page, MACHINE_DEV);
        await dors(500);
        await page.click('[data-rw="superv-desinst-confirmer"]');
    }

    // On attend la PROPRIETE : le verdict apparait a l'ecran.
    for (let i = 0; i < 45; i += 1) {
        const pret = await page.evaluate(() => {
            const m = document.querySelector('[data-rw="superv-desinst-message"]')?.textContent.trim();
            const leg = document.querySelector('#deploy-logs-container')?.innerText || '';

            return (m && ! /\.\.\.$/.test(m)) || /SUCCESS_MACHINE|reussi|desinstalle/i.test(leg);
        });
        if (pret) break;
        await dors(1000);
    }
    await dors(2500);

    const ecran = await page.evaluate(() => {
        const bloc = [...document.querySelectorAll('#tab-deploy, [data-rw="panneau-deploy"]')]
            .find((e) => e.offsetParent !== null);
        const morceaux = bloc ? [bloc.innerText] : [];
        for (const sel of ['#toast-container', '#deploy-logs-container', '#deploy-logs']) {
            const e = document.querySelector(sel);
            if (e) morceaux.push(e.innerText);
        }

        return morceaux.join('\n');
    });

    /* ══ 6. « RIEN A PURGER » N'EST PAS « DESINSTALLE » ═════════════════════
     * Le faux binaire n'est pas un paquet : la commande ne purge rien et rend 0.
     * Le legacy en conclut « desinstalle » ; le portage doit distinguer. */
    const verdict = await page.evaluate(() =>
        document.querySelector('[data-rw="superv-desinst-message"]')?.textContent.trim() || '');
    constate('verdict de la commande', verdict.slice(0, 120) || '(aucun)');
    verifiePortage('« rien a purger » est distingue de « desinstalle »',
        /rien a desinstaller|nothing to uninstall/i.test(verdict),
        `« ${verdict.slice(0, 110)} »`);

    /* ══ 7. LA PROPRIETE CENTRALE : LA VERIFICATION CONTREDIT LA COMMANDE ═══
     * L'agent est TOUJOURS la (le faux binaire), et la commande a rendu un
     * succes. Le portage doit le DIRE. */
    const verif = await page.evaluate(() =>
        document.querySelector('[data-rw="superv-desinst-verif"]')?.textContent.trim() || '');
    constate('resultat de la verification apres coup', verif.slice(0, 130) || '(aucune)');
    verifiePortage('la VERIFICATION contredit le succes annonce, et le dit',
        /TOUJOURS|STILL/i.test(verif) && verif.includes(VERSION_AFFICHEE),
        `« ${verif.slice(0, 120) }»`);
    verifie('l\'agent est effectivement toujours la : la contradiction est REELLE',
        agentDetecte() === 'OUI', `command -v -> ${agentDetecte()}`);
    /*
     * EFFET NON PREVU, MESURE ET CONSERVE. La desinstallation avait vide
     * l'inventaire — a juste titre de son point de vue, puisqu'elle avait rendu
     * un code 0. La verification, elle, RETROUVE l'agent, et la route de version
     * REPOSE la ligne d'inventaire (`_upsert_agent`). L'inventaire finit donc
     * juste, non pas parce que la desinstallation avait raison, mais parce que la
     * verification l'a corrigee. C'est un benefice de plus a verifier apres coup,
     * et il ne se voit qu'EN BASE.
     */
    verifiePortage('la verification REPOSE la ligne d\'inventaire que la commande avait effacee',
        inventaire() === 1, `${inventaire()} ligne(s) apres verification`);

    // Le detail est imprime au PASS comme au FAIL : il doit dire ce qu'on a TROUVE.
    const journal = await page.evaluate(() =>
        document.querySelector('[data-rw="superv-desinst-journal"]')?.textContent || '');
    const preuve = (journal.match(/[^\n]*(RIEN_A_PURGER|SUCCESS_MACHINE)[^\n]*/g) || []);
    verifiePortage('le journal du flux est MONTRE',
        preuve.length > 0,
        preuve.length ? `${journal.split('\n').length} lignes, dont « ${preuve[0].trim()} »`
                      : 'journal absent ou vide');

    if (CIBLE === 'legacy') {
        constate('ce que le legacy conclut',
            (ecran.match(/[^\n]*(desinstalle|reussi)[^\n]*/i) || ['rien'])[0].slice(0, 120));
        verifie('le legacy ne verifie RIEN apres coup',
            ! /TOUJOURS|toujours detecte/i.test(ecran),
            'aucune verification, comme attendu');
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
    // Phrases ENTIERES : « Uninstall » serait un prefixe de trop de choses.
    const anglais = (texteEn.match(/Uninstall the agent|Uninstall a server's agent/g) || []);
    verifiePortage('le geste de desinstallation est traduit en anglais',
        anglais.length > 0, anglais.length ? `trouve : ${anglais[0]}` : 'aucun libelle anglais');
    await ctxEn.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
} finally {
    const avant = nettoie();
    lignes.push(`INFO  etat avant nettoyage de sortie : ${avant}`);
    const apres = `${agentDetecte()} / ${inventaire()}`;
    lignes.push(`${agentDetecte() === 'NON' && inventaire() === 0 ? 'PASS' : 'FAIL'}  le faux agent `
        + `et l'inventaire sont rendus a leur etat initial  — detecte=${agentDetecte()}, `
        + `inventaire=${inventaire()}`);
    if (agentDetecte() !== 'NON' || inventaire() !== 0) echecs++;
    void apres;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
