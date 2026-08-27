/**
 * go-page-supervision-ecriture.mjs - Module `supervision/`, sous-lot V9 :
 * l'ECRITURE du fichier de configuration distant et la RESTAURATION d'une
 * sauvegarde.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/supervision/   (onglet « Editeur de configuration »)
 *   laravel  http://localhost:8444/supervision     (`panneau-editor`)
 *
 * ══ POURQUOI CETTE SUITE PEUT CLIQUER, LA OU CELLE DE V8 NE POUVAIT PAS ══════
 *
 * Le geste de V8 (« relever tout le parc ») joignait `srv-zabbix` PAR
 * CONSTRUCTION : il fallait donc intercepter et avorter. Ici le geste porte sur
 * UNE machine, celle qu'on a choisie dans la liste — **Test-Server-Debian
 * (id 2, DEV)**. La production n'est jamais selectionnee, donc jamais jointe, et
 * le vrai bouton peut etre clique des deux cotes.
 *
 * CE QUE LE GESTE ECRIT, ET RIEN DE PLUS : `/etc/zabbix/zabbix_agent2.conf` sur
 * la machine de test, plus une copie datee dans le meme repertoire. Le
 * repertoire est nettoye A L'ENTREE et dans un `finally`, et l'etat rendu est
 * ANNONCE. Aucun autre chemin n'est touche.
 *
 * ══ CE QUE LA LECTURE A ETABLI AVANT LE MOINDRE CLIC ════════════════════════
 *
 *  1. **LA ROUTE FAIT TROIS CHOSES** : sauvegarde datee, ecriture par base64,
 *     puis `systemctl restart`. Mesure : la sauvegarde est faite AVANT
 *     l'ecriture et contient bien l'ancienne version ; le redemarrage n'est pas
 *     tente si l'ecriture a echoue ; le transport base64 est fidele a l'octet.
 *
 *  2. **AUCUN AGENT N'EST INSTALLE SUR LA MACHINE DE TEST, ET `systemctl` N'Y
 *     EXISTE PAS.** Le cas nominal y est donc « ecriture reussie, redemarrage
 *     impossible » — le TROISIEME cas, celui que le legacy perd. C'est
 *     exactement celui qu'il faut mesurer, et il arrive tout seul.
 *
 *  3. **LE LEGACY PERD L'AVERTISSEMENT.** `toast(__('config_remote_saved') ||
 *     res.message, 'success')` : une cle absente etant RENDUE TELLE QUELLE donc
 *     non vide, `res.message` n'est jamais lu. Le « restart echoue » que le
 *     backend construit exprès n'atteint jamais l'ecran, et l'ecran affiche
 *     `config_remote_saved` en toast VERT. Voir PARITE E-83.
 *
 *  4. **LA RESTAURATION N'A AUCUNE CONFIRMATION cote legacy** : liste dans une
 *     fenetre modale, un bouton par ligne, un clic, la configuration est ecrasee
 *     et l'agent redemarre.
 *
 *  5. **LA TRAVERSEE DE CHEMIN EST REFUSEE** (`^[\w.-]+\.bak\.\d{8}_\d{6}$`) :
 *     exoneration mesuree, conservee ici comme garde de non-regression.
 *
 * ══ LE DEFAUT DE MON PROPRE PORTAGE, CORRIGE EN V9 ══════════════════════════
 *
 * Les quatre URL de l'editeur etaient FIGEES sur `/supervision/zabbix/...`
 * pendant que le chemin affiche suivait le selecteur de plateforme : choisir
 * Telegraf annoncait `/etc/telegraf/telegraf.conf` et lisait
 * `/etc/zabbix/zabbix_agent2.conf`. C'est le defaut E-79 que V7 reprochait au
 * legacy, revenu par la ROUTE au lieu du CHEMIN. La suite de V7 ne pouvait pas
 * le voir : elle n'exercait que Zabbix, la seule plateforme ou l'URL figee se
 * trouvait etre la bonne.
 *
 * La propriete est donc mesuree SUR LES QUATRE PLATEFORMES, et elle est
 * NEGATIVE : aucune plateforme ne doit voir la route et le chemin affiche
 * designer des plateformes differentes. Mesuree par INTERCEPTION — on capture
 * l'URL que le clic emet et on l'avorte : quatre mesures, zero session SSH.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-supervision-ecriture.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';
import { execFileSync } from 'child_process';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/supervision' : '/supervision/';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

/** La SEULE machine que cette suite joint. `srv-zabbix` (id 1) n'est jamais choisie. */
const MACHINE_DEV = 2;
const CONTENEUR = 'rootwarden_test_server';
const REPERTOIRE = '/etc/zabbix';
const FICHIER = `${REPERTOIRE}/zabbix_agent2.conf`;
/** Reconnaissable : si ce texte finit dans le fichier, c'est cette suite. */
const MARQUEUR = 'Hostname=rw-e2e-v9';

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

/** `docker` par TABLEAU d'arguments : jamais une chaine de shell. */
function surLaMachine(...args) {
    try {
        return execFileSync('docker', ['exec', CONTENEUR, ...args],
            { encoding: 'utf8', timeout: 20000 });
    } catch (e) {
        return `(echec: ${String(e.message || e).split('\n')[0]})`;
    }
}

/** L'etat du repertoire, pour l'ANNONCER a l'entree comme en sortie. */
function etatDuRepertoire() {
    const sortie = surLaMachine('sh', '-c', `ls -1 ${REPERTOIRE} 2>/dev/null | tr '\\n' ' '`);
    return sortie.trim() || '(vide)';
}

function nettoie() {
    const avant = etatDuRepertoire();
    surLaMachine('sh', '-c',
        `rm -f ${FICHIER} ${REPERTOIRE}/zabbix_agent2.conf.bak.*`);
    return avant;
}

/** Ce que le fichier contient VRAIMENT, mesure sur la machine. */
function contenuDuFichier() {
    return surLaMachine('sh', '-c', `cat ${FICHIER} 2>/dev/null || echo '(ABSENT)'`).trim();
}

function sauvegardesPresentes() {
    const s = surLaMachine('sh', '-c',
        `ls -1 ${REPERTOIRE}/zabbix_agent2.conf.bak.* 2>/dev/null | wc -l`);
    return Number(String(s).trim()) || 0;
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
    /*
     * LE GARDE ANTI-REJEU TOTP EST PAR COMPTE ET EN BASE : il traverse les
     * contextes de navigateur ET les executions. Une seule nouvelle tentative,
     * avec un code neuf ; un echec apres cela est un vrai echec. Lecon de V8.
     */
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

/** JAMAIS D'ATTENTE FIXE : on attend la PROPRIETE, et on re-clique. Lecon de V8. */
async function ouvreEditeur(page) {
    for (let essai = 0; essai < 20; essai += 1) {
        const visible = await page.evaluate(() => {
            const onglet = document.querySelector('.tab-btn[data-tab="editor"]')
                || document.querySelector('[data-rw="onglet-editor"]');
            const panneau = document.querySelector('#tab-editor, [data-rw="panneau-editor"]');
            if (panneau && panneau.offsetParent !== null) return true;
            onglet?.click();

            return false;
        });
        if (visible) return true;
        await dors(400);
    }

    return false;
}

/** Choisit la machine DEV dans le selecteur, des deux cotes. */
async function choisitLaMachineDev(page, mid) {
    return page.evaluate((id) => {
        const sel = document.getElementById('editor-server')
            || document.querySelector('[data-rw="superv-serveur"]');
        if (! sel) return false;
        sel.value = String(id);
        sel.dispatchEvent(new Event('change', { bubbles: true }));

        return sel.value === String(id);
    }, mid);
}

/** Tout le texte du panneau visible, plus les porte-messages. Lecon de V4. */
async function texteVisible(page) {
    return page.evaluate(() => {
        const morceaux = [];
        const bloc = [...document.querySelectorAll('#tab-editor, [data-rw="panneau-editor"]')]
            .find((e) => e.offsetParent !== null);
        if (bloc) morceaux.push(bloc.innerText);
        for (const sel of ['#toast-container', '[data-rw="superv-sauver-message"]',
                           '[data-rw="superv-restaurer-message"]']) {
            const e = document.querySelector(sel);
            if (e) morceaux.push(e.innerText);
        }

        return morceaux.join('\n');
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
            await verifieMenuLegacy(page, '/supervision', verifie);
            await ctx.close();
            console.log(lignes.join('\n'));
            console.log(`\n${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
            await navigateur.close();
            process.exit(echecs > 0 ? 1 : 0);
        }
    }

    constate('cible', `${CIBLE} — ${PAGE}`);
    constate('machine jointe', `id ${MACHINE_DEV} (Test-Server-Debian, DEV) — srv-zabbix jamais choisie`);
    constate('etat du repertoire a l\'entree', nettoie());

    const { ctx, page } = await connecte('fr');
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const dialogues = [];
    page.on('dialog', (d) => { dialogues.push(`${d.type()}: ${d.message().slice(0, 70)}`); d.dismiss().catch(() => {}); });

    let appels = [];
    page.on('request', (r) => {
        const u = r.url();
        if (/api_proxy\.php\/|\/api\/gateway\//.test(u)) {
            appels.push(r.method() + ' ' + u.replace(BASE, '').slice(0, 80));
        }
    });

    const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie', (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(1800);
    verifie('l\'onglet de l\'editeur s\'ouvre', await ouvreEditeur(page));

    /* ══ 1. LE GESTE D'ECRITURE EXISTE, DES DEUX COTES ══════════════════════ */
    const declencheur = await page.evaluate(() => {
        const portage = document.querySelector('[data-rw="superv-sauver"]');
        if (portage) return { trouve: true, libelle: portage.textContent.trim() };
        const leg = [...document.querySelectorAll('button')]
            .find((b) => /saveRemoteConfig/.test(b.getAttribute('onclick') || ''));

        return leg ? { trouve: true, libelle: leg.textContent.trim() } : { trouve: false };
    });
    verifie('le geste d\'ecriture est present', declencheur.trouve, declencheur.libelle || 'absent');

    /* ══ 2. LE GARDE DU CONTENU VIDE ════════════════════════════════════════
     * Il ne joint rien : c'est le seul geste de V9 mesurable sans toucher la
     * machine. Cote legacy il ouvre un toast portant un francais EN DUR. */
    appels = [];
    verifie('la machine DEV est choisie', await choisitLaMachineDev(page, MACHINE_DEV));
    await page.evaluate(() => {
        const t = document.getElementById('editor-content')
            || document.querySelector('[data-rw="superv-editeur-contenu"]');
        if (t) { t.value = ''; }
    });
    await page.evaluate(() => {
        (document.querySelector('[data-rw="superv-sauver"]')
            || [...document.querySelectorAll('button')]
                .find((b) => /saveRemoteConfig/.test(b.getAttribute('onclick') || '')))?.click();
    });
    await dors(900);
    const refusVide = (await texteVisible(page)) + ' ' + dialogues.join(' ');
    verifie('un contenu vide est REFUSE, et le refus est enonce',
        /vide|empty/i.test(refusVide), refusVide.replace(/\n/g, ' ').slice(-90) || 'rien');
    verifie('le refus n\'envoie AUCUNE requete',
        appels.length === 0, appels.join(' | ') || 'aucune');

    /* ══ 3. LA ROUTE SUIT-ELLE LA PLATEFORME ? — LES QUATRE, PAR INTERCEPTION
     * Propriete NEGATIVE : aucune plateforme ne doit voir la route et le chemin
     * affiche designer des plateformes differentes. Les requetes sont AVORTEES :
     * quatre mesures, zero session SSH. C'est la correction du defaut de mon
     * propre portage de V7. */
    if (CIBLE === 'laravel') {
        const captures = [];
        await page.setRequestInterception(true);
        const arbitre = (r) => {
            if (/\/api\/gateway\/supervision\//.test(r.url())) {
                captures.push(r.url().replace(BASE, ''));
                r.abort('failed').catch(() => {});

                return;
            }
            r.continue().catch(() => {});
        };
        page.on('request', arbitre);

        const divergences = [];
        for (const plateforme of ['zabbix', 'centreon', 'prometheus', 'telegraf']) {
            captures.length = 0;
            await page.evaluate((p) => {
                const sel = document.querySelector('[data-rw="superv-plateforme"]');
                if (sel) { sel.value = p; sel.dispatchEvent(new Event('change', { bubbles: true })); }
            }, plateforme);
            await dors(400);
            const chemin = await page.evaluate(() =>
                document.querySelector('[data-rw="superv-editeur-chemin"]')?.textContent.trim() || '');
            await page.evaluate(() =>
                document.querySelector('[data-rw="superv-lire-config"]')?.click());
            await dors(900);
            const route = captures.find((u) => /config\/read/.test(u)) || '(aucune)';
            const segment = (route.match(/supervision\/([a-z]+)\//) || [])[1] || '?';
            constate(`plateforme ${plateforme}`, `chemin « ${chemin} » — route « ${route} »`);
            if (segment !== plateforme) {
                divergences.push(`${plateforme}: route vise ${segment}`);
            }
        }

        page.off('request', arbitre);
        await page.setRequestInterception(false);

        verifie('aucune plateforme ne voit la route et le chemin divergents',
            divergences.length === 0, divergences.join(' | ') || 'les quatre concordent');

        await page.evaluate(() => {
            const sel = document.querySelector('[data-rw="superv-plateforme"]');
            if (sel) { sel.value = 'zabbix'; sel.dispatchEvent(new Event('change', { bubbles: true })); }
        });
        await dors(400);
    }

    /* ══ 3bis. CHANGER DE SERVEUR VIDE LA ZONE — ET LE DIT ══════════════════
     * Vider est correct : la configuration d'un serveur n'a aucun sens pour un
     * autre. Mais V7 laissait ce champ en LECTURE SEULE, donc vider ne perdait
     * rien ; depuis que V9 le rend modifiable, le meme geste peut effacer ce que
     * quelqu'un vient de taper. Un effacement silencieux devient une perte de
     * travail. */
    await choisitLaMachineDev(page, MACHINE_DEV);
    await page.evaluate(() => {
        const t = document.getElementById('editor-content')
            || document.querySelector('[data-rw="superv-editeur-contenu"]');
        if (t) { t.value = 'saisie-a-perdre'; }
    });
    await page.evaluate(() => {
        const sel = document.getElementById('editor-server')
            || document.querySelector('[data-rw="superv-serveur"]');
        if (sel) { sel.value = ''; sel.dispatchEvent(new Event('change', { bubbles: true })); }
    });
    await dors(500);
    const apresChangement = await page.evaluate(() => {
        const t = document.getElementById('editor-content')
            || document.querySelector('[data-rw="superv-editeur-contenu"]');

        return {
            contenu: t ? t.value : '(pas de zone)',
            message: document.querySelector('[data-rw="superv-editeur-message"]')?.textContent.trim()
                || document.querySelector('#toast-container')?.innerText.trim() || '',
        };
    });
    constate('apres changement de serveur', `contenu « ${apresChangement.contenu} » `
        + `message « ${apresChangement.message.slice(0, 70)} »`);
    verifiePortage('effacer la saisie en changeant de serveur est ANNONCE',
        apresChangement.contenu === '' && apresChangement.message !== '',
        apresChangement.message ? `« ${apresChangement.message.slice(0, 80)} »` : 'aucun message');

    /* ══ 4. OUVRIR LE PANNEAU DE DECISION N'ENVOIE RIEN ═════════════════════ */
    /*
     * L'ORDRE COMPTE, ET IL M'A PIEGE. Choisir un serveur VIDE la zone d'edition
     * — c'est voulu : la configuration d'un serveur n'a aucun sens pour un autre.
     * Remplir puis choisir efface donc ce qu'on vient d'ecrire, et le garde
     * « contenu vide » refuse a juste titre. La suite echouait, le portage avait
     * raison. On choisit D'ABORD, on remplit ENSUITE.
     */
    await choisitLaMachineDev(page, MACHINE_DEV);
    await page.evaluate((marqueur) => {
        const t = document.getElementById('editor-content')
            || document.querySelector('[data-rw="superv-editeur-contenu"]');
        if (t) { t.value = `Server=10.0.0.1\n${marqueur}\n`; }
    }, MARQUEUR);

    if (CIBLE === 'laravel') {
        appels = [];
        await page.click('[data-rw="superv-sauver"]');
        await dors(700);
        const ouvert = await page.evaluate(() =>
            document.querySelector('[data-rw="superv-panneau-sauver"]')?.offsetParent !== null);
        verifie('le geste OUVRE un panneau de decision', ouvert);
        verifie('ouvrir le panneau n\'envoie AUCUNE requete',
            appels.length === 0, appels.join(' | ') || 'aucune');

        /* ══ 5. LE PANNEAU NOMME LE CHEMIN ET ENUMERE LES TROIS EFFETS ══════ */
        const panneau = await page.evaluate(() => {
            const p = document.querySelector('[data-rw="superv-panneau-sauver"]');
            const chemin = document.querySelector('[data-rw="superv-editeur-chemin"]');

            return {
                cout: document.querySelector('[data-rw="superv-sauver-cout"]')?.textContent.trim() || '',
                effets: [...document.querySelectorAll('[data-rw="superv-sauver-effets"] li')]
                    .map((e) => e.textContent.trim()),
                cheminAffiche: chemin?.textContent.trim() || '',
                visible: p?.offsetParent !== null,
            };
        });
        verifie('le panneau NOMME le chemin exact',
            panneau.cout.includes(panneau.cheminAffiche) && panneau.cheminAffiche !== '',
            `« ${panneau.cout} »`);
        verifie('les TROIS effets sont enumeres, pas noyes dans une phrase',
            panneau.effets.length === 3, `${panneau.effets.length} effet(s)`);
        verifie('les trois effets nomment la sauvegarde, l\'ecriture ET le redemarrage',
            /copie|sauvegarde|copy/i.test(panneau.effets[0] || '')
            && /remplac|replaced/i.test(panneau.effets[1] || '')
            && /redemarr|restart/i.test(panneau.effets[2] || ''),
            panneau.effets.join(' | ').slice(0, 110));

        /* ══ 6. ANNULER N'ENVOIE RIEN ══════════════════════════════════════ */
        appels = [];
        await page.click('[data-rw="superv-sauver-annuler"]');
        await dors(600);
        verifie('annuler referme le panneau', await page.evaluate(() =>
            document.querySelector('[data-rw="superv-panneau-sauver"]')?.offsetParent === null));
        verifie('annuler n\'envoie AUCUNE requete',
            appels.length === 0, appels.join(' | ') || 'aucune');
    }

    /* ══ 7. L'ECRITURE REELLE — LE TROISIEME CAS ════════════════════════════
     * La machine de test n'a NI agent NI `systemctl` : l'ecriture reussit, le
     * redemarrage echoue. C'est le cas que le legacy perd. */
    verifie('le fichier n\'existe pas avant le geste',
        contenuDuFichier() === '(ABSENT)', contenuDuFichier().slice(0, 40));

    const observateur = await page.evaluateHandle(() => {
        const vus = [];
        const cibles = ['#toast-container', '[data-rw="superv-sauver-message"]'];
        for (const sel of cibles) {
            const noeud = document.querySelector(sel);
            if (! noeud) continue;
            new MutationObserver(() => {
                const t = noeud.innerText.trim();
                if (t) vus.push(t);
            }).observe(noeud, { childList: true, subtree: true, characterData: true });
        }
        window.__vus = vus;

        return vus;
    });
    void observateur;

    await choisitLaMachineDev(page, MACHINE_DEV);
    await page.evaluate((marqueur) => {
        const t = document.getElementById('editor-content')
            || document.querySelector('[data-rw="superv-editeur-contenu"]');
        if (t) { t.value = `Server=10.0.0.1\n${marqueur}\n`; }
    }, MARQUEUR);

    if (CIBLE === 'laravel') {
        await page.click('[data-rw="superv-sauver"]');
        await dors(500);
        await page.click('[data-rw="superv-sauver-confirmer"]');
    } else {
        await page.evaluate(() => {
            [...document.querySelectorAll('button')]
                .find((b) => /saveRemoteConfig/.test(b.getAttribute('onclick') || ''))?.click();
        });
    }
    // Une session SSH prend une dizaine de secondes : on attend la PROPRIETE.
    for (let i = 0; i < 40 && contenuDuFichier() === '(ABSENT)'; i += 1) await dors(1000);
    await dors(1500);

    const ecrit = contenuDuFichier();
    verifie('le fichier a REELLEMENT ete ecrit sur la machine',
        ecrit.includes(MARQUEUR), ecrit.replace(/\n/g, ' ').slice(0, 60));

    const messages = await page.evaluate(() => (window.__vus || []).slice());
    const ecran = (await texteVisible(page)) + '\n' + messages.join('\n');
    constate('messages apparus pendant le geste',
        messages.slice(0, 3).map((m) => m.replace(/\n/g, ' ').slice(0, 70)).join(' | ') || 'aucun');

    /*
     * LA PROPRIETE CENTRALE DE V9. Le redemarrage n'a PAS eu lieu : l'ecran doit
     * le dire. Le legacy affiche `config_remote_saved` en vert et jette le
     * message du backend — la cle absente etant rendue telle quelle, son
     * `|| res.message` ne se declenche jamais.
     */
    verifiePortage('le redemarrage MANQUANT est annonce, pas tu',
        /redemarr|restart/i.test(ecran) && /PAS|not/i.test(ecran),
        (ecran.match(/[^\n]*(redemarr|restart)[^\n]*/i) || ['rien qui parle du redemarrage'])[0].slice(0, 110));
    verifiePortage('aucune cle de traduction ne s\'affiche en identifiant',
        ! /config_remote_saved|backup_restored|btn_restore/.test(ecran),
        (ecran.match(/config_remote_saved|backup_restored|btn_restore/g) || []).join(', ') || 'aucune');
    /*
     * LA TRACE TECHNIQUE RESTE HORS DE L'ECRAN. Le backend renvoie la sortie
     * d'erreur brute de la commande distante (« sh: 1: systemctl: not found ») :
     * lisible pour qui developpe, pas pour qui exploite.
     */
    verifiePortage('la sortie d\'erreur brute de la commande n\'est pas jetee a l\'ecran',
        ! /sh: \d+:|not found/i.test(ecran),
        (ecran.match(/sh: \d+:[^\n]*/) || ['aucune'])[0].slice(0, 70));

    /* ══ 8. UNE SECONDE ECRITURE CREE UNE SAUVEGARDE ════════════════════════
     * La propriete d'une sauvegarde a deux moities : elle EXISTE, et elle porte
     * l'ANCIENNE version. */
    verifie('aucune sauvegarde avant la seconde ecriture',
        sauvegardesPresentes() === 0, `${sauvegardesPresentes()}`);
    await choisitLaMachineDev(page, MACHINE_DEV);
    await page.evaluate((marqueur) => {
        const t = document.getElementById('editor-content')
            || document.querySelector('[data-rw="superv-editeur-contenu"]');
        if (t) { t.value = `Server=10.0.0.2\n${marqueur}-bis\n`; }
    }, MARQUEUR);
    if (CIBLE === 'laravel') {
        await page.click('[data-rw="superv-sauver"]');
        await dors(500);
        await page.click('[data-rw="superv-sauver-confirmer"]');
    } else {
        await page.evaluate(() => {
            [...document.querySelectorAll('button')]
                .find((b) => /saveRemoteConfig/.test(b.getAttribute('onclick') || ''))?.click();
        });
    }
    for (let i = 0; i < 40 && sauvegardesPresentes() === 0; i += 1) await dors(1000);
    await dors(1500);

    verifie('une sauvegarde datee a ete creee', sauvegardesPresentes() >= 1,
        `${sauvegardesPresentes()} sauvegarde(s)`);
    const ancienne = surLaMachine('sh', '-c',
        `cat ${REPERTOIRE}/zabbix_agent2.conf.bak.* 2>/dev/null | head -5`).trim();
    verifie('la sauvegarde porte l\'ANCIENNE version, pas la nouvelle',
        ancienne.includes('10.0.0.1') && ! ancienne.includes('10.0.0.2'),
        ancienne.replace(/\n/g, ' ').slice(0, 60) || '(vide)');

    /* ══ 9. LA RESTAURATION ════════════════════════════════════════════════ */
    await page.evaluate(() => {
        (document.querySelector('[data-rw="superv-lire-sauvegardes"]')
            || [...document.querySelectorAll('button')]
                .find((b) => /loadBackups/.test(b.getAttribute('onclick') || '')))?.click();
    });
    await dors(6000);

    const listee = await page.evaluate(() => {
        const portage = [...document.querySelectorAll('[data-rw="superv-restaurer"]')];
        if (portage.length) {
            return { nb: portage.length, libelle: portage[0].textContent.trim(), portage: true };
        }
        const leg = [...document.querySelectorAll('#backups-list button')];

        return { nb: leg.length, libelle: leg[0]?.textContent.trim() || '', portage: false };
    });
    constate('sauvegardes listees a l\'ecran', `${listee.nb} — bouton « ${listee.libelle} »`);
    verifie('la sauvegarde apparait dans la liste, avec son bouton', listee.nb >= 1);

    if (CIBLE === 'laravel') {
        /* LE BOUTON OUVRE, IL N'ENVOIE PAS — le legacy restaure au premier clic. */
        appels = [];
        await page.click('[data-rw="superv-restaurer"]');
        await dors(700);
        const ouvert = await page.evaluate(() =>
            document.querySelector('[data-rw="superv-panneau-restaurer"]')?.offsetParent !== null);
        verifie('le bouton de restauration OUVRE un panneau de decision', ouvert);
        verifie('ouvrir ce panneau n\'envoie AUCUNE requete',
            appels.length === 0, appels.join(' | ') || 'aucune');
        const cout = await page.evaluate(() =>
            document.querySelector('[data-rw="superv-restaurer-cout"]')?.textContent.trim() || '');
        verifie('le panneau NOMME la sauvegarde visee et le fichier ecrase',
            /\.bak\.\d{8}_\d{6}/.test(cout) && /zabbix_agent2\.conf/.test(cout),
            `« ${cout.slice(0, 100) }»`);

        /* LA RESTAURATION ABOUTIT, ET LE FICHIER REDEVIENT L'ANCIEN. */
        await page.click('[data-rw="superv-restaurer-confirmer"]');
        for (let i = 0; i < 40 && ! contenuDuFichier().includes('10.0.0.1'); i += 1) await dors(1000);
        await dors(1000);
        verifie('la restauration a REELLEMENT remis l\'ancienne version',
            contenuDuFichier().includes('10.0.0.1'),
            contenuDuFichier().replace(/\n/g, ' ').slice(0, 60));
        /*
         * LE PORTE-MESSAGES DE LA RESTAURATION, ET LUI SEUL. Un premier jet lisait
         * tout le panneau visible : le message de l'ECRITURE, encore a l'ecran,
         * satisfaisait l'assertion — elle passait sans jamais regarder la
         * restauration. Un PASS dont on ne sait pas pourquoi il passe ne vaut
         * rien. On exige en plus que le message NOMME la sauvegarde.
         */
        const apresRestauration = await page.evaluate(() =>
            document.querySelector('[data-rw="superv-restaurer-message"]')?.textContent.trim() || '');
        verifie('la restauration a son PROPRE message, et il nomme la sauvegarde',
            /\.bak\.\d{8}_\d{6}/.test(apresRestauration),
            `« ${apresRestauration.slice(0, 90)} »`);
        verifie('le redemarrage MANQUANT est annonce la aussi',
            /redemarr|restart/i.test(apresRestauration) && /PAS|not/i.test(apresRestauration),
            `« ${apresRestauration.slice(0, 100)} »`);
    }

    verifiePortage('aucune boite native ne s\'ouvre de tout le parcours',
        dialogues.length === 0, dialogues.join(', ') || 'aucune');

    const texte = await page.evaluate(() => document.body.innerText);
    verifie('aucun identifiant de traduction a l\'ecran (fr)',
        ! /superv\.[a-z_]+/.test(texte),
        (texte.match(/superv\.[a-z_]+/g) || []).slice(0, 3).join(', '));
    await ctx.close();

    /* ══ 10. LA PASSE ANGLAISE ═════════════════════════════════════════════
     * Le garde anti-rejeu TOTP traverse les contextes : on attend le
     * basculement, et on VERIFIE que la session a tenu — sinon les controles
     * d'i18n passent sur l'ecran de connexion, qui ne porte aucun identifiant. */
    await dors((resteFenetre() + 1) * 1000);
    const { ctx: ctxEn, page: pageEn } = await connecte('en');
    await pageEn.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await dors(1500);
    verifie('la seconde session (en) est bien authentifiee',
        ! /connexion|login/.test(pageEn.url()), pageEn.url().replace(BASE, ''));
    verifie('l\'onglet de l\'editeur s\'ouvre (en)', await ouvreEditeur(pageEn));
    const texteEn = await pageEn.evaluate(() => document.body.innerText);
    verifie('aucun identifiant de traduction a l\'ecran (en)',
        ! /superv\.[a-z_]+/.test(texteEn),
        (texteEn.match(/superv\.[a-z_]+/g) || []).slice(0, 3).join(', '));
    const anglais = (texteEn.match(/Write to the server|Target file|List the backups/g) || []);
    verifiePortage('le geste d\'ecriture est traduit en anglais',
        anglais.length > 0,
        anglais.length ? `trouve : ${anglais.join(', ')}` : 'aucun libelle anglais');
    await ctxEn.close();

    verifie('aucune erreur JS pendant toute la sequence',
        erreursJs.length === 0, erreursJs.slice(0, 3).join(' · ') || 'aucune');
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
} finally {
    /*
     * L'ETAT EST RENDU, ET IL EST ANNONCE. Cette suite ecrit sur une machine :
     * le fichier et ses copies datees sont supprimes, et le repertoire est relu
     * pour le PROUVER plutot que pour l'affirmer.
     */
    const avant = nettoie();
    lignes.push(`INFO  repertoire avant nettoyage de sortie : ${avant}`);
    const apres = etatDuRepertoire();
    lignes.push(`${apres === '(vide)' ? 'PASS' : 'FAIL'}  la machine de test est rendue a son `
        + `etat initial  — ${apres}`);
    if (apres !== '(vide)') echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
