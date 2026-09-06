/**
 * go-page-supervision-config.mjs - Module `supervision/`, sous-lot V3 : la
 * configuration globale, EN LECTURE.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/supervision/   (onglet « Configuration globale »)
 *   laravel  http://localhost:8444/supervision     (panneau `panneau-config`)
 *
 * V3 NE MODIFIE RIEN et ne joint aucune machine. L'ECRITURE est V4.
 *
 * CE QUE LA MESURE DU SCHEMA A ETABLI, avant d'ecrire une assertion :
 *
 *  1. **`supervision_config` EST VIDE.** Zero ligne, pour les quatre
 *     plateformes. Sans fixture, ce sous-lot ne mesurerait donc qu'un ecran
 *     d'absence — et une suite qui ne mesure que l'absence de donnee ne mesure
 *     pas la lecture. D'ou les deux phases ci-dessous.
 *
 *  2. **AUCUNE CONTRAINTE D'UNICITE SUR `platform`.** La cle primaire est `id`
 *     seul. Or `_get_global_config()` (`supervision.py:128`) et la page legacy
 *     lisent tous deux `ORDER BY id DESC LIMIT 1` : « la » configuration globale
 *     d'une plateforme est en realite **la plus recente**, et rien n'empeche
 *     d'en accumuler. Ce n'est pas la meme chose, et cela se mesure : la suite
 *     pose DEUX lignes pour Zabbix et verifie que c'est la seconde qui s'affiche.
 *
 *  3. **`tls_psk_value` est commente « Chiffre en DB (encryptPassword) »** et
 *     `telegraf_output_token` fait 512 caracteres. Le legacy rend un masque
 *     (`'********'`) dans un `<input type="password">`. LA PROPRIETE A MESURER
 *     N'EST PAS « un masque s'affiche » MAIS « la valeur reelle n'est nulle part
 *     dans la reponse » — masque compris, un attribut peut porter autre chose que
 *     ce que l'oeil lit. La suite cherche donc la valeur posee en fixture dans le
 *     SOURCE SERVI, pas dans le texte visible.
 *
 * UNE ASYMETRIE DU LEGACY, mesuree en V2 dans la trace reseau et confirmee ici :
 * la configuration **Zabbix** est rendue COTE SERVEUR (`$globalConfig` dans
 * `index.php`), les **trois autres** sont rendues avec des valeurs par defaut en
 * dur puis remplies par un appel client `GET /supervision/config/<plateforme>`
 * (`main.js:159`). Deux chemins pour une meme donnee. Le portage n'en a qu'un.
 *
 * SURETE — POURQUOI CETTE FIXTURE NE DECLENCHE RIEN. `backend/scheduler.py` ne
 * lit JAMAIS `supervision_config` (verifie : zero occurrence). Seuls un
 * deploiement ou une reconfiguration la lisent, et aucun des deux ne part sans un
 * clic. Les lignes posees portent un marqueur reconnaissable, sont nettoyees A
 * L'ENTREE et dans un `finally`, et la suite ANNONCE l'etat restaure.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-supervision-config.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
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
const PAGE = CIBLE === 'laravel' ? '/supervision' : '/supervision/';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

/*
 * LA FIXTURE. Des valeurs reconnaissables a l'oeil comme au `grep` : le
 * nettoyage se fait par ce marqueur, et un reliquat se voit dans le journal.
 */
const MARQUE = 'rw-e2e-v3';
const SERVEUR_ANCIEN = `${MARQUE}-ancien.example`;
const SERVEUR_RECENT = `${MARQUE}-recent.example`;
const PSK_SECRET = `${MARQUE}-PSK-b9f4c1a7d2e5`;
const IDENTITE_PSK = `${MARQUE}-identite`;
const PORT_RECENT = '10099';
const CENTREON_HOTE = `${MARQUE}-centreon.example`;

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

/** Combien de lignes de fixture restent en base. */
function fixturesEnBase() {
    return compteEnBase(
        'SELECT COUNT(*) FROM rootwarden.supervision_config '
        + `WHERE zabbix_server LIKE '${MARQUE}%' OR centreon_host LIKE '${MARQUE}%' `
        + `OR tls_psk_identity LIKE '${MARQUE}%'`);
}

function nettoie() {
    const n = fixturesEnBase();
    litEnBase('DELETE FROM rootwarden.supervision_config '
        + `WHERE zabbix_server LIKE '${MARQUE}%' OR centreon_host LIKE '${MARQUE}%' `
        + `OR tls_psk_identity LIKE '${MARQUE}%'`);
    return n;
}

/**
 * DEUX lignes Zabbix, volontairement, plus une pour Centreon.
 *
 * Les deux lignes Zabbix ne sont pas un artifice : la table n'a aucune
 * contrainte d'unicite sur `platform`, et les deux portails lisent
 * `ORDER BY id DESC LIMIT 1`. Poser deux lignes est donc la seule facon de
 * mesurer ce que « la configuration globale » designe vraiment.
 */
function poseLaFixture() {
    litEnBase(
        'INSERT INTO rootwarden.supervision_config '
        + '(platform, agent_type, agent_version, zabbix_server, listen_port, '
        + 'hostname_pattern, tls_connect, tls_accept) VALUES '
        + `('zabbix', 'zabbix-agent', '7.0', '${SERVEUR_ANCIEN}', 10050, `
        + "'{machine.name}', 'unencrypted', 'unencrypted')");
    litEnBase(
        'INSERT INTO rootwarden.supervision_config '
        + '(platform, agent_type, agent_version, zabbix_server, listen_port, '
        + 'hostname_pattern, tls_connect, tls_accept, tls_psk_identity, tls_psk_value, '
        + 'host_metadata_template) VALUES '
        + `('zabbix', 'zabbix-agent2', '7.2', '${SERVEUR_RECENT}', ${PORT_RECENT}, `
        + `'{machine.name}', 'psk', 'psk', '${IDENTITE_PSK}', '${PSK_SECRET}', `
        + "'LinuxInterne')");
    litEnBase(
        'INSERT INTO rootwarden.supervision_config '
        + '(platform, centreon_host, centreon_port, hostname_pattern) VALUES '
        + `('centreon', '${CENTREON_HOTE}', 4317, '{machine.name}')`);
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

async function choisitPlateforme(page, nom) {
    await page.evaluate((n) => {
        const sel = document.getElementById('agent-platform')
            || document.querySelector('[data-rw="superv-plateforme"]');
        if (!sel) return;
        sel.value = n;
        sel.dispatchEvent(new Event('change', { bubbles: true }));
    }, nom);
    await dors(1800);
}

/**
 * Ce que la configuration AFFICHEE porte, quelle que soit la cible.
 *
 * Le legacy montre des champs de formulaire, le portage un rendu en lecture :
 * on ne compare donc pas des `value` a des `textContent`, on collecte LES DEUX
 * dans le bloc VISIBLE et on cherche des valeurs. La propriete est « la donnee
 * de la base est a l'ecran », pas « elle est dans tel type de noeud ».
 */
async function configAffichee(page) {
    return page.evaluate(() => {
        const bloc = [...document.querySelectorAll(
            '[id^="config-"], [data-rw="superv-config-corps"]')]
            .find((e) => e.offsetParent !== null);
        if (!bloc) return { present: false, texte: '', valeurs: [], pskVisible: null };
        const valeurs = [...bloc.querySelectorAll('input, select, textarea')].map((c) => {
            if (c.tagName === 'SELECT') {
                return c.options[c.selectedIndex]?.value ?? '';
            }
            return c.value;
        });
        const psk = document.getElementById('psk-fields')
            || bloc.querySelector('[data-rw="superv-config-psk"]');
        return {
            present: true,
            id: bloc.id || bloc.dataset.rw,
            texte: bloc.innerText,
            valeurs,
            pskVisible: psk ? psk.offsetParent !== null : null,
        };
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
    const reliquats = nettoie();
    constate('fixtures nettoyees a l\'entree', reliquats);

    // ── Phase A : la table est vide, et c'est l'etat reel du parc ────────────
    const restant = compteEnBase('SELECT COUNT(*) FROM rootwarden.supervision_config');
    constate('lignes de configuration en base avant fixture', restant);
    verifie('la table est bien vide avant la fixture — sinon la mesure porterait '
        + 'sur des donnees d\'exploitation',
        restant === 0, `${restant} ligne(s)`);

    const { ctx, page } = await connecte('fr');
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const dialogues = [];
    page.on('dialog', (d) => { dialogues.push(d.type()); d.dismiss().catch(() => {}); });
    const appels = [];
    page.on('request', (r) => {
        if (/api_proxy\.php\/|\/api\/gateway\//.test(r.url())) {
            appels.push(r.method() + ' ' + r.url().replace(BASE, '').slice(0, 70));
        }
    });

    let rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie', (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(2500);

    const sansConfig = await configAffichee(page);
    constate('bloc de configuration visible', sansConfig.id || 'aucun');
    verifie('le bloc de configuration de la plateforme active est rendu',
        sansConfig.present === true, sansConfig.id || 'introuvable');
    /*
     * L'ABSENCE DE CONFIGURATION SE DIT. Sans ligne en base, les deux portails
     * affichent des valeurs par defaut : sans avertissement, un exploitant les
     * lit comme une configuration enregistree. La propriete est « la page
     * annonce qu'aucune configuration n'est enregistree », pas un libelle
     * particulier — chaque cible a le sien.
     */
    const attenduSansConfig = CIBLE === 'laravel'
        ? /Aucune configuration globale/i
        : /Aucune configuration globale/i;
    verifie('sans ligne en base, la page annonce l\'absence de configuration',
        attenduSansConfig.test(sansConfig.texte),
        sansConfig.texte.slice(0, 120).replace(/\n/g, ' '));

    // ── Phase B : la fixture, et ce que « globale » designe vraiment ─────────
    poseLaFixture();
    constate('fixture posee', `${fixturesEnBase()} ligne(s) — deux pour zabbix, une pour centreon`);

    appels.length = 0;
    rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await dors(2500);
    const avecConfig = await configAffichee(page);
    const source = await page.content();

    constate('valeurs rendues dans le bloc actif',
        avecConfig.valeurs.filter(Boolean).join(' | ').slice(0, 300) || 'aucune');

    const toutLeBloc = avecConfig.texte + ' ' + avecConfig.valeurs.join(' ');
    verifie('la configuration de la base est a l\'ecran',
        toutLeBloc.includes(SERVEUR_RECENT), `serveur attendu ${SERVEUR_RECENT}`);
    /*
     * DEUX LIGNES, UNE SEULE AFFICHEE — et c'est la PLUS RECENTE. Faute de
     * contrainte d'unicite, « la configuration globale » est un choix
     * d'implementation, pas une propriete du schema.
     */
    verifie('c\'est la ligne la PLUS RECENTE qui s\'affiche, pas la premiere',
        toutLeBloc.includes(SERVEUR_RECENT) && ! toutLeBloc.includes(SERVEUR_ANCIEN),
        `recent present=${toutLeBloc.includes(SERVEUR_RECENT)}, `
        + `ancien present=${toutLeBloc.includes(SERVEUR_ANCIEN)}`);
    verifie('le port de la ligne recente est celui affiche',
        toutLeBloc.includes(PORT_RECENT), `port attendu ${PORT_RECENT}`);

    /*
     * LE SECRET. On cherche dans le SOURCE SERVI, pas dans le texte visible : un
     * attribut peut porter autre chose que ce que l'oeil lit, et c'est
     * precisement le cas d'un `<input type="password">` dont la `value` ne
     * s'affiche jamais.
     */
    const secretDansSource = source.includes(PSK_SECRET);
    const secretDansValeurs = avecConfig.valeurs.some((v) => String(v).includes(PSK_SECRET));
    constate('secret PSK recherche dans le source servi',
        `source=${secretDansSource}, champs=${secretDansValeurs}`);
    verifie('la valeur reelle du PSK n\'est NULLE PART dans la reponse',
        ! secretDansSource && ! secretDansValeurs,
        secretDansSource ? 'presente dans le HTML servi'
            : (secretDansValeurs ? 'presente dans un champ' : 'absente'));
    verifie('l\'identite PSK, elle, est bien affichee — ce n\'est pas un secret',
        toutLeBloc.includes(IDENTITE_PSK), `identite attendue ${IDENTITE_PSK}`);
    verifie('la page indique que le chiffrement PSK est en place',
        avecConfig.pskVisible === true || /PSK/i.test(toutLeBloc),
        `bloc PSK visible=${avecConfig.pskVisible}`);

    // ── L'asymetrie du legacy : zabbix cote serveur, les autres cote client ──
    appels.length = 0;
    await choisitPlateforme(page, 'centreon');
    const appelsCentreon = appels.slice();
    const centreon = await configAffichee(page);
    constate('appels a la bascule vers centreon',
        appelsCentreon.length ? appelsCentreon.join(' | ') : 'aucun');
    constate('bloc centreon',
        `${centreon.id} — ${centreon.valeurs.filter(Boolean).join(' | ').slice(0, 160)}`);

    const centreonAffiche = (centreon.texte + ' ' + centreon.valeurs.join(' '))
        .includes(CENTREON_HOTE);
    verifie('la configuration de Centreon est affichee elle aussi',
        centreonAffiche, `hote attendu ${CENTREON_HOTE}`);
    verifiePortage('afficher la configuration d\'une autre plateforme n\'emet aucun appel',
        appelsCentreon.length === 0,
        `${appelsCentreon.length} appel(s) — le legacy rend zabbix cote serveur et `
        + 'les trois autres par GET /supervision/config/<plateforme>');

    await ctx.close();
    await dors((resteFenetre() + 1) * 1000);

    // ── En anglais : aucun libelle francais residuel dans le bloc ────────────
    const en = await connecte('en');
    await en.page.goto(`${BASE}${PAGE}?lang=en`, { waitUntil: 'networkidle2' });
    await dors(2500);
    const blocEn = await configAffichee(en.page);
    const francaisResiduel = ['Enregistrer', 'Aucune configuration', 'Configuration globale']
        .filter((m) => blocEn.texte.includes(m));
    constate('francais residuel dans le bloc rendu en anglais',
        francaisResiduel.join(', ') || 'aucun');
    verifiePortage('le bloc de configuration rendu en anglais ne garde aucun libelle francais',
        francaisResiduel.length === 0, francaisResiduel.join(', ') || 'aucun');

    const clesVisibles = ['no_config', 'agent_type', 'zabbix_server', 'listen_port',
        'hostname_pattern', 'tls_connect', 'tls_accept', 'host_metadata', 'extra_config',
        'config_saved', 'config_loaded']
        .filter((c) => blocEn.texte.includes(c));
    verifie('aucune cle de traduction ne s\'affiche en identifiant',
        clesVisibles.length === 0, clesVisibles.join(', ') || 'aucune');

    verifie('aucune boite native n\'a ete ouverte',
        dialogues.length === 0, dialogues.join(', ') || 'aucune');
    verifie('aucune erreur JS pendant toute la sequence',
        erreursJs.length === 0, erreursJs.slice(0, 3).join(' · ') || 'aucune');
    await en.ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
} finally {
    /*
     * RESTAURATION, ET ELLE S'ANNONCE. Une fixture de configuration laissee en
     * base changerait ce qu'un deploiement pousserait sur les machines : le
     * nettoyage n'est pas une politesse, c'est une condition de surete.
     */
    const restes = nettoie();
    lignes.push(`INFO  fixtures supprimees en sortie : ${restes}`);
    const total = compteEnBase('SELECT COUNT(*) FROM rootwarden.supervision_config');
    lignes.push(`${total === 0 ? 'PASS' : 'FAIL'}  la table de configuration est rendue `
        + `a son etat initial  — ${total} ligne(s) restante(s)`);
    if (total !== 0) echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
