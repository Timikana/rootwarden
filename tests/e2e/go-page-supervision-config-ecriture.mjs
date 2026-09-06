/**
 * go-page-supervision-config-ecriture.mjs - Module `supervision/`, sous-lot V4 :
 * l'ECRITURE de la configuration globale.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/supervision/   (onglet « Configuration globale »)
 *   laravel  http://localhost:8444/supervision     (formulaire du bloc visible)
 *
 * PREMIER SOUS-LOT DU MODULE QUI ECRIT. Aucune machine n'est jointe, aucun SSH
 * n'est ouvert — mais la table modifiee est celle que le DEPLOIEMENT lira.
 *
 * SURETE. `backend/scheduler.py` ne lit JAMAIS `supervision_config` (verifie en
 * V3 : zero occurrence), donc ecrire ici n'arme aucun declencheur. La table est
 * VIDE hors fixtures. Toutes les lignes posees portent un marqueur, sont
 * nettoyees A L'ENTREE et dans un `finally`, et l'etat restaure est ANNONCE.
 *
 * ══ LE DEFAUT CENTRAL : UN `UPDATE` SANS FILTRE DE PLATEFORME ══
 *
 * `backend/routes/supervision.py:508` fait
 *   SELECT id, tls_psk_value FROM supervision_config ORDER BY id DESC LIMIT 1
 * — **sans `WHERE platform`** — puis `UPDATE ... WHERE id = %s`.
 *
 * Consequence, et c'est la propriete que cette suite mesure : si la ligne la plus
 * recente appartient a une AUTRE plateforme, enregistrer le formulaire Zabbix
 * ecrit les valeurs Zabbix DANS LA LIGNE CENTREON, et laisse la ligne Zabbix
 * intacte. L'exploitant voit un succes, la configuration Zabbix n'a pas bouge, et
 * la configuration Centreon est corrompue.
 *
 * La suite pose donc une ligne `zabbix` PUIS une ligne `centreon` (id plus grand),
 * enregistre le formulaire Zabbix, et regarde EN BASE laquelle a change. La
 * propriete asserte est « enregistrer une plateforme ne modifie que SA ligne » —
 * pas « le message de succes s'affiche », que les deux cibles affichent.
 *
 * ══ CE QUE V4 FERME ENCORE ══
 *
 *  - **`config_saved`** : la cle du message de succes, absente de `js.php`, donc
 *    affichee en clair. C'est l'une des onze, et seul V4 la rend atteignable.
 *  - **UNE DOUZIEME CLE, non repertoriee** : `main.js:294` appelle
 *    `__('supervision.zabbix_server')` — avec son prefixe de module. Or `__()`
 *    prefixe DEJA par `js.` et cherche dans `js.php` : la cle ne peut pas etre
 *    trouvee, et l'ecran rend l'identifiant brut suivi du mot « requis », ecrit
 *    EN DUR en francais.
 *  - **UN ENREGISTREMENT QUI ECRASE UN CHAMP AFFICHE** : `savePlatformConfig()`
 *    (`main.js:186`) force `hostname_pattern: '{machine.name}'` et
 *    `extra_config: null` quelles que soient les valeurs a l'ecran. Deux champs
 *    que l'utilisateur remplit, et que l'enregistrement jette.
 *
 * ══ LE SECRET ══
 *
 * Le PSK n'est PAS retape a chaque enregistrement : le champ porte un masque. Les
 * deux cibles doivent donc PRESERVER le blob chiffre existant — mesure faite en
 * base, sur la valeur stockee, pas sur l'ecran. Et un PSK reellement saisi doit
 * arriver CHIFFRE : la suite verifie que la valeur en base n'est pas la valeur
 * tapee.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-supervision-config-ecriture.mjs
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

const MARQUE = 'rw-e2e-v4';
/** Ce qui est POSE en base avant l'enregistrement. */
const ZBX_AVANT = `${MARQUE}-zbx-avant.example`;
const CENTREON_AVANT = `${MARQUE}-centreon-avant.example`;
const PSK_EXISTANT = `${MARQUE}-psk-existant`;
/** Ce qui est TAPE dans le formulaire. */
const ZBX_TAPE = `${MARQUE}-zbx-tape.example`;
const PORT_TAPE = '10077';
const MOTIF_TAPE = `${MARQUE}-motif`;
/** Un PSK reellement saisi : il ne doit JAMAIS se retrouver en clair en base. */
const PSK_TAPE = `${MARQUE}-psk-tape-9f3c1b`;

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

/** Toute ligne de fixture, quelle que soit la colonne qui porte la marque. */
const OU_MARQUE = `zabbix_server LIKE '${MARQUE}%' OR centreon_host LIKE '${MARQUE}%' `
    + `OR hostname_pattern LIKE '${MARQUE}%' OR tls_psk_identity LIKE '${MARQUE}%'`;

function nettoie() {
    const n = compteEnBase(`SELECT COUNT(*) FROM rootwarden.supervision_config WHERE ${OU_MARQUE}`);
    litEnBase(`DELETE FROM rootwarden.supervision_config WHERE ${OU_MARQUE}`);
    return n;
}

/**
 * UNE VALEUR EN BASE, avec SENTINELLE explicite.
 *
 * `litEnBase` trime puis filtre les valeurs vides : une colonne NULL
 * DISPARAITRAIT de la liste et le decalage passerait inapercu. La sentinelle
 * rend l'absence lisible au lieu de la faire disparaitre.
 */
function valeurEnBase(colonne, plateforme) {
    return litEnBase(
        `SELECT COALESCE(NULLIF(TRIM(${colonne}), ''), '(VIDE)') `
        + 'FROM rootwarden.supervision_config '
        + `WHERE platform = '${plateforme}' ORDER BY id DESC LIMIT 1`)[0] ?? '(AUCUNE LIGNE)';
}

/**
 * La fixture : Zabbix D'ABORD, Centreon ENSUITE.
 *
 * L'ordre est le coeur du test. `supervision_config` n'a aucune contrainte
 * d'unicite sur `platform` et le backend prend `ORDER BY id DESC LIMIT 1` sans
 * filtre : la ligne Centreon, plus recente, est donc celle qu'il croit etre « la »
 * configuration — y compris quand on enregistre le formulaire Zabbix.
 */
function poseLaFixture() {
    litEnBase(
        'INSERT INTO rootwarden.supervision_config '
        + '(platform, agent_type, agent_version, zabbix_server, listen_port, '
        + 'hostname_pattern, tls_connect, tls_accept, tls_psk_identity, tls_psk_value) VALUES '
        + `('zabbix', 'zabbix-agent2', '7.0', '${ZBX_AVANT}', 10050, `
        + `'{machine.name}', 'psk', 'psk', '${MARQUE}-identite', '${PSK_EXISTANT}')`);
    litEnBase(
        'INSERT INTO rootwarden.supervision_config '
        + '(platform, centreon_host, centreon_port, hostname_pattern) VALUES '
        + `('centreon', '${CENTREON_AVANT}', 4317, '{machine.name}')`);
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

/** Ecrit dans un champ, sur l'une ou l'autre cible. Rend false si absent. */
async function saisit(page, idLegacy, colonnePortage, valeur) {
    return page.evaluate((a, b, v) => {
        const el = document.getElementById(a)
            || document.querySelector(`[data-rw="superv-config-champ-${b}"]`);
        if (!el) return false;
        el.value = v;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        return true;
    }, idLegacy, colonnePortage, valeur);
}

/** Declenche l'enregistrement, sur l'une ou l'autre cible. */
async function enregistre(page) {
    const declenche = await page.evaluate(() => {
        const bouton = document.querySelector('[data-rw="superv-config-enregistrer"]');
        if (bouton) { bouton.click(); return 'bouton du portage'; }
        if (typeof window.saveGlobalConfig === 'function') { window.saveGlobalConfig(); return 'saveGlobalConfig'; }
        return null;
    });
    await dors(2500);
    return declenche;
}

/**
 * Le texte ou un message d'enregistrement PEUT apparaitre, sur l'une ou l'autre
 * cible.
 *
 * PREMIERE MESURE FAUSSE, CORRIGEE : ne lire que le bloc de configuration
 * declarait le refus « non enonce » alors qu'il l'etait — le legacy le passe a
 * `toast()`, qui ecrit dans `#toast-container`, TRES LOIN du bloc dans le
 * document. Chercher dans le seul bloc concerne est la bonne regle quand on
 * cherche ce que le bloc affiche ; ici on cherche un MESSAGE, et c'est la cible
 * qui decide ou elle le met. On lit donc le bloc ET le porte-messages, et rien
 * d'autre : `body` entier ramenerait le menu et les libelles du gabarit.
 */
async function texteMessages(page) {
    return page.evaluate(() => {
        const morceaux = [];
        const bloc = [...document.querySelectorAll('[id^="config-"], [data-rw^="panneau-config"]')]
            .find((e) => e.offsetParent !== null);
        if (bloc) morceaux.push(bloc.innerText);
        // E-250 : les DEUX ancres — cette collecte prend le message quel
        // qu'il soit, pour le donner a une recherche textuelle.
        for (const sel of ['#toast-container',
                           '[data-rw="superv-config-succes"]', '[data-rw="superv-config-erreur"]']) {
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
            await verifieMenuLegacy(page, '/supervision', verifie, constate);
            await ctx.close();
            console.log(lignes.join('\n'));
            console.log(`\n${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
            await navigateur.close();
            process.exit(echecs > 0 ? 1 : 0);
        }
    }

    constate('cible', `${CIBLE} — ${PAGE}`);
    constate('fixtures nettoyees a l\'entree', nettoie());

    const avantTout = compteEnBase('SELECT COUNT(*) FROM rootwarden.supervision_config');
    verifie('la table ne porte aucune donnee d\'exploitation avant la fixture',
        avantTout === 0, `${avantTout} ligne(s)`);

    poseLaFixture();
    constate('fixture posee',
        `zabbix=${valeurEnBase('zabbix_server', 'zabbix')} puis `
        + `centreon=${valeurEnBase('centreon_host', 'centreon')} (id plus grand)`);

    const { ctx, page } = await connecte('fr');
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const dialogues = [];
    page.on('dialog', (d) => { dialogues.push(d.type()); d.dismiss().catch(() => {}); });

    const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie', (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(2500);

    // ── Le refus quand le serveur est vide ──────────────────────────────────
    const videPose = await saisit(page, 'cfg-zabbix-server', 'zabbix_server', '');
    constate('champ serveur vide pose', videPose ? 'oui' : 'champ introuvable');
    const declencheVide = await enregistre(page);
    constate('enregistrement declenche (serveur vide)', declencheVide || 'aucun point d\'entree');
    const texteRefus = await texteMessages(page);
    const refusEnonce = /requis|required|obligatoire|indispensable/i.test(texteRefus);
    constate('refus enonce a l\'ecran', refusEnonce ? 'oui' : 'NON');
    verifie('un serveur vide est REFUSE, et le refus est enonce',
        Boolean(declencheVide) && refusEnonce, refusEnonce ? 'refus visible' : 'aucun refus lisible');
    /*
     * LA DOUZIEME CLE. `main.js:294` appelle `__('supervision.zabbix_server')` :
     * `__()` prefixe deja par `js.` et cherche dans `js.php`, donc la cle est
     * introuvable et rendue telle quelle, suivie du mot « requis » ecrit en dur.
     */
    const cleBrute = texteRefus.includes('supervision.zabbix_server');
    constate('identifiant technique dans le refus', cleBrute ? 'supervision.zabbix_server' : 'aucun');
    verifiePortage('le refus n\'affiche aucun identifiant technique',
        ! cleBrute,
        'supervision.zabbix_server — `__()` prefixe par `js.`, la cle ne peut pas etre trouvee');
    // Le serveur vide n'a rien du ecrire.
    verifie('un refus n\'ecrit rien en base',
        valeurEnBase('zabbix_server', 'zabbix') === ZBX_AVANT,
        `zabbix_server=${valeurEnBase('zabbix_server', 'zabbix')}`);

    // ── L'ENREGISTREMENT, et la ligne qu'il touche ──────────────────────────
    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await dors(2000);
    await saisit(page, 'cfg-zabbix-server', 'zabbix_server', ZBX_TAPE);
    await saisit(page, 'cfg-listen-port', 'listen_port', PORT_TAPE);
    await saisit(page, 'cfg-hostname-pattern', 'hostname_pattern', MOTIF_TAPE);
    const declenche = await enregistre(page);
    constate('enregistrement declenche', declenche || 'aucun point d\'entree');
    verifie('l\'enregistrement a un point d\'entree', Boolean(declenche), declenche || 'aucun');

    const zbxApres = valeurEnBase('zabbix_server', 'zabbix');
    const centreonApres = valeurEnBase('centreon_host', 'centreon');
    const zbxDansCentreon = litEnBase(
        "SELECT COALESCE(NULLIF(TRIM(zabbix_server), ''), '(VIDE)') "
        + "FROM rootwarden.supervision_config WHERE platform = 'centreon' ORDER BY id DESC LIMIT 1")[0]
        ?? '(AUCUNE LIGNE)';
    constate('apres enregistrement — ligne zabbix',
        `zabbix_server=${zbxApres}, port=${valeurEnBase('listen_port', 'zabbix')}`);
    constate('apres enregistrement — ligne centreon',
        `centreon_host=${centreonApres}, zabbix_server=${zbxDansCentreon}`);

    /*
     * LA PROPRIETE CENTRALE DE V4. Deux moities, et les deux comptent :
     * la ligne de la plateforme enregistree doit AVOIR CHANGE, et celle de la
     * plateforme voisine doit etre INTACTE. Mesurer seulement la premiere
     * laisserait passer un `UPDATE` qui ecrit au bon endroit ET a cote.
     */
    verifiePortage('enregistrer Zabbix ecrit bien dans la ligne ZABBIX',
        zbxApres === ZBX_TAPE,
        `attendu ${ZBX_TAPE}, trouve ${zbxApres} — le backend prend `
        + 'ORDER BY id DESC LIMIT 1 sans filtre de plateforme');
    verifiePortage('enregistrer Zabbix ne touche AUCUNE autre plateforme',
        centreonApres === CENTREON_AVANT && zbxDansCentreon === '(VIDE)',
        `centreon_host=${centreonApres} (attendu ${CENTREON_AVANT}), `
        + `zabbix_server dans la ligne centreon=${zbxDansCentreon} (attendu vide)`);

    // Le message de succes, et son identifiant.
    const texteSucces = await texteMessages(page);
    const cleSucces = texteSucces.includes('config_saved');
    constate('identifiant technique apres enregistrement',
        cleSucces ? 'config_saved' : 'aucun');
    verifiePortage('le message d\'enregistrement n\'affiche aucun identifiant technique',
        ! cleSucces, 'config_saved — absente de js.php, donc rendue telle quelle');

    /*
     * LE SECRET SURVIT A UN ENREGISTREMENT OU IL N'A PAS ETE RETAPE. Mesure EN
     * BASE, sur la valeur stockee : c'est la seule qui compte pour le
     * deploiement, et l'ecran n'en montre qu'un masque.
     */
    const pskApres = valeurEnBase('tls_psk_value', 'zabbix');
    constate('PSK en base apres enregistrement',
        pskApres === PSK_EXISTANT ? 'inchange' : `MODIFIE (${pskApres.slice(0, 24)})`);
    verifie('un PSK non retape est PRESERVE par l\'enregistrement',
        pskApres === PSK_EXISTANT, `attendu inchange, trouve ${pskApres.slice(0, 32)}`);

    /*
     * UN PSK REELLEMENT SAISI DOIT ARRIVER CHIFFRE — et c'est la propriete la
     * plus lourde de consequences de tout le sous-lot. Sans elle, un portage qui
     * stockerait le secret en clair passerait toutes les autres assertions.
     *
     * La mesure porte sur TOUTE LA TABLE, pas sur la ligne de la plateforme
     * enregistree : sur le legacy l'ecriture atterrit dans la ligne d'a cote, et
     * une assertion visant la seule ligne Zabbix ne verrait donc rien. « Le
     * secret en clair n'est nulle part » est vrai des deux cotes, ou doit l'etre.
     */
    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await dors(2000);
    await saisit(page, 'cfg-zabbix-server', 'zabbix_server', ZBX_TAPE);
    const pskPose = await saisit(page, 'cfg-psk-value', 'tls_psk_value', PSK_TAPE);
    constate('champ PSK renseigne', pskPose ? 'oui' : 'champ introuvable');
    await enregistre(page);

    const enClair = compteEnBase(
        'SELECT COUNT(*) FROM rootwarden.supervision_config '
        + `WHERE tls_psk_value = '${PSK_TAPE}'`);
    const blobs = litEnBase(
        "SELECT COALESCE(NULLIF(TRIM(tls_psk_value), ''), '(VIDE)') "
        + 'FROM rootwarden.supervision_config ORDER BY id');
    constate('valeurs de PSK en base apres saisie',
        blobs.map((b) => b.slice(0, 20)).join(' | ') || 'aucune');
    verifie('un PSK saisi n\'est stocke EN CLAIR nulle part dans la table',
        enClair === 0, `${enClair} ligne(s) portent la valeur tapee telle quelle`);
    verifie('le PSK stocke porte un prefixe de chiffrement connu',
        blobs.some((b) => b.startsWith('sodium:') || b.startsWith('aes:')),
        blobs.map((b) => b.split(':')[0]).join(', ') || 'aucun');

    verifie('aucune boite native n\'a ete ouverte',
        dialogues.length === 0, dialogues.join(', ') || 'aucune');
    verifie('aucune erreur JS pendant toute la sequence',
        erreursJs.length === 0, erreursJs.slice(0, 3).join(' · ') || 'aucune');
    await ctx.close();
    await dors((resteFenetre() + 1) * 1000);

    // ── En anglais : le francais ecrit en dur ───────────────────────────────
    const en = await connecte('en');
    await en.page.goto(`${BASE}${PAGE}?lang=en`, { waitUntil: 'networkidle2' });
    await dors(2000);
    await saisit(en.page, 'cfg-zabbix-server', 'zabbix_server', '');
    await enregistre(en.page);
    const blocEn = await texteMessages(en.page);
    const francaisResiduel = ['requis', 'Enregistrer', 'obligatoire']
        .filter((m) => blocEn.includes(m));
    constate('francais residuel dans le bloc rendu en anglais',
        francaisResiduel.join(', ') || 'aucun');
    verifiePortage('le refus rendu en anglais ne garde aucun mot francais',
        francaisResiduel.length === 0,
        `${francaisResiduel.join(', ')} — « requis » est ecrit EN DUR dans main.js:294`);
    await en.ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
} finally {
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
