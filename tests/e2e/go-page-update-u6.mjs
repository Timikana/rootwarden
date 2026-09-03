/**
 * go-page-update-u6.mjs - Module `update/`, sous-lot U6a : les deux flux.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/update/
 *   laravel  http://localhost:8444/mises-a-jour
 *
 * CE QUE FONT LES ROUTES, LU DANS `backend/routes/updates.py` AVANT TOUT CLIC.
 *
 *   /dry_run_update    apt-get update && apt-get upgrade --dry-run
 *                      N'installe rien. Reecrit l'index local des paquets.
 *
 *   /security_updates  apt-get update && apt-get upgrade --only-upgrade -y
 *                      INSTALLE. Et si apt ou dpkg tourne deja, elle les TUE
 *                      (`killall -9`), supprime leurs verrous et lance
 *                      `dpkg --configure -a` avant de continuer. Le libelle du
 *                      legacy ne le dit nulle part.
 *
 * Les deux rendent `Response(generate(), 'text/plain')` : leur corps est un
 * FLUX, et ce flux portait le MOT DE PASSE ROOT en ligne 2 jusqu'au correctif
 * du 2026-08-19 (CHANGELOG v1.37.17). CE TEST LE VERIFIE SUR LES DEUX CIBLES :
 * le journal reellement affiche ne doit contenir ni le mot de passe, ni le
 * moindre fragment de six caracteres. La verification passe par
 * `secret-absent.py`, execute dans le conteneur du backend — le secret ne
 * quitte jamais ce conteneur.
 *
 * MACHINE 1 EN PRODUCTION : jamais cochee, jamais designee. La machine 2 est le
 * banc d'essai ; elle n'atteint aucun depot, donc la mise a jour de securite n'y
 * installe rien.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-update-u6.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-update-u6.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { execFileSync } from 'child_process';
import { readFileSync } from 'fs';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/mises-a-jour' : '/update/';

const MACHINE_TEST = 2;
const NOM_TEST = 'Test-Server-Debian';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

const VERIFICATEUR = readFileSync('secret-absent.py');

/** Rend ['ABSENT'|'PRESENT', 'ABSENT'|'PRESENT'] pour (mot entier, fragment). */
function secretDans(texte) {
    const sortie = execFileSync(
        'docker',
        ['exec', '-i', '-e', 'TEXTE_B64=' + Buffer.from(texte, 'utf-8').toString('base64'),
         'rootwarden_python', 'python', '-', String(MACHINE_TEST)],
        { input: VERIFICATEUR, encoding: 'utf-8' },
    ).trim();
    return sortie.split('|');
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
function verifie(libelle, ok, detail, __quatrieme) {
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

    lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${libelle}${detail ? '  — ' + detail : ''}`);
    if (!ok) echecs++;
}
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }

/** Exigence qui ne vaut que pour le portage ; cote legacy, simple constat. */
function verifiePortage(libelle, ok, detail, __quatrieme) {
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

    if (CIBLE === 'laravel') return verifie(libelle, ok, detail);
    constate(libelle, `non exigible du legacy — ${detail}`);
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});

async function connecte(nom, secret) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    page.on('dialog', d => d.accept().catch(() => {}));

    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };

    await page.goto(`${BASE}${chemins.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    await page.type('input[name="2fa_code"]', totp(secret), { delay: 8 });
    nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (chemins.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$('[data-rw="cgu-accepter"]') || await page.$('button[name="accept_terms"]');
        if (b) await b.evaluate(x => x.click());
        try { await nav; } catch {}
    }
    return { ctx, page };
}

/** Tout le texte du journal, panneaux compris. */
function journalEntier(page) {
    return page.evaluate(() => {
        const global = document.getElementById('logs')?.innerText || '';
        const conteneur = document.getElementById('logs-container');
        return global + '\n' + (conteneur ? conteneur.innerText : '');
    });
}

const SEL_SIMULER = '[data-rw="simulation"], button[onclick*="dryRunUpdate"]';
const SEL_SECURITE = '[data-rw="maj-securite"], button[onclick*="applySecurityUpdates"]';

console.log(`\n=== Module update/, sous-lot U6a — les deux flux (${CIBLE}) ===\n`);
constate('cible', `${BASE}${PAGE}`);
constate('ce que font les routes, lu dans backend/routes/updates.py',
    'flux text/plain ; la mise a jour de securite INSTALLE et peut tuer un apt en cours');

/*
 * MODULE ARCHIVE ? Cote legacy, `update/` a ete porte en sept sous-lots puis
 * deplace dans `legacy/_deprecated/`. Ses URL rendent 404 : ce n'est pas un
 * echec, c'est l'aboutissement du portage. Le test le CONSTATE — et verifie
 * surtout que le menu du legacy mene desormais au portage, sans quoi on aurait
 * installe soi-meme un 404 dans un menu.
 *
 * Tant que le module est servi, ce bloc est inerte et la suite se joue.
 */
if (CIBLE === 'legacy') {
    const archivee = await constateArchivage({
        base: BASE,
        chemin: '/update/',
        fichiers: [
        '/update/index.php',
        '/update/js/apiCalls.js',
        '/update/js/domManipulation.js',
        '/update/functions/list_machines.php',
        '/update/functions/filter_servers.php',
        ],
        verifie, constate,
    });
    if (archivee) {
        const { ctx, page } = await connecte('rw-test-admin', SECRET_ADMIN);
        await verifieMenuLegacy(page, '/mises-a-jour', verifie);
        await ctx.close();
        console.log(lignes.join('\n'));
        console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
        await navigateur.close();
        process.exit(echecs > 0 ? 1 : 0);
    }
}

const { ctx, page } = await connecte('rw-test-admin', SECRET_ADMIN);

const appels = [];
page.on('request', (r) => {
    if (/dry_run_update|security_updates/.test(r.url())) {
        appels.push({ url: r.url(), corps: r.postData() || '' });
    }
});

await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });

const nbLignes = await (async () => {
    const limite = Date.now() + 30000;
    let n = 0;
    while (Date.now() < limite && n === 0) {
        n = await page.evaluate(() =>
            document.querySelectorAll('#server-table-body tr[data-machine-id]').length);
        if (!n) await dors(400);
    }
    return n;
})();
verifie('le parc est rendu', nbLignes > 0, `${nbLignes} ligne(s)`);

const aSimuler = await page.$(SEL_SIMULER);
const aSecurite = await page.$(SEL_SECURITE);
verifie("l'action « simuler » est presente", Boolean(aSimuler));
verifie("l'action « mises a jour de securite » est presente", Boolean(aSecurite));

// Repartir d'un etat connu, puis la machine 2 SEULE.
await page.evaluate((id) => {
    for (const c of document.querySelectorAll('input[name="selected_machines[]"]')) {
        c.checked = (c.value === String(id));
        c.dispatchEvent(new Event('change', { bubbles: true }));
    }
}, MACHINE_TEST);

// ── La simulation ───────────────────────────────────────────────────────────
const avantSimulation = appels.length;
await aSimuler.evaluate(b => b.click());

// Attendre LE CONTENU : une ligne d'apt dans le journal du serveur.
const limiteSimulation = Date.now() + 180000;
let journal = '';
while (Date.now() < limiteSimulation && !/Reading|Lecture|W: |apt/i.test(journal)) {
    await dors(600);
    journal = await journalEntier(page);
}

verifie('la simulation appelle la route et rend sa sortie',
    appels.length > avantSimulation && /Reading|Lecture|W: |apt/i.test(journal),
    `${appels.length - avantSimulation} appel(s), ${journal.split('\n').length} ligne(s) au journal`);

const [motSimulation, fragmentSimulation] = secretDans(journal);
verifie('LE MOT DE PASSE ROOT N EST PAS DANS LE JOURNAL apres la simulation',
    motSimulation === 'ABSENT' && fragmentSimulation === 'ABSENT',
    `mot entier : ${motSimulation}, fragment de six caracteres : ${fragmentSimulation}`);

verifiePortage('la sortie est rangee sous le nom de la machine',
    await page.evaluate((nom) => {
        const c = document.getElementById('logs-container');
        return c ? [...c.querySelectorAll('[data-server-name]')]
            .some(el => el.getAttribute('data-server-name') === nom) : false;
    }, NOM_TEST), `panneau ${NOM_TEST}`);

// ── Les mises a jour de securite ────────────────────────────────────────────
await aSecurite.evaluate(b => b.click());
await dors(800);

const panneau = await page.evaluate(() => {
    const p = document.querySelector('[data-rw="panneau-securite"]');
    if (!p) return null;
    const confirmer = p.querySelector('[data-rw="securite-confirmer"]');
    return {
        // Le RENDU, pas l'attribut — voir U5.
        visible: p.getClientRects().length > 0,
        texte: p.innerText,
        desactive: confirmer ? confirmer.disabled : null,
    };
});

verifiePortage('la decision s\'ouvre en ligne, bouton desactive',
    Boolean(panneau) && panneau.visible && panneau.desactive === true,
    panneau ? `desactive : ${panneau.desactive}` : 'aucun panneau de decision');
verifiePortage('le panneau DIT que les verrous apt seront forces',
    Boolean(panneau) && /verrou|lock|ARRETE|KILLS/i.test(panneau.texte),
    'le libelle du legacy ne le dit nulle part');

if (CIBLE === 'laravel') {
    await page.evaluate(() => {
        const champ = document.querySelector('[data-rw="securite-confirmation"]');
        champ.value = 'oui';
        champ.dispatchEvent(new Event('input', { bubbles: true }));
    });
    verifie('un mot qui ne correspond pas laisse le bouton desactive',
        await page.evaluate(() =>
            document.querySelector('[data-rw="securite-confirmer"]').disabled) === true,
        '« oui » saisi');

    await page.evaluate(() => {
        const champ = document.querySelector('[data-rw="securite-confirmation"]');
        champ.value = 'SECURITE';
        champ.dispatchEvent(new Event('input', { bubbles: true }));
    });
    verifie('le mot attendu active le bouton',
        await page.evaluate(() =>
            document.querySelector('[data-rw="securite-confirmer"]').disabled) === false,
        '« SECURITE » saisi');

    await page.evaluate(() =>
        document.querySelector('[data-rw="securite-confirmer"]').click());
}

const avantSecurite = appels.filter(a => /security_updates/.test(a.url)).length;
const limiteSecurite = Date.now() + 240000;
while (Date.now() < limiteSecurite
       && appels.filter(a => /security_updates/.test(a.url)).length === avantSecurite) {
    await dors(600);
}
// Laisser le flux se deverser dans le journal.
let journalFinal = '';
const limiteFlux = Date.now() + 180000;
while (Date.now() < limiteFlux) {
    await dors(1500);
    const maintenant = await journalEntier(page);
    if (maintenant === journalFinal && maintenant.length > journal.length) break;
    journalFinal = maintenant;
}

verifie('la mise a jour de securite appelle la route',
    appels.some(a => /security_updates/.test(a.url)),
    `${appels.filter(a => /security_updates/.test(a.url)).length} appel(s)`);

const [motSecurite, fragmentSecurite] = secretDans(journalFinal);
verifie('LE MOT DE PASSE ROOT N EST PAS DANS LE JOURNAL apres la mise a jour',
    motSecurite === 'ABSENT' && fragmentSecurite === 'ABSENT',
    `mot entier : ${motSecurite}, fragment de six caracteres : ${fragmentSecurite}`);

verifie('la machine 1, en production, n\'est jamais designee',
    !appels.some(a => /"machine_id"\s*:\s*1\b/.test(a.corps)),
    `${appels.length} appel(s) inspecte(s)`);

await ctx.close();
await navigateur.close();

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL\n`);
process.exit(echecs ? 1 : 0);
