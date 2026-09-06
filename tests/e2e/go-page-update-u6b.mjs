/**
 * go-page-update-u6b.mjs - Module `update/`, sous-lot U6b.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/update/
 *   laravel  http://localhost:8444/mises-a-jour
 *
 * CE QUE FONT LES ROUTES, LU AVANT TOUT CLIC.
 *
 *   /update        Consulte la fenetre de maintenance (423 dehors). Si apt ou
 *                  dpkg tourne deja, les TUE (`killall -9`), supprime leurs
 *                  quatre verrous et lance `dpkg --configure -a`. Puis diffuse
 *                  `apt update && apt full-upgrade -y`. FLUX text/plain.
 *
 *   /dpkg_repair   `killall -9 apt apt-get dpkg`, `rm -f` sur les quatre
 *                  verrous, puis `dpkg --configure -a`. Rend du JSON.
 *                  Ne consulte NI la fenetre de maintenance, NI l'approbation,
 *                  et n'ecrit AUCUNE trace bastion.
 *
 * CE QUI N'EST PAS PORTE : `/apt_update` et `/custom_update`. Elles existent
 * cote backend, mais `aptUpdate()` et `customUpdate()` n'ont AUCUN appelant
 * dans le legacy et lisent cinq elements de formulaire absents de la page. Ce
 * test le CONSTATE sur la cible legacy plutot que de le supposer.
 *
 * MACHINE 1 EN PRODUCTION : jamais cochee, jamais designee. La machine 2 est le
 * banc d'essai ; elle n'atteint aucun depot, donc rien ne s'y installe.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-update-u6b.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-update-u6b.mjs   (legacy)
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
    return execFileSync(
        'docker',
        ['exec', '-i', '-e', 'TEXTE_B64=' + Buffer.from(texte, 'utf-8').toString('base64'),
         'rootwarden_python', 'python', '-', String(MACHINE_TEST)],
        { input: VERIFICATEUR, encoding: 'utf-8' },
    ).trim().split('|');
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

/** Messages des boites natives, s'il en apparaît. */
const boites = [];

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

function journalEntier(page) {
    return page.evaluate(() => {
        const global = document.getElementById('logs')?.innerText || '';
        const conteneur = document.getElementById('logs-container');
        return global + '\n' + (conteneur ? conteneur.innerText : '');
    });
}

const SEL_COMPLETE = '[data-rw="maj-complete"], button[onclick="updateLinux()"]';
const SEL_DPKG = '[data-rw="reparation-dpkg"], button[onclick="dpkgRepair()"]';

/** Lit le panneau de decision generique du portage. */
function litPanneau(page) {
    return page.evaluate(() => {
        const p = document.querySelector('[data-rw="panneau-action"]');
        if (!p) return null;
        const confirmer = p.querySelector('[data-rw="action-confirmer"]');
        return {
            // Le RENDU, pas l'attribut : une classe qui pose `display` bat
            // `[hidden]`, et le test le declarait cache a tort.
            visible: p.getClientRects().length > 0,
            titre: p.querySelector('[data-rw="action-titre"]')?.textContent.trim() || '',
            machines: p.querySelector('[data-rw="action-machines"]')?.textContent.trim() || '',
            consequences: p.querySelector('[data-rw="action-consequences"]')?.textContent.trim() || '',
            reserve: p.querySelector('[data-rw="action-reserve"]')?.textContent.trim() || '',
            consigne: p.querySelector('[data-rw="action-consigne"]')?.textContent.trim() || '',
            libelleBouton: confirmer ? confirmer.textContent.trim() : '',
            desactive: confirmer ? confirmer.disabled : null,
        };
    });
}

console.log(`\n=== Module update/, sous-lot U6b (${CIBLE}) ===\n`);
constate('cible', `${BASE}${PAGE}`);
constate('ce que fait /update, lu dans backend/routes/updates.py',
    'flux text/plain ; tue apt et supprime ses verrous si un verrou est detecte');
constate('ce que fait /dpkg_repair',
    'killall -9 apt apt-get dpkg, rm des quatre verrous, dpkg --configure -a ; JSON');

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
        await verifieMenuLegacy(page, '/mises-a-jour', verifie, constate);
        await ctx.close();
        console.log(lignes.join('\n'));
        console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
        await navigateur.close();
        process.exit(echecs > 0 ? 1 : 0);
    }
}

const { ctx, page } = await connecte('rw-test-admin', SECRET_ADMIN);

page.on('dialog', async (d) => {
    boites.push(d.message());
    await d.accept().catch(() => {});
});

const appels = [];
page.on('request', (r) => {
    if (/\/(update|dpkg_repair|apt_update|custom_update)(\?|$)/.test(r.url())) {
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

verifie("l'action « mise a jour complete » est presente", Boolean(await page.$(SEL_COMPLETE)));
verifie("l'action « reparation dpkg » est presente", Boolean(await page.$(SEL_DPKG)));

// ── Ce que le legacy n'expose PAS ───────────────────────────────────────────
if (CIBLE === 'legacy') {
    const mortes = await page.evaluate(() => ({
        aptUpdate: [...document.querySelectorAll('[onclick]')]
            .some(b => /aptUpdate\(/.test(b.getAttribute('onclick'))),
        customUpdate: [...document.querySelectorAll('[onclick]')]
            .some(b => /customUpdate\(/.test(b.getAttribute('onclick'))),
        champsAptUpdate: ['apt-method', 'specific-packages', 'excluded-packages',
                          'update-packages', 'exclude-packages']
            .filter(id => document.getElementById(id)),
    }));
    verifie('aucun bouton du legacy n\'appelle aptUpdate() ni customUpdate()',
        !mortes.aptUpdate && !mortes.customUpdate,
        'les deux fonctions sont sans appelant');
    verifie('les cinq champs que ces fonctions lisent sont absents de la page',
        mortes.champsAptUpdate.length === 0,
        `champs presents : ${mortes.champsAptUpdate.join(', ') || 'aucun'}`);
}

/**
 * Repart d'un etat connu : la machine 2 SEULE, cochee.
 *
 * A rappeler AVANT chaque action : le legacy relit le parc apres une mise a
 * jour et re-rend le tableau, ce qui decoche tout. Cocher une fois au debut
 * puis enchainer deux actions mesurait la seconde sur une selection VIDE.
 */
async function retientLaMachineDeTest() {
    await page.evaluate((id) => {
        for (const c of document.querySelectorAll('input[name="selected_machines[]"]')) {
            c.checked = (c.value === String(id));
            c.dispatchEvent(new Event('change', { bubbles: true }));
        }
    }, MACHINE_TEST);
    return page.evaluate(() =>
        document.querySelectorAll('input[name="selected_machines[]"]:checked').length);
}

verifie('la machine de test est retenue, elle seule',
    await retientLaMachineDeTest() === 1, 'une case cochee');

// ── La mise a jour complete ─────────────────────────────────────────────────
await (await page.$(SEL_COMPLETE)).evaluate(b => b.click());
await dors(800);

const panneauComplete = await litPanneau(page);
verifiePortage('la mise a jour complete demande une decision, bouton desactive',
    Boolean(panneauComplete) && panneauComplete.visible && panneauComplete.desactive === true,
    panneauComplete ? `desactive : ${panneauComplete.desactive}` : 'aucun panneau');
verifiePortage('le panneau distingue « tous les paquets » des seules corrections',
    Boolean(panneauComplete) && /TOUS|EVERY/.test(panneauComplete.consequences),
    "le legacy nomme le bouton « mise a jour » sans dire ce qu'il embarque");

if (CIBLE === 'laravel') {
    await page.evaluate(() => {
        const champ = document.querySelector('[data-rw="action-confirmation"]');
        champ.value = 'MISE A JOUR';
        champ.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await page.evaluate(() =>
        document.querySelector('[data-rw="action-confirmer"]').click());
}

// Attendre LE CONTENU : la sortie d'apt dans le journal.
/**
 * Attend LE CONTENU attendu, pas la stabilite du journal.
 *
 * Piege paye ici meme : entre l'envoi de la requete et l'arrivee du flux, le
 * journal porte deja l'annonce « en cours » et ne bouge plus pendant qu'apt
 * travaille. Une attente qui s'arrete quand le texte cesse de changer s'arrete
 * donc AVANT la premiere ligne de sortie.
 */
async function attendLaSortie(motif, maxMs) {
    const limite = Date.now() + maxMs;
    let texte = await journalEntier(page);
    while (Date.now() < limite && !motif.test(texte)) {
        await dors(1000);
        texte = await journalEntier(page);
    }
    return texte;
}

const journalComplete = await attendLaSortie(/Reading|Lecture|W: |Building|Calculating|apt-get|upgraded|Erreur|error/i, 300000);

constate('appels enregistres', appels.map(a => a.url.replace(/^https?:\/\/[^/]+/, '')).join(' | ') || 'aucun');
constate('trois premieres lignes du journal',
    journalComplete.split('\n').filter(l => l.trim()).slice(0, 3).join(' / ') || 'vide');

verifie('la mise a jour complete appelle la route et rend sa sortie',
    appels.some(a => /\/update(\?|$)/.test(a.url))
    && /Reading|Lecture|W: |apt|Erreur|error/i.test(journalComplete),
    `${journalComplete.split('\n').length} ligne(s) au journal`);

const [motComplete, fragmentComplete] = secretDans(journalComplete);
verifie('LE MOT DE PASSE ROOT N EST PAS DANS LE JOURNAL apres la mise a jour complete',
    motComplete === 'ABSENT' && fragmentComplete === 'ABSENT',
    `mot entier : ${motComplete}, fragment de six caracteres : ${fragmentComplete}`);

// ── La reparation dpkg ──────────────────────────────────────────────────────
verifie('la selection est encore la avant la seconde action',
    await retientLaMachineDeTest() === 1, 'une case cochee');

await (await page.$(SEL_DPKG)).evaluate(b => b.click());
await dors(800);

const panneauDpkg = await litPanneau(page);
verifiePortage('la decision s\'ouvre en ligne, bouton desactive',
    Boolean(panneauDpkg) && panneauDpkg.visible && panneauDpkg.desactive === true,
    panneauDpkg ? `desactive : ${panneauDpkg.desactive}` : 'aucun panneau');
verifiePortage('le panneau NOMME la machine concernee',
    Boolean(panneauDpkg) && panneauDpkg.machines.includes(NOM_TEST),
    panneauDpkg ? `« ${panneauDpkg.machines} »` : 'aucun panneau');
verifiePortage('le panneau DIT que les processus apt seront tues',
    Boolean(panneauDpkg) && /killall|TUES|KILLED/i.test(panneauDpkg.consequences),
    'la consequence est nommee avant le geste');
verifiePortage('le panneau DIT ce qu\'on perd a le lancer a tort',
    Boolean(panneauDpkg) && panneauDpkg.reserve.length > 20,
    panneauDpkg ? `reserve : ${panneauDpkg.reserve.length} caracteres` : 'aucun panneau');

if (CIBLE === 'legacy') {
    constate('boites natives posees par la reparation dpkg', String(boites.length));
    boites.forEach((m, i) => constate(`boite ${i + 1}`, `« ${m.slice(0, 80)} »`));
    // Contraste avec le redemarrage, dont les deux confirmations affichent la
    // cle brute : ici la cle vit dans le catalogue `js.`, donc elle se traduit.
    verifie('la confirmation du legacy affiche un texte, pas une cle',
        boites.length > 0 && !/^updates\./.test(boites[0]),
        boites.length ? `« ${boites[0].slice(0, 50)}... »` : 'aucune boite');
}

if (CIBLE === 'laravel') {
    await page.evaluate(() => {
        const champ = document.querySelector('[data-rw="action-confirmation"]');
        champ.value = 'oui';
        champ.dispatchEvent(new Event('input', { bubbles: true }));
    });
    verifie('un mot qui ne correspond pas laisse le bouton desactive',
        await page.evaluate(() =>
            document.querySelector('[data-rw="action-confirmer"]').disabled) === true,
        '« oui » saisi');

    await page.evaluate(() => {
        const champ = document.querySelector('[data-rw="action-confirmation"]');
        champ.value = 'REPARER';
        champ.dispatchEvent(new Event('input', { bubbles: true }));
    });
    verifie('le mot attendu active le bouton',
        await page.evaluate(() =>
            document.querySelector('[data-rw="action-confirmer"]').disabled) === false,
        '« REPARER » saisi');

    await page.evaluate(() =>
        document.querySelector('[data-rw="action-confirmer"]').click());
}

// Attendre LE CONTENU : la sortie de dpkg dans le journal du serveur.
const journal = await attendLaSortie(/dpkg|Reparation|Repair|configure/i, 180000);

verifie('la reparation dpkg appelle la route',
    appels.some(a => /dpkg_repair/.test(a.url)),
    `${appels.filter(a => /dpkg_repair/.test(a.url)).length} appel(s)`);

verifiePortage('la sortie est rangee sous le nom de la machine',
    await page.evaluate((nom) => {
        const c = document.getElementById('logs-container');
        return c ? [...c.querySelectorAll('[data-server-name]')]
            .some(el => el.getAttribute('data-server-name') === nom) : false;
    }, NOM_TEST), `panneau ${NOM_TEST}`);

const [motDpkg, fragmentDpkg] = secretDans(journal);
verifie('LE MOT DE PASSE ROOT N EST PAS DANS LE JOURNAL apres la reparation',
    motDpkg === 'ABSENT' && fragmentDpkg === 'ABSENT',
    `mot entier : ${motDpkg}, fragment de six caracteres : ${fragmentDpkg}`);

// ── Perimetre ───────────────────────────────────────────────────────────────
verifie('la machine 1, en production, n\'est jamais designee',
    !appels.some(a => /"machine_id"\s*:\s*1\b/.test(a.corps)),
    `${appels.length} appel(s) inspecte(s)`);

verifie('aucun appel a /apt_update ni /custom_update',
    !appels.some(a => /apt_update|custom_update/.test(a.url)),
    'les deux routes restent sans appelant');

await ctx.close();
await navigateur.close();

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL\n`);
process.exit(echecs ? 1 : 0);
