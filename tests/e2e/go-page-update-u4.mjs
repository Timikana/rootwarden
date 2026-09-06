/**
 * go-page-update-u4.mjs - Module `update/`, sous-lot U4 : la planification.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/update/
 *   laravel  http://localhost:8444/mises-a-jour
 *
 * CE QUE FONT LES ROUTES, LU DANS `backend/routes/updates.py` AVANT TOUT CLIC.
 * Les deux ECRIVENT un fichier dans /etc/cron.d/ sur la machine, en root, puis
 * redemarrent cron :
 *   /schedule_advanced_update           -> /etc/cron.d/auto_update_advanced
 *   /schedule_advanced_security_update  -> /etc/cron.d/auto_security_update_advanced
 *                                          + UPDATE machines.maj_secu_date
 *
 * CE QUE LE TEST DOIT PROUVER : un cron ECRIT SUR LA MACHINE 2 ET RELU. Une
 * planification qu'on ne relit pas n'est pas prouvee. La relecture passe par
 * `cron-machine.py`, execute dans le conteneur du backend — seul a savoir
 * dechiffrer les mots de passe et a joindre le parc en SSH.
 *
 * LE TEST NETTOIE : les deux fichiers cron sont effaces et `maj_secu_date` est
 * remise a NULL, avant ET apres, pour repartir d'un etat connu.
 *
 * MACHINE 1 EN PRODUCTION : jamais designee. Le test le verifie sur toutes les
 * requetes emises.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-update-u4.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-update-u4.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { execFileSync } from 'child_process';
import { readFileSync } from 'fs';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
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
const PAGE = CIBLE === 'laravel' ? '/mises-a-jour' : '/update/';

const MACHINE_TEST = 2;
const NOM_TEST = 'Test-Server-Debian';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

/** Scenario fixe : le 15 septembre 2026 est un MARDI. */
const DATE = '2026-09-15';
const HEURE = '03:30';
const RECURRENCE = 'weekly';

/*
 * Attendus ECRITS A LA MAIN depuis la lecture du Python, pas calcules par le
 * meme code que le portage — sans quoi l'assertion se comparerait a elle-meme.
 *   schedule_advanced_update          : weekly -> "* * 1", TOUJOURS lundi
 *   schedule_advanced_security_update : weekly -> jour de la DATE, ici mardi (2)
 */
const CRON_GENERAL = '30 03 * * 1';
const CRON_SECURITE = '30 03 * * 2';

const FICHIER_GENERAL = '/etc/cron.d/auto_update_advanced';
const FICHIER_SECURITE = '/etc/cron.d/auto_security_update_advanced';

const AIDE_CRON = readFileSync('cron-machine.py');

function surLaMachine(...args) {
    return execFileSync('docker', ['exec', '-i', 'rootwarden_python', 'python', '-', ...args],
        { input: AIDE_CRON, encoding: 'utf-8' }).trim();
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

/** Remet la machine et la base dans l'etat connu d'avant le test. */
function nettoie() {
    surLaMachine('efface', String(MACHINE_TEST), FICHIER_GENERAL);
    surLaMachine('efface', String(MACHINE_TEST), FICHIER_SECURITE);
    surLaMachine('oublie-maj-secu', String(MACHINE_TEST));
}

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
    page.on('dialog', d => d.dismiss().catch(() => {}));

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

/** Contrat DOM des deux cibles, par nature de planification. */
const CHAMPS = {
    laravel: {
        generale: { ouvre: `[data-rw="planifier-${MACHINE_TEST}"]`, date: '#sched-date',
                    heure: '#sched-time', recurrence: '#sched-repeat',
                    enregistre: '[data-rw="enregistrer-planification"]' },
        securite: { ouvre: `[data-rw="planifier-secu-${MACHINE_TEST}"]`, date: '#sched-date',
                    heure: '#sched-time', recurrence: '#sched-repeat',
                    enregistre: '[data-rw="enregistrer-planification"]' },
    },
    legacy: {
        generale: { ouvre: `button[onclick="openScheduleModal(${MACHINE_TEST})"]`, date: '#sched-date',
                    heure: '#sched-time', recurrence: '#sched-repeat',
                    enregistre: 'button[onclick="saveAdvancedSchedule()"]' },
        securite: { ouvre: `button[onclick="openSecurityScheduleModal(${MACHINE_TEST})"]`, date: '#sec-date',
                    heure: '#sec-time', recurrence: '#sec-repeat',
                    enregistre: 'button[onclick="saveSecuritySchedule()"]' },
    },
};

/**
 * Ouvre le formulaire, le remplit, enregistre, et rend ce qui a ete MESURE :
 * la route appelee, le statut de la reponse, et l'apercu affiche avant le clic.
 */
async function planifie(page, nature, reponses) {
    const sel = CHAMPS[CIBLE][nature];

    const bouton = await page.$(sel.ouvre);
    if (!bouton) return { ouvert: false };
    await bouton.evaluate(b => b.click());
    await dors(300);

    const apercuAvant = await page.evaluate(() =>
        document.querySelector('[data-rw="apercu"]')?.textContent.trim() || '');
    const boutonInactif = await page.evaluate((s) => {
        const b = document.querySelector(s);
        return b ? b.disabled : null;
    }, sel.enregistre);

    await page.evaluate((s, d, h, r) => {
        const pose = (selecteur, valeur) => {
            const el = document.querySelector(selecteur);
            el.value = valeur;
            el.dispatchEvent(new Event('change', { bubbles: true }));
        };
        pose(s.date, d);
        pose(s.heure, h);
        pose(s.recurrence, r);
    }, sel, DATE, HEURE, RECURRENCE);
    await dors(200);

    const apercu = await page.evaluate(() =>
        document.querySelector('[data-rw="apercu"]')?.textContent.trim() || '');

    const avant = reponses.length;
    await page.evaluate((s) => document.querySelector(s).click(), sel.enregistre);

    // Attendre LA REPONSE de la route de planification : le formulaire du
    // legacy se referme avant meme que l'appel parte, l'ecran ne dit donc rien.
    const limite = Date.now() + 60000;
    while (Date.now() < limite && reponses.length === avant) await dors(300);

    return {
        ouvert: true,
        apercuAvant,
        boutonInactif,
        apercu,
        reponse: reponses[avant] || null,
    };
}

console.log(`\n=== Module update/, sous-lot U4 — planification (${CIBLE}) ===\n`);
constate('cible', `${BASE}${PAGE}`);
constate('ce que font les routes, lu dans backend/routes/updates.py',
    'ecriture d\'un fichier /etc/cron.d/ en root, puis redemarrage de cron');

nettoie();
constate('etat de depart', 'les deux fichiers cron effaces, maj_secu_date remise a NULL');

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

const reponses = [];
const demandes = [];
page.on('request', (r) => {
    if (/schedule_/.test(r.url())) demandes.push({ url: r.url(), corps: r.postData() || '' });
});
page.on('response', (r) => {
    if (/schedule_/.test(r.url())) reponses.push({ url: r.url(), statut: r.status() });
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

// ── Planification GENERALE ──────────────────────────────────────────────────
const generale = await planifie(page, 'generale', reponses);
verifie('l\'action « planifier » est presente sur la ligne de la machine 2', generale.ouvert);

verifiePortage('avant la date et l\'heure, l\'enregistrement est refuse',
    generale.boutonInactif === true, `bouton desactive : ${generale.boutonInactif}`);
verifiePortage('l\'apercu dit ce qui manque tant que la date n\'est pas choisie',
    /date|pick/i.test(generale.apercuAvant), `« ${generale.apercuAvant} »`);

const routeGenerale = generale.reponse ? generale.reponse.url.split('/').pop() : 'aucune';
constate('route appelee par la planification generale', routeGenerale);
constate('statut rendu', generale.reponse ? String(generale.reponse.statut) : 'aucune reponse');

const fichierGeneral = surLaMachine('lit', String(MACHINE_TEST), FICHIER_GENERAL);

if (CIBLE === 'legacy') {
    // E-18 : le formulaire envoie date/time/repeat a une route qui attend
    // `interval_minutes`. Elle refuse avant toute session SSH.
    verifie('la planification generale du legacy est refusee et n\'ecrit rien',
        generale.reponse?.statut === 400 && fichierGeneral === 'ABSENT',
        `statut ${generale.reponse?.statut}, fichier ${fichierGeneral}`);
} else {
    verifie('la planification generale ecrit le cron attendu sur la machine',
        generale.reponse?.statut === 200 && fichierGeneral.includes(CRON_GENERAL),
        `« ${fichierGeneral.split(' root ')[0]} »`);
    verifie('l\'apercu annoncait exactement ce qui a ete ecrit',
        generale.apercu.includes(CRON_GENERAL) && fichierGeneral.includes(CRON_GENERAL),
        `apercu et fichier portent « ${CRON_GENERAL} »`);
    verifie('l\'ecart entre le mot choisi et ce que cron sait exprimer est dit',
        /lundi|Monday/i.test(generale.apercu),
        'le 15/09/2026 est un mardi, le cron general tombe le lundi');
}

// ── Planification de SECURITE ───────────────────────────────────────────────
const securite = await planifie(page, 'securite', reponses);
verifie('l\'action « planifier securite » est presente sur la ligne de la machine 2',
    securite.ouvert);

const fichierSecurite = surLaMachine('lit', String(MACHINE_TEST), FICHIER_SECURITE);
verifie('la planification de securite ecrit le cron attendu sur la machine',
    securite.reponse?.statut === 200 && fichierSecurite.includes(CRON_SECURITE),
    `« ${fichierSecurite.split(' root ')[0]} »`);

verifie('le cron de securite ne met a jour QUE la securite',
    /--only-upgrade/.test(fichierSecurite) && /auto_security_update\.log/.test(fichierSecurite),
    'apt-get upgrade --with-new-pkgs --only-upgrade');

verifiePortage('l\'apercu de securite annoncait exactement ce qui a ete ecrit',
    securite.apercu.includes(CRON_SECURITE),
    `apercu et fichier portent « ${CRON_SECURITE} »`);

// La date planifiee est aussi ecrite en base : la colonne doit la montrer.
const colonne = await (async () => {
    const limite = Date.now() + 20000;
    let v = '';
    while (Date.now() < limite && !/2026-09-15/.test(v)) {
        v = await page.evaluate((id) => {
            const tr = document.querySelector(`tr[data-machine-id="${id}"]`);
            return tr ? (tr.querySelector('.maj-secu-date')?.textContent || '').trim() : '';
        }, MACHINE_TEST);
        if (!/2026-09-15/.test(v)) await dors(400);
    }
    return v;
})();
verifiePortage('la colonne « MAJ securite planifiee » montre la date posee en base',
    /2026-09-15/.test(colonne), `colonne : « ${colonne} »`);

// ── Perimetre ───────────────────────────────────────────────────────────────
verifie('la machine 1, en production, n\'est jamais designee',
    !demandes.some(d => /"machine_id"\s*:\s*1\b/.test(d.corps)),
    `${demandes.length} requete(s) inspectee(s)`);

// Le legacy journalise la planification SANS nom de serveur : ses lignes se
// deposent hors panneau (E-15). L'exigence ne vaut donc que pour le portage.
const trace = await page.evaluate((nom) => {
    const conteneur = document.getElementById('logs-container');
    if (!conteneur) return '';
    for (const el of conteneur.querySelectorAll('[data-server-name]')) {
        if (el.getAttribute('data-server-name') === nom) return el.innerText;
    }
    return '';
}, NOM_TEST);
verifiePortage('le journal du serveur porte l\'expression cron posee',
    trace.includes(CRON_SECURITE), `panneau de ${NOM_TEST} : ${trace.length} caractere(s)`);

await ctx.close();
await navigateur.close();

nettoie();
constate('nettoyage', 'les deux fichiers cron effaces, maj_secu_date remise a NULL');

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL\n`);
process.exit(echecs ? 1 : 0);
