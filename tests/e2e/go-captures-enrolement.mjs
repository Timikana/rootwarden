/**
 * go-captures-enrolement.mjs - L'ecran d'enrolement, EN IMAGES, aux trois
 * largeurs de la convention : 1920, 1400 et 390.
 *
 * Une assertion DOM ne voit ni un QR illisible, ni une cle qui deborde, ni un
 * contraste inverse. Trois defauts du chantier n'ont ete vus qu'a l'image, dont
 * une pastille a 1,06:1 que le HTML rendait pourtant juste.
 *
 * ══ LA FIXTURE, ET POURQUOI ELLE EST DANGEREUSE ═════════════════════════════
 *
 * L'ecran d'enrolement n'est atteignable que par un compte SANS second facteur.
 * Les captures se prennent au compte de ROLE 3 (`rw-test-super`), donc il faut
 * lui retirer son secret le temps des images — et le REMETTRE. Le secret est
 * sauvegarde, retire, puis restaure dans un `finally`, et l'etat rendu est RELU
 * pour etre PROUVE : si la restauration echoue, ce script doit le crier, parce
 * que d'autres suites du LOT se connectent avec ce compte.
 *
 * On ne va JAMAIS jusqu'a l'activation : seul le mot de passe est presente, ce
 * qui suffit a atteindre l'ecran. Aucun secret n'est donc ecrit en base.
 *
 * Usage :
 *   cd tests/e2e && node go-captures-enrolement.mjs
 */
import puppeteer from 'puppeteer';
import { mkdirSync } from 'node:fs';
import { litEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const COMPTE = 'rw-test-super';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const SORTIE = './screenshots/enrolement';

const LARGEURS = [
    { nom: 'grand', width: 1920, height: 1080 },
    { nom: 'bureau', width: 1400, height: 900 },
    { nom: 'mobile', width: 390, height: 844 },
];

let echecs = 0;
function note(l) { console.log(l); }
function verifie(l, ok, d) { note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { note(`INFO  ${l} : ${v}`); }

function secretEnBase() {
    const r = litEnBase(`SELECT COALESCE(totp_secret, '(ABSENT)') FROM rootwarden.users WHERE name = '${COMPTE}'`);

    return (r[0] || '(ABSENT)').trim();
}

mkdirSync(SORTIE, { recursive: true });

const secretOrigine = secretEnBase();
let navigateur = null;

try {
    verifie('le compte de capture part d\'un etat connu', secretOrigine !== '(ABSENT)',
        secretOrigine === '(ABSENT)' ? 'aucun secret — ne pas continuer' : 'secret present');
    if (secretOrigine === '(ABSENT)') {
        throw new Error('refus : le compte n\'a pas de secret a restaurer, la fixture serait a sens unique');
    }

    litEnBase(`UPDATE rootwarden.users SET totp_secret = NULL WHERE name = '${COMPTE}'`);
    litEnBase('DELETE FROM rootwarden.login_attempts');
    verifie('la fixture est posee', secretEnBase() === '(ABSENT)');

    navigateur = await puppeteer.launch({
        headless: 'new',
        args: ['--ignore-certificate-errors', '--allow-insecure-localhost'],
        protocolTimeout: 120000,
    });

    for (const format of LARGEURS) {
        const ctx = await navigateur.createBrowserContext();
        const page = await ctx.newPage();
        await page.setViewport({ width: format.width, height: format.height });
        page.setDefaultTimeout(30000);

        await page.goto(`${BASE}/connexion?lang=fr`, { waitUntil: 'networkidle2' });
        await page.type('input[name="username"]', COMPTE, { delay: 8 });
        await page.type('input[name="password"]', MDP, { delay: 8 });
        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]');
        try { await nav; } catch { /* l'URL tranche */ }

        const surEcran = /second-facteur\/enrolement/.test(page.url());
        verifie(`[${format.nom}] l'ecran d'enrolement est atteint`, surEcran,
            page.url().replace(BASE, ''));
        if (! surEcran) { await ctx.close(); continue; }

        /* LE QR EST-IL VRAIMENT VISIBLE ? On mesure la taille RENDUE, pas la
         * presence dans le DOM : un SVG present mais large de zero ne se scanne
         * pas, et aucune assertion DOM ne le verrait. */
        const vu = await page.evaluate(() => {
            const qr = document.querySelector('[data-rw="enrolement-qr"] svg');
            const cadre = document.querySelector('[data-rw="enrolement-qr"]');
            const cle = document.querySelector('[data-rw="enrolement-secret"]');
            const r = qr ? qr.getBoundingClientRect() : null;

            return {
                largeurQr: r ? Math.round(r.width) : 0,
                hauteurQr: r ? Math.round(r.height) : 0,
                fondCadre: cadre ? getComputedStyle(cadre).backgroundColor : '',
                debordeCle: cle ? cle.scrollWidth > cle.clientWidth + 1 : null,
                debordePage: document.documentElement.scrollWidth > window.innerWidth + 1,
            };
        });
        constate(`[${format.nom}] QR rendu`, `${vu.largeurQr}x${vu.hauteurQr} px, fond ${vu.fondCadre}`);
        verifie(`[${format.nom}] le QR fait au moins 150 px de cote`,
            vu.largeurQr >= 150 && vu.hauteurQr >= 150, `${vu.largeurQr}x${vu.hauteurQr}`);
        /* Un lecteur de QR lit des modules sombres sur fond CLAIR : un SVG pose
         * sur le fond sombre du theme serait illisible a la camera, et le DOM
         * n'en dirait rien. */
        verifie(`[${format.nom}] le QR est pose sur un fond clair`,
            /rgb\(255,\s*255,\s*255\)/.test(vu.fondCadre), vu.fondCadre);
        verifie(`[${format.nom}] la cle en clair ne deborde pas de son cadre`,
            vu.debordeCle === false, `deborde=${vu.debordeCle}`);
        verifie(`[${format.nom}] la page ne defile pas horizontalement`,
            vu.debordePage === false, `deborde=${vu.debordePage}`);

        /*
         * PLEINE PAGE, ET UN ARTEFACT A CONNAITRE : le selecteur de langue est en
         * `position: fixed` (`.rw-langues-flottant`). Dans une capture pleine
         * page il se rend a sa position d'ECRAN, donc au milieu d'une page
         * longue — il SEMBLE alors chevaucher la carte. Mesure faite : ce n'est
         * pas un defaut de mise en page, c'est le rendu de la capture. Ne pas
         * « corriger » ce que l'image invente.
         */
        const chemin = `${SORTIE}/${format.nom}-enrolement.png`;
        await page.screenshot({ path: chemin, fullPage: true });
        constate(`[${format.nom}] capture`, chemin);
        await ctx.close();
    }
} catch (e) {
    verifie('deroulement du script', false, String(e.message || e).split('\n')[0]);
} finally {
    if (navigateur) { try { await navigateur.close(); } catch { /* rien */ } }
    /*
     * RESTAURATION, PUIS RELECTURE POUR PREUVE. D'autres suites du LOT se
     * connectent avec ce compte : une restauration ratee doit se voir ICI et
     * pas trois suites plus loin.
     */
    if (secretOrigine !== '(ABSENT)') {
        litEnBase(`UPDATE rootwarden.users SET totp_secret = '${secretOrigine}' WHERE name = '${COMPTE}'`);
    }
    litEnBase('DELETE FROM rootwarden.login_attempts');
    const rendu = secretEnBase();
    verifie('le second facteur du compte de capture est RESTAURE', rendu === secretOrigine,
        rendu === secretOrigine ? 'identique a l\'entree' : 'DIFFERENT — d\'autres suites en dependent');
    note(`\n${echecs} FAIL`);
    process.exit(echecs === 0 ? 0 : 1);
}
