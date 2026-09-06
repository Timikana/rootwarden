/**
 * go-page-tasks.mjs - Centre de taches : historique de l'activite de fond.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/tasks/
 *   laravel  http://localhost:8444/taches
 *
 * PAGE GARDEE PAR LE SEUL ROLE. Elle n'exige aucune permission — releve tel
 * quel dans INVENTAIRE.md, et porte tel quel : inventer une permission au
 * detour d'un portage serait un changement de droits.
 *
 * MAIS LE MENU, LUI, EXIGE `can_admin_portal`. Un compte role 2 sans cette
 * permission ne voit pas l'entree et atteint pourtant la page en tapant son
 * adresse. Le test le MESURE : c'est la propriete la plus interessante de cette
 * page, et elle ne se voit dans aucune des deux moities prise seule.
 *
 * L'AUTO-RAFRAICHISSEMENT est mesure en COMPTANT LES REQUETES vers
 * `/tasks/list`, pas en regardant si le tableau change : sur un historique
 * stable, un rafraichissement qui fonctionne parfaitement ne change rien a
 * l'ecran. Compter les appels mesure la fonction ; regarder le tableau
 * mesurerait la stabilite des donnees.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-tasks.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-tasks.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
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
const PAGE = CIBLE === 'laravel' ? '/taches' : '/tasks/';

const COMPTES = {
    'rw-test-user':  { role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW', attendu: 'refuse' },
    // Role 2 SANS can_admin_portal : la page ne demande que le role.
    'rw-test-admin': { role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX', attendu: 'autorise' },
    'rw-test-super': { role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW', attendu: 'autorise' },
};

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

/** Attente propre a une cible : le legacy n'a pas ce que le portage ajoute. */
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
    protocolTimeout: 60000,
});

async function connecte(nom) {
    const compte = COMPTES[nom];
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
    await page.type('input[name="2fa_code"]', totp(compte.secret), { delay: 8 });
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

/** Etat de la page tel qu'il est RENDU. */
async function releve(page) {
    return page.evaluate(() => {
        const corps = document.getElementById('task-tbody');
        const toutes = corps ? [...corps.querySelectorAll('tr')] : [];
        const donnees = toutes.filter(tr => tr.querySelectorAll('td').length > 1);
        const texte = (el) => (el?.textContent || '').trim();
        const stats = document.getElementById('task-stats');
        return {
            titre: texte(document.querySelector('h1')),
            filtre: Boolean(document.getElementById('task-filter')),
            optionsFiltre: [...(document.getElementById('task-filter')?.options || [])].map(o => o.value),
            autoRafraichissement: Boolean(document.getElementById('task-autorefresh')),
            tuiles: stats ? stats.children.length : 0,
            colonnes: [...document.querySelectorAll('thead th')].length,
            nbLignes: donnees.length,
            statuts: donnees.map(tr => texte(tr.querySelectorAll('td')[0])),
            types: donnees.map(tr => texte(tr.querySelectorAll('td')[1])),
            durees: donnees.map(tr => texte(tr.querySelectorAll('td')[4])),
            premiereTache: texte(donnees[0]?.querySelectorAll('td')[2]).slice(0, 60),
            texteCorps: texte(corps).slice(0, 200),
            texteEntier: document.body.innerText,
        };
    });
}

/** Attend la condition qu'on va asserter, jamais une duree fixe. */
async function attendJusqua(page, predicat, maxMs = 20000) {
    const limite = Date.now() + maxMs;
    let dernier = await releve(page);
    while (Date.now() < limite && ! predicat(dernier)) {
        await dors(350);
        dernier = await releve(page);
    }
    return dernier;
}

/**
 * Compte les appels a `/tasks/list` pendant une fenetre donnee.
 *
 * C'est la SEULE facon honnete de mesurer l'auto-rafraichissement : sur un
 * historique stable, un rafraichissement parfaitement fonctionnel ne change
 * rien a l'ecran. Regarder le tableau mesurerait la stabilite des donnees, pas
 * la fonction.
 */
async function compteAppels(page, ms) {
    let n = 0;
    const ecoute = (r) => { if (/\/tasks\/list/.test(r.url())) n++; };
    page.on('request', ecoute);
    await dors(ms);
    page.off('request', ecoute);
    return n;
}

try {
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: '/tasks/',
            fichiers: ['/tasks/index.php', '/tasks/js/main.js'], verifie, constate,
        });
        if (archivee) {
            const { ctx, page } = await connecte('rw-test-super');
            await verifieMenuLegacy(page, '/taches', verifie, constate);
            await ctx.close();
            console.log(lignes.join('\n'));
            console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — partie archivee`);
            await navigateur.close();
            process.exit(echecs > 0 ? 1 : 0);
        }
    }

    // ── La garde reelle, avec les trois comptes ─────────────────────────────
    for (const [nom, compte] of Object.entries(COMPTES)) {
        const { ctx, page } = await connecte(nom);

        // Le menu AVANT la page : on veut savoir si l'entree est proposee.
        const entreeAuMenu = await page.evaluate((chemin) =>
            [...document.querySelectorAll('a[href]')]
                .some(a => (a.getAttribute('href') || '').includes(chemin)),
            CIBLE === 'laravel' ? '/taches' : '/tasks/');

        const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
        const statut = rep?.status() ?? 0;
        const affichee = statut === 200
            && ! /connexion|login\.php/i.test(page.url())
            && await page.evaluate(() => Boolean(document.getElementById('task-tbody')));

        verifie(`${nom} (role ${compte.role}) : ${compte.attendu === 'autorise' ? "la page s'affiche" : 'la page est refusee'}`,
                compte.attendu === 'autorise' ? affichee : ! affichee,
                `statut=${statut} url=${page.url().replace(BASE, '')}`);

        /*
         * LE MENU EST-IL D'ACCORD AVEC LA PAGE ?
         *
         * La page ne demande que le role ; le menu, lui, range cette entree
         * dans un bloc garde par `can_admin_portal`. Un compte role 2 sans
         * cette permission ne voit donc PAS l'entree, et atteint pourtant la
         * page en tapant son adresse. Ce n'est un defaut d'aucune des deux
         * moities prise seule — d'ou la mesure ici.
         */
        if (nom === 'rw-test-admin') {
            constate('role 2 sans can_admin_portal',
                     `entree au menu : ${entreeAuMenu ? 'proposee' : 'ABSENTE'} · page : `
                     + `${affichee ? 'ACCESSIBLE' : 'refusee'}`);
            verifie('la page ne demande que le role, comme le legacy', affichee,
                    `statut=${statut}`);
        }

        await ctx.close();
        await dors(1200);
    }

    // ── Le contenu, avec le compte ROLE 2 ───────────────────────────────────
    // Deliberement : c'est lui qui prouve que la page se contente du role.
    await dors((resteFenetre() + 1) * 1000);
    const { ctx, page } = await connecte('rw-test-admin');
    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await attendJusqua(page, (e) => e.nbLignes > 0 || ! /Chargement|Loading/i.test(e.texteCorps));

    const etat = await releve(page);

    verifie('la page porte un titre', etat.titre.length > 0, etat.titre);
    verifie('le filtre par statut est present', etat.filtre, etat.optionsFiltre.join(', '));
    verifie('la case de rafraichissement automatique est presente', etat.autoRafraichissement);
    verifie('le resume compte quatre tuiles', etat.tuiles === 4, `${etat.tuiles}`);
    verifie('le tableau a cinq colonnes', etat.colonnes === 5, `${etat.colonnes}`);
    verifie('aucune cle de traduction morte a l\'ecran',
            ! /\b(tasks|nav|auth|accueil|profil|passerelle)\.[a-z_]{3,}\b/.test(etat.texteEntier));

    constate('taches affichees', `${etat.nbLignes}`);
    constate('statuts vus', [...new Set(etat.statuts)].join(', ') || 'aucun');
    constate('types vus', [...new Set(etat.types)].join(', ') || 'aucun');

    verifie('des taches reelles sont affichees', etat.nbLignes > 0,
            etat.nbLignes === 0 ? etat.texteCorps : `${etat.nbLignes} tache(s)`);
    verifie('les durees sont mises en forme, pas brutes',
            etat.durees.every(d => /^\d+(s|m\d*s?)$|^—$/.test(d)),
            [...new Set(etat.durees)].slice(0, 6).join(', '));

    // ── L'AUTO-RAFRAICHISSEMENT, mesure en comptant les appels ──────────────
    const avecAuto = await compteAppels(page, 7000);
    constate('appels a /tasks/list en 7 s, rafraichissement actif', `${avecAuto}`);
    verifie('le rafraichissement automatique interroge le backend',
            avecAuto >= 1, `${avecAuto} appel(s)`);

    await page.evaluate(() => {
        const c = document.getElementById('task-autorefresh');
        c.checked = false;
        c.dispatchEvent(new Event('change', { bubbles: true }));
    });
    const sansAuto = await compteAppels(page, 7000);
    constate('appels a /tasks/list en 7 s, rafraichissement coupe', `${sansAuto}`);
    verifie('decocher la case arrete vraiment les appels',
            sansAuto === 0, `${sansAuto} appel(s) alors qu'on l'a coupe`);

    /*
     * ── LE FILTRE PAR STATUT EST CASSE, ET L'INTERFACE LE CACHE ────────────
     *
     * `/tasks/list?status=<x>` repond 500 « Erreur BDD », pour TOUT statut.
     * Cause lue dans les journaux du backend : MySQL 1052, « Column 'status'
     * in where clause is ambiguous ». La requete filtree joint `machines`, qui
     * porte elle aussi une colonne `status`, et la clause `WHERE status = %s`
     * n'est pas qualifiee. La requete de comptage, elle, ne joint rien et
     * passe — d'ou une erreur qui n'apparait qu'a la seconde requete.
     *
     * Le JS du legacy n'ecrit le tableau que si l'appel a REUSSI. Sur echec il
     * ne fait RIEN : les lignes precedentes restent a l'ecran. Filtrer sur
     * « Echec » laisse donc 100 taches REUSSIES affichees, sans un mot. C'est
     * pire qu'un tableau vide : la page presente des donnees justes comme si
     * elles repondaient a une question qu'on n'a pas posee.
     *
     * Le test MESURE le 500 sur les deux cibles, et exige du portage qu'il ne
     * mente pas. Voir PARITE.md E-10.
     */
    let statutFiltre = 0;
    const ecoute = async (r) => {
        if (/\/tasks\/list.*status=/.test(r.url())) statutFiltre = r.status();
    };
    page.on('response', ecoute);

    await page.select('#task-filter', 'error');
    // Attendre la reponse, pas le calme : sur le legacy l'ecran ne bouge pas.
    const limite = Date.now() + 15000;
    while (Date.now() < limite && statutFiltre === 0) await dors(300);
    await dors(800);
    page.off('response', ecoute);

    const apresFiltre = await releve(page);
    constate('reponse du backend au filtre « echec »', `HTTP ${statutFiltre || '(aucune)'}`);
    constate('etat du tableau apres le filtre',
             `${apresFiltre.nbLignes} ligne(s), statuts : ${[...new Set(apresFiltre.statuts)].join(', ') || '-'}`);

    verifie('le filtre par statut est bien transmis au backend', statutFiltre !== 0,
            `HTTP ${statutFiltre}`);

    /*
     * La propriete qui compte : ne pas presenter des lignes NON FILTREES comme
     * si elles etaient le resultat du filtre. Soit le filtre aboutit, soit la
     * page le dit — jamais un entre-deux muet.
     */
    const honnete = statutFiltre === 200
        ? apresFiltre.statuts.every(x => /echec|error/i.test(x))
        : (apresFiltre.nbLignes === 0 && apresFiltre.texteCorps.length > 3);

    verifiePortage("un filtre en echec ne laisse pas des lignes non filtrees a l'ecran",
                   honnete,
                   `HTTP ${statutFiltre}, ${apresFiltre.nbLignes} ligne(s) : `
                   + `« ${apresFiltre.texteCorps.slice(0, 70)} »`);

    if (CIBLE === 'legacy') {
        constate('defaut du legacy',
                 `le filtre repond ${statutFiltre} et ${apresFiltre.nbLignes} taches `
                 + `« ${[...new Set(apresFiltre.statuts)].join(', ')} » restent affichees, sans message`);
    }

    await page.select('#task-filter', '');
    const filtreLeve = await attendJusqua(page, (e) => e.nbLignes > 0);
    verifie('lever le filtre ramene les taches', filtreLeve.nbLignes > 0,
            `${apresFiltre.nbLignes} -> ${filtreLeve.nbLignes}`);

    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
