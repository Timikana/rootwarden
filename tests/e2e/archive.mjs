import https from 'node:https';
import http from 'node:http';

/**
 * archive.mjs - Constat d'archivage d'une partie du legacy.
 *
 * Une page portee puis deplacee dans `legacy/_deprecated/` n'existe plus cote
 * legacy. Le test qui la visait n'a pas a ECHOUER pour autant : il doit
 * CONSTATER l'archivage. Sans cela, chaque portage laisse derriere lui une
 * suite rouge, et une suite rouge en permanence finit par ne plus etre lue.
 *
 * Ce que le constat exige, et qui n'est pas rien :
 *   1. l'URL legacy rend bien 404 — le dossier est parti, pas seulement vide ;
 *   2. aucun de ses fichiers ne repond plus, JavaScript compris ;
 *   3. l'entree de menu du legacy mene desormais au portage, et non au 404
 *      qu'on vient de creer soi-meme.
 *
 * La sonde n'ouvre pas de navigateur : Apache rend 404 pour un chemin absent
 * AVANT toute redirection de connexion. Une page encore vivante rend 302.
 */

/**
 * Etat d'une URL legacy : 404 = archivee, 302 = vivante, autre = a regarder.
 *
 * Passe par `node:https` plutot que par `fetch` : le legacy porte un certificat
 * auto-signe, et `fetch` le refuse. La tolerance est bornee A CETTE SONDE — pas
 * question de poser NODE_TLS_REJECT_UNAUTHORIZED sur tout le processus pour
 * lire un code de statut.
 */
export function sondeLegacy(base, chemin) {
    const u = new URL(base + chemin);
    const client = u.protocol === 'https:' ? https : http;
    return new Promise((resolve, reject) => {
        const req = client.request(
            { hostname: u.hostname, port: u.port, path: u.pathname + u.search,
              method: 'GET', rejectUnauthorized: false },
            r => { r.resume(); resolve(r.statusCode); },
        );
        req.on('error', reject);
        req.end();
    });
}

/**
 * Deroule le constat d'archivage. Rend `true` si la partie est archivee — a
 * l'appelant de s'arreter la — et `false` si elle est encore servie.
 *
 * @param {object} o
 * @param {string} o.base        racine du legacy
 * @param {string} o.chemin      chemin de la partie, ex. `/commandlog/`
 * @param {string[]} o.fichiers  sous-ressources qui doivent avoir disparu
 * @param {Function} o.verifie   assertion du test appelant
 * @param {Function} o.constate  releve non bloquant du test appelant
 */
export async function constateArchivage({ base, chemin, fichiers = [], verifie, constate }) {
    const statut = await sondeLegacy(base, chemin);
    if (statut !== 404) {
        constate(`partie ${chemin}`, `encore servie par le legacy (HTTP ${statut})`);
        return false;
    }

    constate('etat de la partie', `archivee — ${chemin} rend 404`);
    verifie(`${chemin} ne repond plus cote legacy`, statut === 404, `HTTP ${statut}`);

    for (const f of fichiers) {
        const s = await sondeLegacy(base, f);
        verifie(`${f} ne repond plus non plus`, s === 404, `HTTP ${s}`);
    }

    return true;
}

/**
 * L'entree de menu DU LEGACY doit mener au portage. C'est la moitie qui compte :
 * un menu qui pointe vers un 404 qu'on vient d'installer soi-meme est pire que
 * l'ancienne page. Se lit dans une session ouverte, le menu n'existant pas pour
 * un visiteur anonyme.
 */
/**
 * Le lien du menu MENE-T-IL quelque part ?
 *
 * Verifier que le `href` CITE la route ne prouve rien : mesure du 2026-08-20 —
 * `LARAVEL_URL` valait `https://localhost:8444` alors que le portage ecoute en
 * clair, et les huit entrees redirigees menaient a un echec TLS. La chaine
 * etait juste, le lien mort.
 */
async function repond(url) {
    const u = new URL(url);
    const client = u.protocol === 'https:' ? https : http;
    return new Promise((resolve) => {
        const req = client.request(
            { hostname: u.hostname, port: u.port, path: u.pathname + u.search,
              method: 'GET', rejectUnauthorized: false, timeout: 8000 },
            r => { r.resume(); resolve(r.statusCode); },
        );
        req.on('error', () => resolve(0));
        req.on('timeout', () => { req.destroy(); resolve(0); });
        req.end();
    });
}

export async function verifieMenuLegacy(page, routeportee, verifie) {
    const liens = await page.evaluate(() =>
        [...document.querySelectorAll('a[href]')].map(a => a.getAttribute('href')));
    const mene = liens.filter(h => h && h.includes(routeportee));
    verifie("l'entree de menu du legacy mene au portage",
            mene.length > 0,
            mene.length ? mene[0] : `aucun lien vers « ${routeportee} » parmi ${liens.length} liens`);

    // Et surtout : que ce lien REPONDE. Un menu qui cite la bonne route mais
    // n'aboutit pas est le defaut qu'on croyait corriger.
    if (mene.length) {
        const statut = await repond(mene[0]);
        verifie('ce lien aboutit', statut > 0 && statut < 500,
                statut ? `HTTP ${statut}` : 'aucune reponse (hote, port ou protocole)');
    }
}
