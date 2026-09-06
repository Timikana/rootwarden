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
    let u;
    try {
        u = new URL(url);
    } catch {
        // Un href relatif n'est pas une URL : le dire plutot que lever. Mesure
        // du 2026-08-23 : l'ancien lien `/supervision/` faisait remonter un
        // `TypeError: Invalid URL` au milieu de la suite, la ou un verdict etait
        // attendu.
        return 0;
    }
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

/*
 * ══ TROIS ISSUES, PAS DEUX — ET LA TROISIEME A COUTE VINGT ROUGES ═════════
 *
 * Mesure du 2026-09-05, moitie legacy du LOT : sur 22 suites rouges, **VINGT**
 * echouaient sur cette seule assertion, avec le meme detail :
 *
 *     FAIL  l'entree de menu du legacy mene au portage
 *           — aucun lien vers « /supervision » parmi 0 liens
 *
 * Zero liens. Pas « un menu qui pointe ailleurs » : **pas de page du tout**.
 * `legacy/index.php` a ete archive dans la journee, donc la page qui PORTE le
 * menu n'existe plus. Le controle lisait un 404, y trouvait zero ancre, et
 * concluait que le menu ne menait nulle part.
 *
 * **Ce n'est pas vingt regressions, c'est un controle qui ECHOUE la ou il
 * devrait S'ABSTENIR.** Et la dissymetrie compte : un controle qui echoue a
 * tort fabrique de l'alarme — coûteuse mais visible ; un controle qui
 * s'abstient a tort fabrique du DEDOUANEMENT, que personne ne rouvre. Celui-ci
 * se trompait du cote le moins coûteux, ce qui n'en fait pas un bon controle.
 *
 * LE DISCRIMINANT EST L'ABSENCE TOTALE D'ANCRES. Une page legacy servie en
 * porte toujours — menu, pied, fil. Zero ancre ne veut pas dire « le menu est
 * faux », ca veut dire « il n'y a pas de page ». Les deux se distinguent, et
 * « je n'ai pas pu regarder » n'est pas « rien a signaler ».
 *
 * ⚠ FAIL-CLOSED : si l'appelant ne fournit pas `constate`, on ECHOUE comme
 * avant. Un appelant qui oublie l'argument ne doit pas heriter d'un silence.
 */
export async function verifieMenuLegacy(page, routeportee, verifie, constate) {
    const liens = await page.evaluate(() =>
        [...document.querySelectorAll('a[href]')].map(a => a.getAttribute('href')));

    /*
     * ⚠ LE DISCRIMINANT EST LE STATUT, PAS LE NOMBRE D'ANCRES.
     *
     * Premiere redaction : `liens.length === 0`. Elle marchait le 2026-09-05 a
     * 23:09 parce qu'une URL archivee rendait le 404 NU d'Apache — 236 octets,
     * zero ancre. **Elle aurait cesse de marcher a 23:18**, quand E-425 a pose
     * un `ErrorDocument 404` qui NOMME et LIE le portail : la page archivee
     * porte desormais UNE ancre, `liens.length` vaut 1, et les vingt suites
     * seraient reparties en echec — avec « parmi 1 liens » au lieu de « parmi
     * 0 », c'est-a-dire sous les traits d'un vrai defaut de menu.
     *
     * **Un discriminant fonde sur une consequence de l'etat (le corps est vide)
     * se perime des que quelqu'un ameliore cet etat.** Celui fonde sur l'etat
     * lui-meme (la page repond 404) survit : le CODE est conserve par E-425,
     * et il est ce que le contrat d'archivage asserte partout ailleurs.
     */
    const statutPage = await repond(page.url());
    if (statutPage === 404 && typeof constate === 'function') {
        constate("entree de menu vers « " + routeportee + " »",
            'NON MESURE — la page ou l\'on se trouve rend 404 (' + page.url() + ') : '
            + 'ce n\'est pas un menu qui echoue, c\'est la page qui le portait qui a '
            + 'ete archivee. Il n\'y a rien a juger, et l\'exigence n°3 du contrat '
            + 'devient sans objet tant qu\'aucune page legacy ne subsiste pour porter '
            + 'un menu.');

        return;
    }
    /*
     * LE LIEN DOIT ETRE ABSOLU, ET SON CHEMIN DOIT ETRE LA ROUTE — pas la
     * contenir.
     *
     * Mesure du 2026-08-23, sur `supervision/` : un filtre `h.includes(route)`
     * acceptait l'ANCIEN lien du legacy, `/supervision/`, qui contient bien
     * `/supervision`. L'assertion annoncait « l'entree de menu mene au
     * portage » en montrant un chemin qui mene au 404 qu'on venait d'installer.
     * C'est le premier module ou la route portee est une sous-chaine du chemin
     * legacy, donc le premier ou ce filtre pouvait mentir — les huit modules
     * archives avant lui (`/update/` contre `/mises-a-jour`, etc.) n'avaient
     * aucune collision, et l'ont donc masquee.
     *
     * Un lien RELATIF est servi par le legacy : par construction il ne peut pas
     * mener au portage. `new URL(h)` sans base echoue sur un relatif, ce qui
     * suffit a l'ecarter.
     */
    const mene = liens.filter((h) => {
        if (! h) return false;
        let u;
        try {
            u = new URL(h);
        } catch {
            return false;
        }

        return u.pathname === routeportee || u.pathname === `${routeportee}/`;
    });
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
