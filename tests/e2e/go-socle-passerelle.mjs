/**
 * go-socle-passerelle.mjs - La passerelle vers le backend Python.
 *
 * C'est l'endpoint le plus puissant du portail : il transmet toutes les routes
 * du backend. Ce test verifie ses gardes DANS L'ORDRE, avec les trois comptes
 * dedies, et non en superadmin.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/api_proxy.php<chemin>
 *   laravel  http://localhost:8444/api/gateway<chemin>
 *
 * Un ecart est VOULU et documente (PARITE.md E-02) : le legacy compare les
 * chemins par DEBUT DE CHAINE, donc `/search` autorise `/searchall`. Le
 * portage compare par SEGMENT. Verifie avant de resserrer sur les 201 routes
 * reelles du backend : zero difference de verdict.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-socle-passerelle.mjs              (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-socle-passerelle.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const RACINE = CIBLE === 'laravel' ? '/api/gateway' : '/api_proxy.php';

const COMPTES = {
    'rw-test-user':  { role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW' },
    'rw-test-super': { role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW' },
};

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0, ecarts = 0;
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
/** Attente qui ne vaut que pour le portage ; ecart connu cote legacy. */
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

    if (ok) { lignes.push(`PASS  ${libelle}${detail ? '  — ' + detail : ''}`); return; }
    if (CIBLE === 'legacy') { lignes.push(`ECART CONNU (legacy)  ${libelle}${detail ? '  — ' + detail : ''}`); ecarts++; }
    else { lignes.push(`FAIL  ${libelle}${detail ? '  — ' + detail : ''}`); echecs++; }
}
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }

const navigateur = await puppeteer.launch({
    headless: 'new',
    protocolTimeout: 60000,
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
});

async function connecte(nom) {
    const compte = COMPTES[nom];
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    page.on('dialog', d => d.dismiss().catch(() => {}));

    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: '/cgu' }
        : { connexion: '/auth/login.php', cgu: '/terms.php' };

    await page.goto(`${BASE}${chemins.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]');
    try { await nav; } catch {}

    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    await page.type('input[name="2fa_code"]', totp(compte.secret), { delay: 8 });
    nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]');
    try { await nav; } catch {}

    // Accepter les conditions pour entrer. Ancrage sur le CONTRAT DOM cote
    // Laravel : la page porte deux boutons submit, refuser vient en premier.
    if (new RegExp(chemins.cgu.replace('.', '\\.')).test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const bouton = await page.$('[data-rw="cgu-accepter"]') || await page.$('button[name="accept_terms"]');
        if (bouton) await bouton.evaluate(b => b.click());
        try { await nav; } catch {}
    }

    return { ctx, page };
}

/** Appelle la passerelle depuis la page, cookies et jeton compris. */
async function appelle(page, chemin, methode = 'GET') {
    return page.evaluate(async (url, m) => {
        const jeton = document.querySelector('meta[name="csrf-token"]')?.content
                   || document.querySelector('input[name="csrf_token"]')?.value || '';
        const entetes = { 'X-Requested-With': 'XMLHttpRequest' };
        if (m !== 'GET') entetes['X-CSRF-TOKEN'] = jeton;
        // Un appel qui ne rend jamais fait echouer TOUT le lot sur un delai de
        // protocole, sans rien mesurer. On borne, et l'absence de reponse
        // devient un resultat comme un autre.
        const arret = new AbortController();
        const minuteur = setTimeout(() => arret.abort(), 15000);
        try {
            const r = await fetch(url, {
                method: m, headers: entetes, credentials: 'same-origin', signal: arret.signal,
            });
            const t = await r.text();
            return { statut: r.status, corps: t.slice(0, 200) };
        } catch (e) {
            return { statut: -1, corps: String(e).slice(0, 120) };
        } finally {
            clearTimeout(minuteur);
        }
    }, `${BASE}${RACINE}${chemin}`, methode);
}

try {
    // ── Sans session : la passerelle ne repond pas ──────────────────────────
    {
        const ctx = await navigateur.createBrowserContext();
        const page = await ctx.newPage();
        const rep = await page.goto(`${BASE}${RACINE}/list_machines`, { waitUntil: 'networkidle2' });
        const refuse = /connexion|login/i.test(page.url()) || [401, 403, 419].includes(rep?.status() ?? 0);
        verifie('sans session, la passerelle refuse', refuse,
                `statut=${rep?.status()} url=${page.url().replace(BASE, '')}`);
        await ctx.close();
    }

    // ── Superadmin ─────────────────────────────────────────────────────────
    {
        const { ctx, page } = await connecte('rw-test-super');

        const permise = await appelle(page, '/list_machines');
        verifie('route de la liste blanche : transmise au backend', permise.statut === 200,
                `statut=${permise.statut}`);
        constate('reponse du backend (extrait)', permise.corps.slice(0, 90).replace(/\s+/g, ' '));

        const hors = await appelle(page, '/route_inexistante_xyz');
        verifie('route hors liste blanche : refusee', hors.statut === 403, `statut=${hors.statut}`);

        const traversee = await appelle(page, '/../etc/passwd');
        verifie('traversee de chemin : refusee', [400, 403, 404].includes(traversee.statut),
                `statut=${traversee.statut}`);

        // Le coeur de l'ecart E-02 : `/search` est autorise, `/searchall` ne
        // doit pas l'etre. Le legacy compare par debut de chaine et le laisse
        // passer (il aboutit alors sur un 404 du backend, pas sur un refus).
        const forge = await appelle(page, '/searchall');
        constate('chemin forge /searchall', `statut=${forge.statut}`);
        verifiePortage('chemin forge /searchall : refuse par la passerelle (403)',
                       forge.statut === 403, `statut=${forge.statut}`);

        /*
         * Les sondes MUTANTES ne sont jouees que sur la cible portee.
         *
         * Deux raisons. D'abord le legacy est la REFERENCE, pas le produit :
         * on ne le teste que pour savoir ce qu'il fait, et son comportement en
         * lecture suffit a l'etablir. Ensuite un POST refuse par son controle
         * CSRF invalide la session, son JS de sondage part alors vers la page
         * de connexion, et cette navigation DETRUIT le contexte d'execution :
         * le page.evaluate en cours ne rend jamais, et tout le lot expire sans
         * rien mesurer. Constate le 2026-08-18.
         */
        if (CIBLE === 'laravel') {
            // Route exigeant une re-authentification ponctuelle : non portee,
            // donc refusee plutot que transmise.
            const stepUp = await appelle(page, '/policy/rollback', 'POST');
            verifie('route exigeant une re-authentification : refusee (403)',
                    stepUp.statut === 403, `statut=${stepUp.statut}`);
        } else {
            constate('sondes mutantes', 'non jouees sur le legacy (voir le commentaire)');
        }

        if (CIBLE === 'laravel') {
            // Falsification de requete : la propriete a verifier est qu'une
            // requete CROSS-SITE soit refusee. Un `fetch` same-origin depuis la
            // page passe LEGITIMEMENT — ce n'est pas une falsification, et le
            // mesurer avait d'abord fait croire a une absence de controle.
            //
            // Le navigateur pose `Sec-Fetch-Site` lui-meme et interdit de le
            // surcharger : on sort donc du navigateur et on rejoue la requete
            // depuis Node, avec les memes cookies de session.
            const cookies = await page.cookies(BASE);
            const entete = cookies.map(c => `${c.name}=${c.value}`).join('; ');
            const url = `${BASE}${RACINE}/list_machines`;

            const statut = async (site) => {
                const r = await fetch(url, {
                    method: 'POST',
                    headers: { Cookie: entete, 'Sec-Fetch-Site': site },
                    redirect: 'manual',
                });
                return r.status;
            };

            const croise = await statut('cross-site');
            verifie('requete CROSS-SITE sans jeton : refusee', croise === 419, `statut=${croise}`);

            const meme = await statut('same-origin');
            verifie('requete same-origin : acceptee (transmise au backend)',
                    meme !== 419, `statut=${meme}`);
        }

        await ctx.close();
    }

    // ── Role 1, sans aucune permission ─────────────────────────────────────
    {
        await dors((resteFenetre() + 1) * 1000);
        const { ctx, page } = await connecte('rw-test-user');

        const admin = await appelle(page, '/admin/users');
        verifie('role 1 : route reservee a l\'administration refusee', admin.statut === 403,
                `statut=${admin.statut}`);

        if (CIBLE === 'laravel') {
            const policy = await appelle(page, '/policy/sudo/deploy', 'POST');
            verifie('role 1 : route de politique sudo refusee', policy.statut === 403,
                    `statut=${policy.statut}`);
        }

        await ctx.close();
    }
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL / ${ecarts} ecart(s) connu(s)`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
