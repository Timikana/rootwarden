/**
 * go-page-search.mjs - Recherche globale (serveurs, utilisateurs, CVE, tickets, audit).
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/search/
 *   laravel  http://localhost:8444/recherche
 *
 * LECTURE SEULE. Un seul appel : `GET /search?q=`, plafonne a 10 resultats par
 * categorie cote backend. Rien a produire, rien a detruire.
 *
 * CE QUE CE TEST CHERCHE VRAIMENT : ou menent les liens des resultats. Le
 * backend Python ne connait qu'un frontend et ecrit ses liens en dur —
 * `/tickets/index.php`, `/adm/audit_log.php`, `/update/index.php`. Chaque page
 * archivee par la migration transforme un de ces liens en **404** : la
 * recherche devient un menu qui mene a des pages disparues. Le test SUIT les
 * liens et mesure ce qu'ils rendent.
 *
 * La latence n'est PAS mesuree : le montage de fichiers de ce poste est ~258x
 * plus lent que le systeme du conteneur, et tout chiffre releve ici dirait
 * surtout combien de fichiers chaque cible charge.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-search.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-search.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { execFileSync } from 'child_process';
import { readdirSync } from 'node:fs';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy, sondeLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
/**
 * La base du legacy, LUE DANS LA CONFIGURATION DU PORTAGE.
 *
 * Ecrite en dur, elle faisait echouer l'assertion des marqueurs des que
 * `LEGACY_URL` pointait ailleurs — par exemple sur l'adresse de la VM, ce qu'il
 * FAUT poser pour ouvrir les deux portails depuis un autre poste. Les liens
 * legacy cessaient alors de commencer par la constante, etaient classes comme
 * INTERNES, et leur `target="_blank"` faisait tomber « aucun lien interne n'est
 * marque ».
 *
 * DEUXIEME suite atteinte par ce defaut apres `go-socle-navigation` : un test ne
 * doit pas ecrire en dur une valeur de DEPLOIEMENT, il doit la lire a la meme
 * source que la page — sinon il la contredit.
 */
function baseLegacyConfiguree() {
    if (process.env.E2E_LEGACY) return process.env.E2E_LEGACY;
    try {
        const sortie = execFileSync('docker',
            ['exec', 'rootwarden_laravel', 'php', 'artisan', 'config:show', 'app'],
            { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
        const ligne = sortie.split('\n').find(l => /^\s+url_legacy\s/.test(l));
        const url = ligne && ligne.match(/(https?:\/\/\S+)/);
        if (url) return url[1].replace(/\/+$/, '');
    } catch { /* le relais docker peut manquer : on retombe sur le defaut */ }
    return 'https://localhost:8443';
}
const LEGACY = baseLegacyConfiguree();
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
const PAGE = CIBLE === 'laravel' ? '/recherche' : '/search/';

const COMPTES = {
    'rw-test-user':  { role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW', attendu: 'refuse' },
    'rw-test-admin': { role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX', attendu: 'refuse' },
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
        const zone = document.getElementById('search-results');
        const texte = (el) => (el?.textContent || '').trim();
        const liens = [...(zone?.querySelectorAll('a[href]') || [])];
        return {
            titre: texte(document.querySelector('h1')),
            champ: Boolean(document.getElementById('search-input')),
            meta: texte(document.getElementById('search-meta')),
            cartes: zone ? zone.querySelectorAll('.rw-tuile, .bg-white, .rw-carte').length : 0,
            nbLiens: liens.length,
            liens: liens.map(a => a.getAttribute('href')),
            libelles: liens.map(a => texte(a).slice(0, 60)),
            externes: liens.filter(a => a.getAttribute('target') === '_blank').length,
            cibles: liens.map(a => a.getAttribute('target') || ''),
            texteZone: texte(zone).slice(0, 200),
            texteEntier: document.body.innerText,
        };
    });
}

/** Attend la condition qu'on va asserter, jamais une duree fixe. */
async function attendJusqua(page, predicat, maxMs = 20000) {
    const limite = Date.now() + maxMs;
    let dernier = await releve(page);
    while (Date.now() < limite && ! predicat(dernier)) {
        await dors(300);
        dernier = await releve(page);
    }
    return dernier;
}

/**
 * Saisit un terme et attend que la recherche ait REPONDU.
 *
 * Attendre « meta est non vide » ne marche pas : la consigne « tape au moins 2
 * caracteres » est deja affichee avant toute saisie, la condition est donc
 * satisfaite d'emblee et la sonde lit l'ecran d'avant. Le premier jet de ce
 * test croyait ainsi n'avoir aucun resultat pour « Test-Server ».
 *
 * On attend donc que la ligne d'etat CHANGE par rapport a ce qu'elle disait
 * avant la frappe, et qu'elle ne soit plus le marqueur d'attente.
 */
async function cherche(page, terme) {
    const avant = (await releve(page)).meta;

    await page.evaluate((t) => {
        const c = document.getElementById('search-input');
        c.value = t;
        c.dispatchEvent(new Event('input', { bubbles: true }));
    }, terme);

    /*
     * « La ligne d'etat a change » ne suffit pas : elle passe d'abord par un
     * message d'attente, qui satisfait la condition. Le second jet de ce test
     * lisait ainsi les resultats de la recherche PRECEDENTE.
     *
     * Les deux cibles annoncent « N resultat(s) pour "terme" » : attendre que
     * la ligne CITE LE TERME est donc un signal de fin exact, et il ne depend
     * d'aucun libelle qu'on pourrait reformuler.
     */
    if (terme.trim().length >= 2) {
        return attendJusqua(page, (e) => e.meta.includes(terme.trim()));
    }

    // Terme trop court : aucun appel n'est emis, la consigne s'affiche seule.
    return attendJusqua(page, (e) => e.meta !== '' && e.meta !== avant, 4000);
}

/*
 * ══ LA TABLE DE REDIRECTION N'ETAIT ASSEREE PAR PERSONNE ═══════════════════
 *
 * `App\Support\LiensLegacy::REMPLACEMENTS` traduit les chemins du legacy que
 * le backend ecrit EN DUR dans ses resultats de recherche. Mesure du
 * 2026-08-27 : **zero occurrence de `LiensLegacy` dans `tests/e2e/` et
 * `laravel/tests/`**. L'oubli de `/docker/` a la `v1.37.54` n'a donc pas ete
 * trouve par un test mais par une relecture — et six modules restent a
 * archiver.
 *
 * LA LISTE ATTENDUE SE DERIVE, ELLE NE SE RECOPIE PAS. Une liste ecrite a la
 * main vieillit : c'est le defaut d'E-142, ou une enumeration recopiee avait
 * derive de sa source. On lit donc `legacy/_deprecated/` — ce qui EST archive —
 * et la table par PHP LUI-MEME (`artisan tinker`), jamais a l'expression
 * reguliere : analyser du PHP au motif revient a reecrire un interpreteur, et
 * une entree mal lue serait declaree absente a tort.
 *
 * PROPRIETE, dans UN SEUL SENS. Toute partie archivee doit avoir son entree,
 * PREVENTIVE quand le backend n'emet pas son chemin. L'inverse n'est pas vrai :
 * la table porte legitimement des entrees qui ne correspondent a aucun dossier
 * archive (`/security/`, `/profile.php/`, `/`), et les compter comme un
 * manquement accuserait une table saine.
 */
function partiesArchivees() {
    const racine = new URL('../../legacy/_deprecated', import.meta.url).pathname;
    try {
        return readdirSync(racine, { withFileTypes: true })
            .filter((e) => e.isDirectory()).map((e) => e.name).sort();
    } catch { return []; }
}
function tableDeRedirection() {
    try {
        // Le mot de passe ne circule pas ici : `tinker` ne lit que du code.
        const sortie = execFileSync('sudo', ['-n', 'docker', 'exec', 'rootwarden_laravel',
            'php', 'artisan', 'tinker', '--execute',
            'foreach (App\\Support\\LiensLegacy::REMPLACEMENTS as $k => $v) echo "$k\\n";'],
            { encoding: 'utf8', timeout: 30000 });

        return sortie.split('\n').map((l) => l.trim()).filter((l) => l.startsWith('/'));
    } catch (e) { return null; }
}

try {
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: '/search/',
            fichiers: ['/search/index.php', '/search/js/main.js'], verifie, constate,
        });
        if (archivee) {
            const { ctx, page } = await connecte('rw-test-super');
            await verifieMenuLegacy(page, '/recherche', verifie, constate);
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
        const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
        const statut = rep?.status() ?? 0;
        const affichee = statut === 200
            && ! /connexion|login\.php/i.test(page.url())
            && await page.evaluate(() => Boolean(document.getElementById('search-input')));

        verifie(`${nom} (role ${compte.role}) : ${compte.attendu === 'autorise' ? "la page s'affiche" : 'la page est refusee'}`,
                compte.attendu === 'autorise' ? affichee : ! affichee,
                `statut=${statut} url=${page.url().replace(BASE, '')}`);
        await ctx.close();
        await dors(1200);
    }

    // ── Le contenu ──────────────────────────────────────────────────────────
    await dors((resteFenetre() + 1) * 1000);
    const { ctx, page } = await connecte('rw-test-super');
    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await dors(600);

    const depart = await releve(page);
    verifie('la page porte un titre', depart.titre.length > 0, depart.titre);
    verifie('le champ de recherche est present', depart.champ);
    verifie('aucune cle de traduction morte a l\'ecran',
            ! /\b(search|nav|auth|accueil|profil|passerelle|tip)\.[a-z_]{3,}\b/.test(depart.texteEntier));

    // ── Un terme trop court n'interroge pas le backend ──────────────────────
    const court = await cherche(page, 'a');
    constate('terme d\'un caractere', `« ${court.meta.slice(0, 60) } » · ${court.nbLiens} lien(s)`);
    verifie('un terme trop court est refuse avec une consigne',
            court.nbLiens === 0 && court.meta.length > 3,
            `« ${court.meta.slice(0, 60)} »`);

    // ── Une recherche qui ne rend rien le DIT ───────────────────────────────
    const vide = await cherche(page, 'zzzintrouvablezzz');
    constate('terme sans resultat', `« ${vide.meta.slice(0, 60)} » · ${vide.nbLiens} lien(s)`);
    verifie('une recherche sans resultat le dit, en citant le terme',
            vide.nbLiens === 0
            && (vide.texteZone.length > 3 || vide.meta.includes('zzzintrouvablezzz')),
            `zone « ${vide.texteZone.slice(0, 50)} » meta « ${vide.meta.slice(0, 50)} »`);

    // ── Une recherche reelle, sur une donnee du parc ────────────────────────
    const trouve = await cherche(page, 'Test-Server');
    constate('recherche « Test-Server »', `${trouve.nbLiens} lien(s) · meta « ${trouve.meta.slice(0, 70)} »`);
    verifie('une recherche sur le parc rend des resultats', trouve.nbLiens > 0,
            trouve.texteZone.slice(0, 80));
    /*
     * « Un chiffre est present » passait sur « Tape au moins 2 caracteres » :
     * une assertion creuse. Ce qu'on exige est que la ligne d'etat parle de LA
     * RECHERCHE — qu'elle cite le terme cherche.
     */
    verifie("la ligne d'etat cite le terme cherche",
            trouve.meta.includes('Test-Server'), trouve.meta.slice(0, 70));

    // ── Recherche transverse : plusieurs categories ─────────────────────────
    const large = await cherche(page, 'Ticket');
    constate('recherche « Ticket »', `${large.nbLiens} lien(s) · ${large.libelles.slice(0, 3).join(' | ')}`);

    /*
     * ── OU MENENT LES LIENS ? ──────────────────────────────────────────────
     *
     * Le backend ecrit ses liens en dur vers l'ANCIEN portail. Chaque partie
     * archivee en transforme un en 404. On SUIT donc chaque lien distinct et on
     * regarde ce qu'il rend, sans supposer.
     */
    const tousLiens = [...new Set([...trouve.liens, ...large.liens])].filter(Boolean);
    constate('liens distincts rendus', tousLiens.join(', ') || 'aucun');

    const morts = [];
    for (const lien of tousLiens) {
        // Un lien interne au portage se verifie sur SA cible ; un lien vers
        // l'ancien portail se verifie sur le legacy.
        const absolu = /^https?:\/\//i.test(lien);
        const base = absolu ? lien.replace(/(https?:\/\/[^/]+).*/i, '$1') : (CIBLE === 'laravel' ? BASE : LEGACY);
        const chemin = absolu ? lien.replace(/^https?:\/\/[^/]+/i, '') : lien;
        let statut = 0;
        try { statut = await sondeLegacy(base, chemin); } catch { statut = -1; }
        if (statut === 404) morts.push(`${lien} -> 404`);
        else constate(`lien ${lien}`, `HTTP ${statut}`);
    }

    if (morts.length) {
        constate('LIENS MORTS', morts.join(' · '));
    }
    verifiePortage('aucun resultat ne mene a une page archivee',
                   morts.length === 0,
                   morts.join(' · ') || 'aucun lien mort');

    /*
     * ══ CHAQUE PARTIE ARCHIVEE A-T-ELLE SON ENTREE DE REDIRECTION ? ═══════
     *
     * DANS UN SEUL SENS, et c'est la borne qui rend l'assertion juste : la
     * table n'est pas une image du dossier. Elle porte legitimement des entrees
     * qui ne correspondent a AUCUNE partie archivee — `/security/`,
     * `/profile.php/`, `/` — et les compter comme un manquement accuserait une
     * table saine. On ne verifie donc que l'implication utile : **archive =>
     * redirige**.
     *
     * Une entree peut etre PREVENTIVE : le backend n'emet en dur que
     * `/update/index.php`, `/tickets/index.php` et `/security/`. Pour les
     * autres, l'entree n'a aucun 404 a reparer — elle evite d'en fabriquer un
     * le jour ou un resultat, un signet ou une documentation cite le chemin.
     * C'est le cycle du plan : « mesurer si le backend emet le chemin,
     * preventif sinon ».
     *
     * COMPARAISON PAR CHEMIN NORMALISE EN ENTIER, jamais par prefixe : le filtre
     * d'archivage a deja accepte `/supervision/` parce qu'il CONTIENT
     * `/supervision`, et huit archivages avaient valide ce filtre sans qu'aucun
     * ne puisse le refuter.
     */
    const archivees = partiesArchivees();
    const table = tableDeRedirection();
    constate('parties archivees', `${archivees.length} — ${archivees.join(' ')}`);
    if (table === null) {
        verifiePortage('la table de redirection est lisible', false,
            'impossible de lire `LiensLegacy::REMPLACEMENTS` — la propriete suivante '
            + 'se serait verifiee sur un ensemble VIDE, donc sur rien');
    } else {
        constate('entrees de `LiensLegacy::REMPLACEMENTS`', `${table.length}`);
        const sansEntree = archivees.filter((p) => ! table.includes(`/${p}/`));
        verifiePortage('chaque partie archivee porte son entree de redirection',
            table.length > 0 && sansEntree.length === 0,
            sansEntree.length === 0
                ? `${archivees.length} partie(s) archivee(s), toutes redirigees`
                : `${sansEntree.map((p) => `/${p}/`).join(' · ')} — archivee(s) sans entree dans `
                  + '`LiensLegacy::REMPLACEMENTS`. Un resultat de recherche, un signet ou une '
                  + 'documentation citant ce chemin mene a un 404 brut d\'Apache');
    }

    if (CIBLE === 'legacy' && morts.length) {
        constate('defaut du legacy',
                 `${morts.length} lien(s) de resultat menent a une page archivee — `
                 + 'le backend ecrit des chemins de l\'ancien portail');
    }

    /*
     * Les liens qui restent sur l'ancien portail doivent le DIRE.
     *
     * Exiger « il existe au moins un lien marque » etait faux : une recherche
     * dont tous les resultats sont portes n'en produit aucun, et l'attente
     * echouait alors que le comportement etait juste. Ce qui doit tenir est une
     * IMPLICATION — tout lien qui sort vers l'ancien portail porte le marqueur,
     * et aucun lien interne ne le porte.
     */
    const paires = [...trouve.liens.map((h, i) => [h, trouve.cibles[i]]),
                    ...large.liens.map((h, i) => [h, large.cibles[i]])];
    const versLegacy = paires.filter(([h]) => String(h).startsWith(LEGACY));
    const versPortage = paires.filter(([h]) => ! String(h).startsWith(LEGACY));

    constate('liens sortants / internes', `${versLegacy.length} / ${versPortage.length}`);
    verifiePortage("tout lien sortant est marque, aucun lien interne ne l'est",
                   versLegacy.every(([, t]) => t === '_blank')
                   && versPortage.every(([, t]) => t !== '_blank'),
                   paires.map(([h, t]) => `${h}${t ? ' [' + t + ']' : ''}`).join(' · '));

    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
