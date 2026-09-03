/**
 * go-page-wazuh.mjs - Module `wazuh/`, sous-lot R1 : la page en LECTURE SEULE.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/wazuh/
 *   laravel  http://localhost:8444/wazuh
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  POURQUOI CETTE SUITE EXISTE : LE MENU EST PASSE A 32/32 AVEC UNE PAGE   ║
 * ║  QU'AUCUNE SUITE NE CONNAISSAIT.                                         ║
 * ║                                                                          ║
 * ║  Mesure du 2026-09-02 20:00 : `wazuh` n'apparait dans AUCUNE des deux    ║
 * ║  listes du runner. Les trois suites `go-wazuh*.mjs` datent d'avril, ne   ║
 * ║  visent que `BASE_URL` et ne sont dans aucun lot — voir §4 du            ║
 * ║  REGISTRE-HORS-LOT.md, ou l'une d'elles est signalee comme DANGEREUSE    ║
 * ║  (elle ecrit, et vise `machine_id: 1`).                                  ║
 * ║                                                                          ║
 * ║  ⚠ Remesurer par les LISTES du runner, jamais par un grep global :       ║
 * ║    sed -n '/^SUITES_LARAVEL=(/,/^)/p' ../../scripts/rejouer-lot.sh       ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * ══ LES DEUX VOIES D'ADMISSION, ET ELLES SONT L'INVERSE D'`audit-ssh` ═════
 *
 * La route porte `role:2` ET `perm:can_manage_wazuh` (`web.php`), et
 * `ExigePermission.php:35` exempte le role 3 : la permission se lit « cette
 * permission OU superadmin ». Mesure du 2026-09-02 20:5x, les trois comptes
 * du banc portent `can_manage_wazuh = 0` :
 *
 *   rw-test-user   role 1  wazuh=0  ->  403, refuse par le ROLE
 *   rw-test-admin  role 2  wazuh=0  ->  403, refuse par la PERMISSION   <- discriminant
 *   rw-test-super  role 3  wazuh=0  ->  200, admis par le ROLE SEUL
 *
 * Dans `audit-ssh`, le role 2 DETIENT la permission et entre par elle. Ici il
 * ne la detient pas et sort par elle. **Les deux branches du OU sont donc
 * exercees, l'une comme admission, l'autre comme refus** — c'est la seule
 * page du banc ou le meme predicat est mesure dans les deux sens.
 *
 * ══ D'OU VIENNENT LES ANCRES : D'UNE INSPECTION A L'ECRAN ═════════════════
 *
 * Relevees par l'inspection manuelle du 2026-09-02 20:36, **pas deduites du
 * blade**. Deux faits de cette inspection changent ce qu'il faut mesurer :
 *
 *   - **il n'y a AUCUN bouton sur la page**, le seul du document etant
 *     « Deconnexion » dans l'en-tete. La page est en lecture pure : cette
 *     suite n'a rien a cliquer, et **ne doit pas chercher un controle qui
 *     n'existe pas** ;
 *   - **le panneau de configuration ne porte AUCUN `<input>`** et decrit les
 *     secrets sans les montrer.
 *
 * ══ LA LISTE VIDE EST UN ETAT, PAS UN VIDE ═══════════════════════════════
 *
 * `wazuh_agents` porte ZERO ligne, et c'est l'etat NORMAL : `install_all`
 * portait `AND a.id IS NULL` sur une table sans colonne `id` et rendait 500
 * sans `try` — **le module n'a jamais servi**. La page rend malgre tout le
 * PARC, chaque machine marquee « aucun agent ».
 *
 * On mesure donc que **les lignes valent les machines vivantes**, jamais que
 * « la liste est vide » : une assertion de vide passerait au vert sur une vue
 * cassee, sur un garde, ET sur une redirection.
 *
 * ══ SURETE — LE DISCRIMINANT EST LA METHODE, PAS LE CHEMIN ════════════════
 *
 * `/wazuh/config`, `/wazuh/options` et `/wazuh/rules/<name>` portent CHACUN un
 * GET qui lit et un non-GET qui ecrit, **au meme chemin** (`web.php` le dit
 * aussi). Un filet qui classe par CHEMIN ne peut structurellement pas les
 * distinguer : il classerait l'ecriture en lecture. Le filet porte donc sur le
 * MODULE et c'est la METHODE qui tranche.
 *
 * ⚠ ET CE MOTIF ATTRAPE LA PAGE ELLE-MEME, servie a `/wazuh/` cote legacy.
 *   Seul le filtre `methode !== 'GET'` l'en preserve, la navigation etant un
 *   GET. **Ne rendez pas ce garde agnostique a la methode sans exclure la
 *   page** : c'est ce qui a fait avorter la navigation dans go-page-pare-feu
 *   le 2026-09-02 (4 FAIL, net::ERR_BLOCKED_BY_CLIENT).
 *
 * Les NEUF gestes d'ecriture du module ne sont jamais exerces : `install`,
 * `install_all`, `uninstall`, `restart`, `detect`, `group`, et les POST de
 * `config`, `options` et `rules`.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=http://localhost:8444  node go-page-wazuh.mjs
 *   E2E_BASE=https://localhost:8443 node go-page-wazuh.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync, readFileSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const MACHINE_PRODUCTION = 1;

/* Secrets RELEVES dans les suites du depot, jamais inventes : 11 occurrences
 * chacun, un seul secret par compte (apparie par script, pas par `grep -A1`
 * qui debordait sur la ligne du compte suivant). */
const COMPTES = {
    user:  { nom: 'rw-test-user',  role: 1, perm: 0, admis: false,
        secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW',
        motif: 'refuse par le ROLE — role 1, et pas de `can_manage_wazuh`' },
    admin: { nom: 'rw-test-admin', role: 2, perm: 0, admis: false,
        secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX',
        motif: 'refuse par la PERMISSION — le role 2 est satisfait, la permission NON' },
    super: { nom: 'rw-test-super', role: 3, perm: 0, admis: true,
        secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW',
        motif: 'admis par le ROLE SEUL, sans detenir la permission' },
};

/*
 * Toute ECRITURE du module. Voir l'en-tete : la METHODE tranche, pas le chemin,
 * et le filet porte sur le MODULE pour qu'une route ajoutee demain soit
 * couverte sans que personne y pense.
 */
const INTERDITS = /\/wazuh\//;
/* Un chemin qui n'existe pas, donc sans effet : le temoin du collecteur. */
const TEMOIN = '/temoin-e2e-inexistant';
const VERS_BACKEND = /\/(api\/gateway|api_proxy\.php)\//;
/*
 * Ce qu'un secret NE DOIT JAMAIS traverser. Le panneau declare la presence
 * d'une valeur chiffree ; s'il en rendait une, elle porterait l'un de ces
 * prefixes. La sonde ne cherche donc pas « un mot de passe » — elle cherche
 * la FORME du chiffre, qui est la seule chose reconnaissable a coup sur.
 */
const FORME_SECRET = /\b(aes:|sodium:|\$2[aby]\$|-----BEGIN)/;

const C = CIBLE === 'laravel'
    ? { connexion: '/connexion', page: '/wazuh',
        portee: '[data-rw="wazuh-portee"]',
        nonPorte: '[data-rw="wazuh-non-porte"]',
        npListe: '[data-rw="wazuh-np-liste"]',
        npReserve: '[data-rw="wazuh-np-reserve"]',
        config: '[data-rw="wazuh-config"]',
        agents: '[data-rw="wazuh-agents"]',
        agent: '[data-rw="wazuh-agent"]',
        serveur: '[data-rw="wazuh-serveur"]',
        options: '[data-rw="wazuh-options"]',
        regles: '[data-rw="wazuh-regles"]',
        regle: '[data-rw="wazuh-regle"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]' }
    : { connexion: '/auth/login.php?lang=fr', page: '/wazuh/',
        portee: null, nonPorte: null, npListe: null, npReserve: null,
        config: null, agents: null, agent: null, serveur: null,
        options: null, regles: null, regle: null,
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]' };

/**
 * Un libelle LU dans le catalogue, jamais recopie ici. Une chaine recopiee fige
 * la valeur du jour : le catalogue peut changer, l'assertion continue de
 * comparer a l'ancienne et devient verte sur un ecran qui ne dit plus rien.
 * Rend `null` si la cle est absente — et une assertion qui recoit `null`
 * s'abstient au lieu de conclure.
 *
 * ⚠ LES DEUX FORMES DE GUILLEMETS. La version de go-page-pare-feu ne lit que
 *   les chaines SIMPLE-quotees ; `lang/fr/wazuh.php` les ecrit en DOUBLE. Elle
 *   aurait rendu `null` sur toutes mes cles, et chaque assertion se serait
 *   declaree SANS OBJET — **un vert par abstention, sur la seule chose que
 *   cette etape mesure.** Copier une fonction voisine sans verifier qu'elle
 *   s'applique au fichier visé est le meme geste que copier un motif.
 */
function libelle(cle) {
    try {
        const chemin = new URL('../../laravel/lang/fr/wazuh.php', import.meta.url).pathname;
        const texte = readFileSync(chemin, 'utf8');
        const simple = texte.match(new RegExp(`'${cle}'\\s*=>\\s*'((?:[^'\\\\]|\\\\.)*)'`));
        if (simple) return simple[1].replace(/\\'/g, "'").replace(/\\\\/g, '\\');
        const double = texte.match(new RegExp(`'${cle}'\\s*=>\\s*"((?:[^"\\\\]|\\\\.)*)"`));

        return double ? double[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\') : null;
    } catch { return null; }
}

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
/** `d` n'est imprime QUE sur un FAIL ; `toujours` sort dans les deux verdicts. */
function verifie(l, ok, d, toujours) {
    const suffixe = toujours || (! ok && d) || '';
    note(`${ok ? 'PASS' : 'FAIL'}  ${l}${suffixe ? '  — ' + suffixe : ''}`);
    if (! ok) echecs += 1;
}
function constate(l, v) { note(`INFO  ${l} : ${v}`); }
function verifiePortage(l, ok, d) {
    if (CIBLE === 'laravel') return verifie(l, ok, ok ? '' : d);
    constate(l, ok ? 'verifie sur le legacy aussi' : `ecart assume du legacy — ${d}`);
}

function b32(s){const A='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.replace(/=+$/,''))b+=A.indexOf(c.toUpperCase()).toString(2).padStart(5,'0');const o=[];for(let i=0;i+8<=b.length;i+=8)o.push(parseInt(b.slice(i,i+8),2));return Buffer.from(o)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

const avortees = [];
const passees = [];
const boites = [];
/* Requetes VUES par l'intercepteur : le temoin que le filet a eu un objet. */
let vues = 0;

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];

async function connecte(compte) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(45000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => {
        boites.push({ type: d.type(), message: d.message() });
        try { await d.dismiss(); } catch { /* deja ferme */ }
    });

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        vues += 1;
        const url = r.url();
        const chemin = url.replace(/^https?:\/\/[^/]+/, '');
        let corps = '';
        try { corps = r.postData() || ''; } catch { /* pas de corps */ }

        // LE TEMOIN PASSE : il vise un chemin inexistant, donc sans effet, et
        // c'est lui qui prouve que le collecteur voit les POST. L'avorter
        // reviendrait a mesurer le filet, pas la page.
        if (chemin.startsWith(TEMOIN)) {
            passees.push({ route: chemin, methode: r.method(), corps });
            r.continue().catch(() => {});

            return;
        }
        // FAIL-CLOSED : le GESTE d'abord, la CIBLE ensuite.
        if (r.method() !== 'GET' && INTERDITS.test(url)) {
            avortees.push({ route: chemin, motif: 'ECRITURE du module wazuh', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(url)
            || /srv-zabbix/.test(corps)) {
            avortees.push({ route: chemin, motif: 'vise la PRODUCTION', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (VERS_BACKEND.test(url) || INTERDITS.test(url)) {
            passees.push({ route: chemin, methode: r.method(), corps });
        }
        r.continue().catch(() => {});
    });

    await page.goto(`${BASE}${C.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', compte.nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    for (let essai = 0; essai < 2; essai += 1) {
        const champ = await page.$('input[name="2fa_code"]');
        if (! champ) break;
        if (essai > 0) await dors((resteFenetre() + 1) * 1000);
        await champ.click({ clickCount: 3 });
        await champ.type(totp(compte.secret), { delay: 8 });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
    }
    if (C.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$(C.accepte);
        if (b) { await b.click(); try { await nav; } catch {} }
    }

    return { ctx, page, erreursJs, surConnexion: /connexion|login\.php/.test(page.url()) };
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

/* L'etat de la base, hisse : releve dans le `try`, relu dans le `finally`.
 * `null` = jamais releve, ce qui n'est PAS zero — voir le `finally`. */
let machinesVivantes = null;
/* L'etat initial des agents, hisse pour la meme raison. `null` = jamais releve. */
let agentsAvant = null;

try {
    /*
     * ══ LA PRECONDITION : LE TRIPLET EST UN ETAT DU BANC ═════════════════
     *
     * Les libelles disent « refuse par la PERMISSION » et « admis par le ROLE
     * SEUL ». Si un `can_manage_wazuh` passait a 1, ils diraient encore la
     * meme chose en mesurant autre chose. On relit donc l'etat, et on refuse
     * de conclure s'il a change.
     */
    const perms = {};
    for (const cle of Object.keys(COMPTES)) {
        const c = COMPTES[cle];
        perms[c.nom] = compteEnBase(
            'SELECT COALESCE(MAX(p.can_manage_wazuh), 0) FROM rootwarden.users u '
            + `LEFT JOIN rootwarden.permissions p ON p.user_id = u.id WHERE u.name = '${c.nom}'`);
    }
    constate('can_manage_wazuh en base', Object.entries(perms)
        .map(([n, v]) => `${n}=${v}`).join(' · '));
    const triplet = Object.values(COMPTES).every((c) => perms[c.nom] === c.perm);
    verifie('le triplet de permissions est celui que les libelles decrivent',
        triplet,
        'un `can_manage_wazuh` a change : les assertions garderaient leur libelle'
        + ' et mesureraient autre chose — la suite ne conclut pas',
        Object.values(COMPTES).map((c) => `${c.nom}:${c.perm}`).join(' '));
    if (! triplet) throw new Error('precondition non tenue');

    /*
     * ⚠ LE PREDICAT DE « MACHINE VIVANTE » N'EST PAS `archived = 0` : CETTE
     *   COLONNE N'EXISTE PAS. Mesure du 2026-09-02 21:0x, avant le premier
     *   lancement — `compteEnBase` aurait leve « Unknown column 'archived' »
     *   et la precondition aurait echoue en accusant la base.
     *
     * Le predicat du depot, releve dans go-page-groupes et non devine :
     *   lifecycle_status IS NULL OR lifecycle_status <> 'archived'
     * Etat mesure : 3 machines, toutes `active`.
     *
     * Remesurer : SELECT id, name, lifecycle_status FROM rootwarden.machines
     */
    machinesVivantes = compteEnBase(
        'SELECT COUNT(*) FROM rootwarden.machines '
        + "WHERE lifecycle_status IS NULL OR lifecycle_status <> 'archived'");
    const nAgents = compteEnBase('SELECT COUNT(*) FROM rootwarden.wazuh_agents');
    agentsAvant = nAgents;
    const nRegles = compteEnBase('SELECT COUNT(*) FROM rootwarden.wazuh_rules');
    constate('etat des donnees',
        `machines vivantes=${machinesVivantes} · wazuh_agents=${nAgents} · wazuh_rules=${nRegles}`);
    constate('agents a zero', nAgents === 0
        ? 'ETAT NORMAL — le module n\'a jamais servi (install_all rendait 500), la page'
          + ' doit rendre le PARC en disant « aucun agent »'
        : `${nAgents} agent(s) : le module a servi depuis, les assertions de cette`
          + ' etape mesurent desormais autre chose');

    // ══ 1. LES DEUX BRANCHES DU « OU », L'UNE EN ADMISSION L'AUTRE EN REFUS
    for (const cle of ['user', 'admin', 'super']) {
        const compte = COMPTES[cle];
        await etape(`garde : ${compte.nom} (role ${compte.role}, perm ${compte.perm})`, async () => {
            const s = await connecte(compte);
            try {
                verifie(`${compte.nom} : la session a tenu`, ! s.surConnexion, s.page.url());
                if (s.surConnexion) return;
                const rep = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
                const statut = rep ? rep.status() : 0;
                constate(`${compte.nom} : statut`, `${statut} — ${compte.motif}`);
                // AU STATUT, jamais au texte : un 404 dit « cette page n'existe
                // pas », pas « vous n'y avez pas droit ».
                verifie(`${compte.nom} (role ${compte.role}) est ${compte.admis ? 'admis' : 'refuse'}`,
                    compte.admis ? statut === 200 : statut === 403, `statut ${statut}`);
            } finally {
                try { await s.ctx.close(); } catch { /* deja ferme */ }
            }
        });
        await dors((resteFenetre() + 1) * 1000);
    }

    // ══ 2. LA PAGE, AU SEUL COMPTE ADMIS ═════════════════════════════════
    const s = await connecte(COMPTES.super);
    verifie('la session a tenu', ! s.surConnexion, s.page.url());
    if (s.surConnexion) throw new Error('session non etablie');
    const page = s.page;
    await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
    await dors(900);
    /*
     * L'URL FINALE, AVANT TOUTE LECTURE DU DOM. Un observable absent peut etre
     * une REDIRECTION : « zero ligne rendue » ressemble a une vue cassee alors
     * que la page n'a jamais ete atteinte.
     */
    constate('URL finale', page.url());
    verifie('la page atteinte est bien celle qu\'on croit',
        new RegExp(`${C.page.replace(/[/]/g, '\\/')}/?$`).test(page.url()),
        `redirige vers ${page.url()} : ce qui suit ne mesurerait pas cette page`,
        page.url().replace(/^https?:\/\/[^/]+/, ''));

    await etape('la liste des agents rend le PARC, et dit son etat', async () => {
        if (CIBLE !== 'laravel') {
            constate('liste des agents',
                'SANS OBJET — les ancres du legacy ne sont pas relevees, rien n\'est mesure ici');

            return;
        }
        const vu = await page.evaluate((sel) => {
            const bloc = document.querySelector(sel.agents);
            const lignesAgent = [...document.querySelectorAll(sel.agent)];

            return {
                bloc: bloc !== null && bloc.offsetParent !== null,
                lignes: lignesAgent.length,
                textes: lignesAgent.map((n) => (n.innerText || '').replace(/\s+/g, ' ').trim()),
            };
        }, C);
        constate('liste des agents', vu.bloc
            ? `${vu.lignes} ligne(s) : ${vu.textes.slice(0, 3).join(' / ') || '(vides)'}`
            : 'bloc NON rendu');

        /*
         * ON MESURE QUE LES LIGNES VALENT LE PARC, JAMAIS QUE LA LISTE EST
         * VIDE. Une assertion de vide passerait au vert sur une vue cassee,
         * sur un garde, et sur une redirection — trois causes que « 0 ligne »
         * ne distingue pas.
         */
        verifiePortage('la liste rend une ligne par machine vivante',
            vu.bloc && machinesVivantes !== null && vu.lignes === machinesVivantes,
            ! vu.bloc ? 'le bloc des agents n\'est pas rendu'
                : `${vu.lignes} ligne(s) pour ${machinesVivantes} machine(s) vivante(s)`);
        /*
         * ET CHAQUE LIGNE DIT SON ETAT. Une ligne presente mais vide
         * satisferait « il y a des lignes » : c'est le piege d'une assertion
         * qui mesure la presence au lieu du contenu.
         */
        verifiePortage('chaque ligne porte un etat lisible, non vide et traduit',
            vu.lignes > 0 && vu.textes.every((t) => t.length > 0 && ! /:[a-z_]{3,}/.test(t)),
            vu.lignes === 0 ? 'aucune ligne'
                : `une ligne est vide ou porte un jeton : ${vu.textes.join(' | ')}`);
    });

    await etape('la configuration DECLARE les secrets et n\'en rend AUCUNE valeur', async () => {
        if (CIBLE !== 'laravel') {
            constate('panneau de configuration',
                'SANS OBJET — les ancres du legacy ne sont pas relevees');

            return;
        }
        const vu = await page.evaluate((sel) => {
            const bloc = document.querySelector(sel.config);
            if (! bloc) return { bloc: false };

            return {
                bloc: true,
                texte: (bloc.innerText || '').replace(/\s+/g, ' ').trim(),
                saisies: bloc.querySelectorAll('input, textarea, select').length,
                html: bloc.innerHTML.length,
            };
        }, C);
        if (! vu.bloc) {
            verifiePortage('le panneau de configuration est rendu', false, 'ancre absente');

            return;
        }
        constate('panneau de configuration', `${vu.saisies} champ(s) de saisie, ${vu.html} octets de balisage`);
        /*
         * AUCUN CHAMP DE SAISIE. La page est en lecture pure — l'inspection a
         * l'ecran du 2026-09-02 20:36 n'a trouve AUCUN `<input>` ici. Une
         * entree libre absente ne se contourne pas ; une entree libre validee,
         * si — par une requete forgee.
         */
        verifiePortage('le panneau n\'offre AUCUN champ de saisie',
            vu.saisies === 0,
            `${vu.saisies} champ(s) de saisie : la page cesserait d'etre en lecture pure`);
        /*
         * ET AUCUNE VALEUR DE SECRET NE TRAVERSE. On ne cherche pas « un mot
         * de passe » — indecidable — mais la FORME du chiffre, seule chose
         * reconnaissable a coup sur. Si quelqu'un « ameliore » ce panneau en
         * affichant la valeur, cette assertion rougit.
         */
        const fuite = FORME_SECRET.test(vu.texte);
        verifiePortage('aucune valeur chiffree n\'est rendue a l\'ecran',
            ! fuite,
            'le panneau rend une valeur portant la forme d\'un secret');
        /*
         * LA PRESENCE EST DECLAREE, ET C'EST LA BONNE FORMULATION : PHP
         * chiffre la chaine vide en `sodium:...`, donc un booleen calcule sur
         * une colonne chiffree mesure des OCTETS et non la presence d'un
         * secret. « une valeur chiffree est enregistree » dit MOINS et dit
         * VRAI ; « un mot de passe est enregistre » dirait plus et faux.
         */
        verifiePortage('la presence d\'un secret est DECLAREE en mots, pas montree',
            /chiffr|enregistr|aucune valeur/i.test(vu.texte),
            `le panneau ne declare pas l'etat des secrets : « ${vu.texte.slice(0, 80)} »`);
    });

    await etape('les blocs de lecture disent leur etat plutot que de rester vides', async () => {
        if (CIBLE !== 'laravel') {
            constate('blocs de lecture', 'SANS OBJET — ancres du legacy non relevees');

            return;
        }
        const vu = await page.evaluate((sel) => {
            const t = (s) => {
                const n = document.querySelector(s);

                return n ? (n.innerText || '').replace(/\s+/g, ' ').trim() : null;
            };

            return {
                options: t(sel.options),
                regles: t(sel.regles),
                nRegles: document.querySelectorAll(sel.regle).length,
                serveur: document.querySelector(sel.serveur) !== null,
            };
        }, C);
        constate('options', vu.options === null ? 'ancre absente' : `« ${(vu.options || '').slice(0, 70)} »`);
        constate('regles', `${vu.nRegles} regle(s) rendue(s)`);
        /*
         * UNE INVITE, PAS UN VIDE. « Choisissez un serveur pour voir ses
         * options » est un ETAT ; une zone vide serait indiscernable d'un
         * echec de lecture.
         */
        verifiePortage('le bloc des options rend une INVITE et non du vide',
            vu.options !== null && vu.options.length > 0 && ! /:[a-z_]{3,}/.test(vu.options),
            vu.options === null ? 'ancre absente'
                : vu.options.length === 0 ? 'le bloc est vide : indiscernable d\'un echec de lecture'
                    : `jeton non traduit : ${vu.options}`);
        verifiePortage('le selecteur de serveur est present — le seul controle de la page',
            vu.serveur, 'aucun selecteur de serveur');
        verifiePortage('les regles rendues valent celles de la base',
            vu.nRegles === nRegles,
            `${vu.nRegles} rendue(s) pour ${nRegles} en base`);
    });

    await etape('la declaration de manque NOMME les gestes absents', async () => {
        if (CIBLE !== 'laravel') {
            constate('declaration de manque', 'SANS OBJET — ancres du legacy non relevees');

            return;
        }
        const vu = await page.evaluate((sel) => {
            const bloc = document.querySelector(sel.nonPorte);
            const liste = document.querySelector(sel.npListe);
            const reserve = document.querySelector(sel.npReserve);
            const portee = document.querySelector(sel.portee);

            return {
                bloc: bloc !== null,
                liste: liste ? (liste.innerText || '').replace(/\s+/g, ' ').trim() : null,
                reserve: reserve ? (reserve.innerText || '').replace(/\s+/g, ' ').trim() : null,
                portee: portee ? (portee.innerText || '').replace(/\s+/g, ' ').trim() : null,
            };
        }, C);
        /*
         * ⚠ MA PREMIERE VERSION CHERCHAIT DES `li` ET DES `p` DESCENDANTS, ET
         *   RENDAIT 0 (1 FAIL, premier lancement 20:57). `wazuh-np-liste` EST
         *   lui-meme un `<p>` : la liste est **une seule chaine traduite**, pas
         *   des noeuds. Le FAIL accusait la page et decrivait mon selecteur —
         *   quatrieme fois aujourd'hui que le message nomme l'objet le plus
         *   PROCHE de la rupture et non la cause.
         *
         * On mesure donc DEUX objets distincts :
         *   1. la PAGE rend bien ce que le catalogue dit (rien d'invente a
         *      l'ecran, rien de perdu entre les deux) ;
         *   2. le CATALOGUE enumere au lieu de compter — c'est la propriete de
         *      fond : « neuf gestes ne sont pas portes » ne peut etre ni
         *      verifie ni infirme, une liste nommee si.
         *
         * ⚠ ET ON N'ASSERTE PAS « NEUF ». Le catalogue nomme neuf gestes mais
         *   rend 8 segments sur `·`, l'un des separateurs portant deux gestes
         *   de part et d'autre d'une incise. Asserter 9 serait un nombre a
         *   entretenir qui ne correspond a aucune mesure ; le seuil dit ce que
         *   la mesure peut soutenir.
         */
        const npListe = libelle('np_liste');
        const segments = npListe ? npListe.split('·').map((x) => x.trim()).filter(Boolean) : [];
        constate('declaration de manque', npListe === null
            ? '⚠ cle `np_liste` absente du catalogue'
            : `${npListe.length} car., ${segments.length} segment(s) enumeres`);

        if (npListe === null) {
            constate('gestes absents',
                'SANS OBJET — la cle du catalogue est illisible, il n\'y a rien a comparer'
                + ' et un vert par abstention ne vaudrait rien');
        } else {
            verifiePortage('la declaration rendue est CELLE du catalogue, mot pour mot',
                vu.liste === npListe.replace(/\s+/g, ' ').trim(),
                vu.liste === null ? 'ancre de liste absente'
                    : `l'ecran dit « ${(vu.liste || '').slice(0, 60)} » et le catalogue`
                      + ` « ${npListe.slice(0, 60)} »`);
            verifiePortage('les gestes absents sont NOMMES, et non comptes',
                segments.length >= 6 && segments.every((x) => x.length > 3),
                `${segments.length} segment(s) enumeres — attendu au moins 6, chacun non trivial`);
        }
        /*
         * ET LA RESERVE SUR LE LEGACY. L'inspection a l'ecran a releve que la
         * page previent que TROIS de ces gestes n'ont pas l'effet que leur nom
         * suggere **y compris sur l'ancien portail**. C'est l'inverse d'une
         * declaration fausse : une page qui previent que ce qu'elle n'offre pas
         * ne marche pas non plus la ou elle renvoie.
         */
        verifiePortage('la reserve sur l\'ancien portail est dite, pas sous-entendue',
            vu.reserve !== null && vu.reserve.length > 0,
            vu.reserve === null ? 'ancre de reserve absente' : 'la reserve est vide');
        /*
         * ET LA PORTEE POSITIVE, l'autre moitie de la declaration.
         *
         * ⚠ `wazuh-portee` etait declaree dans ma table et JAMAIS lue — une
         *   CLE MORTE, trouvee en relisant avant le premier lancement. C'est le
         *   meme signal que les trois cles mortes de go-page-groupes : une
         *   ancre declaree qu'aucun code ne lit annonce une mesure qui n'a pas
         *   lieu. Je la LIS plutot que de la retirer, parce que la propriete
         *   complete est que la page dise les DEUX : ce qu'elle fait, et ce
         *   qu'elle ne fait pas. Un manque declare sans portee declaree
         *   laisserait croire que tout le reste est porte.
         */
        constate('portee declaree', vu.portee === null ? 'ancre absente'
            : `« ${vu.portee.slice(0, 90)} »`);
        verifiePortage('la page declare AUSSI ce qu\'elle fait, pas seulement ce qu\'elle ne fait pas',
            vu.portee !== null && vu.portee.length > 0 && ! /:[a-z_]{3,}/.test(vu.portee),
            vu.portee === null ? 'ancre de portee absente'
                : vu.portee.length === 0 ? 'la portee est declaree vide'
                    : `jeton non traduit : ${vu.portee}`);
    });

    await etape('la page n\'offre aucun geste, et n\'en compose aucun', async () => {
        /*
         * L'INSPECTION A L'ECRAN N'A TROUVE AUCUN BOUTON hors « Deconnexion ».
         * On le MESURE plutot que de s'y fier : une page en lecture pure se
         * verifie par « rien n'est parti », mais l'absence de controle est une
         * propriete distincte, et c'est celle qui se perdrait la premiere si
         * quelqu'un ajoutait une action.
         */
        const nBoutons = await page.evaluate(() => [...document.querySelectorAll('button, [type="submit"]')]
            .filter((b) => ! /deconnexion|logout|deconnecter/i.test(b.innerText || ''))
            .length);
        constate('boutons hors deconnexion', String(nBoutons));
        verifiePortage('la page n\'offre aucun bouton d\'action',
            nBoutons === 0,
            `${nBoutons} bouton(s) : la page cesserait d'etre en lecture pure`);
    });

    await etape('a 390 px, le tableau defile DANS son cadre et la page ne deborde pas', async () => {
        if (CIBLE !== 'laravel') {
            constate('rendu etroit', 'SANS OBJET — ancres du legacy non relevees');

            return;
        }
        /*
         * PROPRIETE TROUVEE EN REGARDANT L'IMAGE, PAS EN LISANT LE CODE.
         *
         * A 390 px la colonne `ENV` est hors champ. C'est CORRECT si le cadre
         * du tableau defile, et c'est une colonne INATTEIGNABLE s'il coupe —
         * deux etats que l'image ne distingue pas. Mesure : le cadre porte
         * `overflow-x: auto`, scrollWidth 391 contre clientWidth 340.
         *
         * Ce qui doit rougir un jour : un `overflow: hidden` pose pour « faire
         * propre », qui rendrait la derniere colonne definitivement illisible
         * sans qu'aucune assertion DOM ni aucune capture ne le montre.
         */
        await page.setViewport({ width: 390, height: 844 });
        await dors(500);
        const r = await page.evaluate((sel) => {
            const t = document.querySelector(`${sel.agents} table`);
            if (! t) return { table: false };
            let c = t.parentElement, cadre = null;
            while (c && c !== document.body) {
                const st = getComputedStyle(c);
                if (/auto|scroll|hidden/.test(st.overflowX)) {
                    cadre = { overflowX: st.overflowX, scrollW: c.scrollWidth, clientW: c.clientWidth };
                    break;
                }
                c = c.parentElement;
            }

            return {
                table: true, cadre,
                entetes: [...t.querySelectorAll('th')].map((x) => (x.innerText || '').trim()),
                pageDeborde: document.documentElement.scrollWidth > window.innerWidth + 1,
            };
        }, C);
        await page.setViewport({ width: 1400, height: 900 });
        await dors(300);

        if (! r.table) {
            constate('rendu etroit', 'SANS OBJET — aucun tableau d\'agents a mesurer');

            return;
        }
        constate('rendu a 390 px', `${r.entetes.length} colonne(s) : ${r.entetes.join(' | ')} · cadre `
            + (r.cadre ? `${r.cadre.overflowX}, ${r.cadre.scrollW}/${r.cadre.clientW}` : 'AUCUN'));
        verifiePortage('la page ne deborde pas horizontalement a 390 px',
            ! r.pageDeborde,
            'le corps de la page defile lateralement : le tableau pousse la mise en page');
        verifiePortage('le cadre du tableau DEFILE plutot que de couper',
            r.cadre !== null && /auto|scroll/.test(r.cadre.overflowX),
            r.cadre === null ? 'aucun cadre a overflow declare : le tableau deborde librement'
                : `overflow-x: ${r.cadre.overflowX} — la derniere colonne serait inatteignable`);
    });

    await etape('l\'entree de menu de la page est LISIBLE, au style calcule', async () => {
        /*
         * CE QUE JE CROYAIS VOIR SUR L'IMAGE, MESURE POUR DE BON.
         *
         * Le rapport de contraste ne se lit ni dans le HTML ni dans une
         * assertion DOM : une pastille a 1,06:1 est invisible alors que son
         * balisage est juste, et ce banc l'a paye trois fois (purge Tailwind).
         * On mesure donc le style CALCULE, et on remonte la chaine des parents
         * jusqu'a un fond opaque — un `background-color: transparent` ne dit
         * rien de ce qu'on voit.
         *
         * L'entree active n'est PAS marquee `aria-current` (mesure du
         * 2026-09-02) : on la trouve par son `href`, qui est le seul lien
         * fiable entre le menu et la page servie.
         */
        const r = await page.evaluate((chemin) => {
            const lum = (c) => {
                const m = (c || '').match(/[\d.]+/g);
                if (! m) return null;
                const [r1, g1, b1] = m.slice(0, 3).map(Number).map((v) => {
                    const x = v / 255;

                    return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4);
                });

                return 0.2126 * r1 + 0.7152 * g1 + 0.0722 * b1;
            };
            const liens = [...document.querySelectorAll('nav a, aside a')];
            const actif = liens.find((a) => {
                try { return new URL(a.href, location.origin).pathname === chemin; } catch { return false; }
            });
            if (! actif) return { trouve: false, total: liens.length };
            const st = getComputedStyle(actif);
            let fond = st.backgroundColor, n = actif;
            while (/rgba\(0, 0, 0, 0\)|transparent/.test(fond) && n.parentElement) {
                n = n.parentElement;
                fond = getComputedStyle(n).backgroundColor;
            }
            const L1 = lum(st.color); const L2 = lum(fond);
            const ratio = (L1 === null || L2 === null) ? null
                : (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);

            return {
                trouve: true, total: liens.length,
                libelle: (actif.innerText || '').trim(),
                couleur: st.color, fond,
                ratio: ratio === null ? null : Math.round(ratio * 100) / 100,
            };
        }, C.page);

        if (! r.trouve) {
            verifiePortage('l\'entree de menu de la page est presente',
                false, `aucun des ${r.total} liens du menu ne pointe vers ${C.page}`);

            return;
        }
        constate('entree de menu', `« ${r.libelle || '(SANS LIBELLE)'} » — ${r.ratio}:1`
            + ` (${r.couleur} sur ${r.fond}), sur ${r.total} liens`);
        verifiePortage('l\'entree porte un libelle non vide',
            r.libelle.length > 0 && ! /:[a-z_]{3,}/.test(r.libelle),
            r.libelle.length === 0 ? 'l\'entree est rendue SANS LIBELLE'
                : `jeton non traduit : ${r.libelle}`);
        verifiePortage('le contraste de l\'entree atteint le seuil AA de 4,5:1',
            r.ratio !== null && r.ratio >= 4.5,
            r.ratio === null ? 'couleurs illisibles : le rapport n\'a pas pu etre calcule'
                : `${r.ratio}:1 — sous 4,5:1, l'entree est illisible alors que son balisage est juste`);
    });

    // ══ 3. LE TEMOIN, PUIS LA FERMETURE PAR L'ABSENCE ════════════════════
    let temoinVu = false;
    await etape('le collecteur voit un POST (temoin)', async () => {
        const n = passees.length;
        await page.evaluate((t) => fetch(t, { method: 'POST', body: '1' }).catch(() => {}), TEMOIN);
        await dors(500);
        temoinVu = passees.slice(n).some((p) => p.methode === 'POST' && p.route.startsWith(TEMOIN));
        constate('temoin', temoinVu ? `POST ${TEMOIN} vu` : `POST ${TEMOIN} NON vu`);
        verifie('le collecteur detecte un POST emis depuis la page', temoinVu,
            'le collecteur ne voit pas les POST : une absence d\'ecriture ne prouverait rien');
    });

    await etape('aucune ecriture du module n\'est partie', async () => {
        const ecritures = passees.filter((p) => p.methode !== 'GET' && INTERDITS.test(p.route));
        const avortEcr = avortees.filter((a) => INTERDITS.test(a.route));
        constate('requetes du module', passees
            .filter((p) => INTERDITS.test(p.route))
            .map((p) => `${p.methode} ${p.route}`).join(' | ') || '(aucune)');

        if (! temoinVu) {
            constate('fermeture par l\'absence',
                'SANS OBJET — le temoin n\'a pas ete vu, une absence de POST ne prouverait rien');

            return;
        }
        verifie('AUCUNE ecriture du module wazuh n\'est partie',
            ecritures.length === 0 && avortEcr.length === 0,
            [...ecritures.map((p) => `${p.methode} ${p.route} (PASSE)`),
             ...avortEcr.map((a) => `${a.route} (avorte)`)].join(' | '),
            `${passees.filter((p) => INTERDITS.test(p.route)).length} requete(s) du module, toutes en GET`);
    });

    await etape('aucune erreur JavaScript', async () => {
        verifie('aucune erreur JavaScript sur la page', s.erreursJs.length === 0,
            s.erreursJs.slice(0, 3).join(' | '), 'aucune');
    });

    // ══ 4. CAPTURES ══════════════════════════════════════════════════════
    await etape('captures', async () => {
        const dossier = new URL(`./screenshots/wazuh/${CIBLE}`, import.meta.url).pathname;
        mkdirSync(dossier, { recursive: true });
        for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                         { n: 'mobile', w: 390, h: 844 }]) {
            await page.setViewport({ width: f.w, height: f.h });
            await dors(400);
            await page.screenshot({ path: `${dossier}/wz-${f.n}.png`, fullPage: true });
        }
        /*
         * ⚠ TROIS CAPTURES, ET PAS QUATRE — POURQUOI J'AI RETIRE LA QUATRIEME.
         *
         * `fullPage: true` tronque la barre laterale : la page est etiree a la
         * hauteur du CONTENU, la barre n'est peinte que sur sa portion visible,
         * et l'entree de menu active tombe sous la coupe. En regardant l'image
         * j'y ai vu une bande bleutee SANS LIBELLE et j'ai failli signaler un
         * defaut de contraste. Mesure ensuite : 65 entrees, ZERO sous le seuil
         * AA, l'entree `Wazuh` a 5,82:1. **L'image mentait, pas la page.**
         *
         * J'ai alors ajoute une capture `fullPage: false`, en croyant que la
         * barre y tiendrait : elle mesure 1328 px et le cadre 900. Meme coupe.
         * Puis une capture a hauteur « mesuree » — et la mesure etait fausse
         * DEUX FOIS : `querySelector('nav, aside')` rend `ASIDE.rw-laterale`,
         * le conteneur DEJA contraint au cadre (900) et non `NAV.rw-menu`
         * (1328), et elle etait prise au gabarit mobile ou la barre est repliee
         * en tiroir. Le `900` affiche etait mon plancher. **Le libelle disait
         * « hauteur MESUREE » et rien n'avait ete mesure.**
         *
         * La propriete que je cherchais — l'entree active est-elle lisible —
         * est une ASSERTION plus haut, au style CALCULE. Elle est meilleure
         * qu'une image sur ce point, et une capture qu'on garde « au cas ou »
         * est une mesure de plus a entretenir sans personne pour la lire.
         */
        verifie('les trois captures sont ecrites', true, '', dossier);
    });
} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    // ══ SURETE — LE FILET NE SE SUPPOSE PAS, IL SE MESURE ════════════════
    try {
        constate('requetes AVORTEES', avortees.length
            ? avortees.map((a) => `${a.route} (${a.motif})`).join(' | ') : '(aucune)');
        constate('boites natives ouvertes', boites.length
            ? boites.map((b) => `${b.type} « ${b.message.slice(0, 60)} »`).join(' | ') : '(aucune)');

        if (vues === 0) {
            constate('controle de surete',
                'SANS OBJET — aucune requete vue, le filet n\'a rien eu a filtrer');
        } else {
            verifie('AUCUNE requete n\'a vise la production',
                ! passees.some((p) => new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(p.route)
                    || /srv-zabbix/.test(p.corps || '')),
                'une requete a vise `srv-zabbix`', `${vues} requete(s) vue(s)`);
        }
    } catch (e) { note(`FAIL  controle de surete : ${e.message}`); echecs += 1; }
    try {
        /*
         * AUCUN AGENT N'A ETE INSTALLE. La page n'offre pas le geste et le
         * filet l'avorterait — mais c'est ICI qu'on le verifie, pas dans le
         * code du portage.
         *
         * ⚠ COMPARE A L'ETAT INITIAL, PAS A ZERO, et `null` signifie « jamais
         * releve » et non « zero » : sans ça, un `0 === 0` decernerait un PASS
         * a une comparaison qui n'a pas eu lieu.
         */
        const apres = compteEnBase('SELECT COUNT(*) FROM rootwarden.wazuh_agents');
        constate('wazuh_agents apres la suite', String(apres));
        if (agentsAvant === null) {
            constate('aucun agent installe',
                `SANS OBJET — l'etat initial n'a jamais ete releve, ${apres} en base : une`
                + ' difference est incalculable et « 0 ajoute » serait une affirmation gratuite');
        } else {
            /*
             * ⚠ J'AI ECRIT « COMPARE A L'ETAT INITIAL, PAS A ZERO » CI-DESSUS
             *   ET COMPARE A ZERO JUSTE EN DESSOUS (2026-09-02 21:0x, avant le
             *   premier lancement). **Une intention ecrite en commentaire n'est
             *   pas une mesure** — c'est le meme defaut que les trois cles
             *   mortes de go-page-groupes, trouve cette fois en relisant.
             */
            verifie('AUCUN agent n\'a ete installe par cette suite', apres === agentsAvant,
                `${agentsAvant} agent(s) avant, ${apres} apres : ${apres - agentsAvant} ajoute(s)`,
                `${apres} agent(s), inchange`);
        }
        const zabbix = litEnBase("SELECT CONCAT(name,'|',ip) FROM rootwarden.machines WHERE id = 1");
        verifie('srv-zabbix est intacte', zabbix.length === 1 && /^srv-zabbix\|/.test(zabbix[0]),
            zabbix[0] || '(absente)', zabbix[0] || '');
    } catch (e) { note(`FAIL  controle de l'etat : ${e.message}`); echecs += 1; }
    for (const c of contextes) { try { await c.close(); } catch { /* deja ferme */ } }
    try { await navigateur.close(); } catch { /* deja ferme */ }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
