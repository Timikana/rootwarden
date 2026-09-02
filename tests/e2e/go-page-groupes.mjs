/**
 * go-page-groupes.mjs — les groupes de machines, en lecture seule.
 *
 * legacy   `/groups/`                      portage  `/groupes`
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  ⚠ E-274 N'EST PAS COUVERT PAR CETTE SUITE, ET C'EST UNE DECISION.       ║
 * ║                                                                          ║
 * ║  E-274 dit : **un groupe dynamique SANS FILTRE doit afficher le PARC,    ║
 * ║  pas du vide** — c'etait une ligne blanche avant R1, et c'est la seule   ║
 * ║  propriete de cette page qu'un « rend 200 » ne verrait pas.              ║
 * ║                                                                          ║
 * ║  ⚠ CE CADRE A ETE ECRIT AVANT R2 ET R3. Depuis, cette suite POSE une     ║
 * ║  fixture — deux groupes STATIQUES et inertes, voir plus bas — et le      ║
 * ║  refus ci-dessous ne porte plus que sur le cas DYNAMIQUE, qui reste      ║
 * ║  entier : un groupe dont les filtres sont rejetes resout le PARC.       ║
 * ║                                                                          ║
 * ║  **Mesure du 2026-09-02 : `machine_groups` porte ZERO ligne.** Il        ║
 * ║  n'existe aucun groupe. Une assertion ecrite ici serait verte sur l'etat ║
 * ║  vide **sans jamais toucher la propriete** — le vert par absence, sur la ║
 * ║  seule chose qui compte.                                                 ║
 * ║                                                                          ║
 * ║  ⚠ **R2 (`5a0ff0b`, 2026-09-02 18:42:58) A LIVRE LA CREATION**, et son   ║
 * ║  message dit E-274 « ferme PAR CONSTRUCTION ». Ce cadre reste vrai sur   ║
 * ║  le point qui compte : **cette suite ne cree toujours aucun groupe.**    ║
 * ║  Elle va desormais jusqu'au panneau d'ANNONCE et s'y arrete — la         ║
 * ║  confirmation n'est jamais prise. Ce qu'elle ne couvre donc PAS : le     ║
 * ║  parc affiche par un groupe dynamique REELLEMENT cree. Le refus de       ║
 * ║  fixture ci-dessous n'a pas bouge, parce que `srv-zabbix` est toujours   ║
 * ║  active — verifier avant de le lever.                                    ║
 * ║                                                                          ║
 * ║  ── POURQUOI LA FIXTURE EST REFUSEE, ET NON REPORTEE ──                  ║
 * ║                                                                          ║
 * ║      machines vivantes : 3, dont  id 1  srv-zabbix  active               ║
 * ║                                                                          ║
 * ║  `srv-zabbix` n'est PAS archivee. Un groupe sans filtre la contiendrait, ║
 * ║  et l'action groupee `cve_scan` sur ce groupe ouvrirait une session SSH  ║
 * ║  **et enverrait un courriel reel** vers elle :                           ║
 * ║                                                                          ║
 * ║      backend/routes/groups.py:278   for _line in _stream_cve_scan([mid]) ║
 * ║      backend/routes/cve.py:77       send_cve_report(...)                 ║
 * ║      srv-docker.env:206             MAIL_ENABLED=true    EN SERVICE      ║
 * ║                                                                          ║
 * ║  **Le danger est l'OBJET, pas le geste.** Un `finally` protege la        ║
 * ║  session qui pose la fixture ; il ne protege pas le banc partage pendant ║
 * ║  la fenetre ou l'objet existe, et il ne s'execute pas si le processus    ║
 * ║  est tue. Le seul moment ou ce groupe peut exister est celui ou          ║
 * ║  l'exploitant le decide.                                                 ║
 * ║                                                                          ║
 * ║  ── ET LE SUBSTITUT NE SUBSTITUE RIEN ──                                 ║
 * ║                                                                          ║
 * ║  Un groupe AVEC filtre ne visant que `Test-Server-Debian` exercerait le  ║
 * ║  chemin de resolution sans toucher `srv-zabbix`. Mais **E-274 porte      ║
 * ║  precisement sur l'ABSENCE de filtre** : le contournement sur mesure une ║
 * ║  AUTRE propriete, et la rendrait verte sous le nom de celle-ci.          ║
 * ║                                                                          ║
 * ║  *Une propriete non couverte et DECLAREE est un fait ; une propriete non ║
 * ║  couverte et VERTE est un mensonge.*                                     ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * ══ CE QUE LA SUITE MESURE ════════════════════════════════════════════════
 *
 * **La garde, et son chemin discriminant.** `role:2` + `perm:can_admin_portal`,
 * et l'etat du banc separe les deux :
 *
 *     rw-test-user   role 1  can_admin_portal = 0  ->  REFUSE
 *     rw-test-admin  role 2  can_admin_portal = 0  ->  REFUSE — il satisfait le ROLE
 *                                                       et pas la PERMISSION
 *     rw-test-super  role 3  can_admin_portal = 1  ->  ADMIS
 *
 * `rw-test-admin` est le seul chemin qui distingue les deux moities de la
 * garde. Sans lui, retirer `perm:can_admin_portal` de la route ne changerait
 * aucun verdict.
 *
 * **L'etat de la liste se resout.** La vue rend d'abord `groupes-chargement` —
 * et son commentaire dit pourquoi : *une grille vide se lit « aucun groupe »
 * alors qu'on ne sait pas encore.* La suite exige donc que l'etat de chargement
 * CEDE la place, sans quoi une page dont le JS ne repond pas afficherait
 * indefiniment « chargement » et passerait pour saine.
 *
 * **Aucun appel compose en ecriture, avec son TEMOIN.** Comme sur `/audit-ssh` :
 * « aucun POST n'est parti » est vraie a vide. On emet un POST forge vers un
 * chemin inexistant ; s'il n'apparait pas dans le collecteur, la suite rend
 * SANS OBJET au lieu d'un vert.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * **Aucune action groupee n'est exercee, sous aucune forme**, et le filet
 * avorte `/groups/*` en ecriture sans condition — voir le cadre ci-dessus.
 * Les panneaux explicatifs sont OUVERTS (le clic est local) mais rien n'est
 * confirme : c'est la regle S7a, *un portail qui declenche AU CLIC ne se teste
 * pas en cliquant*, appliquee a l'envers — ici le clic est sur, c'est la
 * confirmation qui ne l'est pas.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync, readFileSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const MACHINE_PRODUCTION = 1;

/* Secrets RELEVES dans les suites du depot, jamais inventes. */
const COMPTES = {
    user:  { nom: 'rw-test-user',  role: 1, perm: 0, admis: false,
        secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW',
        motif: 'ni le role 2, ni `can_admin_portal`' },
    admin: { nom: 'rw-test-admin', role: 2, perm: 0, admis: false,
        secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX',
        motif: 'satisfait le ROLE et PAS la permission — le chemin discriminant' },
    super: { nom: 'rw-test-super', role: 3, perm: 1, admis: true,
        secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW',
        motif: 'role 3 ET `can_admin_portal`' },
};

/*
 * Toute ECRITURE du module, et l'action groupee — voir le cadre en tete.
 *
 * ⚠ L'ENUMERATION ETAIT FAUSSE (2026-09-02) : `action`, `scan` et `delete` sont
 *   trois FANTOMES — aucun n'existe comme segment de route. Et surtout
 *   `/groups/<id>/run`, l'EXECUTION GROUPEE, donc le geste le plus dangereux du
 *   module, ECHAPPAIT au motif.
 *   Routes reelles : GET /groups · POST /groups · PUT|DELETE /groups/<id> ·
 *   GET /groups/<id>/members · POST /groups/<id>/run.
 *
 * Le filet porte desormais sur le MODULE ; la methode discrimine (voir plus bas).
 * Remesurer : grep -nE "@bp.route" backend/routes/groups.py
 */
const INTERDITS = /\/groups(\/|\?|$)/;
const TEMOIN = '/temoin-e2e-inexistant';
/*
 * Le nom saisi dans le formulaire pour obtenir l'ANNONCE. Il n'est jamais
 * confirme, donc jamais ecrit — mais il est choisi distinctif expres : si un
 * groupe portant ce nom apparaissait un jour en base, on saurait d'ou il vient
 * et quelle suite l'a laisse passer. Un temoin anonyme ne se remonte pas.
 */
const TEMOIN_NOM = 'e2e-annonce-non-confirmee';

/*
 * ══ FIXTURE R3 — DEUX GROUPES INERTES, POSES EN BASE ══════════════════════
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  SI CETTE SUITE MEURT SANS NETTOYER, RETIRER A LA MAIN :                 ║
 * ║                                                                          ║
 * ║    DELETE FROM rootwarden.machine_group_members WHERE group_id IN       ║
 * ║      (SELECT id FROM rootwarden.machine_groups                          ║
 * ║       WHERE name LIKE 'e2e-derive-%');                                  ║
 * ║    DELETE FROM rootwarden.machine_groups WHERE name LIKE 'e2e-derive-%';║
 * ║                                                                          ║
 * ║  ⚠ CE CADRE A PORTE UNE COMMANDE QUI NE MARCHAIT PAS. La forme           ║
 * ║    `DELETE m FROM … JOIN …` leve `ERROR 1046: No database selected`      ║
 * ║    meme avec des tables PLEINEMENT QUALIFIEES — un DELETE multi-tables   ║
 * ║    exige une base par defaut, et `mysql -e` n'en a pas. **Une commande   ║
 * ║    de secours fausse est pire qu'absente** : on la lance, elle echoue    ║
 * ║    en silence si l'on ne lit pas stderr, et l'on croit avoir nettoye.    ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * POURQUOI EN BASE ET NON PAR L'INTERFACE : le filet de cette suite avorte
 * tout non-GET vers `/groups`. Creer la fixture par le formulaire ferait donc
 * avorter sa propre creation — et l'assouplir pour l'occasion reviendrait a
 * desarmer le garde qu'on est venu verifier.
 *
 * POURQUOI STATIQUES, ET POURQUOI CES DEUX-LA :
 *
 *   `_member_ids` resout un groupe STATIQUE par `machine_group_members`, une
 *   liste explicite. Un groupe DYNAMIQUE passe par `_sanitize_filters`, et un
 *   filtre entierement rejete se stocke en `{}` — le meme objet qu'un groupe
 *   sans critere, donc `1=1`, donc LE PARC ENTIER. **Poser une telle fixture
 *   ferait exister, meme brievement, un groupe dont un scan viserait
 *   `srv-zabbix`.** On ne la pose pas.
 *
 *   UN  : un seul membre, la machine 2 (Test-Server-Debian, DEV). Le panneau
 *         doit annoncer 1, ne nommer AUCUNE production, et OFFRIR la
 *         confirmation — qu'on ne prend jamais.
 *   VIDE: aucun membre. C'est la branche FAIL-CLOSED : le panneau doit dire
 *         pourquoi et **ne pas offrir** le lancement. Un groupe vide ne peut
 *         rien scanner : c'est la fixture la plus sure du chantier, et elle
 *         couvre la propriete qui se perdrait la premiere si quelqu'un
 *         « simplifiait » le panneau.
 */
const FIXTURE_UN = 'e2e-derive-un';
const FIXTURE_VIDE = 'e2e-derive-vide';
const MACHINE_SURE = 2;

/**
 * Un libelle LU dans le catalogue, jamais recopie ici : une chaine recopiee
 * fige la valeur du jour et l'assertion devient verte sur un ecran qui ne dit
 * plus rien. Rend `null` si la cle est absente — une assertion qui recoit
 * `null` s'abstient au lieu de conclure.
 *
 * ⚠ LES DEUX FORMES DE GUILLEMETS : `lang/fr/groups.php` melange `'...'` et
 *   `"..."`. Une version qui ne lit que la premiere rendrait `null` sur la
 *   moitie des cles, et chaque assertion se declarerait SANS OBJET — un vert
 *   par abstention, sur la seule chose que l'etape mesure.
 */
function libelle(cle) {
    try {
        const chemin = new URL('../../laravel/lang/fr/groups.php', import.meta.url).pathname;
        const texte = readFileSync(chemin, 'utf8');
        const simple = texte.match(new RegExp(`'${cle}'\\s*=>\\s*'((?:[^'\\\\]|\\\\.)*)'`));
        if (simple) return simple[1].replace(/\\'/g, "'").replace(/\\\\/g, '\\');
        const double = texte.match(new RegExp(`'${cle}'\\s*=>\\s*"((?:[^"\\\\]|\\\\.)*)"`));

        return double ? double[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\') : null;
    } catch { return null; }
}
const VERS_BACKEND = /\/(api\/gateway|api_proxy\.php)\//;

const C = CIBLE === 'laravel'
    ? { connexion: '/connexion', page: '/groupes',
        liste: '[data-rw="groupes-liste"]',
        chargement: '[data-rw="groupes-chargement"]',
        nouveau: '[data-rw="groupes-nouveau"]',
        formulaire: '[data-rw="groupes-formulaire"]',
        champNom: '[data-rw="groupes-nom"]',
        enregistrer: '[data-rw="groupes-enregistrer"]',
        annuler: '[data-rw="groupes-annuler"]',
        formMessage: '[data-rw="groupes-form-message"]',
        panneau: '[data-rw="groupes-panneau"]',
        panneauEffets: '[data-rw="groupes-panneau-effets"]',
        panneauFermer: '[data-rw="groupes-panneau-fermer"]',
        panneauConfirmer: '[data-rw="groupes-panneau-confirmer"]',
        portee: '[data-rw="groupes-portee"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]' }
    : { connexion: '/auth/login.php?lang=fr', page: '/groups/',
        liste: null, chargement: null, nouveau: null, formulaire: null,
        champNom: null, enregistrer: null, annuler: null, formMessage: null,
        panneau: null, panneauEffets: null, panneauFermer: null,
        panneauConfirmer: null, portee: null,
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]' };

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
/*
 * L'ETAT INITIAL DE LA TABLE, HISSE HORS DU `try`.
 *
 * Il est releve dans le `try` et relu dans le `finally` : deux BLOCS, donc un
 * `const` local n'y survit pas (`nGroupes is not defined`, mesure du 2026-09-02
 * 19:56). `node --check` avait dit OK — **un controle de syntaxe ne verifie
 * aucune portee**, et c'est la seule facon dont ce defaut pouvait passer.
 *
 * `null` signifie « jamais releve » et NON « zero » : l'assertion de fin doit
 * alors se declarer SANS OBJET plutot que de comparer a une valeur absente.
 */
let groupesAvant = null;
/*
 * Le nom a-t-il REELLEMENT ete saisi ? Sur legacy, le garde de cible sort avant
 * la saisie : « le nom n'est pas en base » y serait vrai A VIDE, et un PASS
 * decerne a une verification qui n'a pas eu lieu vaut moins que rien — il
 * ANNONCE une couverture. Le drapeau distingue les deux cas.
 */
let nomSaisi = false;
/* La fixture R3 a-t-elle ete POSEE ? `false` = rien a retirer, et le nettoyage
 * doit alors se declarer SANS OBJET plutot que d'annoncer une restauration. */
let fixturePosee = false;
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

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        vues += 1;
        const url = r.url();
        const chemin = url.replace(/^https?:\/\/[^/]+/, '');
        let corps = '';
        try { corps = r.postData() || ''; } catch { /* pas de corps */ }

        // Le TEMOIN passe : chemin inexistant, sans effet, et c'est lui qui
        // prouve que le collecteur voit les POST.
        if (chemin.startsWith(TEMOIN)) {
            passees.push({ route: chemin, methode: r.method(), corps });
            r.continue().catch(() => {});

            return;
        }
        // FAIL-CLOSED : toute ECRITURE du module est avortee sans condition.
        if (r.method() !== 'GET' && INTERDITS.test(url)) {
            avortees.push({ route: chemin, motif: 'ECRITURE du module groupes', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(url)
            || /srv-zabbix/.test(corps)) {
            avortees.push({ route: chemin, motif: 'vise la PRODUCTION', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (VERS_BACKEND.test(url) || /\/groups/.test(url)) {
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

try {
    /*
     * L'ETAT DE LA BASE, RELEVE ET DECLARE. C'est lui qui rend E-274 non
     * mesurable, et il doit figurer dans le journal : le jour ou un groupe
     * existera, la relecture de ce journal dira que la couverture peut changer.
     */
    const nGroupes = compteEnBase('SELECT COUNT(*) FROM rootwarden.machine_groups');
    groupesAvant = nGroupes;
    const nVivantes = compteEnBase(
        "SELECT COUNT(*) FROM rootwarden.machines "
        + "WHERE lifecycle_status IS NULL OR lifecycle_status <> 'archived'");
    constate('groupes en base', String(nGroupes));
    constate('machines vivantes', `${nVivantes} — dont srv-zabbix (id 1), NON archivee`);
    constate('E-274 (groupe sans filtre -> le parc)',
        nGroupes === 0
            ? 'NON COUVERT — aucun groupe n\'existe, une assertion serait verte a vide.'
              + ' La fixture est REFUSEE : voir le cadre en tete de fichier.'
            : `${nGroupes} groupe(s) existent : la couverture d'E-274 peut etre reexaminee`);

    /*
     * LA PRECONDITION DE LA GARDE. Le chemin discriminant est
     * `rw-test-admin` : role 2 SANS `can_admin_portal`. S'il recevait la
     * permission, les trois comptes seraient admis ou refuses pour la meme
     * raison, et retirer `perm:` de la route ne changerait aucun verdict.
     */
    const perms = {};
    for (const c of Object.values(COMPTES)) {
        perms[c.nom] = compteEnBase(
            'SELECT COALESCE(MAX(p.can_admin_portal), 0) FROM rootwarden.users u '
            + `LEFT JOIN rootwarden.permissions p ON p.user_id = u.id WHERE u.name = '${c.nom}'`);
    }
    constate('can_admin_portal en base', Object.entries(perms).map(([n, v]) => `${n}=${v}`).join(' · '));
    const triplet = Object.values(COMPTES).every((c) => perms[c.nom] === c.perm);
    verifie('le chemin discriminant existe (role 2 SANS la permission)',
        triplet,
        'un `can_admin_portal` a change : le role 2 ne separe plus les deux moities'
        + ' de la garde, et retirer `perm:` ne changerait aucun verdict',
        Object.values(COMPTES).map((c) => `${c.nom}:${c.perm}`).join(' '));
    if (! triplet) throw new Error('precondition non tenue');

    // ══ 1. LA GARDE, AUX TROIS COMPTES ═══════════════════════════════════
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

    /*
     * ══ POSE DE LA FIXTURE R3, AVANT LE PREMIER CHARGEMENT ════════════════
     *
     * Deux groupes STATIQUES et inertes — voir le cadre en tete. Ils sont poses
     * ICI et non plus tot pour que la page les rende des son premier
     * chargement : creer puis recharger mesurerait le rechargement autant que
     * la page.
     *
     * `CIBLE === 'laravel'` seulement : R3 n'existe pas sur le legacy, et poser
     * une fixture qu'aucune assertion ne lira serait une ecriture gratuite.
     */
    if (CIBLE === 'laravel') {
        try {
            /*
             * ⚠ FIXTURE EN ASCII PUR. Un tiret cadratin ecrit par `mysql -e`
             *   est ressorti `â€"` a l'ecran (mesure du 2026-09-02 23:47) : la
             *   chaine part en UTF-8 et la connexion ne l'est pas. Ce n'est PAS
             *   un defaut de la page — les donnees ecrites par l'application y
             *   passent par un autre chemin — mais une fixture qui affiche du
             *   charabia fait suspecter la page qu'elle sert a mesurer.
             */
            litEnBase('DELETE FROM rootwarden.machine_group_members WHERE group_id IN '
                + "(SELECT id FROM rootwarden.machine_groups WHERE name LIKE 'e2e-derive-%')");
            litEnBase("DELETE FROM rootwarden.machine_groups WHERE name LIKE 'e2e-derive-%'");
            litEnBase("INSERT INTO rootwarden.machine_groups (name, description, group_type, filters) "
                + `VALUES ('${FIXTURE_UN}', 'fixture e2e R3 - un seul membre', 'static', '{}')`);
            litEnBase("INSERT INTO rootwarden.machine_groups (name, description, group_type, filters) "
                + `VALUES ('${FIXTURE_VIDE}', 'fixture e2e R3 - aucun membre', 'static', '{}')`);
            litEnBase('INSERT INTO rootwarden.machine_group_members (group_id, machine_id) '
                + `SELECT id, ${MACHINE_SURE} FROM rootwarden.machine_groups WHERE name = '${FIXTURE_UN}'`);
            const poses = compteEnBase(
                "SELECT COUNT(*) FROM rootwarden.machine_groups WHERE name LIKE 'e2e-derive-%'");
            const membres = compteEnBase(
                'SELECT COUNT(*) FROM rootwarden.machine_group_members m '
                + `JOIN rootwarden.machine_groups g ON g.id = m.group_id WHERE g.name = '${FIXTURE_UN}'`);
            fixturePosee = poses > 0;
            /*
             * ON VERIFIE LA POSE PLUTOT QUE DE LA CROIRE. Une fixture absente
             * rendrait les assertions R3 vertes a vide — « aucune carte, donc
             * aucun lancement » est vrai et ne mesure rien.
             */
            verifie('la fixture R3 est posee : 2 groupes, 1 membre',
                poses === 2 && membres === 1,
                `${poses} groupe(s) et ${membres} membre(s) : les assertions R3 seraient vertes a vide`,
                `${poses} groupe(s), ${membres} membre(s)`);
            /*
             * ET LA MACHINE VISEE N'EST PAS LA PRODUCTION. Le `2` est ecrit
             * dans une constante, mais un identifiant n'est pas une identite :
             * on relit le NOM avant de s'en servir.
             */
            const cible = litEnBase(
                `SELECT CONCAT(name,'|',COALESCE(environment,'?')) FROM rootwarden.machines WHERE id = ${MACHINE_SURE}`);
            verifie('la machine de la fixture n\'est PAS la production',
                cible.length === 1 && ! /^srv-zabbix\|/.test(cible[0]),
                `machine ${MACHINE_SURE} = ${cible[0] || '(absente)'}`,
                cible[0] || '(absente)');
        } catch (e) {
            verifie('la fixture R3 est posee', false, String(e.message || e).split('\n')[0]);
        }
    }

    await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
    await dors(1200);

    await etape('l\'etat de chargement CEDE la place', async () => {
        if (CIBLE !== 'laravel') {
            constate('etat de la liste',
                'SANS OBJET — les ancres du legacy ne sont pas relevees');

            return;
        }
        const vu = await page.evaluate((sel) => {
            const l = document.querySelector(sel.liste);
            const c = document.querySelector(sel.chargement);

            return {
                liste: l !== null,
                chargementEncore: c !== null && c.offsetParent !== null,
                texte: l ? (l.innerText || '').trim() : '',
                nouveau: document.querySelector(sel.nouveau) !== null,
                portee: document.querySelector(sel.portee) !== null,
            };
        }, C);
        constate('liste', vu.liste
            ? `« ${vu.texte.slice(0, 80).replace(/\s+/g, ' ')} »` : '(absente)');

        /*
         * LA VUE REND D'ABORD UN ETAT DE CHARGEMENT, et son commentaire dit
         * pourquoi : *une grille vide se lit « aucun groupe » alors qu'on ne
         * sait pas encore.* Si le JS ne repond pas, la page afficherait
         * indefiniment « chargement » — et une assertion « la liste est
         * rendue » y passerait. On exige donc que l'etat de chargement CEDE.
         */
        verifiePortage('l\'etat de chargement a cede la place',
            vu.liste && ! vu.chargementEncore,
            ! vu.liste ? 'la liste n\'est pas rendue'
                : 'l\'etat de chargement est encore affiche : le JS n\'a pas repondu,'
                  + ' et une page bloquee sur « chargement » passerait pour saine');

        verifiePortage('le geste de creation est OFFERT (et non exerce)',
            vu.nouveau,
            'aucun bouton de creation : « aucune ecriture » serait vrai a vide');
    });

    // ══ 3. LE PANNEAU S'OUVRE, ET RIEN NE PART ═══════════════════════════
    await etape('le clic revele le formulaire, et l\'annonce precede l\'ecriture', async () => {
        /*
         * ══ CETTE ETAPE A DEFENDU UNE PROPRIETE QUE LE PORTAGE A DEPASSEE ═══
         *
         * Ecrite le 2026-09-02 a 08:29, elle affirmait que `groupes-nouveau`
         * ouvrait un panneau explicatif — celui du « pas encore porte ». R2
         * (`5a0ff0b`, le MEME JOUR a 18:42:58, dix heures plus tard) a livre la
         * creation : le bouton revele desormais `groupes-formulaire`.
         *
         * Rendu avant correction : 3 FAIL. **Elle est tombee ROUGE, pas
         * silencieusement verte** — et ce n'etait pas acquis : `groupes-panneau`
         * EXISTE toujours. Si le panneau s'etait trouve visible pour une autre
         * raison, l'assertion aurait passe en mesurant autre chose que le geste.
         *
         * ⚠ ET LE PANNEAU N'A PAS ETE « REAFFECTE » : il a ete DEPLACE. Il
         * s'ouvre maintenant sur `groupes-enregistrer` (`groupes.js:250`,
         * `ouvrePanneau(..., porteeAnnoncee())`) au lieu de remplacer le geste.
         * La propriete d'aujourd'hui est donc PLUS FORTE que celle d'hier :
         * **le portage annonce ce qu'il va ecrire AVANT de l'ecrire, et
         * l'annonce ne coute aucune requete.**
         *
         * SURETE — lu dans le code, pas suppose (`groupes.js:242`) :
         * `demandeEnregistrement` valide le nom, ouvre le panneau, montre le
         * bouton de confirmation, et N'EMET RIEN. Seul `enregistre()`, sur la
         * CONFIRMATION, appelle `ecris('/groups', ...)`. Cette suite va donc
         * jusqu'au panneau et **ne confirme JAMAIS**. Trois filets derriere :
         * le motif INTERDITS avorte tout non-GET vers `/groups`, l'assertion de
         * fermeture par l'absence, et le comptage final des groupes.
         */
        /*
         * ⚠ LE GARDE DE CIBLE, QUE J'AVAIS SUPPRIME EN REECRIVANT (2026-09-02
         * 20:01). Sur legacy, `C.nouveau` vaut `null` et `page.$(null)` leve
         * « Cannot read properties of null (reading 'startsWith') » — 1 FAIL.
         *
         * **QUATRIEME occurrence de ce defaut sur ce banc** (apres accueil,
         * audit-ssh, cle-plateforme) — et la premiere ou je l'ai RETIRE au lieu
         * de l'oublier : le garde etait present, la reecriture l'a emporte.
         * Une reecriture ne repart pas d'une page blanche : elle DOIT rendre
         * compte de ce que l'ancien code protegeait.
         */
        if (CIBLE !== 'laravel') {
            constate('formulaire de creation',
                'SANS OBJET — les ancres du legacy ne sont pas relevees, et la creation'
                + ' legacy n\'est pas le sujet de cette suite');

            return;
        }
        const avant = passees.length;
        const bouton = await page.$(C.nouveau);
        if (! bouton) {
            verifie('le clic revele le formulaire de creation', false,
                'le bouton de creation est absent : rien a cliquer');

            return;
        }

        // ── a. le clic revele le formulaire, et ne coute rien ────────────
        const cache = await page.$eval(C.formulaire, (n) => n.hidden).catch(() => null);
        await bouton.click();
        await dors(500);
        const vu = await page.evaluate((sel) => {
            const form = document.querySelector(sel.formulaire);
            const nom = document.querySelector(sel.champNom);

            return {
                visible: form !== null && form.offsetParent !== null,
                champ: nom !== null,
                focus: nom !== null && document.activeElement === nom,
            };
        }, C);
        constate('formulaire avant le clic', cache === null ? 'ancre absente' : (cache ? 'masque' : 'DEJA visible'));
        verifiePortage('le clic revele le formulaire de creation',
            cache === true && vu.visible,
            cache !== true ? 'le formulaire n\'etait pas masque avant le clic : le clic ne prouve rien'
                : 'le formulaire ne devient pas visible');
        verifiePortage('le formulaire porte un champ de nom, et le curseur y va',
            vu.champ && vu.focus,
            ! vu.champ ? 'aucun champ de nom' : 'le champ existe mais ne recoit pas le curseur');

        // ── b. sans nom, le formulaire REFUSE et n'ouvre rien ────────────
        const enr = await page.$(C.enregistrer);
        if (enr) {
            await enr.click();
            await dors(400);
            const refus = await page.evaluate((sel) => {
                const m = document.querySelector(sel.formMessage);
                const p = document.querySelector(sel.panneau);

                return {
                    message: m ? (m.innerText || m.textContent || '').trim() : '',
                    panneau: p !== null && p.offsetParent !== null,
                };
            }, C);
            constate('sans nom', `message « ${refus.message || '(aucun)'} », panneau ${refus.panneau ? 'OUVERT' : 'ferme'}`);
            verifiePortage('un nom vide est REFUSE, et rien n\'est annonce',
                refus.message.length > 0 && ! /:[a-z_]{3,}/.test(refus.message) && ! refus.panneau,
                ! refus.message ? 'aucun message de refus'
                    : refus.panneau ? 'le panneau s\'ouvre malgre le refus'
                        : `message non traduit : ${refus.message}`);
        } else {
            constate('refus sur nom vide', 'SANS OBJET — pas de bouton d\'enregistrement');
        }

        // ── c. avec un nom, l'ANNONCE — et on ne confirme pas ────────────
        let ann = { ouvert: false, effets: [], confirmer: false };
        if (enr && vu.champ) {
            await page.type(C.champNom, TEMOIN_NOM, { delay: 20 });
            nomSaisi = true;
            await enr.click();
            await dors(600);
            ann = await page.evaluate((sel) => {
                const p = document.querySelector(sel.panneau);
                const e = document.querySelector(sel.panneauEffets);
                const c = document.querySelector(sel.panneauConfirmer);

                return {
                    ouvert: p !== null && p.offsetParent !== null,
                    effets: e ? [...e.querySelectorAll('li, p')].map((x) => (x.innerText || '').trim())
                        .filter(Boolean) : [],
                    confirmer: c !== null && c.offsetParent !== null,
                };
            }, C);
            constate('annonce', ann.ouvert
                ? `panneau ouvert, ${ann.effets.length} effet(s), confirmation ${ann.confirmer ? 'offerte' : 'absente'}`
                : 'panneau NON ouvert');
            verifiePortage('enregistrer ANNONCE la portee avant d\'ecrire',
                ann.ouvert && ann.effets.length >= 1
                    && ann.effets.every((x) => x.length > 0 && ! /:[a-z_]{3,}/.test(x)),
                ! ann.ouvert ? 'le panneau d\'annonce ne s\'ouvre pas'
                    : `${ann.effets.length} effet(s) — attendu au moins 1, non vide et sans jeton`);
            /*
             * La confirmation doit etre OFFERTE et non exercee : c'est la
             * reprise de main qui separe l'annonce de l'ecriture. Un panneau
             * qui annonce sans offrir de confirmer aurait deja ecrit.
             */
            verifiePortage('la confirmation est OFFERTE, et cette suite ne la prend pas',
                ann.ouvert && ann.confirmer,
                ! ann.ouvert ? 'pas de panneau' : 'aucun bouton de confirmation : le geste serait deja parti');
        }

        // ── d. AU RESEAU : tout ce qui precede est LOCAL ─────────────────
        const parties = passees.slice(avant);
        constate('requetes emises par la sequence', parties.length
            ? parties.map((p) => `${p.methode} ${p.route}`).join(' | ') : '(aucune)');
        verifie('reveler, refuser et ANNONCER n\'a coute AUCUNE requete',
            parties.length === 0,
            parties.map((p) => `${p.methode} ${p.route}`).join(' | '),
            `${parties.length} requete(s)`);

        // ── e. on referme, sans jamais confirmer ─────────────────────────
        const fermer = await page.$(C.panneauFermer);
        if (fermer) { await fermer.click(); await dors(400); }
        const annuler = await page.$(C.annuler);
        if (annuler) { await annuler.click(); await dors(400); }
    });

    // ══ 4. LE TEMOIN, PUIS LA FERMETURE PAR L'ABSENCE ════════════════════
    let temoinVu = false;
    await etape('R3 : le scan de masse annonce le RESOLU, et cette suite ne lance pas', async () => {
        if (CIBLE !== 'laravel') {
            constate('scan de derive de masse', 'SANS OBJET — R3 n\'existe que sur le portage');

            return;
        }
        const nLibelle = libelle('resolu_nombre');
        const vLibelle = libelle('der_vide');
        if (nLibelle === null || vLibelle === null) {
            constate('scan de derive de masse',
                'SANS OBJET — un libelle du catalogue est illisible ; comparer a une chaine'
                + ' recopiee ici mesurerait ma prose et non l\'ecran');

            return;
        }
        /*
         * LE NOMBRE, EXTRAIT PAR LE FORMAT DU CATALOGUE. `:n` y est le
         * marqueur ; on le remplace par une capture plutot que d'ecrire une
         * expression a la main, pour que l'assertion suive le libelle si sa
         * formulation change.
         */
        const motifNombre = new RegExp(nLibelle
            .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
            .replace(':n', '(\\d+)'));

        const avantR3 = passees.length;
        const cartes = await page.evaluate(() => [...document.querySelectorAll('[data-rw="groupes-carte"]')]
            .map((c) => {
                const t = c.querySelector('h2');

                return (t ? t.innerText : '').trim();
            }));
        constate('cartes rendues', cartes.join(' · ') || '(aucune)');

        for (const cas of [
            { nom: FIXTURE_UN, attendu: 1, confirme: true,
                dit: 'annonce le nombre RESOLU et offre la confirmation' },
            { nom: FIXTURE_VIDE, attendu: 0, confirme: false,
                dit: 'FAIL-CLOSED : dit pourquoi et n\'offre PAS le lancement' },
        ]) {
            if (! cartes.includes(cas.nom)) {
                verifie(`la carte « ${cas.nom} » est rendue`, false,
                    `fixture absente de l'ecran : ${cartes.join(' · ') || '(aucune carte)'}`);
                continue;
            }
            const n = passees.length;
            const ouvert = await page.evaluate((nom) => {
                const carte = [...document.querySelectorAll('[data-rw="groupes-carte"]')]
                    .find((c) => { const t = c.querySelector('h2'); return t && t.innerText.trim() === nom; });
                if (! carte) return false;
                const b = carte.querySelector('[data-rw="groupes-derive"]');
                if (! b) return false;
                b.scrollIntoView({ block: 'center' });

                return true;
            }, cas.nom);
            if (! ouvert) {
                verifie(`« ${cas.nom} » offre le geste de scan de derive`, false,
                    'aucun bouton `groupes-derive` sur la carte');
                continue;
            }
            /*
             * CLIC SIMULE, pas un appel de fonction : c'est le geste de
             * l'exploitant qu'on mesure, pas la fonction qu'il declenche.
             */
            const cible = await page.$(`[data-rw="groupes-carte"] [data-rw="groupes-derive"]`);
            const boutons = await page.$$('[data-rw="groupes-derive"]');
            const idx = cartes.indexOf(cas.nom);
            const bouton = boutons[idx] || cible;
            await bouton.click();
            await dors(1200);

            const vu = await page.evaluate((sel) => {
                const p = document.querySelector(sel.panneau);
                const e = document.querySelector(sel.panneauEffets);
                const c = document.querySelector(sel.panneauConfirmer);

                return {
                    ouvert: p !== null && p.offsetParent !== null,
                    texte: e ? (e.innerText || '').replace(/\s+/g, ' ').trim() : '',
                    confirme: c !== null && c.offsetParent !== null,
                };
            }, C);
            const emises = passees.slice(n);
            const litMembres = emises.some((p) => p.methode === 'GET' && /\/groups\/\d+\/members/.test(p.route));
            constate(`« ${cas.nom} »`, `panneau ${vu.ouvert ? 'ouvert' : 'FERME'}, confirmation `
                + `${vu.confirme ? 'offerte' : 'absente'}, ${emises.length} requete(s)`);

            /*
             * ⚠ LA PROPRIETE DE FOND : LE NOMBRE VIENT DU SERVEUR.
             *
             * Un groupe dont tous les filtres ont ete rejetes se stocke en `{}`,
             * soit `1=1`, soit LE PARC ENTIER. Un resume de filtres afficherait
             * « aucun critere » et laisserait croire a une selection. Seule la
             * RESOLUTION distingue « mes trois serveurs de test » de « tout ».
             * On mesure donc que l'appel de resolution PART — si quelqu'un
             * remplaçait l'annonce par un compte calcule dans la page, ce GET
             * disparaitrait et cette assertion rougirait.
             */
            verifie(`« ${cas.nom} » : le nombre est RESOLU par le serveur`,
                litMembres,
                'aucun GET /groups/<id>/members : l\'annonce ne vient pas d\'une resolution',
                emises.map((p) => `${p.methode} ${p.route}`).join(' | ') || 'aucune requete');

            if (cas.attendu > 0) {
                const m = vu.texte.match(motifNombre);
                verifie(`« ${cas.nom} » : l'annonce porte ${cas.attendu}`,
                    m !== null && Number(m[1]) === cas.attendu,
                    m === null ? `aucun nombre annonce dans « ${vu.texte.slice(0, 80)} »`
                        : `annonce ${m[1]}, la base en resout ${cas.attendu}`,
                    m ? `${m[1]} serveur(s)` : '');
                /*
                 * ET AUCUNE PRODUCTION NOMMEE : la fixture ne porte que la
                 * machine 2. Si `srv-zabbix` y apparaissait, ce ne serait pas
                 * un defaut d'affichage — ce serait que le groupe resout autre
                 * chose que ce qu'on y a mis.
                 */
                verifie(`« ${cas.nom} » : aucune machine de production n'est nommee`,
                    ! /srv-zabbix/i.test(vu.texte),
                    `la production est nommee dans l'annonce : « ${vu.texte.slice(0, 120)} »`);
            } else {
                verifie(`« ${cas.nom} » : la raison du refus est DITE`,
                    vu.texte.includes(vLibelle),
                    `le panneau ne dit pas pourquoi : « ${vu.texte.slice(0, 100)} »`);
            }
            verifie(`« ${cas.nom} » : la confirmation est ${cas.confirme ? 'OFFERTE' : 'REFUSEE'}`,
                vu.confirme === cas.confirme,
                cas.confirme ? 'aucun bouton de lancement : le geste serait deja parti ou impossible'
                    : 'le lancement est OFFERT sur une portee que le panneau ne sait pas dire');

            // On referme SANS JAMAIS confirmer.
            const fermer = await page.$(C.panneauFermer);
            if (fermer) { await fermer.click(); await dors(400); }
        }

        /*
         * AU RESEAU, ET C'EST LE CONTROLE QUI COMPTE : annoncer ne lance pas.
         * `POST /groups/<id>/run` est le geste de MASSE — il porte `drift_scan`
         * ici, mais la meme route porte `cve_scan`, qui ouvre une session SSH
         * PAR MACHINE et envoie un courriel par machine a resultats.
         */
        const lancements = passees.slice(avantR3)
            .filter((p) => p.methode !== 'GET' && /\/groups\/\d+\/run/.test(p.route));
        verifie('AUCUN scan de masse n\'a ete lance', lancements.length === 0,
            lancements.map((p) => `${p.methode} ${p.route} ${p.corps || ''}`).join(' | '),
            'aucun lancement');
    });

    await etape('le collecteur voit un POST (temoin)', async () => {
        await page.evaluate(async (chemin) => {
            try { await fetch(chemin, { method: 'POST', body: 'temoin' }); } catch { /* 404 attendu */ }
        }, TEMOIN);
        await dors(500);
        temoinVu = passees.some((p) => p.methode === 'POST' && p.route.startsWith(TEMOIN));
        constate('temoin', temoinVu ? `POST ${TEMOIN} vu` : 'NON VU');
        verifie('le collecteur detecte un POST emis depuis la page',
            temoinVu,
            'le POST temoin n\'a pas ete vu : l\'absence d\'ecriture ne prouverait rien');
    });

    await etape('aucune ecriture du module n\'est partie', async () => {
        const ecritures = passees.filter((p) => p.methode !== 'GET' && /\/groups/.test(p.route));
        constate('requetes du module', passees.filter((p) => /\/groups/.test(p.route))
            .map((p) => `${p.methode} ${p.route}`).join(' | ') || '(aucune)');
        if (! temoinVu) {
            constate('fermeture par l\'absence',
                'SANS OBJET — le temoin n\'a pas ete vu, une absence ne prouverait rien');

            return;
        }
        verifie('AUCUNE ecriture du module groupes n\'est partie',
            ecritures.length === 0 && avortees.length === 0,
            [...ecritures.map((p) => `${p.methode} ${p.route} (PASSE)`),
             ...avortees.map((a) => `${a.route} (avorte)`)].join(' | '),
            `${passees.filter((p) => /\/groups/.test(p.route)).length} requete(s) du module, toutes en GET`);
    });

    await etape('aucune erreur JavaScript', async () => {
        verifie('aucune erreur JavaScript sur la page', s.erreursJs.length === 0,
            s.erreursJs.slice(0, 3).join(' | '), 'aucune');
    });

    await etape('captures', async () => {
        const dossier = new URL(`./screenshots/groupes/${CIBLE}`, import.meta.url).pathname;
        mkdirSync(dossier, { recursive: true });
        for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                         { n: 'mobile', w: 390, h: 844 }]) {
            await page.setViewport({ width: f.w, height: f.h });
            await dors(400);
            await page.screenshot({ path: `${dossier}/gr-${f.n}.png`, fullPage: true });
        }
        verifie('les trois captures sont ecrites', true, '', dossier);
    });
} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    try {
        constate('requetes AVORTEES', avortees.length
            ? avortees.map((a) => `${a.route} (${a.motif})`).join(' | ') : '(aucune)');
        if (vues === 0) {
            constate('controle de surete', 'SANS OBJET — aucune requete vue');
        } else {
            verifie('AUCUNE requete n\'a vise la production',
                ! passees.some((p) => new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(p.route)
                    || /srv-zabbix/.test(p.corps || '')),
                'une requete a vise `srv-zabbix`', `${vues} requete(s) vue(s)`);
        }
    } catch (e) { note(`FAIL  controle de surete : ${e.message}`); echecs += 1; }
    try {
        /*
         * AUCUN GROUPE N'A ETE CREE. C'est la contrepartie du refus de fixture,
         * et depuis R2 c'est le filet qui compte le plus : la suite SAISIT
         * desormais un nom et va jusqu'au panneau d'annonce. Elle ne confirme
         * pas — mais c'est ici qu'on le VERIFIE, pas dans le code du portage.
         *
         * ⚠ COMPARE A L'ETAT INITIAL, PAS A ZERO. `apres === 0` etait juste
         * tant que la creation n'existait pas ; R2 l'a livree, donc un groupe
         * legitime cree par ailleurs ferait rougir cette suite pour un geste
         * qui n'est pas le sien. La propriete a mesurer est « la suite n'a rien
         * ajoute », et elle se mesure par une DIFFERENCE.
         */
        /*
         * ══ RETRAIT DE LA FIXTURE R3, AVANT TOUT COMPTAGE ═════════════════
         *
         * Dans le `finally`, donc meme si la suite est morte en route. Et le
         * retrait est VERIFIE : une commande qui rend sans erreur n'a pas
         * forcement agi. Si la fixture survit, la suite le dit fort — un
         * groupe `e2e-derive-*` laisse en base est un objet cliquable qui
         * porte un scan de masse.
         */
        if (fixturePosee) {
            try {
                litEnBase('DELETE FROM rootwarden.machine_group_members WHERE group_id IN '
                    + "(SELECT id FROM rootwarden.machine_groups WHERE name LIKE 'e2e-derive-%')");
                litEnBase("DELETE FROM rootwarden.machine_groups WHERE name LIKE 'e2e-derive-%'");
            } catch (e) { note(`FAIL  retrait de la fixture : ${e.message}`); echecs += 1; }
            const reste = compteEnBase(
                "SELECT COUNT(*) FROM rootwarden.machine_groups WHERE name LIKE 'e2e-derive-%'");
            verifie('la fixture R3 est RETIREE', reste === 0,
                `${reste} groupe(s) « e2e-derive-* » subsistent — cliquables, et porteurs`
                + ' d\'un scan de masse. Retrait a la main : voir le cadre en tete du fichier',
                `${reste} restant(s)`);
            if (reste !== 0) {
                note('=== LOT-ABATTRE :: une fixture de scan de masse survit en base');
                note("=== REMEDE :: DELETE FROM rootwarden.machine_groups WHERE name LIKE 'e2e-derive-%'");
            }
        } else {
            constate('fixture R3', 'SANS OBJET — jamais posee, il n\'y a rien a retirer');
        }
        const apres = compteEnBase('SELECT COUNT(*) FROM rootwarden.machine_groups');
        if (groupesAvant === null) {
            constate('aucun groupe cree',
                `SANS OBJET — l'etat initial n'a jamais ete releve, ${apres} en base : une`
                + ' difference est incalculable et « 0 ajoute » serait une affirmation gratuite');
        } else {
            verifie('aucun groupe n\'a ete cree par cette suite', apres === groupesAvant,
                `${groupesAvant} groupe(s) avant, ${apres} apres : ${apres - groupesAvant} ajoute(s)`
                + ' — un groupe SANS FILTRE viserait srv-zabbix',
                `${apres} groupe(s), inchange`);
        }
        /*
         * ET LE TEMOIN NOMME : si `TEMOIN_NOM` apparaissait, on saurait que
         * l'annonce a ete confirmee. Le compte seul ne le dirait pas si un
         * groupe legitime etait cree et le temoin aussi.
         */
        const fuite = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.machine_groups WHERE name = '${TEMOIN_NOM}'`);
        if (! nomSaisi) {
            /*
             * Le nom n'a pas ete saisi : l'absence ne prouve rien de CETTE
             * execution. On rend quand meme le compte, parce qu'un residu
             * signalerait une AUTRE execution qui, elle, aurait confirme.
             */
            constate('le nom temoin en base', fuite === 0
                ? `SANS OBJET — le nom n'a pas ete saisi ici ; 0 residu d'une autre execution`
                : `⚠ ${fuite} residu(s) « ${TEMOIN_NOM} » — PAS de cette execution,`
                  + ' donc une autre a confirme l\'annonce');
        } else {
            verifie('le nom saisi par cette suite n\'est PAS en base', fuite === 0,
                `${fuite} groupe(s) nomme(s) « ${TEMOIN_NOM} » : l'annonce a ete confirmee`,
                `0 « ${TEMOIN_NOM} »`);
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
