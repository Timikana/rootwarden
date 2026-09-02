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
 * ║  **Mesure du 2026-09-02 : `machine_groups` porte ZERO ligne.** Il        ║
 * ║  n'existe aucun groupe. Une assertion ecrite ici serait verte sur l'etat ║
 * ║  vide **sans jamais toucher la propriete** — le vert par absence, sur la ║
 * ║  seule chose qui compte.                                                 ║
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
import { mkdirSync } from 'node:fs';

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

/* Toute ECRITURE du module, et l'action groupee — voir le cadre en tete. */
const INTERDITS = /\/groups(\/[0-9]+)?(\/(members|action|scan|delete))?(\?|$)/;
const TEMOIN = '/temoin-e2e-inexistant';
const VERS_BACKEND = /\/(api\/gateway|api_proxy\.php)\//;

const C = CIBLE === 'laravel'
    ? { connexion: '/connexion', page: '/groupes',
        liste: '[data-rw="groupes-liste"]',
        chargement: '[data-rw="groupes-chargement"]',
        nouveau: '[data-rw="groupes-nouveau"]',
        panneau: '[data-rw="groupes-panneau"]',
        panneauEffets: '[data-rw="groupes-panneau-effets"]',
        panneauFermer: '[data-rw="groupes-panneau-fermer"]',
        portee: '[data-rw="groupes-portee"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]' }
    : { connexion: '/auth/login.php?lang=fr', page: '/groups/',
        liste: null, chargement: null, nouveau: null, panneau: null,
        panneauEffets: null, panneauFermer: null, portee: null,
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
    await etape('le clic ouvre un panneau et ne declenche rien', async () => {
        /*
         * L'EN-TETE L'ANNONÇAIT ET LE CODE NE LE FAISAIT PAS.
         *
         * `panneau`, `panneauEffets` et `panneauFermer` etaient declares dans la
         * table et JAMAIS lus — trois cles mortes. C'est la quatrieme fois que
         * ce signal me montre l'ecart entre ce que l'en-tete promet et ce que le
         * code mesure : **une intention ecrite en commentaire n'est pas une
         * mesure**, et c'est exactement ce qui a laisse E-244 vivre quatre jours.
         *
         * La propriete : le clic OUVRE un panneau — geste local — et **aucune
         * requete ne part**. On mesure les deux, et le compte de requetes est
         * releve AVANT et APRES le clic : dire « aucune ecriture » sur le total
         * de la suite ne dirait pas que le CLIC n'a rien declenche.
         */
        if (CIBLE !== 'laravel') {
            constate('panneau explicatif', 'SANS OBJET — ancres du legacy non relevees');

            return;
        }
        const avant = passees.length;
        const bouton = await page.$(C.nouveau);
        if (! bouton) {
            verifie('le clic ouvre un panneau et ne declenche rien', false,
                'le bouton de creation est absent : rien a cliquer');

            return;
        }
        await bouton.click();
        await dors(700);

        const vu = await page.evaluate((sel) => {
            const p = document.querySelector(sel.panneau);
            const e = document.querySelector(sel.panneauEffets);
            const f = document.querySelector(sel.panneauFermer);

            return {
                ouvert: p !== null && p.offsetParent !== null,
                effets: e ? [...e.querySelectorAll('li, p')].map((x) => (x.innerText || '').trim())
                    .filter(Boolean) : [],
                fermer: f !== null,
            };
        }, C);
        constate('panneau', vu.ouvert
            ? `ouvert, ${vu.effets.length} effet(s) enumere(s)` : 'NON ouvert');

        verifiePortage('le clic ouvre le panneau explicatif',
            vu.ouvert && vu.fermer,
            ! vu.ouvert ? 'le panneau ne s\'ouvre pas' : 'aucun moyen de le fermer');

        /*
         * ON EXIGE QUE LES EFFETS SOIENT ENUMERES ET NON VIDES. Un panneau
         * ouvert mais vide satisferait « le panneau s'ouvre » — c'est le piege
         * d'une assertion qui mesure la presence au lieu du contenu.
         */
        verifiePortage('le panneau enumere ce que le geste engage',
            vu.ouvert && vu.effets.length >= 1
                && vu.effets.every((x) => x.length > 0 && ! /:[a-z_]{3,}/.test(x)),
            ! vu.ouvert ? 'le panneau ne s\'ouvre pas'
                : `${vu.effets.length} effet(s) — attendu au moins 1, non vide et sans jeton`);

        // AU RESEAU : le clic est LOCAL, donc rien ne doit partir.
        const parties = passees.slice(avant);
        constate('requetes emises par le clic', parties.length
            ? parties.map((p) => `${p.methode} ${p.route}`).join(' | ') : '(aucune)');
        verifie('le clic n\'a declenche AUCUNE requete',
            parties.length === 0,
            parties.map((p) => `${p.methode} ${p.route}`).join(' | '),
            'aucune');

        const fermer = await page.$(C.panneauFermer);
        if (fermer) { await fermer.click(); await dors(400); }
    });

    // ══ 4. LE TEMOIN, PUIS LA FERMETURE PAR L'ABSENCE ════════════════════
    let temoinVu = false;
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
        // AUCUN GROUPE N'A ETE CREE : c'est la contrepartie du refus de fixture.
        const apres = compteEnBase('SELECT COUNT(*) FROM rootwarden.machine_groups');
        verifie('aucun groupe n\'a ete cree par cette suite', apres === 0,
            `${apres} groupe(s) en base — un groupe SANS FILTRE viserait srv-zabbix`,
            `${apres} groupe(s)`);
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
