/**
 * go-page-pare-feu.mjs — la page pare-feu, et la descente jusqu'a l'historique.
 *
 * legacy   `/iptables/`                    portage  `/pare-feu`
 *
 * ══ POURQUOI CETTE SUITE EXISTE : E-244, ET CE QU'IL A REVELE ═════════════
 *
 * `pare-feu.js:548` appelle `/pare-feu/historique`. Pendant quatre jours
 * AUCUNE route de ce nom n'a existe : `PareFeuController::historique()` etait
 * du code mort et l'appel rendait 404. Le sous-lot s'etait declare porte.
 *
 * Le Lead a ecrit que « la suite reste verte parce qu'elle ne descend pas
 * jusqu'a l'historique ». **La mesure dit pire : il n'y avait AUCUNE suite.**
 * Rien sous `tests/e2e/` ne visitait `/pare-feu` — les six suites `fail2ban`
 * visent `/fail2ban`, une autre page. Vingt-trois ancres `data-rw`, trois
 * routes POST, cinq appels reseau : zero couverture au navigateur.
 *
 *     « la suite ne descend pas assez bas »  n'est pas
 *     « il n'y a pas de suite »
 *
 * La premiere se corrige en ajoutant une assertion. La seconde veut dire que
 * la capacite n'a jamais ete exercee par personne, et qu'un 404 pouvait vivre
 * quatre jours derriere un journal qui l'inscrivait comme portee.
 *
 * ══ CE QUE LA SUITE MESURE, ET POURQUOI CE N'EST PAS « ca repond 200 » ════
 *
 * `chargeHistorique()` distingue TROIS issues, et le commentaire du portage
 * dit pourquoi : le legacy replie l'echec de lecture et l'absence d'historique
 * sur le meme message, « or les deux appellent des gestes opposes : reessayer,
 * ou ne rien attendre ».
 *
 *     r.statut === 0 | !r.ok | success !== true  ->  histo_echec_titre
 *     corps.aucun_historique === true            ->  histo_vide_titre
 *     versions.length > 0                        ->  le tableau
 *
 * `iptables_history` est VIDE au banc. L'issue attendue est donc la DEUXIEME.
 * Et c'est ce qui rend la mesure discriminante : avant `4d25926`, le 404
 * tombait dans la PREMIERE. **Les deux issues rendent un panneau non vide ;
 * seul leur titre les separe.** Une assertion « un etat est rendu » aurait ete
 * verte les deux fois — c'est exactement l'erreur qu'on ne refait pas ici.
 *
 * ══ ASYMETRIE ENTRE LES CIBLES, MESUREE ET NON CONTOURNEE ═════════════════
 *
 * Sur le PORTAGE, `chargeHistorique()` part au `change` du selecteur : l'appel
 * est LOCAL (une lecture en base), donc on selectionne pour de vrai et l'on
 * descend jusqu'au reseau.
 *
 * Sur le LEGACY, `loadHistory()` n'est appele QUE depuis le gestionnaire de
 * `#fetch-rules`, apres un releve SSH abouti (`main.js:80`). **Atteindre
 * l'historique y exige un geste SORTANT sur la machine.** On ne le declenche
 * donc pas : la propriete s'y lit dans la STRUCTURE — le conteneur existe, il
 * est vide au repos, et son remplissage depend du releve. C'est la regle
 * S7a : *un chemin qui ne s'ouvre qu'apres un geste distant ne se teste pas en
 * faisant le geste.*
 *
 * Cette asymetrie n'est pas un defaut du banc, c'est un ECART DE CONCEPTION,
 * et le portage a raison : l'historique est en base, le faire dependre d'un
 * releve distant le rend illisible quand la machine est injoignable — ce que
 * `pare-feu.js:515` dit explicitement.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * Cinq routes de ce module partent sur la machine ou ecrivent : `/iptables`
 * (releve SSH), `/iptables-validate`, `/iptables-apply`, `/iptables-restore`,
 * `/pare-feu/copie/enregistrer`. **Toutes sont AVORTEES sans condition**, et
 * toute requete citant la machine 1 ou `srv-zabbix` l'est aussi. Le filet est
 * mesure a la fin : il ne se suppose pas.
 *
 * Seule machine choisie : Test-Server-Debian (id 2). `srv-zabbix` (id 1) n'est
 * jamais selectionnee, et son intacte est relue en base au verdict.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync, readFileSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
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
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const MACHINE_PRODUCTION = 1;
const MACHINE_BANC = 2;
const NOM_BANC = 'Test-Server-Debian';

/* Secrets RELEVES dans les suites du depot, jamais inventes. */
const COMPTES = {
    user:  { nom: 'rw-test-user',  role: 1,
        secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW',
        admis: false, motif: 'ni le role 3, ni la permission' },
    admin: { nom: 'rw-test-admin', role: 2,
        secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX',
        admis: false, motif: 'role 2 SANS `can_manage_iptables` — le seul chemin discriminant' },
    super: { nom: 'rw-test-super', role: 3,
        secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW',
        admis: true,  motif: 'le role 3 contourne, SANS detenir la permission' },
};

/*
 * Les gestes qui ne doivent JAMAIS partir.
 *
 * ⚠ ICI LA METHODE NE DISCRIMINE PAS, et c'est mesure : `POST /iptables` porte
 *   son verbe dans le CORPS — `action:"get"` LIT les regles, `action:"apply"`
 *   les ECRIT. Un filet par methode y avorterait une lecture legitime. Le filet
 *   est donc par CHEMIN, toutes methodes confondues.
 *
 * Et il DENIE PAR PREFIXE en n'exemptant que les deux lectures, au lieu
 * d'enumerer les ecritures : une route `/iptables-*` ajoutee demain est couverte
 * d'office. L'enumeration inverse a deja trahi trois autres suites de ce banc
 * (2026-09-02) — un nom present qui ne couvre pas se croit couvert.
 *
 * `iptables-save` etait un FANTOME : le nom n'existe que dans un commentaire de
 * backend/iptables_manager.py (le FORMAT de sortie), jamais comme route.
 *
 * Exemptees, les deux seules lectures du module, toutes deux en GET :
 *   /iptables-history · /iptables-logs
 *
 * ⚠ ET LA PAGE ELLE-MEME, servie a `/iptables/` cote legacy. L'ancre `(\?|$)`
 *   que je viens de retirer ne faisait pas QUE bloquer `scan-all` : elle
 *   excluait aussi la PAGE, qui porte un `/` final la ou les routes d'API n'en
 *   ont pas. La retirer sans la remplacer a fait avorter la navigation vers la
 *   page — `net::ERR_BLOCKED_BY_CLIENT`, 4 FAIL sur la cible legacy, mesure du
 *   2026-09-02 08:20. **Une ancre fautive peut faire un second travail, juste.**
 *   (L'auteur de go-bashrc-b2 avait documente ce piege ; je ne l'ai pas lu.)
 *
 * Le predicat exact, en une lecture :
 *   /iptables/      -> la PAGE            passe
 *   /iptables       -> POST d'API         AVORTE
 *   /iptables-*     -> ecritures d'API    AVORTE
 *   /iptables-history · -logs             passe
 * Remesurer : grep -nE "@bp.route" backend/routes/iptables.py
 */
const INTERDITS = new RegExp(
    '/(iptables(?!/|-history|-logs)|pare-feu/copie/enregistrer)');
/* Ce qui vise le backend, quel que soit le portail. */
const VERS_BACKEND = /\/(api\/gateway|api_proxy\.php)\//;

/*
 * SONDE D'AUTO-CONTROLE — `E2E_SONDE_E244=1`, inactive par defaut.
 *
 * Une suite qui ne rougit pas sur le defaut qu'elle pretend couvrir ne vaut
 * rien, et la lecture du code ne l'etablit pas : elle etablit qu'un chemin
 * EXISTE, pas qu'il est atteint. La sonde avorte la route d'historique — ce
 * que faisait le 404 d'E-244 du point de vue de la page — et l'on verifie que
 * la suite passe au ROUGE. Elle se lance a la main, jamais dans le LOT :
 *
 *     E2E_SONDE_E244=1 node go-page-pare-feu.mjs     # doit ECHOUER
 *
 * Fail-safe : toute valeur autre que « 1 » la laisse inerte, et son etat est
 * inscrit dans le journal a chaque execution — une sonde active par accident
 * doit se voir, pas se deviner.
 */
const SONDE_E244 = process.env.E2E_SONDE_E244 === '1';

const C = CIBLE === 'laravel'
    ? { connexion: '/connexion', page: '/pare-feu',
        selecteur: '[data-rw="ipt-serveur"]',
        sectionHisto: '[data-rw="ipt-histo"]',
        cadreHisto: '[data-rw="ipt-histo-cadre"]',
        corpsHisto: '[data-rw="ipt-histo-corps"]',
        etatHisto: '[data-rw="ipt-histo-etat"]',
        releve: '[data-rw="ipt-relever"]',
        routeHisto: /\/pare-feu\/historique$/,
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]' }
    : { connexion: '/auth/login.php?lang=fr', page: '/iptables/',
        selecteur: '#server',
        sectionHisto: '#iptables-history',
        cadreHisto: '#iptables-history',
        corpsHisto: '#iptables-history',
        etatHisto: '#iptables-history',
        releve: '#fetch-rules',
        routeHisto: /\/iptables-history(\?|$)/,
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]' };

/**
 * Un libelle LU dans le catalogue, jamais recopie ici. Une chaine recopiee
 * fige la valeur du jour : le catalogue peut changer, l'assertion continue de
 * comparer a l'ancienne et devient verte sur un ecran qui ne dit plus rien.
 * Rend `null` si la cle est absente — et une assertion qui recoit `null`
 * s'abstient au lieu de conclure.
 */
function libelle(cle) {
    try {
        const chemin = new URL('../../laravel/lang/fr/pare-feu.php', import.meta.url).pathname;
        const texte = readFileSync(chemin, 'utf8');
        const m = texte.match(new RegExp(`'${cle}'\\s*=>\\s*'((?:[^'\\\\]|\\\\.)*)'`));

        return m ? m[1].replace(/\\'/g, "'").replace(/\\\\/g, '\\') : null;
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
const reponses = [];
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

    /*
     * LES REPONSES, PAS SEULEMENT LES DEPARTS. `abouties` compterait des
     * requetes PARTIES ; le defaut d'E-244 etait un STATUT. Sans ce
     * collecteur la suite ne saurait pas distinguer 200 de 404.
     */
    page.on('response', (r) => {
        const chemin = r.url().replace(/^https?:\/\/[^/]+/, '');
        reponses.push({ route: chemin, statut: r.status(), methode: r.request().method() });
    });

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        vues += 1;
        const url = r.url();
        const chemin = url.replace(/^https?:\/\/[^/]+/, '');
        let corps = '';
        try { corps = r.postData() || ''; } catch { /* pas de corps */ }

        // FAIL-CLOSED, DANS CET ORDRE : le geste d'abord, la cible ensuite. Un
        // geste interdit qui viserait la machine 2 est avorte quand meme.
        // La sonde passe AVANT le filet : elle simule l'indisponibilite de la
        // route, pas un geste dangereux.
        if (SONDE_E244 && C.routeHisto.test(chemin)) {
            avortees.push({ route: chemin, motif: 'SONDE E-244 — route rendue injoignable', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (INTERDITS.test(url)) {
            avortees.push({ route: chemin, motif: 'geste SORTANT ou ECRIVANT', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (new RegExp(`"(machine_id|server_id)"\\s*:\\s*${MACHINE_PRODUCTION}\\b`).test(corps)
            || new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(url)
            || /srv-zabbix/.test(corps)) {
            avortees.push({ route: chemin, motif: 'vise la PRODUCTION', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (VERS_BACKEND.test(url) || /\/pare-feu\//.test(url)) {
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

/* Releve AVANT la mesure et lu APRES : il vit donc hors du `try`. */
let nHisto = null;

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

/**
 * Choisit une machine PAR SON NOM, jamais par sa position. Sur le legacy la
 * valeur d'une option est le JSON entier du serveur, pas son identifiant :
 * « la deuxieme option » ne veut rien dire, et « l'option dont la valeur est
 * 2 » n'y existe pas. On lit donc les options, on retient celle qui porte le
 * nom voulu, et l'on selectionne PAR SA VALEUR.
 */
async function choisitMachine(page, nom) {
    const options = await page.$$eval(`${C.selecteur} option`,
        (os) => os.map((o) => ({ valeur: o.value, texte: (o.textContent || '').trim() })));
    const vise = options.find((o) => o.texte.includes(nom));
    if (! vise) {
        return { ok: false, options: options.map((o) => o.texte), valeur: null };
    }
    await page.select(C.selecteur, vise.valeur);

    return { ok: true, options: options.map((o) => o.texte), valeur: vise.valeur, texte: vise.texte };
}

/**
 * Attend que le panneau d'historique se STABILISE : son empreinte doit changer
 * puis cesser de changer. Un delai fixe mesurerait un instant, pas une
 * propriete — le defaut corrige dans `f2`.
 */
async function attendStabilise(page, selecteur, borneMs = 8000) {
    const empreinte = async () => page.evaluate((s) => {
        const e = document.querySelector(s);
        if (! e) return 'absent';

        return `${e.hidden ? 'H' : 'V'}:${(e.innerText || '').trim().length}:${e.querySelectorAll('tr').length}`;
    }, selecteur);

    const debut = Date.now();
    let precedente = await empreinte();
    let stable = 0;
    while (Date.now() - debut < borneMs) {
        await dors(150);
        const courante = await empreinte();
        if (courante === precedente) { stable += 1; if (stable >= 4) break; }
        else { stable = 0; precedente = courante; }
    }

    return precedente;
}

try {
    /*
     * LA PRECONDITION, MESUREE ET NON SUPPOSEE. La garde est « la permission
     * OU le role 3 ». Si un compte d'epreuve venait a DETENIR
     * `can_manage_iptables`, le refus de `rw-test-admin` cesserait d'etre le
     * chemin discriminant, et l'assertion mentirait sous son propre libelle.
     */
    constate('sonde d\'auto-controle E-244',
        SONDE_E244 ? 'ACTIVE — la route d\'historique est rendue injoignable, la suite DOIT rougir'
            : 'inactive');

    const porteurs = litEnBase(
        'SELECT u.name FROM rootwarden.users u JOIN rootwarden.permissions p '
        + 'ON p.user_id = u.id WHERE p.can_manage_iptables = 1');
    constate('comptes detenant `can_manage_iptables`', porteurs.join(', ') || '(aucun)');
    verifie('aucun compte d\'epreuve ne detient `can_manage_iptables`',
        ! porteurs.some((n) => n.startsWith('rw-test-')),
        `${porteurs.join(', ')} — le refus de rw-test-admin ne serait plus discriminant`,
        porteurs.join(', ') || 'aucun');

    /*
     * L'ETAT DE LA TABLE, RELEVE AVANT LA MESURE. L'issue attendue de
     * `chargeHistorique` en depend : vide -> `aucun_historique`, peuplee -> un
     * tableau. Une suite qui ne le lirait pas ne saurait pas laquelle exiger.
     */
    nHisto = compteEnBase(
        `SELECT COUNT(*) FROM rootwarden.iptables_history WHERE server_id = ${MACHINE_BANC}`);
    constate(`versions archivees pour la machine ${MACHINE_BANC}`, String(nHisto));

    // ══ 1. LA GARDE, AUX TROIS COMPTES ═══════════════════════════════════
    for (const cle of ['user', 'admin', 'super']) {
        const compte = COMPTES[cle];
        await etape(`garde : ${compte.nom} (role ${compte.role})`, async () => {
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

    // ══ 2. LA PAGE, AU COMPTE QUI Y ACCEDE ═══════════════════════════════
    const s = await connecte(COMPTES.super);
    verifie('la session a tenu', ! s.surConnexion, s.page.url());
    if (s.surConnexion) throw new Error('session non etablie');
    const page = s.page;
    await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
    await attendStabilise(page, C.selecteur, 4000);

    let choix = { ok: false, options: [] };

    await etape('le selecteur porte la machine du banc', async () => {
        choix = await choisitMachine(page, NOM_BANC);
        constate('options du selecteur', choix.options.join(' | ') || '(aucune)');
        verifie(`le selecteur propose ${NOM_BANC}`, choix.ok,
            `options vues : ${choix.options.join(' | ') || 'aucune'}`,
            `${choix.options.length} option(s)`);
    });

    // ══ 3. E-244 — LA DESCENTE JUSQU'AU FETCH ════════════════════════════
    await etape('l\'historique est joignable', async () => {
        if (! choix.ok) {
            verifie('l\'appel a l\'historique est parti', false,
                'la machine du banc n\'est pas selectionnable — rien n\'a pu partir');

            return;
        }
        await attendStabilise(page, C.sectionHisto, 8000);

        const appels = reponses.filter((r) => C.routeHisto.test(r.route));
        constate('appels a la route d\'historique', appels.length
            ? appels.map((a) => `${a.methode} ${a.route} -> ${a.statut}`).join(' | ')
            : '(aucun)');

        /*
         * SUR LE PORTAGE SEULEMENT. Sur le legacy `loadHistory()` n'est appele
         * que depuis le gestionnaire de `#fetch-rules`, apres un releve SSH
         * abouti : ne pas voir l'appel y est le comportement ATTENDU, pas un
         * defaut. On ne declenche pas le releve, donc on ne l'exige pas.
         */
        verifiePortage('l\'appel a l\'historique part au choix de la machine',
            appels.length > 0,
            'aucun appel n\'est parti apres la selection — le chemin de la page ne descend pas jusqu\'a la route');

        // LE STATUT, ET NON « ca a repondu ». C'est LUI qui valait 404.
        verifiePortage('la route d\'historique existe et repond 200',
            appels.length > 0 && appels.every((a) => a.statut === 200),
            appels.length === 0 ? 'aucune reponse a mesurer'
                : `statuts vus : ${appels.map((a) => a.statut).join(', ')} — un 404 signifie que la route n'est pas exposee`);
    });

    // ══ 4. LES TROIS ISSUES : CELLE QUI EST RENDUE EST LA BONNE ══════════
    await etape('l\'issue rendue distingue « vide » de « en echec »', async () => {
        /*
         * SANS OBJET SUR LE LEGACY, ET C'EST STRUCTUREL. `loadHistory()` n'y
         * part qu'apres un releve SSH ; sans ce geste — qu'on ne fait pas — il
         * n'y a AUCUNE issue rendue. Exiger un panneau non vide y serait un
         * rouge fabrique par le banc, pas un defaut du portail. L'etape 5
         * mesure la face legacy de la meme propriete.
         */
        if (CIBLE !== 'laravel') {
            constate('issue d\'historique',
                'SANS OBJET — le legacy ne charge l\'historique qu\'apres un releve SSH, geste non exerce');

            return;
        }
        const vu = await page.evaluate((sel) => {
            const e = document.querySelector(sel.etat);
            const cadre = document.querySelector(sel.cadre);
            const corps = document.querySelector(sel.corps);

            return {
                present: e !== null,
                texte: e ? (e.innerText || '').trim() : '',
                cadreVisible: cadre ? ! cadre.hidden && cadre.offsetParent !== null : false,
                lignes: corps ? corps.querySelectorAll('tr').length : 0,
            };
        }, { etat: C.etatHisto, cadre: C.cadreHisto, corps: C.corpsHisto });

        constate('panneau d\'historique', vu.present
            ? `« ${vu.texte.slice(0, 90).replace(/\s+/g, ' ')} » — ${vu.lignes} ligne(s)`
            : '(absent)');

        /*
         * LA PROPRIETE PORTE SA PRECONDITION. On exige un panneau non vide
         * AVANT d'interroger ce qu'il dit : un panneau absent satisferait
         * n'importe quelle assertion sur son contenu.
         */
        verifie('un etat d\'historique est rendu', vu.present && vu.texte !== '',
            vu.present ? 'le panneau est rendu mais vide' : 'le panneau n\'est pas rendu',
            `${vu.texte.length} caracteres`);

        if (! vu.present || vu.texte === '') return;

        // AUCUN JETON NON SUBSTITUE : un catalogue incomplet rend `ipt_no_history`
        // en clair, et l'ecran « affiche quelque chose » sans rien dire.
        verifie('le message d\'historique ne porte aucun jeton non substitue',
            ! /:[a-z_]{3,}|^[a-z0-9_]+$|\{[a-z_]+\}/.test(vu.texte.trim()),
            `« ${vu.texte.slice(0, 70)} »`);

        /*
         * L'IDENTITE DE L'ISSUE, ET C'EST LE COEUR DE LA SUITE.
         *
         * Ma propre sonde l'a prouve : sous `E2E_SONDE_E244=1` la page rend
         * « Historique illisible » et les trois assertions ci-dessus restaient
         * VERTES — un panneau non vide, sans jeton, sans ligne. Seul le reseau
         * rougissait. Une route qui rendrait 200 avec `success: false` aurait
         * donc laisse la suite ENTIEREMENT verte sur un defaut.
         *
         * L'en-tete annonçait cette distinction ; le code ne la mesurait pas.
         * On la mesure ici, au DOM, sans dependre du statut : le titre rendu
         * doit etre celui de l'ABSENCE, et surtout PAS celui de l'ECHEC.
         */
        const titreVide = libelle('histo_vide_titre');
        const titreEchec = libelle('histo_echec_titre');
        if (titreVide === null || titreEchec === null) {
            constate('identite de l\'issue',
                'SANS OBJET — un des deux libelles est absent du catalogue, rien a comparer');
        } else if (nHisto === 0) {
            constate('titres compares', `« ${titreVide} » attendu, « ${titreEchec} » interdit`);
            verifiePortage('l\'issue rendue est l\'ABSENCE, et non l\'ECHEC de lecture',
                vu.texte.includes(titreVide) && ! vu.texte.includes(titreEchec),
                vu.texte.includes(titreEchec)
                    ? `la page annonce « ${titreEchec} » — l'historique n'a pas ete lu, ce n'est pas « il est vide »`
                    : `aucun des deux titres connus n'est rendu : « ${vu.texte.slice(0, 60)} »`);
        }

        /*
         * L'ISSUE ATTENDUE SE DEDUIT DE LA BASE, RELEVEE PLUS HAUT. Table vide
         * -> le message d'absence ; table peuplee -> des lignes. Les deux
         * s'excluent, et c'est cette EXCLUSION qui distingue « vide » d'« en
         * echec » : un echec rendrait un panneau non vide LUI AUSSI, avec zero
         * ligne. On exige donc que l'etat concorde avec la base.
         */
        if (nHisto === 0) {
            verifiePortage('table vide : aucune ligne d\'historique n\'est rendue',
                vu.lignes === 0,
                `${vu.lignes} ligne(s) rendue(s) alors que la table est vide`);
        } else {
            verifiePortage('table peuplee : les versions sont rendues',
                vu.lignes > 0,
                `aucune ligne rendue alors que la table en porte ${nHisto}`);
        }
    });

    /*
     * ══ 5. L'ECART DE CONCEPTION, MESURE SUR CHAQUE CIBLE ════════════════
     *
     * L'en-tete annonce que l'historique depend du releve sur le legacy et de
     * la MACHINE sur le portage. Une suite qui l'annonce sans le mesurer
     * transforme une lecture en verdict — c'est precisement ce qu'E-244 a
     * coute. On mesure donc les deux faces, chacune sur sa cible :
     *
     *   portage : la section d'historique est PEUPLEE apres le seul choix de
     *             la machine, sans qu'aucun releve n'ait ete demande ;
     *   legacy  : elle est VIDE au repos, et le bouton de releve — le geste
     *             qu'on ne fait pas — est la, ce qui montre par quoi elle
     *             passe. Structure, jamais declenchement.
     */
    await etape('l\'historique ne depend pas d\'un geste sur la machine', async () => {
        const vu = await page.evaluate((sel) => {
            const histo = document.querySelector(sel.histo);
            const bouton = document.querySelector(sel.releve);

            return {
                histoPresent: histo !== null,
                histoTexte: histo ? (histo.innerText || '').trim() : '',
                // LA VISIBILITE, ET NON LE TEXTE. Un conteneur non rendu voit
                // `innerText` se comporter comme `textContent` : le legacy y
                // porte un texte d'attente qui n'est PAS affiche. Mesurer le
                // texte ferait donc echouer une page qui se comporte bien.
                histoVisible: histo ? histo.offsetParent !== null : false,
                histoLignes: histo ? histo.querySelectorAll('tr, li, [data-history-id]').length : 0,
                boutonPresent: bouton !== null,
            };
        }, { histo: C.sectionHisto, releve: C.releve });

        constate('bouton de releve', vu.boutonPresent ? 'present (non actionne)' : '(absent)');

        if (CIBLE === 'laravel') {
            verifie('l\'historique est renseigne sans qu\'aucun releve soit demande',
                vu.histoPresent && vu.histoTexte !== ''
                    && ! passees.some((p) => INTERDITS.test(p.route)),
                ! vu.histoPresent ? 'la section d\'historique est absente'
                    : vu.histoTexte === '' ? 'la section est rendue mais vide'
                        : 'un geste sortant est parti — l\'historique ne serait plus independant',
                `${vu.histoTexte.length} caracteres`);
        } else {
            /*
             * MESURE : le conteneur existe, il n'est PAS AFFICHE au repos, il
             * ne porte AUCUNE entree, et le bouton de releve — le geste qu'on
             * ne fait pas — est la. C'est la forme de la dependance, lue sans
             * jamais l'exercer.
             *
             * Le texte d'attente ne compte pas : `#iptables-history` vit dans
             * `#rules-container`, masque au chargement, et `innerText` d'un
             * element non rendu retombe sur `textContent`. Une premiere
             * redaction exigeait un texte vide et faisait ECHOUER une page
             * correcte — l'assertion mesurait l'instrument, pas la page.
             */
            const ok = vu.histoPresent && ! vu.histoVisible
                && vu.histoLignes === 0 && vu.boutonPresent;
            verifie('sans releve, l\'historique n\'est ni affiche ni renseigne',
                ok,
                ! vu.histoPresent ? 'le conteneur est absent'
                    : ! vu.boutonPresent ? 'le bouton de releve est absent — le chemin n\'est pas celui decrit'
                        : vu.histoVisible ? 'le conteneur est AFFICHE sans qu\'aucun releve ait eu lieu'
                            : `${vu.histoLignes} entree(s) deja presentes sans releve`,
                // Le detail « toujours » ne doit JAMAIS affirmer ce que
                // l'assertion nie : il ne sort que sur le verdict qu'il decrit.
                ok ? 'conteneur present, masque, sans entree' : '');
        }
    });

    // ══ 6. LE GESTE SORTANT N'EST PAS PARTI SEUL ═════════════════════════
    await etape('aucun releve SSH n\'est parti du seul choix de la machine', async () => {
        const sortis = passees.filter((p) => INTERDITS.test(p.route));
        constate('gestes sortants observes', sortis.length
            ? sortis.map((p) => `${p.methode} ${p.route}`).join(' | ') : '(aucun)');
        // AU RESEAU, jamais au DOM : un bouton peut rester desactive ET l'appel
        // partir quand meme.
        verifie('choisir une machine ne declenche aucun geste sur elle',
            sortis.length === 0,
            sortis.map((p) => p.route).join(' '),
            'aucun');
    });

    await etape('aucune erreur JavaScript', async () => {
        verifie('aucune erreur JavaScript sur la page', s.erreursJs.length === 0,
            s.erreursJs.slice(0, 3).join(' | '), 'aucune');
    });

    // ══ 7. CAPTURES ══════════════════════════════════════════════════════
    await etape('captures', async () => {
        /*
         * LA SONDE ECRIT AILLEURS. Sinon les captures livrees montrent l'etat
         * FORGE — « Historique illisible » — comme s'il etait l'etat normal.
         * C'est arrive une fois, et je l'ai vu en regardant l'image, pas en
         * lisant le code.
         */
        const dossier = new URL(
            `./screenshots/pare-feu/${CIBLE}${SONDE_E244 ? '-sonde' : ''}`, import.meta.url).pathname;
        mkdirSync(dossier, { recursive: true });
        for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                         { n: 'mobile', w: 390, h: 844 }]) {
            await page.setViewport({ width: f.w, height: f.h });
            await dors(400);
            await page.screenshot({ path: `${dossier}/pf-${f.n}.png`, fullPage: true });
        }
        verifie('les trois captures sont ecrites', true, '', dossier);
    });
} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    // ══ SURETE — LE FILET NE SE SUPPOSE PAS, IL SE MESURE ════════════════
    try {
        constate('requetes AVORTEES', avortees.length
            ? avortees.map((a) => `${a.route} (${a.motif})`).join(' | ') : '(aucune)');
        constate('requetes laissees passer', passees.length
            ? passees.map((p) => `${p.methode} ${p.route}`).join(' | ') : '(aucune)');
        constate('boites natives ouvertes', boites.length
            ? boites.map((b) => `${b.type} « ${b.message.slice(0, 60)} »`).join(' | ') : '(aucune)');

        /*
         * UN FILET QUI N'A RIEN VU PASSER NE CERTIFIE RIEN. Si la suite est
         * tombee avant d'ouvrir une page, `passees` est vide et les deux
         * assertions ci-dessous seraient VRAIES — deux PASS decernes a un
         * controle qui n'a jamais eu d'objet. C'est un silence par incapacite
         * sous l'etiquette d'un silence mesure : on s'abstient, en le disant.
         */
        if (vues === 0) {
            constate('controle de surete', 'SANS OBJET — aucune requete vue, le filet n\'a rien eu a filtrer');
        } else {
            verifie('AUCUN geste sortant ou ecrivant n\'a abouti',
                ! passees.some((p) => INTERDITS.test(p.route)),
                passees.filter((p) => INTERDITS.test(p.route)).map((p) => p.route).join(' '),
                `${passees.length} requete(s) laissee(s) passer`);
            verifie('AUCUNE requete n\'a vise la production',
                ! passees.some((p) => new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(p.route)
                    || /srv-zabbix/.test(p.corps || '')),
                'une requete a vise `srv-zabbix`');
        }
    } catch (e) { note(`FAIL  controle de surete : ${e.message}`); echecs += 1; }
    try {
        const zabbix = litEnBase("SELECT CONCAT(name,'|',ip) FROM rootwarden.machines WHERE id = 1");
        verifie('srv-zabbix est intacte', zabbix.length === 1 && /^srv-zabbix\|/.test(zabbix[0]),
            zabbix[0] || '(absente)', zabbix[0] || '');
        /*
         * L'HISTORIQUE N'A PAS BOUGE. La suite ne fait que LIRE ; si le compte
         * changeait entre le debut et la fin, c'est qu'un geste ecrivant est
         * passe sous le filet — et le compte le dit mieux qu'une absence de
         * requete observee.
         */
        const apres = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.iptables_history WHERE server_id = ${MACHINE_BANC}`);
        /*
         * LE COMPTE D'AVANT VIENT DU DEBUT DE LA SUITE, PAS D'UNE SECONDE
         * LECTURE. Comparer deux `SELECT` faits l'un apres l'autre rendrait
         * l'assertion tautologiquement vraie : elle passerait meme si un geste
         * ecrivant avait abouti. `nHisto` reste `null` si la suite est tombee
         * avant de le relever — et une comparaison a `null` doit ECHOUER, pas
         * se taire : un garde qui n'a pas pu mesurer ne rend pas un verdict.
         */
        verifie('l\'historique de la machine du banc n\'a pas ete ecrit',
            nHisto !== null && apres === nHisto,
            nHisto === null ? 'compte initial jamais releve — rien a comparer'
                : `${nHisto} au depart, ${apres} a l'arrivee`,
            nHisto === null ? '' : `${apres} version(s), inchange`);
    } catch (e) { note(`FAIL  controle de l'etat : ${e.message}`); echecs += 1; }
    for (const c of contextes) { try { await c.close(); } catch { /* deja ferme */ } }
    try { await navigateur.close(); } catch { /* deja ferme */ }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
