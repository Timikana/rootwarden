/**
 * go-page-accueil.mjs — les neuf indicateurs de l'accueil, bornes, aux TROIS roles.
 *
 * legacy   `/index.php`                    portage  `/accueil`
 *
 * ══ CE QUI SE MESURE ICI, ET POURQUOI UN SEUL ROLE NE SUFFIT PAS ══════════
 *
 * `legacy/index.php:78-104` calcule neuf valeurs SANS aucune borne : un compte
 * qui n'a acces a aucune machine y lit la taille du parc, le nombre de CVE
 * critiques et la date du dernier scan. Le portage les borne — trois familles,
 * trois bornes, trois seuils de role differents :
 *
 *     parc          `borne` vrai si role < 2
 *     indicateurs   `borne` vrai si role < 2
 *     comptes       `actifs` NULL si role < 2   ·   `sans_2fa` NULL si role < 3
 *
 * **Une suite qui n'exercerait qu'un role ne verrait donc RIEN de tout ça.**
 * Au role 3 les trois bornes sont inertes ; au role 1 elles mordent toutes. Le
 * role 2 est le seul a les separer — il voit le parc entier ET n'a pas droit
 * au compteur `sans_2fa`. C'est le meme motif qui a laisse douze suites d'un
 * module n'exercer qu'un seul role, et un chemin de garde jamais teste.
 *
 * ══ LA PROPRIETE N'EST PAS « LA RESERVE EST LA » ══════════════════════════
 *
 * **La reserve ne doit apparaitre QUE si la borne mord.** L'asserter presente
 * au role 3 serait asserter un defaut : une reserve sans objet devient un
 * decor qu'on ne lit plus. On mesure donc sa PRESENCE au role 1 et son ABSENCE
 * aux roles 2 et 3 — l'assertion change de sens avec le role, ce qui est la
 * seule façon de mesurer une borne.
 *
 * ══ TROIS ETATS, ET DEUX D'ENTRE EUX PRODUISENT LE MEME OBSERVABLE ════════
 *
 * Chaque famille a des issues MUTUELLEMENT EXCLUSIVES :
 *
 *     parc          illisible  |  valeur
 *     indicateurs   illisible  |  la grille
 *     cve           illisible  |  aucun-scan  |  la grille
 *     comptes       illisible  |  reserve     |  la grille
 *
 * « Rien lu » n'est pas « zero », et « aucun scan » n'est ni l'un ni l'autre.
 * Les trois rendent un bloc de texte : **une assertion « un etat est rendu »
 * serait verte sur les trois**. On mesure donc qu'il y en a EXACTEMENT UN, et
 * lequel — la leçon d'E-244, ou l'echec de lecture et l'absence de donnee se
 * ressemblaient a tout sauf a leur titre.
 *
 * ══ CE QUI N'EST PAS MESURE, ET CE N'EST PAS UN OUBLI ═════════════════════
 *
 * **Aucune reference posee ici ne certifie l'onglet « borne ».** La region
 * d'alertes du legacy — neuf alertes au role 1, dont une qui nomme jusqu'a
 * cinq comptes avec l'age de leur cle — n'est pas commencee. Une reference
 * posee sur un etat incomplet transforme un manque en etat normal.
 *
 * **Le LEGACY ne porte aucune ancre d'etat** : ses neuf valeurs sont rendues
 * sans `data-rw`, et ses trois issues ne se distinguent pas a l'ecran. On ne
 * fabrique donc pas d'assertion la-dessus — elle mesurerait l'absence d'un
 * outillage, pas un comportement. Ce qui s'y mesure : la page repond, aux
 * trois roles, et l'ecart est CONSTATE.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * L'accueil ne porte aucun geste. Le filet avorte quand meme tout POST vers un
 * chemin d'action et toute requete citant la machine 1 : une page qui ne doit
 * rien declencher se mesure par « rien n'est parti », pas par « il n'y a pas
 * de bouton ».
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';
import { constateArchivage } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const MACHINE_PRODUCTION = 1;

/* Secrets RELEVES dans les suites du depot, jamais inventes. */
const COMPTES = {
    user:  { nom: 'rw-test-user',  role: 1,
        secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW' },
    admin: { nom: 'rw-test-admin', role: 2,
        secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX' },
    super: { nom: 'rw-test-super', role: 3,
        secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW' },
};

/*
 * CE QUE CHAQUE ROLE DOIT VOIR, DERIVE DES SEUILS DU SERVICE — jamais recopie
 * d'un ecran. `Machines::compteursPerimetre` borne a `role < 2`,
 * `Machines::indicateurs` pose `borne => roleId < 2`, `Comptes::indicateursComptes`
 * rend `actifs = null` sous 2 et `sans_2fa = null` sous 3.
 */
const ATTENDU = {
    1: { parcBorne: true,  indBorne: true,  comptesReserve: true,  sans2fa: false },
    2: { parcBorne: false, indBorne: false, comptesReserve: false, sans2fa: false },
    3: { parcBorne: false, indBorne: false, comptesReserve: false, sans2fa: true },
};

/*
 * Un geste d'action ne doit jamais partir de l'accueil.
 *
 * ⚠ CE MOTIF ETAIT UNE LISTE DE VERBES, et une liste de verbes ne peut pas
 *   etre complete : l'accueil touche TOUS les modules, donc l'ensemble a
 *   couvrir est l'union de leurs ecritures, qui bouge a chaque livraison.
 *   Trois autres suites de ce banc ont ete prises en defaut le meme jour par
 *   une enumeration (2026-09-02), dont une qui ignorait `/deploy`.
 *
 * DEUX CLAUSES :
 *   (1) les verbes d'action, avortes QUELLE QUE SOIT LA METHODE — le legacy
 *       PHP n'a aucune discipline de methode, un GET peut y ecrire ;
 *   (2) tout non-GET vers la passerelle : l'accueil AFFICHE, il n'agit pas.
 *       Cette clause-la ne s'entretient pas et couvre les modules a venir.
 *
 * L'ancre accepte desormais `/` : `scan` n'attrapait pas `scan-all`.
 */
const INTERDITS = /\/(deploy|regenerate|scan|remove|reenter|apply|restore|rotate|revoke|uninstall|reconfigure)[a-z_-]*(\?|\/|$)/i;
const VERS_BACKEND = /\/(api\/gateway|api_proxy\.php)\//;
/* Le filet et le VERDICT portent sur le MEME predicat. Les avoir laisses
 * diverger est ce qui a rendu le trou invisible dans les suites voisines. */
const estInterdit = (route, methode) => INTERDITS.test(route)
    || (methode !== 'GET' && VERS_BACKEND.test(route));

const C = CIBLE === 'laravel'
    ? { connexion: '/connexion', page: '/accueil',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]' }
    : { connexion: '/auth/login.php?lang=fr', page: '/index.php',
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]' };

/*
 * Les prefixes de catalogue RELEVES dans chaque portail, jamais devines :
 *   portage  grep -o "__('[a-z]*\." laravel/resources/views/accueil.blade.php
 *   legacy   grep -o "t('[a-z_]*\."  legacy/index.php legacy/includes/*.php
 * Un nom qu'on n'a pas lu est une hypothese, pas une donnee.
 */
const MOTIF_JETONS = CIBLE === 'laravel'
    ? /\b(accueil|nav)\.[a-z0-9_]{3,}\b/g
    : /\b(common|dashboard|nav|onboarding|tip|profile|guide)\.[a-z0-9_]{3,}\b/g;

/** Les issues exclusives, par famille. Une et une seule doit etre rendue. */
const FAMILLES = [
    { nom: 'parc',        issues: ['accueil-parc-illisible', 'accueil-parc-valeur'] },
    { nom: 'indicateurs', issues: ['accueil-ind-illisible', 'accueil-indicateurs'] },
    { nom: 'cve',         issues: ['accueil-cve-illisible', 'accueil-cve-aucun-scan', 'accueil-cve'] },
    { nom: 'comptes',     issues: ['accueil-comptes-illisible', 'accueil-comptes-reserve', 'accueil-comptes'] },
];

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

/*
 * UNE ASSERTION D'ANCRE, ET LE PIEGE QU'ELLE PORTE HORS DU PORTAGE.
 *
 * `legacy/index.php` ne contient **aucune** ancre `data-rw` — mesure :
 * `grep -c 'data-rw=' legacy/index.php` rend 0. Toute assertion qui exige
 * l'ABSENCE d'une ancre y est donc vraie sans avoir rien mesure, et
 * `verifiePortage` l'annonçait « verifie sur le legacy aussi ».
 *
 * C'est un faux dedouanement DANS LE JOURNAL : le compte n'en est pas gonfle
 * — ce sont des INFO — mais la phrase affirme une verification qui n'a pas eu
 * lieu, et quelqu'un la recopiera. On s'abstient donc en le disant, comme
 * partout ailleurs : « je n'ai pas pu regarder » n'est pas « rien a signaler ».
 *
 * `ancres` est le nombre d'ancres `accueil-*` reellement rendues par la page.
 */
function verifieAncre(l, ok, d, ancres) {
    if (CIBLE !== 'laravel' && ancres === 0) {
        constate(l, 'SANS OBJET — la page ne porte aucune ancre `accueil-*` :'
            + ' une assertion d\'absence y serait vraie sans rien avoir mesure');

        return;
    }
    verifiePortage(l, ok, d);
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

        // Le GESTE d'abord, la CIBLE ensuite : un geste interdit visant une
        // machine sure est avorte quand meme.
        if (estInterdit(chemin, r.method())) {
            avortees.push({ route: chemin, motif: 'geste d\'action depuis l\'accueil', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (new RegExp(`"(machine_id|server_id)"\\s*:\\s*${MACHINE_PRODUCTION}\\b`).test(corps)
            || new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(url)) {
            avortees.push({ route: chemin, motif: 'vise la PRODUCTION', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (VERS_BACKEND.test(url)) passees.push({ route: chemin, methode: r.method(), corps });
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

/** Ce que la page rend, releve en une passe : presence ET valeur des ancres. */
async function releve(page, familles) {
    return page.evaluate((fams) => {
        const vu = (cle) => {
            const e = document.querySelector(`[data-rw="${cle}"]`);
            if (e === null) return null;

            return { texte: (e.innerText || '').trim(), visible: e.offsetParent !== null };
        };
        const etats = {};
        for (const f of fams) {
            etats[f.nom] = {};
            for (const i of f.issues) etats[f.nom][i] = vu(i);
        }

        return {
            etats,
            parcBorne:      vu('accueil-parc-borne'),
            indBorne:       vu('accueil-ind-borne'),
            comptesReserve: vu('accueil-comptes-reserve'),
            sans2fa:        vu('accueil-comptes-sans-2fa'),
            sature:         vu('accueil-comptes-sans-cle-sature'),
            parcValeur:     vu('accueil-parc-valeur'),
            actifs:         vu('accueil-comptes-actifs'),
            sansCle:        vu('accueil-comptes-sans-cle'),
            // Un jeton non substitue trahit un catalogue incomplet : l'ecran
            // « affiche quelque chose » sans rien dire.
            corps: (document.body.innerText || '').trim(),
        };
    }, familles);
}

try {
    /*
     * ══ LE SUJET DE CETTE SUITE N'EXISTE PLUS COTE LEGACY ═════════════════
     *
     * Une suite de parite dont la moitie legacy a ete archivee ne doit pas
     * ECHOUER : un rouge permanent finit par ne plus etre lu, et il occupe la
     * place ou l'on aurait cherche une vraie regression. Elle CONSTATE, et sa
     * moitie portage continue de s'exercer.
     *
     * LE CONSTAT VIENT AVANT LA CONNEXION, et ce n'est pas un detail : la sonde
     * de `archive.mjs` n'ouvre pas de navigateur (Apache rend 404 pour un chemin
     * absent AVANT toute redirection de connexion). Se connecter d'abord ferait
     * consommer un code TOTP — dont le garde anti-rejeu est par COMPTE et
     * PERSISTANT — pour aller mesurer une page qui n'existe plus.
     *
     * ⚠ ET LE CONSTAT EXIGE UN 404, PAS UNE ABSENCE DE PAGE. Le 2026-09-05 ces
     * repertoires rendaient 403 : le `git mv` avait emporte les `.php` et laisse
     * le JavaScript, si bien que le dossier existait encore. `constateArchivage`
     * traite tout statut != 404 comme « encore servie » et rend `false` : le
     * constat aurait ete FAUX et la suite rouge quand meme. L'archivage a ete
     * acheve (`7588e71`) avant que cette ligne soit ecrite.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: C.page, fichiers: [], verifie, constate,
        });
        if (archivee) throw new Error('__archivee__');
    }

    /*
     * L'ETAT DE LA BASE, RELEVE AVANT LA MESURE. Les issues attendues en
     * dependent : `cve_scans` vide -> « aucun scan », peuplee -> la grille.
     * Une suite qui ne le lirait pas ne saurait pas laquelle exiger, et
     * choisirait celle qu'elle observe — ce qui ne mesure rien.
     */
    const nMachines = compteEnBase('SELECT COUNT(*) FROM rootwarden.machines');
    const nScans = compteEnBase('SELECT COUNT(*) FROM rootwarden.cve_scans');
    // `active`, pas `is_active` : la colonne a ete VERIFIEE contre le schema,
    // et c'est celle que `Comptes::indicateursComptes` interroge. Un nom
    // devine aurait fait tomber la suite sur sa premiere ligne, et le filet
    // aurait alors decerne ses PASS a un controle sans objet.
    const nActifs = compteEnBase(
        'SELECT COUNT(*) FROM rootwarden.users WHERE active = 1');
    constate('parc en base', `${nMachines} machine(s)`);
    constate('scans CVE en base', `${nScans} ligne(s) — ${nScans === 0 ? 'issue attendue : « aucun scan »' : 'issue attendue : la grille'}`);
    constate('comptes actifs en base', String(nActifs));

    for (const cle of ['user', 'admin', 'super']) {
        const compte = COMPTES[cle];
        const attendu = ATTENDU[compte.role];

        await etape(`accueil au role ${compte.role} (${compte.nom})`, async () => {
            const s = await connecte(compte);
            try {
                verifie(`${compte.nom} : la session a tenu`, ! s.surConnexion, s.page.url());
                if (s.surConnexion) return;

                const rep = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
                const statut = rep ? rep.status() : 0;
                // L'accueil est ouvert a tous les roles : ce n'est pas une
                // garde qu'on mesure ici, c'est ce que chacun Y LIT.
                verifie(`${compte.nom} : l'accueil repond`, statut === 200, `statut ${statut}`);
                if (statut !== 200) return;

                const vu = await releve(s.page, FAMILLES);
                const ancres = await s.page.evaluate(
                    () => document.querySelectorAll('[data-rw^="accueil-"]').length);
                constate(`${compte.nom} : ancres \`accueil-*\` rendues`, String(ancres));

                /*
                 * ── LES ISSUES SONT EXCLUSIVES ────────────────────────────
                 * Une et une seule par famille. « Il y en a au moins une »
                 * serait vert sur un ecran qui les afficherait TOUTES, et
                 * « il y en a une » ne dirait pas laquelle.
                 */
                for (const f of FAMILLES) {
                    const presentes = f.issues.filter((i) => vu.etats[f.nom][i] !== null);
                    verifieAncre(`${compte.nom} · ${f.nom} : exactement une issue rendue`,
                        presentes.length === 1,
                        presentes.length === 0
                            ? `aucune des ${f.issues.length} issues n'est rendue`
                            : `${presentes.length} issues simultanees : ${presentes.join(', ')}`,
                        ancres);
                }

                /*
                 * ── LA RESERVE N'EXISTE QUE SI LA BORNE MORD ──────────────
                 * L'assertion change de sens avec le role. L'asserter presente
                 * partout serait asserter un defaut.
                 */
                for (const [nom, obtenu, attenduPresent] of [
                    ['reserve du parc',        vu.parcBorne,      attendu.parcBorne],
                    ['reserve des indicateurs', vu.indBorne,      attendu.indBorne],
                    ['reserve des comptes',    vu.comptesReserve, attendu.comptesReserve],
                    ['compteur sans-2FA',      vu.sans2fa,        attendu.sans2fa],
                ]) {
                    const present = obtenu !== null;
                    verifieAncre(
                        `${compte.nom} (role ${compte.role}) · ${nom} ${attenduPresent ? 'PRESENTE' : 'ABSENTE'}`,
                        present === attenduPresent,
                        attenduPresent
                            ? 'la borne mord a ce role et rien ne le dit'
                            : 'affichee alors que la borne ne mord pas — une reserve sans objet devient un decor',
                        ancres);
                }

                if (compte.role === 3) {
                    constate('parc rendu au role 3', vu.parcValeur ? vu.parcValeur.texte.replace(/\s+/g, ' ') : '(absent)');
                    constate('comptes actifs rendus', vu.actifs ? vu.actifs.texte.replace(/\s+/g, ' ') : '(absent)');
                    constate('comptes sans cle rendus', vu.sansCle ? vu.sansCle.texte.replace(/\s+/g, ' ') : '(absent)');
                    constate('indicateur sature', vu.sature ? 'annonce' : 'non annonce');
                    /*
                     * LA VALEUR CONCORDE AVEC LA BASE. Au role 3 aucune borne
                     * ne mord : le nombre affiche DOIT etre le parc entier.
                     * C'est la seule verification qui attrape une borne posee
                     * au mauvais endroit — une borne trop large rendrait un
                     * nombre plus petit sans rien afficher d'anormal.
                     */
                    verifieAncre('role 3 : le parc affiche est le parc entier',
                        vu.parcValeur !== null
                            && new RegExp(`\\b${nMachines}\\b`).test(vu.parcValeur.texte),
                        vu.parcValeur === null ? 'aucune valeur de parc rendue'
                            : `« ${vu.parcValeur.texte.replace(/\s+/g, ' ')} » ne porte pas ${nMachines}`,
                        ancres);
                }

                /*
                 * AUCUN JETON NON SUBSTITUE — MESURE SUR LES DEUX CIBLES.
                 *
                 * Le motif est PROPRE A CHAQUE PORTAIL : le portage nomme ses
                 * cles `accueil.*` et `nav.*`, le legacy `common.*`,
                 * `dashboard.*`, `onboarding.*`… Chercher les cles du portage
                 * dans le legacy ne mesure RIEN, et `verifiePortage` annonçait
                 * pourtant « verifie sur le legacy aussi ».
                 *
                 * Un jeton non substitue est un defaut des DEUX cotes — ce
                 * n'est pas un ecart assume. D'ou `verifie` et non
                 * `verifiePortage` : chaque cible est mesuree avec SON motif.
                 */
                const jetons = (vu.corps.match(MOTIF_JETONS) || []);
                verifie(`${compte.nom} : aucun jeton de catalogue non substitue`,
                    jetons.length === 0,
                    `${jetons.length} jeton(s) : ${[...new Set(jetons)].slice(0, 4).join(', ')}`);

                verifie(`${compte.nom} : aucune erreur JavaScript`, s.erreursJs.length === 0,
                    s.erreursJs.slice(0, 3).join(' | '), 'aucune');

                if (compte.role === 3) {
                    const dossier = new URL(`./screenshots/accueil/${CIBLE}`, import.meta.url).pathname;
                    mkdirSync(dossier, { recursive: true });
                    for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                                     { n: 'mobile', w: 390, h: 844 }]) {
                        await s.page.setViewport({ width: f.w, height: f.h });
                        await dors(400);
                        await s.page.screenshot({ path: `${dossier}/ac-${f.n}.png`, fullPage: true });
                    }
                    verifie('les trois captures sont ecrites', true, '', dossier);
                }
            } finally {
                try { await s.ctx.close(); } catch { /* deja ferme */ }
            }
        });
        await dors((resteFenetre() + 1) * 1000);
    }
} catch (e) {
    // `__archivee__` n'est pas une panne : c'est la sortie NORMALE quand le
    // sujet legacy a ete archive. Le constat a deja tout dit.
    if (String(e && e.message || e).includes('__archivee__')) { /* rien a ajouter */ } else {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
    }
} finally {
    // ══ SURETE — LE FILET NE SE SUPPOSE PAS, IL SE MESURE ════════════════
    try {
        constate('requetes AVORTEES', avortees.length
            ? avortees.map((a) => `${a.route} (${a.motif})`).join(' | ') : '(aucune)');
        constate('requetes laissees passer', passees.length
            ? passees.map((p) => `${p.methode} ${p.route}`).join(' | ') : '(aucune)');
        constate('boites natives ouvertes', boites.length
            ? boites.map((b) => `${b.type} « ${b.message.slice(0, 60)} »`).join(' | ') : '(aucune)');

        // Un filet qui n'a rien vu passer ne certifie rien : il s'abstient en
        // le disant, plutot que de decerner un PASS a un controle sans objet.
        if (vues === 0) {
            constate('controle de surete', 'SANS OBJET — aucune requete vue, le filet n\'a rien eu a filtrer');
        } else {
            verifie('AUCUN geste d\'action n\'est parti de l\'accueil',
                ! passees.some((p) => estInterdit(p.route, p.methode)),
                passees.filter((p) => estInterdit(p.route, p.methode))
                    .map((p) => `${p.methode} ${p.route}`).join(' '),
                `${vues} requete(s) vue(s)`);
            verifie('AUCUNE requete n\'a vise la production',
                ! passees.some((p) => new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(p.route)),
                'une requete a vise `srv-zabbix`');
        }
    } catch (e) { note(`FAIL  controle de surete : ${e.message}`); echecs += 1; }
    try {
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
