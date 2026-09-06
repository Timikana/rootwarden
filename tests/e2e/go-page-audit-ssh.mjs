/**
 * go-page-audit-ssh.mjs — l'audit SSH porte : deux chemins d'admission, et une
 * fermeture PAR L'ABSENCE.
 *
 * legacy   `/ssh-audit/`                    portage  `/audit-ssh`
 *
 * ══ POURQUOI CETTE PAGE A UN TRIPLET DE ROLES REMARQUABLE ═════════════════
 *
 * La garde est `role:1` + `perm:can_audit_ssh`, et l'etat du banc fait que les
 * TROIS comptes empruntent TROIS chemins differents — mesure en base :
 *
 *     rw-test-user   role 1   can_audit_ssh = 0   -> REFUSE  (ni role, ni permission)
 *     rw-test-admin  role 2   can_audit_ssh = 1   -> ADMIS par la PERMISSION
 *     rw-test-super  role 3   can_audit_ssh = 0   -> ADMIS par le ROLE (contournement)
 *
 * **Les deux voies d'admission sont donc exercees separement**, ce qui est rare :
 * ailleurs, le role 3 masque la permission parce qu'il la detient aussi. Une
 * suite qui n'exercerait que `rw-test-super` ne verrait jamais que le
 * contournement, et un retrait de `perm:can_audit_ssh` passerait inaperçu.
 *
 * ⚠ **CE TRIPLET EST UN ETAT DU BANC, PAS UNE PROPRIETE DU CODE.** Si
 * `can_audit_ssh` etait accorde a `rw-test-super` ou retire a `rw-test-admin`,
 * les assertions garderaient leur libelle et mesureraient autre chose. La
 * precondition le relit donc en base et REFUSE de conclure si l'etat a change.
 *
 * ══ LA FERMETURE PAR L'ABSENCE, ET POURQUOI ELLE EXIGE UN TEMOIN ══════════
 *
 * `SEC-013` : cote backend, l'ECRITURE des politiques d'audit est MOINS gardee
 * que leur lecture. Le portage ne doit donc composer aucun appel vers elle —
 * et il n'expose **aucune route POST** : `web.php` ne declare que
 * `GET /audit-ssh`. Le JS ne fait que deux lectures (`/ssh-audit/fleet`,
 * `/ssh-audit/schedules`) par une fonction `lis()` sans `method`, donc en GET.
 *
 * **Mais « aucun POST n'est parti » est une universelle negative, et elle est
 * vraie a vide.** Une suite dont le collecteur serait mal branche rendrait le
 * meme PASS qu'une page irreprochable. On pose donc un TEMOIN : un POST forge
 * vers un chemin inexistant, emis depuis la page. S'il n'apparait pas dans le
 * collecteur, **l'instrument ne mesure rien** et la suite le dit au lieu de
 * conclure.
 *
 *     temoin      POST /temoin-e2e-inexistant   -> DOIT etre vu (sinon SANS OBJET)
 *     propriete   aucun POST vers /ssh-audit/*  -> mesure APRES le temoin
 *
 * Le temoin est inoffensif : le chemin n'existe pas, la reponse est 404 ou 405,
 * et rien n'est ecrit. C'est la contre-epreuve qui manque a toute fermeture par
 * l'absence — *sans elle, on demontre seulement qu'on n'a pas regarde.*
 *
 * ══ CE QUE LA SUITE NE MESURE PAS ═════════════════════════════════════════
 *
 * **Aucune planification n'est creee, sous aucune forme.** Le repli du
 * scheduler (`scheduler.py:190-211`, fonction `_run_scheduled_scan`) fait
 * `SELECT … FROM machines` **sans aucun filtre** des que la cible est vide ou
 * non reconnue : une planification de test peut declencher un scan sur le parc
 * ENTIER, `srv-zabbix` comprise. *Mon garde supposait qu'une cible mal formee ne
 * trouve rien ; elle trouve tout.* La page offre `audit-ssh-planif-creer` : on
 * ne le clique pas, et le filet avorte la route de creation sans condition.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * Tout POST vers `/ssh-audit/*` et toute requete citant la machine 1 sont
 * AVORTES. La page est en lecture seule : le filet ne devrait rien avoir a
 * arreter, et c'est ce qu'on verifie — mais il est pose quand meme, parce
 * qu'une page qui ne doit rien declencher se mesure par « rien n'est parti »,
 * jamais par « il n'y a pas de bouton ».
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';
import { constateArchivage } from './archive.mjs';

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

/* Secrets RELEVES dans les suites du depot, jamais inventes. */
const COMPTES = {
    user:  { nom: 'rw-test-user',  role: 1, perm: 0, admis: false,
        secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW',
        motif: 'ni le role 3, ni `can_audit_ssh`' },
    admin: { nom: 'rw-test-admin', role: 2, perm: 1, admis: true,
        secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX',
        motif: 'admis par la PERMISSION — le role 2 ne suffit pas seul' },
    super: { nom: 'rw-test-super', role: 3, perm: 0, admis: true,
        secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW',
        motif: 'admis par le ROLE, SANS detenir la permission' },
};

/*
 * Ce qui ne doit jamais partir : toute ECRITURE du module, et la creation de
 * planification — voir l'en-tete, le repli du scheduler prend le parc entier.
 *
 * ⚠ CE MOTIF ETAIT UNE ENUMERATION, ET ELLE ETAIT FAUSSE (2026-09-02) :
 *   — `fleet-scan` n'existe pas. La route est `/ssh-audit/fleet`, en GET.
 *   — l'ancre `(\?|$)` coupait APRES le nom : `scan` n'attrapait donc PAS
 *     `scan-all`. Mesure : 3 routes attrapees sur les 13 non-GET du blueprint.
 *   Un nom absent finit par se voir ; un nom PRESENT qui ne couvre pas se croit
 *   couvert. Le second defaut est le plus silencieux des deux.
 *
 * Le filet n'ENUMERE plus : il porte sur le MODULE, et c'est le garde qui
 * discrimine par la methode (voir plus bas). Une route ajoutee demain est
 * couverte sans que personne ait a y penser.
 *
 * RESERVE, mesuree : sur ce backend `POST` ne veut pas dire « ecriture »
 * partout — `/ssh-audit/config` LIT `sshd_config`. Ici la page n'emet que des
 * GET (6 requetes observees, toutes en GET), donc avorter tout non-GET
 * n'avorte rien de legitime. Le jour ou elle en composera un, la suite
 * rougira : c'est le signal qu'on veut, pas un faux positif.
 *
 * ⚠ CE MOTIF ATTRAPE AUSSI LA PAGE, servie a `/ssh-audit/` cote legacy. Seul le
 *   filtre `methode !== 'GET'` du garde l'en preserve. **Ne rendez pas ce garde
 *   agnostique a la methode sans exclure la page** : c'est exactement ce qui a
 *   fait avorter la navigation dans go-page-pare-feu le 2026-09-02 (4 FAIL,
 *   net::ERR_BLOCKED_BY_CLIENT), ou le garde, lui, est agnostique.
 *
 * Remesurer : grep -nE "@bp.route\('/ssh-audit/" backend/routes/ssh_audit.py
 */
const INTERDITS = /\/(ssh-audit|audit-ssh)\//;
/* Le temoin : un chemin qui n'existe pas, donc sans effet. */
const TEMOIN = '/temoin-e2e-inexistant';
const VERS_BACKEND = /\/(api\/gateway|api_proxy\.php)\//;

const C = CIBLE === 'laravel'
    ? { connexion: '/connexion', page: '/audit-ssh',
        parc: '[data-rw="audit-ssh-parc"]',
        borne: '[data-rw="audit-ssh-borne"]',
        illisible: '[data-rw="audit-ssh-perimetre-illisible"]',
        aucunServeur: '[data-rw="audit-ssh-aucun-serveur"]',
        lectureSeule: '[data-rw="audit-ssh-politique-lecture-seule"]',
        creer: '[data-rw="audit-ssh-planif-creer"]',
        serveur: '[data-rw="audit-ssh-serveur"]',
        config: '[data-rw="audit-ssh-config"]',
        panneau: '[data-rw="audit-ssh-panneau"]',
        panneauTitre: '[data-rw="audit-ssh-panneau-titre"]',
        panneauTexte: '[data-rw="audit-ssh-panneau-texte"]',
        panneauEffets: '[data-rw="audit-ssh-panneau-effets"]',
        panneauConfirmer: '[data-rw="audit-ssh-panneau-confirmer"]',
        panneauFermer: '[data-rw="audit-ssh-panneau-fermer"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]' }
    : { connexion: '/auth/login.php?lang=fr', page: '/ssh-audit/',
        parc: null, borne: null, illisible: null, aucunServeur: null,
        lectureSeule: null, creer: null, serveur: null, config: null,
        panneau: null, panneauTitre: null, panneauTexte: null,
        panneauEffets: null, panneauConfirmer: null, panneauFermer: null,
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

        // LE TEMOIN PASSE : il vise un chemin inexistant, donc il est sans
        // effet, et c'est justement lui qui prouve que le collecteur voit
        // les POST. L'avorter reviendrait a mesurer le filet, pas la page.
        if (chemin.startsWith(TEMOIN)) {
            passees.push({ route: chemin, methode: r.method(), corps });
            r.continue().catch(() => {});

            return;
        }
        // FAIL-CLOSED : le GESTE d'abord, la CIBLE ensuite.
        if (r.method() !== 'GET' && INTERDITS.test(url)) {
            avortees.push({ route: chemin, motif: 'ECRITURE du module audit SSH', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(url)
            || /srv-zabbix/.test(corps)) {
            avortees.push({ route: chemin, motif: 'vise la PRODUCTION', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (VERS_BACKEND.test(url) || /\/ssh-audit\//.test(url)) {
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
     * ══ LA PRECONDITION : LE TRIPLET EST UN ETAT DU BANC ═════════════════
     *
     * Les libelles ci-dessous disent « admis par la PERMISSION » et « admis par
     * le ROLE ». Si `can_audit_ssh` bougeait, ils diraient encore la meme chose
     * en mesurant autre chose. On relit donc l'etat, et on refuse de conclure
     * s'il a change.
     */
    const perms = {};
    for (const cle of Object.keys(COMPTES)) {
        const c = COMPTES[cle];
        perms[c.nom] = compteEnBase(
            'SELECT COALESCE(MAX(p.can_audit_ssh), 0) FROM rootwarden.users u '
            + `LEFT JOIN rootwarden.permissions p ON p.user_id = u.id WHERE u.name = '${c.nom}'`);
    }
    constate('can_audit_ssh en base', Object.entries(perms)
        .map(([n, v]) => `${n}=${v}`).join(' · '));
    const triplet = Object.values(COMPTES).every((c) => perms[c.nom] === c.perm);
    verifie('le triplet de roles du banc est celui que les libelles decrivent',
        triplet,
        'un `can_audit_ssh` a change : les assertions garderaient leur libelle et'
        + ' mesureraient autre chose — la suite ne conclut pas',
        Object.values(COMPTES).map((c) => `${c.nom}:${c.perm}`).join(' '));
    if (! triplet) throw new Error('precondition non tenue');

    // ══ 1. LES DEUX VOIES D'ADMISSION, EXERCEES SEPAREMENT ═══════════════
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

    // ══ 2. LA PAGE, AU COMPTE ADMIS PAR LE ROLE ══════════════════════════
    const s = await connecte(COMPTES.super);
    verifie('la session a tenu', ! s.surConnexion, s.page.url());
    if (s.surConnexion) throw new Error('session non etablie');
    const page = s.page;
    await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
    await dors(900);

    await etape('le perimetre est rendu, et son etat est lisible', async () => {
        /*
         * SANS OBJET SUR LE LEGACY, ET IL FAUT LE DIRE AVANT DE TOUCHER AU DOM.
         *
         * Ses ancres ne sont pas relevees : la table des selecteurs y vaut
         * `null` partout. Sans ce garde, `page.$(C.creer)` reçoit `null` et
         * jette « Cannot read properties of null » — ce qui rend un FAIL qui
         * accuse LA PAGE alors qu'il decrit MA TABLE.
         *
         * ⚠ C'est la SECONDE fois : le meme garde existe dans
         * `go-page-mot-de-passe`, pose apres le meme plantage. **Une correction
         * appliquee a un fichier ne se propage pas au suivant** — il a fallu que
         * la faute se reproduise pour que je la reporte.
         */
        if (CIBLE !== 'laravel') {
            constate('perimetre et politiques',
                'SANS OBJET — les ancres du legacy ne sont pas relevees, rien n\'est mesure ici');

            return;
        }
        const vu = await page.evaluate((sel) => {
            const q = (s) => {
                const e = s ? document.querySelector(s) : null;

                return e === null ? null : { texte: (e.innerText || '').trim(),
                    visible: e.offsetParent !== null };
            };

            return { parc: q(sel.parc), borne: q(sel.borne), illisible: q(sel.illisible),
                aucun: q(sel.aucunServeur), lecture: q(sel.lectureSeule) };
        }, C);
        constate('perimetre', vu.parc ? `« ${vu.parc.texte.slice(0, 70).replace(/\s+/g, ' ')} »` : '(absent)');
        constate('reserve de borne', vu.borne ? 'presente' : 'absente');

        /*
         * TROIS ISSUES EXCLUSIVES, comme partout : illisible / aucun serveur /
         * la liste. « Rien lu » n'est pas « zero machine ».
         */
        const presentes = ['parc', 'illisible', 'aucun'].filter((k) => vu[k] !== null);
        verifiePortage('exactement une issue de perimetre est rendue',
            presentes.length === 1,
            presentes.length === 0 ? 'aucune des trois issues n\'est rendue'
                : `${presentes.length} issues simultanees : ${presentes.join(', ')}`);

        /*
         * LE GESTE EST OFFERT, ET C'EST LA PRECONDITION DE LA SURETE.
         *
         * Le verdict final asserte « AUCUNE planification n'a ete creee ». Si la
         * page n'offrait aucun bouton de creation, cette assertion serait vraie
         * **parce qu'il n'y a rien a cliquer** — vraie a vide, comme toute
         * universelle negative. On mesure donc que le bouton EXISTE : c'est ce
         * qui donne un objet a la retenue.
         *
         * `C.creer` etait declare et jamais lu. Une cle morte dans une table de
         * selecteurs signale presque toujours une MESURE ABSENTE, et celle-ci
         * portait la precondition d'une assertion de surete.
         */
        const creer = await page.$(C.creer);
        constate('bouton de creation de planification', creer ? 'present — NON clique' : '(absent)');
        verifiePortage('le geste de planification est OFFERT (et non exerce)',
            creer !== null,
            'aucun bouton de creation : « aucune planification creee » serait vrai a vide');

        // La page annonce sa LECTURE SEULE — sinon un exploitant cherche le
        // bouton d'ecriture et conclut a un defaut d'affichage.
        verifiePortage('la page annonce que les politiques sont en lecture seule',
            vu.lecture !== null && vu.lecture.texte !== ''
                && ! /:[a-z_]{3,}/.test(vu.lecture.texte),
            vu.lecture === null ? 'aucun enonce de lecture seule'
                : vu.lecture.texte === '' ? 'l\'enonce est rendu mais vide'
                    : `jeton non substitue : « ${vu.lecture.texte.slice(0, 50)} »`);
    });

    // ══ 3. LE TEMOIN — SANS LUI, LA SUITE NE MESURE RIEN ═════════════════
    let temoinVu = false;
    await etape('A3 : le panneau de lecture de sshd_config, et on ne confirme pas', async () => {
        if (CIBLE !== 'laravel') {
            constate('lecture de sshd_config', 'SANS OBJET — A3 n\'existe que sur le portage');

            return;
        }
        /*
         * ══ A3 — CE QUI SE MESURE SANS JOINDRE PERSONNE ══════════════════
         *
         * `POST /ssh-audit/config` OUVRE UNE SESSION SSH REELLE
         * (`ssh_audit.py`). Le geste est porte et JAMAIS exerce : son auteur
         * l'a mesure cable, et a declare lui-meme que le rendu du fichier, la
         * separation des trois issues et le cas du fichier vide sont **ECRITS
         * ET NON EPROUVES** — il faut le mot de l'exploitant pour les couvrir.
         *
         * Ce qui se mesure ici est le PANNEAU, et `ouvrePanneau` ne lit que le
         * catalogue : aucune requete ne part avant la confirmation, et cette
         * suite ne la prend jamais.
         *
         * DEUX BRANCHES, et la premiere est celle qui regresserait en silence :
         *   sans serveur choisi -> panneau ouvert, confirmation MASQUEE,
         *                          `gesteConfirme = null` — fail-closed
         *   avec un serveur     -> le panneau NOMME le serveur, confirmation
         *                          offerte
         *
         * ⛔ Le serveur choisi n'est JAMAIS `srv-zabbix`, meme pour un panneau
         *    qui ne part pas : le filet l'avorterait, mais on ne s'appuie pas
         *    sur le filet pour un choix qu'on controle.
         */
        const avantA3 = passees.length;
        const bouton = await page.$(C.config);
        if (! bouton) {
            verifie('le geste de lecture de sshd_config est OFFERT', false,
                'ancre `audit-ssh-config` absente : A3 n\'est pas rendu');

            return;
        }

        // ── a. SANS serveur : le panneau s'ouvre et REFUSE de confirmer ──
        await page.evaluate((sel) => {
            const s0 = document.querySelector(sel.serveur);
            if (s0) { s0.value = ''; s0.dispatchEvent(new Event('change', { bubbles: true })); }
        }, C);
        await dors(300);
        await bouton.click();
        await dors(700);
        const sans = await page.evaluate((sel) => {
            const p = document.querySelector(sel.panneau);
            const x = document.querySelector(sel.panneauTexte);
            const c = document.querySelector(sel.panneauConfirmer);

            return {
                ouvert: p !== null && p.offsetParent !== null,
                texte: x ? (x.innerText || '').replace(/\s+/g, ' ').trim() : '',
                confirme: c !== null && c.offsetParent !== null,
            };
        }, C);
        constate('sans serveur', `panneau ${sans.ouvert ? 'ouvert' : 'FERME'}, confirmation `
            + `${sans.confirme ? 'OFFERTE' : 'masquee'} — « ${sans.texte.slice(0, 70)} »`);
        verifiePortage('sans serveur, le panneau DIT pourquoi et ne confirme pas',
            sans.ouvert && sans.texte.length > 0 && ! /:[a-z_]{3,}/.test(sans.texte)
                && ! sans.confirme,
            ! sans.ouvert ? 'aucun panneau'
                : sans.confirme ? 'la confirmation est OFFERTE sans cible : elle ferait consentir a rien de nommable'
                    : sans.texte.length === 0 ? 'le panneau est vide' : `jeton non traduit : ${sans.texte}`);
        const fermer1 = await page.$(C.panneauFermer);
        if (fermer1) { await fermer1.click(); await dors(400); }

        // ── b. AVEC un serveur, jamais la production ────────────────────
        const opts = await page.$$eval(`${C.serveur} option`,
            (ns) => ns.map((n) => `${n.value}|${(n.textContent || '').trim()}`).filter((o) => ! o.startsWith('|')));
        constate('serveurs offerts', opts.join(' · ') || '(aucun)');
        const sur = opts.find((o) => o && ! /zabbix/i.test(o));
        if (! sur) {
            constate('panneau avec serveur',
                'SANS OBJET — aucun serveur hors production n\'est offert, et on ne choisit pas'
                + ' la production pour ouvrir un panneau');

            return;
        }
        const idSur = sur.split('|')[0];
        verifie('le serveur choisi n\'est PAS la production',
            ! /zabbix/i.test(sur) && idSur !== String(MACHINE_PRODUCTION),
            `choisi : ${sur}`, sur);
        await page.select(C.serveur, idSur);
        await dors(400);
        await bouton.click();
        await dors(800);
        const avec = await page.evaluate((sel) => {
            const p = document.querySelector(sel.panneau);
            const t = document.querySelector(sel.panneauTitre);
            const x = document.querySelector(sel.panneauTexte);
            const e = document.querySelector(sel.panneauEffets);
            const c = document.querySelector(sel.panneauConfirmer);

            return {
                ouvert: p !== null && p.offsetParent !== null,
                titre: t ? (t.innerText || '').replace(/\s+/g, ' ').trim() : '',
                texte: x ? (x.innerText || '').replace(/\s+/g, ' ').trim() : '',
                effets: e ? (e.innerText || '').replace(/\s+/g, ' ').trim() : '',
                confirme: c !== null && c.offsetParent !== null,
                libelle: c ? (c.innerText || '').trim() : '',
            };
        }, C);
        constate('avec serveur', avec.ouvert
            ? `« ${avec.titre} » — confirmation ${avec.confirme ? `offerte (« ${avec.libelle} »)` : 'ABSENTE'}`
            : 'panneau NON ouvert');
        verifiePortage('avec un serveur, le panneau porte un titre ET un texte',
            avec.ouvert && avec.titre.length > 0 && avec.texte.length > 0,
            ! avec.ouvert ? 'aucun panneau'
                : `titre ${avec.titre.length} car., texte ${avec.texte.length} car. —`
                  + ' un panneau vide fait consentir a un geste que rien ne nomme');
        /*
         * IL NOMME SA CIBLE. Un panneau qui dit « lire la configuration » sans
         * dire SUR QUOI fait consentir a un geste dont on ignore la portee —
         * et ce geste-la ouvre une session SSH.
         */
        const nomSur = sur.split('|')[1] || '';
        verifiePortage('le panneau NOMME le serveur vise',
            `${avec.titre} ${avec.texte} ${avec.effets}`.includes(nomSur.split(' ')[0]),
            `« ${nomSur} » n'apparait pas : le panneau ne dit pas sur quelle machine il porte`);
        verifiePortage('la confirmation est OFFERTE, et cette suite ne la prend PAS',
            avec.confirme && avec.libelle.length > 0,
            ! avec.confirme ? 'aucun bouton de confirmation' : 'le bouton n\'a pas de libelle');
        verifiePortage('aucun jeton non traduit dans le panneau',
            avec.titre.length > 0 && avec.texte.length > 0
                && ! /:[a-z_]{3,}/.test(`${avec.titre} ${avec.texte} ${avec.effets} ${avec.libelle}`),
            avec.titre.length === 0 || avec.texte.length === 0
                ? 'panneau vide : rien a verifier, et un vert ici serait une absence'
                : `${avec.titre} | ${avec.texte}`);

        // ── c. AU RESEAU : ouvrir le panneau ne lit rien ────────────────
        const parties = passees.slice(avantA3);
        constate('requetes de l\'etape', parties.length
            ? parties.map((p) => `${p.methode} ${p.route}`).join(' | ') : '(aucune)');
        verifie('OUVRIR le panneau n\'a declenche AUCUNE lecture distante',
            ! parties.some((p) => /\/ssh-audit\/config/.test(p.route)),
            parties.filter((p) => /\/ssh-audit\/config/.test(p.route))
                .map((p) => `${p.methode} ${p.route}`).join(' | '),
            parties.some((p) => /\/ssh-audit\/config/.test(p.route))
                ? '' : 'aucun appel a /ssh-audit/config');

        const fermer2 = await page.$(C.panneauFermer);
        if (fermer2) { await fermer2.click(); await dors(400); }
    });

    await etape('le collecteur voit un POST (temoin)', async () => {
        /*
         * On EMET un POST depuis la page, vers un chemin qui n'existe pas. S'il
         * n'apparait pas dans le collecteur, l'assertion suivante — « aucun POST
         * vers /ssh-audit » — serait vraie sans avoir rien mesure.
         *
         * `fetch` est employe ici DELIBEREMENT et ce n'est pas un clic simule :
         * le temoin ne mesure pas la page, il mesure L'INSTRUMENT. Rien dans
         * l'interface ne doit emettre ce POST, et c'est justement la propriete.
         */
        await page.evaluate(async (chemin) => {
            try { await fetch(chemin, { method: 'POST', body: 'temoin' }); } catch { /* 404 attendu */ }
        }, TEMOIN);
        await dors(500);
        temoinVu = passees.some((p) => p.methode === 'POST' && p.route.startsWith(TEMOIN));
        constate('temoin', temoinVu ? `POST ${TEMOIN} vu par le collecteur` : 'NON VU');
        verifie('le collecteur detecte un POST emis depuis la page',
            temoinVu,
            'le POST temoin n\'a pas ete vu : l\'instrument ne mesure pas les POST,'
            + ' donc l\'absence d\'appel compose ne prouverait rien');
    });

    // ══ 4. LA FERMETURE PAR L'ABSENCE, MESUREE APRES LE TEMOIN ═══════════
    await etape('aucun appel compose vers une ecriture du module', async () => {
        const ecritures = passees.filter((p) => p.methode !== 'GET' && /ssh-audit/.test(p.route));
        const avortEcr = avortees.filter((a) => /ssh-audit/.test(a.route));
        constate('requetes du module observees', passees
            .filter((p) => /ssh-audit/.test(p.route))
            .map((p) => `${p.methode} ${p.route}`).join(' | ') || '(aucune)');

        if (! temoinVu) {
            constate('fermeture par l\'absence',
                'SANS OBJET — le temoin n\'a pas ete vu, une absence de POST ne prouverait rien');

            return;
        }
        // SEC-013 : l'ecriture des politiques est MOINS gardee que leur lecture
        // cote backend. Le portage ne doit en composer aucune.
        verifie('AUCUN appel compose vers une ecriture du module audit SSH',
            ecritures.length === 0 && avortEcr.length === 0,
            [...ecritures.map((p) => `${p.methode} ${p.route} (PASSE)`),
             ...avortEcr.map((a) => `${a.route} (avorte)`)].join(' | '),
            `${passees.filter((p) => /ssh-audit/.test(p.route)).length} requete(s) du module, toutes en GET`);
    });

    await etape('aucune erreur JavaScript', async () => {
        verifie('aucune erreur JavaScript sur la page', s.erreursJs.length === 0,
            s.erreursJs.slice(0, 3).join(' | '), 'aucune');
    });

    // ══ 5. CAPTURES ══════════════════════════════════════════════════════
    await etape('captures', async () => {
        const dossier = new URL(`./screenshots/audit-ssh/${CIBLE}`, import.meta.url).pathname;
        mkdirSync(dossier, { recursive: true });
        for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                         { n: 'mobile', w: 390, h: 844 }]) {
            await page.setViewport({ width: f.w, height: f.h });
            await dors(400);
            await page.screenshot({ path: `${dossier}/as-${f.n}.png`, fullPage: true });
        }
        verifie('les trois captures sont ecrites', true, '', dossier);
    });
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
        constate('boites natives ouvertes', boites.length
            ? boites.map((b) => `${b.type} « ${b.message.slice(0, 60)} »`).join(' | ') : '(aucune)');

        if (vues === 0) {
            constate('controle de surete', 'SANS OBJET — aucune requete vue, le filet n\'a rien eu a filtrer');
        } else {
            verifie('AUCUNE requete n\'a vise la production',
                ! passees.some((p) => new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(p.route)
                    || /srv-zabbix/.test(p.corps || '')),
                'une requete a vise `srv-zabbix`', `${vues} requete(s) vue(s)`);
            // AUCUNE PLANIFICATION CREEE : le repli du scheduler prend le parc
            // entier des que la cible est vide ou non reconnue.
            verifie('AUCUNE planification n\'a ete creee',
                ! passees.some((p) => p.methode !== 'GET' && /schedule/i.test(p.route)),
                passees.filter((p) => /schedule/i.test(p.route)).map((p) => `${p.methode} ${p.route}`).join(' '),
                'aucune');
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
