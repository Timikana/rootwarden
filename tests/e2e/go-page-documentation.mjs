/**
 * go-page-documentation.mjs — le guide porte : une page sans garde de role, et
 * des liens DERIVES du menu plutot que d'un seuil.
 *
 * legacy   `/documentation.php`            portage  `/documentation`
 *
 * ══ UNE PAGE OUVERTE A TOUS, ET C'EST LA PROPRIETE ════════════════════════
 *
 * `legacy/documentation.php:11` pose `checkAuth([1,2,3])` et **aucun** controle
 * de plus. La route portee ne porte donc NI `role:` NI `perm:` : le seuil vit
 * DANS la page (`$role >= 2` enclot six blocs), pas devant elle.
 *
 * **Les trois roles doivent donc obtenir 200.** Une suite qui n'exercerait que
 * le role 3 ne verrait pas qu'une garde a ete ajoutee par erreur — et sur cette
 * page-la, l'ajouter serait plausible : toutes ses voisines en ont une.
 *
 * ══ LE LIEN DERIVE : « PRESENT SSI ACCESSIBLE », PAS « ROLE 3 » ═══════════
 *
 * `doc-derive-lien` pointe l'entree **`api_docs`** — route
 * `autorisations-passerelle`, garde `sa` (superadmin). ⚠ **« derive » est ici le
 * participe passe de DERIVER, pas le module « derive de configuration »** : le
 * controleur fait `firstWhere('cle', 'api_docs')`. Un instrument qui viserait
 * `/derive-config` mesurerait l'entree `drift` (garde `can_view_compliance`),
 * presente des le role 2 — et accuserait le portage d'une incoherence qui
 * n'existe pas. Le controleur ne teste PAS `role >= 3` : il derive du MENU —
 *
 *     'lienDerive' => $derive !== null && isset($derive['route']) ? route(...) : null
 *     $entrees = Navigation::pour($role, $this->droits->permissions($idCompte))
 *
 * et son commentaire dit pourquoi : *conditionner ce lien au seuil de la page
 * (`role >= 2`) offrirait a un role 2 une porte qui refuse, et poser `role >= 3`
 * en dur ici recopierait la garde.* **Deux copies d'une regle de droits finissent
 * par diverger** — c'est le motif que ce portage refuse partout.
 *
 * ⚠ **LA SUITE MESURE DONC LA DERIVATION, PAS LE SEUIL.** Elle compare la
 * presence du lien a la presence de l'entree DANS LE MENU du meme compte. Une
 * assertion « present au role 3, absent ailleurs » serait verte aujourd'hui **et
 * fausse demain** : elle recopierait la garde une troisieme fois, dans le test.
 *
 * ══ DEUX ANCRES CONDITIONNELLES, ET LEUR ABSENCE EST LA CONDITION ═════════
 *
 *     doc-console       role >= 2   (`$administration`)
 *     doc-derive-lien   derive du menu
 *
 * **Si une suite les attend plus bas, elle mesure un defaut qui a ete retire** :
 * le lien avait ete conditionne au seuil de la page, et un role 2 recevait une
 * porte qui refuse. Leur absence au role 1 n'est pas un trou de couverture.
 *
 * ══ CE QUE LA PAGE NE FAIT PAS ════════════════════════════════════════════
 *
 * Elle **ne fait aucune requete** : tout ce qu'elle affirme sur les routes, les
 * roles et les gardes est ecrit dans la vue et le catalogue. La suite le mesure
 * au RESEAU — une page qui ne doit rien demander se verifie par « rien n'est
 * parti », jamais par « il n'y a pas de bouton ».
 *
 * ⚠ **Le guide a reçu ses accents le 2026-09-02** (22 chaines : « securisation »
 * -> « sécurisation »). C'est une correction de CONTENU, pas de portage : **un
 * controle qui comparerait les textes des deux portails sur ce module
 * divergerait, et ce serait voulu.** Aucune assertion ici ne compare les deux.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase } from './lib-base.mjs';
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

/* Secrets RELEVES dans les suites du depot, jamais inventes. */
const COMPTES = {
    user:  { nom: 'rw-test-user',  role: 1,
        secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW' },
    admin: { nom: 'rw-test-admin', role: 2,
        secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX' },
    super: { nom: 'rw-test-super', role: 3,
        secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW' },
};

/* Les ancres rendues QUEL QUE SOIT le role. */
const INCONDITIONNELLES = ['doc-seuil', 'doc-guide', 'doc-securite',
                           'doc-reste-perime', 'doc-reste-cache', 'doc-reste-lien'];
/* Le seuil interne de la page : `$administration = $role >= 2`. */
const SEUIL_ADMIN = 2;
const VERS_BACKEND = /\/(api\/gateway|api_proxy\.php)\//;

const C = CIBLE === 'laravel'
    ? { connexion: '/connexion', page: '/documentation',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]' }
    : { connexion: '/auth/login.php?lang=fr', page: '/documentation.php',
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
        const chemin = r.url().replace(/^https?:\/\/[^/]+/, '');
        if (VERS_BACKEND.test(r.url())) passees.push({ route: chemin, methode: r.method() });
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

const ancresParRole = {};

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

    for (const cle of ['user', 'admin', 'super']) {
        const compte = COMPTES[cle];
        await etape(`documentation au role ${compte.role} (${compte.nom})`, async () => {
            const s = await connecte(compte);
            try {
                verifie(`${compte.nom} : la session a tenu`, ! s.surConnexion, s.page.url());
                if (s.surConnexion) return;

                const rep = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
                const statut = rep ? rep.status() : 0;
                constate(`${compte.nom} : statut`, String(statut));
                /*
                 * AUCUNE GARDE DE ROLE : le legacy pose `checkAuth([1,2,3])`, le
                 * portage ne pose ni `role:` ni `perm:`. Les trois doivent
                 * obtenir 200 — et sur une page dont TOUTES les voisines portent
                 * une garde, en ajouter une par erreur est plausible.
                 */
                verifie(`${compte.nom} (role ${compte.role}) obtient la page`, statut === 200,
                    `statut ${statut} — cette page n'a NI role: NI perm:, le seuil vit DEDANS`);
                if (statut !== 200) return;

                const vu = await s.page.evaluate((incond) => {
                    const q = (cle) => document.querySelector(`[data-rw="${cle}"]`) !== null;
                    const ancres = [...document.querySelectorAll('[data-rw^="doc-"]')]
                        .map((e) => e.getAttribute('data-rw'));

                    return {
                        toutes: ancres,
                        manquantes: incond.filter((c) => ! q(c)),
                        console: q('doc-console'),
                        derive: q('doc-derive-lien'),
                        deriveReserve: q('doc-derive-reserve'),
                        /*
                         * L'entree du MENU vers LA MEME PAGE, chez le meme compte.
                         *
                         * ⚠ C'est `api_docs` -> `autorisations-passerelle`, PAS
                         * `derive-config`. Premiere redaction : je cherchais
                         * `/derive-config` parce que la variable du controleur
                         * s'appelle `$derive` et les ancres `doc-derive-*`.
                         * **« derive » y signifie DERIVE (participe passe), pas
                         * « derive de configuration ».** Le controleur fait
                         * `firstWhere('cle', 'api_docs')`.
                         *
                         * Resultat : l'entree `drift` (garde `can_view_compliance`)
                         * est presente au role 2, donc l'assertion accusait le
                         * portage d'une incoherence qui n'existait pas.
                         */
                        entreeDerive: [...document.querySelectorAll('a[href]')]
                            .some((a) => /\/autorisations-passerelle$/.test(a.getAttribute('href') || '')),
                        corps: (document.body.innerText || '').trim(),
                    };
                }, INCONDITIONNELLES);

                ancresParRole[compte.role] = vu.toutes.length;
                constate(`${compte.nom} : ancres doc-*`, `${vu.toutes.length} — ${vu.toutes.join(', ')}`);

                /*
                 * `verifiePortage`, PAS `verifie` : le legacy ne porte AUCUNE
                 * ancre `doc-*` (mesure : 0 sur les trois roles). Un `verifie`
                 * y rendait trois FAIL qui accusaient LE LEGACY d'un manque
                 * d'outillage, pas d'un defaut.
                 *
                 * ⚠ TROISIEME OCCURRENCE de ce meme oubli — apres
                 * `go-page-accueil` et `go-page-audit-ssh`. **Une correction
                 * appliquee a un fichier ne se propage pas au suivant**, et il
                 * ne suffit pas de la connaitre : il faut la chercher a chaque
                 * table de selecteurs qui porte des `null`.
                 */
                verifiePortage(`${compte.nom} : les ancres inconditionnelles sont rendues`,
                    vu.manquantes.length === 0,
                    `manquantes : ${vu.manquantes.join(', ')}`);

                // LE SEUIL INTERNE, mesure contre le role.
                verifiePortage(`${compte.nom} : la console est ${compte.role >= SEUIL_ADMIN ? 'rendue' : 'absente'}`,
                    vu.console === (compte.role >= SEUIL_ADMIN),
                    compte.role >= SEUIL_ADMIN
                        ? 'absente alors que le seuil interne est role >= 2'
                        : 'rendue a un role 1 — le seuil interne ne tient pas');

                /*
                 * LA DERIVATION, ET NON LE SEUIL. On compare la presence du lien
                 * a la presence de l'entree DANS LE MENU du meme compte. Ecrire
                 * « present au role 3 » recopierait la garde une troisieme fois,
                 * et serait vert aujourd'hui, faux le jour ou `derive-config`
                 * change de garde.
                 */
                constate(`${compte.nom} : lien derive / entree de menu`,
                    `${vu.derive ? 'lien' : 'pas de lien'} · ${vu.entreeDerive ? 'entree presente' : 'pas d\'entree'}`);
                verifiePortage(`${compte.nom} : le lien derive suit le MENU, pas un seuil`,
                    vu.derive === vu.entreeDerive,
                    vu.derive
                        ? 'un lien est offert alors que l\'entree n\'est pas au menu — une porte qui refuse'
                        : 'l\'entree est au menu et le lien manque — la derivation ne suit pas');

                // AUCUN JETON NON SUBSTITUE.
                const jetons = (vu.corps.match(/\b(documentation|nav)\.[a-z0-9_]{3,}\b/g) || []);
                verifie(`${compte.nom} : aucun jeton de catalogue non substitue`,
                    jetons.length === 0,
                    `${[...new Set(jetons)].slice(0, 4).join(', ')}`);

                verifie(`${compte.nom} : aucune erreur JavaScript`, s.erreursJs.length === 0,
                    s.erreursJs.slice(0, 3).join(' | '), 'aucune');

                if (compte.role === 3) {
                    const dossier = new URL(`./screenshots/documentation/${CIBLE}`, import.meta.url).pathname;
                    mkdirSync(dossier, { recursive: true });
                    for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                                     { n: 'mobile', w: 390, h: 844 }]) {
                        await s.page.setViewport({ width: f.w, height: f.h });
                        await dors(400);
                        await s.page.screenshot({ path: `${dossier}/doc-${f.n}.png`, fullPage: true });
                    }
                    verifie('les trois captures sont ecrites', true, '', dossier);
                }
            } finally {
                try { await s.ctx.close(); } catch { /* deja ferme */ }
            }
        });
        await dors((resteFenetre() + 1) * 1000);
    }

    // ══ LA CROISSANCE STRICTE, MESUREE SUR LES TROIS ═════════════════════
    await etape('le contenu croit strictement avec le role', async () => {
        const [u, a, s] = [1, 2, 3].map((r) => ancresParRole[r]);
        constate('ancres par role', `role1=${u} role2=${a} role3=${s}`);
        if ([u, a, s].some((v) => v === undefined)) {
            constate('croissance',
                'SANS OBJET — un role n\'a pas rendu la page, il n\'y a rien a comparer');

            return;
        }
        /*
         * `u < a < s` STRICT, et non `<=`. Une egalite signifierait qu'un seuil
         * ne mord pas — c'est-a-dire qu'un role voit ce qu'il ne devrait pas, ou
         * qu'une section a cesse d'etre conditionnee. Les deux sont des defauts,
         * et `<=` les laisserait passer.
         */
        verifiePortage('le nombre d\'ancres croit STRICTEMENT (role 1 < 2 < 3)',
            u < a && a < s, `${u} < ${a} < ${s} n'est pas verifie`);
    });
} catch (e) {
    // `__archivee__` n'est pas une panne : c'est la sortie NORMALE quand le
    // sujet legacy a ete archive. Le constat a deja tout dit.
    if (String(e && e.message || e).includes('__archivee__')) { /* rien a ajouter */ } else {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
    }
} finally {
    try {
        constate('requetes vers le backend', passees.length
            ? passees.map((p) => `${p.methode} ${p.route}`).join(' | ') : '(aucune)');
        if (vues === 0) {
            constate('controle', 'SANS OBJET — aucune requete vue, rien n\'a ete mesure au reseau');
        } else {
            /*
             * LA PAGE NE DEMANDE RIEN. Son en-tete de controleur l'affirme :
             * « elle ne fait aucune requete ». On le mesure au RESEAU plutot que
             * de le croire — une page qui ne doit rien demander se verifie par
             * « rien n'est parti », jamais par « il n'y a pas de bouton ».
             */
            /*
             * ⚠ LE DETAIL « TOUJOURS » ETAIT UNE CHAINE LITTERALE : j'y avais
             * ecrit « 0 vers le backend » en dur. Sur le legacy, la mesure a
             * rendu **FAIL … 119 requete(s) vue(s), 0 vers le backend** — un
             * detail qui AFFIRME la propriete que le verdict vient de refuter,
             * et qui envoie chercher au mauvais endroit.
             *
             * C'est la faute deja corrigee six fois sur ce depot, commise ici
             * en dur plutot que par une condition mal placee. Le compte est
             * desormais CALCULE, et il ne sort que sur le verdict qu'il decrit.
             *
             * Et `verifiePortage` : « ne rien demander au backend » est une
             * propriete du PORTAGE, dont le controleur l'affirme. Le legacy
             * appelle son proxy, et ce n'est pas un defaut de sa part.
             */
            verifiePortage('la page de documentation ne demande RIEN au backend',
                passees.length === 0,
                `${passees.length} requete(s) vers le backend : `
                + passees.map((p) => `${p.methode} ${p.route}`).slice(0, 4).join(' | '));
        }
    } catch (e) { note(`FAIL  controle : ${e.message}`); echecs += 1; }
    for (const c of contextes) { try { await c.close(); } catch { /* deja ferme */ } }
    try { await navigateur.close(); } catch { /* deja ferme */ }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
