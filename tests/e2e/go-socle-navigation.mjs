/**
 * go-socle-navigation.mjs - Le menu du portail porte.
 *
 * Ce que ce test regarde, et pourquoi :
 *
 *  - IL SUIT LES LIENS. Sur la tentative precedente, sept entrees de menu
 *    rendaient 404 pendant des semaines parce qu'aucune suite ne cliquait
 *    dessus. On ne teste que ce qu'on regarde.
 *  - IL COMPARE LES ROLES. Une suite qui s'authentifie en superadmin ne mesure
 *    aucun cloisonnement. Les trois comptes dedies sont utilises, et le menu
 *    doit STRICTEMENT croitre avec les droits.
 *  - IL CHERCHE LES CLES MORTES. Une cle de traduction absente n'echoue pas :
 *    elle affiche son identifiant. `nav.` visible a l'ecran est un defaut.
 *  - IL VERIFIE LE MARQUEUR DES PAGES NON PORTEES. Un lien qui change de
 *    portail sans le dire trahit l'utilisateur.
 *
 * Cible : Laravel uniquement (le legacy n'a pas ce menu porte).
 *
 * Usage :
 *   cd tests/e2e
 *   node go-socle-navigation.mjs
 */
import puppeteer from 'puppeteer';
import { execFileSync } from 'child_process';
import { createHmac } from 'crypto';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
/**
 * La base du legacy, LUE DANS LA CONFIGURATION DU PORTAGE et non ecrite en dur.
 *
 * L'ancienne valeur figee `https://localhost:8443` faisait echouer trois
 * assertions des que `LEGACY_URL` pointait ailleurs — par exemple sur l'adresse
 * de la VM, ce qu'il FAUT poser pour ouvrir les deux portails depuis un autre
 * poste : un lien « ancien portail » en localhost mene au localhost DU VISITEUR.
 *
 * Le test mesurait donc une VALEUR de deploiement la ou la propriete a verifier
 * est « l'entree vise le portail legacy, quelle que soit son adresse ». Il lit
 * desormais la meme source que la page — il ne peut plus la contredire.
 * `E2E_LEGACY` reste prioritaire pour forcer la main.
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

const COMPTES = [
    { nom: 'rw-test-user',  role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW' },
    { nom: 'rw-test-admin', role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX' },
    { nom: 'rw-test-super', role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW' },
];

/** Nombre total d'entrees declarees dans App\Support\Navigation. */
/*
 * 33 -> 32 le 2026-08-27 : la refonte du menu retire `tickets` et regroupe les
 * entrees en cinq sections (PARC & ACCES, EXPLOITATION, SECURITE,
 * ADMINISTRATION, AUTRE). Mesure : `Navigation::SECTIONS` lue par PHP lui-meme
 * rend `total=32 route=24 legacy=8 ni-l-un-ni-l-autre=0`.
 *
 * Le §2 du plan porte le meme total et se met a jour AVEC celui-ci : l'assertion
 * qui echoue le dit dans son propre detail, « ne pas ajuster l'un sans l'autre ».
 */
const TOTAL_ENTREES = 32;

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
function constate(libelle, valeur) { lignes.push(`INFO  ${libelle} : ${valeur}`); }

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
});

/** Ouvre une session complete et rend le menu observe. */
async function connecte(compte) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    page.on('dialog', d => d.dismiss().catch(() => {}));

    await page.goto(`${BASE}/connexion`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', compte.nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]');
    try { await nav; } catch {}

    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    await page.type('input[name="2fa_code"]', totp(compte.secret), { delay: 8 });
    nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]');
    try { await nav; } catch {}

    // On arrive sur les conditions d'utilisation : on les accepte pour entrer.
    if (/\/cgu/.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        // Ancrage sur le CONTRAT DOM : la page CGU porte deux boutons submit,
        // et refuser vient avant accepter.
        await page.click('[data-rw="cgu-accepter"]');
        try { await nav; } catch {}
    }

    return { ctx, page };
}

/** Releve le menu tel qu'il est RENDU, barre laterale et tiroir separement. */
async function releveMenu(page) {
    return page.evaluate(() => {
        const lire = (racine) => [...racine.querySelectorAll('.rw-menu__lien')].map(a => {
            const libelle = a.querySelector('.rw-menu__libelle');
            const marqueur = a.querySelector('.rw-menu__marqueur');
            return {
                libelle: (libelle?.textContent || '').trim(),
                href: a.getAttribute('href') || '',
                externe: a.classList.contains('rw-menu__lien--externe'),
                marqueur: (marqueur?.textContent || '').trim(),
                cible: a.getAttribute('target') || '',
                // Geometrie reelle : un marqueur declare mais large de zero ne
                // previent personne, et un libelle tronque a l'ecran ne se voit
                // pas dans le HTML. On mesure ce qui est RENDU.
                largeurMarqueur: marqueur ? Math.round(marqueur.getBoundingClientRect().width) : -1,
                libelleTronque: libelle ? libelle.scrollWidth > libelle.clientWidth + 1 : false,
                debordeLien: a.scrollWidth > a.clientWidth + 1,
            };
        });
        const laterale = document.querySelector('.rw-laterale .rw-menu');
        const tiroir = document.querySelector('.rw-tiroir__panneau');

        return {
            laterale: laterale ? lire(laterale) : [],
            tiroir: tiroir ? lire(tiroir) : [],
            sections: [...document.querySelectorAll('.rw-laterale .rw-menu__section')].map(s => s.textContent.trim()),
            texteEntier: document.body.innerText,
        };
    });
}

try {
    const vus = [];

    for (const compte of COMPTES) {
        // Fenetre TOTP distincte entre deux comptes n'est pas necessaire (les
        // comptes different), mais on evite de coller deux connexions.
        const { ctx, page } = await connecte(compte);

        if (! /\/accueil/.test(page.url())) {
            verifie(`${compte.nom} : arrive sur l'accueil`, false, page.url().replace(BASE, ''));
            await ctx.close();
            continue;
        }

        const menu = await releveMenu(page);
        vus.push({ compte, menu });

        /*
         * ══ LA MARGE DE DEFILEMENT COUVRE-T-ELLE L'EN-TETE COLLANT ? ═══════
         *
         * Propriete du SOCLE, mesuree une seule fois — sur le premier compte,
         * puisque `.rw-entete` et `html` ne dependent pas du role.
         *
         * VENUE D'E-241 : un bouton amene par `scrollIntoView` arrivait SOUS
         * l'en-tete collant, et le clic atteignait l'en-tete. `elementFromPoint`
         * l'a nomme. Le correctif est `scroll-padding-top`, et il couvre les
         * DOUZE `scrollIntoView` du portage — dont huit en `block: 'nearest'`,
         * qui posent l'element au bord haut.
         *
         * POURQUOI CETTE MESURE EXISTE : le jeton est un NOMBRE, `.rw-entete`
         * n'a pas de hauteur explicite, et **rien dans le CSS ne relie les
         * deux** — le commentaire du socle le dit. La premiere valeur posee,
         * 64 px, etait deduite d'une lecture (~44 px estimes) et **ne couvrait
         * pas les 65 px reellement rendus**. L'ecart etait d'un pixel ; ce qui
         * comptait est que *la valeur n'etait pas derivee*, et qu'aucun oeil ne
         * remesure un nombre qui a l'air juste. **La derivation vit donc ICI, et
         * nulle part ailleurs.**
         *
         * Une hauteur explicite sur l'en-tete ne fermerait rien : `min-height`
         * l'empeche de RAPETISSER, pas de GRANDIR — or c'est grandir qui rend la
         * marge courte. Et la contraindre couperait un titre long, `$titre`
         * dependant de la page.
         */
        if (vus.length === 1) {
            const geo = await page.evaluate(() => {
                const e = document.querySelector('.rw-entete');

                return {
                    entete: e ? Math.round(e.getBoundingClientRect().height) : null,
                    collant: e ? getComputedStyle(e).position : null,
                    marge: parseInt(getComputedStyle(document.documentElement).scrollPaddingTop, 10) || 0,
                };
            });
            constate('en-tete collante', geo.entete === null ? '(absente)'
                : `hauteur RENDUE ${geo.entete}px · position ${geo.collant}`);
            constate('marge de defilement du socle', `${geo.marge}px`);
            // La propriete porte sa precondition : sans en-tete collante elle
            // n'aurait aucun objet et se verifierait sur rien.
            const couvre = geo.entete !== null && /sticky|fixed/.test(geo.collant || '')
                && geo.marge >= geo.entete;
            verifie('la marge de defilement couvre la hauteur de l\'en-tete',
                couvre,
                couvre ? `marge ${geo.marge}px >= en-tete ${geo.entete}px`
                    : geo.entete === null
                        ? 'aucune `.rw-entete` rendue — la mesure n\'a pas eu lieu'
                        : ! /sticky|fixed/.test(geo.collant || '')
                            ? `en-tete en \`${geo.collant}\` : elle ne recouvre rien`
                            : `marge ${geo.marge}px < en-tete ${geo.entete}px — tout element amene `
                              + 'par `scrollIntoView` arrivera SOUS l\'en-tete, a moitie cache');
        }

        // ── Le menu est rendu DEUX FOIS mais depuis UNE SEULE source ────────
        // On compare les ENTREES, pas leur geometrie : le tiroir est ferme
        // (display:none), donc de largeur nulle. Comparer la geometrie, ce
        // serait faire dependre l'assertion d'une forme qui n'est pas son objet.
        const sansGeometrie = liste => liste.map(e =>
            [e.libelle, e.href, e.externe, e.marqueur, e.cible].join('|'));
        const memeMenu = JSON.stringify(sansGeometrie(menu.laterale))
                      === JSON.stringify(sansGeometrie(menu.tiroir));
        verifie(`${compte.nom} : barre laterale et tiroir rendent les MEMES entrees`,
                memeMenu, `laterale=${menu.laterale.length} tiroir=${menu.tiroir.length}`);

        // ── Aucune cle de traduction morte ──────────────────────────────────
        const clesMortes = menu.laterale.filter(e => /^(nav|auth)\./.test(e.libelle)).map(e => e.libelle);
        verifie(`${compte.nom} : aucune cle de traduction morte dans le menu`,
                clesMortes.length === 0, clesMortes.join(', ') || 'aucune');
        verifie(`${compte.nom} : aucune cle morte ailleurs dans la page`,
                ! /\b(nav|auth)\.[a-z_]{3,}/.test(menu.texteEntier));

        // ── Les liens non portes le DISENT ──────────────────────────────────
        const externes = menu.laterale.filter(e => e.externe);
        const mal = externes.filter(e => ! e.href.startsWith(LEGACY) || e.cible !== '_blank' || e.marqueur === '');
        verifie(`${compte.nom} : chaque entree non portee vise le legacy, en nouvel onglet, avec son marqueur`,
                mal.length === 0, `${externes.length} externes, ${mal.length} incorrectes`);

        // Le marqueur doit etre VISIBLE, pas seulement present dans le HTML.
        const marqueursEcrases = externes.filter(e => e.largeurMarqueur <= 0);
        verifie(`${compte.nom} : le marqueur « non porte » est visible a l'ecran`,
                marqueursEcrases.length === 0,
                `${marqueursEcrases.length} ecrase(s) sur ${externes.length}`);

        // Aucun lien ne doit deborder de sa colonne.
        const debordent = menu.laterale.filter(e => e.debordeLien).map(e => e.libelle);
        verifie(`${compte.nom} : aucune entree ne deborde de la barre laterale`,
                debordent.length === 0, debordent.join(', ') || 'aucune');

        const tronques = menu.laterale.filter(e => e.libelleTronque).map(e => e.libelle);
        if (tronques.length) constate(`${compte.nom} : libelles tronques (title present)`, tronques.join(', '));

        // ── Les liens portes RESOLVENT (le piege des sept 404) ──────────────
        const internes = menu.laterale.filter(e => ! e.externe);
        for (const e of internes) {
            const rep = await page.goto(e.href, { waitUntil: 'networkidle2' });
            const statut = rep ? rep.status() : 0;
            verifie(`${compte.nom} : le lien porte « ${e.libelle} » resout`,
                    statut === 200 && ! /\/connexion/.test(page.url()),
                    `${statut} ${page.url().replace(BASE, '')}`);
        }

        constate(`${compte.nom} (role ${compte.role})`,
                 `${menu.laterale.length} entrees · ${internes.length} portees · ${externes.length} vers le legacy · sections : ${menu.sections.join(', ') || 'aucune'}`);

        await ctx.close();
    }

    // ── Le menu croit STRICTEMENT avec les droits ───────────────────────────
    if (vus.length === 3) {
        const [u, a, s] = vus.map(v => v.menu.laterale.length);
        verifie('le menu croit strictement avec les droits (role 1 < role 2 < role 3)',
                u < a && a < s, `${u} < ${a} < ${s}`);

        verifie('le superadmin voit toutes les entrees declarees',
                s === TOTAL_ENTREES, `${s} sur ${TOTAL_ENTREES}`);

        /* ══ LE TOTAL SE RECONSTITUE-T-IL ? ═══════════════════════════════
         *
         * Personne ne le verifiait, et le decompte a derive : un relevé du
         * 2026-08-26 ne retrouvait que 32 entrees sur 33 — son motif de lecture
         * exigeait la forme sur une seule ligne, et `wazuh`, ecrit autrement,
         * lui echappait. La derive etait inoffensive ; rien ne l'aurait dit.
         *
         * ON NE COMPTE PAS A L'EXPRESSION REGULIERE. La constante est lue PAR
         * PHP, dans le conteneur : un tableau PHP lu par PHP n'a aucun angle
         * mort, la ou tout motif en a un. Meme raison que pour la parite i18n —
         * analyser du PHP a la regex revient a reecrire un interpreteur, et une
         * entree mal lue est declaree absente a tort.
         *
         * ET ON ASSERTE LE ZERO, PAS SEULEMENT LA SOMME. `route + legacy == 33`
         * passerait encore si une entree perdait ses deux cles pendant qu'une
         * autre en gagnait deux. C'est `niLunNiLautre === 0` qui ferme le cas,
         * et c'est l'invariant du projet : chaque entree porte `route` OU
         * `legacy`, jamais les deux, jamais aucun.
         */
        let compte = null;
        try {
            const brut = execFileSync('docker', ['exec', 'rootwarden_laravel', 'php', '-r',
                'require "/var/www/html/vendor/autoload.php";'
                + '$app = require "/var/www/html/bootstrap/app.php";'
                + '$t=0;$r=0;$l=0;$n=0;'
                + 'foreach (App\\Support\\Navigation::SECTIONS as $es) { foreach ($es as $e) {'
                + '$t++; if (isset($e["route"])) $r++; elseif (isset($e["legacy"])) $l++; else $n++; } }'
                + 'echo json_encode(["total"=>$t,"route"=>$r,"legacy"=>$l,"ni"=>$n]);',
            ], { encoding: 'utf8' });
            compte = JSON.parse(brut.trim());
        } catch (e) {
            verifie('la constante Navigation::SECTIONS est lisible', false,
                String(e.message || e).split('\n')[0]);
        }

        if (compte !== null) {
            constate('entrees declarees', `total=${compte.total} route=${compte.route} `
                + `legacy=${compte.legacy} ni-l-un-ni-l-autre=${compte.ni}`);

            verifie('chaque entree porte `route` OU `legacy`, jamais aucun des deux',
                compte.ni === 0,
                `${compte.ni} entree(s) sans route ni legacy — l'etat du portage ne se lit `
                + 'plus d\'un coup d\'oeil, et le total ne veut plus rien dire');

            verifie('le total se reconstitue : route + legacy = total',
                compte.route + compte.legacy === compte.total,
                `${compte.route} + ${compte.legacy} = ${compte.route + compte.legacy}, `
                + `attendu ${compte.total}`);

            /* LE 33 EST UN CHIFFRE DE FLOTTE, PAS UNE CONSTANTE DE TEST. Le jour
             * ou une entree de menu est ajoutee, cette assertion DOIT echouer —
             * c'est ce qu'on veut. Le message le dit, sinon quelqu'un ajustera
             * le nombre sans se demander pourquoi il a bouge. */
            verifie('le nombre d\'entrees declarees vaut celui du plan',
                compte.total === TOTAL_ENTREES,
                `${compte.total} declarees contre ${TOTAL_ENTREES} attendues — si une entree a `
                + 'ete AJOUTEE ou RETIREE, c\'est normal : mettre a jour `TOTAL_ENTREES` ICI **et** '
                + 'le tableau d\'etat du §2 du plan. Ne pas ajuster l\'un sans l\'autre');

            /* Le rendu au role 3 doit egaler la declaration : une entree
             * declaree mais jamais rendue serait invisible a toute autre
             * mesure de cette suite. */
            verifie('le superadmin voit AUTANT d\'entrees que la constante en declare',
                s === compte.total, `${s} rendues, ${compte.total} declarees`);
        }

        // Un role sans permission ne doit voir AUCUNE entree d'administration.
        const sectionsRole1 = vus[0].menu.sections.map(x => x.toLowerCase());
        verifie('un role sans permission ne voit pas la section administration',
                ! sectionsRole1.some(x => /admin/.test(x)), sectionsRole1.join(', ') || 'aucune section');

        // Ce que le role 1 voit doit etre un SOUS-ENSEMBLE de ce que voit le role 3.
        const libelles = v => new Set(v.menu.laterale.map(e => e.libelle));
        const sousEnsemble = [...libelles(vus[0])].every(l => libelles(vus[2]).has(l));
        verifie('ce que voit le role 1 est un sous-ensemble de ce que voit le superadmin', sousEnsemble);
    }
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
