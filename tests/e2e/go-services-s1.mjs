/**
 * go-services-s1.mjs - Sous-lot S1 de `services/` : la page, ses gardes, ses filtres.
 *
 * `legacy/services/index.php` (199 l.), `legacy/services/js/main.js` (432 l.).
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/services/
 *   laravel  http://localhost:8444/services   (pas encore porte)
 *
 * ══ LE TRIPLE CHEMIN DE GARDE, ET IL DIFFERE DE CELUI DE `bashrc/` ═══════
 *
 * La page porte `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` — elle
 * admet donc **le role 1** — ET `checkPermission('can_manage_services')`.
 *
 * Releve en base au 2026-08-27, et c'est ce qui rend les trois chemins
 * mesurables :
 *
 *   rw-test-user   role 1, SANS la permission  -> REFUSE (le role 1 ne contourne pas)
 *   rw-test-admin  role 2, AVEC la permission  -> ADMIS  (par la permission)
 *   rw-test-super  role 3, SANS la permission  -> ADMIS  (par le contournement de role)
 *
 * Les deux derniers sont admis pour des raisons DIFFERENTES, et c'est la seule
 * facon de distinguer « la garde laisse passer parce que la permission est la »
 * de « parce que le role l'emporte ».
 *
 * ══ CE QUE S1 NE MESURE PAS, ET POURQUOI ═════════════════════════════════
 *
 * **E-149 reste un constat de LECTURE.** Les huit routes backend n'ont ni
 * `@require_role` ni `@require_permission`, et `/services/` est absent des deux
 * listes « admin ». Mais le demontrer au navigateur exigerait un compte de role
 * 2 SANS la permission — or le seul role 2 du parc la detient, et le role 1 qui
 * ne l'a pas est arrete par `@require_machine_access`, qui pour lui n'est PAS
 * inerte (aucune machine dans `user_machine_access`).
 *
 * Le trou est donc reel dans le code et non demontrable avec les comptes
 * existants. Le fabriquer — retirer une permission a un compte d'epreuve —
 * modifierait un compte que la convention D-5 protege. **On dit ce qu'on a lu,
 * on ne le maquille pas en mesure.**
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * S1 ne mesure que la page. Toutes les routes `/services/*` sont AVORTEES :
 * `list` et `status` ouvrent une session SSH (ce sera S2), et les cinq autres
 * modifient l'etat de services reels (S3).
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-services-s1
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

/**
 * Les trois comptes et leur attendu. Les secrets ne sont jamais inventes : ce
 * sont ceux qu'emploient les trente autres suites du depot.
 */
const COMPTES = [
    { nom: 'rw-test-user',  role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW',
      admis: false, motif: 'le role 1 ne contourne pas la permission' },
    { nom: 'rw-test-admin', role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX',
      admis: true,  motif: 'il DETIENT `can_manage_services`' },
    { nom: 'rw-test-super', role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW',
      admis: true,  motif: 'le role 3 contourne, SANS detenir la permission' },
];
const COMPTE_CAPTURES = 'rw-test-super';

/** Aucune route du module ne part : `list`/`status` sont S2, le reste S3. */
const ROUTES_MODULE = /\/services\/(list|status|logs|start|stop|restart|enable|disable)(\?|$)/;

const DOSSIER_CAPTURES = new URL('./screenshots/services', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/services',
        serveur: '[data-rw="services-serveur"]',
        filtreEtat: '[data-rw="services-filtre-etat"]',
        filtreCategorie: '[data-rw="services-filtre-categorie"]',
        recherche: '[data-rw="services-recherche"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/services/',
        serveur: '#server',
        filtreEtat: '#filter-status',
        filtreCategorie: '#filter-category',
        recherche: '#filter-search',
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

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
function verifiePortage(l, ok, d, __quatrieme) {
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

    if (CIBLE === 'laravel') return verifie(l, ok, ok ? '' : d);
    constate(l, ok ? 'verifie sur le legacy aussi' : `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];
const avortees = [];

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(45000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => { try { await d.dismiss(); } catch {} });

    // LE FILET vise les NOMS DE ROUTES, pas le prefixe du module : `/services/`
    // est aussi le chemin de LA PAGE, et l'avorter tuerait la suite avant toute
    // mesure. Piege paye en B2.
    await page.setRequestInterception(true);
    page.on('request', (r) => {
        if (ROUTES_MODULE.test(r.url())) {
            avortees.push(`${r.method()} ${r.url().replace(/^https?:\/\/[^/]+/, '')}`);
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        r.continue().catch(() => {});
    });

    await page.goto(`${BASE}${C.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    for (let essai = 0; essai < 2; essai += 1) {
        const champ = await page.$('input[name="2fa_code"]');
        if (! champ) break;
        if (essai > 0) await dors((resteFenetre() + 1) * 1000);
        await champ.click({ clickCount: 3 });
        await champ.type(totp(secret), { delay: 8 });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
    }
    if (C.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$(C.accepte);
        if (b) await b.evaluate((x) => x.click());
        try { await nav; } catch {}
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
    // ══ 1. LA PRECONDITION, MESUREE AVANT LES TROIS CHEMINS ═══════════════
    //
    // Les attendus dependent de QUI detient la permission. Si elle changeait de
    // mains, deux des trois attendus deviendraient faux sans que rien ne le
    // signale — la suite passerait au vert en mesurant autre chose.
    const detenteurs = litEnBase(
        'SELECT u.name FROM rootwarden.users u JOIN rootwarden.permissions p ON p.user_id = u.id '
        + "WHERE p.can_manage_services = 1 AND u.name LIKE 'rw-test-%' ORDER BY u.name");
    constate('comptes d\'epreuve detenant `can_manage_services`', detenteurs.join(', ') || '(aucun)');
    verifie('seul `rw-test-admin` detient la permission',
        detenteurs.length === 1 && detenteurs[0] === 'rw-test-admin',
        `detenteurs : ${detenteurs.join(', ') || 'aucun'} — les attendus ci-dessous ne valent plus`);

    for (const compte of COMPTES) {
        await etape(`garde : ${compte.nom} (role ${compte.role})`, async () => {
            const s = await connecte(compte.nom, compte.secret);
            try {
                verifie(`${compte.nom} : la session a tenu`, ! s.surConnexion, s.page.url());
                if (s.surConnexion) return;
                const rep = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
                const statut = rep ? rep.status() : 0;
                constate(`${compte.nom} : statut`, `${statut} — ${compte.motif}`);
                verifie(`${compte.nom} (role ${compte.role}) est ${compte.admis ? 'admis' : 'refuse'}`,
                    compte.admis ? statut === 200 : statut === 403, `statut ${statut}`);
            } finally {
                await s.ctx.close();
            }
        });
        // Le garde anti-rejeu TOTP est par COMPTE et EN BASE : il traverse les
        // contextes de navigateur.
        await dors((resteFenetre() + 1) * 1000);
    }

    // ══ 2. LA PAGE, AU COMPTE QUI Y ACCEDE ════════════════════════════════
    const s = await connecte(COMPTE_CAPTURES, COMPTES[2].secret);
    const { page, erreursJs } = s;
    verifie('la session de capture a tenu', ! s.surConnexion, page.url());

    await etape('le selecteur de serveur et les trois filtres sont la', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const vu = await page.evaluate((sels) => {
            // PRESENCE **ET** VISIBILITE. Un element present dans le DOM mais
            // masque passe une assertion d'existence sans rien montrer, et ne
            // recoit pas les frappes — piege paye en S3 du module `security/`.
            // Ici les filtres existent des le chargement mais ne paraissent
            // qu'une fois un serveur charge : la nuance appartient au portage.
            const etat = (s) => {
                const e = document.querySelector(s);

                return { present: e !== null, visible: e !== null && e.offsetParent !== null };
            };
            const sel = document.querySelector(sels.serveur);
            const journaux = document.querySelector('#logs-container, [data-rw="services-journaux"]');

            return {
                serveur: sel !== null,
                machines: sel ? [...sel.options].map((o) => (o.textContent || '').trim()).filter(Boolean) : [],
                filtres: {
                    etat: etat(sels.filtreEtat),
                    categorie: etat(sels.filtreCategorie),
                    recherche: etat(sels.recherche),
                },
                // Le panneau de journaux est-il montre AVANT tout geste ? Le
                // legacy affiche un cadre noir vide au chargement.
                journauxVides: journaux !== null && journaux.offsetParent !== null
                    && (journaux.textContent || '').trim().length === 0,
            };
        }, C);
        constate('machines proposees', vu.machines.join(' · ') || '(aucune)');
        verifie('le selecteur de serveur est present', vu.serveur);
        const f = vu.filtres;
        verifie('les trois filtres sont presents',
            f.etat.present && f.categorie.present && f.recherche.present,
            `etat=${f.etat.present} categorie=${f.categorie.present} recherche=${f.recherche.present}`);
        constate('filtres VISIBLES au chargement',
            `etat=${f.etat.visible} categorie=${f.categorie.visible} recherche=${f.recherche.visible}`);

        // UN PANNEAU DE JOURNAUX VIDE, MONTRE AVANT TOUT GESTE. Ce n'est pas un
        // defaut de fonctionnement — c'est un cadre noir qui ne dit rien, la ou
        // la convention du chantier veut qu'un etat vide DISE ce qui manque et
        // pourquoi. Constat pour le portage.
        constate('panneau de journaux vide affiche au chargement',
            vu.journauxVides ? 'OUI' : 'non');
        verifiePortage('aucun cadre vide n\'est montre avant le premier geste',
            ! vu.journauxVides,
            'un panneau de journaux vide est affiche des le chargement, sans rien dire');

        // LE PARC PROPOSE-T-IL LA PRODUCTION ? Constat, pas reproche : ce module
        // pilote des services systemd, et `srv-zabbix` en fait tourner.
        constate('`srv-zabbix` est-elle proposee ?',
            vu.machines.some((m) => /zabbix/i.test(m)) ? 'OUI' : 'non');
    });

    await etape('aucun identifiant de traduction a l\'ecran', async () => {
        const rep = await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        // LA PRECONDITION D'ABORD : une page en erreur n'a pas d'identifiant a
        // montrer, et « aucun trouve » y serait vrai pour la pire des raisons.
        verifie('la page rend avant qu\'on y cherche des identifiants',
            rep && rep.status() === 200, `statut ${rep ? rep.status() : 0}`);
        if (! rep || rep.status() !== 200) return;

        const bruts = await page.evaluate(() => {
            const texte = document.body.innerText || '';
            // Les extensions de fichier sont exclues : sur une pile d'appels,
            // `services.php` serait rapporte comme une cle manquante (piege B1).
            const trouves = texte.match(/\bservices\.[a-z_]+\b/g) || [];

            return [...new Set(trouves.filter((c) => ! /\.(blade|js|php|css|json|log|mjs)$/.test(c)))];
        });
        constate('cles brutes visibles', bruts.join(', ') || '(aucune)');
        verifie('aucune cle de traduction n\'apparait en clair', bruts.length === 0, bruts.join(', '));
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            await dors(500);
            await page.screenshot({ path: `${dossier}/services-s1-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    const causeesParLeFilet = erreursJs.filter((e) => /Failed to fetch|blocked/i.test(e)).length;
    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    constate('dont causees par l\'avortement du filet', `${causeesParLeFilet} sur ${erreursJs.length}`);
    verifiePortage('aucune erreur JavaScript etrangere a l\'avortement',
        erreursJs.length === causeesParLeFilet,
        erreursJs.filter((e) => ! /Failed to fetch|blocked/i.test(e)).slice(0, 2).join(' | '));

} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    try {
        constate('routes du module avortees', avortees.length
            ? [...new Set(avortees)].join(' · ') : '(aucune)');
        verifie('aucune route du module n\'a abouti',
            avortees.every((r) => ROUTES_MODULE.test(r)), avortees.join(' · '));
    } catch (e) { note(`FAIL  controle des requetes : ${e.message}`); echecs += 1; }
    try {
        // S1 NE PILOTE AUCUN SERVICE, et on le prouve — mais avec le BON motif.
        //
        // `_log_service_action` ecrit `service_<action>` : `service_start`,
        // `service_stop`… Une premiere redaction cherchait `%service%`, qui
        // attrapait aussi « Permission refusee : can_manage_services » — le
        // journal du REFUS que la suite venait elle-meme de provoquer. Elle
        // accusait S1 d'avoir pilote un service alors qu'elle avait mesure une
        // garde. `ESCAPE '|'` parce que `_` est un joker en SQL.
        const gestes = compteEnBase('SELECT COUNT(*) FROM rootwarden.user_logs '
            + "WHERE action LIKE 'service|_%' ESCAPE '|' "
            + 'AND created_at > NOW() - INTERVAL 10 MINUTE');
        constate('gestes `service_*` des dix dernieres minutes', String(gestes));
        verifie('S1 n\'a pilote aucun service', gestes === 0, `${gestes} ligne(s)`);

        // ET LE REFUS EST JOURNALISE — un SECOND temoin de la garde, independant
        // du statut HTTP. Un 403 dit que la page a refuse ; cette ligne dit que
        // le refus a laisse une trace, ce qui n'est pas la meme propriete.
        const refus = compteEnBase('SELECT COUNT(*) FROM rootwarden.user_logs '
            + "WHERE action LIKE '%Permission refusee%can_manage_services%' "
            + 'AND created_at > NOW() - INTERVAL 10 MINUTE');
        constate('refus de permission journalises', String(refus));
        verifiePortage('le refus oppose au role 1 laisse une trace en journal', refus > 0,
            'aucun refus journalise — la garde a repondu 403 sans rien enregistrer');
    } catch (e) { note(`FAIL  controle du journal : ${e.message}`); echecs += 1; }
    try {
        const zabbix = litEnBase("SELECT CONCAT(name,'|',ip) FROM rootwarden.machines WHERE id = 1");
        verifie('srv-zabbix est intacte', zabbix.length === 1 && zabbix[0] === 'srv-zabbix|192.168.0.244',
            zabbix[0] || '(absente)');
    } catch (e) { note(`FAIL  controle de srv-zabbix : ${e.message}`); echecs += 1; }
    try { for (const c of contextes) await c.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
    try { await navigateur.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
