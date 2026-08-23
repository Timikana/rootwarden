/**
 * go-page-supervision-version.mjs - Module `supervision/`, sous-lot V6 : la
 * detection de version d'agent. PREMIER SOUS-LOT SSH DU MODULE.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/supervision/   (onglet « Deploiement agents »)
 *   laravel  http://localhost:8444/supervision     (panneau `panneau-deploy`)
 *
 * ══ CE QUE LA LECTURE DU CODE A ETABLI AVANT LE MOINDRE CLIC ══
 *
 * V1 a V5 ne joignaient aucune machine. V6 ouvre une session SSH REELLE. La regle
 * est donc en vigueur : chercher ce que l'action ENVOIE avant de la declencher.
 *
 *  1. **LA COMMANDE DISTANTE EST UNE LECTURE PURE**, verifiee mot pour mot
 *     (`supervision.py:751-754`) :
 *       command -v zabbix_agent2 >/dev/null 2>&1 && zabbix_agent2 -V | head -1
 *       || command -v zabbix_agentd >/dev/null 2>&1 && zabbix_agentd -V | head -1
 *       || echo 'NOT_INSTALLED'
 *     Rien n'installe, rien n'ecrit, rien ne redemarre. `command -v` evite meme le
 *     « sh: not found » qui polluerait la sortie. La cible **Test-Server-Debian**
 *     (id 2, DEV) est donc sure. `srv-zabbix` (id 1, PRODUCTION) n'est JAMAIS
 *     jointe : la suite ne coche QUE la machine 2, jamais « tout cocher ».
 *
 *  2. **LA ROUTE EST BIEN GARDEE — et c'est une exoneration.** `zabbix_version`
 *     (`:732`) et `generic_version` (`:1293`) portent `@require_api_key` +
 *     **`@require_role(2)`** (commentaire « Patch A01 : aligne sur les autres
 *     routes supervision ») + `@require_permission('can_manage_supervision')` +
 *     `@require_machine_access`. Contrairement aux quatre routes de profils
 *     (E-77), celles-ci ont bien recu le correctif.
 *
 *  3. **CORRECTION D'UNE SUPPOSITION DU SUIVI DE CHANTIER.** La question etait :
 *     la detection ecrit-elle `supervision_agents`, `machines.zabbix_agent_version`,
 *     ou les deux ? Reponse mesuree : **`supervision_agents` SEULEMENT**.
 *     `machines.zabbix_agent_version` existe, la page la lit dans son `SELECT`, et
 *     **personne ne l'ecrit ici**.
 *
 * ══ LA PROPRIETE CENTRALE DE V6 : UNE DETECTION QUI NE TROUVE RIEN SUPPRIME ══
 *
 * `zabbix_version` fait `_upsert_agent` si une version sort, et **`_remove_agent`
 * sinon** — un `DELETE FROM supervision_agents WHERE machine_id AND platform`.
 * Aucun agent n'est installe sur Test-Server-Debian, donc la detection y prend le
 * second chemin : la suite pose une ligne d'agent en fixture, declenche la
 * detection, et verifie que la ligne a DISPARU. C'est la propriete qui compte —
 * l'inventaire d'agents suit l'etat reel des machines, y compris quand un agent a
 * ete desinstalle hors du portail — et elle ne se mesure qu'EN BASE.
 *
 * ══ CE QUE LA LECTURE A AUSSI TROUVE, ET QUI SE DECLARE ══
 *
 *  - **une LECTURE passe par `execute_as_root`** : lire un numero de version
 *    n'exige aucun privilege, et le faire en root eleve inutilement le geste ;
 *  - **`agent_type` est calcule puis JETE** : la route distingue `zabbix-agent2` de
 *    `zabbix-agent`, le renvoie au client... et `_upsert_agent` ne prend que la
 *    version. La colonne `supervision_agents.agent_version` existe, aucune colonne
 *    ne recoit le type.
 *
 * SURETE. `backend/scheduler.py` ne lit AUCUNE table de supervision (verifie en
 * V3) : la fixture n'arme aucun declencheur. Elle est nettoyee A L'ENTREE et dans
 * un `finally`, et l'etat restaure est ANNONCE.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-supervision-version.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/supervision' : '/supervision/';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

/**
 * LA SEULE MACHINE QUE CETTE SUITE JOINT. Test-Server-Debian, id 2, DEV,
 * joignable. `srv-zabbix` (id 1) est en PRODUCTION : ni cochee, ni jointe, et
 * « tout cocher » est donc BANNI de cette suite.
 */
const MACHINE_DEV = 2;
/** La version posee en fixture : reconnaissable, et elle doit DISPARAITRE. */
const VERSION_FIXTURE = '0.0.1-rw-e2e-v6';

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
function verifie(l, ok, d) { lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }
function verifiePortage(l, ok, d) {
    if (CIBLE === 'laravel') return verifie(l, ok, d);
    constate(l, `ecart assume du legacy — ${d}`);
}

function agentsDeLaMachine() {
    return compteEnBase(
        'SELECT COUNT(*) FROM rootwarden.supervision_agents '
        + `WHERE machine_id = ${MACHINE_DEV} AND platform = 'zabbix'`);
}

function versionEnBase() {
    return litEnBase(
        "SELECT COALESCE(NULLIF(TRIM(agent_version), ''), '(VIDE)') "
        + 'FROM rootwarden.supervision_agents '
        + `WHERE machine_id = ${MACHINE_DEV} AND platform = 'zabbix'`)[0] ?? '(AUCUNE LIGNE)';
}

function nettoie() {
    const n = agentsDeLaMachine();
    litEnBase('DELETE FROM rootwarden.supervision_agents '
        + `WHERE machine_id = ${MACHINE_DEV} AND platform = 'zabbix'`);
    return n;
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});

async function connecte(langue) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };
    await page.goto(`${BASE}${chemins.connexion}?lang=${langue}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', 'rw-test-admin', { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    const champ = await page.$('input[name="2fa_code"]');
    if (champ) {
        await champ.type(totp(SECRET_ADMIN), { delay: 8 });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
    }
    if (chemins.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$('[data-rw="cgu-accepter"]') || await page.$('button[name="accept_terms"]');
        if (b) await b.evaluate(x => x.click());
        try { await nav; } catch {}
    }
    return { ctx, page };
}

async function ouvreDeploiement(page) {
    await page.evaluate(() => {
        (document.querySelector('.tab-btn[data-tab="deploy"]')
            || document.querySelector('[data-rw="onglet-deploy"]'))?.click();
    });
    await dors(1500);
}

/** Le bloc de deploiement VISIBLE, plus le porte-messages : lecon de V4. */
async function texteMessages(page) {
    return page.evaluate(() => {
        const morceaux = [];
        const bloc = [...document.querySelectorAll('#tab-deploy, [data-rw="panneau-deploy"]')]
            .find((e) => e.offsetParent !== null);
        if (bloc) morceaux.push(bloc.innerText);
        for (const sel of ['#toast-container', '[data-rw="superv-version-message"]']) {
            const e = document.querySelector(sel);
            if (e) morceaux.push(e.innerText);
        }
        return morceaux.join('\n');
    });
}

try {
    /*
     * MODULE ARCHIVE ? Cote legacy, `supervision/` a ete porte en douze
     * sous-lots (V1 a V12) puis deplace dans `legacy/_deprecated/`. Ses URL
     * rendent 404 : ce n'est pas un echec, c'est l'aboutissement du portage. Le
     * test le CONSTATE — et verifie surtout que le menu du legacy mene desormais
     * au portage, sans quoi on aurait installe soi-meme un 404 dans un menu.
     *
     * Le constat vient AVANT toute fixture : rien n'est pose, donc rien n'est a
     * defaire, et `process.exit()` peut court-circuiter le `finally`.
     *
     * Les TROIS fichiers du module sont sondes, pas un echantillon. Et ce sont
     * les fichiers REELS : sonder un chemin qui n'a jamais existe rend 404 et
     * fait passer l'assertion pour rien.
     *
     * Tant que le module est servi, ce bloc est inerte et la suite se joue.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE,
            chemin: '/supervision/',
            fichiers: [
                '/supervision/index.php',
                '/supervision/js/main.js',
                '/supervision/js/profiles.js',
            ],
            verifie, constate,
        });
        if (archivee) {
            const { ctx, page } = await connecte('fr');
            await verifieMenuLegacy(page, '/supervision', verifie);
            await ctx.close();
            console.log(lignes.join('\n'));
            console.log(`\n${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
            await navigateur.close();
            process.exit(echecs > 0 ? 1 : 0);
        }
    }

    constate('cible', `${CIBLE} — ${PAGE}`);
    constate('fixtures nettoyees a l\'entree', nettoie());

    const { ctx, page } = await connecte('fr');
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const dialogues = [];
    page.on('dialog', (d) => { dialogues.push(`${d.type()}: ${d.message().slice(0, 60)}`); d.dismiss().catch(() => {}); });
    /*
     * ON SURVEILLE CE QUI PART. V6 est le premier sous-lot du module a emettre un
     * appel AU CLIC : on veut savoir lequel, et surtout qu'aucun autre ne parte —
     * un `/deploy` ou un `/uninstall` glisse dans la meme barre d'outils.
     */
    const appels = [];
    page.on('request', (r) => {
        if (/api_proxy\.php\/|\/api\/gateway\//.test(r.url())) {
            appels.push(r.method() + ' ' + r.url().replace(BASE, '').slice(0, 70));
        }
    });

    const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie', (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(2000);
    await ouvreDeploiement(page);

    // ── La machine de DEV est-elle bien la, et elle SEULE cochable ? ─────────
    /*
     * LA PROPRIETE EST « LA MACHINE DE DEV EST ACTIONNABLE », pas « elle a une
     * case a cocher ». Les deux cibles n'ont pas le meme chemin, et exiger celui
     * du legacy condamnerait le meilleur des deux : la-bas on coche une case puis
     * on clique une barre d'outils partagee avec « Deployer » et
     * « Desinstaller » ; le portage donne a chaque ligne SON bouton, ce qui rend
     * une action de masse structurellement impossible.
     */
    const parc = await page.evaluate((idDev) => {
        const bloc = [...document.querySelectorAll('#tab-deploy, [data-rw="panneau-deploy"]')]
            .find((e) => e.offsetParent !== null);
        if (! bloc) return { present: false, lignes: 0, dev: null, cases: 0 };
        const parLigne = bloc.querySelector(
            `[data-rw="superv-machine-${idDev}"] [data-rw="superv-detecter-version"]`);
        const parCase = bloc.querySelector(`input[type="checkbox"][value="${idDev}"]`);
        return {
            present: true,
            lignes: bloc.querySelectorAll('tr[data-machine-id], [data-rw^="superv-machine-"]').length,
            dev: parLigne ? 'bouton de ligne' : (parCase ? 'case a cocher' : null),
            cases: bloc.querySelectorAll('input[type="checkbox"]').length,
        };
    }, MACHINE_DEV);
    constate('parc rendu dans l\'onglet de deploiement',
        parc.present ? `${parc.lignes} ligne(s), ${parc.cases} case(s), machine de DEV : ${parc.dev ?? 'INACTIONNABLE'}`
            : 'bloc introuvable');
    verifie('le parc est rendu dans l\'onglet de deploiement',
        parc.present === true, parc.present ? `${parc.lignes} ligne(s)` : 'introuvable');
    verifie('la machine de DEV est ACTIONNABLE — sans elle, rien n\'est mesurable',
        parc.dev !== null, parc.dev ?? `machine ${MACHINE_DEV} inactionnable`);
    /*
     * ET LE PORTAGE N'OFFRE AUCUNE SELECTION DE MASSE. « Tout cocher » du legacy
     * embarque `srv-zabbix`, qui est en PRODUCTION : ne pas avoir de case du tout
     * rend l'erreur impossible, au lieu de compter sur la prudence de qui clique.
     */
    verifiePortage('aucune case a cocher : une action de masse est structurellement impossible',
        parc.cases === 0,
        `${parc.cases} case(s) — « tout cocher » embarquerait srv-zabbix, en PRODUCTION`);

    // ── LA FIXTURE : une version enregistree, qui doit DISPARAITRE ───────────
    litEnBase(
        'INSERT INTO rootwarden.supervision_agents (machine_id, platform, agent_version) '
        + `VALUES (${MACHINE_DEV}, 'zabbix', '${VERSION_FIXTURE}')`);
    constate('fixture posee', `agent zabbix ${VERSION_FIXTURE} sur la machine ${MACHINE_DEV}`);
    verifie('la fixture d\'agent est en place, sinon la suppression ne se mesurerait pas',
        agentsDeLaMachine() === 1 && versionEnBase() === VERSION_FIXTURE,
        `${agentsDeLaMachine()} ligne(s), version=${versionEnBase()}`);

    /*
     * UN MESSAGE EPHEMERE NE SE LIT PAS APRES COUP — et ici c'est structurel.
     * `toast()` s'efface au bout de 4 s (`head.php:172`), alors qu'une session SSH
     * en demande 9. Le verdict a donc TOUJOURS disparu au moment ou son effet
     * devient mesurable : une suite qui lit le DOM apres l'attente ne verra jamais
     * rien — ou, pire, verra quelque chose sur un chemin rapide et plus rien sur un
     * chemin lent, ce qui fait passer un test pour instable alors qu'il mesure mal.
     *
     * On installe donc un OBSERVATEUR avant le clic : il accumule le texte de tout
     * ce qui apparait. La propriete devient « le verdict a ete enonce », et non
     * « le verdict est encore a l'ecran a l'instant ou je regarde ».
     */
    await page.evaluate(() => {
        window.__rwMessages = [];
        /*
         * ON RELIT LE PORTE-MESSAGES ENTIER, PAS LE NOEUD AJOUTE. Premiere version
         * fausse : `toast()` insere un `<div>` puis y met deux `<span>`, et
         * l'observateur voyait donc passer l'ICONE seule (« ℹ ») avant que le
         * texte n'existe. Une assertion assez lache pour s'en satisfaire passait
         * alors pour une raison qui n'etait pas la bonne — pire qu'un echec.
         */
        const collecte = () => {
            for (const sel of ['#toast-container', '[data-rw="superv-version-message"]']) {
                const e = document.querySelector(sel);
                const texte = (e?.innerText || '').trim();
                if (texte) { window.__rwMessages.push(texte.slice(0, 200)); }
            }
        };
        const observateur = new MutationObserver(collecte);
        observateur.observe(document.body, { childList: true, subtree: true, characterData: true });
    });

    // ── LE GESTE : cocher LA machine de DEV, puis cliquer DETECTER ───────────
    appels.length = 0;
    const geste = await page.evaluate((idDev) => {
        const bloc = [...document.querySelectorAll('#tab-deploy, [data-rw="panneau-deploy"]')]
            .find((e) => e.offsetParent !== null);
        if (! bloc) return null;
        /*
         * ON COCHE UNE SEULE CASE, CELLE DE LA MACHINE DE DEV. « Tout cocher »
         * embarquerait `srv-zabbix`, qui est en PRODUCTION — c'est pour cela que
         * cette suite ne l'appelle jamais.
         */
        /*
         * PORTAGE : le bouton de SA ligne, trouve depuis la ligne de la machine —
         * on part de la donnee affichee et on descend, comme en V5.
         */
        const parLigne = bloc.querySelector(
            `[data-rw="superv-machine-${idDev}"] [data-rw="superv-detecter-version"]`);
        if (parLigne) {
            parLigne.click();
            return { coche: false, declenche: 'clic sur le bouton de la ligne' };
        }
        /*
         * LEGACY : cocher UNE SEULE case, celle de la machine de DEV, puis
         * cliquer le bouton de detection. « Tout cocher » embarquerait
         * `srv-zabbix`, en PRODUCTION — c'est pour cela que cette suite ne
         * l'appelle jamais. Le bouton est vise par son CABLAGE et non par son
         * libelle : ses voisins deploient, reconfigurent ou desinstallent.
         */
        const cochee = bloc.querySelector(`input[type="checkbox"][value="${idDev}"]`);
        if (! cochee) return null;
        cochee.click();
        const bouton = bloc.querySelector('[onclick*="detectVersionSelected"]');
        if (! bouton) return { coche: true, declenche: null };
        bouton.click();
        return { coche: true, declenche: 'case cochee, puis clic sur le bouton de detection' };
    }, MACHINE_DEV);
    constate('geste', geste ? `${geste.declenche ?? 'bouton introuvable'}` : 'bloc introuvable');
    verifie('la detection a un point d\'entree atteignable au clic',
        Boolean(geste?.declenche), geste?.declenche ?? 'aucun');

    // La session SSH prend du temps : le backend est en `@threaded_route`.
    await dors(9000);
    const appelsGeste = appels.slice();
    constate('appels emis par le geste',
        appelsGeste.length ? appelsGeste.join(' | ') : 'aucun');
    /*
     * AUCUN APPEL DANGEREUX N'A PU PARTIR. Le bouton de detection voisine avec
     * « Deployer », « Reconfigurer » et « Desinstaller » dans la meme barre :
     * mesurer qu'aucun de ces trois n'a ete appele vaut mieux que de le supposer.
     */
    const dangereux = appelsGeste.filter((a) => /deploy|uninstall|reconfigure/i.test(a));
    verifie('AUCUN appel de deploiement, reconfiguration ou desinstallation n\'est parti',
        dangereux.length === 0, dangereux.join(' | ') || 'aucun');
    verifie('l\'appel de detection de version est bien parti',
        appelsGeste.some((a) => /version/i.test(a)),
        appelsGeste.join(' | ') || 'aucun appel');

    // ── L'EFFET EN BASE : la ligne d'agent a disparu ─────────────────────────
    const apres = agentsDeLaMachine();
    constate('agents enregistres pour la machine de DEV apres detection',
        `${apres} (version : ${versionEnBase()})`);
    verifie('une detection qui ne trouve rien SUPPRIME l\'agent enregistre',
        apres === 0,
        `${apres} ligne(s) restante(s) — aucun agent n'est installe sur cette machine, `
        + 'donc `_remove_agent` doit s\'appliquer');

    // ── Le verdict est ENONCE, et il ne montre aucun identifiant ─────────────
    const texte = await texteMessages(page);
    const apparus = await page.evaluate(() => window.__rwMessages || []);
    /*
     * LE MOTIF EST SERRE, ET LE FRAGMENT RETENU EST IMPRIME. Une regex large finit
     * par attraper un mot du gabarit et l'assertion passe sans mesurer : ici on
     * exige le verdict lui-meme — « non installe » / « not installed », ou un
     * numero de version precede de « v ».
     */
    const MOTIF_VERDICT = /(non install|not installed|aucun agent|no agent|\bv\s?\d+\.\d+)/i;
    const candidats = [...new Set([...apparus, texte, ...dialogues])];
    const retenu = candidats.find((m) => MOTIF_VERDICT.test(m));
    constate('messages apparus pendant le geste',
        apparus.slice(0, 4).map((m) => m.replace(/\n/g, ' ')).join(' | ') || 'aucun');
    verifie('le verdict de la detection est ENONCE',
        Boolean(retenu),
        retenu
            ? `« ${retenu.match(MOTIF_VERDICT)[0]} » dans « ${retenu.replace(/\n/g, ' ').slice(0, 60)} »`
            : 'rien de lisible, ni a l\'ecran ni pendant le geste');

    const clesVisibles = ['scan_all_running', 'scan_all_done', 'select_machine', 'toast_error']
        .filter((c) => (texte + dialogues.join(' ')).includes(c));
    verifie('aucune cle de traduction ne s\'affiche en identifiant',
        clesVisibles.length === 0, clesVisibles.join(', ') || 'aucune');

    verifiePortage('aucune boite native ne s\'ouvre',
        dialogues.length === 0, dialogues.join(', ') || 'aucune');
    verifie('aucune erreur JS pendant toute la sequence',
        erreursJs.length === 0, erreursJs.slice(0, 3).join(' · ') || 'aucune');
    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
} finally {
    const restes = nettoie();
    lignes.push(`INFO  fixtures supprimees en sortie : ${restes}`);
    const total = compteEnBase('SELECT COUNT(*) FROM rootwarden.supervision_agents');
    lignes.push(`${total === 0 ? 'PASS' : 'FAIL'}  la table des agents est rendue a son `
        + `etat initial  — ${total} ligne(s)`);
    if (total !== 0) echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
