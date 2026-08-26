/**
 * go-page-ssh-preflight.mjs - Module `ssh/`, sous-lot K2 : le constat avant
 * deploiement (`POST /preflight_check`).
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/ssh/
 *   laravel  http://localhost:8444/cles-ssh
 *
 * POURQUOI CETTE SUITE N'OUVRE AUCUNE SESSION SSH, ET N'EN A PAS BESOIN.
 *
 * `preflight_check` porte QUATRE portes avant d'ouvrir quoi que ce soit
 * (`backend/routes/ssh.py`) : serveur jamais scanne, utilisateurs en attente de
 * classification, ni mot de passe ni keypair, port injoignable. Les deux
 * premieres sont atteintes par le parc reel :
 *
 *   - **machine 2** (Test-Server-Debian) a `users_scanned_at` a NULL -> premiere
 *     porte, `scan_required`, **aucun SSH** ;
 *   - **machine 3** (OpenCVE-Test-OnPrem) est scannee mais porte un utilisateur
 *     en `pending_review` -> deuxieme porte, **aucun SSH**.
 *
 * Seule la machine 1 irait jusqu'a la session SSH — et c'est `srv-zabbix`, en
 * PRODUCTION. Elle n'est donc JAMAIS visee.
 *
 * ET LE BOUTON DE DEPLOIEMENT N'EST JAMAIS CLIQUE. Cote legacy, le preflight et
 * le deploiement vivent dans la MEME chaine `fetch` : si le preflight passe, le
 * deploiement part **immediatement**, sans reprise de main. Deux freins
 * l'arretent aujourd'hui — la machine 2 non scannee, et `users_with_keys === 0` —
 * mais **on ne s'appuie pas sur un etat qu'on ne controle pas** : c'est
 * exactement la premisse fausse qui a lance deux vrais scans au sous-lot S7a. La
 * suite appelle donc la route DIRECTEMENT, avec des cibles qui ne peuvent rien
 * declencher.
 *
 * LES PRECONDITIONS SONT VERIFIEES AVANT LE GESTE, pas apres : si la machine 2
 * se trouvait scannee ou la machine 3 sans utilisateur en attente, la sonde
 * correspondante est SAUTEE et la suite le dit. Un test qui appelle sans verifier
 * sa premisse finit par joindre une machine qu'il ne voulait pas joindre.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-ssh-preflight.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/cles-ssh' : '/ssh/';
const ROUTE = CIBLE === 'laravel' ? '/api/gateway/preflight_check' : '/api_proxy.php/preflight_check';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';
const SECRET_USER = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';

/** Jamais la machine 1 : elle est en production et passerait la porte SSH. */
const MACHINE_JAMAIS_SCANNEE = 2;
const MACHINE_EN_ATTENTE = 3;

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

// ── L'etat du parc, qui decide de ce qui est mesurable ──────────────────────
/*
 * SENTINELLE, PAS CHAINE VIDE. `litEnBase` fait un `trim()` puis un
 * `.filter(Boolean)` : une valeur vide DISPARAIT de la liste, et la destructuration
 * rendait `undefined`. La suite a alors annonce « la machine 2 porte desormais un
 * scan (« undefined ») » et **saute la porte qu'elle venait mesurer**. Le piege
 * etait deja dans `rw-pieges` ; on ne compare donc plus a `''`.
 */
const [SCAN_M2] = litEnBase(
    "SELECT COALESCE(CAST(users_scanned_at AS CHAR), 'JAMAIS') FROM rootwarden.machines "
    + `WHERE id = ${MACHINE_JAMAIS_SCANNEE}`);
const ATTENTE_M3 = compteEnBase(
    "SELECT COUNT(*) FROM rootwarden.server_user_inventory "
    + `WHERE machine_id = ${MACHINE_EN_ATTENTE} AND status = 'pending_review'`);
const COMPTES_AVEC_CLE = compteEnBase(
    "SELECT COUNT(*) FROM rootwarden.users WHERE active = 1 AND ssh_key IS NOT NULL AND ssh_key <> ''");
const ROLE1_AVEC_ACCES = compteEnBase(
    'SELECT COUNT(*) FROM rootwarden.users u JOIN rootwarden.permissions p ON p.user_id = u.id '
    + 'JOIN rootwarden.user_machine_access a ON a.user_id = u.id '
    + 'WHERE u.active = 1 AND u.role_id = 1 AND p.can_deploy_keys = 1');

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});

async function connecte(nom, secret) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    page.on('dialog', d => d.dismiss().catch(() => {}));
    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };
    await page.goto(`${BASE}${chemins.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    const champ = await page.$('input[name="2fa_code"]');
    if (champ) {
        await champ.type(totp(secret), { delay: 8 });
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

/** Un appel au constat, depuis la page — donc avec sa session et son origine. */
function appelle(page, corps) {
    return page.evaluate(async (route, charge) => {
        try {
            const rep = await fetch(route, {
                method: 'POST', credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(charge),
            });
            const brut = await rep.text();
            let json = null;
            try { json = JSON.parse(brut); } catch { json = null; }
            return {
                statut: rep.status,
                type: rep.headers.get('content-type') || '',
                json,
                corps: brut.slice(0, 500),
            };
        } catch (e) {
            return { statut: 0, type: '', json: null, corps: 'appel impossible : ' + String(e).slice(0, 120) };
        }
    }, ROUTE, corps);
}

try {
    constate('cible', `${CIBLE} — ${PAGE} · route ${ROUTE}`);
    constate('etat du parc',
        `machine ${MACHINE_JAMAIS_SCANNEE} scannee le « ${SCAN_M2 || 'JAMAIS'} », `
        + `machine ${MACHINE_EN_ATTENTE} : ${ATTENTE_M3} en attente · `
        + `${COMPTES_AVEC_CLE} compte(s) actif(s) avec une cle SSH`);

    const { ctx, page } = await connecte('rw-test-admin', SECRET_ADMIN);
    const erreursJs = [];
    page.on('pageerror', e => erreursJs.push(String(e).split('\n')[0]));
    const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie a un role 2 portant can_deploy_keys',
        (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(1200);

    // ── 1. Sans machine : un refus, et il doit se LIRE ──────────────────────
    const sansMachine = await appelle(page, {});
    constate('sans machine', `statut ${sansMachine.statut}, type « ${sansMachine.type.split(';')[0]} »`);
    verifie('sans machine : 400 et du JSON exploitable',
        sansMachine.statut === 400 && /application\/json/.test(sansMachine.type)
            && sansMachine.json?.success === false,
        `statut ${sansMachine.statut}, corps « ${sansMachine.corps.slice(0, 60)} »`);

    // ── 2. La premiere porte : un serveur jamais scanne ─────────────────────
    // PRECONDITION VERIFIEE AVANT LE GESTE. Si la machine se trouvait scannee,
    // l'appel irait jusqu'a la session SSH — on saute plutot que de joindre.
    if (SCAN_M2 === 'JAMAIS') {
        const jamaisScannee = await appelle(page, { machines: [MACHINE_JAMAIS_SCANNEE] });
        const r = (jamaisScannee.json?.results || [])[0] || null;
        constate('machine jamais scannee', `statut ${jamaisScannee.statut}, `
            + `ssh_ok=${r?.ssh_ok}, scan_required=${r?.scan_required}, `
            + `${(r?.errors || []).length} erreur(s)`);
        verifie('un serveur jamais scanne est refuse AVANT toute session SSH',
            jamaisScannee.statut === 200 && r !== null && r.ssh_ok === false
                && r.scan_required === true && (r.errors || []).length > 0,
            r ? `ssh_ok=${r.ssh_ok}, scan_required=${r.scan_required}` : 'aucun resultat');
        verifie('le refus DIT quoi faire, il ne dit pas seulement non',
            Boolean(r) && (r.errors || []).some((e) => /scan|utilisateurs distants/i.test(e)),
            (r?.errors || []).join(' · ').slice(0, 120) || 'aucune erreur');
    } else {
        constate('premiere porte du preflight',
            `SAUTEE : la machine ${MACHINE_JAMAIS_SCANNEE} porte desormais un scan `
            + `(« ${SCAN_M2} »), donc l'appel irait jusqu'a la session SSH`);
    }

    // ── 3. La deuxieme porte : des utilisateurs a classifier ────────────────
    if (ATTENTE_M3 > 0) {
        const enAttente = await appelle(page, { machines: [MACHINE_EN_ATTENTE] });
        const r = (enAttente.json?.results || [])[0] || null;
        constate('machine avec des utilisateurs en attente',
            `ssh_ok=${r?.ssh_ok}, ${(r?.errors || []).length} erreur(s) : `
            + (r?.errors || []).join(' · ').slice(0, 100));
        verifie('des utilisateurs a classifier bloquent AVANT toute session SSH',
            enAttente.statut === 200 && r !== null && r.ssh_ok === false
                && (r.errors || []).some((e) => /classif|attente/i.test(e)),
            r ? `ssh_ok=${r.ssh_ok}` : 'aucun resultat');
        // Le compte annonce doit etre celui de la base, pas un ordre de grandeur.
        verifie('le nombre d\'utilisateurs a classifier est celui de la base',
            Boolean(r) && (r.errors || []).some((e) => new RegExp(`\\b${ATTENTE_M3}\\b`).test(e)),
            `attendu ${ATTENTE_M3} dans « ${(r?.errors || []).join(' ')}».slice(0,80)`);
    } else {
        constate('deuxieme porte du preflight',
            `SAUTEE : la machine ${MACHINE_EN_ATTENTE} n'a plus d'utilisateur en attente, `
            + "donc l'appel irait jusqu'a la session SSH");
    }

    // ── 4. Le compte des cles deployables : la donnee qui decide de tout ────
    //
    // Zero compte porteur d'une cle SSH veut dire qu'un deploiement ne deploierait
    // RIEN, et le legacy en fait — a juste titre — un motif d'echec du preflight.
    // La sonde vise un identifiant VALIDE MAIS INEXISTANT : le `SELECT` ne rend
    // aucune machine, donc aucune porte n'est franchie et rien n'est joint, tandis
    // que `users_with_keys` est calcule et rendu quand meme. La version precedente
    // visait la machine 2 sans reprendre le garde de precondition du point 2 —
    // deux poids, deux mesures pour le meme risque.
    const rapport = await appelle(page, { machines: [99991] });
    constate('comptes avec une cle SSH, rendus par la route',
        String(rapport.json?.users_with_keys));
    verifie('la route rend le nombre de comptes reellement deployables',
        rapport.json?.users_with_keys === COMPTES_AVEC_CLE,
        `${rapport.json?.users_with_keys} rendu(s) pour ${COMPTES_AVEC_CLE} en base`);

    // ── 4 bis. LE CONSTAT EST-IL SEPARABLE DU DEPLOIEMENT ? ────────────────
    //
    // C'est la propriete centrale de K2. Cote legacy, preflight et deploiement
    // vivent dans la MEME chaine `fetch` : si le constat passe, le deploiement
    // part immediatement, sans reprise de main. Il n'existe donc **aucun moyen de
    // verifier sans risquer de deployer** — et c'est mesurable SANS cliquer, en
    // lisant ce que la page offre comme commandes.
    //
    // Le portage doit offrir un bouton qui ne fait QUE le constat. Alors, et
    // alors seulement, le geste devient sur : on peut le cliquer et lire le
    // rapport, ce que cette suite fait cote portage.
    const commandes = await page.evaluate(() => {
        const verif = document.querySelector('[data-rw="ssh-verifier"]');
        const deploie = document.getElementById('deploy-btn')
            || document.querySelector('[data-rw="ssh-deployer"]');
        return {
            verificationSeparee: verif !== null,
            deploiementPresent: deploie !== null,
            zoneRapport: document.getElementById('preflight-rapport') !== null,
            fenetreTexte: document.getElementById('logs') !== null,
        };
    });
    constate('commandes offertes par la page',
        `verification separee=${commandes.verificationSeparee}, `
        + `deploiement=${commandes.deploiementPresent}, `
        + `zone de rapport=${commandes.zoneRapport}, fenetre de texte=${commandes.fenetreTexte}`);
    verifiePortage('le constat est SEPARABLE du deploiement',
        commandes.verificationSeparee && commandes.zoneRapport,
        'aucun bouton de verification seule : le constat et le deploiement sont dans '
        + 'la meme chaine `fetch`, donc verifier expose a deployer');

    // Le rapport ne se clique QUE la ou le clic ne peut rien declencher d'autre.
    if (commandes.verificationSeparee) {
        const partis = [];
        page.on('request', (r) => {
            if (/\/deploy\b/.test(r.url())) partis.push(r.method() + ' ' + r.url());
        });
        // On coche la machine jamais scannee : elle bloque a la premiere porte.
        await page.evaluate((mid) => {
            const c = document.querySelector(`.machine-item input[value="${mid}"]`);
            if (c) { c.checked = true; c.dispatchEvent(new Event('change', { bubbles: true })); }
            document.querySelector('[data-rw="ssh-verifier"]')?.click();
        }, MACHINE_JAMAIS_SCANNEE);
        await dors(4000);

        const rendu = await page.evaluate(() => {
            const z = document.getElementById('preflight-rapport');
            if (!z || z.hidden) return null;
            return {
                texte: z.innerText.replace(/\s+/g, ' ').trim(),
                machines: z.querySelectorAll('[data-rw^="preflight-machine-"]').length,
            };
        });
        constate('rapport rendu par le portage', rendu
            ? `${rendu.machines} machine(s) — « ${rendu.texte.slice(0, 140)} »` : 'aucun');
        verifie('le constat rend un rapport lisible, machine par machine',
            Boolean(rendu) && rendu.machines >= 1 && rendu.texte.length > 0,
            rendu ? `${rendu.machines} machine(s)` : 'aucun rapport');
        /* ══ CETTE ASSERTION PRESUMAIT QU'UN PREREQUIS MANQUE ══════════════
         *
         * Elle exigeait le mot « scan » ou « utilisateurs distants » — le nom
         * du SEUL prerequis qu'elle avait en tete. Or le 2026-08-26 le banc
         * n'avait aucun prerequis manquant : le portage a ecrit « Aucun
         * prerequis manquant », ce qui est EXACT, et l'assertion a echoue en
         * accusant la page.
         *
         * LA PROPRIETE N'EST PAS « un prerequis est nomme », c'est « le rapport
         * est SPECIFIQUE dans les deux sens » : il nomme ce qui manque, ou il
         * dit que rien ne manque. Un rapport qui se contenterait de « echec »
         * ou de « OK » serait le vrai defaut, et c'est celui-la qu'on mesure.
         *
         * Meme correction que celle deja faite trois lignes plus bas, ou une
         * version anterieure exigeait le CHIFFRE zero et condamnait le meilleur
         * rendu des deux. Le defaut se repete parce qu'il est facile : on ecrit
         * l'assertion en pensant au cas qu'on a sous les yeux. */
        const nommeCeQuiManque = /scan|utilisateurs distants|cle ssh|clé ssh/i.test(rendu?.texte || '');
        const ditQueRienNeManque = /aucun prerequis manquant|aucun prérequis manquant|no missing prerequisite/i
            .test(rendu?.texte || '');
        verifie('le rapport est SPECIFIQUE : il nomme ce qui manque, ou dit que rien ne manque',
            Boolean(rendu) && (nommeCeQuiManque || ditQueRienNeManque),
            rendu ? `« ${rendu.texte.slice(0, 100)} »` : 'aucun rapport');
        // ZERO compte porteur d'une cle veut dire qu'un deploiement ne deploierait
        // RIEN : le dire est la moitie utile du constat.
        // LA PROPRIETE, PAS LE RENDU. La version precedente exigeait le CHIFFRE
        // dans le texte : quand le compte vaut zero, le portage ecrit « aucun
        // compte actif ne porte de cle SSH », ce qui est plus clair qu'un « 0 » —
        // et l'assertion condamnait le meilleur rendu des deux.
        const ditLesCles = COMPTES_AVEC_CLE === 0
            ? /aucun compte|no active account/i.test(rendu?.texte || '')
            : new RegExp(`\\b${COMPTES_AVEC_CLE}\\b`).test(rendu?.texte || '');
        verifie('le rapport dit combien de comptes sont reellement deployables',
            Boolean(rendu) && ditLesCles,
            COMPTES_AVEC_CLE === 0
                ? 'zero compte : l\'absence doit etre ENONCEE, pas rendue par un chiffre'
                : `attendu ${COMPTES_AVEC_CLE} dans le rapport`);
        verifie('verifier n\'a declenche AUCUN deploiement', partis.length === 0,
            partis.slice(0, 2).join(' · ') || 'aucun appel vers /deploy');
    } else {
        constate('clic sur la verification',
            'SAUTE : aucun bouton de verification seule. Le seul bouton disponible '
            + 'enchaine le deploiement des que le constat passe — le cliquer pour '
            + 'lire un rapport exposerait a ecrire sur toutes les machines cochees.');
    }

    // ── 5. Un role 1 sans acces machine : 403, et il NOMME la machine ───────
    await dors((resteFenetre() + 1) * 1000);
    const u = await connecte('rw-test-user', SECRET_USER);
    // La page lui est refusee (pas de `can_deploy_keys`), mais la ROUTE, elle,
    // n'a aucune garde de role : on l'appelle depuis une page qu'il peut ouvrir.
    await u.page.goto(`${BASE}${CIBLE === 'laravel' ? '/accueil' : '/index.php'}`,
        { waitUntil: 'networkidle2' });
    const refus = await appelle(u.page, { machines: [MACHINE_JAMAIS_SCANNEE] });
    constate('role 1 sans acces machine', `statut ${refus.statut}, `
        + `corps « ${refus.corps.slice(0, 70)} »`);
    verifie('un role 1 sans acces a la machine est refuse en 403',
        refus.statut === 403, `statut ${refus.statut}`);
    await u.ctx.close();

    // ── 6. Ce qui n'est pas mesurable, et on le DIT ─────────────────────────
    constate('absence de garde de ROLE sur `preflight_check`',
        `NON MESURABLE : ${ROLE1_AVEC_ACCES} compte de role 1 porte a la fois `
        + '`can_deploy_keys` et un acces machine. La route n\'a que `@require_api_key` '
        + '+ `@threaded_route` — aucun `@require_role` — alors qu\'elle enumere les '
        + 'comptes UNIX distants, ce que `/scan_server_users` reserve au role 2 ET '
        + 'place dans ADMIN_ONLY_PREFIXES du proxy. Meme limite que D-5.');
    verifie('l\'absence de compte de role 1 habilite ET attribue est bien la cause',
        ROLE1_AVEC_ACCES === 0, `${ROLE1_AVEC_ACCES} compte(s)`);

    verifie('aucune erreur JS pendant toute la sequence', erreursJs.length === 0,
        erreursJs.slice(0, 3).join(' · ') || 'aucune');
    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
