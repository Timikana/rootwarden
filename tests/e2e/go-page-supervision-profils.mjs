/**
 * go-page-supervision-profils.mjs - Module `supervision/`, sous-lot V2 : le
 * catalogue de profils, EN LECTURE.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/supervision/   (onglet « Profils »)
 *   laravel  http://localhost:8444/supervision     (panneau `panneau-profiles`)
 *
 * V2 NE MODIFIE RIEN, ne joint aucune machine et n'ecrit pas une ligne. Le CRUD
 * et l'assignation appartiennent a V5 ; le tableau de deploiement, a V6..V12.
 *
 * CE QUE LA MESURE DU SCHEMA A CORRIGE, avant d'ecrire une seule assertion :
 *  - la table s'appelle **`supervision_metadata_profiles`**, pas
 *    `supervision_profiles` ;
 *  - les assignations vivent dans **`machine_supervision_profile`**, dont la cle
 *    primaire est `(machine_id, platform)` : une machine porte donc UN profil
 *    PAR PLATEFORME, et le `machine_count` du tableau est un `COUNT(*)` filtre
 *    par plateforme, pas une colonne de `machines` ;
 *  - `fk_msp_profile` porte bien un **`ON DELETE CASCADE`** vers
 *    `supervision_metadata_profiles`. La consequence annoncee en PARITE E-72
 *    tient donc : `DELETE /supervision/profiles/<id>`, qui n'a aucun
 *    `@require_role`, emporte les assignations avec le profil.
 *
 * TROIS DEFAUTS DU LEGACY QUE CE SOUS-LOT MESURE :
 *
 *  1. **« Editer » et « Supprimer » sont ecrits EN DUR dans le JS**
 *     (`profiles.js:43-46`). Ces deux libelles echappent donc a la parite
 *     FR/EN : en anglais, le tableau reste francais. Aucun controle d'i18n ne
 *     les voit — ils cherchent des identifiants `module.cle`, pas du francais.
 *
 *  2. **Le profil ENTIER est serialise dans un attribut `onclick`** :
 *     `editProfile(${JSON.stringify(p)...})`. Le document porte donc, dans un
 *     attribut de gestionnaire d'evenement, toutes les colonnes de la ligne —
 *     `notes` comprise, qui contient les consignes d'exploitation.
 *
 *  3. **La route backend fait `SELECT *`** (`supervision.py`, `list_profiles`) :
 *     le navigateur recoit `notes`, `tls_connect`, `tls_accept`, `created_at` et
 *     `updated_at` alors que le tableau n'affiche que cinq colonnes.
 *
 * Le portage lit la base (decision S3/S4), rend ses cellules par `textContent`
 * et n'expose que ce qu'il affiche.
 *
 * PROPRIETE CENTRALE, ET C'EST CELLE QUE V1 A RENDUE POSSIBLE : le catalogue est
 * peint COTE SERVEUR pour les quatre plateformes, donc ouvrir l'onglet et
 * changer de plateforme n'emettent AUCUN appel. Le legacy, lui, rejoue
 * `GET /supervision/profiles` a chaque fois.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-supervision-profils.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/supervision' : '/supervision/';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

/** La plateforme par defaut, seule a porter des profils dans ce parc. */
const PLATEFORME_GARNIE = 'zabbix';

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

/*
 * L'ETAT DU PARC, LU EN BASE — colonnes SELECTIONNEES SEPAREMENT.
 *
 * `litEnBase` fait un `trim()` puis un `.filter(Boolean)` : une valeur VIDE
 * DISPARAIT de la liste et le decalage passerait inapercu. Chaque colonne
 * nullable part donc avec une SENTINELLE explicite.
 */
const NOMS = litEnBase(
    "SELECT name FROM rootwarden.supervision_metadata_profiles "
    + `WHERE platform = '${PLATEFORME_GARNIE}' ORDER BY name`);
const METADONNEES = litEnBase(
    "SELECT COALESCE(NULLIF(TRIM(host_metadata), ''), '(AUCUNE)') "
    + 'FROM rootwarden.supervision_metadata_profiles '
    + `WHERE platform = '${PLATEFORME_GARNIE}' ORDER BY name`);
/** Nombre d'assignations par profil, dans le MEME ordre que les noms. */
const ASSIGNATIONS = litEnBase(
    'SELECT (SELECT COUNT(*) FROM rootwarden.machine_supervision_profile a '
    + `WHERE a.profile_id = p.id AND a.platform = '${PLATEFORME_GARNIE}') `
    + 'FROM rootwarden.supervision_metadata_profiles p '
    + `WHERE p.platform = '${PLATEFORME_GARNIE}' ORDER BY p.name`);
/** Les plateformes SANS aucun profil : le catalogue doit s'y montrer vide. */
const PLATEFORMES_VIDES = ['centreon', 'prometheus', 'telegraf'].filter((p) =>
    litEnBase('SELECT COUNT(*) FROM rootwarden.supervision_metadata_profiles '
              + `WHERE platform = '${p}'`)[0] === '0');

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

/** Ouvre l'onglet des profils, sur l'une ou l'autre cible. */
async function ouvreProfils(page) {
    await page.evaluate(() => {
        (document.querySelector('.tab-btn[data-tab="profiles"]')
            || document.querySelector('[data-rw="onglet-profiles"]'))?.click();
    });
    await dors(1500);
}

/** Change la plateforme active, sur l'une ou l'autre cible. */
async function choisitPlateforme(page, nom) {
    await page.evaluate((n) => {
        const sel = document.getElementById('agent-platform')
            || document.querySelector('[data-rw="superv-plateforme"]');
        if (!sel) return;
        sel.value = n;
        // Le legacy est cable par `onchange=`, le portage par un ecouteur :
        // l'evenement couvre les deux, une affectation seule n'en declenche
        // aucun des deux.
        sel.dispatchEvent(new Event('change', { bubbles: true }));
    }, nom);
    await dors(1500);
}

/**
 * Les lignes du catalogue rendues a l'ecran, quelle que soit la cible.
 *
 * On ne compte JAMAIS « les `tr` de la page » : le legacy en a d'autres, dans
 * l'onglet de deploiement, deja rendus cote serveur et simplement caches. On
 * vise donc le corps du tableau des profils, et lui seul.
 */
async function catalogueAffiche(page) {
    return page.evaluate(() => {
        /*
         * LE CATALOGUE VISIBLE, PAS LE PREMIER DU DOCUMENT. Le legacy n'en a
         * qu'un et le vide a chaque bascule ; un portage qui peint les quatre
         * plateformes cote serveur en a quatre, dont trois caches. Prendre le
         * premier venu, c'est mesurer le catalogue de Zabbix en croyant mesurer
         * celui de Centreon.
         */
        const corps = [...document.querySelectorAll(
            '#profiles-tbody, [data-rw="superv-profils-corps"]')]
            .find((e) => e.offsetParent !== null || e.closest('table')?.offsetParent !== null)
            || document.getElementById('profiles-tbody')
            || document.querySelector('[data-rw="superv-profils-corps"]');
        if (!corps) return { present: false, lignes: [], vide: null, texte: '' };
        // Et des lignes VISIBLES : `textContent` mesure la presence, pas la
        // visibilite, et une ligne masquee ne dit rien a personne.
        const lignes = [...corps.querySelectorAll('tr')]
            .filter((tr) => tr.offsetParent !== null)
            .map((tr) => ({
            cellules: [...tr.querySelectorAll('td')].map((td) => td.innerText.trim()),
            // La serialisation d'un enregistrement dans un attribut de
            // gestionnaire est mesurable telle quelle.
            gestionnaires: [...tr.querySelectorAll('[onclick]')]
                .map((e) => e.getAttribute('onclick').length),
        }));
        // Meme raison pour l'etat vide : celui de la plateforme AFFICHEE.
        const marqueurVide = [...document.querySelectorAll(
            '#profiles-empty, [data-rw="superv-profils-vide"]')]
            .find((e) => e.offsetParent !== null)
            || document.getElementById('profiles-empty')
            || document.querySelector('[data-rw="superv-profils-vide"]');
        return {
            present: true,
            lignes,
            vide: marqueurVide ? marqueurVide.offsetParent !== null : null,
            texte: (corps.closest('div, article, section') || corps).innerText,
        };
    });
}

try {
    constate('cible', `${CIBLE} — ${PAGE}`);
    constate('profils en base', `${NOMS.length} pour ${PLATEFORME_GARNIE} : ${NOMS.join(', ')}`);
    constate('assignations par profil', ASSIGNATIONS.join(', ') || 'aucune');
    constate('plateformes sans aucun profil', PLATEFORMES_VIDES.join(', ') || 'aucune');

    /*
     * FAIL-CLOSED. Sans profil en base, chaque assertion qui suit reussirait en
     * ne mesurant rien : zero ligne attendue, zero ligne trouvee. Le sous-lot
     * porte la LECTURE d'un catalogue — sans catalogue, il n'y a rien a lire.
     */
    verifie('le parc porte de quoi mesurer un catalogue',
        NOMS.length > 0 && METADONNEES.length === NOMS.length
            && ASSIGNATIONS.length === NOMS.length,
        `${NOMS.length} profil(s), ${METADONNEES.length} metadonnee(s), `
        + `${ASSIGNATIONS.length} compte(s)`);
    verifie('au moins une plateforme est sans profil, pour mesurer le cloisonnement',
        PLATEFORMES_VIDES.length > 0, PLATEFORMES_VIDES.join(', ') || 'aucune');

    // ── En francais : le catalogue lui-meme ─────────────────────────────────
    const { ctx, page } = await connecte('fr');
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const dialogues = [];
    page.on('dialog', (d) => { dialogues.push(d.type()); d.dismiss().catch(() => {}); });
    const appels = [];
    page.on('request', (r) => {
        if (/api_proxy\.php\/|\/api\/gateway\//.test(r.url())) {
            appels.push(r.method() + ' ' + r.url().replace(BASE, '').slice(0, 70));
        }
    });

    const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie', (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(2500);

    // Ouvrir l'onglet : combien d'appels ? Le legacy en rejoue un.
    appels.length = 0;
    await ouvreProfils(page);
    const appelsOnglet = appels.slice();
    constate('appels a l\'ouverture de l\'onglet',
        appelsOnglet.length ? appelsOnglet.join(' | ') : 'aucun');

    const cat = await catalogueAffiche(page);
    verifie('le corps du catalogue est rendu', cat.present === true,
        cat.present ? `${cat.lignes.length} ligne(s)` : 'introuvable');
    constate('lignes rendues', `${cat.lignes.length} — `
        + cat.lignes.map((l) => l.cellules.slice(0, 5).join(' / ')).join(' || '));

    verifie('une ligne par profil de la plateforme active',
        cat.lignes.length === NOMS.length,
        `${cat.lignes.length} rendue(s) contre ${NOMS.length} en base`);

    // NOMINATIF, pas positionnel : l'ordre du rendu n'est pas la propriete.
    const manquants = NOMS.filter((n) => !cat.texte.includes(n));
    verifie('chaque profil de la base est nomme a l\'ecran',
        manquants.length === 0, manquants.join(', ') || 'aucun manquant');

    const metaManquantes = METADONNEES.filter((m) => m !== '(AUCUNE)' && !cat.texte.includes(m));
    verifie('la valeur de HostMetadata de chaque profil est affichee',
        metaManquantes.length === 0, metaManquantes.join(', ') || 'aucune manquante');

    /*
     * UNE COLONNE VIDE DOIT DIRE QU'ELLE EST VIDE, pas rendre le mot d'un
     * langage. Les quatre profils de ce parc ont `zabbix_server` et
     * `zabbix_proxy` a NULL : c'est exactement le cas ou un rendu naif ecrit
     * « null » ou « undefined » a l'ecran.
     */
    const motsDeCode = ['null', 'undefined', 'NaN', '[object Object]']
        .filter((m) => cat.texte.includes(m));
    verifie('aucune valeur absente n\'est rendue par un mot de code',
        motsDeCode.length === 0, motsDeCode.join(', ') || 'aucun');

    // Le compte d'assignations est une DONNEE, pas une decoration.
    const comptesRendus = cat.lignes.map((l) => l.cellules.join(' '));
    const comptesAttendus = ASSIGNATIONS.map(Number);
    verifie('le nombre de machines assignees est rendu pour chaque profil',
        cat.lignes.length === comptesAttendus.length
            && comptesRendus.every((t, i) => new RegExp(`\\b${comptesAttendus[i]}\\b`).test(t)),
        `attendus ${comptesAttendus.join(', ')}`);

    // ── Le cloisonnement par plateforme ─────────────────────────────────────
    appels.length = 0;
    await choisitPlateforme(page, PLATEFORMES_VIDES[0]);
    const appelsPlateforme = appels.slice();
    const catVide = await catalogueAffiche(page);
    constate(`catalogue apres bascule vers ${PLATEFORMES_VIDES[0]}`,
        `${catVide.lignes.length} ligne(s), etat vide ${catVide.vide === null ? 'absent' : catVide.vide}`);
    constate('appels a la bascule de plateforme',
        appelsPlateforme.length ? appelsPlateforme.join(' | ') : 'aucun');

    verifie('une plateforme sans profil rend un catalogue vide',
        catVide.lignes.length === 0,
        `${catVide.lignes.length} ligne(s) pour ${PLATEFORMES_VIDES[0]}`);
    verifie('et elle le DIT, par un etat vide visible',
        catVide.vide === true, `etat vide : ${catVide.vide}`);

    verifiePortage('ouvrir l\'onglet des profils n\'emet aucun appel',
        appelsOnglet.length === 0,
        `${appelsOnglet.length} appel(s) — le legacy rejoue GET /supervision/profiles`);
    verifiePortage('changer de plateforme n\'emet aucun appel',
        appelsPlateforme.length === 0,
        `${appelsPlateforme.length} appel(s) — le catalogue est peint cote serveur`);

    /*
     * L'ENREGISTREMENT ENTIER DANS UN ATTRIBUT `onclick`. Mesure : la longueur
     * de l'attribut. Le legacy y serialise le profil complet, `notes` comprise —
     * plusieurs centaines de caracteres. Le portage n'a aucun gestionnaire en
     * attribut : la mesure est donc « zero attribut », pas « un attribut court ».
     */
    await choisitPlateforme(page, PLATEFORME_GARNIE);
    await ouvreProfils(page);
    const catRevenu = await catalogueAffiche(page);
    const tailles = catRevenu.lignes.flatMap((l) => l.gestionnaires);
    constate('attributs de gestionnaire sur les lignes',
        tailles.length ? `${tailles.length} — tailles ${tailles.join(', ')}` : 'aucun');
    verifiePortage('aucune ligne ne porte un enregistrement serialise dans un attribut',
        tailles.length === 0,
        `${tailles.length} attribut(s), le plus long ${Math.max(0, ...tailles)} caracteres`);

    await ctx.close();
    await dors((resteFenetre() + 1) * 1000);

    // ── En anglais : les deux libelles ecrits en dur dans le JS ─────────────
    const en = await connecte('en');
    await en.page.goto(`${BASE}${PAGE}?lang=en`, { waitUntil: 'networkidle2' });
    await dors(2000);
    await ouvreProfils(en.page);
    const catEn = await catalogueAffiche(en.page);
    /*
     * Les mots sont cherches DANS LE CATALOGUE, pas dans la page : « Supprimer »
     * apparait ailleurs dans les deux portails, et une recherche sur `body`
     * accuserait le tableau de ce que fait son voisin.
     */
    const francaisResiduel = ['Editer', 'Supprimer', 'Nouveau profil']
        .filter((m) => catEn.texte.includes(m));
    constate('francais residuel dans le catalogue rendu en anglais',
        francaisResiduel.join(', ') || 'aucun');
    verifiePortage('le catalogue rendu en anglais ne garde aucun libelle francais',
        francaisResiduel.length === 0,
        `${francaisResiduel.join(', ')} — ecrits en dur dans profiles.js, `
        + 'donc hors de toute parite FR/EN');

    // Une cle de traduction ne s'affiche jamais en identifiant.
    const clesVisibles = ['profiles_empty', 'profile_name', 'profile_host_metadata',
        'profile_server', 'profile_proxy', 'profile_machines', 'profiles_interp_hint']
        .filter((c) => catEn.texte.includes(c));
    verifie('aucune cle de traduction ne s\'affiche en identifiant',
        clesVisibles.length === 0, clesVisibles.join(', ') || 'aucune');

    verifie('aucune boite native n\'a ete ouverte',
        dialogues.length === 0, dialogues.join(', ') || 'aucune');
    verifie('aucune erreur JS pendant toute la sequence',
        erreursJs.length === 0, erreursJs.slice(0, 3).join(' · ') || 'aucune');
    await en.ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
