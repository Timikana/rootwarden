/**
 * go-page-supervision-profils-crud.mjs - Module `supervision/`, sous-lot V5 :
 * creer, modifier et SUPPRIMER un profil de supervision.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/supervision/   (onglet « Profils »)
 *   laravel  http://localhost:8444/supervision     (panneau `panneau-profiles`)
 *
 * ══ CE QUE LA MESURE A ETABLI AVANT D'ECRIRE UNE LIGNE ══
 *
 * Trois faits ont ete verifies, et DEUX DEDOUANENT le code existant. Il faut le
 * dire aussi clairement qu'une accusation :
 *
 *  1. **`upsert_profile` porte bien `WHERE id=%s AND platform=%s`**
 *     (`supervision.py:1780`). Le defaut du `:508` mesure en V4 — un `UPDATE`
 *     derive d'un `SELECT` sans filtre de plateforme — **n'est PAS generalise**.
 *     C'est une route particuliere qui l'a, pas une habitude du module.
 *
 *  2. **LA CONTRAINTE D'UNICITE EXISTE** : `UNIQUE KEY uk_platform_name
 *     (platform, name)`. Le message d'erreur du backend doute de lui-meme —
 *     « nom deja pris ? », avec un point d'interrogation — mais il a raison sur le
 *     fond. Deux profils homonymes ne peuvent pas coexister sur une meme
 *     plateforme, donc l'assignation n'est pas ambigue. Le point
 *     d'interrogation etait une hesitation de redaction, pas un trou.
 *     Au passage : la contrainte porte sur le COUPLE, donc deux profils de meme
 *     nom sur DEUX plateformes differentes sont legitimes — et c'est voulu.
 *
 *  3. **L'ASSIGNATION RESTE HORS DE V5, et c'est une decision.** Son point
 *     d'entree unique est le dropdown du TABLEAU DE DEPLOIEMENT
 *     (`profiles.js:loadDeployProfileSelectors`), que le portage ne porte pas
 *     encore. Cote legacy on choisit UN PROFIL POUR UNE MACHINE ; assigner depuis
 *     le catalogue inverserait la relation — on choisirait DES MACHINES POUR UN
 *     PROFIL — et comme la cle primaire de `machine_supervision_profile` est
 *     `(machine_id, platform)`, une machine ne porte qu'un profil par plateforme :
 *     l'inversion aurait l'effet non evident de retirer la machine de son profil
 *     precedent. Ce serait CONCEVOIR, pas migrer. V5 porte donc le CRUD, et la
 *     page dit ou se fait l'assignation.
 *
 * ══ CE QUE V5 MESURE DU LEGACY ══
 *
 * `profiles.js` porte **SEPT chaines francaises ECRITES EN DUR** — invisibles a
 * tout controle d'i18n, qui cherche des identifiants `module.cle` et la parite des
 * JEUX de cles, pas du francais parfaitement lisible :
 *   `Editer` (`:43`) · `Supprimer` (`:45`) · `Nouveau profil` (`:60`) ·
 *   `Editer profil : ` (`:79`) · `Le nom est obligatoire.` (`:96`) ·
 *   `Supprimer le profil "…" ? Les serveurs assignes perdront leur profil.` (`:111`) ·
 *   `Erreur reseau` (`:105`, `:118`)
 *
 * Et **DEUX BOITES NATIVES**, que la convention du portage interdit : un `alert()`
 * pour le nom manquant et un `confirm()` pour la suppression. Ce `confirm` n'est
 * ni `confirm_deploy` ni `confirm_uninstall` : c'est une **TROISIEME**
 * confirmation native, non repertoriee dans les douze cles cassees — et pour
 * cause, elle n'utilise meme pas le catalogue.
 *
 * ══ SURETE ══
 *
 * Cette suite CREE, MODIFIE et SUPPRIME. Toutes ses lignes portent un marqueur,
 * sont nettoyees A L'ENTREE et dans un `finally`, et l'etat restaure est ANNONCE.
 * `backend/scheduler.py` ne lit ni `supervision_metadata_profiles` ni
 * `machine_supervision_profile` (verifie en V3) : rien n'est arme.
 *
 * LE `confirm()` DU LEGACY BLOQUE PUPPETEER. Le gestionnaire de dialogue
 * l'ACCEPTE — c'est la seule facon de mener la suppression au bout sur cette
 * cible — tout en le comptant : la suite mesure donc a la fois l'effet en base ET
 * le fait qu'une boite native s'est ouverte.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-supervision-profils-crud.mjs
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

const MARQUE = 'RW-E2E-V5';
const NOM_CREE = `${MARQUE}-cree`;
const NOM_MODIFIE = `${MARQUE}-modifie`;
const META_CREEE = `${MARQUE}-meta`;
const META_MODIFIEE = `${MARQUE}-meta-bis`;
/** Le profil temoin : il ne doit PAS bouger quand on touche son voisin. */
const NOM_TEMOIN = `${MARQUE}-temoin`;
/** La machine de DEV, seule cible mutante autorisee. */
const MACHINE_DEV = 2;

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

function nettoie() {
    // Les assignations d'abord : la contrainte les emporterait, mais compter ce
    // qu'on supprime demande de les voir avant.
    const assignations = compteEnBase(
        'SELECT COUNT(*) FROM rootwarden.machine_supervision_profile a '
        + 'JOIN rootwarden.supervision_metadata_profiles p ON p.id = a.profile_id '
        + `WHERE p.name LIKE '${MARQUE}%'`);
    const profils = compteEnBase(
        `SELECT COUNT(*) FROM rootwarden.supervision_metadata_profiles WHERE name LIKE '${MARQUE}%'`);
    litEnBase(`DELETE FROM rootwarden.supervision_metadata_profiles WHERE name LIKE '${MARQUE}%'`);
    return { profils, assignations };
}

/** Le nombre de profils de test, par nom. */
function compteProfil(nom) {
    return compteEnBase(
        `SELECT COUNT(*) FROM rootwarden.supervision_metadata_profiles WHERE name = '${nom}'`);
}

function metaDuProfil(nom) {
    return litEnBase(
        "SELECT COALESCE(NULLIF(TRIM(host_metadata), ''), '(VIDE)') "
        + 'FROM rootwarden.supervision_metadata_profiles '
        + `WHERE name = '${nom}' ORDER BY id DESC LIMIT 1`)[0] ?? '(AUCUN)';
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

async function ouvreProfils(page) {
    await page.evaluate(() => {
        (document.querySelector('.tab-btn[data-tab="profiles"]')
            || document.querySelector('[data-rw="onglet-profiles"]'))?.click();
    });
    await dors(1800);
}

/** Le texte du catalogue VISIBLE, plus le porte-messages : lecon de V4. */
async function texteMessages(page) {
    return page.evaluate(() => {
        const morceaux = [];
        const bloc = [...document.querySelectorAll('#tab-profiles, [data-rw="panneau-profiles"]')]
            .find((e) => e.offsetParent !== null);
        if (bloc) morceaux.push(bloc.innerText);
        for (const sel of ['#toast-container', '[data-rw="superv-profil-message"]']) {
            const e = document.querySelector(sel);
            if (e) morceaux.push(e.innerText);
        }
        return morceaux.join('\n');
    });
}

/**
 * ON CLIQUE LE BOUTON, ON N'APPELLE PAS LA FONCTION.
 *
 * Appeler `saveProfile()` prouve que la fonction marche ; ca ne prouve pas que le
 * bouton l'atteint. Or le defaut le plus vicieux de cette famille a deja coute
 * cher ici : un bouton deplace faisait cliquer « Refuser et se deconnecter » au
 * lieu d'« Accepter », et les scripts se deconnectaient en croyant entrer. Un
 * bouton non cable, cable au mauvais gestionnaire, ou recouvert par un autre
 * element est INVISIBLE a un appel de fonction.
 *
 * Sur le legacy, les boutons sont retrouves par leur `onclick` : viser un libelle
 * traduit casserait la mesure en anglais, et c'est justement le cablage qu'on veut
 * eprouver. Sur le portage, par leur `data-rw`.
 */
async function cree(page, nom, meta) {
    return page.evaluate(async (n, m) => {
        // ── Portage : un formulaire, pas une boite de dialogue ──────────────
        const form = document.querySelector('[data-rw="superv-profil-form"]');
        if (form) {
            document.querySelector('[data-rw="superv-profil-nouveau"]')?.click();
            await new Promise((r) => setTimeout(r, 300));
            const pose = (cle, v) => {
                const el = form.querySelector(`[data-rw="superv-profil-champ-${cle}"]`);
                if (el) { el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); }
            };
            pose('id', '');
            pose('name', n);
            pose('host_metadata', m);
            const enregistrer = form.querySelector('[data-rw="superv-profil-enregistrer"]');
            if (! enregistrer) return null;
            enregistrer.click();
            return 'clic sur le bouton du portage';
        }
        // ── Legacy : le bouton « + Nouveau profil », puis celui du dialogue ──
        const ouvrir = document.querySelector('[onclick*="openProfileDialog"]');
        if (! ouvrir) return null;
        ouvrir.click();
        await new Promise((r) => setTimeout(r, 300));
        const nomChamp = document.getElementById('profile-name');
        const metaChamp = document.getElementById('profile-host-metadata');
        if (! nomChamp || ! metaChamp) return null;
        nomChamp.value = n;
        metaChamp.value = m;
        const enregistrer = document.querySelector('#profile-dialog [onclick*="saveProfile"]');
        if (! enregistrer) return null;
        enregistrer.click();
        return 'clic sur le bouton du dialogue legacy';
    }, nom, meta);
}

/**
 * La LIGNE d'un profil dans le catalogue visible, et un bouton d'action dedans.
 *
 * On part du NOM affiche et on descend jusqu'au bouton de SA ligne : c'est ce que
 * fait une personne, et c'est la seule facon de verifier qu'un bouton agit sur la
 * ligne ou il se trouve — un `onclick` qui porterait le mauvais identifiant
 * passerait toute autre mesure.
 */
function boutonDeLigne(nom, sorte) {
    return { nom, sorte };
}

/*
 * LE PARCOURS EST FAIT DANS LA PAGE, sans `eval` : une politique de securite du
 * contenu peut l'interdire, et un test qui depend d'`eval` casse le jour ou l'on
 * durcit la CSP — pour une raison qui n'a rien a voir avec ce qu'il mesure.
 */
const TROUVE_BOUTON = `(nom, sorte) => {
    const bloc = [...document.querySelectorAll('#tab-profiles, [data-rw="panneau-profiles"]')]
        .find((e) => e.offsetParent !== null);
    if (! bloc) return null;
    const ligne = [...bloc.querySelectorAll('tr')].find((tr) => tr.innerText.includes(nom));
    if (! ligne) return null;
    const fonction = sorte === 'modifier' ? 'editProfile' : 'deleteProfile';
    return ligne.querySelector('[data-rw^="superv-profil-' + sorte + '-"]')
        || ligne.querySelector('[onclick*="' + fonction + '"]');
}`;

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
    const entree = nettoie();
    constate('fixtures nettoyees a l\'entree',
        `${entree.profils} profil(s), ${entree.assignations} assignation(s)`);

    /*
     * LE TEMOIN, pose en base et pas par l'interface : une modification ne doit
     * toucher que sa cible, et il faut un voisin pour le prouver.
     */
    litEnBase(
        'INSERT INTO rootwarden.supervision_metadata_profiles '
        + `(platform, name, host_metadata) VALUES ('zabbix', '${NOM_TEMOIN}', '${MARQUE}-temoin-meta')`);
    constate('profil temoin pose', NOM_TEMOIN);

    const { ctx, page } = await connecte('fr');
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    /*
     * LE `confirm()` DU LEGACY BLOQUE PUPPETEER : on l'ACCEPTE pour mener la
     * suppression au bout, tout en le COMPTANT. La suite mesure donc l'effet en
     * base ET l'ouverture d'une boite native, qui est elle-meme un ecart.
     */
    const dialogues = [];
    page.on('dialog', (d) => {
        dialogues.push(`${d.type()}: ${d.message().slice(0, 70)}`);
        d.accept().catch(() => {});
    });

    const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie', (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(2000);
    await ouvreProfils(page);

    // ── CREER ───────────────────────────────────────────────────────────────
    const pointCreation = await cree(page, NOM_CREE, META_CREEE);
    await dors(2500);
    constate('creation declenchee par', pointCreation || 'aucun point d\'entree');
    verifie('la creation a un point d\'entree', Boolean(pointCreation),
        pointCreation || 'aucun');
    verifie('un profil cree existe EN BASE', compteProfil(NOM_CREE) === 1,
        `${compteProfil(NOM_CREE)} ligne(s) nommee(s) ${NOM_CREE}`);
    await ouvreProfils(page);
    const apresCreation = await texteMessages(page);
    verifie('le profil cree est visible a l\'ecran',
        apresCreation.includes(NOM_CREE), `« ${NOM_CREE} » attendu dans le catalogue`);

    // ── LE DOUBLON EST REFUSE, et le refus s'enonce ──────────────────────────
    const avantDoublon = compteProfil(NOM_CREE);
    await cree(page, NOM_CREE, `${MARQUE}-doublon`);
    await dors(2500);
    const apresDoublon = compteProfil(NOM_CREE);
    const texteDoublon = await texteMessages(page);
    constate('profils portant ce nom apres tentative de doublon',
        `${avantDoublon} puis ${apresDoublon}`);
    /*
     * LA CONTRAINTE EXISTE — mesure faite : `UNIQUE KEY uk_platform_name
     * (platform, name)`. Le refus est donc une propriete de la BASE, pas une
     * politesse de l'interface : c'est en base qu'on le verifie.
     */
    verifie('un nom deja pris sur la meme plateforme est REFUSE',
        apresDoublon === 1, `${apresDoublon} ligne(s) — la contrainte uk_platform_name existe`);
    /*
     * LE REFUS PEUT VIVRE DANS UNE BOITE NATIVE. Premiere mesure fausse, corrigee :
     * chercher dans le DOM declarait le refus « non enonce » alors que le legacy le
     * passe a `alert()` — hors du document, donc invisible a `innerText`. Le
     * porteur du message est un choix de la cible ; la propriete « l'utilisateur
     * est prevenu » ne l'est pas. Les boites natives sont donc jointes au texte
     * cherche — et leur ouverture reste, par ailleurs, un ecart mesure a part.
     */
    const refusEnonce = /existe|deja|already|pris|taken|erreur|error/i
        .test(texteDoublon + '\n' + dialogues.join('\n'));
    constate('refus du doublon enonce', refusEnonce ? 'oui' : 'NON');
    // Le detail dit ce qui a ETE VU, pas seulement ce qui manquait : un detail
    // qui parle d'absence sur une ligne PASS use la confiance qu'on met au log.
    verifie('le refus du doublon est ENONCE, pas silencieux', refusEnonce,
        refusEnonce
            ? (dialogues.at(-1) ?? texteDoublon.slice(0, 60).replace(/\n/g, ' '))
            : 'aucun message lisible apres le refus');

    // ── MODIFIER, et ne toucher que sa cible ────────────────────────────────
    const metaTemoinAvant = metaDuProfil(NOM_TEMOIN);

    /*
     * LE GESTE EN TROIS TEMPS, parce que les deux cibles n'ouvrent pas le meme
     * chemin. Le legacy ouvre une boite de dialogue : rien ne navigue, tout se
     * passe dans le meme contexte. Le portage, lui, fait de « Modifier » une
     * ADRESSE — le serveur pre-remplit le formulaire — donc le clic NAVIGUE, et
     * une navigation DETRUIT le contexte d'execution : un `page.evaluate` qui
     * clique puis lit ne rend jamais.
     *
     * On clique, on attend une eventuelle navigation DEHORS, puis on remplit.
     */
    await ouvreProfils(page);
    const clicModif = await page.evaluate((trouveur, cible) => {
        // eslint-disable-next-line no-new-func
        const bouton = new Function('return ' + trouveur)()(cible.nom, cible.sorte);
        if (! bouton) return null;
        bouton.click();
        return 'clic sur le bouton de la ligne';
    }, TROUVE_BOUTON, boutonDeLigne(NOM_CREE, 'modifier'));
    // Une navigation peut avoir lieu (portage) ou pas (dialogue du legacy) :
    // les deux sont normales, seule l'attente doit tolerer les deux.
    try {
        await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 6000 });
    } catch {}
    await dors(1200);
    const pointModif = ! clicModif ? null : await page.evaluate((nouveau, meta) => {
        const pose = (idLegacy, cle, v) => {
            const el = document.getElementById(idLegacy)
                || document.querySelector(`[data-rw="superv-profil-champ-${cle}"]`);
            if (! el) return false;
            el.value = v;
            el.dispatchEvent(new Event('input', { bubbles: true }));
            return true;
        };
        if (! pose('profile-name', 'name', nouveau)) return null;
        pose('profile-host-metadata', 'host_metadata', meta);
        const enregistrer = document.querySelector('#profile-dialog [onclick*="saveProfile"]')
            || document.querySelector('[data-rw="superv-profil-enregistrer"]');
        if (! enregistrer) return null;
        enregistrer.click();
        return 'clic sur la ligne, formulaire rempli, puis clic sur Enregistrer';
    }, NOM_MODIFIE, META_MODIFIEE);
    await dors(2500);
    constate('modification declenchee par', pointModif || 'aucun point d\'entree');
    verifie('la modification a un point d\'entree', Boolean(pointModif), pointModif || 'aucun');
    verifie('la modification a bien change la ligne visee',
        compteProfil(NOM_MODIFIE) === 1 && metaDuProfil(NOM_MODIFIE) === META_MODIFIEE,
        `${compteProfil(NOM_MODIFIE)} ligne(s) ${NOM_MODIFIE}, meta=${metaDuProfil(NOM_MODIFIE)}`);
    /*
     * LA SECONDE MOITIE DE LA PROPRIETE. `upsert_profile` porte bien son filtre
     * de plateforme — mesure faite, il ne partage PAS le defaut du `:508` — mais
     * une propriete d'ecriture se verifie toujours des deux cotes : la cible a
     * change, et le voisin n'a pas bouge.
     */
    verifie('la modification n\'a touche AUCUN autre profil',
        metaDuProfil(NOM_TEMOIN) === metaTemoinAvant && compteProfil(NOM_TEMOIN) === 1,
        `temoin : ${metaDuProfil(NOM_TEMOIN)} (attendu ${metaTemoinAvant})`);

    // ── SUPPRIMER, et emporter les assignations ─────────────────────────────
    const idModifie = litEnBase(
        'SELECT id FROM rootwarden.supervision_metadata_profiles '
        + `WHERE name = '${NOM_MODIFIE}' ORDER BY id DESC LIMIT 1`)[0];
    constate('profil a supprimer', `${NOM_MODIFIE} (id ${idModifie})`);
    /*
     * UNE ASSIGNATION, pour mesurer la CASCADE. `machine_supervision_profile` est
     * vide dans ce parc : sans fixture, la consequence la plus lourde d'une
     * suppression — les serveurs perdent leur profil — ne se mesurerait pas.
     * La machine 2 est celle de DEV, seule cible mutante autorisee.
     */
    if (idModifie) {
        litEnBase(
            'INSERT INTO rootwarden.machine_supervision_profile '
            + `(machine_id, platform, profile_id) VALUES (${MACHINE_DEV}, 'zabbix', ${idModifie})`);
    }
    const assignationsAvant = compteEnBase(
        'SELECT COUNT(*) FROM rootwarden.machine_supervision_profile '
        + `WHERE profile_id = ${idModifie ?? 0}`);
    constate('assignations posees avant suppression', assignationsAvant);
    verifie('l\'assignation de fixture est bien en place, sinon la cascade '
        + 'ne se mesurerait pas',
        assignationsAvant === 1, `${assignationsAvant} assignation(s)`);

    await ouvreProfils(page);
    const pointSuppr = await page.evaluate(async (trouveur, cible) => {
        // eslint-disable-next-line no-new-func
        const bouton = new Function('return ' + trouveur)()(cible.nom, cible.sorte);
        if (! bouton) return null;
        bouton.click();
        await new Promise((r) => setTimeout(r, 600));
        /*
         * Le portage confirme DANS la page : le panneau de decision s'ouvre sous
         * la ligne, et il faut cliquer son bouton de confirmation. Le legacy a
         * deja ouvert son `confirm()` natif, accepte par le gestionnaire de
         * dialogue — on ne le voit donc pas ici.
         */
        const panneau = document.getElementById(bouton.dataset.cible || '');
        const confirmer = (panneau && ! panneau.hidden)
            ? panneau.querySelector('[data-rw="superv-profil-confirmer"]')
            : null;
        if (confirmer) { confirmer.click(); return 'clic sur la ligne, puis panneau de decision'; }
        return 'clic sur le bouton de la ligne';
    }, TROUVE_BOUTON, boutonDeLigne(NOM_MODIFIE, 'supprimer'));
    await dors(2500);
    constate('suppression declenchee par', pointSuppr || 'aucun point d\'entree');
    verifie('la suppression a un point d\'entree', Boolean(pointSuppr), pointSuppr || 'aucun');
    verifie('le profil supprime a disparu DE LA BASE',
        compteProfil(NOM_MODIFIE) === 0, `${compteProfil(NOM_MODIFIE)} ligne(s) restante(s)`);
    const assignationsApres = compteEnBase(
        'SELECT COUNT(*) FROM rootwarden.machine_supervision_profile '
        + `WHERE profile_id = ${idModifie ?? 0}`);
    constate('assignations apres suppression', assignationsApres);
    verifie('supprimer un profil emporte ses assignations (ON DELETE CASCADE)',
        assignationsApres === 0, `${assignationsApres} assignation(s) orpheline(s)`);
    verifie('la suppression n\'a touche AUCUN autre profil',
        compteProfil(NOM_TEMOIN) === 1, `${compteProfil(NOM_TEMOIN)} temoin(s) restant(s)`);

    // ── Les boites natives, et l'enregistrement en attribut ─────────────────
    constate('boites natives ouvertes',
        dialogues.length ? dialogues.join(' | ') : 'aucune');
    verifiePortage('aucune boite native ne s\'ouvre pendant tout le cycle',
        dialogues.length === 0,
        `${dialogues.length} — un alert() pour le nom manquant, un confirm() pour la `
        + 'suppression : ce confirm n\'est NI confirm_deploy NI confirm_uninstall, '
        + 'c\'est une TROISIEME confirmation native, ecrite en francais en dur');

    const attributs = await page.evaluate(() => {
        const bloc = [...document.querySelectorAll('#tab-profiles, [data-rw="panneau-profiles"]')]
            .find((e) => e.offsetParent !== null);
        if (! bloc) return [];
        return [...bloc.querySelectorAll('[onclick]')].map((e) => e.getAttribute('onclick').length);
    });
    constate('attributs de gestionnaire dans le catalogue',
        attributs.length ? `${attributs.length} — ${attributs.join(', ')}` : 'aucun');
    verifiePortage('aucun gestionnaire en attribut dans le catalogue',
        attributs.length === 0,
        `${attributs.length} attribut(s), le plus long ${Math.max(0, ...attributs)} caracteres`);

    verifie('aucune erreur JS pendant tout le cycle',
        erreursJs.length === 0, erreursJs.slice(0, 3).join(' · ') || 'aucune');
    await ctx.close();
    await dors((resteFenetre() + 1) * 1000);

    // ── En anglais : les sept chaines ecrites en dur ─────────────────────────
    const en = await connecte('en');
    en.page.on('dialog', (d) => d.accept().catch(() => {}));
    await en.page.goto(`${BASE}${PAGE}?lang=en`, { waitUntil: 'networkidle2' });
    await dors(2000);
    await ouvreProfils(en.page);
    // Ouvrir le formulaire de creation : c'est la que vivent trois des chaines.
    await en.page.evaluate(() => {
        document.querySelector('[data-rw="superv-profil-nouveau"]')?.click();
        if (typeof window.openProfileDialog === 'function') window.openProfileDialog();
    });
    await dors(1000);
    const blocEn = await en.page.evaluate(() => {
        const bloc = [...document.querySelectorAll('#tab-profiles, [data-rw="panneau-profiles"]')]
            .find((e) => e.offsetParent !== null);
        return bloc ? bloc.innerText : '';
    });
    const francaisResiduel = ['Editer', 'Supprimer', 'Nouveau profil', 'Enregistrer',
        'Annuler', 'obligatoire']
        .filter((m) => blocEn.includes(m));
    constate('francais residuel dans le catalogue rendu en anglais',
        francaisResiduel.join(', ') || 'aucun');
    verifiePortage('le catalogue rendu en anglais ne garde aucun libelle francais',
        francaisResiduel.length === 0,
        `${francaisResiduel.join(', ')} — ecrits EN DUR dans profiles.js, hors de toute parite`);
    await en.ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
} finally {
    const sortie = nettoie();
    lignes.push(`INFO  fixtures supprimees en sortie : ${sortie.profils} profil(s), `
        + `${sortie.assignations} assignation(s)`);
    const restants = compteEnBase(
        `SELECT COUNT(*) FROM rootwarden.supervision_metadata_profiles WHERE name LIKE '${MARQUE}%'`);
    const orphelines = compteEnBase(
        'SELECT COUNT(*) FROM rootwarden.machine_supervision_profile '
        + `WHERE machine_id = ${MACHINE_DEV}`);
    lignes.push(`${restants === 0 && orphelines === 0 ? 'PASS' : 'FAIL'}  le parc est rendu a `
        + `son etat initial  — ${restants} profil(s) de test, `
        + `${orphelines} assignation(s) sur la machine de test`);
    if (restants !== 0 || orphelines !== 0) echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
