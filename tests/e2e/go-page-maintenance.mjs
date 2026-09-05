/**
 * go-page-maintenance.mjs - La page `maintenance/` : fenetres de maintenance.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/maintenance/index.php
 *   laravel  http://localhost:8444/maintenance
 *
 * ══ ⚠ POURQUOI CETTE SUITE POURRAIT EMPOISONNER LE LOT ENTIER ═══════════════
 *
 * Releve en LISANT `backend/maintenance.py:102-143` avant d'ecrire un seul clic.
 * La logique s'INVERSE :
 *
 *   - **aucune** fenetre activee  -> toute action mutante est AUTORISEE ;
 *   - **une** fenetre activee     -> autorisee SEULEMENT si l'instant courant
 *                                    tombe dedans.
 *
 * Creer une fenetre activee qui ne couvre pas maintenant fait donc rendre **423**
 * a toute action mutante, pour les roles **< 3** (le role 3 a un contournement
 * journalise). Les suites supervision du LOT tournent en **role 2**, et
 * l'enforcement vit dans d'AUTRES modules (`routes/updates.py:19`,
 * `routes/monitoring.py:229`) : l'echec n'aurait aucun rapport visible avec
 * `maintenance/`, et on le chercherait longtemps.
 *
 * ══ LA FIXTURE, ET LES DEUX AUTRES QUI ONT ETE ECARTEES ════════════════════
 *
 *   - fenetre **desactivee** : sure, mais elle n'exerce pas le chemin active ;
 *   - fenetre **toujours ouverte** (7 jours, 00:00->23:59) : `start <= t <= end`
 *     laisse les **59 dernieres secondes de chaque jour** hors fenetre — un 423
 *     possible, rare et inexplicable. Ecartee ;
 *   - **retenue** : fenetre **activee, de portee `machine`, sur `srv-zabbix`**.
 *     `is_allowed` filtre `scope = 'global' OR machine_id = ?`, et **aucune suite
 *     ne mute cette machine** — la regle permanente l'interdit. La fixture ne
 *     peut donc bloquer que ce qui est **deja interdit**.
 *
 * NOMMER cette machine dans une ligne d'horaire n'est pas la JOINDRE : aucune
 * session SSH, aucune requete ne part vers elle.
 *
 * **GARDE-FOU** : juste apres la creation, la suite RELIT `scope` et
 * `machine_id` en base. Si la portee s'averait `global`, la ligne est supprimee
 * IMMEDIATEMENT et l'assertion echoue bruyamment — une fixture qui derape ne
 * doit pas survivre a l'etape qui la pose.
 *
 * Usage :
 *   cd tests/e2e && node go-page-maintenance.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { execFileSync } from 'node:child_process';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

/** Role 3 AVEC `can_admin_portal` : le seul qui atteint la page. */
const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
/** Role 2 SANS la permission — chemin « permission » de la garde. */
const COMPTE_ROLE = 'rw-test-admin';
const SECRET_ROLE = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';
/** Role 1 — chemin « role ». D-5 : lecture seule. */
const COMPTE_BAS = 'rw-test-user';
const SECRET_BAS = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';

/** Le nom d'epreuve borne le nettoyage. Aucune fenetre reelle ne le porte. */
const NOM = 'fenetre-epreuve-e2e';
/** La machine que la regle permanente interdit de muter — donc la plus sure. */
const MACHINE_SURE = 1;

/*
 * ══ LA FENETRE D'EPREUVE EST CONSTRUITE POUR SEPARER LES DEUX HORLOGES ══════
 *
 * Bornes : [heure locale - 20 min, heure locale + 20 min], tous les jours.
 *
 * Cette plage contient l'instant du NAVIGATEUR par construction. Contient-elle
 * celui du SERVEUR ? Seulement si les deux horloges concordent. Avec les deux
 * heures d'ecart mesurees, non — et c'est tout l'interet :
 *
 *   l'ancien calcul, cote navigateur -> « active maintenant »   (FAUX)
 *   le verdict du backend            -> « fermee »              (JUSTE, il refuse)
 *
 * La suite n'attend donc PAS une valeur ecrite d'avance : elle demande son
 * verdict au conteneur qui applique la regle, et exige que la page dise LA MEME
 * CHOSE. Si un jour les deux horloges sont alignees, l'assertion tient encore —
 * elle attendra « active ». Ce qui est mesure, c'est l'ACCORD, pas un etat.
 */
const MARGE = 20;
const _local = (() => { const d = new Date(); return (d.getHours() * 60) + d.getMinutes(); })();
const DEBUT_MIN = ((_local - MARGE) % 1440 + 1440) % 1440;
const FIN_MIN = (_local + MARGE) % 1440;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion?lang=fr',
        page: '/maintenance',
        nouvelle: '[data-rw="maint-nouvelle"]',
        formulaire: '[data-rw="maint-formulaire"]',
        nom: '[data-rw="maint-nom"]',
        portee: '[data-rw="maint-portee"]',
        machine: '[data-rw="maint-machine"]',
        jours: '[data-rw="maint-jour"]',
        debut: '[data-rw="maint-debut"]',
        fin: '[data-rw="maint-fin"]',
        activee: '[data-rw="maint-activee"]',
        enregistrer: '[data-rw="maint-enregistrer"]',
        corps: '[data-rw="maint-corps"]',
        basculer: '[data-rw="maint-basculer"]',
        supprimer: '[data-rw="maint-supprimer"]',
        confirmerEnPage: '[data-rw="maint-confirmer"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/maintenance/index.php',
        nouvelle: '#new-win-btn',
        formulaire: '#win-form',
        nom: '#w-name',
        portee: '#w-scope',
        machine: '#w-machine',
        jours: '.wd',
        debut: '#w-start',
        fin: '#w-end',
        activee: '#w-enabled',
        enregistrer: '#w-save',
        corps: '#win-tbody',
        basculer: null,
        supprimer: null,
        confirmerEnPage: null,
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
function verifie(l, ok, d, __quatrieme) {
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
 note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
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
    constate(l, `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

function compteEpreuve() {
    return compteEnBase(
        `SELECT COUNT(*) FROM rootwarden.maintenance_windows WHERE name = '${NOM}'`);
}
/** La ligne d'epreuve, telle qu'elle est REELLEMENT en base. */
function ligneEpreuve() {
    const r = litEnBase("SELECT CONCAT(scope,'|',IFNULL(machine_id,'NULL'),'|',enabled,'|',days,"
        + `'|',start_time,'|',end_time) FROM rootwarden.maintenance_windows WHERE name = '${NOM}'`);
    const [portee, machine, activee, jours, debut, fin] = (r[0] || '|||||').split('|');

    return { portee, machine, activee, jours, debut, fin, brut: r[0] || '(absente)' };
}
/** Combien de fenetres ACTIVEES au total ? Zero = rien n'est bloque. */
function activeesEnBase() {
    return compteEnBase('SELECT COUNT(*) FROM rootwarden.maintenance_windows WHERE enabled = 1');
}
function supprimeEpreuve() {
    litEnBase(`DELETE FROM rootwarden.maintenance_windows WHERE name = '${NOM}'`);
}

/**
 * L'HEURE DU CONTENEUR QUI APPLIQUE LA REGLE, en minutes depuis minuit.
 *
 * Ce n'est pas un detail d'implementation : c'est la seule horloge qui decide.
 * Mesure du 2026-08-25 — le navigateur est en CEST, `rootwarden_python` en UTC,
 * **deux heures d'ecart**. Une suite qui supposerait les deux egales mesurerait
 * exactement le defaut qu'elle est censee detecter, et le declarerait conforme.
 *
 * Lu par `docker exec`, comme les lectures en base de cette meme suite : la
 * propriete a mesurer est un decalage entre deux processus, elle n'a aucune
 * surface a cliquer.
 */
function minutesServeur() {
    const brut = execFileSync('docker', ['exec', 'rootwarden_python', 'date', '+%H:%M'],
        { encoding: 'utf8', timeout: 15000 }).trim();
    const [h, m] = brut.split(':').map(Number);

    return { texte: brut, minutes: (h * 60) + m };
}

function minutesLocales() {
    const d = new Date();

    return { texte: `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`,
             minutes: (d.getHours() * 60) + d.getMinutes() };
}

/** `HH:MM` a partir de minutes depuis minuit, en repliant sur 24 h. */
function versHM(minutes) {
    const m = ((minutes % 1440) + 1440) % 1440;

    return `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
}

/**
 * Le verdict du backend pour une fenetre [debut, fin] tous les jours, a l'instant
 * du serveur. Miroir de `_in_window` restreint au cas « tous les jours », qui est
 * celui de la fixture : la condition de jour est alors toujours vraie et il ne
 * reste que la comparaison d'heures.
 */
function ouverteCoteServeur(debutMin, finMin) {
    const t = minutesServeur().minutes;

    return debutMin <= finMin
        ? (t >= debutMin && t <= finMin)
        : (t >= debutMin || t <= finMin);
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];

async function connecte(nom, secret) {
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(40000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const boitesNatives = [];
    page.on('dialog', async (d) => {
        boitesNatives.push(d.message());
        try { await d.accept(); } catch { /* deja fermee */ }
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

    return { ctx, page, erreursJs, boitesNatives };
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

async function attendChargement(page) {
    for (let i = 0; i < 40; i += 1) {
        const pret = await page.evaluate((sel) => {
            const tb = document.querySelector(sel);
            if (! tb) return false;

            return ! /chargement|loading/i.test(tb.textContent || '');
        }, C.corps);
        if (pret) return true;
        await dors(250);
    }

    return false;
}

/*
 * Les libelles des trois etats, tels qu'ils sont REELLEMENT ecrits dans les deux
 * portails (releve le 2026-08-25) :
 *
 *   legacy  fr « Ouverte » / « Fermee »            en « Open » / « Closed »
 *   portage fr « Ouverte maintenant » / « Fermée maintenant » / « Désactivée »
 *           en « Open now » / « Closed now » / « Disabled »
 *
 * D'ou `ferm` et non `fermée` : le legacy ecrit son libelle sans accent, et une
 * expression accentuee ne l'aurait pas trouve. Et « Désactivée » ne contient ni
 * `ouvert` ni `ferm`, donc les trois etats restent distincts.
 */
const MOT_ACTIF = /ouvert|open/i;
const MOT_FERME = /ferm|closed/i;

/**
 * L'etat annonce POUR LA LIGNE D'EPREUVE, et non pour le tableau entier.
 *
 * Lire tout le tableau melangerait les etats d'autres fenetres, reelles, dont la
 * suite ne sait rien : une seule ligne « Ouverte » ailleurs suffirait a faire
 * passer l'assertion sans que la ligne mesuree y soit pour rien. La colonne
 * d'etat est la cinquieme dans les deux portails.
 */
function etatLigneEpreuve(page) {
    return page.evaluate((sel, nom) => {
        const tb = document.querySelector(sel);
        if (! tb) return null;
        const ligne = Array.from(tb.querySelectorAll('tr'))
            .find((tr) => (tr.textContent || '').includes(nom));
        if (! ligne) return null;
        const cellules = Array.from(ligne.querySelectorAll('td'));

        return {
            etat: cellules[4] ? (cellules[4].textContent || '').replace(/\s+/g, ' ').trim() : '',
            ligne: (ligne.textContent || '').replace(/\s+/g, ' ').trim(),
        };
    }, C.corps, NOM);
}

function texteTableau(page) {
    return page.evaluate((sel) => {
        const tb = document.querySelector(sel);

        return tb ? (tb.textContent || '').replace(/\s+/g, ' ') : '';
    }, C.corps);
}

/** Le formulaire est-il VISIBLE ? On mesure le rendu, pas l'attribut. */
function formulaireVisible(page) {
    return page.evaluate((sel) => {
        const e = document.querySelector(sel);
        if (! e) return null;

        return getComputedStyle(e).display !== 'none' && ! e.hidden;
    }, C.formulaire);
}

/*
 * ══ LE CONSTAT D'ARCHIVAGE, AVANT TOUT LE RESTE ═════════════════════════════
 *
 * Une partie archivee ne doit pas laisser une suite ROUGE derriere elle : plus
 * personne ne lit les rouges. Tant que la partie est servie, ce bloc est inerte
 * et la suite se joue normalement.
 *
 * LES TROIS CHEMINS SONDES EXISTENT VRAIMENT — mesure du 2026-08-25, AVANT le
 * `git mv`, pour que les assertions ne soient pas creuses :
 *   /maintenance/            302
 *   /maintenance/index.php   302
 *   /maintenance/js/main.js  200
 * Aucun ne rendait 404. Apres archivage, les trois doivent le rendre.
 *
 * `/maintenance/check` et `/maintenance/windows` ne sont PAS sondes : ce sont des
 * routes du BACKEND, que le portage appelle toujours. Les confondre avec des
 * chemins de page ferait echouer un constat sur des routes bien vivantes.
 */
if (CIBLE === 'legacy') {
    const archivee = await constateArchivage({
        base: BASE,
        chemin: '/maintenance/',
        fichiers: ['/maintenance/index.php', '/maintenance/js/main.js'],
        verifie, constate,
    });
    if (archivee) {
        litEnBase('DELETE FROM rootwarden.login_attempts');
        const s = await connecte(COMPTE, SECRET);
        await verifieMenuLegacy(s.page, '/maintenance', verifie, constate);
        for (const ctx of contextes) { try { await ctx.close(); } catch {} }
        try { await navigateur.close(); } catch {}
        litEnBase('DELETE FROM rootwarden.login_attempts');
        note('');
        note(`${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
        process.exit(echecs > 0 ? 1 : 0);
    }
}

const auDepart = compteEpreuve();
const activeesAuDepart = activeesEnBase();

try {
    constate('cible', `${CIBLE} — ${BASE}`);
    constate('fenetres ACTIVEES en base au depart', `${activeesAuDepart}`);
    verifie('aucune fenetre d\'epreuve ne traine', auDepart === 0, `${auDepart}`);
    litEnBase('DELETE FROM rootwarden.login_attempts');

    const s = await connecte(COMPTE, SECRET);

    await etape('la page est servie au role 3 avec la permission', async () => {
        const r = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        constate('statut', `HTTP ${r ? r.status() : 0}`);
        verifie('la page maintenance est servie', r && r.status() === 200,
            `HTTP ${r ? r.status() : 0}`);
        await attendChargement(s.page);
    });

    await etape('le formulaire est CACHE avant qu\'on le demande', async () => {
        const visible = await formulaireVisible(s.page);
        constate('formulaire au chargement', `visible=${visible}`);
        verifie('le formulaire de creation est cache au depart', visible === false,
            `visible=${visible}`);
    });

    await etape('un clic sur « nouvelle » l\'ouvre', async () => {
        await s.page.click(C.nouvelle);
        await dors(400);
        const visible = await formulaireVisible(s.page);
        verifie('le formulaire s\'ouvre au clic', visible === true, `visible=${visible}`);
    });

    await etape('la portee est une LISTE FERMEE', async () => {
        const vu = await s.page.evaluate((sel) => {
            const e = document.querySelector(sel);
            if (! e) return null;

            return {
                balise: e.tagName.toLowerCase(),
                valeurs: e.options ? Array.from(e.options).map((o) => o.value) : [],
            };
        }, C.portee);
        verifie('le champ de portee existe', vu !== null);
        if (! vu) return;
        constate('portees proposees', `${vu.balise} — ${vu.valeurs.join(', ')}`);
        /* La colonne est un `enum('global','machine')` en base : offrir une saisie
         * libre ici produirait une valeur que MySQL refuserait. */
        verifie('la portee se choisit dans une liste',
            vu.balise === 'select' && vu.valeurs.includes('global') && vu.valeurs.includes('machine'),
            vu.valeurs.join(', '));
    });

    await etape('un nom vide est refuse SANS ecrire', async () => {
        const avant = compteEpreuve();
        await s.page.click(C.enregistrer);
        await dors(900);
        verifie('enregistrer sans nom n\'ecrit rien', compteEpreuve() === avant,
            `${compteEpreuve()} vs ${avant}`);
    });

    await etape('aucun jour coche est refuse SANS ecrire', async () => {
        const champNom = await s.page.$(C.nom);
        await champNom.click({ clickCount: 3 });
        await champNom.type(NOM, { delay: 8 });
        /* On decoche tout, par des CLICS. */
        const cases = await s.page.$$(C.jours);
        for (const c of cases) {
            const coche = await c.evaluate((e) => e.checked);
            if (coche) await c.click();
        }
        const avant = compteEpreuve();
        await s.page.click(C.enregistrer);
        await dors(900);
        verifie('enregistrer sans aucun jour n\'ecrit rien', compteEpreuve() === avant,
            `${compteEpreuve()} vs ${avant}`);
    });

    await etape('CREATION, et le garde-fou de la fixture', async () => {
        /* Portee `machine` puis la machine sure : c'est ce qui rend cette
         * fixture incapable de bloquer une action du LOT. */
        await s.page.select(C.portee, 'machine');
        await dors(300);
        await s.page.select(C.machine, String(MACHINE_SURE));
        const cases = await s.page.$$(C.jours);
        for (const c of cases) {
            const coche = await c.evaluate((e) => e.checked);
            if (! coche) await c.click();
        }

        /*
         * LES HEURES, AU CLAVIER. Un champ `type="time"` se remplit en tapant
         * ses chiffres : on selectionne le contenu puis on tape, exactement comme
         * un exploitant. Les bornes encadrent l'heure LOCALE — voir l'encadre en
         * tete de fichier : c'est ce qui separe les deux horloges.
         */
        /*
         * UN `input[type=time]` NE SE VIDE PAS AU TRIPLE-CLIC. Mesure du
         * 2026-08-25 : `click({ clickCount: 3 })` puis `type('1847')` a laisse
         * `22:47` — le champ est un composite de segments, et le clic avait pose
         * le caret sur les MINUTES ; les deux premiers chiffres se sont perdus,
         * les deux suivants ont ecrase les minutes seules. La suite accusait la
         * page alors que le defaut etait dans le geste.
         *
         * On revient donc au premier segment par des fleches — un vrai geste de
         * clavier, et le seul qui replace le caret a coup sur d'ou qu'il vienne.
         */
        for (const [selecteur, valeur] of [[C.debut, versHM(DEBUT_MIN)], [C.fin, versHM(FIN_MIN)]]) {
            const champ = await s.page.$(selecteur);
            await champ.click();
            await s.page.keyboard.press('ArrowLeft');
            await s.page.keyboard.press('ArrowLeft');
            await champ.type(valeur.replace(':', ''), { delay: 40 });
        }
        const heuresSaisies = await s.page.evaluate((a, b) => [
            document.querySelector(a).value, document.querySelector(b).value,
        ], C.debut, C.fin);
        constate('heures saisies au clavier', heuresSaisies.join(' -> '));
        verifie('les deux heures sont bien saisies',
            heuresSaisies[0] === versHM(DEBUT_MIN) && heuresSaisies[1] === versHM(FIN_MIN),
            `attendu ${versHM(DEBUT_MIN)} -> ${versHM(FIN_MIN)}, lu ${heuresSaisies.join(' -> ')}`);

        await s.page.click(C.enregistrer);
        await dors(1600);

        const compte = compteEpreuve();
        constate('fenetres d\'epreuve en base', `${compte}`);
        verifie('la creation ecrit UNE fenetre', compte === 1, `${compte}`);
        if (compte === 0) return;

        const l = ligneEpreuve();
        constate('ligne ecrite', l.brut);

        /*
         * LE GARDE-FOU. Si la portee n'est pas `machine` sur la machine sure, la
         * fixture peut bloquer le LOT : on la retire A L'INSTANT et on echoue
         * bruyamment, plutot que de continuer avec une bombe en base.
         */
        const sure = l.portee === 'machine' && String(l.machine) === String(MACHINE_SURE);
        if (! sure) {
            supprimeEpreuve();
            verifie('LA FIXTURE EST SURE : portee machine sur la machine convenue', false,
                `portee=${l.portee} machine=${l.machine} — ligne SUPPRIMEE immediatement`);

            return;
        }
        verifie('la fixture est sure : portee machine sur la machine convenue', true,
            `${l.portee} / machine ${l.machine}`);
        verifie('la fenetre est bien ACTIVEE', String(l.activee) === '1', `enabled=${l.activee}`);

        const texte = await texteTableau(s.page);
        verifie('la fenetre apparait dans le tableau', texte.includes(NOM), texte.slice(0, 150));
    });

    await etape('LE VERDICT AFFICHE EST-IL CELUI QUI SERA APPLIQUE ?', async () => {
        /*
         * L'assertion centrale de ce sous-lot.
         *
         * La fenetre encadre l'heure LOCALE (± 20 min). Un calcul fait dans le
         * navigateur la declare donc « active maintenant », toujours. Le backend,
         * lui, tranche sur SON horloge — et les deux ne sont pas la meme.
         *
         * On ne compare pas la page a une valeur ecrite d'avance : on demande son
         * verdict au conteneur qui applique la regle, et on exige que la page dise
         * la meme chose. Ce qui est mesure est l'ACCORD, pas un etat.
         */
        const serveur = minutesServeur();
        const local = minutesLocales();
        const ecart = Math.abs(serveur.minutes - local.minutes);
        constate('horloge du navigateur', local.texte);
        constate('horloge du conteneur qui applique', serveur.texte);
        constate('ecart entre les deux', `${ecart} min`);

        const ouvertServeur = ouverteCoteServeur(DEBUT_MIN, FIN_MIN);
        constate('verdict du backend pour cette fenetre',
            ouvertServeur ? 'OUVERTE' : 'FERMEE');
        constate('ce qu\'un calcul cote navigateur dirait', 'OUVERTE (la fenetre encadre l\'heure locale)');

        const lu = await etatLigneEpreuve(s.page);
        if (lu === null) {
            verifie('la ligne d\'epreuve est presente dans le tableau', false,
                'introuvable — les assertions d\'etat ne peuvent rien mesurer');

            return;
        }
        /*
         * ON LIT LA LIGNE ENTIERE, PAS UNE CELLULE PAR SON INDEX.
         *
         * La version precedente lisait `cellules[4]`, l'etat etant la cinquieme
         * colonne — verifie sur les deux cibles a l'epoque. Mais un index EST une
         * hypothese de structure : si l'ordre des colonnes change d'un cote, la
         * suite lit silencieusement la mauvaise cellule et conclut de travers.
         *
         * Leçon payee le 2026-08-26 par la seconde session sur `adm/` : une
         * extraction qui suppose une structure suppose la structure d'UNE des
         * deux cibles. La son soustraction de texte marchait sur le legacy et
         * vidait l'aide sur le portage — le PASS ne mesurait rien.
         *
         * Le texte de la LIGNE est independant du balisage, et il reste borne a
         * la bonne fenetre. Verifie qu'aucun autre libelle de la ligne ne
         * collisionne : les etats sont « Ouverte maintenant », « Fermée
         * maintenant » et « Désactivée » ; les boutons « Désactiver » et
         * « Supprimer » ne contiennent ni `ouvert` ni `ferm`. Et si un jour une
         * colonne en contenait, les deux motifs seraient vrais a la fois et
         * l'assertion echouerait BRUYAMMENT — ce qu'un mauvais index ne fait pas.
         */
        const ditActive = MOT_ACTIF.test(lu.ligne);
        const ditFermee = MOT_FERME.test(lu.ligne);
        constate('ligne d\'epreuve', `« ${lu.ligne.slice(0, 110)} »`);
        constate('cellule d\'etat (releve, non assertee)', `« ${lu.etat} »`);

        /* Les deux cibles doivent au moins DIRE quelque chose de lisible, et un
         * SEUL des deux etats : « ouverte » et « fermee » a la fois signalerait
         * une cellule mal lue plutot qu'un etat. */
        verifie('la ligne annonce un etat lisible, et un seul',
            ditActive !== ditFermee,
            `actif=${ditActive} ferme=${ditFermee} — ligne « ${lu.ligne.slice(0, 90)} »`);

        /*
         * ET VOICI L'ECART. Quand les deux horloges divergent, le legacy annonce
         * l'inverse de ce que fera le backend. Sur la cible legacy la mesure est
         * relevee et non comptee en echec : on ne soigne pas ce qu'on demonte.
         */
        if (ecart <= 1) {
            constate('les deux horloges concordent aujourd\'hui',
                'l\'ecart n\'est pas observable dans ce rejeu — l\'assertion vaut encore, '
                + 'elle attend « active » des deux cotes');
        }
        verifiePortage('l\'etat affiche est celui que le backend APPLIQUERA',
            ditActive === ouvertServeur,
            `la page dit « ${ditActive ? 'active' : 'fermee'} » et le backend dira `
            + `« ${ouvertServeur ? 'active' : 'fermee'} » — verdict calcule dans le navigateur `
            + `(${local.texte}) au lieu du serveur (${serveur.texte})`);
    });

    await etape('L\'HORLOGE DU SERVEUR EST NOMMEE quand elle differe', async () => {
        /*
         * Un verdict juste mais inexplicable ne vaut qu'a moitie : lire « fermee »
         * sur une plage qui contient visiblement l'heure qu'il est passerait pour
         * une panne. La page doit dire SUR QUELLE HORLOGE elle a tranche — et ne
         * le dire que si elle differe, une mention permanente cessant d'etre lue.
         */
        const serveur = minutesServeur();
        const local = minutesLocales();
        const differe = Math.abs(serveur.minutes - local.minutes) > 1;
        const vu = await s.page.evaluate(() => {
            const e = document.querySelector('[data-rw="maint-horloge"]');
            if (! e) return null;

            return { visible: ! e.hidden && getComputedStyle(e).display !== 'none',
                     texte: (e.textContent || '').replace(/\s+/g, ' ').trim() };
        });
        constate('ligne d\'horloge', vu ? `visible=${vu.visible} « ${vu.texte.slice(0, 90)} »` : '(absente)');
        verifiePortage('la page nomme l\'horloge du serveur exactement quand elle differe',
            vu !== null && vu.visible === differe,
            vu === null
                ? 'aucun porte-message d\'horloge dans la page'
                : `differe=${differe} mais visible=${vu.visible}`);
        if (differe && vu && vu.visible) {
            verifiePortage('et elle cite l\'heure du serveur, pas celle du navigateur',
                vu.texte.includes(serveur.texte) && ! vu.texte.includes(local.texte),
                `cite « ${vu.texte.slice(0, 90)} », serveur ${serveur.texte}, navigateur ${local.texte}`);
        }
    });

    await etape('LA PORTEE EST DITE JUSTE : une machine n\'est pas la flotte', async () => {
        /*
         * La fixture est limitee a UNE machine, donc la flotte n'est PAS
         * restreinte — seule cette machine l'est. La requete du backend le dit :
         * `WHERE enabled = 1 AND (scope = 'global' OR machine_id = ?)`.
         *
         * Le premier jet du portage comptait les fenetres activees sans regarder
         * leur portee et affichait « Flotte restreinte » des la premiere. C'etait
         * faux, et faux precisement dans le cas de cette suite. Sans cette
         * assertion, la correction n'aurait aucun temoin.
         */
        const globales = compteEnBase("SELECT COUNT(*) FROM rootwarden.maintenance_windows "
            + "WHERE enabled = 1 AND scope = 'global'");
        constate('fenetres GLOBALES activees en base', `${globales}`);
        verifie('aucune fenetre globale activee — la flotte est libre', globales === 0, `${globales}`);

        const pastille = await s.page.evaluate(() => {
            const e = document.querySelector('[data-rw="maint-etat-flotte"]');
            if (! e) return null;

            return { etat: e.getAttribute('data-rw-etat'),
                     texte: (e.textContent || '').replace(/\s+/g, ' ').trim() };
        });
        constate('pastille d\'etat', pastille ? `${pastille.etat} — « ${pastille.texte} »` : '(absente)');
        verifiePortage('la pastille dit « machines » et non « flotte »',
            pastille !== null && pastille.etat === 'machines',
            pastille === null
                ? 'le legacy n\'affiche aucun etat d\'ensemble : il faut lire le tableau et compter'
                : `etat annonce « ${pastille.etat} » alors qu\'aucune fenetre globale n\'est activee`);
    });

    await etape('BASCULE : l\'etat change VRAIMENT en base', async () => {
        const avant = ligneEpreuve().activee;
        if (CIBLE === 'legacy') {
            /* Deux boutons par ligne : bascule puis suppression. */
            const boutons = await s.page.$$(`${C.corps} button`);
            constate('boutons dans la ligne', `${boutons.length}`);
            if (boutons.length >= 2) await boutons[0].click();
        } else {
            await s.page.click(C.basculer);
        }
        await dors(1500);
        const apres = ligneEpreuve().activee;
        constate('activee avant / apres', `${avant} -> ${apres}`);
        verifie('la bascule change l\'etat en base', avant !== apres, `${avant} -> ${apres}`);
        /* La fixture reste sans effet dans les DEUX sens : sa portee est limitee
         * a une machine qu'aucune suite ne mute. */
        verifie('aucune fenetre GLOBALE activee n\'a apparu',
            compteEnBase("SELECT COUNT(*) FROM rootwarden.maintenance_windows "
                + "WHERE enabled = 1 AND scope = 'global'") === 0, 'aucune');
    });

    await etape('SUPPRESSION : par un clic, et elle disparait vraiment', async () => {
        if (CIBLE === 'legacy') {
            const boutons = await s.page.$$(`${C.corps} button`);
            if (boutons.length >= 2) await boutons[boutons.length - 1].click();
        } else {
            await s.page.click(C.supprimer);
            await s.page.waitForSelector(C.confirmerEnPage, { visible: true, timeout: 8000 });

            /*
             * LE PANNEAU OCCUPE-T-IL LA LARGEUR DE LA LIGNE ?
             *
             * Temoin du correctif d'E-139, pose ici parce que c'est le seul
             * moment ou le panneau est ouvert. `.rw-panneau-decision` porte
             * `display: flex` : pose sur un `<td>`, il ecrasait
             * `display: table-cell`, sortait la cellule du modele de tableau et
             * faisait ignorer son `colspan` — le panneau s'arretait au tiers de
             * la largeur. Aucune assertion DOM ne pouvait le voir, `colSpan`
             * valant bien 6. On mesure donc la largeur RENDUE.
             *
             * Seuil a 92 % : le panneau porte des marges internes et ne peut pas
             * atteindre 100 % de la largeur du tableau.
             */
            const largeurs = await s.page.evaluate((selCorps) => {
                const table = document.querySelector(selCorps)?.closest('table');
                const panneau = document.querySelector('[data-rw="maint-panneau"] .rw-panneau-decision');
                if (! table || ! panneau) return null;

                return {
                    table: Math.round(table.getBoundingClientRect().width),
                    panneau: Math.round(panneau.getBoundingClientRect().width),
                };
            }, C.corps);
            constate('largeur panneau / tableau',
                largeurs ? `${largeurs.panneau} / ${largeurs.table} px` : '(introuvable)');
            verifie('le panneau de decision occupe la largeur de la ligne',
                largeurs !== null && largeurs.panneau >= largeurs.table * 0.92,
                largeurs ? `${largeurs.panneau} px sur ${largeurs.table} px`
                    : 'panneau ou tableau introuvable');

            await s.page.click(C.confirmerEnPage);
        }
        await dors(1600);
        const reste = compteEpreuve();
        verifie('la suppression retire la fenetre de la base', reste === 0, `${reste}`);
        const texte = await texteTableau(s.page);
        verifie('elle disparait aussi du tableau', ! texte.includes(NOM), texte.slice(0, 150));
    });

    await etape('la boite native, et ce que le portage doit faire a la place', async () => {
        constate('boites natives rencontrees', s.boitesNatives.length
            ? s.boitesNatives.join(' | ') : 'aucune');
        verifiePortage('aucune boite native : la decision se prend EN PAGE',
            s.boitesNatives.length === 0,
            'le legacy pose un `confirm()` natif — il recouvre la ligne sur laquelle on '
            + 'decide, ne se style pas, et BLOQUE Puppeteer');
    });

    await etape('aucune erreur JS', async () => {
        verifie('aucune erreur JS pendant la sequence', s.erreursJs.length === 0,
            s.erreursJs.join(' | ') || 'aucune');
    });

    /* ══ LES DEUX CHEMINS DE LA GARDE ══════════════════════════════════════ */
    await etape('un role 2 SANS la permission est refuse', async () => {
        const r2 = await connecte(COMPTE_ROLE, SECRET_ROLE);
        const r = await r2.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const corps = (await r2.page.evaluate(() => document.body.innerText)).slice(0, 160);
        constate('role 2 sans can_admin_portal', `HTTP ${r ? r.status() : 0}`);
        verifie('le role seul ne suffit pas : la permission est exigee',
            (r && r.status() === 403) || /refus|interdit|forbidden/i.test(corps),
            `HTTP ${r ? r.status() : 0} — ${corps.replace(/\s+/g, ' ').slice(0, 70)}`);
    });

    await etape('un role 1 est refuse', async () => {
        const r1 = await connecte(COMPTE_BAS, SECRET_BAS);
        const r = await r1.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const corps = (await r1.page.evaluate(() => document.body.innerText)).slice(0, 160);
        constate('role 1', `HTTP ${r ? r.status() : 0}`);
        verifie('un compte de role 1 est refuse',
            (r && r.status() === 403) || /refus|interdit|forbidden/i.test(corps),
            `HTTP ${r ? r.status() : 0}`);
    });
} catch (e) {
    verifie('deroulement de la suite', false, String(e).split('\n')[0]);
} finally {
    for (const ctx of contextes) { try { await ctx.close(); } catch {} }
    try { await navigateur.close(); } catch {}
    /*
     * NETTOYAGE BORNE PAR LE NOM, jamais par type : un
     * `DELETE FROM maintenance_windows` emporterait des fenetres legitimes le
     * jour ou l'exploitant en aura pose. Etat RELU pour etre prouve, ET on
     * verifie qu'on rend une base ou RIEN n'est bloque.
     */
    try {
        supprimeEpreuve();
        litEnBase('DELETE FROM rootwarden.login_attempts');
    } catch (e) {
        note(`FAIL  nettoyage de la fixture  — ${String(e.message || e).split('\n')[0]}`);
        echecs++;
    }
    const reste = compteEpreuve();
    verifie('aucune fenetre d\'epreuve ne subsiste', reste === 0, `${reste}`);
    const activees = activeesEnBase();
    constate('fenetres ACTIVEES en base a la sortie', `${activees}`);
    verifie('l\'etat de blocage rendu est celui de l\'entree', activees === activeesAuDepart,
        `${activeesAuDepart} a l'entree, ${activees} a la sortie — toute difference peut faire `
        + 'rendre 423 aux suites suivantes');
}

note('');
note(`${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — ${etapes} etapes, cible ${CIBLE}`);
process.exit(echecs === 0 ? 0 : 1);
