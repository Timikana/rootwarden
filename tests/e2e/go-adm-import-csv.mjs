/**
 * go-adm-import-csv.mjs - Sous-lot D6c de `adm/` : l'import par fichier CSV.
 *
 * `legacy/adm/includes/import_csv.php` (189 l.), inclus par `admin_page.php` et
 * offert DEUX fois : un formulaire dans l'onglet Utilisateurs
 * (`import_type=users`, `:229`) et un dans l'onglet Serveurs
 * (`import_type=servers`, `:256`).
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/adm/admin_page.php
 *   laravel  http://localhost:8444/serveurs  (pas encore porte)
 *
 * ══ LE DEFAUT PRINCIPAL : L'IMPORT CONTOURNE UNE GARDE DE ROLE 3 ══════════
 *
 * `users.sudo` est la PRECONDITION du repli `NOPASSWD: ALL` du module `ssh/` —
 * le point le plus dangereux du depot. Le geste dedie pour le poser,
 * `adm/api/toggle_sudo.php`, porte `checkAuth([ROLE_SUPERADMIN])` : role 3 SEUL.
 *
 * L'import CSV, lui, lit `$data['sudo']` (`import_csv.php:162`) et l'ecrit
 * DIRECTEMENT, sans aucun controle de role. Sa garde hierarchique
 * (`:155-158`) ne touche que `$roleId` — jamais `$sudo`.
 *
 * Or le formulaire vit sur `admin_page.php`, atteignable au role 2 porteur de
 * `can_admin_portal`. **Un role 2 pose donc, par un fichier, le drapeau qu'un
 * role 3 seul est cense pouvoir poser.**
 *
 * CE QUI EST MESURE ET CE QUI EST LU, et il faut le dire separement : la
 * CAPACITE (l'import ecrit bien `sudo = 1`) est mesuree ici, au clic. La
 * franchissabilite au role 2 est etablie par LECTURE — aucun compte d'epreuve
 * n'est a la fois de role 2 et porteur de `can_admin_portal`, il n'y a donc pas
 * de quoi la mesurer au navigateur. Voir PARITE E-131.
 *
 * ══ TROIS AUTRES CONSTATS ════════════════════════════════════════════════
 *
 *   - une TROISIEME copie du garde SSRF, en cinq conditions au lieu de sept, et
 *     toujours par PREFIXES DE CHAINE : elle tombe comme les deux autres sur
 *     `::ffff:169.254.169.254` (E-129) ;
 *   - `encryptPassword($data['password'])` est appele SANS son second argument,
 *     donc avec `$validate = true` : le mot de passe d'une MACHINE est soumis a
 *     la politique des COMPTES, la ou le formulaire passe `false`. Deux chemins,
 *     une colonne, deux regles ;
 *   - un compte importe recoit un mot de passe aleatoire que PERSONNE ne
 *     connait, et `$sendWelcome` — qui l'aurait envoye — est du code mort.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 *   - toutes les lignes creees portent un nom d'epreuve et sont retirees ;
 *   - le compte importe avec `sudo = 1` est supprime IMMEDIATEMENT, sans
 *     attendre le `finally` : c'est la precondition du repli `NOPASSWD: ALL` ;
 *   - les adresses des machines importees sont dans `192.0.2.0/24` (RFC 5737,
 *     TEST-NET-1), reservees a la documentation ;
 *   - le parc n'est parcouru que par une planification, et il n'y en a aucune —
 *     remesure fail-closed a chaque execution ;
 *   - `srv-zabbix` (id 1) n'est ni lue, ni citee, ni jointe.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-adm-import-csv
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';

const MACHINE_EPREUVE = 'epreuve-csv-d6c';
const MACHINE_MAPPEE = 'epreuve-csv-mappee';
const COMPTE_EPREUVE = 'epreuve_csv_d6c';
/** RFC 5737 TEST-NET-1 : reservee a la documentation, ne route nulle part. */
const IP_EPREUVE = '192.0.2.91';

const DOSSIER_CAPTURES = new URL('./screenshots/adm', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/serveurs',
        formServeurs: '[data-rw="serveurs-import-form"]',
        champFichier: '[data-rw="serveurs-import-fichier"]',
        valide: '[data-rw="serveurs-import-valider"]',
        formComptes: null,
        onglet: null,
        ongletComptes: null,
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/adm/admin_page.php',
        formServeurs: 'form:has(input[name="import_type"][value="servers"])',
        champFichier: 'input[name="csv_file"]',
        valide: 'button[type="submit"]',
        formComptes: 'form:has(input[name="import_type"][value="users"])',
        onglet: '.tab-btn[data-tab="servers"]',
        ongletComptes: '.tab-btn[data-tab="users"]',
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
 note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs += 1; }
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

function retireLesFixtures() {
    litEnBase(`DELETE FROM rootwarden.machines WHERE name IN ('${MACHINE_EPREUVE}', '${MACHINE_MAPPEE}')`);
    litEnBase(`DELETE FROM rootwarden.users WHERE name = '${COMPTE_EPREUVE}'`);
}

/** Ecrit un CSV d'epreuve et rend son chemin. */
function ecritCsv(nom, contenu) {
    const chemin = join(tmpdir(), `rw-d6c-${nom}.csv`);
    writeFileSync(chemin, contenu, 'utf8');

    return chemin;
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(40000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => { try { await d.accept(); } catch {} });

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

    return { ctx, page, erreursJs };
}

/**
 * Ouvre l'onglet « Serveurs » du legacy. Sans objet sur le portage.
 *
 * CINQUIEME FOIS QUE CE PIEGE COUTE QUELQUE CHOSE, et la premiere execution de
 * cette suite l'a repaye : le formulaire d'import de serveurs vit dans un
 * PANNEAU D'ONGLET masque, pas dans un `<details>`. Le deplier ne suffit donc
 * pas — il faut d'abord activer l'onglet, sinon la boite reste a zero et trois
 * etapes sur cinq ne mesurent rien. Le symptome etait franc (« formulaire
 * replie »), ce qui l'a rendu peu couteux ; il ne l'est pas toujours.
 */
async function ouvreOnglet(page, selecteur) {
    if (! selecteur) return;
    await page.evaluate((sel) => {
        const o = document.querySelector(sel);
        if (o) o.click();
    }, selecteur);
    await dors(400);
}

/**
 * Depose un fichier dans le formulaire d'import DESIGNE, et clique SON bouton.
 *
 * On remonte du FORMULAIRE a son champ et a son bouton — jamais « le premier
 * bouton submit de la page ». `admin_page.php` porte deux formulaires d'import
 * a la structure identique, plus une dizaine d'autres : viser le premier
 * soumettrait l'import des COMPTES en croyant lancer celui des SERVEURS.
 */
async function importe(page, selecteurForm, chemin) {
    // L'ONGLET SUIT LE FORMULAIRE VISE. Ouvrir celui des serveurs FERME celui
    // des comptes : la premiere correction avait deplace le probleme au lieu de
    // le regler, et l'etape suivante mesurait un panneau masque.
    await ouvreOnglet(page, selecteurForm === C.formComptes ? C.ongletComptes : C.onglet);
    const form = await page.$(selecteurForm);
    if (! form) return { emis: false, motif: 'formulaire absent' };

    const ouvert = await form.evaluate((f) => {
        for (let n = f; n; n = n.parentElement) if (n.tagName === 'DETAILS') n.open = true;

        return f.getBoundingClientRect().height > 0;
    });
    if (! ouvert) return { emis: false, motif: 'formulaire replie' };

    const champ = await form.$(C.champFichier);
    if (! champ) return { emis: false, motif: 'champ de fichier absent' };
    await champ.uploadFile(chemin);

    const bouton = await form.$(C.valide);
    if (! bouton) return { emis: false, motif: 'bouton absent' };

    const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 });
    await bouton.click();
    try { await nav; } catch { /* certaines cibles repondent par une redirection */ }
    await dors(800);

    return { emis: true, motif: '' };
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

const session = {};
try {
    retireLesFixtures();

    // ══ 1. LA PRECONDITION DE SURETE ═══════════════════════════════════════
    await etape('le parc est-il parcouru par une planification ?', async () => {
        const cve = compteEnBase('SELECT COUNT(*) FROM rootwarden.cve_scan_schedules');
        const ssh = compteEnBase('SELECT COUNT(*) FROM rootwarden.ssh_audit_schedules');
        constate('planifications de scan CVE', String(cve));
        constate('planifications d\'audit SSH', String(ssh));
        verifie('aucune planification ne parcourt le parc', cve === 0 && ssh === 0,
            `${cve} CVE, ${ssh} SSH — les machines importees ne seraient pas inertes`);
    });

    session.s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = session.s;

    await etape('ouverture', async () => {
        const rep = await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('le role 3 atteint la page', rep.status() === 200, `statut ${rep.status()}`);
    });

    // ══ 2. L'IMPORT DE SERVEURS, PAR LE FORMULAIRE ═════════════════════════
    await etape('importer un serveur par le formulaire', async () => {
        const csv = ecritCsv('serveur', [
            'name,ip,user,password,root_password,port,environment,criticality,network_type,tags',
            `${MACHINE_EPREUVE},${IP_EPREUVE},epreuve,Epreuve@2026-Csv!,Epreuve@2026-Root!,22,DEV,NON CRITIQUE,INTERNE,epreuve;d6c`,
        ].join('\n') + '\n');

        const r = await importe(page, C.formServeurs, csv);
        constate('formulaire d\'import de serveurs', r.emis ? 'soumis' : `NON soumis (${r.motif})`);
        verifiePortage('le formulaire d\'import de serveurs existe et se soumet', r.emis, r.motif);
        if (! r.emis) return;

        const creee = litEnBase(
            `SELECT CONCAT(ip,'|',environment,'|',LEFT(password,7)) FROM rootwarden.machines WHERE name = '${MACHINE_EPREUVE}'`);
        constate('machine importee', creee[0] || '(aucune)');
        verifie('la machine est importee, secret chiffre',
            creee.length === 1 && creee[0] === `${IP_EPREUVE}|DEV|sodium:`, creee[0] || '(aucune)');

        const etiquettes = litEnBase(
            `SELECT GROUP_CONCAT(tag ORDER BY tag) FROM rootwarden.machine_tags mt
             JOIN rootwarden.machines m ON m.id = mt.machine_id WHERE m.name = '${MACHINE_EPREUVE}'`);
        constate('etiquettes importees', etiquettes[0] || '(aucune)');
        verifie('les etiquettes de la colonne `tags` sont posees',
            etiquettes.length === 1 && etiquettes[0] === 'd6c,epreuve', etiquettes[0] || '(aucune)');
    });

    // ══ 3. LA POLITIQUE DE MOT DE PASSE S'APPLIQUE-T-ELLE A UNE MACHINE ? ══
    //
    // `import_csv.php:89` appelle `encryptPassword($data['password'])` SANS son
    // second argument, donc avec `$validate = true`. `manage_servers.php:115`
    // passe `false`. Deux chemins ecrivent la meme colonne avec deux regles.
    //
    // On mesure la PROPRIETE — un mot de passe de machine simple est-il
    // accepte — et non le message : c'est la seule formulation qui vaille sur
    // les deux cibles.
    await etape('un mot de passe de machine simple est-il accepte ?', async () => {
        const nom = `${MACHINE_EPREUVE}-simple`;
        litEnBase(`DELETE FROM rootwarden.machines WHERE name = '${nom}'`);
        const csv = ecritCsv('simple', [
            'name,ip,user,password,root_password',
            `${nom},192.0.2.92,epreuve,motdepasse,motdepasse`,
        ].join('\n') + '\n');

        const r = await importe(page, C.formServeurs, csv);
        if (! r.emis) { constate('import simple', `non soumis (${r.motif})`); return; }

        const creee = compteEnBase(`SELECT COUNT(*) FROM rootwarden.machines WHERE name = '${nom}'`);
        litEnBase(`DELETE FROM rootwarden.machines WHERE name = '${nom}'`);
        constate('machine a mot de passe simple creee', String(creee));
        verifiePortage('un mot de passe de machine n\'est pas soumis a la politique des COMPTES',
            creee === 1,
            'refuse — `encryptPassword()` est appele sans son second argument, donc avec '
            + '`$validate = true`, alors que le formulaire de `manage_servers.php` passe `false`. '
            + 'Un mot de passe de machine est impose par la machine, pas choisi ici');
    });

    // ══ 4. LA TROISIEME COPIE DU GARDE SSRF ════════════════════════════════
    await etape('l\'import refuse-t-il une adresse mappee ?', async () => {
        const csv = ecritCsv('mappee', [
            'name,ip,user,password,root_password',
            `${MACHINE_MAPPEE},::ffff:169.254.169.254,epreuve,Epreuve@2026-Csv!,Epreuve@2026-Root!`,
        ].join('\n') + '\n');

        const r = await importe(page, C.formServeurs, csv);
        if (! r.emis) { constate('import mappe', `non soumis (${r.motif})`); return; }

        const creee = litEnBase(`SELECT ip FROM rootwarden.machines WHERE name = '${MACHINE_MAPPEE}'`);
        constate('machine a adresse mappee importee', creee[0] || '(aucune)');
        // RETIREE TOUT DE SUITE : c'est le point de metadonnees des nuages.
        litEnBase(`DELETE FROM rootwarden.machines WHERE name = '${MACHINE_MAPPEE}'`);

        verifiePortage('l\'import refuse une adresse de metadonnees en IPv6 mappe',
            creee.length === 0,
            `${creee[0]} acceptee — TROISIEME copie du garde A10-01, en cinq conditions au lieu `
            + 'de sept, et toujours par prefixes de chaine (E-129)');
    });

    // ══ 5. L'IMPORT DE COMPTES, ET LE DRAPEAU `sudo` ═══════════════════════
    await etape('l\'import de comptes pose-t-il le drapeau `sudo` ?', async () => {
        if (! C.formComptes) {
            constate('formulaire d\'import de comptes', 'le portage n\'en a pas encore');
            verifiePortage('le formulaire d\'import de comptes existe', false,
                'non porte : voir §4 de MODULE-ADM.md');

            return;
        }
        const csv = ecritCsv('compte', [
            'name,email,role,active,sudo',
            `${COMPTE_EPREUVE},,admin,1,1`,
        ].join('\n') + '\n');

        const r = await importe(page, C.formComptes, csv);
        constate('formulaire d\'import de comptes', r.emis ? 'soumis' : `NON soumis (${r.motif})`);
        if (! r.emis) { verifie('le formulaire d\'import de comptes se soumet', false, r.motif); return; }

        const lu = litEnBase(
            `SELECT CONCAT(role_id,'|',sudo,'|',IFNULL(email,'(nul)')) FROM rootwarden.users WHERE name = '${COMPTE_EPREUVE}'`);
        constate('compte importe (role|sudo|courriel)', lu[0] || '(aucun)');

        // LE DRAPEAU EST RETIRE IMMEDIATEMENT, sans attendre le `finally` :
        // `users.sudo = 1` est la precondition du repli `NOPASSWD: ALL` du
        // module `ssh/`, et rien ne justifie de le laisser une seconde de plus.
        litEnBase(`DELETE FROM rootwarden.users WHERE name = '${COMPTE_EPREUVE}'`);

        const champs = (lu[0] || '||').split('|');
        // LA CAPACITE EST MESUREE ICI. La franchissabilite au role 2 est
        // etablie par LECTURE — aucun compte d'epreuve n'est a la fois role 2
        // et porteur de `can_admin_portal`. Les deux se disent separement.
        verifiePortage('l\'import n\'ecrit pas `users.sudo` sans garde de role 3',
            champs[1] !== '1',
            `sudo=${champs[1]} — \`adm/api/toggle_sudo.php\` exige \`checkAuth([ROLE_SUPERADMIN])\`, `
            + 'et l\'import ecrit la colonne sans aucun controle de role. Sa garde hierarchique '
            + 'ne touche que `role_id`');

        constate('role reellement attribue', champs[0]);
        constate('courriel', champs[2]);
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            await ouvreOnglet(page, C.onglet);
            const form = await page.$(C.formServeurs);
            if (form) {
                await form.evaluate((f) => {
                    for (let n = f; n; n = n.parentElement) if (n.tagName === 'DETAILS') n.open = true;
                    f.scrollIntoView({ block: 'center' });
                });
            }
            await dors(500);
            await page.screenshot({ path: `${dossier}/import-csv-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    verifiePortage('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 2).join(' | '));

} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    try {
        retireLesFixtures();
        const m = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.machines WHERE name LIKE 'epreuve-csv%'`);
        const u = compteEnBase(`SELECT COUNT(*) FROM rootwarden.users WHERE name = '${COMPTE_EPREUVE}'`);
        verifie('aucune fixture ne subsiste', m === 0 && u === 0, `${m} machine(s), ${u} compte(s)`);
    } catch (e) { note(`FAIL  retrait : ${e.message}`); echecs += 1; }
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
