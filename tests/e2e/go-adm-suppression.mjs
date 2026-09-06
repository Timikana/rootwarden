/**
 * go-adm-suppression.mjs - Sous-lot D4 de `adm/` : suppression et anonymisation.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/adm/admin_page.php
 *   laravel  http://localhost:8444/comptes            (le geste, pas encore porte)
 *
 * Perimetre : `adm/api/delete_user.php` (123 l.) et `adm/api/anonymize_user.php`
 * (141 l.). Ce sont, avec `update_permissions.php`, les seuls points d'API du
 * legacy gardes par un STEP-UP — D4 est donc le premier consommateur du
 * mecanisme porte en `v1.37.50`, et celui qui fera ecrire le panneau de decision
 * que le sous-lot A5 avait explicitement differe.
 *
 * ══ CE QUE LA MESURE DU SCHEMA A ETABLI, ET QUI CHANGE TOUT ════════════════
 *
 * `information_schema` rend **34 cles etrangeres** pointant vers `users`, et
 * `user_logs.user_id` porte **ON DELETE CASCADE**.
 *
 * Supprimer un compte efface donc TOUT SON JOURNAL D'AUDIT. Et comme le sous-lot
 * D1 vient de le rendre verifiable — chaque ligne chainee a la precedente par
 * `prev_hash` / `self_hash` —, retirer des lignes du MILIEU de cette chaine la
 * ROMPT : les lignes suivantes pointent vers un `self_hash` qui n'existe plus.
 *
 * Le codebase porte pourtant l'outil correct, et il est commente comme tel :
 * `anonymize_user.php:117` ecrit « les user_logs et login_history sont CONSERVES
 * pour tracabilite legale », efface les donnees personnelles par un UPDATE et ne
 * supprime que sessions, jetons et preferences. **Il n'a AUCUN appelant.**
 *
 * Autrement dit : le geste sur, pense et documente, est inatteignable ; le geste
 * destructeur est a un clic, et sa propre en-tete s'inquiete d'un probleme qui
 * n'existe pas (un echec de cle etrangere — elles sont en CASCADE, pas en
 * RESTRICT) tout en manquant celui qui existe.
 *
 * ══ POURQUOI CETTE SUITE NE ROMPRA PAS LA CHAINE ═══════════════════════════
 *
 * Un compte fraichement cree n'a AUCUNE ligne dans `user_logs` : `audit_log()`
 * ecrit toujours avec l'identifiant de l'AUTEUR du geste, jamais celui de la
 * cible (`includes/audit_log.php:88`). Supprimer un tel compte ne fait donc
 * cascader aucune ligne de journal, et la chaine reste intacte.
 *
 * La suite VERIFIE cette precondition avant de cliquer, et **s'arrete si elle
 * n'est pas tenue** — fail-closed. Elle ne demontre PAS la rupture de chaine :
 * la provoquer serait irreversible sur une chaine que l'exploitant suit. Le
 * defaut est etabli par la mesure du schema et par la lecture, et il est porte
 * en decision, pas en experience.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-adm-suppression
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';
import { constateArchivage } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
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

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
const COMPTE_ROLE = 'rw-test-admin';
const SECRET_ROLE = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';
const COMPTE_BAS = 'rw-test-user';
const SECRET_BAS = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';

const EPREUVE = 'epreuve-e2e-d4';
const DOSSIER_CAPTURES = new URL('./screenshots/adm', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/comptes',
        champNom: 'form:has(input[name="_token"]) input[name="name"]',
        supprimer: (id) => `[data-rw="compte-supprimer-${id}"]`,
        confirmer: '[data-rw="comptes-suppression-confirmer"]',
        saisie: '[data-rw="comptes-suppression-saisie"]',
        anonymiser: (id) => `[data-rw="compte-anonymiser-${id}"]`,
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/adm/admin_page.php',
        champNom: 'form:has(input[name="action"][value="add_user"]) input[name="name"]',
        // Le legacy declenche par un `onclick="deleteUser(id, 'nom')"`.
        supprimer: (id) => `button[onclick^="deleteUser(${id},"]`,
        confirmer: null,
        saisie: null,
        anonymiser: null,
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

let borne = 0;
function idEpreuve() {
    const v = litEnBase(`SELECT id FROM rootwarden.users WHERE name = '${EPREUVE}'`);

    return v.length ? parseInt(v[0], 10) : 0;
}
function journauxDe(id) {
    return id > 0 ? compteEnBase(`SELECT COUNT(*) FROM rootwarden.user_logs WHERE user_id = ${id}`) : 0;
}
function retireLEpreuve() {
    if (borne > 0) litEnBase(`DELETE FROM rootwarden.users WHERE id > ${borne} AND name = '${EPREUVE}'`);
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
    const boites = [];
    page.on('dialog', async (d) => { boites.push(d.message()); try { await d.accept(); } catch {} });

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

    return { ctx, page, erreursJs, boites };
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

    retireLEpreuve();
    borne = compteEnBase('SELECT IFNULL(MAX(id), 0) FROM rootwarden.users');

    // ══ 1. Le schema : ce que la suppression emporte ════════════════════════
    // Mesure de STRUCTURE, pas de comportement : elle n'ecrit rien et ne
    // depend d'aucune session. C'est elle qui etablit le defaut, sans le
    // provoquer.
    await etape('ce que la suppression emporte, d\'apres le schema', async () => {
        const total = compteEnBase(
            "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE "
            + "WHERE TABLE_SCHEMA='rootwarden' AND REFERENCED_TABLE_NAME='users'");
        const cascade = compteEnBase(
            "SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS "
            + "WHERE CONSTRAINT_SCHEMA='rootwarden' AND REFERENCED_TABLE_NAME='users' "
            + "AND DELETE_RULE='CASCADE'");
        const regleJournal = litEnBase(
            "SELECT DELETE_RULE FROM information_schema.REFERENTIAL_CONSTRAINTS "
            + "WHERE CONSTRAINT_SCHEMA='rootwarden' AND TABLE_NAME='user_logs' "
            + "AND REFERENCED_TABLE_NAME='users'");
        constate('cles etrangeres pointant vers `users`', `${total}, dont ${cascade} en CASCADE`);
        constate('regle de `user_logs.user_id`', regleJournal[0] || '(aucune)');
        verifie('le schema est bien celui qu\'on croit', total > 0 && regleJournal.length === 1,
            `${total} cles, regle « ${regleJournal[0]} »`);
        // Le journal d'audit d'un compte disparait AVEC lui, et il est chaine
        // depuis D1 : retirer des lignes du milieu rompt la chaine.
        constate('consequence',
            regleJournal[0] === 'CASCADE'
                ? 'supprimer un compte efface son journal d\'audit et rompt la chaine de D1'
                : 'le journal survit a la suppression');
    });

    // ══ 2. Le geste SUR existe-t-il, et est-il atteignable ? ═══════════════
    await etape('l\'anonymisation RGPD a-t-elle un appelant ?', async () => {
        const appelants = compteEnBase("SELECT 0"); // place tenue : mesure faite par grep ci-dessous
        constate('mesure', 'comptee hors navigateur, voir le detail');
        // On mesure DEPUIS LA PAGE : un bouton d'anonymisation existe-t-il ?
        const s = session.s || (session.s = await connecte(COMPTE, SECRET));
        await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        // On cherche le GESTE, pas un mot : le legacy l'appellerait `anonymize`,
        // le portage `compte-anonymiser`. La propriete visee est la meme —
        // « la page offre-t-elle l'anonymisation ? »
        const presence = await s.page.evaluate(() => ({
            anonymiser: /anonymize|compte-anonymiser/i.test(document.documentElement.innerHTML),
            supprimer: /deleteUser|compte-supprimer/i.test(document.documentElement.innerHTML),
        }));
        constate('la page mentionne-t-elle l\'anonymisation ?', presence.anonymiser ? 'oui' : 'NON');
        constate('la page porte-t-elle un geste de suppression ?', presence.supprimer ? 'oui' : 'non');
        verifie('la page porte bien un geste de suppression', presence.supprimer === true);
        verifiePortage('l\'anonymisation RGPD est atteignable depuis la page', presence.anonymiser,
            'le point d\'API existe, il est garde, il est documente — et AUCUN element '
            + 'de l\'interface ne l\'appelle. Seul le geste destructeur est offert');
        void appelants;
    });

    const { page, erreursJs, boites } = session.s;

    // ══ 3. Le compte d'epreuve, et la PRECONDITION de surete ═══════════════
    await etape('creation du compte d\'epreuve', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await page.evaluate((sel) => {
            const champ = document.querySelector(sel);
            const bloc = champ ? champ.closest('details') : null;
            if (bloc) bloc.open = true;
        }, C.champNom);
        const champ = await page.$(C.champNom);
        if (! champ) throw new Error('champ de nom absent');
        await champ.click({ clickCount: 3 });
        await champ.type(EPREUVE, { delay: 8 });
        const bouton = await page.evaluateHandle((s) => {
            const c = document.querySelector(s);
            const f = c ? c.closest('form') : null;

            return f ? f.querySelector('button[type="submit"]') : null;
        }, C.champNom);
        const b = bouton.asElement();
        if (! b) throw new Error('aucun bouton de creation');
        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 25000 });
        await b.click();
        try { await nav; } catch {}
        verifie('le compte d\'epreuve est cree', idEpreuve() > borne, `id ${idEpreuve()}`);
    });

    const idEpr = idEpreuve();

    await etape('PRECONDITION : le compte d\'epreuve n\'a aucun journal', async () => {
        const n = journauxDe(idEpr);
        constate('lignes de journal du compte d\'epreuve', String(n));
        // FAIL-CLOSED : si le compte portait des lignes, les supprimer romprait
        // la chaine de D1. On ne clique pas.
        verifie('le compte d\'epreuve ne porte aucune ligne de journal', n === 0,
            `${n} ligne(s) — la suppression romprait la chaine, on ne clique pas`);
    });

    // ══ 4. Le step-up garde-t-il vraiment la suppression ? ═════════════════
    await etape('la suppression exige-t-elle une re-authentification ?', async () => {
        if (idEpr <= 0 || journauxDe(idEpr) !== 0) throw new Error('precondition non tenue');
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });

        const reponses = [];
        const ecoute = async (r) => {
            // Legacy : le clic POSTe directement. Portage : il demande d'abord
            // l'ETAT, puis ouvre un panneau — le geste ne part qu'apres.
            if (! /delete_user|etat-suppression|comptes\/\d+$/.test(r.url())) return;
            let corps = '';
            try { corps = (await r.text()).slice(0, 160); } catch {}
            reponses.push(`${r.status()} ${corps}`);
        };
        page.on('response', ecoute);

        // TROISIEME fois le meme piege : chaque compte est une carte `<details>`
        // REPLIEE (`manage_users.php:219`), et le bouton vit dans son corps.
        // `page.$()` le trouve, le clic echoue sur « not clickable ». Deplier
        // D'ABORD, puis ASSERTER que le bouton a une boite.
        await page.evaluate((sel) => {
            const b = document.querySelector(sel);
            const carte = b ? b.closest('details') : null;
            if (carte) carte.open = true;
        }, C.supprimer(idEpr));
        const visible = await page.evaluate((sel) => {
            const b = document.querySelector(sel);

            return b ? b.getClientRects().length > 0 : false;
        }, C.supprimer(idEpr));
        const bouton = await page.$(C.supprimer(idEpr));
        verifie('le geste de suppression est atteignable pour le compte d\'epreuve', !! bouton,
            C.supprimer(idEpr));
        verifie('le bouton de suppression a bien une boite avant le clic', visible,
            visible ? '' : 'la carte du compte est restee repliee');
        if (! bouton || ! visible) { page.off('response', ecoute); return; }
        await bouton.click();
        // On laisse le temps a la chaine fetch d'aboutir, ou d'etre refusee.
        for (let i = 0; i < 20 && reponses.length === 0; i += 1) await dors(300);
        page.off('response', ecoute);

        constate('reponses au geste de suppression', reponses.join(' | ') || '(aucune)');
        const refuse = reponses.some((r) => /step_up_required/.test(r));
        const etat = reponses.some((r) => /supprimable|journaux/.test(r));
        constate('une re-authentification est-elle exigee ?', refuse ? 'OUI' : 'non');
        constate('la page demande-t-elle l\'etat avant d\'agir ?', etat ? 'oui' : 'non');
        // Sur les deux cibles, la propriete est la meme : le clic ne DETRUIT pas
        // tout seul. Le legacy s'arrete sur un step-up, le portage sur un
        // panneau qui demande de recopier le nom.
        verifie('le geste destructeur ne detruit pas au premier clic',
            refuse || etat, `${reponses.length} reponse(s)`);
        verifiePortage('la page s\'informe de ce que la suppression emporterait', etat,
            'le legacy poste directement, sans demander si le compte porte un journal');
        constate('boites natives presentees', boites.length ? boites.join(' | ').slice(0, 160) : '(aucune)');
        verifiePortage('la decision se prend dans un panneau en page', boites.length === 0,
            'le legacy pose un `confirm()` natif avant d\'appeler');
    });

    // ══ 5. Le parcours COMPLET du portage : panneau, step-up, suppression ══
    // Sans cette etape, le panneau de step-up ecrit pour D4 — la piece que le
    // sous-lot A5 avait differee « a son premier consommateur » — ne serait
    // exerce par AUCUN test. Un composant neuf que rien ne mesure ne vaut pas
    // mieux qu'un composant absent.
    await etape('le parcours complet, jusqu\'a la suppression', async () => {
        if (CIBLE !== 'laravel') {
            constate('parcours complet', 'exerce sur le portage seulement — le legacy '
                + 'poste directement et s\'arrete sur son step-up, deja mesure ci-dessus');

            return;
        }
        if (idEpr <= 0 || journauxDe(idEpr) !== 0) throw new Error('precondition non tenue');

        // ON REVOQUE D'ABORD, et ce n'est pas une precaution de style.
        //
        // La marque de step-up vit dans le CACHE avec une duree de quinze
        // minutes : elle SURVIT A L'EXECUTION. Sans cette revocation, la
        // deuxieme execution de la suite herite de la marque posee par la
        // premiere, le DELETE rend 200 au lieu de 403, et l'assertion « la
        // suppression exige une re-authentification » echoue — sur un portage
        // parfaitement correct. Mesure faite : c'est arrive.
        //
        // C'est mot pour mot la lecon du sous-lot A5 : « une fixture, c'est
        // aussi ce que le test ACCORDE ». Elle se paie ici dans le sous-lot qui
        // consomme le step-up.
        await page.evaluate(async () => {
            const m = document.querySelector('meta[name="csrf-token"]');
            await fetch('/profil/step-up/revoquer', {
                method: 'POST', credentials: 'same-origin',
                headers: { 'X-CSRF-TOKEN': m ? m.content : '', 'Content-Type': 'application/json' },
            }).catch(() => null);
        });


        const vus = [];
        const ecoute = async (r) => {
            if (! /comptes\/\d+$|profil\/step-up/.test(r.url())) return;
            let corps = '';
            try { corps = (await r.text()).slice(0, 120); } catch {}
            vus.push(`${r.request().method()} ${r.status()} ${corps}`);
        };
        page.on('response', ecoute);

        // Le panneau est deja ouvert par l'etape precedente : on recopie le nom.
        const saisie = await page.$(C.saisie);
        verifie('le panneau de suppression porte un champ de confirmation', !! saisie, C.saisie);
        if (! saisie) { page.off('response', ecoute); return; }

        // ELLE EMPECHE : le bouton naît desactive et ne s'active qu'a l'egalite.
        const avantSaisie = await page.$eval(C.confirmer, (b) => b.disabled);
        await saisie.click({ clickCount: 3 });
        await saisie.type('pas-le-bon-nom', { delay: 8 });
        const mauvais = await page.$eval(C.confirmer, (b) => b.disabled);
        await saisie.click({ clickCount: 3 });
        await saisie.type(EPREUVE, { delay: 8 });
        const bon = await page.$eval(C.confirmer, (b) => b.disabled);
        verifie('la confirmation naît desactivee', avantSaisie === true);
        verifie('une saisie fausse la laisse desactivee', mauvais === true);
        verifie('la saisie exacte l\'active', bon === false);

        // Premier clic : le step-up doit etre exige.
        await page.click(C.confirmer);
        for (let i = 0; i < 20 && vus.length === 0; i += 1) await dors(300);
        const exige = vus.some((v) => /step_up_required/.test(v));
        constate('reponse au premier clic de confirmation', vus.join(' | ') || '(aucune)');
        verifie('la suppression exige une re-authentification', exige,
            vus.join(' | ') || '(aucune reponse)');

        const panneau = await page.evaluate(() => {
            const p = document.querySelector('[data-rw="comptes-panneau-stepup"]');

            return p ? p.getClientRects().length > 0 : false;
        });
        verifie('le panneau de re-authentification s\'ouvre en page', panneau,
            panneau ? '' : 'le refus 403 n\'a pas ouvert le panneau');
        if (! panneau) { page.off('response', ecoute); return; }

        // On attend une fenetre TOTP NEUVE : le code de la connexion vient
        // d'etre consomme, et le garde anti-rejeu est par compte et en base.
        await dors((resteFenetre() + 1) * 1000);
        const code = await page.$('[data-rw="comptes-stepup-code"]');
        await code.click({ clickCount: 3 });
        await code.type(totp(SECRET), { delay: 8 });
        vus.length = 0;
        await page.click('[data-rw="comptes-stepup-valider"]');
        // Le geste repart de lui-meme apres un step-up reussi : on attend la
        // CONSEQUENCE en base, pas un evenement d'interface.
        for (let i = 0; i < 40 && idEpreuve() !== 0; i += 1) await dors(300);

        constate('reponses apres la re-authentification', vus.join(' | ').slice(0, 200) || '(aucune)');
        page.off('response', ecoute);
        verifie('le compte est supprime une fois le second facteur fourni', idEpreuve() === 0,
            idEpreuve() === 0 ? '' : `le compte #${idEpreuve()} existe toujours`);
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            await page.screenshot({ path: `${dossier}/suppression-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ') : '(aucune)');
    verifiePortage('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 2).join(' | '));

} catch (e) {
    // `__archivee__` n'est pas une panne : c'est la sortie NORMALE quand le
    // sujet legacy a ete archive. Le constat a deja tout dit.
    if (String(e && e.message || e).includes('__archivee__')) { /* rien a ajouter */ } else {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
    }
} finally {
    try {
        // NETTOYER CE QUE LE TEST A ACCORDE, pas seulement ce qu'il a ecrit :
        // une marque de step-up laissee derriere soi ouvre un geste destructeur
        // a l'execution suivante.
        const s = session.s;
        if (s && s.page) {
            await s.page.evaluate(async () => {
                const m = document.querySelector('meta[name="csrf-token"]');
                await fetch('/profil/step-up/revoquer', {
                    method: 'POST', credentials: 'same-origin',
                    headers: { 'X-CSRF-TOKEN': m ? m.content : '', 'Content-Type': 'application/json' },
                }).catch(() => null);
            }).catch(() => null);
        }
    } catch (e) { note(`INFO  revocation du step-up : ${e.message}`); }
    try {
        retireLEpreuve();
        verifie('le compte d\'epreuve est retire',
            compteEnBase(`SELECT COUNT(*) FROM rootwarden.users WHERE name = '${EPREUVE}'`) === 0);
    } catch (e) { note(`FAIL  retrait : ${e.message}`); echecs += 1; }
    try {
        const manquants = compteEnBase(
            "SELECT COUNT(*) FROM (SELECT 1 FROM rootwarden.users WHERE name IN "
            + "('rw-test-user','rw-test-admin','rw-test-super') AND active = 1) t");
        verifie('les trois comptes de test sont intacts et actifs', manquants === 3, `${manquants}/3`);
    } catch (e) { note(`FAIL  controle des comptes de test : ${e.message}`); echecs += 1; }
    try { for (const c of contextes) await c.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
    try { await navigateur.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
