/**
 * go-bashrc-b2.mjs - Sous-lot B2 de `bashrc/` : les lectures DISTANTES.
 *
 * Deux routes, toutes deux des LECTURES qui ouvrent une session SSH :
 *   GET  /bashrc/users     enumere les comptes Linux de la machine
 *   POST /bashrc/preview   lit le `.bashrc` distant et construit un diff
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/bashrc/
 *   laravel  http://localhost:8444/bashrc
 *
 * ══ SURETE : LA PROPRIETE « JAMAIS LA PRODUCTION » SE PROUVE AU RESEAU ════
 *
 * La page propose LES TROIS machines du parc, `srv-zabbix` comprise — c'est le
 * defaut que B1 a corrige a l'ecran, mais le legacy le porte toujours. Une suite
 * qui cocherait « Tout » joindrait donc la production.
 *
 * Le filet ne se contente pas d'avorter les routes d'ECRITURE : il **lit le
 * `machine_id` de chaque requete** et avorte tout ce qui ne vise pas la machine
 * 2. La propriete devient alors mesurable — on compte ce qui est parti, et vers
 * ou — au lieu d'etre affirmee par la construction du test.
 *
 * `srv-zabbix` est id 1, PRODUCTION. `OpenCVE-Test-OnPrem` est id 3 : hors
 * perimetre aussi, faute de raison d'y toucher.
 *
 * ══ CE QUE B2 LAISSE ABOUTIR, ET POURQUOI C'EST SUR ══════════════════════
 *
 * `/bashrc/users` lance `awk` sur `/etc/passwd` ; `/bashrc/preview` lit
 * `.bashrc` en base64 et construit un diff cote serveur. **Aucune des deux
 * n'ecrit quoi que ce soit.** Le controle final le PROUVE : aucun journal
 * `[bashrc] deploy%`, et aucune politique posee.
 *
 * La machine 2 (`10.10.10.10`) a ete verifiee joignable sur le port 22 avant
 * l'ecriture de cette suite. Si elle cesse de l'etre, les deux lectures
 * echoueront et la suite mesurera le TRAITEMENT DE L'ECHEC — ce qui reste une
 * caracterisation valable, et les assertions le disent.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-bashrc-b2
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';

/** `Test-Server-Debian`. JAMAIS 1 (`srv-zabbix`, PRODUCTION) ni 3. */
const MACHINE_ID = 2;

/** Les deux lectures autorisees. Tout le reste part au filet. */
const LECTURES = /\/bashrc\/(users|preview)(\?|$)/;
/** Ce qui ECRIT, sur la machine ou en base. */
const ECRITURES = /\/bashrc\/(prerequisites|deploy|restore)(\?|$)/;
/**
 * TOUTES les routes de l'API du module — et rien d'autre. La PAGE, servie a
 * `/bashrc/`, n'en fait pas partie : elle n'a pas de nom de route apres le
 * prefixe, et c'est ce qui permet de la laisser passer.
 */
const ROUTES_MODULE = /\/bashrc\/(users|prerequisites|preview|deploy|restore|template|backups)(\?|$)/;

const DOSSIER_CAPTURES = new URL('./screenshots/bashrc', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/bashrc',
        machine: `[data-rw="bashrc-cible-${MACHINE_ID}"]`,
        tableauComptes: '[data-rw="bashrc-comptes"]',
        ligneCompte: '[data-rw^="bashrc-compte-"]',
        apercu: '[data-rw="bashrc-apercu"]',
        panneauApercu: '[data-rw="bashrc-apercu-panneau"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/bashrc/',
        machine: `.machine-chk[value="${MACHINE_ID}"]`,
        tableauComptes: '#users-table-container',
        ligneCompte: '#users-table-container input[type="checkbox"]',
        apercu: '#btn-preview',
        panneauApercu: '#preview-panel',
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
/**
 * `d` est le detail d'ECHEC : il n'est imprime QUE sur un FAIL.
 *
 * Sixieme fois que « PASS … — aucune requete n'est partie » est corrige a la
 * main dans ce depot. Une regle qu'on doit se rappeler est une propriete qu'on
 * n'a pas encore construite : la signature l'empeche desormais.
 *
 * Pour un detail qui a du sens dans les DEUX verdicts — « statut 403 »,
 * « 3 comptes » —, quatrieme argument `toujours`.
 */
function verifie(l, ok, d, toujours) {
    const suffixe = toujours || (! ok && d) || '';
    note(`${ok ? 'PASS' : 'FAIL'}  ${l}${suffixe ? '  — ' + suffixe : ''}`);
    if (! ok) echecs += 1;
}
function constate(l, v) { note(`INFO  ${l} : ${v}`); }
function verifiePortage(l, ok, d) {
    if (CIBLE === 'laravel') return verifie(l, ok, ok ? '' : d);
    constate(l, `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

/**
 * Le `machine_id` d'une requete, lu dans l'URL ou dans le corps.
 *
 * Rend `null` quand il n'y en a pas — et un `null` n'est PAS traite comme « la
 * bonne machine » : sans identifiant, on ne peut pas savoir ou ca va, donc on
 * avorte. Fail-closed.
 */
function machineVisee(requete) {
    const m = /[?&]machine_id=(\d+)/.exec(requete.url());
    if (m) return Number(m[1]);
    try {
        const corps = requete.postData();
        if (corps) {
            const b = /"machine_id"\s*:\s*(\d+)/.exec(corps);
            if (b) return Number(b[1]);
        }
    } catch { /* corps illisible */ }

    return null;
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});
const contextes = [];
const abouties = [];
const avortees = [];

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(60000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => { try { await d.dismiss(); } catch {} });

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        const url = r.url();
        // LE GARDE VISE LES NOMS DE ROUTES, PAS LE PREFIXE DU MODULE.
        //
        // Premiere redaction : `/\/bashrc\//`. Elle attrapait **la page
        // elle-meme** — `GET /bashrc/` — et l'avortait : la suite mourait sur
        // `net::ERR_BLOCKED_BY_CLIENT` avant d'avoir rien mesure. Le filet
        // produisait l'echec qu'il rapportait, pour la deuxieme fois sur ce
        // module.
        //
        // Les routes de l'API portent toutes un nom (`users`, `preview`, …) ;
        // la page n'en porte pas. C'est ce qui les distingue.
        if (! ROUTES_MODULE.test(url)) { r.continue().catch(() => {}); return; }

        const cible = machineVisee(r);
        const estLecture = LECTURES.test(url);
        const bonneMachine = (cible === MACHINE_ID);

        // Une lecture VERS LA MACHINE 2 aboutit. Tout le reste est avorte :
        // les ecritures, et toute requete visant une autre machine ou dont on
        // ne sait pas ce qu'elle vise.
        if (estLecture && bonneMachine) {
            abouties.push(`${r.method()} ${url.replace(/^https?:\/\/[^/]+/, '')}`);
            r.continue().catch(() => {});

            return;
        }
        avortees.push({
            geste: `${r.method()} ${url.replace(/^https?:\/\/[^/]+/, '')}`,
            machine: cible === null ? '(indetermine)' : String(cible),
            motif: ECRITURES.test(url) ? 'ecriture'
                : (! estLecture ? 'hors des deux lectures' : 'machine hors perimetre'),
        });
        r.abort('blockedbyclient').catch(() => {});
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

const session = {};
try {
    session.s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = session.s;
    verifie('la session a tenu', ! session.s.surConnexion, page.url());

    // ══ 1. COCHER UNE MACHINE, ET UNE SEULE ═══════════════════════════════
    await etape('cocher la machine d\'essai lance l\'enumeration', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });

        // PAR SA VALEUR, jamais « la premiere case » : les trois machines du
        // parc portent la meme classe, et la premiere dans l'ordre alphabetique
        // n'est pas la machine d'essai.
        const caseMachine = await page.$(C.machine);
        verifie('la case de la machine d\'essai est atteignable', caseMachine !== null,
            caseMachine !== null ? '' : `selecteur ${C.machine}`);
        if (! caseMachine) return;

        const avant = abouties.length;
        await caseMachine.click();
        // L'enumeration ouvre une session SSH : elle prend du temps.
        await dors(15000);

        const enumerations = abouties.filter((r) => /\/bashrc\/users/.test(r)).length;
        constate('requetes d\'enumeration abouties', String(enumerations));
        verifie('cocher une machine declenche l\'enumeration de ses comptes',
            abouties.length > avant, 'aucune requete n\'est partie');
    });

    // ══ 2. LES COMPTES SONT RENDUS ════════════════════════════════════════
    let compteChoisi = '';
    await etape('les comptes de la machine sont affiches', async () => {
        const vu = await page.evaluate((sels) => {
            const bloc = document.querySelector(sels.tableauComptes);
            const cases = [...document.querySelectorAll(sels.ligneCompte)];

            return {
                present: bloc !== null,
                texte: bloc ? (bloc.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 160) : '',
                // `value === 'on'` EST LA CASE « TOUT », pas un compte : un
                // `<input type=checkbox>` sans attribut `value` rend `"on"`.
                // La premiere redaction la rapportait comme un compte nomme
                // « on » — et comme elle vient EN PREMIER, `cases[0]` cliquait
                // « tout selectionner ». Sur cette page, c'est le geste
                // dangereux : il retient `root` avec le reste.
                comptes: cases.map((c) => c.value || c.dataset.rw || '')
                    .filter((v) => v && v !== 'on'),
            };
        }, { tableauComptes: C.tableauComptes, ligneCompte: C.ligneCompte });

        verifie('le bloc des comptes existe', vu.present);
        constate('comptes proposes', vu.comptes.join(', ') || '(aucun)');
        constate('ce que le bloc affiche', vu.texte || '(vide)');

        // La machine peut ne pas repondre : on le CONSTATE plutot que d'echouer
        // sur une propriete qui ne depend pas du code teste. Mais on ne se tait
        // pas — la suite dit alors ce qu'elle n'a pas pu mesurer.
        if (vu.comptes.length === 0) {
            constate('enumeration', 'aucun compte rendu — machine injoignable ou sans compte eligible');
            verifie('le bloc dit pourquoi il est vide', vu.texte.length > 0,
                'bloc vide et muet : rien n\'explique l\'absence de comptes');

            return;
        }
        compteChoisi = vu.comptes[0];
        verifie('au moins un compte est propose', vu.comptes.length > 0, '',
            `${vu.comptes.length} compte(s)`);

        // `root` FAIT-IL PARTIE DE LA LISTE ? `_list_users` retient `UID == 0`,
        // donc oui. Ce n'est pas un defaut a corriger ici — c'est un CONSTAT que
        // le portage devra decider de signaler ou non (MODULE-BASHRC.md §6.4).
        constate('`root` est-il propose ?', vu.comptes.includes('root') ? 'OUI' : 'non');
    });

    // ══ 3. L'APERCU — UNE LECTURE, ET UN DIFF ═════════════════════════════
    await etape('l\'apercu lit le fichier distant et montre un diff', async () => {
        if (! compteChoisi) {
            constate('apercu', '(non exercable — aucun compte propose)');

            return;
        }
        // VISER LE COMPTE PAR SA VALEUR, jamais « la premiere case » : la
        // premiere est « Tout », et la cocher retiendrait `root` avec le reste.
        const coche = await page.evaluateHandle((sel, valeur) => {
            return [...document.querySelectorAll(sel)].find((c) => c.value === valeur) || null;
        }, C.ligneCompte, compteChoisi);
        const element = coche.asElement();
        verifie(`la case du compte « ${compteChoisi} » est atteignable`, element !== null);
        if (! element) return;
        await element.click();
        await dors(500);

        const bouton = await page.$(C.apercu);
        verifie('le bouton d\'apercu est atteignable', bouton !== null);
        if (! bouton) return;

        const avant = abouties.length;
        await bouton.click();
        await dors(20000);

        const apercus = abouties.filter((r) => /\/bashrc\/preview/.test(r)).length;
        constate('requetes d\'apercu abouties', String(apercus));
        verifie('l\'apercu a bien interroge la machine', apercus > 0, '',
            `${abouties.length - avant} requete(s) depuis le clic`);

        const rendu = await page.evaluate((sel) => {
            const p = document.querySelector(sel);

            return {
                visible: p ? p.offsetParent !== null : false,
                texte: p ? (p.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 200) : '',
            };
        }, C.panneauApercu);
        constate('panneau d\'apercu', `${rendu.visible ? 'visible' : 'masque'} — ${rendu.texte || '(vide)'}`);
        verifie('le panneau d\'apercu s\'ouvre et dit quelque chose',
            rendu.visible && rendu.texte.length > 0,
            rendu.visible ? 'panneau vide' : 'panneau reste masque');
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await dors(400);
            await page.screenshot({ path: `${dossier}/bashrc-b2-${nom}.png` });
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
        for (const r of avortees) {
            constate('  AVORTEE', `${r.geste} · machine ${r.machine} · ${r.motif}`);
        }
        constate('requetes abouties', abouties.length ? [...new Set(abouties)].join(' · ') : '(aucune)');
        // LA PROPRIETE CENTRALE : rien n'est parti vers une autre machine que la
        // 2. Elle se mesure sur ce qui a ABOUTI, pas sur ce qu'on a voulu faire.
        verifie('aucune requete aboutie ne visait une autre machine que la 2',
            abouties.every((r) => /machine_id=2(&|$)/.test(r) || ! /machine_id=/.test(r)),
            abouties.join(' · '));
        verifie('aucune requete aboutie n\'ecrivait',
            abouties.every((r) => ! ECRITURES.test(r)), abouties.join(' · '));
    } catch (e) { note(`FAIL  controle des requetes : ${e.message}`); echecs += 1; }
    try {
        const journaux = compteEnBase("SELECT COUNT(*) FROM rootwarden.user_logs "
            + "WHERE action LIKE '[bashrc] deploy%' AND created_at > NOW() - INTERVAL 15 MINUTE");
        constate('journaux de deploiement des quinze dernieres minutes', String(journaux));
        verifie('la suite n\'a produit aucun deploiement', journaux === 0, `${journaux} ligne(s)`);
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
