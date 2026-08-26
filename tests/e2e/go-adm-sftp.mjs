/**
 * go-adm-sftp.mjs - Sous-lot D9b de `adm/` : politiques SFTP / SSH.
 *
 * `server_user_sftp.php` (148 l.), `js/server_user_policy.js` (partage avec D9a,
 * par la variable `TYPE`), `server_user_policies.php` (16 l., une redirection).
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/adm/server_user_sftp.php
 *   laravel  http://localhost:8444/acces-sftp   (pas encore porte)
 *
 * ══ LE DEFAUT : L'AIDE RECOMMANDE L'INVERSE DE CE QUI EST LIVRE ═══════════
 *
 * D9a avait une aide qui DISAIT FAUX. Ici les aides disent VRAI — et c'est ce
 * qui rend le defaut plus net, parce qu'on peut le mesurer sans rien recopier :
 *
 *   « Decoche : il DOIT utiliser une cle SSH (nettement plus sur, RECOMMANDE). »
 *   « Si ce n'est pas necessaire, DECOCHE : c'est plus sur. »        (tunnels)
 *   « Si ce n'est pas necessaire, DECOCHE. »                    (rebond de cle)
 *
 * Les TROIS cases sont cochees par defaut (`server_user_sftp.php:97-99`,
 * `?? true`). **L'interface conseille l'inverse de ce qu'elle livre.**
 *
 * La propriete se mesure donc par APPARIEMENT : pour chaque case, lire SON aide,
 * et refuser qu'une aide recommandant de decocher accompagne une case cochee.
 * Rien n'est recopie — ni la liste des cases, ni le texte des aides.
 *
 * ══ ET LE MODULE SE CONTREDIT LUI-MEME, A SIX LIGNES D'INTERVALLE ═════════
 *
 * `backend/sftp_manager.py`, `render_policy()`. Sa docstring donne l'exemple de
 * reference :
 *     'sftp_only': True, 'allow_password_auth': False,
 *     'allow_tcp_forwarding': False, 'allow_agent_forwarding': False,
 * Le code, six lignes plus bas, prend l'inverse sur QUATRE de ces cinq cles :
 *     policy.get('sftp_only', False) ... policy.get('allow_tcp_forwarding', True)
 *
 * ══ CE QUE CELA PRODUIT, ET POURQUOI C'EST PLUS QU'UN REGLAGE MOU ═════════
 *
 * Une politique neuve sur une page intitulee « Acces SFTP » rend :
 *     Match User <x>
 *         PasswordAuthentication yes
 *         AllowTcpForwarding yes
 *         AllowAgentForwarding yes
 * sans `ForceCommand internal-sftp`, sans `ChrootDirectory`, sans `PermitTTY no`
 * — ceux-la ne sont ajoutes que si `sftp_only`. Ce n'est pas une restriction
 * SFTP : c'est un shell complet avec tunnels.
 *
 * Et un bloc `Match User` FIXE ces directives pour ce compte, a la place de ce
 * que la configuration globale aurait donne. Sur une machine durcie, deployer
 * cela ELARGIT l'acces du compte au lieu de le restreindre.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * `deploy` et `remove` ECRIVENT `sshd_config.d/` sur la machine. Interception
 * avec avortement, filet pose avant toute navigation et jamais leve. Seul
 * `audit` aboutit — il LIT. Cible : machine 2, JAMAIS `srv-zabbix`.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-adm-sftp
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { execFileSync } from 'child_process';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
/** Role 2 : la page est reservee au role 3, il doit etre refuse. */
const COMPTE_ROLE = 'rw-test-admin';
const SECRET_ROLE = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

/** `test-server`. JAMAIS `srv-zabbix` (id 1, PRODUCTION). */
const MACHINE_ID = 2;

/**
 * MEME FIXTURE QU'EN D9a, ET POUR LA MEME RAISON : la page ne rend son
 * formulaire que sous `if ($selectedId && $selectedUserId)`, et les vingt
 * comptes de la machine 2 sont `excluded`. Sans compte pose, la page repond 200
 * et n'affiche aucun champ — trois FAIL « bouton introuvable ».
 *
 * Le compte est FICTIF : il n'existe sur aucune machine.
 */
const COMPTE_DISTANT = 'epreuve-sftp-d9b';

/** Les deux routes qui ECRIVENT. `audit` LIT et peut aboutir. */
const ROUTES_INTERDITES = /\/policy\/(sudo|sftp)\/(deploy|remove)(\?|$)|\/policy\/rollback/;

const DOSSIER_CAPTURES = new URL('./screenshots/adm', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: `/acces-sftp?machine=${MACHINE_ID}`,
        formulaire: '[data-rw="sftp-form"]',
        deployer: '[data-rw="sftp-deployer"]',
        auditer: '[data-rw="sftp-auditer"]',
        retirer: '[data-rw="sftp-retirer"]',
        confirmer: '[data-rw="sftp-confirmer"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: `/adm/server_user_sftp.php?server=${MACHINE_ID}`,
        formulaire: '#sftp-form',
        deployer: '#btn-deploy',
        auditer: '#btn-audit',
        retirer: '#btn-remove',
        // Le legacy n'a pas de controle de confirmation pour `deploy` : il agit
        // au premier clic. Le selecteur vise ce qui n'existe pas, ET C'EST LA
        // MESURE — la suite le constate au lieu de le supposer.
        confirmer: '#btn-deploy-confirm',
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
function verifie(l, ok, d) { note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs += 1; }
function constate(l, v) { note(`INFO  ${l} : ${v}`); }
function verifiePortage(l, ok, d) {
    if (CIBLE === 'laravel') return verifie(l, ok, ok ? '' : d);
    constate(l, `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

/** Idempotent : une execution interrompue a pu laisser la ligne derriere elle. */
function reprendLaFixture() {
    litEnBase(`DELETE FROM rootwarden.server_user_sftp_policies `
        + `WHERE machine_id = ${MACHINE_ID} AND server_user_id IN `
        + `(SELECT id FROM rootwarden.server_user_inventory `
        + ` WHERE machine_id = ${MACHINE_ID} AND username = '${COMPTE_DISTANT}')`);
    litEnBase(`DELETE FROM rootwarden.server_user_inventory `
        + `WHERE machine_id = ${MACHINE_ID} AND username = '${COMPTE_DISTANT}'`);
}
function poseLaFixture() {
    reprendLaFixture();
    litEnBase(`INSERT INTO rootwarden.server_user_inventory `
        + `(machine_id, username, uid, home_dir, shell, status, managed_by, keys_count) VALUES `
        + `(${MACHINE_ID}, '${COMPTE_DISTANT}', 4243, '/home/${COMPTE_DISTANT}', `
        + `'/bin/bash', 'managed', 'manual', 0)`);
    const id = litEnBase(`SELECT id FROM rootwarden.server_user_inventory `
        + `WHERE machine_id = ${MACHINE_ID} AND username = '${COMPTE_DISTANT}'`);

    return id.length === 1 ? id[0] : null;
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];
const interdites = [];
const boites = [];

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(45000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => {
        boites.push(`${d.type()} : ${(d.message() || '').slice(0, 70)}`);
        try { await d.accept(); } catch {}
    });

    // LE FILET, POSE AVANT TOUTE NAVIGATION ET JAMAIS LEVE.
    await page.setRequestInterception(true);
    page.on('request', (r) => {
        if (ROUTES_INTERDITES.test(r.url()) && r.method() !== 'GET') {
            let corps = '';
            try { corps = (r.postData() || '').slice(0, 200); } catch { corps = '(illisible)'; }
            interdites.push({ methode: r.method(), url: r.url(), corps });
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

    return { ctx, page, erreursJs };
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

const session = {};
let URL_PAGE = C.page;
try {
    const idDistant = poseLaFixture();
    if (idDistant === null) throw new Error('la fixture de compte distant n\'a pas ete posee');
    URL_PAGE = `${C.page}${CIBLE === 'laravel' ? '&compte=' : '&user='}${idDistant}`;
    constate('compte distant pose', `${COMPTE_DISTANT} (id ${idDistant}, machine ${MACHINE_ID})`);

    // ══ 1. LA GARDE ════════════════════════════════════════════════════════
    await etape('un role 2 atteint-il la page SFTP ?', async () => {
        const s = await connecte(COMPTE_ROLE, SECRET_ROLE);
        try {
            const rep = await s.page.goto(`${BASE}${URL_PAGE}`, { waitUntil: 'networkidle2' });
            constate('statut au role 2', String(rep.status()));
            verifie('le role 2 est refuse', rep.status() === 403,
                `statut ${rep.status()} — \`checkAuth([ROLE_SUPERADMIN])\``);
        } finally {
            await s.ctx.close();
        }
    });
    await dors((resteFenetre() + 1) * 1000);

    session.s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = session.s;

    await etape('ouverture', async () => {
        const rep = await page.goto(`${BASE}${URL_PAGE}`, { waitUntil: 'networkidle2' });
        verifie('le role 3 atteint la page', rep.status() === 200, `statut ${rep.status()}`);
        const f = await page.$(C.formulaire);
        // Le detail ne parait QUE sur echec. Cinquieme fois que ce travers est
        // corrige : « la page n'affiche aucun champ » imprime a cote d'un PASS
        // se lit comme une contradiction, et un vert contradictoire ne se relit
        // pas. Un detail qui EXPLIQUE UN ECHEC se garde par la condition.
        verifie('le formulaire est rendu', f !== null,
            f !== null ? '' : 'la page repond 200 mais n\'affiche aucun champ — fixture absente ?');
    });

    // ══ 2. UNE AIDE QUI DIT « DECOCHE » ACCOMPAGNE-T-ELLE UNE CASE COCHEE ?
    await etape('les cases livrees suivent-elles ce que leur aide recommande ?', async () => {
        await page.goto(`${BASE}${URL_PAGE}`, { waitUntil: 'networkidle2' });

        // APPARIEMENT CASE <-> SON AIDE, dans le DOM. Rien n'est recopie : ni la
        // liste des cases, ni le texte des aides. On remonte de chaque case a son
        // bloc, et on y lit le texte qui l'accompagne.
        // ANCRE SUR LE FORMULAIRE, pas sur le document.
        //
        // Premiere redaction : `input[type="checkbox"]` sur toute la page. Elle
        // ramassait `rw-tiroir` — la case du tiroir mobile du GABARIT, qui n'est
        // pas un reglage : 6 cases cote portage contre 5 cote legacy, deux
        // nombres qui ne se comparent plus. Meme famille que « le premier bouton
        // submit de la page » : un selecteur qui n'est pas ancre sur l'objet
        // mesure finit par mesurer autre chose.
        const cases = await page.$$eval(`${C.formulaire} input[type="checkbox"]`, (elements) => elements.map((e) => {
            // TOUT LE TEXTE DU BLOC, sans soustraction.
            //
            // Premiere redaction : « le texte du bloc MOINS le libelle du
            // `<label>` ». Elle supposait que le `<label>` ne porte que le
            // titre — vrai sur le legacy (`sftpToggle` met l'aide dans un `<p>`
            // FRERE), faux sur le portage, ou l'aide vit DANS l'etiquette pour
            // que toute la ligne soit cliquable. La soustraction y emportait
            // l'aide entiere : la suite lisait une chaine quasi vide et
            // concluait « aucune case fautive ». **Un PASS pour la mauvaise
            // raison.**
            //
            // Le titre ne contient jamais de recommandation ; l'inclure ne coute
            // rien, et rend la mesure INDEPENDANTE de la structure — donc
            // comparable entre deux cibles qui n'ont pas le meme balisage.
            const bloc = e.closest('div') || e.parentElement;

            return {
                nom: e.name || e.id || '(sans nom)',
                cochee: e.checked,
                aide: (bloc ? (bloc.textContent || '') : '').replace(/\s+/g, ' ').trim(),
            };
        }));

        constate('cases trouvees', String(cases.length));
        // Une aide qui RECOMMANDE de decocher. Les deux langues portent le meme
        // conseil, d'ou les deux formes.
        // Deux formulations, parce que les deux cibles ne conseillent pas de la
        // meme facon : « decoche : c'est plus sur » (legacy) et « inactif au
        // depart : c'est plus sur » (portage). Sans la seconde, il suffirait de
        // REFORMULER une aide pour echapper a la mesure — un controle qu'on
        // contourne en changeant un mot ne controle rien.
        const conseilleDeFermer = (a) =>
            /plus s[uû]r|safer|recommand|recommended|si ce n'est pas n[eé]cessaire|if not needed/i.test(a)
            && /d[eé]coch[eé]|untick|inactif|when off|off to begin/i.test(a);

        const fautives = [];
        for (const c of cases) {
            const conseille = conseilleDeFermer(c.aide);
            constate(`  ${c.nom}`,
                `${c.cochee ? 'COCHEE' : 'decochee'}${conseille ? ' — son aide dit que l\'etat sur est INACTIF' : ''}`);
            if (conseille && c.cochee) fautives.push(c.nom);
        }

        // LA PROPRIETE : ce qui est livre ne contredit pas ce que l'aide conseille.
        // Elle porte sa PRECONDITION — sans case lue, elle serait vraie sur le
        // vide, et c'est le defaut qui a failli passer en D9a.
        verifiePortage('aucune case active dont l\'aide dit que l\'etat sur est inactif',
            cases.length > 0 && fautives.length === 0,
            cases.length === 0
                ? 'aucune case lue — le formulaire n\'a pas ete rendu'
                : `${fautives.length} case(s) : ${fautives.join(', ')} — l'ecran conseille `
                  + 'l\'inverse de ce qu\'il livre');
    });

    // ══ 2b. LE MODULE SE CONTREDIT-IL LUI-MEME ? ══════════════════════════
    await etape('le module tient-il l\'exemple de sa propre docstring ?', async () => {
        // DERIVE du module, jamais recopie : on compare sa docstring a son code,
        // dans le meme fichier, a chaque execution.
        let ecarts = [];
        try {
            const src = execFileSync('docker', ['exec', 'rootwarden_python',
                'sh', '-c', 'cat /app/sftp_manager.py'], { encoding: 'utf8' });
            const bloc = src.slice(src.indexOf('def render_policy'));
            const fin = bloc.indexOf('\n\n\n');
            const corps = fin > 0 ? bloc.slice(0, fin) : bloc;

            // Ce que la docstring donne en exemple.
            const exemple = {};
            for (const m of corps.matchAll(/'(\w+)':\s*(True|False),/g)) exemple[m[1]] = (m[2] === 'True');
            // Ce que le code prend par defaut.
            const defauts = {};
            for (const m of corps.matchAll(/policy\.get\('(\w+)',\s*(True|False)\)/g)) {
                defauts[m[1]] = (m[2] === 'True');
            }
            for (const [cle, val] of Object.entries(exemple)) {
                if (cle in defauts && defauts[cle] !== val) {
                    ecarts.push(`${cle} : docstring=${val}, code=${defauts[cle]}`);
                }
            }
            verifie('le module se laisse lire et comparer',
                Object.keys(exemple).length > 0 && Object.keys(defauts).length > 0,
                Object.keys(exemple).length === 0 || Object.keys(defauts).length === 0
                    ? 'docstring ou defauts illisibles — le motif ne trouve plus rien' : '');
        } catch (e) {
            verifie('le module est lisible', false, String(e.message || e).split('\n')[0]);
        }
        for (const e of ecarts) constate('  ecart docstring/code', e);
        constate('nombre d\'ecarts', String(ecarts.length));

        // Ce constat porte sur le BACKEND : il est identique pour les deux
        // cibles, et aucun portage ne le referme. Il est releve, pas asserte.
        constate('le module tient-il son exemple ?',
            ecarts.length === 0 ? 'oui' : `NON — ${ecarts.length} cle(s), toutes vers le permissif`);
    });

    // ══ 3. UN CLIC SUR « DEPLOYER » ENVOIE-T-IL DEJA ? ════════════════════
    await etape('accorder demande-t-il quelque chose ?', async () => {
        await page.goto(`${BASE}${URL_PAGE}`, { waitUntil: 'networkidle2' });
        const avantClic = interdites.length;
        const avantB = boites.length;

        const bd = await page.$(C.deployer);
        verifie('le bouton de deploiement est atteignable', bd !== null);
        if (bd) { await bd.click(); await dors(1500); }
        const envoyees = interdites.length - avantClic;
        constate('requetes d\'ecriture au seul clic sur « deployer »', String(envoyees));
        constate('boites natives a ce clic', String(boites.length - avantB));

        // MEME PROPRIETE QU'EN D9a, ET MEME MOTIF : elle se mesure a l'EFFET
        // (au reseau), pas a la FORME de la garde. Compter les `confirm()`
        // rendrait 0 des deux cotes — le legacy n'en pose pas sur `deploy`, le
        // portage confirme par un panneau.
        verifiePortage('un clic sur « deployer » n\'envoie rien avant consentement',
            bd !== null && envoyees === 0,
            `${envoyees} requete(s) partie(s) au premier clic — un seul clic ecrit un bloc `
            + '`Match User` dans `sshd_config.d/` sur la machine');

        const confirmer = await page.$(C.confirmer);
        if (confirmer === null) {
            constate('controle de confirmation', '(aucun — la cible agit au premier clic)');
        } else {
            const avant = interdites.length;
            await confirmer.click();
            await dors(2000);
            verifie('le consentement fait bien partir la requete',
                interdites.length - avant === 1, `${interdites.length - avant} requete(s)`);
        }

        for (const r of interdites.slice(avantClic)) {
            constate('  requete AVORTEE', `${r.methode} ${r.url.replace(/^https?:\/\/[^/]+/, '')} ${r.corps}`);
        }
    });

    // ══ 4. L'AUDIT — SEUL GESTE QUI ABOUTIT ═══════════════════════════════
    await etape('auditer la politique, par un clic', async () => {
        await page.goto(`${BASE}${URL_PAGE}`, { waitUntil: 'networkidle2' });
        const b = await page.$(C.auditer);
        verifie('le bouton d\'audit est atteignable', b !== null);
        if (! b) return;
        const avant = interdites.length;
        await b.click();
        await dors(8000);
        verifie('l\'audit n\'a declenche aucune ecriture', interdites.length === avant,
            `${interdites.length - avant} requete(s) d'ecriture`);
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${URL_PAGE}`, { waitUntil: 'networkidle2' });
            await dors(500);
            await page.screenshot({ path: `${dossier}/sftp-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    verifiePortage('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 2).join(' | '));

} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    // Chaque etape dans son PROPRE `try` : une exception ici emporterait les
    // controles suivants, et c'est deja arrive (A2).
    try {
        reprendLaFixture();
        const reste = compteEnBase(`SELECT COUNT(*) FROM rootwarden.server_user_inventory `
            + `WHERE machine_id = ${MACHINE_ID} AND username = '${COMPTE_DISTANT}'`);
        verifie('le compte distant d\'epreuve est repris', reste === 0, `${reste} ligne(s) restante(s)`);
    } catch (e) { note(`FAIL  reprise de la fixture : ${e.message}`); echecs += 1; }
    try {
        constate('total des requetes d\'ecriture, toute l\'execution', String(interdites.length));
        verifie('toutes les requetes d\'ecriture ont ete avortees',
            interdites.every((r) => ROUTES_INTERDITES.test(r.url)));
        const politiques = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.server_user_sftp_policies WHERE machine_id = ${MACHINE_ID}`);
        verifie('aucune politique SFTP n\'a ete posee', politiques === 0, `${politiques} ligne(s)`);
    } catch (e) { note(`FAIL  controle final : ${e.message}`); echecs += 1; }
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
