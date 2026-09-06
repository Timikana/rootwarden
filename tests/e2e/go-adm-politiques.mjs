/**
 * go-adm-politiques.mjs - Sous-lot D9 de `adm/` : politiques sudo et SFTP.
 *
 * `server_user_sudo.php` (167 l.), `server_user_sftp.php` (148 l.),
 * `js/server_user_policy.js` (128 l.), `server_user_policies.php` (16 l., un
 * aiguillage deprecie).
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/adm/server_user_sudo.php
 *   laravel  http://localhost:8444/politiques   (pas encore porte)
 *
 * ══ DEUX DEFAUTS, ET ILS SE RENFORCENT ════════════════════════════════════
 *
 * 1. L'AIDE DU PREREGLAGE PAR DEFAUT DIT L'INVERSE DE SON PROPRE MODULE.
 *
 *    `backend/sudo_manager.py:80-84`, dans la fonction qui produit la regle :
 *      « AVERTISSEMENT : ce preset est EQUIVALENT ROOT. `apt install/upgrade`
 *        execute des scripts de mainteneur en root -> un utilisateur avec ce
 *        preset peut obtenir un shell root via un paquet construit. »
 *    L'aide que la personne lit AU MOMENT DE CHOISIR, dans les DEUX langues :
 *      « Il ne peut pas toucher au reste du systeme. »
 *    Et `apt_only` est le prereglage PAR DEFAUT (`server_user_sudo.php:32`).
 *
 *    C'est « l'en-tete qui ment » sous sa forme la plus couteuse : les cinq
 *    occurrences precedentes etaient des COMMENTAIRES, qui trompaient une
 *    relecture. Celle-ci est une PHRASE D'INTERFACE, qui trompe la personne qui
 *    decide, au moment ou elle decide.
 *
 * 2. ACCORDER ROOT NE DEMANDE RIEN ; LE RETIRER DEMANDE CONFIRMATION.
 *
 *    `server_user_policy.js` : `removePolicy()` commence par
 *    `if (!confirm(T.confirmRemove)) return;` — `deployPolicy()` n'a AUCUNE
 *    confirmation. Un clic ecrit donc `/etc/sudoers.d/rootwarden-<user>` sur la
 *    machine, `all_nopasswd` compris, c'est-a-dire root sans mot de passe.
 *
 *    L'asymetrie est a l'envers : le geste qui DONNE est libre, celui qui
 *    REPREND est garde.
 *
 * ══ CE QUE LA MESURE DEDOUANE ════════════════════════════════════════════
 *
 * `sudo_manager` est bien construit : `visudo -cf` valide le fichier temporaire
 * AVANT tout deplacement, les chemins sont bornes a `/etc/sudoers.d/rootwarden-*`,
 * et un echec de validation leve plutot que d'ecrire. **Le geste distant est
 * sur ; c'est sa presentation qui ne l'est pas.**
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * `deploy` et `remove` ECRIVENT sur la machine. Ils sont exerces par
 * INTERCEPTION AVEC AVORTEMENT : filet pose avant toute navigation, jamais
 * leve. Seul `audit` aboutit — il LIT le fichier, et vise la machine 2.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-adm-politiques
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { execFileSync } from 'child_process';
import { mkdirSync } from 'node:fs';
import { constateArchivage } from './archive.mjs';

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
 * LA SUITE POSE SON PROPRE COMPTE DISTANT, et voici pourquoi.
 *
 * La page ne rend son formulaire que sous `if ($selectedId && $selectedUserId)`,
 * et `$users` ne retient de `server_user_inventory` que les statuts `managed` et
 * `pending_review` (`server_user_sudo.php:20`). Les VINGT comptes de la machine 2
 * sont `excluded` : la page repond 200 et n'affiche AUCUN de ses champs.
 *
 * Premiere execution : 3 FAIL, tous « bouton introuvable ». La suite dependait
 * d'une donnee que personne ne pose — meme defaut que `ssh-parc` et
 * `ssh-preflight`, corriges de la meme facon. **Une suite pose ce dont elle a
 * besoin, et le reprend.**
 *
 * Le compte est FICTIF : il n'existe sur aucune machine. Un deploiement qui
 * echapperait au filet ne pourrait donc rien accorder a personne — c'est une
 * seconde barriere derriere l'interception, pas un remplacement.
 */
const COMPTE_DISTANT = 'epreuve-politique-d9';

/** Les deux routes qui ECRIVENT sur la machine. `audit` LIT et peut aboutir. */
const ROUTES_INTERDITES = /\/policy\/(sudo|sftp)\/(deploy|remove)(\?|$)|\/policy\/rollback/;

const DOSSIER_CAPTURES = new URL('./screenshots/adm', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: `/politiques?machine=${MACHINE_ID}`,   // + &compte=<id>, ajoute a l'execution
        prereglage: '[data-rw="politique-prereglage"]',
        aide: '[data-rw="politique-aide"]',
        portee: '[data-rw="politique-portee"]',
        deployer: '[data-rw="politique-deployer"]',
        auditer: '[data-rw="politique-auditer"]',
        retirer: '[data-rw="politique-retirer"]',
        confirmer: '[data-rw="politique-confirmer"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: `/adm/server_user_sudo.php?server=${MACHINE_ID}`,  // + &user=<id>
        prereglage: '#sudo-preset',
        aide: '#preset-help',
        // Le legacy n'a PAS de marqueur de portee : le selecteur vise ce qui
        // n'existe pas, et l'absence est justement ce qu'on mesure.
        portee: '#preset-scope',
        deployer: '#btn-deploy',
        auditer: '#btn-audit',
        retirer: '#btn-remove',
        // Le legacy n'a pas de controle de confirmation pour `deploy` : il agit
        // au premier clic. Le selecteur vise donc ce qui n'existe pas, ET C'EST
        // LA MESURE — la suite le constate au lieu de le supposer.
        confirmer: '#btn-deploy-confirm',
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

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];
/** Toutes les requetes d'ecriture vues, sur toute l'execution. */
const interdites = [];
/** Les boites natives rencontrees — le legacy en pose sur `remove`. */
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
            try { corps = (r.postData() || '').slice(0, 160); } catch { corps = '(illisible)'; }
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

/** Idempotent : une execution interrompue a pu laisser la ligne derriere elle. */
function reprendLaFixture() {
    litEnBase(`DELETE FROM rootwarden.server_user_inventory `
        + `WHERE machine_id = ${MACHINE_ID} AND username = '${COMPTE_DISTANT}'`);
}
function poseLaFixture() {
    reprendLaFixture();
    litEnBase(`INSERT INTO rootwarden.server_user_inventory `
        + `(machine_id, username, uid, home_dir, shell, status, managed_by, keys_count) VALUES `
        + `(${MACHINE_ID}, '${COMPTE_DISTANT}', 4242, '/home/${COMPTE_DISTANT}', `
        + `'/bin/bash', 'managed', 'manual', 0)`);
    const id = litEnBase(`SELECT id FROM rootwarden.server_user_inventory `
        + `WHERE machine_id = ${MACHINE_ID} AND username = '${COMPTE_DISTANT}'`);

    return id.length === 1 ? id[0] : null;
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

const session = {};
/** Renseignee des que la fixture est posee ; sans elle la page ne rend rien. */
let URL_PAGE = C.page;
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

    const idDistant = poseLaFixture();
    if (idDistant === null) throw new Error('la fixture de compte distant n\'a pas ete posee');
    URL_PAGE = `${C.page}${CIBLE === 'laravel' ? '&compte=' : '&user='}${idDistant}`;
    constate('compte distant pose', `${COMPTE_DISTANT} (id ${idDistant}, machine ${MACHINE_ID})`);

    // ══ 1. LA GARDE ════════════════════════════════════════════════════════
    await etape('un role 2 atteint-il la page des politiques ?', async () => {
        const s = await connecte(COMPTE_ROLE, SECRET_ROLE);
        try {
            const rep = await s.page.goto(`${BASE}${URL_PAGE}`, { waitUntil: 'networkidle2' });
            constate('statut au role 2', String(rep.status()));
            verifie('le role 2 est refuse', rep.status() === 403,
                `statut ${rep.status()} — \`checkAuth([ROLE_SUPERADMIN])\`, sans permission`);
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
    });

    // ══ 2. L'AIDE DU PREREGLAGE PAR DEFAUT ════════════════════════════════
    await etape('l\'aide du prereglage par defaut dit-elle vrai ?', async () => {
        await page.goto(`${BASE}${URL_PAGE}`, { waitUntil: 'networkidle2' });
        const vu = await page.evaluate((sels) => {
            const sel = document.querySelector(sels.prereglage);
            const aide = document.querySelector(sels.aide);

            return {
                defaut: sel ? sel.value : '',
                options: sel ? [...sel.options].map((o) => o.value) : [],
                aide: aide ? (aide.textContent || '').trim() : '',
            };
        }, { prereglage: C.prereglage, aide: C.aide });

        constate('prereglage par defaut', vu.defaut || '(aucun)');
        constate('aide affichee', vu.aide.slice(0, 130) || '(vide)');

        // QUELS PREREGLAGES LE MODULE SIGNALE-T-IL COMME DONNANT ROOT ?
        //
        // DERIVE du module, jamais recopie ici. Une liste recopiee vieillit —
        // c'est exactement le defaut qu'on mesure, et le reproduire dans la
        // suite qui le mesure serait une faute d'un genre particulier.
        //
        // Le marqueur est ETROIT a dessein. Une premiere version cherchait
        // « shell root », qui apparait dans la docstring de `read_logs` —
        // « retrait de `less` (permettait `!sh` = shell root) », c'est-a-dire
        // dans la phrase qui explique un DURCISSEMENT. Elle aurait classe
        // « donne root » le prereglage le plus borne des six.
        const PRESETS_ROOT = [];
        try {
            const src = execFileSync('docker', ['exec', 'rootwarden_python',
                'sh', '-c', 'cat /app/sudo_manager.py'], { encoding: 'utf8' });
            const motif = /def render_preset_(\w+)\s*\([^)]*\)[^:]*:\s*(?:["]{3}([\s\S]*?)["]{3})?/g;
            let m;
            while ((m = motif.exec(src)) !== null) {
                if (/EQUIVALENT ROOT|Acces root complet/i.test(m[2] || '')) PRESETS_ROOT.push(m[1]);
            }
            // Le detail ne parait QUE sur echec : « aucun prereglage signale »
            // affiche a cote d'un PASS se lit comme une contradiction. Quatrieme
            // fois que ce travers est corrige.
            verifie('le module se laisse lire et classe ses prereglages',
                PRESETS_ROOT.length > 0,
                PRESETS_ROOT.length > 0 ? '' : 'aucun prereglage signale — le motif ne trouve plus rien');
        } catch (e) {
            verifie('le module est lisible', false, String(e.message || e).split('\n')[0]);
        }
        constate('prereglages que le module dit equivalents root', PRESETS_ROOT.join(', ') || '(aucun)');
        const avertit = PRESETS_ROOT.includes(vu.defaut);

        // UN DEFAUT NE DOIT PAS ACCORDER ROOT EN SILENCE. Le legacy pre-selectionne
        // `apt_only` ; le portage part sur `read_logs`. Divergence VOULUE, declaree
        // au CHANGELOG et a PARITE : un prereglage retenu par defaut est celui que
        // la plupart des gens laisseront en place.
        verifiePortage('le prereglage retenu par defaut ne donne pas root',
            vu.defaut !== '' && ! PRESETS_ROOT.includes(vu.defaut),
            `« ${vu.defaut} » est signale « EQUIVALENT ROOT » par son propre module, `
            + 'et c\'est pourtant lui qui est pre-selectionne');

        // LA PROPRIETE PORTE SA PROPRE PRECONDITION, et ce n'etait pas le cas a
        // la premiere execution : sur une page qui n'avait rien rendu, `vu.aide`
        // valait `''`, ne contenait donc pas « ne peut pas toucher », et la
        // propriete etait VRAIE. Cote laravel c'eut ete un PASS sur un ecran
        // inexistant — la forme d'echec la plus couteuse, parce qu'un vert ne se
        // relit pas. Une aide ILLISIBLE n'est pas une aide qui dit vrai.
        const aideNie = /ne peut pas toucher|cannot touch/i.test(vu.aide);
        verifiePortage('l\'aide est lisible et ne contredit pas l\'avertissement du module',
            vu.aide !== '' && ! (avertit && aideNie),
            vu.aide === ''
                ? 'aucune aide affichee — la page n\'a pas rendu son formulaire'
                : `le module ecrit « EQUIVALENT ROOT », l'ecran affiche « ${vu.aide.slice(0, 80)} » — `
                  + 'et c\'est le prereglage retenu par defaut');
    });

    // ══ 2b. CHOISIR UN PREREGLAGE QUI DONNE ROOT LE DIT-IL ? ═════════════
    await etape('un prereglage equivalent root s\'annonce-t-il ?', async () => {
        await page.goto(`${BASE}${URL_PAGE}`, { waitUntil: 'networkidle2' });

        // Le choix se fait par `select`, donc `page.select` — c'est le geste
        // reel, pas un appel a la fonction de la page.
        const dispo = await page.$eval(C.prereglage,
            (s) => [...s.options].map((o) => o.value));
        const cible = dispo.includes('all_nopasswd') ? 'all_nopasswd' : dispo[0];
        constate('prereglage choisi pour l\'epreuve', cible);
        await page.select(C.prereglage, cible);
        await dors(600);

        const vu = await page.evaluate((sels) => {
            const a = document.querySelector(sels.aide);
            const m = document.querySelector(sels.portee);

            return {
                aide: a ? (a.textContent || '').trim() : '',
                marqueur: m ? (m.textContent || '').trim() : '',
                // Un marqueur present dans le HTML mais large de zero ne
                // previent personne — meme mesure que pour le menu.
                largeur: m ? Math.round(m.getBoundingClientRect().width) : 0,
            };
        }, { aide: C.aide, portee: C.portee });

        constate('aide du prereglage root', vu.aide.slice(0, 110) || '(vide)');
        constate('marqueur de portee', `${vu.marqueur.slice(0, 70) || '(aucun)'} — ${vu.largeur} px`);

        // LA PROPRIETE : le prereglage le plus dangereux des six doit se dire
        // tel, et se dire VISIBLEMENT.
        verifiePortage('le prereglage qui donne root l\'annonce, et de facon visible',
            /root/i.test(vu.aide) && vu.largeur > 0,
            vu.largeur === 0
                ? `aucun marqueur de portee — l'aide dit « ${vu.aide.slice(0, 60)} »`
                : `l'aide ne parle pas de root : « ${vu.aide.slice(0, 60)} »`);
    });

    // ══ 3. UN CLIC SUR « DEPLOYER » ENVOIE-T-IL DEJA ? ═══════════════════
    await etape('accorder demande-t-il autant que reprendre ?', async () => {
        await page.goto(`${BASE}${URL_PAGE}`, { waitUntil: 'networkidle2' });

        // LA PROPRIETE SE MESURE AU RESEAU, ET PAS AU NOMBRE DE BOITES NATIVES.
        //
        // Premiere redaction : compter les `confirm()`. Elle aurait rendu 0 sur
        // LES DEUX cibles — le legacy n'en pose pas sur `deploy`, et le portage
        // n'en pose nulle part puisqu'il confirme par un PANNEAU. La propriete
        // « deployer est au moins aussi garde que retirer » se serait donc
        // verifiee des deux cotes, sans rien mesurer. Un vert obtenu ainsi ne se
        // relit jamais.
        //
        // Ce qui compte n'est pas la FORME de la confirmation mais son EFFET :
        // apres un clic sur « deployer », et avant tout consentement, rien ne
        // doit etre parti vers la machine.
        const avantClic = interdites.length;
        const avantB = boites.length;
        const bd = await page.$(C.deployer);
        verifie('le bouton de deploiement est atteignable', bd !== null);
        if (bd) { await bd.click(); await dors(1500); }
        const envoyeesAuClic = interdites.length - avantClic;
        constate('requetes d\'ecriture au seul clic sur « deployer »', String(envoyeesAuClic));
        constate('boites natives a ce clic', String(boites.length - avantB));

        verifiePortage('un clic sur « deployer » n\'envoie rien avant consentement',
            bd !== null && envoyeesAuClic === 0,
            `${envoyeesAuClic} requete(s) partie(s) au premier clic — un seul clic ecrit `
            + '`/etc/sudoers.d/`, `all_nopasswd` compris, sans rien demander');

        // ET LE CONSENTEMENT DOIT ABOUTIR : un panneau dont on ne peut pas
        // sortir ne serait pas une confirmation, ce serait une impasse.
        const confirmer = await page.$(C.confirmer);
        if (confirmer === null) {
            constate('controle de confirmation', '(aucun — la cible agit au premier clic)');
        } else {
            const avantConsentement = interdites.length;
            await confirmer.click();
            await dors(2000);
            verifie('le consentement fait bien partir la requete',
                interdites.length - avantConsentement === 1,
                `${interdites.length - avantConsentement} requete(s)`);
        }

        // LE GESTE DE RETRAIT, POUR LA COMPARAISON.
        await page.goto(`${BASE}${URL_PAGE}`, { waitUntil: 'networkidle2' });
        const avantRetrait = interdites.length;
        const br = await page.$(C.retirer);
        verifie('le bouton de retrait est atteignable', br !== null);
        if (br) { await br.click(); await dors(1500); }
        constate('requetes d\'ecriture au seul clic sur « retirer »',
            String(interdites.length - avantRetrait));

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
        await b.click();
        await dors(8000);
        // L'audit LIT le fichier : il aboutit, et ne modifie rien.
        verifie('l\'audit n\'a declenche aucune ecriture', interdites.every(
            (r) => ROUTES_INTERDITES.test(r.url)), `${interdites.length} requete(s) d'ecriture au total`);
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${URL_PAGE}`, { waitUntil: 'networkidle2' });
            await dors(500);
            await page.screenshot({ path: `${dossier}/politiques-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    verifiePortage('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 2).join(' | '));

} catch (e) {
    // `__archivee__` n'est pas une panne : c'est la sortie NORMALE quand le
    // sujet legacy a ete archive. Le constat a deja tout dit.
    if (String(e && e.message || e).includes('__archivee__')) { /* rien a ajouter */ } else {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
    }
} finally {
    // Chaque etape du `finally` dans son PROPRE `try` : une exception ici
    // emporterait les controles suivants, et c'est deja arrive (A2).
    try {
        reprendLaFixture();
        const reste = compteEnBase(`SELECT COUNT(*) FROM rootwarden.server_user_inventory `
            + `WHERE machine_id = ${MACHINE_ID} AND username = '${COMPTE_DISTANT}'`);
        verifie('le compte distant d\'epreuve est repris', reste === 0, `${reste} ligne(s) restante(s)`);
    } catch (e) { note(`FAIL  reprise de la fixture : ${e.message}`); echecs += 1; }
    try {
        // La suite n'ecrit RIEN d'autre, ni en base ni a distance. On le PROUVE
        // plutot que de l'affirmer.
        constate('total des requetes d\'ecriture, toute l\'execution', String(interdites.length));
        verifie('toutes les requetes d\'ecriture ont ete avortees',
            interdites.every((r) => ROUTES_INTERDITES.test(r.url)));
        const politiques = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.server_user_sudo_policies WHERE machine_id = ${MACHINE_ID}`);
        constate('politiques sudo en base pour la machine d\'essai', String(politiques));
        verifie('aucune politique n\'a ete posee', politiques === 0, `${politiques} ligne(s)`);
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
