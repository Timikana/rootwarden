/**
 * go-fail2ban-f7.mjs - Sous-lot F7 de `fail2ban/` : DESACTIVER UNE JAIL.
 *
 * Cible : le portage seul (`http://localhost:8444/fail2ban`). Le legacy porte
 * le meme geste, mais F7 est un sous-lot de PORTAGE : ce qui est mesure ici est
 * ce que le portage AJOUTE — l'annonce de la consequence et la reprise de main.
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  `POST /fail2ban/disable_jail` OUVRE UNE SESSION SSH REELLE              ║
 * ║  (`backend/routes/fail2ban.py:418`) ET ARRETE LA SURVEILLANCE.           ║
 * ║                                                                          ║
 * ║  Ce n'est pas destructeur — « Activer la jail » le retablit — mais c'est ║
 * ║  une BAISSE DE GARDE : la machine cesse d'etre protegee contre le force  ║
 * ║  brute, et les adresses deja bannies ne sont PAS liberees.               ║
 * ║                                                                          ║
 * ║  ⛔ CETTE SUITE NE PREND JAMAIS LA CONFIRMATION.                         ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * ══ CE QU'ON MESURE, EN DEUX TEMPS ════════════════════════════════════════
 *
 * 1. SANS JOINDRE PERSONNE. La vue porte `f2b-desact-jamais` — l'avertissement
 *    que ce geste n'a jamais ete exerce — **a cote du bouton, donc visible
 *    AVANT le clic**. C'est la propriete que le portage ajoute et que le
 *    legacy n'a pas ; elle se mesure sur la page nue.
 *
 * 2. EN JOIGNANT LA MACHINE 2. Le panneau de confirmation ne s'ouvre qu'avec
 *    une jail reelle, et `POST /fail2ban/status` ouvre une session SSH pour
 *    l'obtenir (`fail2ban.py`, `with ssh_session(...)`). C'est ce que font
 *    deja F1 a F6, et la cible est **Test-Server-Debian**, jamais la
 *    production. Si la machine ne rend aucune jail, l'etape se declare SANS
 *    OBJET plutot que de conclure sur du vide.
 *
 * ══ LE FILET : DENI PAR DEFAUT ════════════════════════════════════════════
 *
 * Sur ce module, la METHODE ne discrimine pas : `/fail2ban/status` est un POST
 * qui LIT. Un filet par methode y avorterait les lectures dont la page a
 * besoin. Le filet est donc par CHEMIN — et il DENIE PAR DEFAUT, avec une
 * liste des seules LECTURES autorisees.
 *
 * ⚠ C'EST L'INVERSE DE L'ENUMERATION QUI A TRAHI CINQ SUITES DE CE BANC le
 *   2026-09-02 : une liste d'INTERDITS laisse passer ce qu'elle n'a pas prevu,
 *   une liste d'AUTORISES avorte ce qu'elle n'a pas prevu. Une route ajoutee
 *   demain au module sera donc BLOQUEE, pas laissee filer — et la suite le
 *   dira au lieu de le taire.
 *
 * Les lectures autorisees ont ete RELEVEES par sonde, pas recopiees d'une
 * suite voisine : au chargement, la page n'emet AUCUNE requete du module
 * (mesure du 2026-09-02 23:5x) — tout part du choix de machine.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=http://localhost:8444 node go-fail2ban-f7.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase } from './lib-base.mjs';
import { mkdirSync, readFileSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
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
const MACHINE_ID = 2;
const MACHINE_PRODUCTION = 1;

/* Secret RELEVE dans les suites du depot, jamais invente. */
const COMPTE = {
    nom: 'rw-test-super', role: 3,
    secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW',
};

/*
 * LES SEULES LECTURES QUI PEUVENT ABOUTIR. Tout le reste du module est avorte,
 * y compris ce qui n'est pas dans cette liste — c'est le sens d'un deni par
 * defaut. `status` et `jail` ouvrent une session SSH vers la machine CHOISIE :
 * elles ne sont autorisees que parce que la suite ne choisit que la machine 2,
 * et le controle de cible ci-dessous le verifie a chaque requete.
 */
const LECTURES = /\/fail2ban\/(status|jail|services|history|stats|templates|portee)(\?|$)/;
/*
 * ⚠ `portee` A ETE AJOUTEE APRES LE PREMIER LANCEMENT, et c'est le deni par
 *   defaut qui l'a revelee : `/fail2ban/portee` a ete AVORTEE et le panneau de
 *   portee ne s'est pas rendu. C'est une `Route::get` cote Laravel
 *   (`web.php:945`) qui lit la base avec le SQL des deux gestes de parc — elle
 *   ne joint aucune machine.
 *
 *   **C'est le deni par defaut qui fonctionne, pas qui echoue** : une liste
 *   d'interdits aurait laissé passer cette route sans que personne le sache.
 *   Ici elle s'est fait remarquer, on l'a lue, et on l'autorise en connaissance
 *   de cause. Le prix d'un deni par defaut est ce tour de piste ; son gain est
 *   qu'aucune route inconnue ne file en silence.
 */
/* Tout ce qui porte sur le PARC : avorte AVANT tout autre test, sans exception. */
const PARC = /\/fail2ban\/(ban_all_servers|unban_all|install_all)(\?|$)/;
const MODULE = /\/fail2ban\//;
const TEMOIN = '/temoin-e2e-inexistant';
const VERS_BACKEND = /\/(api\/gateway|api_proxy\.php)\//;

const C = { connexion: '/connexion', page: '/fail2ban',
    serveur: '[data-rw="f2b-serveur"]',
    relever: '[data-rw="f2b-relever"]',
    jails: '[data-rw="f2b-jails"]',
    detail: '[data-rw="f2b-jail-detail"]',
    jailNom: '[data-rw="f2b-jail-nom"]',
    desactiver: '[data-rw="f2b-jail-desactiver"]',
    jamais: '[data-rw="f2b-desact-jamais"]',
    confirmation: '[data-rw="f2b-confirmation"]',
    confTitre: '[data-rw="f2b-confirmation-titre"]',
    confTexte: '[data-rw="f2b-confirmation-texte"]',
    confirmer: '[data-rw="f2b-confirmer"]',
    annuler: '[data-rw="f2b-annuler"]',
    cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]' };

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
/** `d` n'est imprime QUE sur un FAIL ; `toujours` sort dans les deux verdicts. */
function verifie(l, ok, d, toujours) {
    const suffixe = toujours || (! ok && d) || '';
    note(`${ok ? 'PASS' : 'FAIL'}  ${l}${suffixe ? '  — ' + suffixe : ''}`);
    if (! ok) echecs += 1;
}
function constate(l, v) { note(`INFO  ${l} : ${v}`); }

/**
 * Un libelle LU dans le catalogue, jamais recopie ici : une chaine recopiee
 * fige la valeur du jour et l'assertion devient verte sur un ecran qui ne dit
 * plus rien. Les DEUX formes de guillemets, `lang/fr/fail2ban.php` melangeant
 * les deux — une version qui n'en lit qu'une rendrait `null` sur la moitie des
 * cles, et chaque assertion se declarerait SANS OBJET : un vert par abstention.
 */
function libelle(cle) {
    try {
        const chemin = new URL('../../laravel/lang/fr/fail2ban.php', import.meta.url).pathname;
        const texte = readFileSync(chemin, 'utf8');
        const simple = texte.match(new RegExp(`'${cle}'\\s*=>\\s*'((?:[^'\\\\]|\\\\.)*)'`));
        if (simple) return simple[1].replace(/\\'/g, "'").replace(/\\\\/g, '\\');
        const double = texte.match(new RegExp(`'${cle}'\\s*=>\\s*"((?:[^"\\\\]|\\\\.)*)"`));

        return double ? double[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\') : null;
    } catch { return null; }
}

function b32(s){const A='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.replace(/=+$/,''))b+=A.indexOf(c.toUpperCase()).toString(2).padStart(5,'0');const o=[];for(let i=0;i+8<=b.length;i+=8)o.push(parseInt(b.slice(i,i+8),2));return Buffer.from(o)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

const avortees = [];
const passees = [];
const reponsesReleve = [];
/*
 * ══ (d) LA JAIL FOURNIE — CE QU'ELLE MESURE, ET CE QU'ELLE NE MESURE PAS ══
 *
 * Test-Server-Debian n'a AUCUNE jail, et la mesure dit pourquoi : fail2ban
 * n'y est meme pas installe (`fail2ban_status`, `installed=0`). Le panneau de
 * confirmation ne peut donc pas s'ouvrir sur des donnees reelles.
 *
 * La propriete non couverte n'est pourtant PAS « une machine a des jails » :
 * c'est **« le panneau nomme la consequence et offre la confirmation »**, et
 * ça, c'est du RENDU. On fournit donc la jail dans la DONNEE de la page, en
 * repondant a la place du serveur — aucune session SSH, aucune mutation.
 *
 * ⚠ ET LA RESERVE, QUI EST LA MOITIE DE LA MESURE :
 *
 *     MESURE      le RENDU du panneau sur une jail FOURNIE
 *     NON MESURE  qu'une machine reelle en produise une, et que le releve la lise
 *
 * **Une suite qui fabrique son entree mesure sa propre fixture.** Sans cette
 * reserve dite A L'ECRAN, un vert se lirait « le panneau fonctionne sur des
 * donnees reelles » — ce que cette etape n'aura pas mesure. C'est la meme
 * distinction que les trois causes d'« aucune jail » : ce qui n'est pas
 * distingue se lit comme la lecture la plus favorable.
 */
const JAIL_FOURNIE = 'sshd-e2e-fournie';
let injecte = false;
let vues = 0;

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];

async function connecte(compte) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(45000);
    const erreursJs = [];
    /*
     * LA REPONSE DU RELEVE, ENREGISTREE. « Aucune jail » a TROIS causes que le
     * DOM ne distingue pas : la machine n'en a aucune, la lecture a echoue, ou
     * mon selecteur est faux. Sans cette trace, la suite se declarerait SANS
     * OBJET dans les trois cas — et « je n'ai rien mesure » se lirait « il n'y
     * a rien ». C'est le defaut exact contre lequel `go-page-wazuh` asserte.
     */
    page.on('response', async (rep) => {
        if (! /\/fail2ban\/status/.test(rep.url())) return;
        let corps = null;
        try { corps = await rep.json(); } catch { /* pas du JSON */ }
        reponsesReleve.push({
            statut: rep.status(),
            succes: corps ? corps.success === true : null,
            message: corps && corps.message ? String(corps.message).slice(0, 120) : '',
            jails: corps && corps.jails ? (Array.isArray(corps.jails) ? corps.jails.length
                : Object.keys(corps.jails).length) : null,
        });
    });
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => { try { await d.dismiss(); } catch { /* deja ferme */ } });

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        vues += 1;
        const url = r.url();
        const chemin = url.replace(/^https?:\/\/[^/]+/, '');
        let corps = '';
        try { corps = r.postData() || ''; } catch { /* pas de corps */ }

        // Le temoin PASSE : chemin inexistant, donc sans effet, et c'est lui
        // qui prouve que le collecteur voit les POST.
        if (chemin.startsWith(TEMOIN)) {
            passees.push({ route: chemin, methode: r.method(), corps });
            r.continue().catch(() => {});

            return;
        }
        // 1. LE PARC D'ABORD, sans condition : ces routes ne prennent aucun
        //    `machine_id` et joignent TOUT, `srv-zabbix` comprise.
        if (PARC.test(url)) {
            avortees.push({ route: chemin, motif: 'geste de PARC', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        // 2. LA PRODUCTION ENSUITE, quel que soit le geste.
        if (new RegExp(`"machine_id"\\s*:\\s*${MACHINE_PRODUCTION}\\b`).test(corps)
            || new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(url)
            || /srv-zabbix/.test(corps)) {
            avortees.push({ route: chemin, motif: 'vise la PRODUCTION', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        // 2 bis. LA JAIL FOURNIE — on repond A LA PLACE du serveur, donc la
        //        requete ne part pas : aucune session SSH sur cette passe.
        if (injecte && /\/fail2ban\/status/.test(url)) {
            r.respond({
                status: 200, contentType: 'application/json',
                body: JSON.stringify({ success: true, installed: 1, running: 1,
                    jails: [{ name: JAIL_FOURNIE, currently_banned: 0 }] }),
            }).catch(() => {});

            return;
        }
        if (injecte && /\/fail2ban\/jail/.test(url)) {
            r.respond({
                status: 200, contentType: 'application/json',
                body: JSON.stringify({ success: true, config: '', banned_ips: [] }),
            }).catch(() => {});

            return;
        }
        /*
         * ⚠ `services` EST FOURNIE ELLE AUSSI, ET C'EST UNE CORRECTION.
         *
         * J'avais ecrit « aucune session SSH sur cette passe » — **c'etait
         * faux**. Mesure par decoupage sur les decorateurs de `fail2ban.py` :
         *   status · jail · services  ouvrent `ssh_session`
         *   history · stats · templates  ne l'ouvrent pas
         * `services` passait ma liste de lectures et joignait donc la machine 2
         * pour de vrai. On la fournit, et l'affirmation redevient VRAIE.
         *
         * (Ma premiere mesure rendait « pas de SSH » pour les SEPT routes : la
         * plage `sed` se refermait sur la ligne suivante. **Zero partout = la
         * mesure n'a pas eu lieu**, et j'ai failli m'en contenter parce qu'elle
         * allait dans le sens qui rassure.)
         */
        if (injecte && /\/fail2ban\/services/.test(url)) {
            r.respond({
                status: 200, contentType: 'application/json',
                body: JSON.stringify({ success: true, services: [] }),
            }).catch(() => {});

            return;
        }
        // 3. DENI PAR DEFAUT SUR LE MODULE : seules les LECTURES passent.
        if (MODULE.test(url)) {
            if (LECTURES.test(url)) {
                passees.push({ route: chemin, methode: r.method(), corps });
                r.continue().catch(() => {});

                return;
            }
            avortees.push({ route: chemin, motif: 'hors des lectures autorisees', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (VERS_BACKEND.test(url)) passees.push({ route: chemin, methode: r.method(), corps });
        r.continue().catch(() => {});
    });

    await page.goto(`${BASE}${C.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', compte.nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    for (let essai = 0; essai < 2; essai += 1) {
        const champ = await page.$('input[name="2fa_code"]');
        if (! champ) break;
        if (essai > 0) await dors((resteFenetre() + 1) * 1000);
        await champ.click({ clickCount: 3 });
        await champ.type(totp(compte.secret), { delay: 8 });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
    }
    if (C.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$(C.accepte);
        if (b) { await b.click(); try { await nav; } catch {} }
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

try {
    if (CIBLE !== 'laravel') {
        constate('cible', 'SANS OBJET — F7 est un sous-lot de PORTAGE, le legacy n\'ajoute rien a mesurer');
        note('\n0 etapes, 0 PASS, 0 FAIL');
        note('=== TOUT OK ===');
        process.exit(0);
    }

    const s = await connecte(COMPTE);
    verifie('la session a tenu', ! s.surConnexion, s.page.url());
    if (s.surConnexion) throw new Error('session non etablie');
    const page = s.page;
    await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
    await dors(1000);
    constate('URL finale', page.url());
    verifie('la page atteinte est bien celle qu\'on croit',
        /\/fail2ban\/?$/.test(page.url()),
        `redirige vers ${page.url()} : ce qui suit ne mesurerait pas cette page`,
        page.url().replace(/^https?:\/\/[^/]+/, ''));

    // ══ 1. CE QUI SE MESURE SANS JOINDRE PERSONNE ════════════════════════
    await etape('l\'avertissement est A COTE du bouton, et donc lu AVANT le clic', async () => {
        const vu = await page.evaluate((sel) => {
            const b = document.querySelector(sel.desactiver);
            const j = document.querySelector(sel.jamais);
            if (! b || ! j) return { bouton: b !== null, jamais: j !== null };
            /*
             * « A COTE » se mesure par la PARENTE, pas par les coordonnees :
             * un test de position rougirait a la premiere retouche de mise en
             * page sans que rien de vrai ait change.
             */
            let a = b, prof = 0, contient = false;
            while (a && prof < 4) { if (a.contains(j)) { contient = true; break; } a = a.parentElement; prof += 1; }

            return {
                bouton: true, jamais: true, contient, prof,
                texte: (j.innerText || '').replace(/\s+/g, ' ').trim(),
            };
        }, C);
        constate('avertissement', vu.jamais
            ? `« ${(vu.texte || '').slice(0, 90) || '(vide)'} », a ${vu.prof} parent(s) du bouton`
            : 'ancre absente');
        verifie('le bouton de desactivation existe', vu.bouton, 'ancre `f2b-jail-desactiver` absente');
        verifie('l\'avertissement « jamais exerce » est rendu', vu.jamais,
            'ancre `f2b-desact-jamais` absente : le portage n\'annonce plus que ce geste n\'a jamais servi');
        if (! vu.bouton || ! vu.jamais) return;
        verifie('l\'avertissement partage un ancetre proche avec le bouton',
            vu.contient,
            `aucun ancetre commun a moins de 4 niveaux : l'avertissement peut etre ailleurs sur la page`);
        verifie('l\'avertissement est traduit et non vide',
            vu.texte.length > 0 && ! /:[a-z_]{3,}/.test(vu.texte),
            vu.texte.length === 0 ? 'avertissement vide' : `jeton non traduit : ${vu.texte}`);
    });

    // ══ 2. LE PANNEAU, EN JOIGNANT LA SEULE MACHINE 2 ════════════════════
    let jailOuverte = null;
    await etape('une jail est ouverte sur Test-Server-Debian', async () => {
        const opts = await page.$$eval(`${C.serveur} option`,
            (ns) => ns.map((n) => `${n.value}|${n.textContent.trim()}`));
        constate('serveurs offerts', opts.join(' · ') || '(aucun)');
        const cible = opts.find((o) => o.startsWith(`${MACHINE_ID}|`));
        if (! cible) {
            constate('jail', `SANS OBJET — la machine ${MACHINE_ID} n'est pas offerte`);

            return;
        }
        /*
         * ⚠ ON RELIT LE NOM AVANT DE CHOISIR. `MACHINE_ID = 2` est une
         * constante, mais un identifiant n'est pas une identite : si le parc
         * etait renumerote, ce `2` designerait une autre machine et la suite
         * joindrait en SSH quelque chose qu'elle n'a pas choisi.
         */
        verifie(`la machine ${MACHINE_ID} est bien Test-Server-Debian`,
            /Test-Server-Debian/i.test(cible) && ! /srv-zabbix/i.test(cible),
            `l'option ${MACHINE_ID} porte « ${cible} »`, cible);
        if (/srv-zabbix/i.test(cible)) return;

        await page.select(C.serveur, String(MACHINE_ID));
        const b = await page.$(C.relever);
        if (b) { await b.click(); }
        await dors(6000);

        const jails = await page.$$eval(`${C.jails} [data-rw]`,
            (ns) => ns.map((n) => (n.innerText || '').trim()).filter(Boolean)).catch(() => []);
        constate('jails rendues', jails.slice(0, 5).join(' · ') || '(aucune)');
        const rep = reponsesReleve[reponsesReleve.length - 1] || null;
        constate('reponse du releve', rep === null ? '⚠ AUCUNE — la requete de releve n\'a pas eu lieu'
            : `HTTP ${rep.statut}, success=${rep.succes}, jails=${rep.jails === null ? '?' : rep.jails}`
              + (rep.message ? ` — ${rep.message}` : ''));
        if (! jails.length) {
            /*
             * ON NOMME LAQUELLE DES TROIS CAUSES. Un `SANS OBJET` unique les
             * confondrait, et c'est precisement ce qui fait lire « il n'y a
             * rien » a la place de « je n'ai rien su lire ».
             */
            if (rep === null) {
                verifie('le releve a bien ete emis', false,
                    'aucune requete `/fail2ban/status` : le clic sur « relever » n\'a rien declenche');
            } else if (rep.succes !== true) {
                constate('panneau de desactivation',
                    `SANS OBJET — la LECTURE a echoue (HTTP ${rep.statut}, ${rep.message || 'sans message'}) :`
                    + ' on ne sait pas si cette machine a des jails, et une absence non lue ne se conclut pas');
            } else if (rep.jails) {
                verifie('les jails lues sont RENDUES a l\'ecran', false,
                    `le serveur en a rendu ${rep.jails} et l'ecran n'en montre aucune :`
                    + ' le defaut est dans le rendu ou dans mon selecteur, pas dans la machine');
            } else {
                constate('panneau de desactivation',
                    'SANS OBJET — la lecture a REUSSI et cette machine n\'a aucune jail :'
                    + ' le panneau ne peut pas s\'ouvrir, et conclure sur du vide vaudrait moins que rien');
            }

            return;
        }
        const ok = await page.evaluate((sel) => {
            const n = document.querySelector(`${sel.jails} [data-rw]`);
            if (! n) return false;
            n.click();

            return true;
        }, C);
        await dors(2500);
        const nom = await page.$eval(C.jailNom, (n) => (n.innerText || '').trim()).catch(() => null);
        jailOuverte = ok && nom ? nom : null;
        constate('jail ouverte', jailOuverte || '(aucune)');
    });

    await etape('le panneau nomme la CONSEQUENCE, et cette suite ne confirme pas', async () => {
        if (! jailOuverte) {
            constate('panneau de desactivation',
                'SANS OBJET — aucune jail ouverte, il n\'y a pas de panneau a mesurer');

            return;
        }
        const avant = passees.length;
        const b = await page.$(C.desactiver);
        if (! b) {
            verifie('le bouton de desactivation est atteignable', false,
                'le bouton n\'est pas rendu alors qu\'une jail est ouverte');

            return;
        }
        await b.click();
        await dors(1200);
        const vu = await page.evaluate((sel) => {
            const p = document.querySelector(sel.confirmation);
            const t = document.querySelector(sel.confTitre);
            const x = document.querySelector(sel.confTexte);
            const c = document.querySelector(sel.confirmer);

            return {
                ouvert: p !== null && p.offsetParent !== null,
                titre: t ? (t.innerText || '').replace(/\s+/g, ' ').trim() : '',
                texte: x ? (x.innerText || '').replace(/\s+/g, ' ').trim() : '',
                confirme: c !== null && c.offsetParent !== null,
            };
        }, C);
        constate('panneau', vu.ouvert
            ? `« ${vu.titre} » — ${vu.texte.slice(0, 110)}` : 'NON ouvert');
        verifie('le clic ouvre un panneau de confirmation', vu.ouvert,
            'aucun panneau : le geste partirait sans reprise de main');
        if (! vu.ouvert) return;

        /*
         * LA CONSEQUENCE, PAS LE MECANISME. Ce qui compte pour qui decide
         * n'est pas qu'un fichier change : c'est que la protection s'arrete.
         * Le libelle est LU dans le catalogue — le comparer a une chaine
         * recopiee ici mesurerait ma prose et non l'ecran.
         */
        const attendu = libelle('conf_texte_desact');
        if (attendu === null) {
            constate('consequence nommee',
                'SANS OBJET — `conf_texte_desact` illisible dans le catalogue');
        } else {
            const gabarit = attendu.replace(/:[a-z_]+/g, '').replace(/\s+/g, ' ').trim();
            const morceaux = gabarit.split(' ').filter((m) => m.length > 4).slice(0, 6);
            verifie('le panneau nomme la CONSEQUENCE, avec les mots du catalogue',
                morceaux.length > 0 && morceaux.every((m) => vu.texte.includes(m)),
                `le texte affiche ne reprend pas le libelle : « ${vu.texte.slice(0, 120)} »`);
        }
        verifie('le panneau nomme la jail concernee',
            vu.texte.includes(jailOuverte) || vu.titre.includes(jailOuverte),
            `« ${jailOuverte} » n'apparait pas : le panneau ne dit pas SUR QUOI il porte`);
        verifie('aucun jeton non traduit dans le panneau',
            ! /:[a-z_]{3,}/.test(`${vu.titre} ${vu.texte}`),
            `${vu.titre} | ${vu.texte}`);
        verifie('la confirmation est OFFERTE, et cette suite ne la prend PAS',
            vu.confirme,
            'aucun bouton de confirmation : le geste serait deja parti');

        const parties = passees.slice(avant);
        constate('requetes emises par l\'ouverture du panneau', parties.length
            ? parties.map((p) => `${p.methode} ${p.route}`).join(' | ') : '(aucune)');
        verifie('OUVRIR le panneau n\'a coute AUCUNE requete',
            parties.length === 0,
            parties.map((p) => `${p.methode} ${p.route}`).join(' | '), 'aucune');

        const annuler = await page.$(C.annuler);
        if (annuler) { await annuler.click(); await dors(500); }
    });

    // ══ 3. LE PANNEAU, SUR UNE JAIL FOURNIE ══════════════════════════════
    await etape('sur une jail FOURNIE : le panneau nomme la consequence, et on ne confirme pas', async () => {
        /*
         * LA RESERVE EST DITE AVANT LA MESURE, pas apres : un lecteur qui
         * s'arrete au premier PASS doit deja savoir ce qu'il ne lit pas.
         */
        constate('portee de cette etape',
            `MESURE le RENDU du panneau sur une jail FOURNIE (« ${JAIL_FOURNIE} », injectee dans la`
            + ' reponse) — NON MESURE qu\'une machine reelle en produise une et que le releve la lise');

        injecte = true;
        const avant = passees.length;
        await page.select(C.serveur, String(MACHINE_ID));
        const rel = await page.$(C.relever);
        if (rel) { await rel.click(); }
        await dors(1500);

        const carte = await page.$(`[data-rw="f2b-jail-${JAIL_FOURNIE}"]`);
        verifie('la jail fournie est RENDUE comme une carte',
            carte !== null,
            'la reponse fournie n\'a produit aucune carte : le rendu ne suit pas la donnee');
        if (! carte) { injecte = false; return; }

        await carte.click();
        await dors(900);
        const nom = await page.$eval(C.jailNom, (n) => (n.innerText || '').trim()).catch(() => '');
        constate('detail ouvert', nom || '(aucun titre)');

        const b = await page.$(C.desactiver);
        if (! b) {
            verifie('le bouton de desactivation est atteignable', false,
                'le bouton n\'est pas rendu alors qu\'une jail est ouverte');
            injecte = false;

            return;
        }
        await b.click();
        await dors(1000);
        const vu = await page.evaluate((sel) => {
            const p = document.querySelector(sel.confirmation);
            const t = document.querySelector(sel.confTitre);
            const x = document.querySelector(sel.confTexte);
            const c = document.querySelector(sel.confirmer);

            return {
                ouvert: p !== null && p.offsetParent !== null,
                titre: t ? (t.innerText || '').replace(/\s+/g, ' ').trim() : '',
                texte: x ? (x.innerText || '').replace(/\s+/g, ' ').trim() : '',
                confirme: c !== null && c.offsetParent !== null,
            };
        }, C);
        constate('panneau', vu.ouvert ? `« ${vu.titre} » — ${vu.texte.slice(0, 130)}` : 'NON ouvert');
        verifie('le clic ouvre un panneau de confirmation', vu.ouvert,
            'aucun panneau : le geste partirait sans reprise de main');
        if (vu.ouvert) {
            /*
             * LA CONSEQUENCE, PAS LE MECANISME — et le libelle est LU dans le
             * catalogue : le comparer a une chaine recopiee ici mesurerait ma
             * prose et non l'ecran.
             */
            const attendu = libelle('conf_texte_desact');
            if (attendu === null) {
                constate('consequence nommee', 'SANS OBJET — `conf_texte_desact` illisible');
            } else {
                const mots = attendu.replace(/:[a-z_]+/g, ' ').split(/[^A-Za-zÀ-ÿ']+/)
                    .filter((m) => m.length > 5).slice(0, 5);
                verifie('le panneau nomme la CONSEQUENCE, avec les mots du catalogue',
                    mots.length > 0 && mots.every((m) => vu.texte.includes(m)),
                    `mots attendus « ${mots.join(' ')} » absents de « ${vu.texte.slice(0, 130)} »`);
            }
            verifie('le panneau nomme la jail concernee',
                vu.texte.includes(JAIL_FOURNIE) || vu.titre.includes(JAIL_FOURNIE),
                `« ${JAIL_FOURNIE} » n'apparait pas : le panneau ne dit pas SUR QUOI il porte`);
            /*
             * ⚠ « AUCUN JETON NON TRADUIT » EST VRAI A VIDE, et cette suite
             *   l'a decerne sur un panneau ENTIEREMENT VIDE — une universelle
             *   negative satisfaite par l'absence. On exige donc d'abord qu'il
             *   y ait quelque chose a lire : c'est le defaut que je traque
             *   depuis ce matin, commis dans l'assertion que je venais
             *   d'ecrire contre lui.
             */
            verifie('le panneau porte un titre ET un texte, non vides',
                vu.titre.length > 0 && vu.texte.length > 0,
                `titre « ${vu.titre} » (${vu.titre.length} car.), texte ${vu.texte.length} car. —`
                + ' un panneau vide fait consentir a un geste que rien ne nomme');
            verifie('aucun jeton non traduit dans le panneau',
                vu.titre.length > 0 && vu.texte.length > 0
                    && ! /:[a-z_]{3,}/.test(`${vu.titre} ${vu.texte}`),
                vu.titre.length === 0 || vu.texte.length === 0
                    ? 'panneau vide : rien a verifier, et un vert ici serait une absence'
                    : `${vu.titre} | ${vu.texte}`);
            verifie('la confirmation est OFFERTE, et cette suite ne la prend PAS',
                vu.confirme, 'aucun bouton de confirmation : le geste serait deja parti');
        }
        const parties = passees.slice(avant);
        /*
         * ON MESURE CE QUI COMPTE : qu'aucune lecture OUVRANT UNE SESSION SSH
         * ne soit partie. « Aucune requete du tout » etait a la fois trop fort
         * et FAUX — `history`, `stats` et `portee` partent legitimement et ne
         * joignent personne.
         *
         * ⚠ Et le `toujours` disait « aucune session SSH ouverte » en
         *   s'imprimant AUSSI sur le FAIL, affirmant le contraire du verdict
         *   qu'il accompagnait — septieme occurrence de ce motif sur ce banc,
         *   et la premiere que je commets en le connaissant. Un detail qui ne
         *   vaut que pour UN verdict se conditionne a ce verdict.
         */
        const ouvreSSH = /\/fail2ban\/(status|jail|services)(\?|$)/;
        const sessions = parties.filter((p) => ouvreSSH.test(p.route));
        constate('requetes de l\'etape', parties.length
            ? parties.map((p) => `${p.methode} ${p.route}`).join(' | ') : '(aucune)');
        verifie('AUCUNE lecture ouvrant une session SSH n\'est partie',
            sessions.length === 0,
            sessions.map((p) => `${p.methode} ${p.route}`).join(' | '),
            sessions.length === 0
                ? `0 session SSH — status, jail et services ont ete FOURNIES (${parties.length} autre(s) requete(s), sans SSH)`
                : '');

        const annuler = await page.$(C.annuler);
        if (annuler) { await annuler.click(); await dors(400); }
        injecte = false;
    });

    await etape('aucune erreur JavaScript', async () => {
        verifie('aucune erreur JavaScript sur la page', s.erreursJs.length === 0,
            s.erreursJs.slice(0, 3).join(' | '), 'aucune');
    });

    await etape('captures', async () => {
        const dossier = new URL('./screenshots/fail2ban/f7', import.meta.url).pathname;
        mkdirSync(dossier, { recursive: true });
        for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                         { n: 'mobile', w: 390, h: 844 }]) {
            await page.setViewport({ width: f.w, height: f.h });
            await dors(400);
            await page.screenshot({ path: `${dossier}/f7-${f.n}.png`, fullPage: true });
        }
        verifie('les trois captures sont ecrites', true, '', dossier);
    });
} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    try {
        constate('requetes AVORTEES', avortees.length
            ? avortees.map((a) => `${a.route} (${a.motif})`).join(' | ') : '(aucune)');
        if (vues === 0) {
            constate('controle de surete',
                'SANS OBJET — aucune requete vue, le filet n\'a rien eu a filtrer');
        } else {
            /*
             * LE GESTE LUI-MEME : ni abouti, ni meme tente. On distingue les
             * deux — un geste AVORTE veut dire que la page l'a compose, ce qui
             * est un defaut different de « il est parti ».
             */
            const partis = passees.filter((p) => /disable_jail/.test(p.route));
            const tentes = avortees.filter((a) => /disable_jail/.test(a.route));
            verifie('AUCUNE desactivation n\'a abouti', partis.length === 0,
                partis.map((p) => `${p.methode} ${p.route}`).join(' | '),
                `${vues} requete(s) vue(s)`);
            verifie('AUCUNE desactivation n\'a meme ete composee', tentes.length === 0,
                tentes.map((a) => a.route).join(' | '), 'aucune');
            verifie('AUCUNE requete n\'a vise la production',
                ! passees.some((p) => new RegExp(`"machine_id"\\s*:\\s*${MACHINE_PRODUCTION}\\b`).test(p.corps || '')
                    || /srv-zabbix/.test(p.corps || '')),
                'une requete a vise `srv-zabbix`');
        }
    } catch (e) { note(`FAIL  controle de surete : ${e.message}`); echecs += 1; }
    try {
        const zabbix = litEnBase("SELECT CONCAT(name,'|',ip) FROM rootwarden.machines WHERE id = 1");
        verifie('srv-zabbix est intacte', zabbix.length === 1 && /^srv-zabbix\|/.test(zabbix[0]),
            zabbix[0] || '(absente)', zabbix[0] || '');
    } catch (e) { note(`FAIL  controle de l'etat : ${e.message}`); echecs += 1; }
    for (const c of contextes) { try { await c.close(); } catch { /* deja ferme */ } }
    try { await navigateur.close(); } catch { /* deja ferme */ }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
