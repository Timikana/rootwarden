/**
 * go-page-cle-plateforme.mjs — P1 : la cle de plateforme, sur les deux cibles.
 *
 * legacy   `/adm/platform_keys.php`        portage  `/cle-plateforme`
 *
 * ══ CE QUE CETTE SUITE NE MESURERA JAMAIS, ET POURQUOI C'EST ECRIT ICI ════
 *
 * **La REUSSITE de la rotation n'est mesuree sur aucune cible, et ne le sera
 * pas.** Ce n'est pas une lacune a combler un jour : c'est une decision, et
 * elle doit rester lisible pour que personne ne « repare » ce trou.
 *
 * `POST /regenerate_platform_key` ne prend AUCUN `machine_id`. Son corps est
 * vide et il porte sur la FLOTTE :
 *
 *     UPDATE machines SET platform_key_deployed = FALSE   -- sans clause WHERE
 *
 * Il n'existe donc **aucune cible sure**. Le motif habituel du chantier —
 * « retirer la cible plutot que renforcer le garde » — ne s'applique pas, parce
 * qu'il n'y a rien a retirer : la portee est le parc entier, `srv-zabbix`
 * comprise, dont la cle de plateforme est la SEULE authentification (ni mot de
 * passe, ni mot de passe root — mesure de l'exploitant).
 *
 * Une rotation lancee une fois coupe l'acces a toutes les machines jusqu'au
 * re-deploiement, qui exige lui-meme un acces. **Mesurer ce geste une seule
 * fois briquerait la production.**
 *
 * DEUX MISES A JOUR DU 2026-08-27, ET AUCUNE NE CHANGE LA CONCLUSION.
 *
 * (a) `regenerate_platform_key()` ne fait plus `unlink()` mais
 *     `_archive_platform_key()`. **Mais le risque « secret non reproductible »
 *     n'est pas LEVE : il est DEPLACE, et conditionne.** Le catalogue du portage
 *     le dit mieux que ne le disait ma premiere redaction
 *     (`lang/fr/plateforme.php:213`) :
 *
 *         « cette archive vit dans le MEME volume Docker que la clef courante :
 *           une perte du volume emporte les deux, et RootWarden ne sauvegarde
 *           pas ce volume. "Reversible pendant N jours" ne vaut donc que si le
 *           volume survit, et cette seconde condition ne depend pas du produit. »
 *
 *     J'avais ecrit « le risque est LEVE ». C'etait trop optimiste, et du cote
 *     qui rassure. Une conclusion juste dont la raison a change se reecrit —
 *     et une reecriture peut etre fausse a son tour.
 *
 * (b) **ET LA ROTATION NE REVOQUE RIEN** — mesure d'une relecture de securite
 *     (`AUDIT-PRERELECTURE-K-MODULES.md` §9.3, commit `e6b8530`) :
 *
 *         ssh.py:745   printf … >> ~/.ssh/authorized_keys        APPEND
 *         ssh.py:755   printf … >> /root/.ssh/authorized_keys    APPEND
 *         ssh.py:808   printf … >  …/<compte de service>/…       ecrase
 *
 *     La rotation genere une paire neuve ; elle ne retire l'ancienne clef
 *     publique d'AUCUN `authorized_keys`. Apres rotation ET redeploiement,
 *     `root` et le compte nominal portent les DEUX clefs.
 *
 * Il faut donc tenir les deux faits ensemble, et ils ne disent pas la meme chose :
 *
 *   1. **RootWarden PERD l'acces** jusqu'au redeploiement — la nouvelle paire
 *      n'est dans aucun `authorized_keys`, et `srv-zabbix` n'a ni mot de passe
 *      ni mot de passe root. C'est ce qui rend le geste sans retour ICI ;
 *   2. **l'ancienne clef reste AUTORISEE** — qui la detient garde un acces root
 *      sur chaque machine, apres la rotation. Elle arrete l'USAGE de la clef par
 *      RootWarden ; elle ne la REVOQUE pas.
 *
 * La seconde interdit d'ecrire, ici ou a l'ecran, que ce geste « repond a une
 * clef compromise ». **Aucun geste unique n'y repond** : l'en retirer demande
 * `server_user_remove_key`, compte par compte et machine par machine. C'est
 * desagreable a ecrire et c'est ce qu'il faut ecrire.
 *
 * ══ CE QUE LA SUITE MESURE A LA PLACE ═════════════════════════════════════
 *
 * La propriete utile n'est pas « le geste aboutit » mais **« avant tout
 * consentement, RIEN n'est parti »** — mesuree au RESEAU, jamais au DOM : un
 * panneau peut s'ouvrir ET l'appel partir quand meme.
 *
 * ══ ASYMETRIE ASSUMEE ENTRE LES DEUX CIBLES ═══════════════════════════════
 *
 * Sur le PORTAGE le bouton OUVRE un panneau : le clic est LOCAL, donc on clique
 * pour de vrai et l'on mesure qu'aucune requete ne part.
 * Sur le LEGACY, `regenerateKey()` part au premier clic derriere un `confirm()`
 * natif. **On ne clique donc pas** : la propriete « le geste ne part pas seul »
 * s'y lit dans la STRUCTURE — presence du bouton, forme de son `onclick` — sans
 * jamais l'actionner. C'est la regle de S7a : *un portail qui declenche AU CLIC
 * ne se teste pas en cliquant.*
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * Filet a interception : `/regenerate_platform_key`, `/deploy_platform_key`,
 * `/deploy_service_account`, `/remove_ssh_password`, `/reenter_ssh_password`
 * sont AVORTES sans condition, et **toute** requete citant la machine 1 l'est
 * aussi. Une assertion de surete le verifie a la fin — le filet ne se suppose
 * pas, il se mesure.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';
import { constateArchivage } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const MACHINE_PRODUCTION = 1;

/* Secrets RELEVES dans les suites du depot, jamais inventes. */
const COMPTES = {
    super: { nom: 'rw-test-super', role: 3,
        secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW',
        admis: true, motif: 'le role 3 contourne, SANS detenir la permission' },
    user: { nom: 'rw-test-user', role: 1,
        secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW',
        admis: false, motif: 'refuse par la PERMISSION, pas par le role' },
};

/*
 * Les gestes qui ne doivent JAMAIS partir, quelle que soit la cible.
 *
 * ⚠ CETTE LISTE EN COMPTAIT CINQ, LE MODULE EN A QUATORZE (2026-09-02).
 *   `backend/routes/ssh.py` porte 19 routes dont 14 en POST, et **`/deploy`
 *   n'etait pas surveille** — le deploiement de cles, qui ecrit en root sur
 *   toutes les machines cochees et REVOQUE des acces. Une enumeration ecrite de
 *   memoire avait retenu les cinq noms de la page et oublie le geste du module.
 *
 * DEUX CLAUSES, parce que ce module a DEUX regimes :
 *   (1) les chemins destructeurs, avortes QUELLE QUE SOIT LA METHODE — le
 *       legacy PHP n'a aucune discipline de methode, un GET peut y ecrire ;
 *   (2) tout non-GET vers la passerelle : cette page est en LECTURE SEULE,
 *       donc aucune ecriture n'a de raison d'en partir, meme vers un module
 *       dont le nom ne figure pas ci-dessus.
 *
 * La clause (2) est celle qui survit a l'ajout d'une route ; la (1) est celle
 * qui rattrape le legacy. Aucune des deux ne suffit seule.
 *
 * Remesurer : grep -nE "@bp.route" backend/routes/ssh.py
 */
const INTERDITS = new RegExp(
    '/(deploy|preflight_check|deploy_platform_key|revoke_service_account'
    + '|deploy_service_account|test_platform_key|remove_ssh_password'
    + '|reenter_ssh_password|regenerate_platform_key|scan_server_users'
    + '|sshd_allow_user|server_user_remove_key|remove_user_keys'
    + '|delete_remote_user)(\\?|/|$)');
/* Ce qui vise le backend, quel que soit le portail. */
const VERS_BACKEND = /\/(api\/gateway|api_proxy\.php)\//;
/* Le predicat unique : le filet et le VERDICT doivent porter sur la MEME chose.
 * Les avoir laisses diverger est ce qui a rendu le trou invisible ailleurs. */
const estInterdit = (route, methode) => INTERDITS.test(route)
    || (methode !== 'GET' && VERS_BACKEND.test(route));

const C = CIBLE === 'laravel'
    ? { connexion: '/connexion', page: '/cle-plateforme',
        bloc: '[data-rw="cle-bloc"]', valeur: '[data-rw="cle-valeur"]',
        rotation: '[data-rw="cle-rotation"]', lancer: '[data-rw="cle-rotation-lancer"]',
        jamais: '[data-rw="cle-rotation-jamais"]',
        panneau: '[data-rw="cle-panneau"]', panneauTexte: '[data-rw="cle-panneau-texte"]',
        panneauTitre: '[data-rw="cle-panneau-titre"]',
        panneauAnnuler: '[data-rw="cle-panneau-annuler"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]' }
    : { connexion: '/auth/login.php?lang=fr', page: '/adm/platform_keys.php',
        bloc: '#pubkey-display', valeur: '#pubkey-display',
        rotation: null, lancer: 'button[onclick="regenerateKey()"]',
        jamais: null, panneau: null, panneauTexte: null, panneauTitre: null, panneauAnnuler: null,
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]' };

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
function verifiePortage(l, ok, d) {
    if (CIBLE === 'laravel') return verifie(l, ok, ok ? '' : d);
    constate(l, ok ? 'verifie sur le legacy aussi' : `ecart assume du legacy — ${d}`);
}

function b32(s){const A='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.replace(/=+$/,''))b+=A.indexOf(c.toUpperCase()).toString(2).padStart(5,'0');const o=[];for(let i=0;i+8<=b.length;i+=8)o.push(parseInt(b.slice(i,i+8),2));return Buffer.from(o)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

const avortees = [];
const passees = [];
/*
 * REQUETES VUES PAR L'INTERCEPTEUR, avortees et passees confondues. C'est le
 * temoin que le filet a eu un OBJET : sans lui, une suite tombee avant
 * d'ouvrir une page decerne « aucun geste interdit n'a abouti » — vrai, et
 * entierement vide. Ni `passees` ni `avortees` ne suffisent : une page qui
 * n'appelle aucune route filtree les laisse vides alors que le trafic a eu lieu.
 */
let vues = 0;
const boites = [];

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
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    // Un `confirm()` natif du legacy ne doit JAMAIS etre accepte : on le compte
    // et on le REFUSE. C'est ce qui rend le clic impossible a rendre dangereux.
    page.on('dialog', async (d) => {
        boites.push({ type: d.type(), message: d.message() });
        try { await d.dismiss(); } catch { /* deja ferme */ }
    });

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        vues += 1;
        const url = r.url();
        const chemin = url.replace(/^https?:\/\/[^/]+/, '');
        let corps = '';
        try { corps = r.postData() || ''; } catch { /* pas de corps */ }

        // FAIL-CLOSED, DANS CET ORDRE : les gestes interdits d'abord, la machine
        // de production ensuite. Un geste interdit qui citerait la machine 2
        // serait avorte quand meme.
        if (estInterdit(chemin, r.method())) {
            avortees.push({ route: chemin, motif: 'geste INTERDIT sur ce module', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (new RegExp(`"machine_id"\\s*:\\s*${MACHINE_PRODUCTION}\\b`).test(corps)
            || new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(url)) {
            avortees.push({ route: chemin, motif: 'vise la PRODUCTION', corps });
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        if (VERS_BACKEND.test(url)) passees.push({ route: chemin, methode: r.method() });
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

    /*
     * LA PRECONDITION, MESUREE ET NON SUPPOSEE. La garde est « la permission OU
     * le role 3 ». Si un compte d'epreuve venait a DETENIR la permission, le
     * chemin mesure ci-dessous cesserait d'etre le contournement — et les
     * assertions diraient autre chose que ce que leur libelle annonce.
     */
    const porteurs = litEnBase(
        "SELECT u.name FROM rootwarden.users u JOIN rootwarden.permissions p "
        + "ON p.user_id = u.id WHERE p.can_manage_platform_key = 1");
    constate('comptes detenant `can_manage_platform_key`', porteurs.join(', ') || '(aucun)');
    verifie('aucun compte d\'epreuve ne detient la permission',
        ! porteurs.some((n) => n.startsWith('rw-test-')),
        `${porteurs.join(', ')} — le chemin mesure n'est plus le contournement du role 3`,
        porteurs.join(', ') || 'aucun');

    // ══ 1. LES DEUX CHEMINS DE LA GARDE, MESURES AU STATUT ═══════════════
    for (const cle of ['user', 'super']) {
        const compte = COMPTES[cle];
        await etape(`garde : ${compte.nom} (role ${compte.role})`, async () => {
            const s = await connecte(compte);
            try {
                verifie(`${compte.nom} : la session a tenu`, ! s.surConnexion, s.page.url());
                if (s.surConnexion) return;
                const rep = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
                const statut = rep ? rep.status() : 0;
                constate(`${compte.nom} : statut`, `${statut} — ${compte.motif}`);
                // AU STATUT, jamais au texte du corps : un 404 dit « cette page
                // n'existe pas », pas « vous n'y avez pas droit ».
                verifie(`${compte.nom} (role ${compte.role}) est ${compte.admis ? 'admis' : 'refuse'}`,
                    compte.admis ? statut === 200 : statut === 403, `statut ${statut}`);
            } finally {
                try { await s.ctx.close(); } catch { /* deja ferme */ }
            }
        });
        await dors((resteFenetre() + 1) * 1000);
    }

    // ══ 2. LA PAGE, AU COMPTE QUI Y ACCEDE ═══════════════════════════════
    const s = await connecte(COMPTES.super);
    verifie('la session a tenu', ! s.surConnexion, s.page.url());
    if (s.surConnexion) throw new Error('session non etablie');
    const page = s.page;
    await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
    await dors(700);

    await etape('la cle publique est rendue', async () => {
        const vu = await page.evaluate((sel) => {
            const e = document.querySelector(sel);

            return { present: e !== null, texte: e ? (e.textContent || '').trim() : '' };
        }, C.valeur);
        constate('bloc de cle', vu.present ? `${vu.texte.length} caracteres` : '(absent)');
        // LA PROPRIETE PORTE SA PRECONDITION : un bloc vide se verifierait sur
        // rien. On exige qu'il soit rendu ET qu'il porte une clef.
        verifie('la cle publique de la plateforme est affichee',
            vu.present && /^ssh-|^ecdsa-|AAAA/.test(vu.texte),
            vu.present ? `« ${vu.texte.slice(0, 40)} »` : 'le bloc n\'est pas rendu',
            `${vu.texte.length} caracteres`);
    });

    // ══ 3. LA ROTATION — LE GESTE QU'ON N'EXERCE PAS ═════════════════════
    await etape('la rotation ne part pas seule', async () => {
        const avantPassees = passees.length;
        const avantAvortees = avortees.length;
        const bouton = await page.$(C.lancer);
        constate('bouton de rotation', bouton ? 'present' : '(absent)');

        if (CIBLE === 'laravel') {
            /*
             * SUR LE PORTAGE LE CLIC EST LOCAL : il ouvre un panneau. On clique
             * donc pour de vrai — c'est le cablage du bouton qu'on eprouve,
             * qu'un `page.evaluate` ne mesurerait pas — et l'on verifie AU
             * RESEAU qu'aucune requete n'est partie. Un panneau peut s'ouvrir ET
             * l'appel partir quand meme.
             */
            verifie('le bouton de rotation est offert au role 3', bouton !== null, C.lancer);
            if (! bouton) return;
            await bouton.click();
            await dors(800);
            const vu = await page.evaluate((sels) => {
                const p = document.querySelector(sels.panneau);
                if (! p) return { ouvert: false, texte: '' };
                const b = p.getBoundingClientRect();

                const listeEffets = p.querySelector('[data-rw="cle-panneau-effets"]');

                return {
                    // `offsetParent` vaut `null` pour un element en `position: fixed` :
                    // on mesure la place REELLEMENT occupee.
                    ouvert: ! p.hidden && b.height > 0 && getComputedStyle(p).display !== 'none',
                    texte: (p.innerText || '').replace(/\s+/g, ' ').trim(),
                    // Le panneau ENUMERE ce que le geste fait. C'est cette liste
                    // qui rend la perte lisible, et elle a son ancre propre.
                    effets: listeEffets
                        ? [...listeEffets.querySelectorAll('li')].map((e) => (e.textContent || '').trim())
                        : null,
                };
            }, C);
            constate('panneau de decision', vu.ouvert ? `« ${vu.texte.slice(0, 120)} »` : '(ferme)');
            verifie('le clic OUVRE un panneau de decision', vu.ouvert,
                'le panneau ne s\'affiche pas — un geste de flotte partirait sans etre annonce');
            /*
             * ══ ASSERTER LA PROPRIETE, PAS LE VOCABULAIRE ═════════════════
             *
             * Premiere redaction : `/sans retour|irr[ée]versible|no return/`.
             * Elle a rougi le 2026-09-05 sur un panneau qui dit
             *
             *     « il agit sur la flotte entiere, en une fois, et DETRUIT LA
             *       CLE PRIVEE EN COURS »
             *     « les machines gardent l'ANCIENNE cle publique : apres ce
             *       geste RootWarden ne peut plus s'y connecter par cle »
             *
             * — c'est-a-dire un avertissement PLUS FORT que le mot qu'elle
             * exigeait. **Une assertion qui nomme les MOTS attendus plutot que
             * la PROPRIETE attendue echoue sur une amelioration**, et elle
             * envoie corriger l'ecran qui vient de s'ameliorer.
             *
             * La propriete reelle tient en deux morceaux, et le premier est
             * STRUCTUREL — donc insensible a une reformulation :
             *
             *   1. le panneau ENUMERE les effets du geste (`cle-panneau-effets`),
             *      et l'enumeration n'est pas vide ;
             *   2. le texte nomme une CONSEQUENCE qu'on ne peut pas defaire,
             *      quelle que soit la tournure choisie pour le dire.
             */
            const effets = vu.effets || [];
            verifie('le panneau ENUMERE les effets du geste',
                vu.ouvert && effets.length > 0,
                vu.effets === null
                    ? 'l\'ancre cle-panneau-effets est absente du panneau'
                    : `${effets.length} effet(s) enumere(s)`);

            const PERTE = /d[ée]truit|destruction|supprime|perdue?|definitiv|irr[ée]versible|sans retour|no return|ne peut plus/i;
            verifie('le panneau annonce une PERTE DEFINITIVE, quelle qu\'en soit la tournure',
                vu.ouvert && (PERTE.test(vu.texte) || effets.some((e) => PERTE.test(e))),
                `le panneau ne nomme aucune consequence irrattrapable : « ${vu.texte.slice(0, 90)} »`);
            verifie('AUCUNE requete n\'est partie avant consentement',
                passees.length === avantPassees && avortees.length === avantAvortees,
                `${passees.length - avantPassees} passee(s), ${avortees.length - avantAvortees} avortee(s)`,
                'aucune');

            // ON N'IRA PAS PLUS LOIN. Le panneau se referme par ANNULATION.
            const annuler = await page.$(C.panneauAnnuler);
            if (annuler) { await annuler.click(); await dors(400); }
            constate('suite du geste', 'ANNULE — la reussite de la rotation n\'est mesuree sur aucune cible');
        } else {
            /*
             * SUR LE LEGACY, `regenerateKey()` part au PREMIER clic, derriere un
             * `confirm()` natif. On ne clique donc pas : la propriete se lit
             * dans la STRUCTURE. Regle de S7a — un portail qui declenche au clic
             * ne se teste pas en cliquant.
             */
            const forme = await page.evaluate((sel) => {
                const b = document.querySelector(sel);

                return b ? (b.getAttribute('onclick') || '') : null;
            }, C.lancer);
            constate('cablage du bouton legacy', forme === null ? '(absent)' : `onclick="${forme}"`);
            verifie('le geste de rotation est offert par le legacy', forme !== null, C.lancer);
            constate('pourquoi il n\'est pas clique',
                'NON MESURABLE SANS DETRUIRE : `regenerateKey()` part au premier clic et le geste '
                + 'porte sur la FLOTTE. Aucune cible sure n\'existe — la portee est le parc entier');
            verifie('AUCUNE requete n\'est partie de cette etape',
                passees.length === avantPassees && avortees.length === avantAvortees,
                `${passees.length - avantPassees} passee(s)`, 'aucune');
        }
    });

    // ══ 3b. P1 — L'ECRAN DIT-IL VRAI SUR LES MACHINES SANS RETOUR ? ══════
    await etape('les machines sans retour sont dites, ou leur absence est enoncee', async () => {
        /*
         * LA PROPRIETE NAIVE N'A AUCUN OBJET AUJOURD'HUI, ET C'EST TOUT LE SUJET.
         *
         * « L'ecran nomme les machines qui deviendraient injoignables » se
         * verifierait sur ZERO machine : mesure du 2026-08-28, les trois
         * machines du parc portent un mot de passe, donc `sans_retour` vaut 0.
         * Ecrite ainsi, l'assertion passerait **par absence d'objet** — la forme
         * d'echec la plus couteuse, parce qu'un vert ne se relit pas.
         *
         * On mesure donc la propriete qui ne peut PAS etre creuse : **l'ecran
         * concorde-t-il avec la base ?** Elle a un objet dans les deux cas —
         * nommer quand il y en a, enoncer l'absence quand il n'y en a pas — et
         * elle bascule d'elle-meme au premier effacement de mot de passe, sans
         * qu'on ait a la reecrire.
         *
         * LA LISTE ATTENDUE SE DERIVE, elle ne se code pas. Le predicat est
         * celui du portage (`ClePlateforme.php`) : cle deployee ET aucun mot de
         * passe ET aucun mot de passe root. Coder « srv-zabbix » ici
         * mesurerait mon presse-papier, pas le parc.
         */
        const sansRetour = litEnBase(
            'SELECT name FROM rootwarden.machines WHERE platform_key_deployed = 1 '
            + "AND (password IS NULL OR password = '') "
            + "AND (root_password IS NULL OR root_password = '')");
        constate('machines SANS RETOUR, derivees de la base',
            sansRetour.join(' · ') || '(aucune)');

        const vu = await page.evaluate((sels) => {
            const lire = (s) => {
                const e = document.querySelector(s);

                return e ? (e.innerText || '').replace(/\s+/g, ' ').trim() : null;
            };

            return { nomme: lire(sels.sansRetour), aucune: lire(sels.sansRetourAucune) };
        }, { sansRetour: '[data-rw="cle-rotation-sans-retour"]',
             sansRetourAucune: '[data-rw="cle-rotation-sans-retour-aucune"]' });
        constate('ce que l\'ecran affiche',
            vu.nomme !== null ? `NOMME : « ${vu.nomme.slice(0, 100)} »`
                : vu.aucune !== null ? `ENONCE L'ABSENCE : « ${vu.aucune.slice(0, 100)} »`
                : '(ni l\'un ni l\'autre)');

        if (sansRetour.length > 0) {
            // Le cas qui compte : chaque machine derivee doit etre NOMMEE.
            const manquantes = sansRetour.filter((m) => ! (vu.nomme || '').includes(m));
            verifiePortage('chaque machine sans retour est NOMMEE a l\'ecran',
                vu.nomme !== null && manquantes.length === 0,
                vu.nomme === null
                    ? `${sansRetour.length} machine(s) sans retour et l'ecran n'en nomme AUCUNE`
                    : `absentes de l'ecran : ${manquantes.join(', ')}`);
        } else {
            /*
             * UN COMPTEUR A ZERO S'ENONCE. Ne rien afficher laisserait croire
             * que la question n'a pas ete posee — c'est la difference entre
             * « aucune machine n'est concernee » et « on ne sait pas ».
             */
            verifiePortage('l\'absence de machine sans retour est ENONCEE, pas tue',
                vu.aucune !== null && vu.aucune !== '' && ! /:[a-z_]{3,}/.test(vu.aucune),
                vu.aucune === null
                    ? 'aucun enonce : l\'ecran ne dit pas que le compte vaut zero'
                    : `jeton non substitue : « ${vu.aucune.slice(0, 60)} »`);
            verifiePortage('et l\'ecran ne nomme AUCUNE machine sans retour',
                vu.nomme === null,
                `l'ecran nomme « ${(vu.nomme || '').slice(0, 80)} » alors que la base n'en rend aucune`);
        }
    });

    // ══ 3c. P3 — LE PANNEAU PORTE-T-IL SES FAITS ? ═══════════════════════
    await etape('le panneau de decision porte ses faits', async () => {
        if (! C.panneau) {
            constate('panneau de decision', 'le legacy n\'en a pas — il ouvre un `confirm()` natif');
            verifiePortage('le panneau enumere les effets du geste', false,
                'le legacy tient sa confirmation en une ligne de `confirm()`');

            return;
        }
        const bouton = await page.$(C.lancer);
        if (! bouton) { verifie('le bouton de rotation est atteignable', false, C.lancer); return; }
        await bouton.click();
        await dors(700);
        const vu = await page.evaluate(() => {
            const p = document.querySelector('[data-rw="cle-panneau"]');
            if (! p) return { ouvert: false, effets: [], cibles: '' };
            const b = p.getBoundingClientRect();
            const lis = [...p.querySelectorAll('[data-rw="cle-panneau-effets"] li')]
                .map((e) => (e.innerText || '').trim()).filter(Boolean);
            const c = p.querySelector('[data-rw="cle-panneau-cibles"]');

            return {
                ouvert: ! p.hidden && b.height > 0 && getComputedStyle(p).display !== 'none',
                effets: lis,
                cibles: c ? (c.innerText || '').trim() : '',
            };
        });
        constate('effets enumeres par le panneau', vu.effets.length
            ? vu.effets.map((e) => `« ${e.slice(0, 60)} »`).join(' | ') : '(aucun)');
        constate('cibles nommees par le panneau', vu.cibles || '(aucune)');

        /*
         * LA PROPRIETE INCLUT L'EXISTENCE. « Le panneau ne dit rien de faux » se
         * verifie sur un panneau VIDE : c'est le piege de D9a, ou une aide
         * illisible satisfaisait la propriete qu'elle devait porter. On exige
         * donc que les faits SOIENT LA, puis qu'ils disent quelque chose.
         */
        verifiePortage('le panneau enumere les effets du geste',
            vu.ouvert && vu.effets.length >= 3
                && vu.effets.every((e) => e.length > 0 && ! /:[a-z_]{3,}/.test(e)),
            ! vu.ouvert ? 'le panneau ne s\'ouvre pas'
                : `${vu.effets.length} effet(s) enumere(s) — attendu au moins 3, non vides et sans jeton`);

        const annuler = await page.$(C.panneauAnnuler);
        if (annuler) { await annuler.click(); await dors(400); }
    });

    // ══ 4. L'ENONCE QUE LE PORTAGE AJOUTE ════════════════════════════════
    await etape('CHAQUE panneau de decision porte un titre ET un texte', async () => {
        if (CIBLE !== 'laravel') {
            constate('panneaux de decision', 'SANS OBJET — le legacy ouvre un `confirm()` natif');

            return;
        }
        /*
         * ══ LA CLASSE TROUVEE SUR `fail2ban` F7, CHERCHEE ICI ════════════
         *
         * `ouvre(geste)` lit `(textes.panneaux || {})[geste] || {}` — une cle
         * COMPOSEE A L'EXECUTION. Si le geste n'a pas d'entree, `p` vaut `{}`
         * et le panneau s'ouvre avec un titre VIDE et un texte VIDE. C'est
         * exactement ce qui arrive a `conf_titre_desact` dans fail2ban : la
         * cle existe au catalogue, le controleur ne la transmet pas, et
         * **aucune sonde statique ne peut le voir puisque la cle n'apparait
         * litteralement dans aucun fichier**.
         *
         * L'accord des deux ensembles a ete verifie ici — six gestes offerts,
         * six panneaux au catalogue, aucun manquant. **Mais un accord de cles
         * ne dit rien du RENDU** : la structure imbriquee (`titre`, `texte`)
         * peut manquer pour un geste donne. La seule detection est d'OUVRIR.
         *
         * L'etape voisine n'ouvre que la ROTATION — un geste sur six.
         *
         * ⛔ AUCUNE CONFIRMATION N'EST PRISE. Ces panneaux confirment le
         *    deploiement et la revocation de cles SSH : le filet avorte leurs
         *    routes, et cette etape n'appuie que sur « annuler ».
         */
        const gestes = await page.$$eval('[data-geste]', (ns) => ns.map((n) => ({
            geste: n.dataset.geste,
            desactive: n.disabled === true || n.getAttribute('aria-disabled') === 'true',
            visible: n.offsetParent !== null,
        })));
        constate('gestes offerts', gestes.length
            ? gestes.map((g) => `${g.geste}${g.visible ? '' : ' (masque)'}${g.desactive ? ' (desactive)' : ''}`).join(' · ')
            : '(aucun)');
        if (! gestes.length) {
            verifie('la page offre au moins un geste a mesurer', false,
                'aucun `data-geste` : l\'etape ne mesurerait rien');

            return;
        }

        const vus = new Set();
        for (const g of gestes) {
            if (vus.has(g.geste)) continue;
            vus.add(g.geste);
            if (! g.visible || g.desactive) {
                constate(`panneau « ${g.geste} »`,
                    `SANS OBJET — le bouton est ${g.desactive ? 'desactive' : 'masque'},`
                    + ' le panneau ne peut pas s\'ouvrir depuis cette page');
                continue;
            }
            /*
             * ⚠ CHAQUE GESTE EST INDEPENDANT. Au premier jet, une exception sur
             *   l'un abattait l'etape entiere : `rotation` n'a pas ouvert son
             *   panneau, le clic d'annulation a leve « Node is either not
             *   clickable », et les gestes suivants n'ont jamais ete mesures.
             *   **Une boucle de mesure ne doit pas faire dependre les cas les
             *   uns des autres** — sinon le premier defaut cache tous ceux qui
             *   le suivent.
             */
            let b = null;
            try {
                b = await page.$(`[data-geste="${g.geste}"]`);
                if (b) { await b.evaluate((n) => n.scrollIntoView({ block: 'center' })); await dors(200); }
            } catch { b = null; }
            if (! b) { constate(`panneau « ${g.geste} »`, 'SANS OBJET — bouton introuvable'); continue; }
            try { await b.click(); } catch (e) {
                verifie(`« ${g.geste} » : le bouton est cliquable`, false,
                    String(e.message || e).split('\n')[0]);
                continue;
            }
            await dors(700);
            const vu = await page.evaluate((sel) => {
                const p = document.querySelector(sel.panneau);
                const t = document.querySelector(sel.panneauTitre);
                const x = document.querySelector(sel.panneauTexte);

                return {
                    ouvert: p !== null && p.offsetParent !== null,
                    titre: t ? (t.innerText || '').replace(/\s+/g, ' ').trim() : '',
                    texte: x ? (x.innerText || '').replace(/\s+/g, ' ').trim() : '',
                };
            }, C);
            if (! vu.ouvert) {
                constate(`panneau « ${g.geste} »`, 'NON ouvert — le clic n\'a pas produit de panneau');
            } else {
                constate(`panneau « ${g.geste} »`,
                    `titre ${vu.titre.length} car., texte ${vu.texte.length} car.`);
                /*
                 * UN PANNEAU VIDE FAIT CONSENTIR A UN GESTE QUE RIEN NE NOMME.
                 * On exige les DEUX : un titre sans texte dit quoi sans dire
                 * ce que ça fait, et un texte sans titre l'inverse.
                 */
                verifie(`« ${g.geste} » : le panneau porte un titre ET un texte`,
                    vu.titre.length > 0 && vu.texte.length > 0,
                    `titre « ${vu.titre.slice(0, 40)} » (${vu.titre.length} car.),`
                    + ` texte ${vu.texte.length} car. — cle composee non transmise ?`);
                verifie(`« ${g.geste} » : aucun jeton non substitue`,
                    vu.titre.length > 0 && vu.texte.length > 0
                        && ! /:[a-z_]{3,}/.test(`${vu.titre} ${vu.texte}`),
                    vu.titre.length === 0 || vu.texte.length === 0
                        ? 'panneau vide : rien a verifier, et un vert ici serait une absence'
                        : `${vu.titre} | ${vu.texte}`);
            }
            try {
                const annuler = await page.$(C.panneauAnnuler);
                if (annuler) { await annuler.click(); await dors(400); }
            } catch { /* panneau deja ferme : rien a annuler */ }
        }
        /*
         * ET CE QUI N'EST PAS RENDU EST DIT. `compte_service` et `ressaisir`
         * existent dans la vue mais sous condition : ils ne sont pas dans le
         * DOM a l'etat mesure. **Le taire ferait lire « les six panneaux sont
         * sains » a une mesure qui n'en a vu que quatre.**
         */
        const attendus = ['deployer', 'compte_service', 'effacer', 'revoquer', 'ressaisir', 'rotation'];
        const absents = attendus.filter((x) => ! vus.has(x));
        constate('gestes NON rendus a cet etat',
            absents.length ? `${absents.join(' · ')} — non mesures ici` : 'aucun, les six ont ete vus');
    });

    await etape('le portage dit que le geste n\'est jamais exerce', async () => {
        if (! C.jamais) {
            verifiePortage('la page enonce que la rotation n\'est jamais exercee au banc', false,
                'le legacy ne porte pas cet enonce');

            return;
        }
        const texte = await page.evaluate((sel) => {
            const e = document.querySelector(sel);

            return e ? (e.innerText || '').trim() : '';
        }, C.jamais);
        constate('enonce', texte ? `« ${texte.slice(0, 110)} »` : '(absent)');
        verifiePortage('la page enonce que la rotation n\'est jamais exercee au banc',
            texte !== '' && ! /:[a-z_]{3,}/.test(texte),
            texte === '' ? 'aucun enonce rendu' : `jeton non substitue : « ${texte.slice(0, 60)} »`);
    });

    await etape('aucune erreur JavaScript', async () => {
        verifie('aucune erreur JavaScript sur la page', s.erreursJs.length === 0,
            s.erreursJs.slice(0, 3).join(' | '), 'aucune');
    });

    // ══ 5. CAPTURES ══════════════════════════════════════════════════════
    await etape('captures', async () => {
        const dossier = new URL(`./screenshots/cle-plateforme/${CIBLE}`, import.meta.url).pathname;
        mkdirSync(dossier, { recursive: true });
        for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                         { n: 'mobile', w: 390, h: 844 }]) {
            await page.setViewport({ width: f.w, height: f.h });
            await dors(400);
            await page.screenshot({ path: `${dossier}/p1-${f.n}.png`, fullPage: true });
        }
        verifie('les trois captures sont ecrites', true, '', dossier);
    });
} catch (e) {
    // `__archivee__` n'est pas une panne : c'est la sortie NORMALE quand le
    // sujet legacy a ete archive. Le constat a deja tout dit.
    if (String(e && e.message || e).includes('__archivee__')) { /* rien a ajouter */ } else {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
    }
} finally {
    // ══ SURETE — LE FILET NE SE SUPPOSE PAS, IL SE MESURE ════════════════
    try {
        constate('requetes AVORTEES', avortees.length
            ? avortees.map((a) => `${a.route} (${a.motif})`).join(' | ') : '(aucune)');
        constate('requetes laissees passer', passees.length
            ? passees.map((p) => `${p.methode} ${p.route}`).join(' | ') : '(aucune)');
        constate('boites natives ouvertes', boites.length
            ? boites.map((b) => `${b.type} « ${b.message.slice(0, 60)} »`).join(' | ') : '(aucune)');

        // Un filet qui n'a rien vu passer ne certifie rien : il s'abstient en
        // le disant, plutot que de decerner deux PASS a un controle sans objet.
        if (vues === 0) {
            constate('controle de surete', 'SANS OBJET — aucune requete vue, le filet n\'a rien eu a filtrer');
        } else {
            verifie('AUCUN geste interdit n\'a abouti',
                ! passees.some((p) => estInterdit(p.route, p.methode)),
                passees.filter((p) => estInterdit(p.route, p.methode))
                    .map((p) => `${p.methode} ${p.route}`).join(' '),
                `${passees.length} requete(s) laissee(s) passer`);
            verifie('AUCUNE requete n\'a vise la production',
                ! passees.some((p) => new RegExp(`[?&](machine_id|server_id)=${MACHINE_PRODUCTION}\\b`).test(p.route)),
                'une requete a vise `srv-zabbix`');
        }
    } catch (e) { note(`FAIL  controle de surete : ${e.message}`); echecs += 1; }
    try {
        const zabbix = litEnBase("SELECT CONCAT(name,'|',ip) FROM rootwarden.machines WHERE id = 1");
        verifie('srv-zabbix est intacte', zabbix.length === 1 && /^srv-zabbix\|/.test(zabbix[0]),
            zabbix[0] || '(absente)', zabbix[0] || '');
        // L'ETAT DE DEPLOIEMENT DU PARC : c'est LUI que la rotation remettrait a
        // zero. On le relit pour prouver qu'elle n'a pas eu lieu.
        const deployees = compteEnBase(
            'SELECT COUNT(*) FROM rootwarden.machines WHERE platform_key_deployed = 1');
        verifie('l\'etat de deploiement du parc est intact',
            deployees > 0,
            `${deployees} machine(s) marquee(s) deployee(s) — une rotation les remettrait toutes a 0`,
            `${deployees} machine(s) deployee(s)`);
    } catch (e) { note(`FAIL  controle de l'etat : ${e.message}`); echecs += 1; }
    for (const c of contextes) { try { await c.close(); } catch { /* deja ferme */ } }
    try { await navigateur.close(); } catch { /* deja ferme */ }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
