/**
 * go-bashrc-b4.mjs - Sous-lot B4 de `bashrc/` : les ECRITURES DISTANTES.
 *
 *   POST /bashrc/prerequisites   `apt-get install -y figlet`, en root — MODIFIE
 *   POST /bashrc/deploy          ecrit `.bashrc` sur les comptes — MODIFIE
 *   POST /bashrc/restore         restaure la derniere sauvegarde — MODIFIE
 *
 * Plus le DEPLOIEMENT MULTI-MACHINES, qui n'est pas une route : c'est une boucle
 * cote client qui emet un `/bashrc/deploy` PAR MACHINE COCHEE.
 *
 * ══ SURETE : TOUT EST AVORTE, SANS EXCEPTION ═════════════════════════════
 *
 * **Aucune de ces requetes ne quitte le navigateur.** Le filet est pose avant
 * toute navigation et n'a aucune branche qui laisse passer.
 *
 * Y COMPRIS LA SIMULATION. `dry_run: true` emprunte la MEME route que le
 * deploiement reel, et sa sureté ne tient qu'a un booleen dans le corps
 * (`routes/bashrc.py:505` : `if dry_run: … continue`, avant toute ecriture).
 * Laisser passer une requete sur la foi d'un champ de son propre corps
 * reviendrait a faire confiance a ce qu'on est en train de mesurer. Le cout est
 * faible — B2 a deja mesure les lectures — et le risque, lui, est un
 * deploiement reel.
 *
 * ══ CE QUI N'EST PAS MESURE AU NAVIGATEUR, ET POURQUOI ═══════════════════
 *
 * La propriete qui compte le plus est : **une machine de PRODUCTION cochee
 * serait-elle deployee ?** La mesurer exigerait de cocher `srv-zabbix`. Le filet
 * l'avorterait — mais un trou dans le filet, du cote « laisse passer », ferait
 * partir un deploiement reel sur la production. Deux filets de cette session ont
 * eu des trous.
 *
 * **La reponse est donc LUE, pas mesuree**, et elle est nette :
 *
 *     function _bashrcSelectedMachines() {
 *         return Array.from(document.querySelectorAll('.machine-chk:checked'))
 *             .map(c => ({id: parseInt(c.value, 10), …}));
 *     }
 *
 * Aucun filtre. La boucle du multi-deploiement envoie un `/bashrc/deploy` par
 * entree. Cocher `srv-zabbix` enverrait `machine_id: 1`.
 *
 * Ce que la suite mesure, c'est le MECANISME — une requete par machine cochee —
 * sur les machines 2 et 3, jamais la 1.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-bashrc-b4
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { constateArchivage } from './archive.mjs';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';

/** `Test-Server-Debian`. La 1 est `srv-zabbix`, PRODUCTION : jamais cochee. */
const MACHINE_ID = 2;
/** `OpenCVE-Test-OnPrem`. Seconde machine du multi-deploiement, hors production. */
const MACHINE_SECONDE = 3;
const MACHINE_PRODUCTION = 1;

/** Tout ce qui ECRIT. Le filet n'a aucune branche qui laisse passer. */
const ECRITURES = /\/bashrc\/(prerequisites|deploy|restore)(\?|$)/;
/** Les lectures de B2 : elles peuvent aboutir, la page en a besoin pour s'afficher. */
const LECTURES = /\/bashrc\/(users|preview|template)(\?|$)/;

const DOSSIER_CAPTURES = new URL('./screenshots/bashrc', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/bashrc',
        machine: (id) => `[data-rw="bashrc-cible-${id}"]`,
        compte: '[data-rw^="bashrc-compte-"]',
        deployer: '[data-rw="bashrc-deployer"]',
        simuler: '[data-rw="bashrc-simuler"]',
        deployerMulti: '[data-rw="bashrc-deployer-multi"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/bashrc/',
        machine: (id) => `.machine-chk[value="${id}"]`,
        compte: '#users-table-container input[type="checkbox"]',
        deployer: '#btn-deploy',
        simuler: '#btn-dryrun',
        deployerMulti: '#btn-multi-deploy',
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
function verifie(l, ok, d, toujours) {
    const suffixe = toujours || (! ok && d) || '';
    note(`${ok ? 'PASS' : 'FAIL'}  ${l}${suffixe ? '  — ' + suffixe : ''}`);
    if (! ok) echecs += 1;
}
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
    constate(l, ok ? 'verifie sur le legacy aussi' : `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});
const contextes = [];
/** Chaque ecriture avortee, avec sa machine et son corps. */
const avortees = [];
const boites = [];

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(60000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => {
        boites.push({ type: d.type(), texte: (d.message() || '').replace(/\s+/g, ' ').slice(0, 160) });
        // ACCEPTER : on veut voir ce que le geste ENVERRAIT. La requete qui suit
        // est avortee par le filet, donc rien n'atteint la machine.
        try { await d.accept(); } catch {}
    });

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        const url = r.url();
        if (ECRITURES.test(url)) {
            let corps = '';
            try { corps = (r.postData() || '').slice(0, 220); } catch { corps = '(illisible)'; }
            const m = /"machine_id"\s*:\s*(\d+)/.exec(corps);
            avortees.push({
                route: url.replace(/^https?:\/\/[^/]+/, '').replace(/^\/api(_proxy\.php|\/gateway)/, ''),
                machine: m ? Number(m[1]) : null,
                simulation: /"dry_run"\s*:\s*true/.test(corps),
                corps,
            });
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

    return { ctx, page, erreursJs, surConnexion: /connexion|login\.php/.test(page.url()) };
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

/** Cocher une machine par SA VALEUR, jamais « la premiere case ». */
async function coche(page, id) {
    const c = await page.$(C.machine(id));
    if (c) { await c.click(); await dors(1500); }

    return c !== null;
}

/*
 * LA BORNE D'ENTREE — une FENETRE attrape ce que les autres font, un DELTA non.
 *
 * Cette suite comptait les journaux `[bashrc]` des « quinze dernieres minutes ».
 * Jouee SEULE elle est verte ; jouee dans le LOT elle ECHOUE — parce que
 * `go-bashrc-b3` la precede immediatement dans `SUITES_LEGACY` et enregistre un
 * gabarit (`save_template`) une minute avant. **L'assertion accusait donc b4 du
 * geste legitime de sa suite soeur**, et le referait a CHAQUE lot complet.
 *
 * Ce qui a tranche n'est pas le libelle mais l'HORODATAGE : la ligne portait
 * `user_id = 16` et une heure ANTERIEURE au demarrage de b4. Meme famille que
 * « un nettoyage qui supprime par TYPE en retire plus qu'il n'en a pose » : on
 * borne par ce qu'on a soi-meme produit, jamais par une duree.
 */
const JOURNAUX_A_L_ENTREE = compteEnBase(
    "SELECT COUNT(*) FROM rootwarden.user_logs WHERE action LIKE '[bashrc]%'");

try {
    const s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = s;
    verifie('la session a tenu', ! s.surConnexion, page.url());

    /*
     * ══ LE SUJET DE CETTE SUITE N'EXISTE PLUS COTE LEGACY ═════════════════
     *
     * `bashrc/` a ete archive. Une suite de parite dont la moitie legacy a
     * disparu ne doit pas ECHOUER : un rouge permanent finit par ne plus etre
     * lu, et il occupe la place ou l'on aurait cherche une vraie regression.
     * Elle CONSTATE, et la moitie portage continue de s'exercer.
     *
     * ⚠ ET LE CONSTAT EXIGE UN 404, PAS UNE ABSENCE DE PAGE. Le 2026-09-05,
     * ces sept repertoires rendaient 403 : le `git mv` avait emporte les `.php`
     * et laisse le JavaScript, si bien que le dossier existait encore et que
     * `/bashrc/js/bashrc.js` repondait 200 avec 27 Kio. `constateArchivage`
     * traite tout statut != 404 comme « encore servie » et rend `false` — le
     * constat aurait donc ete FAUX et la suite rouge quand meme. L'archivage a
     * ete acheve (`7588e71`) avant que cette ligne soit ecrite.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: C.page, fichiers: [], verifie, constate,
        });
        if (archivee) throw new Error('__archivee__');
    }

    // ══ 1. UN DEPLOIEMENT SUR UNE MACHINE ═════════════════════════════════
    await etape('deployer : ce qui partirait, et ce qui est demande avant', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('la machine d\'essai est cochable', await coche(page, MACHINE_ID));
        await dors(12000);

        const comptes = await page.$$(C.compte);
        // La premiere case du tableau est « Tout » cote legacy : on vise un
        // compte par sa VALEUR (piege paye en B2).
        const cible = await page.evaluateHandle((sel) => {
            return [...document.querySelectorAll(sel)].find((c) => c.value && c.value !== 'on') || null;
        }, C.compte);
        const elt = cible.asElement();
        verifie('un compte est cochable', elt !== null, `${comptes.length} case(s) lues`);
        if (elt) { await elt.click(); await dors(400); }

        const avantB = boites.length;
        const avantR = avortees.length;
        const bouton = await page.$(C.deployer);
        verifie('le bouton de deploiement est atteignable', bouton !== null);
        if (! bouton) return;
        await bouton.click();
        await dors(3000);

        const demandees = boites.slice(avantB);
        const parties = avortees.slice(avantR);
        constate('confirmations avant le deploiement', demandees.length
            ? demandees.map((b) => `${b.type} : ${b.texte.slice(0, 90)}`).join(' | ') : '(aucune)');
        for (const r of parties) {
            constate('  AVORTEE', `${r.route} · machine ${r.machine} · ${r.simulation ? 'SIMULATION' : 'REEL'} · ${r.corps.slice(0, 120)}`);
        }

        // LA PROPRIETE : ce geste ecrit sur une machine, il doit demander avant.
        verifie('le deploiement demande confirmation', demandees.length > 0,
            'aucune confirmation avant une ecriture distante');
        // ET LA CONFIRMATION NOMME LES COMPTES VISES. « Confirmer ? » sans dire
        // sur quoi ne permet pas de decider.
        verifiePortage('la confirmation nomme ce sur quoi elle porte',
            demandees.some((b) => /root|testuser|compte/i.test(b.texte)),
            demandees.map((b) => b.texte.slice(0, 70)).join(' | ') || '(aucune)');
    });

    // ══ 2. LA SIMULATION EMPRUNTE LA MEME ROUTE ═══════════════════════════
    await etape('la simulation et le deploiement reel se distinguent-ils ?', async () => {
        const avantR = avortees.length;
        const bouton = await page.$(C.simuler);
        verifie('le bouton de simulation est atteignable', bouton !== null);
        if (! bouton) return;
        await bouton.click();
        await dors(3000);

        const parties = avortees.slice(avantR);
        for (const r of parties) {
            constate('  AVORTEE', `${r.route} · ${r.simulation ? 'SIMULATION' : 'REEL'}`);
        }
        const memeRoute = parties.length > 0
            && parties.every((r) => /\/bashrc\/deploy/.test(r.route));
        constate('la simulation emprunte-t-elle /bashrc/deploy ?', memeRoute ? 'OUI' : 'non');
        verifie('la simulation part bien en simulation',
            parties.length > 0 && parties.every((r) => r.simulation),
            parties.map((r) => r.corps.slice(0, 80)).join(' | '));

        // CE QUE CELA VEUT DIRE, et c'est un CONSTAT et non un reproche : la
        // sureté d'une simulation ne tient qu'a UN BOOLEEN dans le corps. Le
        // backend l'honore (`if dry_run: … continue` avant toute ecriture), mais
        // une simulation et un deploiement reel sont, sur le reseau, la MEME
        // requete a un champ pres.
        constate('sureté de la simulation',
            memeRoute ? 'repose sur le seul champ `dry_run` du corps' : 'route distincte');
    });

    // ══ 3. LE MULTI-DEPLOIEMENT : UNE REQUETE PAR MACHINE ═════════════════
    await etape('le multi-deploiement emet une requete par machine cochee', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        await coche(page, MACHINE_ID);
        await coche(page, MACHINE_SECONDE);
        await dors(2000);

        const avantR = avortees.length;
        const avantB = boites.length;
        const bouton = await page.$(C.deployerMulti);
        verifie('le bouton multi-machines est atteignable', bouton !== null);
        if (! bouton) return;
        await bouton.click();
        await dors(6000);

        const parties = avortees.slice(avantR);
        const machines = [...new Set(parties.map((r) => r.machine).filter((m) => m !== null))];
        constate('machines visees par le multi-deploiement', machines.join(', ') || '(aucune)');
        constate('confirmations avant le multi-deploiement', boites.slice(avantB).length
            ? boites.slice(avantB).map((b) => b.texte.slice(0, 110)).join(' | ') : '(aucune)');

        verifie('une requete part par machine cochee', machines.length === 2,
            `${machines.length} machine(s) visee(s) pour 2 cochees`);
        // LA PROPRIETE QUI COMPTE : la production n'est JAMAIS visee. Elle n'a
        // pas ete cochee — l'assertion verifie qu'aucun chemin detourne ne l'a
        // ajoutee.
        verifie('la production n\'est visee par aucune requete',
            ! machines.includes(MACHINE_PRODUCTION), `machines : ${machines.join(', ')}`);
        // ET LA CONFIRMATION ENUMERE LES MACHINES : decider d'un geste
        // multi-machines sans savoir lesquelles n'a pas de sens.
        verifiePortage('la confirmation multi-machines enumere les machines',
            boites.slice(avantB).some((b) => /Test-Server|OpenCVE/i.test(b.texte)),
            boites.slice(avantB).map((b) => b.texte.slice(0, 80)).join(' | ') || '(aucune)');
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await dors(400);
            await page.screenshot({ path: `${dossier}/bashrc-b4-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    // LES `Failed to fetch` VIENNENT DU FILET, PAS DE LA PAGE.
    //
    // Avorter une requete produit une erreur reseau dans la page, et cette
    // erreur est indiscernable d'un defaut de la page. En B1 le probleme etait
    // evitable — la route avortee a tort etait une simple lecture, et la laisser
    // passer a suffi. **Ici il ne l'est pas** : ce sont precisement les
    // ecritures qu'on doit avorter.
    //
    // On le DECLARE donc, plutot que de faire echouer une assertion sur un
    // defaut qu'on a soi-meme cause. Le compte est rapporte tel quel.
    const causeesParLeFilet = erreursJs.filter((e) => /Failed to fetch|blocked/i.test(e)).length;
    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    constate('dont causees par l\'avortement du filet', `${causeesParLeFilet} sur ${erreursJs.length}`);
    verifiePortage('aucune erreur JavaScript etrangere a l\'avortement',
        erreursJs.length === causeesParLeFilet,
        erreursJs.filter((e) => ! /Failed to fetch|blocked/i.test(e)).slice(0, 2).join(' | '));

} catch (e) {
    // `__archivee__` n'est pas une panne : c'est la sortie NORMALE quand le
    // sujet legacy a ete archive. Le constat a deja tout dit.
    if (! String(e.message || e).includes('__archivee__')) {
        verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
    }
} finally {
    try {
        constate('total des ecritures avortees', String(avortees.length));
        verifie('aucune ecriture n\'a atteint une machine', true, '',
            `${avortees.length} avortee(s)`);
        verifie('AUCUNE requete n\'a vise la production',
            avortees.every((r) => r.machine !== MACHINE_PRODUCTION),
            avortees.filter((r) => r.machine === MACHINE_PRODUCTION).map((r) => r.route).join(' · '));
    } catch (e) { note(`FAIL  controle des requetes : ${e.message}`); echecs += 1; }
    try {
        const journauxFin = compteEnBase(
            "SELECT COUNT(*) FROM rootwarden.user_logs WHERE action LIKE '[bashrc]%'");
        const produits = journauxFin - JOURNAUX_A_L_ENTREE;
        constate('journaux `[bashrc]` produits PAR CETTE SUITE',
            `${produits} (entree ${JOURNAUX_A_L_ENTREE}, sortie ${journauxFin})`);
        verifie('la suite n\'a produit aucun geste journalise', produits === 0,
            `${produits} ligne(s) ecrite(s) pendant cette suite`,
            `${produits} ligne(s)`);
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
