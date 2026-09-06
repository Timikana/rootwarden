/**
 * go-page-approvals.mjs - Workflow d'approbation a quatre yeux.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/approvals/
 *   laravel  http://localhost:8444/approbations
 *
 * Cette page MUTE : approuver ou rejeter change l'etat d'une demande. Le test
 * en profite pour verifier en direct — il rejette une demande reelle et
 * controle qu'elle change d'onglet. Les demandes utilisees portent sur la
 * machine 2 et sur une cible inoffensive.
 *
 * LIMITE ASSUMEE. La regle « on n'approuve pas sa propre demande » n'est PAS
 * exercable avec les comptes actuels : le demandeur est `rw-test-admin`
 * (role 2), qui n'a pas `can_admin_portal` et ne peut donc pas ouvrir cette
 * page. Il faudrait un compte role 2 AVEC cette permission. Aucun droit n'a
 * ete modifie pour forcer le test : la limite est ecrite plutot que masquee.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-approvals.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-approvals.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/approbations' : '/approvals/';

const COMPTES = {
    'rw-test-user':  { role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW', attendu: 'refuse' },
    'rw-test-admin': { role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX', attendu: 'refuse' },
    'rw-test-super': { role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW', attendu: 'autorise' },
};

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
function verifie(libelle, ok, detail, __quatrieme) {
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

    lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${libelle}${detail ? '  — ' + detail : ''}`);
    if (!ok) echecs++;
}
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 60000,
});

async function connecte(nom) {
    const compte = COMPTES[nom];
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);

    /*
     * Le legacy demande la raison par `prompt()` et confirme par `confirm()`.
     * Une boite native BLOQUE Puppeteer et laisse le bouton de souris enfonce
     * si on ne la traite pas : on repond systematiquement.
     */
    page.on('dialog', d => {
        if (d.type() === 'prompt') d.accept('rejet de test automatise').catch(() => {});
        else d.accept().catch(() => {});
    });

    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };

    await page.goto(`${BASE}${chemins.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    await page.type('input[name="2fa_code"]', totp(compte.secret), { delay: 8 });
    nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (chemins.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$('[data-rw="cgu-accepter"]') || await page.$('button[name="accept_terms"]');
        if (b) await b.evaluate(x => x.click());
        try { await nav; } catch {}
    }

    return { ctx, page };
}

/** Etat de la page tel qu'il est RENDU. */
async function releve(page) {
    return page.evaluate(() => {
        const corps = document.getElementById('appr-tbody');
        const toutes = corps ? [...corps.querySelectorAll('tr')] : [];
        const donnees = toutes.filter(tr => tr.querySelectorAll('td').length > 1);
        return {
            titre: (document.querySelector('h1')?.textContent || '').trim(),
            onglets: [...document.querySelectorAll('.appr-tab')].map(b => b.dataset.status),
            colonnes: [...document.querySelectorAll('thead th')].length,
            nbLignes: donnees.length,
            actions: donnees.map(tr => (tr.querySelectorAll('td')[0]?.textContent || '').trim()),
            statuts: donnees.map(tr => (tr.querySelectorAll('td')[4]?.textContent || '').trim()),
            boutons: donnees.reduce((n, tr) => n + tr.querySelectorAll('button').length, 0),
            texteCorps: (corps?.textContent || '').trim().slice(0, 120),
            texteEntier: document.body.innerText,
        };
    });
}

/**
 * Attend que le tableau CESSE DE BOUGER, au lieu de dormir un temps fixe.
 *
 * Une attente fixe de 1,5 s a fait lire l'ancien onglet et rapporter deux faux
 * echecs : le rejet avait bien eu lieu cote backend, mais la mesure regardait
 * un rendu perime. Une mesure qui depend d'un delai devine ; celle-ci observe.
 */
async function attendStabilite(page, maxMs = 12000) {
    const empreinte = () => page.evaluate(() =>
        (document.getElementById('appr-tbody')?.textContent || '').replace(/\s+/g, ' ').trim());

    const depart = await empreinte();
    const limite = Date.now() + maxMs;

    // 1. Attendre un CHANGEMENT. La stabilite seule ne suffit pas : un
    //    « Chargement… » qui dure est parfaitement stable, et le prendre pour
    //    un resultat fait lire un tableau vide.
    let courante = depart;
    while (Date.now() < limite && courante === depart) {
        await dors(200);
        courante = await empreinte();
    }

    // 2. Puis attendre que ca cesse de bouger.
    let precedente = courante;
    let stables = 0;
    while (Date.now() < limite) {
        await dors(250);
        courante = await empreinte();
        stables = courante === precedente ? stables + 1 : 0;
        precedente = courante;
        if (stables >= 3) return;   // ~750 ms sans changement
    }
}

/** Clique un onglet et attend que le tableau ait fini de se rendre. */
async function ongletVers(page, statut) {
    await page.evaluate((s) => {
        const b = [...document.querySelectorAll('.appr-tab')].find(x => x.dataset.status === s);
        if (b) b.click();
    }, statut);
    await attendStabilite(page);
}

/**
 * Produit les demandes sur lesquelles le test va decider.
 *
 * La premiere version de ce test travaillait sur des demandes creees A LA MAIN
 * avant lui. Il rejetait la derniere en attente a chaque execution, si bien
 * qu'apres quelques passages la file etait vide et le test rapportait un echec
 * — non pas parce que la page etait cassee, mais parce qu'il avait consomme
 * ses propres donnees. Un test qui depend d'un etat qu'il detruit ne peut etre
 * joue qu'une fois.
 *
 * Il produit donc lui-meme ses demandes, avec le compte qui en produit
 * legitimement : `rw-test-admin`, role 2. Les cibles sont des comptes
 * INEXISTANTS sur la machine 2 — la demande est bloquee par l'approbation, et
 * meme approuvee elle ne supprimerait rien. Le nom porte l'horodatage : le
 * backend refuse une demande identique deja en attente.
 *
 * Ne tourne QUE sur Laravel. Sonder le legacy avec des requetes mutantes
 * invalide sa session et detruit le contexte d'execution.
 */
async function produitDemandes(page, combien) {
    const marque = Date.now().toString(36);
    const resultats = [];
    for (let i = 0; i < combien; i++) {
        resultats.push(await page.evaluate(async (cible) => {
            const jeton = document.querySelector('meta[name="csrf-token"]')?.content || '';
            const r = await fetch('/api/gateway/delete_remote_user', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': jeton,
                           'X-Requested-With': 'XMLHttpRequest' },
                body: JSON.stringify({ machine_id: 2, username: cible, remove_home: false }),
            });
            let corps = null;
            try { corps = await r.json(); } catch (e) {}
            return { statut: r.status, attente: Boolean(corps && corps.pending_approval) };
        }, `absent-${marque}-${i}`));
    }
    return resultats;
}

try {
    /*
     * PARTIE ARCHIVEE ? Cote legacy, la page a ete portee puis deplacee dans
     * `legacy/_deprecated/`. Elle rend 404 : ce n'est pas un echec, c'est
     * l'aboutissement du portage. Le test le CONSTATE — et verifie surtout que
     * l'entree de menu du legacy mene desormais au portage, sans quoi on aurait
     * installe soi-meme un 404 dans un menu.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: '/approvals/', fichiers: ['/approvals/index.php', '/approvals/js/main.js'], verifie, constate,
        });
        if (archivee) {
            const { ctx, page } = await connecte('rw-test-super');
            await verifieMenuLegacy(page, '/approbations', verifie, constate);
            await ctx.close();
            console.log(lignes.join('\n'));
            console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — partie archivee`);
            await navigateur.close();
            process.exit(echecs > 0 ? 1 : 0);
        }
    }
    // ── La garde reelle, avec les trois comptes ─────────────────────────────
    for (const [nom, compte] of Object.entries(COMPTES)) {
        const { ctx, page } = await connecte(nom);
        const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
        const statut = rep?.status() ?? 0;
        const affichee = statut === 200
            && ! /connexion|login\.php/i.test(page.url())
            && await page.evaluate(() => Boolean(document.getElementById('appr-tbody')));

        verifie(`${nom} (role ${compte.role}) : ${compte.attendu === 'autorise' ? "la page s'affiche" : 'la page est refusee'}`,
                compte.attendu === 'autorise' ? affichee : ! affichee,
                `statut=${statut} url=${page.url().replace(BASE, '')}`);

        // Le compte role 2 est refuse sur la PAGE, mais c'est bien lui qui
        // produit les demandes : on profite de sa session pour en creer.
        if (nom === 'rw-test-admin' && CIBLE === 'laravel') {
            const creees = await produitDemandes(page, 2);
            constate('demandes produites pour ce passage',
                     creees.map(r => `${r.statut}${r.attente ? ' en attente' : ''}`).join(', '));
            verifie('les actions destructrices passent par une approbation',
                    creees.every(r => r.attente),
                    creees.map(r => r.statut).join(', '));
        }

        await ctx.close();
        await dors(1200);
    }

    // ── Le contenu ──────────────────────────────────────────────────────────
    await dors((resteFenetre() + 1) * 1000);
    const { ctx, page } = await connecte('rw-test-super');
    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await attendStabilite(page);

    const attente = await releve(page);
    verifie('la page porte un titre', attente.titre.length > 0, attente.titre);
    verifie('les quatre onglets sont presents',
            ['pending', 'approved', 'rejected', 'all'].every(s => attente.onglets.includes(s)),
            attente.onglets.join(', '));
    verifie('le tableau a six colonnes', attente.colonnes === 6, String(attente.colonnes));
    verifie('aucune cle de traduction morte a l\'ecran',
            ! /\b(appr|nav|auth|accueil|profil|passerelle|cmdlog)\.[a-z_]{3,}\b/.test(attente.texteEntier));

    constate('demandes en attente', `${attente.nbLignes} — ${attente.actions.join(', ') || 'aucune'}`);
    verifie('des demandes reelles sont affichees', attente.nbLignes > 0,
            attente.nbLignes === 0 ? attente.texteCorps : `${attente.nbLignes}`);
    verifie('chaque demande en attente porte des boutons de decision',
            attente.boutons >= attente.nbLignes, `${attente.boutons} bouton(s) pour ${attente.nbLignes} ligne(s)`);

    // ── Un onglet vide dit qu'il est vide ───────────────────────────────────
    await ongletVers(page, 'rejected');
    const rejeteesAvant = await releve(page);
    constate('onglet « rejetees » avant action', `${rejeteesAvant.nbLignes} ligne(s)`);

    // ── VERIFICATION EN DIRECT : on rejette une demande reelle ──────────────
    await ongletVers(page, 'pending');
    const avant = await releve(page);
    if (avant.nbLignes > 0) {
        // On vise la demande de suppression de compte : sa cible est un compte
        // inexistant, donc sans consequence quelle que soit l'issue.
        const clique = await page.evaluate(() => {
            const lignes = [...document.querySelectorAll('#appr-tbody tr')]
                .filter(tr => tr.querySelectorAll('td').length > 1);
            const cible = lignes.find(tr => /delete_remote_user/.test(tr.textContent)) || lignes[0];
            const boutons = [...cible.querySelectorAll('button')];
            // Le bouton de rejet est le dernier des deux.
            const rejet = boutons[boutons.length - 1];
            if (!rejet) return null;
            const action = (cible.querySelectorAll('td')[0]?.textContent || '').trim();
            rejet.click();
            return action;
        });
        await dors(900);

        /*
         * Le portage remplace `confirm()`/`prompt()` par une confirmation EN
         * LIGNE dans la ligne concernee. Le test reste le meme pour les deux
         * cibles : s'il existe un controle de confirmation, on le renseigne et
         * on le valide ; sinon la boite native a deja ete acceptee par le
         * gestionnaire de dialogues.
         */
        const confirmation = await page.$('[data-rw="rejet-confirmer"]');
        if (confirmation) {
            const motif = await page.$('[data-rw="rejet-motif"]');
            if (motif) await motif.type('rejet de test automatise', { delay: 5 });
            await confirmation.evaluate(b => b.click());
            constate('confirmation du rejet', 'panneau en ligne (portage)');
        } else {
            constate('confirmation du rejet', 'boite native (legacy)');
        }
        await attendStabilite(page);

        const apres = await releve(page);
        constate('demande rejetee', clique || 'aucune');
        verifie('apres rejet, la demande quitte l\'onglet « en attente »',
                apres.nbLignes === avant.nbLignes - 1,
                `${avant.nbLignes} -> ${apres.nbLignes}`);

        await ongletVers(page, 'rejected');
        const rejeteesApres = await releve(page);
        verifie('et se retrouve dans l\'onglet « rejetees »',
                rejeteesApres.nbLignes === rejeteesAvant.nbLignes + 1,
                `${rejeteesAvant.nbLignes} -> ${rejeteesApres.nbLignes}`);
    } else {
        constate('rejet en direct', 'aucune demande en attente, non verifie');
    }

    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
