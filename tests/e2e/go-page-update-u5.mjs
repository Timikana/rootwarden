/**
 * go-page-update-u5.mjs - Module `update/`, sous-lot U5 : le redemarrage.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/update/
 *   laravel  http://localhost:8444/mises-a-jour
 *
 * CE QUE FAIT LA ROUTE, LU DANS `backend/routes/monitoring.py` AVANT TOUT CLIC.
 * `/reboot_server` exige `@require_role(2)` et passe DEUX gardes avant toute
 * session SSH : la fenetre de maintenance (423 dehors) puis l'approbation a
 * quatre yeux (202 avec `pending_approval` et l'identifiant de la demande).
 *
 * LA PORTE NE LAISSE PASSER QUE DANS TROIS CAS : l'action n'est pas soumise a
 * approbation, le demandeur est SUPERADMIN (role 3), ou une demande DEJA
 * APPROUVEE existe — elle est alors consommee et le redemarrage part pour de
 * bon. C'est ce dernier cas qui a envoye deux redemarrages reels sur la machine
 * 2 le 2026-08-18, et leurs traces sont encore dans `command_log`.
 *
 * LE TEST NE JOUE DONC JAMAIS DE REDEMARRAGE :
 *   - il se connecte en `rw-test-admin` (role 2), JAMAIS en role 3 ;
 *   - il VERIFIE d'abord qu'aucune demande approuvee n'attend d'etre consommee,
 *     et s'arrete sans cliquer si ce n'est pas le cas ;
 *   - il compte les traces `command_log` de contexte « reboot » avant et apres :
 *     elles ne s'ecrivent qu'APRES l'execution SSH. Si le nombre n'a pas bouge,
 *     la commande n'est jamais partie. C'est la preuve, par la machine, que
 *     rien n'a redemarre.
 *
 * MACHINE 1 EN PRODUCTION : jamais cochee, jamais designee.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-update-u5.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-update-u5.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { execFileSync } from 'child_process';
import { readFileSync } from 'fs';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/mises-a-jour' : '/update/';

const MACHINE_TEST = 2;
const NOM_TEST = 'Test-Server-Debian';
const UTILISATEUR_ADMIN = 15;

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

const GARDE = readFileSync('reboot-garde.py');

function garde(...args) {
    return execFileSync('docker', ['exec', '-i', 'rootwarden_python', 'python', '-', ...args],
        { input: GARDE, encoding: 'utf-8' }).trim();
}

/** {approuvees, attente, traces} — les trois nombres qui encadrent le geste. */
function etatGardes() {
    const [approuvees, attente, traces] = garde('etat', String(MACHINE_TEST)).split('|').map(Number);
    return { approuvees, attente, traces };
}

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

/** Exigence qui ne vaut que pour le portage ; cote legacy, simple constat. */
function verifiePortage(libelle, ok, detail, __quatrieme) {
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

    if (CIBLE === 'laravel') return verifie(libelle, ok, detail);
    constate(libelle, `non exigible du legacy — ${detail}`);
}

console.log(`\n=== Module update/, sous-lot U5 — redemarrage (${CIBLE}) ===\n`);
constate('cible', `${BASE}${PAGE}`);
constate('ce que fait la route, lu dans backend/routes/monitoring.py',
    'role 2 exige, puis fenetre de maintenance (423) et approbation a quatre yeux (202)');

// ── GARDE-FOU : on ne clique pas si une approbation attend d'etre consommee ──
const avant = etatGardes();
constate('demandes approuvees en attente de consommation', String(avant.approuvees));
constate('traces « reboot » dans command_log avant le test', String(avant.traces));

if (avant.approuvees > 0) {
    console.log(lignes.join('\n'));
    console.log('\nARRET : une demande de redemarrage APPROUVEE existe pour la machine '
        + MACHINE_TEST + '. La porte la consommerait et le redemarrage partirait pour de bon. '
        + 'Aucun clic n\'a ete fait.\n');
    process.exit(1);
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});

/** Messages des boites natives, s'il en apparaît. */
const boites = [];

async function connecte(nom, secret) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);

    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };

    await page.goto(`${BASE}${chemins.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    await page.type('input[name="2fa_code"]', totp(secret), { delay: 8 });
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

/*
 * MODULE ARCHIVE ? Cote legacy, `update/` a ete porte en sept sous-lots puis
 * deplace dans `legacy/_deprecated/`. Ses URL rendent 404 : ce n'est pas un
 * echec, c'est l'aboutissement du portage. Le test le CONSTATE — et verifie
 * surtout que le menu du legacy mene desormais au portage, sans quoi on aurait
 * installe soi-meme un 404 dans un menu.
 *
 * Tant que le module est servi, ce bloc est inerte et la suite se joue.
 */
if (CIBLE === 'legacy') {
    const archivee = await constateArchivage({
        base: BASE,
        chemin: '/update/',
        fichiers: [
        '/update/index.php',
        '/update/js/apiCalls.js',
        '/update/js/domManipulation.js',
        '/update/functions/list_machines.php',
        '/update/functions/filter_servers.php',
        ],
        verifie, constate,
    });
    if (archivee) {
        const { ctx, page } = await connecte('rw-test-admin', SECRET_ADMIN);
        await verifieMenuLegacy(page, '/mises-a-jour', verifie);
        await ctx.close();
        console.log(lignes.join('\n'));
        console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
        await navigateur.close();
        process.exit(echecs > 0 ? 1 : 0);
    }
}

const { ctx, page } = await connecte('rw-test-admin', SECRET_ADMIN);

// Les deux `confirm()` du legacy sont MESURES, puis acceptes : c'est le seul
// moyen de voir ce qu'ils disent vraiment a l'operateur.
page.on('dialog', async (d) => {
    boites.push(d.message());
    await d.accept().catch(() => {});
});

const appels = [];
page.on('request', (r) => {
    if (/reboot_server/.test(r.url())) appels.push({ url: r.url(), corps: r.postData() || '' });
});
const reponses = [];
page.on('response', (r) => {
    if (/reboot_server/.test(r.url())) reponses.push({ statut: r.status() });
});

await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });

const nbLignes = await (async () => {
    const limite = Date.now() + 30000;
    let n = 0;
    while (Date.now() < limite && n === 0) {
        n = await page.evaluate(() =>
            document.querySelectorAll('#server-table-body tr[data-machine-id]').length);
        if (!n) await dors(400);
    }
    return n;
})();
verifie('le parc est rendu', nbLignes > 0, `${nbLignes} ligne(s)`);

// Repartir d'un etat connu : aucune case cochee, puis la machine 2 SEULE.
await page.evaluate(() => {
    for (const c of document.querySelectorAll('input[name="selected_machines[]"]')) c.checked = false;
});

const SEL_REDEMARRER = '[data-rw="redemarrer"], button[onclick="rebootSelected()"]';
const bouton = await page.$(SEL_REDEMARRER);
verifie("l'action « redemarrer » est presente", Boolean(bouton));

// ── Sans machine cochee : rien ne part ──────────────────────────────────────
const avantVide = appels.length;
await bouton.evaluate(b => b.click());
await dors(1200);
verifie("sans machine cochee, aucun appel n'est emis",
    appels.length === avantVide, `${appels.length - avantVide} appel(s)`);

// ── Machine 2 seule ─────────────────────────────────────────────────────────
await page.evaluate((id) => {
    const c = document.querySelector(`input[name="selected_machines[]"][value="${id}"]`);
    c.checked = true;
    c.dispatchEvent(new Event('change', { bubbles: true }));
}, MACHINE_TEST);

await bouton.evaluate(b => b.click());
await dors(800);

// Cote portage : le panneau de decision s'ouvre, le bouton naît DESACTIVE.
const panneau = await page.evaluate(() => {
    const p = document.querySelector('[data-rw="panneau-redemarrage"]');
    if (!p) return null;
    const confirmer = p.querySelector('[data-rw="redemarrage-confirmer"]');
    return {
        // Le RENDU, pas l'attribut : `.rw-panneau-decision { display: flex }`
        // a longtemps battu `[hidden]`, et lire `p.hidden` declarait cache un
        // panneau qui restait a l'ecran.
        visible: p.getClientRects().length > 0,
        attributCache: p.hidden,
        machines: p.querySelector('[data-rw="redemarrage-machines"]')?.textContent.trim() || '',
        approbation: p.querySelector('[data-rw="redemarrage-approbation"]')?.textContent.trim() || '',
        consigne: p.querySelector('[data-rw="redemarrage-consigne"]')?.textContent.trim() || '',
        delais: [...(p.querySelector('[data-rw="redemarrage-delai"]')?.options || [])].map(o => o.value),
        desactive: confirmer ? confirmer.disabled : null,
    };
});

verifiePortage('la decision s\'ouvre en ligne, sans boite native',
    Boolean(panneau) && panneau.visible && boites.length === 0,
    `${boites.length} boite(s) native(s)`);
verifiePortage('le panneau NOMME la machine concernee',
    Boolean(panneau) && panneau.machines.includes(NOM_TEST), panneau ? `« ${panneau.machines} »` : 'aucun panneau de decision');
verifiePortage('la regle des quatre yeux est dite AVANT le geste',
    Boolean(panneau) && /second administrateur|second administrator/i.test(panneau.approbation),
    panneau ? `« ${panneau.approbation.slice(0, 60)}... »` : 'aucun panneau de decision');
verifiePortage('le bouton de confirmation naît desactive',
    panneau?.desactive === true, panneau ? `desactive : ${panneau.desactive}` : 'aucun panneau de decision');
verifiePortage('le delai que le backend accepte est offert',
    Boolean(panneau) && panneau.delais.length > 1 && panneau.delais.includes('60'),
    panneau ? `choix : ${panneau.delais.join(', ')} minutes` : 'aucun panneau de decision');

// Le panneau doit REPARTIR D'UN ETAT CONNU a chaque ouverture. Le nombre a
// recopier est bien remis a vide, mais le DELAI ne l'etait pas : choisi pour une
// machine, il survivait a la fermeture et repartait avec la suivante. Le geste
// delibere porte sur le NOMBRE, pas sur le delai — personne ne relit un champ
// qu'il n'a pas touche, et `shutdown -r +60` part alors a la place du
// redemarrage immediat attendu.
if (CIBLE === 'laravel' && panneau) {
    await page.evaluate(() => {
        const champ = document.querySelector('[data-rw="redemarrage-delai"]');
        champ.value = '60';
        champ.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await page.evaluate(() =>
        document.querySelector('[data-rw="redemarrage-annuler"]').click());
    await dors(300);

    // Retablir la selection : fermer le panneau re-rend le tableau et decoche.
    await page.evaluate((id) => {
        const c = document.querySelector(`input[name="selected_machines[]"][value="${id}"]`);
        if (!c) return;
        c.checked = true;
        c.dispatchEvent(new Event('change', { bubbles: true }));
    }, MACHINE_TEST);
    await page.evaluate(() =>
        document.getElementById('reboot-btn').click());
    await dors(500);

    const delaiRouvert = await page.evaluate(() =>
        document.querySelector('[data-rw="redemarrage-delai"]')?.value ?? null);
    verifie('le delai repart de son defaut a la reouverture du panneau',
        delaiRouvert === '0', `delai relu : « ${delaiRouvert} » minute(s)`);
}

if (CIBLE === 'legacy') {
    // Les deux confirmations du legacy : ce qu'elles DISENT vraiment.
    constate('boites natives posees', String(boites.length));
    boites.forEach((m, i) => constate(`boite ${i + 1}`, `« ${m.slice(0, 90)} »`));
    verifie('le legacy pose bien deux confirmations natives', boites.length === 2,
        `${boites.length} boite(s)`);
}

// ── Confirmer ───────────────────────────────────────────────────────────────
if (CIBLE === 'laravel') {
    // Recopier un nombre FAUX ne doit pas activer le bouton.
    await page.evaluate(() => {
        const champ = document.querySelector('[data-rw="redemarrage-nombre"]');
        champ.value = '2';
        champ.dispatchEvent(new Event('input', { bubbles: true }));
    });
    const apresFaux = await page.evaluate(() =>
        document.querySelector('[data-rw="redemarrage-confirmer"]').disabled);
    verifie('un nombre qui ne correspond pas laisse le bouton desactive',
        apresFaux === true, 'une machine retenue, « 2 » saisi');

    await page.evaluate(() => {
        const champ = document.querySelector('[data-rw="redemarrage-nombre"]');
        champ.value = '1';
        champ.dispatchEvent(new Event('input', { bubbles: true }));
    });
    const apresJuste = await page.evaluate(() =>
        document.querySelector('[data-rw="redemarrage-confirmer"]').disabled);
    verifie('le bon nombre active le bouton', apresJuste === false, '« 1 » saisi');

    const avantAppel = reponses.length;
    await page.evaluate(() =>
        document.querySelector('[data-rw="redemarrage-confirmer"]').click());
    const limite = Date.now() + 60000;
    while (Date.now() < limite && reponses.length === avantAppel) await dors(300);
}

// Attendre LA REPONSE de la route, sur les deux cibles.
const limiteReponse = Date.now() + 60000;
while (Date.now() < limiteReponse && reponses.length === 0) await dors(300);

verifie('la route de redemarrage a bien ete appelee', reponses.length > 0,
    `${reponses.length} reponse(s)`);
constate('statut rendu', reponses.length ? String(reponses[0].statut) : 'aucun');

verifie("la reponse est une demande d'approbation, pas un redemarrage",
    reponses[0]?.statut === 202, `statut ${reponses[0]?.statut} (202 attendu)`);

// ── LA PREUVE : rien n'a redemarre ──────────────────────────────────────────
const apres = etatGardes();
verifie('aucune trace de redemarrage ne s\'est ajoutee',
    apres.traces === avant.traces,
    `command_log contexte « reboot » : ${avant.traces} avant, ${apres.traces} apres`);

// Le nettoyage de fin laisse toujours zero demande en attente : l'increment est
// donc exigible. S'il ne se produit pas, c'est que l'etat de depart n'etait pas
// propre — et je veux le savoir plutot que de l'absorber dans un « ou bien ».
verifie("une demande d'approbation est desormais en attente",
    apres.attente === avant.attente + 1,
    `${avant.attente} avant, ${apres.attente} apres`);

verifie('la machine 1, en production, n\'est jamais designee',
    !appels.some(a => /"machine_id"\s*:\s*1\b/.test(a.corps)),
    `${appels.length} appel(s) inspecte(s)`);

// Sous quel NOM le journal range-t-il la ligne ? Le legacy lit
// `document.getElementById('server-' + id)` pour retrouver le nom du serveur ;
// cet element n'existe pas dans la page — seul `#server-table-body` existe — et
// le nom retombe donc sur « #<id> ».
const panneauxNommes = await page.evaluate(() =>
    [...document.querySelectorAll('#logs-container [data-server-name]')]
        .map(el => el.getAttribute('data-server-name')));
constate('panneaux du journal apres la demande',
    panneauxNommes.length ? panneauxNommes.join(', ') : 'aucun');
verifiePortage('le journal range la ligne sous le NOM de la machine',
    panneauxNommes.includes(NOM_TEST),
    `panneaux : ${panneauxNommes.join(', ') || 'aucun'}`);

// Le portage annonce la demande pour ce qu'elle est, pas comme une erreur.
const trace = await page.evaluate((nom) => {
    const conteneur = document.getElementById('logs-container');
    if (!conteneur) return { texte: '', erreurs: 0 };
    for (const el of conteneur.querySelectorAll('[data-server-name]')) {
        if (el.getAttribute('data-server-name') === nom) {
            return {
                texte: el.innerText,
                erreurs: el.querySelectorAll('.log-line.error').length,
            };
        }
    }
    return { texte: '', erreurs: 0 };
}, NOM_TEST);
verifiePortage("la demande creee n'est pas annoncee comme une erreur",
    /approbation|approval/i.test(trace.texte) && trace.erreurs === 0,
    `${trace.erreurs} ligne(s) en erreur dans le panneau`);

await ctx.close();
await navigateur.close();

// ── Nettoyage : effacer la demande creee, si elle est encore en attente ─────
const derniere = garde('derniere-demande', String(MACHINE_TEST), String(UTILISATEUR_ADMIN));
const [idDemande, statutDemande] = derniere.split('|');
if (statutDemande === 'pending') {
    constate('nettoyage', `demande #${idDemande} ${garde('oublie-demande', idDemande)}`);
} else {
    constate('nettoyage', `derniere demande #${idDemande} au statut ${statutDemande}, laissee intacte`);
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL\n`);
process.exit(echecs ? 1 : 0);
