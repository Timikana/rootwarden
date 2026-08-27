/**
 * go-page-drift.mjs - Detection de derive de configuration.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/drift/
 *   laravel  http://localhost:8444/derive-config
 *
 * PREMIERE PAGE OU LA PERMISSION DISCRIMINE VRAIMENT. Les deux pages portees
 * jusqu'ici exigeaient `can_admin_portal`, que seul le superadministrateur
 * possede parmi les comptes de test : la garde ne se distinguait pas d'une
 * garde par role. Celle-ci exige `can_view_compliance`, que `rw-test-admin`
 * porte — le compte role 2 est donc AUTORISE ici et refuse ailleurs. C'est la
 * seule configuration qui prouve qu'une permission est lue, et non devinee
 * depuis le role.
 *
 * Ce que le test verifie :
 *   - la garde reelle, avec les trois comptes ;
 *   - le resume (quatre tuiles) et le tableau (six colonnes) ;
 *   - une ligne par machine du parc, avec ses trois pastilles de categorie ;
 *   - le tri : les machines en derive remontent en tete ;
 *   - un RE-SCAN REEL de la machine 2, dont l'horodatage doit avancer ;
 *   - un SCAN GLOBAL, et la coherence du resume avec le tableau ;
 *   - l'absence de cle de traduction morte a l'ecran.
 *
 * SUR LA MACHINE DE PRODUCTION. Le scan global couvre tout le parc, machine 1
 * comprise. Il ne la TOUCHE PAS : `/drift/scan_all` ne fait aucun appel SSH,
 * il recalcule depuis des donnees deja en base et ecrit dans `config_drift`.
 * Verifie dans `backend/routes/drift.py` avant d'ecrire ce test — cliquer un
 * bouton dont on n'a pas lu l'effet sur un parc de production ne se fait pas.
 *
 * Les identifiants d'element sont ceux du legacy (`drift-summary`,
 * `drift-tbody`, `scan-all-btn`) : le MEME test vise les deux cibles.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-drift.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-drift.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/derive-config' : '/drift/';

const COMPTES = {
    'rw-test-user':  { role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW', attendu: 'refuse' },
    // Role 2 AVEC can_view_compliance : autorise. C'est tout l'interet.
    'rw-test-admin': { role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX', attendu: 'autorise' },
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
    page.on('dialog', d => d.dismiss().catch(() => {}));

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
        const corps = document.getElementById('drift-tbody');
        const toutes = corps ? [...corps.querySelectorAll('tr')] : [];
        const donnees = toutes.filter(tr => tr.querySelectorAll('td').length > 1);
        const resume = document.getElementById('drift-summary');
        return {
            titre: (document.querySelector('h1')?.textContent || '').trim(),
            boutonScanTout: Boolean(document.getElementById('scan-all-btn')),
            tuiles: resume ? resume.children.length : 0,
            chiffresResume: resume
                ? [...resume.children].map(c => (c.textContent.match(/\d+/) || ['?'])[0])
                : [],
            colonnes: [...document.querySelectorAll('thead th')].length,
            nbLignes: donnees.length,
            noms: donnees.map(tr => (tr.querySelectorAll('td')[0]?.textContent || '').trim()),
            // Une pastille par categorie : sudo, sshd, fail2ban.
            pastillesParLigne: donnees.map(tr =>
                [1, 2, 3].filter(i => (tr.querySelectorAll('td')[i]?.textContent || '').trim().length > 0).length),
            etats: donnees.map(tr => [1, 2, 3]
                .map(i => (tr.querySelectorAll('td')[i]?.textContent || '').trim()).join('/')),
            dernierScan: donnees.map(tr => (tr.querySelectorAll('td')[4]?.textContent || '').trim()),
            boutonsRescan: donnees.reduce((n, tr) => n + tr.querySelectorAll('button').length, 0),
            texteCorps: (corps?.textContent || '').trim().slice(0, 120),
            texteEntier: document.body.innerText,
        };
    });
}

/**
 * Attend un CHANGEMENT puis la STABILITE. Jamais une duree fixe : une attente
 * fixe tient tant que le parc est petit, puis lit le rendu precedent des qu'il
 * grossit, et le test accuse alors la page d'un defaut qui est le sien.
 */
async function attendRendu(page, maxMs = 15000) {
    const empreinte = () => page.evaluate(() =>
        ((document.getElementById('drift-tbody')?.textContent || '') +
         (document.getElementById('drift-summary')?.textContent || '')).replace(/\s+/g, ' ').trim());

    const depart = await empreinte();
    const limite = Date.now() + maxMs;

    let courante = depart;
    while (Date.now() < limite && courante === depart) {
        await dors(200);
        courante = await empreinte();
    }

    let precedente = courante;
    let stables = 0;
    while (Date.now() < limite) {
        await dors(250);
        courante = await empreinte();
        stables = courante === precedente ? stables + 1 : 0;
        precedente = courante;
        if (stables >= 3) return;
    }
}

/**
 * Attend que le RELEVE satisfasse la condition qu'on va asserter.
 *
 * L'attente de stabilite ne suffit pas ici : pendant que le scan tourne, le
 * bouton affiche « Scan en cours » et le tableau ne bouge PLUS DU TOUT. Une
 * sonde qui attend le calme le trouve tout de suite, lit les horodatages
 * d'avant, et rapporte que le scan n'a rien fait — alors que la requete a
 * abouti et que la base a bien ete ecrite. Attendre la condition elle-meme,
 * avec une limite, ne peut pas se tromper de cette facon.
 */
async function attendJusqua(page, predicat, maxMs = 25000) {
    const limite = Date.now() + maxMs;
    let dernier = await releve(page);
    while (Date.now() < limite && ! predicat(dernier)) {
        await dors(300);
        dernier = await releve(page);
    }
    return dernier;
}

/** Ce que la page ANNONCE apres une action. Le legacy n'annonce rien de durable. */
async function annonce(page) {
    return page.evaluate(() =>
        (document.querySelector('[data-rw="annonce"]')?.textContent || '').trim());
}

/**
 * Convertit un horodatage AFFICHE en secondes comparables.
 *
 * Les deux cibles rendent la date par `toLocaleString()` : « 18/08/2026
 * 13:04:23 ». Comparer ces chaines a l'ordre alphabetique classerait le
 * 18 janvier apres le 17 decembre. On extrait donc les six nombres.
 * Rend `null` si la lecture echoue — auquel cas l'appelant doit le DIRE et
 * non conclure.
 */
function enSecondes(texte) {
    const n = String(texte || '').match(/\d+/g);
    if (!n || n.length < 6) return null;
    const [j, mois, a, h, mi, sec] = n.map(Number);
    return Date.UTC(a, mois - 1, j, h, mi, sec) / 1000;
}

try {
    /*
     * PARTIE ARCHIVEE ? Voir `archive.mjs` : une page portee puis deplacee
     * rend 404, ce qui n'est pas un echec mais l'aboutissement du portage.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: '/drift/',
            fichiers: ['/drift/index.php', '/drift/js/main.js'], verifie, constate,
        });
        if (archivee) {
            const { ctx, page } = await connecte('rw-test-super');
            await verifieMenuLegacy(page, '/derive-config', verifie);
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
        const url = page.url();
        const corps = await page.evaluate(() => document.body.innerText.slice(0, 200));

        const affichee = statut === 200
            && ! /connexion|login\.php/i.test(url)
            && Boolean(await page.$('#drift-tbody'));

        if (compte.attendu === 'autorise') {
            verifie(`${nom} (role ${compte.role}) voit la page`, affichee,
                    affichee ? `HTTP ${statut}` : `HTTP ${statut} · ${url} · ${corps.slice(0, 80)}`);
        } else {
            verifie(`${nom} (role ${compte.role}) est refuse`, ! affichee,
                    `HTTP ${statut} · ${corps.slice(0, 60).replace(/\s+/g, ' ')}`);
        }

        await ctx.close();
        await dors(1200);
    }

    /*
     * Le contenu, avec le compte ROLE 2. Deliberement : c'est lui qui prouve
     * que la permission est lue. Un releve fait en superadministrateur ne
     * distinguerait pas `can_view_compliance` d'un simple role 3.
     */
    await dors((resteFenetre() + 1) * 1000);
    const { ctx, page } = await connecte('rw-test-admin');
    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await attendRendu(page);

    const etat = await releve(page);

    verifie('la page porte un titre', etat.titre.length > 0, etat.titre);
    verifie('le bouton de scan global est present', etat.boutonScanTout);
    verifie('le resume compte quatre tuiles', etat.tuiles === 4, `${etat.tuiles} tuile(s)`);
    verifie('le tableau a six colonnes', etat.colonnes === 6, `${etat.colonnes} colonne(s)`);
    verifie('aucune cle de traduction morte a l\'ecran',
            ! /\b(drift|nav|auth|accueil|profil|passerelle)\.[a-z_]{3,}\b/.test(etat.texteEntier));

    constate('machines listees', etat.noms.join(', ') || 'aucune');
    constate('resume', etat.chiffresResume.join(' / '));
    constate('etats par machine', etat.etats.join(' | '));

    verifie('le parc est liste', etat.nbLignes > 0,
            etat.nbLignes === 0 ? etat.texteCorps : `${etat.nbLignes} machine(s)`);
    verifie('chaque ligne porte ses trois categories',
            etat.pastillesParLigne.every(n => n === 3),
            etat.pastillesParLigne.join(', '));
    verifie('chaque ligne offre un re-scan',
            etat.boutonsRescan === etat.nbLignes,
            `${etat.boutonsRescan} bouton(s) pour ${etat.nbLignes} ligne(s)`);

    // ── Le resume DIT LA VERITE sur le tableau ──────────────────────────────
    // Le nombre de serveurs annonce doit etre celui des lignes rendues : une
    // tuile qui compte autre chose que ce qu'on voit est pire qu'une absence.
    verifie('la tuile « serveurs » compte les lignes rendues',
            Number(etat.chiffresResume[0]) === etat.nbLignes,
            `${etat.chiffresResume[0]} annonce(s) pour ${etat.nbLignes} ligne(s)`);
    verifie('conformes + en derive = total',
            Number(etat.chiffresResume[1]) + Number(etat.chiffresResume[2]) === etat.nbLignes,
            `${etat.chiffresResume[1]} + ${etat.chiffresResume[2]} vs ${etat.nbLignes}`);

    // ── Le tri fait remonter ce qui demande une action ──────────────────────
    const derivee = etat.etats.map(e => (e.match(/D[eé]rive|Drift/gi) || []).length);
    const trie = derivee.every((n, i) => i === 0 || derivee[i - 1] >= n);
    if (new Set(derivee).size > 1) {
        verifie('les machines en derive remontent en tete', trie, derivee.join(' >= '));
    } else {
        // Toutes les machines portent le MEME nombre d'ecarts : n'importe quel
        // ordre satisferait l'attente. La declarer verte serait une assertion
        // creuse, qui occuperait la place d'une vraie.
        constate("tri par nombre d'ecarts",
                 `non discriminant — les ${derivee.length} machines en portent ${derivee[0]} chacune`);
    }

    // ── RE-SCAN REEL de la machine 2 ────────────────────────────────────────
    const indice = etat.noms.findIndex(n => /Test-Server-Debian/i.test(n));
    if (indice >= 0) {
        const avant = etat.dernierScan[indice];
        constate('dernier scan avant', `${etat.noms[indice]} : ${avant}`);

        await page.evaluate((i) => {
            const tr = [...document.querySelectorAll('#drift-tbody tr')]
                .filter(x => x.querySelectorAll('td').length > 1)[i];
            tr.querySelector('button').scrollIntoView({ block: 'center' });
            tr.querySelector('button').click();
        }, indice);
        const apres = await attendJusqua(page, (e) => {
            const k = e.noms.findIndex(n => /Test-Server-Debian/i.test(n));
            return k >= 0 && e.dernierScan[k] !== avant;
        });

        const j = apres.noms.findIndex(n => /Test-Server-Debian/i.test(n));
        const dit = await annonce(page);
        if (dit) constate('la page annonce', dit);
        constate('dernier scan apres', `${apres.noms[j]} : ${apres.dernierScan[j]}`);
        verifie('le re-scan avance l\'horodatage de la machine visee',
                j >= 0 && apres.dernierScan[j] !== avant,
                `« ${avant} » -> « ${apres.dernierScan[j]} »`);
        verifie('le re-scan ne change pas le nombre de machines',
                apres.nbLignes === etat.nbLignes,
                `${etat.nbLignes} -> ${apres.nbLignes}`);
    } else {
        constate('re-scan', 'Test-Server-Debian absente du parc, non verifie');
    }

    // ── SCAN GLOBAL ─────────────────────────────────────────────────────────
    // Sans appel SSH : recalcul depuis la base, machine de production comprise.
    const avantGlobal = await releve(page);
    await page.evaluate(() => document.getElementById('scan-all-btn').click());
    // Le scan global reecrit l'horodatage de TOUTES les machines : on attend
    // que le tableau le montre, pas qu'il se taise.
    // Meme condition que l'attente que l'assertion posera : attendre autre
    // chose ferait patienter 25 s pour rien quand une machine vient d'etre
    // re-scannee dans la meme seconde.
    const plusRecentAvant = Math.max(...avantGlobal.dernierScan.map(enSecondes).map(v => v ?? 0));
    const apresGlobal = await attendJusqua(page, (e) => {
        const v = e.dernierScan.map(enSecondes);
        return v.length === avantGlobal.dernierScan.length
            && v.every(x => x !== null && x >= plusRecentAvant)
            && v.some(x => x > plusRecentAvant - 1);
    });
    const ditGlobal = await annonce(page);
    if (ditGlobal) constate('la page annonce', ditGlobal);

    constate('resume apres scan global', apresGlobal.chiffresResume.join(' / '));
    verifie('le scan global conserve le parc',
            apresGlobal.nbLignes === avantGlobal.nbLignes,
            `${avantGlobal.nbLignes} -> ${apresGlobal.nbLignes}`);
    verifie('le scan global laisse un resume coherent',
            Number(apresGlobal.chiffresResume[1]) + Number(apresGlobal.chiffresResume[2]) === apresGlobal.nbLignes,
            apresGlobal.chiffresResume.join(' / '));
    /*
     * Le scan global a-t-il vraiment touche TOUT le parc ?
     *
     * « chaque horodatage a change » etait trop strict : une machine
     * re-scannee la seconde d'avant affiche la meme valeur, et le test
     * mesurait alors la resolution de l'horloge, pas le scan. La propriete
     * juste est que le PLUS ANCIEN horodatage d'apres ne soit pas anterieur au
     * PLUS RECENT d'avant : aucune machine n'a ete oubliee.
     */
    const avantSec = avantGlobal.dernierScan.map(enSecondes);
    const apresSec = apresGlobal.dernierScan.map(enSecondes);
    if (avantSec.every(v => v !== null) && apresSec.every(v => v !== null)) {
        verifie('le scan global ne laisse aucune machine en arriere',
                Math.min(...apresSec) >= Math.max(...avantSec),
                `plus ancien apres ${apresGlobal.dernierScan[apresSec.indexOf(Math.min(...apresSec))]}`
                + ` vs plus recent avant ${avantGlobal.dernierScan[avantSec.indexOf(Math.max(...avantSec))]}`);
    } else {
        constate('scan global', 'horodatages illisibles, couverture non verifiee');
    }
    verifie('le bouton de scan global redevient utilisable',
            await page.evaluate(() => ! document.getElementById('scan-all-btn').disabled));

    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
