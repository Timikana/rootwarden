/**
 * go-page-update-u1.mjs - Module `update/`, sous-lot U1 : parc et filtres.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/update/
 *   laravel  http://localhost:8444/mises-a-jour
 *
 * PERIMETRE U1 — LECTURE SEULE. Le tableau du parc, ses filtres, son
 * rafraichissement, et les trois relevés par machine (version Linux, statut,
 * dernier redemarrage). Les mises a jour, la planification et le redemarrage
 * appartiennent a U3..U6 : ce test n'y touche pas, et le decoupage est dans
 * `docs/migration/MODULE-UPDATE.md`.
 *
 * CE QUE LE TEST CHERCHE : le rafraichissement de la liste PERD des colonnes.
 * `populateMachineTable()` lit `maj_secu_date`, `maj_secu_last_exec_date` et
 * `last_reboot` ; `update/functions/list_machines.php` ne les SELECTionne pas.
 * Rafraichir remplace donc trois colonnes renseignees par « N/A », sans qu'on
 * l'ait demande et sans rien annoncer.
 *
 * MACHINE 1 EN PRODUCTION : jamais selectionnee. Les relevés par machine
 * ouvrent une session SSH — ils sont sans effet, mais ils touchent la machine.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-update-u1.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-update-u1.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/mises-a-jour' : '/update/';

const COMPTES = {
    'rw-test-user':  { role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW', attendu: 'refuse' },
    // Role 2 AVEC can_update_linux : autorise.
    'rw-test-admin': { role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX', attendu: 'autorise' },
    'rw-test-super': { role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW', attendu: 'autorise' },
};

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
function verifie(libelle, ok, detail) {
    lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${libelle}${detail ? '  — ' + detail : ''}`);
    if (!ok) echecs++;
}
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }

function verifiePortage(libelle, ok, detail) {
    if (CIBLE === 'laravel') return verifie(libelle, ok, detail);
    constate(libelle, `non exigible du legacy — ${detail}`);
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 90000,
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

/**
 * Etat du tableau tel qu'il est RENDU.
 *
 * Les colonnes sont lues par leur CLASSE (`linux-version`, `maj-secu-date`...),
 * comme le legacy les pose. Le portage garde ces classes : c'est ce qui permet
 * a un seul test de viser les deux cibles.
 */
async function releve(page) {
    return page.evaluate(() => {
        const corps = document.getElementById('server-table-body');
        const lignes = corps ? [...corps.querySelectorAll('tr')] : [];
        const t = (el) => (el?.textContent || '').trim();
        const parLigne = (tr) => ({
            id: tr.getAttribute('data-machine-id'),
            nom: t(tr.querySelector('.server-name')),
            version: t(tr.querySelector('.linux-version')),
            controle: t(tr.querySelector('.last-checked')),
            statut: t(tr.querySelector('.online-status')),
            majSecu: t(tr.querySelector('.maj-secu-date')),
            majSecuExec: t(tr.querySelector('.maj-secu-lastexec-date')),
            redemarrage: t(tr.querySelector('.last-reboot')),
            environnement: t(tr.querySelector('.environment')),
            criticite: t(tr.querySelector('.criticality')),
            reseau: t(tr.querySelector('.network-type')),
        });
        return {
            titre: t(document.querySelector('h1')),
            colonnes: [...document.querySelectorAll('thead th')].length,
            filtres: {
                environnement: Boolean(document.getElementById('environment')),
                criticite: Boolean(document.getElementById('criticality')),
                reseau: Boolean(document.getElementById('network-type')),
            },
            nbLignes: lignes.length,
            machines: lignes.map(parLigne),
            texteEntier: document.body.innerText,
        };
    });
}

async function attendJusqua(page, predicat, maxMs = 25000) {
    const limite = Date.now() + maxMs;
    let dernier = await releve(page);
    while (Date.now() < limite && ! predicat(dernier)) {
        await dors(350);
        dernier = await releve(page);
    }
    return dernier;
}

/** Colonnes renseignees, c'est-a-dire ni vides ni « N/A » ni « non verifie ». */
function renseignee(valeur) {
    const v = (valeur || '').trim();
    return v !== '' && !/^N\/A$/i.test(v) && !/non v[ée]rifi|not check/i.test(v);
}

try {
    // ── La garde reelle, avec les trois comptes ─────────────────────────────
    for (const [nom, compte] of Object.entries(COMPTES)) {
        const { ctx, page } = await connecte(nom);
        const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
        const statut = rep?.status() ?? 0;
        const affichee = statut === 200
            && ! /connexion|login\.php/i.test(page.url())
            && await page.evaluate(() => Boolean(document.getElementById('server-table-body')));

        verifie(`${nom} (role ${compte.role}) : ${compte.attendu === 'autorise' ? "la page s'affiche" : 'la page est refusee'}`,
                compte.attendu === 'autorise' ? affichee : ! affichee,
                `statut=${statut} url=${page.url().replace(BASE, '')}`);
        await ctx.close();
        await dors(1200);
    }

    /*
     * LE CLOISONNEMENT DU ROLE 1 N'EST PAS EXERCABLE. La page admet le role 1
     * s'il porte `can_update_linux`, et ne lui montre alors que les machines de
     * `user_machine_access`. Aucun compte de test ne cumule les deux, et en
     * fabriquer un reviendrait a changer des droits.
     */
    constate('cloisonnement du role 1',
             'non exercable — aucun compte de test ne cumule role 1 et can_update_linux');

    // ── Le contenu, avec le compte ROLE 2 ───────────────────────────────────
    await dors((resteFenetre() + 1) * 1000);
    const { ctx, page } = await connecte('rw-test-admin');
    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await attendJusqua(page, (e) => e.nbLignes > 0);

    const depart = await releve(page);

    verifie('la page porte un titre', depart.titre.length > 0, depart.titre);
    verifie('le tableau a treize colonnes', depart.colonnes === 13, `${depart.colonnes}`);
    verifie('les trois filtres sont presents',
            depart.filtres.environnement && depart.filtres.criticite && depart.filtres.reseau,
            JSON.stringify(depart.filtres));
    verifie('aucune cle de traduction morte a l\'ecran',
            ! /\b(updates|upd|nav|auth|accueil|profil|passerelle)\.[a-z_]{3,}\b/.test(depart.texteEntier));

    constate('machines listees', depart.machines.map(m => m.nom).join(', ') || 'aucune');
    verifie('le parc est liste', depart.nbLignes > 0, `${depart.nbLignes} machine(s)`);

    // Les colonnes qui viennent de la base doivent etre renseignees au depart.
    constate('environnements', depart.machines.map(m => m.environnement).join(', '));
    constate('criticites', depart.machines.map(m => m.criticite).join(', '));
    verifie('environnement et criticite sont renseignes au chargement',
            depart.machines.every(m => m.environnement && m.criticite),
            depart.machines.map(m => `${m.nom}:${m.environnement}/${m.criticite}`).join(' · '));

    // ── LE FILTRE REDUIT, ET NE MENT PAS ────────────────────────────────────
    const envPresents = [...new Set(depart.machines.map(m => m.environnement).filter(Boolean))];
    constate('environnements distincts au parc', envPresents.join(', ') || 'aucun');

    if (envPresents.length > 1) {
        const cible = envPresents[0];
        await page.select('#environment', cible);
        await page.evaluate(() => {
            const b = [...document.querySelectorAll('button')].find(x => /filtr/i.test(x.textContent));
            if (b) b.click();
        });
        const filtre = await attendJusqua(page, (e) => e.nbLignes < depart.nbLignes || e.nbLignes === 0);

        constate(`apres filtre « ${cible} »`, `${filtre.nbLignes} ligne(s)`);
        verifie(`le filtre « ${cible} » ne garde que cet environnement`,
                filtre.machines.every(m => m.environnement === cible),
                filtre.machines.map(m => m.environnement).join(', ') || 'aucune ligne');
    } else {
        constate('filtre par environnement',
                 `non discriminant — les ${depart.nbLignes} machines partagent « ${envPresents[0] || '?'} »`);
    }

    /*
     * ── LE RAFRAICHISSEMENT PERD-IL DES COLONNES ? ─────────────────────────
     *
     * `populateMachineTable()` lit `maj_secu_date`, `maj_secu_last_exec_date` et
     * `last_reboot`. L'endpoint que le legacy interroge — `list_machines.php` —
     * ne les SELECTionne pas : elles retombent a « N/A ». Le portage passe par
     * `/filter_servers`, qui rend les quatorze colonnes.
     *
     * On mesure ce qui etait renseigne AVANT, et ce qui l'est encore APRES.
     */
    const avantRafraichi = await releve(page);
    const remplies = (etat) => ({
        majSecu: etat.machines.filter(m => renseignee(m.majSecu)).length,
        majSecuExec: etat.machines.filter(m => renseignee(m.majSecuExec)).length,
        redemarrage: etat.machines.filter(m => renseignee(m.redemarrage)).length,
        environnement: etat.machines.filter(m => renseignee(m.environnement)).length,
    });
    const avant = remplies(avantRafraichi);
    constate('colonnes renseignees avant rafraichissement', JSON.stringify(avant));

    const clique = await page.evaluate(() => {
        const b = [...document.querySelectorAll('button')]
            .find(x => /rafra|refresh|actualis/i.test(x.textContent));
        if (b) { b.click(); return b.textContent.trim().slice(0, 40); }
        return null;
    });
    constate('bouton de rafraichissement', clique || 'introuvable');

    if (clique) {
        // Attendre que la liste ait ete RELUE : le tableau est reconstruit, donc
        // ses lignes changent d'identite meme quand leur texte est identique.
        await dors(2500);
        const apres = remplies(await releve(page));
        constate('colonnes renseignees apres rafraichissement', JSON.stringify(apres));

        const perdues = Object.keys(avant).filter(k => apres[k] < avant[k]);
        if (perdues.length) {
            constate('COLONNES PERDUES', perdues.join(', '));
        }

        verifiePortage('le rafraichissement ne perd aucune colonne',
                       perdues.length === 0,
                       perdues.length ? `perdues : ${perdues.join(', ')}` : 'aucune perte');

        if (CIBLE === 'legacy' && perdues.length) {
            constate('defaut du legacy',
                     `rafraichir la liste vide ${perdues.join(', ')} — `
                     + 'list_machines.php ne SELECTionne pas ces colonnes');
        }
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
