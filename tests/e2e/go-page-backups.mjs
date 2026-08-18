/**
 * go-page-backups.mjs - Sauvegardes de la base : liste, creation, verification.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/backups/
 *   laravel  http://localhost:8444/sauvegardes
 *
 * CE QUE CE TEST NE FAIT PAS : il ne RESTAURE jamais. `/admin/backups/restore`
 * fait un DROP TABLE sur la base PARTAGEE par le legacy, par Laravel et par le
 * backend Python. Une suite qui la restaure en pleine execution detruirait les
 * sessions et les donnees des autres suites. Le test verifie donc que la
 * restauration EXISTE, qu'elle est reservee au superadministrateur, et qu'un
 * nom de fichier errone ne la declenche pas — sans jamais la mener a bien.
 *
 * Ce qu'il fait pour de vrai, en revanche :
 *   - il CREE une sauvegarde (le repertoire est vide au depart, un test sur une
 *     liste vide ne prouverait rien) ;
 *   - il VERIFIE celle qu'il vient de creer.
 *
 * Il mesure aussi une propriete qui n'est pas dans la page : la permission
 * `can_admin_portal` garde-t-elle la CAPACITE ou seulement la PAGE ? Le backend
 * ne demande que le role 2 sur `/admin/backups` — c'est un releve, pas une
 * correction.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-backups.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-backups.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/sauvegardes' : '/backups/';

const COMPTES = {
    'rw-test-user':  { role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW', attendu: 'refuse' },
    'rw-test-admin': { role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX', attendu: 'refuse' },
    'rw-test-super': { role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW', attendu: 'autorise' },
};

const NOM_ATTENDU = /^rootwarden_backup_\d{8}_\d{6}\.sql\.gz$/;

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

/** Attente propre a une cible : le legacy n'a pas ce que le portage ajoute. */
function verifiePortage(libelle, ok, detail) {
    if (CIBLE === 'laravel') return verifie(libelle, ok, detail);
    constate(libelle, `non exigible du legacy — ${detail}`);
}

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
    // Le legacy demande le nom du fichier par `prompt()`. Le refuser annule la
    // restauration : c'est exactement ce qu'on veut, et cela evite qu'une boite
    // native bloque le pilotage.
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
        const corps = document.getElementById('backup-tbody');
        const toutes = corps ? [...corps.querySelectorAll('tr')] : [];
        const donnees = toutes.filter(tr => tr.querySelectorAll('td').length > 1);
        const texte = (el) => (el?.textContent || '').trim();
        return {
            titre: texte(document.querySelector('h1')),
            boutonCreer: Boolean(document.getElementById('create-btn')),
            colonnes: [...document.querySelectorAll('thead th')].length,
            nbLignes: donnees.length,
            fichiers: donnees.map(tr => texte(tr.querySelectorAll('td')[0])),
            tailles: donnees.map(tr => texte(tr.querySelectorAll('td')[1])),
            boutons: donnees.map(tr => [...tr.querySelectorAll('button')].map(b => texte(b))),
            texteCorps: texte(corps).slice(0, 160),
            texteEntier: document.body.innerText,
        };
    });
}

/**
 * Attend que le RELEVE satisfasse la condition qu'on va asserter.
 *
 * Pendant une creation, le bouton est desactive et le tableau ne bouge pas :
 * attendre le calme le trouverait tout de suite et lirait l'etat d'avant.
 */
async function attendJusqua(page, predicat, maxMs = 40000) {
    const limite = Date.now() + maxMs;
    let dernier = await releve(page);
    while (Date.now() < limite && ! predicat(dernier)) {
        await dors(400);
        dernier = await releve(page);
    }
    return dernier;
}

/** Ce que la page ANNONCE. Le legacy n'annonce rien de durable. */
async function annonce(page) {
    return page.evaluate(() =>
        (document.querySelector('[data-rw="annonce"]')?.textContent || '').trim());
}

try {
    /*
     * PARTIE ARCHIVEE ? Voir `archive.mjs` : une page portee puis deplacee rend
     * 404, ce qui n'est pas un echec mais l'aboutissement du portage.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: '/backups/',
            fichiers: ['/backups/index.php', '/backups/js/main.js'], verifie, constate,
        });
        if (archivee) {
            const { ctx, page } = await connecte('rw-test-super');
            await verifieMenuLegacy(page, '/sauvegardes', verifie);
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
            && await page.evaluate(() => Boolean(document.getElementById('backup-tbody')));

        verifie(`${nom} (role ${compte.role}) : ${compte.attendu === 'autorise' ? "la page s'affiche" : 'la page est refusee'}`,
                compte.attendu === 'autorise' ? affichee : ! affichee,
                `statut=${statut} url=${page.url().replace(BASE, '')}`);

        /*
         * LA PERMISSION GARDE-T-ELLE LA PAGE, OU LA CAPACITE ?
         *
         * La page exige `can_admin_portal`. Le backend, lui, ne demande que le
         * role 2 sur `/admin/backups` — et la passerelle applique la meme regle.
         * `rw-test-admin` est donc refuse sur la page tout en pouvant lister les
         * sauvegardes par l'API. C'est un RELEVE : le corriger changerait des
         * droits, ce qui ne se fait pas au detour d'un portage.
         *
         * Requete en LECTURE seule, cote Laravel uniquement.
         */
        if (nom === 'rw-test-admin' && CIBLE === 'laravel') {
            const parApi = await page.evaluate(async () => {
                const r = await fetch('/api/gateway/admin/backups', {
                    credentials: 'same-origin',
                    headers: { 'X-Requested-With': 'XMLHttpRequest' },
                });
                let c = null; try { c = await r.json(); } catch (e) {}
                return { statut: r.status, liste: Array.isArray(c?.backups) };
            });
            constate('role 2 sans can_admin_portal, par la passerelle',
                     `GET /admin/backups -> ${parApi.statut}${parApi.liste ? ' avec la liste' : ''}`
                     + ' (la permission garde la PAGE, pas la CAPACITE)');
        }

        await ctx.close();
        await dors(1200);
    }

    // ── Le contenu, avec le superadministrateur ─────────────────────────────
    await dors((resteFenetre() + 1) * 1000);
    const { ctx, page } = await connecte('rw-test-super');
    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await attendJusqua(page, (e) => ! /Chargement|Loading/i.test(e.texteCorps), 15000);

    const avant = await releve(page);

    verifie('la page porte un titre', avant.titre.length > 0, avant.titre);
    verifie('le bouton de creation est present', avant.boutonCreer);
    verifie('le tableau a quatre colonnes', avant.colonnes === 4, String(avant.colonnes));
    verifie('aucune cle de traduction morte a l\'ecran',
            ! /\b(backup|nav|auth|accueil|profil|passerelle|tip)\.[a-z_]{3,}\b/.test(avant.texteEntier));

    // L'avertissement sur le caractere destructif doit etre VISIBLE, pas cache.
    verifie('le caractere destructif de la restauration est annonce',
            /DROP TABLE|ecrase|écrase|overwrit/i.test(avant.texteEntier));

    constate('sauvegardes avant creation', `${avant.nbLignes}`);
    if (avant.nbLignes === 0) {
        verifie('sans sauvegarde, un message explicite remplace le tableau',
                avant.texteCorps.length > 3, `« ${avant.texteCorps.slice(0, 60)} »`);
    } else {
        constate('etat vide', 'des sauvegardes existent deja, non verifie ce passage');
    }

    // ── CREATION REELLE ─────────────────────────────────────────────────────
    await page.evaluate(() => document.getElementById('create-btn').click());
    const apres = await attendJusqua(page, (e) => e.nbLignes > avant.nbLignes);

    constate('sauvegardes apres creation', `${apres.nbLignes}`);
    const dit = await annonce(page);
    if (dit) constate('la page annonce', dit);

    verifie('la creation ajoute une sauvegarde',
            apres.nbLignes === avant.nbLignes + 1,
            `${avant.nbLignes} -> ${apres.nbLignes}`);
    verifie('le fichier cree porte le nom attendu',
            apres.fichiers.some(f => NOM_ATTENDU.test(f)),
            apres.fichiers.join(', ') || 'aucun');
    verifie('la taille est renseignee',
            apres.tailles.every(t => /\d/.test(t)),
            apres.tailles.join(', ') || 'aucune');

    // ── VERIFICATION REELLE de la sauvegarde qu'on vient de creer ───────────
    const nouveau = apres.fichiers.find(f => ! avant.fichiers.includes(f)) || apres.fichiers[0];
    constate('sauvegarde verifiee', nouveau);

    const indice = apres.fichiers.indexOf(nouveau);
    await page.evaluate((i) => {
        const tr = [...document.querySelectorAll('#backup-tbody tr')]
            .filter(x => x.querySelectorAll('td').length > 1)[i];
        const b = [...tr.querySelectorAll('button')][0];
        b.scrollIntoView({ block: 'center' });
        b.click();
    }, indice);

    /*
     * Attendre la FIN du controle, pas sa premiere annonce.
     *
     * Le premier jet lisait l'annonce des qu'elle etait non vide et recoltait
     * « Controle en cours... » — le message de travail, pas le verdict. Le
     * signal juste est le bouton : il est desactive pendant l'appel et
     * reactive juste avant que le verdict soit ecrit, dans le meme bloc
     * synchrone. Il ne depend ni de la cible ni de la langue.
     */
    const ditVerif = await (async () => {
        const limite = Date.now() + 25000;
        while (Date.now() < limite) {
            const fini = await page.evaluate((i) => {
                const tr = [...document.querySelectorAll('#backup-tbody tr')]
                    .filter(x => x.querySelectorAll('td').length > 1)[i];
                const b = tr ? [...tr.querySelectorAll('button')][0] : null;
                return b ? ! b.disabled : false;
            }, indice);
            if (fini) return annonce(page);
            await dors(300);
        }
        return annonce(page);
    })();
    if (ditVerif) constate('resultat de la verification', ditVerif);
    /*
     * Asserter sur le MOT « valide » liait le test a un libelle que le portage
     * a justement change : le controle ne prouve pas qu'une sauvegarde est
     * valide, seulement qu'elle est lisible et intacte. Ce qu'on exige est
     * qu'il RAPPORTE ce qu'il a lu — un nombre de tables et un nombre
     * d'instructions. Deux nombres, dans n'importe quelle langue.
     */
    verifiePortage("le controle annonce ce qu'il a lu",
                   (ditVerif.match(/\d+/g) || []).length >= 2,
                   ditVerif || 'aucune annonce durable');

    // ── LA RESTAURATION : elle existe, elle est gardee, elle n'est PAS menee ─
    const boutonsLigne = apres.boutons[indice] || [];
    verifie('le superadministrateur dispose de la restauration',
            boutonsLigne.some(b => /restaur/i.test(b)),
            boutonsLigne.join(' | ') || 'aucun bouton');

    /*
     * Un nom errone ne doit RIEN restaurer. Sur le legacy, le nom est demande
     * par `prompt()` : la boite est refusee par le gestionnaire de dialogue, ce
     * qui annule — on ne peut donc pas y saisir un mauvais nom. Le portage
     * ouvre un panneau en ligne, ou la saisie est pilotable.
     */
    if (CIBLE === 'laravel') {
        await page.evaluate((i) => {
            const tr = [...document.querySelectorAll('#backup-tbody tr')]
                .filter(x => x.querySelectorAll('td').length > 1)[i];
            const b = [...tr.querySelectorAll('button')].find(x => /restaur/i.test(x.textContent));
            b.scrollIntoView({ block: 'center' });
            b.click();
        }, indice);
        await dors(400);

        const panneau = await page.$('[data-rw="restauration-nom"]');
        verifie('la restauration ouvre une confirmation en ligne', Boolean(panneau));

        if (panneau) {
            await panneau.type('rootwarden_backup_00000000_000000.sql.gz', { delay: 5 });
            const bouton = await page.$('[data-rw="restauration-confirmer"]');
            verifie('le bouton de confirmation reste inactif tant que le nom differe',
                    bouton ? await bouton.evaluate(b => b.disabled) : false,
                    bouton ? 'present' : 'bouton absent');

            const etatApres = await releve(page);
            verifie('un nom errone ne restaure rien',
                    etatApres.nbLignes === apres.nbLignes,
                    `${apres.nbLignes} -> ${etatApres.nbLignes}`);

            const annuler = await page.$('[data-rw="restauration-annuler"]');
            if (annuler) await annuler.evaluate(b => b.click());
        }
    } else {
        constate('confirmation de restauration',
                 'boite native `prompt()` : refusee par le gestionnaire de dialogue, non pilotable');
    }

    constate('restauration reelle', 'JAMAIS jouee — DROP TABLE sur la base partagee');

    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
