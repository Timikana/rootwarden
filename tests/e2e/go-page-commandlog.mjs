/**
 * go-page-commandlog.mjs - Journal des commandes (bastion trail), lecture seule.
 *
 * Premiere page metier portee. Le test vise les DEUX cibles :
 *   legacy   https://localhost:8443/commandlog/
 *   laravel  http://localhost:8444/journal-commandes
 *
 * Il mesure ce que la page fait VRAIMENT, avec les trois comptes dedies :
 *   - la garde reelle (role ET permission), et non celle qu'annonce l'en-tete ;
 *   - le rendu des lignes venues du backend, colonne par colonne ;
 *   - le filtre par contexte, qui doit REDUIRE le nombre de lignes ;
 *   - l'etat vide, qui doit etre explicite et non un tableau muet ;
 *   - l'absence de cle de traduction morte a l'ecran.
 *
 * Les identifiants d'element sont ceux du legacy (`f-machine`, `f-context`,
 * `refresh-btn`, `cmdlog-tbody`) : le portage les conserve, sans quoi un meme
 * test ne pourrait pas viser les deux cibles.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-commandlog.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-commandlog.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/journal-commandes' : '/commandlog/';

const COMPTES = {
    'rw-test-user':  { role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW', attendu: 'refuse' },
    'rw-test-admin': { role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX', attendu: 'refuse' },
    'rw-test-super': { role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW', attendu: 'autorise' },
};

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}

/*
 * ATTENDRE UN CHANGEMENT, PUIS LA STABILITE — jamais une duree fixe.
 *
 * Ce test dormait 1500 ms apres chaque changement de filtre. Il a tenu tant que
 * le journal etait court, puis il a rendu deux FAUX ECHECS des que la table a
 * grossi : la passerelle repondait apres le reveil, et la sonde lisait encore
 * le resultat du filtre PRECEDENT. Ce que le test disait alors — « le filtre ne
 * filtre pas » — etait faux ; c'est la sonde qui mesurait trop tot.
 */
async function empreinteCorps(page) {
    return page.evaluate(() =>
        (document.getElementById('cmdlog-tbody')?.textContent || '').replace(/\s+/g, ' ').trim());
}

async function attendReponse(page, maxMs = 15000) {
    const depart = await empreinteCorps(page);
    const limite = Date.now() + maxMs;

    // 1. Attendre que quelque chose BOUGE. Un filtre qui rend le meme contenu
    //    existe : on sort alors sur la stabilite, pas sur le changement.
    while (Date.now() < limite) {
        const maintenant = await empreinteCorps(page);
        if (maintenant !== depart && ! /Chargement|Loading/i.test(maintenant)) break;
        await dors(150);
    }

    // 2. Puis attendre que ca cesse de bouger : une reponse en retard peut
    //    encore ecraser ce qu'on vient de lire.
    let precedent = null;
    let stable = 0;
    while (Date.now() < limite) {
        const maintenant = await empreinteCorps(page);
        stable = maintenant === precedent ? stable + 1 : 0;
        precedent = maintenant;
        if (stable >= 3 && ! /Chargement|Loading/i.test(maintenant)) return;
        await dors(150);
    }
}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0, ecarts = 0;
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
/** Attente qui ne vaut que pour le portage ; ecart connu cote legacy. */
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

    if (ok) { lignes.push(`PASS  ${libelle}${detail ? '  — ' + detail : ''}`); return; }
    if (CIBLE === 'legacy') { lignes.push(`ECART CONNU (legacy)  ${libelle}${detail ? '  — ' + detail : ''}`); ecarts++; }
    else { lignes.push(`FAIL  ${libelle}${detail ? '  — ' + detail : ''}`); echecs++; }
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
        const corps = document.getElementById('cmdlog-tbody');
        const lignes = corps ? [...corps.querySelectorAll('tr')] : [];
        // Une ligne d'attente ou d'etat vide occupe toute la largeur : elle ne
        // compte pas comme une ligne de donnees.
        const donnees = lignes.filter(tr => tr.querySelectorAll('td').length > 1);
        return {
            titre: (document.querySelector('h1')?.textContent || '').trim(),
            filtreMachine: Boolean(document.getElementById('f-machine')),
            filtreContexte: Boolean(document.getElementById('f-context')),
            rafraichir: Boolean(document.getElementById('refresh-btn')),
            colonnes: [...document.querySelectorAll('thead th')].map(t => t.textContent.trim()),
            nbLignes: donnees.length,
            contextes: donnees.map(tr => (tr.querySelectorAll('td')[3]?.textContent || '').trim()),
            optionsContexte: [...(document.getElementById('f-context')?.options || [])].map(o => o.value),
            texteCorps: (corps?.textContent || '').trim().slice(0, 120),
            texteEntier: document.body.innerText,
        };
    });
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
            base: BASE, chemin: '/commandlog/', fichiers: ['/commandlog/index.php', '/commandlog/js/main.js'], verifie, constate,
        });
        if (archivee) {
            const { ctx, page } = await connecte('rw-test-super');
            await verifieMenuLegacy(page, '/journal-commandes', verifie);
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

        // « Autorise » veut dire : la page s'affiche, avec son tableau.
        const affichee = statut === 200
            && ! /connexion|login\.php/i.test(url)
            && await page.evaluate(() => Boolean(document.getElementById('cmdlog-tbody')));

        if (compte.attendu === 'autorise') {
            verifie(`${nom} (role ${compte.role}) : la page s'affiche`, affichee,
                    `statut=${statut} url=${url.replace(BASE, '')}`);
        } else {
            verifie(`${nom} (role ${compte.role}) : la page est refusee`, ! affichee,
                    `statut=${statut} url=${url.replace(BASE, '')} corps=${corps.slice(0, 60).replace(/\s+/g, ' ')}`);
        }
        await ctx.close();
        await dors(1200);
    }

    // ── Le contenu, avec le compte autorise ─────────────────────────────────
    await dors((resteFenetre() + 1) * 1000);
    const { ctx, page } = await connecte('rw-test-super');
    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await attendReponse(page); // le tableau se remplit par un appel a la passerelle

    const etat = await releve(page);

    verifie('la page porte un titre', etat.titre.length > 0, etat.titre);
    verifie('le filtre par machine est present', etat.filtreMachine);
    verifie('le filtre par contexte est present', etat.filtreContexte);
    verifie('le bouton de rafraichissement est present', etat.rafraichir);
    verifie('le tableau a six colonnes', etat.colonnes.length === 6, etat.colonnes.join(' | '));
    verifie('aucune cle de traduction morte a l\'ecran',
            ! /\b(cmdlog|nav|auth|accueil|profil|passerelle)\.[a-z_]{3,}\b/.test(etat.texteEntier));

    constate('lignes affichees', etat.nbLignes);
    constate('contextes vus', [...new Set(etat.contextes)].join(', ') || 'aucun');
    verifie('des lignes reelles sont affichees', etat.nbLignes > 0,
            etat.nbLignes === 0 ? etat.texteCorps : `${etat.nbLignes} ligne(s)`);

    // ── Le filtre par contexte REDUIT le nombre de lignes ───────────────────
    const contexteChoisi = etat.optionsContexte.find(v => v);
    if (contexteChoisi) {
        await page.select('#f-context', contexteChoisi);
        await attendReponse(page);
        const filtre = await releve(page);
        constate(`apres filtre « ${contexteChoisi} »`, `${filtre.nbLignes} ligne(s)`);
        verifie(`le filtre « ${contexteChoisi} » reduit ou conserve, jamais n'augmente`,
                filtre.nbLignes <= etat.nbLignes && filtre.nbLignes > 0,
                `${etat.nbLignes} -> ${filtre.nbLignes}`);
        verifie('toutes les lignes filtrees portent le contexte choisi',
                filtre.contextes.every(c => c === contexteChoisi),
                [...new Set(filtre.contextes)].join(', '));
    } else {
        constate('filtre par contexte', 'aucune option disponible, filtre non verifie');
    }

    // ── L'etat vide est EXPLICITE ───────────────────────────────────────────
    // On demande une machine qui n'a aucune commande journalisee.
    const machineSansLog = await page.evaluate(() => {
        const opts = [...(document.getElementById('f-machine')?.options || [])].map(o => o.value).filter(Boolean);
        return opts.find(v => v !== '2') || null;
    });
    if (machineSansLog) {
        // Un geste a la fois, avec le temps de la reponse entre les deux : une
        // personne ne change pas deux filtres dans la meme milliseconde, et
        // enchainer les deux fait courir deux requetes dont la plus ancienne
        // peut arriver en dernier et ecraser la plus recente.
        await page.select('#f-context', '');
        await attendReponse(page);
        await page.select('#f-machine', machineSansLog);
        await attendReponse(page);
        const vide = await releve(page);
        verifie('sans resultat, un message explicite remplace le tableau',
                vide.nbLignes === 0 && vide.texteCorps.length > 3,
                `lignes=${vide.nbLignes} message=« ${vide.texteCorps.slice(0, 50)} »`);
    } else {
        constate('etat vide', 'aucune autre machine disponible, non verifie');
    }

    // ── Deux filtres changes COUP SUR COUP ──────────────────────────────────
    // Le legacy lance un chargement par changement sans ordonner les reponses :
    // la plus ancienne peut arriver en dernier et ecraser la plus recente.
    // L'utilisateur voit alors le resultat d'un filtre qu'il vient de quitter.
    // Le portage numerote ses chargements ; seul le dernier ecrit.
    await page.select('#f-machine', '');
    await page.select('#f-context', '');
    await attendReponse(page);
    const avantCourse = await releve(page);

    await page.select('#f-context', contexteChoisi || '');
    await page.select('#f-machine', '2');   // deux gestes dans la meme milliseconde
    await attendReponse(page);
    const apresCourse = await releve(page);

    constate('apres deux changements coup sur coup', `${apresCourse.nbLignes} ligne(s), contextes : ${[...new Set(apresCourse.contextes)].join(', ') || '-'}`);
    verifiePortage('deux filtres changes coup sur coup : le dernier gagne',
                   contexteChoisi ? apresCourse.contextes.every(c => c === contexteChoisi) : true,
                   `attendu « ${contexteChoisi} », vu « ${[...new Set(apresCourse.contextes)].join(', ')} » (avant : ${avantCourse.nbLignes} lignes)`);

    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
