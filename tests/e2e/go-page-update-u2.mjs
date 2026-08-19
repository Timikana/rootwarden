/**
 * go-page-update-u2.mjs - Module `update/`, sous-lot U2 : le journal d'execution.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/update/
 *   laravel  http://localhost:8444/mises-a-jour
 *
 * PERIMETRE U2 — PRESENTATION PURE. Aucune route backend. Le journal est
 * alimente par les autres sous-lots ; ce qu'on mesure ici est son CONTRAT :
 * un panneau par serveur, cree une seule fois, une ligne par message, une ligne
 * de progression qui se REMPLACE au lieu de s'empiler, et un effacement.
 *
 * CE QUE LE TEST CHERCHE : `appendLog` est defini DEUX FOIS dans le legacy —
 * dans `domManipulation.js` (ecrit dans `#logs`) puis dans `apiCalls.js` (ecrit
 * dans `#logs-container`). `apiCalls.js` charge en second, sa definition gagne,
 * et la premiere est du code mort. La zone `#logs` — un cadre noir de 12 rem
 * rendu par la page — n'est donc alimentee par PERSONNE, et `clearLog()` vide
 * une zone toujours vide.
 *
 * AUCUNE ACTION MUTANTE. Le seul geste declenche est un filtrage du parc, en
 * lecture seule, qui journalise son resultat. Le reste passe par l'API de
 * journal de la page.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-update-u2.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-update-u2.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/mises-a-jour' : '/update/';

const COMPTE = {
    nom: 'rw-test-admin',
    secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX',
};

const SERVEUR = 'Test-Server-Debian';

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
    protocolTimeout: 60000,
});

async function connecte() {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    page.on('dialog', d => d.dismiss().catch(() => {}));

    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };

    await page.goto(`${BASE}${chemins.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', COMPTE.nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    await page.type('input[name="2fa_code"]', totp(COMPTE.secret), { delay: 8 });
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
 * Ecrit dans le journal de la page.
 *
 * Les deux cibles exposent la meme intention par des chemins differents : le
 * legacy par des fonctions globales (`appendLog`), le portage par un objet
 * declare, `window.rwJournal`. Le test s'adapte ICI, une fois, pour que le
 * reste des attentes soit identique des deux cotes.
 */
async function journalAjoute(page, message, type, serveur) {
    return page.evaluate((m, t, s) => {
        if (window.rwJournal && typeof window.rwJournal.ajoute === 'function') {
            window.rwJournal.ajoute(m, t, s);
            return 'rwJournal';
        }
        if (typeof window.appendLog === 'function') {
            window.appendLog(m, t, s);
            return 'appendLog';
        }
        return null;
    }, message, type, serveur ?? null);
}

async function journalVide(page) {
    return page.evaluate(() => {
        if (window.rwJournal && typeof window.rwJournal.vide === 'function') {
            window.rwJournal.vide();
            return 'rwJournal';
        }
        if (typeof window.clearLogs === 'function') { window.clearLogs(); return 'clearLogs'; }
        return null;
    });
}

/** Etat du journal tel qu'il est RENDU. */
async function releve(page) {
    return page.evaluate(() => {
        const conteneur = document.getElementById('logs-container');
        const globale = document.getElementById('logs');
        const t = (el) => (el?.textContent || '').trim();
        const panneaux = [...(conteneur?.querySelectorAll('.server-log-window') || [])];
        return {
            conteneur: Boolean(conteneur),
            zoneGlobale: Boolean(globale),
            texteGlobale: t(globale),
            nbPanneaux: panneaux.length,
            serveurs: panneaux.map(p => p.getAttribute('data-server-name')),
            suivi: panneaux.map(p => Boolean(p.querySelector('.log-follow-toggle input'))),
            lignesParPanneau: panneaux.map(p => p.querySelectorAll('.log-window .log-line').length),
            textesPanneau: panneaux.map(p => t(p.querySelector('.log-window'))),
            classesLignes: panneaux.map(p =>
                [...p.querySelectorAll('.log-window .log-line')].map(l => l.className)),
            // Ce qui vit dans le conteneur SANS etre un panneau de serveur :
            // c'est la que le legacy depose ses messages globaux.
            horsPanneau: conteneur
                ? [...conteneur.children].filter(e => !e.classList.contains('server-log-window')).length
                : 0,
            texteHorsPanneau: conteneur
                ? [...conteneur.children]
                    .filter(e => !e.classList.contains('server-log-window'))
                    .map(e => (e.textContent || '').trim()).join(' | ')
                : '',
        };
    });
}

try {
    const { ctx, page } = await connecte();
    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await dors(800);

    const depart = await releve(page);
    verifie('la zone de journal est presente', depart.conteneur);
    constate('zone globale `#logs` presente', depart.zoneGlobale ? 'oui' : 'non');

    const voie = await journalAjoute(page, 'Ligne de caracterisation', 'info', SERVEUR);
    constate('voie du journal', voie || 'AUCUNE');
    verifie('la page expose une API de journal', Boolean(voie), voie || 'ni rwJournal ni appendLog');

    // ── UN PANNEAU PAR SERVEUR, CREE UNE SEULE FOIS ─────────────────────────
    const apresUne = await releve(page);
    verifie('un panneau est cree pour le serveur',
            apresUne.nbPanneaux === 1 && apresUne.serveurs[0] === SERVEUR,
            `${apresUne.nbPanneaux} panneau(x) : ${apresUne.serveurs.join(', ')}`);
    verifie('le panneau porte une case de suivi', apresUne.suivi[0] === true);
    verifie('la ligne est ecrite dans le panneau',
            apresUne.lignesParPanneau[0] === 1
            && apresUne.textesPanneau[0].includes('Ligne de caracterisation'),
            `${apresUne.lignesParPanneau[0]} ligne(s) : « ${apresUne.textesPanneau[0].slice(0, 50)} »`);

    await journalAjoute(page, 'Deuxieme ligne', 'info', SERVEUR);
    const apresDeux = await releve(page);
    verifie('un second message REUTILISE le panneau, il n\'en cree pas un autre',
            apresDeux.nbPanneaux === 1 && apresDeux.lignesParPanneau[0] === 2,
            `${apresDeux.nbPanneaux} panneau(x), ${apresDeux.lignesParPanneau[0]} ligne(s)`);

    // ── UNE LIGNE DE PROGRESSION SE REMPLACE ────────────────────────────────
    await journalAjoute(page, 'Progression 1/3', 'progress', SERVEUR);
    const p1 = await releve(page);
    await journalAjoute(page, 'Progression 2/3', 'progress', SERVEUR);
    await journalAjoute(page, 'Progression 3/3', 'progress', SERVEUR);
    const p3 = await releve(page);

    constate('lignes apres trois progressions', `${p1.lignesParPanneau[0]} -> ${p3.lignesParPanneau[0]}`);
    verifie('trois progressions n\'ajoutent qu\'UNE ligne, remplacee a chaque fois',
            p3.lignesParPanneau[0] === p1.lignesParPanneau[0]
            && p3.textesPanneau[0].includes('Progression 3/3')
            && ! p3.textesPanneau[0].includes('Progression 1/3'),
            `${p3.lignesParPanneau[0]} ligne(s), fin : « ${p3.textesPanneau[0].slice(-30)} »`);

    // ── LE TYPE EST PORTE PAR LA LIGNE ──────────────────────────────────────
    await journalAjoute(page, 'Un echec', 'error', SERVEUR);
    const apresErreur = await releve(page);
    verifie('le type du message se lit sur la ligne',
            apresErreur.classesLignes[0].some(c => /error/.test(c)),
            [...new Set(apresErreur.classesLignes[0])].join(' | '));

    // ── UN SECOND SERVEUR A SON PROPRE PANNEAU ──────────────────────────────
    await journalAjoute(page, 'Ligne pour un autre serveur', 'info', 'OpenCVE-Test-OnPrem');
    const deuxServeurs = await releve(page);
    verifie('chaque serveur a son panneau',
            deuxServeurs.nbPanneaux === 2
            && deuxServeurs.serveurs.includes(SERVEUR)
            && deuxServeurs.serveurs.includes('OpenCVE-Test-OnPrem'),
            deuxServeurs.serveurs.join(', '));

    /*
     * ── OU VA UN MESSAGE GLOBAL ? ──────────────────────────────────────────
     *
     * Sans nom de serveur, le legacy ecrit un `<p>` nu DANS `#logs-container`,
     * cote a cote avec les panneaux — pendant que `#logs`, le cadre noir rendu
     * par la page, reste vide. Cause : `appendLog` est defini deux fois, et la
     * definition de `apiCalls.js`, chargee en second, ecrase celle de
     * `domManipulation.js` qui visait `#logs`.
     *
     * Ce qu'on exige du portage : un message global doit atterrir dans une
     * zone VISIBLE et identifiable, pas melange aux panneaux.
     */
    await journalAjoute(page, 'Message global de caracterisation', 'info', null);
    const global = await releve(page);

    constate('apres un message global',
             `#logs : « ${global.texteGlobale.slice(0, 40)} » · hors panneau : `
             + `${global.horsPanneau} element(s) « ${global.texteHorsPanneau.slice(0, 50)} »`);

    const dansZoneGlobale = global.texteGlobale.includes('Message global de caracterisation');
    const dansConteneur = global.texteHorsPanneau.includes('Message global de caracterisation');

    /*
     * Le detail d'une attente decrit CE QU'ON A MESURE, pas ce qu'on aurait dit
     * en cas d'echec : « introuvable dans les deux zones » s'affichait sur un
     * PASS et donnait a lire l'inverse du resultat.
     */
    verifie('un message global est ecrit quelque part', dansZoneGlobale || dansConteneur,
            dansZoneGlobale ? 'dans la zone globale'
                            : (dansConteneur ? 'parmi les panneaux' : 'nulle part'));

    verifiePortage('un message global va dans la zone globale, pas parmi les panneaux',
                   dansZoneGlobale && ! dansConteneur,
                   `zone globale : ${dansZoneGlobale} · melange aux panneaux : ${dansConteneur}`);

    if (CIBLE === 'legacy' && dansConteneur && ! dansZoneGlobale) {
        constate('defaut du legacy',
                 'le message global se depose parmi les panneaux et `#logs` reste vide — '
                 + '`appendLog` est defini deux fois, la seconde definition ecrase la premiere');
    }

    // ── L'EFFACEMENT ────────────────────────────────────────────────────────
    const voieVide = await journalVide(page);
    constate('voie d\'effacement', voieVide || 'AUCUNE');
    const apresVidage = await releve(page);
    verifie('l\'effacement retire les panneaux',
            apresVidage.nbPanneaux === 0,
            `${apresVidage.nbPanneaux} panneau(x) restant(s)`);

    /*
     * ── LE JOURNAL RECOIT CE QUE LA PAGE FAIT ──────────────────────────────
     *
     * Un filtrage est en LECTURE SEULE et journalise son resultat : c'est le
     * seul geste de la page qu'on puisse declencher sans sortir du perimetre
     * de U1/U2.
     */
    await page.evaluate(() => {
        const b = [...document.querySelectorAll('button')].find(x => /filtr/i.test(x.textContent));
        if (b) b.click();
    });
    // Attendre LE CONTENU, pas un delai : un 2500 ms fixe passe quand la
    // machine est libre et echoue quand elle enchaine les navigateurs. C'est
    // le journal qu'on attend, alors c'est le journal qu'on interroge.
    const tracesDuFiltre = () => page.evaluate(() => {
        const conteneur = document.getElementById('logs-container');
        const horsPanneau = conteneur
            ? [...conteneur.children].filter(el => !el.hasAttribute('data-server-name'))
                .map(el => el.innerText).join(' ')
            : '';
        return ((document.getElementById('logs')?.innerText || '') + ' ' + horsPanneau).trim();
    });
    const limiteFiltre = Date.now() + 30000;
    while (Date.now() < limiteFiltre && !(await tracesDuFiltre())) await dors(300);

    const apresFiltre = await releve(page);

    const trace = apresFiltre.texteGlobale + ' ' + apresFiltre.texteHorsPanneau
        + ' ' + apresFiltre.textesPanneau.join(' ');
    constate('journal apres un filtrage', trace.trim().slice(0, 90) || 'rien');
    verifie('le filtrage laisse une trace dans le journal', trace.trim().length > 0,
            trace.trim() ? `« ${trace.trim().slice(0, 60)} »` : 'aucune trace');

    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
