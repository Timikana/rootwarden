/**
 * go-page-tickets.mjs - Ticketing ITSM : liste et creation manuelle.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/tickets/
 *   laravel  http://localhost:8444/tickets
 *
 * CREATION REELLE, SANS APPEL EXTERNE. `TICKETING_ENABLED=false` : le backend
 * n'appelle aucun ITSM et enregistre un ticket `local`. Lu dans
 * `backend/ticketing.py` (`is_enabled()`) avant d'ecrire ce test — cliquer
 * « Creer » sans savoir ou part la requete n'aurait pas ete raisonnable.
 *
 * CE QUE LE TEST CHERCHE VRAIMENT : la deduplication porte sur le triplet
 * `(source, ref, machine_id)` et NON sur le resume. Pour un ticket manuel,
 * `ref` vaut toujours NULL et `source` toujours « manual » : deux tickets de
 * resumes DIFFERENTS sur la MEME machine sont donc fusionnes. L'aide de la page
 * annonce pourtant « ne pas creer plusieurs tickets pour la meme alerte ». Le
 * test cree deux tickets de resumes distincts sur la machine 2 et mesure ce qui
 * se passe.
 *
 * Le test PRODUIT ce qu'il consomme : la table est vide au depart, et il ne
 * peut de toute facon pas s'appuyer sur ce qu'un passage precedent a laisse —
 * la deduplication le lui rendrait.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-tickets.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-tickets.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
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
const PAGE = CIBLE === 'laravel' ? '/tickets' : '/tickets/';

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

/** Attente propre a une cible : le legacy n'a pas ce que le portage ajoute. */
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
        const corps = document.getElementById('tickets-tbody');
        const toutes = corps ? [...corps.querySelectorAll('tr')] : [];
        const donnees = toutes.filter(tr => tr.querySelectorAll('td').length > 1);
        const texte = (el) => (el?.textContent || '').trim();
        const formulaire = document.getElementById('ticket-form');
        return {
            titre: texte(document.querySelector('h1')),
            boutonNouveau: Boolean(document.getElementById('new-ticket-btn')),
            etatFournisseur: texte(document.getElementById('tickets-status')),
            // « Visible » se lit sur la geometrie, pas sur une classe : un
            // formulaire cache par `hidden` et un autre par `display:none`
            // doivent se mesurer de la meme facon.
            formulaireVisible: Boolean(formulaire && formulaire.getClientRects().length),
            colonnes: [...document.querySelectorAll('thead th')].length,
            nbLignes: donnees.length,
            resumes: donnees.map(tr => texte(tr.querySelectorAll('td')[2])),
            machines: donnees.map(tr => texte(tr.querySelectorAll('td')[3])),
            fournisseurs: donnees.map(tr => texte(tr.querySelectorAll('td')[4])),
            texteCorps: texte(corps).slice(0, 160),
            texteEntier: document.body.innerText,
        };
    });
}

async function attendJusqua(page, predicat, maxMs = 20000) {
    const limite = Date.now() + maxMs;
    let dernier = await releve(page);
    while (Date.now() < limite && ! predicat(dernier)) {
        await dors(350);
        dernier = await releve(page);
    }
    return dernier;
}

async function annonce(page) {
    return page.evaluate(() =>
        (document.querySelector('[data-rw="annonce"]')?.textContent || '').trim());
}

/** Remplit le formulaire et soumet. Rend l'etat une fois la reponse arrivee. */
async function creeTicket(page, resume, machineValeur, description) {
    await page.evaluate(() => {
        const f = document.getElementById('ticket-form');
        if (! f.getClientRects().length) document.getElementById('new-ticket-btn').click();
    });
    await dors(250);

    await page.evaluate((r, m, d) => {
        const s = document.getElementById('t-summary');
        const ma = document.getElementById('t-machine');
        const de = document.getElementById('t-desc');
        s.value = r; s.dispatchEvent(new Event('input', { bubbles: true }));
        ma.value = m; ma.dispatchEvent(new Event('change', { bubbles: true }));
        de.value = d; de.dispatchEvent(new Event('input', { bubbles: true }));
    }, resume, machineValeur, description);

    /*
     * Attendre le RECHARGEMENT, pas une duree.
     *
     * Le premier jet dormait 1000 ms apres la reponse du POST et lisait le
     * tableau d'AVANT : il rapportait « la creation n'ajoute rien » alors que
     * le ticket etait bien cree. Le signal juste est la relecture de la liste
     * que les deux cibles declenchent apres l'envoi — et il vaut aussi bien
     * pour une creation que pour une fusion, ou le nombre de lignes ne bouge
     * pas et ou attendre un changement ne finirait jamais.
     */
    let statut = 0;
    let relectures = 0;
    const ecoute = (r) => {
        const estTickets = /\/tickets(\?|$)/.test(r.url());
        if (!estTickets) return;
        if (r.request().method() === 'POST') statut = r.status();
        else if (statut !== 0) relectures++;
    };
    page.on('response', ecoute);

    await page.evaluate(() => {
        const b = document.getElementById('t-save');
        b.scrollIntoView({ block: 'center' });
        b.click();
    });

    const limite = Date.now() + 25000;
    while (Date.now() < limite && (statut === 0 || relectures === 0)) await dors(200);
    await dors(400);   // laisser le rendu suivre la reponse
    page.off('response', ecoute);

    return { statut, etat: await releve(page), dit: await annonce(page) };
}

try {
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: '/tickets/',
            fichiers: ['/tickets/index.php', '/tickets/js/main.js'], verifie, constate,
        });
        if (archivee) {
            const { ctx, page } = await connecte('rw-test-super');
            await verifieMenuLegacy(page, '/tickets', verifie, constate);
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
            && await page.evaluate(() => Boolean(document.getElementById('tickets-tbody')));

        verifie(`${nom} (role ${compte.role}) : ${compte.attendu === 'autorise' ? "la page s'affiche" : 'la page est refusee'}`,
                compte.attendu === 'autorise' ? affichee : ! affichee,
                `statut=${statut} url=${page.url().replace(BASE, '')}`);
        await ctx.close();
        await dors(1200);
    }

    // ── Le contenu ──────────────────────────────────────────────────────────
    await dors((resteFenetre() + 1) * 1000);
    const { ctx, page } = await connecte('rw-test-super');
    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await attendJusqua(page, (e) => ! /Chargement|Loading/i.test(e.texteCorps));

    const depart = await releve(page);

    verifie('la page porte un titre', depart.titre.length > 0, depart.titre);
    verifie('le bouton de creation est present', depart.boutonNouveau);
    verifie('le tableau a six colonnes', depart.colonnes === 6, `${depart.colonnes}`);
    verifie('aucune cle de traduction morte a l\'ecran',
            ! /\b(tickets|nav|auth|accueil|profil|passerelle|tip)\.[a-z_]{3,}\b/.test(depart.texteEntier));

    // L'etat du fournisseur ITSM doit etre ANNONCE : sans lui, on ne sait pas
    // si « Creer » ouvre un ticket dans Jira ou une ligne en base.
    constate('etat du fournisseur', depart.etatFournisseur || 'rien affiche');
    verifie('l\'etat du fournisseur ITSM est affiche', depart.etatFournisseur.length > 3,
            depart.etatFournisseur);

    constate('tickets au depart', `${depart.nbLignes}`);
    if (depart.nbLignes === 0) {
        verifie('sans ticket, un message explicite remplace le tableau',
                depart.texteCorps.length > 3, `« ${depart.texteCorps.slice(0, 60)} »`);
    }

    // ── Le formulaire s'ouvre et se ferme ───────────────────────────────────
    verifie('le formulaire est masque au chargement', ! depart.formulaireVisible);
    await page.evaluate(() => document.getElementById('new-ticket-btn').click());
    await dors(300);
    verifie('le bouton ouvre le formulaire',
            (await releve(page)).formulaireVisible);
    await page.evaluate(() => document.getElementById('t-cancel').click());
    await dors(300);
    verifie('« Annuler » referme le formulaire',
            ! (await releve(page)).formulaireVisible);

    /*
     * ── CREATION REELLE, SUR UNE MACHINE ENCORE LIBRE ──────────────────────
     *
     * La cle de dedoublonnage d'un ticket manuel se reduit a la MACHINE. Un
     * test qui cree toujours sur la machine 2 ne peut donc reussir qu'UNE
     * fois — la premiere execution consomme le seul creneau, et toutes les
     * suivantes tombent sur la fusion. Le premier jet de ce test faisait
     * exactement cela, et rapportait deux echecs des la seconde cible.
     *
     * Il choisit donc une machine SANS ticket manuel. La machine 1 est en
     * production : elle est exclue de la selection, bien qu'un ticket ne soit
     * qu'une ligne en base.
     *
     * Que le creneau existe ou non, quelque chose est mesure : la creation
     * dans un cas, la fusion dans l'autre. Le test dit laquelle des deux
     * branches il a jouee.
     */
    const manuelsExistants = new Set(
        (await page.evaluate(() => {
            const corps = document.getElementById('tickets-tbody');
            return [...(corps?.querySelectorAll('tr') || [])]
                .filter(tr => tr.querySelectorAll('td').length > 1)
                .filter(tr => /manual/i.test(tr.querySelectorAll('td')[1]?.textContent || ''))
                .map(tr => (tr.querySelectorAll('td')[3]?.textContent || '').trim());
        })));
    constate("machines deja pourvues d'un ticket manuel",
             [...manuelsExistants].join(', ') || 'aucune');

    // Valeur du selecteur -> libelle affiche dans la colonne « Machine ».
    const creneaux = await page.evaluate(() =>
        [...document.getElementById('t-machine').options]
            .map(o => ({ valeur: o.value, libelle: o.textContent.trim() })));

    const libre = creneaux.find(c =>
        c.valeur !== '1'                                  // machine de production, exclue
        && ! manuelsExistants.has(c.libelle)
        && ! (c.valeur === '' && manuelsExistants.has('—')));

    const marque = Date.now().toString(36);
    let apresCreation = depart;

    if (libre) {
        constate('creneau retenu', `${libre.libelle || '(aucune)'} (valeur « ${libre.valeur} »)`);
        const resume = `Ticket de caracterisation ${marque}`;
        const r1 = await creeTicket(page, resume, libre.valeur, 'Cree par la suite de caracterisation.');
        apresCreation = r1.etat;

        constate('reponse a la creation', `HTTP ${r1.statut}`);
        if (r1.dit) constate('la page annonce', r1.dit);

        verifie('la creation ajoute un ticket',
                r1.etat.nbLignes === depart.nbLignes + 1,
                `${depart.nbLignes} -> ${r1.etat.nbLignes}`);
        verifie('le resume saisi apparait dans la liste',
                r1.etat.resumes.some(x => x.includes(marque)),
                r1.etat.resumes.slice(0, 3).join(' | ') || 'aucun');
        verifie('sans fournisseur configure, le ticket reste local',
                r1.etat.fournisseurs.some(p => /local/i.test(p)),
                [...new Set(r1.etat.fournisseurs)].join(', ') || 'aucun');
    } else {
        constate('creation',
                 'aucune machine libre — toutes ont deja un ticket manuel, '
                 + 'le formulaire ne peut plus rien creer');
    }

    /*
     * ── LA DEDUPLICATION NE PORTE PAS SUR CE QUE L'AIDE ANNONCE ────────────
     *
     * On vise DELIBEREMENT une machine deja pourvue, avec un resume different.
     * L'aide du legacy annonce « ne pas creer plusieurs tickets pour la meme
     * alerte » ; la cle reelle etant (source, reference, machine), deux sujets
     * distincts sur une meme machine sont fusionnes.
     */
    const pourvue = libre || creneaux.find(c => c.valeur !== '1' && manuelsExistants.has(c.libelle));
    if (pourvue) {
        const avantFusion = await releve(page);
        const r2 = await creeTicket(page, `Autre sujet, meme machine ${marque}`,
                                    pourvue.valeur, 'Sujet different, machine identique.');

        constate('reponse a la seconde creation', `HTTP ${r2.statut}`);
        if (r2.dit) constate('la page annonce', r2.dit);

        const fusionne = r2.etat.nbLignes === avantFusion.nbLignes
            && ! r2.etat.resumes.some(x => x.includes('Autre sujet'));

        constate('second ticket, meme machine, resume different',
                 fusionne
                     ? 'FUSIONNE — la cle de dedoublonnage est la machine, pas le sujet'
                     : `cree (${avantFusion.nbLignes} -> ${r2.etat.nbLignes})`);

        verifie('un second sujet sur la meme machine est fusionne, pas cree',
                r2.statut === 200 && fusionne,
                `HTTP ${r2.statut}, ${avantFusion.nbLignes} -> ${r2.etat.nbLignes}`);

        verifiePortage('la fusion est annoncee, et sur quelle cle',
                       /machine|dedoublon|existe|deja/i.test(r2.dit),
                       r2.dit || 'aucune annonce durable');

        apresCreation = r2.etat;
    } else {
        constate('fusion', 'aucune machine pourvue, branche non jouee');
    }

    // ── UN RESUME VIDE NE CREE RIEN ─────────────────────────────────────────
    const r3 = await creeTicket(page, '', '', '');
    constate('creation sans resume', `HTTP ${r3.statut || '(aucune requete)'}`);
    verifie('un resume vide ne cree pas de ticket',
            r3.etat.nbLignes === apresCreation.nbLignes,
            `${apresCreation.nbLignes} -> ${r3.etat.nbLignes}`);
    verifiePortage('le bouton de creation reste inactif tant que le resume est vide',
                   await page.evaluate(() => document.getElementById('t-save').disabled),
                   'bouton actif alors que le resume est vide');

    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
