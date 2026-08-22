/**
 * go-page-supervision-releve.mjs - Module `supervision/`, sous-lot V8 : le
 * releve des agents de TOUT LE PARC.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/supervision/   (« Scanner tous les agents »)
 *   laravel  http://localhost:8444/supervision     (`panneau-deploy`, bloc de releve)
 *
 * ══ LA REGLE QUI GOUVERNE CETTE SUITE ══════════════════════════════════════
 *
 * **LE GESTE DU LEGACY N'EST JAMAIS DECLENCHE.** `scanAllAgents` itere
 * `#deploy-table-body tr[data-machine-id]` — TOUTES les lignes, filtre ignore —
 * et lance quatre requetes par machine. `srv-zabbix` (id 1) etant en PRODUCTION
 * et presente dans ce tableau, un seul clic la joindrait. Cote legacy, cette
 * suite ne clique donc RIEN : elle LIT ce que le clic aurait vise, et prouve au
 * reseau qu'aucune requete n'est partie.
 *
 * ══ CE QUE LA LECTURE A ETABLI AVANT D'ECRIRE UNE LIGNE ═════════════════════
 *
 *  1. **LE FILTRE NE BORNE PAS LE RELEVE.** `filterDeployTable` pose
 *     `row.style.display = 'none'`, que le selecteur du releve ne regarde pas —
 *     alors que celui de « Tout cocher » le regarde
 *     (`tr:not([style*="display: none"])`). Deux actions de masse voisines, deux
 *     perimetres opposes. C'est la propriete centrale mesuree ici.
 *
 *  2. **DEUX CLES i18n S'AFFICHENT EN IDENTIFIANT.** `scan_all_running` et
 *     `scan_all_done` sont traduites sous `supervision.*`, que `window._i18n`
 *     (peuple par `getJsTranslations('js.')`) ne contient pas. `__()` rend alors
 *     la cle telle quelle, donc le repli `|| 'Scan en cours...'` ne se declenche
 *     JAMAIS. Miroir exact de `supervision.zabbix_server` (V4).
 *
 *  3. **`updateAgentCounter` PORTE UN FRANCAIS EN DUR**, et celui-la est
 *     toujours affiche : `count + '/' + total + ' avec ' + currentPlatform`.
 *
 *  4. **LE COMPTEUR EST EXONERE.** Son `startsWith(letter)` ne confond aucune
 *     plateforme avec le jeu de badges actuel (Z/C/P/T distincts, aucun autre
 *     element arrondi dans la cellule). Le selecteur reste fragile ; il ne
 *     produit pas de faux compte. Dit aussi nettement qu'une accusation.
 *
 * ══ CE QUE LE PORTAGE FAIT, ET COMMENT ON LE MESURE SANS RIEN JOINDRE ═══════
 *
 * Le portage remplace la rafale par une TACHE DE FOND : `POST /supervision/
 * scan-all` rend `{queued, background, task_id}` immediatement, et un unique
 * thread demon balaie le parc SEQUENTIELLEMENT — une seule session SSH par
 * machine pour les quatre plateformes, mesure au journal paramiko (un transport
 * authentifie, canaux 0 a 3).
 *
 * Le clic sur « Relever le parc » N'ENVOIE RIEN : il ouvre un panneau de
 * decision qui CHIFFRE le cout et NOMME les machines de production. La suite
 * clique donc le vrai bouton, puis le vrai bouton de confirmation — mais la
 * requete de confirmation est **INTERCEPTEE ET AVORTEE**. Le geste est exerce de
 * bout en bout, la requete est mesuree (methode, chemin, corps), et aucune
 * machine n'est jointe. Cliquer le bouton sans joindre la production : les deux
 * regles tiennent ensemble.
 *
 * Le contrat de mise en file, lui, se mesure sur une PORTEE EXPLICITE
 * (`machine_ids: [2]`, Test-Server-Debian, DEV) : c'est le seul appel de cette
 * suite qui atteint vraiment le backend, et il ne peut pas joindre la
 * production. La tache creee est supprimee dans un `finally`, et l'etat rendu
 * est ANNONCE.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-supervision-releve.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/supervision' : '/supervision/';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

/** LE GESTE NE SE FAIT QUE COTE PORTAGE. Voir l'en-tete : celui du legacy
 *  joindrait la production. */
const GESTE_AUTORISE = CIBLE === 'laravel';
/** La seule machine que le contrat de mise en file peut atteindre. */
const MACHINE_DEV = 2;
/** Le nom que le parc porte pour la machine de PRODUCTION. */
const NOM_PROD = 'srv-zabbix';

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
function verifie(l, ok, d) { lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }
function verifiePortage(l, ok, d) {
    if (CIBLE === 'laravel') return verifie(l, ok, d);
    constate(l, `ecart assume du legacy — ${d}`);
}

/** Les taches de releve presentes en base, pour rendre l'etat initial. */
function tachesDeReleve() {
    return compteEnBase(
        "SELECT COUNT(*) FROM rootwarden.tasks WHERE task_type = 'supervision_scan'");
}

/*
 * LA SEULE TACHE QUE CETTE SUITE A LE DROIT DE SUPPRIMER EST CELLE QU'ELLE A
 * CREEE. Un premier jet nettoyait PAR TYPE : il aurait efface l'historique d'un
 * releve lance par un exploitant, sans que rien ne le signale. Un nettoyage qui
 * en retire plus qu'il n'en a pose n'est pas un nettoyage.
 */
let tacheCreee = null;
/** Le nombre de taches de releve AVANT la suite : le repere du delta. */
let tachesAvant = 0;

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});

async function connecte(langue) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };
    await page.goto(`${BASE}${chemins.connexion}?lang=${langue}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', 'rw-test-admin', { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    /*
     * LE GARDE ANTI-REJEU TRAVERSE LES EXECUTIONS. Il est par COMPTE et EN BASE :
     * deux passages de cette suite a moins de 30 s d'intervalle rejouent le meme
     * code, et le second est refuse. Mesure : une execution sur trois echouait a
     * la PREMIERE connexion quand on relancait la suite a la chaine.
     *
     * Plutot que de declarer la suite instable — ce qui a deja ete fait a tort
     * pour deux autres suites de ce depot — on attend le basculement de la
     * fenetre et on repropose un code NEUF, une seule fois. Un echec apres cela
     * est un vrai echec.
     */
    for (let essai = 0; essai < 2; essai += 1) {
        const champ = await page.$('input[name="2fa_code"]');
        if (! champ) break;
        if (essai > 0) await dors((resteFenetre() + 1) * 1000);
        await champ.click({ clickCount: 3 });
        await champ.type(totp(SECRET_ADMIN), { delay: 8 });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
    }
    if (chemins.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$('[data-rw="cgu-accepter"]') || await page.$('button[name="accept_terms"]');
        if (b) await b.evaluate(x => x.click());
        try { await nav; } catch {}
    }
    return { ctx, page };
}

/**
 * JAMAIS D'ATTENTE FIXE APRES UN GESTE. Un premier jet dormait 1200 ms apres le
 * clic d'onglet : seule, la suite passait ; DANS LE LOT, sous la charge des
 * autres suites, le script de la page n'avait pas encore pris la main, le clic
 * ne faisait rien, et le panneau restait cache — donc son texte anglais
 * n'existait pas dans `innerText`. Une assertion juste echouait pour une raison
 * qui n'avait rien a voir avec ce qu'elle mesure.
 *
 * On attend donc la PROPRIETE — le panneau est visible — avec une borne, et on
 * re-clique tant qu'elle n'est pas obtenue : c'est le geste qui peut avoir ete
 * perdu, pas seulement son effet.
 */
async function ouvreDeploiement(page) {
    for (let essai = 0; essai < 20; essai += 1) {
        const visible = await page.evaluate(() => {
            const onglet = document.querySelector('.tab-btn[data-tab="deploy"]')
                || document.querySelector('[data-rw="onglet-deploy"]');
            const panneau = document.querySelector('#tab-deploy, [data-rw="panneau-deploy"]');
            if (panneau && panneau.offsetParent !== null) return true;
            onglet?.click();

            return false;
        });
        if (visible) return true;
        await dors(400);
    }

    return false;
}

try {
    constate('cible', `${CIBLE} — ${PAGE}`);
    constate('geste declenche sur cette cible',
        GESTE_AUTORISE ? 'oui (portage)' : 'NON — celui du legacy joindrait la production');
    tachesAvant = tachesDeReleve();
    constate('taches de releve en base a l\'entree', tachesAvant);

    const { ctx, page } = await connecte('fr');
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const dialogues = [];
    page.on('dialog', (d) => { dialogues.push(`${d.type()}: ${d.message().slice(0, 60)}`); d.dismiss().catch(() => {}); });

    /*
     * LE COLLECTEUR EST LA PREUVE DU NON-EFFET. On veut pouvoir dire « aucune
     * requete de releve n'est partie » autrement qu'en le supposant.
     */
    let appels = [];
    page.on('request', (r) => {
        const u = r.url();
        if (/api_proxy\.php\/|\/api\/gateway\//.test(u)) {
            appels.push(r.method() + ' ' + u.replace(BASE, '').slice(0, 80));
        }
    });

    const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie', (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(1800);
    verifie('l\'onglet du parc s\'ouvre', await ouvreDeploiement(page));

    /* ══ 1. LE DECLENCHEUR EXISTE, DES DEUX COTES ═══════════════════════════ */
    const declencheur = await page.evaluate(() => {
        const portage = document.querySelector('[data-rw="superv-relever-parc"]');
        if (portage) return { trouve: true, libelle: portage.textContent.trim() };
        const leg = [...document.querySelectorAll('button')]
            .find((b) => /scanAllAgents/.test(b.getAttribute('onclick') || ''));
        return leg ? { trouve: true, libelle: leg.textContent.trim() } : { trouve: false };
    });
    verifie('le declencheur du releve de parc est present',
        declencheur.trouve, declencheur.libelle || 'absent');

    /* ══ 2. LA PROPRIETE CENTRALE : LE FILTRE BORNE-T-IL LE RELEVE ? ════════
     * Mesuree par LECTURE, jamais par clic. Cote legacy on saisit le filtre et
     * on relit ce que `scanAllAgents` viserait ; cote portage il n'y a ni
     * filtre ni case, et la portee vient du serveur. */
    const portee = await page.evaluate((nomProd) => {
        const f = document.getElementById('deploy-filter');
        if (f) { f.value = 'Test-Server'; f.dispatchEvent(new Event('input')); }
        const lignes = [...document.querySelectorAll('#deploy-table-body tr[data-machine-id]')];
        const visibles = lignes.filter((r) => r.offsetParent !== null);
        // Cote portage : la portee n'est pas dans le DOM, elle est enoncee.
        const cout = document.querySelector('[data-rw="superv-releve-cout"]');
        const prod = document.querySelector('[data-rw="superv-releve-production"]');
        return {
            visees: lignes.length,
            visibles: visibles.length,
            noms: lignes.map((r) => r.querySelector('.deploy-name')?.textContent.trim()),
            cases: document.querySelectorAll('input[name="deploy_machines[]"]').length,
            coutEnonce: cout ? cout.textContent.replace(/\s+/g, ' ').trim() : null,
            prodNommee: prod ? prod.textContent.replace(/\s+/g, ' ').trim() : null,
            prodPresente: (prod?.textContent || '').includes(nomProd),
        };
    }, NOM_PROD);

    if (CIBLE === 'legacy') {
        constate('lignes visibles apres filtre sur « Test-Server »', portee.visibles);
        constate('lignes que le releve viserait quand meme', `${portee.visees} — ${portee.noms.join(', ')}`);
        verifie('le defaut est bien celui qui etait annonce : le filtre NE borne PAS le releve',
            portee.visees > portee.visibles,
            `${portee.visibles} visible(s), ${portee.visees} visee(s)`);
    }
    verifiePortage('aucune case a cocher ne survit dans le tableau de parc',
        portee.cases === 0, `${portee.cases} case(s)`);

    /* ══ 3. LE COUT EST ENONCE AVANT LE GESTE, ET LA PRODUCTION EST NOMMEE ══
     * Le panneau est rendu par le serveur : on peut donc lire son contenu avant
     * tout clic. Le legacy n'a rien de tel — il n'annonce ni le nombre de
     * machines, ni le nombre de sessions, ni que la production est dedans. */
    verifiePortage('le cout du releve est CHIFFRE avant le geste',
        Boolean(portee.coutEnonce) && /\d/.test(portee.coutEnonce || ''),
        portee.coutEnonce || 'rien d\'enonce');
    verifiePortage('les machines de PRODUCTION sont NOMMEES, pas comptees',
        portee.prodPresente,
        portee.prodNommee || `« ${NOM_PROD} » introuvable dans l'avertissement`);

    /* ══ 4. OUVRIR N'EST PAS ENVOYER ════════════════════════════════════════ */
    if (GESTE_AUTORISE) {
        appels = [];
        await page.click('[data-rw="superv-relever-parc"]');
        await dors(700);
        const ouvert = await page.evaluate(() =>
            document.querySelector('[data-rw="superv-panneau-releve"]')?.offsetParent !== null);
        verifie('le declencheur OUVRE un panneau de decision', ouvert);
        verifie('ouvrir le panneau n\'envoie AUCUNE requete',
            appels.length === 0, appels.join(' | ') || 'aucune');
        verifie('aucune boite native ne s\'ouvre a la place',
            dialogues.length === 0, dialogues.join(', ') || 'aucune');

        /* ══ 5. ANNULER N'ENVOIE RIEN NON PLUS ═════════════════════════════ */
        appels = [];
        await page.click('[data-rw="superv-releve-annuler"]');
        await dors(600);
        const referme = await page.evaluate(() =>
            document.querySelector('[data-rw="superv-panneau-releve"]')?.offsetParent === null);
        verifie('annuler referme le panneau', referme);
        verifie('annuler n\'envoie AUCUNE requete',
            appels.length === 0, appels.join(' | ') || 'aucune');

        /* ══ 6. LE VRAI BOUTON DE CONFIRMATION EST CLIQUE — ET LA REQUETE EST
         * AVORTEE. C'est ce qui permet d'exercer le geste jusqu'au bout sans
         * joindre la production : on mesure la requete que le portage EMET
         * (methode, chemin, corps) et elle n'atteint jamais le backend. */
        const interceptee = [];
        await page.setRequestInterception(true);
        const arbitre = (r) => {
            if (/\/api\/gateway\/supervision\/scan-all/.test(r.url())) {
                interceptee.push({
                    methode: r.method(),
                    chemin: r.url().replace(BASE, ''),
                    corps: r.postData() || '',
                });
                r.abort('failed').catch(() => {});

                return;
            }
            r.continue().catch(() => {});
        };
        page.on('request', arbitre);

        await page.click('[data-rw="superv-relever-parc"]');
        await dors(500);
        await page.click('[data-rw="superv-releve-confirmer"]');
        await dors(2500);

        page.off('request', arbitre);
        await page.setRequestInterception(false);

        verifie('confirmer emet UNE seule requete de releve',
            interceptee.length === 1, `${interceptee.length} requete(s)`);
        const req = interceptee[0] || {};
        verifie('la requete est un POST vers la route de parc',
            req.methode === 'POST' && /\/supervision\/scan-all$/.test(req.chemin || ''),
            `${req.methode || '?'} ${req.chemin || '?'}`);
        /*
         * LE CORPS EST VIDE, ET C'EST LA PROPRIETE. La portee vient du SERVEUR.
         * Envoyer une liste d'identifiants lue dans le tableau, c'est le defaut
         * du legacy : sa liste ne correspond plus a ce qui est affiche des qu'on
         * filtre.
         */
        let corpsVide = false;
        try {
            const c = JSON.parse(req.corps || '{}');
            corpsVide = Object.keys(c).length === 0;
        } catch { corpsVide = false; }
        verifie('le corps ne porte AUCUNE liste de machines : la portee vient du serveur',
            corpsVide, `corps « ${(req.corps || '').slice(0, 60)} »`);

        // La requete a echoue (avortee) : le portage doit le DIRE, pas se taire.
        const apresEchec = await page.evaluate(() =>
            document.querySelector('[data-rw="superv-releve-message"]')?.textContent.trim() || '');
        verifie('une requete qui n\'aboutit pas est ANNONCEE',
            apresEchec.length > 0, `« ${apresEchec.slice(0, 70) || 'rien' } »`);
    }

    /* ══ 7. LE CONTRAT DE MISE EN FILE, SUR UNE PORTEE EXPLICITE ════════════
     * Le SEUL appel de cette suite qui atteint le backend. Portee
     * `machine_ids: [2]` — Test-Server-Debian, DEV : la production ne peut pas
     * etre jointe. C'est la propriete que V8 apporte : la reponse est immediate,
     * le balayage continue derriere. */
    if (GESTE_AUTORISE) {
        const contrat = await page.evaluate(async (mid) => {
            const jeton = document.querySelector('meta[name="csrf-token"]');
            const t0 = performance.now();
            const r = await fetch('/api/gateway/supervision/scan-all', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': jeton ? jeton.content : '',
                },
                body: JSON.stringify({ machine_ids: [mid] }),
            });
            const ms = performance.now() - t0;
            let corps = null;
            try { corps = await r.json(); } catch { corps = null; }

            return { statut: r.status, ms: Math.round(ms), corps };
        }, MACHINE_DEV);

        if (Number.isInteger(contrat.corps?.task_id)) tacheCreee = contrat.corps.task_id;
        constate('appel porte a la route de parc',
            `statut ${contrat.statut} en ${contrat.ms} ms`);
        verifie('la route de parc repond IMMEDIATEMENT, sans tenir la connexion',
            contrat.statut === 200 && contrat.ms < 5000, `${contrat.ms} ms`);
        verifie('la reponse annonce une mise en file, pas un resultat',
            contrat.corps?.background === true && contrat.corps?.queued === 1,
            `background=${contrat.corps?.background} queued=${contrat.corps?.queued}`);
        verifie('une tache est creee et son identifiant est rendu',
            Number.isInteger(contrat.corps?.task_id) && contrat.corps.task_id > 0,
            `task_id=${contrat.corps?.task_id}`);

        const enBase = litEnBase(
            "SELECT CONCAT(task_type, '|', status) FROM rootwarden.tasks "
            + `WHERE id = ${Number(contrat.corps?.task_id) || 0}`)[0] || '(AUCUNE LIGNE)';
        verifie('la tache existe en base sous son propre type',
            enBase.startsWith('supervision_scan|'), enBase);
    }

    /* ══ 8. LES CLES QUI S'AFFICHENT EN IDENTIFIANT ═════════════════════════
     * Resolues dans la page, sans declencher le releve : c'est une lecture de
     * `window._i18n`, aucune requete. */
    const i18n = await page.evaluate(() => {
        if (typeof __ !== 'function') return null;

        return {
            scan_all_running: __('scan_all_running'),
            scan_all_done: __('scan_all_done'),
            select_machine: __('select_machine'),
        };
    });
    if (i18n) {
        constate('resolution des cles du chemin de releve',
            Object.entries(i18n).map(([k, v]) => `${k} -> « ${v} »`).join(' | '));
        verifie('`select_machine` est bien traduite (exoneration mesuree)',
            i18n.select_machine !== 'select_machine', `« ${i18n.select_machine} »`);
    }

    const texte = await page.evaluate(() => document.body.innerText);
    const cassees = ['scan_all_running', 'scan_all_done']
        .filter((c) => (i18n ? i18n[c] === c : false) || texte.includes(c));
    verifiePortage('aucune cle du chemin de releve ne s\'affiche en identifiant',
        cassees.length === 0, cassees.join(', ') || 'aucune');

    /* ══ 9. LE FRANCAIS EN DUR DU COMPTEUR ══════════════════════════════════ */
    const compteur = await page.evaluate(() =>
        document.getElementById('agent-counter')?.textContent.trim() || null);
    if (compteur !== null) constate('compteur d\'agents rendu par le legacy', `« ${compteur} »`);
    /*
     * GARDE TOURNEE VERS L'AVENIR, et elle le dit. Le portage n'a pas de
     * compteur d'agents : cette assertion ne mesure donc rien aujourd'hui, elle
     * echouera le jour ou l'on en portera un avec un mot francais concatene dans
     * le script, comme le legacy le fait (` avec `). Le nommer evite de la
     * prendre pour une mesure.
     */
    verifiePortage('aucun libelle francais en dur dans le compteur',
        compteur === null || ! / avec /.test(compteur),
        compteur ? `« ${compteur} »` : 'pas de compteur dans le portage — garde pour le jour ou il y en aura un');

    /* ══ 10. AUCUN IDENTIFIANT DE TRADUCTION A L'ECRAN, DANS LES DEUX LANGUES ══ */
    verifie('aucun identifiant de traduction a l\'ecran (fr)',
        ! /superv\.[a-z_]+/.test(texte), (texte.match(/superv\.[a-z_]+/g) || []).slice(0, 3).join(', '));
    await ctx.close();

    /*
     * LE GARDE ANTI-REJEU TOTP EST PAR COMPTE ET EN BASE : il TRAVERSE les
     * contextes de navigateur. Se reconnecter avec le meme compte dans la MEME
     * fenetre de 30 s rejoue le code deja consomme, la seconde session n'est pas
     * authentifiee, et la page servie est celle de connexion. Le premier jet ne
     * le voyait pas : ses controles i18n passaient sur l'ecran de connexion, qui
     * ne porte evidemment aucun identifiant de traduction. Un PASS dont on ne
     * sait pas pourquoi il passe ne vaut rien.
     *
     * On attend donc le basculement de la fenetre, ET on assert que la session a
     * tenu — sans quoi tout ce qui suit mesurerait la mauvaise page.
     */
    await dors((resteFenetre() + 1) * 1000);
    const { ctx: ctxEn, page: pageEn } = await connecte('en');
    await pageEn.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await dors(1500);
    const urlEn = pageEn.url();
    verifie('la seconde session (en) est bien authentifiee',
        ! /connexion|login/.test(urlEn), urlEn.replace(BASE, ''));
    verifie('l\'onglet du parc s\'ouvre (en)', await ouvreDeploiement(pageEn));
    const texteEn = await pageEn.evaluate(() => document.body.innerText);
    verifie('aucun identifiant de traduction a l\'ecran (en)',
        ! /superv\.[a-z_]+/.test(texteEn),
        (texteEn.match(/superv\.[a-z_]+/g) || []).slice(0, 3).join(', '));
    /*
     * LE DETAIL EST IMPRIME AU PASS COMME AU FAIL : il doit dire ce qu'on a
     * TROUVE, pas presumer l'echec. Un premier jet rendait
     * « PASS ... — aucun libelle anglais du releve », qui se lit comme une
     * contradiction et fait douter d'une assertion juste.
     */
    const anglais = (texteEn.match(/Survey the fleet|Start the survey|PRODUCTION machines/g) || []);
    verifiePortage('le bloc de releve est traduit en anglais',
        anglais.length > 0,
        anglais.length > 0 ? `trouve : ${anglais.join(', ')}` : 'aucun libelle anglais du releve');
    await ctxEn.close();

    verifie('aucune erreur JS pendant toute la sequence',
        erreursJs.length === 0, erreursJs.slice(0, 3).join(' · ') || 'aucune');
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
} finally {
    /*
     * L'ETAT EST RENDU, ET IL EST ANNONCE. La seule ecriture de cette suite est
     * la tache creee par l'appel porte ; elle est supprimee ici. Les lignes
     * d'agents ne sont PAS touchees : le releve porte sur Test-Server-Debian, ou
     * aucun agent n'est installe, donc il n'en cree aucune.
     */
    if (tacheCreee !== null) {
        litEnBase(`DELETE FROM rootwarden.tasks WHERE id = ${Number(tacheCreee)} `
            + "AND task_type = 'supervision_scan'");
        lignes.push(`INFO  tache creee par cette suite, supprimee en sortie : #${tacheCreee}`);
    } else {
        lignes.push('INFO  aucune tache creee par cette suite, rien a supprimer');
    }
    /*
     * LA PROPRIETE EST UN DELTA, PAS UN ZERO. Les taches presentes AVANT ne sont
     * pas les siennes : les compter comme un echec ferait echouer la suite sur
     * l'historique de quelqu'un d'autre.
     */
    const restant = tachesDeReleve();
    lignes.push(`${restant === tachesAvant ? 'PASS' : 'FAIL'}  la suite ne laisse aucune `
        + `tache derriere elle  — ${tachesAvant} a l'entree, ${restant} en sortie`);
    if (restant !== tachesAvant) echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
