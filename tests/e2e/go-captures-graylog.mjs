/**
 * go-captures-graylog.mjs - La page de transfert des journaux, EN IMAGES, aux
 * trois largeurs de la convention : 1920, 1400 et 390.
 *
 * Deux etats sont photographies, parce que le second porte la correction du
 * sous-lot :
 *
 *   1. l'onglet CONFIGURATION — les reglages de flotte et l'encart qui dit ce
 *      que les boutons font vraiment ;
 *   2. l'onglet MACHINES avec une CONFIRMATION OUVERTE sur « Tester ». C'est la
 *      correction : le legacy execute ce geste sans rien demander.
 *
 * ══ AUCUNE FIXTURE, ET AUCUN GESTE ═════════════════════════════════════════
 *
 * Rien n'est ecrit : la configuration, les quatre gabarits et le parc existent
 * deja. Le seul clic qui touche une ligne est celui qui OUVRE le panneau de
 * confirmation — `ouvreConfirmation` ne fait que rendre du DOM, il n'emet
 * aucune requete. Le bouton « Confirmer » n'est JAMAIS clique.
 *
 * Et la ligne choisie est celle de `test-server`, jamais celle de `srv-zabbix` :
 * meme si ouvrir un panneau est inerte, viser la production pour une capture
 * serait prendre l'habitude inverse de celle qu'on veut.
 *
 * Usage :
 *   cd tests/e2e && node go-captures-graylog.mjs
 */
import puppeteer from 'puppeteer';
import { mkdirSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { litEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const SORTIE = './screenshots/graylog';
/** La machine du banc. Jamais `srv-zabbix` (id 1). */
const MACHINE_SURE = /test-server/i;

const LARGEURS = [
    { nom: 'grand', width: 1920, height: 1080 },
    { nom: 'bureau', width: 1400, height: 900 },
    { nom: 'mobile', width: 390, height: 844 },
];

let echecs = 0;
function note(l) { console.log(l); }
function verifie(l, ok, d) { note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { note(`INFO  ${l} : ${v}`); }

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

/** Le contraste RENDU, pas la classe posee — trois defauts n'ont ete vus qu'ainsi. */
const MESURE_CONTRASTE = () => {
    function canal(v) { const c = v / 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); }
    function lum(rgb) { const [r, g, b] = rgb; return (0.2126 * canal(r)) + (0.7152 * canal(g)) + (0.0722 * canal(b)); }
    function lit(c) { const m = String(c).match(/\d+(\.\d+)?/g); return m ? m.slice(0, 3).map(Number) : null; }
    function fond(e) {
        let n = e;
        while (n) {
            const c = getComputedStyle(n).backgroundColor;
            const v = lit(c);
            const transparent = /rgba\([^)]*,\s*0\s*\)/.test(c) || c === 'transparent';
            if (v && ! transparent) return v;
            n = n.parentElement;
        }

        return [255, 255, 255];
    }
    function rapport(e) {
        if (! e) return null;
        const t = lit(getComputedStyle(e).color);
        if (! t) return null;
        const a = lum(t); const b = lum(fond(e));

        return Math.round(((Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)) * 100) / 100;
    }

    return {
        ongletActif: rapport(document.querySelector('.rw-onglet--actif')),
        pastille: rapport(document.querySelector('[data-rw="graylog-serveurs"] .rw-pastille')),
        encart: rapport(document.querySelector('.rw-encart')),
    };
};

mkdirSync(SORTIE, { recursive: true });
let navigateur = null;

try {
    litEnBase('DELETE FROM rootwarden.login_attempts');

    navigateur = await puppeteer.launch({
        headless: 'new',
        args: ['--ignore-certificate-errors', '--allow-insecure-localhost'],
        protocolTimeout: 120000,
    });

    for (const format of LARGEURS) {
        const ctx = await navigateur.createBrowserContext();
        const page = await ctx.newPage();
        await page.setViewport({ width: format.width, height: format.height });
        page.setDefaultTimeout(40000);
        const boites = [];
        page.on('dialog', async (d) => { boites.push(d.type()); try { await d.accept(); } catch {} });

        await page.goto(`${BASE}/connexion?lang=fr`, { waitUntil: 'networkidle2' });
        await page.type('input[name="username"]', COMPTE, { delay: 8 });
        await page.type('input[name="password"]', MDP, { delay: 8 });
        let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
        if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
        for (let essai = 0; essai < 2; essai += 1) {
            const champ = await page.$('input[name="2fa_code"]');
            if (! champ) break;
            if (essai > 0) await dors((resteFenetre() + 1) * 1000);
            await champ.click({ clickCount: 3 });
            await champ.type(totp(SECRET), { delay: 8 });
            nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
            await page.click('button[type="submit"]'); try { await nav; } catch {}
        }
        if (/\/cgu/.test(page.url())) {
            nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
            const b = await page.$('[data-rw="cgu-accepter"]');
            if (b) await b.evaluate((x) => x.click());
            try { await nav; } catch {}
        }

        await page.goto(`${BASE}/graylog`, { waitUntil: 'networkidle2' });
        await dors(1400);

        /* ── 1. Configuration ─────────────────────────────────────────────── */
        const vuConfig = await page.evaluate(() => ({
            hote: (document.querySelector('[data-rw="graylog-hote"]') || {}).value,
            encart: !! document.querySelector('.rw-encart'),
            debordePage: document.documentElement.scrollWidth > window.innerWidth + 1,
        }));
        constate(`[${format.nom}] configuration`, `hote « ${vuConfig.hote} », encart=${vuConfig.encart}`);
        verifie(`[${format.nom}] la configuration est pre-remplie`, !! vuConfig.hote, vuConfig.hote);
        verifie(`[${format.nom}] l'encart d'avertissement est present`, vuConfig.encart === true);
        verifie(`[${format.nom}] la page ne defile pas horizontalement`,
            vuConfig.debordePage === false, `deborde=${vuConfig.debordePage}`);
        await page.screenshot({ path: `${SORTIE}/${format.nom}-graylog-config.png`, fullPage: true });
        constate(`[${format.nom}] capture`, `${SORTIE}/${format.nom}-graylog-config.png`);

        /* ── 2. Machines, avec la confirmation de « Tester » ouverte ───────── */
        await page.click('[data-rw="graylog-onglet-deploy"]');
        for (let i = 0; i < 40; i += 1) {
            const pret = await page.evaluate(() => {
                const e = document.querySelector('[data-rw="graylog-serveurs"]');

                return e && ! /chargement|loading/i.test(e.textContent || '');
            });
            if (pret) break;
            await dors(250);
        }

        /*
         * OUVRIR la confirmation de « Tester » sur la ligne du BANC. Ce clic ne
         * fait que rendre du DOM : `ouvreConfirmation` n'emet aucune requete. Le
         * bouton « Confirmer » n'est jamais touche.
         */
        const ouvert = await page.evaluate((motif) => {
            const lignes = Array.from(
                document.querySelectorAll('[data-rw="graylog-serveurs"] tbody tr'));
            const ligne = lignes.find((tr) => new RegExp(motif, 'i').test(tr.textContent || ''));
            if (! ligne) return null;
            const b = ligne.querySelector('[data-rw="graylog-machine-test"]');
            if (! b) return null;
            b.click();

            return (ligne.cells[0] || {}).textContent || '';
        }, MACHINE_SURE.source);
        await dors(500);

        const vuPanneau = await page.evaluate(() => {
            const p = document.querySelector('[data-rw="graylog-panneau-machine"]');

            return {
                present: !! p,
                texte: p ? (p.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 160) : '',
                confirmer: !! document.querySelector('[data-rw="graylog-machine-confirmer"]'),
            };
        });
        constate(`[${format.nom}] ligne visee`, String(ouvert));
        constate(`[${format.nom}] panneau de confirmation`, vuPanneau.texte || '(absent)');
        verifie(`[${format.nom}] « Tester » ouvre une confirmation EN PAGE`,
            vuPanneau.present === true && vuPanneau.confirmer === true,
            `present=${vuPanneau.present} bouton=${vuPanneau.confirmer}`);
        verifie(`[${format.nom}] la confirmation NOMME la machine`,
            MACHINE_SURE.test(vuPanneau.texte), vuPanneau.texte);
        verifie(`[${format.nom}] aucune boite native n'est apparue`, boites.length === 0,
            boites.join(', ') || 'aucune');

        /*
         * LE PANNEAU OCCUPE-T-IL LA LARGEUR DE LA LIGNE ?
         *
         * Assertion ajoutee apres avoir vu le defaut A L'IMAGE : le conteneur
         * flex etait pose SUR le `<td>`, ce qui sortait la cellule du modele de
         * tableau et faisait ignorer son `colspan`. Le panneau s'arretait au
         * tiers de la largeur, le reste de la ligne restant blanc — et
         * l'attribut `colSpan` valait bien 6, donc aucune assertion DOM ne
         * pouvait le voir. On mesure la largeur RENDUE, rapportee a celle du
         * tableau.
         */
        const largeurs = await page.evaluate(() => {
            const table = document.querySelector('[data-rw="graylog-serveurs"] table');
            const panneau = document.querySelector('[data-rw="graylog-panneau-machine"] .rw-panneau-decision');
            if (! table || ! panneau) return null;

            return {
                table: Math.round(table.getBoundingClientRect().width),
                panneau: Math.round(panneau.getBoundingClientRect().width),
            };
        });
        constate(`[${format.nom}] largeur panneau / tableau`,
            largeurs ? `${largeurs.panneau} / ${largeurs.table} px` : '(introuvable)');
        verifie(`[${format.nom}] le panneau occupe la largeur de la ligne`,
            largeurs !== null && largeurs.panneau >= largeurs.table * 0.9,
            largeurs ? `${largeurs.panneau} px sur ${largeurs.table} px` : 'introuvable');

        const contrastes = await page.evaluate(MESURE_CONTRASTE);
        constate(`[${format.nom}] contrastes`,
            `onglet ${contrastes.ongletActif}:1 · pastille ${contrastes.pastille}:1 · encart ${contrastes.encart}:1`);
        for (const [nom, valeur] of Object.entries(contrastes)) {
            verifie(`[${format.nom}] « ${nom} » est lisible (>= 4,5:1)`,
                valeur !== null && valeur >= 4.5, `${valeur}:1`);
        }

        await page.screenshot({ path: `${SORTIE}/${format.nom}-graylog-machines.png`, fullPage: true });
        constate(`[${format.nom}] capture`, `${SORTIE}/${format.nom}-graylog-machines.png`);

        /* ── 3. L'AVERTISSEMENT D'UN RETRAIT ECHOUE ────────────────────────
         *
         * C'est le produit VISIBLE du correctif de v1.37.78 : avant lui la route
         * rendait `success: true` et marquait la machine « non deployee », donc
         * l'ecran affirmait un retrait qui pouvait n'avoir rien fait.
         *
         * Le geste est reellement emis, sur la machine 2 uniquement, et il echoue
         * naturellement — le banc est un conteneur sans `systemctl`. Rien n'est
         * supprime puisque rien n'etait la : mesure faite avant d'ecrire cette
         * capture, et le `finally` de `go-page-graylog-g2.mjs` le reverifie.
         */
        /*
         * REFERMER LE PANNEAU DE « TESTER » AVANT D'EN OUVRIR UN AUTRE.
         *
         * Defaut mesure le 2026-08-26 : `ouvreConfirmation` refuse d'ouvrir un
         * second panneau tant que le premier est la
         * (`if (ligne.nextElementSibling?.dataset.rw === …) return`). Le panneau de
         * « Tester » etant reste ouvert pour la capture precedente, le clic sur
         * « Retirer » ne le remplacait pas — et le clic suivant sur « Confirmer »
         * validait donc LE TEST.
         *
         * L'assertion, elle, lisait l'identifiant du bouton « Retirer » et passait :
         * elle mesurait le bouton CLIQUE et non le panneau CONFIRME. C'est la meme
         * faute que « jamais le premier bouton de la page », deplacee d'un cran.
         */
        const ferme = await page.$('[data-rw="graylog-machine-annuler"]');
        if (ferme) { await ferme.click(); await dors(400); }

        const vise = await page.evaluate((motif) => {
            const lignes = Array.from(
                document.querySelectorAll('[data-rw="graylog-serveurs"] tbody tr'));
            const ligne = lignes.find((tr) => new RegExp(motif, 'i').test(tr.textContent || ''));
            if (! ligne) return null;
            const b = ligne.querySelector('[data-rw="graylog-machine-uninstall"]');
            if (! b) return null;
            b.click();

            return b.dataset.machine;
        }, MACHINE_SURE.source);
        verifie(`[${format.nom}] le retrait vise la machine du banc`, String(vise) === '2',
            `vise ${vise}`);
        if (String(vise) === '2') {
            await page.waitForSelector('[data-rw="graylog-machine-confirmer"]',
                { visible: true, timeout: 10000 });
            /*
             * ET ON VERIFIE QUE LE PANNEAU EST BIEN CELUI DU RETRAIT avant de le
             * confirmer. Sans ce controle, un panneau reste ouvert d'un autre geste
             * ferait executer cet autre geste — c'est exactement ce qui est arrive.
             * Le titre est le seul element qui distingue les trois panneaux.
             */
            const titre = await page.evaluate(() => {
                const p = document.querySelector('[data-rw="graylog-panneau-machine"] strong');

                return p ? (p.textContent || '').trim() : '';
            });
            constate(`[${format.nom}] panneau ouvert`, titre || '(sans titre)');
            verifie(`[${format.nom}] le panneau confirme est bien celui du RETRAIT`,
                /retirer|remove/i.test(titre), titre || '(sans titre)');
            if (! /retirer|remove/i.test(titre)) {
                await ctx.close();
                continue;
            }
            await page.click('[data-rw="graylog-machine-confirmer"]');
            await dors(8000);
            const message = await page.evaluate(() => {
                const e = document.querySelector('[data-rw="graylog-machines-etat"]');

                return e ? (e.textContent || '').trim() : '';
            });
            constate(`[${format.nom}] avertissement rendu`, message.slice(0, 90) || '(vide)');
            verifie(`[${format.nom}] l'avertissement dit que le transfert peut durer`,
                /encore actif|still be active/i.test(message), message.slice(0, 90) || '(vide)');
            await page.screenshot({ path: `${SORTIE}/${format.nom}-graylog-retrait-echoue.png`,
                                    fullPage: true });
            constate(`[${format.nom}] capture`, `${SORTIE}/${format.nom}-graylog-retrait-echoue.png`);
        }

        await ctx.close();
    }
} catch (e) {
    verifie('deroulement du script', false, String(e.message || e).split('\n')[0]);
} finally {
    if (navigateur) { try { await navigateur.close(); } catch { /* rien */ } }
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* rien */ }
    note(`\n${echecs} FAIL`);
    process.exit(echecs === 0 ? 0 : 1);
}
