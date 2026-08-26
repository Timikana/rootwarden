/**
 * go-page-graylog-g2.mjs - `graylog/` sous-lot G2 : les TROIS gestes qui ouvrent
 * une session SSH reelle sur une machine.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/graylog/index.php
 *   laravel  http://localhost:8444/graylog
 *
 * ══ CE QUE G1 AVAIT LAISSE, ET POURQUOI ═════════════════════════════════════
 *
 * G1 a mesure la configuration, les gabarits, les onglets et les gardes. Elle
 * ouvrait l'onglet Machines et LISAIT le tableau sans cliquer aucun bouton de
 * ligne : `glTest` (legacy, js:100) n'a pas de `confirm()`, donc un seul clic y
 * ouvre une session SSH sur la machine de la ligne — et `srv-zabbix` figure dans
 * ce tableau. G2 est le sous-lot qui leve cette reserve, et il ne peut le faire
 * qu'en NOMMANT sa cible.
 *
 * ══ LE BANC A ETE MESURE AVANT D'ECRIRE CETTE SUITE ════════════════════════
 *
 * Releve sur `rootwarden_test_server` (machine 2) le 2026-08-26, AVANT la
 * premiere ligne — et il a fait abandonner le plan initial, qui prevoyait un
 * gabarit volontairement invalide pour atteindre la branche d'echec :
 *
 *   command -v rsyslogd      absent
 *   command -v systemctl     ABSENT — le banc est un conteneur sans systemd
 *   command -v logger        present
 *   apt-get install -s -y    « E: Unable to locate package rsyslog » (pas de DNS)
 *   port 22 depuis python    ouvert
 *
 * Consequence : LES DEUX BRANCHES D'ECHEC SONT ATTEIGNABLES NATURELLEMENT, ET
 * SANS RIEN MUTER.
 *
 *   `deploy`    echoue a sa PREMIERE commande — le paquet est introuvable — donc
 *               la route rend 500 AVANT d'ecrire quoi que ce soit : ni fichier
 *               sur la machine, ni ligne dans `graylog_rsyslog` ;
 *   `uninstall` fait `rm -f <confs> && systemctl restart rsyslog`. Le `rm -f`
 *               reussit sur des fichiers absents, puis `systemctl` n'existe pas,
 *               donc la chaine echoue.
 *
 * Je cherchais comment RENDRE la branche d'echec atteignable sans degat ; ce banc
 * ne permet QUE les branches d'echec. C'est un cas ou la contrainte du banc rend
 * le test plus sur que ce qu'on avait prevu, et il faut le dire plutot que de
 * faire croire a une precaution qu'on n'a pas eu a prendre.
 *
 * ══ CE QUI EST MESURE ICI, ET CE QUI NE PEUT PAS L'ETRE ════════════════════
 *
 *   ici, au navigateur   ouvrir une confirmation n'emet AUCUNE requete (x3)
 *                        `deploy` echoue n'ecrit AUCUN etat
 *                        `uninstall` echoue rend 500 et NE TOUCHE PAS l'etat
 *                        `uninstall` echoue AVERTIT que le transfert peut durer
 *                        `test` ouvre une vraie session SSH et execute `logger`
 *
 *   impossible ici       `deploy` REUSSI marque et date le transfert
 *                        syntaxe invalide, redemarrage echoue
 *                        -> couverts par `backend/tests/test_graylog_etat.py`,
 *                           qui n'est donc PAS redondant avec cette suite
 *
 * ══ LA CIBLE, ET CE QUI EST INTERDIT ══════════════════════════════════════
 *
 * `test-server` (machine 2) pour tout clic qui aboutit. `srv-zabbix` (id 1) :
 * JAMAIS. La suite refuse de demarrer si elle ne trouve pas la ligne du banc, et
 * elle verifie a chaque geste que l'identifiant vise est bien le sien — un
 * tableau reordonne ne doit pas pouvoir deplacer un clic sur la production.
 *
 * Usage :
 *   cd tests/e2e && node go-page-graylog-g2.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

/** Role 3 : il contourne `checkPermission`, donc il atteint la page. */
const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';

/** La machine du banc. Le nom est un MOTIF : le tableau affiche `Test-Server-Debian`. */
const MACHINE_ID = 2;
const MACHINE_MOTIF = /test-server/i;
/** La machine de production. Elle ne doit JAMAIS etre visee. */
const MACHINE_INTERDITE = 1;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion?lang=fr',
        page: '/graylog',
        ongletMachines: '[data-rw="graylog-onglet-deploy"]',
        serveurs: '[data-rw="graylog-serveurs"]',
        bouton: (geste) => `[data-rw="graylog-machine-${geste}"]`,
        panneau: '[data-rw="graylog-panneau-machine"]',
        confirmer: '[data-rw="graylog-machine-confirmer"]',
        annuler: '[data-rw="graylog-machine-annuler"]',
        etat: '[data-rw="graylog-machines-etat"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/graylog/index.php',
        ongletMachines: '.tab-btn[data-tab="deploy"]',
        serveurs: '#gl-servers-container',
        /* Le legacy pose ses trois boutons par `onclick="glDeploy(<id>)"` : il n'y
         * a aucun attribut stable, donc on les retrouve par leur appel. C'est
         * fragile par nature — et c'est precisement ce que le portage corrige. */
        bouton: (geste) => ({ deploy: 'glDeploy', test: 'glTest', uninstall: 'glUninstall' }[geste]),
        panneau: null,
        confirmer: null,
        annuler: null,
        etat: null,
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
function verifie(l, ok, d) { note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { note(`INFO  ${l} : ${v}`); }
function verifiePortage(l, ok, d) {
    if (CIBLE === 'laravel') return verifie(l, ok, ok ? '' : d);
    constate(l, `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

/* ── L'etat en base, lu et non suppose ────────────────────────────────────── */

/** L'etat de transfert d'une machine, ou `(absente)` si aucune ligne. */
function etatEnBase(machineId) {
    const r = litEnBase('SELECT CONCAT(IFNULL(forward_deployed,\'?\'),\'|\','
        + "IFNULL(rsyslog_version,'?'),'|',IFNULL(last_deploy_at,'jamais')) "
        + `FROM rootwarden.graylog_rsyslog WHERE machine_id = ${machineId}`);

    return r[0] || '(absente)';
}
function compteLignesEtat() {
    return compteEnBase('SELECT COUNT(*) FROM rootwarden.graylog_rsyslog');
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});
const contextes = [];

/**
 * Une session, avec DEUX compteurs qui servent aux assertions les plus
 * importantes de cette suite :
 *
 *   `requetes`  toutes les requetes partant vers la passerelle ou le proxy. Une
 *               confirmation qui s'ouvre ne doit RIEN y ajouter ;
 *   `boites`    les boites natives. Le legacy en pose, le portage n'en pose pas.
 */
async function connecte(nom, secret) {
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(60000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const boites = [];
    page.on('dialog', async (d) => {
        boites.push(`${d.type()}: ${(d.message() || '').slice(0, 50)}`);
        try { await d.accept(); } catch { /* deja fermee */ }
    });
    const requetes = [];
    page.on('request', (r) => {
        const u = r.url();
        if (/api_proxy\.php|\/api\/gateway/.test(u) && r.method() !== 'GET') {
            requetes.push(`${r.method()} ${u.replace(BASE, '')}`);
        }
    });

    await page.goto(`${BASE}${C.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    for (let essai = 0; essai < 2; essai += 1) {
        const champ = await page.$('input[name="2fa_code"]');
        if (! champ) break;
        if (essai > 0) await dors((resteFenetre() + 1) * 1000);
        await champ.click({ clickCount: 3 });
        await champ.type(totp(secret), { delay: 8 });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
    }
    if (C.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$(C.accepte);
        if (b) await b.evaluate((x) => x.click());
        try { await nav; } catch {}
    }

    return { ctx, page, erreursJs, boites, requetes };
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

/** Attendre que le tableau des machines soit charge ET stable. */
async function attendTableau(page) {
    let precedent = null;
    for (let i = 0; i < 60; i += 1) {
        const t = await page.evaluate((s) => {
            const e = document.querySelector(s);

            return e ? (e.textContent || '').replace(/\s+/g, ' ').trim() : null;
        }, C.serveurs);
        if (t && ! /chargement|loading/i.test(t) && t === precedent) return t;
        precedent = t;
        await dors(250);
    }

    return precedent;
}

/**
 * Clique le bouton `geste` SUR LA LIGNE DU BANC, et rend l'identifiant reellement
 * vise pour qu'il puisse etre asserte.
 *
 * LE POINT IMPORTANT : on ne clique pas « le premier bouton `test` de la page ».
 * On retrouve la LIGNE par le nom de la machine, puis le bouton DANS cette ligne,
 * et on relit l'identifiant que le bouton porte. Un tableau reordonne ne peut donc
 * pas deplacer un clic sur `srv-zabbix`.
 */
function cliqueSurLeBanc(page, geste) {
    if (CIBLE === 'laravel') {
        return page.evaluate((motif, sel, selBouton) => {
            const lignes_ = Array.from(document.querySelectorAll(`${sel} tbody tr`));
            const ligne = lignes_.find((tr) => new RegExp(motif, 'i').test(tr.textContent || ''));
            if (! ligne) return { vise: null, raison: 'ligne du banc introuvable' };
            const b = ligne.querySelector(selBouton);
            if (! b) return { vise: null, raison: 'bouton introuvable dans la ligne' };
            b.click();

            return { vise: b.dataset.machine, libelle: (b.textContent || '').trim() };
        }, MACHINE_MOTIF.source, C.serveurs, C.bouton(geste));
    }

    /* Le legacy n'a aucun attribut stable : ses boutons portent
     * `onclick="glDeploy(2)"`. On lit donc l'identifiant DANS l'appel, ce qui est
     * la seule facon de savoir qui est vise — et c'est exactement la fragilite que
     * le portage supprime en posant `data-machine`. */
    return page.evaluate((motif, sel, appel) => {
        const lignes_ = Array.from(document.querySelectorAll(`${sel} table tr`));
        const ligne = lignes_.find((tr) => new RegExp(motif, 'i').test(tr.textContent || ''));
        if (! ligne) return { vise: null, raison: 'ligne du banc introuvable' };
        const b = Array.from(ligne.querySelectorAll('button'))
            .find((x) => (x.getAttribute('onclick') || '').startsWith(appel + '('));
        if (! b) return { vise: null, raison: `aucun bouton ${appel} dans la ligne` };
        const m = (b.getAttribute('onclick') || '').match(/\((\d+)\)/);
        b.click();

        return { vise: m ? m[1] : null, libelle: (b.textContent || '').trim() };
    }, MACHINE_MOTIF.source, C.serveurs, C.bouton(geste));
}

const etatAuDepart = etatEnBase(MACHINE_ID);
const lignesAuDepart = compteLignesEtat();
const etatProdAuDepart = etatEnBase(MACHINE_INTERDITE);

try {
    constate('cible', `${CIBLE} — ${BASE}`);
    constate('etat du banc au depart', etatAuDepart);
    constate('lignes dans graylog_rsyslog', `${lignesAuDepart}`);
    litEnBase('DELETE FROM rootwarden.login_attempts');

    /* ══ Le constat d'archivage, en tete ══════════════════════════════════ */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE,
            chemin: '/graylog/',
            fichiers: ['/graylog/index.php', '/graylog/js/graylog.js'],
            verifie, constate,
        });
        if (archivee) {
            const s = await connecte(COMPTE, SECRET);
            await verifieMenuLegacy(s.page, '/graylog', verifie);
            for (const ctx of contextes) { try { await ctx.close(); } catch {} }
            await navigateur.close();
            note('');
            note(`${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
            process.exit(echecs > 0 ? 1 : 0);
        }
    }

    const s = await connecte(COMPTE, SECRET);

    await etape('la page et le tableau des machines', async () => {
        const r = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        verifie('la page graylog est servie', r && r.status() === 200,
            `HTTP ${r ? r.status() : 0}`);
        await s.page.click(C.ongletMachines);
        const texte = await attendTableau(s.page);
        constate('tableau', (texte || '').slice(0, 130));
        verifie('la ligne du banc est presente', MACHINE_MOTIF.test(texte || ''),
            (texte || '').slice(0, 130));
        /* Refuser de continuer plutot que de cliquer au hasard : sans la ligne du
         * banc, tout clic viserait une autre machine. */
        if (! MACHINE_MOTIF.test(texte || '')) {
            throw new Error('refus : la ligne du banc est absente, aucun clic ne peut etre sur');
        }
    });

    /* ══ OUVRIR UNE CONFIRMATION N'EMET AUCUNE REQUETE ═══════════════════ */
    for (const geste of ['deploy', 'test', 'uninstall']) {
        await etape(`« ${geste} » : ouvrir la confirmation n'emet AUCUNE requete`, async () => {
            /*
             * LE COMPTEUR EST RELEVE JUSTE AVANT LE CLIC, jamais au debut de
             * l'etape : le geste precedent a pu emettre, et une borne perimee
             * fait dire n'importe quoi a une difference.
             */
            const avant = s.requetes.length;
            const r = await cliqueSurLeBanc(s.page, geste);
            await dors(900);
            const emises = s.requetes.slice(avant);

            constate(`[${geste}] identifiant vise`, `${r.vise} (${r.libelle || r.raison || '—'})`);
            verifie(`[${geste}] le clic vise bien la machine du banc`,
                String(r.vise) === String(MACHINE_ID),
                `vise « ${r.vise} », attendu ${MACHINE_ID}`);
            verifie(`[${geste}] et JAMAIS la machine de production`,
                String(r.vise) !== String(MACHINE_INTERDITE), `vise ${r.vise}`);

            constate(`[${geste}] requetes emises par l'ouverture`, emises.join(' | ') || 'aucune');
            verifiePortage(`[${geste}] ouvrir la confirmation n'emet aucune requete`,
                emises.length === 0,
                'le legacy n\'a pas de panneau : `glTest` part au premier clic sans rien '
                + 'demander, et `glDeploy`/`glUninstall` derriere un `confirm()` natif que '
                + 'le gestionnaire de dialogue accepte — donc la requete part aussi');

            if (CIBLE === 'laravel') {
                const vu = await s.page.evaluate((sel, selC) => ({
                    panneau: !! document.querySelector(sel),
                    confirmer: !! document.querySelector(selC),
                }), C.panneau, C.confirmer);
                verifie(`[${geste}] un panneau de decision s'ouvre EN PAGE`,
                    vu.panneau && vu.confirmer, `panneau=${vu.panneau} bouton=${vu.confirmer}`);
                /* Refermer avant le geste suivant : deux panneaux ouverts en meme
                 * temps rendraient le suivant introuvable. */
                await s.page.click(C.annuler);
                await dors(300);
            }
        });
    }

    /* ══ LE GESTE QUI ABOUTIT : `deploy` echoue AVANT toute ecriture ══════ */
    await etape('DEPLOY : il echoue a l\'installation, et n\'ecrit AUCUN etat', async () => {
        const avantEtat = etatEnBase(MACHINE_ID);
        const avantLignes = compteLignesEtat();
        const avant = s.requetes.length;

        const r = await cliqueSurLeBanc(s.page, 'deploy');
        verifie('le clic de deploiement vise le banc', String(r.vise) === String(MACHINE_ID),
            `vise ${r.vise}`);
        if (CIBLE === 'laravel') {
            await s.page.waitForSelector(C.confirmer, { visible: true, timeout: 10000 });
            await s.page.click(C.confirmer);
        }
        /* `apt-get update` puis l'echec d'installation : laisser le temps. */
        await dors(12000);

        const emises = s.requetes.slice(avant);
        constate('requetes emises', emises.join(' | ') || 'aucune');
        verifie('la confirmation emet bien la requete de deploiement',
            emises.some((x) => /deploy/.test(x)), emises.join(' | ') || 'aucune');

        const apresEtat = etatEnBase(MACHINE_ID);
        const apresLignes = compteLignesEtat();
        constate('etat du banc avant / apres', `${avantEtat} -> ${apresEtat}`);
        /*
         * LE POINT DE CE SOUS-LOT. Le deploiement echoue a `apt-get install` : la
         * route sort avant toute ecriture. Aucune ligne ne doit apparaitre, et si
         * une existait elle ne doit pas changer.
         */
        verifie('un deploiement echoue n\'ecrit AUCUN etat',
            apresEtat === avantEtat && apresLignes === avantLignes,
            `etat ${avantEtat} -> ${apresEtat}, lignes ${avantLignes} -> ${apresLignes}`);

        if (CIBLE === 'laravel') {
            const message = await s.page.evaluate((sel) => {
                const e = document.querySelector(sel);

                return e ? (e.textContent || '').trim() : null;
            }, C.etat);
            constate('message rendu par la page', message || '(vide)');
            verifie('la page DIT l\'echec plutot que de le taire',
                !! message && message.length > 0, message || '(vide)');
        }
    });

    /* ══ `uninstall` : le temoin du correctif de v1.37.78 ════════════════ */
    await etape('UNINSTALL : il echoue, ne touche pas l\'etat, et AVERTIT', async () => {
        const avantEtat = etatEnBase(MACHINE_ID);
        const avantLignes = compteLignesEtat();
        const avant = s.requetes.length;

        const r = await cliqueSurLeBanc(s.page, 'uninstall');
        verifie('le clic de retrait vise le banc', String(r.vise) === String(MACHINE_ID),
            `vise ${r.vise}`);
        if (CIBLE === 'laravel') {
            await s.page.waitForSelector(C.confirmer, { visible: true, timeout: 10000 });
            await s.page.click(C.confirmer);
        }
        await dors(8000);

        const emises = s.requetes.slice(avant);
        verifie('la confirmation emet bien la requete de retrait',
            emises.some((x) => /uninstall/.test(x)), emises.join(' | ') || 'aucune');

        const apresEtat = etatEnBase(MACHINE_ID);
        constate('etat du banc avant / apres', `${avantEtat} -> ${apresEtat}`);
        /*
         * LE TEMOIN DU CORRECTIF (v1.37.78, PARITE E-145). Le `systemctl` du banc
         * n'existe pas, donc la chaine echoue. Avant le correctif la route rendait
         * `success: true` et ecrivait `forward_deployed = 0` : l'ecran affirmait un
         * retrait qui n'avait pas eu lieu. Desormais elle ne touche pas l'etat.
         */
        verifie('un retrait echoue ne touche PAS l\'etat',
            apresEtat === avantEtat && compteLignesEtat() === avantLignes,
            `${avantEtat} -> ${apresEtat}`);

        if (CIBLE === 'laravel') {
            const message = await s.page.evaluate((sel) => {
                const e = document.querySelector(sel);

                return e ? (e.textContent || '').trim() : '';
            }, C.etat);
            constate('message rendu par la page', message || '(vide)');
            /*
             * Le message doit dire ce qui reste POSSIBLE, pas seulement « echec ».
             * C'est le seul geste de la page ou l'utilisateur croit avoir ARRETE
             * quelque chose : un « echec » sec le laisserait conclure que le
             * transfert est de toute facon absent.
             */
            verifie('le message AVERTIT que le transfert peut continuer',
                /encore actif|still be active/i.test(message), message || '(vide)');
        }
    });

    /* ══ `test` : une vraie session SSH, et rien de plus ═════════════════ */
    await etape('TEST : il ouvre une session SSH et n\'ecrit aucun etat', async () => {
        const avantEtat = etatEnBase(MACHINE_ID);
        const avant = s.requetes.length;

        const r = await cliqueSurLeBanc(s.page, 'test');
        verifie('le clic de test vise le banc', String(r.vise) === String(MACHINE_ID),
            `vise ${r.vise}`);
        if (CIBLE === 'laravel') {
            await s.page.waitForSelector(C.confirmer, { visible: true, timeout: 10000 });
            await s.page.click(C.confirmer);
        }
        await dors(7000);

        const emises = s.requetes.slice(avant);
        verifie('la confirmation emet bien la requete de test',
            emises.some((x) => /test/.test(x)), emises.join(' | ') || 'aucune');
        /* `logger` existe sur le banc : le geste aboutit, et il n'ecrit rien en
         * base — c'est une entree de journal LOCALE sur la machine. */
        verifie('un test n\'ecrit aucun etat de transfert',
            etatEnBase(MACHINE_ID) === avantEtat, `${avantEtat} -> ${etatEnBase(MACHINE_ID)}`);
    });

    await etape('les boites natives, et ce que le portage fait a la place', async () => {
        constate('boites natives rencontrees', s.boites.join(' | ') || 'aucune');
        verifiePortage('aucune boite native : la decision se prend EN PAGE',
            s.boites.length === 0,
            'le legacy pose `confirm()` pour deployer et retirer, RIEN pour tester, '
            + 'et rend ses resultats par `alert()`');
    });

    await etape('aucune erreur JS', async () => {
        verifie('aucune erreur JS pendant la sequence', s.erreursJs.length === 0,
            s.erreursJs.join(' | ') || 'aucune');
    });
} catch (e) {
    verifie('deroulement de la suite', false, String(e).split('\n')[0]);
} finally {
    for (const ctx of contextes) { try { await ctx.close(); } catch {} }
    try { await navigateur.close(); } catch {}
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* rien */ }

    /*
     * AUCUNE FIXTURE A DEFAIRE — et c'est le resultat de la mesure du banc, pas
     * une negligence. Les deux gestes mutants echouent avant d'ecrire quoi que ce
     * soit : `deploy` a l'installation, `uninstall` au `systemctl` absent. Aucun
     * fichier n'est pose, aucun paquet installe, aucune ligne d'etat creee.
     *
     * On le VERIFIE tout de meme, pour les deux machines : la propriete « rien n'a
     * bouge » est le coeur de ce sous-lot, et l'affirmer sans la relire serait
     * exactement le defaut qu'on mesure.
     */
    const etatFinal = etatEnBase(MACHINE_ID);
    verifie('l\'etat du banc est celui de l\'entree', etatFinal === etatAuDepart,
        `${etatAuDepart} a l'entree, ${etatFinal} a la sortie`);
    verifie('l\'etat de la machine de PRODUCTION n\'a pas bouge',
        etatEnBase(MACHINE_INTERDITE) === etatProdAuDepart,
        `${etatProdAuDepart} -> ${etatEnBase(MACHINE_INTERDITE)}`);
    verifie('aucune ligne d\'etat n\'est apparue', compteLignesEtat() === lignesAuDepart,
        `${lignesAuDepart} a l'entree, ${compteLignesEtat()} a la sortie`);
}

note('');
note(`${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — ${etapes} etapes, cible ${CIBLE}`);
process.exit(echecs === 0 ? 0 : 1);
