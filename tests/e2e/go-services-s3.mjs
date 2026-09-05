/**
 * go-services-s3.mjs - Sous-lot S3 de `services/` : les ECRITURES distantes.
 *
 *   POST /services/start · stop · restart · enable · disable
 *
 * Les cinq pilotent un service systemd sur une machine reelle.
 *
 * ══ POURQUOI CETTE SUITE FORGE UNE REQUETE ═══════════════════════════════
 *
 * **Aucun bouton d'action n'existe a cliquer.** `Test-Server-Debian` est un
 * conteneur SANS systemd : `systemctl list-units` n'y rend rien, le tableau est
 * vide sur LES DEUX cibles, et les boutons par ligne ne sont donc jamais rendus.
 * Mesure de S2, verifiee sur les deux portails.
 *
 * C'est exactement l'exception prevue : la requete FORGEE, emise DEPUIS LA PAGE
 * — donc avec sa session et ses en-tetes reels — pour exercer ce qu'aucun clic
 * ne peut atteindre.
 *
 * ══ CE QU'ELLE FORGE, ET CE QU'ELLE NE FORGERA PAS ═══════════════════════
 *
 * **Uniquement `stop` sur un service PROTEGE.** `services_stop` teste
 * `PROTECTED_SERVICES` et rend **403 AVANT** `_resolve_ssh_creds` — verifie
 * ligne par ligne : aucune session SSH n'est ouverte, aucune commande n'est
 * lancee, rien n'est journalise. La requete prouve que la garde vit sur la
 * REQUETE et pas seulement a l'ecran, et elle ne peut rien casser.
 *
 * **Elle ne forge JAMAIS de geste non protege.** Notamment pas `stop
 * ssh.socket`, qui est le coeur d'E-150 : cette forme n'est PAS dans la liste,
 * la requete aboutirait, et sur un hote a activation par socket elle couperait
 * l'acces SSH — y compris celui par lequel RootWarden pilote la machine.
 * **Demontrer le defaut reviendrait a le commettre.** E-150 reste donc un
 * constat CALCULE, et la suite le dit plutot que de le maquiller.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * Le filet avorte toute ecriture qui n'est pas la requete forgee ci-dessus, et
 * toute requete ne visant pas la machine 2 — y compris celle dont la cible est
 * indeterminable. `srv-zabbix` (id 1) n'est jamais choisie.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-services-s3
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';

const MACHINE_ID = 2;
const MACHINE_PRODUCTION = 1;

/** Le service PROTEGE que la requete forgee vise. Refuse avant tout SSH. */
const SERVICE_PROTEGE = 'sshd';

/**
 * UNE ENUMERATION SYNTHETIQUE, servie a la place de la vraie.
 *
 * ══ POURQUOI, ET POURQUOI CE N'EST PAS UN CONTOURNEMENT ══════════════════
 *
 * Le banc n'a pas de systemd : la vraie enumeration rend une liste VIDE, donc
 * aucune ligne, aucun bouton, et **tout le chemin de rendu reste non mesure**.
 * Deux defauts du portage y ont d'ailleurs vecu sans etre vus — le champ lu
 * s'appelle `unit_file_state` et non `enabled`, et c'est une CHAINE a cinq
 * valeurs, pas un booleen.
 *
 * On ne contourne pas la mesure : **on FOURNIT l'entree que la machine ne peut
 * pas produire**, et on laisse tourner le vrai chemin — le `fetch` de la page,
 * son analyse, son rendu, ses boutons. Rien n'est appele a la main.
 *
 * Aucune machine n'est jointe : la reponse ne sort pas du navigateur.
 *
 * Les cinq entrees couvrent ce qui differencie les branches du rendu :
 * un service actif et active au boot, un arrete et desactive, un STATIC, un
 * MASKED, et un PROTEGE. Les formes viennent de `services_manager.py` — nom
 * suffixe `.service`, `unit_file_state`, `protected`.
 */
const ENUMERATION_SYNTHETIQUE = {
    success: true,
    total: 5,
    services: [
        { name: 'nginx.service', active: 'active', sub: 'running',
          unit_file_state: 'enabled', category: 'web', protected: false,
          description: 'A high performance web server' },
        { name: 'postfix.service', active: 'inactive', sub: 'dead',
          unit_file_state: 'disabled', category: 'mail', protected: false,
          description: 'Postfix Mail Transport Agent' },
        { name: 'dbus.service', active: 'active', sub: 'running',
          unit_file_state: 'static', category: 'system', protected: true,
          description: 'D-Bus System Message Bus' },
        { name: 'telnet.service', active: 'inactive', sub: 'dead',
          unit_file_state: 'masked', category: '', protected: false,
          description: 'Masked unit' },
        { name: 'fail2ban.service', active: 'failed', sub: 'failed',
          unit_file_state: 'enabled', category: 'security', protected: false,
          description: 'Fail2Ban Service' },
    ],
};

const ECRITURES = /\/services\/(start|stop|restart|enable|disable)(\?|$)/;
const ROUTES_MODULE = /\/services\/(list|status|logs|start|stop|restart|enable|disable)(\?|$)/;

const DOSSIER_CAPTURES = new URL('./screenshots/services', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion', page: '/services',
        serveur: '[data-rw="services-serveur"]', charger: '[data-rw="services-charger"]',
        ligne: '[data-rw^="services-ligne-"]',
        action: '[data-rw^="services-action-"]',
        prefixe: '/api/gateway',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr', page: '/services/',
        serveur: '#server', charger: 'button[onclick*="loadServices"]',
        ligne: '#services-tbody tr',
        action: '#services-tbody button',
        prefixe: '/api_proxy.php',
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
function verifie(l, ok, d, toujours) {
    const suffixe = toujours || (! ok && d) || '';
    note(`${ok ? 'PASS' : 'FAIL'}  ${l}${suffixe ? '  — ' + suffixe : ''}`);
    if (! ok) echecs += 1;
}
function constate(l, v) { note(`INFO  ${l} : ${v}`); }
function verifiePortage(l, ok, d, __quatrieme) {
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

    if (CIBLE === 'laravel') return verifie(l, ok, ok ? '' : d);
    constate(l, ok ? 'verifie sur le legacy aussi' : `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

function machineVisee(requete) {
    try {
        const corps = requete.postData();
        if (corps) {
            const b = /"machine_id"\s*:\s*"?(\d+)"?/.exec(corps);
            if (b) return Number(b[1]);
        }
    } catch { /* corps illisible */ }
    const m = /[?&]machine_id=(\d+)/.exec(requete.url());

    return m ? Number(m[1]) : null;
}
/** Le corps vise-t-il le service PROTEGE ? Seule ecriture laissee passer. */
function viseLeProtege(requete) {
    try {
        const corps = requete.postData() || '';

        return new RegExp(`"service"\\s*:\\s*"${SERVICE_PROTEGE}"`).test(corps);
    } catch { return false; }
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});
const contextes = [];
/** Quand vrai, l'enumeration est SERVIE au lieu d'etre transmise. */
let synthetique = false;
const abouties = [];
const avortees = [];

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(60000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => { try { await d.accept(); } catch {} });

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        const url = r.url();
        if (! ROUTES_MODULE.test(url)) { r.continue().catch(() => {}); return; }

        const cible = machineVisee(r);
        const bonneMachine = (cible === MACHINE_ID);

        // L'ENUMERATION EST SERVIE, PAS TRANSMISE. La machine n'est jamais
        // jointe — et le rendu, lui, s'execute pour de vrai.
        if (/\/services\/list/.test(url) && bonneMachine && synthetique) {
            abouties.push({ route: url.replace(/^https?:\/\/[^/]+/, ''), machine: cible,
                            ecriture: false, servie: true });
            r.respond({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify(ENUMERATION_SYNTHETIQUE),
            }).catch(() => {});

            return;
        }
        // UNE SEULE ECRITURE PASSE : celle qui vise le service PROTEGE, sur la
        // machine d'essai. Le backend la refuse AVANT toute session SSH.
        const forgeeAutorisee = ECRITURES.test(url) && bonneMachine && viseLeProtege(r);

        if ((! ECRITURES.test(url) && bonneMachine) || forgeeAutorisee) {
            abouties.push({ route: url.replace(/^https?:\/\/[^/]+/, ''), machine: cible,
                            ecriture: ECRITURES.test(url) });
            r.continue().catch(() => {});

            return;
        }
        avortees.push({
            route: url.replace(/^https?:\/\/[^/]+/, ''),
            machine: cible === null ? '(indetermine)' : String(cible),
            motif: ! bonneMachine ? 'machine hors perimetre' : 'ecriture non protegee',
        });
        r.abort('blockedbyclient').catch(() => {});
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

    return { ctx, page, erreursJs, surConnexion: /connexion|login\.php/.test(page.url()) };
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

try {
    /*
     * ══ `services/` EST ARCHIVE — LE CONSTAT VIENT EN TETE DU `try` ═══════
     *
     * EN TETE, et c'est la seule place possible : le bloc appelle
     * `process.exit()`, qui **ne joue pas le `finally`**. Place plus bas, il
     * laisserait derriere lui tout ce que la suite a pose — fixture en base,
     * etat distant, autorisation accordee. Ici, il n'y a rien a defaire.
     *
     * Sonde AVANT / APRES relevee par la session 2, meme sonde :
     *     /services/            302 -> 404
     *     /services/index.php   302 -> 404
     *     /services/js/main.js  **200** -> 404
     * Le `200` du script rend l'assertion MESURANTE plutot que creuse : elle
     * passe d'un contenu servi a un 404, au lieu de valider du vide. C'est le
     * contraire du piege « sonder un chemin qui n'a jamais existe ».
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: '/services/',
            fichiers: ['/services/index.php', '/services/js/main.js'], verifie, constate,
        });
        if (archivee) {
            const s = await connecte(COMPTE, SECRET);
            await verifieMenuLegacy(s.page, '/services', verifie, constate);
            try { await s.ctx.close(); } catch { /* deja ferme */ }
            /*
             * PAS DE `console.log(lignes.join())` ICI : dans ces suites, `note()`
             * fait DEJA `console.log` au fil de l'eau. Reimprimer le tampon
             * doublait chaque ligne — le runner compte `grep -c '^PASS'`, et il
             * a rendu **10** la ou la suite en mesurait 5. Un compte double est
             * un compte faux, et il ne se voit pas dans un verdict « 0 FAIL ».
             */
            console.log(`\ncible=${CIBLE} : `
                + `${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`
                + ' — partie archivee');
            try { await navigateur.close(); } catch { /* deja ferme */ }
            process.exit(echecs > 0 ? 1 : 0);
        }
    }
    const s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = s;
    verifie('la session a tenu', ! s.surConnexion, page.url());

    // ══ 1. AUCUN BOUTON D'ACTION N'EST RENDU, ET ON DIT POURQUOI ═════════
    await etape('les boutons d\'action existent-ils sur ce banc ?', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const valeur = await page.$$eval(`${C.serveur} option`, (options, id) => {
            const c = options.find((o) => {
                if (! o.value) return false;
                if (o.value === String(id)) return true;
                try { return JSON.parse(o.value).id === id; } catch { return false; }
            });

            return c ? c.value : '';
        }, MACHINE_ID);
        if (valeur !== '') { await page.select(C.serveur, valeur); await dors(1200); }
        const bouton = await page.$(C.charger);
        if (bouton) { await bouton.click(); await dors(22000); }

        const vu = await page.evaluate((sels) => ({
            lignes: document.querySelectorAll(sels.ligne).length,
            actions: document.querySelectorAll(sels.action).length,
        }), { ligne: C.ligne, action: C.action });

        constate('lignes de service rendues', String(vu.lignes));
        constate('boutons d\'action rendus', String(vu.actions));
        // CE N'EST PAS UN ECHEC : c'est la propriete du banc, et elle est la
        // RAISON pour laquelle la suite forge. On la mesure au lieu de la
        // supposer — si le banc changeait, la suite devrait etre reecrite.
        verifie('le banc ne rend aucun bouton d\'action, comme attendu',
            vu.actions === 0,
            `${vu.actions} bouton(s) : le banc expose desormais des services, la suite doit passer au CLIC`);
    });

    // ══ 2. LA GARDE DES SERVICES PROTEGES VIT SUR LA REQUETE ════════════
    await etape('un service protege est refuse par le BACKEND', async () => {
        const avant = abouties.length;

        // LA REQUETE FORGEE, EMISE DEPUIS LA PAGE — donc avec sa session et ses
        // en-tetes reels. Motif : aucun bouton n'existe (etape 1), et la cible
        // est un service PROTEGE, refuse avant toute session SSH.
        const verdict = await page.evaluate(async (prefixe, machine, service) => {
            try {
                const r = await fetch(`${prefixe}/services/stop`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ machine_id: machine, service }),
                });
                const corps = await r.json().catch(() => null);

                return { statut: r.status, message: (corps && corps.message) || '', succes: corps && corps.success };
            } catch (e) {
                return { statut: 0, message: String(e), succes: null };
            }
        }, C.prefixe, MACHINE_ID, SERVICE_PROTEGE);

        constate(`reponse a « stop ${SERVICE_PROTEGE} »`,
            `${verdict.statut} — ${verdict.message || '(sans message)'}`);
        const partie = abouties.slice(avant).filter((r) => r.ecriture).length;
        constate('requetes d\'ecriture abouties', String(partie));

        // LA PROPRIETE : la garde est sur la REQUETE. Le legacy desactive aussi
        // le bouton, mais un bouton desactive ne protege que qui clique.
        verifie('le backend refuse d\'arreter un service protege',
            verdict.statut === 403, `statut ${verdict.statut}`);
        verifie('le refus NOMME le service protege',
            /prote/i.test(verdict.message), verdict.message || '(sans message)');
        verifie('la reponse ne se declare pas reussie', verdict.succes !== true,
            `success=${verdict.succes}`);
    });

    // ══ 2b. LE RENDU D'UN TABLEAU PEUPLE, SUR UNE ENUMERATION SERVIE ════
    //
    // C'est l'etape qui aurait attrape les DEUX defauts du portage de S2 : le
    // champ `unit_file_state` lu sous le nom `enabled`, et son traitement comme
    // un booleen alors qu'il porte cinq valeurs.
    await etape('un tableau peuple se rend correctement', async () => {
        synthetique = true;
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const valeur = await page.$$eval(`${C.serveur} option`, (options, id) => {
            const c = options.find((o) => {
                if (! o.value) return false;
                if (o.value === String(id)) return true;
                try { return JSON.parse(o.value).id === id; } catch { return false; }
            });

            return c ? c.value : '';
        }, MACHINE_ID);
        if (valeur !== '') { await page.select(C.serveur, valeur); await dors(1000); }
        const bouton = await page.$(C.charger);
        if (bouton) { await bouton.click(); await dors(3000); }

        // ── REPERAGE PAR LE CONTENU ET PAR L'EN-TETE, PAS PAR UN ANCRAGE ──
        //
        // Une premiere redaction identifiait les lignes par `data-rw` et lisait
        // la colonne par son INDEX. Le legacy n'a **aucun** `data-rw` sur ses
        // `<tr>` et n'a pas le meme ordre de colonnes : les quatre proprietes
        // ont donc rendu « ecart assume du legacy » — **quatre accusations
        // fausses**, alors qu'il retire bien le suffixe et desactive bien les
        // boutons proteges (lu dans `actionButtons`).
        //
        // On repere donc la ligne par son CONTENU et la colonne par son
        // EN-TETE : le seul reperage qui vise la meme chose sur deux balisages
        // differents.
        const rendu = await page.evaluate((sel, motsEtat) => {
            const tableau = document.querySelector(sel) ? document.querySelector(sel).closest('table') : null;
            // ACCENTS NORMALISES AVANT COMPARAISON. Le legacy titre « au boot »,
            // le portage « activé au démarrage » : chercher `demarrage` sans
            // accent ne trouvait rien, et la colonne rendait -1 — deux
            // assertions en echec sur un libelle parfaitement correct.
            const sansAccent = (t) => (t || '').normalize('NFD')
                .replace(/[\u0300-\u036f]/g, '').trim().toLowerCase();
            const entetes = tableau
                ? [...tableau.querySelectorAll('thead th')].map((t) => sansAccent(t.textContent))
                : [];
            // La colonne de l'etat au demarrage, trouvee par son intitule.
            let colonneBoot = entetes.findIndex((t) => motsEtat.some((m) => t.includes(m)));

            return {
                entetes,
                colonneBoot,
                lignes: [...document.querySelectorAll(sel)].map((tr) => ({
                    // LE TEXTE SE COMPOSE DES CELLULES, SEPAREES. `textContent`
                    // sur un `<tr>` colle les cellules bout a bout : la ligne
                    // rendait « nginxen marcheactive… », et `\bnginx\b` n'y
                    // trouvait aucune frontiere de mot. Trois lignes sur quatre
                    // etaient introuvables, et deux assertions echouaient sur un
                    // rendu parfaitement correct.
                    texte: [...tr.children].map((c) => (c.textContent || '').trim())
                        .join(' | ').replace(/\s+/g, ' ').trim(),
                    cellules: [...tr.children].map((c) => (c.textContent || '').trim()),
                    boot: colonneBoot >= 0 && tr.children[colonneBoot]
                        ? (tr.children[colonneBoot].textContent || '').trim() : '',
                    actions: [...tr.querySelectorAll('button')].map((b) => ({
                        libelle: (b.textContent || '').trim(),
                        desactive: b.disabled,
                        // UN BOUTON DE LECTURE N'EST PAS UN GESTE. « Detail » et
                        // « Journaux » consultent : ils restent actifs meme sur
                        // un service protege, et c'est correct. Une premiere
                        // redaction exigeait que TOUS les boutons soient
                        // desactives, et accusait donc le legacy a tort.
                        lecture: /detail|logs?|journ/i.test(b.textContent || ''),
                    })),
                })),
            };
        }, C.ligne, ['demarrage', 'boot', 'active', 'enabled']);

        constate('en-tetes du tableau', rendu.entetes.join(' | ') || '(aucun)');
        constate('colonne de l\'etat au demarrage', String(rendu.colonneBoot));
        for (const l of rendu.lignes) {
            constate('  ligne', `${l.texte.slice(0, 70)} · boot=« ${l.boot} » · ${l.actions.length} action(s)`
                + `${l.actions.some((a) => a.desactive) ? ' (desactivees)' : ''}`);
        }
        verifie('les cinq services sont rendus', rendu.lignes.length === 5, `${rendu.lignes.length} ligne(s)`);
        if (rendu.lignes.length !== 5) { synthetique = false; return; }

        /** La ligne qui PARLE de ce service — par son contenu, jamais par un index. */
        const pour = (nom) => rendu.lignes.find((l) => new RegExp(`\\b${nom}\\b`).test(l.texte));

        // 1. LE SUFFIXE `.service` EST RETIRE. Les deux cibles le font.
        verifiePortage('le suffixe `.service` est retire des noms',
            rendu.lignes.every((l) => ! /\.service\b/.test(l.texte)),
            'un nom garde son suffixe');

        // 2. L'ETAT AU DEMARRAGE DISTINGUE LES VALEURS DE systemd. Un booleen
        //    ne sait dire ni `static` ni `masked` ; un champ lu sous le mauvais
        //    nom rend la meme chose pour tous.
        const boots = ['nginx', 'postfix', 'dbus', 'telnet'].map((n) => (pour(n) || {}).boot || '');
        constate('etat au demarrage, service par service',
            ['nginx', 'postfix', 'dbus', 'telnet'].map((n, i) => `${n}=${boots[i] || '?'}`).join(' · '));
        verifiePortage('l\'etat au demarrage distingue les valeurs de systemd',
            new Set(boots.filter(Boolean)).size === 4,
            `${new Set(boots).size} valeur(s) distincte(s) pour quatre etats differents`);

        // 3. UN SERVICE PROTEGE A SES GESTES DESACTIVES.
        const protege = pour('dbus');
        const gestesProteges = protege ? protege.actions.filter((a) => ! a.lecture) : [];
        constate('gestes offerts sur le service protege',
            gestesProteges.map((a) => `${a.libelle}${a.desactive ? ' (desactive)' : ' (ACTIF)'}`)
                .join(' · ') || '(aucun)');
        verifiePortage('les gestes d\'un service protege sont desactives',
            gestesProteges.length > 0 && gestesProteges.every((a) => a.desactive),
            'un service protege offre un geste actif');

        // 4. UNE UNITE MASQUEE N'OFFRE PAS D'INTERRUPTEUR AU DEMARRAGE.
        const masque = pour('telnet');
        verifiePortage('un service masque n\'offre ni activer ni desactiver',
            masque !== undefined
                && ! masque.actions.some((a) => ! a.lecture && /activ|enable|disable/i.test(a.libelle)),
            'un interrupteur au demarrage est offert sur une unite masquee');

        synthetique = false;
    });

    // ══ 3. E-150 : CE QUI N'EST PAS EXERCE, ET POURQUOI ═════════════════
    await etape('E-150 : la forme `.socket` n\'est pas exercee', async () => {
        // ON NE FORGE PAS `stop ssh.socket`. La forme n'est pas dans
        // `PROTECTED_SERVICES`, donc la requete ABOUTIRAIT — et sur un hote a
        // activation par socket elle couperait l'acces SSH, y compris celui de
        // RootWarden. Demontrer le defaut reviendrait a le commettre.
        constate('E-150', 'non exerce — la requete aboutirait et couperait potentiellement SSH');
        constate('statut du constat', 'CALCULE contre le module reel, jamais mesure au navigateur');
        // On asserte ce qu'on PEUT : qu'aucune requete de cette forme n'est
        // partie. Une suite qui nomme un defaut doit prouver qu'elle ne l'a pas
        // declenche.
        verifie('aucune requete visant une forme `.socket` n\'a ete emise',
            [...abouties, ...avortees].every((r) => ! /\.socket/.test(r.route)));
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await dors(400);
            await page.screenshot({ path: `${dossier}/services-s3-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    const causeesParLeFilet = erreursJs.filter((e) => /Failed to fetch|blocked/i.test(e)).length;
    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    verifiePortage('aucune erreur JavaScript etrangere a l\'avortement',
        erreursJs.length === causeesParLeFilet,
        erreursJs.filter((e) => ! /Failed to fetch|blocked/i.test(e)).slice(0, 2).join(' | '));

} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    try {
        for (const r of avortees) constate('  AVORTEE', `${r.route} · machine ${r.machine} · ${r.motif}`);
        constate('requetes abouties', abouties.length
            ? abouties.map((r) => `${r.route}${r.ecriture ? ' (ECRITURE)' : ''}`).join(' · ') : '(aucune)');
        verifie('aucune requete aboutie ne visait une autre machine que la 2',
            abouties.every((r) => r.machine === MACHINE_ID));
        verifie('la production n\'a ete visee par aucune requete',
            [...abouties].every((r) => r.machine !== MACHINE_PRODUCTION));
        // La SEULE ecriture aboutie doit etre la requete forgee sur le protege.
        const ecritures = abouties.filter((r) => r.ecriture);
        verifie('une seule ecriture a abouti, et c\'est la requete forgee sur le service protege',
            ecritures.length === 1, `${ecritures.length} ecriture(s) : ${ecritures.map((r) => r.route).join(' · ')}`);
    } catch (e) { note(`FAIL  controle des requetes : ${e.message}`); echecs += 1; }
    try {
        // LA PREUVE QUE RIEN N'A ETE PILOTE : `_log_service_action` n'est appele
        // qu'APRES l'execution reelle. Aucune ligne = aucun geste abouti.
        const gestes = compteEnBase('SELECT COUNT(*) FROM rootwarden.user_logs '
            + "WHERE action LIKE 'service|_%' ESCAPE '|' "
            + 'AND created_at > NOW() - INTERVAL 15 MINUTE');
        constate('gestes `service_*` des quinze dernieres minutes', String(gestes));
        verifie('aucun service n\'a ete pilote', gestes === 0, `${gestes} ligne(s)`);
    } catch (e) { note(`FAIL  controle du journal : ${e.message}`); echecs += 1; }
    try {
        const zabbix = litEnBase("SELECT CONCAT(name,'|',ip) FROM rootwarden.machines WHERE id = 1");
        verifie('srv-zabbix est intacte', zabbix.length === 1 && zabbix[0] === 'srv-zabbix|192.168.0.244',
            zabbix[0] || '(absente)');
    } catch (e) { note(`FAIL  controle de srv-zabbix : ${e.message}`); echecs += 1; }
    try { for (const c of contextes) await c.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
    try { await navigateur.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
