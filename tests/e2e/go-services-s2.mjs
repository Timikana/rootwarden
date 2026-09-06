/**
 * go-services-s2.mjs - Sous-lot S2 de `services/` : les LECTURES distantes.
 *
 * Trois routes, toutes des lectures qui ouvrent une session SSH :
 *   POST /services/list     `systemctl list-units` — enumere les services
 *   POST /services/status   l'etat d'UN service
 *   POST /services/logs     ses dernieres lignes de journal
 *
 * **Les trois rendent du JSON**, question laissee ouverte par l'inventaire et
 * fermee le 2026-08-27 : `jsonify({'success': True, 'logs': logs})`, et `lines`
 * est borne a `[10, 500]` cote backend. Aucun relais en flux n'est necessaire.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * Les CINQ routes mutantes — `start`, `stop`, `restart`, `enable`, `disable` —
 * sont avortees sans exception. Et comme en B2, le filet **lit le `machine_id`**
 * de chaque requete : tout ce qui ne vise pas la machine 2 est avorte, y compris
 * une requete dont on ne peut pas determiner la cible (fail-closed).
 *
 * `srv-zabbix` (id 1) fait tourner des services de PRODUCTION. Elle n'est jamais
 * choisie, et l'assertion finale le mesure sur ce qui a ABOUTI.
 *
 * ══ CE QUE S2 NE MESURE PAS ══════════════════════════════════════════════
 *
 * **E-150 appartient a S3.** La liste des services proteges n'est consultee que
 * par les routes MUTANTES : aucune lecture ne la traverse. Le demontrer exigerait
 * d'appeler `stop` sur `ssh.socket`, ce qui couperait l'acces SSH a la machine —
 * exactement ce que le defaut permet. Il restera donc un constat CALCULE.
 *
 * ══ CE QUE LE BANC BORNE, ET IL FAUT LE DIRE ═════════════════════════════
 *
 * `Test-Server-Debian` est un CONTENEUR SANS systemd. `systemctl list-units` n'y
 * rend rien, et la page annonce « 0 services charges » — un appel REUSSI qui
 * rend une liste vide, pas un echec.
 *
 * **S2 ne peut donc pas mesurer le rendu d'un tableau peuple sur ce banc.** Les
 * assertions qui en dependent — le filtre de recherche notamment — le CONSTATENT
 * au lieu de passer en silence. Ce qui est mesure : que le geste part, qu'il
 * vise la bonne machine, qu'aucune ecriture ne l'accompagne, et que la page DIT
 * ce qu'elle a obtenu.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-services-s2
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
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
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';

/** `Test-Server-Debian`. La 1 est `srv-zabbix`, PRODUCTION : jamais choisie. */
const MACHINE_ID = 2;
const MACHINE_PRODUCTION = 1;

const LECTURES = /\/services\/(list|status|logs)(\?|$)/;
const ECRITURES = /\/services\/(start|stop|restart|enable|disable)(\?|$)/;
const ROUTES_MODULE = /\/services\/(list|status|logs|start|stop|restart|enable|disable)(\?|$)/;

const DOSSIER_CAPTURES = new URL('./screenshots/services', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/services',
        serveur: '[data-rw="services-serveur"]',
        charger: '[data-rw="services-charger"]',
        tableau: '[data-rw="services-tableau"]',
        ligne: '[data-rw^="services-ligne-"]',
        recherche: '[data-rw="services-recherche"]',
        journaux: '[data-rw="services-journaux"], [data-rw="services-etat"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/services/',
        serveur: '#server',
        // LE BOUTON DE CHARGEMENT DU LEGACY N'A PAS D'IDENTIFIANT — seulement
        // `onclick="loadServices()"`. On l'ancre donc sur cet attribut : c'est
        // le VRAI bouton, clique pour de vrai, et non un appel a la fonction.
        // Une premiere redaction visait `#services-table-container` en croyant
        // que le legacy chargeait au `change` : zero requete, et deux FAIL.
        //
        // Note de portage : la version portee lui donne un `data-rw`.
        charger: 'button[onclick*="loadServices"]',
        tableau: '#services-tbody',
        ligne: '#services-tbody tr',
        recherche: '#filter-search',
        // LA PAGE N'ECRIT PAS DANS LE TABLEAU. `appendLog` (js:27-34) ajoute
        // ses messages a `#logs-container` — une premiere redaction lisait
        // `#services-tbody` et accusait la page d'etre MUETTE alors qu'elle
        // explique, ailleurs. « Le legacy n'ecrit pas ou l'on croit. »
        journaux: '#logs-container',
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

/** Le `machine_id` d'une requete. `null` si indeterminable — et alors on avorte. */
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

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});
const contextes = [];
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
    page.on('dialog', async (d) => { try { await d.dismiss(); } catch {} });

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        const url = r.url();
        // LE GARDE VISE LES NOMS DE ROUTES : `/services/` est aussi le chemin de
        // LA PAGE, et l'avorter tuerait la suite avant toute mesure (piege B2).
        if (! ROUTES_MODULE.test(url)) { r.continue().catch(() => {}); return; }

        const cible = machineVisee(r);
        if (LECTURES.test(url) && cible === MACHINE_ID) {
            abouties.push({ route: url.replace(/^https?:\/\/[^/]+/, ''), machine: cible });
            r.continue().catch(() => {});

            return;
        }
        avortees.push({
            route: url.replace(/^https?:\/\/[^/]+/, ''),
            machine: cible === null ? '(indetermine)' : String(cible),
            motif: ECRITURES.test(url) ? 'ecriture' : 'machine hors perimetre',
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

    // ══ 1. CHOISIR LA MACHINE D'ESSAI DECLENCHE L'ENUMERATION ════════════
    await etape('choisir une machine enumere ses services', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });

        // ON CHOISIT L'OPTION DANS LES DONNEES RENDUES, jamais par une valeur
        // supposee.
        //
        // Le legacy met un OBJET JSON dans `option.value` — `getServer()` fait
        // `JSON.parse(sel.value)`. Un `page.select(sel, '2')` ne trouvait donc
        // aucune option : rien n'etait selectionne, `getServer()` sortait en
        // silence sur un `toast`, et la suite mesurait « 0 requete » en accusant
        // la page. Le portage, lui, met l'identifiant nu.
        //
        // On lit donc les valeurs REELLES et on retient celle dont l'id est
        // celui voulu — quelle que soit sa forme.
        const valeur = await page.$$eval(`${C.serveur} option`, (options, id) => {
            const cherchee = options.find((o) => {
                if (! o.value) return false;
                if (o.value === String(id)) return true;
                try { return JSON.parse(o.value).id === id; } catch { return false; }
            });

            return cherchee ? cherchee.value : '';
        }, MACHINE_ID);
        verifie(`l'option de la machine ${MACHINE_ID} existe`, valeur !== '',
            'aucune option ne porte cet identifiant');
        if (valeur === '') return;
        await page.select(C.serveur, valeur);
        await dors(1500);
        // LES DEUX CIBLES exigent un clic : le legacy comme le portage. C'est
        // une bonne chose — choisir une machine ne doit pas, a soi seul, ouvrir
        // une session SSH vers elle.
        const bouton = await page.$(C.charger);
        verifie('le bouton de chargement est atteignable', bouton !== null,
            `selecteur ${C.charger}`);
        if (! bouton) return;
        await bouton.click();
        await dors(25000);

        const enumerations = abouties.filter((r) => /\/services\/list/.test(r.route)).length;
        constate('requetes d\'enumeration abouties', String(enumerations));
        verifie('choisir une machine declenche son enumeration', enumerations > 0, '',
            `${enumerations} requete(s)`);
    });

    // ══ 2. LES SERVICES SONT RENDUS ══════════════════════════════════════
    let serviceChoisi = '';
    await etape('les services de la machine sont affiches', async () => {
        const vu = await page.evaluate((sels) => {
            const corps = document.querySelector(sels.tableau);
            const rangs = [...document.querySelectorAll(sels.ligne)];

            return {
                present: corps !== null,
                nombre: rangs.length,
                noms: rangs.slice(0, 6).map((r) => (r.textContent || '').trim().split(/\s+/)[0]).filter(Boolean),
                texte: corps ? (corps.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 140) : '',
            };
        }, { tableau: C.tableau, ligne: C.ligne });

        verifie('le tableau des services existe', vu.present);
        constate('services listes', `${vu.nombre} — ${vu.noms.join(', ') || '(aucun)'}`);
        constate('ce que le tableau affiche', vu.texte || '(vide)');

        // CE QUE LA PAGE DIT, LU DANS TOUS SES PORTE-MESSAGES.
        //
        // Pas dans le tableau — la page n'y ecrit pas — mais pas non plus dans
        // UN SEUL conteneur. Une premiere redaction lisait le seul journal ;
        // quand le portage a deplace l'explication vers la ligne d'etat pour
        // supprimer une repetition, l'assertion a echoue sur une page qui disait
        // pourtant la bonne chose.
        //
        // **La propriete porte sur la PAGE** : c'est ce que la personne lit qui
        // compte, pas le `div` ou c'est ecrit. On concatene donc les
        // porte-messages, et le selecteur en liste plusieurs.
        const message = await page.evaluate((sel) => {
            return [...document.querySelectorAll(sel)]
                .map((c) => (c.textContent || '')).join(' ')
                .replace(/\s+/g, ' ').trim();
        }, C.journaux);
        constate('ce que la page dit du chargement', message.slice(0, 180) || '(rien)');

        if (vu.nombre === 0) {
            // La machine peut ne pas repondre. On le CONSTATE — mais on exige
            // que la page le DISE : un tableau vide sans explication laisse
            // croire a une machine sans services.
            constate('enumeration', 'aucun service rendu');
            verifie('la page dit pourquoi aucun service n\'est affiche', message.length > 0,
                'ni tableau ni message : rien n\'explique l\'absence de services');

            // UN ZERO S'ENONCE. « 0 services charges » est exact mais ne
            // distingue pas « cette machine n'a pas systemd » de « l'enumeration
            // a echoue » — et sur un module dont c'est tout l'objet, la
            // difference decide du geste suivant.
            verifiePortage('un resultat vide dit s\'il vient de la machine ou du geste',
                /systemd|aucun service|pas de service|no service/i.test(message),
                `« ${message.slice(0, 90)} » — un zero sans explication`);

            return;
        }
        serviceChoisi = vu.noms[0] || '';
        verifie('au moins un service est liste', vu.nombre > 0, '', `${vu.nombre} service(s)`);
    });

    // ══ 3. LE FILTRE DE RECHERCHE REPEUPLE LE TABLEAU ════════════════════
    await etape('la recherche filtre bien le tableau', async () => {
        if (! serviceChoisi) { constate('recherche', '(non exercable — aucun service)'); return; }
        const champ = await page.$(C.recherche);
        verifie('le champ de recherche est atteignable', champ !== null);
        if (! champ) return;

        const avant = await page.$$eval(C.ligne, (r) => r.filter((x) => x.offsetParent !== null).length);
        // On tape un fragment du PREMIER service rendu : une fixture choisie
        // DANS les donnees affichees, jamais inventee (lecon de S5).
        const fragment = serviceChoisi.slice(0, Math.min(6, serviceChoisi.length));
        await champ.click({ clickCount: 3 });
        await champ.type(fragment, { delay: 12 });
        await dors(1200);
        const apres = await page.$$eval(C.ligne, (r) => r.filter((x) => x.offsetParent !== null).length);

        constate('lignes visibles avant / apres le filtre', `${avant} → ${apres} (fragment « ${fragment} »)`);
        // LA PROPRIETE : le filtre REDUIT et garde au moins la ligne cherchee.
        // « moins de lignes » seul serait vrai d'un filtre qui vide tout.
        verifie('la recherche reduit le tableau sans le vider',
            apres > 0 && apres <= avant, `${avant} → ${apres}`);
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await dors(400);
            await page.screenshot({ path: `${dossier}/services-s2-${nom}.png` });
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
            ? [...new Set(abouties.map((r) => r.route))].join(' · ') : '(aucune)');
        // LES DEUX PROPRIETES CENTRALES, mesurees sur ce qui a ABOUTI.
        verifie('aucune requete aboutie ne visait une autre machine que la 2',
            abouties.every((r) => r.machine === MACHINE_ID),
            abouties.map((r) => `${r.route}:${r.machine}`).join(' · '));
        verifie('aucune requete aboutie ne pilotait un service',
            abouties.every((r) => ! ECRITURES.test(r.route)),
            abouties.map((r) => r.route).join(' · '));
        verifie('la production n\'a ete visee par aucune requete aboutie',
            abouties.every((r) => r.machine !== MACHINE_PRODUCTION));
    } catch (e) { note(`FAIL  controle des requetes : ${e.message}`); echecs += 1; }
    try {
        // `_log_service_action` ecrit `service_<action>` : le motif vise CE
        // prefixe, pas `%service%` — qui attraperait le journal des refus de
        // permission (defaut paye en S1). `_` est un joker, d'ou `ESCAPE`.
        const gestes = compteEnBase('SELECT COUNT(*) FROM rootwarden.user_logs '
            + "WHERE action LIKE 'service|_%' ESCAPE '|' "
            + 'AND created_at > NOW() - INTERVAL 15 MINUTE');
        constate('gestes `service_*` des quinze dernieres minutes', String(gestes));
        verifie('S2 n\'a pilote aucun service', gestes === 0, `${gestes} ligne(s)`);
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
