/**
 * go-page-supervision-reglages.mjs - Module `supervision/`, sous-lot V10a :
 * les REGLAGES PAR MACHINE (`supervision_overrides`).
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/supervision/   (aucune interface — c'est la mesure)
 *   laravel  http://localhost:8444/supervision?reglages=<id>
 *
 * ══ CE N'EST PAS UN PORTAGE, C'EST UNE CONCEPTION AUTORISEE ═════════════════
 *
 * `supervision_overrides` n'a JAMAIS eu d'interface, dans aucun des deux
 * portails. La priorite `overrides > profil > globale` existait donc avec son
 * etage le plus fort INATTEIGNABLE. Cote legacy, cette suite ne mesure qu'une
 * chose : qu'il n'y a rien. C'est un ecart assume, pas une regression.
 *
 * ══ CE QUE LA MESURE AVAIT TROUVE, ET QUI GOUVERNE CE DESSIN ════════════════
 *
 * `_build_config_lines` traite huit parametres PAR LEUR NOM, puis injecte tout
 * nom inconnu directement dans le fichier de configuration. La CLE etait validee,
 * la VALEUR non : un saut de ligne y produisait une DIRECTIVE AUTONOME. Mesure du
 * 2026-08-22, charge inoffensive (PARITE E-85) :
 *
 *     POST /supervision/overrides/2  {"Timeout": "3\nLIGNE_INJECTEE=temoin"}
 *     -> fichier ecrit :  7  Timeout=3
 *                         8  LIGNE_INJECTEE_PAR_LA_MESURE=temoin
 *
 * Sur un agent Zabbix reel, un `UserParameter` : l'execution d'une commande
 * arbitraire. Le backend valide desormais la valeur (v1.37.41).
 *
 * LA PROPRIETE CENTRALE DE CETTE SUITE EST NEGATIVE : **aucun champ ne permet de
 * saisir un NOM de parametre**. Huit champs, huit noms fixes, pas de neuvieme.
 * Valider une entree libre et ne pas offrir d'entree libre ne se valent pas — la
 * seconde ne peut pas etre contournee par une requete forgee.
 *
 * Et parce qu'une requete forgee, elle, ne passe pas par le formulaire, la suite
 * en emet une : c'est la seule facon d'exercer la revalidation du controleur.
 *
 * ══ CE GESTE NE JOINT AUCUNE MACHINE ═══════════════════════════════════════
 *
 * Ces reglages vivent en base et ne partent qu'a la prochaine reconfiguration.
 * La page le DIT, et la suite le MESURE : aucune requete vers la passerelle
 * pendant l'enregistrement. C'est ce qui distingue ce sous-lot de V9.
 *
 * Fixtures : des lignes de `supervision_overrides` pour la machine 2 (DEV).
 * Nettoyees a l'entree et dans un `finally`, et l'etat rendu est RELU.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-supervision-reglages.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/supervision' : '/supervision/';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

/** La seule machine reglee ici. `srv-zabbix` (id 1) n'est jamais visee. */
const MACHINE_DEV = 2;
/** Les huit noms que le backend traite PAR LEUR NOM. Il ne doit pas y en avoir neuf. */
const HUIT = ['Hostname', 'Server', 'ServerActive', 'HostMetadata', 'ListenPort',
              'TLSConnect', 'TLSAccept', 'TLSPSKIdentity'];

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
function verifie(l, ok, d, __quatrieme) {
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
 lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }
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

    if (CIBLE === 'laravel') return verifie(l, ok, d);
    constate(l, `ecart assume du legacy — ${d}`);
}

function reglagesEnBase() {
    return compteEnBase(
        `SELECT COUNT(*) FROM rootwarden.supervision_overrides WHERE machine_id = ${MACHINE_DEV}`);
}

/** La valeur d'un reglage, avec SENTINELLE : `litEnBase` fait disparaitre le vide. */
function valeurEnBase(nom) {
    return litEnBase(
        "SELECT COALESCE(NULLIF(TRIM(param_value), ''), '(VIDE)') "
        + 'FROM rootwarden.supervision_overrides '
        + `WHERE machine_id = ${MACHINE_DEV} AND param_name = '${nom}'`)[0] ?? '(AUCUNE LIGNE)';
}

function nettoie() {
    const avant = reglagesEnBase();
    litEnBase('DELETE FROM rootwarden.supervision_overrides '
        + `WHERE machine_id = ${MACHINE_DEV}`);
    return avant;
}

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
    // Le garde anti-rejeu TOTP traverse les contextes ET les executions : une
    // seule nouvelle tentative, avec un code neuf. Lecon de V8.
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

/** JAMAIS D'ATTENTE FIXE : on attend la PROPRIETE, et on re-clique. */
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

/** Poste le formulaire des reglages en forgeant le corps : c'est la SEULE facon
 *  d'exercer la revalidation du controleur, qu'un `<input>` ne peut pas violer. */
async function posteForge(page, champs) {
    return page.evaluate(async (paires) => {
        const jeton = document.querySelector('meta[name="csrf-token"]')?.content
            || document.querySelector('input[name="_token"]')?.value || '';
        const corps = new URLSearchParams();
        corps.set('_token', jeton);
        for (const [cle, valeur] of paires) corps.set(cle, valeur);
        const r = await fetch('/supervision/reglages', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: corps.toString(),
            redirect: 'follow',
        });

        return { statut: r.status, url: r.url };
    }, champs);
}

try {
    /*
     * MODULE ARCHIVE ? Cote legacy, `supervision/` a ete porte en douze
     * sous-lots (V1 a V12) puis deplace dans `legacy/_deprecated/`. Ses URL
     * rendent 404 : ce n'est pas un echec, c'est l'aboutissement du portage. Le
     * test le CONSTATE — et verifie surtout que le menu du legacy mene desormais
     * au portage, sans quoi on aurait installe soi-meme un 404 dans un menu.
     *
     * Le constat vient AVANT toute fixture : rien n'est pose, donc rien n'est a
     * defaire, et `process.exit()` peut court-circuiter le `finally`.
     *
     * Les TROIS fichiers du module sont sondes, pas un echantillon. Et ce sont
     * les fichiers REELS : sonder un chemin qui n'a jamais existe rend 404 et
     * fait passer l'assertion pour rien.
     *
     * Tant que le module est servi, ce bloc est inerte et la suite se joue.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE,
            chemin: '/supervision/',
            fichiers: [
                '/supervision/index.php',
                '/supervision/js/main.js',
                '/supervision/js/profiles.js',
            ],
            verifie, constate,
        });
        if (archivee) {
            const { ctx, page } = await connecte('fr');
            await verifieMenuLegacy(page, '/supervision', verifie, constate);
            await ctx.close();
            console.log(lignes.join('\n'));
            console.log(`\n${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
            await navigateur.close();
            process.exit(echecs > 0 ? 1 : 0);
        }
    }

    constate('cible', `${CIBLE} — ${PAGE}`);
    constate('machine reglee', `id ${MACHINE_DEV} (DEV) — srv-zabbix jamais visee`);
    constate('reglages en base a l\'entree', nettoie());

    const { ctx, page } = await connecte('fr');
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    let appels = [];
    page.on('request', (r) => {
        const u = r.url();
        if (/api_proxy\.php\/|\/api\/gateway\//.test(u)) {
            appels.push(r.method() + ' ' + u.replace(BASE, '').slice(0, 70));
        }
    });

    const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie', (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(1600);
    verifie('l\'onglet du parc s\'ouvre', await ouvreDeploiement(page));

    /* ══ 1. LE GESTE EST UNE ADRESSE, PAS UN GESTIONNAIRE ═══════════════════ */
    const lien = await page.evaluate((mid) => {
        const a = document.querySelector(`[data-rw="superv-reglages-lien-${mid}"]`);
        if (a) return { trouve: true, libelle: a.textContent.trim(), href: a.getAttribute('href') };

        return { trouve: false };
    }, MACHINE_DEV);
    constate('geste de reglages sur la ligne de la machine DEV',
        lien.trouve ? `« ${lien.libelle} » -> ${lien.href}` : 'aucun');
    verifiePortage('chaque ligne du parc porte un geste de reglages, et c\'est une ADRESSE',
        lien.trouve && /reglages=/.test(lien.href || ''),
        lien.trouve ? String(lien.href) : 'le legacy n\'a aucune interface de reglages');

    /* ══ 2. SANS ADRESSE, LA SECTION DIT QUOI FAIRE ═════════════════════════ */
    const vide = await page.evaluate(() => {
        const s = document.querySelector('[data-rw="superv-reglages"]');

        return s ? s.innerText.replace(/\s+/g, ' ').trim() : '';
    });
    verifiePortage('sans serveur choisi, la section DIT quel geste l\'ouvre',
        /Reglages|bouton/i.test(vide) && vide.length > 40, vide.slice(0, 90) || 'rien');

    if (CIBLE === 'laravel') {
        /* ══ 3. LE FORMULAIRE VIENT DU SERVEUR ET NOMME SA MACHINE ══════════ */
        await page.goto(`${BASE}${PAGE}?reglages=${MACHINE_DEV}`, { waitUntil: 'networkidle2' });
        await dors(1200);
        verifie('l\'onglet du parc s\'ouvre (adresse de reglages)', await ouvreDeploiement(page));

        const form = await page.evaluate(() => {
            const f = document.querySelector('[data-rw="superv-reglages-form"]');
            if (! f) return null;
            const champs = [...f.querySelectorAll('input, select, textarea')];

            return {
                machine: document.querySelector('[data-rw="superv-reglages-machine"]')
                    ?.textContent.trim() || '',
                effet: document.querySelector('[data-rw="superv-reglages-effet"]')
                    ?.textContent.trim() || '',
                noms: champs.map((c) => c.getAttribute('name')).filter(Boolean),
                types: champs.map((c) => c.tagName.toLowerCase() + ':' + (c.type || '')),
                action: f.getAttribute('action'),
            };
        });
        verifie('le formulaire des reglages est rendu', form !== null);
        verifie('il NOMME la machine qu\'il regle',
            /Test-Server-Debian/.test(form?.machine || ''), form?.machine || 'rien');
        /*
         * IL DIT QUE LE GESTE NE JOINT RIEN. C'est la difference avec V9 : ici
         * on ecrit en base, et rien ne part sur la machine avant la prochaine
         * reconfiguration. Le taire laisserait croire le contraire.
         */
        verifie('il DIT qu\'enregistrer ne joint aucun serveur',
            /AUCUN|joint/i.test(form?.effet || ''), form?.effet?.slice(0, 90) || 'rien');

        /* ══ 4. LA PROPRIETE CENTRALE, ET ELLE EST NEGATIVE ═════════════════
         * Aucun champ ne permet de saisir un NOM de parametre. Valider une
         * entree libre et ne pas en offrir ne se valent pas : la seconde ne se
         * contourne pas par une requete forgee. */
        const attendus = new Set(['_token', 'machine_id',
            ...HUIT.map((n) => `override_${n}`)]);
        const inattendus = (form?.noms || []).filter((n) => ! attendus.has(n));
        constate('champs du formulaire', (form?.noms || []).join(', '));
        verifie('les HUIT reglages sont proposes, et eux seuls',
            HUIT.every((n) => (form?.noms || []).includes(`override_${n}`))
            && inattendus.length === 0,
            inattendus.length ? `en trop : ${inattendus.join(', ')}` : `${HUIT.length} champs`);
        /*
         * UN MOTIF TROP LARGE ECHOUE SUR UN CHAMP LEGITIME. Un premier jet
         * cherchait `/nom|name|param/` dans les noms de champs pour prouver
         * qu'aucun ne saisit un NOM de parametre — et `override_Hostname`
         * contient « name ». L'assertion tombait sur un champ juste, et elle ne
         * disait rien de plus que celle du dessus, qui compare a la liste
         * FERMEE. Elle est remplacee par une propriete qui, elle, n'etait pas
         * mesuree : le formulaire poste vers la route du PORTAGE, pas vers la
         * route backend `POST /supervision/overrides/<id>` — la seule route du
         * module touchant une machine sans `@require_machine_access` (E-85).
         */
        verifie('le formulaire poste vers la route du portage, pas vers la passerelle',
            /\/supervision\/reglages$/.test(form?.action || '')
            && ! /api\/gateway/.test(form?.action || ''),
            String(form?.action));

        /* ══ 5. LES DEUX CHAMPS TLS SONT DES LISTES FERMEES ═════════════════ */
        const listes = await page.evaluate(() => {
            const lire = (n) => {
                const e = document.querySelector(`[data-rw="superv-reglage-${n}"]`);

                return e ? { balise: e.tagName.toLowerCase(),
                             options: [...(e.options || [])].map((o) => o.value) } : null;
            };

            return { TLSConnect: lire('TLSConnect'), TLSAccept: lire('TLSAccept') };
        });
        constate('valeurs offertes pour TLSConnect',
            (listes.TLSConnect?.options || []).join(' | ') || 'aucune');
        verifie('les champs TLS sont des listes fermees, pas du texte libre',
            listes.TLSConnect?.balise === 'select' && listes.TLSAccept?.balise === 'select'
            && (listes.TLSConnect?.options || []).includes('psk'),
            `${listes.TLSConnect?.balise} / ${listes.TLSAccept?.balise}`);

        /* ══ 6. ENREGISTRER FONCTIONNE, ET NE JOINT AUCUNE MACHINE ══════════ */
        appels = [];
        await page.evaluate(() => {
            document.querySelector('[data-rw="superv-reglage-ListenPort"]').value = '10099';
            document.querySelector('[data-rw="superv-reglage-Server"]').value = '10.9.9.9';
        });
        let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 25000 });
        await page.click('[data-rw="superv-reglages-enregistrer"]');
        try { await nav; } catch {}
        await dors(800);
        /*
         * UNE NAVIGATION REFERME L'ONGLET. Les panneaux arrivent `hidden` et
         * c'est le script qui en ouvre un : apres chaque aller-retour de
         * formulaire, le bouton suivant vit donc dans un panneau cache et n'est
         * pas cliquable. Le premier jet ne le rouvrait pas et echouait sur
         * « Node is either not clickable » — deux gestes plus loin.
         */
        await ouvreDeploiement(page);

        verifie('le reglage est enregistre EN BASE', valeurEnBase('ListenPort') === '10099',
            `ListenPort = ${valeurEnBase('ListenPort')}`);
        verifie('le second reglage aussi', valeurEnBase('Server') === '10.9.9.9',
            `Server = ${valeurEnBase('Server')}`);
        verifie('seuls les reglages remplis sont ecrits, pas les huit',
            reglagesEnBase() === 2, `${reglagesEnBase()} ligne(s)`);
        verifie('enregistrer n\'a joint AUCUNE machine',
            appels.length === 0, appels.join(' | ') || 'aucune requete');
        /*
         * ⚠ CELLE-CI N'EST PAS COMME LES QUATRE AUTRES. Elle asserte une
         * CONFIRMATION — `/Test-Server-Debian/` sur le message — pas la presence
         * d'un message. Avec l'ancre partagee `-message`, **un message d'ERREUR
         * qui nomme la machine la fait passer au VERT**, et les messages
         * d'erreur de ce module nomment la machine : la suite l'exige d'eux
         * ailleurs. Le dedoublement d'E-250 ne preserve donc pas cette
         * assertion, il la REPARE — a condition de viser le SUCCES, jamais les
         * deux.
         *
         * ⚠ **`superv-reglages-erreur` N'EST VISEE PAR AUCUNE SUITE, ET C'EST
         * VOULU.** Si vous trouvez cette ancre « non couverte » dans un
         * inventaire, ce n'est pas un trou : lui donner un lecteur ICI rendrait
         * a cette assertion la capacite de passer au vert sur un echec. **Le
         * defaut reviendrait par la porte du soin.** Un zero qui n'explique pas
         * pourquoi il est zero se fait completer par quelqu'un de bien
         * intentionne — d'ou cette phrase, a cote du selecteur, qui est le seul
         * endroit que lira forcement celui qui voudra completer.
         */
        const confirme = await page.evaluate(() =>
            document.querySelector('[data-rw="superv-reglages-succes"]')?.textContent.trim() || '');
        verifie('l\'enregistrement est CONFIRME a l\'ecran, en nommant la machine',
            /Test-Server-Debian/.test(confirme), `« ${confirme.slice(0, 80)} »`);

        /* ══ 7. LE FORMULAIRE REVIENT PRE-REMPLI PAR LE SERVEUR ═════════════ */
        const relu = await page.evaluate(() => ({
            port: document.querySelector('[data-rw="superv-reglage-ListenPort"]')?.value,
            serveur: document.querySelector('[data-rw="superv-reglage-Server"]')?.value,
        }));
        verifie('le formulaire revient pre-rempli par le SERVEUR',
            relu.port === '10099' && relu.serveur === '10.9.9.9',
            `port=${relu.port} serveur=${relu.serveur}`);

        /* ══ 8. VIDER UN CHAMP SUPPRIME LA LIGNE, il ne l'enregistre pas VIDE
         * Un `param_value` vide serait relu comme une directive sans valeur. */
        await page.evaluate(() => {
            document.querySelector('[data-rw="superv-reglage-ListenPort"]').value = '';
        });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 25000 });
        await page.click('[data-rw="superv-reglages-enregistrer"]');
        try { await nav; } catch {}
        await dors(800);
        await ouvreDeploiement(page);
        verifie('vider un champ SUPPRIME la ligne, il ne l\'enregistre pas vide',
            valeurEnBase('ListenPort') === '(AUCUNE LIGNE)', valeurEnBase('ListenPort'));
        verifie('les autres reglages sont intacts', valeurEnBase('Server') === '10.9.9.9',
            `Server = ${valeurEnBase('Server')}`);

        /* ══ 9. LA REVALIDATION DU CONTROLEUR, PAR UNE REQUETE FORGEE ═══════
         * Un `<input>` ne peut pas porter de saut de ligne ; une requete forgee,
         * si. C'est le chemin par lequel E-85 etait atteignable. */
        const avant = valeurEnBase('HostMetadata');
        const forge = await posteForge(page, [
            ['machine_id', String(MACHINE_DEV)],
            ['override_HostMetadata', 'ok\nLIGNE_INJECTEE=temoin'],
        ]);
        constate('requete forgee (valeur multiligne)', `statut ${forge.statut}`);
        verifie('une valeur multiligne est REFUSEE par le controleur',
            valeurEnBase('HostMetadata') === avant,
            `HostMetadata = ${valeurEnBase('HostMetadata')}`);
        const apresForge = await page.goto(`${BASE}${PAGE}?reglages=${MACHINE_DEV}`,
            { waitUntil: 'networkidle2' });
        void apresForge;
        await dors(900);
        await ouvreDeploiement(page);
        verifie('aucune ligne injectee n\'existe en base',
            compteEnBase("SELECT COUNT(*) FROM rootwarden.supervision_overrides "
                + "WHERE param_name LIKE 'LIGNE_INJECTEE%' OR param_value LIKE '%\\n%'") === 0);

        /* ══ 10. LA LISTE FERMEE EST REVALIDEE, elle aussi ══════════════════ */
        const avantTls = valeurEnBase('TLSConnect');
        await posteForge(page, [
            ['machine_id', String(MACHINE_DEV)],
            ['override_TLSConnect', 'n-importe-quoi'],
        ]);
        verifie('une valeur hors de la liste fermee est REFUSEE',
            valeurEnBase('TLSConnect') === avantTls,
            `TLSConnect = ${valeurEnBase('TLSConnect')}`);

        /* ══ 11. UN PORT HORS BORNES EST REFUSE ════════════════════════════ */
        await posteForge(page, [
            ['machine_id', String(MACHINE_DEV)],
            ['override_ListenPort', '70000'],
        ]);
        verifie('un port hors bornes est REFUSE',
            valeurEnBase('ListenPort') === '(AUCUNE LIGNE)', valeurEnBase('ListenPort'));

        /* ══ 12. ON N'AFFICHE PAS SEULEMENT CE QU'ON SAIT ECRIRE ═══════════
         * Un reglage pose hors de la liste fermee, par une autre voie, EXISTE et
         * AGIT : le cacher laisserait croire qu'il n'y en a pas. */
        litEnBase('INSERT INTO rootwarden.supervision_overrides '
            + `(machine_id, param_name, param_value) VALUES (${MACHINE_DEV}, 'Timeout', '30')`);
        await page.goto(`${BASE}${PAGE}?reglages=${MACHINE_DEV}`, { waitUntil: 'networkidle2' });
        await dors(900);
        await ouvreDeploiement(page);
        const horsListe = await page.evaluate(() =>
            document.querySelector('[data-rw="superv-reglages-hors-liste"]')?.textContent.trim() || '');
        verifie('un reglage HORS de la liste fermee est tout de meme ANNONCE',
            /Timeout/.test(horsListe), `« ${horsListe.slice(0, 100)} »`);

        /* ══ 13. UNE MACHINE INEXISTANTE N'OUVRE PAS DE FORMULAIRE ═════════ */
        await page.goto(`${BASE}${PAGE}?reglages=99999`, { waitUntil: 'networkidle2' });
        await dors(900);
        await ouvreDeploiement(page);
        const inexistante = await page.evaluate(() =>
            document.querySelector('[data-rw="superv-reglages-form"]') !== null);
        verifie('une machine inexistante n\'ouvre AUCUN formulaire', ! inexistante);
    }

    const texte = await page.evaluate(() => document.body.innerText);
    verifie('aucun identifiant de traduction a l\'ecran (fr)',
        ! /superv\.[a-z_]+/.test(texte),
        (texte.match(/superv\.[a-z_]+/g) || []).slice(0, 3).join(', '));
    await ctx.close();

    /* ══ 14. LA PASSE ANGLAISE ═════════════════════════════════════════════ */
    await dors((resteFenetre() + 1) * 1000);
    const { ctx: ctxEn, page: pageEn } = await connecte('en');
    await pageEn.goto(`${BASE}${PAGE}?reglages=${MACHINE_DEV}`, { waitUntil: 'networkidle2' });
    await dors(1200);
    verifie('la seconde session (en) est bien authentifiee',
        ! /connexion|login/.test(pageEn.url()), pageEn.url().replace(BASE, ''));
    verifie('l\'onglet du parc s\'ouvre (en)', await ouvreDeploiement(pageEn));
    const texteEn = await pageEn.evaluate(() => document.body.innerText);
    verifie('aucun identifiant de traduction a l\'ecran (en)',
        ! /superv\.[a-z_]+/.test(texteEn),
        (texteEn.match(/superv\.[a-z_]+/g) || []).slice(0, 3).join(', '));
    const anglais = (texteEn.match(/Per-machine settings|Save the settings|Listening port/g) || []);
    verifiePortage('les reglages sont traduits en anglais',
        anglais.length > 0,
        anglais.length ? `trouve : ${anglais.join(', ')}` : 'aucun libelle anglais');
    await ctxEn.close();

    verifie('aucune erreur JS pendant toute la sequence',
        erreursJs.length === 0, erreursJs.slice(0, 3).join(' · ') || 'aucune');
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
} finally {
    const avant = nettoie();
    lignes.push(`INFO  reglages supprimes en sortie : ${avant}`);
    const restant = reglagesEnBase();
    lignes.push(`${restant === 0 ? 'PASS' : 'FAIL'}  la table des reglages est rendue a son `
        + `etat initial  — ${restant} ligne(s)`);
    if (restant !== 0) echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
