/**
 * go-fail2ban-f5.mjs - Sous-lot F5 de `fail2ban/` : jails et liste blanche.
 *
 * `POST /fail2ban/enable_jail` (fail2ban.py:353), `/disable_jail` (:386) et
 * `/whitelist` (:414). Frontend : `openJailModal` (main.js:381),
 * `submitEnableJail` (:395), `loadWhitelist` (:432), `addWhitelistIp` (:454),
 * `removeWhitelistIp` (:466).
 *
 * ══ POURQUOI LES ECRITURES SONT *SERVIES*, ET CE N'EST PAS PAR PRUDENCE ═══
 *
 * `enable_jail`, `disable_jail` et `whitelist add|remove` font toutes trois
 * `touch /etc/fail2ban/jail.local` : **elles CREENT le fichier**, puis
 * redemarrent le service.
 *
 * Or `go-fail2ban-f3` mesure precisement que ce fichier est ABSENT du banc — la
 * machine y repond `[FICHIER ABSENT]`, et c'est ce retour qui porte E-161.
 * **Laisser passer une seule ecriture de F5 casserait la caracterisation de
 * F3**, et le LOT deviendrait dependant de l'ordre de ses suites.
 *
 * Le filet REPOND donc a ces routes. Ce qui reste mesure : le corps EMIS (la
 * methode, la machine visee, les valeurs), et ce que la page dit — pas l'effet
 * distant, et c'est ecrit ici plutot que sous-entendu.
 *
 * ══ UNE SEULE ECRITURE EST LAISSEE PASSER, ET ELLE NE PEUT PAS ECRIRE ═════
 *
 * Le retrait de `127.0.0.1/8` de la liste blanche. `manage_whitelist` fait la
 * lecture `grep`, PUIS `_validate_ip(ip)` — qui appelle
 * `ipaddress.ip_address()`. Un CIDR y leve une `ValueError`, **avant toute
 * commande d'ecriture**. Le geste se solde donc par une lecture inoffensive et
 * un refus. C'est ce qui rend E-168 mesurable sans rien toucher.
 *
 * ══ CE QUI N'EST PAS MESURE, ET POURQUOI ══════════════════════════════════
 *
 * `manage_whitelist` compose sa premiere branche par INTERPOLATION BRUTE :
 *
 *     f"sed -i '/\\[DEFAULT\\]/a\\{new_line}' /etc/fail2ban/jail.local || "
 *     f"printf '%s\\n' '{base64...}' | base64 -d | ..."
 *
 * `new_line` contient les adresses **deja presentes dans le fichier distant**,
 * lues et decoupees sans aucune validation. Une apostrophe dans `jail.local`
 * casse le litteral shell. La branche de secours du meme `||` passe, elle, par
 * base64 : **une branche sur deux**.
 *
 * **Ce defaut n'est pas exerce.** Le demontrer exigerait d'ecrire une apostrophe
 * dans le `jail.local` d'une vraie machine — c'est-a-dire de le COMMETTRE. Il
 * est releve par LECTURE, et dit comme tel dans `PARITE.md`.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-fail2ban-f5
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';

const MACHINE_ID = 2;
const MACHINE_PRODUCTION = 1;
const JAIL = 'sshd';
/** Le defaut que `manage_whitelist` suppose quand le fichier n'a pas d'`ignoreip`. */
const BLANCHE = ['127.0.0.1/8', '::1'];
/** Celle qu'aucun `_validate_ip` n'acceptera : c'est un CIDR, pas une adresse. */
const IRRETIRABLE = '127.0.0.1/8';
/** TEST-NET-2 (RFC 5737), pour l'ajout. */
const A_AJOUTER = '198.51.100.9';

const STATUT = /\/fail2ban\/status(\?|$)/;
/** Servies : elles CREERAIENT `/etc/fail2ban/jail.local` — voir l'en-tete. */
const ECRITURES = /\/fail2ban\/(enable_jail|disable_jail)(\?|$)/;
const SERVICES = /\/fail2ban\/services(\?|$)/;
const BLANCHE_ROUTE = /\/fail2ban\/whitelist(\?|$)/;
const BASE_SEULE = /\/fail2ban\/(history|stats)(\?|$)/;
const HORS_LOT = /\/fail2ban\/(ban|unban|ban_all_servers|unban_all|install|install_all|restart|geoip|config|logs)(\?|$)/;
const ROUTES_MODULE = /\/fail2ban\/(status|jail|services|history|stats|config|logs|ban|unban|ban_all_servers|unban_all|install|install_all|restart|enable_jail|disable_jail|whitelist|geoip)(\?|$)/;

const DOSSIER_CAPTURES = new URL('./screenshots/fail2ban', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion', page: '/fail2ban',
        serveur: '[data-rw="f2b-serveur"]', relever: '[data-rw="f2b-relever"]',
        blocBlanche: '[data-rw="f2b-blanche"]', listeBlanche: '[data-rw="f2b-blanche-liste"]',
        champBlanche: '[data-rw="f2b-blanche-ip"]', ajouterBlanche: '[data-rw="f2b-blanche-ajouter"]',
        retirer: (ip) => `[data-rw="f2b-blanche-retirer-${ip}"]`,
        activerJail: `[data-rw="f2b-activer-${JAIL}"]`,
        modale: '[data-rw="f2b-jail-reglages"]',
        confirmation: '[data-rw="f2b-confirmation"]', confirmer: '[data-rw="f2b-confirmer"]',
        journal: '[data-rw="f2b-journal"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr', page: '/fail2ban/',
        serveur: '#server', relever: 'button[onclick="loadStatus()"]',
        blocBlanche: '#whitelist-section', listeBlanche: '#whitelist-list',
        champBlanche: '#whitelist-ip-input', ajouterBlanche: 'button[onclick="addWhitelistIp()"]',
        retirer: () => '#whitelist-list > span:first-child button',
        activerJail: `button[onclick="openJailModal('${JAIL}')"]`,
        modale: '#jail-config-modal',
        confirmation: null, confirmer: null,
        journal: '#logs-container',
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
function verifiePortage(l, ok, d) {
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
            const b = /"(machine_id|server_id)"\s*:\s*"?(\d+)"?/.exec(corps);
            if (b) return Number(b[2]);
        }
    } catch { /* corps illisible */ }
    const m = /[?&](machine_id|server_id)=(\d+)/.exec(requete.url());

    return m ? Number(m[2]) : null;
}
function actionDe(requete) {
    try {
        const m = /"action"\s*:\s*"([a-z]+)"/.exec(requete.postData() || '');

        return m ? m[1] : null;
    } catch { return null; }
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
const servies = [];
const boites = [];
let accepteLaBoite = false;

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(60000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => {
        boites.push({ type: d.type(), message: (d.message() || '').slice(0, 160) });
        try { await (accepteLaBoite ? d.accept() : d.dismiss()); } catch {}
    });

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        const url = r.url();
        const chemin = url.replace(/^https?:\/\/[^/]+/, '');
        if (! ROUTES_MODULE.test(url)) { r.continue().catch(() => {}); return; }
        const cible = machineVisee(r);
        const action = actionDe(r);

        if (STATUT.test(url)) {
            servies.push({ route: chemin, machine: cible, quoi: 'statut' });
            r.respond({ status: 200, contentType: 'application/json',
                body: JSON.stringify({ success: true, installed: true, running: true,
                    jails: [{ name: JAIL, currently_banned: 0, total_banned: 0 }] }) }).catch(() => {});

            return;
        }
        if (SERVICES.test(url)) {
            // La detection est deja mesuree par F3 ; ici elle sert seulement a
            // faire paraitre le bouton « + » d'activation d'une jail.
            servies.push({ route: chemin, machine: cible, quoi: 'services' });
            r.respond({ status: 200, contentType: 'application/json',
                body: JSON.stringify({ success: true, services: [
                    { service: 'sshd', installed: true, log_path: '/var/log/auth.log',
                      jails: [{ name: JAIL, available: true, enabled: false }] },
                ] }) }).catch(() => {});

            return;
        }
        if (BLANCHE_ROUTE.test(url)) {
            if (action === 'list') {
                servies.push({ route: chemin, machine: cible, quoi: 'blanche/list' });
                r.respond({ status: 200, contentType: 'application/json',
                    body: JSON.stringify({ success: true, ips: BLANCHE }) }).catch(() => {});

                return;
            }
            // LE SEUL GESTE MUTANT LAISSE PASSER, et il ne peut pas ecrire : le
            // retrait d'un CIDR leve une `ValueError` dans `_validate_ip`, AVANT
            // toute commande d'ecriture. Voir l'en-tete.
            const corps = (() => { try { return r.postData() || ''; } catch { return ''; } })();
            if (action === 'remove' && corps.includes(IRRETIRABLE) && cible === MACHINE_ID) {
                abouties.push({ route: chemin, machine: cible, quoi: 'blanche/remove-cidr' });
                r.continue().catch(() => {});

                return;
            }
            servies.push({ route: chemin, machine: cible, quoi: 'blanche/' + (action || '?') });
            r.respond({ status: 200, contentType: 'application/json',
                body: JSON.stringify({ success: true, ips: BLANCHE.concat([A_AJOUTER]),
                    message: 'servi par la suite — aucune ecriture distante' }) }).catch(() => {});

            return;
        }
        if (ECRITURES.test(url)) {
            servies.push({ route: chemin, machine: cible, quoi: 'jail/' + (/enable/.test(url) ? 'activer' : 'desactiver'),
                corps: (() => { try { return r.postData() || ''; } catch { return ''; } })() });
            r.respond({ status: 200, contentType: 'application/json',
                body: JSON.stringify({ success: true,
                    message: 'servi par la suite — aucune ecriture distante' }) }).catch(() => {});

            return;
        }
        if (BASE_SEULE.test(url) && cible === MACHINE_ID) {
            abouties.push({ route: chemin, machine: cible, quoi: 'base' });
            r.continue().catch(() => {});

            return;
        }
        avortees.push({ route: chemin, machine: cible === null ? '(indetermine)' : String(cible),
            motif: HORS_LOT.test(url) ? 'hors de F5' : 'machine hors perimetre' });
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

async function choisitMachine(page, id) {
    const valeur = await page.evaluate((sel, cible) => {
        const s = document.querySelector(sel);
        if (! s) return null;
        for (const o of s.options) {
            if (! o.value) continue;
            if (o.value === String(cible)) return o.value;
            try { if (JSON.parse(o.value)?.id === cible) return o.value; } catch { /* pas du JSON */ }
        }

        return null;
    }, C.serveur, id);
    if (valeur === null) throw new Error(`aucune option ne designe la machine ${id}`);
    await page.select(C.serveur, valeur);
    await dors(250);
}

async function cliqueEtAttend(page, selecteur, ms) {
    const avant = abouties.length + avortees.length + servies.length;
    await page.click(selecteur);
    for (let i = 0; i < 80; i += 1) {
        if (abouties.length + avortees.length + servies.length > avant) break;
        await dors(200);
    }
    await dors(ms || 1500);
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

let session = null;

try {
    session = await connecte(COMPTE, SECRET);
    verifie('la session a tenu', ! session.surConnexion, session.page.url());
    if (session.surConnexion) throw new Error('session non etablie');
    const page = session.page;

    await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
    await dors(400);
    await choisitMachine(page, MACHINE_ID);
    await cliqueEtAttend(page, C.relever, 2500);

    // ═══ 1. LA LISTE BLANCHE S'AFFICHE ═══════════════════════════════════
    await etape('la liste blanche', async () => {
        const vu = await page.evaluate((sels) => {
            const bloc = document.querySelector(sels.blocBlanche);
            const liste = document.querySelector(sels.listeBlanche);

            return {
                visible: bloc ? (bloc.offsetParent !== null && ! bloc.hidden) : false,
                entrees: liste ? [...liste.children].map((e) => (e.textContent || '').trim()) : [],
                texte: bloc ? (bloc.innerText || '').replace(/\s+/g, ' ').trim() : '',
            };
        }, C);
        constate('bloc visible', `${vu.visible}`);
        constate('entrees rendues', vu.entrees.join(' · ') || '(aucune)');
        verifie('la liste blanche est rendue', vu.visible && vu.entrees.length === BLANCHE.length,
            `visible=${vu.visible} entrees=${vu.entrees.length}`);

        /*
         * D'OU VIENNENT CES DEUX ENTREES ?
         *
         * `manage_whitelist` ne les LIT pas : quand le fichier distant n'a pas de
         * ligne `ignoreip`, il SUPPOSE `['127.0.0.1/8', '::1']`. L'ecran affiche
         * donc une liste blanche qui n'existe nulle part sur la machine, sans
         * jamais dire qu'elle est supposee.
         */
        const ditSuppose = /par défaut|suppos|default|implicite|non lue/i.test(vu.texte);
        constate('l\'ecran dit-il que cette liste est SUPPOSEE ?', ditSuppose ? 'OUI' : 'non');
        verifiePortage('une liste blanche SUPPOSEE est annoncee comme telle',
            ditSuppose,
            '`manage_whitelist` rend `[\'127.0.0.1/8\', \'::1\'] quand le fichier distant n\'a '
            + 'aucune ligne `ignoreip` — l\'ecran affiche donc une liste qui n\'existe pas sur '
            + 'la machine, et rien ne le dit');
    });

    // ═══ 2. LE `×` QUI NE PEUT JAMAIS ABOUTIR ════════════════════════════
    await etape('retirer une entree que le backend refusera', async () => {
        /*
         * `127.0.0.1/8` est un CIDR. `_validate_ip` appelle
         * `ipaddress.ip_address()`, qui le refuse. Son `×` ne peut donc JAMAIS
         * aboutir — et c'est une des deux entrees que la page affiche par defaut.
         *
         * Le geste est laisse passer parce qu'il ne peut pas ecrire : la
         * `ValueError` est levee avant toute commande d'ecriture.
         */
        const cible = C.retirer(IRRETIRABLE);
        const existe = await page.$(cible);
        verifie(`le retrait de ${IRRETIRABLE} est offert a l'ecran`, existe !== null, cible);
        if (! existe) return;

        const avant = boites.length;
        accepteLaBoite = true;
        await cliqueEtAttend(page, cible, 3000);
        accepteLaBoite = false;
        if (C.confirmer) {
            const ouvert = await page.evaluate((s) => {
                const p = document.querySelector(s);

                return p ? (p.offsetParent !== null && ! p.hidden) : false;
            }, C.confirmation);
            if (ouvert) await cliqueEtAttend(page, C.confirmer, 3000);
        }
        constate('confirmations ouvertes', `${boites.length - avant}`);

        const partie = abouties.some((a) => a.quoi === 'blanche/remove-cidr');
        constate('la requete de retrait est-elle partie ?', partie ? 'OUI' : 'non');
        const vu = await page.evaluate((sels) => {
            const j = document.querySelector(sels.journal);
            const liste = document.querySelector(sels.listeBlanche);

            return {
                journal: j ? (j.innerText || '').replace(/\s+/g, ' ').trim().slice(-200) : '',
                entrees: liste ? [...liste.children].map((e) => (e.textContent || '').trim()) : [],
            };
        }, C);
        constate('ce que la page dit', vu.journal.slice(-130) || '(rien)');
        constate('entrees apres le geste', vu.entrees.join(' · ') || '(aucune)');

        /*
         * LA PROPRIETE : on n'offre pas un geste qui ne peut pas aboutir.
         *
         * Soit l'entree ne porte pas de `×`, soit le `×` mene a quelque chose.
         * Le legacy offre les deux, et le refus qui suit n'est meme pas explique
         * — il arrive en fin de course, apres une confirmation.
         */
        verifiePortage('un geste qui ne peut pas aboutir n\'est pas offert',
            ! partie,
            `le × de ${IRRETIRABLE} envoie une requete que le backend refuse toujours : `
            + '`_validate_ip` appelle `ipaddress.ip_address()`, qui n\'accepte pas un CIDR — '
            + 'et c\'est une des DEUX entrees affichees par defaut');
    });

    // ═══ 3. LES GESTES QUI REDEMARRENT LE SERVICE LE DISENT-ILS ? ════════
    await etape('ajouter a la liste blanche', async () => {
        /*
         * `manage_whitelist` finit par `restart_fail2ban(...)`. Ajouter une
         * exemption REDEMARRE donc le service — et un redemarrage lache tous les
         * bans en cours. `addWhitelistIp` n'ouvre aucune confirmation ; c'est
         * `removeWhitelistIp`, qui RETIRE une exemption, qui en ouvre une.
         * Le geste qui affaiblit la protection est celui qui ne confirme pas.
         */
        const avantBoites = boites.length;
        await page.click(C.champBlanche, { clickCount: 3 });
        await page.type(C.champBlanche, A_AJOUTER, { delay: 10 });
        accepteLaBoite = true;
        await cliqueEtAttend(page, C.ajouterBlanche, 2500);
        accepteLaBoite = false;

        const nouvelles = boites.slice(avantBoites);
        const panneau = C.confirmation ? await page.evaluate((s) => {
            const p = document.querySelector(s);

            return p ? { ouvert: p.offsetParent !== null && ! p.hidden,
                texte: (p.innerText || '').replace(/\s+/g, ' ').trim() } : null;
        }, C.confirmation) : null;
        const texteConf = nouvelles.map((b) => b.message).join(' ')
            + ' ' + (panneau && panneau.ouvert ? panneau.texte : '');
        constate('confirmation ouverte', texteConf.trim() ? `« ${texteConf.trim().slice(0, 120) }»` : '(aucune)');

        verifiePortage('ajouter une exemption demande confirmation',
            nouvelles.length > 0 || (panneau && panneau.ouvert),
            'aucune confirmation — alors que RETIRER une exemption en ouvre une : '
            + 'le geste qui affaiblit la protection est celui qui ne confirme pas');
        verifiePortage('le redemarrage du service est ANNONCE',
            /red[eé]marr|restart|coupure|bans en cours/i.test(texteConf),
            '`manage_whitelist` finit par `restart_fail2ban` — le service redemarre, '
            + 'et un redemarrage lache tous les bans en cours. Rien ne le dit');

        if (panneau && panneau.ouvert && C.confirmer) {
            await cliqueEtAttend(page, C.confirmer, 2500);
        }
        const envoyees = servies.filter((s) => s.quoi === 'blanche/add');
        constate('requetes d\'ajout emises', `${envoyees.length}`);
        verifie('l\'ajout vise la machine d\'essai',
            envoyees.every((s) => s.machine === MACHINE_ID),
            envoyees.map((s) => s.machine).join(' '));
    });

    // ═══ 4. ACTIVER UNE JAIL ═════════════════════════════════════════════
    await etape('activer une jail', async () => {
        const bouton = await page.$(C.activerJail);
        verifie('le geste d\'activation d\'une jail est offert', bouton !== null, C.activerJail);
        if (! bouton) return;

        const avantBoites = boites.length;
        accepteLaBoite = true;
        await cliqueEtAttend(page, C.activerJail, 1500);
        const vu = await page.evaluate((sels) => {
            const m = document.querySelector(sels.modale);
            /*
             * `offsetParent` VAUT `null` POUR UN ELEMENT EN `position: fixed`.
             *
             * Une premiere redaction testait `m.offsetParent !== null` : la
             * fenetre de reglages est en `fixed`, elle etait donc declaree
             * FERMEE alors que son contenu se lisait dans la meme mesure —
             * « Configurer le jail : sshd, Template… ». Une modale visible s'y
             * lit comme cachee, sur les DEUX cibles.
             *
             * Ce qui se mesure : la place REELLEMENT occupee a l'ecran.
             */
            const visible = (e) => {
                if (! e || e.hidden) return false;
                const st = getComputedStyle(e);
                if (st.display === 'none' || st.visibility === 'hidden') return false;

                return e.getBoundingClientRect().height > 0;
            };

            return {
                ouverte: visible(m),
                texte: m ? (m.innerText || '').replace(/\s+/g, ' ').trim() : '',
            };
        }, C);
        accepteLaBoite = false;
        constate('fenetre de reglages ouverte', `${vu.ouverte}`);
        constate('ce qu\'elle dit', vu.texte.slice(0, 130) || '(rien)');
        verifie('un panneau de reglages s\'ouvre avant d\'activer', vu.ouverte, `${vu.ouverte}`);

        /*
         * Activer une jail ECRIT `/etc/fail2ban/jail.local` et REDEMARRE le
         * service. La fenetre de reglages propose trois nombres et ne dit ni
         * l'un ni l'autre.
         */
        verifiePortage('la fenetre dit que le service va REDEMARRER',
            /red[eé]marr|restart|bans en cours/i.test(vu.texte),
            '`enable_jail` reecrit `jail.local` et appelle `restart_fail2ban` : la fenetre '
            + 'propose trois nombres et ne dit ni l\'ecriture ni le redemarrage');
        constate('boites natives pendant l\'ouverture', `${boites.length - avantBoites}`);
    });

    // ═══ 5. SURETE ══════════════════════════════════════════════════════
    await etape('surete', async () => {
        constate('requetes SERVIES', servies.map((s) => s.quoi).join(' ') || '(aucune)');
        constate('requetes abouties', abouties.map((a) => `${a.quoi}→${a.machine}`).join(' ') || '(aucune)');
        constate('requetes avortees', avortees.length
            ? avortees.map((a) => `${a.route}→${a.machine} (${a.motif})`).join(' ') : '(aucune)');
        /*
         * LA PROPRIETE DE SURETE DE CE LOT : aucune ecriture distante n'a eu
         * lieu. La seule requete mutante laissee passer est le retrait d'un
         * CIDR, qui ne peut pas ecrire.
         */
        const ecrituresParties = abouties.filter((a) => a.quoi !== 'base' && a.quoi !== 'blanche/remove-cidr');
        verifie('aucune ecriture distante n\'a ete laissee passer',
            ecrituresParties.length === 0,
            ecrituresParties.map((a) => a.quoi).join(' '));
        verifie('aucune requete n\'a vise la production',
            ! [...abouties, ...servies].some((a) => Number(a.machine) === MACHINE_PRODUCTION),
            'une requete a vise `srv-zabbix`');
        verifie('aucune erreur JavaScript', session.erreursJs.length === 0,
            session.erreursJs.join(' | '));
    });

    // ═══ 6. CAPTURES ════════════════════════════════════════════════════
    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                         { n: 'mobile', w: 390, h: 844 }]) {
            await page.setViewport({ width: f.w, height: f.h });
            await dors(350);
            await page.screenshot({ path: `${dossier}/f5-${f.n}.png`, fullPage: true });
        }
        verifie('les trois captures sont ecrites', true, '', `${dossier}/f5-*.png`);
    });
} catch (e) {
    verifie('deroulement sans exception', false, String(e.message || e).split('\n')[0]);
} finally {
    try {
        for (const ctx of contextes) { try { await ctx.close(); } catch {} }
        await navigateur.close();
    } catch { /* deja ferme */ }
}

note(`${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
process.exit(echecs === 0 ? 0 : 1);
