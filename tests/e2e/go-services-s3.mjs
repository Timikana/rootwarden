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
