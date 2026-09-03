/**
 * go-captures-maintenance.mjs - La page des fenetres de maintenance, EN IMAGES,
 * aux trois largeurs de la convention : 1920, 1400 et 390.
 *
 * Une assertion DOM ne voit ni un tableau qui deborde, ni un avertissement
 * illisible, ni une pastille dont le contraste est inexistant. Trois defauts du
 * chantier n'ont ete vus qu'a l'image, dont une pastille a 1,06:1 que le HTML
 * rendait pourtant juste.
 *
 * ══ LA FIXTURE, ET POURQUOI ELLE EST SANS DANGER ═══════════════════════════
 *
 * Une page vide ne montre rien : il faut une fenetre a l'ecran. Elle est ecrite
 * DIRECTEMENT en base — les gestes sont deja mesures par
 * `go-page-maintenance.mjs`, ici on ne veut qu'un etat a photographier.
 *
 * Sa portee est `machine` sur `srv-zabbix` (id 1), la machine qu'aucune suite ne
 * mute et que la regle permanente interdit de joindre. `is_allowed` filtre
 * `enabled = 1 AND (scope = 'global' OR machine_id = ?)` : cette ligne ne peut
 * donc bloquer que ce qui est **deja interdit**. NOMMER cette machine dans une
 * ligne d'horaire n'est pas la JOINDRE — aucune requete ne part vers elle.
 *
 * Ses bornes encadrent l'heure LOCALE (± 20 min) : c'est ce qui rend l'image
 * interessante, puisque le serveur tranche sur SON horloge. L'ecran doit donc
 * montrer « Fermee maintenant » ET la ligne qui nomme l'horloge du serveur.
 *
 * Nettoyage borne par le NOM dans un `finally`, etat relu pour etre prouve : les
 * autres suites du LOT rendraient 423 si une fenetre survivait.
 *
 * Usage :
 *   cd tests/e2e && node go-captures-maintenance.mjs
 */
import puppeteer from 'puppeteer';
import { mkdirSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const SORTIE = './screenshots/maintenance';

const NOM = 'fenetre-capture-e2e';
const MACHINE_SURE = 1;

const LARGEURS = [
    { nom: 'grand', width: 1920, height: 1080 },
    { nom: 'bureau', width: 1400, height: 900 },
    { nom: 'mobile', width: 390, height: 844 },
];

let echecs = 0;
function note(l) { console.log(l); }
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
 note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { note(`INFO  ${l} : ${v}`); }

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

function compteCapture() {
    return compteEnBase(`SELECT COUNT(*) FROM rootwarden.maintenance_windows WHERE name = '${NOM}'`);
}
function supprimeCapture() {
    litEnBase(`DELETE FROM rootwarden.maintenance_windows WHERE name = '${NOM}'`);
}
function activeesEnBase() {
    return compteEnBase('SELECT COUNT(*) FROM rootwarden.maintenance_windows WHERE enabled = 1');
}
function versHM(minutes) {
    const m = ((minutes % 1440) + 1440) % 1440;

    return `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
}

mkdirSync(SORTIE, { recursive: true });

const d = new Date();
const local = (d.getHours() * 60) + d.getMinutes();
const DEBUT = versHM(local - 20);
const FIN = versHM(local + 20);

const activeesAuDepart = activeesEnBase();
let navigateur = null;

try {
    constate('fenetres ACTIVEES en base au depart', `${activeesAuDepart}`);
    verifie('aucune fenetre de capture ne traine', compteCapture() === 0, `${compteCapture()}`);

    litEnBase("INSERT INTO rootwarden.maintenance_windows "
        + '(name, scope, machine_id, days, start_time, end_time, enabled) VALUES '
        + `('${NOM}', 'machine', ${MACHINE_SURE}, '0,1,2,3,4,5,6', '${DEBUT}:00', '${FIN}:00', 1)`);
    const posee = litEnBase("SELECT CONCAT(scope,'|',machine_id,'|',enabled) "
        + `FROM rootwarden.maintenance_windows WHERE name = '${NOM}'`)[0] || '';
    constate('fixture posee', `${posee} — ${DEBUT} → ${FIN}`);
    /* GARDE-FOU : une portee `global` bloquerait le LOT. On refuse d'aller plus
     * loin plutot que de photographier une base piegee. */
    verifie('la fixture est de portee machine, sur la machine convenue',
        posee === `machine|${MACHINE_SURE}|1`, posee);
    if (posee !== `machine|${MACHINE_SURE}|1`) {
        throw new Error('refus : la fixture n\'a pas la portee convenue');
    }
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

        await page.goto(`${BASE}/maintenance`, { waitUntil: 'networkidle2' });
        /* Attendre que le tableau soit CHARGE : photographier « Chargement… »
         * produirait une image qui ne montre rien de la page. */
        for (let i = 0; i < 40; i += 1) {
            const pret = await page.evaluate(() => {
                const tb = document.querySelector('[data-rw="maint-corps"]');

                return tb && ! /chargement|loading/i.test(tb.textContent || '');
            });
            if (pret) break;
            await dors(250);
        }

        /* CE QUE L'IMAGE DOIT MONTRER, mesure sur le rendu et non sur le DOM. */
        const vu = await page.evaluate(() => {
            const pastille = document.querySelector('[data-rw="maint-etat-flotte"]');
            const horloge = document.querySelector('[data-rw="maint-horloge"]');
            const cadre = document.querySelector('.rw-tableau-cadre');

            return {
                etat: pastille ? pastille.getAttribute('data-rw-etat') : null,
                pastille: pastille ? (pastille.textContent || '').trim() : '',
                horlogeVisible: horloge ? (! horloge.hidden
                    && getComputedStyle(horloge).display !== 'none') : false,
                tableauDeborde: cadre ? cadre.scrollWidth > cadre.clientWidth + 1 : null,
                pageDeborde: document.documentElement.scrollWidth > window.innerWidth + 1,
            };
        });
        /*
         * LE CONTRASTE DES PASTILLES, MESURE SUR LE STYLE CALCULE.
         *
         * Troisieme piege du meme genre dans ce projet : une pastille KEV a
         * 1,06:1 etait INVISIBLE alors que le HTML etait juste, et aucune
         * assertion DOM ne pouvait le voir. On mesure donc le rapport reel, sur
         * les couleurs rendues, pour les pastilles neuves de cette page.
         */
        const contrastes = await page.evaluate(() => {
            function canal(v) {
                const c = v / 255;

                return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
            }
            function luminance(rgb) {
                const [r, g, b] = rgb;

                return (0.2126 * canal(r)) + (0.7152 * canal(g)) + (0.0722 * canal(b));
            }
            function lit(couleur) {
                const m = String(couleur).match(/\d+(\.\d+)?/g);

                return m ? m.slice(0, 3).map(Number) : null;
            }
            /* Un fond transparent laisse voir celui du parent : remonter jusqu'a
             * une couleur reellement peinte, sans quoi on mesurerait un contraste
             * contre du vide. */
            function fondPeint(e) {
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
                const texte = lit(getComputedStyle(e).color);
                const fond = fondPeint(e);
                if (! texte) return null;
                const a = luminance(texte);
                const b = luminance(fond);

                return Math.round(((Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)) * 100) / 100;
            }

            const lignes = document.querySelectorAll('[data-rw="maint-corps"] tr td:nth-child(5) .rw-pastille');

            return {
                flotte: rapport(document.querySelector('[data-rw="maint-etat-flotte"]')),
                etatLigne: rapport(lignes[0] || null),
                horloge: rapport(document.querySelector('[data-rw="maint-horloge"]')),
            };
        });
        constate(`[${format.nom}] contrastes`,
            `flotte ${contrastes.flotte}:1 · etat ${contrastes.etatLigne}:1 · horloge ${contrastes.horloge}:1`);
        for (const [nom, valeur] of Object.entries(contrastes)) {
            /* 4,5:1 est le seuil AA pour du texte courant ; ces pastilles portent
             * du petit texte, donc le seuil « grand texte » ne s'applique pas. */
            verifie(`[${format.nom}] « ${nom} » est lisible (>= 4,5:1)`,
                valeur !== null && valeur >= 4.5, `${valeur}:1`);
        }

        constate(`[${format.nom}] pastille`, `${vu.etat} — « ${vu.pastille} »`);
        verifie(`[${format.nom}] la pastille annonce « machines », pas « flotte »`,
            vu.etat === 'machines', String(vu.etat));
        verifie(`[${format.nom}] l'avertissement d'horloge est visible`, vu.horlogeVisible === true,
            `visible=${vu.horlogeVisible}`);
        /* Le defilement horizontal appartient au CADRE du tableau, jamais a la
         * page : une page qui defile de cote cache la colonne d'actions sans le
         * dire. */
        verifie(`[${format.nom}] la page ne defile pas horizontalement`,
            vu.pageDeborde === false, `deborde=${vu.pageDeborde}`);
        constate(`[${format.nom}] le tableau defile dans son cadre`, `${vu.tableauDeborde}`);

        const chemin = `${SORTIE}/${format.nom}-maintenance.png`;
        await page.screenshot({ path: chemin, fullPage: true });
        constate(`[${format.nom}] capture`, chemin);
        await ctx.close();
    }
} catch (e) {
    verifie('deroulement du script', false, String(e.message || e).split('\n')[0]);
} finally {
    if (navigateur) { try { await navigateur.close(); } catch { /* rien */ } }
    /*
     * NETTOYAGE BORNE PAR LE NOM, puis RELECTURE POUR PREUVE. Une fenetre
     * survivante ferait rendre 423 aux suites suivantes, et l'echec n'aurait
     * aucun rapport visible avec cette capture.
     */
    try {
        supprimeCapture();
        litEnBase('DELETE FROM rootwarden.login_attempts');
    } catch (e) {
        note(`FAIL  nettoyage de la fixture  — ${String(e.message || e).split('\n')[0]}`);
        echecs++;
    }
    verifie('aucune fenetre de capture ne subsiste', compteCapture() === 0, `${compteCapture()}`);
    const activees = activeesEnBase();
    verifie('l\'etat de blocage rendu est celui de l\'entree', activees === activeesAuDepart,
        `${activeesAuDepart} a l'entree, ${activees} a la sortie`);
    note(`\n${echecs} FAIL`);
    process.exit(echecs === 0 ? 0 : 1);
}
