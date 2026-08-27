/**
 * go-captures-fail2ban.mjs - La page fail2ban (sous-lot F1), EN IMAGES, aux
 * trois largeurs de la convention : 1920, 1400 et 390.
 *
 * ══ POURQUOI LES REPONSES SONT *SERVIES* ET NON TRANSMISES ═════════════════
 *
 * Le banc est un CONTENEUR SANS systemd. La seule reponse que la machine 2
 * puisse rendre est « fail2ban absent » : photographier le banc tel quel ne
 * montrerait donc JAMAIS la grille des jails, ni la pastille « actif », ni le
 * compteur d'adresses bannies — c'est-a-dire l'essentiel de ce que F1 rend.
 *
 * Le filet REPOND a `/api/gateway/fail2ban/status` au lieu de la laisser
 * partir. Consequences, toutes voulues :
 *   — tout le chemin de rendu s'execute pour de vrai (le clic, le `fetch`, le
 *     `then`, `rendStatut`, `rendJails`) ; seule la SOURCE de la donnee change ;
 *   — aucune machine n'est jointe, sur aucune des deux cibles ;
 *   — le cache `fail2ban_status` n'est pas ecrit, donc rien a restaurer : ce
 *     script ne touche AUCUN etat partage. Une assertion le verifie en base.
 *
 * Le meme procede, en S3, avait revele deux defauts du portage qui avaient vecu
 * tout un sous-lot cache par un tableau toujours vide. Servir n'est pas tricher :
 * c'est deplacer la frontiere du test d'un cran, et le DIRE.
 *
 * L'etat « machine sensible » se photographie SANS filet et sans danger : il
 * naît d'un `change` sur la liste deroulante, qui n'emet aucune requete. Un
 * compteur de requetes l'atteste.
 *
 * Usage :
 *   cd tests/e2e && node go-captures-fail2ban.mjs            # portage (8444)
 *   E2E_BASE=https://localhost:8443 node go-captures-fail2ban.mjs   # legacy
 */
import puppeteer from 'puppeteer';
import { mkdirSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const SORTIE = './screenshots/fail2ban';

/** Machine 2 = `Test-Server-Debian`, le banc. Jamais la 1 (`srv-zabbix`, PROD). */
const MACHINE_BANC = 2;
const MACHINE_SENSIBLE = 1;

const LARGEURS = [
    { nom: 'grand', width: 1920, height: 1080 },
    { nom: 'bureau', width: 1400, height: 900 },
    { nom: 'mobile', width: 390, height: 844 },
];

/* Les deux charges servies. Elles ont la FORME que le backend rend vraiment :
 * `installed`, `running`, `jails[]` avec `name` et `currently_banned` — releve
 * dans `fail2ban_routes.py`, pas invente. */
const ABSENT = { success: true, installed: false, running: false, jails: [] };
const ACTIF = {
    success: true,
    installed: true,
    running: true,
    jails: [
        { name: 'sshd', currently_banned: 3 },
        { name: 'nginx-http-auth', currently_banned: 0 },
        { name: 'recidive', currently_banned: 1 },
    ],
};

let echecs = 0;
function note(l) { console.log(l); }
function verifie(l, ok, d) { note(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { note(`INFO  ${l} : ${v}`); }

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

function cacheEnBase() {
    /* La colonne est `server_id`, PAS `machine_id` — le reste du module parle
     * de machines, la table parle de serveurs. */
    const l = litEnBase('SELECT CONCAT_WS("|", server_id, installed, running, '
        + 'IFNULL(jails_json,""), total_banned, last_checked) '
        + 'FROM rootwarden.fail2ban_status ORDER BY server_id');

    return l.join(' | ');
}

mkdirSync(SORTIE, { recursive: true });

const cacheAuDepart = cacheEnBase();
let navigateur = null;

try {
    constate('cache `fail2ban_status` au depart', cacheAuDepart || '(vide)');
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

        /* ── LE FILET ────────────────────────────────────────────────────────
         * Il REPOND a la seule route sortante de F1, et laisse tout le reste
         * passer. `charge` dit ce qu'il faut servir au prochain clic. */
        let charge = ABSENT;
        let requetesSortantes = 0;
        await page.setRequestInterception(true);
        page.on('request', (req) => {
            const u = req.url();
            if (/\/(api\/gateway\/)?fail2ban\/status(\?|$)/.test(u)) {
                requetesSortantes += 1;
                req.respond({
                    status: 200,
                    contentType: 'application/json',
                    body: JSON.stringify(charge),
                });

                return;
            }
            req.continue();
        });

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
        verifie(`[${format.nom}] session ouverte`, ! /connexion/.test(page.url()), page.url());

        await page.goto(`${BASE}/fail2ban`, { waitUntil: 'networkidle2' });
        await dors(400);

        async function photo(nom) {
            await page.screenshot({ path: `${SORTIE}/${format.nom}-${nom}.png`, fullPage: true });
        }

        // ── 1. L'ETAT D'ACCUEIL : rien n'est releve, la page GUIDE.
        await photo('1-accueil');

        // ── 2. LA MACHINE SENSIBLE. Un `change`, aucune requete.
        const avant = requetesSortantes;
        await page.select('[data-rw="f2b-serveur"]', String(MACHINE_SENSIBLE));
        await dors(250);
        const avert = await page.evaluate(() => {
            const m = document.querySelector('[data-rw="f2b-etat-message"]');
            if (! m) return { texte: '', rouge: false, visible: false };
            const st = getComputedStyle(m);

            return {
                texte: (m.textContent || '').trim(),
                rouge: m.classList.contains('rw-erreur'),
                visible: st.display !== 'none' && m.getBoundingClientRect().height > 0,
            };
        });
        constate(`[${format.nom}] avertissement machine sensible`, avert.texte || '(vide)');
        verifie(`[${format.nom}] choisir une machine sensible n'emet AUCUNE requete`,
            requetesSortantes === avant, `${requetesSortantes - avant}`);
        verifie(`[${format.nom}] l'avertissement est VISIBLE et signale`,
            avert.visible && avert.rouge && avert.texte.length > 0,
            `visible=${avert.visible} signale=${avert.rouge}`);
        await photo('2-machine-sensible');

        // ── 3. L'ETAT « ABSENT », servi. Le banc reel ne rend que celui-la.
        charge = ABSENT;
        await page.select('[data-rw="f2b-serveur"]', String(MACHINE_BANC));
        await dors(200);
        await page.click('[data-rw="f2b-relever"]');
        await page.waitForSelector('[data-rw="f2b-etat-absent"]', { timeout: 15000 });
        await dors(250);
        const vuAbsent = await page.evaluate(() => {
            const aide = document.querySelector('[data-rw="f2b-statut-contenu"] .rw-aide');
            const jails = document.querySelector('[data-rw="f2b-jails-bloc"]');

            return {
                aide: aide ? (aide.textContent || '').trim() : '',
                jailsCachees: jails ? jails.hidden : null,
            };
        });
        constate(`[${format.nom}] ce que « absent » explique`, vuAbsent.aide || '(rien)');
        verifie(`[${format.nom}] « absent » dit ce que l'etat IMPLIQUE`,
            vuAbsent.aide.length > 0, vuAbsent.aide);
        verifie(`[${format.nom}] aucune grille de jails sous un « absent »`,
            vuAbsent.jailsCachees === true, `hidden=${vuAbsent.jailsCachees}`);
        await photo('3-absent');

        // ── 4. L'ETAT « ACTIF » avec ses jails.
        charge = ACTIF;
        await page.click('[data-rw="f2b-relever"]');
        await page.waitForSelector('[data-rw="f2b-etat-actif"]', { timeout: 15000 });
        await dors(300);
        const vuActif = await page.evaluate(() => {
            /*
             * ══ LE CONTRASTE SE COMPOSE, IL NE SE PARSE PAS ═════════════════
             *
             * Deux erreurs, dans une seule ligne, et elles rendaient un PASS :
             *
             * 1. `color-mix()` se CALCULE en `color(srgb 0.0823529 0.501961
             *    0.239216 / 0.18)` — des composantes de 0 a 1, pas de 0 a 255.
             *    Une lecture par `/\d+/g` y voit « 823529 » et annonce un
             *    contraste de 793 790 048:1, pour un maximum theorique de 21:1.
             *    Aucune notation de couleur ne se lit a l'expression reguliere.
             *
             * 2. Ce fond est TRANSLUCIDE (alpha 0,18). Un contraste calcule
             *    contre une couleur translucide ne veut rien dire : ce que
             *    l'oeil voit, c'est la COMPOSITION sur ce qu'il y a derriere.
             *
             * On empile donc les fonds jusqu'au premier OPAQUE, et on laisse le
             * navigateur composer sur un canevas de 1 px. Il connait toutes les
             * notations qu'il calcule — nous non.
             */
            const cv = document.createElement('canvas');
            cv.width = 1; cv.height = 1;
            const ctx = cv.getContext('2d', { willReadFrequently: true });

            /* Une couleur que le canevas ne SAIT PAS lire laisse `fillStyle`
             * inchange : on le detecte par deux sentinelles differentes, sans
             * quoi un noir legitime passerait pour une erreur. */
            function lisible(c) {
                ctx.fillStyle = '#010203'; ctx.fillStyle = c; const a = ctx.fillStyle;
                ctx.fillStyle = '#040506'; ctx.fillStyle = c; const b = ctx.fillStyle;

                return a === b;
            }
            function compose(couches) {
                ctx.clearRect(0, 0, 1, 1);
                for (const c of couches) { ctx.fillStyle = c; ctx.fillRect(0, 0, 1, 1); }
                const d = ctx.getImageData(0, 0, 1, 1).data;

                return [d[0], d[1], d[2]];
            }
            function canal(v) { const c = v / 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); }
            function lum(rgb) {
                return (0.2126 * canal(rgb[0])) + (0.7152 * canal(rgb[1])) + (0.0722 * canal(rgb[2]));
            }
            /* Les fonds, du plus EXTERIEUR au plus interieur : c'est l'ordre
             * dans lequel ils se peignent. On remonte jusqu'au premier opaque —
             * inutile d'aller au-dela, il masque tout ce qui est derriere. */
            function couchesDeFond(el) {
                const pile = [];
                let n = el;
                while (n) {
                    const c = getComputedStyle(n).backgroundColor;
                    if (c && c !== 'transparent' && lisible(c)) {
                        ctx.clearRect(0, 0, 1, 1);
                        ctx.fillStyle = c; ctx.fillRect(0, 0, 1, 1);
                        const alpha = ctx.getImageData(0, 0, 1, 1).data[3];
                        if (alpha > 0) {
                            pile.unshift(c);
                            if (alpha === 255) { return pile; }
                        }
                    }
                    n = n.parentElement;
                }
                /* Rien d'opaque jusqu'a la racine : le canevas du navigateur est
                 * blanc, on le dit plutot que de le supposer. */
                pile.unshift('rgb(255, 255, 255)');

                return pile;
            }

            const p = document.querySelector('[data-rw="f2b-etat-actif"]');
            const st = getComputedStyle(p);
            const couches = couchesDeFond(p);
            const fondRgb = compose(couches);
            /* La couleur du TEXTE se compose elle aussi sur ce fond : un texte
             * a alpha < 1 ne se lit pas a sa valeur nominale. */
            const texteRgb = compose(couches.concat([st.color]));
            const a = lum(texteRgb);
            const b = lum(fondRgb);
            const contraste = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);

            const cartes = [...document.querySelectorAll('[data-rw^="f2b-jail-"]')];
            const grille = document.querySelector('[data-rw="f2b-jails"]');
            const pistes = grille
                ? getComputedStyle(grille).gridTemplateColumns.split(/\s+/).filter(Boolean)
                : [];

            return {
                contraste: Math.round(contraste * 100) / 100,
                lisibleParLeCanevas: lisible(st.color) && couches.every(lisible),
                brutTexte: st.color,
                brutFond: couches.join('  sur  '),
                composeTexte: `rgb(${texteRgb.join(', ')})`,
                composeFond: `rgb(${fondRgb.join(', ')})`,
                taille: `${st.fontSize} / ${st.fontWeight}`,
                pastille: (p.textContent || '').trim(),
                jails: cartes.map((c) => (c.textContent || '').replace(/\s+/g, ' ').trim()),
                pistes: pistes.join(' '),
                compte: (document.querySelector('[data-rw="f2b-jails-compte"]')?.textContent || '').trim(),
                pageDeborde: document.documentElement.scrollWidth > window.innerWidth + 1,
            };
        });
        constate(`[${format.nom}] pastille « actif »`, `${vuActif.pastille} — contraste ${vuActif.contraste}:1`);
        constate(`[${format.nom}] couleurs declarees`, `texte=${vuActif.brutTexte} fond=${vuActif.brutFond}`);
        constate(`[${format.nom}] couleurs COMPOSEES`, `texte=${vuActif.composeTexte} fond=${vuActif.composeFond} (${vuActif.taille})`);
        constate(`[${format.nom}] compteur de jails`, vuActif.compte);
        constate(`[${format.nom}] jails rendues`, vuActif.jails.join(' · '));
        /* Les pistes a `0px` ne sont PAS un defaut : `auto-fit` effondre les
         * pistes vides, c'est ce qui fait que trois cartes occupent toute la
         * largeur au lieu de se serrer a gauche. On les affiche telles quelles
         * plutot que d'en tirer un compte qui se lirait comme un manque. */
        constate(`[${format.nom}] pistes de la grille (0px = effondrees par auto-fit)`, vuActif.pistes);
        /* Si le canevas n'a pas su lire une couleur, le chiffre ne vaut rien :
         * on le dit, plutot que de rendre un verdict sur une valeur inventee. */
        verifie(`[${format.nom}] toutes les couleurs ont ete LUES`,
            vuActif.lisibleParLeCanevas === true, `${vuActif.lisibleParLeCanevas}`);
        /* CONTRASTE MESURE SUR LE STYLE CALCULE. Troisieme piege du meme genre
         * dans ce projet : une pastille a 1,06:1 etait invisible alors que le
         * HTML etait juste, et aucune assertion DOM ne pouvait le voir. */
        verifie(`[${format.nom}] la pastille « actif » est LISIBLE (>= 4,5:1)`,
            vuActif.contraste >= 4.5, `${vuActif.contraste}:1`);
        verifie(`[${format.nom}] les trois jails sont rendues`, vuActif.jails.length === 3,
            `${vuActif.jails.length}`);
        verifie(`[${format.nom}] la page ne deborde pas lateralement`,
            vuActif.pageDeborde === false, `${vuActif.pageDeborde}`);
        await photo('4-actif');

        await ctx.close();
    }
} catch (e) {
    verifie('deroulement sans exception', false, e.message);
} finally {
    if (navigateur) { try { await navigateur.close(); } catch {} }
    /* AUCUN ETAT PARTAGE N'A ETE TOUCHE : les reponses etant SERVIES, la route
     * `/fail2ban/status` n'a jamais tourne, donc le cache n'a pas ete ecrit.
     * On le PROUVE plutot que de l'affirmer. */
    try {
        const apres = cacheEnBase();
        verifie('le cache `fail2ban_status` est intact', apres === cacheAuDepart,
            `avant=${cacheAuDepart || '(vide)'} apres=${apres || '(vide)'}`);
    } catch (e) {
        verifie('relecture du cache', false, e.message);
    }
}

note(echecs === 0 ? '=== TOUT OK ===' : `=== ${echecs} ECHEC(S) ===`);
process.exit(echecs === 0 ? 0 : 1);
