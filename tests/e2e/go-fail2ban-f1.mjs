/**
 * go-fail2ban-f1.mjs - Sous-lot F1 de `fail2ban/` : statut et jails.
 *
 * `legacy/fail2ban/index.php` (245 l.), `legacy/fail2ban/js/main.js` (627 l.).
 *
 * ══ F1 N'EST PAS UN LOT EN LECTURE SEULE, ET L'INVENTAIRE LE DISAIT ══════
 *
 * `/fail2ban/status` appelle `_update_status_cache`, qui ECRIT dans
 * `fail2ban_status` — un cache de tableau de bord, une ligne par machine. La
 * suite en prend donc une COPIE avant, et la remet apres : un test ne change pas
 * silencieusement un etat partage, meme un cache.
 *
 * ══ L'EN-TETE MENT, ET LE JOURNAL LE PROUVE ══════════════════════════════
 *
 * `index.php:5` annonce « Permissions : admin (2), superadmin (3) ». `:10`
 * applique `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` — **le role 1
 * est admis**. Troisieme occurrence du motif E-36.
 *
 * Aucun compte d'epreuve ne permet de le montrer par un clic : `rw-test-user`
 * (role 1) n'a pas `can_manage_fail2ban`, donc il est refuse — mais par la
 * PERMISSION, pas par le role.
 *
 * **Le journal d'audit tranche.** Un refus par permission s'enregistre
 * « Permission refusee : can_manage_fail2ban » ; un refus par role ne passe
 * jamais par la. Trouver cette ligne apres un 403 oppose a un role 1 prouve donc
 * que `checkAuth` l'a LAISSE PASSER — et que l'en-tete dit faux.
 *
 * C'est une mesure indirecte, et elle est nommee comme telle.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * F1 ne touche qu'au statut et aux jails. Toutes les routes qui BANNISSENT,
 * DEBANNISSENT, INSTALLENT, REDEMARRENT ou modifient une jail sont avortees —
 * ce sont F4, F5 et F6. `srv-zabbix` (id 1) n'est jamais choisie.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-fail2ban-f1
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { execFileSync } from 'child_process';
import { mkdirSync } from 'node:fs';
import { constateArchivage } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTES = [
    { nom: 'rw-test-user',  role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW',
      admis: false, motif: 'refuse par la PERMISSION, pas par le role' },
    { nom: 'rw-test-admin', role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX',
      admis: true,  motif: 'il DETIENT `can_manage_fail2ban`' },
    { nom: 'rw-test-super', role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW',
      admis: true,  motif: 'le role 3 contourne, SANS detenir la permission' },
];
const COMPTE_CAPTURES = 'rw-test-super';

const MACHINE_ID = 2;
const MACHINE_PRODUCTION = 1;

/** Les seules routes que F1 laisse aboutir, et seulement vers la machine 2. */
const LECTURES = /\/fail2ban\/(status|jail|services)(\?|$)/;
/** Tout ce qui bannit, installe, redemarre ou modifie : F4, F5, F6. */
const AUTRES = /\/fail2ban\/(ban|unban|ban_all_servers|unban_all|install|install_all|restart|enable_jail|disable_jail|whitelist|config|logs|geoip)(\?|$)/;
/**
 * Les routes de l'API du module — et **rien d'autre**.
 *
 * Une premiere redaction s'ecrivait `/\/fail2ban\/[a-z_]+/` : elle attrapait
 * **`/fail2ban/js/main.js`**, le JavaScript de la page. Le script n'etait donc
 * jamais charge, la page rendait son HTML statique — les selecteurs se
 * trouvaient — mais **rien ne s'executait**. La suite passait au vert en
 * mesurant une page morte : zero requete, zero erreur JS, et pas une assertion
 * pour le dire.
 *
 * Quatrieme fois de la session qu'un filet vise trop large. Le motif exige donc
 * une fin de chemin SANS extension de fichier, et liste les routes reelles.
 */
const ROUTES_MODULE = /\/fail2ban\/(status|jail|services|ban|unban|ban_all_servers|unban_all|install|install_all|restart|enable_jail|disable_jail|whitelist|config|logs|geoip)(\?|$)/;

const DOSSIER_CAPTURES = new URL('./screenshots/fail2ban', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion', page: '/fail2ban',
        serveur: '[data-rw="f2b-serveur"]', statut: '[data-rw="f2b-statut"]',
        jails: '[data-rw="f2b-jails"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr', page: '/fail2ban/',
        serveur: '#server', statut: '#status-container', jails: '#jails-grid',
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
            const b = /"(machine_id|server_id)"\s*:\s*"?(\d+)"?/.exec(corps);
            if (b) return Number(b[2]);
        }
    } catch { /* corps illisible */ }
    const m = /[?&](machine_id|server_id)=(\d+)/.exec(requete.url());

    return m ? Number(m[2]) : null;
}

/** Le cache de statut de la machine d'essai, en une chaine comparable. */
function cacheEnBase() {
    const r = litEnBase(`SELECT CONCAT_WS('|', installed, running, total_banned, `
        + `IFNULL(jails_json,''), last_checked) FROM rootwarden.fail2ban_status `
        + `WHERE server_id = ${MACHINE_ID}`);

    return r[0] || '(absent)';
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});
const contextes = [];
const abouties = [];
/** Les sondes E-152, laissees passer DELIBEREMENT — voir le filet. */
const sondes = [];
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
        // LE GARDE VISE LES NOMS DE ROUTES : `/fail2ban/` est aussi le chemin de
        // LA PAGE, et l'avorter tuerait la suite (piege paye en B2).
        if (! ROUTES_MODULE.test(url)) { r.continue().catch(() => {}); return; }

        /*
         * LA SONDE E-152 EST DELIBEREE : LE FILET DOIT LA LAISSER PASSER.
         *
         * Premiere redaction : elle partait sans marque, `machineVisee` rendait
         * `null` sur un corps VIDE — c'est tout l'objet de la sonde — et le filet
         * l'avortait comme « machine hors perimetre ». Les six mesures rendaient
         * `HTTP 0 — Failed to fetch`, et l'assertion accusait le BACKEND de ne
         * pas repondre. **Le filet avait fabrique le defaut qu'il rapportait
         * ensuite** — le piege que ce chantier documente, commis ici.
         *
         * La laisser passer est SUR, et ce n'est pas une concession : le corps
         * vide fait sortir la route sur « machine_id requis. » (400) AVANT tout
         * `ssh_session` (`fail2ban.py:131-133`). Aucune machine n'est jointe.
         */
        if (r.headers()['x-sonde-e152']) {
            sondes.push(url.replace(/^https?:\/\/[^/]+/, ''));
            r.continue().catch(() => {});

            return;
        }
        const cible = machineVisee(r);
        if (LECTURES.test(url) && ! AUTRES.test(url) && cible === MACHINE_ID) {
            abouties.push({ route: url.replace(/^https?:\/\/[^/]+/, ''), machine: cible });
            r.continue().catch(() => {});

            return;
        }
        avortees.push({
            route: url.replace(/^https?:\/\/[^/]+/, ''),
            machine: cible === null ? '(indetermine)' : String(cible),
            motif: AUTRES.test(url) ? 'appartient a F4, F5 ou F6' : 'machine hors perimetre',
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

// LE CACHE EST RELEVE AVANT TOUTE NAVIGATION — voir l'en-tete, F1 ECRIT.
const CACHE_ORIGINE = cacheEnBase();

try {
    /*
     * ══ LE SUJET DE CETTE SUITE N'EXISTE PLUS COTE LEGACY ═════════════════
     *
     * Une suite de parite dont la moitie legacy a ete archivee ne doit pas
     * ECHOUER : un rouge permanent finit par ne plus etre lu, et il occupe la
     * place ou l'on aurait cherche une vraie regression. Elle CONSTATE, et sa
     * moitie portage continue de s'exercer.
     *
     * LE CONSTAT VIENT AVANT LA CONNEXION, et ce n'est pas un detail : la sonde
     * de `archive.mjs` n'ouvre pas de navigateur (Apache rend 404 pour un chemin
     * absent AVANT toute redirection de connexion). Se connecter d'abord ferait
     * consommer un code TOTP — dont le garde anti-rejeu est par COMPTE et
     * PERSISTANT — pour aller mesurer une page qui n'existe plus.
     *
     * ⚠ ET LE CONSTAT EXIGE UN 404, PAS UNE ABSENCE DE PAGE. Le 2026-09-05 ces
     * repertoires rendaient 403 : le `git mv` avait emporte les `.php` et laisse
     * le JavaScript, si bien que le dossier existait encore. `constateArchivage`
     * traite tout statut != 404 comme « encore servie » et rend `false` : le
     * constat aurait ete FAUX et la suite rouge quand meme. L'archivage a ete
     * acheve (`7588e71`) avant que cette ligne soit ecrite.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: C.page, fichiers: [], verifie, constate,
        });
        if (archivee) throw new Error('__archivee__');
    }

    constate('cache `fail2ban_status` a l\'entree', CACHE_ORIGINE);
    const detenteurs = litEnBase(
        'SELECT u.name FROM rootwarden.users u JOIN rootwarden.permissions p ON p.user_id = u.id '
        + "WHERE p.can_manage_fail2ban = 1 AND u.name LIKE 'rw-test-%' ORDER BY u.name");
    constate('comptes d\'epreuve detenant `can_manage_fail2ban`', detenteurs.join(', ') || '(aucun)');
    verifie('seul `rw-test-admin` detient la permission',
        detenteurs.length === 1 && detenteurs[0] === 'rw-test-admin',
        `detenteurs : ${detenteurs.join(', ') || 'aucun'} — les attendus ne valent plus`);

    const refusAvant = compteEnBase('SELECT COUNT(*) FROM rootwarden.user_logs '
        + "WHERE action LIKE '%Permission refusee%can_manage_fail2ban%'");

    for (const compte of COMPTES) {
        await etape(`garde : ${compte.nom} (role ${compte.role})`, async () => {
            const s = await connecte(compte.nom, compte.secret);
            try {
                verifie(`${compte.nom} : la session a tenu`, ! s.surConnexion, s.page.url());
                if (s.surConnexion) return;
                const rep = await s.page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
                const statut = rep ? rep.status() : 0;
                constate(`${compte.nom} : statut`, `${statut} — ${compte.motif}`);
                verifie(`${compte.nom} (role ${compte.role}) est ${compte.admis ? 'admis' : 'refuse'}`,
                    compte.admis ? statut === 200 : statut === 403, `statut ${statut}`);

                /*
                 * ══ E-152 — LA SONDE A CORPS VIDE, ET SON TEMOIN ═══════════
                 *
                 * 16 des 19 routes de `fail2ban.py` ne portent NI role NI
                 * permission : seule la PAGE est gardee. La sonde mesure ce que
                 * le BACKEND oppose, la ou l'ecran ne dit rien.
                 *
                 * POURQUOI UN CORPS VIDE. `require_machine_access` ne trouve
                 * alors aucun identifiant a refuser — son no-op connu, « un
                 * garde sans objet ne garde rien » — et laisse passer ; c'est le
                 * corps de la route qui refuse ensuite (`machine_id requis.`,
                 * 400). La faiblesse du garde du dessous devient donc
                 * l'INSTRUMENT qui mesure le garde pose au-dessus de lui. Et
                 * l'on mesure au STATUT, jamais au texte du corps.
                 *
                 * CE QUE CETTE SONDE REND AUJOURD'HUI :
                 *     rw-test-user   role 1, SANS la permission  -> 400
                 *     rw-test-admin  role 2, AVEC la permission  -> 400
                 *     rw-test-super  role 3, contournement       -> 400
                 * **Les trois se ressemblent, et c'est le resultat attendu** :
                 * le patch d'E-152 est GELE, donc aucune permission n'est encore
                 * exigee sur cette route. C'est la BASE ROUGE de la propriete.
                 * Le jour ou le correctif sera pose, seule la PREMIERE ligne
                 * passera a 403 — les deux autres resteront a 400, et c'est
                 * ce qui isolera la cause. Un 400 lu ici n'est donc PAS un
                 * echec de la sonde.
                 *
                 * REQUETE FORGEE, et son motif : aucune interface n'envoie un
                 * corps vide, donc aucun `<input>` ne peut violer cette
                 * propriete. Elle part DEPUIS LA PAGE, avec la session reelle.
                 */
                const sonde = await s.page.evaluate(async (chemin) => {
                    try {
                        const rep = await fetch(chemin, {
                            method: 'POST', credentials: 'same-origin',
                            // La marque que le filet reconnait : sans elle, la
                            // sonde est avortee comme « machine hors perimetre ».
                            headers: { 'Content-Type': 'application/json',
                                'X-Sonde-E152': '1' },
                            body: '{}',
                        });

                        return { statut: rep.status, corps: (await rep.text()).slice(0, 120) };
                    } catch (e) { return { statut: 0, corps: String(e.message || e) }; }
                }, CIBLE === 'laravel'
                    ? '/api/gateway/fail2ban/status' : '/api_proxy.php/fail2ban/status');
                constate(`${compte.nom} : sonde E-152 (corps vide)`,
                    `HTTP ${sonde.statut} — ${sonde.corps}`);

                /*
                 * LA SONDE N'EST PAS EMISSIBLE DEPUIS UNE PAGE REFUSEE, et le
                 * legacy vient de me l'apprendre. `rw-test-user` y rend
                 * « Aucun jeton CSRF trouve dans la requete » : le legacy
                 * SURCHARGE `window.fetch` pour y joindre le jeton (`js/utils.js`),
                 * et sur la page 403 servie a ce compte ce script n'est jamais
                 * charge. Ma requete forgee part donc SANS jeton, et le proxy la
                 * refuse — pour une raison qui n'a rien a voir avec E-152.
                 *
                 * On ne peut pas asserter une propriete du BACKEND a travers un
                 * refus du PROXY. On le DIT — une propriete sans objet ne se
                 * tait pas — mais on ne compte pas un echec la ou la mesure n'a
                 * pas eu lieu : ce serait un rouge permanent qui n'apprend rien.
                 */
                const sansJeton = /csrf|jeton/i.test(sonde.corps);
                if (sansJeton) {
                    constate(`${compte.nom} : sonde E-152 NON MESURABLE`,
                        `le proxy refuse faute de jeton CSRF — la page etant refusee a ce compte, `
                        + 'la surcouche `fetch` qui joint le jeton n\'est pas chargee. '
                        + 'La propriete se mesure sur le PORTAGE, ou la passerelle lit '
                        + 'le jeton dans l\'en-tete du cadre');
                } else {
                    verifie(`${compte.nom} : la route repond, et son refus n'est pas un 403 de PERMISSION`,
                        sonde.statut === 400,
                        `HTTP ${sonde.statut} — un 403 ICI signifie que le correctif d'E-152 est POSE `
                        + '(attendu, et alors il faut inverser cette attente pour le role 1 seul) ; '
                        + 'tout autre statut est un defaut',
                        `HTTP ${sonde.statut}`);
                }
            } finally {
                await s.ctx.close();
            }
        });
        await dors((resteFenetre() + 1) * 1000);
    }

    // ══ L'EN-TETE MENT, ET LE JOURNAL LE PROUVE ══════════════════════════
    await etape('l\'en-tete dit-il vrai sur les roles admis ?', async () => {
        const refusApres = compteEnBase('SELECT COUNT(*) FROM rootwarden.user_logs '
            + "WHERE action LIKE '%Permission refusee%can_manage_fail2ban%'");
        constate('refus par PERMISSION journalises pendant la suite', String(refusApres - refusAvant));

        // MESURE INDIRECTE, ET NOMMEE COMME TELLE. Un refus par ROLE ne passe
        // jamais par `checkPermission` : trouver une ligne « Permission
        // refusee » apres le 403 oppose au role 1 prouve que `checkAuth` l'a
        // LAISSE PASSER — donc que l'en-tete, qui annonce « admin (2),
        // superadmin (3) », dit faux.
        verifie('le refus oppose au role 1 vient de la PERMISSION, pas du role',
            refusApres > refusAvant,
            'aucun refus de permission journalise : le role aurait donc refuse en amont');
        // LA PROPRIETE SE MESURE, ELLE NE SE POSTULE PAS.
        //
        // Une premiere redaction ecrivait `false` en dur : INFO cote legacy,
        // mais ECHEC cote portage — sur une page dont la documentation dit
        // pourtant vrai. **Une assertion codee en dur ne mesure rien** ; elle
        // affirme ce que son auteur croyait au moment de l'ecrire.
        //
        // Ce qui se mesure : est-ce que la SOURCE annonce un acces plus strict
        // que ce que la garde applique ? Le legacy dit « admin (2), superadmin
        // (3) » et admet le role 1. Le portage doit dire le role 1.
        // ON NE LIT QUE LES COMMENTAIRES, JAMAIS LE CODE.
        //
        // Une premiere redaction lisait les vingt premieres lignes du fichier —
        // donc l'en-tete ET le `checkAuth([ROLE_USER, ...])` de la ligne 10. Elle
        // concluait « la source cite le role 1 » a partir du CODE, et dedouanait
        // ainsi un fichier qui ment. **Un faux PASS, c'est-a-dire le sens le
        // plus couteux** : une accusation fausse se corrige, une exoneration
        // fausse se propage.
        //
        // La propriete porte sur ce que la source ANNONCE. On ne retient donc
        // que les lignes de commentaire.
        const brut = CIBLE === 'laravel'
            ? execFileSync('docker', ['exec', 'rootwarden_laravel', 'sh', '-c',
                'cat /var/www/html/app/Services/Fail2ban.php '
                + '/var/www/html/app/Http/Controllers/Fail2banController.php'],
                { encoding: 'utf8' })
            : execFileSync('sh', ['-c', 'cat legacy/fail2ban/index.php'],
                { encoding: 'utf8', cwd: new URL('../..', import.meta.url).pathname });
        const source = brut.split('\n')
            .filter((l) => /^\s*(\/\*|\*|\/\/)/.test(l))
            .join('\n');

        // Une annonce est « plus stricte » si elle enumere les roles admis SANS
        // citer le role 1, alors que la garde l'admet.
        const annonceRoles = /Permissions?\s*:.*admin\s*\(2\)/i.test(source);
        const citeRole1 = /role\s*1|ROLE_USER|role:1/i.test(source);
        constate('la source enumere-t-elle les roles admis ?', annonceRoles ? 'OUI' : 'non');
        constate('cite-t-elle le role 1 ?', citeRole1 ? 'OUI' : 'non');
        verifiePortage('la source n\'annonce pas un acces plus strict que la garde appliquee',
            ! annonceRoles || citeRole1,
            'l\'en-tete enumere « admin (2), superadmin (3) » sans citer le role 1, '
            + 'que la garde admet — troisieme occurrence du motif E-36');
    });

    const s = await connecte(COMPTE_CAPTURES, COMPTES[2].secret);
    const { page, erreursJs } = s;
    verifie('la session de capture a tenu', ! s.surConnexion, page.url());

    await etape('la page rend son selecteur et ses zones', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const vu = await page.evaluate((sels) => ({
            serveur: document.querySelector(sels.serveur) !== null,
            machines: [...(document.querySelector(sels.serveur)?.options || [])]
                .map((o) => (o.textContent || '').trim()).filter(Boolean),
            statut: document.querySelector(sels.statut) !== null,
            jails: document.querySelector(sels.jails) !== null,
            // Un symbole que SEUL le script du module pose. Sa presence prouve
            // que le fichier a ete charge ET evalue — un `<script>` present dans
            // le HTML ne prouve ni l'un ni l'autre.
            // Un symbole que SEUL le script du module pose. Sa presence prouve
            // que le fichier a ete charge ET evalue — un `<script>` present dans
            // le HTML ne prouve ni l'un ni l'autre.
            //
            // Legacy : `getServer` est declare en global par `js/main.js`.
            // Portage : son script pose `window.RW_FAIL2BAN`.
            scriptCharge: typeof window.getServer === 'function'
                || window.RW_FAIL2BAN === true,
        }), C);
        constate('machines proposees', vu.machines.join(' · ') || '(aucune)');
        // LE SCRIPT DE LA PAGE A-T-IL TOURNE ? Sans lui, la page rend son HTML
        // statique et TOUT le reste de la suite mesure une page morte. La
        // premiere redaction du filet avortait `/fail2ban/js/main.js` et la
        // suite passait au vert sans que rien ne le dise.
        constate('le script de la page a tourne', vu.scriptCharge ? 'OUI' : 'NON');
        verifie('le script de la page a bien ete charge et execute', vu.scriptCharge,
            'aucun symbole du module en memoire : le script n\'a pas tourne, '
            + 'et tout ce qui precede ne mesure rien');
        verifie('le selecteur de machine est present', vu.serveur);
        verifie('les zones statut et jails existent', vu.statut && vu.jails,
            `statut=${vu.statut} jails=${vu.jails}`);
        constate('`srv-zabbix` est-elle proposee ?',
            vu.machines.some((m) => /zabbix/i.test(m)) ? 'OUI' : 'non');
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
            await dors(500);
            await page.screenshot({ path: `${dossier}/fail2ban-f1-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    const causeesParLeFilet = erreursJs.filter((e) => /Failed to fetch|blocked/i.test(e)).length;
    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    verifiePortage('aucune erreur JavaScript etrangere a l\'avortement',
        erreursJs.length === causeesParLeFilet,
        erreursJs.filter((e) => ! /Failed to fetch|blocked/i.test(e)).slice(0, 2).join(' | '));

} catch (e) {
    // `__archivee__` n'est pas une panne : c'est la sortie NORMALE quand le
    // sujet legacy a ete archive. Le constat a deja tout dit.
    if (String(e && e.message || e).includes('__archivee__')) { /* rien a ajouter */ } else {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
    }
} finally {
    try {
        const maintenant = cacheEnBase();
        constate('cache `fail2ban_status` a la sortie', maintenant);
        if (maintenant !== CACHE_ORIGINE && CACHE_ORIGINE !== '(absent)') {
            // LE CACHE EST REMIS. `/fail2ban/status` le rafraichit — c'est son
            // role — mais une suite ne laisse pas derriere elle un etat partage
            // modifie, meme un cache : d'autres mesures s'y appuient.
            const champs = CACHE_ORIGINE.split('|');
            litEnBase(`UPDATE rootwarden.fail2ban_status SET installed = ${Number(champs[0]) || 0}, `
                + `running = ${Number(champs[1]) || 0}, total_banned = ${Number(champs[2]) || 0}, `
                + `last_checked = '${champs[4]}' WHERE server_id = ${MACHINE_ID}`);
            constate('cache remis', cacheEnBase());
        }
        verifie('le cache de statut est rendu a son etat d\'entree',
            cacheEnBase().split('|').slice(0, 3).join('|') === CACHE_ORIGINE.split('|').slice(0, 3).join('|'),
            `${cacheEnBase()} au lieu de ${CACHE_ORIGINE}`);
    } catch (e) { note(`FAIL  restauration du cache : ${e.message}`); echecs += 1; }
    try {
        for (const r of avortees) constate('  AVORTEE', `${r.route} · machine ${r.machine} · ${r.motif}`);
        constate('requetes abouties', abouties.length
            ? [...new Set(abouties.map((r) => r.route))].join(' · ') : '(aucune)');
        verifie('aucune requete aboutie ne visait une autre machine que la 2',
            abouties.every((r) => r.machine === MACHINE_ID));
        verifie('aucune requete de bannissement ou d\'installation n\'a abouti',
            abouties.every((r) => ! AUTRES.test(r.route)),
            abouties.map((r) => r.route).join(' · '));
        verifie('la production n\'a ete visee par aucune requete aboutie',
            abouties.every((r) => r.machine !== MACHINE_PRODUCTION));
    } catch (e) { note(`FAIL  controle des requetes : ${e.message}`); echecs += 1; }
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
