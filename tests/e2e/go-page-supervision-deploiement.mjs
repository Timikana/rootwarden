/**
 * go-page-supervision-deploiement.mjs - Module `supervision/`, sous-lot V12 :
 * le DEPLOIEMENT d'un agent (flux `text/plain`, INSTALLE, et commence par PURGER).
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/supervision/   (`confirm()` natif + action de masse)
 *   laravel  http://localhost:8444/supervision     (panneau + etapes + VERIFICATION)
 *
 * == POURQUOI CETTE SUITE PEUT CLIQUER LE GESTE QUI INSTALLE ==================
 *
 * Le geste porte sur UNE machine, celle de la ligne : **Test-Server-Debian
 * (id 2, DEV)**. `srv-zabbix` (id 1, PROD) n'est jamais visee — et la suite
 * OUVRE pourtant le panneau sur sa ligne, pour mesurer que la production est
 * NOMMEE. Ouvrir n'envoie rien : la propriete est mesuree AU RESEAU, en
 * comptant les requetes vers `/deploy`, pas en regardant le DOM.
 *
 * Le perimetre a ete MESURE avant d'etre paye, et il est etroit par accident :
 *
 *   - ni `wget` ni `curl` sur le banc  -> la chaine s'arrete AVANT l'URL, donc
 *     aucune requete ne part vers repo.zabbix.com ;
 *   - pas de resolution DNS            -> `apt-get update` echoue vite ;
 *   - `zabbix-agent2` hors de l'index  -> `apt-get install` rend 100 ;
 *   - pas de `systemctl`               -> le redemarrage rend 127.
 *
 * Rien ne s'installe donc, et rien ne sort. Les deux SEULS effets reels sont un
 * fichier ecrit dans `/etc/zabbix/` et une ligne dans `supervision_agents` :
 * tous deux nettoyes dans un `finally`, avec l'etat RELU pour etre prouve.
 *
 * == LA PROPRIETE CENTRALE ===================================================
 *
 * Le backend ne regarde AUCUN code de retour : `yield from
 * execute_as_root_stream(...)` ignore la valeur rendue, et `_upsert_agent`
 * inscrit l'agent quoi qu'il arrive. Releve du flux, sur le banc :
 *
 *     Execution terminee (code 127).   <- wget absent
 *     Execution terminee (code 100).   <- paquet introuvable
 *     Execution terminee (code 127).   <- systemctl absent
 *     SUCCESS_MACHINE::2::Deploiement reussi pour Test-Server-Debian.
 *
 * Trois echecs, un succes annonce, et `supervision_agents` qui porte
 * `machine 2, zabbix, 7.0, config_deployed = 1` alors que `dpkg-query` ne trouve
 * aucun paquet. Le portage lit le flux ENTIER, conclut a l'ECHEC en citant les
 * codes, puis VERIFIE : la detection de version ne trouve rien, et il dit que
 * c'est l'inventaire qui a tort.
 *
 * == LA 19e CLE CASSEE, ET LA PLUS INSTRUCTIVE ===============================
 *
 * `confirm_deploy` n'est pas une traduction manquante : elle EXISTE, en FR et en
 * EN, correctement redigee — dans `lang/*​/supervision.php`, donc hors de
 * l'espace `js.` que `getJsTranslations('js.')` charge. Elle est ecrite,
 * correcte, et inaccessible. Le repli `|| 'Confirmer le deploiement ?'` a bien
 * ete anticipe, mais il reste inerte : `__()` rend la cle TELLE QUELLE, donc une
 * chaine non vide. La suite mesure les DEUX faits.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-supervision-deploiement.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';
import { execFileSync } from 'child_process';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/supervision' : '/supervision/';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

const MACHINE_DEV = 2;
const MACHINE_PROD = 1;
const CONTENEUR = 'rootwarden_test_server';
const VERSION_DEMANDEE = '7.0';

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
function verifie(l, ok, d) { lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`); if (!ok) echecs++; }
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }
function verifiePortage(l, ok, d) {
    if (CIBLE === 'laravel') return verifie(l, ok, d);
    constate(l, `ecart assume du legacy — ${d}`);
}

function surLaMachine(...args) {
    try {
        return execFileSync('docker', ['exec', CONTENEUR, ...args],
            { encoding: 'utf8', timeout: 40000 });
    } catch (e) {
        return `(echec: ${String(e.message || e).split('\n')[0]})`;
    }
}

/** Ce que `/etc/zabbix/` porte reellement. Vide = la chaine `(vide)`. */
function repertoireZabbix() {
    const brut = surLaMachine('sh', '-c', 'ls -A /etc/zabbix/ 2>/dev/null | tr "\\n" " "').trim();

    return brut === '' ? '(vide)' : brut;
}

/** Un agent est-il REELLEMENT installe ? Le paquet ET le binaire. */
function agentInstalle() {
    return surLaMachine('sh', '-c',
        'command -v zabbix_agent2 zabbix_agentd >/dev/null 2>&1 && echo OUI || echo NON').trim();
}

function inventaire() {
    return compteEnBase(
        `SELECT COUNT(*) FROM rootwarden.supervision_agents WHERE machine_id = ${MACHINE_DEV}`);
}

function configGlobales() {
    return compteEnBase("SELECT COUNT(*) FROM rootwarden.supervision_config WHERE platform = 'zabbix'");
}

function poseConfigGlobale() {
    litEnBase('INSERT INTO rootwarden.supervision_config (platform, agent_type, agent_version,'
        + ' zabbix_server, zabbix_server_active, listen_port, hostname_pattern, tls_connect, tls_accept)'
        + ` VALUES ('zabbix','zabbix-agent2','${VERSION_DEMANDEE}','10.0.0.253','10.0.0.253',`
        + "10050,'{machine.name}','unencrypted','unencrypted')");
}

function nettoie() {
    const avant = `/etc/zabbix/=${repertoireZabbix()} agent=${agentInstalle()} `
        + `inventaire=${inventaire()} config=${configGlobales()}`;
    surLaMachine('sh', '-c', 'rm -f /etc/zabbix/zabbix_agent2.conf /etc/zabbix/zabbix_agent2.conf.old'
        + ' /etc/zabbix/zabbix_agentd.conf /etc/zabbix/zabbix_agentd.conf.old');
    litEnBase(`DELETE FROM rootwarden.supervision_agents WHERE machine_id = ${MACHINE_DEV}`);
    litEnBase("DELETE FROM rootwarden.supervision_config WHERE platform = 'zabbix'");

    return avant;
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 240000,
});

async function connecte(langue) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(40000);
    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };
    await page.goto(`${BASE}${chemins.connexion}?lang=${langue}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', 'rw-test-admin', { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
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

/** L'etat du bouton de deploiement d'une ligne, cote portage. */
async function etatBouton(page, mid) {
    return page.evaluate((id) => {
        const b = document.querySelector(`[data-rw="superv-deployer"][data-machine="${id}"]`);
        if (! b) return { present: false };

        return { present: true, desactive: b.disabled === true, infobulle: b.title || '' };
    }, mid);
}

async function cliqueDeployer(page, mid) {
    return page.evaluate((id) => {
        const portage = document.querySelector(`[data-rw="superv-deployer"][data-machine="${id}"]`);
        if (portage) {
            if (portage.disabled) return 'desactive';
            portage.click();

            return 'clique';
        }
        const leg = [...document.querySelectorAll('button')].find((b) =>
            (b.getAttribute('onclick') || '').includes(`deploySingle(${id})`));
        if (! leg) return 'absent';
        leg.click();

        return 'clique';
    }, mid);
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
            await verifieMenuLegacy(page, '/supervision', verifie);
            await ctx.close();
            console.log(lignes.join('\n'));
            console.log(`\n${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
            await navigateur.close();
            process.exit(echecs > 0 ? 1 : 0);
        }
    }

    constate('cible', `${CIBLE} — ${PAGE}`);
    constate('machine visee', `id ${MACHINE_DEV} (DEV) — srv-zabbix jamais deployee`);
    constate('etat a l\'entree', nettoie());
    /*
     * LE PERIMETRE, MESURE AVANT D'ETRE PAYE. Un chemin destructeur se simule
     * d'abord (V11) ; ici on constate surtout que l'outil de telechargement
     * MANQUE, donc que la chaine s'arrete avant toute requete sortante.
     */
    constate('outils reseau sur le banc', surLaMachine('sh', '-c',
        'command -v wget >/dev/null 2>&1 && echo "wget=OUI" || echo "wget=ABSENT";'
        + ' command -v curl >/dev/null 2>&1 && echo "curl=OUI" || echo "curl=ABSENT"')
        .trim().replace(/\n/g, ' '));
    constate('simulation de l\'installation', surLaMachine('sh', '-c',
        'apt-get install -y --dry-run zabbix-agent2 >/dev/null 2>&1; echo "code=$?"').trim());

    /* ── LA CLE `confirm_deploy` : ECRITE, CORRECTE, INACCESSIBLE ───────────
     * Mesuree NOMINATIVEMENT, dans QUEL fichier. Deux faits distincts : elle
     * existe dans les deux langues, et elle est absente de l'espace `js.`.
     */
    const cleDansSupervision = execFileSync('docker',
        ['exec', 'rootwarden_php', 'sh', '-c',
            'for L in fr en; do grep -c "supervision.confirm_deploy" '
            + '/var/www/html/lang/$L/supervision.php; done'],
        { encoding: 'utf8', timeout: 15000 }).trim().split('\n').map(Number);
    const cleDansJs = execFileSync('docker',
        ['exec', 'rootwarden_php', 'sh', '-c',
            'grep -c "js.confirm_deploy" /var/www/html/lang/fr/js.php || true'],
        { encoding: 'utf8', timeout: 15000 }).trim();
    verifie('la traduction de la confirmation EXISTE, en FR et en EN',
        cleDansSupervision.length === 2 && cleDansSupervision.every((n) => n >= 1),
        `supervision.php fr=${cleDansSupervision[0]} en=${cleDansSupervision[1]}`);
    verifie('mais elle est ABSENTE de l\'espace `js.` que le script charge',
        cleDansJs === '0', `js.confirm_deploy dans js.php : ${cleDansJs} occurrence(s)`);

    const { ctx, page } = await connecte('fr');
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const dialogues = [];
    page.on('dialog', (d) => {
        dialogues.push(`${d.type()}: ${d.message().slice(0, 80)}`);
        // Cote legacy on ACCEPTE : c'est le seul moyen de mesurer ce qui suit.
        d.accept().catch(() => {});
    });
    /*
     * LES REQUETES DE DEPLOIEMENT SONT COMPTEES AU RESEAU. « Le panneau ne
     * declenche rien » ne se mesure pas dans le DOM : la propriete est qu'aucune
     * requete ne PART.
     */
    let requetesDeploy = 0;
    page.on('request', (r) => { if (/\/deploy(\?|$)/.test(r.url())) requetesDeploy += 1; });

    const reponse = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie', reponse.status() === 200, `statut ${reponse.status()}`);
    verifie('l\'onglet du parc s\'ouvre', await ouvreDeploiement(page));

    /* ══ SANS CONFIGURATION GLOBALE ════════════════════════════════════════
     * `zabbix_deploy` rend 400 (mesure : 513 ms). Un bouton cliquable pour se
     * faire refuser fait decider dans le vide.
     */
    const sansConfig = await etatBouton(page, MACHINE_DEV);
    constate('sans configuration globale, le bouton', sansConfig.present
        ? `desactive=${sansConfig.desactive} infobulle="${sansConfig.infobulle}"` : 'absent (legacy)');
    // LE DETAIL EST IMPRIME AU PASS COMME AU FAIL : il dit ce qu'on a TROUVE,
    // pas ce qu'on redoutait. Troisieme fois que ce piege se presente.
    verifiePortage('sans configuration globale, le geste est DESACTIVE et dit pourquoi',
        sansConfig.present && sansConfig.desactive && sansConfig.infobulle !== '',
        sansConfig.present
            ? `desactive=${sansConfig.desactive}, infobulle="${sansConfig.infobulle}"`
            : 'aucun bouton par ligne du portage');
    const annonceSansConfig = await page.evaluate(() => {
        const n = document.querySelector('[data-rw="superv-depl-indisponible"]');

        return n && n.offsetParent !== null ? n.textContent.replace(/\s+/g, ' ').trim().slice(0, 90) : '';
    });
    verifiePortage('et la page l\'ANNONCE plutot que de laisser deviner',
        annonceSansConfig !== '', annonceSansConfig || 'rien');

    /* ══ AVEC CONFIGURATION GLOBALE ════════════════════════════════════════ */
    poseConfigGlobale();
    await page.reload({ waitUntil: 'networkidle2' });
    await ouvreDeploiement(page);

    const formes = await page.evaluate(() => ({
        parLigne: document.querySelectorAll('[data-rw="superv-deployer"]').length,
        legacyLigne: [...document.querySelectorAll('button')]
            .filter((b) => (b.getAttribute('onclick') || '').includes('deploySingle(')).length,
        masse: [...document.querySelectorAll('button')]
            .filter((b) => (b.getAttribute('onclick') || '').includes('deploySelected(')).length,
        cases: document.querySelectorAll('input[name="deploy_machines[]"]').length,
    }));
    constate('gestes de deploiement', `portage par ligne : ${formes.parLigne} · legacy par ligne : `
        + `${formes.legacyLigne} · sur selection : ${formes.masse} · cases : ${formes.cases}`);
    verifie('un geste de deploiement existe par ligne',
        formes.parLigne > 0 || formes.legacyLigne > 0);
    verifiePortage('aucune action de masse ni case a cocher ne subsiste',
        formes.masse === 0 && formes.cases === 0,
        `${formes.masse} geste(s) de masse, ${formes.cases} case(s)`);

    const avecConfig = await etatBouton(page, MACHINE_DEV);
    verifiePortage('la configuration posee, le geste redevient atteignable',
        avecConfig.present && ! avecConfig.desactive,
        avecConfig.present ? `desactive=${avecConfig.desactive}` : 'absent');

    /* ── OUVRIR N'ENVOIE RIEN, ET LA PRODUCTION EST NOMMEE ─────────────────
     * On ouvre le panneau sur la ligne de PRODUCTION pour lire l'avertissement,
     * puis on annule. La propriete « rien n'est parti » est mesuree au RESEAU.
     */
    const requetesAvant = requetesDeploy;
    const surProd = await page.evaluate((id) => {
        const b = document.querySelector(`[data-rw="superv-deployer"][data-machine="${id}"]`);
        if (! b) return { porte: false, texte: '' };
        b.click();
        const prod = document.querySelector('[data-rw="superv-depl-prod"]');
        const texte = prod && ! prod.hidden ? prod.textContent.replace(/\s+/g, ' ').trim() : '';
        document.querySelector('[data-rw="superv-depl-annuler"]')?.click();

        return { porte: true, texte };
    }, MACHINE_PROD);
    verifiePortage('le panneau NOMME la production quand la ligne en est une',
        surProd.porte && /srv-zabbix/i.test(surProd.texte) && /PRODUCTION/.test(surProd.texte),
        surProd.porte ? (surProd.texte || 'aucun avertissement') : 'pas de bouton par ligne');
    verifie('ouvrir un panneau n\'envoie AUCUNE requete de deploiement',
        requetesDeploy === requetesAvant,
        `${requetesDeploy - requetesAvant} requete(s) vers /deploy`);

    const surDev = await page.evaluate((id) => {
        const b = document.querySelector(`[data-rw="superv-deployer"][data-machine="${id}"]`);
        // UNE FORME DE RETOUR CONSTANTE. Rendre `{porte:false}` seul laissait
        // `items` indefini, et `items.length` levait DEUX assertions plus loin —
        // la suite avait tort, pas le portage.
        if (! b) return { porte: false, ouvert: false, prodVisible: null, items: [] };
        b.click();
        /*
         * LE PANNEAU DOIT ETRE REELLEMENT OUVERT. Premier jet : la liste etait
         * lue directement, `hidden` teste sur le `<ul>` et non sur le panneau
         * qui le contient — l'assertion passait alors que le bouton etait
         * desactive et que le panneau n'avait jamais paru. Un PASS dont on ne
         * sait pas pourquoi il passe ne vaut rien.
         */
        const panneau = document.querySelector('[data-rw="superv-panneau-depl"]');
        const ouvert = !! panneau && panneau.offsetParent !== null;
        const prod = document.querySelector('[data-rw="superv-depl-prod"]');
        const etapes = [...document.querySelectorAll(
            '[data-rw^="superv-depl-etapes-"]')].filter((u) => u.offsetParent !== null);
        const items = ouvert && etapes.length ? [...etapes[0].querySelectorAll('li')]
            .map((l) => l.textContent.replace(/\s+/g, ' ').trim()) : [];
        document.querySelector('[data-rw="superv-depl-annuler"]')?.click();

        return { porte: true, ouvert, prodVisible: prod ? ! prod.hidden : null, items };
    }, MACHINE_DEV);
    verifiePortage('le panneau de decision s\'ouvre reellement sous la ligne',
        surDev.porte && surDev.ouvert === true,
        surDev.porte ? `ouvert=${surDev.ouvert}` : 'pas de bouton par ligne');
    verifiePortage('et il ne le dit PAS sur une machine de developpement',
        surDev.porte && surDev.prodVisible === false,
        surDev.porte ? `avertissement visible=${surDev.prodVisible}` : 'pas de bouton');
    constate('etapes enumerees par le panneau', surDev.items.length);
    verifiePortage('le panneau ENUMERE les etapes plutot que d\'en compter',
        surDev.items.length >= 8, `${surDev.items.length} etape(s)`);
    verifiePortage('il dit que deployer commence par PURGER l\'agent en place',
        surDev.items.some((i) => /PURGES/.test(i)),
        surDev.items.find((i) => /purg/i.test(i)) || 'aucune etape ne parle de purge');
    verifiePortage('il nomme l\'effet SORTANT : le depot a joindre sur Internet',
        surDev.items.some((i) => i.includes('repo.zabbix.com')),
        surDev.items.find((i) => /depot/i.test(i)) || 'aucun depot nomme');
    verifiePortage('et il previent que l\'inventaire sera ecrit MEME en cas d\'echec',
        surDev.items.some((i) => /inventaire/i.test(i) && /echou/i.test(i)),
        surDev.items.find((i) => /inventaire/i.test(i)) || 'rien sur l\'inventaire');

    /* ══ LE GESTE, POUR DE VRAI, SUR LA MACHINE DE DEVELOPPEMENT ═══════════ */
    const clic = await cliqueDeployer(page, MACHINE_DEV);
    constate('resultat du clic', clic);
    verifie('le geste est atteignable', clic === 'clique', clic);

    if (CIBLE === 'laravel') {
        await page.evaluate(() => document.querySelector('[data-rw="superv-depl-confirmer"]')?.click());
    }

    // Le deploiement dure ~9,3 s sur le banc ; on attend un VERDICT, pas un delai.
    let verdict = '';
    let verification = '';
    for (let essai = 0; essai < 90; essai += 1) {
        await dors(1000);
        const vu = await page.evaluate(() => ({
            v: document.querySelector('[data-rw="superv-depl-message"]')?.textContent.trim() || '',
            c: document.querySelector('[data-rw="superv-depl-verif"]')?.textContent.trim() || '',
            // LE LEGACY N'ECRIT PAS OU JE CROYAIS. `appendDeployLog` cree une
            // fenetre par serveur dans `#deploy-logs-container` ; `#deploy-logs`
            // reste vide. Premier jet : verdict toujours vide, et l'assertion
            // accusait le legacy de ne rien conclure alors qu'il concluait
            // ailleurs. La suite avait tort.
            l: (document.querySelector('#deploy-logs-container')?.textContent
                || document.querySelector('#deploy-logs')?.textContent || '').trim(),
        }));
        verdict = vu.v || vu.l;
        verification = vu.c;
        const conclu = CIBLE === 'laravel'
            ? (verdict !== '' && ! /\.\.\.$/.test(verdict) && verification !== ''
                && ! /\.\.\.$/.test(verification))
            : /SUCCESS_MACHINE|reussi|ERROR_MACHINE/i.test(verdict);
        if (conclu) break;
    }
    constate('verdict de la commande', verdict.slice(0, 200) || '(aucun)');
    verifiePortage('le portage conclut a l\'ECHEC, en citant les codes du flux',
        /ECHOU/i.test(verdict) && /127/.test(verdict) && /100/.test(verdict),
        verdict.slice(0, 160) || '(aucun verdict)');
    constate('resultat de la verification apres coup', verification.slice(0, 220) || '(aucune)');
    verifiePortage('la VERIFICATION dit qu\'AUCUN agent n\'est detecte',
        /AUCUN agent/i.test(verification), verification.slice(0, 160) || '(aucune)');
    verifiePortage('et elle dit que c\'est l\'INVENTAIRE qui a tort',
        /inventaire/i.test(verification) && /tort/i.test(verification),
        verification.slice(0, 160) || '(aucune)');

    /* ── L'INVENTAIRE, ET POURQUOI IL FINIT JUSTE ──────────────────────────
     *
     * MESURE QUI M'A CORRIGE. `_upsert_agent` inscrit l'agent quoi qu'il arrive,
     * mais la ligne fausse est TRANSITOIRE : `zabbix_version` appelle
     * `_remove_agent` quand elle ne trouve rien, et les DEUX portails relancent
     * une detection juste apres — le legacy par `autoDetect` sur les ids ayant
     * emis `SUCCESS_MACHINE::`, le portage par sa verification. Chacun efface
     * donc son propre mensonge sans le savoir.
     *
     * L'inventaire finit juste, et ce n'est PAS le merite du deploiement.
     */
    const ligneInventaire = litEnBase('SELECT CONCAT(platform, " ", COALESCE(agent_version, "?"),'
        + ' " ", config_deployed) FROM rootwarden.supervision_agents'
        + ` WHERE machine_id = ${MACHINE_DEV}`);
    constate('l\'inventaire une fois la detection passee', ligneInventaire.join(' | ') || '(vide)');
    verifie('l\'inventaire finit coherent avec la machine — corrige par la detection, pas par le deploiement',
        ligneInventaire.length === 0 && agentInstalle() === 'NON',
        `inventaire=${ligneInventaire.join('|') || 'vide'} · agent reellement installe=${agentInstalle()}`);
    constate('ce que /etc/zabbix/ porte apres le geste', repertoireZabbix());

    const journal = await page.evaluate(() => {
        const j = document.querySelector('[data-rw="superv-depl-journal"]');

        return j && ! j.hidden ? j.textContent.trim().length : 0;
    });
    verifiePortage('le journal du flux est MONTRE, pour pouvoir verifier ce verdict',
        journal > 0, journal === 0 ? 'journal absent ou vide' : `${journal} caracteres`);

    /* ── CE QUE LE LEGACY, LUI, A FAIT ─────────────────────────────────────── */
    if (CIBLE === 'legacy') {
        constate('boite native ouverte par le legacy', dialogues.join(' | ') || '(aucune)');
        verifie('le legacy ouvre bien une boite native', dialogues.length > 0,
            dialogues.join(' | ') || 'aucune');
        verifie('et cette boite affiche la CLE, pas la phrase pourtant traduite',
            dialogues.some((d) => d.includes('confirm_deploy')), dialogues.join(' | '));
        verifie('le legacy conclut a la REUSSITE la ou trois etapes ont echoue',
            /reussi/i.test(verdict), verdict.slice(0, 140));
        verifie('et il ne verifie RIEN apres coup', verification === '',
            verification === '' ? 'aucune verification, comme attendu' : verification.slice(0, 80));
    }

    /* ── LE MENSONGE, ISOLE PAR UNE REQUETE FORGEE ─────────────────────────
     *
     * Pour le voir il faut un deploiement que AUCUNE detection ne suit. Aucun
     * bouton ne produit cela — les deux portails enchainent — donc on emet la
     * requete depuis la page, avec les memes en-tetes et la meme cible que le
     * bouton. Meme motif qu'en V10a : une requete forgee exerce ce qu'un clic ne
     * peut pas atteindre. Aucun effet nouveau sur la machine : c'est le meme
     * geste, sur la meme machine DEV, deja paye une fois ci-dessus.
     */
    litEnBase(`DELETE FROM rootwarden.supervision_agents WHERE machine_id = ${MACHINE_DEV}`);
    const forgee = await page.evaluate(async (id, portage) => {
        // LA CIBLE EST CONNUE : on ne la DEDUIT pas de la presence d'un `meta`
        // CSRF, que les deux portails peuvent porter. Une garde qui devine son
        // objet finit par se tromper d'objet.
        const url = portage
            ? '/api/gateway/supervision/zabbix/deploy'
            : (window.API_URL || '') + '/supervision/zabbix/deploy';
        const entetes = { 'Content-Type': 'application/json' };
        if (portage) {
            const jeton = document.querySelector('meta[name="csrf-token"]');
            entetes['X-CSRF-TOKEN'] = jeton ? jeton.content : '';
        } else if (window.API_KEY) {
            entetes['X-API-KEY'] = window.API_KEY;
        }
        try {
            const r = await fetch(url, {
                method: 'POST', headers: entetes,
                body: JSON.stringify({ machine_id: id }),
            });
            const t = await r.text();

            return { statut: r.status, conclut: /SUCCESS_MACHINE::/.test(t),
                codes: (t.match(/\(code (\d+)\)/g) || []).join(' ') };
        } catch (e) {
            return { statut: 0, conclut: false, codes: String(e).slice(0, 60) };
        }
    }, MACHINE_DEV, CIBLE === 'laravel');
    constate('deploiement forge, sans detection apres',
        `statut ${forgee.statut} · conclut au succes=${forgee.conclut} · codes releves : ${forgee.codes || '(aucun)'}`);
    const apresForge = litEnBase('SELECT CONCAT(platform, " ", COALESCE(agent_version, "?"),'
        + ' " ", config_deployed) FROM rootwarden.supervision_agents'
        + ` WHERE machine_id = ${MACHINE_DEV}`);
    verifie('le deploiement inscrit un agent que la machine ne porte pas, et conclut au succes',
        forgee.conclut === true && apresForge.length === 1 && agentInstalle() === 'NON',
        `inventaire="${apresForge.join('|') || 'vide'}" · agent reellement installe=${agentInstalle()}`
        + ` · succes annonce=${forgee.conclut}`);
    litEnBase(`DELETE FROM rootwarden.supervision_agents WHERE machine_id = ${MACHINE_DEV}`);

        verifie('aucune erreur JS pendant toute la sequence',
        erreursJs.length === 0, erreursJs.join(' | ') || 'aucune');

    const idsFr = await page.evaluate(() =>
        (document.body.innerText.match(/\b(superv|supervision)\.[a-z0-9_]+/gi) || []).slice(0, 4));
    verifie('aucun identifiant de traduction a l\'ecran (fr)', idsFr.length === 0, idsFr.join(', '));
    await ctx.close();

    /* ── LA SECONDE SESSION : le garde anti-rejeu TOTP est PAR COMPTE et EN
     * BASE, donc il traverse les contextes. On attend le basculement.
     */
    await dors((resteFenetre() + 2) * 1000);
    const { ctx: ctxEn, page: pageEn } = await connecte('en');
    await pageEn.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la seconde session (en) est bien authentifiee',
        /supervision/.test(pageEn.url()), pageEn.url().replace(BASE, ''));
    verifie('l\'onglet du parc s\'ouvre (en)', await ouvreDeploiement(pageEn));
    const idsEn = await pageEn.evaluate(() =>
        (document.body.innerText.match(/\b(superv|supervision)\.[a-z0-9_]+/gi) || []).slice(0, 4));
    verifie('aucun identifiant de traduction a l\'ecran (en)', idsEn.length === 0, idsEn.join(', '));
    const libelleEn = await pageEn.evaluate(() => {
        const b = document.querySelector('[data-rw="superv-deployer"]')
            || [...document.querySelectorAll('button')].find((x) =>
                (x.getAttribute('onclick') || '').includes('deploySingle('));

        return b ? b.textContent.trim() : '';
    });
    verifiePortage('le geste de deploiement est traduit en anglais',
        libelleEn === 'Deploy', `trouve : ${libelleEn || '(aucun libelle)'}`);
    await ctxEn.close();
} finally {
    constate('etat avant nettoyage de sortie', `${repertoireZabbix()} | agent=${agentInstalle()}`
        + ` | inventaire=${inventaire()} | config=${configGlobales()}`);
    nettoie();
    // L'ETAT RENDU EST RELU POUR ETRE PROUVE, pas suppose.
    verifie('le banc et la base sont rendus a leur etat initial',
        repertoireZabbix() === '(vide)' && agentInstalle() === 'NON'
        && inventaire() === 0 && configGlobales() === 0,
        `/etc/zabbix/=${repertoireZabbix()}, agent=${agentInstalle()}, `
        + `inventaire=${inventaire()}, config=${configGlobales()}`);
    await navigateur.close();
    console.log(lignes.join('\n'));
    console.log(`\n${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
    process.exit(echecs === 0 ? 0 : 1);
}
