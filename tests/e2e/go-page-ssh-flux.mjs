/**
 * go-page-ssh-flux.mjs - Module `ssh/`, sous-lot K3 : la lecture du flux de logs.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/ssh/
 *   laravel  http://localhost:8444/cles-ssh
 *
 * K3 NE DEPLOIE RIEN. `GET /logs` ouvre `deployment.log`, envoie son contenu
 * existant, puis suit le fichier pendant **30 secondes d'inactivite** (60 tours de
 * 0,5 s) avant d'emettre son marqueur de fin. Aucune machine n'est jointe.
 *
 * QUATRE DEFAUTS, ET LE PREMIER EST UN PIEGE DE TRADUCTION.
 *
 *  1. **LE MARQUEUR DE FIN EST UN TEXTE FRANCAIS EN DUR.** Le backend emet
 *     `data: [Fin du flux de logs]` et le client compare `event.data` a cette
 *     chaine, LITTERALEMENT. **Le traduire cote portage ferait que le flux ne se
 *     termine plus jamais** : le bouton resterait desactive, et seul le
 *     `onerror` finirait par le rendre — donc par le chemin d'echec.
 *  2. **UN `EventSource` NE PEUT PAS LIRE UN STATUT HTTP.** `GET /logs` est
 *     `@require_role(2)` : pour un role 1 il rend 403, ce qui declenche
 *     `onerror`. Le legacy y ecrit « [Fin du flux] », **rend le bouton et ne dit
 *     RIEN**. Un role 1 peut declencher le deploiement (`POST /deploy` n'a ni
 *     role ni permission) et conclure que tout s'est bien passe. Le portage lit
 *     donc le flux par `fetch`, dont le statut EST lisible.
 *  3. **XSS STOCKEE.** `main.js:264` fait `logWindow.innerHTML += event.data` et
 *     son commentaire pretend « pas de donnees utilisateur non maitrisees ».
 *     C'est faux : `configure_servers.py:112` injecte `machines.name` dans CHAQUE
 *     ligne, sans validation, et `:785` journalise verbatim les noms
 *     d'utilisateur refuses. La branche preflight du MEME fichier echappe tout
 *     (`_escHtml`) : une moitie traitee, l'autre pas.
 *  4. **LES DEUX CHEMINS NE LAISSENT PAS LA PAGE DANS LE MEME ETAT.** Le chemin
 *     de succes remet le libelle « Deployer les cles » et affiche un toast ; le
 *     chemin d'erreur ecrit « Lancer le Deploiement » et n'affiche rien. L'etat
 *     de la page depend de la facon dont le flux s'est termine.
 *
 * LA FIXTURE, ET SA RESTAURATION. Pour mesurer si une ligne de journal est rendue
 * comme BALISAGE ou comme TEXTE, il faut une ligne dedans. `deployment.log` est
 * vide, gitignore, et tronque par l'application a chaque deploiement : la suite y
 * ajoute une ligne portant une balise BENIGNE — pas une charge executable, la
 * propriete a mesurer etant « est-ce interprete », pas « peut-on executer » — puis
 * **remet le fichier a zero**. L'ecriture passe par le conteneur, seul proprietaire
 * du fichier.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-ssh-flux.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { execFileSync } from 'child_process';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/cles-ssh' : '/ssh/';
const ROUTE = CIBLE === 'laravel' ? '/api/gateway/logs' : '/api_proxy.php/logs';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';
const SECRET_USER = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';

/** Le marqueur de fin, EN DUR des deux cotes. Le traduire casse le flux. */
const MARQUEUR_FIN = '[Fin du flux de logs]';
/** Une balise benigne : on mesure si c'est INTERPRETE, pas si c'est exploitable. */
const SONDE_BALISE = '<b data-rw="k3-balise">SONDE-K3</b>';

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

/** Le journal du deploiement, ecrit et remis a zero par le conteneur. */
const JOURNAL = '/app/logs/deployment.log';
function journal(commande) {
    return execFileSync('sudo', ['-n', 'docker', 'exec', 'rootwarden_python', 'sh', '-c', commande],
        { encoding: 'utf-8' });
}
/*
 * ══ LE JOURNAL PEUT NE PAS EXISTER, ET LA SUITE MOURAIT AVANT SON TAMPON ══
 *
 * Mesure du LOT du 2026-08-28 : **0 PASS / 0 FAIL sur les DEUX cibles**, en
 * 2 et 3 secondes.
 *
 *     sh: cannot open /app/logs/deployment.log: No such file
 *
 * `deployment.log` avait ete ROTATIONNE en `deployment.log.1` la veille a 22:43
 * — c'est E-196, le correctif des regles de rotation. Le fichier n'est recree
 * qu'au prochain deploiement.
 *
 * **Ni le correctif ni cette suite n'etait fautif : c'est le LIEN qui n'existait
 * nulle part.** Aucune execution isolee ne pouvait le trouver — il fallait que
 * la rotation ait eu lieu — et il aurait mordu a chaque LOT. Meme famille que
 * `go-bashrc-b4`, qui accusait la page d'un geste produit par sa suite soeur.
 *
 * ⚠ ET ON NE LE CREE PAS NAIVEMENT. `docker exec` tourne en **root** : un
 * `touch` nu laisserait un fichier `root:root` dans un repertoire que
 * l'application possede (`rootwarden:rootwarden`, verifie), et **le prochain
 * deploiement ne pourrait plus y ecrire**. La suite aurait casse la
 * fonctionnalite qu'elle mesure. On repose donc le proprietaire.
 */
function assureJournal() {
    journal(`[ -e ${JOURNAL} ] || { : > ${JOURNAL}; `
        + `chown rootwarden:rootwarden ${JOURNAL} 2>/dev/null; chmod 640 ${JOURNAL}; }`);
}
function ecritSonde() { assureJournal(); journal(`printf '%s\\n' '${SONDE_BALISE}' >> ${JOURNAL}`); }
function videJournal() { assureJournal(); journal(`: > ${JOURNAL}`); }
/** Rend 0 quand le fichier est absent : « absent » et « vide » se valent ICI,
 *  puisque la propriete mesuree est la taille de ce que le flux transporte. */
function tailleJournal() {
    const t = journal(`wc -c < ${JOURNAL} 2>/dev/null || echo 0`).trim();

    return parseInt(t, 10) || 0;
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});

async function connecte(nom, secret) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(60000);
    page.on('dialog', d => d.dismiss().catch(() => {}));
    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };
    await page.goto(`${BASE}${chemins.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    const champ = await page.$('input[name="2fa_code"]');
    if (champ) {
        await champ.type(totp(secret), { delay: 8 });
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

let sondeEcrite = false;
try {
    constate('cible', `${CIBLE} — ${PAGE} · route ${ROUTE}`);
    constate('journal avant la suite', `${tailleJournal()} octet(s)`);

    // ── La fixture : une ligne portant une balise, dans le journal ──────────
    ecritSonde();
    sondeEcrite = true;
    constate('journal apres la sonde', `${tailleJournal()} octet(s)`);

    const { ctx, page } = await connecte('rw-test-admin', SECRET_ADMIN);
    const erreursJs = [];
    page.on('pageerror', e => erreursJs.push(String(e).split('\n')[0]));
    // Le TYPE de requete dit si le statut est lisible : un `EventSource` ne peut
    // pas le lire, un `fetch` si. C'est la cause du silence sur un 403.
    const typesFlux = [];
    page.on('request', (r) => {
        if (/\/logs\b/.test(r.url())) typesFlux.push(r.resourceType());
    });

    const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie a un role 2 portant can_deploy_keys',
        (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(1200);

    // ── 1. Le flux lui-meme : type, contenu, marqueur de fin ────────────────
    // Lu par `fetch` depuis la page, pour controler l'attente : le backend suit le
    // fichier 30 s avant d'emettre son marqueur.
    const flux = await page.evaluate(async (route, marqueur) => {
        const rep = await fetch(route, { credentials: 'same-origin' });
        const type = rep.headers.get('content-type') || '';
        if (!rep.ok) return { statut: rep.status, type, lignes: [], marqueur: false };
        const lecteur = rep.body.getReader();
        const decodeur = new TextDecoder();
        let tampon = '';
        const donnees = [];
        const limite = Date.now() + 45000;
        for (;;) {
            if (Date.now() > limite) break;
            const { done, value } = await lecteur.read();
            if (done) break;
            tampon += decodeur.decode(value, { stream: true });
            const morceaux = tampon.split('\n');
            tampon = morceaux.pop();
            for (const m of morceaux) {
                if (m.startsWith('data: ')) donnees.push(m.slice(6));
            }
            if (donnees.includes(marqueur)) break;
        }
        try { await lecteur.cancel(); } catch { /* deja ferme */ }
        return { statut: rep.status, type, lignes: donnees, marqueur: donnees.includes(marqueur) };
    }, ROUTE, MARQUEUR_FIN);

    constate('flux', `statut ${flux.statut}, type « ${flux.type.split(';')[0]} », `
        + `${flux.lignes.length} ligne(s)`);
    verifie('le flux est servi en text/event-stream a un role 2',
        flux.statut === 200 && /text\/event-stream/.test(flux.type),
        `statut ${flux.statut}, type « ${flux.type.split(';')[0]} »`);
    verifie('le flux livre le contenu deja present dans le journal',
        flux.lignes.some((l) => l.includes('SONDE-K3')),
        `${flux.lignes.length} ligne(s) : ${flux.lignes.slice(0, 2).join(' | ').slice(0, 80)}`);
    verifie('le flux se termine par son marqueur, EN DUR et non traduit',
        flux.marqueur, `marqueur « ${MARQUEUR_FIN} » ${flux.marqueur ? 'recu' : 'ABSENT'}`);

    // ── 2. Le client de la page : balisage ou texte ? ────────────────────────
    // LE COLLECTEUR EST REMIS A ZERO ICI : sans cela il comptait aussi la sonde
    // `fetch` de la suite elle-meme, et l'assertion « pas d'EventSource » aurait
    // reussi meme si le client de la page n'avait rien demande du tout.
    typesFlux.length = 0;
    const pilote = await page.evaluate(() => {
        if (typeof window.fetchLogs === 'function') { window.fetchLogs(); return 'fetchLogs'; }
        const b = document.querySelector('[data-rw="ssh-journal"]');
        if (b) { b.click(); return 'bouton du portage'; }
        return null;
    });
    constate('client de flux pilote', pilote || 'aucun point d\'entree');
    // Le marqueur arrive apres 30 s d'inactivite : on attend au-dela.
    await dors(pilote ? 40000 : 0);

    const rendu = await page.evaluate((marqueur) => {
        const z = document.getElementById('logs') || document.getElementById('journal-flux');
        if (!z) return null;
        return {
            // BALISAGE : la sonde est-elle devenue un ELEMENT du document ?
            balises: z.querySelectorAll('[data-rw="k3-balise"]').length,
            // TEXTE : la sonde apparait-elle telle quelle, chevrons compris ?
            litteral: z.innerText.includes('<b data-rw="k3-balise">'),
            porteMarqueur: z.innerText.includes(marqueur),
            texte: z.innerText.replace(/\s+/g, ' ').trim().slice(-160),
        };
    }, MARQUEUR_FIN);
    constate('zone de flux', rendu
        ? `${rendu.balises} balise(s) interpretee(s), litteral=${rendu.litteral} — « ${rendu.texte} »`
        : 'absente');
    verifie('la zone de flux existe et a recu quelque chose',
        Boolean(rendu) && rendu.texte.length > 0, rendu ? 'oui' : 'absente');
    verifiePortage('une ligne de journal est rendue comme du TEXTE, jamais comme du balisage',
        Boolean(rendu) && rendu.balises === 0 && rendu.litteral === true,
        rendu ? `${rendu.balises} balise(s) interpretee(s) : \`innerHTML +=\` fait de `
            + '`machines.name` un fragment de document — XSS STOCKEE' : 'non mesurable');

    // Le marqueur ne doit PAS s'afficher : il pilote, il n'informe pas.
    verifie('le marqueur de fin ne s\'affiche pas comme une ligne de journal',
        Boolean(rendu) && rendu.porteMarqueur === false,
        rendu ? `porteMarqueur=${rendu.porteMarqueur}` : 'non mesurable');

    // ── 3. Le TYPE de requete : un statut lisible, ou non ───────────────────
    constate('type de la requete de flux', typesFlux.join(', ') || 'aucune');
    verifiePortage('le flux est lu par une requete dont le STATUT est lisible',
        typesFlux.length > 0 && !typesFlux.includes('eventsource'),
        // `typesFlux.length > 0` n'est pas decoratif : une assertion vraie parce
        // qu'aucune requete n'est partie ne mesure rien.

        `« ${typesFlux.join(', ')} » — un \`EventSource\` ne peut pas lire un statut HTTP, `
        + 'donc un 403 tombe dans `onerror` et le legacy y ecrit « [Fin du flux] » '
        + 'sans rien dire');

    verifie('aucune erreur JS pendant toute la sequence', erreursJs.length === 0,
        erreursJs.slice(0, 3).join(' · ') || 'aucune');
    await ctx.close();

    // ── 4. Un role 1 est refuse par la ROUTE — et le legacy l'avale ─────────
    await dors((resteFenetre() + 1) * 1000);
    const u = await connecte('rw-test-user', SECRET_USER);
    await u.page.goto(`${BASE}${CIBLE === 'laravel' ? '/accueil' : '/index.php'}`,
        { waitUntil: 'networkidle2' });
    const refus = await u.page.evaluate(async (route) => {
        const rep = await fetch(route, { credentials: 'same-origin' });
        return { statut: rep.status, corps: (await rep.text()).slice(0, 120) };
    }, ROUTE);
    constate('role 1 sur le flux', `statut ${refus.statut}, « ${refus.corps.slice(0, 60)} »`);
    verifie('le flux est refuse a un role 1 par un 403 EXACT',
        refus.statut === 403, `statut ${refus.statut}`);
    constate('ce que le legacy fait de ce 403',
        'NON MESURABLE SUR SA PAGE : un role 1 n\'a pas `can_deploy_keys`, donc il ne peut '
        + 'pas ouvrir `/ssh/` et n\'atteint pas le client. La route, elle, le refuse bien — '
        + 'et `onerror` du legacy y ecrirait « [Fin du flux] » en rendant le bouton, sans '
        + 'rien dire. Meme limite que D-5.');
    await u.ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
} finally {
    // LE JOURNAL EST REMIS A ZERO, quoi qu'il arrive. Il etait vide au depart, et
    // l'application le tronque de toute facon a chaque deploiement.
    if (sondeEcrite) {
        try { videJournal(); lignes.push(`INFO  journal restaure : ${tailleJournal()} octet(s)`); }
        catch (e) { lignes.push('FAIL  restauration du journal  — ' + String(e).slice(0, 80)); echecs++; }
    }
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
