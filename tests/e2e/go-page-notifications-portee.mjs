/*
 * ═══ LA PORTEE DES NOTIFICATIONS — UN GARDE ACQUIS, RIEN NE LE PROTEGE ════
 *
 * HORS-LOT: pose une ligne de DIFFUSION (`user_id = 0`) dans `notifications`,
 * visible de tout compte de role >= 2 le temps de la mesure. A enroler quand la
 * fixture aura une reference et que le lot pourra l'absorber.
 *
 * ══ CE QUE CETTE SUITE PROTEGE, ET POURQUOI MAINTENANT ════════════════════
 *
 * `Services/Notifications::portee()` calcule la portee de TOUS les gestes de
 * notification — les six, lecture comme ecriture, passent par `base()`. Trois
 * comportements y sont decides :
 *
 *     :93-95   $userId <= 0   ->  whereRaw('1 = 0')   AUCUNE ligne
 *     :96-98   $roleId >= 2   ->  user_id = $userId OR user_id = 0
 *     :100     sinon          ->  user_id = $userId  (pas les diffusions)
 *
 * Le legacy porte la meme distinction de role en LECTURE
 * (`adm/api/notifications.php:33` et `:35`) — mesure du 2026-09-07, et c'est ce
 * qui rend le portage fidele sur ce point. **Mais il ne porte AUCUN equivalent du
 * garde `$userId <= 0`** : ce garde est ACQUIS, pas porte.
 *
 * ⚠ ET C'EST PRECISEMENT CE QUI LE MET EN DANGER. Tant que le fichier legacy
 * existe, une regression se verrait par comparaison. **Le jour ou il est
 * archive, plus rien ne dit ce que la portee devait faire** — un garde acquis et
 * non teste disparait avec la seule chose qui permettait de le retrouver.
 *
 * ══ LA TROISIEME PROPRIETE EST NON MESURABLE ICI, ET C'EST DIT ════════════
 *
 * `$userId <= 0` est l'etat d'une session dont l'identifiant ne se lit pas.
 * **Aucun geste de navigateur ne le produit** : une requete non authentifiee est
 * arretee par l'intergiciel d'authentification AVANT d'atteindre `portee()`, donc
 * une suite E2E ne peut pas exercer cette branche. La forger demanderait de
 * fabriquer une session incoherente, ce que ce banc ne sait pas faire.
 *
 * **Elle releve d'un test unitaire sur `portee()`, dans un autre perimetre.**
 * Je l'ecris ici plutot que de rendre une assertion qui aurait l'air de la
 * couvrir : une suite qui pretend trois proprietes et n'en mesure que deux est
 * pire qu'une suite qui en mesure deux et le dit.
 *
 * ══ LE TEMOIN POSITIF EST LA PREMIERE ASSERTION, PAS LA DERNIERE ══════════
 *
 * « un role 1 ne voit pas les diffusions » est une universelle NEGATIVE : elle
 * est vraie a vide, et le resterait si la page ne rendait rien du tout, si la
 * fixture n'avait pas ete posee, ou si la session avait ete perdue. **On mesure
 * donc d'abord qu'un role >= 2 VOIT la diffusion** — sans quoi l'absence
 * constatee ensuite ne prouve rien.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = (() => {
    const d = process.env.E2E_BASE;
    if (! d) {
        throw new Error(
            'E2E_BASE n\'est pas declaree. Les deux portails ont echange leurs ports le\n'
            + '  2026-09-06 : une valeur en dur mesurerait l\'AUTRE portail en rendant du vert.\n'
            + '  L\'ETAT, jamais le numero :  curl -sk https://<hote>:<port>/up\n'
            + '    200 = portage · 404 = legacy');
    }

    return d;
})();
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

/* Secrets RELEVES dans les suites existantes, jamais inventes. */
const COMPTES = {
    'rw-test-user':  { id: 14, role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW' },
    'rw-test-super': { id: 16, role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW' },
};

/*
 * LE TITRE DE LA FIXTURE EST SA PROPRE ETIQUETTE DE RETRAIT. Une ligne de
 * diffusion est visible de TOUT compte de role >= 2, y compris de l'exploitant.
 * Elle doit etre reconnaissable au premier coup d'oeil et retiree en `finally`.
 */
const MARQUE = '[E2E-PORTEE] diffusion de mesure — a supprimer';

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,''))b+=a.indexOf(c).toString(2).padStart(5,'0');const o=[];for(let i=0;i+8<=b.length;i+=8)o.push(parseInt(b.slice(i,i+8),2));return Buffer.from(o)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[19]&0xf;return String(((h.readUInt32BE(o)&0x7fffffff)%1000000)).padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
const avortees = [];
let enConnexion = false;

function verifie(l, ok, d) {
    lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${l}${d ? '  — ' + d : ''}`);
    if (! ok) echecs++;
}
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }

/* Le filet : cette suite ne fait que LIRE, hors sa propre connexion. */
function installeFilet(page) {
    page.setRequestInterception(true);
    page.on('request', (r) => {
        if (r.method() !== 'GET' && ! enConnexion) {
            avortees.push(`${r.method()} ${r.url().replace(BASE, '')}`);

            return r.abort('blockedbyclient').catch(() => {});
        }
        r.continue().catch(() => {});
    });
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 90000,
});

async function connecte(nom) {
    enConnexion = true;
    const compte = COMPTES[nom];
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    page.on('dialog', d => d.dismiss().catch(() => {}));
    installeFilet(page);

    await page.goto(`${BASE}/connexion`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    await page.type('input[name="2fa_code"]', totp(compte.secret), { delay: 8 });
    nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (/\/cgu/.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$('[data-rw="cgu-accepter"]');
        if (b) await b.evaluate(x => x.click());
        try { await nav; } catch {}
    }
    enConnexion = false;

    return { ctx, page };
}

/** Le corps de la page de notifications, tel qu'il est RENDU. */
async function corps(page) {
    await page.goto(`${BASE}/notifications`, { waitUntil: 'networkidle2' });

    return page.evaluate(() => {
        const c = document.querySelector('[data-rw="notif-corps"]');
        const vide = document.querySelector('[data-rw="notif-vide"]');

        return {
            texte: c ? (c.innerText || '').replace(/\s+/g, ' ') : null,
            vide: vide !== null && ! vide.hasAttribute('hidden'),
        };
    });
}

let posee = null;
try {
    /*
     * ══ ETAT D'ENTREE, RELEVE AVANT D'ECRIRE ══════════════════════════════
     * Sans ce releve, la restauration ne se verifie pas : « la fixture est
     * partie » et « il n'y en a jamais eu » rendent le meme zero.
     */
    const diffusionsAvant = compteEnBase(
        'SELECT COUNT(*) FROM rootwarden.notifications WHERE user_id = 0');
    constate('lignes de diffusion AVANT', String(diffusionsAvant));

    litEnBase("INSERT INTO rootwarden.notifications (user_id, type, title, message) "
        + `VALUES (0, 'info', '${MARQUE}', 'Mesure de portee, sans effet.')`);
    const [idPose] = litEnBase(
        `SELECT id FROM rootwarden.notifications WHERE title = '${MARQUE}' ORDER BY id DESC LIMIT 1`);
    posee = parseInt(idPose, 10);
    verifie('la ligne de diffusion est posee', Number.isFinite(posee) && posee > 0,
        Number.isFinite(posee) && posee > 0 ? `id=${posee}, user_id=0`
            : 'aucun id rendu par l\'insertion');

    /*
     * ══ 1. TEMOIN POSITIF — UN ROLE >= 2 VOIT LA DIFFUSION ════════════════
     *
     * PREMIERE assertion, et pas la derniere. Ce qui suit est une universelle
     * negative ; sans ce temoin, elle serait vraie a vide sur une page cassee,
     * une fixture non posee ou une session perdue.
     */
    const sup = await connecte('rw-test-super');
    const vuSup = await corps(sup.page);
    constate('corps rendu au role 3', vuSup.texte === null ? '(ancre absente)'
        : `${vuSup.texte.length} caracteres, vide=${vuSup.vide}`);
    /*
     * ⚠ LE DETAIL EST CONDITIONNE AU VERDICT, et ce n'est pas cosmetique.
     *
     * Premier jet : le detail decrivait l'ECHEC et s'imprimait aussi sur le PASS.
     * La sortie disait « PASS … la marque n'apparait pas », c'est-a-dire
     * l'inverse de ce que l'assertion venait d'etablir. **Un detail qui ne vaut
     * que pour un verdict se conditionne a ce verdict** — sinon la ligne verte
     * affirme ce qu'elle vient de refuter, et fait chercher au mauvais endroit.
     */
    const vuSupOk = vuSup.texte !== null && vuSup.texte.includes('[E2E-PORTEE]');
    verifie('TEMOIN POSITIF : un role >= 2 VOIT la ligne de diffusion', vuSupOk,
        vuSupOk ? `marque trouvee dans les ${vuSup.texte.length} caracteres rendus`
            : (vuSup.texte === null ? 'l\'ancre notif-corps est absente de la page'
                : `la marque est ABSENTE des ${vuSup.texte.length} caracteres rendus`));
    await sup.ctx.close();

    // Le garde anti-rejeu TOTP est par COMPTE et persistant : deux comptes
    // differents, mais la fenetre TOTP est commune.
    await dors(31000);

    /*
     * ══ 2. UN ROLE 1 NE VOIT PAS LA DIFFUSION ═════════════════════════════
     *
     * `portee()` :100 rend `where('user_id', $userId)` pour un role < 2 — les
     * lignes `user_id = 0` en sont exclues. Le legacy fait de meme en lecture
     * (`adm/api/notifications.php:33`), donc c'est une fidelite et non un choix
     * du portage.
     */
    const usr = await connecte('rw-test-user');
    const vuUsr = await corps(usr.page);
    constate('corps rendu au role 1', vuUsr.texte === null ? '(ancre absente)'
        : `${vuUsr.texte.length} caracteres, vide=${vuUsr.vide}`);
    const vuUsrOk = vuUsr.texte !== null && ! vuUsr.texte.includes('[E2E-PORTEE]');
    verifie('un role 1 ne voit PAS la ligne de diffusion', vuUsrOk,
        vuUsrOk ? `marque absente des ${vuUsr.texte.length} caracteres rendus`
            : (vuUsr.texte === null ? 'l\'ancre est absente — on ne mesure rien'
                : 'la marque APPARAIT : la portee du role 1 inclut les diffusions'));
    await usr.ctx.close();

    /*
     * ══ 3. CE QUE CETTE SUITE NE PEUT PAS MESURER, ET QUI EST REEL ════════
     */
    constate('garde `$userId <= 0` (portee:93-95)',
        'NON MESURABLE DEPUIS UN NAVIGATEUR — cet etat est celui d\'une session dont '
        + 'l\'identifiant ne se lit pas. Une requete non authentifiee est arretee par '
        + 'l\'intergiciel AVANT d\'atteindre `portee()`, et forger une session incoherente '
        + 'depasse ce banc. Releve d\'un test unitaire sur `portee()`, autre perimetre.');
} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    /*
     * ══ LA RESTAURATION SE MESURE, ELLE NE SE SUPPOSE PAS ═════════════════
     *
     * Une ligne de diffusion oubliee resterait visible de TOUT compte de role
     * >= 2, l'exploitant compris. On la retire et on VERIFIE qu'elle est partie —
     * « le bloc a tourne » n'est pas « la ligne n'est plus la ».
     */
    try {
        if (posee) litEnBase(`DELETE FROM rootwarden.notifications WHERE id = ${posee}`);
        const reste = compteEnBase(
            `SELECT COUNT(*) FROM rootwarden.notifications WHERE title = '${MARQUE}'`);
        verifie('la ligne de diffusion posee est RETIREE', reste === 0,
            `${reste} ligne(s) portant la marque subsistent`);
    } catch (e) {
        lignes.push(`FAIL  retrait de la fixture : ${String(e.message || e).split('\n')[0]}`);
        echecs++;
    }
    constate('requetes non-GET avortees par le filet',
        avortees.length ? avortees.join(' | ') : '(aucune)');
}

console.log(lignes.join('\n'));
console.log(`\ncible=laravel : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
