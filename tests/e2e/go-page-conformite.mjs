/**
 * go-page-conformite.mjs - Module `security/`, sous-lot S2a : le rapport de
 * conformite, page HTML.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/security/compliance_report.php
 *   laravel  http://localhost:8444/rapport-conformite
 *
 * PERIMETRE S2a — LECTURE SEULE. Les sept collectes SQL, la notation de posture,
 * et la page. L'export CSV est S2c, le PDF est S2b : ce test ne les demande pas.
 * `compliance_report.php` pese 579 lignes ; le decoupage de MODULE-SECURITY.md
 * annoncait un seul sous-lot pour le HTML ET le CSV, c'etait trop gros — le
 * document a ete corrige, c'est un document de migration, pas une promesse.
 *
 * CE QUE FAIT LA PAGE, lu avant d'ecrire une assertion : aucune route backend,
 * aucun SSH. Sept `$pdo->query()` — machines (avec quatre sous-requetes de scan
 * CVE), comptes joints aux roles, statistiques de remediation, dix dernieres
 * modifications iptables, derniers scores d'audit SSH, agents de supervision,
 * et fail2ban + `config_drift` pour la posture. Puis un score par serveur :
 * 50 par defaut (ou le score d'audit sshd), -30 par CVE critique, -15 par CVE
 * haute, -15 sans fail2ban, -10 par derive plafonne a -30, borne a [0,100], et
 * une lettre A-F.
 *
 * LA GARDE, ET CE QU'ELLE CACHE. Le legacy admet `ROLE_USER` — son en-tete
 * annonce pourtant « Acces : admin (2) et superadmin (3) » — et ne cloisonne
 * AUCUNE donnee : un role 1 porteur de `can_view_compliance` obtiendrait tout le
 * parc avec IP, port et utilisateur SSH, tous les comptes, et la posture par
 * serveur AVEC LES ECARTS EN CLAIR. Le portage restreint a `role >= 2`
 * (decision D-1, PARITE.md).
 *
 * CETTE DIVERGENCE N'EST PAS MESURABLE avec les comptes existants, et il faut le
 * dire : elle exige un role 1 PORTANT `can_view_compliance`. `rw-test-user` a
 * zero permission, donc il est refuse des deux cotes — par la PERMISSION cote
 * legacy, par le ROLE cote portage. Meme cause que E-34. Ce qui est mesurable, et
 * qui l'est ici pour la premiere fois du module : la paire qui distingue une
 * garde par PERMISSION d'une garde par ROLE — `rw-test-admin` porte
 * `can_view_compliance` et pas `can_admin_portal`.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-conformite.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-conformite.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { compteEnBase } from './lib-base.mjs';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';

/**
 * Le nombre de machines au parc, lu DANS LA BASE.
 *
 * Croiser avec la source vaut mieux que mesurer une forme : « la posture a des
 * lignes » passe au vert sur un tableau incomplet, « la posture en a autant que
 * le parc » ne passe que si elle le couvre. Le nombre n'est pas ecrit en dur —
 * il changerait au premier ajout de machine, et le test accuserait la page.
 *
 * `execFileSync` avec un tableau d'arguments, JAMAIS une chaine de shell : un
 * shell POSIX viderait les `$` du SQL. Le relais `docker` est celui du lanceur.
 */
function parcEnBase() {
    return compteEnBase('SELECT COUNT(*) FROM rootwarden.machines');
}

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/rapport-conformite' : '/security/compliance_report.php';

const COMPTES = {
    // Role 1, ZERO permission : refuse. Cote legacy par `can_view_compliance`,
    // cote portage par le role — le MEME resultat pour deux raisons differentes.
    'rw-test-user':  { role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW', attendu: 'refuse' },
    // Role 2 PORTANT can_view_compliance et PAS can_admin_portal : c'est cette
    // paire qui prouve qu'on lit bien une PERMISSION et non un ROLE.
    'rw-test-admin': { role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX', attendu: 'autorise' },
    'rw-test-super': { role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW', attendu: 'autorise' },
};

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
function verifie(libelle, ok, detail) {
    lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${libelle}${detail ? '  — ' + detail : ''}`);
    if (!ok) echecs++;
}
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }
function verifiePortage(libelle, ok, detail) {
    if (CIBLE === 'laravel') return verifie(libelle, ok, detail);
    constate(libelle, `non exigible du legacy — ${detail}`);
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});

async function connecte(nom) {
    const compte = COMPTES[nom];
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
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
    await page.type('input[name="2fa_code"]', totp(compte.secret), { delay: 8 });
    nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (chemins.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$('[data-rw="cgu-accepter"]') || await page.$('button[name="accept_terms"]');
        if (b) await b.evaluate(x => x.click());
        try { await nav; } catch {}
    }
    return { ctx, page };
}

/** Le statut REEL de la page, mesure par une requete et non par une navigation. */
async function statutDe(page, chemin) {
    return page.evaluate(async (url) => {
        const r = await fetch(url, { credentials: 'same-origin' });
        return r.status;
    }, chemin);
}

/** Ce que la page rend, tel qu'elle le rend. */
async function releve(page) {
    return page.evaluate(() => {
        const t = (s) => (document.querySelector(s)?.textContent || '').trim();
        const nombres = (s) => [...document.querySelectorAll(s)].map(e => e.textContent.trim());
        // La posture : une ligne par serveur, avec un score et une lettre.
        const posture = [...document.querySelectorAll('[data-rw="posture-ligne"], tbody tr')]
            .map(tr => [...tr.querySelectorAll('td')].map(td => td.textContent.trim()))
            .filter(c => c.length === 5 && /^\d+\/100$/.test(c[2]));
        const texte = document.body.innerText;
        return {
            titre: t('h1'),
            // Les tuiles de resume portent un grand nombre : on les compte.
            tuiles: nombres('[data-rw="tuile-valeur"]').length
                || document.querySelectorAll('.text-2xl.font-bold').length,
            posture,
            // Empreinte : 64 hexadecimaux, nulle part ailleurs dans la page.
            empreinte: (texte.match(/\b[0-9a-f]{64}\b/) || [])[0] || '',
            // Une cle de traduction morte s'affiche telle quelle.
            clesMortes: (texte.match(/\bcompliance\.[a-z0-9_]+/g) || []),
            boutons: {
                imprimer: Boolean([...document.querySelectorAll('button,a')]
                    .find(b => /imprim|print/i.test(b.textContent))),
                pdf: Boolean([...document.querySelectorAll('a')].find(a => /format=pdf|pdf/i.test(a.getAttribute('href') || a.textContent))),
                csv: Boolean([...document.querySelectorAll('a')].find(a => /format=csv|csv/i.test(a.getAttribute('href') || a.textContent))),
            },
            longueur: texte.length,
        };
    });
}

console.log(`\n=== Module security/, sous-lot S2a — rapport de conformite (${CIBLE}) ===\n`);
constate('cible', `${BASE}${PAGE}`);
constate('ce que fait la page, lu dans legacy/security/compliance_report.php',
    'sept collectes SQL, aucune route backend, aucun SSH — puis une notation de posture par serveur');

const PARC_ATTENDU = parcEnBase();
constate('machines au parc, lues en base', String(PARC_ATTENDU));

const erreursJs = [];

try {
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: PAGE, fichiers: [], verifie, constate,
        });
        if (archivee) throw new Error('__archivee__');
    }

    // ── La garde, et la paire qui distingue permission et role ──────────────
    let sessionAdmin = null;
    for (const nom of Object.keys(COMPTES)) {
        const compte = COMPTES[nom];
        const session = await connecte(nom);
        const statut = await statutDe(session.page, PAGE);
        constate(`${nom} (role ${compte.role})`, `statut ${statut}`);
        if (compte.attendu === 'refuse') {
            verifie(`${nom} : role 1 sans can_view_compliance est refuse`,
                statut === 403, `statut ${statut}`);
        } else {
            verifie(`${nom} : autorise a lire le rapport`, statut === 200, `statut ${statut}`);
        }
        // On GARDE la session du role 2 : c'est elle qui prouve la lecture d'une
        // PERMISSION, et se reconnecter dans la meme fenetre TOTP rejouerait le
        // meme code — que le portage refuse, a juste titre.
        if (nom === 'rw-test-admin') sessionAdmin = session;
        else await session.ctx.close();
    }

    // `rw-test-admin` porte can_view_compliance et PAS can_admin_portal : s'il
    // entre ici et reste refuse ailleurs, c'est bien la permission qui est lue.
    //
    // LA PAGE TEMOIN DOIT ETRE VIVANTE, et l'assertion doit exiger 403 et non
    // « pas 200 ». Premier jet : `/commandlog/`, qui est ARCHIVE cote legacy et
    // rend donc 404 — l'assertion passait au vert sans rien mesurer. Cote legacy
    // on vise `groups/`, encore servi et garde par la meme permission ; cote
    // portage, `journal-commandes`, porte et garde par elle aussi.
    const cheminAutrePerm = CIBLE === 'laravel' ? '/journal-commandes' : '/groups/index.php';
    const statutAutre = await statutDe(sessionAdmin.page, cheminAutrePerm);
    constate('le meme compte sur une page exigeant can_admin_portal', `statut ${statutAutre}`);
    verifie('la garde lit une PERMISSION et non un ROLE',
        statutAutre === 403,
        `role 2 autorise ici, ${statutAutre} sur ${cheminAutrePerm}`);

    // ── Ce que la page rend ────────────────────────────────────────────────
    const { ctx, page } = sessionAdmin;
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    const vue = await releve(page);

    verifie('la page porte un titre', vue.titre.length > 0, `« ${vue.titre} »`);
    verifie('aucune cle de traduction morte a l\'ecran',
        vue.clesMortes.length === 0,
        vue.clesMortes.length ? vue.clesMortes.slice(0, 3).join(', ') : 'aucune');
    verifie('aucune erreur JavaScript', erreursJs.length === 0,
        erreursJs.length ? erreursJs[0] : 'aucune');

    constate('tuiles de resume', String(vue.tuiles));
    verifie('le resume porte ses six indicateurs', vue.tuiles >= 6, `${vue.tuiles} tuile(s)`);

    // La posture : croisee avec le parc, pas mesuree contre elle-meme.
    constate('lignes de posture', String(vue.posture.length));
    verifie('la posture couvre le parc entier',
        vue.posture.length === PARC_ATTENDU,
        `${vue.posture.length} ligne(s) pour ${PARC_ATTENDU} machine(s) au parc`);
    // `[].every()` rend `true` : asserter d'abord qu'il y en a.
    verifie('chaque ligne de posture porte un score borne et une note A-F',
        vue.posture.length > 0
            && vue.posture.every(c => {
                const score = parseInt(c[2], 10);
                return score >= 0 && score <= 100 && /^[A-F]$/.test(c[3]);
            }),
        vue.posture.length ? `exemple : ${vue.posture[0][0]} ${vue.posture[0][2]} ${vue.posture[0][3]}` : 'aucune ligne');
    verifie('chaque ligne DIT ce qui manque, ou qu\'elle est conforme',
        vue.posture.length > 0 && vue.posture.every(c => c[4].length > 0),
        `${vue.posture.length} ligne(s) inspectee(s)`);

    verifie('le rapport porte son empreinte SHA-256',
        /^[0-9a-f]{64}$/.test(vue.empreinte),
        vue.empreinte ? `${vue.empreinte.slice(0, 16)}...` : 'aucune empreinte');

    constate('boutons d\'export', JSON.stringify(vue.boutons));
    verifie('l\'impression est offerte', vue.boutons.imprimer);

    await ctx.close();
} catch (e) {
    if (String(e).includes('__archivee__')) {
        // Le constat d'archivage a deja tout dit.
    } else {
        lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
        echecs++;
    }
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
