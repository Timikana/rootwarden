/**
 * go-socle-i18n.mjs - Bascule de langue et integrite des traductions.
 *
 * DEUX controles distincts, parce qu'un seul ne suffit pas :
 *
 *  1. AUCUN IDENTIFIANT DE CLE A L'ECRAN. Une cle absente des DEUX langues
 *     n'echoue pas : elle affiche son propre identifiant (`auth.xxx`).
 *
 *  2. PARITE DES JEUX DE CLES entre fr et en. Une cle presente en anglais mais
 *     absente en francais n'affiche PAS son identifiant : le repli de langue
 *     rend le texte ANGLAIS. Le defaut est alors invisible a l'oeil comme au
 *     controle 1. Seule la comparaison des jeux de cles le voit.
 *
 * S'y ajoutent la persistance de la bascule et le fait qu'une langue hors
 * liste blanche retombe sur le defaut — cote legacy, un cookie forge
 * permettait d'inclure un fichier arbitraire.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-socle-i18n.mjs
 */
import puppeteer from 'puppeteer';
import { execFileSync } from 'child_process';
import { createHmac } from 'crypto';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';

/** Pages portees a verifier dans les deux langues. */
const PAGES = ['/connexion', '/accueil', '/profil', '/cgu'];

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

// ── Controle 2 : parite des jeux de cles, hors navigateur ──────────────────
// Les fichiers de langue sont du PHP : on les fait lire par PHP, dans le
// conteneur. Les analyser par expression reguliere depuis Node reviendrait a
// reecrire un interpreteur — et une cle mal lue serait declaree absente a tort.
function pariteDesCles() {
    const script = [
        '$ecarts = [];',
        '$total = 0;',
        'foreach (glob("/var/www/html/lang/fr/*.php") as $f) {',
        '  $m = basename($f, ".php");',
        '  $fr = require $f;',
        '  $cheminEn = "/var/www/html/lang/en/$m.php";',
        '  if (!file_exists($cheminEn)) { $ecarts[] = "$m: absent en anglais"; continue; }',
        '  $en = require $cheminEn;',
        '  $total += count($fr);',
        '  foreach (array_keys(array_diff_key($fr, $en)) as $k) $ecarts[] = "$m.$k: absente en anglais";',
        '  foreach (array_keys(array_diff_key($en, $fr)) as $k) $ecarts[] = "$m.$k: absente en francais";',
        '}',
        'foreach (glob("/var/www/html/lang/en/*.php") as $f) {',
        '  $m = basename($f, ".php");',
        '  if (!file_exists("/var/www/html/lang/fr/$m.php")) $ecarts[] = "$m: absent en francais";',
        '}',
        'echo json_encode(["total" => $total, "ecarts" => $ecarts]);',
    ].join(' ');

    // Le PHP part par un TABLEAU d'arguments, jamais par une chaine de shell :
    // il porte des `$variable`, et un shell POSIX les remplace par du vide des
    // lors qu'elles sont entre guillemets — le code arrivait mutile cote
    // conteneur. `execFileSync` remet argv tel quel a `docker`, sans shell
    // intermediaire, donc sans expansion.
    const sortie = execFileSync(
        'docker',
        ['exec', 'rootwarden_laravel', 'php', '-r', script],
        { encoding: 'utf-8' },
    );

    return JSON.parse(sortie);
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 60000,
});

async function connecte(page) {
    await page.goto(`${BASE}/connexion`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', COMPTE, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    await page.type('input[name="2fa_code"]', totp(SECRET), { delay: 8 });
    nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (/\/cgu/.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$('[data-rw="cgu-accepter"]');
        if (b) await b.evaluate(x => x.click());
        try { await nav; } catch {}
    }
}

/** Identifiants de cle visibles a l'ecran (module.cle_en_minuscules). */
async function clesMortes(page) {
    return page.evaluate(() => {
        const texte = document.body.innerText;
        const trouvees = texte.match(/\b(auth|nav|accueil|profil|passerelle)\.[a-z_]{3,}\b/g) || [];
        return [...new Set(trouvees)];
    });
}

try {
    // ── Controle 2 d'abord : il ne demande pas de navigateur ────────────────
    const parite = pariteDesCles();
    constate('cles francaises comparees', parite.total);
    verifie('parite des jeux de cles fr / en', parite.ecarts.length === 0,
            parite.ecarts.slice(0, 6).join(' · ') || 'aucun ecart');

    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    page.on('dialog', d => d.dismiss().catch(() => {}));

    // ── La bascule fonctionne AVANT toute connexion ─────────────────────────
    await page.goto(`${BASE}/connexion`, { waitUntil: 'networkidle2' });
    const fr = await page.evaluate(() => document.documentElement.lang);
    verifie('la page de connexion est en francais par defaut', fr === 'fr', `lang=${fr}`);

    const selecteur = await page.$('[data-rw="langue-en"]');
    verifie('le selecteur de langue est atteignable sans etre connecte', Boolean(selecteur));

    if (selecteur) {
        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await selecteur.evaluate(a => a.click());
        try { await nav; } catch {}
        const en = await page.evaluate(() => document.documentElement.lang);
        verifie('un clic sur EN bascule la page de connexion', en === 'en', `lang=${en}`);
        const texte = await page.evaluate(() => document.body.innerText);
        verifie('la page de connexion affiche bien l\'anglais',
                /Sign in|Username|Password/.test(texte));
    }

    // ── Une langue hors liste blanche retombe sur le defaut ─────────────────
    for (const forge of ['de', '../../etc/passwd', 'fr; DROP TABLE users']) {
        const rep = await page.goto(`${BASE}/connexion?lang=${encodeURIComponent(forge)}`,
                                    { waitUntil: 'networkidle2' });
        const lang = await page.evaluate(() => document.documentElement.lang);
        verifie(`langue hors liste blanche « ${forge.slice(0, 18)} » : ignoree`,
                ['fr', 'en'].includes(lang) && (rep?.status() ?? 0) === 200,
                `statut=${rep?.status()} lang=${lang}`);
    }

    // ── Connexion, puis les pages portees dans les DEUX langues ─────────────
    await page.goto(`${BASE}/connexion?lang=fr`, { waitUntil: 'networkidle2' });
    await connecte(page);
    verifie('connexion aboutie', /\/accueil/.test(page.url()), page.url().replace(BASE, ''));

    for (const langue of ['fr', 'en']) {
        for (const chemin of PAGES) {
            if (chemin === '/connexion') continue; // deja vue, et hors session
            await page.goto(`${BASE}${chemin}?lang=${langue}`, { waitUntil: 'networkidle2' });
            const lang = await page.evaluate(() => document.documentElement.lang);
            const mortes = await clesMortes(page);
            verifie(`${langue} · ${chemin} : rendue dans la bonne langue`, lang === langue, `lang=${lang}`);
            verifie(`${langue} · ${chemin} : aucune cle morte a l'ecran`,
                    mortes.length === 0, mortes.slice(0, 4).join(', ') || 'aucune');
        }
    }

    // ── La bascule PERSISTE sans reprendre le parametre ─────────────────────
    await page.goto(`${BASE}/accueil?lang=en`, { waitUntil: 'networkidle2' });
    await page.goto(`${BASE}/profil`, { waitUntil: 'networkidle2' });
    const persiste = await page.evaluate(() => document.documentElement.lang);
    verifie('la langue choisie persiste d\'une page a l\'autre', persiste === 'en', `lang=${persiste}`);

    // ── Et survit a une session neuve, par le cookie ────────────────────────
    const cookies = await page.cookies(BASE);
    const cookieLangue = cookies.find(c => c.name === 'langue');
    verifie('un cookie de preference est pose', Boolean(cookieLangue),
            cookieLangue ? `langue=${cookieLangue.value}` : 'absent');

    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
