/*
 * ═══ LE FORMULAIRE DE PLANIFICATION SSH — ET AUCUNE PLANIFICATION POSEE ═══
 *
 * ══ CE QUE CETTE SUITE NE FERA JAMAIS, ET POURQUOI C'EST LA PREMIERE LIGNE ═
 *
 * Elle ne SOUMET pas. Aucune ligne n'est ecrite dans `ssh_audit_schedules`.
 *
 * L'ordonnanceur tourne dans un thread INVISIBLE a `ps` : une planification de
 * test posee en base peut declencher un VRAI releve SSH sur le parc. Et la
 * parade qu'on croyait suffisante ne l'est pas — « cible sure = tag inexistant »
 * etait FAUX tant que `scheduler.py` retombait, quand `target_value` etait vide,
 * sur un `SELECT ... FROM machines` sans filtre : TOUT LE PARC, production
 * comprise.
 *
 * ⚠ CETTE RAISON A CHANGE LE 2026-09-05 (E-280), et il faut la DATER plutot que
 * la recopier : les deux chemins portent desormais un `else` qui REFUSE et
 * journalise (`WHERE 1=0`, aucune machine). **La conclusion tient dans les deux
 * mondes, mais pas pour la meme raison** — et qui reprendrait l'ancienne se
 * protegerait d'un danger disparu en manquant celui qui existe.
 *
 * La surete n'est donc pas une intention, c'est une CONSTRUCTION : le filet de
 * cette suite avorte tout non-GET des que la connexion est finie. Meme un clic
 * mal ancre sur « valider » ne peut pas atteindre le backend. Et la suite le
 * MESURE au lieu de le promettre : elle rend la liste des requetes avortees, et
 * cette liste doit etre VIDE — un avortement signifierait qu'un geste a essaye.
 *
 * ══ CE QU'ELLE PROUVE ═════════════════════════════════════════════════════
 *
 * 1. LA GARDE PAR CONSTRUCTION. Le `<select>` de portee ne peut pas exprimer
 *    « tout le parc ». Ce n'est pas un controle qu'on ajoute, c'est une option
 *    qui n'existe pas : `AuditSshController::PORTEES` vaut
 *    `['environment','tag','machines']`, et le gabarit construit ses `<option>`
 *    DEPUIS cette constante. Une liste rendue depuis sa source ne peut pas la
 *    contredire — c'est ce qui a manque a `scan-cve` (E-387), ou la liste etait
 *    ecrite a la main et ou retirer la constante laissait une option que le
 *    serveur refuse.
 *
 * 2. LE PANNEAU S'OUVRE VRAIMENT. Le bouton « creer » est un basculement
 *    d'interface, sans requete. On CLIQUE, et on mesure que le bloc devient
 *    visible — pas qu'il existe dans le DOM. Un panneau present et haut de zero
 *    pixel satisfait toute assertion de presence.
 *
 * 3. LES LIBELLES SONT RENDUS. C'est la classe du defaut F7 : les cles etaient
 *    dans `lang/fr` ET dans `lang/en`, la parite i18n etait verte, les ancres
 *    DOM etaient la, le panneau s'ouvrait — et il s'affichait VIDE, parce que
 *    le controleur ne passait pas les textes. Seul un RENDU l'attrape. On exige
 *    donc que chaque etiquette et chaque option porte du texte non vide, et
 *    qu'aucune ne laisse fuiter une cle brute (`ssh_audit.planif_...`).
 *
 * 4. LE CONTRASTE. Une classe absente de `rw.css` ne leve aucune erreur : le
 *    HTML est juste, l'element est la, et il est invisible. Ce depot l'a paye
 *    quatre fois, dont une pastille a 1,06:1. On mesure le style CALCULE du
 *    bouton, ce qu'aucune assertion DOM ne voit.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { mkdirSync } from 'fs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = (() => {
    /*
     * ══ LA CIBLE VIENT DE L'ENVIRONNEMENT, L'URL N'EST QU'UN REPLI ════════
     *
     * `/8444|laravel/i.test(BASE)` deduit la cible d'un NUMERO DE PORT. Tant que
     * le portage vit sur 8444 c'est juste ; **le jour ou les ports s'echangent,
     * ce predicat rend 87 suites MENTEUSES et non rouges** — elles appliqueraient
     * les attentes du legacy au portage, et rendraient du VERT.
     *
     * `E2E_CIBLE` devient donc l'autorite, et `rejouer-lot.sh` l'exporte pour
     * chaque moitie. Le motif d'URL ne sert plus qu'aux lancements a la main.
     *
     * ⚠ ET IL N'Y A PAS DE GARDE DE COHERENCE ENTRE LES DEUX — c'est deliberé,
     * et l'inverse a ete demande puis ecarte apres mesure :
     *
     *     E2E_CIBLE=laravel + BASE=…:8443
     *       AVANT l'echange  incoherent   (a refuser)
     *       APRES l'echange  CORRECT      (a accepter)
     *
     * **Une garde « l'environnement doit concorder avec le motif d'URL »
     * refuserait exactement la configuration que cet elargissement existe pour
     * permettre.** Le motif d'URL n'est pas un invariant : c'est la chose meme
     * qu'on rend caduque. On ne garde pas une valeur contre une heuristique
     * qu'on sait perimee.
     *
     * CE QUI EST INVARIANT, ET SUR QUOI LA GARDE SE POSE : la cible appartient a
     * une LISTE FERMEE. Une valeur hors liste est refusee bruyamment, au
     * chargement, avant qu'une seule assertion ne s'execute — une faute de frappe
     * ne doit pas se lire comme « legacy » par repli silencieux.
     */
    const CIBLES = ['laravel', 'legacy'];
    const declaree = process.env.E2E_CIBLE;
    if (declaree !== undefined && declaree !== '') {
        if (! CIBLES.includes(declaree)) {
            throw new Error(
                `E2E_CIBLE=${JSON.stringify(declaree)} n'est pas une cible connue `
                + `(${CIBLES.join(' | ')}). Rien n'est joue : une cible inconnue `
                + `retomberait sur « legacy » et la suite mesurerait le mauvais portail.`);
        }

        return declaree;
    }

    return /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
})();
const PAGE = CIBLE === 'laravel' ? '/audit-ssh' : '/ssh-audit/';

/* Secret RELEVE dans les suites existantes (61 fichiers au 2026-09-04). */
const COMPTE = { nom: 'rw-test-super', secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW' };

/* La liste fermee attendue. `all` n'en fait PAS partie, et c'est le sujet. */
const PORTEES_ATTENDUES = ['environment', 'tag', 'machines'];

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,''))b+=a.indexOf(c).toString(2).padStart(5,'0');const o=[];for(let i=0;i+8<=b.length;i+=8)o.push(parseInt(b.slice(i,i+8),2));return Buffer.from(o)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[19]&0xf;return String(((h.readUInt32BE(o)&0x7fffffff)%1000000)).padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
const avortees = [];
let enConnexion = false;

function verifie(libelle, ok, detail, __quatrieme) {
    if (__quatrieme !== undefined) {
        throw new Error('INF-002 : `verifie` de ce fichier prend TROIS arguments.');
    }
    lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${libelle}${detail ? '  — ' + detail : ''}`);
    if (!ok) echecs++;
}
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }
function verifiePortage(libelle, ok, detail) {
    if (CIBLE === 'laravel') return verifie(libelle, ok, detail);
    constate(libelle, `non exigible du legacy — ${detail}`);
}

/* Le rapport de contraste WCAG entre deux couleurs `rgb(...)`. */
function contraste(avant, arriere) {
    const lum = (c) => {
        const [r, g, b] = (c.match(/\d+(\.\d+)?/g) || ['0', '0', '0']).slice(0, 3)
            .map((v) => Number(v) / 255)
            .map((v) => (v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4)));
        return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const a = lum(avant), b = lum(arriere);
    return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 90000,
});

/*
 * LE FILET — refus par ETAT, pas par liste d'URL.
 *
 * Un premier jet nommait les URL de connexion et oubliait `/second-facteur` :
 * la connexion n'aboutissait pas et toutes les assertions suivantes mesuraient
 * la page de connexion, en vert-faux. Une phase est fermee par construction ;
 * une liste d'URL oublie toujours l'etape suivante.
 */
function installeFilet(page) {
    page.setRequestInterception(true);
    page.on('request', (r) => {
        if (r.method() !== 'GET' && !enConnexion) {
            avortees.push(`${r.method()} ${r.url().replace(BASE, '')}`);
            return r.abort('blockedbyclient').catch(() => {});
        }
        r.continue().catch(() => {});
    });
}

async function connecte() {
    enConnexion = true;
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(30000);
    page.on('dialog', d => d.dismiss().catch(() => {}));
    installeFilet(page);

    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/ }
        : { connexion: '/auth/login.php', cgu: /terms\.php/ };

    await page.goto(`${BASE}${chemins.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', COMPTE.nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    await page.type('input[name="2fa_code"]', totp(COMPTE.secret), { delay: 8 });
    nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}

    if (chemins.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$('[data-rw="cgu-accepter"]') || await page.$('button[name="accept_terms"]');
        if (b) await b.evaluate(x => x.click());
        try { await nav; } catch {}
    }
    // Phase CLOSE : a partir d'ici tout non-GET est avorte.
    enConnexion = false;

    return { ctx, page };
}

/** Un element est-il VISIBLE ? Present dans le DOM ne suffit pas. */
async function visible(page, ancre) {
    return page.evaluate((sel) => {
        const e = document.querySelector(sel);
        if (!e) return { present: false, visible: false, h: 0, w: 0 };
        const r = e.getBoundingClientRect();
        const s = getComputedStyle(e);
        return {
            present: true,
            visible: r.height > 0 && r.width > 0 && s.visibility !== 'hidden'
                     && s.display !== 'none' && !e.hasAttribute('hidden'),
            h: Math.round(r.height), w: Math.round(r.width),
        };
    }, `[data-rw="${ancre}"]`);
}

try {
    const { ctx, page } = await connecte();

    const reponse = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    const statut = reponse ? reponse.status() : 0;
    verifie('la page d\'audit SSH repond 200, et n\'est pas la connexion',
        statut === 200 && !/\/connexion|login\.php/.test(page.url()),
        `statut ${statut}, URL finale ${page.url().replace(BASE, '')}`);

    // ══ 1. LE BOUTON D'OUVERTURE, ET LE PANNEAU FERME AU DEPART ═══════════
    const bouton = await visible(page, 'audit-ssh-planif-creer');
    verifiePortage('le bouton de creation d\'une planification est visible',
        bouton.visible, bouton.present ? `${bouton.w}x${bouton.h} px` : 'ancre absente du DOM');

    const avantClic = await visible(page, 'audit-ssh-planif-bloc');
    verifiePortage('le formulaire est FERME tant qu\'on n\'a rien demande',
        avantClic.present && !avantClic.visible,
        avantClic.present ? `hauteur ${avantClic.h} px` : 'ancre absente du DOM');

    // ══ 2. LE CLIC OUVRE — un basculement d'interface, AUCUNE requete ═════
    if (bouton.present) {
        await page.click('[data-rw="audit-ssh-planif-creer"]');
        await dors(500);
    }
    const apresClic = await visible(page, 'audit-ssh-planif-bloc');
    verifiePortage('le clic OUVRE le formulaire, et il occupe une hauteur reelle',
        apresClic.visible && apresClic.h > 40,
        apresClic.present ? `${apresClic.w}x${apresClic.h} px` : 'ancre absente du DOM');

    // ══ 3. LES CHAMPS ═════════════════════════════════════════════════════
    for (const champ of ['audit-ssh-planif-nom', 'audit-ssh-planif-freq',
                         'audit-ssh-planif-portee', 'audit-ssh-planif-valider']) {
        const v = await visible(page, champ);
        verifiePortage(`le champ ${champ.replace('audit-ssh-planif-', '')} est visible`,
            v.visible, v.present ? `${v.w}x${v.h} px` : 'ancre absente du DOM');
    }

    // ══ 4. LA GARDE PAR CONSTRUCTION ══════════════════════════════════════
    //
    // Le sujet de cette suite. On lit les options RENDUES, pas la constante PHP :
    // c'est ce que l'ecran propose qui peut etre choisi.
    const options = await page.evaluate(() => {
        const s = document.querySelector('[data-rw="audit-ssh-planif-portee"]');
        return s ? [...s.options].map((o) => ({ valeur: o.value, libelle: (o.textContent || '').trim() })) : null;
    });
    verifiePortage('le <select> de portee est rendu',
        Array.isArray(options) && options.length > 0,
        options ? `${options.length} option(s)` : 'select introuvable');

    if (Array.isArray(options)) {
        const valeurs = options.map((o) => o.valeur);
        verifiePortage('AUCUNE option ne permet de viser tout le parc',
            !valeurs.includes('all') && !valeurs.includes(''),
            `valeurs proposees : ${JSON.stringify(valeurs)}`);
        verifiePortage('les portees proposees sont exactement la liste fermee',
            valeurs.length === PORTEES_ATTENDUES.length
                && PORTEES_ATTENDUES.every((p) => valeurs.includes(p)),
            `rendu ${JSON.stringify(valeurs)} contre ${JSON.stringify(PORTEES_ATTENDUES)}`);

        // ══ 5. LES LIBELLES SONT RENDUS — la classe du defaut F7 ══════════
        const vides = options.filter((o) => !o.libelle);
        const brutes = options.filter((o) => /^ssh_audit\./.test(o.libelle));
        verifiePortage('chaque option porte un libelle non vide',
            vides.length === 0,
            vides.length === 0 ? `${options.length} libelle(s)` : `vides : ${JSON.stringify(vides.map(o => o.valeur))}`);
        verifiePortage('aucune option ne laisse fuiter une cle de traduction brute',
            brutes.length === 0,
            brutes.length === 0 ? 'aucune' : JSON.stringify(brutes.map(o => o.libelle)));
    }

    // Les etiquettes du formulaire, meme exigence : rendues, pas seulement la.
    const etiquettes = await page.evaluate(() => {
        const bloc = document.querySelector('[data-rw="audit-ssh-planif-bloc"]');
        if (!bloc) return null;
        return [...bloc.querySelectorAll('label')].map((l) => (l.textContent || '').trim());
    });
    verifiePortage('chaque etiquette du formulaire porte du texte',
        Array.isArray(etiquettes) && etiquettes.length > 0 && etiquettes.every((t) => t.length > 0),
        etiquettes ? `${etiquettes.length} etiquette(s), la plus courte « ${
            etiquettes.slice().sort((a, b) => a.length - b.length)[0]} »` : 'bloc introuvable');

    // ══ 6. LE CONTRASTE — ce qu'aucune assertion DOM ne voit ══════════════
    const couleurs = await page.evaluate(() => {
        const e = document.querySelector('[data-rw="audit-ssh-planif-valider"]');
        if (!e) return null;
        const s = getComputedStyle(e);
        return { texte: s.color, fond: s.backgroundColor };
    });
    if (couleurs) {
        const r = contraste(couleurs.texte, couleurs.fond);
        verifiePortage('le bouton de validation est lisible (contraste WCAG >= 4,5:1)',
            r >= 4.5,
            `${r.toFixed(2)}:1 — texte ${couleurs.texte} sur fond ${couleurs.fond}`);
    } else {
        constate('contraste du bouton de validation', 'NON MESURE — bouton introuvable');
    }

    // ══ 7. CAPTURES ═══════════════════════════════════════════════════════
    const dossier = new URL(`./screenshots/audit-ssh-planif/${CIBLE}`, import.meta.url).pathname;
    mkdirSync(dossier, { recursive: true });
    for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                     { n: 'mobile', w: 390, h: 844 }]) {
        await page.setViewport({ width: f.w, height: f.h });
        await dors(400);
        await page.screenshot({ path: `${dossier}/planif-${f.n}.png`, fullPage: true });
    }
    constate('captures ecrites', dossier);

    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e.message || e).split('\n')[0]);
    echecs++;
} finally {
    /*
     * LE FILET SE MESURE, IL NE SE PROMET PAS. Cette liste doit etre VIDE :
     * un avortement signifierait qu'un geste de cette suite a tente d'ecrire,
     * et le prochain lecteur doit le voir plutot que de me croire.
     */
    verifie('AUCUNE ecriture n\'a ete tentee vers le backend',
        avortees.length === 0,
        avortees.length === 0 ? 'le filet n\'a rien eu a avorter'
            : `⚠ tentatives avortees : ${avortees.join(' | ')}`);
    constate('planification posee en base', 'AUCUNE — cette suite ne soumet pas.');
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
