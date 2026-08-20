/**
 * go-page-conformite-pdf.mjs - Module `security/`, sous-lot S2b : l'export PDF
 * du rapport de conformite.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/security/compliance_report.php?format=pdf
 *   laravel  http://localhost:8444/rapport-conformite/pdf
 *
 * CE QUE FAIT LE LEGACY, lu avant d'ecrire une assertion (lignes 183-287) :
 * il construit un HTML par concatenation, le passe a dompdf, pose A4 paysage,
 * puis — et c'est le point qui compte — **purge toute sortie parasite avant
 * d'emettre le binaire** :
 *
 *     while (ob_get_level() > 0) { ob_end_clean(); }
 *     $dompdf->stream(...);
 *
 * Son commentaire nomme exactement E-33/E-40 : « purger tout output parasite
 * (notices PHP captures par ob_start en mode debug) avant d'emettre le binaire
 * PDF -> evite un PDF corrompu prefixe de "<br />..." ». C'est la MOITIE du
 * defaut qui avait ete corrigee — la branche CSV du meme fichier ne l'etait pas
 * (E-40). Cette suite verifie donc que la moitie protegee l'est vraiment, des
 * deux cotes.
 *
 * L'`ob_start()` de la ligne 276 est VESTIGIAL : le HTML est monte par
 * concatenation de chaines, rien n'est capture. Il n'existe que pour donner
 * quelque chose a purger. Le portage ne le reproduit pas : il n'ouvre aucun
 * tampon, donc il n'a rien a purger — la charge utile est assemblee puis rendue
 * d'un bloc, comme en S1 et S2c.
 *
 * COMMENT ON MESURE UN BINAIRE. Un PDF ne se lit pas comme du texte : dompdf
 * compresse ses flux (zlib est charge), donc un `grep` sur les octets ne trouve
 * pas le contenu. On mesure donc a deux niveaux :
 *   - la STRUCTURE, sur les octets bruts : l'en-tete `%PDF-` en tout premier —
 *     c'est la l'equivalent du BOM de S1 et S2c — et le marqueur `%%EOF` ;
 *   - le CONTENU, par `pdftotext`, present sur la VM. Il est croise avec la
 *     base : le rapport doit NOMMER chaque machine du parc.
 * Le fichier temporaire porte des donnees du parc : il est efface a la fin.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-conformite-pdf.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-conformite-pdf.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { execFileSync } from 'child_process';
import { litEnBase } from './lib-base.mjs';
import { writeFileSync, unlinkSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { constateArchivage } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel'
    ? '/rapport-conformite/pdf'
    : '/security/compliance_report.php?format=pdf';

const COMPTES = {
    'rw-test-user':  { role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW', attendu: 'refuse' },
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

/** Les noms des machines, LUS A LA SOURCE : on croise, on ne suppose pas. */
function nomsDesMachines() {
    return litEnBase('SELECT name FROM rootwarden.machines ORDER BY name');
}

/** Les noms des comptes, meme principe : on croise avec la base. */
function nomsDesComptes() {
    return litEnBase('SELECT name FROM rootwarden.users ORDER BY name');
}

/** Le texte PAGE PAR PAGE : une propriete de mise en page ne se mesure pas
 *  sur le document aplati — l'en-tete peut y figurer une fois et manquer la
 *  ou il sert. */
function textePages(fichier) {
    let pages = 0;
    try {
        const info = execFileSync('pdfinfo', [fichier],
            { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
        pages = parseInt((info.match(/^Pages:\s*(\d+)/m) || [])[1] || '0', 10);
    } catch { return []; }
    const out = [];
    for (let i = 1; i <= pages; i++) {
        try {
            out.push(execFileSync('pdftotext',
                ['-layout', '-f', String(i), '-l', String(i), fichier, '-'],
                { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] }));
        } catch { out.push(''); }
    }
    return out;
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

/** Le binaire tel qu'il arrive. Le corps revient en base64 : c'est un binaire. */
async function exporte(page) {
    return page.evaluate(async (url) => {
        const r = await fetch(url, { credentials: 'same-origin' });
        const tampon = await r.arrayBuffer();
        const octets = new Uint8Array(tampon);
        let binaire = '';
        for (let i = 0; i < octets.length; i++) binaire += String.fromCharCode(octets[i]);
        return {
            statut: r.status,
            type: r.headers.get('content-type') || '',
            disposition: r.headers.get('content-disposition') || '',
            taille: octets.length,
            entete: [...octets.slice(0, 8)],
            b64: btoa(binaire),
        };
    }, PAGE);
}

console.log(`\n=== Module security/, sous-lot S2b — export PDF du rapport (${CIBLE}) ===\n`);
constate('cible', `${BASE}${PAGE}`);
constate('ce que fait le legacy, lu dans compliance_report.php:183-287',
    'HTML monte par concatenation -> dompdf -> A4 paysage, avec purge ob_end_clean AVANT le binaire');

const NOMS = nomsDesMachines();
const NOMS_COMPTES = nomsDesComptes();
constate('machines lues en base', `${NOMS.length}`);
constate('comptes lus en base', `${NOMS_COMPTES.length}`);

let fichier = null;
try {
    if (CIBLE === 'legacy') {
        const archive = await constateArchivage({
            base: BASE, chemin: '/security/compliance_report.php', fichiers: [], verifie, constate,
        });
        if (archive) throw new Error('__archivee__');
    }

    // La session du role 2 est CONSERVEE : se reconnecter dans la meme fenetre
    // TOTP rejoue le meme code, et le portage refuse.
    let session = null;
    for (const nom of Object.keys(COMPTES)) {
        const compte = COMPTES[nom];
        const s = await connecte(nom);
        const r = await exporte(s.page);
        constate(`${nom} (role ${compte.role})`, `statut ${r.statut}, ${r.taille} octet(s)`);
        if (compte.attendu === 'refuse') {
            verifie(`${nom} : role 1 sans can_view_compliance est refuse`,
                r.statut === 403, `statut ${r.statut}`);
        } else {
            verifie(`${nom} : autorise a exporter`, r.statut === 200, `statut ${r.statut}`);
        }
        if (nom === 'rw-test-admin') session = s; else await s.ctx.close();
    }

    const { ctx, page } = session;
    const pdf = await exporte(page);

    verifie('le type dit bien un PDF', /application\/pdf/.test(pdf.type), `type « ${pdf.type} »`);
    verifie('le fichier est propose en telechargement, date du jour',
        /attachment/.test(pdf.disposition)
            && /filename="?rapport_conformite_\d{4}-\d{2}-\d{2}\.pdf"?/.test(pdf.disposition),
        `disposition « ${pdf.disposition} »`);

    // ── La structure, sur les OCTETS BRUTS ──────────────────────────────────
    // `%PDF-` doit etre en TOUT PREMIER. C'est ici l'equivalent du BOM de S1 et
    // S2c : si une notice PHP a fui avant le binaire, ces cinq octets ne sont
    // plus les premiers et le lecteur refuse le fichier.
    const magique = String.fromCharCode(...pdf.entete.slice(0, 5));
    constate('cinq premiers octets', `« ${magique} » (${pdf.entete.slice(0, 5).join(' ')})`);
    verifie('le fichier commence par %PDF-, en tout premier',
        magique === '%PDF-',
        `« ${magique} »`);

    const octets = Buffer.from(pdf.b64, 'base64');
    fichier = join(tmpdir(), `rw-conformite-${CIBLE}-${process.pid}.pdf`);
    writeFileSync(fichier, octets);
    constate('taille du fichier', `${statSync(fichier).size} octets`);
    verifie('le fichier n\'est pas tronque : il porte son marqueur de fin',
        octets.slice(-1024).includes('%%EOF'), 'les 1024 derniers octets portent %%EOF');
    verifie('le fichier a une taille plausible pour un rapport de parc',
        octets.length > 4096, `${octets.length} octets`);

    // ── Le contenu, par pdftotext ───────────────────────────────────────────
    let texte = '';
    try {
        texte = execFileSync('pdftotext', ['-layout', fichier, '-'],
            { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
    } catch (e) {
        constate('pdftotext', `indisponible ou en echec : ${String(e).split('\n')[0]}`);
    }
    constate('texte extrait', `${texte.length} caractere(s)`);
    verifie('le PDF est lisible par un extracteur de texte',
        texte.length > 200, `${texte.length} caractere(s)`);

    const nomme = NOMS.filter(n => texte.includes(n));
    constate('machines nommees dans le PDF', `${nomme.length}/${NOMS.length}`);
    verifie('le rapport NOMME chaque machine du parc',
        NOMS.length > 0 && nomme.length === NOMS.length,
        `${nomme.length} sur ${NOMS.length}`);

    const empreinte = (texte.match(/\b[0-9a-f]{64}\b/) || [])[0] || '';
    verifie('le rapport porte son empreinte SHA-256',
        /^[0-9a-f]{64}$/.test(empreinte),
        empreinte ? `${empreinte.slice(0, 16)}...` : 'aucune empreinte trouvee');

    // Les sections, reperees par un mot-cle robuste a une reformulation.
    const sections = { posture: /[Pp]osture/, cve: /CVE/, comptes: /[Cc]ompte|[Uu]tilisateur/ };
    const presentes = Object.entries(sections).filter(([, m]) => m.test(texte)).map(([k]) => k);
    constate('sections reconnues', presentes.join(', ') || 'aucune');
    verifie('le rapport porte ses sections : posture, CVE, comptes',
        presentes.length === 3, `${presentes.length}/3`);

    // ── Un tableau qui change de page REDONNE son en-tete ───────────────────
    // ECART VOULU, cote portage seul (E-45). Le legacy monte ses tableaux en
    // `<table><tr><th>` sans `<thead>` : dompdf ne repete alors rien, et les
    // lignes qui debordent arrivent page suivante en colonnes ANONYMES — sur le
    // tableau des comptes, trois lignes de « Oui / Non / — » sans rien qui dise
    // de quoi. Ce defaut ne se voit PAS sur le document aplati : l'en-tete y est
    // present une fois. Il a fallu rendre les pages en images pour le voir.
    // Le portage enveloppe donc ses en-tetes dans `<thead>`. Cote legacy la
    // propriete est MESUREE mais rendue en constat, par `verifiePortage` : un
    // FAIL y serait compte comme une regression par le rejeu du LOT, alors que
    // c'est un ecart assume et declare (E-45).
    const pages = textePages(fichier);
    constate('pages du document', String(pages.length));
    // Une page « de comptes » est une page qui porte AU MOINS DEUX noms de
    // comptes : un seul pourrait etre la mention « genere par ».
    const pagesComptes = pages
        .map((t, i) => ({ n: i + 1, t, nb: NOMS_COMPTES.filter(c => t.includes(c)).length }))
        .filter(p => p.nb >= 2);
    const sansEntete = pagesComptes.filter(p => !/\bCle SSH\b/.test(p.t)).map(p => p.n);
    constate('pages portant des lignes de comptes',
        pagesComptes.map(p => `p${p.n} (${p.nb})`).join(', ') || 'aucune');
    verifiePortage('chaque page de comptes redonne l\'en-tete du tableau',
        pagesComptes.length > 0 && sansEntete.length === 0,
        pagesComptes.length === 0
            ? 'non mesurable : aucune page ne porte deux comptes'
            : (sansEntete.length ? `en-tete absent page(s) ${sansEntete.join(', ')}`
                                 : `${pagesComptes.length} page(s), en-tete partout`));

    // ── Ce que la purge doit garantir ───────────────────────────────────────
    // Exigible des DEUX cotes : c'est justement la moitie du defaut que le
    // legacy avait corrigee (`ob_end_clean` avant le `stream`).
    // ASSERTER D'ABORD QU'IL Y A DU TEXTE. Sur un document illisible — un 500
    // rendu en HTML, par exemple — `texte` est vide, aucun motif ne matche, et
    // « aucun fragment n'a fui » passe au vert sans rien mesurer. C'est la meme
    // faille que `[].every()`, et elle s'est produite au premier passage.
    const fragments = (texte.match(/<(br|b|div|span)\b/gi) || []).length;
    constate('fragments HTML dans le texte extrait', String(fragments));
    verifie('aucun fragment HTML n\'a fui dans le document',
        texte.length > 200 && fragments === 0,
        texte.length > 200 ? `${fragments} fragment(s)` : 'sans objet : aucun texte extrait');

    await ctx.close();
} catch (e) {
    if (! String(e).includes('__archivee__')) {
        lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
        echecs++;
    }
} finally {
    // Le fichier porte des donnees du parc : il ne reste pas sur le disque.
    if (fichier) { try { unlinkSync(fichier); } catch {} }
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
