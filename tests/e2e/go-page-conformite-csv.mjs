/**
 * go-page-conformite-csv.mjs - Module `security/`, sous-lot S2c : l'export CSV
 * du rapport de conformite.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/security/compliance_report.php?format=csv
 *   laravel  http://localhost:8444/rapport-conformite/csv
 *
 * PERIMETRE S2c. L'export CSV seul. La page HTML est S2a (portee), le PDF est
 * S2b. Les sept collectes et le bareme de posture vivent deja dans
 * `App\Services\Conformite` : ce sous-lot n'ecrit que le fichier.
 *
 * CE QUE FAIT LE LEGACY, lu avant d'ecrire une assertion (lignes 146-180) :
 * un BOM UTF-8, puis un titre, puis quatre sections separees par une ligne vide
 * — `=== RESUME ===` (quatre lignes de compteurs), `=== POSTURE PAR SERVEUR ===`
 * (un en-tete de cinq colonnes puis une ligne par machine), `=== SERVEURS ===`
 * (neuf colonnes, une ligne par machine), `=== UTILISATEURS ===` (sept colonnes,
 * une ligne par compte) — et enfin `SHA-256,<empreinte>`.
 *
 * DEUX DETAILS RELEVES A LA LECTURE, ET QUI COMPTENT :
 *
 * 1. E-33 SE REJOUE ICI. Le legacy ecrit au fil de l'eau dans `php://output`, et
 *    `verify.php` pose `display_errors=1` quand `DEBUG_MODE=true` : sur PHP 8.4,
 *    chaque `fputcsv()` sans son argument `$escape` injecte un bloc HTML
 *    `<b>Deprecated</b>` DANS le fichier telecharge. La branche PDF du MEME
 *    fichier porte deja un `ob_end_clean()` dont le commentaire nomme exactement
 *    ce defaut — quelqu'un l'a rencontre et n'a corrige qu'une moitie.
 *
 * 2. LA SECTION DES COMPTES N'A PAS LE MEME PERIMETRE QUE LA PAGE. Le CSV
 *    parcourt TOUS les comptes ; le tableau HTML saute les inactifs
 *    (`if (!$u['active']) continue;`). Deux vues du meme rapport, deux
 *    populations. Repris tel quel — restreindre l'un ou elargir l'autre change
 *    ce que le rapport DIT, ce qui est une decision et non un effet de bord.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-conformite-csv.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-conformite-csv.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { constateArchivage } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel'
    ? '/rapport-conformite/csv'
    : '/security/compliance_report.php?format=csv';

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

/**
 * Les comptes du parc et de la base, LUS A LA SOURCE.
 *
 * Croiser avec la source vaut mieux que mesurer une forme : « la section a des
 * lignes » passe au vert sur une section tronquee, « elle en a autant que la
 * base » ne passe que si elle est complete. Et rien n'est ecrit en dur : un
 * nombre fige accuserait la page au premier ajout de machine ou de compte.
 */
// Les deux lecteurs vivent dans `lib-base.mjs` : voir son en-tete pour la
// raison — le mot de passe ne doit pas sortir dans un message d'echec.

/**
 * Decoupe un CSV en ENREGISTREMENTS, pas en lignes physiques : un champ entre
 * guillemets peut contenir des retours a la ligne, et c'est du CSV valide.
 * Compter les lignes faisait passer les suites de champ pour des lignes
 * etrangeres — 6 117 fausses « lignes » sur l'export d'un scan.
 */
function enregistrements(texte) {
    const sortie = [];
    let courant = '';
    let dedans = false;
    for (let i = 0; i < texte.length; i++) {
        const c = texte[i];
        if (c === '"') {
            if (dedans && texte[i + 1] === '"') { courant += '""'; i++; continue; }
            dedans = !dedans; courant += c; continue;
        }
        if (!dedans && (c === '\n' || c === '\r')) {
            if (c === '\r' && texte[i + 1] === '\n') i++;
            sortie.push(courant); courant = ''; continue;
        }
        courant += c;
    }
    if (courant !== '') sortie.push(courant);
    return sortie;
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 90000,
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

/** Le fichier tel qu'il arrive : statut, en-tetes, octets bruts et texte. */
async function exporte(page) {
    return page.evaluate(async (url) => {
        const r = await fetch(url, { credentials: 'same-origin' });
        const tampon = await r.arrayBuffer();
        return {
            statut: r.status,
            type: r.headers.get('content-type') || '',
            disposition: r.headers.get('content-disposition') || '',
            // Les octets BRUTS : `Response.text()` SUPPRIME le BOM au decodage.
            octets: [...new Uint8Array(tampon.slice(0, 3))],
            corps: new TextDecoder('utf-8').decode(tampon),
        };
    }, PAGE);
}

console.log(`\n=== Module security/, sous-lot S2c — export CSV du rapport (${CIBLE}) ===\n`);
constate('cible', `${BASE}${PAGE}`);
constate('ce que fait le legacy, lu dans compliance_report.php:146-180',
    'BOM, un titre, quatre sections separees par une ligne vide, puis SHA-256 — aucune route backend');

const PARC = compteEnBase('SELECT COUNT(*) FROM rootwarden.machines');
const NB_COMPTES = compteEnBase('SELECT COUNT(*) FROM rootwarden.users');
const NOMS_MACHINES = litEnBase('SELECT name FROM rootwarden.machines ORDER BY name');
constate('lus en base', `${PARC} machine(s), ${NB_COMPTES} compte(s)`);

try {
    if (CIBLE === 'legacy') {
        const archive = await constateArchivage({
            base: BASE, chemin: '/security/compliance_report.php', fichiers: [], verifie, constate,
        });
        if (archive) throw new Error('__archivee__');
    }

    // ── La garde ────────────────────────────────────────────────────────────
    // La session du role 2 est CONSERVEE : se reconnecter avec le meme compte
    // dans la meme fenetre TOTP rejoue le meme code, et le portage refuse.
    let session = null;
    for (const nom of Object.keys(COMPTES)) {
        const compte = COMPTES[nom];
        const s = await connecte(nom);
        const r = await exporte(s.page);
        constate(`${nom} (role ${compte.role})`, `statut ${r.statut}`);
        if (compte.attendu === 'refuse') {
            verifie(`${nom} : role 1 sans can_view_compliance est refuse`,
                r.statut === 403, `statut ${r.statut}`);
        } else {
            verifie(`${nom} : autorise a exporter`, r.statut === 200, `statut ${r.statut}`);
        }
        if (nom === 'rw-test-admin') session = s; else await s.ctx.close();
    }

    const { ctx, page } = session;
    const csv = await exporte(page);

    verifie('le type dit bien un CSV', /text\/csv/.test(csv.type), `type « ${csv.type} »`);
    verifie('le fichier est propose en telechargement, date du jour',
        /attachment/.test(csv.disposition)
            && /filename="rapport_conformite_\d{4}-\d{2}-\d{2}\.csv"/.test(csv.disposition),
        `disposition « ${csv.disposition} »`);
    verifie('le fichier commence par le BOM UTF-8 qu\'Excel attend',
        csv.octets[0] === 0xEF && csv.octets[1] === 0xBB && csv.octets[2] === 0xBF,
        `trois premiers octets : ${csv.octets.map(o => o.toString(16).padStart(2, '0').toUpperCase()).join(' ')}`);

    // ── Le flux ne doit porter que du CSV ───────────────────────────────────
    const avertissements = (csv.corps.match(/<b>(Deprecated|Warning|Notice|Fatal error)<\/b>/g) || []).length;
    constate('blocs d\'avertissement PHP dans le flux du fichier', String(avertissements));
    verifiePortage('le flux du fichier ne porte AUCUN avertissement PHP',
        avertissements === 0,
        `${avertissements} bloc(s) — un telechargement n'herite pas de display_errors`);

    // ── La structure ────────────────────────────────────────────────────────
    const rangs = enregistrements(csv.corps.replace(/^﻿/, ''));
    const nu = (l) => l.replace(/"/g, '').trim();
    // Les marqueurs sont reperes par leur FORME (`=== … ===`) et non par leur
    // texte : le portage les traduit, comme le reste du fichier, et une
    // assertion sur le libelle francais rougirait en anglais. On mesure qu'il y
    // en a quatre et qu'ils se suivent — c'est la structure qui compte.
    const positions = rangs.reduce((acc, l, i) => (/^===\s.*\s===$/.test(nu(l)) ? [...acc, i] : acc), []);
    constate('marqueurs de section', positions.length
        ? positions.map(i => `${i}:${nu(rangs[i])}`).join(' | ') : 'aucun');
    verifie('le fichier porte ses quatre sections, dans l\'ordre',
        positions.length === 4 && positions.every((p, i) => i === 0 || p > positions[i - 1]),
        `${positions.length} marqueur(s)`);

    // Un titre avant tout, et une empreinte apres tout.
    verifiePortage('le fichier s\'ouvre sur son titre',
        /^Rapport de conformite/.test(nu(rangs[0] || '')), `« ${nu(rangs[0] || '').slice(0, 50)} »`);
    const dernier = rangs.filter(l => l.trim() !== '').pop() || '';
    const empreinte = (nu(dernier).match(/\b[0-9a-f]{64}\b/) || [])[0] || '';
    verifie('le fichier se ferme sur son empreinte SHA-256',
        /^SHA-256/.test(nu(dernier)) && /^[0-9a-f]{64}$/.test(empreinte),
        empreinte ? `${empreinte.slice(0, 16)}...` : `« ${nu(dernier).slice(0, 40)} »`);

    // ── Le contenu des sections, croise avec la base ────────────────────────
    // Les lignes d'une section vont de son en-tete a la ligne vide suivante.
    const corpsDe = (debut) => {
        const lignesSection = [];
        for (let i = debut + 2; i < rangs.length; i++) {   // +1 marqueur, +1 en-tete
            if (rangs[i].trim() === '') break;
            lignesSection.push(rangs[i]);
        }
        return lignesSection;
    };
    const posture = corpsDe(positions[1]);
    const serveurs = corpsDe(positions[2]);
    const comptes = corpsDe(positions[3]);
    constate('lignes par section', `posture ${posture.length}, serveurs ${serveurs.length}, comptes ${comptes.length}`);

    verifiePortage('la section de posture ne porte QUE le parc',
        posture.length === PARC, `${posture.length} pour ${PARC} machine(s)`);
    verifiePortage('la section des serveurs ne porte QUE le parc',
        serveurs.length === PARC, `${serveurs.length} pour ${PARC} machine(s)`);
    // Le CSV parcourt TOUS les comptes, la page HTML saute les inactifs.
    verifiePortage('la section des comptes ne porte QUE les comptes',
        comptes.length === NB_COMPTES, `${comptes.length} pour ${NB_COMPTES} compte(s)`);

    // `[].every()` rend `true` : asserter d'abord qu'il y en a.
    verifiePortage('chaque ligne de posture porte un score borne et une note A-F',
        posture.length > 0 && posture.every(l => {
            const c = nu(l).split(',');
            const score = parseInt(c[2], 10);
            return /^\d+\/100$/.test(c[2]) && score >= 0 && score <= 100 && /^[A-F]$/.test(c[3]);
        }),
        posture.length ? `exemple : ${nu(posture[0]).split(',').slice(0, 4).join(' | ')}` : 'aucune ligne');

    // Exigible des DEUX cotes : la contamination AJOUTE des lignes, elle n'en
    // retire pas. Une section qui n'aurait pas toutes les machines serait
    // tronquee — et cela, le legacy doit le tenir aussi. C'est la COUVERTURE
    // qu'on mesure ici, pas la proprete du fichier.
    const nomme = (section) => NOMS_MACHINES.filter(n => section.some(l => l.includes(n)));
    constate('machines nommees', `posture ${nomme(posture).length}/${PARC}, serveurs ${nomme(serveurs).length}/${PARC}`);
    verifie('la section de posture NOMME chaque machine du parc',
        nomme(posture).length === PARC, `${nomme(posture).length} sur ${PARC}`);
    verifie('la section des serveurs NOMME chaque machine du parc',
        nomme(serveurs).length === PARC, `${nomme(serveurs).length} sur ${PARC}`);

    verifiePortage('le fichier ne porte aucun enregistrement etranger',
        rangs.filter(l => l.trim() !== '').length
            === 1 + 1 + 4 + 1 + 1 + PARC + 1 + 1 + PARC + 1 + 1 + NB_COMPTES + 1,
        `${rangs.filter(l => l.trim() !== '').length} enregistrement(s) non vides`);

    await ctx.close();
} catch (e) {
    if (! String(e).includes('__archivee__')) {
        lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
        echecs++;
    }
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
