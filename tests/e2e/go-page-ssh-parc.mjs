/**
 * go-page-ssh-parc.mjs - Module `ssh/` (« Cles SSH »), sous-lot K1 : la page nue.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/ssh/
 *   laravel  http://localhost:8444/cles-ssh
 *
 * K1 NE TOUCHE AUCUNE ROUTE. C'est tout l'interet de commencer par lui : le module
 * `ssh/` est le plus dangereux du depot, et sa page nue n'appelle rien.
 *
 * CE QUE LE MODULE FAIT, POUR SAVOIR CE QU'ON NE TOUCHE PAS.
 *
 * Un seul bouton (`onclick="deploySSH()"`), **sans confirmation d'aucune sorte**,
 * declenche trois routes en cascade sans reprise de main. `POST /deploy` lance
 * `configure_servers.py` sur CHAQUE machine selectionnee, en root, cinq en
 * parallele : il installe `sudo` par `apt-get`, cree des comptes UNIX, ECRASE des
 * `authorized_keys`, installe des politiques sudoers — et **REVOQUE** les cles de
 * tout compte ayant perdu son habilitation. `srv-zabbix` est en PRODUCTION.
 *
 * Cette suite ne clique donc JAMAIS le bouton de deploiement. Qu'il declenche
 * immediatement se LIT dans son attribut `onclick` : un portail qui agit au clic
 * ne se teste pas en cliquant. Lecon payee au sous-lot S7a, ou deux vrais scans
 * ont demarre parce que le garde-fou reposait sur une premisse fausse.
 *
 * CE QUE K1 MESURE ET QUI EST DEJA FAUX SUR LE LEGACY.
 *
 *  1. **`:count` s'affiche en clair.** Le gabarit ecrit `count($machines)` PUIS
 *     `t('ssh.servers_available')`, dont la valeur est « :count serveur(s)
 *     disponible(s) ». Le jeton n'est jamais substitue : l'ecran porte
 *     « 3 :count serveur(s) disponible(s) ». Aucune suite ne le voyait —
 *     `go-socle-i18n` cherche des identifiants de la forme `module.cle`, pas des
 *     jetons `:xxx`.
 *  2. **L'en-tete du fichier annonce une garde qu'il n'applique pas.** Il dit
 *     « Acces refuse pour les utilisateurs standards (role_id = 1) » ; la garde
 *     reelle est `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` +
 *     `checkPermission('can_deploy_keys')`. Meme nature que E-36.
 *
 * CE QUI N'EST PAS MESURABLE, ET POURQUOI ON LE DIT PLUTOT QUE DE L'INVENTER.
 *
 * `$allTags` interroge `machine_tags` **sans aucun cloisonnement**, la ou
 * `$allEnvs` est derive de la liste DEJA filtree — deux lignes adjacentes, une
 * cloisonnee, l'autre pas. Un role 1 verrait donc le vocabulaire de tags de tout
 * le parc. Mesure du jour : **aucun compte de role 1 ne porte `can_deploy_keys`**
 * (seuls `superadmin` et `rw-test-admin`), donc aucun role 1 ne peut ouvrir cette
 * page et la fuite n'est pas exercable. Meme limite que D-5. Modifier des droits
 * pour se satisfaire ne mesurerait plus l'application reelle.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-page-ssh-parc.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/cles-ssh' : '/ssh/';

const SECRET_ADMIN = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';
const SECRET_USER = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW';

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

// ── Ce que la base dit du parc visible, et avec quoi tout sera croise ────────
const MACHINES_VISIBLES = compteEnBase(
    "SELECT COUNT(*) FROM rootwarden.machines "
    + "WHERE lifecycle_status IS NULL OR lifecycle_status <> 'archived'");
const NOMS = litEnBase(
    "SELECT name FROM rootwarden.machines "
    + "WHERE lifecycle_status IS NULL OR lifecycle_status <> 'archived' ORDER BY name");
const TAGS_DU_PARC = litEnBase('SELECT DISTINCT tag FROM rootwarden.machine_tags ORDER BY tag');
const ROLE1_AVEC_DEPLOY = compteEnBase(
    'SELECT COUNT(*) FROM rootwarden.users u JOIN rootwarden.permissions p ON p.user_id = u.id '
    + 'WHERE u.active = 1 AND u.role_id = 1 AND p.can_deploy_keys = 1');

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});

async function connecte(nom, secret) {
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

/** L'etat de la liste : lignes, cases cochees, cases VISIBLES. */
function etatListe(page) {
    return page.evaluate(() => {
        // `.machine-item` SEUL, et pas un prefixe `data-rw^="machine-"` : ce
        // prefixe attrapait aussi un `data-rw="machine-nom"` pose plus tard dans
        // le portage, et la liste comptait six lignes pour trois machines. Un
        // selecteur par prefixe finit toujours par attraper autre chose ; les deux
        // portails portent la meme classe, elle suffit.
        const lignes = [...document.querySelectorAll('.machine-item')];
        const cases = [...document.querySelectorAll('input[name="selected_machines[]"]')];
        return {
            lignes: lignes.length,
            visibles: lignes.filter((l) => l.offsetParent !== null).length,
            cases: cases.length,
            cochees: cases.filter((c) => c.checked).length,
            cocheesVisibles: cases.filter((c) => c.checked && c.offsetParent !== null).length,
            noms: lignes.map((l) => l.innerText.replace(/\s+/g, ' ').trim().split(' ')[0]),
        };
    });
}

try {
    constate('cible', `${CIBLE} — ${PAGE}`);
    constate('parc visible en base',
        `${MACHINES_VISIBLES} machine(s) : ${NOMS.join(', ')} · tags : ${TAGS_DU_PARC.join(', ') || 'aucun'}`);
    verifie('le parc porte de quoi mesurer la page',
        MACHINES_VISIBLES > 0 && NOMS.length === MACHINES_VISIBLES,
        `${MACHINES_VISIBLES} machine(s), ${NOMS.length} nom(s)`);

    // ── Un role 1 SANS la permission est refuse ─────────────────────────────
    const u = await connecte('rw-test-user', SECRET_USER);
    const refus = await u.page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    constate('role 1 sans can_deploy_keys', `statut ${refus?.status()}`);
    verifie('un role 1 sans can_deploy_keys est refuse par un 403 EXACT',
        (refus?.status() ?? 0) === 403, `statut ${refus?.status()}`);
    await u.ctx.close();
    await dors((resteFenetre() + 1) * 1000);

    // ── Un role 2 qui la porte voit la page et TOUT le parc ─────────────────
    const { ctx, page } = await connecte('rw-test-admin', SECRET_ADMIN);
    const erreursJs = [];
    page.on('pageerror', e => erreursJs.push(String(e).split('\n')[0]));

    const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page est servie a un role 2 portant can_deploy_keys',
        (rep?.status() ?? 0) === 200, `statut ${rep?.status()}`);
    await dors(1200);

    const liste = await etatListe(page);
    constate('liste rendue', `${liste.lignes} ligne(s), ${liste.cases} case(s), `
        + `${liste.cochees} cochee(s)`);
    verifie('un role 2 voit TOUTES les machines non archivees',
        liste.lignes === MACHINES_VISIBLES,
        `${liste.lignes} ligne(s) pour ${MACHINES_VISIBLES} machine(s) en base`);
    // FAIL-CLOSED : sans `liste.lignes > 0`, l'assertion reussissait sur 0 ligne et
    // 0 case — vraie parce que l'ensemble mesure etait VIDE, donc mesurant rien.
    verifie('chaque ligne porte une case a cocher, et aucune n\'est cochee d\'avance',
        liste.lignes > 0 && liste.cases === liste.lignes && liste.cochees === 0,
        `${liste.lignes} ligne(s), ${liste.cases} case(s), ${liste.cochees} cochee(s)`);

    // ── LE BOUTON A L'ARRIVEE, AVANT TOUTE SELECTION ────────────────────────
    // Mesure PRISE ICI et pas plus loin : des qu'une machine est cochee le bouton
    // s'active legitimement, et l'assertion ne dirait plus rien de son etat
    // INITIAL. Un bouton de deploiement actif sans selection part vers le backend
    // pour rien — c'est ce que fait le legacy.
    const boutonInitial = await page.evaluate(() => {
        const b = document.getElementById('deploy-btn')
            || document.querySelector('[data-rw="ssh-deployer"]');
        return b ? { present: true, desactive: b.disabled === true } : { present: false };
    });
    constate('bouton de deploiement a l\'arrivee', boutonInitial.present
        ? `desactive=${boutonInitial.desactive}` : 'absent');
    verifiePortage('le bouton de deploiement nait DESACTIVE, faute de selection',
        boutonInitial.present && boutonInitial.desactive,
        'il est actif des l\'arrivee, sans qu\'aucune machine soit cochee');

    // ── LE COMPTEUR : `:count` s'affiche-t-il en clair ? ────────────────────
    const compteur = await page.evaluate(() => {
        const t = document.body.innerText;
        const m = /(\d+)\s*(:count)?\s*serveur|server/i.exec(t);
        return {
            jetonsBruts: (t.match(/:[a-z_]{3,}/g) || []).filter((j) => j !== ':count' ? true : true),
            porteCount: /:count/.test(t),
            extrait: (m ? t.slice(Math.max(0, m.index - 10), m.index + 60) : '').replace(/\s+/g, ' '),
        };
    });
    constate('extrait autour du compteur', `« ${compteur.extrait} »`);
    constate('jetons de substitution visibles a l\'ecran',
        compteur.jetonsBruts.join(', ') || 'aucun');
    // Le `liste.lignes > 0` n'est pas decoratif : sur une page absente, le corps ne
    // contient aucun jeton et l'assertion passait sans que la page existe.
    verifiePortage('aucun jeton de substitution ne s\'affiche en clair',
        liste.lignes > 0 && compteur.porteCount === false,
        'l\'ecran porte « :count » : le gabarit ecrit `count($machines)` PUIS '
        + '`t(\'ssh.servers_available\')`, dont la valeur est « :count serveur(s) '
        + 'disponible(s) » — le jeton n\'est jamais substitue');

    // ── Les filtres ────────────────────────────────────────────────────────
    const filtres = await page.evaluate(() => {
        const tag = document.getElementById('filter-tag');
        const env = document.getElementById('filter-env');
        const val = (s) => s ? [...s.options].map((o) => o.value).filter(Boolean) : null;
        return { tags: val(tag), envs: val(env) };
    });
    constate('options du filtre de tags', filtres.tags ? filtres.tags.join(', ') || 'aucune' : 'filtre absent');
    constate('options du filtre d\'environnements',
        filtres.envs ? filtres.envs.join(', ') || 'aucune' : 'filtre absent');
    verifie('le filtre de tags propose exactement le vocabulaire du parc',
        Array.isArray(filtres.tags)
            && filtres.tags.slice().sort().join('|') === TAGS_DU_PARC.slice().sort().join('|'),
        `${JSON.stringify(filtres.tags)} contre ${JSON.stringify(TAGS_DU_PARC)}`);

    // Filtrer par un tag reel doit reduire la liste VISIBLE — et le nombre de
    // lignes du document, lui, ne change pas : c'est un masquage, pas un re-rendu.
    if (TAGS_DU_PARC.length) {
        const attendu = compteEnBase(
            'SELECT COUNT(DISTINCT m.id) FROM rootwarden.machines m '
            + 'JOIN rootwarden.machine_tags t ON t.machine_id = m.id '
            + `WHERE t.tag = '${TAGS_DU_PARC[0].replace(/'/g, "''")}' `
            + "AND (m.lifecycle_status IS NULL OR m.lifecycle_status <> 'archived')");
        await page.select('#filter-tag', TAGS_DU_PARC[0]);
        await dors(600);
        const apres = await etatListe(page);
        constate(`apres filtrage sur « ${TAGS_DU_PARC[0]} »`,
            `${apres.visibles} ligne(s) visible(s) sur ${apres.lignes}`);
        verifie('filtrer par tag ne laisse visibles que les machines qui le portent',
            apres.visibles === attendu, `${apres.visibles} visible(s) pour ${attendu} en base`);

        // « Cocher le filtre » ne doit cocher QUE ce qui est visible.
        await page.evaluate(() => {
            const b = [...document.querySelectorAll('button')]
                .find((x) => /filtr|filtered/i.test(x.textContent));
            b?.click();
        });
        await dors(500);
        const coche = await etatListe(page);
        constate('apres « cocher le filtre »',
            `${coche.cochees} cochee(s), dont ${coche.cocheesVisibles} visible(s)`);
        verifie('« cocher le filtre » ne coche QUE les machines visibles',
            coche.cochees === attendu && coche.cocheesVisibles === attendu,
            `${coche.cochees} cochee(s) pour ${attendu} visible(s)`);
    }

    // ── LE BOUTON DE DEPLOIEMENT : on le LIT, on ne le clique JAMAIS ────────
    const bouton = await page.evaluate(() => {
        const b = document.getElementById('deploy-btn')
            || document.querySelector('[data-rw="ssh-deployer"]');
        if (!b) return { present: false };
        return {
            present: true,
            desactive: b.disabled === true,
            onclick: String(b.getAttribute('onclick') || ''),
            panneau: document.getElementById('deploy-panneau') !== null,
        };
    });
    constate('bouton de deploiement', bouton.present
        ? `desactive=${bouton.desactive}, onclick « ${bouton.onclick.slice(0, 24) }», `
          + `panneau de decision : ${bouton.panneau}`
        : 'absent');
    verifie('le deploiement est offert', bouton.present, bouton.present ? 'present' : 'absent');
    constate('deploiement declenche',
        'NON, et il ne le sera pas : `configure_servers.py` ecrit sur CHAQUE machine '
        + 'selectionnee, en root — installation de paquet, creation de comptes, '
        + 'ecrasement ET REVOCATION d\'authorized_keys. srv-zabbix est en PRODUCTION.');
    verifiePortage('le deploiement est precede d\'une decision, pas declenche au clic',
        bouton.present && bouton.panneau,
        `aucun panneau : \`onclick="${bouton.onclick.slice(0, 20)}"\` appelle la cascade `
        + 'directement, sans confirmation d\'aucune sorte — mesure prise SANS cliquer');

    // ── Ce qui n'est pas mesurable, et on le DIT ────────────────────────────
    constate('cloisonnement du vocabulaire de tags',
        `NON MESURABLE : ${ROLE1_AVEC_DEPLOY} compte de role 1 porte can_deploy_keys, `
        + 'donc aucun role 1 ne peut ouvrir cette page. `$allTags` interroge pourtant '
        + '`machine_tags` sans filtre, la ou `$allEnvs` derive de la liste deja '
        + 'cloisonnee. Meme limite que D-5.');
    verifie('l\'absence de compte de role 1 habilite est bien la cause, et elle est verifiee',
        ROLE1_AVEC_DEPLOY === 0, `${ROLE1_AVEC_DEPLOY} compte(s)`);

    verifie('aucune erreur JS pendant toute la sequence', erreursJs.length === 0,
        erreursJs.slice(0, 3).join(' · ') || 'aucune');
    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
}

console.log(lignes.join('\n'));
console.log(`\n${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
