/**
 * go-page-update-u1.mjs - Module `update/`, sous-lot U1 : parc et filtres.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/update/
 *   laravel  http://localhost:8444/mises-a-jour
 *
 * PERIMETRE U1 — LECTURE SEULE. Le tableau du parc, ses filtres, son
 * rafraichissement, et les trois relevés par machine (version Linux, statut,
 * dernier redemarrage). Les mises a jour, la planification et le redemarrage
 * appartiennent a U3..U6 : ce test n'y touche pas, et le decoupage est dans
 * `docs/migration/MODULE-UPDATE.md`.
 *
 * CE QUE LE TEST CHERCHE : le rafraichissement de la liste PERD des colonnes.
 * `populateMachineTable()` lit `maj_secu_date`, `maj_secu_last_exec_date` et
 * `last_reboot` ; `update/functions/list_machines.php` ne les SELECTionne pas.
 * Rafraichir remplace donc trois colonnes renseignees par « N/A », sans qu'on
 * l'ait demande et sans rien annoncer.
 *
 * MACHINE 1 EN PRODUCTION : jamais selectionnee. Les relevés par machine
 * ouvrent une session SSH — ils sont sans effet, mais ils touchent la machine.
 *
 * Usage :
 *   cd tests/e2e
 *   node go-page-update-u1.mjs                                   (Laravel)
 *   E2E_BASE=https://localhost:8443 node go-page-update-u1.mjs   (legacy)
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { constateArchivage, verifieMenuLegacy } from './archive.mjs';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/mises-a-jour' : '/update/';

const COMPTES = {
    'rw-test-user':  { role: 1, secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW', attendu: 'refuse' },
    // Role 2 AVEC can_update_linux : autorise.
    'rw-test-admin': { role: 2, secret: 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX', attendu: 'autorise' },
    'rw-test-super': { role: 3, secret: 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW', attendu: 'autorise' },
};

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

let echecs = 0;
const lignes = [];
function verifie(libelle, ok, detail, __quatrieme) {
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

    lignes.push(`${ok ? 'PASS' : 'FAIL'}  ${libelle}${detail ? '  — ' + detail : ''}`);
    if (!ok) echecs++;
}
function constate(l, v) { lignes.push(`INFO  ${l} : ${v}`); }

function verifiePortage(libelle, ok, detail, __quatrieme) {
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

    if (CIBLE === 'laravel') return verifie(libelle, ok, detail);
    constate(libelle, `non exigible du legacy — ${detail}`);
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

/**
 * Etat du tableau tel qu'il est RENDU.
 *
 * Les colonnes sont lues par leur CLASSE (`linux-version`, `maj-secu-date`...),
 * comme le legacy les pose. Le portage garde ces classes : c'est ce qui permet
 * a un seul test de viser les deux cibles.
 */
async function releve(page) {
    return page.evaluate(() => {
        const corps = document.getElementById('server-table-body');
        const lignes = corps ? [...corps.querySelectorAll('tr')] : [];
        const t = (el) => (el?.textContent || '').trim();
        const parLigne = (tr) => ({
            id: tr.getAttribute('data-machine-id'),
            nom: t(tr.querySelector('.server-name')),
            version: t(tr.querySelector('.linux-version')),
            controle: t(tr.querySelector('.last-checked')),
            statut: t(tr.querySelector('.online-status')),
            majSecu: t(tr.querySelector('.maj-secu-date')),
            majSecuExec: t(tr.querySelector('.maj-secu-lastexec-date')),
            redemarrage: t(tr.querySelector('.last-reboot')),
            environnement: t(tr.querySelector('.environment')),
            criticite: t(tr.querySelector('.criticality')),
            reseau: t(tr.querySelector('.network-type')),
        });
        return {
            titre: t(document.querySelector('h1')),
            colonnes: [...document.querySelectorAll('thead th')].length,
            filtres: {
                environnement: Boolean(document.getElementById('environment')),
                criticite: Boolean(document.getElementById('criticality')),
                reseau: Boolean(document.getElementById('network-type')),
                etiquette: Boolean(document.getElementById('tag-filter')),
            },
            etiquettes: [...(document.getElementById('tag-filter')?.options || [])]
                .map(o => o.value).filter(Boolean),
            nbLignes: lignes.length,
            machines: lignes.map(parLigne),
            texteEntier: document.body.innerText,
        };
    });
}

async function attendJusqua(page, predicat, maxMs = 25000) {
    const limite = Date.now() + maxMs;
    let dernier = await releve(page);
    while (Date.now() < limite && ! predicat(dernier)) {
        await dors(350);
        dernier = await releve(page);
    }
    return dernier;
}

/** Colonnes renseignees, c'est-a-dire ni vides ni « N/A » ni « non verifie ». */
function renseignee(valeur) {
    const v = (valeur || '').trim();
    return v !== '' && !/^N\/A$/i.test(v) && !/non v[ée]rifi|not check/i.test(v);
}

/*
 * ══ LA FIXTURE D'ETIQUETTE, ET POURQUOI ELLE EST DEVENUE NECESSAIRE ═════════
 *
 * Cette suite lisait le vocabulaire d'etiquettes DU PARC et n'exercait le filtre
 * que s'il en trouvait un. Le fichier le disait et le CONSTATAIT au lieu
 * d'echouer — honnete, mais sa reference encodait alors un etat du banc.
 *
 * Le 2026-08-26 l'etiquette `banc-essai`, posee A LA MAIN des mois plus tot et
 * maintenue par aucune suite, a disparu. TROIS suites en dependaient sans le
 * savoir : `go-page-ssh-parc` a echoue en accusant la page, `ssh-preflight` a
 * perdu deux assertions, et celle-ci en a perdu UNE en silence — 18 -> 17, zero
 * FAIL. Un ecart a zero FAIL est justement le motif « une assertion a cesse de
 * s'executer », et il est passe inapercu un rejeu entier.
 *
 * La suite pose donc son etiquette elle-meme et la reprend dans un `finally` : le
 * filtre est mesure TOUJOURS, y compris sur un banc remis a zero.
 *
 * Bornee par son NOM — un `DELETE FROM machine_tags` emporterait les etiquettes
 * reelles. Posee sur la machine 2 : nommer une machine dans une table n'est pas
 * la joindre, aucune requete ne part vers elle.
 */
const ETIQUETTE_EPREUVE = 'epreuve-u1';
const MACHINE_EPREUVE = 2;

const compteEtiquetteEpreuve = () => compteEnBase(
    `SELECT COUNT(*) FROM rootwarden.machine_tags WHERE tag = '${ETIQUETTE_EPREUVE}'`);
const compteEtiquettes = () => compteEnBase('SELECT COUNT(*) FROM rootwarden.machine_tags');
const retireEtiquetteEpreuve = () => litEnBase(
    `DELETE FROM rootwarden.machine_tags WHERE tag = '${ETIQUETTE_EPREUVE}'`);

const etiquettesAuDepart = compteEtiquettes();
retireEtiquetteEpreuve();
litEnBase('INSERT INTO rootwarden.machine_tags (machine_id, tag) VALUES '
    + `(${MACHINE_EPREUVE}, '${ETIQUETTE_EPREUVE}')`);

try {
    /*
     * MODULE ARCHIVE ? Cote legacy, `update/` a ete porte en sept sous-lots puis
     * deplace dans `legacy/_deprecated/`. Ses URL rendent 404 : ce n'est pas un
     * echec, c'est l'aboutissement du portage. Le test le CONSTATE — et verifie
     * surtout que le menu du legacy mene desormais au portage, sans quoi on aurait
     * installe soi-meme un 404 dans un menu.
     *
     * Tant que le module est servi, ce bloc est inerte et la suite se joue.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE,
            chemin: '/update/',
            fichiers: [
            '/update/index.php',
            '/update/js/apiCalls.js',
            '/update/js/domManipulation.js',
            '/update/functions/list_machines.php',
            '/update/functions/filter_servers.php',
            ],
            verifie, constate,
        });
        if (archivee) {
            const { ctx, page } = await connecte('rw-test-admin');
            await verifieMenuLegacy(page, '/mises-a-jour', verifie, constate);
            await ctx.close();
            /*
             * ⚠ REPRENDRE LA FIXTURE ICI, PARCE QUE `process.exit()` NE JOUE PAS
             * LE `finally`.
             *
             * Cette branche sort par `process.exit()` quelques lignes plus bas.
             * Une fixture reprise seulement dans le `finally` FUIRAIT donc a
             * chaque passage sur le versant legacy — et une etiquette restee au
             * parc fausse ensuite toutes les suites qui en comptent, dont
             * `go-adm-etiquettes-notes` et `go-page-ssh-parc`.
             *
             * Mesure du 2026-08-26 : la fuite a eu lieu pour de vrai, `epreuve-u1`
             * s'est retrouvee en base apres une execution interrompue. Le `DELETE`
             * est idempotent, donc le repeter ici est sans risque.
             *
             * C'est la regle du §8 sur l'archivage prise EN SENS INVERSE : le
             * constat se greffe en tete du `try` parce que `process.exit()` ignore
             * le `finally` ; pour la meme raison, une fixture posee avant le `try`
             * a besoin d'une reprise avant CHAQUE sortie.
             */
            try { retireEtiquetteEpreuve(); } catch { /* rien */ }
            const resteArchive = compteEtiquetteEpreuve();
            lignes.push(`${resteArchive === 0 ? 'PASS' : 'FAIL'}`
                + `  aucune etiquette d'epreuve ne subsiste  — ${resteArchive}`);
            if (resteArchive !== 0) echecs++;
            console.log(lignes.join('\n'));
            console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL — module archive`);
            await navigateur.close();
            process.exit(echecs > 0 ? 1 : 0);
        }
    }

    // ── La garde reelle, avec les trois comptes ─────────────────────────────
    for (const [nom, compte] of Object.entries(COMPTES)) {
        const { ctx, page } = await connecte(nom);
        const rep = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
        const statut = rep?.status() ?? 0;
        const affichee = statut === 200
            && ! /connexion|login\.php/i.test(page.url())
            && await page.evaluate(() => Boolean(document.getElementById('server-table-body')));

        verifie(`${nom} (role ${compte.role}) : ${compte.attendu === 'autorise' ? "la page s'affiche" : 'la page est refusee'}`,
                compte.attendu === 'autorise' ? affichee : ! affichee,
                `statut=${statut} url=${page.url().replace(BASE, '')}`);
        await ctx.close();
        await dors(1200);
    }

    /*
     * LE CLOISONNEMENT DU ROLE 1 N'EST PAS EXERCABLE. La page admet le role 1
     * s'il porte `can_update_linux`, et ne lui montre alors que les machines de
     * `user_machine_access`. Aucun compte de test ne cumule les deux, et en
     * fabriquer un reviendrait a changer des droits.
     */
    constate('cloisonnement du role 1',
             'non exercable — aucun compte de test ne cumule role 1 et can_update_linux');

    // ── Le contenu, avec le compte ROLE 2 ───────────────────────────────────
    await dors((resteFenetre() + 1) * 1000);
    const { ctx, page } = await connecte('rw-test-admin');
    await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    await attendJusqua(page, (e) => e.nbLignes > 0);

    const depart = await releve(page);

    verifie('la page porte un titre', depart.titre.length > 0, depart.titre);
    verifie('le tableau a treize colonnes', depart.colonnes === 13, `${depart.colonnes}`);
    verifie('les trois filtres sont presents',
            depart.filtres.environnement && depart.filtres.criticite && depart.filtres.reseau,
            JSON.stringify(depart.filtres));
    verifie('aucune cle de traduction morte a l\'ecran',
            ! /\b(updates|upd|nav|auth|accueil|profil|passerelle)\.[a-z_]{3,}\b/.test(depart.texteEntier));

    constate('machines listees', depart.machines.map(m => m.nom).join(', ') || 'aucune');
    verifie('le parc est liste', depart.nbLignes > 0, `${depart.nbLignes} machine(s)`);

    // Les colonnes qui viennent de la base doivent etre renseignees au depart.
    constate('environnements', depart.machines.map(m => m.environnement).join(', '));
    constate('criticites', depart.machines.map(m => m.criticite).join(', '));
    verifie('environnement et criticite sont renseignes au chargement',
            depart.machines.every(m => m.environnement && m.criticite),
            depart.machines.map(m => `${m.nom}:${m.environnement}/${m.criticite}`).join(' · '));

    // ── LE FILTRE REDUIT, ET NE MENT PAS ────────────────────────────────────
    const envPresents = [...new Set(depart.machines.map(m => m.environnement).filter(Boolean))];
    constate('environnements distincts au parc', envPresents.join(', ') || 'aucun');

    if (envPresents.length > 1) {
        const cible = envPresents[0];
        await page.select('#environment', cible);
        await page.evaluate(() => {
            const b = [...document.querySelectorAll('button')].find(x => /filtr/i.test(x.textContent));
            if (b) b.click();
        });
        const filtre = await attendJusqua(page, (e) => e.nbLignes < depart.nbLignes || e.nbLignes === 0);

        constate(`apres filtre « ${cible} »`, `${filtre.nbLignes} ligne(s)`);

        /*
         * D'ABORD : le tableau est REPEUPLE. `[].every()` rend `true`, donc
         * l'assertion suivante passerait sur un tableau VIDE — c'est-a-dire
         * exactement sur la regression que `go-update-filter.mjs` gardait
         * (mauvaise cle JSON, `forEach` sur `undefined`, tableau jamais
         * regarni). L'environnement vise vient du parc reel : au moins une
         * machine le porte.
         */
        verifie(`le filtre « ${cible} » repeuple le tableau`,
                filtre.nbLignes > 0,
                `${filtre.nbLignes} ligne(s) pour un environnement porte par le parc`);

        verifie(`le filtre « ${cible} » ne garde que cet environnement`,
                filtre.machines.length > 0 && filtre.machines.every(m => m.environnement === cible),
                filtre.machines.map(m => m.environnement).join(', ') || 'aucune ligne');
    } else {
        constate('filtre par environnement',
                 `non discriminant — les ${depart.nbLignes} machines partagent « ${envPresents[0] || '?'} »`);
    }

    /*
     * ── LE FILTRE PAR ETIQUETTE ────────────────────────────────────────────
     *
     * Les etiquettes sont ecrites par le module `adm/`, non porte : cette page
     * ne fait que les lire, et AUCUNE route backend ne permet d'en poser. La
     * fixture est donc directement en base — voir MODULE-UPDATE.md pour la
     * recreer. Sans etiquette au parc, le filtre existe mais n'a rien a
     * filtrer : le test le CONSTATE au lieu d'echouer.
     */
    verifie('le filtre par etiquette est present', depart.filtres.etiquette);
    constate('etiquettes proposees', depart.etiquettes.join(', ') || 'aucune');

    /*
     * L'ETIQUETTE VISEE EST CELLE DE LA FIXTURE, pas « la premiere du parc ».
     * Prendre `depart.etiquettes[0]` faisait dependre l'assertion de l'ordre des
     * options et du contenu du banc : une etiquette reelle posee sur plusieurs
     * machines aurait rendu le filtre non discriminant, et l'assertion aurait
     * accuse la page pour un etat des donnees.
     */
    verifie('le filtre propose l\'etiquette de la fixture',
            depart.etiquettes.includes(ETIQUETTE_EPREUVE),
            depart.etiquettes.join(', ') || 'aucune');

    if (depart.etiquettes.includes(ETIQUETTE_EPREUVE)) {
        const etiquette = ETIQUETTE_EPREUVE;

        /*
         * REMETTRE LES AUTRES FILTRES A ZERO D'ABORD.
         *
         * Le premier jet enchainait sur le filtre par environnement reste
         * actif : « 3 -> 2 » passait, mais les deux lignes rendues etaient
         * celles de l'environnement, pas de l'etiquette. Une assertion qui
         * mesure la combinaison de deux filtres ne dit rien du second.
         */
        await page.select('#environment', '');
        await page.select('#criticality', '');
        await page.select('#network-type', '');
        await page.evaluate(() => {
            const b = [...document.querySelectorAll('button')].find(x => /filtr/i.test(x.textContent));
            if (b) b.click();
        });

        /*
         * REPARTIR D'UN ETAT CONNU. Le filtre precedent laissait deux lignes a
         * l'ecran ; l'attente « le nombre de lignes a change » etait donc DEJA
         * VRAIE et rendait la main sur un ecran perime — le test lisait le
         * resultat de l'environnement en croyant lire celui de l'etiquette.
         */
        await attendJusqua(page, (e) => e.nbLignes === depart.nbLignes);

        await page.select('#tag-filter', etiquette);
        await page.evaluate(() => {
            const b = [...document.querySelectorAll('button')].find(x => /filtr/i.test(x.textContent));
            if (b) b.click();
        });
        const parEtiquette = await attendJusqua(page, (e) => e.nbLignes !== depart.nbLignes);

        constate(`apres filtre « ${etiquette} »`,
                 `${parEtiquette.nbLignes} ligne(s) : ${parEtiquette.machines.map(m => m.nom).join(', ') || 'aucune'}`);

        /*
         * L'etiquette de la fixture n'est posee que sur `Test-Server-Debian`.
         * Compter les lignes ne suffit donc pas : on exige que le resultat soit
         * EXACTEMENT cette machine. Sans cela, un filtre qui ne s'applique pas
         * mais laisse un autre filtre actif passerait pour un succes.
         */
        verifie(`le filtre « ${etiquette} » ne garde que les machines etiquetees`,
                parEtiquette.nbLignes > 0
                && parEtiquette.nbLignes < depart.nbLignes
                && parEtiquette.machines.every(m => /Test-Server-Debian/i.test(m.nom)),
                `${depart.nbLignes} -> ${parEtiquette.nbLignes} : `
                + (parEtiquette.machines.map(m => m.nom).join(', ') || 'aucune'));

        // Remettre le parc entier avant la suite : la mesure du
        // rafraichissement compare des colonnes, pas un sous-ensemble.
        await page.select('#tag-filter', '');
        await page.evaluate(() => {
            const b = [...document.querySelectorAll('button')].find(x => /filtr/i.test(x.textContent));
            if (b) b.click();
        });
        await attendJusqua(page, (e) => e.nbLignes === depart.nbLignes);
    } else {
        constate('filtre par etiquette',
                 "aucune etiquette au parc — le champ existe, il n'a rien a proposer");
    }

    /*
     * ── LE RAFRAICHISSEMENT PERD-IL DES COLONNES ? ─────────────────────────
     *
     * `populateMachineTable()` lit `maj_secu_date`, `maj_secu_last_exec_date` et
     * `last_reboot`. L'endpoint que le legacy interroge — `list_machines.php` —
     * ne les SELECTionne pas : elles retombent a « N/A ». Le portage passe par
     * `/filter_servers`, qui rend les quatorze colonnes.
     *
     * On mesure ce qui etait renseigne AVANT, et ce qui l'est encore APRES.
     */
    const avantRafraichi = await releve(page);
    const remplies = (etat) => ({
        majSecu: etat.machines.filter(m => renseignee(m.majSecu)).length,
        majSecuExec: etat.machines.filter(m => renseignee(m.majSecuExec)).length,
        redemarrage: etat.machines.filter(m => renseignee(m.redemarrage)).length,
        environnement: etat.machines.filter(m => renseignee(m.environnement)).length,
    });
    const avant = remplies(avantRafraichi);
    constate('colonnes renseignees avant rafraichissement', JSON.stringify(avant));

    const clique = await page.evaluate(() => {
        const b = [...document.querySelectorAll('button')]
            .find(x => /rafra|refresh|actualis/i.test(x.textContent));
        if (b) { b.click(); return b.textContent.trim().slice(0, 40); }
        return null;
    });
    constate('bouton de rafraichissement', clique || 'introuvable');

    if (clique) {
        // Attendre que la liste ait ete RELUE : le tableau est reconstruit, donc
        // ses lignes changent d'identite meme quand leur texte est identique.
        await dors(2500);
        const apres = remplies(await releve(page));
        constate('colonnes renseignees apres rafraichissement', JSON.stringify(apres));

        const perdues = Object.keys(avant).filter(k => apres[k] < avant[k]);
        if (perdues.length) {
            constate('COLONNES PERDUES', perdues.join(', '));
        }

        verifiePortage('le rafraichissement ne perd aucune colonne',
                       perdues.length === 0,
                       perdues.length ? `perdues : ${perdues.join(', ')}` : 'aucune perte');

        // Les quatre colonnes de dates viennent de DEUX sources : le controleur
        // au premier rendu (format MySQL) et `/filter_servers` aux relectures
        // (`isoformat()` cote Python). Sans normalisation, elles changeaient de
        // forme au premier clic. On mesure la FORME, pas la valeur : un `T`
        // entre la date et l'heure suffit a la trahir.
        const formes = await page.evaluate(() => {
            const lu = (classe) => [...document.querySelectorAll('td.' + classe)]
                .map(td => td.textContent.trim())
                .filter(t => /^\d{4}-\d{2}-\d{2}/.test(t));
            return {
                verifie: lu('last-checked'),
                secu: lu('maj-secu-date'),
                exec: lu('maj-secu-lastexec-date'),
                reboot: lu('last-reboot'),
            };
        });
        const horodatages = Object.values(formes).flat();
        constate('horodatages relus apres rafraichissement', String(horodatages.length));
        // `[].every()` rend `true` : asserter d'abord qu'il y en a.
        verifiePortage("aucune date ne change de forme au rafraichissement",
            horodatages.length > 0 && horodatages.every(t => !t.includes('T')),
            horodatages.length
                ? `${horodatages.length} date(s), exemple « ${horodatages[0]} »`
                : 'aucune date rendue — assertion sans objet');

        if (CIBLE === 'legacy' && perdues.length) {
            constate('defaut du legacy',
                     `rafraichir la liste vide ${perdues.join(', ')} — `
                     + 'list_machines.php ne SELECTionne pas ces colonnes');
        }
    }

    // ── Ce que le compteur dit quand la relecture ECHOUE ────────────────────
    // Un tableau vide et un compteur qui annonce des machines retenues sont deux
    // affirmations contradictoires affichees en meme temps — et l'action suivante
    // repond « aucune machine selectionnee », ce que l'ecran contredit. On mesure
    // sur `data-nombre`, pose par le code a cote du libelle : l'assertion ne
    // depend d'aucune traduction.
    if (CIBLE === 'laravel') {
        const nombreDe = () => page.evaluate(() =>
            document.querySelector('[data-rw="compteur-selection"]')?.getAttribute('data-nombre'));

        await page.evaluate(() => {
            const c = document.querySelector('input[name="selected_machines[]"]');
            if (!c) return;
            c.checked = true;
            c.dispatchEvent(new Event('change', { bubbles: true }));
        });
        const avantEchec = await nombreDe();
        verifie('precondition : une machine est retenue', avantEchec === '1',
            `compteur : ${avantEchec}`);

        // Faire echouer la relecture, plutot que d'attendre qu'elle echoue seule.
        await page.setRequestInterception(true);
        const coupe = (req) => {
            if (/filter_servers/.test(req.url())) req.abort('failed').catch(() => {});
            else req.continue().catch(() => {});
        };
        page.on('request', coupe);

        await page.evaluate(() => document.getElementById('refresh-list-btn')?.click()
            ?? [...document.querySelectorAll('button')]
                .find(x => /rafra|refresh|actualis/i.test(x.textContent))?.click());

        // Viser LE CONTENU : le message d'echec dans le tableau. Attendre la
        // stabilite s'arreterait avant, le tableau ne bougeant pas entre-temps.
        const limite = Date.now() + 20000;
        let texte = '';
        while (Date.now() < limite) {
            texte = await page.evaluate(() =>
                document.querySelector('tbody')?.textContent.trim() || '');
            if (/Impossible de relire|could not be re-read|unable/i.test(texte)) break;
            await dors(300);
        }
        page.off('request', coupe);
        await page.setRequestInterception(false);

        verifie("l'echec de relecture vide le tableau et le DIT",
            /Impossible de relire|could not be re-read|unable/i.test(texte),
            `tableau : « ${texte.slice(0, 60)} »`);

        const apresEchec = await nombreDe();
        verifie('le compteur ne survit pas au tableau qu\'il decrivait',
            apresEchec === '0', `compteur : ${apresEchec} apres un tableau vide`);
    }

    await ctx.close();
} catch (e) {
    lignes.push('EXCEPTION ' + String(e).split('\n')[0]);
    echecs++;
} finally {
    /*
     * NETTOYAGE BORNE PAR LE NOM, PUIS RELECTURE POUR PREUVE. Une etiquette qui
     * survivrait changerait le vocabulaire du parc pour les suites suivantes — et
     * c'est exactement le mecanisme qui a fait tomber trois suites ce jour-la.
     */
    try { retireEtiquetteEpreuve(); } catch { /* rien */ }
    const reste = compteEtiquetteEpreuve();
    lignes.push(`${reste === 0 ? 'PASS' : 'FAIL'}  aucune etiquette d'epreuve ne subsiste  — ${reste}`);
    if (reste !== 0) echecs++;
    const total = compteEtiquettes();
    lignes.push(`${total === etiquettesAuDepart ? 'PASS' : 'FAIL'}`
        + `  le vocabulaire d'etiquettes est celui de l'entree`
        + `  — ${etiquettesAuDepart} a l'entree, ${total} a la sortie`);
    if (total !== etiquettesAuDepart) echecs++;
}

console.log(lignes.join('\n'));
console.log(`\ncible=${CIBLE} : ${lignes.filter(l => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
await navigateur.close();
process.exit(echecs > 0 ? 1 : 0);
