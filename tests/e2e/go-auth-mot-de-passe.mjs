/**
 * go-auth-mot-de-passe.mjs - `auth/` sous-lot A2 : le CHANGEMENT DE MOT DE PASSE.
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/profile.php   (formulaire complet)
 *   laravel  http://localhost:8444/profil         (le portage)
 *
 * ══ POURQUOI CE SOUS-LOT ════════════════════════════════════════════════════
 *
 * C'est l'un des DEUX blocages de la v2.0. **Six comptes actifs sur dix** portent
 * `force_password_change = 1`, dont **`superadmin`**. Le portage DETECTE le
 * drapeau (`SecondFacteurController` pose `changement_mot_de_passe_requis`) et
 * `/profil` l'annonce par un bandeau — mais **n'offre aucun formulaire**. Apres
 * une bascule directe, ces comptes ne pourraient jamais satisfaire l'exigence.
 *
 * ══ PILOTEE PAR DES CLICS ═══════════════════════════════════════════════════
 *
 * Convention du projet : on remplit au clavier (`page.type`) et on soumet par un
 * CLIC (`page.click`). Appeler la fonction ne mesure pas que le bouton l'appelle.
 *
 * ══ CE QUE LA MESURE A DEJA ETABLI (MODULE-AUTH §8-1, ferme le 2026-08-23) ═══
 *
 * `users.password_updated_at` porte `ON UPDATE CURRENT_TIMESTAMP`, et
 * `verify.php:159` calcule l'expiration dessus. La clause est effective, MAIS
 * seulement quand la ligne change vraiment : une connexion « propre » ne repousse
 * rien, un ECHEC SUIVI D'UN SUCCES si. La politique d'expiration est desactivee
 * (`PASSWORD_EXPIRY_DAYS` commentee), donc le defaut est **LATENT**.
 *
 * D'ou la propriete que le portage doit tenir : **ecrire `password_updated_at`
 * EXPLICITEMENT**, jamais s'appuyer sur la clause. `profile.php` ne l'ecrit pas —
 * il ecrit en revanche `password_expires_at`, une colonne que **personne ne lit**
 * (0 ligne renseignee, et `verify.php` calcule depuis `password_updated_at`).
 *
 * ══ LA FIXTURE, ET POURQUOI ELLE EST SURE ═══════════════════════════════════
 *
 * Elle change le mot de passe de `rw-test-admin` (arbitrage de l'exploitant). Le
 * hache d'origine, `force_password_change` et les lignes de `password_history`
 * sont SAUVEGARDES, puis RESTAURES dans un `finally`, l'etat rendu etant RELU
 * pour etre prouve — **treize suites dependent de ce compte**, et le runner les
 * joue en SEQUENCE. Ni `rw-test-user` (D-5), ni `opsuser` (compte reel), ni les
 * residus `e2e_test_*`.
 *
 * Usage :
 *   cd tests/e2e
 *   E2E_BASE=https://localhost:8443 node go-auth-mot-de-passe.mjs
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const PAGE = CIBLE === 'laravel' ? '/profil' : '/profile.php';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';
const COMPTE = 'rw-test-admin';
const SECRET = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';
/** Un mot de passe qui satisfait les quatre classes et les 15 caracteres. */
const NOUVEAU = 'Migration-A2-2026!x';

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

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

function etatCompte() {
    const r = litEnBase("SELECT CONCAT(password, '|', force_password_change, '|', "
        + `IFNULL(password_updated_at,'NULL')) FROM rootwarden.users WHERE name = '${COMPTE}'`);
    const [hache, force, maj] = (r[0] || '||').split('|');

    return { hache, force, maj };
}
function lignesHistorique() {
    return compteEnBase(`SELECT COUNT(*) FROM rootwarden.password_history h `
        + `JOIN rootwarden.users u ON u.id = h.user_id WHERE u.name = '${COMPTE}'`);
}
/**
 * LA BORNE D'ENTREE. Le nettoyage supprime ce qui a un identifiant SUPERIEUR :
 * c'est un DELTA, pas une suppression par type — un nettoyage par type
 * emporterait l'historique legitime du compte.
 *
 * Un premier jet employait `DELETE ... JOIN ... ORDER BY ... LIMIT`, que **MySQL
 * refuse** : `DELETE` avec jointure n'accepte ni `ORDER BY` ni `LIMIT`. L'erreur
 * etait levee DANS le `finally` et emportait tout le journal.
 */
function borneHistorique() {
    return compteEnBase('SELECT IFNULL(MAX(id), 0) FROM rootwarden.password_history');
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});

/** Connexion complete, AU CLAVIER ET A LA SOURIS. */
async function connecte(motDePasse) {
    const ctx = await navigateur.createBrowserContext();
    const page = await ctx.newPage();
    page.setDefaultTimeout(40000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e).split('\n')[0]));
    const chemins = CIBLE === 'laravel'
        ? { connexion: '/connexion', cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]' }
        : { connexion: '/auth/login.php', cgu: /terms\.php/, accepte: 'button[name="accept_terms"]' };

    await page.goto(`${BASE}${chemins.connexion}?lang=fr`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', COMPTE, { delay: 8 });
    await page.type('input[name="password"]', motDePasse, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    for (let essai = 0; essai < 2; essai += 1) {
        const champ = await page.$('input[name="2fa_code"]');
        if (! champ) break;
        if (essai > 0) await dors((resteFenetre() + 1) * 1000);
        await champ.click({ clickCount: 3 });
        await champ.type(totp(SECRET), { delay: 8 });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
    }
    if (chemins.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$(chemins.accepte);
        if (b) await b.evaluate((x) => x.click());
        try { await nav; } catch {}
    }

    return { ctx, page, erreursJs };
}

/** Le formulaire de changement : trois champs et un bouton. */
function litFormulaire(page) {
    return page.evaluate(() => ({
        actuel: !! document.querySelector('input[name="current_password"]'),
        nouveau: !! document.querySelector('input[name="new_password"]'),
        confirmation: !! document.querySelector('input[name="confirm_password"]'),
        // Le bouton du formulaire QUI PORTE le champ, pas le premier de la page.
        bouton: (() => {
            const champ = document.querySelector('input[name="new_password"]');
            const form = champ ? champ.closest('form') : null;

            return !! (form && form.querySelector('button[type="submit"], input[type="submit"]'));
        })(),
    }));
}

/**
 * Un essai de changement : on TAPE les trois champs et on CLIQUE. Rend le
 * message affiche apres coup.
 */
async function essaie(page, actuel, nouveau, confirmation) {
    for (const [nom, valeur] of [['current_password', actuel],
        ['new_password', nouveau], ['confirm_password', confirmation]]) {
        const champ = await page.$(`input[name="${nom}"]`);
        if (! champ) { return '(champ absent : ' + nom + ')'; }
        await champ.click({ clickCount: 3 });
        await champ.type(valeur, { delay: 4 });
    }
    /*
     * LE BOUTON DU BON FORMULAIRE, PAS LE PREMIER DE LA PAGE.
     *
     * `profile.php` porte CINQ formulaires, et le premier bouton `submit` de la
     * page appartient a celui du COURRIEL (`:301`). Un premier jet cliquait
     * celui-la : les six « refus » passaient donc pour une mauvaise raison — le
     * message lu n'etait pas le leur, et le mot de passe n'a jamais bouge. La
     * skill du projet le dit d'ailleurs : ne jamais ancrer un test sur « le
     * premier bouton submit ».
     *
     * On remonte donc du CHAMP a son formulaire, et on clique le bouton de CE
     * formulaire.
     */
    const bouton = await page.evaluateHandle(() => {
        const champ = document.querySelector('input[name="new_password"]');
        const form = champ ? champ.closest('form') : null;

        return form ? form.querySelector('button[type="submit"], input[type="submit"]') : null;
    });
    const element = bouton.asElement();
    if (! element) { return '(aucun bouton dans le formulaire du mot de passe)'; }
    const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await element.click();
    try { await nav; } catch { /* certaines soumissions ne naviguent pas */ }
    await dors(300);

    /*
     * LE MESSAGE SE LIT DANS SON BLOC, pas par une classe approchante. Un premier
     * jet acceptait `[class*="text-red"]` et attrapait un compteur valant « 0 » :
     * chaque assertion lisait « 0 » et concluait a un refus, sans rien mesurer.
     */
    return page.evaluate(() => {
        /*
         * LE PORTE-MESSAGES DU FORMULAIRE, PAS UNE CLASSE VOISINE. Le portage
         * affiche AUSSI un bandeau d'exigence en `.rw-erreur`, place AVANT dans
         * le DOM : un selecteur par classe attrapait ce bandeau et les six refus
         * passaient en le lisant, sans jamais voir le vrai message. Le portage
         * porte donc un `data-rw` dedie, et le legacy a son propre bloc.
         */
        /* E-250 : la vue porte DEUX ancres, une par etat. Cette lecture
           prend le message QUEL QU'IL SOIT — elle rend le texte, elle ne
           juge pas — donc il lui faut les deux. */
        const n = document.querySelector(
            '[data-rw="profil-mdp-succes"], [data-rw="profil-mdp-erreur"]')
            || document.querySelector('div[class*="bg-green-50"], div[class*="bg-red-50"]');

        return n ? n.textContent.replace(/\s+/g, ' ').trim().slice(0, 120) : '';
    });
}

const origine = etatCompte();
const historiqueOrigine = lignesHistorique();
const borneEntree = borneHistorique();
let fixturePosee = false;

try {
    constate('cible', `${CIBLE} — ${PAGE}`);
    verifie('la fixture part d\'un compte lisible en base',
        origine.hache !== '' && origine.hache !== undefined,
        origine.hache ? 'hache present' : 'AUCUN hache lu');
    constate('etat a l\'entree',
        `force_password_change=${origine.force} historique=${historiqueOrigine} maj=${origine.maj}`);
    litEnBase('DELETE FROM rootwarden.login_attempts');

    /*
     * LA FIXTURE POSE L'EXIGENCE. On veut mesurer le chemin qui debloque les six
     * comptes : `force_password_change = 1`.
     */
    litEnBase(`UPDATE rootwarden.users SET force_password_change = 1 WHERE name = '${COMPTE}'`);
    fixturePosee = true;
    verifie('la fixture est en place : le compte doit changer son mot de passe',
        etatCompte().force === '1', `force_password_change=${etatCompte().force}`);

    const { ctx, page, erreursJs } = await connecte(MDP);
    constate('apres connexion', page.url().replace(BASE, ''));

    const r = await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
    verifie('la page de profil est servie', r?.status() === 200, `statut ${r?.status()}`);

    /*
     * L'EXIGENCE EST-ELLE ANNONCEE ? Le portage le fait deja par un bandeau ; ce
     * qui manque, c'est le formulaire. On mesure les deux separement : annoncer et
     * pouvoir faire ne sont pas la meme chose.
     */
    const annonce = await page.evaluate(() => {
        const t = document.body.innerText;

        return /changer|change|expir/i.test(t) ? t.match(/[^.\n]*(changer|change|expir)[^.\n]*/i)[0].trim().slice(0, 110) : '';
    });
    constate('ce que la page annonce', annonce || '(rien)');
    verifie('l\'exigence de changement est ANNONCEE', annonce !== '', annonce || 'rien');

    const form = await litFormulaire(page);
    constate('le formulaire', `actuel=${form.actuel} nouveau=${form.nouveau} `
        + `confirmation=${form.confirmation} bouton=${form.bouton}`);
    verifie('un formulaire de changement de mot de passe est OFFERT',
        form.actuel && form.nouveau && form.confirmation && form.bouton,
        `actuel=${form.actuel} nouveau=${form.nouveau} confirmation=${form.confirmation} bouton=${form.bouton}`);

    if (form.actuel && form.nouveau && form.confirmation) {
        /* ── LES REFUS : chaque regle de la politique, une par une ──────────── */
        const refus = [
            ['un mot de passe actuel FAUX', 'MauvaisMotDePasse-1!', NOUVEAU, NOUVEAU],
            ['une confirmation qui ne correspond pas', MDP, NOUVEAU, NOUVEAU + 'z'],
            ['moins de 15 caracteres', MDP, 'Court-1!aZ', 'Court-1!aZ'],
            ['aucune majuscule', MDP, 'migration-a2-2026!x', 'migration-a2-2026!x'],
            ['aucun chiffre', MDP, 'Migration-Aa-abcd!x', 'Migration-Aa-abcd!x'],
            ['aucun caractere special', MDP, 'MigrationA22026xyz', 'MigrationA22026xyz'],
        ];
        for (const [libelle, actuel, nouveau, confirmation] of refus) {
            await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
            const msg = await essaie(page, actuel, nouveau, confirmation);
            constate(`refus attendu — ${libelle}`, msg || '(aucun message — refus par le navigateur)');
            /*
             * ON MESURE LA PROPRIETE, PAS LA FORME DU REFUS. Le portage pose
             * `minlength` sur ses champs : le navigateur refuse d'envoyer un mot
             * de passe trop court, donc le serveur ne voit rien et aucun message
             * n'apparait. Le legacy, lui, n'a pas cet attribut et refuse cote
             * serveur, avec un message.
             *
             * Les deux refusent — differemment. Exiger un message ferait echouer
             * une garde qui agit PLUS TOT. Ce qui compte est que le mot de passe
             * ne soit PAS accepte : ni message de succes, ni hache modifie. La
             * revalidation SERVEUR est prouvee separement, par une requete forgee.
             */
            const accepte = /succ|modifi|updated/i.test(msg);
            const hacheIntact = etatCompte().hache === origine.hache;
            verifie(`refuse : ${libelle}`, ! accepte && hacheIntact,
                accepte ? `ACCEPTE : ${msg}` : (msg || 'refuse par le navigateur, sans requete'));
            verifie(`  et le hache n'a pas change apres ce refus`, hacheIntact,
                hacheIntact ? 'inchange' : 'MODIFIE');
        }

        /*
         * ── LA REVALIDATION SERVEUR, PAR UNE REQUETE FORGEE ─────────────────
         *
         * `minlength` est une commodite du navigateur : un attaquant ne la
         * respecte pas. La seule facon d'exercer la garde SERVEUR est d'emettre la
         * requete sans passer par le formulaire — depuis la PAGE, donc avec la
         * session et le jeton reels. Meme motif qu'en E-86 : une revalidation
         * qu'un `<input>` ne peut pas violer ne se mesure pas par un clic.
         */
        if (CIBLE === 'laravel') {
            const forge = await page.evaluate(async (mdp) => {
                const jeton = document.querySelector('meta[name="csrf-token"]');
                const corps = new URLSearchParams({
                    current_password: mdp,
                    new_password: 'Court-1!aZ',
                    confirm_password: 'Court-1!aZ',
                    _token: jeton ? jeton.content : '',
                }).toString();
                const r = await fetch('/profil/mot-de-passe', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: corps,
                    redirect: 'follow',
                });
                const t = await r.text();

                return { statut: r.status, refuse: /15 caracteres|15 characters/i.test(t) };
            }, MDP);
            constate('requete forgee, mot de passe trop court',
                `statut ${forge.statut} · le serveur refuse=${forge.refuse}`);
            verifie('le SERVEUR refuse aussi un mot de passe trop court, sans le navigateur',
                forge.refuse === true && etatCompte().hache === origine.hache,
                `refus serveur=${forge.refuse}, hache ${etatCompte().hache === origine.hache ? 'inchange' : 'MODIFIE'}`);
        }

        /* ── L'ACCEPTATION, et ce qu'elle doit produire ─────────────────────── */
        const avantMaj = etatCompte().maj;
        const avantHisto = lignesHistorique();
        await dors(1200);
        await page.goto(`${BASE}${PAGE}`, { waitUntil: 'networkidle2' });
        const ok = await essaie(page, MDP, NOUVEAU, NOUVEAU);
        constate('message apres un mot de passe valide', ok || '(aucun)');
        verifie('accepte un mot de passe conforme a la politique',
            /succ|modifi|updated/i.test(ok), ok || 'aucun message');

        const apres = etatCompte();
        verifie('le hache a REELLEMENT change', apres.hache !== origine.hache,
            apres.hache !== origine.hache ? 'nouveau hache' : 'INCHANGE');
        verifie('`force_password_change` est leve', apres.force === '0',
            `force_password_change=${apres.force}`);
        verifie('l\'ANCIEN hache est enregistre dans password_history',
            lignesHistorique() === avantHisto + 1,
            `${avantHisto} -> ${lignesHistorique()} ligne(s)`);
        verifie('`password_updated_at` a avance', apres.maj !== avantMaj,
            `${avantMaj} -> ${apres.maj}`);
        constate('`password_expires_at` apres le changement',
            litEnBase(`SELECT IFNULL(password_expires_at,'NULL') FROM rootwarden.users WHERE name='${COMPTE}'`)[0] || 'NULL');
    }

    verifie('aucune erreur JS pendant la sequence', erreursJs.length === 0,
        erreursJs.join(' | ') || 'aucune');
    await ctx.close();

    /*
     * UNE REUSSITE ANNONCEE N'EST PAS UNE REUSSITE VERIFIEE : on se reconnecte
     * avec le NOUVEAU mot de passe. Si le changement n'avait pas pris, le message
     * de succes aurait menti.
     */
    if (etatCompte().hache !== origine.hache) {
        await dors((resteFenetre() + 2) * 1000);
        litEnBase('DELETE FROM rootwarden.login_attempts');
        const seconde = await connecte(NOUVEAU);
        const entre = ! /login\.php|\/connexion/.test(seconde.page.url());
        constate('connexion avec le NOUVEAU mot de passe', seconde.page.url().replace(BASE, ''));
        verifie('le nouveau mot de passe ouvre bien la session', entre,
            seconde.page.url().replace(BASE, ''));
        await seconde.ctx.close();
    }
} catch (e) {
    verifie('la suite s\'est deroulee sans exception', false, String(e).split('\n')[0]);
} finally {
    /*
     * RESTAURATION, ET ETAT RELU POUR ETRE PROUVE. Treize suites dependent de ce
     * compte : si la restauration echoue, il faut que ca se voie ICI.
     */
    if (origine.hache) {
        litEnBase(`UPDATE rootwarden.users SET password = '${origine.hache}', `
            + `force_password_change = ${origine.force === '1' ? 1 : 0} WHERE name = '${COMPTE}'`);
    }
    /*
     * CHAQUE ETAPE DE NETTOYAGE EST ISOLEE. Une exception dans le `finally`
     * emporte le journal entier : on l'a paye une fois, la suite rendant
     * « 0 PASS / 0 FAIL » sans dire si la restauration avait abouti.
     */
    for (const [libelle, requete] of [
        ['historique', 'DELETE FROM rootwarden.password_history WHERE id > '
            + `${borneEntree} AND user_id = (SELECT id FROM rootwarden.users WHERE name = '${COMPTE}')`],
        ['tentatives', 'DELETE FROM rootwarden.login_attempts'],
    ]) {
        try {
            litEnBase(requete);
        } catch (e) {
            verifie(`le nettoyage « ${libelle} » a abouti`, false, String(e).split('\n')[0].slice(0, 90));
        }
    }
    const rendu = etatCompte();
    verifie('le hache d\'origine du compte est RESTAURE', rendu.hache === origine.hache,
        rendu.hache === origine.hache ? 'identique a l\'entree' : 'DIFFERENT — treize suites en dependent');
    verifie('l\'historique est rendu a son compte d\'entree',
        lignesHistorique() === historiqueOrigine,
        `${historiqueOrigine} a l'entree, ${lignesHistorique()} en sortie`);
    constate('fixture posee pendant la suite', fixturePosee ? 'oui, et defaite' : 'non');
    await navigateur.close();
    console.log(lignes.join('\n'));
    console.log(`\n${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
    process.exit(echecs === 0 ? 0 : 1);
}
