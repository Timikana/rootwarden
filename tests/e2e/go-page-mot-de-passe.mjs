/**
 * go-page-mot-de-passe.mjs — l'exigence de changement : un verrou, pas un bandeau.
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  SI LE BANC RESTE ENFERME, VOICI LA COMMANDE. Ne cherchez pas plus loin. ║
 * ║                                                                          ║
 * ║      UPDATE rootwarden.users SET force_password_change = 0 WHERE id = 15 ║
 * ║                                                                          ║
 * ║  Cette suite POSE le drapeau sur `rw-test-admin` (id 15) puis le retire.  ║
 * ║  Le `finally` protege contre l'echec du test ; il ne protege PAS contre   ║
 * ║  la mort du processus. Ce qui protege alors est que le prochain sache     ║
 * ║  quoi taper — et ce chantier a deja paye une demi-journee pour un etat    ║
 * ║  residuel dont personne ne connaissait le remede.                        ║
 * ║                                                                          ║
 * ║  Symptome d'un banc enferme : TOUTE page du portage renvoie vers          ║
 * ║  `/profil?force_change=1`, pour ce compte seulement.                     ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * ══ CE QUI SE MESURE : L'ENFERMEMENT, PAS L'EXEMPTION ═════════════════════
 *
 * `ChangementMotDePasseExige` redirige tout compte portant
 * `force_password_change` vers son profil, sauf deux routes exemptees. La
 * question utile n'est pas « la redirection a-t-elle lieu » — elle a lieu,
 * c'est le but — mais **« le compte marque peut-il en SORTIR ? »**
 *
 *     atteindre le formulaire      `GET /profil`            exempte par nom
 *     le soumettre                 `POST /profil/mot-de-passe`  exempte par nom
 *     se deconnecter               `POST /deconnexion`      HORS du groupe
 *
 * *Un garde-fou qui se declenche a tort ne protege plus : il empeche.* Et le
 * chantier en a un precedent — un remede rendu definitivement inerte par la
 * garde censee le proteger.
 *
 * ══ POURQUOI LE FORMULAIRE EST SOUMIS AVEC UN MOT DE PASSE REFUSE ═════════
 *
 * Le soumettre avec un mot de passe VALIDE changerait le secret de
 * `rw-test-admin` — et casserait toutes les suites du LOT, qui s'y connectent.
 * On le soumet donc avec une valeur que la politique refuse.
 *
 * **La propriete mesuree est que la route est ATTEIGNABLE**, pas que le
 * changement aboutit : c'est l'accessibilite qui est en jeu dans un
 * enfermement, jamais le succes du geste. Un refus de politique prouve que le
 * middleware a laisse passer — une redirection vers le profil prouverait le
 * contraire. Les deux se distinguent par l'URL d'arrivee, pas par le message.
 *
 * ══ LE PIEGE DU `GET /deconnexion`, ET POURQUOI ON NE LE CLIQUE PAS ═══════
 *
 * `web.php:71` declare `Route::get('/deconnexion', …)` **sans `->name()`**, et
 * les deux routes de deconnexion vivent HORS du groupe protege. Une liste
 * d'exemptions par NOM aurait couvert le POST et manque le GET.
 *
 * Mais dans le portage **aucun lien ne pointe vers ce GET** : le bandeau porte
 * un `<form method="POST">`. Le clic naturel est donc un POST, et c'est celui
 * qu'on clique. Le GET est un chemin d'entree depuis l'ancien portail : il se
 * mesure par navigation directe, et **c'est dit** plutot que presente comme un
 * clic qu'il n'est pas.
 *
 * ══ CE QUI N'EST PAS ASSERTE, DELIBEREMENT ════════════════════════════════
 *
 * Le **fail-open** du middleware est voulu et journalise : une base injoignable
 * laisse passer, parce que refuser transformerait une panne de lecture en
 * indisponibilite totale pour tous. Ce n'est pas un defaut et rien ici ne le
 * traite comme tel.
 *
 * ══ SURETE ════════════════════════════════════════════════════════════════
 *
 * Cible unique : `rw-test-admin` (id 15). **Jamais `rw-test-user` (id 14)** —
 * lecture seule par consigne. La suite REFUSE de tourner si le drapeau n'est
 * pas a 0 au depart : restaurer un etat qu'on n'a pas cree serait effacer la
 * trace de quelqu'un d'autre.
 */
import puppeteer from 'puppeteer';
import { createHmac } from 'crypto';
import { litEnBase, compteEnBase } from './lib-base.mjs';
import { mkdirSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'http://localhost:8444';
const CIBLE = /8444|laravel/i.test(BASE) ? 'laravel' : 'legacy';
const MDP = process.env.E2E_TEST_PASS || 'RootWarden@2026-Test!';

/* La cible du drapeau. `rw-test-user` (14) est en lecture seule : jamais lui. */
const CIBLE_ID = 15;
const CIBLE_NOM = 'rw-test-admin';
const CIBLE_SECRET = 'KRSXG5BAKBSWY3DPEHPK3PXPKRSXG5BAKBSWY3DPEHPK3PXPKRSX';

const C = CIBLE === 'laravel'
    ? { connexion: '/connexion', profil: '/profil', ailleurs: '/cles-ssh',
        formulaire: '[data-rw="profil-mdp-form"]',
        soumettre: '[data-rw="profil-mdp-enregistrer"]',
        // E-250 : LES DEUX ancres. Cette suite mesure qu'UN message est
        // rendu — jamais lequel — parce que ce qu'elle etablit est que le
        // controleur a ete ATTEINT, pas qu'il a accepte.
        message: '[data-rw="profil-mdp-succes"], [data-rw="profil-mdp-erreur"]',
        deconnexion: 'form[action$="/deconnexion"] button',
        cgu: /\/cgu/, accepte: '[data-rw="cgu-accepter"]' }
    : { connexion: '/auth/login.php?lang=fr', profil: '/profile.php', ailleurs: '/iptables/',
        formulaire: null, soumettre: null, message: null,
        deconnexion: null,
        cgu: /terms\.php/, accepte: 'button[name="accept_terms"]' };

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

function b32(s){const A='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let b='';for(const c of s.replace(/=+$/,''))b+=A.indexOf(c.toUpperCase()).toString(2).padStart(5,'0');const o=[];for(let i=0;i+8<=b.length;i+=8)o.push(parseInt(b.slice(i,i+8),2));return Buffer.from(o)}
function totp(s){const k=b32(s);const c=Math.floor(Date.now()/1000/30);const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(c));const h=createHmac('sha1',k).update(buf).digest();const o=h[h.length-1]&0x0f;return((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0')}
function dors(ms){return new Promise(r=>setTimeout(r,ms))}
function resteFenetre(){return 30 - (Math.floor(Date.now()/1000) % 30)}

function drapeau() {
    return compteEnBase(
        `SELECT COALESCE(force_password_change, 0) FROM rootwarden.users WHERE id = ${CIBLE_ID}`);
}

/* Vrai seulement si NOUS avons pose le drapeau : sinon on ne restaure rien. */
let posePar = false;
/* Vrai si la restauration a echoue : le LOT ne doit alors PAS enchainer. */
let bancEnferme = false;

/*
 * LES REPONSES, PARCE QU'UNE URL D'ARRIVEE NE DIT PAS PAR QUEL CHEMIN ON Y EST.
 *
 * Premiere redaction : j'ai conclu « la soumission atteint la route » de ce que
 * l'URL valait `/profil` sans `force_change=1`. Or **rester sur `/profil` et y
 * etre redirige produisent la MEME URL**. L'assertion etait verte et ne
 * mesurait rien — un observable ne dit jamais par quel chemin il a ete produit.
 * Seul le reseau tranche.
 */
const reponses = [];

const navigateur = await puppeteer.launch({
    headless: 'new',
    args: ['--ignore-certificate-errors', '--allow-insecure-localhost'],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
});
const contextes = [];

async function connecte() {
    try { litEnBase('DELETE FROM rootwarden.login_attempts'); } catch { /* deja vide */ }
    const ctx = await navigateur.createBrowserContext();
    contextes.push(ctx);
    const page = await ctx.newPage();
    page.setDefaultTimeout(45000);
    const erreursJs = [];
    page.on('pageerror', (e) => erreursJs.push(String(e.message || e).split('\n')[0]));
    page.on('response', (r) => reponses.push({
        route: r.url().replace(/^https?:\/\/[^/]+/, ''),
        methode: r.request().method(),
        statut: r.status(),
    }));

    await page.goto(`${BASE}${C.connexion}`, { waitUntil: 'networkidle2' });
    await page.type('input[name="username"]', CIBLE_NOM, { delay: 8 });
    await page.type('input[name="password"]', MDP, { delay: 8 });
    let nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
    await page.click('button[type="submit"]'); try { await nav; } catch {}
    if (resteFenetre() < 6) await dors((resteFenetre() + 1) * 1000);
    for (let essai = 0; essai < 2; essai += 1) {
        const champ = await page.$('input[name="2fa_code"]');
        if (! champ) break;
        if (essai > 0) await dors((resteFenetre() + 1) * 1000);
        await champ.click({ clickCount: 3 });
        await champ.type(totp(CIBLE_SECRET), { delay: 8 });
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click('button[type="submit"]'); try { await nav; } catch {}
    }
    if (C.cgu.test(page.url())) {
        nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        const b = await page.$(C.accepte);
        if (b) { await b.click(); try { await nav; } catch {} }
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

try {
    /*
     * ══ CETTE SUITE NE MESURE QUE LE PORTAGE, ET LE GESTE N'Y PART PAS ═══
     *
     * Le legacy exerce le meme controle (`auth/verify.php:169-183`) mais ses
     * ancres n'ont pas ete relevees : le formulaire et le bouton valent `null`
     * dans la table des selecteurs. Une execution sur cette cible POSERAIT le
     * drapeau puis echouerait a le mesurer — **un geste mutant lance pour
     * rien**, et le risque d'un banc enferme sans meme une mesure en echange.
     *
     * On s'abstient donc AVANT le geste, en disant pourquoi : « je n'ai pas pu
     * mesurer » n'est pas « rien a signaler », et ici cela vaut aussi pour
     * « je n'ai pas touche a la base ».
     */
    if (CIBLE !== 'laravel') {
        constate('cible', 'legacy — SANS OBJET : les ancres du formulaire ne sont pas relevees,'
            + ' et le drapeau N\'A PAS ETE POSE');
        note('\n0 etapes, 0 PASS, 0 FAIL');
        note('=== SANS OBJET ===');
        try { await navigateur.close(); } catch { /* deja ferme */ }
        process.exit(0);
    }

    /*
     * ══ LA PRECONDITION QUI AUTORISE LE GESTE ════════════════════════════
     *
     * Le drapeau DOIT etre a 0 au depart. S'il vaut deja 1, un autre l'a pose
     * — ou une execution precedente est morte — et le remettre a 0 en sortant
     * effacerait un etat qui n'est pas le mien. On s'arrete, et on dit quoi
     * regarder.
     */
    const avant = drapeau();
    constate(`drapeau de ${CIBLE_NOM} (id ${CIBLE_ID}) au depart`, String(avant));
    verifie(`${CIBLE_NOM} ne porte PAS le drapeau au depart`, avant === 0,
        'le drapeau vaut deja 1 — pose par un tiers ou reste d\'une execution morte.'
        + ' La suite ne tourne pas : restaurer un etat qu\'on n\'a pas cree l\'effacerait');
    if (avant !== 0) throw new Error('precondition non tenue, aucun geste pose');

    /*
     * LE GESTE : local a la base du banc, ni sortant ni irreversible. La
     * commande de restauration est en tete de ce fichier, en clair.
     */
    litEnBase(`UPDATE rootwarden.users SET force_password_change = 1 WHERE id = ${CIBLE_ID}`);
    posePar = true;
    const pose = drapeau();
    // ON VERIFIE APRES LE GESTE, on ne croit pas la commande.
    verifie('le drapeau est effectivement pose', pose === 1, `il vaut ${pose}`, 'pose');
    if (pose !== 1) throw new Error('le drapeau n\'a pas ete pose : rien a mesurer');

    const s = await connecte();
    verifie('la session s\'ouvre malgre le drapeau', ! s.surConnexion, s.page.url());
    if (s.surConnexion) throw new Error('session non etablie');
    const page = s.page;

    // ══ 1. L'ENFERMEMENT A LIEU : une route protegee renvoie au profil ═══
    await etape('une route protegee renvoie vers le profil', async () => {
        await page.goto(`${BASE}${C.ailleurs}`, { waitUntil: 'networkidle2' });
        const arrivee = page.url();
        constate('depart', C.ailleurs);
        constate('arrivee', arrivee.replace(BASE, ''));
        // L'URL D'ARRIVEE, jamais le message : deux issues peuvent afficher le
        // meme texte et n'etre pas au meme endroit.
        verifie('le compte marque est renvoye vers son profil',
            /\/profil/.test(arrivee) && /force_change=1/.test(arrivee),
            `arrive sur ${arrivee.replace(BASE, '')} — attendu /profil?force_change=1`);
    });

    // ══ 2. IL PEUT ATTEINDRE LE FORMULAIRE ═══════════════════════════════
    await etape('le formulaire de changement est atteignable', async () => {
        const rep = await page.goto(`${BASE}${C.profil}`, { waitUntil: 'networkidle2' });
        const statut = rep ? rep.status() : 0;
        verifie('le profil repond', statut === 200, `statut ${statut}`);

        const vu = await page.evaluate((sel) => {
            const f = document.querySelector(sel.formulaire);
            const b = document.querySelector(sel.soumettre);

            return {
                formulaire: f !== null,
                // La VISIBILITE, pas la seule presence : un formulaire rendu
                // dans un bloc masque n'offre rien a personne.
                visible: f ? f.offsetParent !== null : false,
                bouton: b !== null,
                champs: f ? f.querySelectorAll('input[type="password"]').length : 0,
            };
        }, C);
        constate('formulaire', vu.formulaire
            ? `present, ${vu.visible ? 'visible' : 'MASQUE'}, ${vu.champs} champ(s), bouton ${vu.bouton ? 'present' : 'absent'}`
            : '(absent)');
        verifie('le formulaire est rendu, visible et complet',
            vu.formulaire && vu.visible && vu.bouton && vu.champs === 3,
            ! vu.formulaire ? 'le formulaire n\'est pas rendu'
                : ! vu.visible ? 'le formulaire est rendu mais masque'
                    : ! vu.bouton ? 'le bouton de soumission est absent'
                        : `${vu.champs} champ(s) de mot de passe — attendu 3`);
    });

    // ══ 3. IL PEUT LE SOUMETTRE — la ROUTE, pas le succes du geste ═══════
    await etape('la route de soumission est atteignable', async () => {
        const champs = await page.$$(`${C.formulaire} input[type="password"]`);
        if (champs.length !== 3) {
            verifie('la soumission atteint la route et n\'est pas redirigee', false,
                `${champs.length} champ(s) trouve(s) : rien a soumettre`);

            return;
        }
        /*
         * ══ IL Y A DEUX GARDES, ET LE PREMIER EST DANS LE NAVIGATEUR ══════
         *
         * Premiere redaction : `new_password = 'court'`, pour que la POLITIQUE
         * SERVEUR refuse. Mesure : **aucun POST n'est jamais parti.** Le
         * diagnostic a nomme la cause — le bouton recevait bien le clic
         * (`elementFromPoint` le confirme, ce n'est donc pas E-241) mais
         * `profil.blade.php` pose `minlength="{{ $longueurMinimale }}"` = 15
         * sur les deux champs neufs. **Le navigateur refusait la soumission
         * avant l'envoi**, et l'URL restait `/profil` — exactement ce que
         * produit une redirection vers `/profil`. D'ou le faux vert initial.
         *
         *     une suite qui veut mesurer un refus SERVEUR doit d'abord
         *     SATISFAIRE le garde CLIENT, sinon elle ne mesure que lui
         *
         * On satisfait donc `minlength` (et la confirmation, pour ne pas
         * echouer sur elle), et l'on fait porter le refus par le **mot de passe
         * courant FAUX** — la seule des trois erreurs qui ne peut en aucun cas
         * modifier le secret du compte.
         */
        await champs[0].type('ce-mot-de-passe-courant-est-faux', { delay: 5 });
        await champs[1].type('Rejet-Volontaire-2026-Banc!', { delay: 5 });
        await champs[2].type('Rejet-Volontaire-2026-Banc!', { delay: 5 });

        // LE GARDE CLIENT EST SATISFAIT — mesure, pas supposition : si le
        // formulaire est invalide, rien ne partira et l'assertion suivante
        // accuserait le middleware a tort.
        const valide = await page.evaluate((sel) => {
            const f = document.querySelector(sel);

            return f === null ? null : f.checkValidity();
        }, C.formulaire);
        verifie('le formulaire satisfait la validation du navigateur',
            valide === true,
            valide === null ? 'formulaire introuvable'
                : 'le navigateur refuse la soumission : le POST ne partira pas, et'
                  + ' l\'absence de requete serait imputee au middleware');

        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await page.click(C.soumettre);
        try { await nav; } catch { /* pas de navigation : on lira l'URL */ }
        const arrivee = page.url().replace(BASE, '');
        constate('arrivee apres soumission', arrivee);

        /*
         * AU RESEAU. Le POST doit avoir ETE EMIS et avoir reçu une reponse :
         * c'est la seule mesure qui distingue « redirige vers /profil » de
         * « jamais parti ». L'URL, elle, vaut `/profil` dans les deux cas.
         */
        const posts = reponses.filter(
            (r) => r.methode === 'POST' && /\/profil\/mot-de-passe$/.test(r.route));
        constate('POST vers la route de changement', posts.length
            ? posts.map((p) => `${p.statut}`).join(', ') : '(AUCUN — la requete n\'est jamais partie)');
        verifie('le POST atteint la route de changement',
            posts.length > 0,
            'aucun POST vers /profil/mot-de-passe n\'a ete emis : le clic n\'a pas soumis'
            + ' le formulaire, ou le navigateur l\'a refuse avant l\'envoi');

        // ET IL N'A PAS ETE INTERCEPTE : un 302 vers le profil AVEC
        // `force_change=1` serait l'enfermement.
        verifie('le POST n\'est pas intercepte par le middleware',
            posts.length > 0 && ! /force_change=1/.test(arrivee),
            posts.length === 0 ? 'aucun POST a examiner'
                : 'le POST a ete INTERCEPTE : le compte marque ne peut pas soumettre');

        /*
         * LE CONTROLEUR A BIEN TRAITE LA REQUETE, ET NON PAS SEULEMENT REPONDU.
         *
         * Arriver sur `/profil` sans `force_change=1` prouve que le middleware
         * n'a pas intercepte. Ça ne prouve pas que `POST /profil/mot-de-passe`
         * a ete ATTEINT : une redirection vers le profil peut venir d'ailleurs.
         * Le message de refus, lui, n'existe que si le controleur a lu les trois
         * champs et applique la politique (`with('mdp_erreur', …)`).
         *
         * `C.message` etait declare et jamais lu — une cle morte dans une table
         * de selecteurs signale presque toujours une mesure absente, pas un
         * oubli de menage.
         */
        const refus = await page.evaluate((sel) => {
            const e = document.querySelector(sel);

            return e === null ? null : (e.innerText || '').trim();
        }, C.message);
        constate('message de refus', refus === null ? '(absent)' : `« ${refus.slice(0, 80)} »`);
        /*
         * CONDITIONNEE AU POST : si la requete n'est pas partie, l'absence de
         * message n'est pas un defaut de l'ecran — il n'y a rien a afficher.
         * Une assertion qui accuserait l'ecran ici viserait le mauvais objet.
         *
         * ⚠ ON MESURE QU'UN MESSAGE EST RENDU, JAMAIS LEQUEL — ET C'EST VOULU
         * ICI. Ce que cette assertion etablit est que le controleur a ete
         * ATTEINT, pas qu'il a accepte : le refus est justement ce qu'on
         * attend. D'ou les DEUX ancres.
         *
         * L'ancre etait AMBIGUE jusqu'a E-250 : `profil.blade.php` portait
         * `profil-mdp-message` sur la confirmation ET sur l'erreur — deux etats
         * opposes sous un nom commun, la classe d'E-244. Elle est dedoublee
         * depuis (`succes` / `erreur`), et cette suite prend les deux DELIBEREMENT.
         * **Une suite qui asserterait une REUSSITE ne le pourrait pas** : voir
         * `go-page-supervision-reglages`, ou le meme dedoublement a fait passer
         * l'assertion du couple d'ancres au succes SEUL, parce qu'elle jugeait
         * au lieu de constater.
         */
        if (posts.length === 0) {
            constate('message de refus',
                'SANS OBJET — aucun POST n\'est parti, il n\'y a rien a afficher');
        } else {
            verifie('le controleur a applique la politique et l\'a DIT',
                refus !== null && refus !== '' && ! /:[a-z_]{3,}|^[a-z0-9_.]+$/.test(refus),
                refus === null ? 'aucun message rendu alors que le POST a bien atteint la route'
                    : refus === '' ? 'le bloc de message est rendu mais vide'
                        : `jeton non substitue : « ${refus.slice(0, 50)} »`);
        }

        // ET LE SECRET N'A PAS CHANGE : la politique a bien refuse.
        const encorePose = drapeau();
        verifie('le drapeau n\'a pas ete leve par une soumission refusee',
            encorePose === 1, `il vaut ${encorePose} — un mot de passe refuse a leve l'exigence`);
    });

    // ══ 4. IL PEUT SORTIR ════════════════════════════════════════════════
    await etape('la deconnexion sort, elle ne renvoie pas au profil', async () => {
        await page.goto(`${BASE}${C.profil}`, { waitUntil: 'networkidle2' });
        const bouton = await page.$(C.deconnexion);
        constate('bouton de deconnexion du bandeau', bouton ? 'present (POST)' : '(absent)');
        if (! bouton) {
            verifie('le compte marque peut se deconnecter', false,
                'aucun bouton de deconnexion dans le bandeau — le compte est enferme');

            return;
        }
        const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 });
        await bouton.click();
        try { await nav; } catch { /* on lira l'URL */ }
        const arrivee = page.url().replace(BASE, '');
        constate('arrivee apres deconnexion', arrivee);
        /*
         * CE QUI DECIDE : on arrive sur la connexion, PAS sur le profil. Si le
         * middleware avait ete pose par NOM d'exemption, le POST aurait ete
         * couvert et le GET manque ; ici les deux vivent hors du groupe.
         */
        verifie('le compte marque SORT au clic sur deconnexion',
            /connexion|login/.test(arrivee) && ! /force_change=1/.test(arrivee),
            `arrive sur ${arrivee} — un compte marque doit pouvoir sortir`);
    });

    // ══ 5. LE `GET /deconnexion` — navigation directe, et c'est dit ══════
    await etape('le GET de deconnexion sort aussi', async () => {
        const s2 = await connecte();
        try {
            if (s2.surConnexion) {
                verifie('le GET de deconnexion sort aussi', false,
                    'la seconde session ne s\'est pas ouverte');

                return;
            }
            // AUCUN LIEN NE POINTE VERS CE GET dans le portage : ce n'est donc
            // pas un clic, c'est un chemin d'entree depuis l'ancien portail. On
            // le mesure comme tel plutot que de le presenter comme un clic.
            await s2.page.goto(`${BASE}/deconnexion`, { waitUntil: 'networkidle2' });
            const arrivee = s2.page.url().replace(BASE, '');
            constate('arrivee apres GET /deconnexion', arrivee);
            verifie('le GET de deconnexion sort aussi (route SANS nom, hors du groupe)',
                /connexion|login/.test(arrivee) && ! /force_change=1/.test(arrivee),
                `arrive sur ${arrivee} — une exemption par NOM aurait manque ce GET`);
        } finally {
            try { await s2.ctx.close(); } catch { /* deja ferme */ }
        }
    });

    await etape('captures', async () => {
        const s3 = await connecte();
        try {
            if (s3.surConnexion) { verifie('captures', false, 'session non etablie'); return; }
            await s3.page.goto(`${BASE}${C.profil}`, { waitUntil: 'networkidle2' });
            const dossier = new URL(`./screenshots/mot-de-passe/${CIBLE}`, import.meta.url).pathname;
            mkdirSync(dossier, { recursive: true });
            for (const f of [{ n: 'grand', w: 1920, h: 1080 }, { n: 'bureau', w: 1400, h: 900 },
                             { n: 'mobile', w: 390, h: 844 }]) {
                await s3.page.setViewport({ width: f.w, height: f.h });
                await dors(400);
                await s3.page.screenshot({ path: `${dossier}/mdp-${f.n}.png`, fullPage: true });
            }
            verifie('les trois captures sont ecrites', true, '', dossier);
        } finally {
            try { await s3.ctx.close(); } catch { /* deja ferme */ }
        }
    });

    verifie('aucune erreur JavaScript sur le profil', s.erreursJs.length === 0,
        s.erreursJs.slice(0, 3).join(' | '), 'aucune');
} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
} finally {
    /*
     * ══ LA RESTAURATION, ET ELLE SE MESURE ═══════════════════════════════
     *
     * On ne restaure QUE si c'est nous qui avons pose. Et l'on relit apres :
     * une commande qui rend un code de succes n'est pas une preuve d'etat.
     */
    if (posePar) {
        try {
            litEnBase(`UPDATE rootwarden.users SET force_password_change = 0 WHERE id = ${CIBLE_ID}`);
            const apres = drapeau();
            if (apres !== 0) bancEnferme = true;
            verifie(`${CIBLE_NOM} est RESTAURE (drapeau a 0)`, apres === 0,
                `il vaut ${apres} — LE BANC EST ENFERME. Taper :`
                + ` UPDATE rootwarden.users SET force_password_change = 0 WHERE id = ${CIBLE_ID}`,
                'drapeau a 0');
        } catch (e) {
            bancEnferme = true;
            note(`FAIL  restauration impossible : ${e.message}`);
            note(`FAIL  LE BANC EST ENFERME — taper : UPDATE rootwarden.users`
                + ` SET force_password_change = 0 WHERE id = ${CIBLE_ID}`);
            echecs += 2;
        }
    } else {
        constate('restauration', 'SANS OBJET — le drapeau n\'a pas ete pose par cette execution');
    }
    for (const c of contextes) { try { await c.close(); } catch { /* deja ferme */ } }
    try { await navigateur.close(); } catch { /* deja ferme */ }
}

note(`\n${etapes} etapes, ${lignes.filter((l) => l.startsWith('PASS')).length} PASS, ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');

/*
 * ══ UN CODE DE SORTIE DISTINCTIF QUAND LE BANC RESTE ENFERME ═════════════
 *
 * 61 suites du LOT emploient `rw-test-admin`, et ce drapeau garde TOUTE page du
 * portage : une restauration ratee ne fait pas echouer UNE suite, elle en fait
 * echouer ~61 en cascade sur un LOT de 2 h 40. Continuer produit alors 61 faux
 * rouges a rediagnostiquer un par un.
 *
 * **99 signifie « n'enchaine pas », et le runner l'applique** :
 * `rejouer-lot.sh:1180` detecte le code 99 **OU** le marqueur `LOT-ABATTRE` dans
 * le journal, et `:1295` sort en 99 **dans la boucle**, avant la suite suivante.
 * Les deux voies sont necessaires : un `timeout` tue avec 124 sans laisser de
 * marqueur, un plantage apres l'impression laisse le marqueur sans le code.
 *
 * Le remede est **lu dans ce journal**, jamais recopie dans le runner : une
 * commande figee la-bas mentirait le jour ou cette suite change de cible.
 */
if (bancEnferme) {
    note('=== LOT-ABATTRE :: le banc reste ENFERME, ne pas enchainer ===');
    note(`=== REMEDE :: UPDATE rootwarden.users SET force_password_change = 0 WHERE id = ${CIBLE_ID} ===`);
    process.exit(99);
}
process.exit(echecs === 0 ? 0 : 1);
