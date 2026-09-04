/**
 * lib-arbre.mjs — l'arbre a-t-il bouge PENDANT la mesure ?
 *
 * ══ POURQUOI CE MODULE EXISTE ═════════════════════════════════════════════
 *
 * Le 2026-09-01 a 15:29:58 un LOT complet est lance. A **15:30:15**, dix-sept
 * secondes plus tard, une autre session ecrit dans `profil.blade.php` et
 * `supervision.blade.php`, puis **annule** son geste. `go-socle-navigation`
 * tournait de 15:30:00 a 15:31:19 — a cheval sur la fenetre — et a rendu :
 *
 *     PASS=64  FAIL=2      500 /supervision, aux deux roles
 *
 * La page est saine : `curl /supervision` rend 302 apres le rangement. **Le
 * FAIL etait entierement un artefact de l'ecriture transitoire**, et il aurait
 * ete indiscernable d'une regression : `Machines.php` avait effectivement bouge
 * une heure plus tot, ce qui offrait une explication plausible et fausse.
 *
 * Trois choses que rien d'autre ne voit :
 *
 *   1. **`git status` ne suffit pas.** Une ecriture annulee ne laisse rien : au
 *      moment ou j'ai verifie, l'arbre etait propre et les ancres etaient les
 *      bonnes. *Verifier l'etat present ne refute pas une alerte sur un etat
 *      passe* — il faut DATER les fichiers ;
 *   2. **un preflight seul ne couvre rien.** A 15:30:00 l'arbre etait intact ;
 *      l'ecriture est arrivee a 15:30:15. L'empreinte se releve **au debut ET a
 *      la fin**, et c'est l'ECART qui informe ;
 *   3. **rendre le banc ne protege que la CHARGE.** Ni `ps`, ni une duree, ni un
 *      `StartedAt` ne montrent une ecriture dans l'arbre.
 *
 * ══ TROIS REGIMES DE LECTURE, ET UN MEME ECART VEUT DIRE TROIS CHOSES ═════
 *
 *     charge au demarrage   backend/**.py       -> se mesure au STATUT
 *                                                  (StartedAt vs mtime)
 *     relu par requete      laravel/** legacy/** -> ne diverge PAS du service,
 *                                                  mais fausse la FENETRE
 *     bati                  *.css *.js compiles  -> la fraicheur est un INDICE,
 *                                                  la mesure est le STYLE CALCULE
 *
 * Mesure du 2026-09-01 : `rootwarden_python` demarre le 27/08 a 14:28 porte
 * **20 fichiers `.py` plus neufs** — vraie divergence ; `rootwarden_php`
 * demarre le 20/08 en porte **337** et **ne diverge pas**, parce qu'il relit a
 * chaque requete. **Un garde qui alarmerait sur la fraicheur seule crierait 337
 * fois sans objet, serait eteint au deuxieme LOT, et emporterait les 20 vrais.**
 *
 * ══ CE QUE CE MODULE NE FAIT PAS ══════════════════════════════════════════
 *
 * ⚠ **UN ANGLE MORT, TROUVE PAR L'EPREUVE ET NON PAR LA RELECTURE.**
 *
 * Un fichier **cree puis supprime** pendant la fenetre est INVISIBLE : il n'est
 * ni dans l'empreinte de depart (il n'existait pas) ni dans celle d'arrivee (il
 * n'existe plus), et `plusNeufsQue` scanne l'arbre ACTUEL. Mesure :
 *
 *     ecriture ANNULEE (creation + suppression)   ->  propre=true   RATE
 *     cas REEL du 2026-09-01 (modifie puis remis) ->  propre=false  DETECTE
 *
 * Le second est celui qui a fausse le LOT — un fichier EXISTANT modifie puis
 * remis a l'identique garde son `mtime` neuf, et c'est ce que ce module lit
 * quand `git status` est deja redevenu propre. Le premier reste hors de portee
 * d'une comparaison d'etats : il faudrait observer les ECRITURES, pas les etats
 * (`inotify`), ce qui n'est pas a la portee d'une suite.
 *
 * **La limite est ecrite ici plutot que corrigee**, parce qu'un garde dont on se
 * croit couvert est pire qu'un garde absent : il occupe la place ou l'on aurait
 * cherche.
 *
 * ══ CE QUE CE MODULE NE FAIT PAS (SUITE) ══════════════════════════════════
 *
 * Il ne juge pas. Il rend un ECART date et NOMME — « ces fichiers-la ont bouge
 * pendant ta fenetre » — parce qu'un « quelque chose a bouge » ne dit pas s'il
 * touche ce que la suite mesurait. La suite decide ; et si elle ne peut pas
 * mesurer (aucun chemin lisible), elle doit **s'abstenir en le disant**, jamais
 * rendre un PASS : « je n'ai pas pu regarder » n'est pas « rien a signaler ».
 */
import { readdirSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

const RACINE = new URL('../../', import.meta.url).pathname;

/*
 * ══ TROIS RACINES, ET NON UNE LISTE BLANCHE POUR L'UNE DES TROIS ══════════
 *
 * `legacy` et `backend` etaient deja donnes en RACINE ; `laravel` seul portait
 * une enumeration de huit sous-repertoires. Mesure du 2026-09-04 : 34 fichiers
 * SUIVIS par git vivaient sous `laravel/` hors de ces huit, et parmi eux
 *
 *     laravel/public/index.php        le controleur frontal — toute page
 *     laravel/public/.htaccess        les reecritures, donc le routage
 *     laravel/Dockerfile              +  docker-entrypoint.sh : regime IMAGE
 *     laravel/composer.json/.lock     l'autochargement
 *     laravel/database/migrations/    le schema que les pages rendent
 *     laravel/phpunit.xml             (celui-la meme que 09f2be0 a du reparer)
 *
 * Une ecriture sur `public/index.php` pendant une fenetre changeait TOUTES les
 * pages et mon garde rendait « 0 modifie ». **Un angle mort d'une liste blanche
 * ne se trompe pas du cote qui alarme : il DEDOUANE**, et un garde qui dedouane
 * a tort est exactement la place ou l'on ne cherche plus.
 *
 * ══ POURQUOI LA RACINE NE RAMENE PAS LE BRUIT QU'ON CRAINDRAIT ════════════
 *
 * Parce que le tri ne se fait pas ici. Deux filtres, tous deux par FICHIER :
 * `JAMAIS_SERVI` (plus bas) et `git check-ignore`. Mesure du 2026-09-04, sur
 * les 10 178 fichiers presents sous `laravel/` :
 *
 *     ignores par git, PAR FICHIER          9 845    (dont vendor/, .env,
 *                                                    storage/**, bootstrap/cache/*)
 *     retenus                                 333    dont 11 `.gitignore` immobiles
 *     retenus dans un chemin de cache           0    hors ces `.gitignore`
 *
 * ⚠ ET J'AI FAILLI CONCLURE L'INVERSE. `git check-ignore laravel/storage/
 * framework/views` — le REPERTOIRE — rend « non ignore », et j'en avais deduit
 * 113 vues compilees dans l'empreinte, donc un mecanisme inutilisable. Chaque
 * FICHIER de ce repertoire est pourtant ignore, par un `.gitignore` local
 * portant `*`. **Interroger un garde sur le mauvais objet rend un verdict
 * faux, et celui-la se trompait du cote qui alarme** : il m'aurait fait garder
 * l'angle mort au nom d'un bruit qui n'existe pas.
 *
 * ══ CE QUE `laravel/version.txt` FERA APPARAITRE, ET C'EST VOULU ═══════════
 *
 * Ce fichier existe sur l'hote a 0 octet et n'est pas suivi. Ce n'est pas une
 * ecriture : c'est le POINT DE MONTAGE que Docker cree sous le montage englobant
 * `./laravel:/var/www/html`, pour y attacher `legacy/version.txt` en lecture
 * seule (`docker inspect`, 2026-09-04 : Source=legacy/version.txt, RW=false ;
 * dans le conteneur le chemin rend `1.39.5`). Il entre donc dans l'empreinte, et
 * sa mtime bouge a chaque demarrage du conteneur SANS qu'un octet soit ecrit.
 *
 * **Le signaler est juste** : un redemarrage du conteneur pendant une fenetre
 * change le regime SERVICE au milieu de la mesure. Ce qu'il faut savoir le lire :
 * un ECART qui ne nomme que ce seul chemin dit « le conteneur a redemarre »,
 * pas « une session a ecrit ».
 */

/** Ce qui est SERVI par chaque portail, par regime de lecture. */
export const CHEMINS_SERVIS = {
    laravel: ['laravel'],
    legacy:  ['legacy'],
    backend: ['backend'],
};

/*
 * Ce qui n'est JAMAIS servi par une requete HTTP, meme sous un chemin servi.
 * `laravel/tests/` est declare en `autoload-dev` seul : aucune requete ne peut
 * charger ce qui s'y trouve — mesure faite le 2026-09-01 sur `composer.json`,
 * et c'est ce qui a permis de dedouaner une ecriture pendant une fenetre plutot
 * que de rejouer 82 secondes pour rien.
 */
const JAMAIS_SERVI = [
    /\/tests?\//, /\/node_modules\//, /\/vendor\//, /\/\.git\//, /\/screenshots\//,
];

function pertinent(chemin) {
    return ! JAMAIS_SERVI.some((m) => m.test(chemin));
}

/*
 * ══ CODE SOURCE CONTRE ETAT D'EXECUTION — LE CRITERE, PAS UNE LISTE ═══════
 *
 * Premiere redaction : j'excluais `laravel/storage/` et les `.log` **par leur
 * nom**. Insuffisant, et la surveillance du Lead l'a mesure pendant un LOT :
 *
 *     backend/logs/deployment.log   ecrit par MA PROPRE `assureJournal()`
 *     backend/__pycache__/          ecrit a chaque import Python
 *     backend/.pytest_cache/ .ruff_cache/   ecrits par les outils
 *     legacy/logs/                  journaux du portail
 *
 * Le module aurait signale « fenetre sale » sur toute suite declenchant un
 * deploiement, tout redemarrage backend, tout `pytest`. **C'est exactement la
 * classe que j'ai fait corriger au Lead deux heures plus tot**, commise dans
 * mon propre garde.
 *
 * **Allonger la liste serait se preparer au prochain repertoire de cache qu'un
 * outil creera.** La distinction reelle n'est pas « servi / non servi », c'est :
 *
 *     code source        ecrit par un DEVELOPPEUR  -> la mesure devient fausse
 *     etat d'execution   ecrit par le SYSTEME      -> c'est le fonctionnement normal
 *
 * La question posee est « quelqu'un a-t-il change le CODE sous mes pieds »,
 * jamais « un octet a-t-il change ». Et `.gitignore` porte deja cette
 * distinction, par construction : personne ne versionne son etat d'execution.
 * On la DERIVE donc de `git check-ignore` plutot que de la reecrire — mesure
 * du 2026-09-01 : **779 fichiers ignores sur 1420** sous `backend/ legacy/
 * laravel/`, et le classement est correct sur les six cas eprouves.
 *
 * ⚠ L'ANGLE MORT REEL EST L'INVERSE DE CELUI QU'ON M'AVAIT ANNONCE. On m'a dit
 * qu'un fichier de code **non encore suivi** serait classe « etat » — mesure :
 * un `.blade.php` neuf non suivi et non ignore est classe **CODE**, donc il n'y
 * a pas d'angle mort de ce cote. Le vrai est le symetrique : un fichier de code
 * qui figurerait dans `.gitignore` serait classe « etat » et passerait
 * inaperçu. C'est rare et c'est ecrit ici plutot que corrige.
 */
let CACHE_IGNORES = null;

function ignoresParGit(chemins) {
    if (chemins.length === 0) return new Set();
    try {
        const sortie = execFileSync('git', ['check-ignore', '--stdin'], {
            cwd: RACINE, input: chemins.join('\n'), encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'ignore'],
        });

        return new Set(sortie.split('\n').filter(Boolean));
    } catch (e) {
        // `git check-ignore` sort en 1 quand AUCUN chemin n'est ignore : ce
        // n'est pas une erreur. Toute autre sortie rend `null` -> l'appelant
        // s'abstient plutot que de classer tout en « code » et d'alarmer.
        if (e && e.status === 1) return new Set();

        return null;
    }
}

function parcourt(dossier, sortie) {
    let entrees;
    try { entrees = readdirSync(dossier, { withFileTypes: true }); } catch { return; }
    for (const e of entrees) {
        const p = join(dossier, e.name);
        if (! pertinent(p)) continue;
        if (e.isDirectory()) { parcourt(p, sortie); continue; }
        try {
            const s = statSync(p);
            sortie.set(p.replace(RACINE, ''), `${Math.round(s.mtimeMs)}:${s.size}`);
        } catch { /* disparu entre readdir et stat : c'est un ECART, pas une erreur */ }
    }
}

/**
 * L'empreinte du chemin servi d'une cible. Rend `null` si RIEN n'a pu etre lu —
 * et `null` doit faire s'abstenir, jamais conclure.
 *
 * @param {string} cible  'laravel' | 'legacy' | 'backend'
 * @returns {Map<string,string>|null}
 */
export function empreinteServie(cible) {
    const chemins = CHEMINS_SERVIS[cible];
    if (! chemins) return null;
    const sortie = new Map();
    for (const c of chemins) parcourt(join(RACINE, c), sortie);

    return sortie.size === 0 ? null : sortie;
}

/**
 * L'ECART entre deux empreintes, NOMME. Un « quelque chose a bouge » ne dit pas
 * s'il touche ce que la suite mesurait ; la liste, oui.
 *
 * @returns {{modifies: string[], apparus: string[], disparus: string[], total: number}}
 */
export function ecartServi(avant, apres) {
    if (avant === null || apres === null) {
        return { modifies: [], apparus: [], disparus: [], total: -1 };
    }
    const modifies = [];
    const disparus = [];
    for (const [f, e] of avant) {
        if (! apres.has(f)) { disparus.push(f); continue; }
        if (apres.get(f) !== e) modifies.push(f);
    }
    const apparus = [...apres.keys()].filter((f) => ! avant.has(f));

    return { modifies, apparus, disparus,
        total: modifies.length + apparus.length + disparus.length };
}

/**
 * Les fichiers du chemin servi plus NEUFS qu'un instant donne. C'est la forme
 * qui a manque le 2026-09-01 : `git status` etait propre parce que l'ecriture
 * avait ete annulee, mais le `mtime` portait encore la trace.
 *
 * @param {string} cible
 * @param {number} depuisMs  epoch en millisecondes
 * @returns {{fichier: string, mtime: number}[]|null}
 */
export function plusNeufsQue(cible, depuisMs) {
    const e = empreinteServie(cible);
    if (e === null) return null;
    const sortie = [];
    for (const [f, v] of e) {
        const mtime = Number(v.split(':')[0]);
        if (mtime >= depuisMs) sortie.push({ fichier: f, mtime });
    }

    return sortie.sort((a, b) => a.mtime - b.mtime);
}

/**
 * Rend le verdict PRET A IMPRIMER pour une suite, sous la forme convenue :
 * ni PASS ni FAIL quand la mesure n'a pas eu lieu.
 *
 * ══ LE CONTRAT DE RETOUR, ET POURQUOI IL PORTE `abattre` ══════════════════
 *
 * Premiere redaction : `propre` n'existait **que** dans la branche mesurable.
 * Un appelant ecrivant `if (! v.propre) abattre()` recevait `undefined`, donc
 * faux, **donc il abattait sur une ABSENCE de mesure** — 156 executions tuees
 * parce que le chemin servi n'avait pas pu etre lu. Trou signale par le Lead
 * avant de le consommer, et il avait raison.
 *
 * **Mais rendre `propre: null` NE SUFFIT PAS, et c'est mesure :**
 *
 *     { mesurable:false }                 if (!v.propre) -> ABAT   (faux positif)
 *     { mesurable:false, propre:null }    if (!v.propre) -> ABAT ENCORE
 *     { mesurable:false, abattre:false }  if (v.abattre) -> n'abat pas
 *
 * `null` est falsy : rendre l'intention explicite ne rend pas la consommation
 * sure. C'est la meme famille que `''` chiffre en `sodium:…` et que `None` lu
 * comme « absent » — *un champ absent, un champ faux et un champ nul se lisent
 * pareil chez l'appelant.*
 *
 * D'ou **`abattre`** : le module rend LA DECISION, pas la donnee dont on la
 * derive. Il est present dans les deux branches, toujours booleen, et il vaut
 * **`false` quand la mesure n'a pas eu lieu** — on n'abat pas sur un silence.
 * `propre` reste pour l'information (`true` / `false` / `null`), et ne doit
 * jamais servir a decider.
 *
 * Usage dans une suite :
 *
 *     const t0 = Date.now();
 *     const av = empreinteServie(CIBLE);
 *     …  la suite tourne  …
 *     const v = verdictFenetre(CIBLE, av, t0);
 *     if (v.mesurable) verifie(v.libelle, v.propre, v.detail, v.toujours);
 *     else             constate(v.libelle, v.detail);
 *
 * Usage dans un runner :
 *
 *     if (v.abattre) { … }        // JAMAIS `if (! v.propre)`
 */
export function verdictFenetre(cible, avant, departMs) {
    const apres = empreinteServie(cible);
    const ecart = ecartServi(avant, apres);
    if (ecart.total === -1) {
        return { mesurable: false,
            // `null` informe ; les BOOLEENS decident, et ils valent `false`
            // quand la mesure n'a pas eu lieu — voir l'en-tete du contrat.
            propre: null,
            ecritureCode: false,
            fichiers: [],
            fichiersEtat: [],
            toujours: '',
            libelle: `le CODE servi de ${cible} n'a pas bouge pendant la mesure`,
            detail: 'SANS OBJET — le chemin servi n\'a pas pu etre lu, ni au depart ni a l\'arrivee' };
    }
    const bouges = [...ecart.modifies, ...ecart.apparus, ...ecart.disparus];
    const recents = (plusNeufsQue(cible, departMs) || []).map((r) => r.fichier);
    // L'UNION des deux : l'empreinte attrape ce qui a change de contenu, le
    // `mtime` attrape ce qui a ete ECRIT PUIS REMIS EN ETAT — le cas du
    // 2026-09-01, que l'empreinte seule aurait manque.
    const tous = [...new Set([...bouges, ...recents])];

    /*
     * On SEPARE le code de l'etat d'execution. Sans cette separation, une suite
     * qui declenche un deploiement se signalerait elle-meme — sa propre
     * `assureJournal()` ecrit `backend/logs/deployment.log`.
     */
    const ignores = ignoresParGit(tous);
    if (ignores === null) {
        return { mesurable: false, propre: null, ecritureCode: false,
            fichiers: [], fichiersEtat: [], toujours: '',
            libelle: `le CODE servi de ${cible} n'a pas bouge pendant la mesure`,
            detail: 'SANS OBJET — `git check-ignore` a echoue : impossible de'
                + ' separer le code de l\'etat d\'execution, on ne conclut pas' };
    }
    const code = tous.filter((f) => ! ignores.has(f));
    const etat = tous.filter((f) => ignores.has(f));

    return {
        mesurable: true,
        propre: code.length === 0,
        /*
         * LE FAIT, PAS LA DECISION — et c'est deliberement l'inverse du choix
         * fait pour le drapeau residuel. Abattre depend de ce que la suite LIT,
         * ce que ce module ne peut pas savoir : il a failli tuer 158 executions
         * sur un `legacy/version.txt` qu'aucune suite ne lit. Le runner decide,
         * et l'arbitrage rendu est « FENETRE SALE — a rejouer », SANS abattage :
         * l'ecriture est PASSEE, les suites suivantes sont saines.
         */
        ecritureCode: code.length > 0,
        libelle: `le CODE servi de ${cible} n'a pas bouge pendant la mesure`,
        detail: code.length === 0 ? ''
            : `${code.length} fichier(s) de CODE ecrit(s) pendant la fenetre : `
              + `${code.slice(0, 5).join(', ')}${code.length > 5 ? ' …' : ''}`
              + ' — cette mesure n\'est pas interpretable, elle est A REJOUER',
        toujours: code.length === 0
            ? `aucun${etat.length ? ` (${etat.length} ecriture(s) d'etat d'execution, normales)` : ''}`
            : '',
        fichiers: code,
        fichiersEtat: etat,
    };
}
