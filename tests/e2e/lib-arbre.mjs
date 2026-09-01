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
import { join } from 'node:path';

const RACINE = new URL('../../', import.meta.url).pathname;

/** Ce qui est SERVI par chaque portail, par regime de lecture. */
export const CHEMINS_SERVIS = {
    laravel: ['laravel/app', 'laravel/routes', 'laravel/resources/views',
              'laravel/lang', 'laravel/public/css', 'laravel/public/js',
              'laravel/config', 'laravel/bootstrap'],
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
    /\/tests?\//, /\/node_modules\//, /\/vendor\//, /\/storage\//,
    /\/\.git\//, /\/screenshots\//, /\.log(\.\d+)?$/, /\.result\.cache$/,
];

function pertinent(chemin) {
    return ! JAMAIS_SERVI.some((m) => m.test(chemin));
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
            // `null` informe, `abattre: false` DECIDE — voir l'en-tete : on
            // n'abat pas un LOT sur une absence de mesure.
            propre: null,
            abattre: false,
            fichiers: [],
            toujours: '',
            libelle: `l'arbre servi de ${cible} n'a pas bouge pendant la mesure`,
            detail: 'SANS OBJET — le chemin servi n\'a pas pu etre lu, ni au depart ni a l\'arrivee' };
    }
    const bouges = [...ecart.modifies, ...ecart.apparus, ...ecart.disparus];
    const recents = (plusNeufsQue(cible, departMs) || []).map((r) => r.fichier);
    // L'UNION des deux : l'empreinte attrape ce qui a change de contenu, le
    // `mtime` attrape ce qui a ete ECRIT PUIS REMIS EN ETAT — le cas du
    // 2026-09-01, que l'empreinte seule aurait manque.
    const tous = [...new Set([...bouges, ...recents])];

    return {
        mesurable: true,
        propre: tous.length === 0,
        // La DECISION, jamais derivee par l'appelant.
        abattre: tous.length > 0,
        libelle: `l'arbre servi de ${cible} n'a pas bouge pendant la mesure`,
        detail: `${tous.length} fichier(s) ecrit(s) pendant la fenetre : `
            + `${tous.slice(0, 5).join(', ')}${tous.length > 5 ? ' …' : ''}`
            + ' — la mesure ne veut rien dire, elle est a REJOUER',
        toujours: tous.length === 0 ? 'aucun' : '',
        fichiers: tous,
    };
}
