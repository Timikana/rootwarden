/**
 * withNavigateur — la propriete du navigateur ne quitte JAMAIS cet enveloppeur.
 *
 * POURQUOI CE FICHIER EXISTE. `helpers.mjs::launchBrowser()` fait
 * `return puppeteer.launch(...)` : il REND le navigateur, donc il cede la
 * propriete a l'appelant. Une fabrique qui rend la ressource ne peut pas
 * garantir sa liberation, ni aujourd'hui ni jamais — ce n'est pas un oubli
 * qu'on repare, c'est ce que sa signature permet. Mesure du 2026-09-08 :
 * 23 Chromium abandonnes sous ~/.cache/puppeteer/, le plus vieux depuis 2,7 j.
 *
 * DEUX CAUSES DE FUITE, INDEPENDANTES, et la seconde defait la parade de la
 * premiere :
 *
 *   (a) le `close()` n'est pas gouverne par un `finally`         62 suites
 *       -> 12 sans aucune fermeture de navigateur, et 50 qui en ont une
 *          DEHORS d'un `finally` existant. Un `finally` qui existe ne gouverne
 *          pas ce qui est hors de lui : mesurer sa PRESENCE dedouane a tort.
 *
 *   (b) un `process.exit()` est interpose entre le lancement et la fermeture
 *       -> 37 suites. `process.exit()` termine IMMEDIATEMENT et n'execute
 *          AUCUN bloc `finally`.
 *
 *   ⚠ CES DEUX CHIFFRES ONT ETE FAUX DEUX FOIS, ET DANS LE MEME SENS.
 *   Premiers relevés : 67 et 41. Aucun des deux ne DEPOUILLAIT LES
 *   COMMENTAIRES — et dans ces suites, **79 des 167 occurrences de `finally`
 *   vivent dans de la prose** (47 %), ainsi que 41 des 182 `process.exit`. La
 *   population elle-meme etait fausse : 114 suites annoncees, 110 reelles, les
 *   quatre autres ne portant `puppeteer.launch` qu'en commentaire.
 *   *Un motif trouve dans un commentaire compte comme du code jusqu'a ce qu'on
 *   depouille, et la prose de ce depot parle beaucoup de ses propres defauts.*
 *   L'instrument qui rend 62 / 37 est `lib-navigateur.invariant.mjs` : il
 *   depouille, apparie les accolades, et porte trois temoins forges — dont un
 *   fichier dont le `finally` n'existe QUE dans un commentaire.
 *
 * CE QUE L'ENVELOPPEUR REND INEXPRIMABLE :
 *   - l'appelant ne detient jamais le navigateur, donc il ne peut pas oublier
 *     de le fermer  -> (a) devient impossible a ecrire
 *
 * ⛔ CE QU'IL NE FAIT PAS, et le dire est le point de ce bloc. Une version
 * anterieure de ce commentaire affirmait que le filet « rattrape (b) meme
 * quand le finally est saute ». **C'etait surpromis.** Table de couverture,
 * mesuree au mecanisme par `gestion-ssh-key-c6` dans `@puppeteer/browsers`
 * (`lib/cjs/launch.js:91`), et non deduite :
 *
 *   chemin de sortie      puppeteer   un finally   withNavigateur
 *   sortie propre            oui         oui           oui
 *   process.exit()           oui         NON           oui
 *   SIGINT / TERM / HUP      oui         NON           oui
 *   SIGKILL (tueur memoire)  NON         NON           NON   <- par definition
 *
 * **Puppeteer pose deja des gestionnaires sur `exit`, `SIGINT`, `SIGHUP` et
 * `SIGTERM`.** Le filet ci-dessous est donc REDONDANT avec le sien sur les
 * quatre chemins qu'il couvre. Il ne devient utile que si une suite passait
 * `handleSIGINT: false` — et aucune ne le fait aujourd'hui (0 occurrence).
 * *Il est garde parce qu'il coute une ligne et ferme un cas qu'une option
 * pourrait ouvrir, pas parce qu'on peut montrer qu'il sert.*
 *
 * ⚠ POURQUOI IL EST SYNCHRONE, quand meme. Un gestionnaire de
 * `process.on('exit')` ne peut pas attendre une promesse : tout `await` y est
 * ignore. `close()` est asynchrone, donc inoperant a cet endroit ; `kill()`
 * est synchrone. C'est la seule forme qui puisse mordre depuis un `exit`.
 *
 * ⚠ ET LA VALEUR REELLE DE L'ENVELOPPEUR N'EST PAS UN NETTOYAGE. `SIGKILL`
 * n'est couvert par rien — c'est la definition du signal. Les 23 Chromium
 * mesures le 2026-09-08 (dont 15 reparentes a `init`, tous du meme evenement
 * a 2,8 jours, avec le swap plein a 120 Ki pres) viennent de la : un tueur de
 * memoire. **Donc cet enveloppeur ne nettoie pas apres l'OOM, il le rend
 * MOINS PROBABLE** — en ne gardant pas un navigateur ouvert pendant qu'une
 * suite echoue. *Il agit sur la cause mesuree, pas sur son symptome, et il n'a
 * pas a avoir de chemin par lequel il reduirait un compte d'orphelins.*
 * (formulation de `c6`)
 *
 * ⚠ CE QUI RESTE A LA CHARGE DE L'APPELANT : ne pas appeler `process.exit()`
 * dans le corps. Poser `process.exitCode = n` et laisser le processus finir
 * seul — le filet existe pour les suites qu'on n'a pas encore converties, pas
 * comme permission d'appeler `exit`.
 */

import puppeteer from 'puppeteer';

/*
 * Les memes options que `_av.mjs`, qui est la seule suite du depot dont la
 * fermeture etait deja correcte a la main (`finally` a :363, chaque `close()`
 * dans son propre `try`). On reprend sa forme plutot que d'en inventer une.
 */
const OPTIONS = {
    headless: 'new',
    args: [
        '--no-sandbox',
        '--ignore-certificate-errors',
        '--allow-insecure-localhost',
    ],
    defaultViewport: { width: 1400, height: 900 },
    protocolTimeout: 120000,
};

/**
 * Lance un navigateur, execute `corps(navigateur)`, et le ferme QUOI QU'IL
 * ARRIVE — retour normal, exception, ou `process.exit()` dans le corps.
 *
 * @param {(navigateur: import('puppeteer').Browser) => Promise<any>} corps
 * @param {object} [options] fusionnees par-dessus OPTIONS
 * @returns {Promise<any>} ce que rend `corps`
 */
export async function withNavigateur(corps, options = {}) {
    if (typeof corps !== 'function') {
        // Fail-closed : un appel mal forme ne doit pas laisser un navigateur ouvert.
        throw new TypeError('withNavigateur attend une fonction en premier argument');
    }

    const navigateur = await puppeteer.launch({ ...OPTIONS, ...options });
    const processus = navigateur.process();

    /*
     * Le filet tue le GROUPE de processus quand c'est possible. Puppeteer lance
     * Chromium en `detached` hors Windows, donc le navigateur est chef de son
     * groupe et `kill(-pid)` emporte les processus fils (zygote, moteurs de
     * rendu). Si le groupe n'existe pas, on retombe sur le pid seul : moins
     * complet, mais jamais pire que rien.
     */
    const filet = () => {
        const pid = processus?.pid;
        if (!pid) return;
        try { process.kill(-pid, 'SIGKILL'); return; } catch { /* pas chef de groupe */ }
        try { process.kill(pid, 'SIGKILL'); } catch { /* deja mort */ }
    };

    process.on('exit', filet);

    try {
        return await corps(navigateur);
    } finally {
        /*
         * L'ordre compte. On retire d'abord le filet pour ne pas tuer un
         * navigateur que `close()` est en train de fermer proprement, puis on
         * ferme, puis on rappelle le filet : `close()` peut rendre sans que le
         * processus soit mort (delai de sortie, contexte bloque).
         */
        process.removeListener('exit', filet);
        try { await navigateur.close(); } catch { /* deja ferme */ }
        filet();
    }
}

export default withNavigateur;
