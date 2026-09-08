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
 *   (a) le `close()` n'est pas gouverne par un `finally`         67 suites
 *       -> 12 sans aucun `close()`, et 55 qui en ont un DEHORS d'un `finally`
 *          existant. Un `finally` qui existe ne gouverne pas ce qui est hors
 *          de lui : mesurer sa PRESENCE dedouane a tort.
 *
 *   (b) un `process.exit()` est interpose entre le lancement et la fermeture
 *       -> 41 suites. `process.exit()` termine IMMEDIATEMENT et n'execute
 *          AUCUN bloc `finally`. Donc un `finally` irreprochable ne ferme
 *          rien si un `exit` le precede a l'execution.
 *
 * CE QUE L'ENVELOPPEUR REND INEXPRIMABLE :
 *   - l'appelant ne detient jamais le navigateur, donc il ne peut pas oublier
 *     de le fermer  -> (a) devient impossible a ecrire
 *   - un filet SYNCHRONE sur `process.on('exit')` tue le processus du
 *     navigateur  -> (b) est rattrape meme quand le `finally` est saute
 *
 * ⚠ POURQUOI LE FILET EST SYNCHRONE. Un gestionnaire de `process.on('exit')`
 * ne peut pas attendre une promesse : tout `await` y est ignore. `close()` est
 * asynchrone et serait donc inoperant a cet endroit. `kill()` sur le processus
 * du navigateur, lui, est synchrone — c'est la seule forme qui morde depuis un
 * `exit`. Ce n'est PAS un remplacement de `close()` (qui ferme proprement les
 * contextes et vide le profil) : c'est un filet, et son efficacite est
 * MESUREE par `lib-navigateur.epreuve.mjs`, pas supposee.
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
