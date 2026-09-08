/**
 * Epreuve de `withNavigateur` — au PROCESSUS, pas dans l'arbre.
 *
 * La propriete a demontrer n'est pas « un `finally` est ecrit » : c'est
 * « plus aucun Chromium ne subsiste ». Un `finally` vert dans l'arbre sur une
 * fuite ouverte au processus est plus trompeur qu'une absence de test — la
 * fuite se remarque, le vert rassure. Donc on COMPTE les processus, avant et
 * apres, dans la meme execution.
 *
 * QUATRE CAS, et le quatrieme est le temoin :
 *   A  corps normal                        -> 0 orphelin
 *   B  corps qui LEVE                      -> 0 orphelin
 *   C  corps qui appelle process.exit()    -> 0 orphelin (le filet synchrone)
 *   T  TEMOIN : lancement SANS enveloppeur -> DOIT laisser un orphelin
 *
 * ⚠ SANS LE CAS T, « 0 orphelin » serait indiscernable de « le compteur ne
 * voit rien ». Zero sur la sonde ET zero sur le temoin veut dire que la mesure
 * n'a pas eu lieu. Le temoin cree donc une vraie fuite, la prouve, et la
 * FAUCHE ensuite par son pid — on ne laisse pas derriere soi ce qu'on
 * reprochait aux autres.
 *
 * C et T exigent un PROCESSUS FILS : `process.exit()` tuerait l'epreuve
 * elle-meme, et le temoin doit survivre a son propre lancement.
 */

import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { withNavigateur } from './lib-navigateur.mjs';

const MOTIF = '.cache/puppeteer';
let echecs = 0;
const note = (s) => process.stdout.write(`${s}\n`);

function chromiumVivants() {
    try {
        const sortie = execFileSync('ps', ['-eo', 'pid=,args='], { encoding: 'utf8' });
        return sortie.split('\n')
            .filter((l) => l.includes(MOTIF) && !l.includes('ps -eo'))
            .map((l) => Number(l.trim().split(/\s+/)[0]))
            .filter((n) => Number.isInteger(n));
    } catch { return []; }
}

function verifie(quoi, ok, detail) {
    if (ok) { note(`PASS  ${quoi}`); return; }
    echecs += 1;
    // Le detail ne vaut que pour un ECHEC : l'afficher sur un PASS ferait
    // chercher au mauvais endroit.
    note(`FAIL  ${quoi}${detail ? `\n        ${detail}` : ''}`);
}

// ── un fils qui lance un navigateur et fait ce qu'on lui dit ────────────────
function fils(source) {
    return spawnSync(process.execPath, ['--input-type=module', '-e', source],
        { cwd: process.cwd(), encoding: 'utf8', timeout: 120000 });
}

const RACINE = process.cwd();

/*
 * ⚠ UN FILS LANCE PAR `-e` NE RESOUT PAS LES PAQUETS DEPUIS LE CWD. Sa base de
 * resolution est `/`, donc `import 'puppeteer'` y leve ERR_MODULE_NOT_FOUND —
 * et le temoin rendait alors « 0 orphelin cree », c'est-a-dire exactement la
 * sortie d'un temoin qui NE MORD PAS. Le cas C, lui, passait deja : son import
 * etait un chemin ABSOLU. On resout donc le paquet ici, dans le parent, et on
 * transmet l'URL au fils.
 */
const URL_PUPPETEER = import.meta.resolve('puppeteer');

note('══ epreuve withNavigateur — au processus ══\n');

const base = chromiumVivants();
note(`  base : ${base.length} Chromium sous ${MOTIF} avant l'epreuve\n`);

/*
 * ⚠ MON PREMIER TEMOIN NE FUYAIT PAS, ET C'EST CE QUI A CORRIGE MA PREMISSE.
 * Il lançait un navigateur puis appelait `process.exit(0)` sans fermer —
 * fuite VOULUE. Mesure : 0 orphelin. **Puppeteer pose ses propres
 * gestionnaires de sortie et fauche son Chromium**, donc une sortie propre,
 * meme sans `close()`, ne laisse rien.
 *
 * Consequence sur ce que l'enveloppeur apporte, dite ici parce qu'elle borne
 * sa valeur : `withNavigateur` NE REDUIT PAS le compte d'orphelins d'un arret
 * propre. Ce qu'il borne est la DUREE DE VIE du navigateur PENDANT une
 * execution — une suite qui leve au milieu garde sinon un navigateur ouvert
 * jusqu'a sa fin, et c'est precisement ce qui se fait tuer sous pression
 * memoire.
 *
 * Le VRAI chemin de fuite est donc celui ou les gestionnaires ne tournent
 * PAS : SIGKILL, tueur de memoire, panne dure. Les 23 orphelins mesures ont
 * TOUS le meme age (2,8 jours) et 15 sont reparentes a `init` : un evenement
 * unique, pas un suintement. Le temoin ci-dessous reproduit CE chemin.
 */

// ── T — LE TEMOIN, D'ABORD : sans lui, tout le reste est indiscernable ─────
{
    // Le fils annonce le pid du navigateur puis ATTEND : on le tue par SIGKILL,
    // donc aucun gestionnaire de sortie ne tourne — ni le sien, ni celui de
    // puppeteer. C'est la seule forme qui laisse reellement un orphelin.
    const enfant = spawn(process.execPath, ['--input-type=module', '-e', `
        const { default: puppeteer } = await import(${JSON.stringify(URL_PUPPETEER)});
        const n = await puppeteer.launch({ headless: 'new',
            args: ['--no-sandbox','--ignore-certificate-errors'] });
        console.log('PID=' + n.process().pid);
        await new Promise(() => {});   // ne rend jamais : on le SIGKILL
    `], { cwd: process.cwd(), stdio: ['ignore', 'pipe', 'pipe'] });

    let vu = '';
    enfant.stdout.on('data', (d) => { vu += d.toString(); });
    // Attendre l'annonce du pid, pas une duree.
    const t0 = Date.now();
    while (!/PID=\d+/.test(vu) && Date.now() - t0 < 60000) {
        await new Promise((r) => setTimeout(r, 200));
    }
    const m = /PID=(\d+)/.exec(vu);
    enfant.kill('SIGKILL');
    await new Promise((r) => setTimeout(r, 1500));
    const r = { stdout: vu, stderr: '' };
    const apres = chromiumVivants().filter((p) => !base.includes(p));
    verifie('TEMOIN — un lancement sans enveloppeur LAISSE un orphelin',
        apres.length > 0,
        `0 nouveau processus vu : le compteur ne discrimine pas. `
        + `stdout=${JSON.stringify((r.stdout || '').slice(0, 120))} `
        + `stderr=${JSON.stringify((r.stderr || '').slice(0, 200))}`);
    // On fauche ce qu'on a semé, par pid, et rien d'autre.
    let fauches = 0;
    for (const pid of apres) {
        try { process.kill(-pid, 'SIGKILL'); fauches += 1; continue; } catch { /* pas chef */ }
        try { process.kill(pid, 'SIGKILL'); fauches += 1; } catch { /* deja mort */ }
    }
    note(`        (temoin : ${apres.length} orphelin(s) cree(s), ${fauches} fauche(s)`
        + `${m ? `, pid annonce ${m[1]}` : ''})`);
}

// ── A — corps normal ───────────────────────────────────────────────────────
{
    const avant = chromiumVivants();
    const rendu = await withNavigateur(async (n) => (await n.version()).length > 0);
    const apres = chromiumVivants().filter((p) => !avant.includes(p));
    verifie('A — corps normal : le corps s\'execute', rendu === true, `rendu = ${rendu}`);
    verifie('A — corps normal : 0 orphelin', apres.length === 0, `${apres.length} restant(s) : ${apres}`);
}

// ── B — corps qui leve ─────────────────────────────────────────────────────
{
    const avant = chromiumVivants();
    let leve = null;
    try { await withNavigateur(async () => { throw new Error('panne forgee'); }); }
    catch (e) { leve = e.message; }
    const apres = chromiumVivants().filter((p) => !avant.includes(p));
    verifie('B — corps qui leve : l\'exception TRAVERSE l\'enveloppeur',
        leve === 'panne forgee', `levee = ${JSON.stringify(leve)}`);
    verifie('B — corps qui leve : 0 orphelin', apres.length === 0, `${apres.length} restant(s) : ${apres}`);
}

// ── C — corps qui appelle process.exit() : le filet synchrone ─────────────
{
    const avant = chromiumVivants();
    const r = fils(`
        const { withNavigateur } = await import(${JSON.stringify(`${RACINE}/tests/e2e/lib-navigateur.mjs`)});
        await withNavigateur(async (n) => {
            console.log('PID=' + n.process().pid);
            process.exit(3);        // saute le finally : seul le filet peut mordre
        });
    `);
    // Laisser au noyau le temps de reaper le groupe tue.
    spawnSync('sleep', ['2']);
    const apres = chromiumVivants().filter((p) => !avant.includes(p));
    verifie('C — process.exit() dans le corps : le code de sortie passe',
        r.status === 3, `status = ${r.status}, stderr=${JSON.stringify((r.stderr || '').slice(0, 200))}`);
    /*
     * ⚠ CE CAS NE DISTINGUE PAS MON FILET DU GESTIONNAIRE DE PUPPETEER. Les
     * deux fauchent sur `exit`, donc un vert ici ne prouve pas que le mien
     * serve. Il prouve que l'enveloppeur ne CASSE pas la reprise existante —
     * ce qui est plus modeste, et c'est ce qui est ecrit.
     */
    verifie('C — process.exit() dans le corps : 0 orphelin (filet OU puppeteer)',
        apres.length === 0, `${apres.length} restant(s) : ${apres}`);
}

note(`\n${echecs === 0 ? '=== TOUT OK ===' : `=== ${echecs} ECHEC(S) ===`}`);
note(`  fin : ${chromiumVivants().length} Chromium sous ${MOTIF} (base : ${base.length})`);
process.exitCode = echecs === 0 ? 0 : 1;
