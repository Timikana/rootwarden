/**
 * lib-base.mjs - Lire la base depuis une suite E2E, sans repandre le mot de passe.
 *
 * DEUX RAISONS D'EXISTER, mesurees toutes les deux.
 *
 * 1. LE MOT DE PASSE NE DOIT PAS SORTIR DANS UN MESSAGE D'ERREUR. `mysql` ne
 *    prend son mot de passe que sur la ligne de commande ou par l'environnement,
 *    et `execFileSync` recopie TOUT l'argv dans le message quand la commande
 *    echoue. Une suite qui tombe imprimait donc :
 *      Command failed: docker exec rootwarden_db mysql -uroot -prootpassword ...
 *    C'est exactement le defaut corrige cote SSH en v1.37.17, reapparu dans
 *    l'outillage de test. On rattrape donc l'echec et on le renvoie EXPURGE.
 *
 * 2. LE MEME LECTEUR ETAIT RECOPIE CINQ FOIS dans les suites du module
 *    `security/`. Cinq copies d'un acces a la base divergent : la premiere qui
 *    apprend quelque chose ne l'apprend pas aux autres.
 *
 * Le mot de passe est lu dans `srv-docker.env`, jamais ecrit dans une suite :
 * gitleaks est bloquant en CI, et un secret en dur y resterait.
 */
import { execFileSync } from 'child_process';

const ENV = '/home/utilisateur/Documents/Gestion_SSH_KEY/srv-docker.env';

let motDePasse = null;
function mdp() {
    if (motDePasse === null) {
        motDePasse = execFileSync('sh', ['-c',
            `grep -m1 MYSQL_ROOT_PASSWORD ${ENV} | cut -d= -f2`],
            { encoding: 'utf-8' }).trim();
    }
    return motDePasse;
}

/** Le texte brut rendu par mysql, ou une erreur EXPURGEE du mot de passe. */
function interroge(requete) {
    const secret = mdp();
    try {
        return execFileSync('docker',
            ['exec', 'rootwarden_db', 'mysql', '-uroot', `-p${secret}`, '-N', '-B',
             '-e', requete],
            { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
    } catch (e) {
        // Ne JAMAIS relayer `e` tel quel : son message porte l'argv complet.
        const cause = String(e.message || e).replace(secret, '***');
        throw new Error(
            `lecture en base en echec (${requete.slice(0, 60)}...) : ` +
            cause.replace(/-p\S+/g, '-p***'));
    }
}

/** Les lignes non vides d'un resultat a une colonne. */
export function litEnBase(requete) {
    return interroge(requete).trim().split('\n').filter(Boolean);
}

/** Un COUNT(*), en entier. Rend NaN si la requete ne rend pas un nombre. */
export function compteEnBase(requete) {
    return parseInt(interroge(requete).trim(), 10);
}
