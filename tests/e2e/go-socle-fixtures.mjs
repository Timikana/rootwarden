/**
 * go-socle-fixtures.mjs — LES INVARIANTS DU BANC, ET RIEN D'AUTRE.
 *
 * Cette suite ne mesure aucune page. Elle mesure **ce sur quoi les autres
 * suites s'appuient sans le verifier** : les droits des trois comptes
 * d'epreuve, et la composition du parc.
 *
 * ══ POURQUOI ELLE EXISTE ══════════════════════════════════════════════════
 *
 * Le plan a annonce **UNE** permission pour `rw-test-admin`. Il en porte
 * **NEUF**. Plusieurs suites mesurent une garde en s'appuyant sur « ce compte
 * n'a PAS telle permission » : concevoir un tel test sur une ligne fausse
 * produit **un vert qui ne mesure rien**. Le chiffre a ete corrige a la main
 * une fois ; rien n'empeche qu'il derive a nouveau, et **une permission
 * s'accorde par un geste d'administration ordinaire**.
 *
 * ══ LA FIXTURE LA PLUS FRAGILE DU BANC ════════════════════════════════════
 *
 * La regle du depot est « cette permission **OU** le role >= 3 ». Le seul
 * chemin qui **DISCRIMINE** les deux est un **role 2 SANS la permission -> 403**.
 *
 * Pour `fail2ban` ce chemin **n'existe pas** : `rw-test-admin` detient
 * `can_manage_fail2ban`. C'est pourquoi les cinq suites `f2` a `f6` resteraient
 * vertes **meme si le correctif de garde n'etait jamais applique** — elles ne
 * peuvent pas distinguer « 200 parce qu'il n'y a aucune garde » de « 200 parce
 * que le role contourne ».
 *
 * Pour `iptables` il **EXISTE**, et c'est le seul du parc : `rw-test-admin` est
 * role 2 et ne detient pas `can_manage_iptables`. **Accorder cette permission
 * detruirait la seule mesure possible de cette garde**, sans qu'aucun test ne
 * rougisse — jusqu'a celui-ci.
 *
 * ══ CE QU'ELLE N'EST PAS ══════════════════════════════════════════════════
 *
 * Ce n'est pas une politique de securite : elle ne dit pas quels droits les
 * comptes DOIVENT avoir. Elle dit **quels droits le corpus de tests SUPPOSE**,
 * et elle rougit quand la supposition cesse d'etre vraie. Un changement
 * deliberé se traduit par une mise a jour de ce fichier, dans le meme commit —
 * c'est le point : que le changement soit VU.
 *
 * Une seule cible : la base est PARTAGEE par les deux portails. La jouer deux
 * fois mesurerait deux fois la meme chose.
 */
import { litEnBase, compteEnBase } from './lib-base.mjs';

let echecs = 0;
const lignes = [];
function note(l) { lignes.push(l); console.log(l); }
/** `d` n'est imprime QUE sur un FAIL ; `toujours` sort dans les deux verdicts. */
/*
 * ⚠ `toujours` NE SORT QUE SUR UN PASS, ET C'EST UNE LECON PAYEE ICI MEME.
 *
 * Fourni inconditionnellement, il PRIME sur l'explication d'echec et la MASQUE :
 * l'epreuve par mutation a rendu « FAIL … — 9 permission(s) » au lieu de nommer
 * la permission fautive. **Un FAIL qui ne dit pas POURQUOI vaut a peine mieux
 * qu'un silence** — et le defaut ne se voit pas tant que la suite est verte.
 *
 * C'est le symetrique exact du piege corrige la veille sur quatre suites : la,
 * l'explication d'echec s'imprimait sur des PASS ; ici, l'informatif efface
 * l'explication sur les FAIL. **Les deux viennent du meme oubli — un detail
 * doit dependre du VERDICT.**
 */
function verifie(l, ok, d, toujours) {
    const suffixe = toujours || (! ok && d) || '';
    note(`${ok ? 'PASS' : 'FAIL'}  ${l}${suffixe ? '  — ' + suffixe : ''}`);
    if (! ok) echecs += 1;
}
function constate(l, v) { note(`INFO  ${l} : ${v}`); }

/** Les permissions REELLEMENT detenues, derivees du schema. */
function permissionsDe(compte) {
    // Les colonnes se lisent dans `information_schema` plutot que d'etre
    // recopiees : une liste ecrite a la main vieillit, et le portage des
    // permissions lit deja le schema pour cette raison. Une colonne AJOUTEE au
    // schema entre donc d'elle-meme dans la mesure.
    const colonnes = litEnBase(
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        + "WHERE TABLE_SCHEMA='rootwarden' AND TABLE_NAME='permissions' "
        + "AND COLUMN_NAME LIKE 'can\\_%' ORDER BY COLUMN_NAME");
    if (! colonnes.length) return null;      // schema illisible : on le dira
    const sel = colonnes
        .map((c) => `SELECT '${c}' AS p FROM rootwarden.users u `
            + `JOIN rootwarden.permissions pe ON pe.user_id = u.id `
            + `WHERE u.name = '${compte}' AND pe.${c} = 1`)
        .join(' UNION ALL ');

    return litEnBase(sel).sort();
}

/*
 * L'ETAT ATTENDU, mesure le 2026-08-28. Il est ecrit EXPLICITEMENT et non
 * derive : c'est une fixture, pas une propriete du code. La deriver reviendrait
 * a comparer la base a elle-meme, et la suite serait verte quoi qu'il arrive.
 */
const ATTENDU = {
    'rw-test-user': [],
    'rw-test-admin': [
        'can_audit_ssh', 'can_deploy_keys', 'can_manage_backups',
        'can_manage_fail2ban', 'can_manage_services', 'can_manage_supervision',
        'can_scan_cve', 'can_update_linux', 'can_view_compliance',
    ],
    'rw-test-super': ['can_admin_portal'],
};

try {
    // ══ 0. L'INSTRUMENT D'ABORD ══════════════════════════════════════════
    const colonnes = litEnBase(
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        + "WHERE TABLE_SCHEMA='rootwarden' AND TABLE_NAME='permissions' "
        + "AND COLUMN_NAME LIKE 'can\\_%'");
    constate('colonnes de permission au schema', String(colonnes.length));
    // Sans ce controle, une lecture vide rendrait « aucune permission detenue »
    // pour les trois comptes, et les trois assertions passeraient sur du vide.
    verifie('le schema des permissions est lisible', colonnes.length >= 15,
        `${colonnes.length} colonne(s) — la lecture ne voit pas la table`,
        colonnes.length >= 15 ? `${colonnes.length} colonnes` : '');

    // ══ 1. LES TROIS COMPTES PORTENT EXACTEMENT CE QUE LE CORPUS SUPPOSE ══
    for (const [compte, attendu] of Object.entries(ATTENDU)) {
        const reel = permissionsDe(compte) || [];
        constate(`${compte} detient`, reel.join(' ') || '(aucune)');
        const enTrop = reel.filter((p) => ! attendu.includes(p));
        const manquantes = attendu.filter((p) => ! reel.includes(p));
        verifie(`${compte} porte exactement les droits que le corpus suppose`,
            enTrop.length === 0 && manquantes.length === 0,
            [enTrop.length ? `EN TROP : ${enTrop.join(', ')}` : '',
             manquantes.length ? `MANQUANTES : ${manquantes.join(', ')}` : '']
                .filter(Boolean).join(' · ')
            + ' — plusieurs suites mesurent une garde en supposant ces droits ;'
            + ' mettre a jour ce fichier DANS LE MEME COMMIT que le changement',
            (enTrop.length === 0 && manquantes.length === 0)
                ? `${reel.length} permission(s)` : '');
    }

    // ══ 2. LE CHEMIN QUI DISCRIMINE, ET IL EST UNIQUE ════════════════════
    /*
     * On ne mesure pas « personne ne detient `can_manage_iptables` » — ce serait
     * plus large que la propriete. Ce qui compte est qu'il existe **un compte de
     * ROLE 2 qui ne la detient pas** : c'est lui, et lui seul, qui peut prouver
     * qu'une garde « permission OU role 3 » refuse pour la bonne raison.
     */
    const role2SansIptables = litEnBase(
        "SELECT u.name FROM rootwarden.users u "
        + 'JOIN rootwarden.permissions p ON p.user_id = u.id '
        + "WHERE u.role_id = 2 AND u.active = 1 "
        + 'AND (p.can_manage_iptables = 0 OR p.can_manage_iptables IS NULL)');
    constate('comptes de role 2 SANS `can_manage_iptables`',
        role2SansIptables.join(' ') || '(aucun)');
    verifie('le chemin qui DISCRIMINE la garde iptables existe encore',
        role2SansIptables.length > 0,
        'plus aucun compte de role 2 ne manque de `can_manage_iptables` : la garde '
        + '« permission OU role 3 » ne peut plus etre distinguee d\'une absence de garde, '
        + 'et une suite iptables resterait verte meme si le correctif n\'etait jamais applique',
        role2SansIptables.length > 0 ? role2SansIptables.join(' ') : '');

    // ══ 3. AUCUN OCTROI TEMPORAIRE EN VOL ════════════════════════════════
    /*
     * `checkPermissionFromDB` lit TROIS sources : le repli superadministrateur,
     * `permissions`, et `temporary_permissions` non expirees. Un octroi
     * temporaire ouvre donc une page que la mesure croit fermee — et il expire
     * tout seul, donc le meme test rougit ou passe selon l'heure.
     */
    const temporaires = compteEnBase(
        'SELECT COUNT(*) FROM rootwarden.temporary_permissions '
        + 'WHERE expires_at IS NULL OR expires_at > NOW()');
    constate('octrois temporaires en vigueur', String(temporaires));
    verifie('aucun octroi temporaire ne fausse les mesures de garde',
        temporaires === 0,
        `${temporaires} octroi(s) en vigueur — une page mesuree « fermee » peut etre ouverte, `
        + 'et l\'octroi expire de lui-meme : la meme suite passerait ou rougirait selon l\'heure',
        temporaires === 0 ? '0' : '');

    // ══ 4. LE PARC EST CELUI QUE LES SUITES DESIGNENT ════════════════════
    const parc = litEnBase(
        "SELECT CONCAT(id,'|',name) FROM rootwarden.machines ORDER BY id");
    constate('parc', parc.join(' · '));
    verifie('la machine 1 est bien la PRODUCTION que les suites evitent',
        parc.some((m) => m.startsWith('1|srv-zabbix')),
        `la machine 1 n'est plus \`srv-zabbix\` : ${parc[0] || '(aucune)'} — `
        + 'toutes les suites qui evitent « la machine 1 » evitent autre chose',
        parc.some((m) => m.startsWith('1|srv-zabbix')) ? (parc[0] || '') : '');
    verifie('la machine 2 est bien le banc mutable',
        parc.some((m) => m.startsWith('2|Test-Server-Debian')),
        `la machine 2 n'est plus le banc : ${parc[1] || '(aucune)'} — `
        + 'les suites qui MUTENT la machine 2 muteraient autre chose',
        parc.some((m) => m.startsWith('2|Test-Server-Debian')) ? (parc[1] || '') : '');
} catch (e) {
    verifie('deroulement de la suite', false, String(e.message || e).split('\n')[0]);
}

note(`\n${lignes.filter((l) => l.startsWith('PASS')).length} PASS / ${echecs} FAIL`);
note(echecs === 0 ? '=== TOUT OK ===' : '=== DES ECHECS ===');
process.exit(echecs === 0 ? 0 : 1);
