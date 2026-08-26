<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Les droits `sudo` accordes a un compte distant — module `adm/`, sous-lot D9a.
 *
 * Porte `legacy/adm/server_user_sudo.php`. Le versant SFTP
 * (`server_user_sftp.php`) est D9b : il partage le meme JS et le meme module
 * backend, mais ses politiques n'ont pas de prereglages, et c'est ici que vit la
 * question de l'equivalence root.
 *
 * ══ CE QUE CE PORTAGE CORRIGE, ET POURQUOI CA NE POUVAIT PAS ETRE DES MOTS ══
 *
 * L'ecran du legacy affirme, sous son prereglage PAR DEFAUT :
 *   « Il ne peut pas toucher au reste du systeme. »
 * Le module qui produit la regle, `backend/sudo_manager.py:80-84`, ecrit :
 *   « AVERTISSEMENT : ce preset est EQUIVALENT ROOT. `apt install/upgrade`
 *     execute des scripts de mainteneur en root -> un utilisateur avec ce preset
 *     peut obtenir un shell root via un paquet construit. »
 *
 * C'est « l'en-tete qui ment » — le motif releve quatre fois ailleurs — mais
 * sous sa forme la plus couteuse : les autres occurrences sont des COMMENTAIRES,
 * qui trompent une relecture. Celle-ci est une PHRASE D'INTERFACE, qui trompe la
 * personne qui decide, au moment ou elle decide.
 *
 * **Le corriger en reecrivant la phrase ne suffirait pas.** Une phrase juste
 * ecrite ici derivera de `sudo_manager.py` exactement comme l'autre l'a fait ;
 * on aurait reconstruit le defaut avec de meilleurs mots. Et recopier les
 * gabarits de regles en PHP serait pire — deux sources de verite pour une regle
 * de securite, la chose que ce depot s'interdit.
 *
 * La garantie est donc STRUCTURELLE et vit dans la suite : `go-adm-politiques`
 * relit `sudo_manager.py` DANS LE CONTENEUR a chaque execution et refuse que
 * l'ecran contredise le module. Les mots peuvent deriver ; le LOT le verra.
 * Ce que le service apporte, c'est le CLASSEMENT ci-dessous — verifiable, et
 * verifie.
 *
 * ══ ACCORDER SE CONFIRME ; C'EST L'INVERSE DU LEGACY ══════════════════════
 *
 * `js/server_user_policy.js` : `removePolicy()` ouvre par
 * `if (!confirm(T.confirmRemove)) return;`, `rollback()` aussi — **`deployPolicy()`
 * n'a AUCUNE confirmation**. Mesure de la suite : deployer = 0 boite, retirer = 1.
 * Un seul clic envoyait donc
 *   POST /policy/sudo/deploy {"preset":"apt_only","runas":"root",...}
 * c'est-a-dire l'ecriture d'un `/etc/sudoers.d/rootwarden-<user>` sur la machine.
 *
 * L'asymetrie est a l'envers : le geste qui DONNE etait libre, celui qui REPREND
 * etait garde. Le portage separe VERIFIER et AGIR comme `ssh/` l'a fait en K3 —
 * le panneau enonce la machine, le compte, le prereglage et sa portee reelle
 * avant que quoi que ce soit ne parte.
 *
 * ══ CE QUE LA MESURE DEDOUANE ════════════════════════════════════════════
 *
 * Deux choses, et elles meritent d'etre dites parce que ce module est le seul du
 * chantier a les avoir toutes les deux :
 *
 * 1. **Les gardes sont completes aux TROIS niveaux.** La page porte
 *    `checkAuth([ROLE_SUPERADMIN])` (mesure : role 2 -> 403), le proxy inscrit
 *    `/policy/` dans ses prefixes d'administration, et les onze routes de
 *    `backend/routes/policies.py` portent toutes `@require_role(3)`. Cinq autres
 *    modules ont laisse passer la requete en gardant la page ; celui-ci non.
 *
 * 2. **Le geste distant est sur.** `sudo_manager` valide par `visudo -cf` AVANT
 *    tout deplacement, borne les chemins a `/etc/sudoers.d/rootwarden-*`, et
 *    leve plutot que d'ecrire si la validation echoue. Ce n'est pas l'ecriture
 *    qui est dangereuse ici : c'est sa PRESENTATION.
 */
class Politiques
{
    /**
     * Reprise de l'enum de `server_user_sudo_policies.preset` ET de
     * `PRESET_RENDERERS` (`backend/sudo_manager.py:147`). Liste FERMEE : une
     * valeur hors liste ne se propose pas et ne se transmet pas.
     *
     * `custom` est dans l'enum de la colonne sans etre dans `PRESET_RENDERERS` —
     * il a son propre rendu (`render_preset_custom`), qui ne fait aucun
     * templating. Il est donc offert, mais classe a part (voir `PORTEE`).
     */
    public const PREREGLAGES = [
        'all_nopasswd',
        'restart_services',
        'apt_only',
        'read_logs',
        'systemctl_specific',
        'custom',
    ];

    /** Le prereglage retenu quand aucune politique n'existe encore. */
    public const PREREGLAGE_INITIAL = 'read_logs';

    /**
     * Ce que chaque prereglage accorde REELLEMENT, tel que son propre module le
     * documente. Trois valeurs, et la troisieme n'est pas un adoucissement de la
     * deuxieme : elle dit qu'on ne SAIT pas.
     *
     *   'root'    le module documente une equivalence root, ou la regle l'est par
     *             construction ;
     *   'borne'   le module documente un durcissement explicite et une liste de
     *             commandes close ;
     *   'inconnu' la regle vient de la personne qui la saisit ; seule sa SYNTAXE
     *             est verifiee (`visudo -cf`), jamais sa portee.
     *
     * `apt_only` est ici pour la raison ecrite en tete de classe. `all_nopasswd`
     * rend litteralement `<user> ALL=(root) NOPASSWD:ALL`.
     *
     * `restart_services` n'est PAS classe 'root' : son module ne le documente pas
     * comme tel, et rien ne l'a mesure. On decrit ce qu'il accorde, sans lui
     * preter une portee qu'on n'a pas etablie — la regle de ce depot est de ne
     * jamais recopier ni deviner une affirmation de securite.
     */
    public const PORTEE = [
        'all_nopasswd'       => 'root',
        'apt_only'           => 'root',
        'restart_services'   => 'borne',
        'read_logs'          => 'borne',
        'systemctl_specific' => 'borne',
        'custom'             => 'inconnu',
    ];

    /** Les prereglages dont l'ecran doit dire qu'ils donnent root. */
    public static function donneRoot(string $prereglage): bool
    {
        return (self::PORTEE[$prereglage] ?? 'inconnu') === 'root';
    }

    /** Les machines proposables — les archivees sont hors du choix. */
    public function machines(): array
    {
        return DB::select(
            'SELECT id, name, ip, port FROM machines '
            . "WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived' "
            . 'ORDER BY name'
        );
    }

    /**
     * Les comptes distants d'une machine sur lesquels une politique a un sens.
     *
     * Meme filtre que le legacy : `managed` et `pending_review`. Un compte
     * `excluded` est un compte qu'on a decide de ne pas gerer — lui poser des
     * droits sudo serait se contredire.
     */
    public function comptes(int $machine): array
    {
        return DB::select(
            'SELECT id, username, status FROM server_user_inventory '
            . "WHERE machine_id = ? AND status IN ('managed','pending_review') "
            . 'ORDER BY username',
            [$machine]
        );
    }

    /** La politique sudo en vigueur pour ce couple, ou `null`. */
    public function politique(int $machine, int $compte): ?object
    {
        $lignes = DB::select(
            'SELECT * FROM server_user_sudo_policies WHERE machine_id = ? AND server_user_id = ?',
            [$machine, $compte]
        );

        return $lignes[0] ?? null;
    }

    /**
     * L'historique des deploiements du couple, le plus recent d'abord.
     *
     * Lu en base et non sur la machine : `policy_deployments` est ecrit par le
     * backend a chaque geste. La machine, elle, ne porte que l'etat FINAL — elle
     * ne sait pas dire qui a accorde quoi, ni quand.
     *
     * La table garde `new_file_content` : l'historique peut donc montrer la
     * REGLE REELLEMENT ECRITE, et non une description de ce qu'elle etait censee
     * etre. C'est la seule source de verite du depot sur ce qui a ete accorde,
     * et elle vient du backend — pas d'un gabarit recopie ici.
     *
     * Il n'y a pas de colonne `action` : un retrait ou une annulation se lisent
     * dans `status` (`applied`, `rolled_back`, `failed`, `superseded`).
     */
    public function historique(int $machine, int $compte, int $limite = 20): array
    {
        return DB::select(
            'SELECT d.id, d.status, d.target_path, d.deployed_at, d.rolled_back_at, '
            . 'd.new_file_content, u.name AS auteur '
            . 'FROM policy_deployments d '
            . 'LEFT JOIN users u ON u.id = d.deployed_by '
            . "WHERE d.machine_id = ? AND d.server_user_id = ? AND d.policy_type = 'sudo' "
            . 'ORDER BY d.deployed_at DESC LIMIT ' . max(1, min(100, $limite)),
            [$machine, $compte]
        );
    }
}
