<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * L'acces SFTP/SSH d'un compte distant — module `adm/`, sous-lot D9b.
 *
 * Porte `legacy/adm/server_user_sftp.php`. Complete D9a (`Politiques`), avec
 * lequel il partage le module backend (`routes/policies.py`) et, cote legacy, le
 * meme fichier JS — `server_user_policy.js`, aiguille par une variable `TYPE`.
 *
 * ══ LE DEFAUT : L'ECRAN CONSEILLE L'INVERSE DE CE QU'IL LIVRE ═════════════
 *
 * D9a avait une aide qui DISAIT FAUX. Ici les aides disent VRAI, et c'est ce qui
 * rend le defaut plus net :
 *
 *   « Decoche : il DOIT utiliser une cle SSH (nettement plus sur, RECOMMANDE). »
 *   « Si ce n'est pas necessaire, DECOCHE : c'est plus sur. »        (tunnels)
 *   « Si ce n'est pas necessaire, DECOCHE. »                    (rebond de cle)
 *
 * Les trois cases correspondantes sont **cochees par defaut**
 * (`server_user_sftp.php:97-99`, `?? true`). Mesure de la suite sur le legacy :
 * cinq cases lues, trois cochees dont l'aide recommande de les decocher.
 *
 * ══ ET LE MODULE SE CONTREDIT A SIX LIGNES D'INTERVALLE ═══════════════════
 *
 * `backend/sftp_manager.py`, `render_policy()`. Sa docstring donne l'exemple de
 * reference — `sftp_only: True`, les trois autorisations a `False`. Son code, six
 * lignes plus bas, prend l'inverse sur QUATRE de ces cinq cles. Mesure derivee
 * du fichier lui-meme, a chaque execution de la suite : 4 ecarts, tous vers le
 * permissif ; `x11_forwarding` concorde, ce qui montre que la comparaison ne
 * signale pas tout indistinctement.
 *
 * ══ CE QUE CELA PRODUIT, ET POURQUOI C'EST PLUS QU'UN REGLAGE MOU ═════════
 *
 * Corps reellement intercepte au premier clic sur « Deployer », legacy :
 *
 *   {"sftp_only":false,"chroot_dir":null,"working_dir":null,
 *    "allow_password_auth":true,"allow_tcp_forwarding":true,
 *    "allow_agent_forwarding":true,"x11_forwarding":false}
 *
 * `render_policy` en tire :
 *
 *   Match User <x>
 *       PasswordAuthentication yes
 *       AllowTcpForwarding yes
 *       AllowAgentForwarding yes
 *       X11Forwarding no
 *
 * Sans `ForceCommand internal-sftp`, sans `ChrootDirectory`, sans `PermitTTY no`
 * — ceux-la ne sont ajoutes que si `sftp_only`. **Ce n'est pas une restriction
 * SFTP : c'est un shell complet avec tunnels**, sur une page qui s'intitule
 * « Acces SFTP ».
 *
 * Et un bloc `Match User` FIXE ces directives pour ce compte, a la place de ce
 * que la configuration globale de la machine aurait donne. Sur une machine
 * durcie, deployer ce bloc ELARGIT l'acces du compte au lieu de le restreindre —
 * c'est le contraire de ce que la page laisse attendre.
 *
 * ══ CE QUE LA MESURE DEDOUANE ════════════════════════════════════════════
 *
 * Comme en D9a, et pour les memes raisons : gardes completes aux trois niveaux
 * (page en `checkAuth([ROLE_SUPERADMIN])` — role 2 mesure a 403 —, `/policy/`
 * en prefixe d'administration du proxy, `@require_role(3)` sur les routes), et
 * geste distant sur — `sftp_manager` ecrit un temporaire, lance `sshd -t` pour
 * valider la configuration COMPLETE, et ne deplace qu'ensuite. Un bloc syntaxi-
 * quement invalide ne peut pas fermer l'acces SSH a la machine.
 *
 * Les chemins `chroot_dir` et `working_dir` passent par `_validate_path` :
 * absolu, sans traversee. C'est verifie AU BACKEND, donc une requete forgee ne
 * le contourne pas.
 */
class AccesSftp
{
    /**
     * Les reglages proposes, et ce que chacun VAUT quand il est actif.
     *
     *   'restreint' l'activer RESSERRE l'acces ;
     *   'ouvre'     l'activer l'ELARGIT.
     *
     * Cette colonne est ce qui permet a l'ecran de proposer un etat initial
     * coherent SANS recopier la liste des valeurs par defaut du backend : le
     * defaut du portage est « tout ce qui restreint est actif, tout ce qui
     * ouvre ne l'est pas ». Voir `INITIAL`.
     */
    public const REGLAGES = [
        'sftp_only'              => 'restreint',
        'allow_password_auth'    => 'ouvre',
        'allow_tcp_forwarding'   => 'ouvre',
        'allow_agent_forwarding' => 'ouvre',
        'x11_forwarding'         => 'ouvre',
    ];

    /**
     * L'etat d'une politique NEUVE, cote portage.
     *
     * DIVERGENCE ASSUMEE, declaree au CHANGELOG et a PARITE. Le legacy livre
     * `allow_password_auth`, `allow_tcp_forwarding` et `allow_agent_forwarding`
     * a `true` — c'est-a-dire l'inverse de ce que ses propres aides recommandent,
     * et l'inverse de l'exemple que `sftp_manager.render_policy` donne dans sa
     * docstring.
     *
     * Le portage part de la position que le module documente : restreint d'abord.
     * Ce n'est pas une preference — c'est la seule position ou l'ecran ne se
     * contredit pas lui-meme.
     *
     * Derive de `REGLAGES`, jamais ecrit a la main : ajouter un reglage ne peut
     * donc pas faire naitre un defaut permissif par oubli.
     */
    public static function initial(): array
    {
        $etat = [];
        foreach (self::REGLAGES as $cle => $effet) {
            $etat[$cle] = ($effet === 'restreint');
        }

        return $etat;
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
     * Les comptes distants sur lesquels une politique a un sens.
     *
     * Meme filtre que le legacy et que D9a : `managed` et `pending_review`. Un
     * compte `excluded` est un compte qu'on a decide de ne pas gerer.
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

    /** La politique SFTP en vigueur pour ce couple, ou `null`. */
    public function politique(int $machine, int $compte): ?object
    {
        $lignes = DB::select(
            'SELECT * FROM server_user_sftp_policies WHERE machine_id = ? AND server_user_id = ?',
            [$machine, $compte]
        );

        return $lignes[0] ?? null;
    }

    /**
     * L'etat a afficher : celui de la politique existante, sinon `initial()`.
     *
     * `(bool) (int)` explicite sur chaque colonne. **Mesure du 2026-08-26 : ce
     * pilote rend les `tinyint(1)` en ENTIERS**, donc `(bool)` seul suffirait
     * ici et maintenant. Le double transtypage est garde parce que la reponse
     * depend du pilote et du mode de preparation : avec des requetes emulees,
     * PDO rend des CHAINES, et `"0"` est VRAI en PHP faible — une case decochee
     * en base s'afficherait alors cochee, du cote permissif, ce qui est
     * precisement le defaut que ce sous-lot corrige.
     */
    public function etat(?object $politique): array
    {
        if ($politique === null) {
            return self::initial();
        }
        $etat = [];
        foreach (array_keys(self::REGLAGES) as $cle) {
            $etat[$cle] = (bool) ((int) ($politique->{$cle} ?? 0));
        }

        return $etat;
    }

    /**
     * L'historique des deploiements SFTP du couple, le plus recent d'abord.
     *
     * Meme table et memes colonnes qu'en D9a — il n'y a pas de colonne `action`,
     * un retrait ou une annulation se lisent dans `status`. `new_file_content`
     * porte le bloc REELLEMENT ECRIT, seule source de verite du depot sur ce qui
     * a ete accorde.
     */
    public function historique(int $machine, int $compte, int $limite = 20): array
    {
        return DB::select(
            'SELECT d.id, d.status, d.target_path, d.deployed_at, d.rolled_back_at, '
            . 'd.new_file_content, u.name AS auteur '
            . 'FROM policy_deployments d '
            . 'LEFT JOIN users u ON u.id = d.deployed_by '
            . "WHERE d.machine_id = ? AND d.server_user_id = ? AND d.policy_type = 'sftp' "
            . 'ORDER BY d.deployed_at DESC LIMIT ' . max(1, min(100, $limite)),
            [$machine, $compte]
        );
    }
}
