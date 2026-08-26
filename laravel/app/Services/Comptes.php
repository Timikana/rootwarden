<?php

namespace App\Services;

use App\Support\TotpCrypto;
use Illuminate\Support\Facades\DB;

/**
 * Les comptes du portail — module `adm/`, sous-lot D3.
 *
 * ══ UN SEUL CHEMIN D'ECRITURE DU MOT DE PASSE, ET IL APPLIQUE LA POLITIQUE ══
 *
 * Le legacy en a plusieurs, et un seul echappe a la politique : celui par lequel
 * un administrateur fixe le mot de passe de QUELQU'UN D'AUTRE
 * (`manage_roles.php:65-88`). Mesure du 2026-08-26, au clic :
 *
 *   exigence            | libre-service | administrateur
 *   longueur            | >= 15         | >= 8
 *   quatre classes      | oui           | non
 *   non reutilise       | oui           | non
 *   ecrit l'historique  | oui           | non
 *
 * `password123` est donc refuse a quelqu'un pour lui-meme et accepte a un
 * administrateur pour autrui, et `password_history` reste vide — si bien que le
 * mot de passe pose peut etre repose aussitot, la politique n'en ayant aucune
 * trace. C'est E-112.
 *
 * `definitMotDePasse()` est le seul point d'ecriture ici. Il applique la
 * politique et ecrit l'historique, quel que soit l'auteur du geste.
 *
 * ══ LA MESURE A DEDOUANE SUR LE COUT, ET C'EST DIT ═════════════════════════
 *
 * `manage_roles.php:85` emploie `PASSWORD_DEFAULT` la ou tout le reste emploie
 * `BCRYPT_COST`. Sur ce PHP les deux rendent `$2y$12$` : le hache n'est PAS plus
 * faible aujourd'hui. Mais `BCRYPT_COST` se lit dans une variable
 * d'environnement (`auth/password_policy.php:28`, defaut 12) : si l'exploitant
 * la releve, tous les chemins suivent SAUF celui-la. Ici le cout est lu au meme
 * endroit que le legacy, donc les deux portails restent d'accord.
 *
 * ══ LA CLE SSH : UN SEUL ECRIVAIN, ET IL VALIDE ════════════════════════════
 *
 * Le legacy en a TROIS, qui ne s'accordent ni sur la validation, ni sur le
 * journal, ni sur la forme stockee (E-115) — dont un qui applique
 * `htmlspecialchars` A L'ECRITURE, sur une valeur que `ssh/` deploie ensuite
 * dans `authorized_keys`. L'echappement appartient au RENDU.
 */
class Comptes
{
    /** Les roles, en liste FERMEE. Le legacy fait de meme (`manage_users.php:84`). */
    public const ROLES = [1, 2, 3];

    /** Longueur minimale — celle de la politique, pas celle de l'administrateur. */
    public const LONGUEUR_MINIMALE = 15;

    /** Nombre de mots de passe passes qu'on refuse de reutiliser. */
    public const HISTORIQUE = 5;

    /**
     * Les algorithmes que `sshd` accepte en tete d'une ligne `authorized_keys`.
     * Liste fermee : une cle est deployee sur des machines, ce n'est pas un
     * champ libre.
     */
    public const ALGOS_SSH = [
        'ssh-rsa', 'ssh-ed25519', 'ssh-dss',
        'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
        'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com',
    ];

    public function liste(): array
    {
        return DB::table('users')
            ->select('id', 'name', 'email', 'company', 'role_id', 'active', 'sudo',
                'ssh_key', 'ssh_key_updated_at', 'failed_attempts', 'locked_until',
                'totp_secret', 'force_password_change', 'password_updated_at')
            ->orderBy('name')
            ->get()->map(static fn ($u) => (array) $u)->all();
    }

    public function trouve(int $id): ?array
    {
        $u = DB::table('users')->where('id', $id)->first();

        return $u ? (array) $u : null;
    }

    /* ═══ Mot de passe ══════════════════════════════════════════════════════ */

    /** Le cout, lu la ou le legacy le lit — les deux portails restent d'accord. */
    private function cout(): int
    {
        return (int) config('rootwarden.bcrypt_cost', 12);
    }

    /**
     * Les quatre classes et la longueur. Reprise mot pour mot de
     * `passwordPolicyCheckComplexity` (`auth/password_policy.php:35-41`) : une
     * regle de securite ne se recopie pas de memoire, elle se releve.
     *
     * @return string|null la cle du message d'erreur, ou null si conforme
     */
    public function verifieComplexite(string $mdp): ?string
    {
        if (mb_strlen($mdp) < self::LONGUEUR_MINIMALE) {
            return 'comptes.err_mdp_longueur';
        }
        if (! preg_match('/[a-z]/', $mdp)) {
            return 'comptes.err_mdp_classes';
        }
        if (! preg_match('/[A-Z]/', $mdp)) {
            return 'comptes.err_mdp_classes';
        }
        if (! preg_match('/[0-9]/', $mdp)) {
            return 'comptes.err_mdp_classes';
        }
        if (! preg_match('/[^a-zA-Z0-9]/', $mdp)) {
            return 'comptes.err_mdp_classes';
        }

        return null;
    }

    /**
     * La non-reutilisation : les N derniers hachés de `password_history`, PLUS
     * le haché courant — qui n'y est pas encore. Le legacy fait de meme
     * (`password_policy.php:67`), et l'oublier laisserait reposer le mot de
     * passe qu'on vient de remplacer.
     */
    public function verifieHistorique(int $id, string $mdp): ?string
    {
        $anciens = DB::table('password_history')->where('user_id', $id)
            ->orderByDesc('changed_at')->limit(self::HISTORIQUE)
            ->pluck('password_hash')->all();

        $courant = DB::table('users')->where('id', $id)->value('password');
        if ($courant) {
            $anciens[] = $courant;
        }
        foreach ($anciens as $hache) {
            if ($hache && password_verify($mdp, $hache)) {
                return 'comptes.err_mdp_reutilise';
            }
        }

        return null;
    }

    /**
     * L'UNIQUE ecriture d'un mot de passe. Elle applique la politique et ecrit
     * l'historique — que le geste vienne de la personne ou d'un administrateur.
     *
     * @return string|null la cle du message d'erreur, ou null si l'ecriture a eu lieu
     */
    public function definitMotDePasse(int $id, string $mdp, bool $forceChangement = true): ?string
    {
        if (($err = $this->verifieComplexite($mdp)) !== null) {
            return $err;
        }
        if (($err = $this->verifieHistorique($id, $mdp)) !== null) {
            return $err;
        }

        $ancien = DB::table('users')->where('id', $id)->value('password');

        DB::transaction(function () use ($id, $mdp, $ancien, $forceChangement): void {
            // L'ANCIEN d'abord : c'est lui qu'on archive, pour que la
            // verification de non-reutilisation retrouve la suite complete.
            if ($ancien) {
                DB::table('password_history')->insert([
                    'user_id' => $id, 'password_hash' => $ancien,
                ]);
                $garder = self::HISTORIQUE * 2;
                $ids = DB::table('password_history')->where('user_id', $id)
                    ->orderByDesc('changed_at')->limit($garder)->pluck('id')->all();
                if ($ids !== []) {
                    DB::table('password_history')->where('user_id', $id)
                        ->whereNotIn('id', $ids)->delete();
                }
            }
            DB::table('users')->where('id', $id)->update([
                'password' => password_hash($mdp, PASSWORD_BCRYPT, ['cost' => $this->cout()]),
                'force_password_change' => $forceChangement ? 1 : 0,
            ]);
        });

        return null;
    }

    /**
     * Un mot de passe genere qui SATISFAIT la politique.
     *
     * L'alphabet du legacy (`crypto.php:253`) contient `<` et `>`, et son message
     * de succes traverse `strip_tags` : un mot de passe contenant `<` est AMPUTE
     * a l'affichage (E-113). Ici l'alphabet exclut les caracteres de balisage —
     * non pour se proteger d'une injection, mais parce qu'un secret ne doit pas
     * dependre de ce qu'un filtre d'affichage voudra bien en laisser.
     */
    public function genereMotDePasse(int $longueur = 20): string
    {
        $minuscules = 'abcdefghijkmnopqrstuvwxyz';
        $majuscules = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        $chiffres = '23456789';
        $symboles = '!@#%^*()-_=+[]{}:,.?';
        $tout = $minuscules . $majuscules . $chiffres . $symboles;

        // Une de chaque classe D'ABORD : un tirage uniforme peut, rarement, ne
        // produire aucun symbole — et le mot de passe genere serait alors refuse
        // par notre propre politique.
        $car = [
            $minuscules[random_int(0, strlen($minuscules) - 1)],
            $majuscules[random_int(0, strlen($majuscules) - 1)],
            $chiffres[random_int(0, strlen($chiffres) - 1)],
            $symboles[random_int(0, strlen($symboles) - 1)],
        ];
        for ($i = count($car); $i < max($longueur, self::LONGUEUR_MINIMALE); $i++) {
            $car[] = $tout[random_int(0, strlen($tout) - 1)];
        }
        // Melange a tirage sur : `shuffle()` n'emploie pas un generateur
        // cryptographique.
        for ($i = count($car) - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            [$car[$i], $car[$j]] = [$car[$j], $car[$i]];
        }

        return implode('', $car);
    }

    /* ═══ Clé SSH — un seul ecrivain, et il valide ══════════════════════════ */

    /**
     * Valide la FORME d'une cle publique : algorithme dans la liste fermee, corps
     * en base64, commentaire libre. Refuse tout ce qui precede l'algorithme —
     * c'est la que vivent les options d'`authorized_keys` (`command=`, `from=`,
     * `no-pty`), qui changent le sens de la ligne deployee.
     *
     * @return string|null la cle du message d'erreur, ou null si la forme est bonne
     */
    public function verifieCleSsh(string $cle): ?string
    {
        $cle = trim($cle);
        if ($cle === '') {
            return null; // une cle vide efface la cle : c'est un geste valide
        }
        if (str_contains($cle, "\n") || str_contains($cle, "\r")) {
            return 'comptes.err_cle_lignes';
        }
        $morceaux = preg_split('/\s+/', $cle);
        if (count($morceaux) < 2) {
            return 'comptes.err_cle_forme';
        }
        if (! in_array($morceaux[0], self::ALGOS_SSH, true)) {
            return 'comptes.err_cle_algo';
        }
        if (preg_match('#^[A-Za-z0-9+/]+={0,2}$#', $morceaux[1]) !== 1) {
            return 'comptes.err_cle_base64';
        }

        return null;
    }

    /**
     * L'UNIQUE ecriture de la cle SSH. Stockee TELLE QUELLE — l'echappement
     * appartient au rendu. Le legacy a trois ecrivains, dont un qui applique
     * `htmlspecialchars` a l'ecriture (E-115).
     */
    public function definitCleSsh(int $id, string $cle): ?string
    {
        if (($err = $this->verifieCleSsh($cle)) !== null) {
            return $err;
        }
        $cle = trim($cle);
        DB::table('users')->where('id', $id)->update([
            'ssh_key' => $cle === '' ? null : $cle,
            'ssh_key_updated_at' => now(),
        ]);

        return null;
    }

    /* ═══ Etats du compte ══════════════════════════════════════════════════ */

    /** Un compte verrouille se deverrouille : compteur a zero, verrou leve. */
    public function deverrouille(int $id): void
    {
        DB::table('users')->where('id', $id)
            ->update(['failed_attempts' => 0, 'locked_until' => null]);
        $nom = DB::table('users')->where('id', $id)->value('name');
        if ($nom) {
            DB::table('login_attempts')->where('username', $nom)->where('success', 0)->delete();
        }
    }

    /**
     * Reinitialise le second facteur : le secret est efface, la personne devra
     * s'enroler a nouveau. GARDE HIERARCHIQUE reprise du legacy
     * (`manage_roles.php:111`) : un role 2 ne touche pas un role 3.
     */
    public function reinitialiseTotp(int $id): void
    {
        DB::table('users')->where('id', $id)->update(['totp_secret' => null]);
    }

    public function porteUnSecondFacteur(int $id): bool
    {
        $secret = DB::table('users')->where('id', $id)->value('totp_secret');

        return $secret !== null && $secret !== '';
    }

    /* ═══ Suppression et anonymisation — sous-lot D4 ═══════════════════════ */

    /**
     * Combien de lignes de journal ce compte porte-t-il ?
     *
     * C'est la question qui decide du geste. `user_logs.user_id` est en
     * **ON DELETE CASCADE** — mesure du 2026-08-26 dans `information_schema` :
     * 34 cles etrangeres pointent vers `users`, douze en cascade, et celle-ci en
     * fait partie. Supprimer un compte efface donc son journal, et comme le
     * sous-lot D1 a rendu ce journal VERIFIABLE — chaque ligne chainee a la
     * precedente —, en retirer du milieu ROMPT la chaine.
     *
     * Voir PARITE E-116.
     */
    public function journauxDe(int $id): int
    {
        return (int) DB::table('user_logs')->where('user_id', $id)->count();
    }

    /**
     * Un compte est-il supprimable sans dommage ?
     *
     * Oui s'il ne porte aucune ligne de journal — un compte fraichement cree est
     * dans ce cas, `audit_log` ecrivant toujours avec l'identifiant de l'AUTEUR
     * et jamais de la cible. Sinon, l'anonymisation est le geste juste : elle
     * efface les donnees personnelles et PRESERVE le journal.
     */
    public function supprimableSansPerte(int $id): bool
    {
        return $this->journauxDe($id) === 0;
    }

    /**
     * Les refus communs aux deux gestes, dans l'ordre du legacy
     * (`delete_user.php:69-97`) : soi-meme, hierarchie, dernier role 3.
     *
     * @return string|null la cle du message de refus, ou null si le geste est permis
     */
    public function refusePourquoi(int $id, int $auteur, int $roleAuteur): ?string
    {
        if ($id === $auteur) {
            return 'comptes.err_soi_meme';
        }
        $cible = $this->trouve($id);
        if (! $cible) {
            return 'comptes.err_inconnu';
        }
        // Un role ne touche que des roles STRICTEMENT inferieurs. Repris tel
        // quel : deux administrateurs compromis pourraient sinon se purger.
        if ((int) $cible['role_id'] >= $roleAuteur) {
            return 'comptes.err_rang';
        }
        if ((int) $cible['role_id'] === 3 && $this->superadminsActifs() <= 1) {
            return 'comptes.err_dernier_sa';
        }

        return null;
    }

    /**
     * Supprime un compte. Les cles etrangeres font le reste — et c'est bien le
     * probleme : la cascade manuelle du legacy (`delete_user.php:104-113`) est du
     * CODE MORT, les deux tables qu'il supprime explicitement etant deja parties
     * avec la premiere ligne.
     *
     * L'appelant doit avoir verifie `supprimableSansPerte()`. On le REVERIFIE
     * ici : une garde qui n'existe qu'a l'appel n'est pas une garde.
     */
    public function supprime(int $id): ?string
    {
        if (! $this->supprimableSansPerte($id)) {
            return 'comptes.err_journal_present';
        }
        DB::table('users')->where('id', $id)->delete();

        return null;
    }

    /**
     * Anonymise un compte : les donnees personnelles sont effacees, le JOURNAL
     * EST CONSERVE. C'est le geste que le legacy porte, commente, garde — et
     * qu'aucun element de son interface n'appelle (PARITE E-117).
     *
     * Ce qui part : sessions, jetons, preferences, permissions, acces machines.
     * Ce qui reste : `user_logs` et `login_history`, pour la tracabilite.
     */
    public function anonymise(int $id): void
    {
        $marque = 'compte-anonymise-' . $id;
        DB::transaction(function () use ($id, $marque): void {
            DB::table('users')->where('id', $id)->update([
                'name' => $marque,
                'email' => null,
                'company' => null,
                'ssh_key' => null,
                'ssh_key_updated_at' => null,
                'totp_secret' => null,
                'active' => 0,
                // Un hache de 64 octets aleatoires : le compte ne peut plus
                // servir, et aucun clair n'existe pour y entrer.
                'password' => password_hash(bin2hex(random_bytes(32)), PASSWORD_BCRYPT,
                    ['cost' => $this->cout()]),
            ]);
            foreach (['active_sessions', 'remember_tokens', 'password_history',
                      'notification_preferences', 'permissions', 'user_machine_access'] as $table) {
                DB::table($table)->where('user_id', $id)->delete();
            }
            // `user_logs` et `login_history` ne sont PAS touches : c'est tout
            // l'objet de ce geste.
        });
    }

    /** @return int le nombre de comptes de role 3 encore ACTIFS */
    public function superadminsActifs(): int
    {
        return (int) DB::table('users')->where('role_id', 3)->where('active', 1)->count();
    }
}
