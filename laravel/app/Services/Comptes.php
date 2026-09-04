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

    /**
     * Les colonnes EXIGEES par l'import de comptes.
     *
     * ⚠ `email` est exigee ici alors que le legacy la laisse FACULTATIVE
     * (`import_csv.php:159`, `trim($data['email'] ?? '')`). C'est une divergence
     * VOULUE : un compte importe sans adresse et sans mot de passe connu n'a ni
     * acces ni recuperation — le legacy en fabriquait en serie (E-131). Le
     * portage exige donc l'adresse ET rend le mot de passe genere une fois.
     *
     * `role`, `ssh_key`, `active` et `sudo` restent facultatives, comme dans le
     * legacy.
     */
    public const IMPORT_COLONNES = ['name', 'email'];

    /** Le plafond que le legacy n'a pas. Ce qui depasse est DIT, pas tronque en silence. */
    public const IMPORT_MAX_LIGNES = 500;

    /**
     * La table des roles du CSV — LISTE FERMEE, reprise du legacy
     * (`import_csv.php:150`). Un nom inconnu ne cree pas un compte privilegie :
     * il retombe sur le role le plus faible. **Pas d'entree libre a valider,
     * donc pas d'entree libre.**
     */
    public const IMPORT_ROLES = ['user' => 1, 'admin' => 2, 'superadmin' => 3];

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

    /**
     * Les trois indicateurs de COMPTES du tableau de bord, bornes par ROLE.
     *
     * ══ POURQUOI PAR ROLE ET NON PAR PERIMETRE ═══════════════════════════
     *
     * L'arbitrage `DECISIONS-DSI.md` §1 borne cette page « au perimetre du
     * compte ». **Cette borne n'a aucun sens pour un compteur de comptes** : un
     * perimetre de MACHINES ne borne pas une population d'utilisateurs. Ces
     * trois-la se bornent donc par role, et l'arbitrage ne le disait pas —
     * decision n°12.
     *
     * ══ `sans_2fa` EST RESERVE AU ROLE 3, ET CE N'EST PAS DE LA PUDEUR ═══
     *
     * Mesure du 2026-09-01 : **8 comptes actifs sur 12 sont sans second
     * facteur.** Le legacy affiche ce nombre des le role 1.
     *
     * Ce n'est pas un chiffre genant, c'est **une carte de la surface
     * d'attaque** : un role 1 compromis apprend que les deux tiers des comptes
     * s'attaquent sans second facteur. Directement actionnable pour un
     * attaquant, d'aucune utilite pour lui-meme.
     *
     * **Et le geler ne coute rien** : la page porte deja une tuile qui dit a
     * chaque compte SON PROPRE etat (`accueil.securite_*`). *Une information sur
     * ses propres limites n'est pas une information sur des objets.* « Votre
     * compte n'a pas de second facteur » est actionnable et ne fuit rien ;
     * « 8 comptes n'en ont pas » est une liste de cibles.
     *
     * ══ `null` N'EST PAS `0` ═════════════════════════════════════════════
     *
     * Une valeur `null` veut dire « pas montre a ce role », jamais « zero ». Le
     * gel vit ICI, avec la donnee, pour qu'un second appelant ne puisse pas
     * l'oublier — une garde posee dans la vue serait a reecrire a chaque vue.
     *
     * ══ LA REGLE DU SECOND FACTEUR EST REPRISE, PAS REECRITE ═════════════
     *
     * `porteUnSecondFacteur()` ci-dessous decide par `!== null && !== ''`. Le
     * predicat SQL est le meme, ecrit une fois.
     *
     * RESERVE MESUREE : ce test porte sur les OCTETS de la colonne. Les colonnes
     * chiffrees de ce produit ont deja rendu « non vide » pour une valeur
     * reellement vide (PHP chiffre `''` en `sodium:…`). Verifie le 2026-09-01
     * **par les seules longueurs, sans dechiffrer aucun secret vivant** : 136
     * (x3) et 204 (x1), aucune proche d'un chiffre de chaine vide (~63 octets
     * sur la meme famille). Le compte est donc exact aujourd'hui. **Le jour ou
     * une longueur courte apparaitra, il SOUS-ESTIMERA** — la mauvaise direction
     * pour un indicateur de securite.
     *
     * @return array{lisible:bool,actifs:?int,sans_cle:?int,sans_2fa:?int}
     */
    public function indicateursComptes(int $roleId): array
    {
        if ($roleId < 2) {
            // Rien n'est lu : un role 1 ne declenche meme pas la requete.
            return ['lisible' => true, 'actifs' => null, 'sans_cle' => null, 'sans_2fa' => null];
        }

        try {
            $actifs = DB::table('users')->where('active', 1);

            $sansCle = DB::table('users')->where('active', 1)
                ->where(function ($q) {
                    $q->whereNull('ssh_key')->orWhere('ssh_key', '');
                })->count();

            return [
                'lisible'  => true,
                'actifs'   => (clone $actifs)->count(),
                'sans_cle' => $sansCle,
                'sans_2fa' => $roleId >= 3
                    ? DB::table('users')->where('active', 1)
                        ->where(function ($q) {
                            $q->whereNull('totp_secret')->orWhere('totp_secret', '');
                        })->count()
                    : null,
            ];
        } catch (\Throwable $e) {
            // UNE LECTURE ECHOUEE N'EST PAS « AUCUN COMPTE ». Zero se lirait
            // comme un fait, et « 0 compte sans second facteur » est exactement
            // ce qu'on aimerait croire.
            \Illuminate\Support\Facades\Log::error(
                '[Comptes::indicateursComptes] lecture impossible : ' . $e->getMessage()
            );

            return ['lisible' => false, 'actifs' => null, 'sans_cle' => null, 'sans_2fa' => null];
        }
    }

    /*
     * ══ LES CLES DE COMPTE DE PLUS DE 90 JOURS — SANS NOMMER PERSONNE ═══
     *
     * E-264. `legacy/index.php:119-126` fait deux choses de trop :
     *
     *  1. il NOMME jusqu'a cinq comptes et l'age de leur cle, dans le message
     *     ET dans l'attribut `title=` du rendu (`:213`) — deux endroits pour la
     *     meme divulgation. Une alerte n'a pas besoin de nommer pour etre
     *     actionnable : le lien vers la page des comptes y mene, et cette page
     *     a ses propres droits ;
     *
     *  2. il COMPTE FAUX, et c'est une consequence du point 1. Sa requete porte
     *     `LIMIT 5` — posee pour ne recuperer que cinq noms — puis il fait
     *     `$oldKeys = count($oldKeysData)`. Le nombre annonce est donc plafonne
     *     a 5 : quarante comptes concernes s'affichent « 5 ». Retirer la liste
     *     nominative retire aussi le `LIMIT`, donc corrige le nombre. Les deux
     *     defauts n'en font qu'un.
     *
     * Meme gel de role que `indicateursComptes` : au-dessous de 2 rien n'est
     * lu, et `null` dit « ce role n'a pas a le voir » — pas « aucun ».
     * `ssh_key` est une cle PUBLIQUE, stockee en clair : le test `<> ''` mesure
     * donc bien une presence ici, contrairement aux colonnes chiffrees.
     */
    public function alertesCles(int $roleId): array
    {
        if ($roleId < 2) {
            return ['lisible' => true, 'cles_anciennes' => null];
        }

        try {
            $n = DB::table('users')
                ->where('active', 1)
                ->whereNotNull('ssh_key')
                ->where('ssh_key', '<>', '')
                ->whereNotNull('ssh_key_updated_at')
                ->where('ssh_key_updated_at', '<', now()->subDays(90))
                ->count();

            return ['lisible' => true, 'cles_anciennes' => $n];
        } catch (\Throwable $e) {
            \Illuminate\Support\Facades\Log::error(
                '[Comptes::alertesCles] lecture impossible : ' . $e->getMessage()
            );

            return ['lisible' => false, 'cles_anciennes' => null];
        }
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
    /**
     * Le role qu'un auteur est REELLEMENT autorise a poser, et s'il a ete abaisse.
     *
     * ══ UNE SEULE IMPLEMENTATION, DEUX APPELANTS ══════════════════════════
     *
     * La creation unitaire (`ComptesController::creer`) et l'import CSV posent
     * la meme regle. La recopier en donnerait deux versions qui divergeraient :
     * le LEGACY en porte TROIS (`manage_users:92`, `manage_roles:154`,
     * `import_csv:156`) et elles n'ont deja pas la meme forme — deux annoncent
     * la coercition, la troisieme est muette.
     *
     * LA REGLE, reprise de `manage_users.php:92` : un non-superadministrateur ne
     * pose qu'un role STRICTEMENT INFERIEUR au sien. Le commentaire du legacy dit
     * l'incident qui l'a fait ecrire — quelqu'un *« creait un superadmin,
     * recevait le magic-link sur son email et prenait le controle »*.
     *
     * ⚠ La liste fermee `ROLES` borne a des valeurs VALIDES ; celle-ci borne a
     * des valeurs PERMISES. Ce sont deux proprietes, et E-385 vient de ce que
     * seule la premiere etait verifiee.
     *
     * @return array{0: int, 1: bool} le role effectif, et s'il a ete abaisse
     */
    public function roleAutorise(int $demande, int $roleAuteur): array
    {
        $role = in_array($demande, self::ROLES, true) ? $demande : 1;
        if ($roleAuteur < 3 && $role >= $roleAuteur) {
            return [1, true];
        }

        return [$role, false];
    }

    /**
     * Importe des comptes depuis un CSV. Rend le bilan ET les secrets generes.
     *
     * ══ POURQUOI LES SECRETS SORTENT A PART ═══════════════════════════════
     *
     * Chaque compte cree recoit un mot de passe genere que PERSONNE ne connait
     * encore. Le legacy le jette (`import_csv.php:148`) : ses comptes importes
     * sont inutilisables, sans acces ni recuperation (E-131). Ici il est rendu a
     * l'appelant, qui l'affichera UNE FOIS — et il ne doit transiter par aucun
     * stockage, donc ni par le bilan qu'on pourrait flasher en session, ni par
     * le journal d'audit, ni par le compte-rendu par ligne.
     *
     * @return array{bilan: array<string, mixed>, secrets: list<array{nom: string, mdp: string}>}
     */
    public function importeCsv(string $chemin, int $roleAuteur): array
    {
        $bilan = ['lignes' => 0, 'crees' => 0, 'manquantes' => [], 'tronque' => false, 'erreurs' => []];
        $secrets = [];

        $flux = @fopen($chemin, 'r');
        if ($flux === false) {
            $bilan['erreurs'][] = ['ligne' => 0, 'nom' => '', 'texte' => __('comptes.imp_err_illisible')];

            return ['bilan' => $bilan, 'secrets' => $secrets];
        }

        try {
            $entete = fgetcsv($flux);
            if ($entete === false || $entete === [null]) {
                $bilan['erreurs'][] = ['ligne' => 0, 'nom' => '', 'texte' => __('comptes.imp_err_vide')];

                return ['bilan' => $bilan, 'secrets' => $secrets];
            }
            $entete = array_map(static fn ($c) => mb_strtolower(trim((string) $c)), $entete);

            $manquantes = array_values(array_diff(self::IMPORT_COLONNES, $entete));
            if ($manquantes !== []) {
                $bilan['manquantes'] = $manquantes;

                return ['bilan' => $bilan, 'secrets' => $secrets];
            }

            $ligne = 1;
            while (($brut = fgetcsv($flux)) !== false) {
                if ($brut === [null]) {      // ligne vide : fgetcsv rend [null]
                    continue;
                }
                $ligne++;
                if ($bilan['lignes'] >= self::IMPORT_MAX_LIGNES) {
                    $bilan['tronque'] = true;
                    break;
                }
                $bilan['lignes']++;
                $this->importeUnCompte($entete, $brut, $ligne, $roleAuteur, $bilan, $secrets);
            }
        } finally {
            fclose($flux);
        }

        return ['bilan' => $bilan, 'secrets' => $secrets];
    }

    /**
     * Une ligne. Tout refus s'inscrit dans `erreurs` AVEC son numero de ligne :
     * un import qui cree 8 comptes sur 10 sans dire lesquels ont echoue se lit
     * comme une reussite.
     *
     * @param  list<string>  $entete
     * @param  list<string|null>  $brut
     */
    private function importeUnCompte(
        array $entete, array $brut, int $ligne, int $roleAuteur,
        array &$bilan, array &$secrets,
    ): void {
        $data = [];
        foreach ($entete as $i => $col) {
            $data[$col] = trim((string) ($brut[$i] ?? ''));
        }

        $nom = $data['name'] ?? '';
        if ($nom === '' || mb_strlen($nom) > 255) {
            $bilan['erreurs'][] = ['ligne' => $ligne, 'nom' => $nom, 'texte' => __('comptes.err_nom')];

            return;
        }
        if (DB::table('users')->where('name', $nom)->exists()) {
            $bilan['erreurs'][] = ['ligne' => $ligne, 'nom' => $nom, 'texte' => __('comptes.imp_doublon')];

            return;
        }
        $courriel = filter_var($data['email'] ?? '', FILTER_VALIDATE_EMAIL);
        if ($courriel === false) {
            $bilan['erreurs'][] = ['ligne' => $ligne, 'nom' => $nom, 'texte' => __('comptes.imp_err_courriel')];

            return;
        }

        [$role, $rangRamene] = $this->roleAutorise(
            self::IMPORT_ROLES[mb_strtolower($data['role'] ?? 'user')] ?? 1,
            $roleAuteur,
        );

        /*
         * `sudo` EXIGE LE ROLE 3, ET LA COERCITION SE DIT.
         *
         * Le legacy ecrit `users.sudo` depuis le CSV sans AUCUN controle de role
         * (`import_csv.php:162,166`), alors que son geste dedie
         * (`api/toggle_sudo.php:26`) exige `ROLE_SUPERADMIN` et refuse meme de
         * modifier son propre sudo. C'est E-130.
         *
         * On coerce a 0 et on le DIT par ligne : un importeur qui croit avoir
         * accorde sudo et ne l'a pas accorde prendra la decision suivante sur une
         * croyance fausse.
         */
        $sudoDemande = ($data['sudo'] ?? '') !== '' && (int) $data['sudo'] === 1;
        $sudo = ($sudoDemande && $roleAuteur >= 3) ? 1 : 0;

        $mdp = $this->genereMotDePasse();
        try {
            DB::table('users')->insert([
                'name' => $nom,
                'email' => $courriel,
                // `cout()` et non un `config()` recopie : ce service porte deja
                // le cout, « lu la ou le legacy le lit » dit son commentaire.
                'password' => password_hash($mdp, PASSWORD_BCRYPT, ['cost' => $this->cout()]),
                'ssh_key' => ($data['ssh_key'] ?? '') !== '' ? $data['ssh_key'] : null,
                'role_id' => $role,
                'active' => ($data['active'] ?? '') === '' ? 1 : (int) $data['active'],
                'sudo' => $sudo,
                /*
                 * ⚠ `force_password_change` A 1 — ET C'EST UNE CORRECTION DE MON
                 * PROPRE COMMIT D'HIER (E-386).
                 *
                 * J'avais ecrit ici « PAS de force_password_change », au motif
                 * que forcer un changement sans canal de delivrance fabriquerait
                 * un compte inaccessible. **Ce motif etait juste du cas ou
                 * PERSONNE ne connait le mot de passe. Il est faux ici** : le
                 * mot de passe genere est REMIS a l'importeur, donc il est
                 * connu, transmis, et la personne peut se connecter puis le
                 * changer — `/profil` et `/profil/mot-de-passe` sont les DEUX
                 * exemptions de `ChangementMotDePasseExige`, et
                 * `changerMotDePasse` n'exige que le mot de passe ACTUEL.
                 *
                 * **Et un mot de passe qui a transite par l'ecran d'un tiers,
                 * puis par un courriel ou une conversation, ne doit pas rester
                 * celui du compte.** *Le laisser vivre indefiniment etait le
                 * defaut symetrique de celui que ce meme arbitrage corrigeait
                 * sur la creation manuelle.*
                 */
                'force_password_change' => 1,
                /*
                 * AUCUNE ligne dans `permissions` : `Permissions::pour()` traite
                 * l'absence comme « aucun droit », et `definit()` en cree une au
                 * premier reglage. Le legacy insere 15 colonnes NOMMEES a zero —
                 * une liste qui omettrait silencieusement une permission ajoutee
                 * apres coup, alors que `Permissions::toutes()` lit le SCHEMA.
                 */
            ]);
        } catch (\Throwable $e) {
            $bilan['erreurs'][] = ['ligne' => $ligne, 'nom' => $nom, 'texte' => __('comptes.imp_err_ecriture')];

            return;
        }

        $bilan['crees']++;
        // LE SECRET NE VA QUE LA. Ni dans `erreurs`, ni dans le journal.
        $secrets[] = ['nom' => $nom, 'mdp' => $mdp];
        if ($rangRamene) {
            $bilan['erreurs'][] = ['ligne' => $ligne, 'nom' => $nom, 'texte' => __('comptes.imp_rang_ramene')];
        }
        if ($sudoDemande && $sudo === 0) {
            $bilan['erreurs'][] = ['ligne' => $ligne, 'nom' => $nom, 'texte' => __('comptes.imp_sudo_refuse')];
        }
    }

    public function superadminsActifs(): int
    {
        return (int) DB::table('users')->where('role_id', 3)->where('active', 1)->count();
    }
}
