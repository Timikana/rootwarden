<?php

namespace App\Console\Commands;

use App\Services\Comptes;
use App\Services\JournalAudit;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

/**
 * Crée le PREMIER compte superadministrateur d'une installation neuve.
 *
 * ══ CE QUI MANQUAIT — audit du 2026-10-13, H-5 ════════════════════════════
 *
 * `mysql/init.sql:229` insère un compte `superadmin` dont le mot de passe est
 * le littéral `$PLACEHOLDER$` — PAS un hachage bcrypt : aucune connexion n'est
 * possible. C'est `legacy/_deprecated/php/install.sh:94-95` qui le remplaçait au
 * premier démarrage (`UPDATE users SET password = ?, force_password_change = 1`).
 * Archivé avec le legacy, il n'avait aucun remplaçant : une installation neuve
 * — ou une reconstruction après sinistre — n'offrait AUCUN chemin vers une
 * première connexion.
 *
 * Cette commande en est le portage : elle donne un vrai mot de passe au compte
 * encore factice, ou crée le compte s'il n'existe pas.
 *
 * ══ POURQUOI ELLE EST INOFFENSIVE SUR UNE INSTALLATION EN SERVICE ═════════
 *
 * Elle REFUSE d'agir dès qu'un superadministrateur ACTIF portant un VRAI mot de
 * passe existe (un compte encore à `$PLACEHOLDER$` ne compte pas : personne ne
 * peut s'y connecter). Ce n'est pas
 * un outil de récupération de compte : un superadmin qui a perdu son accès en
 * fait réinitialiser un autre depuis le portail. Elle ne sert qu'à amorcer.
 *
 * Le mot de passe est généré par `Comptes::genereMotDePasse()` — donc conforme
 * à la politique —, affiché UNE fois, et `force_password_change` vaut 1 : il a
 * transité par un terminal, il ne doit pas rester celui du compte. Le compte
 * n'a pas de secret TOTP : le portail impose l'enrôlement du second facteur à
 * la première connexion.
 *
 * Usage, sur l'hôte :
 *     docker exec -u www-data rootwarden_laravel php artisan rootwarden:premier-compte
 */
class PremierCompte extends Command
{
    protected $signature = 'rootwarden:premier-compte {nom=superadmin : identifiant du compte}';

    protected $description = 'Cree le premier compte superadministrateur (refuse si un superadmin actif existe)';

    /** Le mot de passe factice posé par `mysql/init.sql:229`. */
    public const FACTICE = '$PLACEHOLDER$';

    /** Même forme que les identifiants acceptés ailleurs dans le portail. */
    private const NOM_VALIDE = '/^[A-Za-z0-9._-]{3,50}$/';

    public function handle(Comptes $comptes, JournalAudit $journal): int
    {
        $nom = (string) $this->argument('nom');

        if (! preg_match(self::NOM_VALIDE, $nom)) {
            $this->error("Identifiant refuse : 3 a 50 caracteres parmi lettres, chiffres, point, tiret, souligne.");

            return self::INVALID;
        }

        $utilisables = DB::table('users')->where('role_id', 3)->where('active', 1)
            ->where('password', '!=', self::FACTICE)->count();
        if ($utilisables > 0) {
            $this->error("Refuse : {$utilisables} superadministrateur(s) actif(s) existe(nt) deja. "
                . 'Cette commande ne sert qu\'a amorcer une installation neuve.');

            return self::FAILURE;
        }

        $existant = DB::table('users')->where('name', $nom)->first();
        if ($existant && $existant->password !== self::FACTICE) {
            $this->error("Refuse : un compte nomme '{$nom}' existe deja (inactif ou d'un autre role).");

            return self::FAILURE;
        }

        $mdp = $comptes->genereMotDePasse();
        $hache = password_hash($mdp, PASSWORD_BCRYPT, ['cost' => (int) config('rootwarden.bcrypt_cost', 12)]);

        if ($existant) {
            // Le compte factice d'`init.sql` : on lui donne un vrai mot de passe,
            // exactement comme `install.sh:94-95`. Il est (re)mis superadmin actif.
            DB::table('users')->where('id', $existant->id)->update([
                'password' => $hache,
                'role_id' => 3,
                'active' => 1,
                'force_password_change' => 1,
            ]);
            $id = (int) $existant->id;
            $geste = 'Mot de passe initial pose sur le compte factice';
        } else {
            $id = (int) DB::table('users')->insertGetId([
                'name' => $nom,
                'password' => $hache,
                'role_id' => 3,
                'active' => 1,
                'sudo' => 0,
                'force_password_change' => 1,
            ]);
            $geste = 'Creation du premier compte superadmin';
        }

        $journal->ajoute($id, "{$geste} '{$nom}' (console, amorcage)");

        $this->info("Compte superadministrateur '{$nom}' pret.");
        $this->line('');
        $this->line("  Mot de passe initial : {$mdp}");
        $this->line('');
        $this->warn('Il n\'est affiche qu\'une fois. Il devra etre change a la premiere connexion,');
        $this->warn('et le second facteur (TOTP) sera enrole a ce moment-la.');

        return self::SUCCESS;
    }
}
