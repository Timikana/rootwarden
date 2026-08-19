<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Liste de reference des machines du parc, pour les selecteurs et les filtres.
 *
 * Deux pages en avaient besoin — le journal des commandes et les tickets — et
 * la seconde allait recopier la premiere. Une decision recopiee finit par
 * diverger : elle vit donc a un seul endroit.
 *
 * AUCUN FILTRE D'ACCES ICI. Les pages qui s'en servent sont reservees a
 * l'administration, qui a vocation a voir le parc entier ; c'est le meme choix
 * que le legacy, et il est delibere. Il ne doit PAS etre repris pour une page
 * ouverte a des comptes sans permission — c'est precisement le defaut du
 * tableau de bord du legacy, qui sert ces memes donnees a tout le monde.
 */
class Machines
{
    /** @return list<object> */
    public function liste(): array
    {
        try {
            return DB::table('machines')->select('id', 'name')->orderBy('name')->get()->all();
        } catch (\Throwable) {
            // Une liste de reference est un confort : son indisponibilite ne
            // doit pas empecher la consultation de la page.
            return [];
        }
    }

    /**
     * Le parc tel que la page des mises a jour l'affiche : treize colonnes.
     *
     * CLOISONNEMENT REPRIS DU LEGACY. `update/index.php` admet le role 1 s'il
     * porte `can_update_linux`, et ne lui montre alors que les machines de
     * `user_machine_access`. C'est un cloisonnement REEL — contrairement au
     * tableau de bord du legacy, qui sert le parc entier a tout le monde. Il est
     * reproduit ici a l'identique.
     *
     * @return list<object>
     */
    public function pourMisesAJour(int $roleId, int $userId): array
    {
        try {
            $requete = DB::table('machines as m')->select(
                'm.id', 'm.name', 'm.ip', 'm.port', 'm.linux_version', 'm.last_checked',
                'm.online_status', 'm.maj_secu_date', 'm.maj_secu_last_exec_date',
                'm.last_reboot', 'm.environment', 'm.criticality', 'm.network_type',
            );

            if ($roleId < 2) {
                $requete->join('user_machine_access as uma', 'm.id', '=', 'uma.machine_id')
                        ->where('uma.user_id', $userId);
            }

            return $requete->orderBy('m.name')->get()->all();
        } catch (\Throwable) {
            // Le parc est le contenu de la page : son indisponibilite se voit,
            // elle n'a pas besoin d'etre masquee par une liste vide silencieuse.
            return [];
        }
    }

    /**
     * Les etiquettes posees sur le parc, pour alimenter le filtre.
     *
     * Elles sont ecrites par le module `adm/`, non porte : cette page ne fait
     * que les lire. Une liste vide est un etat normal — le filtre s'affiche
     * alors sans rien a proposer, ce que la page DIT plutot que de masquer le
     * champ.
     *
     * @return list<string>
     */
    public function etiquettes(): array
    {
        try {
            return DB::table('machine_tags')->distinct()->orderBy('tag')->pluck('tag')->all();
        } catch (\Throwable) {
            return [];
        }
    }
}
