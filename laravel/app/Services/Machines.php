<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

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
     * LES MACHINES ARCHIVEES SONT EXCLUES, comme le fait `/filter_servers`, qui
     * sert les relectures de la meme page. Sans ce filtre les deux sources ne
     * montraient pas le meme parc : une machine archivee s'affichait au premier
     * rendu, etait cochable, pouvait recevoir un `apt full-upgrade` ou un
     * redemarrage — puis disparaissait sans un mot au premier « Rafraichir »,
     * le nombre de lignes changeant tout seul. Le rendu est commun aux deux
     * sources ; les DONNEES doivent l'etre aussi.
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
            )->where(function ($q) {
                $q->whereNull('m.lifecycle_status')
                  ->orWhere('m.lifecycle_status', '!=', 'archived');
            });

            if ($roleId < 2) {
                $requete->join('user_machine_access as uma', 'm.id', '=', 'uma.machine_id')
                        ->where('uma.user_id', $userId);
            }

            return $requete->orderBy('m.name')->get()->all();
        } catch (\Throwable $e) {
            // Une base injoignable rend EXACTEMENT le meme ecran qu'un parc vide,
            // texte d'aide compris. L'ancien commentaire pretendait le contraire
            // (« son indisponibilite se voit ») : elle ne se voyait pas, et rien
            // n'en gardait trace. Au moins la journaliser.
            Log::error('[Machines::pourMisesAJour] parc illisible : ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Le parc VU PAR CE COMPTE, et le parc entier — les deux, jamais l'un seul.
     *
     * ══ E-208 : LE TABLEAU DE BORD DU LEGACY NE CLOISONNE PAS ════════════
     *
     * `legacy/index.php` sert la taille du parc a tout le monde, sans filtrer
     * selon les machines auxquelles le compte a acces. Porter fidelement
     * reproduirait la fuite ; porter borne sans rien dire retirerait une
     * visibilite. L'arbitrage rendu est : **borner, ET dire le total.**
     *
     * D'ou DEUX nombres. « 1 de vos machines » seul laisserait croire que le
     * parc en compte une ; « 3 au parc » seul serait la fuite. Ensemble, ils
     * disent la borne sans la cacher : un compte qui ne voit qu'une machine sur
     * trois DOIT savoir que le parc en compte trois, sinon le tableau de bord
     * mentirait par omission au lieu de fuir.
     *
     * Le predicat de bornage est celui de `pourMisesAJour` ci-dessus, et celui
     * d'`Iptables::machines` et `Fail2ban::machines` : role >= 2 voit le parc,
     * role 1 est joint a `user_machine_access`. On le REPREND, on ne le
     * reinvente pas — trois implementations d'une meme regle finissent par
     * diverger.
     *
     * Cout mesure de la borne : un seul compte reel la subit, et les deux
     * machines qu'il cesse de voir sont deux machines auxquelles il n'a aucun
     * acces.
     *
     * @return array{perimetre:int,parc:int,borne:bool,lisible:bool}
     */
    public function compteursPerimetre(int $roleId, int $userId): array
    {
        $actives = function ($q) {
            $q->whereNull('m.lifecycle_status')
              ->orWhere('m.lifecycle_status', '!=', 'archived');
        };

        try {
            $parc = DB::table('machines as m')->where($actives)->count();

            if ($roleId >= 2) {
                // Pas de jointure : le perimetre EST le parc. Le dire ainsi
                // evite un compte redondant et rend `borne` faux, ce qui permet
                // a l'ecran de ne pas afficher une reserve sans objet.
                return ['perimetre' => $parc, 'parc' => $parc, 'borne' => false, 'lisible' => true];
            }

            $perimetre = DB::table('machines as m')
                ->join('user_machine_access as uma', 'm.id', '=', 'uma.machine_id')
                ->where('uma.user_id', $userId)
                ->where($actives)
                ->count();

            return [
                'perimetre' => $perimetre,
                'parc'      => $parc,
                'borne'     => true,
                'lisible'   => true,
            ];
        } catch (\Throwable $e) {
            // UNE BASE INJOIGNABLE N'EST PAS UN PARC VIDE. Rendre des zeros
            // afficherait « 0 de vos machines · 0 au parc », ce qui se lit comme
            // un fait. `lisible` a faux laisse l'ecran DIRE qu'il n'a pas su
            // lire — c'est le defaut que le commentaire de `pourMisesAJour`
            // signale juste au-dessus, et qu'on ne refait pas ici.
            Log::error('[Machines::compteursPerimetre] parc illisible : ' . $e->getMessage());

            return ['perimetre' => 0, 'parc' => 0, 'borne' => false, 'lisible' => false];
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
