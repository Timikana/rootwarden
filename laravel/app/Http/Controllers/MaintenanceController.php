<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;
use Illuminate\View\View;

/**
 * Fenetres de maintenance : les plages ou les actions mutantes sont autorisees.
 *
 * Les gestes de la page — lire, creer, basculer, supprimer — passent TOUS par la
 * passerelle (`GET`, `POST /maintenance/windows`, `PUT`, `DELETE .../<id>`) et
 * jamais par un appel direct au backend Python. Ce que ce controleur lit
 * lui-meme, il le lit dans MySQL, exactement comme le legacy le fait avec son
 * `$pdo` : la base n'est pas le backend, et cette phrase l'a d'abord dit trop
 * vite.
 *
 * ══ ⚠ LA LOGIQUE S'INVERSE, ET IL FAUT LE DIRE A L'ECRAN ════════════════════
 *
 * Releve en lisant `backend/maintenance.py:102-143` :
 *
 *   - **aucune** fenetre activee -> toute action mutante est AUTORISEE ;
 *   - **une** fenetre activee    -> autorisee SEULEMENT si l'instant courant
 *                                   tombe dedans, pour les roles < 3.
 *
 * Autrement dit, **creer sa premiere fenetre RESTREINT** au lieu d'autoriser.
 * C'est contre-intuitif, et le legacy le mentionne d'une demi-phrase au milieu
 * d'un paragraphe. Le portage en fait un encart, parce que se tromper ici bloque
 * la flotte a l'heure ou l'on en a besoin.
 *
 * L'enforcement vit dans d'AUTRES modules (`routes/updates.py:19`,
 * `routes/monitoring.py:229`) : un blocage ne se lit donc pas ici, mais sur la
 * page qui a refuse l'action. La page nomme ce lien plutot que de le laisser
 * deviner.
 */
class MaintenanceController extends Controller
{
    public function __invoke(): View
    {
        $machines = DB::table('machines')
            ->select('id', 'name')
            ->orderBy('name')
            ->get();

        /*
         * ══ CE QUI EST RESTREINT, ET CE QUI NE L'EST PAS ════════════════════
         *
         * Le premier jet comptait les fenetres activees SANS REGARDER LEUR
         * PORTEE et annoncait « flotte restreinte » des qu'il en trouvait une.
         * C'etait faux, et faux precisement dans le cas le plus courant du banc
         * d'essai : une fenetre limitee a UNE machine ne restreint QUE cette
         * machine.
         *
         * La requete du backend le dit mot pour mot
         * (`backend/maintenance.py:120-123`) :
         *
         *     WHERE enabled = 1 AND (scope = 'global' OR machine_id = %s)
         *
         * Donc, pour une machine donnee, les fenetres applicables sont les
         * globales activees PLUS celles activees qui la nomment. Aucune
         * applicable = aucune restriction. D'ou trois etats, et non deux :
         *
         *   une globale activee            -> TOUTE la flotte est restreinte
         *   sinon, N machines nommees      -> ces N machines seulement
         *   aucune                         -> aucune restriction
         *
         * Une pastille qui dit « flotte restreinte » alors qu'une seule machine
         * l'est ferait chercher une panne generale la ou il n'y en a pas — et
         * c'est le genre d'erreur qu'on ne decouvre qu'en la cherchant, puisque
         * le refus se produit ailleurs.
         */
        $globales = (int) DB::table('maintenance_windows')
            ->where('enabled', 1)->where('scope', 'global')->count();

        $machinesRestreintes = (int) DB::table('maintenance_windows')
            ->where('enabled', 1)->where('scope', 'machine')
            ->whereNotNull('machine_id')
            ->distinct()->count('machine_id');

        $activees = (int) DB::table('maintenance_windows')->where('enabled', 1)->count();

        if ($globales > 0) {
            $etat = 'flotte';
        } elseif ($machinesRestreintes > 0) {
            $etat = 'machines';
        } else {
            $etat = 'libre';
        }

        return view('maintenance', [
            'machines'            => $machines,
            'activees'            => $activees,
            'globales'            => $globales,
            'machinesRestreintes' => $machinesRestreintes,
            'etat'                => $etat,
        ]);
    }
}
