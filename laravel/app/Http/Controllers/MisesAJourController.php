<?php

namespace App\Http\Controllers;

use App\Services\Machines;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Mises a jour Linux — sous-lot U1 : le parc et ses filtres, LECTURE SEULE.
 *
 * Le module `update/` du legacy pese 2 094 lignes ; son decoupage en six
 * sous-lots est dans `docs/migration/MODULE-UPDATE.md`. U1 porte le tableau,
 * les filtres, le rafraichissement et les trois relevés par machine. Les mises
 * a jour, la planification et le redemarrage restent servis par l'ancien
 * portail jusqu'a U6 — la page le DIT plutot que de les faire disparaitre.
 *
 * Le parc est lu EN BASE, comme le fait le legacy : les treize colonnes
 * affichees ne sont pas toutes servies par la passerelle. Le cloisonnement du
 * role 1 par `user_machine_access` est repris a l'identique.
 *
 * Garde : `role:1` + `perm:can_update_linux` — celle du legacy, qui admet le
 * role 1 porteur de la permission.
 */
class MisesAJourController extends Controller
{
    public function __invoke(Request $requete, Machines $machines): View
    {
        $session = $requete->session();

        return view('mises-a-jour', [
            'machines' => $machines->pourMisesAJour(
                (int) $session->get('role_id', 0),
                (int) $session->get('user_id', 0),
            ),
        ]);
    }
}
