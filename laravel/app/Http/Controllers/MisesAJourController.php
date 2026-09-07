<?php

namespace App\Http\Controllers;

use App\Services\Machines;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Mises a jour Linux — le module `update/` PORTE EN ENTIER.
 *
 * Le module `update/` du legacy pesait 2 094 lignes ; son decoupage en sept
 * sous-lots (U1 a U6b) est dans `docs/migration/MODULE-UPDATE.md`. Tout est
 * porte, et `legacy/update/` est archive dans `legacy/_deprecated/` depuis le
 * 2026-08-20 : plus rien ici ne renvoie a l'ancien portail.
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
            // ⚠ `utilisateur_id`, et le nom compte. `SecondFacteurController:289`
            // est le SEUL poseur de cle d'identite en session ; ce controleur
            // lisait `user_id`, que rien ne pose. `$userId` valait donc 0, et
            // `pourMisesAJour` fait `if ($roleId < 2) join uma WHERE user_id = 0`
            // — AUCUNE machine rendue au role 1, precisement le role auquel
            // cette page est ouverte (`web.php:563`, `role:1`).
            //
            // POURQUOI PERSONNE NE L'A VU : au role >= 2 la jointure est SAUTEE,
            // donc l'identifiant n'est jamais employe. **Le defaut est invisible
            // au role qui teste.** Corrige le 2026-09-07 avec les deux autres
            // sites (`ClesSshController`, `SupervisionController`).
            'machines' => $machines->pourMisesAJour(
                (int) $session->get('role_id', 0),
                (int) $session->get('utilisateur_id', 0),
            ),
            'etiquettes' => $machines->etiquettes(),
        ]);
    }
}
