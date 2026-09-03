<?php

namespace App\Http\Controllers;

use App\Services\Machines;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Journal des commandes — tracabilite de type bastion, LECTURE SEULE.
 *
 * La page ne fait qu'afficher : les lignes viennent du backend Python par la
 * passerelle (`/command_log`), qui est deja reservee a l'administration.
 *
 * La garde vit dans les middlewares de la route (`role:2` + `perm:...`), pas
 * ici : une decision d'acces ecrite a deux endroits finit par diverger.
 */
class JournalCommandesController extends Controller
{
    public function __invoke(Request $requete, Machines $machines): View
    {
        return view('journal-commandes', [
            'machines' => $machines->liste(),
        ]);
    }
}
