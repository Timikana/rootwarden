<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
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
    public function __invoke(Request $requete): View
    {
        return view('journal-commandes', [
            'machines' => $this->machines(),
        ]);
    }

    /**
     * Liste des machines, pour le filtre.
     *
     * Aucun filtre d'acces : la page est reservee a l'administration, qui a
     * vocation a voir le parc entier. C'est le meme choix que le legacy, et il
     * est delibere — a la difference du tableau de bord, qui sert ces memes
     * donnees a des comptes sans aucune permission.
     *
     * @return list<object>
     */
    private function machines(): array
    {
        try {
            return DB::table('machines')->select('id', 'name')->orderBy('name')->get()->all();
        } catch (\Throwable) {
            // Le filtre est un confort : son indisponibilite ne doit pas
            // empecher la consultation du journal.
            return [];
        }
    }
}
