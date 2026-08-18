<?php

namespace App\Http\Controllers;

use App\Services\Droits;
use App\Support\Navigation;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Pages du portail deja atteignables apres authentification.
 *
 * Elles sont volontairement minimales : seul le SOCLE est porte a ce stade.
 * Mais elles ORIENTENT — un ecran vide qui ne dit ni ce qui existe ni ou aller
 * laisse croire que la fonction a disparu.
 */
class PortailController extends Controller
{
    public function __construct(private readonly Droits $droits)
    {
    }

    public function cgu(Request $requete): View
    {
        return view('cgu');
    }

    public function accepterCgu(Request $requete): RedirectResponse
    {
        $requete->session()->put('cgu_acceptees', true);

        return redirect()->route('accueil');
    }

    public function accueil(Request $requete): View
    {
        $menu = $this->menuDuCompte($requete);
        $entrees = collect($menu)->flatten(1);

        return view('accueil', [
            'modulesAccessibles' => $entrees->count(),
            'modulesPortes'      => $entrees->filter(fn ($e) => isset($e['route']))->count(),
            'libelleRole'        => $this->libelleRole((int) $requete->session()->get('role_id', 0)),
        ]);
    }

    public function profil(Request $requete): View
    {
        return view('profil', [
            'changementRequis' => (bool) $requete->session()->get('changement_mot_de_passe_requis', false),
            'libelleRole'      => $this->libelleRole((int) $requete->session()->get('role_id', 0)),
        ]);
    }

    /** Le menu tel que le compte connecte le voit — meme source que la vue. */
    private function menuDuCompte(Request $requete): array
    {
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);

        return Navigation::pour(
            (int) $requete->session()->get('role_id', 0),
            $this->droits->permissions($idCompte),
            $this->droits->fonctionnalites(),
        );
    }

    /**
     * Libelle du role. Les identifiants numeriques (1, 2, 3) sont ceux du
     * legacy : ils ne se traduisent pas, ils s'affichent.
     */
    private function libelleRole(int $roleId): string
    {
        return match (true) {
            $roleId >= 3 => __('accueil.role_superadmin'),
            $roleId === 2 => __('accueil.role_admin'),
            default => __('accueil.role_lecteur'),
        };
    }
}
