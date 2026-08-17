<?php

namespace App\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Pages du portail deja atteignables apres authentification.
 *
 * Elles sont volontairement minimales : seul le SOCLE est porte a ce stade.
 * Chaque page renvoie vers le frontend legacy pour ce qui n'est pas encore
 * porte — mieux vaut un renvoi explicite qu'un ecran vide qui laisse croire
 * que la fonction a disparu.
 */
class PortailController extends Controller
{
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
        return view('accueil');
    }

    public function profil(Request $requete): View
    {
        return view('profil', [
            'changementRequis' => (bool) $requete->session()->get('changement_mot_de_passe_requis', false),
        ]);
    }
}
