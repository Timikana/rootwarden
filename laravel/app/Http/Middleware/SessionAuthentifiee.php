<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Refuse toute requete dont la session n'est pas COMPLETEMENT authentifiee.
 *
 * « Completement » veut dire : mot de passe ET second facteur. Entre les deux,
 * la session ne porte qu'un `compte_temporaire` — elle ne donne acces a rien.
 * C'est l'invariant B du test de caracterisation : il n'existe aucun chemin
 * sans second facteur.
 *
 * La decision d'acces vit ICI et nulle part ailleurs. Recopiee dans un
 * controleur, elle finirait par diverger.
 */
class SessionAuthentifiee
{
    public function handle(Request $requete, Closure $suite): Response
    {
        if (! $requete->session()->has('utilisateur_id')) {
            return redirect()->route('connexion');
        }

        return $suite($requete);
    }
}
