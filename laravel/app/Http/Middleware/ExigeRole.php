<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Exige un role au moins egal a celui demande.
 *
 * `role:2` = administrateur ou au-dessus. Les identifiants numeriques sont
 * ceux du legacy : 1 lecteur, 2 administrateur, 3 superadministrateur.
 *
 * Le role vient de la session, mais il y a ete pose apres verification EN BASE
 * au moment du second facteur, et la session est regeneree a cet instant.
 */
class ExigeRole
{
    public function handle(Request $requete, Closure $suite, string $minimum): Response
    {
        if ((int) $requete->session()->get('role_id', 0) < (int) $minimum) {
            abort(403, __('acces.role_insuffisant'));
        }

        return $suite($requete);
    }
}
