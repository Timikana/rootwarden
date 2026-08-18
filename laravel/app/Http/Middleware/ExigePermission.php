<?php

namespace App\Http\Middleware;

use App\Services\Droits;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Exige une permission, ou le role superadministrateur.
 *
 * `perm:can_admin_portal` se lit « cette permission OU superadmin », comme
 * partout ailleurs dans le projet — c'est la regle du legacy et celle de
 * App\Support\Navigation. Une regle d'acces qui differe selon l'endroit ou on
 * la lit finit par diverger.
 *
 * Les permissions sont relues EN BASE a chaque requete (memorisees pour sa
 * duree) : une permission revoquee cesse d'ouvrir la page a la requete
 * suivante, sans attendre une reconnexion.
 */
class ExigePermission
{
    public function __construct(private readonly Droits $droits)
    {
    }

    public function handle(Request $requete, Closure $suite, string $permission): Response
    {
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);
        $roleId   = (int) $requete->session()->get('role_id', 0);

        if ($roleId >= 3) {
            return $suite($requete);
        }

        if (! ($this->droits->permissions($idCompte)[$permission] ?? false)) {
            // 403 et non une redirection : la page existe, l'acces est refuse.
            // Rediriger ferait croire a une page disparue.
            abort(403, __('acces.permission_manquante'));
        }

        return $suite($requete);
    }
}
