<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Approbation a quatre yeux des actions destructrices.
 *
 * La page n'interroge pas la base : tout passe par la passerelle
 * (`/approvals`), ou le backend applique la regle — un administrateur ne peut
 * pas approuver sa propre demande, et le superadministrateur en est exempt.
 *
 * La garde vit dans la route (`role:2` + `perm:can_admin_portal`).
 */
class ApprobationsController extends Controller
{
    public function __invoke(Request $requete): View
    {
        return view('approbations');
    }
}
