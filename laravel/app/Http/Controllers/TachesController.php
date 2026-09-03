<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Centre de taches : historique de l'activite de fond (scans, sauvegardes...).
 *
 * Lecture seule. Tout passe par la passerelle (`/tasks/list`, `/tasks/stats`).
 *
 * GARDE : `role:2` SEUL, sans permission — comme le legacy, qui n'appelle que
 * `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])`. Inventer une permission au detour
 * d'un portage serait un changement de droits.
 *
 * A savoir, et mesure par `tests/e2e/go-page-tasks.mjs` : l'entree de MENU, elle,
 * vit dans le bloc garde par `can_admin_portal`. Un compte role 2 sans cette
 * permission ne voit donc pas l'entree et atteint pourtant la page en tapant son
 * adresse. Le portage reproduit cet ecart tel quel et le consigne, plutot que de
 * le corriger d'un cote ou de l'autre sans arbitrage.
 */
class TachesController extends Controller
{
    public function __invoke(Request $requete): View
    {
        return view('taches');
    }
}
