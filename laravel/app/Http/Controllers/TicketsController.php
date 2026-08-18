<?php

namespace App\Http\Controllers;

use App\Services\Machines;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Ticketing ITSM : liste des tickets et creation manuelle.
 *
 * La liste et la creation passent par la passerelle (`/tickets`). Seule la
 * liste des machines du selecteur est lue en base, comme le fait le legacy —
 * c'est une liste de reference, pas une donnee metier de la page.
 *
 * La garde vit dans la route (`role:2` + `perm:can_admin_portal`), et le
 * backend applique la meme, ce qui n'est pas le cas partout : voir
 * DEPRECIATION.md pour les pages ou la garde de la page et celle de la
 * capacite divergent.
 */
class TicketsController extends Controller
{
    public function __invoke(Request $requete, Machines $machines): View
    {
        return view('tickets', ['machines' => $machines->liste()]);
    }
}
