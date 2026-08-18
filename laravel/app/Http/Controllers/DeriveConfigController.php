<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Detection de derive de configuration.
 *
 * Compare l'etat DESIRE (gere par RootWarden) a l'etat REEL connu des serveurs,
 * pour trois categories : sudo, sshd, fail2ban. La page n'interroge pas la
 * base : tout passe par la passerelle (`/drift/results`, `/drift/scan`,
 * `/drift/scan_all`), ou le backend fait le calcul.
 *
 * Le scan ne joint AUCUN serveur : il recalcule depuis des donnees deja en
 * base. C'est ce qui rend le bouton « scanner tout » sans danger sur un parc
 * de production.
 *
 * La garde vit dans la route (`role:2` + `perm:can_view_compliance`).
 */
class DeriveConfigController extends Controller
{
    public function __invoke(Request $requete): View
    {
        return view('derive-config');
    }
}
