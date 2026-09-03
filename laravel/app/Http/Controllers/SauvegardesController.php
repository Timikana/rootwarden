<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Sauvegardes de la base : liste, creation, verification, restauration.
 *
 * La page n'interroge pas la base : tout passe par la passerelle
 * (`/admin/backups`, `/admin/backups/verify`, `/admin/backups/restore`).
 *
 * La RESTAURATION est destructive — `DROP TABLE` sur la base partagee par le
 * legacy, Laravel et le backend Python. Le backend la reserve au role 3 ; la
 * page ne montre le bouton qu'a lui, non pour garder l'action — un bouton cache
 * ne garde rien — mais pour ne pas proposer ce qui sera refuse.
 *
 * La garde de la page vit dans la route (`role:2` + `perm:can_admin_portal`).
 * A noter, et mesure par `tests/e2e/go-page-backups.mjs` : le backend ne demande
 * que le role 2 sur `/admin/backups`. La permission garde donc la PAGE, pas la
 * CAPACITE. Ce releve n'est pas corrige ici : changer des droits ne se fait pas
 * au detour d'un portage.
 */
class SauvegardesController extends Controller
{
    public function __invoke(Request $requete): View
    {
        return view('sauvegardes', [
            'estSuperadmin' => (int) $requete->session()->get('role_id', 0) >= 3,
        ]);
    }
}
