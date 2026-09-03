<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;
use Illuminate\View\View;

/**
 * Inventaire et veille des conteneurs Docker des serveurs.
 *
 * La page ne parle jamais au backend : tout passe par la passerelle
 * (`/docker/results`, `/docker/scan`, `/docker/scan_all`).
 *
 * ══ UN « SCAN » N'EST PAS UNE LECTURE ═══════════════════════════════════════
 *
 * Releve avant portage, et il faut le savoir avant de cliquer :
 * `backend/docker_monitor.py:116` lance un **`git fetch`** dans le depot de
 * chaque projet compose de la machine visee — ca ecrit dans `.git/` et ca fait
 * sortir la MACHINE sur le reseau. Et `backend/docker_registry.py` interroge le
 * registre distant pour comparer les empreintes.
 *
 * Surtout, **`/docker/scan_all` frappe TOUTES les machines**, `srv-zabbix`
 * (production) comprise. La page le dit desormais dans son encart de guidage :
 * le legacy laissait croire a un geste anodin.
 *
 * ══ LA GARDE ═══════════════════════════════════════════════════════════════
 *
 * `role:2`, sans permission — repris tel quel du legacy
 * (`checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])`). C'est la seule entree de menu
 * gardee par le ROLE et non par une permission ; le releve est signale dans
 * `INVENTAIRE.md` et n'est pas corrige au detour d'un portage.
 */
class DockerController extends Controller
{
    public function __invoke(): View
    {
        /*
         * Les machines viennent de la base, comme dans le legacy : c'est la
         * seule requete SQL de la page, et elle ne sert qu'a peupler le
         * selecteur. Les machines archivees sont exclues.
         */
        $machines = DB::table('machines')
            ->select('id', 'name')
            ->where(function ($q) {
                $q->whereNull('lifecycle_status')->orWhere('lifecycle_status', '<>', 'archived');
            })
            ->orderBy('name')
            ->get();

        return view('docker', ['machines' => $machines]);
    }
}
