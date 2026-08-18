<?php

namespace App\Http\Controllers;

use App\Support\LiensLegacy;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Recherche globale : serveurs, utilisateurs, CVE, tickets, journal d'audit.
 *
 * Lecture seule, un seul appel par recherche (`/search?q=`), plafonne a dix
 * resultats par categorie cote backend.
 *
 * Le backend rend, pour chaque resultat, un lien de navigation ecrit pour
 * l'ANCIEN portail. `App\Support\LiensLegacy` les traduit : une partie portee
 * mene a sa route, une partie encore sur l'ancien portail mene la-bas et le
 * DIT. Sans cette traduction, chaque archivage transformerait un resultat de
 * recherche en 404.
 *
 * La garde vit dans la route (`role:2` + `perm:can_admin_portal`), la meme que
 * le backend applique sur `/search`.
 */
class RechercheController extends Controller
{
    public function __invoke(Request $requete): View
    {
        return view('recherche', [
            'terme'  => trim((string) $requete->query('q', '')),
            'liens'  => LiensLegacy::pourLeNavigateur(),
        ]);
    }
}
