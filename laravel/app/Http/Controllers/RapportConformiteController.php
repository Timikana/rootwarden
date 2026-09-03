<?php

namespace App\Http\Controllers;

use App\Services\Conformite;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Module `security/`, sous-lot S2a : le rapport de conformite, page HTML.
 *
 * Portage de `legacy/security/compliance_report.php` (579 lignes), hors export
 * CSV (S2c) et hors export PDF (S2b). Aucune route backend, aucun SSH.
 *
 * TOUTE LA COLLECTE VIT DANS `App\Services\Conformite::rapport()`, pas ici : la
 * page et l'export CSV presentent les MEMES chiffres, et deux calculs separes
 * finissent par ne plus dire la meme chose. C'est le defaut trouve sur la page
 * des mises a jour, ou le premier rendu et les relectures venaient de deux
 * requetes qui ne s'accordaient ni sur les machines archivees ni sur le format
 * des dates.
 *
 * GARDE — DIVERGENCE VOULUE, decision D-1. Le legacy admet `ROLE_USER` et ne
 * cloisonne AUCUNE donnee : un role 1 porteur de `can_view_compliance` obtenait
 * tout le parc avec IP, port et utilisateur SSH, tous les comptes avec leur
 * e-mail et l'age de leur cle, et la posture par serveur AVEC LES ECARTS EN
 * CLAIR — soit une liste de cibles priorisee. L'en-tete du fichier annoncait
 * pourtant « Acces : admin (2) et superadmin (3) », et c'est ce commentaire faux
 * qui a rendu le defaut durable. La route porte `role:2`. Voir `PARITE.md` E-36.
 *
 * PAS DE JAVASCRIPT : le legacy rend cette page en PHP de bout en bout, sans
 * appel asynchrone. Le seul comportement est l'impression, qui appartient au
 * navigateur.
 */
class RapportConformiteController extends Controller
{
    public function __construct(private readonly Conformite $conformite)
    {
    }

    public function __invoke(Request $requete): View
    {
        $rapport = $this->conformite->rapport(date('d/m/Y H:i'));

        return view('rapport-conformite', $rapport + [
            'genereePar' => (string) $requete->session()->get('utilisateur_nom', ''),
        ]);
    }
}
