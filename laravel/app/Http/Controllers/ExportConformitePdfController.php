<?php

namespace App\Http\Controllers;

use App\Services\Conformite;
use Dompdf\Dompdf;
use Dompdf\Options;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * Module `security/`, sous-lot S2b : l'export PDF du rapport de conformite.
 *
 * Meme garde que la page (S2a) et que l'export CSV (S2c), et MEMES CHIFFRES :
 * tout vient de `Conformite::rapport()`. Trois vues d'un meme rapport, un seul
 * calcul.
 *
 * PAS DE TAMPON DE SORTIE, ET C'EST LE POINT. Le legacy ouvre un `ob_start()`
 * (`compliance_report.php:276`) qui ne capture rien — le HTML est monte par
 * concatenation de chaines — puis purge tout avant d'emettre le binaire :
 *
 *     while (ob_get_level() > 0) { ob_end_clean(); }
 *     $dompdf->stream(...);
 *
 * Son commentaire nomme exactement le defaut : « purger tout output parasite
 * (notices PHP captures par ob_start en mode debug) avant d'emettre le binaire
 * PDF -> evite un PDF corrompu prefixe de "<br />..." ». C'etait la MOITIE
 * corrigee du defaut ; la branche CSV du meme fichier ne l'etait pas (E-40).
 *
 * Ici il n'y a rien a purger parce qu'on n'ouvre rien : la vue est rendue en
 * chaine, dompdf rend ses octets, et la reponse les porte. Aucune sortie n'est
 * ouverte pendant qu'on calcule, donc rien ne peut s'y glisser — meme parade
 * structurelle que S1 et S2c, sous une autre forme.
 *
 * `isRemoteEnabled` reste a FALSE, comme dans le legacy : un document qui charge
 * une ressource distante est une requete sortante declenchee par le contenu du
 * rapport.
 */
class ExportConformitePdfController extends Controller
{
    public function __construct(private readonly Conformite $conformite)
    {
    }

    public function __invoke(Request $requete): Response
    {
        $rapport = $this->conformite->rapport(date('d/m/Y H:i'));

        $html = view('rapport-conformite-pdf', $rapport + [
            'genereePar' => (string) $requete->session()->get('utilisateur_nom', ''),
            'appName'    => (string) config('app.name'),
        ])->render();

        $options = new Options();
        $options->set('isRemoteEnabled', false);
        $options->set('defaultFont', 'DejaVu Sans');

        $dompdf = new Dompdf($options);
        $dompdf->loadHtml($html, 'UTF-8');
        // A4 PAYSAGE, comme le legacy : la table de posture a cinq colonnes dont
        // une de texte libre, et le portrait la coupe.
        $dompdf->setPaper('A4', 'landscape');
        $dompdf->render();

        $nom = 'rapport_conformite_' . date('Y-m-d') . '.pdf';

        // FAIL-CLOSED SUR LA SORTIE. `output()` peut rendre `null`, et un flux
        // tronque resterait un `string`. Servir cela avec un 200 et un
        // `Content-Type: application/pdf` livrerait un fichier corrompu en le
        // presentant comme valide — c'est exactement le defaut que ce sous-lot
        // traite (E-33/E-40), simplement venu de l'autre bout.
        //
        // Les DEUX marqueurs sont exiges, et ce sont les deux memes que la suite
        // mesure sur les octets recus : `%PDF-` en tete dit que rien ne s'est
        // glisse AVANT le document, `%%EOF` dit qu'il n'a pas ete coupe APRES.
        // Verifier le seul premier laisserait passer un fichier tronque, alors
        // que ce commentaire aurait affirme le contraire.
        $octets = (string) $dompdf->output();
        if (! str_starts_with($octets, '%PDF-') || ! str_contains($octets, '%%EOF')) {
            abort(500, 'Le rendu PDF n\'a pas produit un document valide.');
        }

        return response($octets, 200, [
            'Content-Type'        => 'application/pdf',
            'Content-Disposition' => 'attachment; filename="' . $nom . '"',
            'Pragma'              => 'no-cache',
        ]);
    }
}
