<?php

namespace App\Http\Controllers;

use App\Services\ScansCve;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * Module `security/`, sous-lot S1 : export CSV d'un scan CVE.
 *
 * Portage de `legacy/security/cve_export.php` (101 lignes). Aucune route
 * backend, aucun SSH, aucune ecriture : un export est une LECTURE.
 *
 * GARDE REPRISE DU LEGACY, telle quelle : `checkAuth([1,2,3])` +
 * `checkPermission('can_scan_cve')` devient `role:1` + `perm:can_scan_cve` dans
 * la route. Le role 1 est bien admis — c'est le cloisonnement par
 * `user_machine_access`, plus bas, qui borne ce qu'il peut lire.
 *
 * LE REFUS DE CLOISONNEMENT REND 404, PAS 403, et le MEME corps que « aucun
 * scan trouve ». C'est deliberé cote legacy et repris ici : un 403 confirmerait
 * l'existence de la machine a qui n'y a pas acces. Le test verifie que les deux
 * corps sont identiques, sans quoi la difference elle-meme renseignerait.
 *
 * LE CONTROLE PORTE SUR L'OBJET RESOLU. On verifie l'acces au `machine_id` DU
 * SCAN, jamais a celui recu dans l'URL : `?scan_id=N` n'en porte aucun, et un
 * garde qui lirait le parametre laisserait passer toute cette branche.
 *
 * LA CHARGE UTILE EST ASSEMBLEE AVANT D'ETRE ENVOYEE, et c'est structurel, pas
 * cosmetique. Le legacy ecrit dans `php://output` au fil de l'eau ; sur ce poste
 * `verify.php` pose `display_errors=1` quand `DEBUG_MODE=true`, et sur PHP 8.4
 * chacun de ses ~1465 `fputcsv()` sans argument `$escape` injecte un bloc HTML
 * `<b>Deprecated</b>` DANS le fichier. Resultat mesure : un corps qui commence
 * par « < » au lieu du BOM, des avertissements intercales entre les lignes, et
 * 1458 vulnerabilites rendues sur 10 492 lignes. Ici rien ne part avant que tout
 * soit ecrit, donc aucun avertissement ne peut s'y glisser. Et `$escape` est
 * passe EXPLICITEMENT, a sa valeur historique, pour taire la depreciation sans
 * changer un octet de la sortie.
 */
class ExportCveController extends Controller
{
    public function __construct(private readonly ScansCve $scans)
    {
    }

    public function __invoke(Request $requete): Response|JsonResponse
    {
        $machineId = (int) $requete->query('machine_id', 0);
        $scanId    = (int) $requete->query('scan_id', 0);

        if (! $machineId && ! $scanId) {
            return response()->json(['error' => __('cve.export_parametre_requis')], 400);
        }

        $scan = $scanId
            ? $this->scans->parId($scanId)
            : $this->scans->dernierScanComplet($machineId);

        if (! $scan) {
            return $this->introuvable();
        }

        // Cloisonnement : au-dela du role 1, le legacy ne borne rien.
        if ((int) $requete->session()->get('role_id', 0) < 2) {
            $idCompte = (int) $requete->session()->get('utilisateur_id', 0);
            if (! $this->scans->accesMachine($idCompte, (int) $scan->machine_id)) {
                return $this->introuvable();
            }
        }

        return $this->fichier($scan, $this->scans->resultats((int) $scan->id));
    }

    /**
     * Le meme corps pour « pas de scan » et pour « pas d'acces ». Deux reponses
     * distinctes suffiraient a renseigner sur l'existence de la machine.
     */
    private function introuvable(): JsonResponse
    {
        return response()->json(['error' => __('cve.export_scan_introuvable')], 404);
    }

    private function fichier(object $scan, array $resultats): Response
    {
        $nom = 'cve_'
            . preg_replace('/[^a-zA-Z0-9_-]/', '_', (string) $scan->machine_name)
            . '_' . date('Y-m-d', strtotime((string) $scan->scan_date)) . '.csv';

        return response($this->csv($scan, $resultats), 200, [
            'Content-Type'        => 'text/csv; charset=utf-8',
            'Content-Disposition' => 'attachment; filename="' . $nom . '"',
            'Pragma'              => 'no-cache',
        ]);
    }

    /**
     * Le CSV, ecrit EN MEMOIRE puis rendu d'un bloc.
     *
     * L'ordre et le nombre de lignes sont ceux du legacy : le BOM qu'Excel
     * attend, cinq lignes de metadonnees prefixees `#`, une ligne vide, un
     * en-tete de six colonnes, une ligne par vulnerabilite — ou une seule ligne
     * qui DIT que la liste est vide, plutot qu'un tableau nu.
     */
    private function csv(object $scan, array $resultats): string
    {
        $flux = fopen('php://temp', 'r+');
        fwrite($flux, "\xEF\xBB\xBF");

        $ligne = static function (array $cellules) use ($flux): void {
            // `$escape` EXPLICITE, a sa valeur historique : la depreciation de
            // PHP 8.4 porte sur l'ABSENCE de l'argument, pas sur sa valeur. Le
            // passer tait l'avertissement sans changer la sortie d'un octet.
            fputcsv($flux, $cellules, ',', '"', '\\');
        };

        $ligne(['# ' . __('cve.export_titre', ['machine' => $scan->machine_name])]);
        $ligne(['# ' . __('cve.export_date', ['date' => $scan->scan_date])]);
        $ligne(['# ' . __('cve.export_paquets', ['nombre' => $scan->packages_scanned])]);
        $ligne(['# ' . __('cve.export_seuil', ['seuil' => $scan->min_cvss])]);
        $ligne(['# ' . __('cve.export_repartition', [
            'critical' => $scan->critical_count,
            'high'     => $scan->high_count,
            'medium'   => $scan->medium_count,
            'low'      => $scan->low_count,
        ])]);
        $ligne([]);

        $ligne([
            __('cve.col_cve'), __('cve.col_paquet'), __('cve.col_version'),
            __('cve.col_cvss'), __('cve.col_severite'), __('cve.col_resume'),
        ]);

        foreach ($resultats as $r) {
            $ligne([
                $r->cve_id, $r->package_name, $r->package_version,
                $r->cvss_score, $r->severity, $r->summary,
            ]);
        }

        if ($resultats === []) {
            $ligne([__('cve.export_aucune')]);
        }

        rewind($flux);
        $contenu = stream_get_contents($flux);
        fclose($flux);

        return $contenu;
    }
}
