<?php

namespace App\Http\Controllers;

use App\Services\ScansCve;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Module `security/`, sous-lot S3 : la comparaison des deux derniers scans CVE
 * d'une machine.
 *
 * Appelee au clic depuis la page de consultation, pas au chargement : le diff
 * relit DEUX jeux de findings entiers, et personne n'a encore ouvert le panneau.
 *
 * REMPLACE `GET /cve_compare` DU BACKEND, il ne l'appelle pas. Cette route
 * Python n'a ni role ni permission, son garde d'acces resout la machine par le
 * CORPS JSON quand la route la lit dans la query string, et son diff est fait en
 * Python (`backend/routes/cve.py:368-370`). Le portage lit la base, comme S1, et
 * le diff revient dans `ScansCve::comparaison()`.
 *
 * LE CLOISONNEMENT EST CONTROLE SUR LA MACHINE RESOLUE, jamais sur le parametre
 * recu : c'est la lecon d'un garde qui ne trouvait pas son objet et laissait donc
 * tout passer.
 *
 * `assez = false` n'est PAS une erreur : une machine qui n'a qu'un scan n'a rien
 * a comparer, et l'ecran doit le DIRE. Le legacy repond deja 200 dans ce cas ;
 * ce qui manquait, c'est que la reponse soit lisible.
 */
class ComparaisonCveController extends Controller
{
    public function __construct(private readonly ScansCve $scans)
    {
    }

    public function __invoke(Request $requete): JsonResponse
    {
        $machineId = (int) $requete->query('machine_id', 0);
        if ($machineId <= 0) {
            return response()->json(['erreur' => __('cve.machine_invalide')], 400);
        }

        if ((int) $requete->session()->get('role_id', 0) < 2) {
            $idCompte = (int) $requete->session()->get('utilisateur_id', 0);
            if (! $this->scans->accesMachine($idCompte, $machineId)) {
                // Le meme code que pour une machine inexistante : distinguer les
                // deux revelerait l'existence des machines d'autrui.
                return response()->json(['erreur' => __('cve.machine_invalide')], 404);
            }
        }

        $c = $this->scans->comparaison($machineId);

        $abrege = static fn (array $liste) => array_map(static fn ($f) => [
            'c' => (string) $f->cve_id,
            'p' => (string) ($f->package_name ?? ''),
            's' => (string) ($f->severity ?? 'NONE'),
            'n' => (float) ($f->cvss_score ?? 0),
        ], $liste);

        return response()->json([
            'assez'      => $c['assez'],
            'nb_scans'   => $c['nb_scans'],
            'scan1'      => $c['scan1'] ? [
                'id' => (int) $c['scan1']->id,
                'date' => (string) $c['scan1']->scan_date,
                'total' => (int) $c['scan1']->cve_count,
            ] : null,
            'scan2'      => $c['scan2'] ? [
                'id' => (int) $c['scan2']->id,
                'date' => (string) $c['scan2']->scan_date,
                'total' => (int) $c['scan2']->cve_count,
            ] : null,
            'ajoutees'   => $abrege($c['ajoutees']),
            'corrigees'  => $abrege($c['corrigees']),
            'inchangees' => $c['inchangees'],
        ]);
    }
}
