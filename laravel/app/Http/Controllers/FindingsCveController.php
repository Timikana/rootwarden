<?php

namespace App\Http\Controllers;

use App\Services\ScansCve;
use App\Services\SuiviCve;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Les vulnerabilites du dernier scan d'UNE machine, une page a la fois.
 *
 * POURQUOI CETTE ROUTE EXISTE. La page `/scan-cve` mettait dans son gabarit
 * TOUS les findings du dernier scan de CHAQUE machine visible : 85 133 lignes
 * pour 32 machines en production, et le `json_encode` final epuisait les 128 Mo
 * de PHP — un 500 sur toute la page. Elle ne rend plus que le resume ; le detail
 * d'une machine arrive ICI, a l'ouverture de sa carte, et chaque filtre, chaque
 * recherche et chaque « Voir plus » redemande une page au lieu de filtrer un
 * tableau entier en memoire.
 *
 * LA GARDE EST CELLE DE LA PAGE, ET LE PERIMETRE AUSSI. La route porte le meme
 * `role:1` + `perm:can_scan_cve`, et la machine doit figurer dans
 * `machinesVisibles()` — la liste meme qui peint les cartes. Un role 1 ne lit
 * donc que ses machines, et personne ne lit une machine archivee, que la page ne
 * montre pas non plus. Le scan lu est celui que la page annonce
 * (`derniersScansParMachine`), jamais un identifiant recu.
 *
 * Machine inconnue, non attribuee ou archivee : le meme 404. Distinguer les cas
 * renseignerait sur l'existence des machines d'autrui.
 */
class FindingsCveController extends Controller
{
    /** Le pas de la pagination, celui du tableau. */
    public const PAR_PAGE = 50;

    public function __construct(
        private readonly ScansCve $scans,
        private readonly SuiviCve $suivi,
    ) {
    }

    public function __invoke(Request $requete, int $machine): JsonResponse
    {
        $role     = (int) $requete->session()->get('role_id', 0);
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);

        $visibles = array_map(static fn ($m) => (int) $m->id, $this->scans->machinesVisibles($idCompte, $role));
        if (! in_array($machine, $visibles, true)) {
            return response()->json(['erreur' => __('cve.machine_invalide')], 404);
        }

        $severite = strtoupper((string) $requete->query('severite', 'ALL'));
        $annee    = (string) $requete->query('annee', 'ALL');
        $q        = (string) $requete->query('q', '');
        $page     = (int) $requete->query('page', 1);

        // Un parametre hors liste est REFUSE, pas ignore : ignore, il rendrait le
        // tableau entier sous un filtre qui annonce le contraire.
        if (! in_array($severite, ScansCve::FILTRES_SEVERITE, true)
            || ($annee !== 'ALL' && $annee !== '?' && ! preg_match('/^\d{4}$/', $annee))
            || mb_strlen($q) > 100
            || $page < 1) {
            return response()->json(['erreur' => __('cve.filtre_invalide')], 422);
        }

        $scan = $this->scans->derniersScansParMachine([$machine])[$machine] ?? null;
        if ($scan === null) {
            // Une machine visible mais jamais scannee : rien a lister, et ce
            // n'est pas une erreur.
            return response()->json(['lignes' => [], 'total' => 0, 'page' => 1,
                                     'par_page' => self::PAR_PAGE, 'suivi' => (object) []]);
        }

        $resultat = $this->scans->pageFindings((int) $scan->id, $machine,
            ['severite' => $severite, 'annee' => $annee, 'q' => $q], $page, self::PAR_PAGE);

        return response()->json([
            'lignes'   => $resultat['lignes'],
            'total'    => $resultat['total'],
            'page'     => $page,
            'par_page' => self::PAR_PAGE,
            // Le suivi STOCKE des seules CVE de la page. Objet, jamais liste :
            // vide, `[]` se lirait comme un tableau cote navigateur.
            'suivi'    => (object) $this->suivi->pourCves($machine, array_column($resultat['lignes'], 'c')),
        ]);
    }
}
