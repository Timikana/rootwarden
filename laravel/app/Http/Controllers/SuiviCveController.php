<?php

namespace App\Http\Controllers;

use App\Services\ScansCve;
use App\Services\SuiviCve;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Module `security/`, sous-lot S5 : le suivi de remediation d'une vulnerabilite.
 *
 * LECTURE ET ECRITURE EN BASE, comme S3 et S4 : la table `cve_remediation`
 * n'a aucun effet de bord externe. Le backend Python n'est pas touche.
 *
 * L'EXCEPTION EST LE TICKET, et elle est fondee. `POST /tickets` appelle un
 * FOURNISSEUR ITSM EXTERNE quand il est configure
 * (`backend/routes/tickets.py`, `ticketing.create_ticket`) : le reimplementer
 * cote portage dupliquerait une integration et ses identifiants. La creation de
 * ticket passe donc par la PASSERELLE, contrairement au reste du module — et la
 * chaine de gardes y est deja en place : `/tickets` est dans `ADMIN_SEULEMENT`
 * de `RoutesBackend`, donc la passerelle exige le role 2, et le backend exige
 * `can_admin_portal`. Voir PARITE.
 *
 * CE QUE FAIT CE CONTROLEUR POUR LE TICKET : rien, sinon dire a la page si le
 * compte peut en creer. Une regle appliquee par le backend se REND VISIBLE — le
 * bouton est desactive avec son explication plutot que cliquable pour rien — mais
 * elle n'est jamais DEPLACEE cote navigateur : c'est toujours le backend qui
 * refuse.
 */
class SuiviCveController extends Controller
{
    public function __construct(
        private readonly SuiviCve $suivi,
        private readonly ScansCve $scans,
    ) {
    }

    /** Les statuts stockes d'une machine, pour peupler le tableau. */
    public function index(Request $requete): JsonResponse
    {
        $machineId = (int) $requete->query('machine_id', 0);
        if ($machineId <= 0) {
            return response()->json(['success' => false,
                                     'message' => __('suivi.err_machine')], 400);
        }
        if (! $this->autorise($requete, $machineId)) {
            return response()->json(['success' => false,
                                     'message' => __('suivi.err_machine')], 404);
        }

        return response()->json([
            'success' => true,
            'suivi' => $this->suivi->parMachine($machineId),
        ]);
    }

    public function store(Request $requete): JsonResponse
    {
        $donnees = (array) $requete->json()->all();
        $cveId = trim((string) ($donnees['cve_id'] ?? ''));
        $machineId = (int) ($donnees['machine_id'] ?? 0);
        $statut = trim((string) ($donnees['status'] ?? ''));

        if ($cveId === '' || $machineId <= 0) {
            return response()->json(['success' => false,
                                     'message' => __('suivi.err_parametres')], 400);
        }
        // LISTE BLANCHE AVANT ECRITURE. Cote legacy, un statut invente remontait
        // l'erreur MySQL 1265 nue : un 500 avec une page HTML au lieu d'un 400.
        if (! $this->suivi->statutChoisissable($statut)) {
            return response()->json([
                'success' => false,
                'message' => __('suivi.err_statut', ['statut' => $statut]),
            ], 400);
        }
        if (! $this->autorise($requete, $machineId)) {
            // Le meme code que pour une machine inexistante : distinguer les deux
            // revelerait l'existence des machines d'autrui.
            return response()->json(['success' => false,
                                     'message' => __('suivi.err_machine')], 404);
        }

        $this->suivi->definirStatut($cveId, $machineId, $statut);

        return response()->json([
            'success' => true,
            'status' => $this->suivi->statut($cveId, $machineId),
        ]);
    }

    /**
     * Le cloisonnement, sur la machine RESOLUE et non sur le parametre recu.
     *
     * Au-dela du role 1, le legacy ne borne rien : la garde est reprise telle
     * quelle, cran par cran.
     */
    private function autorise(Request $requete, int $machineId): bool
    {
        if ((int) $requete->session()->get('role_id', 0) >= 2) {
            return true;
        }

        return $this->scans->accesMachine(
            (int) $requete->session()->get('utilisateur_id', 0), $machineId);
    }
}
