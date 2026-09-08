<?php

namespace App\Http\Controllers;

use App\Services\DeploiementCles;
use App\Services\Droits;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Déclenchement du déploiement des clés SSH — sous-lot K4.
 *
 * ⛔ **CE CONTRÔLEUR DÉCLENCHE UN GESTE QUI ÉCRIT EN ROOT SUR PLUSIEURS
 * MACHINES, ET QUI PEUT RÉVOQUER DES ACCÈS.** Il n'a jamais été exercé : le
 * portage écrit le chemin, l'exercice appartient à l'exploitant.
 *
 * ══ LA GARDE DE ROUTE N'EST PAS CELLE DE LA PAGE, ET C'EST VOULU ═════════
 *
 * La page `/cles-ssh` est `role:1` + `perm:can_deploy_keys`, reprise du legacy.
 * **Ce déclencheur est `role:2`**, parce que c'est ce que le backend exige
 * (`backend/routes/ssh.py:393`, `@require_role(2)` depuis E-191).
 *
 * *Offrir un bouton qu'un rôle 1 ne peut pas utiliser reproduirait la lettre du
 * legacy en produisant un 403 systématique.* La page reste ouverte au rôle 1 —
 * il voit le parc et le preflight —, le déclenchement ne l'est pas.
 *
 * ══ TOUT OU RIEN ═════════════════════════════════════════════════════════
 *
 * Un échec de preflight sur une seule machine refuse **tout** le déploiement et
 * nomme la fautive. C'est le comportement du legacy (`ssh/js/main.js:186-191`)
 * et le seul défendable : *un déploiement partiel silencieux laisse croire que
 * toutes les machines ont été traitées.*
 */
class DeploiementClesController extends Controller
{
    public function __construct(
        private readonly DeploiementCles $deploiement,
        private readonly Droits $droits,
    ) {
    }

    public function __invoke(Request $requete): JsonResponse
    {
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);
        $role = (int) $requete->session()->get('role_id', 0);

        /*
         * Les identifiants sont normalisés ICI et non plus loin : une valeur non
         * numérique glissée dans la liste partirait sinon telle quelle au backend.
         */
        $machines = array_values(array_unique(array_map(
            static fn ($m) => (int) $m,
            array_filter((array) $requete->input('machines', []),
                         static fn ($m) => is_numeric($m) && (int) $m > 0)
        )));

        $permissions = $this->droits->permissions($idCompte);

        $verdict = $this->deploiement->preflight($machines, $idCompte, $role, $permissions);

        if ($verdict['erreur'] !== null) {
            return response()->json([
                'success' => false,
                'etape' => 'preflight',
                'message' => __('ssh.err_' . $verdict['erreur']),
                'preflight' => $verdict['brut'],
            ], $verdict['erreur'] === 'aucune_machine' ? 400 : 502);
        }

        if ($verdict['concluant'] === null) {
            return response()->json([
                'success' => false,
                'etape' => 'preflight',
                'echecs' => $verdict['echecs'],
                'message' => __('ssh.err_preflight_echoue', [
                    'machines' => implode(', ', $verdict['echecs']),
                ]),
                'preflight' => $verdict['brut'],
            ], 409);
        }

        // Le laissez-passer est le SEUL argument accepte par `deploie()` : il
        // n'existe pas de chemin qui atteigne cette ligne sans preflight concluant.
        $resultat = $this->deploiement->deploie($verdict['concluant'], $idCompte, $role, $permissions);

        return response()->json([
            'success' => $resultat['success'],
            'etape' => 'deploiement',
            'message' => $resultat['message'] ?? __('ssh.err_backend_injoignable'),
            'preflight' => $verdict['brut'],
        ], $resultat['success'] ? 200 : 502);
    }
}
