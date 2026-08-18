<?php

namespace App\Http\Controllers;

use App\Services\Droits;
use App\Support\RoutesBackend;
use Illuminate\Http\Request;
// Type de retour : l'ancetre commun de Response et JsonResponse. Annoncer
// Illuminate\Http\Response ferait echouer tout `response()->json()` — qui
// n'en herite PAS — avec une erreur 500 au lieu du refus attendu.
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Passerelle vers le backend Python.
 *
 * Le navigateur ne parle JAMAIS au backend directement : il passe par ici. La
 * cle d'API reste cote serveur, et chaque appel est filtre avant d'etre
 * transmis.
 *
 * L'ordre des controles n'est pas negociable, du moins couteux au plus
 * couteux, et fail-closed a chaque etape :
 *   1. session completement authentifiee  (middleware)
 *   2. jeton CSRF sur les methodes mutantes (middleware web)
 *   3. chemin sans traversee
 *   4. liste blanche
 *   5. reserve a l'administration
 *   6. re-authentification ponctuelle exigee
 *   7. transmission
 */
class PasserelleController extends Controller
{
    /** Methodes qui portent un corps a transmettre. */
    private const AVEC_CORPS = ['POST', 'PUT', 'PATCH'];

    public function __construct(private readonly Droits $droits)
    {
    }

    public function __invoke(Request $requete, string $chemin = ''): Response
    {
        $chemin = '/' . ltrim($chemin, '/');

        if ($chemin === '/') {
            return $this->refus(400, 'passerelle.aucune_route');
        }

        // 3. Traversee de chemin. Meme liste que le legacy.
        if (str_contains($chemin, '..') || str_contains($chemin, '//') || str_contains($chemin, '\\')) {
            return $this->refus(400, 'passerelle.chemin_invalide');
        }

        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);
        $roleId   = (int) $requete->session()->get('role_id', 0);

        // 4. Liste blanche, fail-closed : tout ce qui n'est pas liste est refuse.
        if (! RoutesBackend::autorisee($chemin)) {
            Log::warning('passerelle: route hors liste blanche', ['chemin' => $chemin, 'compte' => $idCompte]);

            return $this->refus(403, 'passerelle.route_non_autorisee');
        }

        // 5. Defense en profondeur : le backend garde deja ces routes, on ne
        //    depend jamais d'un seul rempart.
        if ($roleId < 2 && RoutesBackend::reserveeAdmin($chemin)) {
            Log::warning('passerelle: route admin refusee', ['chemin' => $chemin, 'role' => $roleId, 'compte' => $idCompte]);

            return $this->refus(403, 'passerelle.privileges_insuffisants');
        }

        // 6. Re-authentification ponctuelle. Elle n'est PAS encore portee : on
        //    refuse plutot que de transmettre. Accorder une action qui donne
        //    root sans le second controle que le legacy exige serait un recul.
        if (RoutesBackend::exigeStepUp($chemin)) {
            return response()->json([
                'success'          => false,
                'message'          => __('passerelle.step_up_requis'),
                'step_up_required' => true,
                'action'           => 'policy_action',
                'portage'          => 'non_porte',
            ], 403);
        }

        return $this->transmet($requete, $chemin, $idCompte, $roleId);
    }

    /** Transmet la requete au backend et rend sa reponse telle quelle. */
    private function transmet(Request $requete, string $chemin, int $idCompte, int $roleId): Response
    {
        $base = rtrim((string) config('rootwarden.backend.url'), '/');
        $cle  = (string) config('rootwarden.backend.cle_api');

        $entetes = [
            'X-API-KEY'           => $cle,
            'X-User-ID'           => (string) $idCompte,
            'X-User-Role'         => (string) $roleId,
            // Les permissions sont relues EN BASE, pas prises dans la session :
            // une permission revoquee cesse d'agir a la requete suivante.
            'X-User-Permissions'  => json_encode($this->droits->permissions($idCompte)),
        ];

        $methode = strtoupper($requete->method());

        try {
            $client = Http::withHeaders($entetes)
                // Le backend presente un certificat interne : la verification
                // n'a pas de sens sur un reseau Docker prive, et le legacy la
                // desactive deja.
                ->withoutVerifying()
                ->timeout((int) config('rootwarden.backend.delai', 120));

            $reponse = match (true) {
                in_array($methode, self::AVEC_CORPS, true) => $client
                    ->withBody($requete->getContent(), $requete->header('Content-Type', 'application/json'))
                    ->send($methode, $base . $chemin, ['query' => $requete->query()]),
                default => $client->send($methode, $base . $chemin, ['query' => $requete->query()]),
            };
        } catch (\Throwable $e) {
            Log::error('passerelle: backend injoignable', ['chemin' => $chemin, 'erreur' => $e->getMessage()]);

            return $this->refus(502, 'passerelle.backend_injoignable');
        }

        // Le statut du backend est PROPAGE : un 404 qui deviendrait 200 ferait
        // croire au frontend que l'appel a reussi.
        return response(
            $reponse->body(),
            $reponse->status(),
            ['Content-Type' => $reponse->header('Content-Type') ?: 'application/json'],
        );
    }

    private function refus(int $statut, string $cle): Response
    {
        return response()->json(['success' => false, 'message' => __($cle)], $statut);
    }
}
