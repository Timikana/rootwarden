<?php

namespace App\Http\Controllers;

use App\Services\ListeBlancheCve;
use App\Services\Machines;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * La liste blanche des CVE — l'ecran rendu au portage.
 *
 * Meme forme que `PlanificationsCveController` : le controleur ne DECIDE de rien.
 * Il lit la requete, la passe au service, et traduit le refus. Toute la
 * validation vit dans `ListeBlancheCve::valide()`, et c'est ce qui rend
 * impossible un chemin d'ecriture qui sauterait un controle.
 *
 * ⚠ `whitelisted_by` N'EST JAMAIS LU DANS LA REQUETE. Le legacy le prenait du
 * client avec « admin » en repli (`cve.py:673`) ; ici l'identifiant vient de la
 * SESSION et le service resout le nom. Un champ `whitelisted_by` envoye par un
 * client est donc simplement ignore — il n'existe aucun chemin pour l'ecrire.
 */
class ListeBlancheCveController extends Controller
{
    public function __construct(
        private readonly ListeBlancheCve $listeBlanche,
        private readonly Machines $machines,
    ) {
    }

    public function index(): JsonResponse
    {
        return response()->json([
            'success' => true,
            'entrees' => $this->listeBlanche->liste(),
        ]);
    }

    public function store(Request $requete): JsonResponse
    {
        $saisie = $requete->only(['cve_id', 'reason', 'machine_id', 'expires_at', 'sans_expiration']);

        if ($refus = $this->listeBlanche->valide($saisie)) {
            return $this->refuse($refus);
        }

        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);

        return response()->json([
            'success' => true,
            'id' => $this->listeBlanche->pose($saisie, $idCompte),
        ]);
    }

    public function destroy(int $id): JsonResponse
    {
        /*
         * Le legacy rend `{'deleted': rowcount > 0}` avec un 200 meme quand
         * l'entree n'existait pas (`cve.py:705`). Ici l'absence est un 404 : un
         * 200 sur une suppression qui n'a rien supprime laisse croire que le
         * geste a eu lieu — la meme forme que le « 200 + la liste » corrige sur
         * les planifications.
         */
        if (! $this->listeBlanche->supprime($id)) {
            return response()->json([
                'success' => false,
                'message' => __('liste_blanche.err_introuvable'),
            ], 404);
        }

        return response()->json(['success' => true, 'deleted' => true]);
    }

    /**
     * Un refus de validation, en 400, avec le motif de CHAQUE champ.
     *
     * @param  array<string,string>  $refus
     */
    private function refuse(array $refus): JsonResponse
    {
        $messages = [];
        foreach ($refus as $champ => $motif) {
            $messages[$champ] = __('liste_blanche.err_' . $motif);
        }

        return response()->json([
            'success' => false,
            'champs' => $messages,
            'message' => implode(' · ', $messages),
        ], 400);
    }
}
