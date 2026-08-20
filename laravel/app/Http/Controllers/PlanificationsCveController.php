<?php

namespace App\Http\Controllers;

use App\Services\PlanificationsCve;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Module `security/`, sous-lot S4 : les planifications de scans CVE.
 *
 * REMPLACE les cinq routes `cve_schedules` / `cron_preview` du backend, il ne les
 * appelle pas — meme decision qu'en S3, et pour les memes trois raisons mesurees :
 * sur les 19 routes CVE du backend `require_permission` apparait zero fois, le
 * garde d'acces ne lit pas le meme parametre que sa route, et il ne refuse pas
 * quand aucun identifiant n'est trouve. Le backend Python n'est pas touche.
 *
 * UN REFUS REND UN 400 AVEC UN MOTIF TRADUIT. Cote legacy, un `target_type` hors
 * ENUM produit un **500 avec une page HTML** : la route n'a qu'un `try/finally`,
 * l'erreur MySQL 1265 remonte nue. Mesure en fonctionnement. Ici la validation
 * precede l'ecriture, et chaque refus nomme son champ.
 *
 * AUCUN SCAN N'EST DECLENCHE. Creer ou modifier n'ecrit que la table ; le seul
 * declencheur est la boucle du scheduler Python. Voir `PlanificationsCve` pour ce
 * que ce service n'ecrit jamais — `last_run`, et un `next_run` NULL sur une ligne
 * active.
 */
class PlanificationsCveController extends Controller
{
    public function __construct(private readonly PlanificationsCve $planifs)
    {
    }

    public function index(): JsonResponse
    {
        return response()->json([
            'success' => true,
            'planifications' => $this->planifs->liste(),
            'tags' => $this->planifs->tagsDisponibles(),
        ]);
    }

    public function apercu(Request $requete): JsonResponse
    {
        $expression = trim((string) $requete->query('expr', ''));
        if ($expression === '') {
            return response()->json(['success' => false, 'valide' => false,
                                     'message' => __('planif.err_cron_requis')], 400);
        }

        $apercu = $this->planifs->apercu($expression);

        // Une expression invalide n'est pas une erreur de la requete : c'est une
        // REPONSE, et le formulaire l'affiche au fil de la saisie. Le legacy rend
        // 200 ici aussi ; c'est le seul endroit ou son choix est le bon.
        return response()->json([
            'success' => true,
            'valide' => $apercu['valide'],
            'prochaines' => $apercu['prochaines'],
            'intervalle' => $apercu['intervalle'],
            'trop_frequent' => $apercu['valide']
                && $apercu['intervalle'] !== null
                && $apercu['intervalle'] < PlanificationsCve::INTERVALLE_MINIMUM,
        ]);
    }

    public function store(Request $requete): JsonResponse
    {
        $donnees = (array) $requete->json()->all();

        $refus = $this->planifs->valide($donnees, true);
        if ($refus !== []) {
            return $this->refuse($refus);
        }

        $id = $this->planifs->creer(
            $donnees,
            (int) $requete->session()->get('utilisateur_id', 0),
        );

        return response()->json(['success' => true, 'id' => $id]);
    }

    public function update(Request $requete, int $id): JsonResponse
    {
        if (! $this->planifs->parId($id)) {
            return response()->json(['success' => false,
                                     'message' => __('planif.err_introuvable')], 404);
        }

        $donnees = (array) $requete->json()->all();

        // LA MEME VALIDATION QU'A LA CREATION, sur les champs presents. C'est tout
        // le sous-lot : le legacy revalide `scan_source` et RIEN d'autre, si bien
        // que le clamp anti-frequence est contournable par une modification.
        $refus = $this->planifs->valide($donnees, false);
        if ($refus !== []) {
            return $this->refuse($refus);
        }

        $this->planifs->modifier($id, $donnees);

        return response()->json(['success' => true]);
    }

    public function destroy(int $id): JsonResponse
    {
        if (! $this->planifs->parId($id)) {
            return response()->json(['success' => false,
                                     'message' => __('planif.err_introuvable')], 404);
        }

        return response()->json(['success' => true, 'deleted' => $this->planifs->supprimer($id)]);
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
            $messages[$champ] = __('planif.err_' . $motif);
        }

        return response()->json([
            'success' => false,
            'champs' => $messages,
            // Un message unique pour l'affichage court, le detail par champ pour
            // le formulaire.
            'message' => implode(' · ', $messages),
        ], 400);
    }
}
