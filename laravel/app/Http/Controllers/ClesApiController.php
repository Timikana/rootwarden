<?php

namespace App\Http\Controllers;

use App\Services\ClesApi;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Les cles d'API — module `adm/`, sous-lot D7.
 *
 * LA CREATION NE REDIRIGE PAS, ET C'EST DELIBERE. La cle en clair n'existe
 * qu'une fois ; la faire transiter par un message de session la deposerait sur
 * le disque du conteneur (pilote `file`), la ou le legacy ne l'ecrit nulle
 * part. La vue est donc rendue DIRECTEMENT en reponse au POST.
 *
 * Le prix est connu et assume : recharger la page apres une creation repropose
 * le formulaire au navigateur. Le legacy a exactement le meme comportement, et
 * la deuxieme soumission echouerait de toute facon sur l'unicite du nom.
 */
class ClesApiController extends Controller
{
    public function __construct(private readonly ClesApi $cles) {}

    public function __invoke(): View
    {
        return $this->rendu();
    }

    public function creer(Request $requete): View
    {
        $modules = $requete->input('modules', []);
        $resultat = $this->cles->cree(
            (string) $requete->input('nom', ''),
            is_array($modules) ? array_map('strval', $modules) : [],
            $requete->input('indice') === null ? null : (string) $requete->input('indice'),
            (int) $requete->session()->get('utilisateur_id', 0),
        );

        if (isset($resultat['erreur'])) {
            return $this->rendu(erreur: __($resultat['erreur']));
        }

        // LA VALEUR EN CLAIR NE VA PAS PLUS LOIN QUE CETTE REPONSE.
        return $this->rendu(cleUnique: $resultat['cle'], succes: __('cles.creee'));
    }

    public function revoquer(int $id): RedirectResponse
    {
        // Le nom se lit AVANT : apres, « cle revoquee » sans son nom ne dit pas
        // laquelle. Et une revocation ne rend jamais de secret : redirection.
        $nom = $this->cles->nom($id);

        return $this->cles->revoque($id)
            ? redirect()->route('cles-api')->with('succes', __('cles.revoquee', ['nom' => (string) $nom]))
            : redirect()->route('cles-api')->with('erreur', __('cles.err_revocation'));
    }

    /** Le rendu commun. `cleUnique` n'est jamais lue depuis la session. */
    private function rendu(?string $cleUnique = null, ?string $succes = null, ?string $erreur = null): View
    {
        return view('cles-api', [
            'cles' => $this->cles->liste(),
            'modules' => array_keys(ClesApi::MODULES),
            'motifsParModule' => ClesApi::MODULES,
            'cleUnique' => $cleUnique,
            'succesDirect' => $succes,
            'erreurDirecte' => $erreur,
        ]);
    }
}
