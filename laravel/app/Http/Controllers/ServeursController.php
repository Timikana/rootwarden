<?php

namespace App\Http\Controllers;

use App\Services\Serveurs;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * L'onglet « Serveurs » d'`admin_page.php` — module `adm/`, sous-lot D6a.
 *
 * TROIS GESTES, TROIS ROUTES, TROIS FORMULAIRES. Le legacy les distingue par la
 * presence d'un `name` de bouton dans le meme POST (`add_server`,
 * `update_server`, `delete_server`) : la page entiere repond a une URL unique, et
 * c'est le nom du bouton clique qui decide du geste. Un bouton renomme, un
 * `name` oublie sur un `<button>`, et la modification devient une creation.
 *
 * Ici chaque geste a sa route. Le routeur ne peut plus se tromper de branche, et
 * une suite peut viser un geste sans en traverser un autre.
 */
class ServeursController extends Controller
{
    public function __construct(private readonly Serveurs $serveurs) {}

    public function __invoke(): View
    {
        return view('serveurs', [
            'machines' => $this->serveurs->liste(),
            'environnements' => Serveurs::ENVIRONNEMENTS,
            'criticites' => Serveurs::CRITICITES,
            'reseaux' => Serveurs::RESEAUX,
            // Les libelles que le JS compose lui-meme. Ils partent en JSON, pas
            // en interpolation : un nom de machine peut porter une apostrophe,
            // et le legacy s'y est casse (E-114).
            'libelles' => [
                'suppr_titre' => __('serveurs.suppr_titre', ['nom' => '__NOM__']),
                'filtre_resultat' => __('serveurs.filtre_resultat', ['n' => '__N__']),
            ],
        ]);
    }

    public function ajouter(Request $requete): RedirectResponse
    {
        $brut = $this->brut($requete);

        $refuses = $this->serveurs->champsRefuses($brut);
        if ($refuses !== []) {
            return back()->with('erreur', $this->messageRefus($refuses));
        }

        $brut['password'] = (string) $requete->input('password', '');
        $brut['root_password'] = (string) $requete->input('root_password', '');

        $erreur = $this->serveurs->ajoute($brut);
        if ($erreur !== null) {
            return back()->with('erreur', __($erreur));
        }

        return back()->with('succes', __('serveurs.ajoutee', ['nom' => $brut['name']]));
    }

    public function modifier(Request $requete, int $id): RedirectResponse
    {
        $brut = $this->brut($requete);

        $refuses = $this->serveurs->champsRefuses($brut);
        if ($refuses !== []) {
            return back()->with('erreur', $this->messageRefus($refuses));
        }

        $brut['password'] = (string) $requete->input('password', '');
        $brut['root_password'] = (string) $requete->input('root_password', '');

        // UNE CASE NON COCHEE N'EST PAS SOUMISE. `boolean()` rend false sur un
        // champ absent comme sur « 0 » : c'est exactement la lecture du legacy
        // (`isset($_POST['cleanup_users']) ? 1 : 0`), et elle ne depend pas de
        // `ConvertEmptyStringsToNull`, qui rendrait « vide » indiscernable
        // d'« absent » si on lisait `input()`.
        $erreur = $this->serveurs->modifie($id, $brut, $requete->boolean('cleanup_users'));
        if ($erreur !== null) {
            return back()->with('erreur', __($erreur));
        }

        return back()->with('succes', __('serveurs.modifiee', ['nom' => $brut['name']]));
    }

    public function supprimer(int $id): RedirectResponse
    {
        // Le nom se lit AVANT la suppression : apres, il n'y a plus rien a
        // nommer, et « machine supprimee » sans son nom ne dit pas laquelle.
        $nom = $this->serveurs->nom($id);

        $erreur = $this->serveurs->supprime($id);
        if ($erreur !== null) {
            return back()->with('erreur', __($erreur));
        }

        return back()->with('succes', __('serveurs.supprimee', ['nom' => (string) $nom]));
    }

    /** @return array<string, mixed> */
    private function brut(Request $requete): array
    {
        return [
            'name' => (string) $requete->input('name', ''),
            'ip' => (string) $requete->input('ip', ''),
            'user' => (string) $requete->input('user', ''),
            'port' => (string) $requete->input('port', ''),
            'environment' => (string) $requete->input('environment', ''),
            'criticality' => (string) $requete->input('criticality', ''),
            'network_type' => (string) $requete->input('network_type', ''),
        ];
    }

    /** @param  list<string>  $refuses */
    private function messageRefus(array $refuses): string
    {
        return __('serveurs.err_champs', [
            'champs' => implode(', ', array_map(static fn ($c) => __($c), $refuses)),
        ]);
    }
}
