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
            'etiquettes' => $this->serveurs->etiquettesParMachine(),
            'notes' => $this->serveurs->notesParMachine(),
            'borneNotes' => Serveurs::NOTES_PAR_MACHINE,
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

    /* ═══ Etiquettes et notes — sous-lot D6b ════════════════════════════════ */

    /*
     * QUATRE FORMULAIRES, PAS UN `fetch`. Les quatre gestes du legacy passent
     * par `fetch('/adm/includes/server_actions.php')`, et les quatre sont
     * INERTES : l'enrobage de `window.fetch` n'injecte le jeton CSRF que pour
     * trois familles d'URL, dont `/adm/includes/` ne fait pas partie. Chaque
     * clic recoit « Token CSRF invalide » (PARITE E-125).
     *
     * Un formulaire n'a pas ce probleme : `@csrf` pose le champ, le cadre le
     * verifie, et le geste marche SANS une ligne de JavaScript. Le legacy
     * rechargeait la page apres chaque succes (`location.reload()`) — le rendu
     * est donc le meme, pour une piece mobile en moins.
     */

    public function poserEtiquette(Request $requete, int $id): RedirectResponse
    {
        $erreur = $this->serveurs->poseEtiquette($id, (string) $requete->input('etiquette', ''));

        return $erreur !== null
            ? back()->with('erreur', __($erreur))
            : back()->with('succes', __('serveurs.etiquette_posee'));
    }

    public function retirerEtiquette(Request $requete, int $id): RedirectResponse
    {
        $this->serveurs->retireEtiquette($id, (string) $requete->input('etiquette', ''));

        return back()->with('succes', __('serveurs.etiquette_retiree'));
    }

    public function poserNote(Request $requete, int $id): RedirectResponse
    {
        // L'AUTEUR VIENT DE LA SESSION. Le legacy fait de meme
        // (`$_SESSION['username']`), et c'est le seul choix defendable : une
        // trace dont on choisit la signature ne trace rien.
        $auteur = (string) $requete->session()->get('utilisateur_nom', '');
        $erreur = $this->serveurs->poseNote($id, (string) $requete->input('note', ''), $auteur);

        return $erreur !== null
            ? back()->with('erreur', __($erreur))
            : back()->with('succes', __('serveurs.note_posee'));
    }

    public function supprimerNote(int $id, int $note): RedirectResponse
    {
        // Resolue par le COUPLE machine + note : viser la note d'une autre
        // machine ne supprime rien. Le legacy resout par le seul identifiant.
        return $this->serveurs->supprimeNote($id, $note)
            ? back()->with('succes', __('serveurs.note_supprimee'))
            : back()->with('erreur', __('serveurs.err_note_introuvable'));
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
