<?php

namespace App\Http\Controllers;

use App\Services\JournalAudit;
use App\Services\Serveurs;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
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
    /** Plafond de taille du CSV importe, en kio. Le legacy n'en a aucun. */
    private const IMPORT_MAX_KO = 512;

    /** Le plafond, pour que la vue l'ANNONCE au lieu de le laisser decouvrir au refus. */
    public static function importMaxKo(): int
    {
        return self::IMPORT_MAX_KO;
    }

    public function __construct(
        private readonly Serveurs $serveurs,
        private readonly JournalAudit $journal,
    ) {}

    public function __invoke(): View
    {
        return view('serveurs', [
            'machines' => $this->serveurs->liste(),
            'etiquettes' => $this->serveurs->etiquettesParMachine(),
            'notes' => $this->serveurs->notesParMachine(),
            'borneNotes' => Serveurs::NOTES_PAR_MACHINE,
            'serveurs' => $this->serveurs,
            'environnements' => Serveurs::ENVIRONNEMENTS,
            'criticites' => Serveurs::CRITICITES,
            'reseaux' => Serveurs::RESEAUX,
            // Les libelles que le JS compose lui-meme. Ils partent en JSON, pas
            // en interpolation : un nom de machine peut porter une apostrophe,
            // et le legacy s'y est casse (E-114).
            'libelles' => [
                'suppr_titre' => __('serveurs.suppr_titre', ['nom' => '__NOM__']),
                'filtre_resultat' => __('serveurs.filtre_resultat', ['n' => '__N__']),
                'test_en_cours' => __('serveurs.test_en_cours'),
                'test_en_ligne' => __('serveurs.test_en_ligne', ['ip' => '__IP__']),
                'test_hors_ligne' => __('serveurs.test_hors_ligne', ['ip' => '__IP__']),
                'test_echec' => __('serveurs.test_echec'),
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

    /**
     * L'import CSV — sous-lot D6e.
     *
     * ══ LE FICHIER EST LA SEULE ENTREE LIBRE, ET ELLE EST BORNEE ════════════
     *
     * Le formulaire ne porte que deux commandes : un champ fichier et une case
     * a cocher. Aucun champ de texte : les colonnes du CSV sont connues
     * d'avance et validees par `champsRefuses()`, le predicat du formulaire
     * d'ajout. Une entree libre validee se contourne par une requete forgee ;
     * une entree libre absente, non.
     *
     * `mimes:csv,txt` se lit sur le CONTENU par Laravel, pas sur l'extension
     * envoyee. Un CSV est du texte : `text/plain` et `text/csv` sont tous deux
     * legitimes, et un `.csv` renomme depuis un binaire est refuse ici plutot
     * que de finir dans `fgetcsv`.
     */
    public function importer(Request $requete): RedirectResponse
    {
        $valide = $requete->validate([
            'fichier' => ['required', 'file', 'mimes:csv,txt', 'max:' . self::IMPORT_MAX_KO],
        ], [], ['fichier' => __('serveurs.imp_champ')]);

        $bilan = $this->serveurs->importeCsv(
            $valide['fichier']->getRealPath(),
            $requete->boolean('ignore_doublons'),
        );

        if ($bilan['crees'] > 0) {
            $this->journalise(
                (int) $requete->session()->get('utilisateur_id', 0),
                'Import CSV: ' . $bilan['crees'] . ' serveurs importes',
            );
        }

        return back()->with('import', $bilan);
    }

    /**
     * Journalise dans `user_logs` EN REPRENANT LA CHAINE DE HACHAGE.
     *
     * Le legacy pose sa trace d'import par un `INSERT (user_id, action)` nu et
     * fabrique donc une orpheline — 1 385 sur 5 939 le 2026-09-02, que son
     * propre bouton « Sceller » ne peut jamais rattraper. Meme idiome que
     * `comptes` et `permissions` : une ecriture non scellee creuserait le trou
     * que D1 a mesure.
     */
    private function journalise(int $auteur, string $action): void
    {
        $action = mb_substr($action, 0, 255);
        $tete = DB::table('user_logs')->whereNotNull('self_hash')
            ->orderByDesc('id')->value('self_hash') ?: JournalAudit::GENESE;
        $ts = time();
        DB::table('user_logs')->insert([
            'user_id' => $auteur,
            'action' => $action,
            'created_at' => date('Y-m-d H:i:s', $ts),
            'prev_hash' => $tete,
            'self_hash' => $this->journal->empreinte($tete, $auteur, $action, $ts),
        ]);
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

    /* ═══ Cycle de vie — sous-lot D6d ═══════════════════════════════════════ */

    /**
     * TROIS ISSUES, TROIS MESSAGES. Le backend n'en distingue que deux, et l'une
     * des deux est un mensonge : son `updated: false` recouvre « rien a changer »
     * et « machine absente » (PARITE E-133). Ici la machine est resolue avant
     * d'etre mutee, donc on sait laquelle des trois on a.
     */
    public function cycle(Request $requete, int $id): RedirectResponse
    {
        $etat = (string) $requete->input('etat', '');

        return match ($this->serveurs->definitCycle($id, $etat)) {
            'introuvable' => back()->with('erreur', __('serveurs.err_introuvable')),
            'inchange' => back()->with('succes', __('serveurs.cycle_inchange')),
            default => back()->with('succes', __('serveurs.cycle_' . $etat . '_fait')),
        };
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
