<?php

namespace App\Http\Controllers;

use App\Services\Droits;
use App\Services\MotDePasse;
use App\Services\StepUp;
use App\Support\Navigation;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Pages du portail deja atteignables apres authentification.
 *
 * Elles sont volontairement minimales : seul le SOCLE est porte a ce stade.
 * Mais elles ORIENTENT — un ecran vide qui ne dit ni ce qui existe ni ou aller
 * laisse croire que la fonction a disparu.
 */
class PortailController extends Controller
{
    public function __construct(private readonly Droits $droits)
    {
    }

    public function cgu(Request $requete): View
    {
        return view('cgu');
    }

    public function accepterCgu(Request $requete): RedirectResponse
    {
        $requete->session()->put('cgu_acceptees', true);

        return redirect()->route('accueil');
    }

    public function accueil(Request $requete): View
    {
        $menu = $this->menuDuCompte($requete);
        $entrees = collect($menu)->flatten(1);

        return view('accueil', [
            'modulesAccessibles' => $entrees->count(),
            'modulesPortes'      => $entrees->filter(fn ($e) => isset($e['route']))->count(),
            'libelleRole'        => $this->libelleRole((int) $requete->session()->get('role_id', 0)),
        ]);
    }

    public function profil(Request $requete): View
    {
        return view('profil', [
            'changementRequis' => (bool) $requete->session()->get('changement_mot_de_passe_requis', false),
            'libelleRole'      => $this->libelleRole((int) $requete->session()->get('role_id', 0)),
            // La politique s'ANNONCE avant d'etre appliquee : personne ne devrait
            // decouvrir une regle en s'y cognant.
            'longueurMinimale' => (int) config('rootwarden.mot_de_passe.longueur_minimale', 15),
            'tailleHistorique' => (int) config('rootwarden.mot_de_passe.taille_historique', 5),
        ]);
    }

    /**
     * Le changement de mot de passe — sous-lot A2.
     *
     * L'un des DEUX blocages de la v2.0 : six comptes actifs sur dix portent
     * `force_password_change = 1`, dont `superadmin`. La page annoncait
     * l'exigence sans l'offrir.
     *
     * Les trois champs sont OBLIGATOIRES et lus par `input()` : ils portent des
     * secrets, donc rien n'est journalise, rien n'est renvoye a la vue, et le
     * formulaire est REVIDE a chaque retour — `withInput()` republierait un mot
     * de passe dans la reponse.
     */
    public function changerMotDePasse(Request $requete, MotDePasse $politique): RedirectResponse
    {
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);
        if ($idCompte === 0) {
            return redirect()->route('connexion');
        }

        $cle = $politique->change(
            $idCompte,
            (string) ($requete->input('current_password') ?? ''),
            (string) ($requete->input('new_password') ?? ''),
            (string) ($requete->input('confirm_password') ?? ''),
            $requete->session()->getId(),
        );

        if ($cle !== MotDePasse::OK) {
            return redirect()->route('profil')->with('mdp_erreur', __($cle));
        }

        /*
         * L'EXIGENCE EST LEVEE EN SESSION AUSSI. La base ne porte plus
         * `force_password_change`, mais le drapeau de session survivrait a la
         * redirection et le bandeau reapparaitrait sur une exigence satisfaite.
         */
        $requete->session()->forget('changement_mot_de_passe_requis');
        // La session courante a survecu a la purge ; on la regenere quand meme,
        // un changement de secret etant le bon moment pour changer d'identifiant.
        $requete->session()->regenerate();

        return redirect()->route('profil')->with('mdp_message', __(MotDePasse::OK));
    }

    /**
     * La re-authentification ponctuelle : verifie un code et pose la marque.
     *
     * Rend du JSON, comme le `step_up_verify.php` du legacy : l'appelant est un
     * script de page, pas une navigation. Le refus ne dit JAMAIS pourquoi il a
     * echoue au-dela du message — ni si le compte a un second facteur, ni
     * combien de tentatives restent.
     *
     * Aucune garde de role : l'exigence porte sur l'action, et l'identifiant du
     * compte vient de la SESSION, jamais du corps de la requete. Un compte de
     * role 1 qui valide un step-up n'obtient rien de plus : la passerelle lui
     * refusera la route pour une autre raison.
     */
    public function verifieStepUp(Request $requete, StepUp $stepUp): JsonResponse
    {
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);
        if ($idCompte === 0) {
            return response()->json(['success' => false, 'message' => __('step_up.session_absente')], 403);
        }

        $cle = $stepUp->verifie(
            $idCompte,
            (string) ($requete->input('action') ?? ''),
            (string) ($requete->input('totp_code') ?? $requete->input('code') ?? ''),
        );

        if ($cle !== StepUp::OK) {
            /*
             * 429 POUR LE SEUL DEPASSEMENT DE QUOTA. Les autres refus rendent
             * 200 avec `success: false`, comme le legacy : un code faux n'est pas
             * une erreur de protocole, et distinguer les statuts renseignerait
             * l'attaquant sur la nature du refus.
             */
            $statut = $cle === 'step_up.trop_de_tentatives' ? 429 : 200;

            return response()->json(['success' => false, 'message' => __($cle)], $statut);
        }

        return response()->json([
            'success'      => true,
            'message'      => __('step_up.valide'),
            'action'       => (string) $requete->input('action'),
            'expire_dans'  => (int) config('rootwarden.step_up_ttl', 900),
        ]);
    }

    /**
     * Rend ses privileges : efface les marques de step-up du compte.
     *
     * Sans garde de role : renoncer a une autorisation n'en demande aucune. Le
     * legacy n'offre aucun equivalent — sa marque vit quinze minutes et rien ne
     * permet de l'abreger.
     */
    public function revoqueStepUp(Request $requete, StepUp $stepUp): JsonResponse
    {
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);
        if ($idCompte === 0) {
            return response()->json(['success' => false, 'message' => __('step_up.session_absente')], 403);
        }

        return response()->json([
            'success'   => true,
            'message'   => __('step_up.revoque'),
            'revoquees' => $stepUp->revoque($idCompte),
        ]);
    }

    /** Le menu tel que le compte connecte le voit — meme source que la vue. */
    private function menuDuCompte(Request $requete): array
    {
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);

        return Navigation::pour(
            (int) $requete->session()->get('role_id', 0),
            $this->droits->permissions($idCompte),
            $this->droits->fonctionnalites(),
        );
    }

    /**
     * Libelle du role. Les identifiants numeriques (1, 2, 3) sont ceux du
     * legacy : ils ne se traduisent pas, ils s'affichent.
     */
    private function libelleRole(int $roleId): string
    {
        return match (true) {
            $roleId >= 3 => __('accueil.role_superadmin'),
            $roleId === 2 => __('accueil.role_admin'),
            default => __('accueil.role_lecteur'),
        };
    }
}
