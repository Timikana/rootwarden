<?php

namespace App\Http\Controllers;

use App\Services\AlertesAccueil;
use App\Services\Droits;
use App\Services\Comptes;
use App\Services\Machines;
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
    public function __construct(
        private readonly Droits $droits,
        private readonly Machines $machines,
        private readonly Comptes $comptes,
        private readonly AlertesAccueil $alertes,
    )
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

    /**
     * L'ORDRE DES RACCOURCIS, repris de `legacy/index.php:363-385`.
     *
     * Douze tuiles, dans cet ordre. Ce ne sont pas les douze premieres entrees
     * du menu : c'est une selection, et l'ordre du legacy est conserve parce
     * qu'un exploitant qui connait la page retrouve ses reperes au meme endroit.
     *
     * `documentation` est la douzieme et le legacy l'affiche SANS condition.
     * Elle est ici soumise au menu comme les autres — ce qui ne change rien en
     * pratique (l'entree est accessible a tous les roles) et evite une regle
     * particuliere pour une seule tuile.
     */
    private const RACCOURCIS = [
        'ssh_keys', 'updates', 'iptables', 'cve_scan', 'admin', 'supervision',
        'bashrc', 'graylog', 'wazuh', 'ssh_audit', 'compliance', 'documentation',
    ];

    public function accueil(Request $requete): View
    {
        $menu = $this->menuDuCompte($requete);
        $entrees = collect($menu)->flatten(1);

        /*
         * ══ LES TUILES SE DERIVENT DU MENU, ELLES NE RECOPIENT PAS SES GARDES ══
         *
         * `legacy/index.php` reecrit ONZE tests de permission pour ses douze
         * tuiles — les memes que son menu, une seconde fois. Deux copies d'une
         * regle de droits finissent par diverger, et c'est le motif que ce
         * portage refuse partout ailleurs.
         *
         * Ici `Navigation::pour()` a deja applique le role, les permissions ET
         * le drapeau de fonctionnalite (`wazuh`) : on FILTRE son resultat. Une
         * tuile ne peut donc pas apparaitre sans son entree de menu, ni viser
         * l'ancien portail quand la page est portee — les deux se lisent au meme
         * endroit.
         *
         * Le LIBELLE vient de `nav.<cle>`, pas d'un second jeu de cles : le
         * legacy en a deux (`dashboard.sc_*` et son menu) qui disent la meme
         * chose. Seule la DESCRIPTION est propre aux tuiles.
         */
        $parCle = $entrees->keyBy('cle');
        $raccourcis = collect(self::RACCOURCIS)
            ->map(fn (string $cle) => $parCle->get($cle))
            ->filter()
            ->values()
            ->all();

        $role = (int) $requete->session()->get('role_id', 0);
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);

        // Calcules UNE fois : les tuiles les affichent, la region d'alertes les
        // derive. Deux appels donneraient deux nombres a un instant different.
        $indicateurs = $this->machines->indicateurs($role, $idCompte);
        $cve = $this->machines->indicateursCve($role, $idCompte);
        $comptesInd = $this->comptes->indicateursComptes($role);

        /*
         * ══ LE LIEN D'UNE ALERTE SE RESOUT PAR LE MENU ══════════════════
         *
         * Le service ne rend qu'une CLE de navigation ; la destination et le
         * DROIT d'y aller se lisent ici, dans `$parCle`, exactement comme pour
         * les tuiles. Deux consequences, toutes deux voulues :
         *
         *  - `ssh_audit` n'est pas porte : son entree porte `legacy`, donc
         *    l'alerte pointe l'ancien portail avec le marqueur, comme le menu ;
         *  - une personne SANS le droit correspondant n'a pas l'entree, donc
         *    l'alerte s'affiche SANS lien. Le fait reste dit — on ne cache pas
         *    un probleme parce que sa page est fermee — mais on n'offre pas une
         *    porte qui refusera. Aucune garde n'est recopiee ici.
         */
        $alertes = $this->alertes->pour($role, $idCompte, $indicateurs, $cve, $comptesInd);

        $alertes['alertes'] = array_map(function (array $a) use ($parCle) {
            $entree = $a['nav'] !== null ? $parCle->get($a['nav']) : null;

            $a['lien'] = null;
            $a['externe'] = false;

            if ($entree !== null) {
                if (isset($entree['route'])) {
                    $a['lien'] = route($entree['route']);
                } else {
                    $a['lien'] = rtrim((string) config('app.url_legacy'), '/') . $entree['legacy'];
                    $a['externe'] = true;
                }
            }

            return $a;
        }, $alertes['alertes']);

        return view('accueil', [
            'modulesAccessibles' => $entrees->count(),
            'modulesPortes'      => $entrees->filter(fn ($e) => isset($e['route']))->count(),
            'libelleRole'        => $this->libelleRole((int) $requete->session()->get('role_id', 0)),
            'raccourcis'         => $raccourcis,
            /*
             * ══ LES NEUF INDICATEURS DU LEGACY, TOUS BORNES ══════════════
             *
             * `legacy/index.php:78-104` les calcule SANS borne. Trois familles,
             * trois bornes differentes, et c'est ce que l'arbitrage §1 ne
             * couvrait qu'a moitie :
             *
             *   - les indicateurs de MACHINES  -> bornes au perimetre ;
             *   - ceux de VULNERABILITES       -> bornes au perimetre aussi,
             *     parce que `cve_scans` porte `machine_id` (mesure) — le DSI
             *     les donnait pour non bornables, la donnee dit le contraire ;
             *   - ceux de COMPTES              -> bornes par ROLE, parce qu'un
             *     perimetre de machines ne borne pas une population d'usagers.
             *
             * Le gel de role des trois derniers vit DANS le service, pas ici :
             * une garde posee dans le controleur serait a reecrire au second
             * appelant.
             */
            'indicateurs'        => $indicateurs,
            'cve'                => $cve,
            'comptes'            => $comptesInd,
            /*
             * ══ LA REGION D'ALERTES SE DERIVE, ELLE NE RELIT PAS ══════════
             *
             * E-264. Cinq des huit alertes du legacy comptent un fait deja
             * affiche par les tuiles ci-dessus — et le legacy les relit sans
             * borne. Les passer ici, plutot que de les recalculer, garantit que
             * l'alerte et la tuile portent LE MEME NOMBRE : la coherence n'est
             * plus une propriete a surveiller, elle est structurelle.
             *
             * Le service ajoute les trois faits qu'aucune tuile ne montre, et
             * NOMME les familles qu'il n'a pas su lire — une region vide se lit
             * « tout va bien », et c'est le mensonge le plus couteux d'un
             * tableau de bord de securite.
             */
            'alertes'            => $alertes,
            // E-208 : borne au perimetre, ET le total du parc avec.
            'parc'               => $this->machines->compteursPerimetre(
                (int) $requete->session()->get('role_id', 0),
                (int) $requete->session()->get('utilisateur_id', 0),
            ),
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
