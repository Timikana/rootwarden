<?php

namespace App\Http\Controllers;

use App\Services\ClesPubliques;
use App\Services\Comptes;
use App\Services\JournalAudit;
use App\Services\Machines;
use App\Services\Permissions;
use App\Services\StepUp;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\View\View;

/**
 * Les permissions fonctionnelles et les acces machines — sous-lot D5.
 *
 * ══ LA GARDE RESTE, ET LE CHEMIN POUR Y REPONDRE EXISTE ════════════════════
 *
 * Le legacy exige un step-up sur `update_permissions.php:60` — c'est bien. Mais
 * le modal qui permettrait de le fournir est une surcouche de `window.fetch`,
 * et la case est declenchee par htmx, qui n'emploie que `XMLHttpRequest` : la
 * surcouche ne voit jamais la requete, aucun geste d'interface ne permet
 * d'obtenir la marque, et htmx ne remplace rien sur un 4xx. Mesure du
 * 2026-08-26 : le POST part, le 403 revient, `can_scan_cve` reste a 0, et
 * l'ecran ne bouge pas. Trois pieces correctes qui forment une impasse — E-119.
 *
 * Ici la garde est la MEME, et le panneau de re-authentification EN PAGE ecrit
 * pour D4 la rend franchissable : le refus s'annonce, on saisit le code, et le
 * geste repart.
 */
class PermissionsController extends Controller
{
    public function __construct(
        private readonly Permissions $permissions,
        private readonly Comptes $comptes,
        private readonly JournalAudit $journal,
        private readonly StepUp $stepUp,
        private readonly ClesPubliques $cles,
    ) {
    }

    private function qui(Request $requete): array
    {
        return [
            (int) $requete->session()->get('utilisateur_id', 0),
            (int) $requete->session()->get('role_id', 0),
        ];
    }

    /**
     * Journalise dans `user_logs` en DELEGUANT au seul ecrivain qui verrouille.
     *
     * ⚠ CETTE METHODE LISAIT LA TETE DE CHAINE SANS VERROU — corrige le
     * 2026-09-05. Elle faisait `orderByDesc('id')->value('self_hash')` hors
     * transaction, la ou `JournalAudit::ajoute()` prend `lockForUpdate()` sur la
     * tete DANS une transaction.
     *
     * > *Deux ecritures concurrentes qui lisent la meme tete produisent deux
     * > lignes portant le MEME `prev_hash`, donc une chaine FOURCHUE, que
     * > `verifie()` signalera comme rompue sans pouvoir dire laquelle des deux
     * > branches est la bonne.*
     *
     * C'etait l'une des « trois copies restant a migrer » que le docblock
     * d'`ajoute()` annonce lui-meme. *Une copie qui delegue ne peut plus
     * diverger.*
     */
    private function journalise(int $auteur, string $action): void
    {
        $this->journal->ajoute($auteur, $action);
    }

    public function __invoke(Request $requete, Machines $machines): View
    {
        $comptes = $this->comptes->liste();
        $droits = [];
        $acces = [];
        $presets = [];
        $cles = [];
        foreach ($comptes as $c) {
            $droits[$c['id']] = $this->permissions->pour($c['id']);
            $acces[$c['id']] = $this->permissions->machinesDe($c['id']);
            $presets[$c['id']] = $this->permissions->presetsDe($c['id']);
            $cles[$c['id']] = $this->cles->duCompte($c['id']);
        }

        [$moi, $monRole] = $this->qui($requete);

        return view('permissions', [
            'comptes' => $comptes,
            /*
             * Qui regarde : la vue ne propose pas un geste que `refuse()` et
             * `definitAcces()` rejetteraient (soi-meme, rang egal ou superieur).
             * Une case qui repond toujours « impossible » n'est pas un controle.
             */
            'moi' => $moi,
            'monRole' => $monRole,
            'permissions' => $this->permissions->toutes(),
            'droits' => $droits,
            'acces' => $acces,
            'presets' => $presets,
            // Les cles SSH de chaque compte, avec leur portee : la vue les range
            // PAR MACHINE, l'inverse du profil qui les range par cle.
            'cles' => $cles,
            /*
             * La liste FERMEE vient du SERVICE, pas de la vue : c'est la meme
             * qui valide cote serveur. Deux listes divergeraient, et celle qui
             * decide n'est pas celle qu'on lit.
             */
            'presetsProposes' => Permissions::PRESETS,
            'presetsAbsents' => Permissions::PRESETS_ABSENTS,
            'machines' => $machines->liste(),
            // Sous-lot D5b : la moitie de `manage_permissions.php` que D5 avait
            // laissee dehors. Lue en base ; l'octroi passe par la passerelle,
            // parce qu'il NOTIFIE (E-134).
            'temporaires' => $this->permissions->temporaires(),
            'dureesTemporaires' => [1, 4, 8, 24, 72, 168],
        ]);
    }

    /**
     * Revoque un octroi temporaire — sous-lot D5b.
     *
     * ECRIT EN BASE : `DELETE /admin/temp_permissions/<id>` n'a aucun effet de
     * bord, contrairement a l'octroi qui notifie. Et c'est un FORMULAIRE, pas un
     * `fetch` : les quatre gestes de D6b ont montre ce que coute un jeton qui
     * n'arrive pas.
     *
     * LE ROLE 2 REVOQUE, LA OU IL FAUT LE ROLE 3 POUR ACCORDER. Ce n'est pas une
     * incoherence : `admin.py` fait le meme partage (`@require_role(3)` sur le
     * POST, `(2)` sur le DELETE). Retirer un droit est un geste de moindre
     * consequence que l'accorder. La route de cette page exige de toute facon
     * `role:3` — le partage est releve, pas exerce.
     */
    public function revoquerTemporaire(int $id): RedirectResponse
    {
        // Le libelle se lit AVANT : apres, il n'y a plus rien a nommer.
        $libelle = $this->permissions->libelleTemporaire($id);

        return $this->permissions->revoqueTemporaire($id)
            ? redirect()->route('permissions')->with('succes', __('perms.temp_revoque', ['quoi' => (string) $libelle]))
            : redirect()->route('permissions')->with('erreur', __('perms.temp_err_revocation'));
    }

    /** Le refus commun : soi-meme, et le rang. Repris du legacy. */
    private function refuse(int $id, int $auteur, int $roleAuteur): ?string
    {
        if ($id === $auteur) {
            return 'perms.err_soi_meme';
        }
        $cible = $this->comptes->trouve($id);
        if (! $cible) {
            return 'perms.err_inconnu';
        }
        if ((int) $cible['role_id'] >= $roleAuteur) {
            return 'perms.err_rang';
        }

        return null;
    }

    public function definir(Request $requete, int $id): JsonResponse
    {
        [$auteur, $roleAuteur] = $this->qui($requete);
        if (($refus = $this->refuse($id, $auteur, $roleAuteur)) !== null) {
            return response()->json(['success' => false, 'message' => __($refus)], 403);
        }
        $nom = (string) $requete->input('permission', '');
        if (! $this->permissions->connue($nom)) {
            return response()->json(['success' => false, 'message' => __('perms.err_permission')], 422);
        }
        // `ConvertEmptyStringsToNull` rend « vide » indiscernable d'« absent » :
        // on teste la PRESENCE avant de lire la valeur.
        if (! $requete->has('value')) {
            return response()->json(['success' => false, 'message' => __('perms.err_valeur')], 422);
        }

        // LA GARDE RESTE — et cette fois il existe un chemin pour y repondre.
        if (! $this->stepUp->valide($auteur, 'permission_definir')) {
            return response()->json([
                'success' => false,
                'step_up_required' => true,
                'action' => 'permission_definir',
                'message' => __('perms.err_step_up'),
            ], 403);
        }

        $actif = $requete->boolean('value');
        $this->permissions->definit($id, $nom, $actif);
        $this->journalise($auteur,
            ($actif ? 'Activation' : 'Desactivation') . " de la permission {$nom} pour le compte #{$id}");

        return response()->json([
            'success' => true,
            'actif' => $actif,
            'message' => $actif ? __('perms.activee') : __('perms.desactivee'),
        ]);
    }

    public function acces(Request $requete, int $id): JsonResponse
    {
        [$auteur, $roleAuteur] = $this->qui($requete);
        $cible = $this->comptes->trouve($id);
        if (! $cible) {
            return response()->json(['success' => false, 'message' => __('perms.err_inconnu')], 404);
        }
        // Pas de garde de rang ici : le legacy n'en pose pas non plus sur les
        // acces machines, et en ajouter une RETIRERAIT une possibilite a un
        // role — ce n'est pas une decision de portage.
        $machine = (int) $requete->input('machine_id', 0);
        if (! $requete->has('value')) {
            return response()->json(['success' => false, 'message' => __('perms.err_valeur')], 422);
        }
        $accorde = $requete->boolean('value');

        /*
         * `has()` pour l'EXISTENCE, `input() ?? ''` pour la valeur.
         * `ConvertEmptyStringsToNull` est dans le groupe `web` : `input('preset')`
         * rend `null` pour une chaine vide, ce qui est indiscernable d'un champ
         * non soumis. Ici la distinction compte — « ne touche pas au prereglage »
         * n'est pas « mets-le a vide ».
         */
        $preset = $requete->has('preset')
            ? (string) ($requete->input('preset') ?? '')
            : null;

        $err = $this->permissions->definitAcces($id, $machine, $accorde, $auteur, $roleAuteur, $preset);
        if ($err !== null) {
            return response()->json(['success' => false, 'message' => __($err)], 403);
        }
        $trace = $accorde ? 'Octroi' : 'Retrait';
        if ($accorde && $preset !== null) {
            // Un octroi de PRIVILEGE se trace avec le privilege accorde : sans le
            // prereglage, le journal ne dit pas ce qui a ete donne.
            $trace .= " (sudo: {$preset})";
        }
        $this->journalise($auteur,
            $trace . " de l'acces machine #{$machine} pour le compte #{$id}");

        /*
         * `preset` est rendu pour que l'ECRAN affiche ce que le serveur a ECRIT,
         * et non ce qui lui a ete demande. Sur un ecran de privilege la
         * difference compte : une liste qui montre « sudo complet » alors que la
         * base porte autre chose ferait decider la suite sur une croyance
         * fausse. Un octroi sans prereglage explicite vaut `none` — c'est le
         * defaut de la colonne (051), pas une absence de decision.
         */
        return response()->json([
            'success' => true,
            'actif' => $accorde,
            'preset' => $accorde ? ($preset ?? 'none') : null,
            'message' => $accorde ? __('perms.acces_accorde') : __('perms.acces_retire'),
        ]);
    }

    /**
     * Pose ou retire une cle RESTREINTE d'un compte sur une machine — la vue par
     * serveur des cles. Elle ecrit `user_ssh_key_machines` par le meme service
     * que le profil, donc sous les memes regles : la machine doit etre
     * accessible au compte, une cle valable partout ne se decoche pas ici, et
     * une portee ne se vide pas.
     *
     * Pas de garde de rang ni de step-up, comme `acces()` : ce geste ne fait
     * que REPARTIR des cles deja enregistrees sur des machines deja ouvertes.
     * Il n'ouvre rien que `acces()` n'ait ouvert.
     */
    public function cle(Request $requete, int $id, int $cle): JsonResponse
    {
        [$auteur] = $this->qui($requete);
        if (! $this->comptes->trouve($id)) {
            return response()->json(['success' => false, 'message' => __('perms.err_inconnu')], 404);
        }
        if (! $requete->has('value')) {
            return response()->json(['success' => false, 'message' => __('perms.err_valeur')], 422);
        }
        $machine = (int) $requete->input('machine_id', 0);
        $posee = $requete->boolean('value');

        $avant = $this->cles->portee($id, $cle);
        $err = $this->cles->basculeSurMachine($id, $cle, $machine, $posee);
        if ($err !== null) {
            // Les messages du service parlent au titulaire (« votre compte ») ;
            // ici c'est un administrateur qui lit, d'ou le jeu `perms.`.
            return response()->json(['success' => false, 'message' => __(str_replace('profil.', 'perms.', $err))],
                $err === 'profil.err_cle_introuvable' ? 404 : 422);
        }
        $apres = (array) $this->cles->portee($id, $cle);
        $this->journalise($auteur, "Portee de la cle SSH #{$cle} du compte #{$id} modifiee ("
            . ClesPubliques::decrit((array) $avant) . ' → ' . ClesPubliques::decrit($apres) . ')');

        return response()->json([
            'success' => true,
            'actif' => in_array($machine, array_column($apres['machines'], 'id'), true),
            'message' => $posee ? __('perms.cle_posee') : __('perms.cle_retiree'),
        ]);
    }

    /**
     * Ajoute une cle SSH au compte d'AUTRUI — le geste du legacy
     * (`manage_users.php`, superadmin) que le portage n'exposait sur aucun
     * ecran. Il AJOUTE une cle : les autres cles du compte restent.
     *
     * ⚠ GARDE DE RANG ET STEP-UP. Une cle posee ouvre une connexion SSH sous le
     * nom du compte : on ne la pose ni dans son propre compte (le profil sert a
     * ca), ni dans celui d'un rang egal ou superieur — un superadmin ne plante
     * pas une cle chez un autre. Et la marque est propre au geste
     * (`cle_ssh_poser`).
     */
    public function ajouterCle(Request $requete, int $id): JsonResponse
    {
        [$auteur, $roleAuteur] = $this->qui($requete);
        if (($refus = $this->refuse($id, $auteur, $roleAuteur)) !== null) {
            return response()->json(['success' => false, 'message' => __($refus)], 403);
        }
        if (! $this->stepUp->valide($auteur, 'cle_ssh_poser')) {
            return response()->json([
                'success' => false,
                'step_up_required' => true,
                'action' => 'cle_ssh_poser',
                'message' => __('perms.err_step_up'),
            ], 403);
        }

        $toutes = $requete->input('portee', 'toutes') !== 'machines';
        $libelle = trim((string) $requete->input('libelle', ''));
        $err = $this->cles->ajoute($id, $libelle, (string) $requete->input('cle_ssh', ''),
            $toutes, (array) $requete->input('machines', []));
        if ($err !== null) {
            return response()->json(['success' => false, 'message' => __(str_replace('profil.', 'perms.', $err))], 422);
        }
        $this->journalise($auteur, "Cle SSH « {$libelle} » ajoutee au compte #{$id} ("
            . ($toutes ? 'toutes ses machines' : 'portee restreinte') . ')');
        $message = __('perms.cle_ajoutee');
        // La page se RECHARGE apres le geste : la liste se relit du serveur.
        $requete->session()->flash('succes', $message);

        return response()->json(['success' => true, 'message' => $message]);
    }

    /** Retire UNE cle d'un compte. Meme garde de rang ; pas de step-up : retirer ferme. */
    public function retirerCle(Request $requete, int $id, int $cle): JsonResponse
    {
        [$auteur, $roleAuteur] = $this->qui($requete);
        if (($refus = $this->refuse($id, $auteur, $roleAuteur)) !== null) {
            return response()->json(['success' => false, 'message' => __($refus)], 403);
        }
        if (! $this->cles->retire($id, $cle)) {
            return response()->json(['success' => false, 'message' => __('perms.err_cle_introuvable')], 404);
        }
        $this->journalise($auteur, "Cle SSH #{$cle} retiree du compte #{$id}");
        $message = __('perms.cle_retiree_du_compte');
        $requete->session()->flash('succes', $message);

        return response()->json(['success' => true, 'message' => $message]);
    }
}
