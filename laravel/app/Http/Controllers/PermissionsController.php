<?php

namespace App\Http\Controllers;

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
    ) {
    }

    private function qui(Request $requete): array
    {
        return [
            (int) $requete->session()->get('utilisateur_id', 0),
            (int) $requete->session()->get('role_id', 0),
        ];
    }

    /** Meme scellement que D1 : une ecriture nue creuserait le trou qu'il mesure. */
    private function journalise(int $auteur, string $action): void
    {
        $tete = DB::table('user_logs')->whereNotNull('self_hash')
            ->orderByDesc('id')->value('self_hash') ?: JournalAudit::GENESE;
        $ts = time();
        DB::table('user_logs')->insert([
            'user_id' => $auteur,
            'action' => mb_substr($action, 0, 255),
            'created_at' => date('Y-m-d H:i:s', $ts),
            'prev_hash' => $tete,
            'self_hash' => $this->journal->empreinte($tete, $auteur, mb_substr($action, 0, 255), $ts),
        ]);
    }

    public function __invoke(Request $requete, Machines $machines): View
    {
        $comptes = $this->comptes->liste();
        $droits = [];
        $acces = [];
        foreach ($comptes as $c) {
            $droits[$c['id']] = $this->permissions->pour($c['id']);
            $acces[$c['id']] = $this->permissions->machinesDe($c['id']);
        }

        return view('permissions', [
            'comptes' => $comptes,
            'permissions' => $this->permissions->toutes(),
            'droits' => $droits,
            'acces' => $acces,
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
        $err = $this->permissions->definitAcces($id, $machine, $accorde, $auteur, $roleAuteur);
        if ($err !== null) {
            return response()->json(['success' => false, 'message' => __($err)], 403);
        }
        $this->journalise($auteur,
            ($accorde ? 'Octroi' : 'Retrait') . " de l'acces machine #{$machine} pour le compte #{$id}");

        return response()->json([
            'success' => true,
            'actif' => $accorde,
            'message' => $accorde ? __('perms.acces_accorde') : __('perms.acces_retire'),
        ]);
    }
}
