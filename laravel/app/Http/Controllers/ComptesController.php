<?php

namespace App\Http\Controllers;

use App\Services\Comptes;
use App\Services\JournalAudit;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\View\View;

/**
 * Les comptes du portail — module `adm/`, sous-lot D3.
 *
 * ══ CE QUE CE CONTROLEUR REFUSE, ET QUE LE LEGACY ACCEPTE ══════════════════
 *
 * Un mot de passe que la politique refuse. Le legacy n'exige que huit
 * caracteres quand c'est un administrateur qui fixe le mot de passe d'autrui
 * (E-112) ; ici `Comptes::definitMotDePasse()` est le seul chemin d'ecriture, et
 * il applique la meme politique pour tout le monde.
 *
 * ══ CE QU'IL N'AFFICHE PAS ═════════════════════════════════════════════════
 *
 * Le mot de passe genere. Le legacy le place dans le HTML de la page
 * (`manage_roles.php:93`), d'ou il part dans l'historique du navigateur et dans
 * tout cache intermediaire — et `strip_tags` l'ampute au passage (E-113). Ici il
 * est rendu UNE fois, dans la reponse JSON du geste qui l'a demande, et la page
 * le montre dans un champ prevu pour cela. Il ne traverse aucun filtre.
 *
 * ══ AUCUNE BOITE NATIVE ════════════════════════════════════════════════════
 *
 * E-114 : deux chaines de langue francaises portent une apostrophe, placee dans
 * un `confirm('…')` — le litteral se ferme, l'`onclick` ne s'analyse pas, et
 * DEUX actions destructrices partent sans confirmation. En anglais elles
 * demandent bien confirmation. Le portage n'a pas de boite native : le texte
 * traduit y est du CONTENU, jamais du code, et le probleme ne peut pas exister.
 *
 * ══ CHAQUE ECRITURE EST JOURNALISEE, QUELLE QUE SOIT LA PORTE ══════════════
 *
 * E-115 : le legacy a trois ecrivains pour `users.ssh_key`, dont un qui ne
 * journalise rien. Ici il n'y a qu'un chemin par geste, et chacun journalise.
 */
class ComptesController extends Controller
{
    public function __construct(
        private readonly Comptes $comptes,
        private readonly JournalAudit $journal,
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
     * Journalise dans `user_logs` en reprenant la chaine de hachage — le meme
     * scellement que le sous-lot D1 verifie. Une ecriture non scellee creuserait
     * le trou que D1 vient de mesurer.
     */
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

    public function __invoke(Request $requete): View
    {
        [, $roleId] = $this->qui($requete);

        return view('comptes', [
            'comptes' => $this->comptes->liste(),
            'roles' => Comptes::ROLES,
            'estSuperadmin' => $roleId >= 3,
            'longueurMinimale' => Comptes::LONGUEUR_MINIMALE,
        ]);
    }

    /* ═══ Creation ═════════════════════════════════════════════════════════ */

    public function creer(Request $requete): RedirectResponse
    {
        [$auteur] = $this->qui($requete);
        $nom = trim((string) $requete->input('name', ''));
        if ($nom === '' || mb_strlen($nom) > 255) {
            return back()->with('erreur', __('comptes.err_nom'));
        }
        if (DB::table('users')->where('name', $nom)->exists()) {
            return back()->with('erreur', __('comptes.err_nom_pris'));
        }
        $courriel = filter_var(trim((string) $requete->input('email', '')), FILTER_VALIDATE_EMAIL) ?: null;
        $role = (int) $requete->input('role_id', 1);
        if (! in_array($role, Comptes::ROLES, true)) {
            $role = 1;
        }

        $id = DB::table('users')->insertGetId([
            'name' => $nom,
            // `password` est NOT NULL sans defaut. On pose un hache de 64 octets
            // ALEATOIRES, dont personne ne connait le clair : le compte existe
            // et aucune connexion n'est possible tant qu'un mot de passe n'a pas
            // ete fixe. Idee reprise du legacy (`manage_users.php:97`), avec le
            // cout partage plutot que `PASSWORD_DEFAULT`.
            'password' => password_hash(bin2hex(random_bytes(32)), PASSWORD_BCRYPT,
                ['cost' => (int) config('rootwarden.bcrypt_cost', 12)]),
            'email' => $courriel,
            'company' => trim((string) $requete->input('company', '')) ?: null,
            'role_id' => $role,
            'active' => 1,
            'sudo' => 0,
            'force_password_change' => 1,
        ]);
        $this->journalise($auteur, "Creation du compte '{$nom}' (role={$role})");

        return back()->with('succes', __('comptes.cree', ['nom' => $nom, 'id' => $id]));
    }

    /* ═══ Mot de passe ═════════════════════════════════════════════════════ */

    /**
     * Fixe le mot de passe d'un compte, ou en genere un.
     *
     * Le mot de passe genere est rendu DANS CETTE REPONSE et nulle part
     * ailleurs : ni dans une page, ni dans un journal, ni dans un message de
     * session qui survivrait a la requete.
     */
    public function motDePasse(Request $requete, int $id): JsonResponse
    {
        [$auteur, $roleId] = $this->qui($requete);
        $cible = $this->comptes->trouve($id);
        if (! $cible) {
            return response()->json(['success' => false, 'message' => __('comptes.err_inconnu')], 404);
        }
        // GARDE HIERARCHIQUE, relevee du legacy (`manage_roles.php:80`) : un
        // role 2 ne touche pas au mot de passe d'un role 3.
        if ($roleId < 3 && (int) $cible['role_id'] >= 3) {
            return response()->json(['success' => false, 'message' => __('comptes.err_hierarchie')], 403);
        }

        $genere = $requete->boolean('generer');
        $mdp = $genere ? $this->comptes->genereMotDePasse() : (string) $requete->input('mot_de_passe', '');

        $err = $this->comptes->definitMotDePasse($id, $mdp);
        if ($err !== null) {
            return response()->json([
                'success' => false,
                'message' => __($err, ['minimum' => Comptes::LONGUEUR_MINIMALE]),
            ], 422);
        }
        $this->journalise($auteur, "Mot de passe redefini pour le compte #{$id}");

        return response()->json([
            'success' => true,
            'message' => __('comptes.mdp_change'),
            // Rendu UNE fois, ici. Absent quand l'administrateur a saisi le mot
            // de passe : il le connait deja, l'echo serait gratuit.
            'genere' => $genere ? $mdp : null,
        ]);
    }

    /* ═══ Clé SSH ══════════════════════════════════════════════════════════ */

    public function cleSsh(Request $requete, int $id): JsonResponse
    {
        [$auteur] = $this->qui($requete);
        if (! $this->comptes->trouve($id)) {
            return response()->json(['success' => false, 'message' => __('comptes.err_inconnu')], 404);
        }
        $cle = (string) $requete->input('cle_ssh', '');
        $err = $this->comptes->definitCleSsh($id, $cle);
        if ($err !== null) {
            return response()->json(['success' => false, 'message' => __($err)], 422);
        }
        $this->journalise($auteur, trim($cle) === ''
            ? "Cle SSH effacee pour le compte #{$id}"
            : "Cle SSH remplacee pour le compte #{$id}");

        return response()->json(['success' => true, 'message' => __('comptes.cle_enregistree')]);
    }

    /* ═══ Etats ════════════════════════════════════════════════════════════ */

    public function deverrouiller(Request $requete, int $id): JsonResponse
    {
        [$auteur] = $this->qui($requete);
        if (! $this->comptes->trouve($id)) {
            return response()->json(['success' => false, 'message' => __('comptes.err_inconnu')], 404);
        }
        $this->comptes->deverrouille($id);
        $this->journalise($auteur, "Compte #{$id} deverrouille");

        return response()->json(['success' => true, 'message' => __('comptes.deverrouille')]);
    }

    public function reinitialiserTotp(Request $requete, int $id): JsonResponse
    {
        [$auteur, $roleId] = $this->qui($requete);
        $cible = $this->comptes->trouve($id);
        if (! $cible) {
            return response()->json(['success' => false, 'message' => __('comptes.err_inconnu')], 404);
        }
        if ($roleId < 3 && (int) $cible['role_id'] >= 3) {
            return response()->json(['success' => false, 'message' => __('comptes.err_hierarchie')], 403);
        }
        $this->comptes->reinitialiseTotp($id);
        $this->journalise($auteur, "Second facteur reinitialise pour le compte #{$id}");

        return response()->json(['success' => true, 'message' => __('comptes.totp_reinitialise')]);
    }
}
