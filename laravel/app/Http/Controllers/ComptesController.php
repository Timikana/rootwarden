<?php

namespace App\Http\Controllers;

use App\Services\Comptes;
use App\Services\JournalAudit;
use App\Services\StepUp;
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
    /** Borne de taille du fichier importe, en kio — meme valeur que `serveurs`. */
    private const IMPORT_MAX_KO = 512;

    public function __construct(
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
        return $this->rendu($requete);
    }

    /**
     * Le rendu commun. `secretsImport` n'est JAMAIS lu depuis la session.
     *
     * ══ L'IMPORT NE REDIRIGE PAS, ET C'EST DELIBERE ═══════════════════════
     *
     * Chaque compte importe recoit un mot de passe genere qui n'existe qu'une
     * fois. Le faire transiter par un message de session le deposerait sur le
     * disque du conteneur — le pilote est `file`. Meme motif que
     * `ClesApiController`, et meme prix, connu et assume : recharger la page
     * apres un import repropose le formulaire au navigateur.
     *
     * @param  list<array{nom: string, mdp: string}>  $secretsImport
     */
    private function rendu(
        Request $requete,
        ?array $import = null,
        array $secretsImport = [],
    ): View {
        [, $roleId] = $this->qui($requete);

        return view('comptes', [
            'comptes' => $this->comptes->liste(),
            'roles' => Comptes::ROLES,
            'estSuperadmin' => $roleId >= 3,
            'longueurMinimale' => Comptes::LONGUEUR_MINIMALE,
            'importMaxKo' => self::IMPORT_MAX_KO,
            'importColonnes' => Comptes::IMPORT_COLONNES,
            'importRoles' => array_keys(Comptes::IMPORT_ROLES),
            'import' => $import,
            'secretsImport' => $secretsImport,
        ]);
    }

    /**
     * L'import CSV de comptes — sous-lot D6c, la moitie COMPTES de
     * `legacy/adm/includes/import_csv.php`. La moitie SERVEURS est portee
     * ailleurs (`ServeursController::importer`).
     *
     * `mimes:csv,txt` se lit sur le CONTENU par Laravel, pas sur l'extension : un
     * `.csv` renomme depuis un binaire est refuse ici plutot que de finir dans
     * `fgetcsv`.
     */
    public function importer(Request $requete): View
    {
        $valide = $requete->validate([
            'fichier' => ['required', 'file', 'mimes:csv,txt', 'max:' . self::IMPORT_MAX_KO],
        ], [], ['fichier' => __('comptes.imp_champ')]);

        [$auteur, $roleAuteur] = $this->qui($requete);

        $resultat = $this->comptes->importeCsv($valide['fichier']->getRealPath(), $roleAuteur);

        if ($resultat['bilan']['crees'] > 0) {
            // Le NOMBRE, jamais les noms ni les secrets : le journal est lisible
            // par qui peut lire le journal, et un mot de passe n'y a pas sa place.
            $this->journalise($auteur, 'Import CSV: ' . $resultat['bilan']['crees'] . ' comptes importes');
        }

        return $this->rendu($requete, $resultat['bilan'], $resultat['secrets']);
    }

    /* ═══ Creation ═════════════════════════════════════════════════════════ */

    public function creer(Request $requete): RedirectResponse
    {
        [$auteur, $roleAuteur] = $this->qui($requete);
        $nom = trim((string) $requete->input('name', ''));
        if ($nom === '' || mb_strlen($nom) > 255) {
            return back()->with('erreur', __('comptes.err_nom'));
        }
        if (DB::table('users')->where('name', $nom)->exists()) {
            return back()->with('erreur', __('comptes.err_nom_pris'));
        }
        $courriel = filter_var(trim((string) $requete->input('email', '')), FILTER_VALIDATE_EMAIL) ?: null;
        // La liste fermee ET l'anti-escalade, en UN appel : `roleAutorise()` porte
        // les deux, et l'import CSV appelle la meme. Deux copies divergeraient —
        // le legacy en a trois, dont une muette.
        [$role, $rangRamene] = $this->comptes->roleAutorise(
            (int) $requete->input('role_id', 1),
            $roleAuteur,
        );

        /*
         * ══ ANTI-ESCALADE — REPRISE DU LEGACY, ELLE MANQUAIT ICI ══════════
         *
         * La liste fermee `Comptes::ROLES` bornait le role a [1,2,3] et rien ne
         * le bornait au role de l'AUTEUR. Or cette route est gardee `role:2`,
         * et `ExigeRole` compare avec `<` : un compte de role 2 porteur de
         * `can_admin_portal` la franchit. Il pouvait donc creer un
         * SUPERADMINISTRATEUR.
         *
         * Le legacy s'en protege, et son commentaire dit l'incident qui l'a fait
         * ecrire (`manage_users.php:88-89`) : quelqu'un *« creait un superadmin,
         * recevait le magic-link sur son email et prenait le controle »*. La
         * regle est a `:92` — un non-superadmin ne cree qu'un role
         * STRICTEMENT inferieur au sien.
         *
         * ⚠ ET LA FORME COMPTE. Le legacy pose ici une COERCITION, pas un refus,
         * et il l'ANNONCE : son propre commentaire dit *« feedback utilisateur
         * (toast) au lieu d'un clamp silencieux »*. On reprend les deux — la
         * coercition ET l'annonce. Un rang ramene sans le dire ferait croire au
         * demandeur qu'il a cree un administrateur.
         *
         * *La MODIFICATION de role, elle, REFUSE (`manage_roles.php:154`). Les
         * deux formes sont voulues : creer avec un rang moindre reste utile,
         * modifier vers un rang interdit n'a aucun sens.*
         */

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
        // La coercition entre dans la TRACE : une decision de rang qui n'est pas
        // journalisee ne se retrouve pas, et c'en est une.
        $this->journalise($auteur, "Creation du compte '{$nom}' (role={$role})"
            . ($rangRamene ? ' [rang ramene a 1 : anti-escalade]' : ''));

        /*
         * ⚠ UN SEUL MESSAGE, ET IL PASSE PAR `succes`.
         *
         * Mon premier jet posait un `avertissement` — une cle que
         * `comptes.blade.php` NE RENDAIT PAS (elle n'affiche que `succes` et
         * `erreur`, `:36-37`), et qui n'avait qu'une seule occurrence dans tout
         * le portage : la mienne. La coercition aurait donc ete SILENCIEUSE,
         * derriere une annonce qui n'atteignait aucun ecran — exactement le
         * defaut que cette annonce existe pour eviter.
         */
        return back()->with('succes', $rangRamene
            ? __('comptes.cree_rang_ramene', ['nom' => $nom, 'id' => $id])
            : __('comptes.cree', ['nom' => $nom, 'id' => $id]));
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

    /* ═══ Suppression et anonymisation — sous-lot D4 ═══════════════════════ */

    /**
     * Ce que la page a besoin de savoir AVANT de proposer un geste : le compte
     * porte-t-il un journal ? Si oui, la suppression l'emporterait (E-116), et
     * c'est l'anonymisation qu'il faut proposer.
     */
    public function etatSuppression(Request $requete, int $id): JsonResponse
    {
        [$auteur, $roleAuteur] = $this->qui($requete);
        if (! $this->comptes->trouve($id)) {
            return response()->json(['success' => false, 'message' => __('comptes.err_inconnu')], 404);
        }
        $refus = $this->comptes->refusePourquoi($id, $auteur, $roleAuteur);
        $journaux = $this->comptes->journauxDe($id);

        return response()->json([
            'success' => true,
            'journaux' => $journaux,
            'supprimable' => $refus === null && $journaux === 0,
            'anonymisable' => $refus === null,
            'refus' => $refus === null ? null : __($refus),
        ]);
    }

    /**
     * PREMIER CONSOMMATEUR DU STEP-UP PORTE EN `v1.37.50`.
     *
     * Le sous-lot A5 avait explicitement differe le panneau de decision en page,
     * faute de consommateur : « il sera porte AVEC son premier consommateur ».
     * Le voici. Tant qu'aucune marque fraiche n'existe pour ce compte et cette
     * action, la reponse est un 403 qui NOMME l'action — la page ouvre alors son
     * panneau, demande un code, et rejoue le geste.
     */
    private function exigeStepUp(int $auteur, string $action): ?JsonResponse
    {
        if ($this->stepUp->valide($auteur, $action)) {
            return null;
        }

        return response()->json([
            'success' => false,
            'step_up_required' => true,
            'action' => $action,
            'message' => __('comptes.err_step_up'),
        ], 403);
    }

    public function supprimer(Request $requete, int $id): JsonResponse
    {
        [$auteur, $roleAuteur] = $this->qui($requete);
        if (! $this->comptes->trouve($id)) {
            return response()->json(['success' => false, 'message' => __('comptes.err_inconnu')], 404);
        }
        if (($refus = $this->comptes->refusePourquoi($id, $auteur, $roleAuteur)) !== null) {
            return response()->json(['success' => false, 'message' => __($refus)], 403);
        }
        // LA GARDE QUI N'EXISTE PAS DANS LE LEGACY : un compte qui porte un
        // journal ne se supprime pas, parce que la cascade l'emporterait et
        // romprait la chaine que D1 verifie. On oriente vers l'anonymisation.
        if (! $this->comptes->supprimableSansPerte($id)) {
            return response()->json([
                'success' => false,
                'journaux' => $this->comptes->journauxDe($id),
                'anonymiser_plutot' => true,
                'message' => __('comptes.err_journal_present',
                    ['nombre' => $this->comptes->journauxDe($id)]),
            ], 409);
        }
        if (($refus = $this->exigeStepUp($auteur, 'compte_supprimer')) !== null) {
            return $refus;
        }

        $nom = $this->comptes->trouve($id)['name'] ?? ('#' . $id);
        // Le journal AVANT la suppression, comme le legacy — mais ici la ligne
        // ne peut pas creuser de trou : le compte n'a aucun journal a emporter,
        // c'est la condition qu'on vient de verifier.
        $this->journalise($auteur, "Suppression du compte '{$nom}' (#{$id})");
        if (($err = $this->comptes->supprime($id)) !== null) {
            return response()->json(['success' => false, 'message' => __($err)], 409);
        }

        return response()->json(['success' => true, 'message' => __('comptes.supprime', ['nom' => $nom])]);
    }

    public function anonymiser(Request $requete, int $id): JsonResponse
    {
        [$auteur, $roleAuteur] = $this->qui($requete);
        if (! $this->comptes->trouve($id)) {
            return response()->json(['success' => false, 'message' => __('comptes.err_inconnu')], 404);
        }
        if (($refus = $this->comptes->refusePourquoi($id, $auteur, $roleAuteur)) !== null) {
            return response()->json(['success' => false, 'message' => __($refus)], 403);
        }
        if (($refus = $this->exigeStepUp($auteur, 'compte_anonymiser')) !== null) {
            return $refus;
        }

        $nom = $this->comptes->trouve($id)['name'] ?? ('#' . $id);
        $journaux = $this->comptes->journauxDe($id);
        $this->comptes->anonymise($id);
        $this->journalise($auteur,
            "[rgpd] Anonymisation du compte '{$nom}' (#{$id}) - donnees personnelles effacees, journal conserve");

        return response()->json([
            'success' => true,
            'journaux_conserves' => $journaux,
            'message' => __('comptes.anonymise', ['nom' => $nom, 'nombre' => $journaux]),
        ]);
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
