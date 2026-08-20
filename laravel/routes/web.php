<?php

use App\Http\Controllers\Auth\ConnexionController;
use App\Http\Controllers\Auth\SecondFacteurController;
use App\Http\Controllers\ApprobationsController;
use App\Http\Controllers\DeriveConfigController;
use App\Http\Controllers\SauvegardesController;
use App\Http\Controllers\TachesController;
use App\Http\Controllers\MisesAJourController;
use App\Http\Controllers\RechercheController;
use App\Http\Controllers\TicketsController;
use App\Http\Controllers\JournalCommandesController;
use App\Http\Controllers\ExportCveController;
use App\Http\Controllers\RapportConformiteController;
use App\Http\Controllers\PasserelleController;
use App\Http\Controllers\PortailController;
use Illuminate\Support\Facades\Route;

/*
 * Socle d'authentification. Aucune page metier n'est encore portee.
 *
 * La regle : tout ce qui n'est pas explicitement public passe par
 * `session.authentifiee`. Entre le mot de passe et le second facteur, la
 * session ne porte qu'un compte temporaire — elle ne franchit pas ce garde.
 */

Route::redirect('/', '/accueil')->name('racine');

// ── Public ───────────────────────────────────────────────────────────────────
Route::get('/connexion', [ConnexionController::class, 'formulaire'])->name('connexion');
Route::post('/connexion', [ConnexionController::class, 'soumettre'])->name('connexion.soumettre');

// Etape intermediaire : le compte temporaire suffit, la session n'est PAS
// encore authentifiee. Ces routes ne sont donc pas derriere le garde.
Route::get('/second-facteur', [SecondFacteurController::class, 'formulaire'])->name('second-facteur');
Route::post('/second-facteur', [SecondFacteurController::class, 'soumettre'])->name('second-facteur.soumettre');
Route::get('/second-facteur/enrolement', [SecondFacteurController::class, 'enrolement'])->name('second-facteur.enrolement');

Route::post('/deconnexion', [ConnexionController::class, 'deconnexion'])->name('deconnexion');
Route::get('/deconnexion', [ConnexionController::class, 'deconnexion']);

// ── Authentifie ──────────────────────────────────────────────────────────────
Route::middleware('session.authentifiee')->group(function () {
    Route::get('/cgu', [PortailController::class, 'cgu'])->name('cgu');
    Route::post('/cgu', [PortailController::class, 'accepterCgu'])->name('cgu.accepter');
    Route::get('/accueil', [PortailController::class, 'accueil'])->name('accueil');
    Route::get('/profil', [PortailController::class, 'profil'])->name('profil');

    /*
     * Pages metier reservees a l'administration.
     *
     * La garde est ici et NULLE PART ailleurs : ecrite aussi dans le
     * controleur, elle finirait par diverger.
     */

    // Approbation a quatre yeux des actions destructrices.
    Route::get('/approbations', ApprobationsController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('approbations');

    /*
     * Derive de configuration. Seule page portee a ce jour dont la garde
     * n'est PAS `can_admin_portal` : `can_view_compliance` est portee par un
     * compte role 2, ce qui rend la permission observable independamment du
     * role.
     */
    Route::get('/derive-config', DeriveConfigController::class)
        ->middleware(['role:2', 'perm:can_view_compliance'])
        ->name('derive-config');

    /*
     * Sauvegardes de la base. La RESTAURATION est destructive et le backend la
     * reserve au role 3 : la garde de la page n'est donc pas celle de l'action.
     */
    Route::get('/sauvegardes', SauvegardesController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('sauvegardes');

    /*
     * Centre de taches. `role:2` SEUL, sans permission : c'est ce que fait le
     * legacy, qui n'appelle que `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])`.
     * L'entree de MENU, elle, vit dans le bloc garde par `can_admin_portal` —
     * un role 2 sans la permission ne la voit pas et atteint pourtant la page.
     * Ecart reproduit tel quel et consigne, plutot que corrige sans arbitrage.
     */
    Route::get('/taches', TachesController::class)
        ->middleware(['role:2'])
        ->name('taches');

    // Ticketing ITSM : liste et creation manuelle.
    Route::get('/tickets', TicketsController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('tickets');

    // Recherche globale : serveurs, utilisateurs, CVE, tickets, journal d'audit.
    Route::get('/recherche', RechercheController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('recherche');

    /*
     * Mises a jour Linux — sous-lot U1 du module `update/`, lecture seule.
     * Garde reprise du legacy : role 1 ADMIS s'il porte can_update_linux, et
     * cloisonne alors par `user_machine_access`.
     */
    Route::get('/mises-a-jour', MisesAJourController::class)
        ->middleware(['role:1', 'perm:can_update_linux'])
        ->name('mises-a-jour');

    /*
     * Rapport de conformite — module `security/`, sous-lot S2a.
     *
     * GARDE VOLONTAIREMENT PLUS STRICTE QUE LE LEGACY (decision D-1). Le legacy
     * admet `ROLE_USER` et ne cloisonne aucune donnee, alors que l'en-tete de son
     * fichier annonce « Acces : admin (2) et superadmin (3) ». Un role 1 porteur
     * de `can_view_compliance` obtenait donc tout le parc avec IP, port et
     * utilisateur SSH, tous les comptes, et la posture par serveur avec les
     * ecarts en clair. La route porte la garde que le fichier annoncait.
     * Consigne dans PARITE.md : c'est une divergence, pas un oubli.
     */
    Route::get('/rapport-conformite', RapportConformiteController::class)
        ->middleware(['role:2', 'perm:can_view_compliance'])
        ->name('rapport-conformite');

    /*
     * Export CSV d'un scan CVE — module `security/`, sous-lot S1.
     *
     * Garde reprise du legacy : `checkAuth([1,2,3])` + `can_scan_cve`. Le role 1
     * est bien ADMIS ; c'est le cloisonnement par `user_machine_access`, dans le
     * controleur, qui borne ce qu'il peut lire — et son refus rend 404, pas 403.
     *
     * PAS D'ENTREE DE MENU : le legacy la declenche depuis un bouton de la page
     * des vulnerabilites, qui appartient au sous-lot S3. Jusque-la la route
     * existe et se teste, mais n'est atteignable qu'en tapant son adresse. Dit
     * ici pour que personne ne cherche l'entree manquante dans Navigation.
     */
    Route::get('/export-cve', ExportCveController::class)
        ->middleware(['role:1', 'perm:can_scan_cve'])
        ->name('export-cve');

    // Journal des commandes — tracabilite de type bastion, lecture seule.
    Route::get('/journal-commandes', JournalCommandesController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('journal-commandes');

    /*
     * Passerelle vers le backend Python. Elle reste dans le groupe `web` : la
     * session ET le jeton CSRF s'appliquent, ce qui est le point de la
     * manoeuvre — c'est l'endpoint le plus puissant du portail, il transmet
     * toutes les routes du backend.
     *
     * `where` autorise le slash dans le parametre, sinon `/fail2ban/status`
     * ne serait pas capture.
     */
    Route::any('/api/gateway/{chemin?}', PasserelleController::class)
        ->where('chemin', '.*')
        ->name('passerelle');
});

/*
 * Compatibilite avec les chemins du legacy, pour que le MEME test de
 * caracterisation puisse viser les deux cibles sans etre reecrit. Un test qui
 * doit changer d'adresse selon la cible ne compare plus rien.
 */
Route::get('/auth/login.php', fn () => redirect()->route('connexion'));
Route::get('/auth/verify_2fa.php', fn () => redirect()->route('second-facteur'));
Route::get('/index.php', fn () => redirect()->route('accueil'));
Route::get('/profile.php', fn () => redirect()->route('profil'));
Route::get('/terms.php', fn () => redirect()->route('cgu'));
Route::get('/adm/admin_page.php', fn () => redirect()->route('accueil'));
Route::get('/commandlog/', fn () => redirect()->route('journal-commandes'));
Route::get('/approvals/', fn () => redirect()->route('approbations'));
Route::get('/drift/', fn () => redirect()->route('derive-config'));
Route::get('/backups/', fn () => redirect()->route('sauvegardes'));
Route::get('/tasks/', fn () => redirect()->route('taches'));
Route::get('/search/', fn () => redirect()->route('recherche'));
