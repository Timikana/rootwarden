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
use App\Http\Controllers\ComparaisonCveController;
use App\Http\Controllers\ExportCveController;
use App\Http\Controllers\RapportConformiteController;
use App\Http\Controllers\ScanCveController;
use App\Http\Controllers\SuiviCveController;
use App\Http\Controllers\ExportConformiteController;
use App\Http\Controllers\ExportConformitePdfController;
use App\Http\Controllers\PasserelleController;
use App\Http\Controllers\PlanificationsCveController;
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
     * Export CSV du meme rapport — sous-lot S2c. MEME garde que la page, et
     * memes chiffres : tout vient de `Conformite::rapport()`, jamais recalcule.
     */
    Route::get('/rapport-conformite/csv', ExportConformiteController::class)
        ->middleware(['role:2', 'perm:can_view_compliance'])
        ->name('rapport-conformite.csv');

    /*
     * Export PDF du meme rapport — sous-lot S2b. Meme garde, memes chiffres.
     * Le rendu vit dans une vue dediee : le gabarit du portail porte une barre
     * laterale et des jetons de theme dont dompdf ne sait rien.
     */
    Route::get('/rapport-conformite/pdf', ExportConformitePdfController::class)
        ->middleware(['role:2', 'perm:can_view_compliance'])
        ->name('rapport-conformite.pdf');

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
    /*
     * Consultation des scans CVE — module `security/`, sous-lot S3.
     *
     * GARDE REPRISE TELLE QUELLE de la page legacy (`security/index.php:37-38`) :
     * `checkAuth([USER,ADMIN,SUPERADMIN])` + `checkPermission('can_scan_cve')`,
     * soit role >= 1 AVEC la permission. C'est la meme que l'export de S1.
     *
     * ECART ASSUME (E-48) : cote legacy cette permission ne garde que la PAGE.
     * Le proxy met `/cve_` en liste blanche pour tout role >= 1 sans jamais
     * regarder de permission, et sur les 19 routes CVE du backend
     * `require_permission` apparait zero fois. Ici la lecture ne passe pas par
     * une route backend : elle est faite en base par le controleur, DERRIERE
     * cette garde. La permission garde donc enfin la requete.
     */
    Route::get('/scan-cve', ScanCveController::class)
        ->middleware(['role:1', 'perm:can_scan_cve'])
        ->name('scan-cve');

    Route::get('/scan-cve/comparaison', ComparaisonCveController::class)
        ->middleware(['role:1', 'perm:can_scan_cve'])
        ->name('scan-cve.comparaison');

    /*
     * Planification des scans CVE — sous-lot S4.
     *
     * `role:2` ET NON `role:1` : le bloc de planification du legacy vit sous
     * `if ($role >= 2)` (`legacy/security/index.php:231`), et ses cinq routes
     * backend portent `require_role(2)`. La consultation reste ouverte au role 1,
     * l'ecriture non — la garde est reprise telle quelle, cran par cran.
     *
     * ECART ASSUME (E-52) : ces routes REMPLACENT `cve_schedules` et
     * `cron_preview` du backend, elles ne les appellent pas. Meme raison qu'en S3
     * — la permission ne garde aucune requete backend, et le garde d'acces ne lit
     * pas le meme parametre que sa route. Ici `perm:can_scan_cve` garde enfin
     * l'ecriture.
     */
    Route::get('/scan-cve/planifications', [PlanificationsCveController::class, 'index'])
        ->middleware(['role:2', 'perm:can_scan_cve'])->name('scan-cve.planifs');
    Route::post('/scan-cve/planifications', [PlanificationsCveController::class, 'store'])
        ->middleware(['role:2', 'perm:can_scan_cve'])->name('scan-cve.planifs.creer');
    Route::put('/scan-cve/planifications/{id}', [PlanificationsCveController::class, 'update'])
        ->middleware(['role:2', 'perm:can_scan_cve'])->whereNumber('id')->name('scan-cve.planifs.modifier');
    Route::delete('/scan-cve/planifications/{id}', [PlanificationsCveController::class, 'destroy'])
        ->middleware(['role:2', 'perm:can_scan_cve'])->whereNumber('id')->name('scan-cve.planifs.supprimer');
    Route::get('/scan-cve/apercu-cron', [PlanificationsCveController::class, 'apercu'])
        ->middleware(['role:2', 'perm:can_scan_cve'])->name('scan-cve.apercu-cron');

    /*
     * Suivi de remediation — sous-lot S5.
     *
     * `role:1` + `perm:can_scan_cve`, la garde de la page : le suivi se consulte
     * et se pose depuis le tableau des vulnerabilites, pas depuis un ecran
     * d'administration.
     *
     * LA CREATION DE TICKET N'EST PAS ICI, et c'est deliberé (E-58) :
     * `POST /tickets` appelle un fournisseur ITSM EXTERNE quand il est configure.
     * Elle passe donc par la PASSERELLE, ou `/tickets` est deja dans
     * `ADMIN_SEULEMENT` — role 2 exige par la passerelle, `can_admin_portal` par
     * le backend.
     */
    Route::get('/scan-cve/suivi', [SuiviCveController::class, 'index'])
        ->middleware(['role:1', 'perm:can_scan_cve'])->name('scan-cve.suivi');
    Route::post('/scan-cve/suivi', [SuiviCveController::class, 'store'])
        ->middleware(['role:1', 'perm:can_scan_cve'])->name('scan-cve.suivi.poser');

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
