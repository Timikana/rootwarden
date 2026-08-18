<?php

use App\Http\Controllers\Auth\ConnexionController;
use App\Http\Controllers\Auth\SecondFacteurController;
use App\Http\Controllers\JournalCommandesController;
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
     * Passerelle vers le backend Python. Elle reste dans le groupe `web` : la
     * session ET le jeton CSRF s'appliquent, ce qui est le point de la
     * manoeuvre — c'est l'endpoint le plus puissant du portail, il transmet
     * toutes les routes du backend.
     *
     * `where` autorise le slash dans le parametre, sinon `/fail2ban/status`
     * ne serait pas capture.
     */
    /*
     * Journal des commandes — lecture seule, reserve a l'administration.
     * La garde est ici et NULLE PART ailleurs : ecrite aussi dans le
     * controleur, elle finirait par diverger.
     */
    Route::get('/journal-commandes', JournalCommandesController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('journal-commandes');

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
