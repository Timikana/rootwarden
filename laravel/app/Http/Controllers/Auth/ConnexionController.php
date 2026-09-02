<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\RedirectResponse;
use App\Services\SessionsActives;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\View\View;

/**
 * Etape mot de passe.
 *
 * Cette etape n'authentifie PERSONNE. Elle ne fait que poser un
 * `compte_temporaire` en session et renvoyer vers le second facteur. Aucun
 * chemin ne mene ailleurs : c'est l'invariant B du test de caracterisation.
 */
class ConnexionController extends Controller
{
    /** Duree du verrouillage apres trop d'echecs, en secondes. */
    private const VERROU_SECONDES = 900;

    /** Nombre d'echecs consecutifs avant verrouillage du compte. */
    private const ECHECS_AVANT_VERROU = 5;

    public function formulaire(Request $requete): View|RedirectResponse
    {
        if ($requete->session()->has('utilisateur_id')) {
            return redirect()->route('accueil');
        }

        return view('auth.connexion');
    }

    public function soumettre(Request $requete): RedirectResponse
    {
        $donnees = $requete->validate([
            'username' => ['required', 'string', 'max:190'],
            'password' => ['required', 'string'],
        ]);

        $compte = DB::table('users')
            ->select('id', 'name', 'password', 'role_id', 'totp_secret', 'active', 'failed_attempts', 'locked_until')
            ->where('name', $donnees['username'])
            ->first();

        // Compte verrouille : on refuse avant meme de verifier le mot de passe.
        if ($compte && $compte->locked_until !== null && strtotime((string) $compte->locked_until) > time()) {
            $this->journalise($requete, $donnees['username'], false);

            return back()->withErrors(['username' => __('auth.erreur_verrouille')])->onlyInput('username');
        }

        $motDePasseValide = $compte && password_verify($donnees['password'], (string) $compte->password);

        if (! $motDePasseValide || ! $compte->active) {
            if ($compte) {
                $this->compteEchec($compte);
            }
            $this->journalise($requete, $donnees['username'], false);

            // Message IDENTIQUE que le compte existe ou non : un message
            // different revelerait quels identifiants existent.
            return back()->withErrors(['username' => __('auth.erreur_identifiants')])->onlyInput('username');
        }

        // Mot de passe bon : on remet les compteurs a zero, on regenere la
        // session (anti-fixation) et on passe la main au second facteur.
        DB::table('users')->where('id', $compte->id)
            ->update(['failed_attempts' => 0, 'locked_until' => null]);

        $requete->session()->regenerate();
        $requete->session()->put('compte_temporaire', [
            'id'   => (int) $compte->id,
            'nom'  => (string) $compte->name,
            'role' => (int) $compte->role_id,
        ]);

        // Aucun secret TOTP : le compte doit d'abord en enroler un. Il n'existe
        // pas de porte de sortie sans second facteur.
        if (empty($compte->totp_secret)) {
            return redirect()->route('second-facteur.enrolement');
        }

        return redirect()->route('second-facteur');
    }

    public function deconnexion(Request $requete): RedirectResponse
    {
        // E-203 : retirer la ligne AVANT de detruire la session — apres
        // `regenerate()` l'identifiant a change, et l'ancienne ligne
        // resterait en base a decrire une session qui n'existe plus.
        app(SessionsActives::class)->ferme($requete->session()->getId());

        $requete->session()->flush();
        $requete->session()->regenerate();

        return redirect()->route('connexion');
    }

    /** Incremente les echecs et verrouille au-dela du seuil. */
    private function compteEchec(object $compte): void
    {
        $echecs = ((int) ($compte->failed_attempts ?? 0)) + 1;

        $maj = ['failed_attempts' => $echecs];
        if ($echecs >= self::ECHECS_AVANT_VERROU) {
            $maj['locked_until'] = date('Y-m-d H:i:s', time() + self::VERROU_SECONDES);
        }

        DB::table('users')->where('id', $compte->id)->update($maj);
    }

    /** Trace la tentative pour le compteur par IP, partage avec le legacy. */
    private function journalise(Request $requete, string $nom, bool $succes): void
    {
        try {
            DB::table('login_attempts')->insert([
                'ip_address'   => $requete->ip() ?? '0.0.0.0',
                'username'     => $nom,
                'success'      => $succes ? 1 : 0,
                'step'         => 'password',
                'attempted_at' => now(),
            ]);
        } catch (\Throwable) {
            // Le compteur par IP est une defense supplementaire, pas la
            // principale : son indisponibilite ne doit pas bloquer la connexion.
        }
    }
}
