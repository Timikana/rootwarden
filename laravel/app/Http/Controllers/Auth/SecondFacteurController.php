<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Services\Totp;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\View\View;

/**
 * Second facteur. C'est ici, et seulement ici, que la session devient
 * authentifiee.
 */
class SecondFacteurController extends Controller
{
    public function __construct(private readonly Totp $totp)
    {
    }

    public function formulaire(Request $requete): View|RedirectResponse
    {
        if (! $requete->session()->has('compte_temporaire')) {
            return redirect()->route('connexion');
        }

        return view('auth.second-facteur');
    }

    /**
     * Compte sans secret TOTP. L'enrolement complet n'est pas encore porte :
     * on refuse explicitement plutot que d'ouvrir une porte sans second
     * facteur. Un ecran qui expliquerait « rendez-vous sur le legacy » vaut
     * mieux qu'un acces accorde.
     */
    public function enrolement(Request $requete): View|RedirectResponse
    {
        if (! $requete->session()->has('compte_temporaire')) {
            return redirect()->route('connexion');
        }

        return view('auth.enrolement');
    }

    public function soumettre(Request $requete): RedirectResponse
    {
        $temporaire = $requete->session()->get('compte_temporaire');
        if (! $temporaire) {
            return redirect()->route('connexion');
        }

        // Le champ garde le nom du legacy : le MEME test de caracterisation
        // vise les deux cibles, il ne peut pas connaitre deux noms de champ.
        $requete->validate(['2fa_code' => ['required', 'string', 'max:10']]);

        // Limitation de debit par session : 5 tentatives glissantes sur 60 s.
        $tentatives = collect($requete->session()->get('tentatives_2fa', []))
            ->filter(fn ($t) => $t > time() - 60)
            ->values();
        $tentatives->push(time());
        $requete->session()->put('tentatives_2fa', $tentatives->all());

        if ($tentatives->count() > (int) config('rootwarden.connexion.max_tentatives_2fa', 5)) {
            return back()->withErrors(['2fa_code' => __('auth.erreur_trop_de_tentatives')]);
        }

        if ($this->ipBloquee($requete)) {
            return back()->withErrors(['2fa_code' => __('auth.erreur_trop_de_tentatives')]);
        }

        // Le secret est relu en base a cet instant : la session ne transporte
        // jamais de secret TOTP.
        $compte = DB::table('users')
            ->select('id', 'name', 'role_id', 'active', 'totp_secret', 'force_password_change')
            ->where('id', $temporaire['id'])
            ->first();

        if (! $compte || ! $compte->active) {
            // Compte desactive entre le mot de passe et le second facteur.
            $requete->session()->flush();

            return redirect()->route('connexion');
        }

        $verdict = $this->totp->verifie((int) $compte->id, $compte->totp_secret, (string) $requete->input('2fa_code'));

        $this->journalise($requete, (string) $compte->name, $verdict === 'ok');

        if ($verdict === 'rejeu') {
            return back()->withErrors(['2fa_code' => __('auth.erreur_code_deja_utilise')]);
        }
        if ($verdict === 'sans_secret') {
            return back()->withErrors(['2fa_code' => __('auth.erreur_sans_secret')]);
        }
        if ($verdict !== 'ok') {
            return back()->withErrors(['2fa_code' => __('auth.erreur_code_invalide')]);
        }

        // Authentification complete. Nouvelle rotation de session, puis on ne
        // garde que ce qui a ete verifie EN BASE a l'instant present.
        $requete->session()->regenerate();
        $requete->session()->forget(['compte_temporaire', 'tentatives_2fa']);
        $requete->session()->put('utilisateur_id', (int) $compte->id);
        $requete->session()->put('utilisateur_nom', (string) $compte->name);
        $requete->session()->put('role_id', (int) $compte->role_id);

        if ((int) ($compte->force_password_change ?? 0) === 1) {
            $requete->session()->put('changement_mot_de_passe_requis', true);

            return redirect()->route('profil', ['force_change' => 1]);
        }

        return redirect()->route('cgu');
    }

    /** Compteur d'echecs par IP sur 10 minutes, partage avec le legacy. */
    private function ipBloquee(Request $requete): bool
    {
        try {
            $echecs = DB::table('login_attempts')
                ->where('ip_address', $requete->ip() ?? '0.0.0.0')
                ->where('step', '2fa')
                ->where('success', 0)
                ->where('attempted_at', '>', now()->subMinutes(10))
                ->count();

            return $echecs >= (int) config('rootwarden.connexion.max_echecs_ip', 10);
        } catch (\Throwable) {
            return false;
        }
    }

    private function journalise(Request $requete, string $nom, bool $succes): void
    {
        try {
            DB::table('login_attempts')->insert([
                'ip_address'   => $requete->ip() ?? '0.0.0.0',
                'username'     => $nom,
                'success'      => $succes ? 1 : 0,
                'step'         => '2fa',
                'attempted_at' => now(),
            ]);
        } catch (\Throwable) {
        }
    }
}
