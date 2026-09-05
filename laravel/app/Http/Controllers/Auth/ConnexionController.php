<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\RedirectResponse;
use App\Services\HistoriqueConnexions;
use App\Services\MotDePasse;
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
    public function __construct(
        private readonly MotDePasse $motDePasse,
        private readonly HistoriqueConnexions $historique,
    ) {
    }

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
                /*
                 * ⚠ L'HISTORIQUE N'EST ECRIT QUE SI LE COMPTE EXISTE, et c'est
                 * une contrainte du SCHEMA, pas un choix : `login_history`
                 * porte `user_id NOT NULL` avec une cle etrangere vers `users`.
                 * *Un echec sur un identifiant inconnu n'a donc aucune ligne ou
                 * s'attacher* — c'est aussi ce que fait le legacy (`:267`, dans
                 * la branche ou `$user` existe), et le compteur par IP qui
                 * borne l'enumeration vit ailleurs, dans `login_attempts`.
                 */
                $this->historique->enregistre(
                    (int) $compte->id,
                    'failed_password',
                    $requete->ip(),
                    $requete->userAgent(),
                );
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

        /*
         * ══ LA REMISE A NIVEAU DU COUT BCRYPT ════════════════════════════
         *
         * **C'est le seul instant du produit ou le mot de passe en clair
         * existe** — quelqu'un vient de le saisir, et il vient d'etre verifie.
         * Aucune tache de fond ne peut faire ce geste : aucune ne detient le
         * clair. C'est pour cela qu'il vit ici et nulle part ailleurs.
         *
         * ⚠ IL EST DORMANT AUJOURD'HUI, ET C'EST LA RAISON DE L'ECRIRE. Les
         * douze comptes de cette base portent tous `$2y$12$`, et le cout courant
         * vaut 12 : la condition ne se declenche jamais. *Son absence serait donc
         * indetectable jusqu'au jour ou quelqu'un releve le cout — et ce jour-la
         * les comptes existants garderaient l'ancien, indefiniment, sans que rien
         * ne le signale.*
         *
         * ⚠⚠ ET LE COMMENTAIRE DU LEGACY RACONTE PRECISEMENT CE PIEGE :
         * *« Avant, le commentaire l'annoncait mais ce n'etait pas fait »*
         * (`login.php:159-161`). Le portage avait herite de la version corrigee
         * du commentaire et pas du geste. **Le geste est ici, et une assertion le
         * mord sur un compte FORGE au cout 10** — un test sur les douze comptes
         * deja au cout courant passerait a vide.
         *
         * L'echec ne casse pas la connexion : le mot de passe est bon, la
         * personne entre. Il se JOURNALISE — voir le service.
         */
        /*
         * ══ L'HISTORIQUE DES CONNEXIONS ══════════════════════════════════
         *
         * `login_history` porte 5 067 lignes et **un seul ecrivain : le
         * legacy**. `ExportRgpd` la LIT — c'est une section d'un livrable
         * d'exercice du droit d'acces. *Eteindre le legacy sans cette ligne
         * figerait la donnee au jour de l'extinction, et l'export continuerait
         * de la presenter comme complete.*
         *
         * ⚠ ET C'EST ICI, PAS APRES LE SECOND FACTEUR. Le legacy l'ecrit au
         * meme endroit (`login.php:206`) : le statut `success` de cette table
         * dit « le mot de passe etait bon », pas « la session est ouverte ».
         * *Le deplacer apres la 2FA changerait le sens de 4 957 lignes deja
         * ecrites, et l'export melangerait deux definitions.*
         */
        $this->historique->enregistre(
            (int) $compte->id,
            'success',
            $requete->ip(),
            $requete->userAgent(),
        );

        $this->motDePasse->rehacheSiNecessaire(
            (int) $compte->id,
            (string) $compte->password,
            (string) $donnees['password'],
        );

        $requete->session()->regenerate();
        $requete->session()->put('compte_temporaire', [
            'id'   => (int) $compte->id,
            'nom'  => (string) $compte->name,
            'role' => (int) $compte->role_id,
            /*
             * ⚠ SEULE L'INTENTION VOYAGE ICI, JAMAIS UN JETON.
             *
             * Le legacy emet le jeton A CET INSTANT (`login.php:176`), juste
             * apres avoir pose `2fa_required` — donc AVANT que le second facteur
             * soit presente. On ne porte pas ce choix : voir
             * `JetonMemorisation`, divergence 2. Ici on ne retient que le
             * souhait, et l'emission attend la reussite du defi.
             */
            'memoriser' => $requete->boolean('memorisation'),
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

        /*
         * Le jeton de memorisation meurt avec la deconnexion, et le cookie avec
         * lui. Se deconnecter en laissant vivre un jeton qui restitue l'identite
         * serait un mensonge d'interface : la personne a demande a sortir.
         */
        $idSortant = (int) $requete->session()->get('utilisateur_id', 0);
        if ($idSortant > 0) {
            app(\App\Services\JetonMemorisation::class)->revoque($idSortant);
        }

        $requete->session()->flush();
        $requete->session()->regenerate();

        return redirect()->route('connexion')
            ->withoutCookie(\App\Services\JetonMemorisation::COOKIE);
    }

    /** Incremente les echecs et verrouille au-dela du seuil. */
    private function compteEchec(object $compte): void
    {
        $echecs = ((int) ($compte->failed_attempts ?? 0)) + 1;

        /*
         * `last_failed_login_at` DANS LA MEME ECRITURE. Le legacy la pose aux
         * deux endroits ou il touche `failed_attempts` (`login.php:249` et
         * `:260`) ; ici il n'y a qu'un point d'ecriture, donc une seule ligne.
         *
         * **Elle est lue par les DEUX exports de donnees personnelles**
         * (`ExportRgpd:103`) et n'avait AUCUN ecrivain dans le portage : deux
         * comptes seulement la portent aujourd'hui, tous deux ecrits par le
         * legacy. *Une colonne exportee que plus personne n'ecrit devient un
         * champ qui dit « jamais » pour tout le monde.*
         */
        $maj = ['failed_attempts' => $echecs, 'last_failed_login_at' => now()];
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
