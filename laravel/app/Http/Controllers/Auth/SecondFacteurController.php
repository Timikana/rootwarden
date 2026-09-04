<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Services\JetonMemorisation;
use App\Services\SessionsActives;
use App\Services\Totp;
use App\Support\TotpCrypto;
use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use OTPHP\TOTP as OtpHp;
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
    /**
     * L'etape inscrite dans `login_attempts` — et pourquoi il en faut DEUX.
     *
     * ══ DIX REJEUX BLOQUAIENT TOUTE UNE ADRESSE ═══════════════════════════
     *
     * `journalise()` etait appele AVANT l'aiguillage sur le verdict, donc un
     * rejeu s'inscrivait avec `success = 0` et `step = '2fa'` : un ECHEC. Or
     * `ipBloquee()` compte exactement ces lignes et bloque a dix en dix minutes.
     *
     * **Un bureau derriere un NAT partage une adresse.** *Et un rejeu est le cas
     * legitime le plus banal : le meme compte, un second appareil, la meme
     * fenetre de trente secondes.* **Dix refus de rejeu fermaient donc l'etape
     * du second facteur pour tout le monde derriere cette adresse.**
     *
     * ⚠ LA DISTINCTION QUI PORTE LE CORRECTIF : *un rejeu n'est pas un echec
     * d'identifiant, c'est une soumission EN DOUBLE d'un identifiant VALIDE.*
     * **Il doit etre inscrit et ne doit pas compter.**
     *
     * Ce qu'on ne fait donc PAS :
     *   — l'inscrire en `success = 1`, ce serait falsifier le journal ;
     *   — cesser de l'inscrire, alors qu'un rejeu est une PREUVE : quelqu'un
     *     resoumet un code cryptographiquement valide, et c'est exactement ce
     *     qu'on veut pouvoir relire apres coup.
     *
     * `ipBloquee()` n'est PAS touche : il filtre deja `step = '2fa'`, donc il
     * cesse de voir les rejeux sans qu'on ait a modifier le compteur. Et les
     * trois compteurs du legacy (`verify_2fa`, `confirm_2fa`, `enable_2fa`)
     * filtrent la meme valeur : ils cessent de les voir aussi.
     *
     * `varchar(16)` en base ; `2fa_rejeu` en fait neuf.
     */
    private const ETAPE_2FA = '2fa';
    private const ETAPE_REJEU = '2fa_rejeu';

    public function __construct(
        private readonly Totp $totp,
        private readonly SessionsActives $sessions,
        private readonly JetonMemorisation $jetons,
    ) {
    }

    public function formulaire(Request $requete): View|RedirectResponse
    {
        if (! $requete->session()->has('compte_temporaire')) {
            return redirect()->route('connexion');
        }

        return view('auth.second-facteur');
    }

    /**
     * L'enrolement du second facteur — le dernier blocage de la v2.0.
     *
     * PORTAGE DU LEGACY CORRIGE, PAS DU LEGACY. `enable_2fa.php` divulguait le
     * secret d'un compte DEJA enrole a qui ne presentait que le mot de passe
     * (corrige en v1.37.48, PARITE E-94). Les trois proprietes qui ferment ce
     * trou sont reprises ici comme des invariants, pas comme des precautions :
     *
     *   1. un compte qui a DEJA un secret n'atteint jamais cet ecran ;
     *   2. le secret propose vit en SESSION et ne touche la base qu'APRES la
     *      preuve — un GET n'ecrit rien ;
     *   3. il ne change pas d'un affichage a l'autre, sans quoi le QR scanne et
     *      le code attendu ne concorderaient jamais.
     */
    public function enrolement(Request $requete): View|RedirectResponse
    {
        $temporaire = $requete->session()->get('compte_temporaire');
        if (! $temporaire) {
            return redirect()->route('connexion');
        }

        $idCompte = (int) $temporaire['id'];

        /*
         * INVARIANT 1. Relu EN BASE a cet instant, jamais depuis la session :
         * c'est exactement la lecture que le legacy omettait.
         */
        if (! empty(DB::table('users')->where('id', $idCompte)->value('totp_secret'))) {
            return redirect()->route('second-facteur');
        }

        /*
         * INVARIANT 3. Le secret est genere UNE FOIS par session, et lie au
         * compte : un enrolement entame puis repris sur un autre compte ne doit
         * pas herite du secret precedent.
         */
        if (! $requete->session()->has('enrolement_secret')
            || (int) $requete->session()->get('enrolement_compte') !== $idCompte) {
            $requete->session()->put('enrolement_secret', OtpHp::generate()->getSecret());
            $requete->session()->put('enrolement_compte', $idCompte);
        }

        $secret = (string) $requete->session()->get('enrolement_secret');

        return view('auth.enrolement', [
            'secret' => $secret,
            'qr'     => $this->qrCode($secret, (string) $temporaire['nom']),
        ]);
    }

    /**
     * Le code d'enrolement. C'est ici, et seulement ici, que le secret est ECRIT.
     *
     * Le code est verifie contre le secret de SESSION, chiffre a la volee pour
     * passer par le meme `Totp::verifie` que la connexion — donc avec le meme
     * anti-rejeu monotone par compte. Consequence voulue : un code employe pour
     * enroler ne peut pas etre rejoue pour ouvrir une session.
     */
    public function activer(Request $requete): RedirectResponse
    {
        $temporaire = $requete->session()->get('compte_temporaire');
        if (! $temporaire) {
            return redirect()->route('connexion');
        }

        $requete->validate(['2fa_code' => ['required', 'string', 'max:10']]);

        $idCompte = (int) $temporaire['id'];
        $secret   = (string) $requete->session()->get('enrolement_secret', '');

        if ($secret === '' || (int) $requete->session()->get('enrolement_compte') !== $idCompte) {
            return redirect()->route('second-facteur.enrolement');
        }

        /* INVARIANT 1, VERIFIE UNE SECONDE FOIS. Entre l'affichage et la preuve,
         * un autre chemin a pu enroler ce compte : ecraser son secret le rendrait
         * inaccessible. Fail-closed. */
        if (! empty(DB::table('users')->where('id', $idCompte)->value('totp_secret'))) {
            $requete->session()->forget(['enrolement_secret', 'enrolement_compte']);

            return redirect()->route('second-facteur');
        }

        if ($this->tropDeTentatives($requete) || $this->ipBloquee($requete)) {
            return back()->withErrors(['2fa_code' => __('auth.erreur_trop_de_tentatives')]);
        }

        $verdict = $this->totp->verifie($idCompte, TotpCrypto::chiffre($secret), (string) $requete->input('2fa_code'));
        $this->journalise($requete, (string) $temporaire['nom'], $verdict);

        if ($verdict === 'rejeu') {
            return back()->withErrors(['2fa_code' => __('auth.erreur_code_deja_utilise')]);
        }
        if ($verdict !== 'ok') {
            return back()->withErrors(['2fa_code' => __('auth.erreur_code_invalide')]);
        }

        /* INVARIANT 2. L'ecriture arrive ICI, apres la preuve, et jamais avant. */
        DB::table('users')->where('id', $idCompte)->update([
            'totp_secret' => TotpCrypto::chiffre($secret),
        ]);
        $requete->session()->forget(['enrolement_secret', 'enrolement_compte']);

        return $this->ouvreLaSession($requete, $idCompte);
    }

    /**
     * Le QR code, en SVG.
     *
     * Le conteneur du portage n'a **ni gd ni imagick** (mesure) : le legacy rend
     * un PNG en base64, ce qui est ici impossible. Le SVG s'inscrit directement
     * dans la page, ne demande aucune extension, et reste net a toute taille.
     */
    private function qrCode(string $secret, string $nom): string
    {
        $emetteur = (string) config('app.name', 'RootWarden');
        $uri = 'otpauth://totp/' . rawurlencode($emetteur . ':' . $nom)
            . '?secret=' . $secret . '&issuer=' . rawurlencode($emetteur);

        $rendu = new ImageRenderer(new RendererStyle(220, 1), new SvgImageBackEnd());

        return (new Writer($rendu))->writeString($uri);
    }

    /** Debit par session, 5 tentatives glissantes sur 60 s — comme la connexion. */
    private function tropDeTentatives(Request $requete): bool
    {
        $tentatives = collect($requete->session()->get('tentatives_2fa', []))
            ->filter(fn ($t) => $t > time() - 60)
            ->values();
        $tentatives->push(time());
        $requete->session()->put('tentatives_2fa', $tentatives->all());

        return $tentatives->count() > (int) config('rootwarden.connexion.max_tentatives_2fa', 5);
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
        if ($this->tropDeTentatives($requete)) {
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

        $this->journalise($requete, (string) $compte->name, $verdict);

        if ($verdict === 'rejeu') {
            return back()->withErrors(['2fa_code' => __('auth.erreur_code_deja_utilise')]);
        }
        if ($verdict === 'sans_secret') {
            return back()->withErrors(['2fa_code' => __('auth.erreur_sans_secret')]);
        }
        if ($verdict !== 'ok') {
            return back()->withErrors(['2fa_code' => __('auth.erreur_code_invalide')]);
        }

        return $this->ouvreLaSession($requete, (int) $compte->id);
    }

    /**
     * Le seul endroit ou une session devient authentifiee.
     *
     * Partage par la verification et par l'enrolement : deux copies de ce
     * chemin auraient fini par diverger, et c'est le chemin ou une divergence
     * accorde un acces.
     *
     * Le compte est RELU en base a cet instant — role et exigences comprises —
     * plutot que repris d'un objet charge plus tot : entre le mot de passe et
     * ici, un role a pu changer.
     */
    private function ouvreLaSession(Request $requete, int $idCompte): RedirectResponse
    {
        $compte = DB::table('users')
            ->select('id', 'name', 'role_id', 'active', 'force_password_change')
            ->where('id', $idCompte)
            ->first();

        if (! $compte || ! $compte->active) {
            $requete->session()->flush();

            return redirect()->route('connexion');
        }

        $requete->session()->regenerate();
        $requete->session()->forget(['compte_temporaire', 'tentatives_2fa']);
        $requete->session()->put('utilisateur_id', (int) $compte->id);

        /*
         * E-203 — la ligne de revocation, posee APRES `regenerate()`.
         *
         * Avant, l'identifiant serait l'ancien, et le garde
         * `session.revoquee` ne retrouverait pas la session au premier
         * passage : la personne serait mise dehors immediatement apres
         * s'etre authentifiee.
         */
        $this->sessions->enregistre($requete, (int) $compte->id);
        $requete->session()->put('utilisateur_nom', (string) $compte->name);
        $requete->session()->put('role_id', (int) $compte->role_id);

        /*
         * ══ « SE SOUVENIR DE MOI » — L'EMISSION EST ICI, ET NULLE PART AILLEURS
         *
         * Ce point est le succes UNIQUE des deux chemins du second facteur, donc
         * le seul endroit ou « le defi a ete franchi » est vrai. Le legacy emet
         * le jeton a `login.php:176`, juste apres avoir pose `2fa_required` —
         * c'est-a-dire AVANT le defi. On ne porte pas ce choix : voir
         * `JetonMemorisation`, divergence 2.
         *
         * ⚠ ET UNE RESTAURATION NE RENOUVELLE PAS LE JETON. `memoriser` n'est
         * pose que par `ConnexionController`, jamais par
         * `RestaureMemorisation` : les trente jours courent depuis la derniere
         * saisie du mot de passe, pas depuis la derniere visite. Une expiration
         * glissante ferait vivre un porteur d'identite indefiniment sans qu'on
         * ait jamais reverifie quoi que ce soit.
         */
        $memoriser = (bool) ($temporaire['memoriser'] ?? false);

        if ((int) ($compte->force_password_change ?? 0) === 1) {
            $requete->session()->put('changement_mot_de_passe_requis', true);
            $reponse = redirect()->route('profil', ['force_change' => 1]);
        } else {
            $reponse = redirect()->route('cgu');
        }

        return $memoriser ? $reponse->withCookie($this->cookieMemorisation((int) $compte->id)) : $reponse;
    }

    /**
     * Le cookie du jeton — TOUS ses attributs explicites.
     *
     * ⚠ AUCUN TEST FEATURE NE VOIT UN ATTRIBUT DE COOKIE, et un test de
     * navigateur exige le banc. **La parite avec le legacy se verifie donc par
     * LECTURE**, et voici la table de correspondance
     * (`legacy/auth/login.php:206-211`) :
     *
     *     expires   time() + 2592000        ->  30 jours (JetonMemorisation::JOURS)
     *     path      '/'                     ->  '/'
     *     secure    true                    ->  true
     *     httponly  true                    ->  true
     *     samesite  'Strict'                ->  'Strict'
     *
     * **La DUREE est un attribut de securite autant que les trois autres** — et
     * si on laissait le defaut du cadre plutot que de l'ecrire, la divergence
     * serait SILENCIEUSE : un cookie qui vit plus longtemps que prevu ne se voit
     * nulle part. Elle est donc posee explicitement.
     *
     * ⚠ CONSEQUENCE DE PERIODE DE TRANSITION, DECLAREE. Ce cookie est CHIFFRE :
     * `EncryptCookies` s'applique et on ne l'en exempte pas — un porteur
     * d'identite n'a rien a faire dans une liste d'exceptions. Le legacy, lui,
     * lit `$_COOKIE['remember_token']` en clair : il ne saura pas le lire et
     * l'effacera (`functions.php:111`). **Donc visiter l'ancien portail annule la
     * memorisation du nouveau.** *C'est un desagrement de transition, pas un
     * defaut de securite — et il vaut mieux que d'exempter le jeton du
     * chiffrement pour un portail qu'on demonte.*
     */
    private function cookieMemorisation(int $idCompte): \Symfony\Component\HttpFoundation\Cookie
    {
        return cookie()->make(
            JetonMemorisation::COOKIE,
            $this->jetons->emet($idCompte),
            JetonMemorisation::JOURS * 24 * 60,
            '/',
            null,
            true,      // secure
            true,      // httpOnly
            false,     // raw
            'Strict',  // sameSite
        );
    }

    /** Compteur d'echecs par IP sur 10 minutes, partage avec le legacy. */
    private function ipBloquee(Request $requete): bool
    {
        try {
            $echecs = DB::table('login_attempts')
                ->where('ip_address', $requete->ip() ?? '0.0.0.0')
                // La CONSTANTE, pas le litteral : si l'etape des rejeux changeait
                // de nom, ce compteur doit continuer de ne compter que celle-ci.
                ->where('step', self::ETAPE_2FA)
                ->where('success', 0)
                ->where('attempted_at', '>', now()->subMinutes(10))
                ->count();

            return $echecs >= (int) config('rootwarden.connexion.max_echecs_ip', 10);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Inscrit la tentative. Recoit le VERDICT et non un booleen, pour qu'UNE
     * SEULE place decide `success` ET `step` : passes separement, les deux
     * finiraient par se contredire — un rejeu inscrit en echec, ou un echec
     * inscrit hors du compteur.
     */
    private function journalise(Request $requete, string $nom, string $verdict): void
    {
        try {
            DB::table('login_attempts')->insert([
                'ip_address'   => $requete->ip() ?? '0.0.0.0',
                'username'     => $nom,
                'success'      => $verdict === 'ok' ? 1 : 0,
                'step'         => $verdict === 'rejeu' ? self::ETAPE_REJEU : self::ETAPE_2FA,
                'attempted_at' => now(),
            ]);
        } catch (\Throwable) {
        }
    }
}
