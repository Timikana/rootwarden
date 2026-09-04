<?php

declare(strict_types=1);

namespace App\Services;

use App\Support\DecisionRestauration;
use App\Support\DepotJetonsMemorisation;

/**
 * « Se souvenir de moi » — l'emission et la DECISION de restauration.
 *
 * Porte de `legacy/auth/login.php:176-196` (emission) et
 * `legacy/auth/functions.php:101` + `verify.php:126-151` (restauration).
 *
 * ══ DEUX DIVERGENCES DELIBEREES, ET LA PREMIERE EST UN CORRECTIF ══════════
 *
 * ⛔ **1. LA RESTAURATION N'AUTHENTIFIE JAMAIS.** Le legacy conditionne sa
 * re-authentification a `if ($totpSecret)` **sans `else`**. Pour un compte SANS
 * secret TOTP : aucun drapeau n'est pose, le garde de `verify.php:153` ne tire
 * pas, et l'execution continue avec `$_SESSION['user_id']` renseigne — **le
 * cookie authentifie seul**, sans second facteur et sans la redirection vers
 * l'enrolement que `login.php` impose partout ailleurs.
 *
 * *Un compte actif est aujourd'hui dans ce cas. Et le filet qui rattrape les
 * sept autres est le garde de CHANGEMENT DE MOT DE PASSE, qui parle d'autre
 * chose — il s'evapore des qu'un compte fait ce qu'on lui demande.*
 *
 * **Ici la propriete est INCONDITIONNELLE, et portee par le TYPE** :
 * `DecisionRestauration` n'a pas de cas « portail ». L'acces direct n'est pas
 * « jamais rendu », il est inexprimable.
 *
 * ⛔ **2. LE JETON EST EMIS APRES LE SECOND FACTEUR, jamais avant.** Le legacy
 * le cree a `login.php:176`, juste apres `$_SESSION['2fa_required'] = true`.
 * Deux raisons de ne pas porter ce choix :
 *
 *   — `remember_tokens` porte `PRIMARY KEY (user_id)`, donc une connexion
 *     ABANDONNEE au stade du second facteur sur un appareil evince
 *     silencieusement le jeton qui fonctionnait sur l'autre ;
 *   — et surtout : emis avant, le cas « restaure sans avoir JAMAIS franchi le
 *     second facteur » devient **produisible par le portage**. Ce ne serait plus
 *     une compatibilite heritee, ce serait une creation.
 *
 * ══ CE QU'AUCUN TEST HERMETIQUE NE VERIFIERA, ET QUI SE LIT ═══════════════
 *
 * Les attributs du cookie — `Secure`, `HttpOnly`, `SameSite=Strict` — sont poses
 * par l'appelant, pas ici. Le legacy les pose a `login.php:206-211`, et **la
 * parite se verifie par LECTURE** : aucun test Feature ne voit un attribut de
 * cookie, et un test de navigateur exige le banc. *C'est ecrit la plutot que
 * dans un compte rendu, parce qu'une reserve qui vit dans un message ne protege
 * personne.*
 */
class JetonMemorisation
{
    /** Le nom du cookie, repris du legacy pour que les deux portails s'entendent. */
    public const COOKIE = 'remember_token';

    /** Trente jours, comme `login.php:180`. */
    public const JOURS = 30;

    public function __construct(private readonly DepotJetonsMemorisation $depot)
    {
    }

    /**
     * Ce que ce cookie obtient. AUCUN effet de bord — voir la note sur `retire()`.
     *
     * L'ordre des refus est celui du legacy (`functions.php:101-140`), et chaque
     * etape refuse pour une raison DISTINCTE plutot que de retomber sur un
     * verdict commun.
     */
    public function decide(?string $cookie): DecisionRestauration
    {
        if ($cookie === null || $cookie === '') {
            return DecisionRestauration::Refus;
        }

        // `<user_id>:<jeton>` — deux morceaux, pas plus : un jeton contenant un
        // deux-points ne doit pas se faire couper.
        $morceaux = explode(':', $cookie, 2);
        if (count($morceaux) !== 2) {
            return DecisionRestauration::Refus;
        }
        [$brut, $jeton] = $morceaux;

        if (! ctype_digit($brut) || (int) $brut <= 0 || $jeton === '') {
            return DecisionRestauration::Refus;
        }
        $idCompte = (int) $brut;

        $ligne = $this->depot->pour($idCompte);
        if ($ligne === null) {
            return DecisionRestauration::Refus;
        }

        /*
         * `password_verify` et non une comparaison : le jeton est stocke HACHE,
         * et il ne doit pas etre comparable en temps constant a autre chose que
         * son empreinte. C'est aussi ce qui fait qu'un `user_id` d'autrui ne
         * sert a rien : le jeton de la ligne trouvee ne correspondra pas.
         */
        if (! password_verify($jeton, $ligne->token_hash)) {
            return DecisionRestauration::Refus;
        }

        /*
         * ⚠ L'EXPIRATION EST DECIDEE PAR LE SERVEUR, jamais par le cookie. Un
         * cookie non expire cote client peut l'etre en base — et c'est la base
         * qui detient la verite. Signale par la session 6 : mon premier releve de
         * temoins ne couvrait pas ce cas.
         */
        if (strtotime((string) $ligne->expires_at) <= time()) {
            return DecisionRestauration::Refus;
        }

        $compte = $this->depot->compte($idCompte);
        if ($compte === null || (int) $compte->active !== 1) {
            return DecisionRestauration::Refus;
        }

        /*
         * ⛔ LE SEUL ENDROIT OU LES DEUX CHEMINS DIVERGENT — et aucun des deux
         * ne mene au portail. Le legacy n'a PAS de branche `else` ici, et c'est
         * tout le defaut.
         */
        return ($compte->totp_secret ?? '') !== ''
            ? DecisionRestauration::Defi
            : DecisionRestauration::Enrolement;
    }

    /**
     * Emet un jeton et rend la valeur A POSER DANS LE COOKIE.
     *
     * ⚠ N'APPELER QU'APRES LA REUSSITE DU SECOND FACTEUR. Voir la divergence 2
     * en tete de classe : appele plus tot, ce geste fabrique le defaut qu'il
     * existe pour ne pas porter.
     *
     * Le clair n'est rendu qu'ICI et ne s'ecrit nulle part : la base ne recoit
     * que son empreinte.
     */
    public function emet(int $idCompte): string
    {
        $jeton = bin2hex(random_bytes(32));
        $this->depot->remplace(
            $idCompte,
            // Le cout est celui que les deux portails partagent — un hache plus
            // faible d'un cote serait le maillon du systeme entier.
            password_hash($jeton, PASSWORD_BCRYPT, ['cost' => (int) config('rootwarden.bcrypt_cost', 12)]),
            now()->addDays(self::JOURS)->format('Y-m-d H:i:s'),
        );

        return $idCompte . ':' . $jeton;
    }

    /**
     * Retire le jeton d'un compte.
     *
     * ⚠ `decide()` ne le fait PAS, deliberement : il reste sans effet de bord
     * pour que la session 6 puisse le verrouiller avec un depot en LECTURE
     * SEULE. C'est donc a l'appelant de nettoyer sur `Refus` — le legacy le fait
     * (`functions.php:135`), et ne pas le faire laisserait une ligne morte
     * ressusciter au prochain cookie forge portant le meme identifiant.
     */
    public function revoque(int $idCompte): void
    {
        $this->depot->retire($idCompte);
    }

    /**
     * L'identite TEMPORAIRE a poser en session, dans la forme que
     * `SecondFacteurController` consomme — `['id', 'nom', 'role']`.
     *
     * ⚠ Elle n'authentifie RIEN : c'est la meme cle et la meme forme qu'apres un
     * mot de passe correct, et elle ne donne que le droit de presenter son
     * second facteur.
     *
     * @return array{id: int, nom: string, role: int}|null
     */
    public function identite(int $idCompte): ?array
    {
        $compte = $this->depot->compte($idCompte);
        if ($compte === null || (int) $compte->active !== 1) {
            return null;
        }

        return [
            'id'   => $idCompte,
            'nom'  => (string) ($compte->name ?? ''),
            'role' => (int) ($compte->role_id ?? 1),
        ];
    }

    /** L'identifiant porte par un cookie, sans rien decider. Pour le nettoyage. */
    public function idDuCookie(?string $cookie): ?int
    {
        $morceaux = explode(':', (string) $cookie, 2);

        return count($morceaux) === 2 && ctype_digit($morceaux[0]) && (int) $morceaux[0] > 0
            ? (int) $morceaux[0]
            : null;
    }
}
