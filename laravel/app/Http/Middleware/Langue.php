<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * Langue active de la requete.
 *
 * Portage fidele de legacy/includes/lang.php :
 *   priorite  ?lang= (valide)  >  session  >  cookie  >  defaut
 *   persistance  session ET cookie (365 jours)
 *
 * LA LISTE BLANCHE EST UN CONTROLE DE SECURITE, pas une commodite. Cote legacy,
 * un pentest a montre qu'un cookie `lang` forge permettait d'inclure un fichier
 * arbitraire (`require '/lang/<valeur>.php'`). Laravel ne construit pas de
 * chemin de la meme facon, mais la valeur alimente `setLocale()` et finit dans
 * l'attribut `lang` du document : toute valeur hors liste retombe sur le defaut,
 * sans exception et sans message.
 */
class Langue
{
    /** Seules langues acceptees. Toute autre valeur est ignoree. */
    public const LANGUES = ['fr', 'en'];

    public const DEFAUT = 'fr';

    /** Duree du cookie de preference, en minutes (365 jours). */
    private const DUREE_COOKIE = 60 * 24 * 365;

    public function handle(Request $requete, Closure $suite): Response
    {
        $demandee = $this->valide($requete->query('lang'));

        $langue = $demandee
            ?? $this->valide($requete->session()->get('langue'))
            ?? $this->valide($requete->cookie('langue'))
            ?? self::DEFAUT;

        app()->setLocale($langue);

        $reponse = $suite($requete);

        // On ne persiste QUE sur un changement explicite : reecrire le cookie a
        // chaque requete pour rien allonge la reponse sans rien apporter.
        if ($demandee !== null) {
            $requete->session()->put('langue', $demandee);

            // Cookie de PREFERENCE, non sensible : SameSite Lax suffit, comme
            // le legacy.
            //
            // La valeur part CHIFFREE : le middleware EncryptCookies du cadre
            // chiffre tout ce qui n'est pas explicitement exclu, et la relit de
            // meme. L'avant-dernier argument de `cookie()` est le drapeau `raw`
            // (encodage d'URL), pas le chiffrement — les confondre conduit a
            // ecrire un commentaire qui dit l'inverse du code.
            $reponse->headers->setCookie(
                cookie('langue', $demandee, self::DUREE_COOKIE, '/', null, $requete->secure(), true, false, 'lax')
            );
        }

        return $reponse;
    }

    /** Rend la langue si elle est dans la liste blanche, sinon null. */
    private function valide(mixed $valeur): ?string
    {
        return is_string($valeur) && in_array($valeur, self::LANGUES, true) ? $valeur : null;
    }
}
