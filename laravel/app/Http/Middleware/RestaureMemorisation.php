<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Services\JetonMemorisation;
use App\Support\DecisionRestauration;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * « Se souvenir de moi » — l'aiguillage, et RIEN de plus.
 *
 * Il s'execute AVANT `session.authentifiee`, parce que celui-ci renvoie vers la
 * connexion des que `utilisateur_id` manque : apres lui, il n'y aurait plus rien
 * a restaurer.
 *
 * ══ CE QUE CET INTERGICIEL NE FAIT PAS ═══════════════════════════════════
 *
 * **Il n'ouvre AUCUNE session.** Il ne pose ni `utilisateur_id`, ni
 * `utilisateur_nom`, ni `role_id`. Il pose `compte_temporaire` — la meme cle que
 * `ConnexionController` apres un mot de passe correct — et renvoie vers le second
 * facteur ou vers l'enrolement.
 *
 * *La restauration rend donc exactement ce que rend un mot de passe correct : le
 * DROIT DE PRESENTER son second facteur. Rien de plus.*
 *
 * ⚠ **L'EXHAUSTIVITE EST TENUE PAR `match`, ET C'EST DELIBERE.** La session 6 a
 * releve que retirer le cas « portail » de `DecisionRestauration` deplace le
 * risque : la valeur fautive n'existe plus, mais **un appelant qui recoit `Defi`
 * et ne fait rien laisse la requete continuer** — sans qu'aucune valeur fautive
 * ne soit en cause.
 *
 * `match` sur une enumeration leve `UnhandledMatchError` sur un cas non traite.
 * **Donc ajouter un cas a l'enumeration casse CET intergiciel bruyamment, au lieu
 * de le laisser tomber en silence dans un chemin qui passe.** *C'est la propriete
 * que la session 6 verrouillera : « aucun cas non traite ne laisse la requete
 * continuer » — et elle vit ici, pas dans le type.*
 */
class RestaureMemorisation
{
    public function __construct(private readonly JetonMemorisation $jetons)
    {
    }

    public function handle(Request $requete, Closure $suite): Response
    {
        // Deja authentifie : il n'y a rien a restaurer, et toucher a la session
        // d'une personne connectee serait un effet de bord gratuit.
        if ($requete->session()->has('utilisateur_id')) {
            return $suite($requete);
        }

        $cookie = $requete->cookie(JetonMemorisation::COOKIE);
        if (! is_string($cookie) || $cookie === '') {
            return $suite($requete);
        }

        return match ($this->jetons->decide($cookie)) {
            /*
             * Le compte porte un second facteur : on lui rend le droit de le
             * presenter, exactement comme un mot de passe correct.
             */
            DecisionRestauration::Defi => $this->versLeFacteur($requete, 'second-facteur'),

            /*
             * Il n'en porte pas : l'ENROLEMENT, jamais le portail. C'est le cas
             * ou le legacy laisse passer (`verify.php:139`, `if` sans `else`).
             */
            DecisionRestauration::Enrolement => $this->versLeFacteur($requete, 'second-facteur.enrolement'),

            /*
             * Rien de valide. On NETTOIE — `decide()` reste sans effet de bord
             * pour rester verrouillable a sec, donc le menage est ici — puis on
             * laisse `session.authentifiee` decider. Ne pas nettoyer laisserait
             * une ligne morte ressusciter au prochain cookie portant le meme
             * identifiant.
             */
            DecisionRestauration::Refus => $this->oublie($requete, $suite),
        };
    }

    /**
     * Pose l'identite TEMPORAIRE et renvoie vers l'etape du second facteur.
     *
     * ⚠ `compte_temporaire` et non `utilisateur_id` : cette cle est celle que le
     * second facteur consomme, et elle n'ouvre aucun acces par elle-meme.
     */
    private function versLeFacteur(Request $requete, string $route): Response
    {
        $id = $this->jetons->idDuCookie($requete->cookie(JetonMemorisation::COOKIE));
        $identite = $id === null ? null : $this->jetons->identite($id);

        /*
         * FAIL-CLOSED. `decide()` vient de rendre `Defi` ou `Enrolement`, donc
         * l'identite EXISTE — mais si elle manquait quand meme, poser une cle
         * incomplete ferait lire `$temporaire['nom']` sur du vide au tour
         * suivant. On renvoie a la connexion plutot que de fabriquer un etat
         * que le second facteur devra deviner.
         */
        if ($identite === null) {
            return redirect()->route('connexion');
        }

        // La MEME forme qu'apres un mot de passe correct : `['id','nom','role']`.
        $requete->session()->put('compte_temporaire', $identite);

        return redirect()->route($route);
    }

    /** Retire le jeton et le cookie, puis rend la main. */
    private function oublie(Request $requete, Closure $suite): Response
    {
        $id = $this->jetons->idDuCookie($requete->cookie(JetonMemorisation::COOKIE));
        if ($id !== null) {
            $this->jetons->revoque($id);
        }

        /** @var Response $reponse */
        $reponse = $suite($requete);
        $reponse->headers->clearCookie(JetonMemorisation::COOKIE, '/');

        return $reponse;
    }
}
