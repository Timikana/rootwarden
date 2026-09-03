<?php

namespace App\Http\Middleware;

use App\Services\SessionsActives;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Le garde qui rend la revocation EFFECTIVE — E-203, troisieme volet.
 *
 * ══ SANS LUI, LES DEUX AUTRES VOLETS NE FONT RIEN ═════════════════════════
 *
 * Ecrire dans `active_sessions` et offrir un bouton « Revoquer » produit une
 * SUPPRESSION que personne ne lit. Les sessions du portage vivent en FICHIERS
 * (`SESSION_DRIVER=file`) : retirer une ligne de base n'en ferme aucune.
 *
 * **C'est E-188 pris un cran plus haut** — la, une colonne etait ecrite et
 * jamais lue ; ici c'est une DECISION qui ne serait jamais consultee. Et le
 * cout est pire : un ecran qui offre une revocation sans effet ne se signale
 * par rien, et se decouvre le jour ou quelqu'un compte dessus.
 *
 * ══ FAIL-OPEN, ET C'EST UN ARBITRAGE ══════════════════════════════════════
 *
 * Base injoignable => on laisse passer, et on journalise. Le legacy prend le
 * meme parti (`verify.php:116-121`). Deconnecter tout le monde sur un incident
 * de base serait un deni de service que la revocation ne merite pas : les
 * gardes de ROLE et de PERMISSION restent en place derriere.
 *
 * `estVivante()` rend donc `null` pour « pas lu » et `false` pour « absente »,
 * et ce garde distingue les deux. Confondre les deux, c'est soit cacher
 * l'incident, soit mettre tout le monde dehors.
 */
class SessionRevoquee
{
    public function __construct(private readonly SessionsActives $sessions)
    {
    }

    public function handle(Request $requete, Closure $suivant): Response
    {
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);

        // Session pas encore pleinement authentifiee : rien a verifier. Le
        // legacy pose la meme condition, par l'absence de `2fa_required`.
        if ($idCompte <= 0) {
            return $suivant($requete);
        }

        $identifiant = $requete->session()->getId();
        $vivante = $this->sessions->estVivante($identifiant, $idCompte);

        // `null` = la table n'a pas repondu. On NE decide pas.
        if ($vivante === null) {
            return $suivant($requete);
        }

        if ($vivante === false) {
            /*
             * La ligne a disparu : revoquee depuis le profil, fermee par un
             * changement de mot de passe, ou jamais posee. Dans tous les cas
             * la session ne doit plus servir.
             *
             * `invalidate()` detruit le fichier de session ; `regenerateToken()`
             * evite qu'un jeton de l'ancienne session reste valable sur
             * l'ecran de connexion.
             */
            $requete->session()->invalidate();
            $requete->session()->regenerateToken();

            return redirect()->route('connexion', ['expiree' => 1]);
        }

        // Vivante : on note le passage, au plus une fois par minute.
        $this->sessions->touche($identifiant, $idCompte);

        return $suivant($requete);
    }
}
