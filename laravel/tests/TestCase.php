<?php

namespace Tests;

use App\Services\Droits;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Tests\Doubles\DroitsFictifs;

/**
 * Socle des tests Feature et Unit du portage.
 *
 * ── CE QUE CES TESTS MESURENT, ET CE QU'ILS NE MESURENT PAS ──────────────────
 *
 * Ils sont HERMETIQUES : aucune base MySQL, aucun backend Python, aucun
 * navigateur. `phpunit.xml` pointe `DB_CONNECTION` sur un SQLite en memoire qui
 * ne porte AUCUNE table — le schema appartient au backend Python
 * (`mysql/migrations/*.sql`), il n'existe pas de migration Laravel, et en
 * fabriquer une ici ferait diverger deux descriptions du meme schema.
 *
 * Consequence a dire clairement, plutot que de la laisser deviner :
 *
 *   mesure ici          les REFUS — redirection sans session, 403 de role, 403
 *                       de permission — et la logique pure (RoutesBackend,
 *                       StepUp, Droits sur un schema pose par le test).
 *   NE mesure PAS ici   qu'une page AUTORISEE rende son contenu. Cela demande
 *                       la base du banc et le backend : c'est le domaine des
 *                       suites `tests/e2e/`, au navigateur.
 *   NE mesure PAS ici   le jeton CSRF. Le cadre EXEMPTE les tests
 *                       (`PreventRequestForgery::runningUnitTests`, verifie
 *                       ligne 99 de vendor/.../PreventRequestForgery.php) : une
 *                       assertion CSRF ecrite ici passerait sans rien mesurer.
 *                       C'est `tests/e2e/go-socle-passerelle.mjs` qui la porte.
 *
 * ── LA BASE N'EST PAS TOUCHEE, ET C'EST VOULU ────────────────────────────────
 *
 * `connecte()` installe un DOUBLE de `App\Services\Droits` dans le conteneur.
 * Deux raisons, dans cet ordre :
 *   1. le double ENREGISTRE ses consultations, ce qui permet d'affirmer non
 *      seulement qu'un acces a ete refuse, mais que le garde de permission a
 *      bel et bien ete INTERROGE — un 403 obtenu pour une autre raison ne
 *      prouverait pas que la permission est controlee ;
 *   2. la base du banc est UNIQUE et partagee par sept sessions de travail :
 *      un test qui la lit accuserait la page pour un etat du banc.
 */
abstract class TestCase extends BaseTestCase
{
    /** Identifiant de compte employe par defaut. Aucun compte reel ne le porte. */
    public const COMPTE = 90001;

    /** Le double installe par le dernier appel a `connecte()`. */
    protected ?DroitsFictifs $droits = null;

    /**
     * Pose une session COMPLETEMENT authentifiee et le jeu de permissions du
     * compte, sans toucher la base.
     *
     * @param  list<string>  $permissions  noms des permissions accordees
     */
    protected function connecte(int $roleId, array $permissions = [], int $idCompte = self::COMPTE): static
    {
        $this->droits = new DroitsFictifs(array_fill_keys($permissions, true));
        $this->instance(Droits::class, $this->droits);

        return $this->withSession([
            'utilisateur_id' => $idCompte,
            'role_id'        => $roleId,
        ]);
    }

    /**
     * Installe le double sans ouvrir de session : l'appelant est un visiteur.
     *
     * Sans cela, un garde qui laisserait passer un visiteur irait interroger la
     * base — et l'echec ressemblerait a un defaut d'infrastructure au lieu d'un
     * defaut de garde.
     */
    protected function visiteur(): static
    {
        $this->droits = new DroitsFictifs([]);
        $this->instance(Droits::class, $this->droits);

        return $this;
    }
}
