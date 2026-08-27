<?php

namespace Tests\Feature;

use Illuminate\Routing\Route;
use Illuminate\Support\Facades\Route as Routeur;
use PHPUnit\Framework\Attributes\Test;
use Tests\Support\TableDesGardes;
use Tests\TestCase;

/**
 * L'INVENTAIRE DES GARDES : ce que chaque route DECLARE, compare au releve figé.
 *
 * Ce fichier ne fait tourner aucune requete. Il compare deux listes : celle que
 * le routeur porte, et celle que `TableDesGardes` a figée. Sa raison d'etre est
 * la classe de defaut la plus couteuse du chantier — « la garde est sur la
 * PAGE, pas sur la REQUETE » — releve trois fois dans trois modules
 * differents : une route ajoutee hors du groupe authentifie, une garde retiree,
 * un commentaire qui annonce un acces plus strict que le code.
 *
 * Aucune de ces trois n'aurait ete vue par un test qui se contente de verifier
 * que les pages connues refusent bien. Ce qu'il faut mesurer, c'est
 * l'ENSEMBLE : toute route du portage est soit dans le releve authentifie, soit
 * dans la liste publique motivee. Il n'y a pas de troisieme cas.
 */
class InventaireDesGardesTest extends TestCase
{
    /** Les gardes du portage, par opposition a celles du cadre. */
    private const NOTRES = ['session.authentifiee', 'role', 'perm'];

    #[Test]
    public function aucune_route_n_echappe_au_releve(): void
    {
        $manquantes = [];

        foreach ($this->routesDuPortage() as $cle => $gardes) {
            if (! isset($this->releveAuthentifie()[$cle]) && ! isset(TableDesGardes::publiques()[$cle])) {
                $manquantes[$cle] = $gardes === [] ? '(AUCUNE GARDE)' : implode(',', $gardes);
            }
        }

        $this->assertSame([], $manquantes,
            "Des routes ne figurent dans AUCUNE des deux listes de TableDesGardes.\n"
            . "Une route neuve doit y etre inscrite dans le meme commit que sa declaration.\n"
            . 'Trouve : ' . json_encode($manquantes, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    #[Test]
    public function le_releve_ne_nomme_aucune_route_disparue(): void
    {
        $connues  = $this->routesDuPortage();
        $fantomes = [];

        foreach (array_keys($this->releveAuthentifie()) as $cle) {
            if (! isset($connues[$cle])) {
                $fantomes[] = $cle;
            }
        }

        foreach (array_keys(TableDesGardes::publiques()) as $cle) {
            if (! isset($connues[$cle])) {
                $fantomes[] = $cle;
            }
        }

        $this->assertSame([], $fantomes,
            "Le releve nomme des routes qui n'existent plus. Une attente qui ne "
            . "porte sur rien passe toujours : elle doit etre retiree ou corrigee.\n"
            . 'Trouve : ' . implode(', ', $fantomes));
    }

    #[Test]
    public function chaque_route_authentifiee_declare_exactement_les_gardes_relevees(): void
    {
        $connues   = $this->routesDuPortage();
        $divergent = [];

        foreach ($this->releveAuthentifie() as $cle => $attendues) {
            $reelles = $connues[$cle] ?? null;

            if ($reelles === null) {
                continue; // deja dit par le test des routes disparues
            }

            $attenduComplet = array_merge(['session.authentifiee'], $attendues);

            if ($reelles !== $attenduComplet) {
                $divergent[$cle] = [
                    'attendu' => implode(',', $attenduComplet),
                    'declare' => implode(',', $reelles) ?: '(AUCUNE)',
                ];
            }
        }

        $this->assertSame([], $divergent,
            "Des gardes declarees different du releve figé.\n"
            . "Si le changement est VOULU, corriger TableDesGardes dans le meme commit "
            . "et dire pourquoi dans son message. Sinon, c'est une regression d'acces.\n"
            . json_encode($divergent, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    #[Test]
    public function chaque_route_publique_est_motivee_et_ne_porte_aucune_garde(): void
    {
        $connues = $this->routesDuPortage();
        $fautifs = [];

        foreach (TableDesGardes::publiques() as $cle => $motif) {
            $this->assertNotSame('', trim($motif), "La route publique $cle n'a pas de motif ecrit.");

            if (($connues[$cle] ?? []) !== []) {
                $fautifs[$cle] = implode(',', $connues[$cle]);
            }
        }

        // Une route publique qui porterait une garde n'est pas un danger — c'est
        // le releve qui serait faux, et un releve faux endort la relecture.
        $this->assertSame([], $fautifs,
            'Des routes relevees comme publiques portent en realite une garde : ' . json_encode($fautifs));
    }

    #[Test]
    public function le_compte_des_deux_listes_se_reconstitue(): void
    {
        // « Un total qu'on ne sait pas reconstituer n'est pas un total. » Sans
        // cette assertion, les deux listes pourraient deriver ensemble sans que
        // rien ne le dise.
        $this->assertCount(
            count($this->routesDuPortage()),
            $this->releveAuthentifie() + TableDesGardes::publiques(),
            'authentifiees + publiques doit rendre exactement le nombre de routes declarees',
        );
    }

    #[Test]
    public function la_passerelle_est_la_seule_route_authentifiee_sans_role(): void
    {
        /*
         * Cette route relaie 200 routes du backend derriere UNE seule
         * declaration. Elle ne peut donc pas porter de `role:` : ses gardes
         * vivent DANS le controleur, par liste blanche, reserve
         * administrateur et re-authentification. C'est une exception, et une
         * exception qui n'est pas nommee finit par etre imitee.
         *
         * PasserelleTest mesure ces gardes-la. Ici on mesure seulement que
         * l'exception reste unique dans sa famille : une AUTRE route de relais
         * sans role apparaitrait ici.
         */
        $sansRole = [];

        foreach ($this->releveAuthentifie() as $cle => $gardes) {
            if ($gardes === []) {
                $sansRole[] = $cle;
            }
        }

        sort($sansRole);

        $this->assertSame([
            'GET accueil',
            'GET api/gateway/{chemin?}',
            'GET cgu',
            'GET profil',
            'POST cgu',
            'POST profil/mot-de-passe',
            'POST profil/step-up',
            'POST profil/step-up/revoquer',
        ], $sansRole, 'Les routes authentifiees sans garde de role doivent rester ces huit — '
            . 'les sept pages du compte lui-meme, et la passerelle qui garde ailleurs.');
    }

    /** @return array<string,list<string>> "METHODE uri" => gardes du portage */
    private function routesDuPortage(): array
    {
        $table = [];

        /** @var Route $route */
        foreach (Routeur::getRoutes() as $route) {
            $methodes = array_values(array_diff($route->methods(), ['HEAD']));

            if ($methodes === []) {
                continue;
            }

            $gardes = array_values(array_filter(
                $route->gatherMiddleware(),
                fn ($m) => is_string($m) && in_array(explode(':', $m)[0], self::NOTRES, true),
            ));

            $table[$methodes[0] . ' ' . ($route->uri() === '/' ? '/' : $route->uri())] = $gardes;
        }

        return $table;
    }

    /** @return array<string,list<string>> */
    private function releveAuthentifie(): array
    {
        $table = [];

        foreach (TableDesGardes::authentifiees() as [$methode, $uri, $gardes]) {
            $table[$methode . ' ' . $uri] = $gardes;
        }

        return $table;
    }
}
