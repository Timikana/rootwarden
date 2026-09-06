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
    public function les_routes_authentifiees_sans_role_sont_CELLES_QUI_SONT_GELEES(): void
    {
        /*
         * ── LE NOM DE CE TEST ETAIT FAUX, ET C'EST MOI QUI L'AVAIS ECRIT ────
         *
         * Il s'appelait « la passerelle est la SEULE route authentifiee sans
         * role ». L'assertion, elle, gelait DEJA huit noms : le titre promettait
         * une unicite que le code ne verifiait pas, et il l'a promise jusqu'a ce
         * qu'une route legitime le contredise. C'est exactement le defaut que ce
         * chantier poursuit ailleurs — un texte qui affirme plus que son code —
         * trouve ici dans MON PROPRE test, par un rouge que je ne pouvais pas
         * voir tant que `php artisan test` mourait avant de lancer.
         *
         * Ce que ce test fait reellement : il GELE la famille des routes
         * ouvertes a tout compte connecte. Chaque entree doit avoir une raison
         * ecrite, et une entree NEUVE fait rougir — ce qui oblige a la motiver
         * plutot qu'a la glisser.
         *
         * La passerelle reste le cas particulier de la famille : elle relaie 200
         * routes du backend derriere UNE declaration, donc ses gardes vivent dans
         * le controleur (liste blanche, reserve administrateur,
         * re-authentification) et `PasserelleTest` les mesure.
         *
         * Les autres n'ont pas d'objet a proteger au-dela de l'authentification :
         *   accueil, cgu (GET+POST), profil        l'ecran de tout compte
         *   profil/mot-de-passe, profil/step-up*   ses propres identifiants
 *   profil/courriel, profil/cle-ssh        SES propres coordonnees et SA
 *       propre cle — `feaaaa2`, DOSSIER-30. La cible EST le demandeur,
 *       l'identifiant vient de la SESSION. Le pendant administratif
 *       (`POST comptes/{id}/cle-ssh`) reste `role:3` : deux arites, deux
 *       gardes. Exiger un role ici interdirait a un role 1 de poser la cle
 *       qui sert son propre acces.
 *   profil/effacement                      SON propre compte — et c'est la
 *       seule entree IRREVERSIBLE de cette liste, donc celle a relire.
 *       Le geste est une ANONYMISATION : `user_logs` est une chaine de
 *       hachage, retirer une ligne romprait la verification des suivantes.
 *       Trois protections REELLES dans le controleur — identifiant de
 *       session, RESSAISIE du nom du compte, refus au dernier
 *       superadministrateur.
 *       ⚠ RE-AUTHENTIFICATION EXIGEE depuis le 2026-09-06 (E-449, `f94c947`)
 *       — et cette route reste dans CETTE liste, parce que la garde vit dans
 *       le CONTROLEUR et non sur la route. `TableDesGardes` gele les gardes de
 *       ROUTE ; l'y inscrire dirait qu'un intergiciel la porte, c'est-a-dire
 *       une chose fausse dans le fichier meme qui existe pour dire le vrai.
 *       *La garde est attestee par `EffacementLibreServiceTest` (C1/C2), pas
 *       par ce releve.*
 *       LES DEUX CONTROLES NE PROTEGENT PAS DE LA MEME CHOSE : le nom a
 *       retaper est AFFICHE sur la page, donc il protege du geste ACCIDENTEL ;
 *       le code TOTP protege d'une session VOLEE. `eff_code_aide` le dit a
 *       l'ecran. *Deux controles ne font pas deux protections quand leurs
 *       objets different.*
 *       CAPACITE NEUVE, non portee : `legacy/profile.php` n'offre que
 *       l'export, alors que `legacy/lang/fr/terms.php:78` promet le droit
 *       a l'effacement. Le legacy annoncait ce droit sans l'implementer.
         *   profil/sessions/fermer                 ses propres sessions
     *   accueil/assistant/masquer              SA propre preference
     *   profil/donnees-personnelles            SES propres donnees — export
     *       RGPD art. 20, FIDELE au legacy qui l'ouvre a tout compte connecte
     *       des le role 1. L'identifiant vient de la SESSION, aucun parametre
     *       n'est offert : il n'y a pas d'objet a garder au-dela de
     *       l'authentification.
         *   documentation                          FIDELE au legacy, qui pose
         *       `checkAuth([1,2,3])` sans aucun `checkPermission` : son seul
         *       cloisonnement est un SEUIL DANS LA PAGE (`role >= 2` sur cinq
         *       sections). Poser `role:2` sur la route fermerait a un role 1 les
         *       43 sections que le legacy lui ouvre. La console d'API, elle,
         *       n'est PAS reprise — decision rendue, verifiee dans la vue.
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
            'GET documentation',
            'GET profil',
            'GET profil/donnees-personnelles',
            'POST accueil/assistant/masquer',
            'POST cgu',
            'POST profil/cle-ssh',
            'POST profil/courriel',
            'POST profil/effacement',
            'POST profil/mot-de-passe',
            'POST profil/sessions/fermer',
            'POST profil/step-up',
            'POST profil/step-up/revoquer',
        ], $sansRole, "Une route est ouverte a TOUT COMPTE CONNECTE sans qu'elle "
            . "figure dans ce gel, ou l'une a disparu.\n"
            . "CE ROUGE N'ACCUSE PERSONNE : il demande une RAISON ECRITE. Une "
            . "route du compte lui-meme (ses identifiants, ses sessions, son "
            . "ecran) en a une ; une route qui touche le PARC n'en a pas, et "
            . 'doit porter un `role:`.');
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

    /**
     * ⚠ L'ANGLE MORT DE `TableDesGardes`, GELE PLUTOT QUE DECLARE.
     *
     * Ce releve ne peut pas exprimer une garde qui vit dans un CONTROLEUR. Son
     * en-tete le dit maintenant — et une limitation qui n'est QUE dite se perime
     * en silence, ce qui est le defaut que ce depot demonte le plus souvent.
     *
     * Ce test gele donc les sites. Un SIXIEME fait rougir, et c'est le but :
     * une garde de controleur neuve doit etre inscrite dans l'en-tete, sans quoi
     * un lecteur du releve conclura qu'un geste n'est garde que par sa route.
     *
     * Le decompte porte sur le SITE QUI DECIDE, pas sur les mentions : la
     * definition de l'aide `ComptesController::exigeStepUp()` n'en est pas un, et
     * la compter donnerait un total qui ne correspond a aucun geste.
     */
    #[Test]
    public function les_gardes_de_CONTROLEUR_sont_recensees(): void
    {
        $sites = [];

        foreach (glob(base_path('app/Http/Controllers/*.php')) ?: [] as $chemin) {
            $lignes = file($chemin, FILE_IGNORE_NEW_LINES) ?: [];
            $dansBloc = false;

            foreach ($lignes as $numero => $ligne) {
                $nu = trim($ligne);

                // Depouiller par etat, et non par motif : ce fichier et ceux
                // qu'il lit PORTENT leurs demonstrations en commentaire.
                if (str_starts_with($nu, '/*')) {
                    $dansBloc = true;
                }
                if ($dansBloc) {
                    if (str_contains($nu, '*/')) {
                        $dansBloc = false;
                    }
                    continue;
                }
                if (str_starts_with($nu, '*') || str_starts_with($nu, '//')) {
                    continue;
                }

                if (preg_match('/!\s*\$this->stepUp->valide|\(\$refus = \$this->exigeStepUp/', $ligne) === 1) {
                    $sites[] = basename($chemin) . ':' . ($numero + 1);
                }
            }
        }

        sort($sites);

        // TEMOIN : l'enumeration a bien parcouru des fichiers. Une liste vide
        // satisferait toute attente d'absence, et rendrait ce gel vacant.
        $this->assertGreaterThan(30, count(glob(base_path('app/Http/Controllers/*.php')) ?: []),
            'le balayage ne trouve presque aucun controleur : la mesure ci-dessous '
            . "n'a pas eu lieu");

        $this->assertSame([
            'ComptesController.php:514',      // compte_supprimer
            'ComptesController.php:539',      // compte_anonymiser
            'PasserelleController.php:88',    // generique, action DERIVEE du chemin
            'PermissionsController.php:165',  // permission_definir
            'PortailController.php:196',      // profil_effacement (E-449)
        ], $sites,
            "Les gardes de step-up vivant dans un CONTROLEUR ont change.\n"
            . "`TableDesGardes` ne peut pas les exprimer : son en-tete les recense, "
            . "et il doit etre mis a jour DANS CE COMMIT.\n"
            . "Un simple decalage de lignes compte aussi — c'est le prix d'un gel "
            . "qui pointe l'endroit exact, et il oblige a relire le site.");
    }
}
