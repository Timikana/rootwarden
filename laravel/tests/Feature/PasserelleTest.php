<?php

namespace Tests\Feature;

use App\Services\StepUp;
use Tests\Doubles\StepUpFictif;
use App\Support\RoutesBackend;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * LA PASSERELLE — la seule route du portail qui garde DANS son contrôleur.
 *
 * Les 85 autres routes portent leurs gardes sur leur déclaration, et
 * `InventaireDesGardesTest` les relève. Celle-ci relaie **environ 200 routes du
 * backend** derrière une seule déclaration qui ne porte que
 * `session.authentifiee` : ses quatre contrôles vivent dans le code, et rien ne
 * les mesurait côté PHP.
 *
 * ── LA PROPRIÉTÉ CENTRALE SE MESURE AU RÉSEAU, PAS AU STATUT ─────────────────
 *
 * Un 403 rendu par la passerelle ne prouve pas que la requête n'est pas partie.
 * Elle pourrait très bien avoir été transmise, avoir échoué en aval, et le refus
 * arriver quand même — l'appelant ne verrait aucune différence, et le backend
 * aurait travaillé.
 *
 * Chaque refus est donc mesuré DEUX FOIS : le statut rendu, et
 * `Http::assertNothingSent()`. C'est la même règle que « mesurer l'EFFET d'une
 * garde, pas sa FORME » : ce qui compte n'est pas le message, c'est qu'aucun
 * octet ne soit sorti.
 *
 * ── HERMÉTIQUE ───────────────────────────────────────────────────────────────
 *
 * `Http::fake()` intercepte tout : aucun backend n'est joint, aucune machine
 * n'est touchée. Les chemins employés sont volontairement inoffensifs, et
 * `srv-zabbix` n'est nommée nulle part — une ligne de fixture qui nomme la
 * production finit par être recopiée dans un test qui, lui, joindrait quelque
 * chose.
 */
class PasserelleTest extends TestCase
{
    private const CLE = 'CLE-API-DE-TEST-JAMAIS-REELLE';

    /**
     * Ce que le backend factice répondra. Modifiable EN COURS DE TEST.
     *
     * `Http::fake()` **fusionne** les stubs au lieu de les remplacer : un second
     * appel dans un test ne prend donc pas la main sur celui de `setUp`, et la
     * réponse d'origine continue de gagner. Mesuré — deux tests annonçaient un
     * 404 et recevaient un 200. La parade est un stub UNIQUE qui lit cette
     * propriété à chaque appel.
     */
    private \Closure $reponseBackend;

    protected function setUp(): void
    {
        parent::setUp();

        config([
            'rootwarden.backend.url'     => 'https://backend-factice.invalide',
            'rootwarden.backend.cle_api' => self::CLE,
        ]);

        $this->reponseBackend = fn () => Http::response(['success' => true, 'donnee' => 'ok'], 200);

        Http::preventStrayRequests();
        Http::fake(['*' => fn ($requete) => ($this->reponseBackend)($requete)]);
    }

    private function appelle(string $chemin, string $methode = 'GET', array $corps = [])
    {
        return $this->call($methode, '/api/gateway' . $chemin, [], [], [], [], $corps ? json_encode($corps) : null);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Traversée de chemin
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Les trois formes refusées, et une quatrième qui ne l'est pas.
     *
     * `//` est dans la liste, et il faut dire pourquoi : un chemin à double
     * barre a déjà traversé un garde de ce chantier — `//exemple.com` passe tout
     * contrôle fondé sur une classe de caractères, parce qu'il n'a pas de
     * schéma. Le refuser ici est un durcissement hérité de cette mesure.
     */
    #[Test]
    #[DataProvider('cheminsDeTraversee')]
    public function une_traversee_de_chemin_est_refusee_sans_rien_emettre(string $chemin): void
    {
        $reponse = $this->connecte(3)->appelle($chemin);

        $reponse->assertStatus(400);
        Http::assertNothingSent();
    }

    public static function cheminsDeTraversee(): iterable
    {
        yield 'remontee'         => ['/../secret'];
        yield 'remontee enfouie' => ['/list_machines/../../etc/passwd'];
    }

    /**
     * DEUX DES TROIS PROTECTIONS DU CONTRÔLEUR SONT INATTEIGNABLES PAR LE WEB.
     *
     * Mesuré, pas déduit — et c'est le genre de fait qu'une relecture ne donne
     * jamais, parce que le code du contrôleur est parfaitement correct :
     *
     *   `//list_machines`  le cadre NORMALISE la double barre avant le routage.
     *                      Le contrôleur reçoit `/list_machines`, donc il
     *                      TRANSMET — le test de `str_contains('//')` ne peut
     *                      jamais être vrai sur une requête HTTP réelle ;
     *   `…\..\secret`      le cadre REFUSE l'anti-slash lui-même, avant le
     *                      contrôleur (`BadRequestException`). Le refus a bien
     *                      lieu, mais ce n'est pas celui qu'on croit lire.
     *
     * **Ce n'est pas un trou** : la première forme est neutralisée par la
     * normalisation, la seconde est refusée plus tôt. C'est une garde présente
     * et sans objet — la même famille que `@require_machine_access`, inerte sur
     * 57 routes du backend, et que les cinq en-têtes qui annoncent un accès plus
     * strict que leur code.
     *
     * Le dire évite qu'on la croie protectrice, et évite surtout qu'on la
     * retire un jour en la prenant pour du code mort : elle protégerait encore
     * un appelant qui n'est pas un navigateur.
     */
    #[Test]
    public function la_double_barre_est_normalisee_par_le_CADRE_avant_le_controleur(): void
    {
        $reponse = $this->connecte(3)->appelle('//list_machines');

        $reponse->assertOk();
        Http::assertSent(fn ($r) => str_ends_with($r->url(), '/list_machines'));
    }

    #[Test]
    public function un_chemin_vide_est_refuse(): void
    {
        $reponse = $this->connecte(3)->call('GET', '/api/gateway');

        $reponse->assertStatus(400);
        Http::assertNothingSent();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Liste blanche — fail-closed
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    public function une_route_hors_liste_blanche_est_refusee_sans_rien_emettre(): void
    {
        $reponse = $this->connecte(3)->appelle('/route_qui_n_existe_pas');

        $reponse->assertStatus(403);
        Http::assertNothingSent();
    }

    /**
     * LA DIFFÉRENCE AVEC LE LEGACY, ET ELLE SE MESURE.
     *
     * Le legacy compare par DÉBUT DE CHAÎNE : `/search` y autorise `/searchall`,
     * et toute route Python future dont le nom commence par un préfixe autorisé
     * devient publique sans que personne ne l'ait décidé. Ce portage compare par
     * SEGMENT.
     *
     * Sans cette assertion, le resserrement pourrait être défait par une
     * simplification qui « ne change rien » — et la mesure serait perdue.
     */
    #[Test]
    #[DataProvider('cheminsVoisins')]
    public function la_comparaison_se_fait_par_segment_et_non_par_prefixe(string $chemin, bool $accepte): void
    {
        $reponse = $this->connecte(3)->appelle($chemin);

        if ($accepte) {
            $reponse->assertOk();
            Http::assertSentCount(1);
        } else {
            $reponse->assertStatus(403);
            Http::assertNothingSent();
        }
    }

    public static function cheminsVoisins(): iterable
    {
        yield '/search exact'        => ['/search', true];
        yield '/search/xyz'          => ['/search/xyz', true];
        yield '/searchall REFUSE'    => ['/searchall', false];
        yield '/logs exact'          => ['/logs', true];
        yield '/logsecret REFUSE'    => ['/logsecret', false];
        yield '/cve_ (racine)'       => ['/cve_scan', true];
        yield '/fail2ban/ (espace)'  => ['/fail2ban/status', true];
        yield '/fail2banXYZ REFUSE'  => ['/fail2banXYZ', false];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Réservé à l'administration — défense en profondeur
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    public function un_role_1_ne_peut_pas_atteindre_une_route_reservee(): void
    {
        // `/admin/` est dans les deux listes : blanche ET réservée. Le rôle 1
        // franchit donc la liste blanche et doit être arrêté par la seconde.
        $reponse = $this->connecte(1)->appelle('/admin/quelque_chose');

        $reponse->assertStatus(403);
        Http::assertNothingSent();
    }

    #[Test]
    public function un_role_2_atteint_la_meme_route(): void
    {
        // L'AUTRE MOITIÉ. Une garde qui refuse tout le monde n'est pas une garde,
        // et sans cette assertion un durcissement excessif passerait inaperçu.
        $reponse = $this->connecte(2)->appelle('/admin/quelque_chose');

        $reponse->assertOk();
        Http::assertSentCount(1);
    }

    #[Test]
    public function la_reserve_administration_couvre_supervision_que_le_legacy_laissait_ouverte(): void
    {
        /*
         * `/supervision/` est ABSENT de `ADMIN_ONLY_PREFIXES` côté legacy, et la
         * liste de ce portage en était le relevé fidèle — elle recopiait donc le
         * trou. L'ajouter est une divergence VOULUE, et une divergence non
         * déclarée se relit comme une erreur puis se « corrige » à l'envers.
         *
         * Cette assertion est ce qui l'empêche : elle dit que le refus opposé au
         * rôle 1 est délibéré.
         */
        $reponse = $this->connecte(1)->appelle('/supervision/profiles');

        $reponse->assertStatus(403);
        Http::assertNothingSent();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. Re-authentification ponctuelle
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    public function une_route_root_sans_marque_est_refusee_sans_rien_emettre(): void
    {
        $reponse = $this->connecte(3)->appelle('/policy/sudo/deploy', 'POST', ['machine_id' => 4242]);

        $reponse->assertStatus(403);
        $reponse->assertJson(['step_up_required' => true, 'action' => 'policy_sudo_deploy']);

        // LA propriété. Un déploiement sudo accordé sans second contrôle donne
        // root sur la machine cible : le refus ne vaut que si rien n'est parti.
        Http::assertNothingSent();
    }

    #[Test]
    public function le_nom_de_l_action_est_PROPRE_A_LA_ROUTE(): void
    {
        /*
         * Ce qui distingue ce portage du legacy. Là-bas, les trois routes root
         * partagent `policy_action`, si bien qu'un step-up consenti pour ANNULER
         * une politique autorise un DÉPLOIEMENT sudo pendant quinze minutes.
         *
         * On mesure que les trois noms DIFFÈRENT. Une assertion sur un seul nom
         * ne dirait rien de la fusion — c'est leur distinction qui est la
         * propriété.
         */
        $noms = [];

        foreach (['/policy/sudo/deploy', '/policy/sudo/remove', '/policy/rollback'] as $chemin) {
            $reponse = $this->connecte(3)->appelle($chemin, 'POST');
            $noms[]  = $reponse->json('action');
        }

        $this->assertSame(['policy_sudo_deploy', 'policy_sudo_remove', 'policy_rollback'], $noms);
        $this->assertCount(3, array_unique($noms), 'les trois actions doivent être distinctes');
    }

    /** Installe un `StepUp` qui accorde exactement ces actions, et rien d'autre. */
    private function stepUpAccordant(array $actions): StepUpFictif
    {
        $double = new StepUpFictif($actions);
        $this->instance(StepUp::class, $double);

        return $double;
    }

    #[Test]
    public function une_marque_fraiche_laisse_passer_la_route_qu_elle_NOMME(): void
    {
        $stepUp = $this->stepUpAccordant(['policy_sudo_deploy']);

        $this->connecte(3)->appelle('/policy/sudo/deploy', 'POST')->assertOk();

        Http::assertSentCount(1);
        // La passerelle a bien interrogé, et sur le NOM de cette route-là.
        $this->assertSame(['policy_sudo_deploy'], $stepUp->demandes);
    }

    #[Test]
    public function une_marque_pour_UNE_action_n_ouvre_pas_les_AUTRES(): void
    {
        // Le défaut du legacy, mesuré à l'envers : la marque est accordée pour
        // l'annulation, et le déploiement doit rester fermé. Là-bas les trois
        // routes root partagent `policy_action`, donc celle-ci ouvrirait.
        $stepUp  = $this->stepUpAccordant(['policy_rollback']);
        $reponse = $this->connecte(3)->appelle('/policy/sudo/deploy', 'POST');

        $reponse->assertStatus(403);
        $reponse->assertJson(['action' => 'policy_sudo_deploy']);
        Http::assertNothingSent();
        $this->assertSame(['policy_sudo_deploy'], $stepUp->demandes);
    }

    #[Test]
    public function le_refus_ne_dit_RIEN_de_plus_que_l_action_a_faire_valider(): void
    {
        // Ni la durée restante, ni l'état des autres actions : un refus qui
        // renseigne est un refus qui aide à contourner.
        $reponse = $this->connecte(3)->appelle('/policy/rollback', 'POST');

        $donnees = $reponse->json();
        $this->assertSame(
            ['success', 'message', 'step_up_required', 'action'],
            array_keys($donnees),
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 7. Transmission
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    public function l_identite_est_transmise_au_backend_et_relue_en_base(): void
    {
        $this->connecte(2, ['can_scan_cve'])->appelle('/list_machines')->assertOk();

        Http::assertSent(function ($requete) {
            return $requete->hasHeader('X-API-KEY', self::CLE)
                && $requete->hasHeader('X-User-ID', (string) self::COMPTE)
                && $requete->hasHeader('X-User-Role', '2')
                && str_contains($requete->header('X-User-Permissions')[0], 'can_scan_cve');
        });

        // Les permissions viennent des DROITS, pas de la session : une
        // permission révoquée cesse d'agir à la requête suivante, sans attendre
        // une reconnexion. Le double a donc dû être interrogé.
        $this->assertSame([self::COMPTE], $this->droits->consultations);
    }

    #[Test]
    public function la_cle_d_api_ne_ressort_JAMAIS_vers_le_navigateur(): void
    {
        $reponse = $this->connecte(3)->appelle('/list_machines');

        $this->assertStringNotContainsString(self::CLE, $reponse->getContent());

        foreach ($reponse->headers->all() as $nom => $valeurs) {
            foreach ($valeurs as $valeur) {
                $this->assertStringNotContainsString(self::CLE, (string) $valeur,
                    "la clé d'API apparaît dans l'en-tête $nom");
            }
        }
    }

    #[Test]
    public function le_statut_du_backend_est_PROPAGE(): void
    {
        $this->reponseBackend = fn () => Http::response(['success' => false, 'message' => 'Machine introuvable'], 404);

        // Un 404 qui deviendrait 200 ferait croire au frontend que l'appel a
        // réussi — c'est la classe de défaut que trois correctifs viennent de
        // fermer côté backend, et elle se referme aussi ici.
        $this->connecte(3)->appelle('/list_machines')->assertStatus(404);
    }

    #[Test]
    public function un_backend_injoignable_rend_502_et_non_une_erreur_de_serveur(): void
    {
        $this->reponseBackend = fn () => throw new \RuntimeException('connexion refusee');

        $reponse = $this->connecte(3)->appelle('/list_machines');

        $reponse->assertStatus(502);
        $reponse->assertJson(['success' => false]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // L'ordre des contrôles, mesuré plutôt que lu
    // ─────────────────────────────────────────────────────────────────────────

    #[Test]
    public function la_traversee_est_refusee_AVANT_la_liste_blanche(): void
    {
        /*
         * L'en-tête du contrôleur annonce un ordre : traversée, liste blanche,
         * réserve administration, step-up. Un commentaire n'est pas une
         * propriété — ce chantier compte cinq en-têtes qui annoncent un accès
         * plus strict que leur code.
         *
         * Le chemin ci-dessous est À LA FOIS une traversée ET hors liste
         * blanche. Le statut dit lequel des deux contrôles a parlé : 400 pour la
         * traversée, 403 pour la liste. C'est la seule façon de mesurer un ORDRE
         * sans lire le code.
         */
        $reponse = $this->connecte(3)->appelle('/inconnu/../autre');

        $reponse->assertStatus(400);
        Http::assertNothingSent();
    }

    #[Test]
    public function la_reserve_administration_est_evaluee_AVANT_le_step_up(): void
    {
        // `/policy/` est réservé à l'administration ET porte un step-up. Un rôle
        // 1 doit être arrêté par la réserve — donc sans `step_up_required`, qui
        // lui indiquerait quoi faire valider pour avancer.
        $reponse = $this->connecte(1)->appelle('/policy/sudo/deploy', 'POST');

        $reponse->assertStatus(403);
        $this->assertArrayNotHasKey('step_up_required', (array) $reponse->json());
        Http::assertNothingSent();
    }

    #[Test]
    public function le_relais_en_flux_ne_concerne_que_les_chemins_releves(): void
    {
        // Un réglage, pas une garde — mais un réglage qui décide d'un délai de
        // 900 s au lieu de 120 s. `estUnFlux` est mesurée ici sur sa forme
        // exacte : la comparaison se fait sur le chemin sans barre finale.
        $this->assertTrue(RoutesBackend::estUnFlux('/update'));
        $this->assertTrue(RoutesBackend::estUnFlux('/update/'));
        $this->assertTrue(RoutesBackend::estUnFlux('/supervision/zabbix/deploy'));
        $this->assertFalse(RoutesBackend::estUnFlux('/update-logs'));
        $this->assertFalse(RoutesBackend::estUnFlux('/list_machines'));
    }
}
