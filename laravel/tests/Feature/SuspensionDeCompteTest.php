<?php

namespace Tests\Feature;

use App\Services\Comptes;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

/**
 * E-555 ① — LA SUSPENSION D'UN COMPTE, GESTE PERDU A L'EXTINCTION DU LEGACY.
 *
 * ══ CE QUI MANQUAIT, ET COMMENT ON L'A SU ═════════════════════════════════
 *
 * `legacy/adm/api/toggle_user.php` portait ce geste. Apres l'archivage du
 * legacy, `users.active` n'etait plus ecrit que par DEUX `insert` (la creation)
 * et par UNE `update` — celle de l'ANONYMISATION, irreversible.
 *
 * **Suspendre un compte le temps d'un preavis imposait donc de le DETRUIRE.**
 *
 * Trouve par `gestion-ssh-key-5f` le 2026-09-09, avec le grain qui convient :
 * le couple **(verbe, colonnes)** et non la table. Un releve par TABLE repondait
 * « `users` a six ecrivains vivants » et ne voyait rien.
 *
 *   > Un ecrivain vivant sur la meme table peut porter UN geste la ou l'archive
 *   > en portait SIX. Arite, pas presence.
 *
 * ══ ET `active` DECIDE, ce n'est pas un drapeau d'affichage ════════════════
 *
 * `backend/configure_servers.py:873` ne construit `allowed_usernames` qu'avec
 * `user['active']`. Suspendre retire donc reellement l'acces aux machines au
 * prochain deploiement. C'est ce qui rend le geste utile — et ce qui rend son
 * absence couteuse.
 *
 * ══ LES TROIS GARDES DU LEGACY SONT REPRISES ══════════════════════════════
 *
 *   1. superadministrateur seulement   `toggle_user.php:26` -> la ROUTE (role:3)
 *   2. pas sur soi-meme                `:49`  -> teste ici
 *   3. pas le dernier superadmin actif `:71`  -> teste ici, et c'est LA garde
 *      qui empeche de verrouiller le portail pour tout le monde
 *
 * ══ UN BOOLEEN EXPLICITE, PAS LA BASCULE ══════════════════════════════════
 *
 * `toggle_user.php:64-68` LISAIT `active` puis l'inversait. Deux appels
 * concurrents s'annulent, et un rejeu ne rend pas le meme etat. L'idempotence
 * est donc une propriete de ce portage, pas du legacy, et elle est TESTEE.
 *
 * ⚠ AUCUN COMPTE REEL, AUCUN HTTP : ce fichier mesure le SERVICE. La garde 1
 * vit dans la route et est mesuree par `GardesDeRoutesTest`.
 */
class SuspensionDeCompteTest extends TestCase
{
    private Comptes $comptes;

    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('users', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name', 255);
            $table->integer('role_id')->default(1);
            $table->tinyInteger('active')->default(1);
        });

        $this->comptes = app(Comptes::class);
    }

    protected function tearDown(): void
    {
        Schema::dropIfExists('users');
        parent::tearDown();
    }

    private function pose(int $id, string $nom, int $role, int $actif): void
    {
        DB::table('users')->insert([
            'id' => $id, 'name' => $nom, 'role_id' => $role, 'active' => $actif,
        ]);
    }

    private function actif(int $id): int
    {
        return (int) DB::table('users')->where('id', $id)->value('active');
    }

    /* ═══ LE CAS BANAL, D'ABORD ═════════════════════════════════════════════ */

    public function test_un_superadmin_suspend_un_compte_ordinaire(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(2, 'chef-bis', 3, 1);   // pour que la garde 3 ne morde pas
        $this->pose(9, 'jean', 1, 1);

        $this->assertNull($this->comptes->definitActivite(9, false, 1));
        $this->assertSame(0, $this->actif(9), 'le compte devait etre suspendu');
    }

    public function test_et_le_reactive(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(9, 'jean', 1, 0);

        $this->assertNull($this->comptes->definitActivite(9, true, 1));
        $this->assertSame(1, $this->actif(9));
    }

    /**
     * L'IDEMPOTENCE — la propriete que la bascule du legacy n'avait pas.
     *
     * Deux appels au meme etat rendent le meme etat. Avec `toggle_user.php`,
     * deux appels s'annulaient.
     */
    public function test_le_geste_est_IDEMPOTENT(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(9, 'jean', 1, 1);

        $this->comptes->definitActivite(9, false, 1);
        $this->comptes->definitActivite(9, false, 1);
        $this->assertSame(0, $this->actif(9), 'deux suspensions ne doivent pas reactiver');

        $this->comptes->definitActivite(9, true, 1);
        $this->comptes->definitActivite(9, true, 1);
        $this->assertSame(1, $this->actif(9));
    }

    /* ═══ LES GARDES ════════════════════════════════════════════════════════ */

    public function test_on_ne_se_suspend_PAS_soi_meme(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(2, 'chef-bis', 3, 1);

        $this->assertSame(
            'comptes.err_auto_activite',
            $this->comptes->definitActivite(1, false, 1),
            'sans cette garde, un superadmin se ferme la porte et personne ne la rouvre'
        );
        $this->assertSame(1, $this->actif(1), 'et rien ne doit avoir change');
    }

    /**
     * ⛔ LA GARDE DECISIVE : le dernier superadministrateur ACTIF.
     *
     * Sans elle, suspendre le seul superadmin restant verrouille le portail
     * pour tout le monde, sans chemin de retour.
     */
    public function test_on_ne_suspend_PAS_le_dernier_superadmin_actif(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(2, 'ancien-chef', 3, 0);   // role 3 mais INACTIF : ne compte pas
        $this->pose(9, 'jean', 1, 1);

        $this->assertSame(
            'comptes.err_dernier_superadmin',
            $this->comptes->definitActivite(1, false, 9),
            'un role 3 inactif ne doit pas compter comme un remplacant'
        );
        $this->assertSame(1, $this->actif(1));
    }

    public function test_mais_on_suspend_un_superadmin_s_il_en_reste_un_AUTRE_actif(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(2, 'chef-bis', 3, 1);
        $this->pose(9, 'jean', 1, 1);

        $this->assertNull($this->comptes->definitActivite(1, false, 9));
        $this->assertSame(0, $this->actif(1));
        $this->assertSame(1, $this->actif(2), 'le second superadmin reste actif');
    }

    /**
     * CONTRE-EPREUVE DE LA GARDE 3 : elle ne joue QU'A la desactivation.
     *
     * Sans ce test, une garde qui refuserait aussi la REACTIVATION passerait
     * les precedents — et rendrait le dernier superadmin inactif definitivement
     * inactivable.
     */
    public function test_la_garde_du_dernier_superadmin_ne_bloque_PAS_la_reactivation(): void
    {
        $this->pose(1, 'chef', 3, 0);   // le seul role 3, INACTIF
        $this->pose(9, 'jean', 1, 1);

        $this->assertNull(
            $this->comptes->definitActivite(1, true, 9),
            'reactiver le dernier superadmin doit rester possible'
        );
        $this->assertSame(1, $this->actif(1));
    }

    public function test_un_compte_inconnu_rend_err_inconnu(): void
    {
        $this->pose(1, 'chef', 3, 1);

        $this->assertSame(
            'comptes.err_inconnu',
            $this->comptes->definitActivite(4242, false, 1)
        );
    }

    /**
     * TEMOIN DE L'INSTRUMENT : la table est bien lue.
     *
     * Sans lui, tous les tests ci-dessus passeraient sur une base vide en
     * rendant `err_inconnu` — et « la garde refuse » serait indiscernable de
     * « rien n'existe ».
     */
    public function test_temoin_la_table_est_bien_lue(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(2, 'chef-bis', 3, 1);
        $this->pose(9, 'jean', 1, 1);

        $this->assertSame(3, (int) DB::table('users')->count());
        $this->assertSame(1, $this->actif(9), 'la valeur posee doit se relire');
        $this->assertNull($this->comptes->definitActivite(9, false, 1),
            'et le geste doit aboutir sur un cas legitime');
    }

    /**
     * GARDE SUR LA FORME : les clefs d'erreur EXISTENT dans les deux langues.
     *
     * Une clef absente rend son propre nom a l'ecran. Le test ne verifie pas la
     * traduction : il verifie que les deux catalogues portent la MEME clef.
     */
    public function test_les_clefs_d_erreur_existent_en_fr_ET_en_en(): void
    {
        $attendues = ['active', 'suspendu', 'err_auto_activite',
                      'err_dernier_superadmin', 'err_actif_requis'];
        foreach (['fr', 'en'] as $langue) {
            $catalogue = require base_path("lang/{$langue}/comptes.php");
            foreach ($attendues as $clef) {
                $this->assertArrayHasKey($clef, $catalogue,
                    "clef `{$clef}` absente du catalogue {$langue}");
                $this->assertNotSame('', trim((string) $catalogue[$clef]),
                    "clef `{$clef}` vide en {$langue}");
            }
        }
    }
}
