<?php

namespace Tests\Feature;

use App\Services\Comptes;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

/**
 * E-555 ③ — LE CHANGEMENT DE ROLE, second geste perdu a l'extinction.
 *
 * ══ CE QUI MANQUAIT ═══════════════════════════════════════════════════════
 *
 * `legacy/adm/includes/manage_roles.php:124-163` le portait. Apres l'archivage,
 * `users.role_id` n'etait plus ecrit que par DEUX `insert` — et il est LU par
 * 39 fichiers de `laravel/app`.
 *
 * **Promouvoir ou retrograder imposait donc de RECREER le compte**, donc de
 * perdre son historique, ses attributions de machines et ses permissions.
 *
 * ══ CINQ GARDES PORTEES, UNE SIXIEME AJOUTEE ══════════════════════════════
 *
 *   1. role >= 2                          `:31`  -> la ROUTE (`role:2`)
 *   2. le role cible EXISTE               `:131`
 *   3. un role 2 ne touche pas un role 3  `:148`
 *   4. un non-superadmin n'assigne qu'un role STRICTEMENT inferieur  `:154`
 *   5. pas sur soi-meme                   `:157`
 *   6. ⛔ pas le dernier superadmin ACTIF — ABSENTE DU LEGACY.
 *
 * **La 6 est de moi, et elle est nommee comme telle.** Le legacy protege le
 * dernier superadmin contre la SUSPENSION (`toggle_user.php:71`) et PAS contre
 * la RETROGRADATION, alors que le danger est identique : plus personne ne peut
 * administrer, et aucun chemin ne rouvre.
 *
 * ⚠ LA GARDE 1 EST `role:2` ET CE N'EST PAS UNE FAUTE. Le legacy pose
 * `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])`. Mettre `role:3` serait un
 * DURCISSEMENT silencieux — il retirerait a un administrateur une capacite
 * qu'il avait. Ce qui borne un role 2 sont les gardes 3 et 4, pas la route.
 *
 * ⚠ AUCUN COMPTE REEL, AUCUN HTTP : ce fichier mesure le SERVICE.
 */
class ChangementDeRoleTest extends TestCase
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
        Schema::create('roles', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name', 50);
        });
        foreach ([[1, 'user'], [2, 'admin'], [3, 'superadmin']] as [$id, $nom]) {
            DB::table('roles')->insert(['id' => $id, 'name' => $nom]);
        }

        $this->comptes = app(Comptes::class);
    }

    protected function tearDown(): void
    {
        Schema::dropIfExists('roles');
        Schema::dropIfExists('users');
        parent::tearDown();
    }

    private function pose(int $id, string $nom, int $role, int $actif = 1): void
    {
        DB::table('users')->insert([
            'id' => $id, 'name' => $nom, 'role_id' => $role, 'active' => $actif,
        ]);
    }

    private function role(int $id): int
    {
        return (int) DB::table('users')->where('id', $id)->value('role_id');
    }

    /* ═══ LE CAS BANAL ══════════════════════════════════════════════════════ */

    public function test_un_superadmin_promeut_un_user_en_admin(): void
    {
        $this->pose(1, 'chef', 3);
        $this->pose(9, 'jean', 1);

        $this->assertNull($this->comptes->definitRole(9, 2, 1, 3));
        $this->assertSame(2, $this->role(9));
    }

    public function test_un_superadmin_retrograde_un_admin_en_user(): void
    {
        $this->pose(1, 'chef', 3);
        $this->pose(9, 'jean', 2);

        $this->assertNull($this->comptes->definitRole(9, 1, 1, 3));
        $this->assertSame(1, $this->role(9));
    }

    public function test_le_geste_est_IDEMPOTENT(): void
    {
        $this->pose(1, 'chef', 3);
        $this->pose(9, 'jean', 1);

        $this->comptes->definitRole(9, 2, 1, 3);
        $this->comptes->definitRole(9, 2, 1, 3);
        $this->assertSame(2, $this->role(9));
    }

    /* ═══ LES SIX GARDES ════════════════════════════════════════════════════ */

    /** GARDE 5 — sans elle, on se promeut soi-meme. */
    public function test_garde5_on_ne_change_PAS_son_propre_role(): void
    {
        $this->pose(1, 'chef', 3);
        $this->pose(2, 'chef-bis', 3);

        $this->assertSame('comptes.err_auto_role',
            $this->comptes->definitRole(1, 1, 1, 3));
        $this->assertSame(3, $this->role(1));
    }

    /** GARDE 2 — un role qui n'existe pas dans la table `roles`. */
    public function test_garde2_un_role_inexistant_est_refuse(): void
    {
        $this->pose(1, 'chef', 3);
        $this->pose(9, 'jean', 1);

        $this->assertSame('comptes.err_role_inconnu',
            $this->comptes->definitRole(9, 42, 1, 3));
        $this->assertSame(1, $this->role(9), 'et rien ne doit avoir change');
    }

    /** GARDE 3 — un administrateur ne touche pas un superadministrateur. */
    public function test_garde3_un_role2_ne_touche_pas_un_role3(): void
    {
        $this->pose(1, 'chef', 3);
        $this->pose(5, 'admin', 2);

        $this->assertSame('comptes.err_role_superadmin_intouchable',
            $this->comptes->definitRole(1, 1, 5, 2));
        $this->assertSame(3, $this->role(1));
    }

    /**
     * GARDE 4 — un non-superadmin n'assigne qu'un role STRICTEMENT inferieur.
     *
     * Le legacy porte la trace de son propre defaut a `:154` : « Patch A01 :
     * avant, `>` autorisait l'egalite -> un admin pouvait promouvoir un user en
     * admin ». C'est l'egalite qui est testee ici, pas seulement le superieur.
     */
    public function test_garde4_un_role2_ne_peut_pas_promouvoir_en_role2(): void
    {
        $this->pose(5, 'admin', 2);
        $this->pose(9, 'jean', 1);

        $this->assertSame('comptes.err_role_trop_haut',
            $this->comptes->definitRole(9, 2, 5, 2),
            "l'EGALITE doit etre refusee, pas seulement le superieur");
        $this->assertSame(1, $this->role(9));
    }

    public function test_garde4_un_role2_ne_peut_pas_promouvoir_en_role3(): void
    {
        $this->pose(5, 'admin', 2);
        $this->pose(9, 'jean', 1);

        $this->assertSame('comptes.err_role_trop_haut',
            $this->comptes->definitRole(9, 3, 5, 2));
    }

    /** CONTRE-EPREUVE de la garde 4 : un role 2 peut quand meme assigner 1. */
    public function test_garde4_un_role2_peut_assigner_le_role_1(): void
    {
        $this->pose(5, 'admin', 2);
        $this->pose(9, 'jean', 2);

        $this->assertNull($this->comptes->definitRole(9, 1, 5, 2),
            'sans ce cas, une garde 4 qui refuse TOUT passerait les deux precedents');
        $this->assertSame(1, $this->role(9));
    }

    /** CONTRE-EPREUVE de la garde 4 : un superadmin reste libre. */
    public function test_garde4_un_superadmin_peut_assigner_le_role_3(): void
    {
        $this->pose(1, 'chef', 3);
        $this->pose(9, 'jean', 1);

        $this->assertNull($this->comptes->definitRole(9, 3, 1, 3));
        $this->assertSame(3, $this->role(9));
    }

    /**
     * ⛔ GARDE 6 — LA MIENNE, ABSENTE DU LEGACY.
     *
     * Retrograder le seul superadministrateur actif verrouille l'administration
     * pour tout le monde, sans chemin de retour.
     */
    public function test_garde6_on_ne_retrograde_PAS_le_dernier_superadmin_actif(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(2, 'ancien-chef', 3, 0);   // role 3 mais INACTIF
        $this->pose(9, 'jean', 1);

        $this->assertSame('comptes.err_dernier_superadmin',
            $this->comptes->definitRole(1, 1, 9, 3),
            'un role 3 inactif ne remplace personne');
        $this->assertSame(3, $this->role(1));
    }

    public function test_garde6_mais_on_retrograde_s_il_en_reste_un_AUTRE_actif(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(2, 'chef-bis', 3, 1);
        $this->pose(9, 'jean', 1);

        $this->assertNull($this->comptes->definitRole(1, 1, 9, 3));
        $this->assertSame(1, $this->role(1));
        $this->assertSame(3, $this->role(2), "l'autre superadmin ne bouge pas");
    }

    /**
     * CONTRE-EPREUVE de la garde 6 : elle ne joue QUE sur une RETROGRADATION.
     *
     * Sans ce cas, une garde qui refuserait aussi de PROMOUVOIR le dernier
     * superadmin — un no-op — passerait les precedents.
     */
    public function test_garde6_ne_bloque_pas_un_role3_qui_RESTE_role3(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(9, 'jean', 1);

        $this->assertNull($this->comptes->definitRole(1, 3, 9, 3),
            'poser 3 sur un role 3 est un no-op, pas une retrogradation');
        $this->assertSame(3, $this->role(1));
    }

    public function test_un_compte_inconnu_rend_err_inconnu(): void
    {
        $this->pose(1, 'chef', 3);

        $this->assertSame('comptes.err_inconnu',
            $this->comptes->definitRole(4242, 1, 1, 3));
    }

    /**
     * TEMOIN DE L'INSTRUMENT : les deux tables sont bien lues.
     *
     * Sans lui, tous les tests passeraient sur une base vide — `roles` vide
     * rendrait `err_role_inconnu` partout, et « la garde refuse » serait
     * indiscernable de « rien n'existe ».
     */
    public function test_temoin_les_deux_tables_sont_lues(): void
    {
        $this->pose(1, 'chef', 3);
        $this->pose(9, 'jean', 1);

        $this->assertSame(3, (int) DB::table('roles')->count(), 'les 3 roles doivent etre poses');
        $this->assertSame(2, (int) DB::table('users')->count());
        $this->assertNull($this->comptes->definitRole(9, 2, 1, 3),
            'et le geste doit aboutir sur un cas legitime');
    }

    public function test_les_clefs_d_erreur_existent_en_fr_ET_en_en(): void
    {
        $attendues = ['role_change', 'role_titre', 'err_auto_role', 'err_role_inconnu',
                      'err_role_superadmin_intouchable', 'err_role_trop_haut',
                      'err_role_requis'];
        foreach (['fr', 'en'] as $langue) {
            $catalogue = require base_path("lang/{$langue}/comptes.php");
            foreach ($attendues as $clef) {
                $this->assertArrayHasKey($clef, $catalogue,
                    "clef `{$clef}` absente du catalogue {$langue}");
                $this->assertNotSame('', trim((string) $catalogue[$clef]));
            }
        }
    }
}
