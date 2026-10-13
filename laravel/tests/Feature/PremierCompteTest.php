<?php

namespace Tests\Feature;

use App\Console\Commands\PremierCompte;
use App\Services\Comptes;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * `rootwarden:premier-compte` — audit du 2026-10-13, H-5.
 *
 * Une installation neuve n'avait AUCUN chemin vers un premier compte : le seul
 * créateur (`legacy/_deprecated/php/install.sh`) est parti avec l'archivage.
 * Ces tests portent les deux faces : elle amorce une base vide, et elle est
 * INOFFENSIVE sur une installation en service.
 */
class PremierCompteTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Les seules colonnes NOT NULL sans défaut du vrai schéma sont `name` et
        // `password` (`mysql/init.sql`) ; les autres sont celles que la commande écrit.
        Schema::create('users', function (Blueprint $t) {
            $t->increments('id');
            $t->string('name', 255)->unique();
            $t->string('password', 512);
            $t->integer('role_id')->default(1);
            $t->boolean('active')->default(true);
            $t->boolean('sudo')->default(false);
            $t->boolean('force_password_change')->default(false);
            $t->string('email')->nullable();
        });
        Schema::create('user_logs', function (Blueprint $t) {
            $t->increments('id');
            $t->integer('user_id');
            $t->string('action', 255);
            $t->dateTime('created_at')->nullable();
            $t->string('prev_hash', 64)->nullable();
            $t->string('self_hash', 64)->nullable();
        });
    }

    private function lance(string ...$args): array
    {
        $code = Artisan::call('rootwarden:premier-compte', $args === [] ? [] : ['nom' => $args[0]]);

        return [$code, Artisan::output()];
    }

    #[Test]
    public function sur_une_base_vide_elle_cree_un_superadmin_utilisable(): void
    {
        [$code, $sortie] = $this->lance();

        $this->assertSame(0, $code, $sortie);
        $u = DB::table('users')->where('name', 'superadmin')->first();
        $this->assertNotNull($u, 'aucun compte cree');
        $this->assertSame(3, (int) $u->role_id);
        $this->assertSame(1, (int) $u->active);
        $this->assertSame(1, (int) $u->force_password_change, 'le mot de passe affiche doit etre change');

        // Le mot de passe AFFICHE ouvre bien le compte, et respecte la politique.
        $this->assertSame(1, preg_match('/Mot de passe initial : (\S+)/', $sortie, $m), $sortie);
        $this->assertTrue(password_verify($m[1], $u->password), 'le mot de passe affiche n ouvre pas le compte');
        $this->assertNull(app(Comptes::class)->verifieComplexite($m[1]), 'mot de passe hors politique');

        // Le geste est trace et scelle dans le journal d'audit.
        $trace = DB::table('user_logs')->where('user_id', $u->id)->first();
        $this->assertNotNull($trace, 'aucune trace au journal d audit');
        $this->assertNotEmpty($trace->self_hash, 'trace non scellee');
    }

    #[Test]
    public function elle_refuse_des_qu_un_superadmin_actif_existe(): void
    {
        DB::table('users')->insert(['name' => 'chef', 'password' => 'x', 'role_id' => 3, 'active' => 1]);

        [$code, $sortie] = $this->lance('autre');

        $this->assertSame(1, $code);
        $this->assertStringContainsString('Refuse', $sortie);
        $this->assertSame(1, DB::table('users')->count(), 'un compte a ete cree malgre un superadmin actif');
        $this->assertStringNotContainsString('Mot de passe initial', $sortie);
    }

    #[Test]
    public function un_superadmin_inactif_ne_bloque_pas_l_amorcage(): void
    {
        // Une base dont le seul superadmin est désactivé est elle aussi sans accès.
        DB::table('users')->insert(['name' => 'ancien', 'password' => 'x', 'role_id' => 3, 'active' => 0]);

        [$code] = $this->lance('relance');

        $this->assertSame(0, $code);
        $this->assertTrue(DB::table('users')->where('name', 'relance')->where('role_id', 3)->exists());
    }

    #[Test]
    public function elle_refuse_un_nom_deja_pris_ou_invalide(): void
    {
        DB::table('users')->insert(['name' => 'pris', 'password' => 'x', 'role_id' => 1, 'active' => 1]);

        [$codePris] = $this->lance('pris');
        [$codeInvalide] = $this->lance("a'; DROP TABLE users; --");

        $this->assertSame(1, $codePris);
        $this->assertSame(2, $codeInvalide, 'un identifiant invalide doit etre refuse avant toute ecriture');
        $this->assertSame(1, DB::table('users')->count());
    }

    #[Test]
    public function le_compte_factice_d_init_sql_recoit_un_vrai_mot_de_passe(): void
    {
        // Exactement la ligne de `mysql/init.sql:229-230`.
        DB::table('users')->insert(['name' => 'superadmin', 'password' => PremierCompte::FACTICE,
                                    'role_id' => 3, 'active' => 1, 'sudo' => 1]);

        [$code, $sortie] = $this->lance();

        $this->assertSame(0, $code, $sortie);
        $this->assertSame(1, DB::table('users')->count(), 'le compte factice doit etre REPRIS, pas double');
        $u = DB::table('users')->where('name', 'superadmin')->first();
        $this->assertNotSame(PremierCompte::FACTICE, $u->password);
        $this->assertSame(1, preg_match('/Mot de passe initial : (\S+)/', $sortie, $m), $sortie);
        $this->assertTrue(password_verify($m[1], $u->password), 'le compte factice reste inutilisable');
        $this->assertSame(1, (int) $u->force_password_change);
        $this->assertSame(1, (int) $u->sudo, 'le sudo pose par init.sql ne doit pas etre retire');
    }

    #[Test]
    public function un_compte_factice_ne_compte_pas_comme_un_superadmin_utilisable(): void
    {
        // Sinon la commande refuserait precisement dans le cas pour lequel elle existe.
        DB::table('users')->insert(['name' => 'superadmin', 'password' => PremierCompte::FACTICE,
                                    'role_id' => 3, 'active' => 1]);

        [$code] = $this->lance('premier');

        $this->assertSame(0, $code);
        $this->assertTrue(DB::table('users')->where('name', 'premier')->where('role_id', 3)->exists());
    }

    #[Test]
    public function un_superadmin_utilisable_bloque_meme_la_reprise_du_factice(): void
    {
        DB::table('users')->insert(['name' => 'superadmin', 'password' => PremierCompte::FACTICE,
                                    'role_id' => 3, 'active' => 1]);
        DB::table('users')->insert(['name' => 'chef', 'password' => password_hash('x', PASSWORD_BCRYPT),
                                    'role_id' => 3, 'active' => 1]);

        [$code] = $this->lance();

        $this->assertSame(1, $code);
        $this->assertSame(PremierCompte::FACTICE,
            DB::table('users')->where('name', 'superadmin')->value('password'));
    }
}
