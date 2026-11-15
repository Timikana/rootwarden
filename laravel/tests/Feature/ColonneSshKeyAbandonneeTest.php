<?php

namespace Tests\Feature;

use App\Services\Comptes;
use App\Services\Conformite;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * `users.ssh_key` n'est plus LUE — migration 067.
 *
 * La colonne reste en base pour un retour arriere, et c'est precisement le
 * danger : un lecteur oublie continuerait de lire la cle UNIQUE d'avant, figee,
 * pendant que les vraies cles vivent dans `user_ssh_keys`. Deux sources qui
 * divergent sans bruit.
 *
 * L'epreuve est de COMPORTEMENT, pas un motif : les lecteurs tournent sur une
 * table `users` SANS les colonnes `ssh_key` et `ssh_key_updated_at`. Un lecteur
 * qui y toucherait encore echoue sur « no such column ».
 */
class ColonneSshKeyAbandonneeTest extends TestCase
{
    private const CLE = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDF3OcRPzDUQ29GJoN0OUlbkiu5jhEWwwQiqZwklL46Y test-a';

    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('roles', function (Blueprint $t) {
            $t->increments('id');
            $t->string('name');
        });
        Schema::create('users', function (Blueprint $t) {
            // ⚠ NI `ssh_key` NI `ssh_key_updated_at` : c'est toute l'epreuve.
            $t->increments('id');
            $t->string('name');
            $t->string('email')->nullable();
            $t->string('company')->nullable();
            $t->integer('role_id')->default(1);
            $t->tinyInteger('active')->default(1);
            $t->tinyInteger('sudo')->default(0);
            $t->integer('failed_attempts')->default(0);
            $t->dateTime('locked_until')->nullable();
            $t->text('totp_secret')->nullable();
            $t->tinyInteger('force_password_change')->default(0);
            $t->dateTime('password_updated_at')->nullable();
            $t->string('password_expiry_override')->nullable();
            $t->dateTime('created_at')->nullable();
        });
        Schema::create('user_ssh_keys', function (Blueprint $t) {
            $t->increments('id');
            $t->integer('user_id');
            $t->string('libelle', 100);
            $t->text('cle');
            $t->tinyInteger('toutes_machines')->default(1);
            $t->dateTime('created_at')->nullable();
        });
        DB::table('roles')->insert(['id' => 1, 'name' => 'user']);
        DB::table('users')->insert([['id' => 1, 'name' => 'avec-cle'], ['id' => 2, 'name' => 'sans-cle']]);
        DB::table('user_ssh_keys')->insert(['user_id' => 1, 'libelle' => 'ancienne', 'cle' => self::CLE,
            'toutes_machines' => 1, 'created_at' => now()->subDays(120)]);
    }

    #[Test]
    public function la_liste_des_comptes_compte_leurs_cles(): void
    {
        $liste = collect((new Comptes())->liste())->keyBy('name');

        $this->assertSame(1, (int) $liste['avec-cle']['nb_cles']);
        $this->assertSame(0, (int) $liste['sans-cle']['nb_cles']);
    }

    #[Test]
    public function les_indicateurs_lisent_la_nouvelle_table(): void
    {
        $indicateurs = (new Comptes())->indicateursComptes(3);
        $alertes = (new Comptes())->alertesCles(3);

        $this->assertTrue($indicateurs['lisible'], 'lecture echouee : un lecteur touche encore la colonne');
        $this->assertSame(1, $indicateurs['sans_cle']);
        $this->assertTrue($alertes['lisible']);
        $this->assertSame(1, $alertes['cles_anciennes'], 'la cle de 120 jours n\'est pas comptee');
    }

    #[Test]
    public function la_conformite_garde_ses_deux_champs_remplis_depuis_la_nouvelle_table(): void
    {
        $comptes = collect(app(Conformite::class)->comptes())->keyBy('name');

        $this->assertSame(self::CLE, $comptes['avec-cle']->ssh_key);
        $this->assertNotNull($comptes['avec-cle']->ssh_key_updated_at);
        $this->assertNull($comptes['sans-cle']->ssh_key);
        // L'ordre des champs entre dans l'empreinte (D-2) : il ne bouge pas.
        $this->assertSame(['name', 'email', 'active', 'sudo', 'ssh_key', 'ssh_key_updated_at', 'totp_secret',
            'password_updated_at', 'created_at', 'role_name'], array_keys((array) $comptes['avec-cle']));
    }
}
