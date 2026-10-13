<?php

namespace Tests\Feature;

use App\Support\TotpCrypto;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * Limite du second facteur PAR COMPTE — audit du 2026-10-13, B-7.
 *
 * Deux limites existaient : par SESSION (jeter son cookie la remet à zéro) et
 * par IP (dix échecs en dix minutes). Un attaquant qui détient déjà le mot de
 * passe pouvait donc répartir ses essais de codes TOTP sur plusieurs adresses.
 * La troisième limite compte les échecs du COMPTE, toutes IP confondues.
 */
class LimiteSecondFacteurParCompteTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Une cle factice : le chiffrement TOTP la lit dans la config (SECRET_KEY).
        config(['rootwarden.secret_key' => str_repeat('ab', 32)]);
        Schema::create('users', function (Blueprint $t) {
            $t->increments('id');
            $t->string('name')->unique();
            $t->string('password')->default('x');
            $t->integer('role_id')->default(1);
            $t->boolean('active')->default(true);
            $t->text('totp_secret')->nullable();
            $t->boolean('force_password_change')->default(false);
        });
        Schema::create('login_attempts', function (Blueprint $t) {
            $t->increments('id');
            $t->string('ip_address')->nullable();
            $t->string('username')->nullable();
            $t->boolean('success')->default(false);
            $t->string('step')->nullable();
            $t->dateTime('attempted_at')->nullable();
        });
        DB::table('users')->insert(['id' => 5, 'name' => 'cible',
            'totp_secret' => TotpCrypto::chiffre('JBSWY3DPEHPK3PXP')]);
    }

    /** `n` échecs du compte `cible`, chacun depuis une IP DIFFÉRENTE. */
    private function echecsRepartis(int $n): void
    {
        for ($i = 0; $i < $n; $i++) {
            DB::table('login_attempts')->insert(['ip_address' => "198.51.100.{$i}", 'username' => 'cible',
                'success' => 0, 'step' => '2fa', 'attempted_at' => now()->subMinutes(2)]);
        }
    }

    private function soumet()
    {
        return $this->withSession(['compte_temporaire' => ['id' => 5, 'nom' => 'cible', 'role' => 1]])
            ->post('/second-facteur', ['2fa_code' => '000000']);
    }

    #[Test]
    public function dix_echecs_repartis_sur_dix_ip_bloquent_le_compte(): void
    {
        $this->echecsRepartis(10);

        $this->soumet()->assertSessionHasErrors(['2fa_code' => __('auth.erreur_trop_de_tentatives')]);
    }

    #[Test]
    public function en_dessous_du_seuil_le_code_est_verifie(): void
    {
        // Témoin : neuf échecs ne bloquent pas — le code est examiné, et refusé.
        $this->echecsRepartis(9);

        $this->soumet()->assertSessionHasErrors(['2fa_code' => __('auth.erreur_code_invalide')]);
    }

    #[Test]
    public function les_echecs_d_un_autre_compte_ne_comptent_pas(): void
    {
        for ($i = 0; $i < 10; $i++) {
            DB::table('login_attempts')->insert(['ip_address' => "198.51.100.{$i}", 'username' => 'autre',
                'success' => 0, 'step' => '2fa', 'attempted_at' => now()->subMinutes(2)]);
        }

        $this->soumet()->assertSessionHasErrors(['2fa_code' => __('auth.erreur_code_invalide')]);
    }

    #[Test]
    public function les_echecs_anciens_ne_comptent_plus(): void
    {
        for ($i = 0; $i < 10; $i++) {
            DB::table('login_attempts')->insert(['ip_address' => "198.51.100.{$i}", 'username' => 'cible',
                'success' => 0, 'step' => '2fa', 'attempted_at' => now()->subMinutes(30)]);
        }

        $this->soumet()->assertSessionHasErrors(['2fa_code' => __('auth.erreur_code_invalide')]);
    }
}
