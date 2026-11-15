<?php

namespace Tests\Feature;

use App\Services\Serveurs;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * L'option « Nettoyer les comptes obsoletes » n'est plus offerte (aucun code ne
 * la lisait). Enregistrer une machine ne doit donc plus toucher la colonne :
 * avant, la case absente la remettait a 0 a chaque enregistrement.
 */
class NettoyageComptesNonOffertTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('machines', function (Blueprint $t) {
            $t->id();
            $t->string('name'); $t->string('ip'); $t->string('user')->default('u');
            $t->integer('port')->default(22);
            $t->string('environment')->default('DEV'); $t->string('criticality')->default('NON CRITIQUE');
            $t->string('network_type')->default('INTERNE');
            $t->text('password')->nullable(); $t->text('root_password')->nullable();
            $t->boolean('cleanup_users')->default(true);
        });
        DB::table('machines')->insert(['id' => 1, 'name' => 'm', 'ip' => '192.0.2.10', 'cleanup_users' => 1]);
    }

    private function brut(): array
    {
        return ['name' => 'm', 'ip' => '192.0.2.10', 'user' => 'u', 'port' => 22, 'environment' => 'DEV',
                'criticality' => 'NON CRITIQUE', 'network_type' => 'INTERNE', 'password' => '', 'root_password' => ''];
    }

    #[Test]
    public function enregistrer_sans_l_option_ne_touche_pas_la_colonne(): void
    {
        $this->assertNull(app(Serveurs::class)->modifie(1, $this->brut()));
        $this->assertSame(1, (int) DB::table('machines')->where('id', 1)->value('cleanup_users'));
    }

    #[Test]
    public function temoin_une_valeur_explicite_s_ecrit_toujours(): void
    {
        $this->assertNull(app(Serveurs::class)->modifie(1, $this->brut(), false));
        $this->assertSame(0, (int) DB::table('machines')->where('id', 1)->value('cleanup_users'));
    }
}
