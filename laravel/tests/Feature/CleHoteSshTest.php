<?php

namespace Tests\Feature;

use App\Services\ClesHoteSsh;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * Oublier la clé d'hôte SSH d'une machine réinstallée — audit du 2026-10-13, H-3.
 *
 * Le backend refuse désormais toute connexion dont la clé d'hôte diffère de celle
 * vue au premier usage. Sans ce geste, une machine légitimement réinstallée serait
 * refusée pour toujours. Le geste est sensible — oublier une clé, c'est accepter
 * la suivante, y compris celle d'un usurpateur — d'où le rôle 3 et la confirmation.
 */
class CleHoteSshTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('machines', function (Blueprint $t) {
            $t->increments('id');
            $t->string('name');
            $t->string('ip');
            $t->integer('port')->default(22);
        });
        Schema::create('ssh_host_keys', function (Blueprint $t) {
            $t->string('hote', 300)->primary();
            $t->string('key_type', 64);
            $t->text('key_b64');
            $t->char('fingerprint_sha256', 64);
            $t->dateTime('first_seen')->nullable();
            $t->dateTime('last_seen')->nullable();
        });
        Schema::create('user_logs', function (Blueprint $t) {
            $t->increments('id');
            $t->integer('user_id');
            $t->string('action', 255);
            $t->dateTime('created_at')->nullable();
            $t->string('prev_hash', 64)->nullable();
            $t->string('self_hash', 64)->nullable();
        });
        DB::table('machines')->insert([
            ['id' => 1, 'name' => 'srv-a', 'ip' => '192.0.2.10', 'port' => 22],
            ['id' => 2, 'name' => 'srv-b', 'ip' => '192.0.2.20', 'port' => 2222],
        ]);
        foreach (['192.0.2.10', '[192.0.2.20]:2222', '[192.0.2.10]:22'] as $h) {
            DB::table('ssh_host_keys')->insert(['hote' => $h, 'key_type' => 'ssh-ed25519', 'key_b64' => 'AAAA',
                'fingerprint_sha256' => str_repeat('a', 64), 'first_seen' => '2026-10-13 12:00:00']);
        }
    }

    private function oublie(int $id, array $corps, int $role = 3)
    {
        return $this->connecte($role, ['can_admin_portal'])
            ->post("/serveurs/{$id}/cle-hote/oublier", $corps);
    }

    #[Test]
    public function un_administrateur_de_role_2_ne_peut_pas_oublier_une_cle(): void
    {
        $this->oublie(1, ['confirme' => 1], 2)->assertForbidden();
        $this->assertSame(3, DB::table('ssh_host_keys')->count());
    }

    #[Test]
    public function sans_confirmation_rien_n_est_oublie(): void
    {
        $this->oublie(1, [])->assertSessionHas('erreur');
        $this->assertSame(3, DB::table('ssh_host_keys')->count());
    }

    #[Test]
    public function avec_confirmation_seule_la_cle_de_cette_machine_est_oubliee(): void
    {
        $this->oublie(1, ['confirme' => 1])->assertSessionHas('succes');

        $restantes = DB::table('ssh_host_keys')->pluck('hote')->all();
        $this->assertSame(['[192.0.2.20]:2222'], $restantes,
            'les deux formes de srv-a doivent partir, et srv-b rester');
        $trace = DB::table('user_logs')->value('action');
        $this->assertStringContainsString("srv-a", (string) $trace, 'le geste n est pas journalise');
    }

    #[Test]
    public function un_port_non_standard_est_reconnu(): void
    {
        $cles = app(ClesHoteSsh::class)->parMachine([
            ['id' => 1, 'ip' => '192.0.2.10', 'port' => 22],
            ['id' => 2, 'ip' => '192.0.2.20', 'port' => 2222],
            ['id' => 3, 'ip' => '192.0.2.30', 'port' => 22],
        ]);

        $this->assertNotNull($cles[1]);
        $this->assertNotNull($cles[2], 'la forme [ip]:port n est pas lue');
        $this->assertNull($cles[3]);
    }

    #[Test]
    public function la_page_ne_tombe_pas_si_la_table_manque(): void
    {
        Schema::drop('ssh_host_keys');

        $cles = app(ClesHoteSsh::class)->parMachine([['id' => 1, 'ip' => '192.0.2.10', 'port' => 22]]);

        $this->assertSame([1 => null], $cles);
    }
}
