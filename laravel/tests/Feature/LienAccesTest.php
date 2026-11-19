<?php

namespace Tests\Feature;

use App\Services\LienAcces;
use App\Services\ReinitialisationMotDePasse;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

/**
 * Le lien d'acces envoye par un administrateur (`LienAcces`).
 *
 * Le courriel passe par le transport `array` : `Mail::fake()` ne capture pas
 * `Mail::raw()` (sa methode `raw` est vide), il ferait passer un envoi absent.
 * Le lien lu dans le corps du message est ensuite eprouve par
 * `ReinitialisationMotDePasse::valide()`, celui qu'appelle le formulaire.
 */
class LienAccesTest extends TestCase
{
    private LienAcces $lien;

    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('users', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name', 255);
            $table->string('email', 255)->nullable();
            $table->integer('role_id')->default(1);
            $table->tinyInteger('active')->default(1);
        });
        Schema::create('password_reset_tokens', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id');
            $table->string('token_hash', 255);
            $table->dateTime('expires_at');
            $table->dateTime('used_at')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->dateTime('created_at')->nullable();
        });

        config(['mail.default' => 'array', 'rootwarden.bcrypt_cost' => 4]);
        Cache::flush();
        $this->lien = app(LienAcces::class);
    }

    protected function tearDown(): void
    {
        Schema::dropIfExists('password_reset_tokens');
        Schema::dropIfExists('users');
        parent::tearDown();
    }

    private function pose(int $id, int $role = 1, int $actif = 1, ?string $courriel = 'jean@example.com'): void
    {
        DB::table('users')->insert([
            'id' => $id, 'name' => 'compte' . $id, 'email' => $courriel, 'role_id' => $role, 'active' => $actif,
        ]);
    }

    private function envoie(int $id, int $roleAuteur = 3): ?string
    {
        return $this->lien->envoie($id, $roleAuteur, '10.0.0.1',
            fn (int $uid, string $jeton) => "https://portail.example/reinitialiser?uid={$uid}&jeton={$jeton}");
    }

    /** @return list<\Symfony\Component\Mailer\SentMessage> */
    private function envoyes(): array
    {
        return app('mail.manager')->mailer('array')->getSymfonyTransport()->messages()->all();
    }

    private function jetonsVivants(int $id): int
    {
        return DB::table('password_reset_tokens')->where('user_id', $id)
            ->whereNull('used_at')->where('expires_at', '>', now())->count();
    }

    public function test_le_courriel_part_et_son_lien_ouvre_le_formulaire(): void
    {
        $this->pose(9);

        $this->assertNull($this->envoie(9));

        $messages = $this->envoyes();
        $this->assertCount(1, $messages);
        $courriel = $messages[0]->getOriginalMessage();
        $this->assertSame('jean@example.com', $courriel->getTo()[0]->getAddress());

        $corps = (string) $courriel->getTextBody();
        $this->assertSame(1, preg_match('/uid=9&jeton=([a-f0-9]{64})/', $corps, $m), $corps);
        $this->assertNotNull(app(ReinitialisationMotDePasse::class)->valide(9, $m[1]),
            'le jeton du courriel doit etre celui que le formulaire accepte');
        $this->assertStringContainsString('24', $corps);
    }

    public function test_le_lien_vit_24_heures_et_non_une(): void
    {
        $this->pose(9);
        $this->envoie(9);

        $expire = strtotime((string) DB::table('password_reset_tokens')->where('user_id', 9)->value('expires_at'));
        $this->assertGreaterThan(time() + 23 * 3600, $expire);
        $this->assertLessThanOrEqual(time() + 24 * 3600 + 5, $expire);
    }

    public function test_un_seul_lien_vivant_par_compte(): void
    {
        $this->pose(9);
        app(ReinitialisationMotDePasse::class)->emet(9, '10.0.0.2');

        $this->envoie(9);

        $this->assertSame(1, $this->jetonsVivants(9), 'le lien precedent devait mourir');
    }

    public function test_un_role_2_ne_vise_pas_un_role_3(): void
    {
        $this->pose(9, role: 3);

        $this->assertSame('comptes.err_hierarchie', $this->envoie(9, roleAuteur: 2));
        $this->assertSame([], $this->envoyes());
        $this->assertSame(0, $this->jetonsVivants(9));
    }

    public function test_un_role_2_vise_un_role_1(): void
    {
        $this->pose(9, role: 1);

        $this->assertNull($this->envoie(9, roleAuteur: 2));
        $this->assertCount(1, $this->envoyes());
    }

    public function test_compte_suspendu_sans_adresse_ou_inconnu(): void
    {
        $this->pose(7, actif: 0);
        $this->pose(8, courriel: null);
        $this->pose(9, courriel: 'pas-une-adresse');

        $this->assertSame('comptes.lien_inactif', $this->envoie(7));
        $this->assertSame('comptes.lien_sans_courriel', $this->envoie(8));
        $this->assertSame('comptes.lien_sans_courriel', $this->envoie(9));
        $this->assertSame('comptes.err_inconnu', $this->envoie(99));
        $this->assertSame([], $this->envoyes());
        $this->assertSame(0, DB::table('password_reset_tokens')->count());
    }

    public function test_un_double_clic_n_envoie_qu_un_courriel(): void
    {
        $this->pose(9);

        $this->assertNull($this->envoie(9));
        $this->assertSame('comptes.lien_trop_tot', $this->envoie(9));
        $this->assertCount(1, $this->envoyes());
    }

    public function test_un_envoi_echoue_ne_laisse_aucun_lien_valable(): void
    {
        // Un port ferme : la connexion SMTP est refusee aussitot.
        config(['mail.default' => 'smtp', 'mail.mailers.smtp.host' => '127.0.0.1',
            'mail.mailers.smtp.port' => 1, 'mail.mailers.smtp.scheme' => 'smtp']);
        $this->pose(9);

        $this->assertSame('comptes.lien_echec', $this->envoie(9));
        $this->assertSame(0, $this->jetonsVivants(9));
    }

    public function test_le_transport_local_se_dit(): void
    {
        config(['mail.default' => 'log']);
        $this->assertTrue($this->lien->transportLocal());

        config(['mail.default' => 'smtp']);
        $this->assertFalse($this->lien->transportLocal());
    }
}
