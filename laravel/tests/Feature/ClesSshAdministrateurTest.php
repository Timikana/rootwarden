<?php

namespace Tests\Feature;

use App\Services\ClesPubliques;
use App\Services\Comptes;
use App\Services\JournalAudit;
use App\Services\StepUp;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Test;
use Tests\Doubles\StepUpFictif;
use Tests\TestCase;

/**
 * Un administrateur ajoute ou retire UNE cle SSH d'un compte, depuis Acces &
 * permissions — le geste du legacy (`manage_users.php`) qu'aucun ecran du
 * portage n'exposait.
 *
 * Une cle posee ouvre une connexion SSH SOUS LE NOM du compte : l'ajout exige
 * un step-up (`cle_ssh_poser`), et ni l'ajout ni le retrait ne visent soi-meme
 * ou un rang egal ou superieur.
 */
class ClesSshAdministrateurTest extends TestCase
{
    private const CLE_A = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDF3OcRPzDUQ29GJoN0OUlbkiu5jhEWwwQiqZwklL46Y test-a';
    private const CLE_B = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILxHVQBWaEPwMqxOnxfmFPiwS1zez/97krpH4/2gQYzw test-b';

    /** L'administrateur connecte, role 3. */
    private const AUTEUR = 5;
    /** Un autre superadmin : rang egal a celui de l'auteur. */
    private const PAIR = 78;

    private ?JournalAudit $journal = null;

    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('machines', function (Blueprint $t) {
            $t->increments('id');
            $t->string('name');
            $t->string('lifecycle_status')->nullable();
        });
        Schema::create('user_machine_access', function (Blueprint $t) {
            $t->integer('user_id');
            $t->integer('machine_id');
        });
        Schema::create('user_ssh_keys', function (Blueprint $t) {
            $t->increments('id');
            $t->integer('user_id');
            $t->string('libelle', 100);
            $t->text('cle');
            $t->tinyInteger('toutes_machines')->default(1);
            $t->dateTime('created_at')->nullable();
        });
        Schema::create('user_ssh_key_machines', function (Blueprint $t) {
            $t->integer('key_id');
            $t->integer('machine_id');
        });
        DB::table('machines')->insert([['id' => 1, 'name' => 'srv-web01'], ['id' => 2, 'name' => 'srv-db01']]);
        DB::table('user_machine_access')->insert(['user_id' => self::COMPTE, 'machine_id' => 1]);

        $comptes = $this->createStub(Comptes::class);
        $comptes->method('trouve')->willReturnCallback(fn (int $id) => match ($id) {
            self::COMPTE => ['id' => $id, 'name' => 'jdupont', 'role_id' => 1, 'active' => 1],
            self::PAIR => ['id' => $id, 'name' => 'autre-admin', 'role_id' => 3, 'active' => 1],
            self::AUTEUR => ['id' => $id, 'name' => 'admin', 'role_id' => 3, 'active' => 1],
            default => null,
        });
        $this->instance(Comptes::class, $comptes);
    }

    private function stepUp(bool $accorde): StepUpFictif
    {
        $double = new StepUpFictif($accorde ? ['cle_ssh_poser'] : []);
        $this->instance(StepUp::class, $double);

        return $double;
    }

    private function journalAttendu(int $fois): void
    {
        $journal = $this->createMock(JournalAudit::class);
        $journal->expects($this->exactly($fois))->method('ajoute');
        $this->instance(JournalAudit::class, $journal);
    }

    private function ajoute(int $cible, array $corps)
    {
        return $this->connecte(3, ['can_admin_portal'], self::AUTEUR)->postJson("/permissions/{$cible}/cles", $corps);
    }

    #[Test]
    public function l_administrateur_ajoute_une_cle_sans_toucher_aux_autres(): void
    {
        (new ClesPubliques())->ajoute(self::COMPTE, 'perso', self::CLE_A, true);
        $this->stepUp(true);
        $this->journalAttendu(1);

        $this->ajoute(self::COMPTE, ['libelle' => 'automate', 'cle_ssh' => self::CLE_B, 'portee' => 'machines', 'machines' => ['1']])
            ->assertOk()->assertJson(['success' => true]);

        $cles = (new ClesPubliques())->duCompte(self::COMPTE);
        $this->assertSame(['perso', 'automate'], array_column($cles, 'libelle'), 'la cle existante doit rester');
        $this->assertFalse($cles[1]['toutes_machines']);
        $this->assertSame([['id' => 1, 'name' => 'srv-web01']], $cles[1]['machines']);
    }

    #[Test]
    public function sans_step_up_rien_n_est_pose(): void
    {
        $double = $this->stepUp(false);
        $this->journalAttendu(0);

        $this->ajoute(self::COMPTE, ['libelle' => 'x', 'cle_ssh' => self::CLE_A])
            ->assertForbidden()->assertJson(['step_up_required' => true, 'action' => 'cle_ssh_poser']);

        $this->assertSame(0, DB::table('user_ssh_keys')->count());
        $this->assertSame(['cle_ssh_poser'], $double->demandes, 'la marque demandee doit etre propre au geste');
    }

    #[Test]
    public function on_ne_pose_pas_de_cle_chez_un_pair_ni_chez_soi(): void
    {
        $this->stepUp(true);
        $this->journalAttendu(0);

        $this->ajoute(self::PAIR, ['libelle' => 'x', 'cle_ssh' => self::CLE_A])
            ->assertForbidden()->assertJson(['message' => __('perms.err_rang')]);
        $this->ajoute(self::AUTEUR, ['libelle' => 'x', 'cle_ssh' => self::CLE_A])
            ->assertForbidden()->assertJson(['message' => __('perms.err_soi_meme')]);

        $this->assertSame(0, DB::table('user_ssh_keys')->count());
    }

    #[Test]
    public function une_cle_mal_formee_ou_une_machine_hors_acces_est_refusee(): void
    {
        $this->stepUp(true);
        $this->journalAttendu(0);

        $this->ajoute(self::COMPTE, ['libelle' => 'x', 'cle_ssh' => 'command="/bin/sh" ' . self::CLE_A])
            ->assertStatus(422)->assertJson(['message' => __('comptes.err_cle_algo')]);
        $this->ajoute(self::COMPTE, ['libelle' => 'x', 'cle_ssh' => self::CLE_A, 'portee' => 'machines', 'machines' => ['2']])
            ->assertStatus(422)->assertJson(['message' => __('perms.err_cle_portee_hors_acces')]);

        $this->assertSame(0, DB::table('user_ssh_keys')->count());
    }

    #[Test]
    public function l_administrateur_retire_une_seule_cle(): void
    {
        $cles = new ClesPubliques();
        $cles->ajoute(self::COMPTE, 'perso', self::CLE_A, true);
        $cles->ajoute(self::COMPTE, 'automate', self::CLE_B, true);
        $id = (int) DB::table('user_ssh_keys')->where('libelle', 'automate')->value('id');
        $this->journalAttendu(1);

        $this->connecte(3, ['can_admin_portal'], self::AUTEUR)
            ->postJson('/permissions/' . self::COMPTE . "/cles/{$id}/retirer")
            ->assertOk()->assertJson(['success' => true]);

        $this->assertSame(['perso'], array_column($cles->duCompte(self::COMPTE), 'libelle'));
    }

    #[Test]
    public function le_retrait_ne_trouve_pas_la_cle_d_un_autre_compte(): void
    {
        (new ClesPubliques())->ajoute(self::PAIR, 'la sienne', self::CLE_A, true);
        $id = (int) DB::table('user_ssh_keys')->value('id');
        $this->journalAttendu(0);

        // L'URL vise COMPTE (role 1, la garde de rang passe) ; la cle est a PAIR.
        $this->connecte(3, ['can_admin_portal'], self::AUTEUR)
            ->postJson('/permissions/' . self::COMPTE . "/cles/{$id}/retirer")
            ->assertNotFound();

        $this->assertSame(1, DB::table('user_ssh_keys')->count());
    }

    #[Test]
    public function on_ne_retire_pas_la_cle_d_un_pair(): void
    {
        (new ClesPubliques())->ajoute(self::PAIR, 'la sienne', self::CLE_A, true);
        $id = (int) DB::table('user_ssh_keys')->value('id');
        $this->journalAttendu(0);

        $this->connecte(3, ['can_admin_portal'], self::AUTEUR)
            ->postJson('/permissions/' . self::PAIR . "/cles/{$id}/retirer")
            ->assertForbidden();

        $this->assertSame(1, DB::table('user_ssh_keys')->count());
    }

    #[Test]
    public function l_ancienne_ecriture_qui_remplacait_toutes_les_cles_n_existe_plus(): void
    {
        $this->assertFalse(Route::has('comptes.cle-ssh'));
        $this->assertTrue(Route::has('permissions.cles.ajouter'), 'temoin : la route qui la remplace');
        $this->connecte(3, ['can_admin_portal'], self::AUTEUR)
            ->postJson('/comptes/' . self::COMPTE . '/cle-ssh', ['cle_ssh' => ''])
            ->assertNotFound();
    }
}
