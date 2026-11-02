<?php

namespace Tests\Feature;

use App\Services\ClesPubliques;
use App\Services\Comptes;
use App\Services\JournalAudit;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * Plusieurs cles SSH par compte, chacune avec sa portee — migration 067.
 *
 * Le besoin : une cle personnelle valable sur toutes ses machines, et des cles
 * dediees a UN serveur. La portee RESTREINT : elle ne peut designer que des
 * machines auxquelles le compte a acces, et elle n'en ouvre aucune.
 *
 * Les empreintes attendues ont ete calculees par `ssh-keygen -lf` sur ces deux
 * cles, pas par la formule testee : un oracle independant.
 */
class ClesSshMultiplesTest extends TestCase
{
    private const CLE_A = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDF3OcRPzDUQ29GJoN0OUlbkiu5jhEWwwQiqZwklL46Y test-a';
    private const EMPREINTE_A = 'Tq8YuM6dwb+CrX7Kly3JFyuO65tYV1YGGpWT5jiCNOQ';
    private const CLE_B = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILxHVQBWaEPwMqxOnxfmFPiwS1zez/97krpH4/2gQYzw test-b';

    private const AUTRE_COMPTE = 77;

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
        DB::table('machines')->insert([['id' => 1, 'name' => 'srv-web01'], ['id' => 2, 'name' => 'srv-db01'],
                                       ['id' => 3, 'name' => 'srv-hors-acces']]);
        DB::table('user_machine_access')->insert([['user_id' => self::COMPTE, 'machine_id' => 1],
                                                  ['user_id' => self::COMPTE, 'machine_id' => 2]]);
    }

    private function cles(): ClesPubliques
    {
        return new ClesPubliques();
    }

    #[Test]
    public function une_cle_valable_partout_et_une_cle_dediee_a_un_serveur(): void
    {
        $this->assertNull($this->cles()->ajoute(self::COMPTE, 'perso', self::CLE_A, true));
        $this->assertNull($this->cles()->ajoute(self::COMPTE, 'automate-srv-web01', self::CLE_B, false, ['1']));

        $liste = $this->cles()->duCompte(self::COMPTE);
        $this->assertCount(2, $liste);
        $this->assertTrue($liste[0]['toutes_machines']);
        $this->assertSame([], $liste[0]['machines']);
        $this->assertFalse($liste[1]['toutes_machines']);
        $this->assertSame([['id' => 1, 'name' => 'srv-web01']], $liste[1]['machines']);
    }

    #[Test]
    public function l_empreinte_est_celle_de_ssh_keygen(): void
    {
        $this->assertSame(self::EMPREINTE_A, ClesPubliques::empreinte(self::CLE_A));
    }

    #[Test]
    public function une_portee_ne_peut_designer_qu_une_machine_accessible(): void
    {
        $err = $this->cles()->ajoute(self::COMPTE, 'x', self::CLE_A, false, [1, 3]);

        $this->assertSame('profil.err_cle_portee_hors_acces', $err);
        $this->assertSame(0, DB::table('user_ssh_keys')->count(), 'refus ENTIER : rien ne doit etre ecrit');
    }

    #[Test]
    public function une_portee_restreinte_vide_est_refusee(): void
    {
        $this->assertSame('profil.err_cle_portee_vide', $this->cles()->ajoute(self::COMPTE, 'x', self::CLE_A, false, []));
    }

    #[Test]
    public function une_option_devant_la_cle_est_refusee(): void
    {
        // `command=` change le sens de la ligne posee dans authorized_keys.
        $err = $this->cles()->ajoute(self::COMPTE, 'x', 'command="/bin/sh" ' . self::CLE_A, true);

        $this->assertSame('comptes.err_cle_algo', $err);
    }

    #[Test]
    public function la_meme_cle_n_est_pas_enregistree_deux_fois(): void
    {
        $this->cles()->ajoute(self::COMPTE, 'perso', self::CLE_A, true);

        $this->assertSame('profil.err_cle_doublon',
            $this->cles()->ajoute(self::COMPTE, 'perso bis', self::CLE_A . ' autre-commentaire', true));
    }

    #[Test]
    public function on_ne_retire_que_SES_cles(): void
    {
        $this->cles()->ajoute(self::AUTRE_COMPTE, 'la sienne', self::CLE_A, true);
        $id = (int) DB::table('user_ssh_keys')->value('id');

        $this->assertFalse($this->cles()->retire(self::COMPTE, $id));
        $this->assertSame(1, DB::table('user_ssh_keys')->count());
        $this->assertTrue($this->cles()->retire(self::AUTRE_COMPTE, $id));   // temoin
    }

    #[Test]
    public function l_ecriture_administrative_garde_son_sens_une_seule_cle_partout(): void
    {
        $this->cles()->ajoute(self::COMPTE, 'perso', self::CLE_A, true);
        $this->cles()->ajoute(self::COMPTE, 'dediee', self::CLE_B, false, [1]);

        $this->assertNull($this->cles()->remplaceParUneSeule(self::COMPTE, self::CLE_B));
        $liste = $this->cles()->duCompte(self::COMPTE);
        $this->assertCount(1, $liste);
        $this->assertTrue($liste[0]['toutes_machines']);

        $this->assertNull($this->cles()->remplaceParUneSeule(self::COMPTE, ''));
        $this->assertSame([], $this->cles()->duCompte(self::COMPTE));
    }

    private function harnais(): void
    {
        $comptes = $this->createStub(Comptes::class);
        $comptes->method('trouve')->willReturn(['id' => self::COMPTE, 'name' => 'compte', 'role_id' => 1, 'active' => 1]);
        $this->instance(Comptes::class, $comptes);
        $this->instance(JournalAudit::class, $this->createStub(JournalAudit::class));
    }

    #[Test]
    public function le_profil_ajoute_une_cle_au_compte_DE_LA_SESSION(): void
    {
        $this->harnais();

        $this->connecte(1)->post('/profil/cles-ssh', [
            'libelle' => 'automate-srv-db01', 'cle_ssh' => self::CLE_B, 'portee' => 'machines', 'machines' => ['2'],
        ])->assertRedirect('/profil');

        $ligne = DB::table('user_ssh_keys')->first();
        $this->assertSame(self::COMPTE, (int) $ligne->user_id);
        $this->assertSame(0, (int) $ligne->toutes_machines);
        $this->assertSame([2], DB::table('user_ssh_key_machines')->pluck('machine_id')->map('intval')->all());
    }

    #[Test]
    public function le_profil_ne_retire_pas_la_cle_d_un_autre_compte(): void
    {
        $this->harnais();
        $this->cles()->ajoute(self::AUTRE_COMPTE, 'la sienne', self::CLE_A, true);
        $id = (int) DB::table('user_ssh_keys')->value('id');

        $this->connecte(1)->post("/profil/cles-ssh/{$id}/retirer")
            ->assertRedirect('/profil')->assertSessionHas('cle_erreur');

        $this->assertSame(1, DB::table('user_ssh_keys')->count(), 'la cle d\'un autre compte a ete retiree');
    }

    #[Test]
    public function temoin_le_profil_retire_bien_SA_propre_cle(): void
    {
        // Sans ce temoin, le refus ci-dessus pourrait venir d'une route cassee.
        $this->harnais();
        $this->cles()->ajoute(self::COMPTE, 'la mienne', self::CLE_A, true);
        $id = (int) DB::table('user_ssh_keys')->value('id');

        $this->connecte(1)->post("/profil/cles-ssh/{$id}/retirer")
            ->assertRedirect('/profil')->assertSessionHas('cle_message');

        $this->assertSame(0, DB::table('user_ssh_keys')->count());
    }
}
