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
 * Changer la portee d'une cle SANS la retirer — par la cle (profil) et par la
 * machine (Acces & permissions). Les deux ecrivent `user_ssh_key_machines` par
 * `ClesPubliques`, donc sous les memes regles qu'a l'ajout.
 *
 * Le retrait EFFECTIF sur le serveur est eprouve cote passerelle
 * (`test_cles_ssh_multiples.py`) : c'est elle qui ecrit `authorized_keys`.
 */
class PorteeClesSshTest extends TestCase
{
    private const CLE_A = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDF3OcRPzDUQ29GJoN0OUlbkiu5jhEWwwQiqZwklL46Y test-a';
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

    /** Une cle du compte restreinte a `$machines`, ou valable partout. */
    private function pose(array $machines = [], int $compte = self::COMPTE, string $cle = self::CLE_A): int
    {
        $this->assertNull($this->cles()->ajoute($compte, 'k', $cle, $machines === [], $machines));

        return (int) DB::table('user_ssh_keys')->where('user_id', $compte)->max('id');
    }

    /** @return list<int> */
    private function machinesDe(int $cle): array
    {
        return DB::table('user_ssh_key_machines')->where('key_id', $cle)->orderBy('machine_id')
            ->pluck('machine_id')->map('intval')->all();
    }

    private function toutes(int $cle): bool
    {
        return (bool) DB::table('user_ssh_keys')->where('id', $cle)->value('toutes_machines');
    }

    /* ═══ Le service ═══════════════════════════════════════════════════════ */

    #[Test]
    public function la_portee_change_et_la_cle_reste(): void
    {
        $id = $this->pose([1]);

        $this->assertNull($this->cles()->changePortee(self::COMPTE, $id, false, ['2']));

        $this->assertSame([2], $this->machinesDe($id));
        $this->assertSame(1, DB::table('user_ssh_keys')->count(), 'la cle ne doit pas etre retiree');
        $this->assertSame(self::CLE_A, DB::table('user_ssh_keys')->where('id', $id)->value('cle'));
    }

    #[Test]
    public function une_portee_restreinte_vide_est_refusee_et_rien_ne_bouge(): void
    {
        $id = $this->pose([1]);

        $this->assertSame('profil.err_cle_portee_vide', $this->cles()->changePortee(self::COMPTE, $id, false, []));
        $this->assertSame([1], $this->machinesDe($id));
    }

    #[Test]
    public function une_machine_hors_acces_refuse_tout(): void
    {
        $id = $this->pose([1]);

        $this->assertSame('profil.err_cle_portee_hors_acces',
            $this->cles()->changePortee(self::COMPTE, $id, false, [2, 3]));
        $this->assertSame([1], $this->machinesDe($id), 'refus ENTIER : srv-db01 ne doit pas avoir ete ajoute');
    }

    #[Test]
    public function la_cle_d_un_autre_compte_est_introuvable(): void
    {
        $id = $this->pose([], self::AUTRE_COMPTE);

        $this->assertSame('profil.err_cle_introuvable', $this->cles()->changePortee(self::COMPTE, $id, false, [1]));
        $this->assertTrue($this->toutes($id));
        $this->assertSame([], $this->machinesDe($id));
    }

    #[Test]
    public function de_restreinte_a_partout_puis_l_inverse(): void
    {
        $id = $this->pose([1, 2]);

        $this->assertNull($this->cles()->changePortee(self::COMPTE, $id, true, ['1']));
        $this->assertTrue($this->toutes($id));
        $this->assertSame([], $this->machinesDe($id), 'une cle valable partout ne garde pas de portee');

        $this->assertNull($this->cles()->changePortee(self::COMPTE, $id, false, [2]));
        $this->assertFalse($this->toutes($id));
        $this->assertSame([2], $this->machinesDe($id));
    }

    #[Test]
    public function la_portee_lue_et_decrite(): void
    {
        $id = $this->pose([2, 1]);

        $portee = $this->cles()->portee(self::COMPTE, $id);
        $this->assertSame('srv-db01, srv-web01', ClesPubliques::decrit($portee));
        $this->assertSame('toutes ses machines', ClesPubliques::decrit(['toutes' => true, 'machines' => []]));
        $this->assertNull($this->cles()->portee(self::AUTRE_COMPTE, $id));
    }

    /* ═══ La bascule par machine ═══════════════════════════════════════════ */

    #[Test]
    public function une_cle_restreinte_se_pose_et_se_retire_sur_une_machine(): void
    {
        $id = $this->pose([1]);

        $this->assertNull($this->cles()->basculeSurMachine(self::COMPTE, $id, 2, true));
        $this->assertSame([1, 2], $this->machinesDe($id));

        $this->assertNull($this->cles()->basculeSurMachine(self::COMPTE, $id, 1, false));
        $this->assertSame([2], $this->machinesDe($id));
    }

    #[Test]
    public function la_derniere_machine_ne_se_decoche_pas(): void
    {
        $id = $this->pose([1]);

        $this->assertSame('profil.err_cle_derniere_machine', $this->cles()->basculeSurMachine(self::COMPTE, $id, 1, false));
        $this->assertSame([1], $this->machinesDe($id));
    }

    #[Test]
    public function une_cle_valable_partout_ne_se_bascule_pas_par_machine(): void
    {
        $id = $this->pose();

        $this->assertSame('profil.err_cle_portee_toutes', $this->cles()->basculeSurMachine(self::COMPTE, $id, 1, false));
        $this->assertTrue($this->toutes($id));
    }

    #[Test]
    public function la_bascule_n_ouvre_pas_une_machine_hors_acces(): void
    {
        $id = $this->pose([1]);

        $this->assertSame('profil.err_cle_portee_hors_acces', $this->cles()->basculeSurMachine(self::COMPTE, $id, 3, true));
        $this->assertSame([1], $this->machinesDe($id));
    }

    #[Test]
    public function une_machine_dont_l_acces_a_ete_retire_ne_bloque_pas_la_bascule(): void
    {
        // Portee {1, 2}, puis l'acces a srv-db01 est retire. Poser ou retirer
        // ailleurs ne doit pas buter sur une machine que la case ne montre plus.
        $id = $this->pose([1, 2]);
        DB::table('user_machine_access')->where('machine_id', 2)->delete();
        DB::table('user_machine_access')->insert(['user_id' => self::COMPTE, 'machine_id' => 3]);

        $this->assertNull($this->cles()->basculeSurMachine(self::COMPTE, $id, 3, true));
        $this->assertSame([1, 3], $this->machinesDe($id));
    }

    /* ═══ Le profil ════════════════════════════════════════════════════════ */

    private function harnais(?JournalAudit $journal = null): void
    {
        $comptes = $this->createStub(Comptes::class);
        $comptes->method('trouve')->willReturn(['id' => self::COMPTE, 'name' => 'compte', 'role_id' => 1, 'active' => 1]);
        $this->instance(Comptes::class, $comptes);
        $this->instance(JournalAudit::class, $journal ?? $this->createStub(JournalAudit::class));
    }

    #[Test]
    public function le_profil_change_la_portee_et_journalise_l_avant_et_l_apres(): void
    {
        $id = $this->pose([1]);
        $journal = $this->createMock(JournalAudit::class);
        $journal->expects($this->once())->method('ajoute')
            ->with(self::COMPTE, "profil: portee de la cle SSH #{$id} modifiee (srv-web01 → srv-db01, srv-web01)");
        $this->harnais($journal);

        $this->connecte(1)->post("/profil/cles-ssh/{$id}/portee", ['portee' => 'machines', 'machines' => ['1', '2']])
            ->assertRedirect('/profil')->assertSessionHas('cle_message');

        $this->assertSame([1, 2], $this->machinesDe($id));
    }

    #[Test]
    public function le_profil_passe_une_cle_a_toutes_ses_machines(): void
    {
        $id = $this->pose([1]);
        $this->harnais();

        $this->connecte(1)->post("/profil/cles-ssh/{$id}/portee", ['portee' => 'toutes'])
            ->assertRedirect('/profil')->assertSessionHas('cle_message');

        $this->assertTrue($this->toutes($id));
        $this->assertSame([], $this->machinesDe($id));
    }

    #[Test]
    public function le_profil_ne_touche_pas_la_cle_d_un_autre_compte(): void
    {
        $id = $this->pose([], self::AUTRE_COMPTE);
        $journal = $this->createMock(JournalAudit::class);
        $journal->expects($this->never())->method('ajoute');
        $this->harnais($journal);

        $this->connecte(1)->post("/profil/cles-ssh/{$id}/portee", ['portee' => 'machines', 'machines' => ['1']])
            ->assertRedirect('/profil')->assertSessionHas('cle_erreur');

        $this->assertTrue($this->toutes($id));
    }

    #[Test]
    public function le_profil_refuse_une_portee_vide(): void
    {
        $id = $this->pose([1]);
        $this->harnais();

        $this->connecte(1)->post("/profil/cles-ssh/{$id}/portee", ['portee' => 'machines'])
            ->assertRedirect('/profil')->assertSessionHas('cle_erreur', __('profil.err_cle_portee_vide'));

        $this->assertSame([1], $this->machinesDe($id));
    }

    #[Test]
    public function le_profil_affiche_le_formulaire_pre_coche(): void
    {
        $id = $this->pose([2]);
        // Le gabarit compte les notifications non lues.
        Schema::create('notifications', function (Blueprint $t) {
            $t->increments('id');
            $t->integer('user_id')->nullable();
            $t->dateTime('read_at')->nullable();
        });

        $vue = $this->view('profil', [
            'cles' => $this->cles()->duCompte(self::COMPTE),
            'machinesCles' => $this->cles()->machinesAccessibles(self::COMPTE),
            'compte' => [], 'sessions' => [], 'sessionsLisibles' => true, 'sessionsTotal' => 0,
            'changementRequis' => false, 'libelleRole' => 'utilisateur',
            'longueurMinimale' => 15, 'tailleHistorique' => 5,
        ]);

        $vue->assertSee('data-rw="profil-cle-portee-' . $id . '"', false);
        $vue->assertSee(route('profil.cles-ssh.portee', ['cle' => $id]), false);
        $html = (string) $vue;
        $debut = strpos($html, 'data-rw="profil-cle-portee-' . $id . '"');
        $form = substr($html, $debut, (int) strpos($html, '</details>', $debut) - $debut);
        $this->assertMatchesRegularExpression('/value="2" class="rw-case"\s+checked/', $form, 'srv-db01 doit partir coche');
        $this->assertDoesNotMatchRegularExpression('/value="1" class="rw-case"\s+checked/', $form, 'temoin : srv-web01 decoche');
    }

    /* ═══ Acces & permissions ══════════════════════════════════════════════ */

    #[Test]
    public function l_administrateur_pose_une_cle_du_compte_sur_une_machine(): void
    {
        $id = $this->pose([1]);
        $this->harnais();

        $this->connecte(3, ['can_admin_portal'], 5)
            ->postJson('/permissions/' . self::COMPTE . "/cles/{$id}", ['machine_id' => 2, 'value' => 1])
            ->assertOk()->assertJson(['success' => true, 'actif' => true]);

        $this->assertSame([1, 2], $this->machinesDe($id));
    }

    #[Test]
    public function l_administrateur_retire_une_cle_d_une_machine(): void
    {
        $id = $this->pose([1, 2]);
        $this->harnais();

        $this->connecte(3, ['can_admin_portal'], 5)
            ->postJson('/permissions/' . self::COMPTE . "/cles/{$id}", ['machine_id' => 1, 'value' => 0])
            ->assertOk()->assertJson(['success' => true, 'actif' => false]);

        $this->assertSame([2], $this->machinesDe($id));
    }

    #[Test]
    public function l_administrateur_ne_deplace_pas_une_cle_vers_un_autre_compte(): void
    {
        // La cle appartient a AUTRE_COMPTE ; l'URL designe COMPTE.
        $id = $this->pose([], self::AUTRE_COMPTE);
        $this->harnais();

        $this->connecte(3, ['can_admin_portal'], 5)
            ->postJson('/permissions/' . self::COMPTE . "/cles/{$id}", ['machine_id' => 1, 'value' => 0])
            ->assertNotFound();

        $this->assertTrue($this->toutes($id));
    }

    #[Test]
    public function l_administrateur_ne_decoche_pas_la_derniere_machine(): void
    {
        $id = $this->pose([1]);
        $this->harnais();

        $this->connecte(3, ['can_admin_portal'], 5)
            ->postJson('/permissions/' . self::COMPTE . "/cles/{$id}", ['machine_id' => 1, 'value' => 0])
            ->assertStatus(422)->assertJson(['message' => __('perms.err_cle_derniere_machine')]);

        $this->assertSame([1], $this->machinesDe($id));
    }

    #[Test]
    public function la_bascule_sans_valeur_n_est_pas_un_retrait(): void
    {
        $id = $this->pose([1, 2]);
        $this->harnais();

        $this->connecte(3, ['can_admin_portal'], 5)
            ->postJson('/permissions/' . self::COMPTE . "/cles/{$id}", ['machine_id' => 1])
            ->assertStatus(422);

        $this->assertSame([1, 2], $this->machinesDe($id));
    }
}
