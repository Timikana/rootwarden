<?php

namespace Tests\Feature;

use App\Services\Comptes;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

/**
 * E-555 ① — LE SUDO GLOBAL, troisieme et dernier geste perdu a l'extinction.
 *
 * ══ CE QUI MANQUAIT ═══════════════════════════════════════════════════════
 *
 * `legacy/adm/api/toggle_sudo.php` le portait. Apres l'archivage, `users.sudo`
 * n'etait plus ecrit que par DEUX `insert` (la creation, gatee
 * `roleAuteur >= 3`). **Retirer le sudo global imposait de supprimer ou
 * d'anonymiser le compte.**
 *
 * ══ CE QUE CE DRAPEAU COMMANDE, MESURE ════════════════════════════════════
 *
 * `ssh_utils.py:937` le SELECT, `configure_servers.py:1058` le porte, et
 * `:1086-1094` decide :
 *
 *     preset par machine != 'none'  -> add_to_sudoers(policy)
 *     preset par machine == 'none'  -> remove_from_sudoers
 *     sinon SI users.sudo           -> add_to_sudoers() = NOPASSWD ALL
 *     sinon                         -> remove_from_sudoers
 *
 * C'est un REPLI : il ne decide que sans politique par machine. Mais quand il
 * decide, il accorde `NOPASSWD ALL`.
 *
 * ⚠ L'EFFET ETAIT DEJA REVOCABLE (poser le preset a 'none', ou retirer l'acces
 * machine — les deux portes). **Ce qui n'etait pas revocable, c'est le
 * DRAPEAU.**
 *
 * ══ DEUX GARDES, ET PAS TROIS ═════════════════════════════════════════════
 *
 *   1. superadministrateur seulement  `:26` -> la ROUTE (`role:3`)
 *   2. pas sur soi-meme               `:46` -> teste ici
 *
 * ⚠ ET JE N'AI PAS AJOUTE « pas le dernier superadmin ». Le parallele avec les
 * deux autres gestes serait tentant, mais le sudo GLOBAL n'a rien a voir avec
 * l'administration du portail : un superadmin sans `users.sudo` administre
 * toujours le portail. **Ajouter la garde serait raisonner par ANALOGIE DE
 * FORME au lieu de regarder l'objet.** Un test le CONSTATE, pour que l'absence
 * soit lue comme un choix.
 */
class SudoGlobalTest extends TestCase
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
            $table->tinyInteger('sudo')->default(0);
        });

        $this->comptes = app(Comptes::class);
    }

    protected function tearDown(): void
    {
        Schema::dropIfExists('users');
        parent::tearDown();
    }

    private function pose(int $id, string $nom, int $role, int $sudo, int $actif = 1): void
    {
        DB::table('users')->insert([
            'id' => $id, 'name' => $nom, 'role_id' => $role,
            'active' => $actif, 'sudo' => $sudo,
        ]);
    }

    private function sudo(int $id): int
    {
        return (int) DB::table('users')->where('id', $id)->value('sudo');
    }

    /* ═══ LE CAS BANAL ══════════════════════════════════════════════════════ */

    public function test_un_superadmin_RETIRE_le_sudo_global(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(9, 'jean', 1, 1);

        $this->assertNull($this->comptes->definitSudoGlobal(9, false, 1));
        $this->assertSame(0, $this->sudo(9), 'le retrait est le geste qui MANQUAIT');
    }

    public function test_et_il_peut_l_accorder(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(9, 'jean', 1, 0);

        $this->assertNull($this->comptes->definitSudoGlobal(9, true, 1));
        $this->assertSame(1, $this->sudo(9));
    }

    /** L'idempotence — la propriete que la bascule du legacy n'avait pas. */
    public function test_le_geste_est_IDEMPOTENT(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(9, 'jean', 1, 1);

        $this->comptes->definitSudoGlobal(9, false, 1);
        $this->comptes->definitSudoGlobal(9, false, 1);
        $this->assertSame(0, $this->sudo(9), 'deux retraits ne doivent pas re-accorder');
    }

    /* ═══ LES GARDES ════════════════════════════════════════════════════════ */

    public function test_on_ne_modifie_PAS_son_propre_sudo(): void
    {
        $this->pose(1, 'chef', 3, 1);

        $this->assertSame('comptes.err_auto_sudo',
            $this->comptes->definitSudoGlobal(1, false, 1));
        $this->assertSame(1, $this->sudo(1), 'et rien ne doit avoir change');
    }

    public function test_un_compte_inconnu_rend_err_inconnu(): void
    {
        $this->pose(1, 'chef', 3, 1);

        $this->assertSame('comptes.err_inconnu',
            $this->comptes->definitSudoGlobal(4242, false, 1));
    }

    /**
     * ⚠ L'ABSENCE DE LA GARDE « DERNIER SUPERADMIN » EST UN CHOIX, PAS UN OUBLI.
     *
     * Les deux autres gestes perdus la portent — la suspension et la
     * retrogradation, parce que les deux peuvent priver le portail de tout
     * administrateur. Le sudo GLOBAL ne peut pas : un superadmin sans
     * `users.sudo` administre toujours le portail, il n'a plus qu'un repli sudo
     * sur les machines.
     *
     *   > Ajouter la garde ici serait raisonner par ANALOGIE DE FORME au lieu de
     *   > regarder l'objet.
     *
     * Ce test CONSTATE l'absence pour qu'elle se lise comme un choix. S'il
     * devient rouge, c'est que quelqu'un a ajoute la garde — et il devra dire
     * pourquoi ici.
     */
    public function test_retirer_le_sudo_du_dernier_superadmin_est_PERMIS(): void
    {
        $this->pose(1, 'chef', 3, 1);   // le SEUL superadmin, actif, avec sudo
        $this->pose(9, 'jean', 1, 0);

        $this->assertNull(
            $this->comptes->definitSudoGlobal(1, false, 9),
            'le sudo global ne conditionne PAS l administration du portail'
        );
        $this->assertSame(0, $this->sudo(1));
    }

    /**
     * TEMOIN DE L'INSTRUMENT : la colonne est bien lue ET ecrite.
     *
     * Sans lui, tous les tests passeraient sur une base vide en rendant
     * `err_inconnu`.
     */
    public function test_temoin_la_colonne_est_lue_et_ecrite(): void
    {
        $this->pose(1, 'chef', 3, 1);
        $this->pose(9, 'jean', 1, 1);

        $this->assertSame(2, (int) DB::table('users')->count());
        $this->assertSame(1, $this->sudo(9), 'la valeur posee doit se relire');
        $this->assertNull($this->comptes->definitSudoGlobal(9, false, 1));
        $this->assertSame(0, $this->sudo(9), 'et l ecriture doit se relire');
    }

    public function test_les_clefs_existent_en_fr_ET_en_en(): void
    {
        $attendues = ['sudo_accorde', 'sudo_retire', 'sudo_titre', 'sudo_donner',
                      'sudo_retirer', 'err_auto_sudo', 'err_sudo_requis'];
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
