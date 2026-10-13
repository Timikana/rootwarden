<?php

namespace Tests\Feature;

use App\Http\Controllers\Auth\ConnexionController;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * IDENTIFIANTS PUBLIÉS — audit du 2026-10-13, C-1.
 *
 * Le dépôt est PUBLIC et publie le mot de passe ET les secrets TOTP des comptes
 * `rw-test-*` (dont un rôle 3), ainsi que plusieurs mots de passe par défaut.
 * Les retirer de l'arbre ne les retire pas de l'historique git : la protection
 * doit tenir MÊME SI ces comptes existent en production.
 *
 * Ces tests ne recopient aucun mot de passe : ils lisent la valeur publiée dans
 * le dépôt, là où un attaquant la lirait.
 */
class IdentifiantsPubliesTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Schema::create('users', function (Blueprint $t) {
            $t->increments('id');
            $t->string('name', 255)->unique();
            $t->string('password', 512);
            $t->integer('role_id')->default(1);
            $t->boolean('active')->default(true);
            $t->text('totp_secret')->nullable();
            $t->integer('failed_attempts')->default(0);
            $t->dateTime('locked_until')->nullable();
            $t->dateTime('last_failed_login_at')->nullable();
            $t->boolean('force_password_change')->default(false);
        });
        Schema::create('login_attempts', function (Blueprint $t) {
            $t->increments('id');
            $t->string('ip_address')->nullable();
            $t->string('username')->nullable();
            $t->boolean('success')->default(false);
            $t->string('step')->nullable();
            $t->dateTime('attempted_at')->nullable();
            $t->dateTime('created_at')->nullable();
        });
        Schema::create('login_history', function (Blueprint $t) {
            $t->increments('id');
            $t->integer('user_id');
            $t->string('status')->nullable();
            $t->string('ip_address')->nullable();
            $t->text('user_agent')->nullable();
            $t->dateTime('created_at')->nullable();
        });
    }

    /** Le mot de passe de test tel qu'il est PUBLIÉ dans le dépôt. */
    private function motDePassePublie(): string
    {
        $source = file_get_contents(base_path('../tests/e2e/_av.mjs'));
        $this->assertNotFalse($source, 'tests/e2e/_av.mjs introuvable : la mesure n a pas lieu');
        $this->assertSame(1, preg_match("/E2E_TEST_PASS \\|\\| '([^']+)'/", $source, $m), 'valeur publiee introuvable');

        return $m[1];
    }

    private function poseCompte(string $nom, string $mdp, int $role = 3): void
    {
        DB::table('users')->insert([
            'name' => $nom, 'password' => password_hash($mdp, PASSWORD_BCRYPT, ['cost' => 4]),
            'role_id' => $role, 'active' => 1, 'totp_secret' => 'chiffre',
        ]);
    }

    private function connexion(string $nom, string $mdp)
    {
        // Ces tests changent `app.env` ; or l'exemption CSRF du harnais repose sur
        // l'environnement `testing` (`runningUnitTests()`). Sans cette ligne, CHAQUE
        // connexion rendait 419 avant d'atteindre le controleur — mesure du
        // 2026-10-13 : le test « production refuse » passait alors POUR RIEN.
        // Le CSRF n'est pas ce qu'on mesure ici ; il l'est dans les suites E2E.
        $this->withoutMiddleware(PreventRequestForgery::class);

        return $this->post('/connexion', ['username' => $nom, 'password' => $mdp]);
    }

    #[Test]
    public function en_production_un_compte_de_test_ne_peut_pas_se_connecter(): void
    {
        $this->app['env'] = 'production';
        $this->poseCompte('rw-test-super', 'Un-Mot-De-Passe-Valide-2026!');

        $r = $this->connexion('rw-test-super', 'Un-Mot-De-Passe-Valide-2026!');

        $r->assertStatus(302);
        $r->assertSessionHasErrors('username');
        $this->assertNotSame(route('second-facteur'), $r->headers->get('Location'),
            'un compte de test a franchi le premier facteur en production');
    }

    #[Test]
    public function hors_production_les_comptes_de_test_restent_utilisables(): void
    {
        // Témoin : les suites E2E du banc de dev s'authentifient avec ces comptes.
        $this->app['env'] = 'local';
        $this->poseCompte('rw-test-super', 'Un-Mot-De-Passe-Valide-2026!');

        $r = $this->connexion('rw-test-super', 'Un-Mot-De-Passe-Valide-2026!');

        $r->assertSessionHasNoErrors();
        $r->assertRedirect(route('second-facteur'));
    }

    #[Test]
    public function le_refus_ne_revele_pas_que_le_compte_existe(): void
    {
        $this->app['env'] = 'production';
        $this->poseCompte('rw-test-super', 'Un-Mot-De-Passe-Valide-2026!');

        // Le MEME message, mot pour mot, pour un compte de banc refuse et pour un
        // identifiant inconnu : sinon le refus revelerait que le compte existe.
        $this->connexion('rw-test-super', 'Un-Mot-De-Passe-Valide-2026!')
            ->assertSessionHasErrors(['username' => __('auth.erreur_identifiants')]);
        $this->connexion('compte-inexistant', 'Un-Mot-De-Passe-Valide-2026!')
            ->assertSessionHasErrors(['username' => __('auth.erreur_identifiants')]);
    }

    #[Test]
    public function un_mot_de_passe_publie_force_son_changement(): void
    {
        $this->app['env'] = 'production';
        $publie = $this->motDePassePublie();
        $this->poseCompte('admin-reel', $publie);

        $r = $this->connexion('admin-reel', $publie);

        $r->assertSessionHasNoErrors();
        $this->assertSame(1, (int) DB::table('users')->where('name', 'admin-reel')->value('force_password_change'),
            'un compte de production au mot de passe PUBLIE garde ce mot de passe');
    }

    #[Test]
    public function un_mot_de_passe_ordinaire_ne_force_rien(): void
    {
        $this->app['env'] = 'production';
        $this->poseCompte('admin-reel', 'Un-Mot-De-Passe-Valide-2026!');

        $this->connexion('admin-reel', 'Un-Mot-De-Passe-Valide-2026!');

        $this->assertSame(0, (int) DB::table('users')->where('name', 'admin-reel')->value('force_password_change'));
    }

    #[Test]
    public function la_liste_porte_des_empreintes_jamais_un_clair(): void
    {
        $this->assertNotEmpty(ConnexionController::EMPREINTES_PUBLIEES);
        foreach (ConnexionController::EMPREINTES_PUBLIEES as $e) {
            $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $e);
        }
        $this->assertContains(hash('sha256', $this->motDePassePublie()), ConnexionController::EMPREINTES_PUBLIEES,
            'le mot de passe publie le plus repandu n est pas dans la liste');
    }
}
