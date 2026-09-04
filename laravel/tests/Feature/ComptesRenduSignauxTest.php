<?php

namespace Tests\Feature;

use App\Services\Comptes;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

/**
 * E-399 / E-397 — les trois proprietes inscrites `NON MESURE`, et deux d'entre
 * elles n'exigeaient rien de ce qu'on leur pretait.
 *
 * ══ POURQUOI ELLES ETAIENT DECLAREES NON MESURABLES ══════════════════════
 *
 * Le motif inscrit etait « exige de creer un compte reel dans une base
 * partagee ». C'est vrai du CHEMIN D'ACCES — la route est gardee `role:2` +
 * `can_admin_portal` — et FAUX de la PROPRIETE :
 *
 *     2. le bilan d'import REND chaque signal, avec son nom et sa ligne
 *     3. le mot de passe genere PARAIT a l'ecran, une fois
 *        -> les DEUX vivent dans une VUE, et une vue se rend avec une charge
 *           FORGEE : aucune session, aucune base, aucun HTTP.
 *
 *     1. les deux phrases paraissent ENSEMBLE
 *        -> une session forgee `role_id = 2` et un double de `Droits`, que le
 *           socle de ces tests installe deja. Pas un compte.
 *
 * > **« Il faut un compte pour ATTEINDRE la route » est vrai ; « il faut un
 * > compte pour MESURER la propriete » ne l'est pas.**
 *
 * ⚠ CE RELEVE M'A ETE TRANSMIS, ET JE L'AI EPROUVE AVANT DE L'ECRIRE : rendu de
 * la vue avec une charge forgee, 29 966 octets, les trois motifs presents. Ce
 * qui suit mesure la propriete, pas la description qu'on m'en a faite.
 *
 * ── CE QUI RESTE VRAI, ET QUI VIENT DE LA SESSION 1 ────────────────────────
 *
 * `rolePose` ne peut pas declencher `rangRamene` pour un auteur de role 3
 * (`$roleAuteur < 3` le garde). **Le cas « les deux drapeaux » est donc
 * INATTEIGNABLE en superadministrateur** — et une suite qui s'authentifierait en
 * superadmin par commodite mesurerait la composition SANS JAMAIS L'EXERCER.
 * C'est pourquoi le test de composition force un auteur de role 2.
 *
 * ── AUCUN COMPTE REEL, ET C'EST UNE PROPRIETE ──────────────────────────────
 *
 * `phpunit.xml` pose `DB_CONNECTION=sqlite` en memoire. Les tables sont creees
 * ici et detruites avec le test. Le refus du compte jetable est maintenu : il
 * n'a jamais ete contourne, il s'est revele inutile.
 */
class ComptesRenduSignauxTest extends TestCase
{
    private const AUTEUR = 90201;

    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('users', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name', 255);
            $table->string('email', 255)->nullable();
            $table->string('company', 255)->nullable();
            $table->string('password', 255)->nullable();
            $table->text('ssh_key')->nullable();
            $table->integer('role_id')->default(1);
            $table->tinyInteger('active')->default(1);
            $table->tinyInteger('sudo')->default(0);
            $table->tinyInteger('force_password_change')->default(0);
            $table->dateTime('created_at')->nullable();
            $table->dateTime('password_updated_at')->nullable();
        });
        /*
         * ⚠ LE GABARIT INTERROGE LA BASE, ET MA PREMIERE SONDE NE L'A PAS VU.
         *
         * J'ai eprouve le releve qu'on me transmettait par un script autonome —
         * rendu OK, 29 966 octets, les trois motifs presents. Il tournait contre
         * MYSQL, ou toutes les tables existent. Dans le socle de test
         * (`DB_CONNECTION=sqlite`, aucune migration Laravel), `layouts.portail`
         * leve : `no such table: permissions`, via
         * `Notifications::nonLues()` et le calcul des droits du menu.
         *
         * *J'ai verifie la bonne propriete dans le mauvais REGIME — la faute que
         * je poursuis depuis une semaine, commise en verifiant celle d'un autre.*
         *
         * Les tables du GABARIT sont donc creees ici aussi. Elles restent vides :
         * ce fichier mesure ce que la vue REND, pas ce que la base contient.
         *
         * La liste est DERIVEE des services que le gabarit appelle — `Droits`,
         * `Notifications`, `Navigation`, `Permissions` — et non decouverte une
         * par une en relançant : la premiere levee nommait `permissions`, la
         * seconde `temporary_permissions`, et rien ne disait combien il en
         * restait. *Un defaut qu'on decouvre par iteration ne dit jamais quand
         * il s'arrete.*
         */
        Schema::create('permissions', function (Blueprint $table) {
            $table->integer('user_id')->primary();
        });
        Schema::create('temporary_permissions', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id')->nullable();
            $table->string('permission', 64)->nullable();
            $table->dateTime('expires_at')->nullable();
        });
        Schema::create('user_machine_access', function (Blueprint $table) {
            $table->integer('user_id')->nullable();
            $table->integer('machine_id')->nullable();
        });
        Schema::create('notification_preferences', function (Blueprint $table) {
            $table->integer('user_id')->nullable();
            $table->string('event_type', 64)->nullable();
        });
        Schema::create('machines', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name', 255)->nullable();
        });
        Schema::create('notifications', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id')->nullable();
            $table->integer('role_min')->nullable();
            $table->dateTime('lue_le')->nullable();
            $table->dateTime('created_at')->nullable();
        });
        Schema::create('user_logs', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id')->nullable();
            $table->string('action', 255)->nullable();
            $table->dateTime('created_at')->nullable();
            $table->string('prev_hash', 128)->nullable();
            $table->string('self_hash', 128)->nullable();
        });
    }

    protected function tearDown(): void
    {
        Schema::dropIfExists('user_logs');
        Schema::dropIfExists('notifications');
        Schema::dropIfExists('machines');
        Schema::dropIfExists('notification_preferences');
        Schema::dropIfExists('user_machine_access');
        Schema::dropIfExists('temporary_permissions');
        Schema::dropIfExists('permissions');
        Schema::dropIfExists('users');
        parent::tearDown();
    }

    /**
     * La vue, rendue avec une charge FORGEE.
     *
     * @param  array<string, mixed>  $surcharge
     */
    private function vue(array $surcharge = []): string
    {
        session()->put(['utilisateur_id' => self::AUTEUR, 'role_id' => 3]);

        return view('comptes', array_merge([
            'comptes' => [],
            'roles' => Comptes::ROLES,
            'import' => null,
            'importColonnes' => Comptes::IMPORT_COLONNES,
            'importMaxKo' => 512,
            'importRoles' => Comptes::IMPORT_ROLES,
            'libelles' => __('comptes'),
            'longueurMinimale' => Comptes::LONGUEUR_MINIMALE,
            'estSuperadmin' => true,
            'secretsImport' => [],
        ], $surcharge))->render();
    }

    // ══════════════════════════════════════════════════════════════════════
    // PROPRIETE 2 — le bilan REND chaque signal, avec son nom et sa ligne
    // ══════════════════════════════════════════════════════════════════════

    public function test_chaque_signal_du_bilan_est_RENDU_avec_son_nom_et_sa_ligne(): void
    {
        $html = $this->vue(['import' => [
            'lignes' => 3, 'crees' => 2, 'manquantes' => [], 'tronque' => false,
            'erreurs' => [
                ['ligne' => 2, 'nom' => 'zoe', 'texte' => 'PREMIER-SIGNAL'],
                ['ligne' => 5, 'nom' => 'max', 'texte' => 'SECOND-SIGNAL'],
            ],
        ]]);

        // Les DEUX, et pas seulement le premier : une liste qui n'affiche que
        // sa premiere entree se lit comme un bilan complet.
        foreach ([['2', 'zoe', 'PREMIER-SIGNAL'], ['5', 'max', 'SECOND-SIGNAL']] as [$ligne, $nom, $texte]) {
            $this->assertStringContainsString($texte, $html, "texte de $nom absent");
            $this->assertStringContainsString($nom, $html, "nom $nom absent");
            $this->assertStringContainsString($ligne, $html, "ligne $ligne absente");
        }
    }

    public function test_un_bilan_SANS_signal_ne_rend_aucune_liste_vide(): void
    {
        // Une liste vide affichee sous un titre « lignes a signaler » ferait
        // chercher un signal qui n'existe pas. Contre-cas du test precedent.
        $html = $this->vue(['import' => [
            'lignes' => 1, 'crees' => 1, 'manquantes' => [], 'tronque' => false,
            'erreurs' => [],
        ]]);

        $this->assertStringNotContainsString('data-rw="comptes-import-erreurs"', $html);
    }

    public function test_le_texte_d_un_signal_est_ECHAPPE(): void
    {
        /*
         * Le texte porte une valeur SOUMISE — le libelle de role fautif, cite
         * depuis le CSV. Un fichier d'import est un contenu que l'utilisateur
         * FABRIQUE : s'il n'etait pas echappe, il porterait du balisage jusque
         * dans la page d'administration.
         */
        $html = $this->vue(['import' => [
            'lignes' => 1, 'crees' => 1, 'manquantes' => [], 'tronque' => false,
            'erreurs' => [['ligne' => 2, 'nom' => '<script>x</script>',
                           'texte' => '<img src=x onerror=alerte>']],
        ]]);

        $this->assertStringNotContainsString('<script>x</script>', $html,
            'le NOM soumis traverse sans etre echappe');
        $this->assertStringNotContainsString('<img src=x', $html,
            'le TEXTE du signal traverse sans etre echappe');
        $this->assertStringContainsString('&lt;img src=x', $html,
            "le texte n'est pas rendu du tout : l'echappement ne se mesure que "
            . 'si la valeur PARAIT');
    }

    // ══════════════════════════════════════════════════════════════════════
    // PROPRIETE 3 — le mot de passe genere PARAIT, une fois
    // ══════════════════════════════════════════════════════════════════════

    public function test_le_mot_de_passe_genere_PARAIT_a_l_ecran(): void
    {
        /*
         * E-397 : le legacy JETTE le mot de passe genere a l'import
         * (`import_csv.php:148`) — ses comptes importes sont inutilisables, sans
         * acces ni recuperation. Le portage le rend a l'ecran UNE FOIS. S'il ne
         * paraissait pas, le compte serait cree et inaccessible : un echec
         * SILENCIEUX, avec un compte bien reel derriere.
         */
        $html = $this->vue(['secretsImport' => [
            ['nom' => 'zoe', 'mdp' => 'SECRET-EN-CLAIR-1234'],
            ['nom' => 'max', 'mdp' => 'AUTRE-SECRET-5678'],
        ]]);

        $this->assertStringContainsString('SECRET-EN-CLAIR-1234', $html);
        $this->assertStringContainsString('AUTRE-SECRET-5678', $html,
            'seul le premier secret parait : les comptes suivants seraient '
            . 'crees et inaccessibles');
        $this->assertStringContainsString('zoe', $html);
    }

    public function test_sans_secret_la_section_ne_parait_PAS(): void
    {
        // Contre-cas indispensable : une section de secrets rendue vide sur
        // chaque affichage de la page apprendrait au lecteur a l'ignorer.
        $html = $this->vue(['secretsImport' => []]);

        $this->assertStringNotContainsString('comptes-secrets-remis', $html);
    }

    // ══════════════════════════════════════════════════════════════════════
    // PROPRIETE 1 — les deux phrases paraissent ENSEMBLE
    // ══════════════════════════════════════════════════════════════════════

    public function test_la_phrase_de_VALIDITE_parait_seule_sur_une_valeur_inventee(): void
    {
        $reponse = $this->connecte(2, ['can_admin_portal'], self::AUTEUR)
            ->post('/comptes', [
                'name' => 'valeur-inventee',
                'email' => 'inventee@exemple.test',
                'role_id' => '99',
            ]);

        /*
         * ⚠ L'ANNONCE SE LIT DANS LA REPONSE, PAS DANS LA SESSION.
         *
         * Le controleur pose `session()->now('succes', …)` — `now()` ne flashe
         * QUE pour la requete courante — puis rend la VUE directement plutot que
         * de rediriger (E-397 : `SESSION_DRIVER=file` deposerait le mot de passe
         * genere sur le disque). Apres la reponse, `session('succes')` est VIDE.
         * Mesure : statut 200, 1 compte en base, session vide — un rouge qui
         * accusait la composition alors qu'il disait ou elle vit.
         */
        $annonce = $reponse->getContent();

        $this->assertSame(200, $reponse->getStatusCode(),
            'la creation ne rend plus la vue directement — E-397');
        $this->assertSame(1, DB::table('users')->count(), "le compte n'a pas ete cree");
        // ⚠ `e()` ET NON LA CHAINE BRUTE. Blade ECHAPPE : « n'est » devient
        // « n&#039;est ». Comparer le catalogue brut au HTML rendu fait echouer
        // sur toute phrase portant une apostrophe — et passer sur celles qui
        // n'en ont pas, ce qui rend l'erreur intermittente selon la phrase.
        // *Mesurer ce que le navigateur RECOIT, pas ce que le catalogue DIT.*
        $this->assertStringContainsString(e(__('comptes.cree_valeur_role')), $annonce,
            'la phrase de VALIDITE manque');
        $this->assertStringNotContainsString('inférieur au vôtre', $annonce,
            'la phrase de SECURITE parait alors que le rang n\'a pas ete ramene : '
            . 'une valeur inventee tombe sur le PLANCHER, qui est sous le rang de '
            . "tout auteur admis sur cette route");
    }

    public function test_la_phrase_de_SECURITE_parait_seule_sur_un_rang_egal(): void
    {
        // Auteur 2 demandant 2 : valeur VALIDE, mais « egal n'est pas
        // inferieur ». Un seul drapeau, celui de securite.
        $reponse = $this->connecte(2, ['can_admin_portal'], self::AUTEUR)
            ->post('/comptes', [
                'name' => 'rang-egal',
                'email' => 'egal@exemple.test',
                'role_id' => '2',
            ]);

        $annonce = $reponse->getContent();

        $this->assertSame(1, DB::table('users')->count());
        $this->assertStringContainsString('inférieur au vôtre', $annonce,
            'la phrase de SECURITE manque : le rang a ete ramene sans le dire');
        $this->assertStringNotContainsString(e(__('comptes.cree_valeur_role')), $annonce,
            'la phrase de VALIDITE parait alors que la valeur etait valide');
    }

    public function test_aucune_phrase_de_coercition_quand_rien_n_est_coerce(): void
    {
        // Contre-cas : sans lui, une composition qui ajouterait TOUJOURS les
        // deux phrases passerait les deux tests precedents.
        $reponse = $this->connecte(2, ['can_admin_portal'], self::AUTEUR)
            ->post('/comptes', [
                'name' => 'sans-coercition',
                'email' => 'ok@exemple.test',
                'role_id' => '1',
            ]);

        $annonce = $reponse->getContent();

        $this->assertSame(1, DB::table('users')->count());
        $this->assertStringNotContainsString(e(__('comptes.cree_valeur_role')), $annonce);
        $this->assertStringNotContainsString('inférieur au vôtre', $annonce);
    }

    // ══════════════════════════════════════════════════════════════════════
    // ⚠ CE QUE LA MESURE A TROUVE, ET QUI N'ETAIT PAS DEMANDE
    // ══════════════════════════════════════════════════════════════════════

    public function test_le_cas_DEUX_PHRASES_est_INATTEIGNABLE_par_les_routes(): void
    {
        /*
         * ⚠ LA COMPOSITION DES DEUX PHRASES NE PEUT PAS SE PRODUIRE EN SERVICE.
         *
         * On m'a demande de mesurer « les deux phrases paraissent ensemble », et
         * la note qu'on m'avait transmise disait que le cas exigeait un auteur
         * de role 2. La mesure dit autre chose — table complete, 15 couples :
         *
         *     auteur | demande | valeurInvalide | rangRamene
         *       1    | null/99 |     true       |   true      <== LES DEUX
         *       2    | null/99 |     true       |   false
         *       3    | null/99 |     true       |   false
         *
         * **Le cas « les deux » n'existe que pour un auteur de role 1.** Une
         * valeur invalide tombe toujours sur le PLANCHER (1), et l'anti-escalade
         * ne mord que si ce plancher est `>=` au rang de l'auteur — donc jamais
         * au-dessus du role 1.
         *
         * Or LES DEUX ROUTES qui appellent ceci — creation manuelle et import
         * CSV — sont gardees `role:2` + `can_admin_portal`. **Aucun auteur de
         * role 1 ne les atteint.**
         *
         * DONC : la composition est correcte, commentee, defendue — et son cas
         * ne se produit sur AUCUN chemin de production. Ce n'est pas un defaut :
         * c'est du code juste dont la condition est fermee ailleurs. **Transmis,
         * non tranche** — le retirer perdrait la propriete si une route
         * s'ouvrait un jour a un auteur de role 1, et le garder coute un `if`.
         *
         * Ce test verrouille le FAIT, pas l'opinion : s'il rougit, une route a
         * change de garde ou le plancher a bouge, et il faut relire la
         * composition avant de conclure.
         */
        $comptes = app(Comptes::class);
        $deuxDrapeaux = [];
        foreach ([1, 2, 3] as $auteur) {
            foreach ([null, 1, 2, 3, 99] as $demande) {
                $p = $comptes->rolePose($demande, $auteur);
                if ($p->valeurInvalide && $p->rangRamene) {
                    $deuxDrapeaux[] = $auteur;
                }
            }
        }

        $this->assertSame([1, 1], $deuxDrapeaux,
            'le cas « les deux drapeaux » est desormais atteignable par un auteur '
            . 'de role ' . implode('/', array_unique($deuxDrapeaux)) . '. Les deux '
            . 'routes appelantes sont gardees `role:2` : si un auteur de role 2 ou '
            . '3 y arrive, la composition des deux phrases devient exercable, et '
            . 'ce fichier doit alors la mesurer par la route.');
    }
}
