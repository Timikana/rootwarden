<?php

namespace Tests\Feature;

use App\Services\Comptes;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

/**
 * E-399 — ce que le bilan d'import SIGNALE, et ce qu'il a quand meme CREE.
 *
 * ══ LE PIEGE DE CE BILAN, ET IL EST DANS LE MOT ══════════════════════════
 *
 * `imp_err_role` est poussee dans `$bilan['erreurs']` **APRES** la creation,
 * pas a sa place : **la ligne est CREEE ET signalee**. Le titre de la liste est
 * neutre — « :n ligne(s) a signaler » — mais des textes voisins de ce meme
 * bilan disent « ligne ignoree ».
 *
 * *Une assertion qui chercherait « ignoree » dans cette liste passerait donc
 * pour une raison FAUSSE : elle trouverait le mot chez un voisin.* C'est
 * pourquoi chaque test ci-dessous asserte le COUPLE — combien de comptes crees,
 * et quel signal — jamais un mot isole.
 *
 * ══ DEUX SIGNAUX DISTINCTS, ET ILS PEUVENT PARAITRE ENSEMBLE ═════════════
 *
 *     `imp_err_role`      « cette valeur n'est pas un role »      VALIDITE
 *     `imp_rang_ramene`   « votre autorisation ne permettait pas » SECURITE
 *
 * Confondre les deux ferait chercher un probleme de droits la ou il y a une
 * faute de frappe — et l'inverse.
 *
 * ── AUCUN COMPTE REEL N'EST TOUCHE ─────────────────────────────────────────
 *
 * Le socle tourne sur SQLite en memoire sans migration Laravel : la table
 * `users` est CREEE ICI, peuplee ici, et detruite avec le test. `importeCsv`
 * ecrit donc dans une base jetable — pas dans MySQL, pas sur `rw-test-*`, et
 * aucun etat partage ne bouge. *Ce n'est pas une promesse, c'est une propriete :
 * `DB_CONNECTION=sqlite` est pose par `phpunit.xml`.*
 */
class ImportComptesSignalementTest extends TestCase
{
    private Comptes $comptes;

    /** @var list<string> */
    private array $fichiers = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->comptes = app(Comptes::class);

        Schema::create('users', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name', 255);
            $table->string('email', 255)->nullable();
            $table->string('password', 255)->nullable();
            $table->text('ssh_key')->nullable();
            $table->integer('role_id')->default(1);
            $table->tinyInteger('active')->default(1);
            $table->tinyInteger('sudo')->default(0);
            $table->tinyInteger('force_password_change')->default(0);
            $table->dateTime('created_at')->nullable();
            $table->dateTime('password_updated_at')->nullable();
        });
    }

    protected function tearDown(): void
    {
        Schema::dropIfExists('users');
        foreach ($this->fichiers as $f) {
            @unlink($f);
        }
        parent::tearDown();
    }

    private function csv(string $contenu): string
    {
        $chemin = tempnam(sys_get_temp_dir(), 'rw-comptes-') . '.csv';
        file_put_contents($chemin, $contenu);
        $this->fichiers[] = $chemin;

        return $chemin;
    }

    /** @return array{bilan: array<string, mixed>, secrets: list<array<string, string>>} */
    private function importe(string $contenu, int $roleAuteur = 3): array
    {
        return $this->comptes->importeCsv($this->csv($contenu), $roleAuteur);
    }

    private function textes(array $bilan): string
    {
        return implode(' | ', array_column($bilan['erreurs'], 'texte'));
    }

    // ══════════════════════════════════════════════════════════════════════
    // LA LIGNE EST CREEE **ET** SIGNALEE
    // ══════════════════════════════════════════════════════════════════════

    public function test_un_libelle_de_role_INCONNU_cree_le_compte_ET_le_signale(): void
    {
        $r = $this->importe("name,email,role\nzoe,zoe@exemple.test,admni\n");

        // LE COUPLE, et c'est tout l'objet de ce fichier : signaler n'est pas
        // refuser. Asserter le seul signal laisserait croire a un rejet.
        $this->assertSame(1, $r['bilan']['crees'],
            'la ligne a ete REFUSEE alors que le signal n\'est pas un refus');
        $this->assertCount(1, $r['bilan']['erreurs'],
            'la ligne creee n\'est pas signalee : la valeur fautive passe en silence');
        $this->assertSame(1, DB::table('users')->where('name', 'zoe')->count());
        $this->assertSame(Comptes::ROLE_PLANCHER,
            (int) DB::table('users')->where('name', 'zoe')->value('role_id'),
            'le role plancher n\'a pas ete pose');
    }

    public function test_le_signal_CITE_la_valeur_fautive_et_les_valeurs_admises(): void
    {
        // Sans la citation, l'importeur d'un fichier de 500 lignes ne sait pas
        // quoi corriger — et sans la liste des valeurs admises, il ne sait pas
        // par quoi.
        $r = $this->importe("name,email,role\nzoe,zoe@exemple.test,admni\n");
        $texte = $this->textes($r['bilan']);

        $this->assertStringContainsString('admni', $texte,
            'la valeur soumise n\'est pas citee');
        foreach (array_keys(Comptes::IMPORT_ROLES) as $admis) {
            $this->assertStringContainsString($admis, $texte,
                "la valeur admise « $admis » n'est pas citee");
        }
    }

    public function test_la_valeur_citee_est_BORNEE_a_quarante_caracteres(): void
    {
        // Une borne SILENCIEUSE se lit comme une reussite ; celle-ci est mesuree
        // pour qu'un elargissement ou un retrait se voie.
        $longue = str_repeat('x', 200);
        $r = $this->importe("name,email,role\nzoe,zoe@exemple.test,$longue\n");
        $texte = $this->textes($r['bilan']);

        $this->assertStringContainsString(str_repeat('x', 40), $texte);
        $this->assertStringNotContainsString(str_repeat('x', 41), $texte,
            'la valeur fautive est citee au-dela de 40 caracteres');
    }

    public function test_une_cellule_VIDE_ne_signale_RIEN(): void
    {
        /*
         * ⚠ LE CAS QUI N'EST PAS UN SIGNAL, et que l'ancienne expression
         * ecrasait : elle fabriquait le role 1 pour l'absence ET pour `'admni'`.
         * Personne n'a rien demande — crier au loup sur chaque ligne d'un CSV
         * sans colonne `role` rendrait la liste des signaux illisible, donc
         * inutile le jour ou elle porte un vrai signal.
         */
        $r = $this->importe("name,email,role\nzoe,zoe@exemple.test,\n");

        $this->assertSame(1, $r['bilan']['crees']);
        $this->assertSame([], $r['bilan']['erreurs'],
            'une cellule vide est signalee comme une valeur fautive');
        $this->assertSame(Comptes::IMPORT_ROLES[Comptes::IMPORT_ROLE_DEFAUT],
            (int) DB::table('users')->where('name', 'zoe')->value('role_id'));
    }

    public function test_une_colonne_role_ABSENTE_ne_signale_RIEN(): void
    {
        $r = $this->importe("name,email\nzoe,zoe@exemple.test\n");

        $this->assertSame(1, $r['bilan']['crees']);
        $this->assertSame([], $r['bilan']['erreurs']);
    }

    // ══════════════════════════════════════════════════════════════════════
    // LES DEUX SIGNAUX, SEPAREMENT ET ENSEMBLE
    // ══════════════════════════════════════════════════════════════════════

    public function test_un_rang_ramene_est_signale_A_PART_de_la_validite(): void
    {
        // Auteur de role 2 : `admin` est refuse par l'anti-escalade, mais la
        // VALEUR etait valide. Un seul signal, et c'est celui de securite.
        $r = $this->importe("name,email,role\nzoe,zoe@exemple.test,admin\n", 2);

        $this->assertSame(1, $r['bilan']['crees']);
        $this->assertCount(1, $r['bilan']['erreurs']);
        $this->assertSame(__('comptes.imp_rang_ramene'),
            $r['bilan']['erreurs'][0]['texte'],
            'le rang ramene est annonce avec le texte de la VALIDITE');
    }

    public function test_les_DEUX_signaux_paraissent_quand_les_deux_jouent(): void
    {
        /*
         * ⚠ LE CAS QUI JUSTIFIE DEUX DRAPEAUX PLUTOT QU'UN.
         *
         * Auteur de role 1 et valeur inventee : la valeur est invalide (elle
         * devient le plancher) ET l'autorisation refuse ce plancher. Rendre
         * « laquelle des deux » au singulier aurait force a en taire une, et
         * l'importeur aurait cherche une faute de frappe la ou il y a un
         * probleme de droits — ou l'inverse.
         */
        $r = $this->importe("name,email,role\nzoe,zoe@exemple.test,admni\n", 1);

        $this->assertCount(2, $r['bilan']['erreurs'],
            'les deux coercitions ont joue et un seul signal parait');
        $textes = array_column($r['bilan']['erreurs'], 'texte');
        $this->assertContains(__('comptes.imp_rang_ramene'), $textes);
        $this->assertStringContainsString('admni', implode(' ', $textes));
    }

    public function test_chaque_signal_NOMME_sa_ligne_et_son_compte(): void
    {
        // Un signal sans son numero de ligne oblige a relire le fichier ; sans
        // le nom, il ne dit pas DE QUI il parle.
        $r = $this->importe("name,email,role\nzoe,zoe@exemple.test,admni\n"
                            . "max,max@exemple.test,admni\n");

        $this->assertCount(2, $r['bilan']['erreurs']);
        $this->assertSame(['zoe', 'max'], array_column($r['bilan']['erreurs'], 'nom'));
        $this->assertSame([2, 3], array_column($r['bilan']['erreurs'], 'ligne'));
    }

    // ══════════════════════════════════════════════════════════════════════
    // LA PHRASE AJOUTEE DE LA CREATION MANUELLE
    // ══════════════════════════════════════════════════════════════════════

    public function test_la_phrase_AJOUTEE_ne_porte_aucun_jeton_a_substituer(): void
    {
        /*
         * ⚠ CE QUE LE CONTROLEUR FAIT, ET POURQUOI C'EST FRAGILE.
         *
         *     $annonce = rangRamene ? cree_rang_ramene(:nom, :id) : cree(:nom, :id)
         *     if (valeurInvalide) $annonce .= ' ' . __('comptes.cree_valeur_role')
         *
         * La seconde phrase est traduite SANS AUCUN ARGUMENT. Si quelqu'un y
         * ajoute `:nom` — ce qui semblerait une amelioration —, le jeton
         * s'afficherait EN CLAIR a l'ecran. Ce chantier l'a deja paye :
         * « 3 :count serveur(s) disponible(s) », qu'aucun controle d'i18n ne
         * voyait parce qu'ils cherchent des identifiants `module.cle`, pas des
         * jetons.
         *
         * La composition elle-meme vit dans le controleur et demande la route
         * `role:2` + `can_admin_portal` : elle se mesure au banc, pas ici. Ce
         * qui se mesure ici est ce qui la rendrait FAUSSE sans que personne ne
         * la relise.
         */
        foreach (['fr', 'en'] as $langue) {
            $phrase = __('comptes.cree_valeur_role', [], $langue);

            $this->assertIsString($phrase);
            $this->assertStringNotContainsString(':nom', $phrase,
                "[$langue] la phrase AJOUTEE porte `:nom`, qui ne sera jamais "
                . "substitue — elle est traduite sans argument");
            $this->assertStringNotContainsString(':id', $phrase,
                "[$langue] la phrase AJOUTEE porte `:id`, qui ne sera jamais substitue");
        }
    }

    public function test_les_deux_phrases_de_creation_sont_DISTINCTES_dans_les_deux_langues(): void
    {
        // Les rendre identiques — ou l'une vide — ferait disparaitre un signal
        // sans qu'aucune assertion de contenu ne bouge.
        foreach (['fr', 'en'] as $langue) {
            $securite = __('comptes.cree_rang_ramene', ['nom' => 'x', 'id' => 1], $langue);
            $validite = __('comptes.cree_valeur_role', [], $langue);
            $neutre = __('comptes.cree', ['nom' => 'x', 'id' => 1], $langue);

            $this->assertNotSame($securite, $validite, "[$langue]");
            $this->assertNotSame($neutre, $securite, "[$langue]");
            $this->assertNotSame('', trim($validite), "[$langue] phrase de validite vide");
            $this->assertStringNotContainsString('comptes.', $validite,
                "[$langue] la cle n'est pas traduite — elle manque au catalogue");
        }
    }
}
