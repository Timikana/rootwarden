<?php

namespace Tests\Feature;

use App\Services\JournalAudit;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

/**
 * E-415 — le bouton « Sceller » ne scelle plus, et il ne DOIT plus.
 *
 * ══ POURQUOI UN RETRAIT, ET POURQUOI IL EST JUSTE ════════════════════════
 *
 * Mesure du 2026-09-05 : `user_logs` porte 4788 lignes scellees dont la chaine
 * est INTACTE — 4788 `prev_hash` distincts — et 1484 lignes NUES, dont le
 * `prev_hash` est nul pour les 1484.
 *
 *     id 1  prev=GENESIS   self=d36ccba
 *     id 2  prev=(null)    self=(NULL)   <- nue
 *     id 3  prev=d36ccba   self=5a07037  <- reprend id 1, SAUTE id 2
 *
 * **Les nues sont hors chaine PAR CONSTRUCTION** : la tete se calcule en les
 * sautant. Les y rattacher exigerait de reecrire le `prev_hash` des 4788 autres
 * — c'est-a-dire de detruire la seule propriete que la chaine apporte.
 *
 * Les deux scelleurs etaient deux impasses : le legacy avance sa tete et casse a
 * la premiere scellee suivante ; le portage posait 1484 `prev_hash` IDENTIQUES
 * et son `whereNull('self_hash')` interdisait la reprise — **casse ET bloque,
 * irreversible**.
 *
 * ══ CE QUE CE FICHIER VERROUILLE ═════════════════════════════════════════
 *
 * Que le desarmement TIENNE. Un bouton qui promet une reparation impossible est
 * pire qu'un etat qui dit la verite — et rien n'empeche qu'on le remette, parce
 * que le remettre a l'air d'une amelioration.
 *
 * ⚠ CE FICHIER N'A PAS ETE ECRIT AVANT LE CORRECTIF, ET C'ETAIT VOULU. Un test
 * assertant « `scelle` n'ecrit rien » aurait ete ROUGE tant que la methode
 * ecrivait, et un rouge en attente dans un arbre partage fausse un lot — c'est
 * ce qui a coute 50 des 55 FAIL du 03/09. *Le rouge est arrive dans une suite
 * EXISTANTE (`go-adm-audit`, 4 FAIL sur l'ancien bouton), ou il se classe comme
 * decision assumee et non comme regression.*
 *
 * ── AUCUNE DONNEE REELLE N'EST TOUCHEE ────────────────────────────────────
 *
 * `phpunit.xml` pose `DB_CONNECTION=sqlite` en memoire : la table est creee ici,
 * peuplee ici, detruite avec le test. Le journal reel n'est ni lu ni ecrit.
 */
class ScellementDesarmeTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        /*
         * ⚠ QUATRIEME FORME DU REGIME : LE DIALECTE SQL.
         *
         * `parcourt()` appelle `UNIX_TIMESTAMP(created_at)` — une fonction
         * MySQL que SQLite n'a pas. Le socle de test tourne sur SQLite : sans
         * ce relais, les cinq tests qui touchent la base echouent sur
         * « no such function », c'est-a-dire POUR UNE RAISON ETRANGERE A LEUR
         * PROPRIETE.
         *
         * On declare donc la fonction au moteur du harnais. **Ce que ce relais
         * prouve est la LOGIQUE, pas la portabilite** : `JournalAudit` est
         * ecrit pour MySQL et le reste. Si quelqu'un porte ce service sur un
         * autre moteur, ce test passera et le produit cassera — c'est dit ici
         * pour que personne ne lise ce vert comme une garantie de portabilite.
         */
        DB::connection()->getPdo()->sqliteCreateFunction(
            'UNIX_TIMESTAMP',
            static fn (?string $date): int => $date === null ? 0 : (int) strtotime($date),
            1
        );

        Schema::create('user_logs', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id')->nullable();
            $table->string('action', 255)->nullable();
            $table->dateTime('created_at')->nullable();
            $table->string('prev_hash', 128)->nullable();
            $table->string('self_hash', 128)->nullable();
        });

        // Un journal qui REPRODUIT la forme mesuree : des scellees chainees, et
        // des nues intercalees que la chaine saute.
        $tete = JournalAudit::GENESE;
        foreach ([1, 2, 3, 4, 5] as $i) {
            $nue = ($i % 2 === 0);
            $auteur = 90300 + $i;
            $action = "geste-$i";
            $ts = 1_757_000_000 + $i;
            $self = $nue ? null : app(JournalAudit::class)->empreinte($tete, $auteur, $action, $ts);
            DB::table('user_logs')->insert([
                'user_id' => $auteur, 'action' => $action,
                'created_at' => date('Y-m-d H:i:s', $ts),
                'prev_hash' => $nue ? null : $tete,
                'self_hash' => $self,
            ]);
            if (! $nue) {
                $tete = $self;
            }
        }
    }

    protected function tearDown(): void
    {
        Schema::dropIfExists('user_logs');
        parent::tearDown();
    }

    private function journal(): JournalAudit
    {
        return app(JournalAudit::class);
    }

    /** L'etat du journal, tel qu'il est en base. */
    private function empreintesEnBase(): array
    {
        return DB::table('user_logs')->orderBy('id')
            ->get(['id', 'prev_hash', 'self_hash'])
            ->map(static fn ($l) => [$l->id, $l->prev_hash, $l->self_hash])->all();
    }

    // ══════════════════════════════════════════════════════════════════════
    // LA PROPRIETE CENTRALE : `scelle` N'ECRIT RIEN
    // ══════════════════════════════════════════════════════════════════════

    public function test_sceller_n_ecrit_AUCUNE_ligne(): void
    {
        /*
         * Mesure par COMPARAISON D'ETAT, pas par relecture du code : un
         * `UPDATE` ajoute demain dans une methode appelee par `scelle` ne se
         * verrait pas dans une assertion textuelle, et se verrait ici.
         */
        $avant = $this->empreintesEnBase();

        $this->journal()->scelle(false);

        $this->assertSame($avant, $this->empreintesEnBase(),
            'SCELLER A ECRIT. Les lignes nues sont hors chaine PAR CONSTRUCTION : '
            . "les y rattacher exige de reecrire l'empreinte de toutes les autres, "
            . 'et la chaine perd la propriete qu\'elle porte.');
    }

    public function test_sceller_n_ecrit_rien_NON_PLUS_hors_simulation(): void
    {
        // Les deux valeurs du drapeau, parce que `simulation` etait justement ce
        // qui separait « regarder » de « ecrire » AVANT le desarmement.
        $avant = $this->empreintesEnBase();

        $this->journal()->scelle(true);
        $this->journal()->scelle(false);

        $this->assertSame($avant, $this->empreintesEnBase());
    }

    public function test_le_verdict_annonce_ZERO_scellee_et_l_impossibilite(): void
    {
        foreach ([true, false] as $simulation) {
            $r = $this->journal()->scelle($simulation);

            $this->assertSame(0, $r['scellees'],
                'le verdict annonce des lignes scellees alors qu\'aucune ne l\'a ete');
            $this->assertFalse($r['scellement_possible'],
                'le verdict laisse croire que le scellement redeviendra possible');
            $this->assertSame('audit.scellement_impossible', $r['motif'],
                'le motif ne renvoie plus a la cle qui explique POURQUOI');
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // LE CONTRE-CAS : LA VERIFICATION, ELLE, DOIT RESTER JUSTE
    // ══════════════════════════════════════════════════════════════════════

    public function test_la_VERIFICATION_reste_juste_sur_une_chaine_intacte(): void
    {
        /*
         * Sans ce test, un `scelle` qui rendrait un tableau vide passerait les
         * trois precedents. C'est `parcourt()` qui porte toute la valeur du
         * journal : desarmer l'ECRITURE ne doit rien retirer a la LECTURE.
         */
        $r = $this->journal()->scelle(false);

        $this->assertSame(5, $r['total'], 'le parcours ne compte plus toutes les lignes');
        $this->assertSame(2, $r['orphelines'],
            'les lignes nues ne sont plus comptees : leur nombre est ce que '
            . "l'ecran annonce");
        $this->assertNull($r['erreur'],
            'une chaine intacte est declaree incoherente : ' . var_export($r['erreur'], true));
        $this->assertNotNull($r['tete']);
    }

    public function test_la_VERIFICATION_voit_une_chaine_ROMPUE(): void
    {
        // Le contre-cas du contre-cas : si la verification ne detecte plus rien,
        // les tests precedents passent sur un journal casse.
        DB::table('user_logs')->where('id', 3)->update(['prev_hash' => 'empreinte-forgee']);

        $r = $this->journal()->scelle(false);

        $this->assertNotNull($r['erreur'],
            "une chaine ROMPUE est declaree intacte : la verification ne mesure "
            . 'plus rien, et c\'est elle qui porte toute la valeur du journal');
        $this->assertTrue($r['arret_sur_incoherence']);
    }

    // ══════════════════════════════════════════════════════════════════════
    // L'ECRAN OFFRE UN ETAT, PAS UNE ACTION
    // ══════════════════════════════════════════════════════════════════════

    public function test_l_ecran_n_offre_plus_de_bouton_qui_scelle(): void
    {
        $vue = (string) file_get_contents(base_path('resources/views/journal-audit.blade.php'));

        $this->assertStringContainsString('data-rw="audit-verifier"', $vue,
            'la verification a disparu de l\'ecran : mesure invalide');
        $this->assertStringNotContainsString('data-rw="audit-sceller"', $vue,
            'le bouton qui SCELLE est revenu. Il promettrait une reparation '
            . 'impossible — et le remettre a l\'air d\'une amelioration.');
        $this->assertStringContainsString('data-rw="audit-scellement-etat"', $vue,
            "l'etat a disparu : l'ecran ne dit plus que des lignes sont hors chaine");
    }

    public function test_les_deux_cles_de_l_etat_existent_dans_LES_DEUX_langues(): void
    {
        foreach (['fr', 'en'] as $langue) {
            $cles = require base_path("lang/$langue/audit.php");

            $this->assertArrayHasKey('scellement_impossible', $cles, "[$langue]");
            $this->assertArrayHasKey('scellement_impossible_tip', $cles, "[$langue]");
            $this->assertNotSame('', trim((string) $cles['scellement_impossible_tip']),
                "[$langue] l'explication est vide : l'etat dit QUOI sans dire POURQUOI");
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // ⚠ CE QUE LA MESURE A TROUVE, ET QUI N'ETAIT PAS DEMANDE
    // ══════════════════════════════════════════════════════════════════════

    public function test_le_COMPTE_est_fige_dans_le_catalogue_et_derivera(): void
    {
        /*
         * ⚠ « 1484 evenements hors chaine » est ECRIT EN DUR dans les deux
         * catalogues. C'est un nombre MESURE, pose a cote de la grandeur qu'il
         * pretend decrire, et rien ne les relie.
         *
         * Il est juste aujourd'hui : `audit_chain.py` a repris les 11 sites
         * d'insertion nue et le compte restant est 0, donc les nues ne
         * grandissent plus. **Mais si une seule reapparait, le libelle ment — et
         * il mentira en silence**, puisque aucun mecanisme ne le remesure.
         *
         * C'est la famille du `scroll-padding-top: 64px` pose sur un en-tete qui
         * rend 65 : *une constante posee a cote d'une grandeur qu'elle doit
         * decrire finit par diverger, et personne ne remesure un nombre qui a
         * l'air juste.*
         *
         * CE TEST NE DEMANDE PAS DE CORRECTIF — la forme derivee coute une
         * substitution de jeton et c'est un arbitrage de produit. Il verrouille
         * LE FAIT que le nombre est fige, pour que le jour ou on le derive, on
         * le fasse en connaissance de cause plutot que par hasard.
         */
        foreach (['fr', 'en'] as $langue) {
            $cles = require base_path("lang/$langue/audit.php");
            $libelle = (string) $cles['scellement_impossible'];

            $this->assertMatchesRegularExpression('/\d{3,}/', $libelle,
                "[$langue] le compte n'est plus ecrit en dur : s'il est DERIVE "
                . 'maintenant, remplacer ce test par la propriete retenue — il '
                . 'verrouillait une observation, pas une intention.');
            $this->assertStringNotContainsString(':', $libelle,
                "[$langue] un jeton est apparu dans le libelle : le compte est "
                . 'peut-etre derive, verifier avant de conclure');
        }
    }
}
