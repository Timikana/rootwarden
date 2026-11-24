<?php

namespace Tests\Feature;

use App\Http\Controllers\FindingsCveController;
use App\Services\ScansCve;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * `/scan-cve` en 500 en production : « Allowed memory size of 134217728 bytes
 * exhausted » sur le `json_encode($findings)` du gabarit. La page mettait TOUS
 * les findings du dernier scan de CHAQUE machine visible — 85 133 pour 32
 * machines — et PHP tourne a la limite par defaut de l'image, 128 Mo.
 *
 * La page ne rend plus que le resume ; le detail d'une machine arrive par page,
 * a l'ouverture de sa carte, par `GET /scan-cve/{machine}/findings`.
 *
 * LA LIMITE EST CELLE DE LA PRODUCTION, POSEE ICI : 128 Mo, la valeur par defaut
 * de l'image. Elle est fixee au demarrage du processus plutot que lue dans
 * l'environnement — la CI execute PHPUnit sous un autre `memory_limit` que
 * l'image. Le premier test verifie qu'elle a pris avant de mesurer : une limite
 * relevee ferait passer n'importe quoi.
 *
 * UN PROCESSUS PAR TEST. Dans la suite complete, le processus PHPUnit tient deja
 * ce que les centaines de tests precedents ont laisse : le temoin y depassait
 * les 128 Mo pour une raison qui n'etait pas la sienne. Isole, chaque test part
 * a vide, comme une requete.
 */
#[RunTestsInSeparateProcesses]
#[PreserveGlobalState(false)]
class ScanCveMemoireTest extends TestCase
{
    private const MACHINES = 32;
    private const PAR_MACHINE = 3125;   // 32 x 3 125 = 100 000

    /** Ce que la page a le droit d'allouer pendant la requete, tout compris. */
    private const BUDGET_OCTETS = 24 * 1024 * 1024;

    protected function setUp(): void
    {
        // Processus neuf (un par test) : il tient bien moins de 128 Mo, donc la
        // limite se pose. `ini_set` rend false sinon, et le test le dira.
        ini_set('memory_limit', '128M');
        parent::setUp();
        // SQLite ne connait pas FIELD(), que le tri des severites emploie (MySQL).
        $field = static function ($valeur, ...$liste) {
            $i = array_search($valeur, $liste, true);

            return $i === false ? 0 : $i + 1;
        };
        $pdo = DB::connection()->getPdo();
        method_exists($pdo, 'createFunction')
            ? $pdo->createFunction('FIELD', $field, -1)
            : $pdo->sqliteCreateFunction('FIELD', $field, -1);

        Schema::create('machines', function (Blueprint $t) {
            $t->increments('id');
            $t->string('name');
            $t->string('ip')->default('10.0.0.1');
            $t->string('environment')->nullable();
            $t->string('criticality')->nullable();
            $t->string('lifecycle_status')->nullable();
        });
        Schema::create('user_machine_access', function (Blueprint $t) {
            $t->integer('user_id');
            $t->integer('machine_id');
        });
        Schema::create('cve_scans', function (Blueprint $t) {
            $t->increments('id');
            $t->integer('machine_id');
            $t->dateTime('scan_date')->nullable();
            foreach (['packages_scanned', 'cve_count', 'critical_count', 'high_count', 'medium_count', 'low_count'] as $c) {
                $t->integer($c)->default(0);
            }
            $t->float('min_cvss')->default(7);
            $t->string('status')->default('completed');
        });
        Schema::create('cve_findings', function (Blueprint $t) {
            $t->increments('id');
            $t->integer('scan_id')->index();
            $t->string('cve_id');
            $t->string('package_name')->default('openssl');
            $t->string('package_version')->default('3.0.2');
            $t->float('cvss_score')->default(7.5);
            $t->string('severity')->nullable();
            $t->text('summary')->nullable();
            $t->float('epss_score')->nullable();
            $t->integer('kev')->default(0);
            $t->date('kev_date_added')->nullable();
            $t->float('priority_score')->nullable();
            $t->string('priority_label')->nullable();
        });
        Schema::create('cve_whitelist', function (Blueprint $t) {
            $t->increments('id');
            $t->string('cve_id');
            $t->integer('machine_id')->nullable();
            $t->date('expires_at')->nullable();
        });
        Schema::create('cve_remediation', function (Blueprint $t) {
            $t->increments('id');
            $t->string('cve_id');
            $t->integer('machine_id');
            $t->string('status');
        });
        // Le gabarit compte les notifications non lues.
        Schema::create('notifications', function (Blueprint $t) {
            $t->increments('id');
            $t->integer('user_id')->nullable();
            $t->dateTime('read_at')->nullable();
        });
    }

    /** Une machine, attribuee au compte de test, et son scan. Rend l'id du scan. */
    private function machineScannee(int $id, string $nom, int $findings, ?callable $ligne = null): int
    {
        DB::table('machines')->insert(['id' => $id, 'name' => $nom]);
        DB::table('user_machine_access')->insert(['user_id' => self::COMPTE, 'machine_id' => $id]);
        $scan = DB::table('cve_scans')->insertGetId([
            'machine_id' => $id, 'scan_date' => '2026-11-20 03:00:00', 'cve_count' => $findings,
            'critical_count' => intdiv($findings, 4), 'high_count' => intdiv($findings, 4),
        ]);

        // Par paquets : un seul INSERT de 3 125 lignes depasserait la limite de
        // variables de SQLite, et un tableau de 100 000 lignes, la memoire.
        $resume = str_repeat('Une vulnerabilite dans le traitement des certificats. ', 4);
        for ($debut = 0; $debut < $findings; $debut += 500) {
            $lot = [];
            for ($i = $debut; $i < min($findings, $debut + 500); $i++) {
                $lot[] = ($ligne ?? static fn (int $i) => [])($i) + [
                    'scan_id' => $scan,
                    'cve_id' => sprintf('CVE-%d-%05d', 2015 + $i % 10, $i),
                    'package_name' => 'openssl',
                    'severity' => ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'][$i % 4],
                    'summary' => $resume,
                    'kev' => $i % 100 === 0 ? 1 : 0,
                    'epss_score' => 0.01,
                    'priority_score' => $i % 997,
                    'priority_label' => 'calcule',
                ];
            }
            DB::table('cve_findings')->insert($lot);
        }

        return $scan;
    }

    private function parc(): void
    {
        for ($m = 1; $m <= self::MACHINES; $m++) {
            $this->machineScannee($m, sprintf('srv-%02d', $m), self::PAR_MACHINE);
        }
    }

    /** Le pic d'allocation PHP pendant `$geste`, au-dessus de ce qui etait deja tenu. */
    private function pic(callable $geste): array
    {
        gc_collect_cycles();
        $avant = memory_get_usage();
        memory_reset_peak_usage();
        $resultat = $geste();

        return [memory_get_peak_usage() - $avant, $resultat];
    }

    /* ═══ La page ═══════════════════════════════════════════════════════════ */

    #[Test]
    public function la_page_repond_200_sous_128m_avec_100_000_findings(): void
    {
        $this->assertSame('128M', ini_get('memory_limit'),
            'la limite de la production n\'a pas pu etre posee : le test ne mesurerait rien');
        $this->parc();
        $this->assertSame(100000, DB::table('cve_findings')->count());

        [$pic, $reponse] = $this->pic(fn () => $this->connecte(1, ['can_scan_cve'])->get('/scan-cve'));

        $reponse->assertOk();
        $this->assertLessThan(self::BUDGET_OCTETS, $pic,
            sprintf('la page a alloue %.1f Mo pour un resume', $pic / 1048576));

        $html = $reponse->getContent();
        $this->assertStringNotContainsString('id="cve-findings"', $html, 'les findings ne partent plus dans la page');
        $this->assertStringNotContainsString('id="cve-suivi"', $html);
        // Le resume et les facettes sont la, comptes en SQL.
        $this->assertStringContainsString('3125 CVE', $html);
        $this->assertStringContainsString('data-sev="CRITICAL">CRITICAL (782)', $html);
        $this->assertStringContainsString('KEV (32)', $html);
        $this->assertStringContainsString(route('scan-cve.findings', ['machine' => 7]), $html);
    }

    /**
     * LE TEMOIN DE L'INSTRUMENT : la meme mesure, sur l'ancien chemin et sur le
     * TIERS des donnees, depasse le budget que la page tient avec tout le parc.
     * Sans lui, un pic toujours nul passerait le test ci-dessus.
     */
    #[Test]
    public function temoin_l_ancien_chargement_depasse_le_budget_sur_un_tiers_du_parc(): void
    {
        $scans = [];
        for ($m = 1; $m <= 10; $m++) {
            $scans[] = $this->machineScannee($m, "srv-$m", self::PAR_MACHINE);
        }
        $service = app(ScansCve::class);

        [$pic] = $this->pic(function () use ($scans, $service) {
            $tout = [];
            foreach ($scans as $s) {
                $tout[$s] = $service->findingsPourAffichage($s);
            }

            return json_encode($tout);
        });

        $this->assertGreaterThan(self::BUDGET_OCTETS, $pic,
            sprintf('31 250 findings charges en entier n\'ont pris que %.1f Mo', $pic / 1048576));
    }

    /* ═══ Le detail, par page ═══════════════════════════════════════════════ */

    private function page(int $machine, array $params = [], int $role = 1)
    {
        return $this->connecte($role, ['can_scan_cve'])
            ->getJson(route('scan-cve.findings', ['machine' => $machine] + $params));
    }

    #[Test]
    public function le_detail_arrive_par_pages_de_cinquante(): void
    {
        $this->parc();

        [$pic, $r] = $this->pic(fn () => $this->page(7));
        $r->assertOk()->assertJsonPath('total', 3125)->assertJsonPath('page', 1)
          ->assertJsonPath('par_page', FindingsCveController::PAR_PAGE);
        $this->assertCount(50, $r->json('lignes'));
        $this->assertLessThan(self::BUDGET_OCTETS, $pic);

        $derniere = $this->page(7, ['page' => 63]);
        $this->assertCount(25, $derniere->json('lignes'), '3125 = 62 x 50 + 25');
        $this->assertSame([], $this->page(7, ['page' => 64])->json('lignes'));
    }

    #[Test]
    public function les_pages_mises_bout_a_bout_rendent_l_ordre_de_l_export(): void
    {
        // Des EGALITES partout : meme kev, meme priorite, meme severite, meme
        // score. Sans departage, une ligne peut apparaitre sur deux pages.
        $scan = $this->machineScannee(1, 'srv-1', 180, static fn () => [
            'priority_score' => 5, 'severity' => 'HIGH', 'kev' => 0,
        ]);
        DB::table('cve_findings')->where('scan_id', $scan)->update(['kev' => 0, 'priority_score' => 5, 'severity' => 'HIGH']);

        $vu = [];
        DB::enableQueryLog();
        for ($p = 1; $p <= 4; $p++) {
            array_push($vu, ...array_column($this->page(1, ['page' => $p])->json('lignes'), 'c'));
        }
        // SQLite rend les egalites dans un ordre stable : sans departage, ce test
        // resterait vert ici et la pagination sauterait des lignes sur MySQL. Le
        // departage se lit donc dans la requete reellement emise.
        $pages = array_values(array_filter(array_column(DB::getQueryLog(), 'query'),
            static fn ($q) => str_contains($q, 'from "cve_findings"') && str_contains($q, 'limit')));
        $this->assertNotEmpty($pages, 'temoin : la requete paginee a ete capturee');
        $this->assertMatchesRegularExpression('/order by .*"cvss_score" desc, "id" asc limit/', $pages[0]);

        $this->assertSame(array_map(static fn ($f) => $f->cve_id, app(ScansCve::class)->resultats($scan)), $vu);
        $this->assertCount(180, array_unique($vu));
    }

    #[Test]
    public function chaque_filtre_rend_exactement_ce_que_sa_facette_annonce(): void
    {
        $scan = $this->machineScannee(1, 'srv-1', 400, static fn (int $i) => match (true) {
            $i === 0 => ['severity' => null],
            $i === 1 => ['severity' => ''],
            $i === 2 => ['cve_id' => 'GHSA-xxxx-yyyy'],
            $i === 3 => ['package_name' => 'lib100%_pur'],
            default => [],
        });
        $f = app(ScansCve::class)->facettesParScan([$scan])[$scan];

        $this->assertSame(400, $f['total']);
        $this->assertSame(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'], array_keys($f['severites']));
        $this->assertSame(2, $f['severites']['NONE'], 'severite NULL et vide comptent pour NONE');
        $this->assertSame(1, $f['annees']['?'], 'un identifiant sans annee');

        foreach ($f['severites'] as $sev => $n) {
            $this->assertSame($n, $this->page(1, ['severite' => $sev])->json('total'), "severite $sev");
        }
        foreach ($f['annees'] as $an => $n) {
            $this->assertSame($n, $this->page(1, ['annee' => (string) $an])->json('total'), "annee $an");
        }
        $this->assertSame($f['kev'], $this->page(1, ['severite' => 'KEV'])->json('total'));
        $this->assertGreaterThan(0, $f['kev'], 'temoin : il y a des KEV a filtrer');
    }

    #[Test]
    public function la_recherche_porte_sur_cve_paquet_et_resume_et_un_joker_tape_reste_un_caractere(): void
    {
        $this->machineScannee(1, 'srv-1', 400, static fn (int $i) => match ($i) {
            3 => ['package_name' => 'lib100%_pur'],
            4 => ['summary' => 'Debordement dans Kerberos'],
            default => [],
        });

        $this->assertSame(1, $this->page(1, ['q' => 'CVE-2015-00010'])->json('total'));
        $this->assertSame(1, $this->page(1, ['q' => 'kerberos'])->json('total'), 'insensible a la casse');
        $this->assertSame(1, $this->page(1, ['q' => '100%_'])->json('total'));
        $this->assertSame(1, $this->page(1, ['q' => '%'])->json('total'), '% tape cherche un %, pas les 400 lignes');
        $this->assertSame(400, $this->page(1, ['q' => 'openssl'])->json('total') + 1, 'temoin : le paquet commun');
    }

    #[Test]
    public function un_filtre_hors_liste_est_refuse(): void
    {
        $this->machineScannee(1, 'srv-1', 10);

        $this->page(1, ['severite' => 'URGENT'])->assertStatus(422);
        $this->page(1, ['annee' => '20x5'])->assertStatus(422);
        $this->page(1, ['page' => 0])->assertStatus(422);
        $this->page(1, ['q' => str_repeat('a', 101)])->assertStatus(422);
        $this->page(1, ['severite' => 'high'])->assertOk();
    }

    #[Test]
    public function le_perimetre_est_celui_de_la_page(): void
    {
        $this->machineScannee(1, 'srv-1', 10);
        $this->machineScannee(2, 'srv-2', 10);
        DB::table('user_machine_access')->where('machine_id', 2)->delete();
        $this->machineScannee(3, 'srv-3', 10);
        DB::table('machines')->where('id', 3)->update(['lifecycle_status' => 'archived']);

        $this->page(1)->assertOk();
        $this->page(2)->assertNotFound();                  // non attribuee a un role 1
        $this->page(2, [], 2)->assertOk();                 // un role 2 voit tout le parc...
        $this->page(3, [], 3)->assertNotFound();           // ...sauf ce qui est archive
        $this->page(99)->assertNotFound();
        $this->connecte(1, [])->getJson(route('scan-cve.findings', ['machine' => 1]))->assertForbidden();
    }

    #[Test]
    public function une_machine_jamais_scannee_rend_une_liste_vide(): void
    {
        DB::table('machines')->insert(['id' => 4, 'name' => 'neuve']);
        DB::table('user_machine_access')->insert(['user_id' => self::COMPTE, 'machine_id' => 4]);

        $this->page(4)->assertOk()->assertJsonPath('total', 0)->assertJsonPath('lignes', []);
    }

    #[Test]
    public function le_suivi_voyage_avec_les_seules_lignes_de_la_page(): void
    {
        $this->machineScannee(1, 'srv-1', 120);
        $premiere = $this->page(1)->json('lignes.0.c');
        $hors = $this->page(1, ['page' => 3])->json('lignes.0.c');
        DB::table('cve_remediation')->insert([
            ['cve_id' => $premiere, 'machine_id' => 1, 'status' => 'in_progress'],
            ['cve_id' => $hors, 'machine_id' => 1, 'status' => 'accepted'],
        ]);

        $this->assertSame([$premiere => 'in_progress'], $this->page(1)->json('suivi'));
        $this->assertSame([$hors => 'accepted'], $this->page(1, ['page' => 3])->json('suivi'));
    }

    /* ═══ L'export d'un scan dont la retention a purge le detail ════════════ */

    #[Test]
    public function l_export_d_un_scan_purge_le_dit_au_lieu_d_annoncer_zero_cve(): void
    {
        $scan = $this->machineScannee(1, 'srv-1', 3);
        DB::table('cve_findings')->where('scan_id', $scan)->delete();   // ce que fait la retention

        $csv = $this->connecte(1, ['can_scan_cve'])->get('/export-cve?scan_id=' . $scan)->assertOk()->getContent();
        $this->assertStringContainsString(__('cve.export_detail_purge'), $csv);
        $this->assertStringNotContainsString(__('cve.export_aucune'), $csv);

        $vide = DB::table('cve_scans')->insertGetId(['machine_id' => 1, 'cve_count' => 0, 'scan_date' => '2026-11-21 03:00:00']);
        $this->assertStringContainsString(__('cve.export_aucune'),
            $this->connecte(1, ['can_scan_cve'])->get('/export-cve?scan_id=' . $vide)->getContent(),
            'temoin : un scan reellement vide le dit toujours');
    }
}
