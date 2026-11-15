<?php

namespace Tests\Feature;

use App\Services\ListeBlancheCve;
use App\Services\ScansCve;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * La liste blanche CVE AGIT : une CVE blanchie est marquee dans le tableau du
 * scan, pour sa machine ou pour toutes, tant qu'elle n'a pas expire. Avant,
 * la table etait ecrite et lue par personne.
 */
class ListeBlancheCveActiveTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // SQLite ne connait pas FIELD(), que le tri des severites emploie (MySQL).
        $pdo = DB::connection()->getPdo();
        $field = static function ($valeur, ...$liste) {
            $i = array_search($valeur, $liste, true);

            return $i === false ? 0 : $i + 1;
        };
        if (method_exists($pdo, 'createFunction')) {
            $pdo->createFunction('FIELD', $field, -1);
        } else {
            $pdo->sqliteCreateFunction('FIELD', $field, -1);
        }
        Schema::create('cve_whitelist', function (Blueprint $t) {
            $t->id();
            $t->string('cve_id');
            $t->integer('machine_id')->nullable();
            $t->string('reason')->default('');
            $t->string('whitelisted_by')->default('');
            $t->date('expires_at')->nullable();
            $t->timestamp('created_at')->nullable();
        });
        Schema::create('machines', function (Blueprint $t) {
            $t->id();
            $t->string('name');
        });
        DB::table('machines')->insert([['id' => 7, 'name' => 'demo-7'], ['id' => 8, 'name' => 'demo-8']]);
        Schema::create('cve_scans', function (Blueprint $t) {
            $t->id();
            $t->integer('machine_id');
            $t->string('status')->default('completed');
        });
        Schema::create('cve_findings', function (Blueprint $t) {
            $t->id();
            $t->integer('scan_id');
            $t->string('cve_id');
            $t->string('package_name')->default('p');
            $t->string('package_version')->default('1');
            $t->decimal('cvss_score', 3, 1)->default(9.8);
            $t->string('severity')->default('CRITICAL');
            $t->string('summary')->default('');
            $t->decimal('epss_score', 6, 5)->nullable();
            $t->boolean('kev')->default(false);
            $t->date('kev_date_added')->nullable();
            $t->decimal('priority_score', 6, 2)->nullable();
            $t->string('priority_label')->nullable();
        });
        DB::table('cve_whitelist')->insert([
            ['cve_id' => 'CVE-GLOBALE', 'machine_id' => null, 'expires_at' => null],
            ['cve_id' => 'cve-machine-7', 'machine_id' => 7, 'expires_at' => null],
            ['cve_id' => 'CVE-AUTRE-MACHINE', 'machine_id' => 8, 'expires_at' => null],
            ['cve_id' => 'CVE-EXPIREE', 'machine_id' => null, 'expires_at' => now()->subDay()->toDateString()],
            ['cve_id' => 'CVE-EXPIRE-AUJOURDHUI', 'machine_id' => null, 'expires_at' => now()->toDateString()],
        ]);
    }

    #[Test]
    public function seules_les_entrees_actives_de_la_machine_comptent(): void
    {
        $actives = array_keys(app(ListeBlancheCve::class)->cvesActives(7));
        sort($actives);
        $this->assertSame(['CVE-EXPIRE-AUJOURDHUI', 'CVE-GLOBALE', 'CVE-MACHINE-7'], $actives);
    }

    #[Test]
    public function le_tableau_du_scan_marque_les_cve_blanchies(): void
    {
        $scan = DB::table('cve_scans')->insertGetId(['machine_id' => 7]);
        foreach (['CVE-GLOBALE', 'CVE-MACHINE-7', 'CVE-AUTRE-MACHINE', 'CVE-EXPIREE', 'CVE-LIBRE'] as $c) {
            DB::table('cve_findings')->insert(['scan_id' => $scan, 'cve_id' => $c]);
        }
        $marques = [];
        foreach (app(ScansCve::class)->findingsPourAffichage($scan) as $f) {
            $marques[$f['c']] = $f['b'];
        }
        $this->assertCount(5, $marques, 'le tableau ne rend pas les cinq lignes');
        $this->assertSame([
            'CVE-GLOBALE' => true, 'CVE-MACHINE-7' => true, 'CVE-AUTRE-MACHINE' => false,
            'CVE-EXPIREE' => false, 'CVE-LIBRE' => false,
        ], array_intersect_key($marques, array_flip(['CVE-GLOBALE', 'CVE-MACHINE-7', 'CVE-AUTRE-MACHINE', 'CVE-EXPIREE', 'CVE-LIBRE'])));
    }
}
