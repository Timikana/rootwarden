<?php

namespace Tests\Unit;

use App\Support\RelaisFlux;
use GuzzleHttp\Client;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

/**
 * Le relais des flux arrive AU FIL DE L'EAU — 2026-10-27.
 *
 * Mesure sur la pile isolee : la passerelle lisait le flux du backend par
 * `read(8192)`, qui, sur la socket TLS du backend, attend 8 Ko ou la fin. Un
 * journal de 1 076 octets disponible a 292 ms etait rendu a 7 465 ms, d'un bloc.
 *
 * Le serveur de `tests/Outils/serveur-tls-lent.php` envoie « debut », marque une
 * pause, puis « fin » — en HTTPS, la seule condition qui reproduit le blocage.
 */
class RelaisFluxTest extends TestCase
{
    /** @var resource|null */
    private $processus = null;

    protected function tearDown(): void
    {
        if (is_resource($this->processus)) {
            proc_terminate($this->processus);
            proc_close($this->processus);
        }
        parent::tearDown();
    }

    private function flux(int $pauseUs): StreamInterface
    {
        $this->processus = proc_open(
            [PHP_BINARY, dirname(__DIR__) . '/Outils/serveur-tls-lent.php', (string) $pauseUs],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $tubes);
        $ligne = (string) fgets($tubes[1]);
        $this->assertMatchesRegularExpression('/^pret \d+$/', trim($ligne), 'le serveur de test ne demarre pas');
        $port = (int) substr(trim($ligne), 5);

        return (new Client())->request('GET', "https://127.0.0.1:{$port}/",
            ['stream' => true, 'verify' => false, 'timeout' => 30])->getBody();
    }

    /** @return list<array{float, string}> */
    private function relaie(StreamInterface $corps, int $inactiviteMax = 30, ?callable $abandonne = null): array
    {
        $t0 = microtime(true);
        $recus = [];
        RelaisFlux::relaie($corps, function (string $m) use (&$recus, $t0): void {
            $recus[] = [microtime(true) - $t0, $m];
        }, $inactiviteMax, $abandonne);

        return $recus;
    }

    #[Test]
    public function le_premier_morceau_arrive_avant_la_fin_du_flux(): void
    {
        $recus = $this->relaie($this->flux(1_500_000));

        $this->assertNotSame([], $recus);
        [$quand, $premier] = $recus[0];
        $this->assertSame("debut\n", $premier, 'le premier morceau a attendu la suite du flux');
        $this->assertLessThan(0.8, $quand, sprintf('premier morceau rendu a %.2f s', $quand));
        $this->assertSame("debut\nfin\n", implode('', array_column($recus, 1)), 'contenu altere');
    }

    #[Test]
    public function temoin_la_lecture_par_8_ko_attend_la_fin(): void
    {
        // Ce que faisait la passerelle. Si ce temoin cessait de bloquer (autre
        // version de PHP), le test ci-dessus ne prouverait plus rien.
        $corps = $this->flux(1_500_000);
        $t0 = microtime(true);
        $premier = '';
        while ($premier === '' && ! $corps->eof()) {
            $premier = $corps->read(8192);
        }

        $this->assertGreaterThan(1.2, microtime(true) - $t0, 'read(8192) ne bloque plus : revoir le test');
        $this->assertSame("debut\nfin\n", $premier);
    }

    #[Test]
    public function un_silence_trop_long_interrompt_le_relais(): void
    {
        $t0 = microtime(true);
        $recus = $this->relaie($this->flux(4_000_000), inactiviteMax: 1);

        $this->assertLessThan(3.0, microtime(true) - $t0, 'le delai d\'inactivite n\'a pas joue');
        $this->assertSame("debut\n", implode('', array_column($recus, 1)));
    }

    #[Test]
    public function un_navigateur_parti_arrete_le_relais(): void
    {
        $recus = [];
        $t0 = microtime(true);
        $corps = $this->flux(4_000_000);
        // Une fonction flechee capturerait `$recus` PAR VALEUR (tableau vide pour
        // toujours) : la fermeture d'abandon le lit par reference.
        RelaisFlux::relaie($corps, function (string $m) use (&$recus): void {
            $recus[] = $m;
        }, 30, function () use (&$recus): bool {
            return $recus !== [];
        });

        $this->assertLessThan(3.0, microtime(true) - $t0);
        $this->assertSame(["debut\n"], $recus);
    }
}
