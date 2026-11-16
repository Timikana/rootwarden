<?php

namespace Tests\Feature;

use App\Services\Bashrc;
use App\Services\ClePlateforme;
use App\Services\Fail2ban;
use App\Services\Iptables;
use App\Services\ServicesSystemd;
use App\Support\MachineSensible;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * UNE REGLE « MACHINE SENSIBLE », ET LES CINQ PAGES QUI L'AVERTISSENT LA SUIVENT.
 *
 * Mesure du 2026-11-16 : la copie de `ClePlateforme` ne lisait que
 * l'environnement. Une machine DEV marquee CRITIQUE n'etait pas signalee sur
 * la page qui peut couper l'acces a tout le parc, alors que bashrc, services,
 * fail2ban et iptables la signalaient.
 */
class MachineSensibleTest extends TestCase
{
    /** @return array<string, array{?string, ?string, bool}> */
    public static function cas(): array
    {
        return [
            'prod non critique'   => ['PROD', 'NON CRITIQUE', true],
            'dev critique'        => ['DEV', 'CRITIQUE', true],
            'dev non critique'    => ['DEV', 'NON CRITIQUE', false],
            'test non critique'   => ['TEST', 'NON CRITIQUE', false],
            'other'               => ['OTHER', 'NON CRITIQUE', true],
            'environnement vide'  => ['', 'NON CRITIQUE', true],
            'environnement null'  => [null, null, true],
            'minuscules'          => ['dev', 'critique', true],
        ];
    }

    #[DataProvider('cas')]
    public function test_la_regle(?string $env, ?string $crit, bool $attendu): void
    {
        $this->assertSame($attendu, MachineSensible::est((object) ['environment' => $env, 'criticality' => $crit]));
    }

    #[DataProvider('cas')]
    public function test_les_cinq_services_disent_la_meme_chose(?string $env, ?string $crit, bool $attendu): void
    {
        $m = (object) ['environment' => $env, 'criticality' => $crit];
        foreach ([Bashrc::class, ClePlateforme::class, Fail2ban::class, Iptables::class, ServicesSystemd::class] as $service) {
            $this->assertSame($attendu, app($service)->estSensible($m), $service);
        }
    }

    public function test_la_regle_n_est_ecrite_qu_une_fois(): void
    {
        // Une sixieme copie ecrite a la main reouvrirait la divergence. La
        // valeur `'CRITIQUE'` ne doit apparaitre, dans les services, que dans
        // la liste fermee de la fiche serveur.
        $copies = [];
        foreach (glob(app_path('Services/*.php')) as $f) {
            $code = preg_replace('#/\*.*?\*/|//[^\n]*#s', '', (string) file_get_contents($f));
            if (preg_match("/=== 'CRITIQUE'/", $code)) {
                $copies[] = basename($f);
            }
        }
        $this->assertSame([], $copies);

        // Temoin : le motif mord bien sur la regle partagee.
        $this->assertMatchesRegularExpression("/=== 'CRITIQUE'/", (string) file_get_contents(app_path('Support/MachineSensible.php')));
    }
}
