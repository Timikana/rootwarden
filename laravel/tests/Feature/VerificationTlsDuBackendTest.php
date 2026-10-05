<?php

namespace Tests\Feature;

use App\Services\DeploiementCles;
use App\Services\MotDePasse;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * LE BACKEND INTERNE PRÉSENTE UN CERTIFICAT AUTO-SIGNÉ — INTERNET, NON.
 *
 * Mesure du 2026-10-05 en production : « Déployer les clés SSH » échouait à
 * chaque clic, et l'écran ne le disait pas. Journal Laravel :
 *
 *     deploiement de cles : backend injoignable {"chemin":"/preflight_check",
 *     "erreur":"cURL error 60: SSL certificate problem: self-signed certificate"}
 *
 * `PasserelleController` appelle le backend avec `->withoutVerifying()` depuis
 * l'origine. `DeploiementCles::appelle()` avait recopié son adresse et ses
 * en-têtes — son propre docblock dit qu'« une seconde source d'adresse finirait
 * par diverger » — et pas la ligne TLS. Les tests hermétiques ne pouvaient pas le
 * voir : `Http::fake()` ne fait aucune poignée de main TLS. Et les suites E2E ne
 * cliquent pas sur « Déployer », qui écrit des `authorized_keys` en root.
 *
 * Ce test lit donc l'OPTION que chaque requête emporte, telle que Guzzle la
 * recevrait (`$options['verify']`), au lieu d'attendre un échec réseau que le
 * faux ne produit jamais.
 *
 * Il porte AUSSI le sens inverse, parce que le remède naïf — désactiver la
 * vérification partout — serait une faute : `api.pwnedpasswords.com` est sur
 * Internet, et là la vérification doit RESTER.
 */
class VerificationTlsDuBackendTest extends TestCase
{
    private const BACKEND = 'https://python:5000';

    /** @var list<array{url: string, verify: mixed}> */
    private array $vues = [];

    protected function setUp(): void
    {
        parent::setUp();
        config(['rootwarden.backend.url' => self::BACKEND]);

        Http::fake(function ($requete, array $options) {
            // `array_key_exists` et pas `??` : une option ABSENTE et une option
            // à `false` ne disent pas la même chose, et c'est toute la question.
            $this->vues[] = [
                'url' => $requete->url(),
                'verify' => array_key_exists('verify', $options) ? $options['verify'] : 'ABSENTE',
            ];

            if (str_ends_with($requete->url(), '/preflight_check')) {
                // Forme RÉELLE du backend (`backend/routes/ssh.py:791-795`) :
                // `users_with_keys` est À LA RACINE. La première version de ce faux
                // le plaçait dans chaque machine — la même erreur que le code
                // qu'elle prétendait garder, donc un test vert sur un défaut.
                return Http::response(['success' => true, 'users_with_keys' => 1, 'results' => [
                    ['name' => 'machine-fictive', 'machine_id' => 3, 'ssh_ok' => true, 'errors' => []],
                ]]);
            }

            return Http::response(['success' => true, 'message' => 'ok']);
        });
    }

    /** @return list<array{url: string, verify: mixed}> */
    private function vuesVers(string $prefixe): array
    {
        return array_values(array_filter($this->vues, fn ($v) => str_starts_with($v['url'], $prefixe)));
    }

    #[Test]
    public function le_preflight_ne_verifie_pas_le_certificat_interne(): void
    {
        $verdict = app(DeploiementCles::class)->preflight([3], 1, 3, []);

        $vues = $this->vuesVers(self::BACKEND);
        $this->assertCount(1, $vues, 'le preflight doit emettre UNE requete vers le backend');
        $this->assertFalse($vues[0]['verify'],
            'verify=' . var_export($vues[0]['verify'], true) . ' : le certificat auto-signe du backend serait refuse (cURL 60)');
        // Témoin : le faux a bien été lu jusqu'au bout, la mesure a eu lieu.
        $this->assertNotNull($verdict['concluant'], 'preflight non concluant : ' . json_encode($verdict));
    }

    #[Test]
    public function le_deploiement_ne_verifie_pas_le_certificat_interne(): void
    {
        $service = app(DeploiementCles::class);
        $verdict = $service->preflight([3], 1, 3, []);
        $this->assertNotNull($verdict['concluant'], 'pas de preflight concluant, le deploiement ne peut pas etre mesure');

        $this->vues = [];
        $resultat = $service->deploie($verdict['concluant'], 1, 3, []);

        $vues = $this->vuesVers(self::BACKEND . '/deploy');
        $this->assertCount(1, $vues, 'le deploiement doit emettre UNE requete vers /deploy');
        $this->assertFalse($vues[0]['verify'],
            'verify=' . var_export($vues[0]['verify'], true) . ' : le certificat auto-signe du backend serait refuse (cURL 60)');
        $this->assertTrue($resultat['success']);
    }

    #[Test]
    public function la_verification_reste_active_vers_internet(): void
    {
        config(['rootwarden.mot_de_passe.hibp' => true]);

        app(MotDePasse::class)->compromis('un-mot-de-passe-de-test');

        $vues = $this->vuesVers('https://api.pwnedpasswords.com/');
        // Témoin : sans requête vue, « la vérification n'est pas désactivée »
        // serait vrai de rien du tout.
        $this->assertCount(1, $vues, 'aucune requete vers le service distant : la mesure n a pas eu lieu');
        $this->assertNotFalse($vues[0]['verify'],
            'la verification TLS ne doit JAMAIS etre desactivee vers un service sur Internet');
    }
}
