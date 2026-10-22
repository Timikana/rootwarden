<?php

namespace Tests\Feature;

use App\Support\RoutesBackend;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * Les routes que le backend rend EN FLUX doivent etre relayees en flux.
 *
 * Mesure du 2026-10-22 : six routes du backend ecrivaient leur reponse morceau
 * par morceau et la passerelle les lisait EN ENTIER avant de repondre — le scan
 * CVE, le journal du deploiement des cles, le scan Docker du parc n'affichaient
 * rien avant la fin, et tombaient en erreur de passerelle au-dela de 120 s.
 * Rien ne reliait `EN_FLUX` au backend : une route en flux ajoutee d'un cote
 * ne l'etait jamais de l'autre.
 *
 * Ce test lit `backend/routes/*.py` et releve les routes dont la reponse est
 * construite sur un generateur (`Response(gen(), mimetype='text/plain'|
 * 'text/event-stream')`). Chacune doit etre dans `EN_FLUX`, ou dans
 * `BUFFERISEES` avec sa raison.
 */
class FluxDuBackendTest extends TestCase
{
    /**
     * Bufferisees VOLONTAIREMENT. Decision du sous-lot V12, sur mesure : une
     * reconfiguration ou une desinstallation d'agent dure environ 1,4 s
     * (voir le commentaire de `RoutesBackend::EN_FLUX`).
     */
    private const BUFFERISEES = [
        '/supervision/zabbix/uninstall',
        '/supervision/zabbix/reconfigure',
        '/supervision/<platform>/uninstall',
        '/supervision/<platform>/reconfigure',
    ];

    /**
     * `/supervision/<platform>/deploy` n'accepte que ces trois-la
     * (`backend/routes/supervision.py`, garde `platform not in (...)`) : Zabbix
     * a sa propre route.
     */
    private const PLATEFORMES_GENERIQUES = ['centreon', 'prometheus', 'telegraf'];

    /** @return list<string> les chemins des routes du backend qui rendent un flux */
    private function routesEnFluxDuBackend(): array
    {
        $fichiers = glob(dirname(base_path()) . '/backend/routes/*.py') ?: [];
        $trouvees = [];

        foreach ($fichiers as $fichier) {
            $route = null;
            foreach (file($fichier) as $ligne) {
                if (preg_match("#@bp\.route\('([^']+)'#", $ligne, $m)) {
                    $route = $m[1];
                }
                if ($route !== null
                    && preg_match("#return Response\(\w+\(\),\s*(mimetype|content_type)='text/(plain|event-stream)'#", $ligne)) {
                    $trouvees[] = $route;
                }
            }
        }

        return array_values(array_unique($trouvees));
    }

    #[Test]
    public function chaque_flux_du_backend_est_relaye_en_flux_ou_bufferise_avec_sa_raison(): void
    {
        $routes = $this->routesEnFluxDuBackend();

        // TEMOIN : `/update` est un flux depuis le premier jour. S'il n'est pas
        // releve, le releve n'a pas eu lieu (chemin faux, motif perime) — et un
        // releve vide ne trouverait jamais rien a reprocher.
        $this->assertContains('/update', $routes, 'releve des routes en flux du backend inoperant');

        $nonRelayees = [];
        foreach ($routes as $route) {
            if (in_array($route, self::BUFFERISEES, true)) {
                continue;
            }
            $concretes = str_contains($route, '<platform>')
                ? array_map(fn ($p) => str_replace('<platform>', $p, $route), self::PLATEFORMES_GENERIQUES)
                : [$route];
            foreach ($concretes as $c) {
                if (! RoutesBackend::estUnFlux($c)) {
                    $nonRelayees[] = $c;
                }
            }
        }

        $this->assertSame([], $nonRelayees,
            'routes rendues en flux par le backend mais lues EN ENTIER par la passerelle');
    }

    #[Test]
    public function chaque_entree_de_en_flux_designe_un_flux_du_backend(): void
    {
        // Le sens inverse : une entree qui ne designe plus rien passerait
        // inapercue et laisserait croire a un relais qui n'a pas lieu.
        $routes = $this->routesEnFluxDuBackend();
        $connues = [];
        foreach ($routes as $route) {
            foreach (self::PLATEFORMES_GENERIQUES as $p) {
                $connues[] = str_replace('<platform>', $p, $route);
            }
        }

        $orphelines = array_values(array_diff(RoutesBackend::EN_FLUX, $connues));

        $this->assertSame([], $orphelines, 'entrees de EN_FLUX sans route en flux cote backend');
    }
}
