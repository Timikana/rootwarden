<?php

namespace Tests\Feature;

use App\Services\ClePlateforme;
use Tests\TestCase;

/**
 * LA JAUGE DE LA CLE DE PLATEFORME COMPTE LES ETATS DU TABLEAU.
 *
 * Mesure du 2026-11-16 sur le banc : la part « cle seule » de la jauge comptait
 * les machines SANS MOT DE PASSE CONNU, cle ou non — 5 machines en vert pour 3
 * cles. Et une machine sans cle ni mot de passe portait la pastille « mot de
 * passe seul », un acces que RootWarden n'a pas.
 */
class JaugeClePlateformeTest extends TestCase
{
    private function machine(bool $cle, bool $mdp, bool $mdpRoot = false): object
    {
        return (object) [
            'name' => 'srv', 'platform_key_deployed' => (int) $cle, 'service_account_deployed' => 0,
            'a_mot_de_passe' => (int) $mdp, 'a_mot_de_passe_root' => (int) $mdpRoot,
        ];
    }

    public function test_les_quatre_etats(): void
    {
        $c = app(ClePlateforme::class);
        $this->assertSame('cle_seule', $c->etatAuth($this->machine(true, false)));
        $this->assertSame('cle_et_mot_de_passe', $c->etatAuth($this->machine(true, true)));
        $this->assertSame('cle_et_mot_de_passe', $c->etatAuth($this->machine(true, false, true)));
        $this->assertSame('mot_de_passe_seul', $c->etatAuth($this->machine(false, true)));
        $this->assertSame('aucun_acces', $c->etatAuth($this->machine(false, false)));
    }

    public function test_la_part_cle_seule_ne_compte_pas_une_machine_sans_cle(): void
    {
        // Le banc du 2026-11-16, en petit : 1 cle seule, 1 cle + mdp,
        // 1 mot de passe seul, 1 machine sans rien.
        $parc = [$this->machine(true, false), $this->machine(true, true), $this->machine(false, true), $this->machine(false, false)];
        $n = app(ClePlateforme::class)->compteurs($parc);

        $this->assertSame(['cle_seule' => 1, 'cle_et_mot_de_passe' => 1, 'mot_de_passe_seul' => 1, 'aucun_acces' => 1], $n['par_etat']);
        $this->assertSame(25, $n['pct_cle_seule']);   // l'ancienne jauge disait 50 : deux machines sans mot de passe
        $this->assertSame(25, $n['pct_cle_et_mdp']);
        $this->assertSame(25, $n['pct_aucun_acces']);
        // Temoin : le compteur « sans mot de passe connu » garde son sens.
        $this->assertSame(2, $n['sans_mot_de_passe']);
    }
}
