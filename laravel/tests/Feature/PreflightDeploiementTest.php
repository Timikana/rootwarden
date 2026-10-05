<?php

namespace Tests\Feature;

use App\Services\DeploiementCles;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * LE VERDICT DU PREFLIGHT, LU SUR LA FORME QUE LE BACKEND REND VRAIMENT.
 *
 * Mesure du 2026-10-05 en production, une fois la panne TLS levée : « Déployer »
 * refusait Eos — une machine saine, SSH authentifié, scannée, rien en attente.
 * `preflight()` lisait `users_with_keys` DANS chaque résultat de machine ; le
 * backend ne le rend qu'UNE fois, à la racine :
 *
 *     backend/routes/ssh.py:791-795
 *         return jsonify({'success': True, 'results': results,
 *                         'users_with_keys': users_with_keys})
 *
 * Le champ étant absent de chaque machine, `?? 0` rendait 0 partout, et TOUTES
 * les machines étaient refusées. L'ancienne interface lisait bien la racine
 * (`legacy/_deprecated/ssh/main.js:177`, `data.users_with_keys`).
 *
 * ⚠ LES FAUX CI-DESSOUS SONT RECOPIÉS DU BACKEND, PAS DU CODE LARAVEL. Le premier
 * test de ce service les avait écrits d'après `preflight()` lui-même — il plaçait
 * le champ dans chaque machine, reproduisait le défaut, et passait au vert. Un
 * faux dérivé du code qu'il éprouve ne mesure que l'accord du code avec lui-même.
 * Forme d'un résultat de machine : `ssh.py:635-661`.
 *
 * Second défaut, fermé dans le même geste : les `errors` par machine étaient
 * IGNORÉES. Le backend y signale exprès un audit d'inventaire échoué
 * (`ssh.py:780-784`, « Ne pas déployer sans l'avoir relue ») sur une machine
 * dont `ssh_ok` vaut pourtant `true` — et c'est la liste des accès qui seront
 * RÉVOQUÉS qu'il n'a pas pu établir. C'était aussi la règle du legacy
 * (`main.js:132-138` : une erreur suffit à faire échouer la machine).
 */
class PreflightDeploiementTest extends TestCase
{
    private function machine(string $nom, bool $sshOk = true, array $erreurs = []): array
    {
        return ['machine_id' => 3, 'name' => $nom, 'ip' => '192.0.2.3', 'ssh_ok' => $sshOk,
                'os_version' => null, 'disk_free' => null, 'audit_inventaire' => $sshOk && $erreurs === [],
                'errors' => $erreurs];
    }

    private function preflightAvec(array $corps): array
    {
        config(['rootwarden.backend.url' => 'https://python:5000']);
        Http::fake(['*' => Http::response($corps)]);

        return app(DeploiementCles::class)->preflight([3], 1, 3, []);
    }

    #[Test]
    public function une_machine_saine_passe_quand_le_compte_global_est_positif(): void
    {
        // Le cas exact de la production : Eos, 3 comptes avec une clé.
        $v = $this->preflightAvec(['success' => true, 'users_with_keys' => 3,
                                   'results' => [$this->machine('Eos')]]);

        $this->assertNull($v['erreur'], 'erreur inattendue : ' . var_export($v['erreur'], true));
        $this->assertSame([], $v['echecs'], 'machine saine refusee : ' . json_encode($v['echecs']));
        $this->assertNotNull($v['concluant']);
    }

    #[Test]
    public function aucun_compte_avec_cle_refuse_tout_et_le_dit_globalement(): void
    {
        // Le zéro qui transforme un déploiement en révocation générale
        // (`MODULE-SSH.md:280`). Il porte sur le PARC, pas sur une machine :
        // l'imputer à Eos ferait chercher sur Eos un défaut qui n'y est pas.
        $v = $this->preflightAvec(['success' => true, 'users_with_keys' => 0,
                                   'results' => [$this->machine('Eos')]]);

        $this->assertNull($v['concluant']);
        $this->assertSame('aucun_compte_avec_cle', $v['erreur']);
    }

    #[Test]
    public function un_compte_global_absent_est_un_refus(): void
    {
        // Fail-closed : une réponse qui ne porte pas le compte n'autorise rien.
        $v = $this->preflightAvec(['success' => true, 'results' => [$this->machine('Eos')]]);

        $this->assertNull($v['concluant']);
        $this->assertSame('aucun_compte_avec_cle', $v['erreur']);
    }

    #[Test]
    public function une_erreur_par_machine_la_fait_echouer_meme_si_ssh_repond(): void
    {
        $audit = "Audit d'inventaire indisponible : la liste des acces qui seront REVOQUES n'a pas pu etre etablie.";
        $v = $this->preflightAvec(['success' => true, 'users_with_keys' => 3,
                                   'results' => [$this->machine('Eos', true, [$audit])]]);

        $this->assertNull($v['concluant'], 'une machine dont l inventaire n a pas pu etre lu a ete acceptee');
        $this->assertSame(['Eos'], $v['echecs']);
        $this->assertSame(['Eos' => [$audit]], $v['raisons'], 'la raison du refus doit voyager jusqu a l ecran');
    }

    #[Test]
    public function seule_la_machine_fautive_est_nommee(): void
    {
        $v = $this->preflightAvec(['success' => true, 'users_with_keys' => 3, 'results' => [
            $this->machine('Eos'),
            $this->machine('Hyades', false, ['Port 22 injoignable sur 192.0.2.4']),
        ]]);

        $this->assertNull($v['concluant'], 'tout ou rien : une machine en echec bloque le lot');
        $this->assertSame(['Hyades'], $v['echecs']);
        $this->assertSame(['Port 22 injoignable sur 192.0.2.4'], $v['raisons']['Hyades']);
    }

    #[Test]
    public function aucune_machine_rend_son_propre_code_et_pas_null(): void
    {
        // `$vide + [...]` gardait `erreur => null` (l'union garde la clé de
        // gauche) : l'écran annonçait « en échec pour : . ».
        $v = app(DeploiementCles::class)->preflight([], 1, 3, []);

        $this->assertSame('aucune_machine', $v['erreur']);
        $this->assertNull($v['concluant']);
    }

    #[Test]
    public function l_ecran_recoit_la_machine_ET_sa_raison(): void
    {
        config(['rootwarden.backend.url' => 'https://python:5000']);
        $raison = "Audit d'inventaire indisponible";
        Http::fake(['*' => Http::response(['success' => true, 'users_with_keys' => 3,
                                           'results' => [$this->machine('Eos', true, [$raison])]])]);

        $r = $this->connecte(3)->postJson('/cles-ssh/deployer', ['machines' => [3]]);

        $r->assertStatus(409);
        $this->assertStringContainsString('Eos (' . $raison . ')', (string) $r->json('message'),
            'le message doit nommer la machine ET dire pourquoi : ' . $r->json('message'));
        // Le déploiement n'est jamais parti : une seule requête, le preflight.
        Http::assertSentCount(1);
    }

    #[Test]
    public function aucun_compte_avec_cle_rend_409_et_un_message_de_parc(): void
    {
        config(['rootwarden.backend.url' => 'https://python:5000']);
        Http::fake(['*' => Http::response(['success' => true, 'users_with_keys' => 0,
                                           'results' => [$this->machine('Eos')]])]);

        $r = $this->connecte(3)->postJson('/cles-ssh/deployer', ['machines' => [3]]);

        $r->assertStatus(409);
        $this->assertSame(__('ssh.err_aucun_compte_avec_cle'), $r->json('message'));
        $this->assertStringNotContainsString('Eos', (string) $r->json('message'),
            'un defaut de PARC ne doit pas etre impute a une machine');
        Http::assertSentCount(1);
    }
}
