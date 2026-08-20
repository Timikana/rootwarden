<?php

namespace App\Http\Controllers;

use App\Services\Conformite;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Module `security/`, sous-lot S2a : le rapport de conformite, page HTML.
 *
 * Portage de `legacy/security/compliance_report.php` (579 lignes), hors export
 * CSV (S2c) et hors export PDF (S2b). Aucune route backend, aucun SSH : sept
 * collectes SQL et un rendu.
 *
 * GARDE — DIVERGENCE VOULUE, decision D-1. Le legacy admet `ROLE_USER` et ne
 * cloisonne AUCUNE donnee : un role 1 porteur de `can_view_compliance` obtenait
 * tout le parc avec IP, port et utilisateur SSH, tous les comptes avec leur
 * e-mail et l'age de leur cle, et la posture par serveur AVEC LES ECARTS EN
 * CLAIR — soit une liste de cibles priorisee. L'en-tete du fichier annoncait
 * pourtant « Acces : admin (2) et superadmin (3) », et c'est ce commentaire
 * faux qui a rendu le defaut durable : une relecture de l'en-tete ne pouvait pas
 * le voir. La route porte donc `role:2`, la garde que le fichier annoncait.
 * Voir `PARITE.md`.
 *
 * CETTE DIVERGENCE N'EST PAS MESURABLE avec les comptes de test actuels : elle
 * exige un role 1 PORTANT `can_view_compliance`, et `rw-test-user` a zero
 * permission. Meme manque de fixture que E-34. Ce qui EST mesure ici, et pour la
 * premiere fois du module : la garde lit bien une PERMISSION et non un role —
 * `rw-test-admin` (role 2) entre ici et reste refuse sur `journal-commandes`,
 * qui exige `can_admin_portal`.
 *
 * PAS DE JAVASCRIPT. Le legacy rend cette page en PHP de bout en bout, sans
 * appel asynchrone ; le portage fait de meme. Le seul comportement de la page
 * est l'impression, qui appartient au navigateur.
 */
class RapportConformiteController extends Controller
{
    public function __construct(private readonly Conformite $conformite)
    {
    }

    public function __invoke(Request $requete): View
    {
        $serveurs = $this->conformite->serveurs();
        $comptes  = $this->conformite->comptes();
        $remStats = $this->conformite->remediation();
        $auditSsh = $this->conformite->auditSsh();
        $agents   = $this->conformite->agentsSupervision();
        $posture  = $this->conformite->posture($serveurs, $auditSsh);

        $date = date('d/m/Y H:i');

        $comptesActifs = array_filter($comptes, static fn ($c) => (bool) $c->active);
        $nbAvec2fa = count(array_filter($comptesActifs, static fn ($c) => ! empty($c->totp_secret)));
        $nbCles90j = count(array_filter($comptesActifs, static fn ($c) =>
            $c->ssh_key && $c->ssh_key_updated_at
            && strtotime((string) $c->ssh_key_updated_at) < strtotime('-90 days')));

        $scoreSshMoyen = $auditSsh === []
            ? null
            : (int) (array_sum(array_map(static fn ($a) => (int) $a->score, $auditSsh)) / count($auditSsh));
        $postureMoyenne = $posture === []
            ? 0
            : (int) (array_sum(array_column($posture, 'score')) / count($posture));

        return view('rapport-conformite', [
            'date'            => $date,
            'genereePar'      => (string) $requete->session()->get('utilisateur_nom', ''),
            'serveurs'        => $serveurs,
            'comptesActifs'   => $comptesActifs,
            'remStats'        => $remStats,
            'parefeu'         => $this->conformite->historiqueParefeu(),
            'auditSsh'        => $auditSsh,
            'agentsParMachine' => $this->grouperAgents($agents),
            'posture'         => $posture,
            'nbServeurs'      => count($serveurs),
            'nbEnLigne'       => count(array_filter($serveurs, static fn ($s) =>
                                    strtolower((string) ($s->online_status ?? '')) === 'online')),
            'nbComptesActifs' => count($comptesActifs),
            'nbAvec2fa'       => $nbAvec2fa,
            'nbCles90j'       => $nbCles90j,
            'scoreSshMoyen'   => $scoreSshMoyen,
            'nbAvecAgent'     => count(array_unique(array_map(
                                    static fn ($a) => $a->machine_id, $agents))),
            'postureMoyenne'  => $postureMoyenne,
            'noteMoyenne'     => $this->conformite->note($postureMoyenne),
            'empreinte'       => $this->conformite->empreinte($serveurs, $comptes, $remStats, $date),
        ]);
    }

    /**
     * Un serveur, ses agents. Le legacy groupe par `machine_id` dans la vue ;
     * le regroupement appartient au controleur — une vue qui calcule finit par
     * calculer differemment de l'export qui la double.
     *
     * @param  list<object>  $agents
     * @return array<int,array{nom:string,ip:string,agents:list<object>}>
     */
    private function grouperAgents(array $agents): array
    {
        $parMachine = [];
        foreach ($agents as $a) {
            $parMachine[$a->machine_id]['nom'] = (string) $a->name;
            $parMachine[$a->machine_id]['ip'] = (string) $a->ip;
            $parMachine[$a->machine_id]['agents'][] = $a;
        }
        return $parMachine;
    }
}
