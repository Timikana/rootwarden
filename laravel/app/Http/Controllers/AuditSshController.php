<?php

namespace App\Http\Controllers;

use App\Services\Machines;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Audit de configuration SSH — sous-lot A1.
 *
 * ══ CE QUE A1 PORTE ═══════════════════════════════════════════════════════
 *
 * La LECTURE, et elle seule : les relevés déjà faits (`GET /ssh-audit/results`),
 * la politique appliquée (`GET /ssh-audit/policies`), l'état de la flotte
 * (`GET /ssh-audit/fleet`) et les relevés planifiés (`GET /ssh-audit/schedules`).
 *
 * ══ ET CE QU'IL N'APPELLE JAMAIS, DELIBEREMENT ════════════════════════════
 *
 * **`POST /ssh-audit/policies` n'est compose nulle part.** SEC-013 :
 *
 *     GET  /ssh-audit/policies  ->  require_permission('can_audit_ssh') + require_machine_access
 *     POST /ssh-audit/policies  ->  require_role(2)  SEUL
 *
 * Un role 2 sans la permission ne peut donc pas LIRE une politique et peut en
 * ECRIRE une, sur n'importe quelle machine. L'ecriture est moins gardee que la
 * lecture, sur la MEME URL — et la passerelle ne peut pas les separer :
 * `RoutesBackend::correspond` compare des CHEMINS, jamais des methodes. C'est
 * structurel, pas un oubli. La fermeture se fait donc **par l'absence
 * d'appel**, ici comme sur `iptables` en I1.
 *
 * ══ LA GARDE EST CELLE DU LEGACY, PAS UNE PLUS LARGE ══════════════════════
 *
 * `role:1` + `perm:can_audit_ssh`, comme `legacy/ssh-audit/index.php:12-13`.
 * **Surtout pas `role:2`** : cinq routes du module sont reellement concues
 * pour le role 1, et le passer a 2 reproduirait cote portage le croisement
 * qu'on reproche au backend.
 */
class AuditSshController extends Controller
{
    public function __construct(private readonly Machines $machines)
    {
    }

    public function __invoke(Request $requete): View
    {
        $role = (int) $requete->session()->get('role_id', 0);
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);

        /*
         * Le legacy refait la borne a la main (`index.php:22-33`) — sa propre
         * correction d'IDOR, le selecteur ayant liste tout le parc, noms et IP
         * compris, quel que soit le role. Ici c'est `Machines::perimetre` qui
         * la porte, et elle est ecrite UNE fois pour tout le service.
         */
        $perimetre = $this->machines->perimetre($role, $idCompte);

        return view('audit-ssh', [
            'serveurs' => $perimetre['serveurs'],
            'lisible'  => $perimetre['lisible'],
            // La borne MORD au role 1 seulement. Le dire evite d'afficher une
            // reserve a qui ne subit aucune restriction.
            'borne'    => $role < 2,
            // La flotte et les planifications sont reservees a
            // l'administration cote backend (`@require_role(2)`). Les afficher
            // au role 1 produirait deux 403 a l'ecran plutot qu'une absence
            // expliquee.
            'administration' => $role >= 2,
            'libelles' => __('ssh_audit'),
            'lienLegacy' => rtrim((string) config('app.url_legacy'), '/') . '/ssh-audit/',
        ]);
    }
}
