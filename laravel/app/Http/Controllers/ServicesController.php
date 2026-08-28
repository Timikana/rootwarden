<?php

namespace App\Http\Controllers;

use App\Services\ServicesSystemd;
use Illuminate\View\View;

/**
 * Les services systemd distants — sous-lot S1.
 *
 * **Ce controleur ne fait AUCUNE ecriture et n'ouvre aucune session SSH.** Les
 * huit routes du module partent par la passerelle : trois lectures (S2) et cinq
 * ecritures (S3).
 *
 * La garde est `role:1` + `perm:can_manage_services`, reprise telle quelle du
 * legacy (`checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` +
 * `checkPermission`). **Le role 1 est admis** — contrairement a `bashrc/` — ce
 * qui rend les trois chemins de garde distincts, et mesures par S1 :
 * role 1 sans la permission -> 403, role 2 AVEC -> 200, role 3 SANS -> 200.
 */
class ServicesController extends Controller
{
    public function __construct(private ServicesSystemd $services)
    {
    }

    public function __invoke(): View
    {
        $machines = $this->services->machines();

        $lignes = [];
        foreach ($machines as $m) {
            $lignes[] = ['machine' => $m, 'sensible' => $this->services->estSensible($m)];
        }

        // Les phrases du JS partent en UN bloc, calcule ici : `@json` avec un
        // litteral inline casse le PHP compile par Blade (defaut paye en
        // `bashrc/` B1 — la page rendait 500).
        $textes = [];
        foreach ([
            'choisir_serveur', 'chargement', 'echec', 'aucun_service',
            'filtres_inactifs', 'journaux_vides', 'sensible_confirmer',
            // S2 — le tableau et ses filtres.
            'etat_actif', 'etat_arrete', 'etat_echoue', 'active_oui', 'active_non',
            'protege', 'protege_aide', 'charges', 'aucun_systemd', 'filtres_actifs',
            'filtre_tous', 'aucun_resultat', 'resultat_compte', 'journal_lu',
            // S3 — les etats au demarrage et les cinq gestes.
            'boot_enabled', 'boot_disabled', 'boot_static', 'boot_masked', 'boot_unknown',
            'boot_static_aide', 'boot_masked_aide',
            'act_demarrer', 'act_arreter', 'act_redemarrer', 'act_activer', 'act_desactiver',
            'confirmer_arreter', 'confirmer_redemarrer', 'confirmer_demarrer',
            'confirmer_activer', 'confirmer_desactiver', 'geste_fait', 'geste_echec',
            // Le panneau de decision qui remplace `window.confirm()` : la boite
            // native bloquait Puppeteer, donc les cinq gestes qui ECRIVENT
            // etaient les seuls du module qu'aucune suite ne pouvait exercer.
            'panneau_aide',
        ] as $cle) {
            $textes[$cle] = __('services.' . $cle);
        }

        return view('services', [
            'lignes'    => $lignes,
            'sensibles' => $this->services->compteSensibles($machines),
            'total'     => count($machines),
            'textes'    => $textes,
        ]);
    }
}
