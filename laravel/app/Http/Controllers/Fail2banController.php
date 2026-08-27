<?php

namespace App\Http\Controllers;

use App\Services\Fail2ban;
use Illuminate\View\View;

/**
 * Fail2ban — sous-lot F1.
 *
 * **Ce controleur n'ouvre aucune session SSH.** Le statut affiche vient du CACHE
 * (`fail2ban_status`), et le rafraichir demande un geste explicite : ouvrir la
 * page ne doit pas joindre toutes les machines du parc.
 *
 * Garde : `role:1` + `perm:can_manage_fail2ban`, reprise telle quelle du legacy
 * — dont l'en-tete annonce pourtant « admin (2), superadmin (3) ». Voir
 * `App\Services\Fail2ban` : le role 1 est un choix assume du projet, l'en-tete
 * est une erreur.
 */
class Fail2banController extends Controller
{
    public function __construct(private Fail2ban $fail2ban)
    {
    }

    public function __invoke(): View
    {
        $machines = $this->fail2ban->machines();
        $statuts = $this->fail2ban->dernierStatut();

        $lignes = [];
        foreach ($machines as $m) {
            $lignes[] = [
                'machine'  => $m,
                'sensible' => $this->fail2ban->estSensible($m),
                'cache'    => $statuts[(int) $m->id] ?? null,
            ];
        }

        // `@json` avec un litteral inline casse le PHP compile par Blade : les
        // libelles se calculent ici (defaut paye en `bashrc/` B1 — page en 500).
        $textes = [];
        foreach ([
            'choisir', 'chargement', 'echec', 'etat_absent', 'etat_absent_aide',
            'etat_arrete', 'etat_arrete_aide', 'etat_actif', 'jails_aucune',
            'jails_une', 'jails_plusieurs', 'adresses_une', 'adresses_plusieurs',
            'compte_bannies_une', 'compte_bannies_plusieurs',
            'cache_maintenant', 'sensible_avert',
        ] as $cle) {
            $textes[$cle] = __('fail2ban.' . $cle);
        }

        return view('fail2ban', [
            'lignes'    => $lignes,
            'sensibles' => $this->fail2ban->compteSensibles($machines),
            'total'     => count($machines),
            'textes'    => $textes,
        ]);
    }
}
