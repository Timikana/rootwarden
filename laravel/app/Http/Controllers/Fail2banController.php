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

        // ── F2 : ce qu'il faut pour que l'ecran ne mente pas ────────────
        //
        // `GET /fail2ban/history` rend 50 lignes au plus SANS annoncer de total,
        // et `performed_by` est un identifiant NUMERIQUE. Les deux valeurs qui
        // manquent au navigateur pour dire vrai — le total par machine et les
        // noms de comptes — se lisent ici, en deux requetes, et voyagent avec
        // la page.
        $totaux = $this->fail2ban->totauxHistorique();
        $noms = $this->fail2ban->nomsUtilisateurs();

        $lignes = [];
        foreach ($machines as $m) {
            $lignes[] = [
                'machine'  => $m,
                'sensible' => $this->fail2ban->estSensible($m),
                'cache'    => $statuts[(int) $m->id] ?? null,
                'histo'    => $totaux[(int) $m->id] ?? 0,
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
            // F2
            'histo_choisir', 'histo_vide_titre', 'histo_vide', 'histo_echec_titre',
            'histo_echec', 'histo_tout', 'histo_tronque',
            'action_ban', 'action_unban', 'par_inconnu', 'par_repli', 'par_repli_aide',
            'frise_vide_titre', 'frise_vide', 'frise_jour',
            // F3
            'lu_a_l_instant', 'fichier_absent_titre', 'fichier_absent',
            'journal_absent_titre', 'journal_absent',
            'lecture_echec_titre', 'lecture_echec',
            'services_installe', 'services_absent', 'services_jails',
            'services_jail_active', 'services_vide_titre', 'services_vide',
        ] as $cle) {
            $textes[$cle] = __('fail2ban.' . $cle);
        }

        return view('fail2ban', [
            'lignes'    => $lignes,
            'noms'      => $noms,
            'sensibles' => $this->fail2ban->compteSensibles($machines),
            'total'     => count($machines),
            'textes'    => $textes,
        ]);
    }
}
