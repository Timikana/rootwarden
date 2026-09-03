<?php

namespace App\Http\Controllers;

use App\Services\Bashrc;
use Illuminate\View\View;

/**
 * Le deploiement du `.bashrc` standardise — sous-lot B1.
 *
 * **Ce controleur ne fait AUCUNE ecriture, et n'ouvre aucune session SSH.**
 * B1 ne porte que la page : son inventaire de machines se lit en base, et les
 * six routes qui joignent une machine partent par la passerelle (B2 pour les
 * lectures, B4 pour les ecritures).
 *
 * La garde est `role:2` + `perm:can_manage_bashrc`, reprise telle quelle du
 * legacy (`checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` + `checkPermission`). Le
 * contournement par le role 3 vient du middleware `perm`, comme partout — et il
 * est identique cote backend (`require_permission`, `helpers.py:280`). Mesure
 * de B1 sur le legacy : role 1 -> 403, role 2 SANS la permission -> 403,
 * role 3 SANS la permission -> 200.
 */
class BashrcController extends Controller
{
    public function __construct(private Bashrc $bashrc)
    {
    }

    public function __invoke(): View
    {
        $machines = $this->bashrc->machines();
        $derniers = $this->bashrc->derniersDeploiements();

        // La sensibilite est calculee ICI, une fois, et non dans la vue : une
        // vue qui appelle un service par ligne finit par le faire deux fois
        // avec deux reponses.
        $lignes = [];
        foreach ($machines as $m) {
            $lignes[] = [
                'machine'     => $m,
                'sensible'    => $this->bashrc->estSensible($m),
                'deploiement' => $derniers[$m->id]['deploiement'] ?? null,
                'simulation'  => $derniers[$m->id]['simulation'] ?? null,
            ];
        }

        // Les phrases du compteur sont calculees ICI et passees comme UNE
        // variable. `@json` avec un litteral de tableau inline ne survit pas a
        // la compilation Blade : sa lecture d'arguments decoupe sur les virgules
        // de premier niveau sans suivre les crochets, et tronque le tableau —
        // le PHP compile devenait `json_encode([... )`, sans crochet fermant,
        // et la page rendait 500. Meme famille que « `@json` multiligne casse le
        // PHP compile », deja ecrit dans les conventions du portage.
        //
        // **`@json` prend une VARIABLE, pas une expression.** C'est le motif
        // employe en D9a et D9b, et oublie ici.
        $textes = [
            'aucune'    => __('bashrc.aucune_selection'),
            'une'       => __('bashrc.selection_une'),
            'plusieurs' => __('bashrc.selection_n'),
            'avec_prod' => __('bashrc.selection_prod'),

            // B2. **Prefixes distincts, et ce n'est pas cosmetique** : une
            // premiere redaction reutilisait `plusieurs` — qui vaut
            // « :nb machines selectionnees » pour le compteur et « plusieurs
            // machines sont cochees » pour les comptes. Deux sens, une cle : le
            // second aurait ecrase le premier a l'ecran.
            'choisir'           => __('bashrc.comptes_choisir'),
            'plusieurs_cochees' => __('bashrc.comptes_plusieurs'),
            'chargement'        => __('bashrc.comptes_chargement'),
            'echec'             => __('bashrc.comptes_echec'),
            'aucun'             => __('bashrc.comptes_aucun'),
            'absent'            => __('bashrc.bashrc_absent'),
            'root'              => __('bashrc.compte_root'),
            'root_aide'         => __('bashrc.compte_root_aide'),
            'perso'             => __('bashrc.perso'),
            'perso_aide'        => __('bashrc.perso_aide'),
            'apercu_vide'       => __('bashrc.apercu_vide'),
            'apercu_chargement' => __('bashrc.apercu_chargement'),
            'apercu_echec'      => __('bashrc.apercu_echec'),
            'taille'            => __('bashrc.apercu_taille'),

            // B3 — l'onglet Gabarit.
            'g_chargement'  => __('bashrc.gabarit_chargement'),
            'g_echec'       => __('bashrc.gabarit_echec'),
            'g_modifie'     => __('bashrc.gabarit_modifie'),
            'g_enregistre'  => __('bashrc.gabarit_enregistre'),
            'g_erreur'      => __('bashrc.gabarit_erreur'),
            'g_encours'     => __('bashrc.gabarit_encours'),
            'g_confirmer'   => __('bashrc.gabarit_confirmer'),
            'd_reconnu'     => __('bashrc.danger_reconnu'),
            'd_confirmer'   => __('bashrc.danger_confirmer'),
            // Les MOTIFS partent avec les libelles : une seule source cote
            // portage (`Bashrc::MOTIFS_DANGEREUX`), jamais recopies dans le JS.
            'motifs'        => Bashrc::MOTIFS_DANGEREUX,
        ];

        return view('bashrc', [
            'textes'    => $textes,
            'lignes'    => $lignes,
            'sensibles' => $this->bashrc->compteSensibles($machines),
            'total'     => count($machines),
        ]);
    }
}
