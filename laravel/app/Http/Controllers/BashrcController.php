<?php

namespace App\Http\Controllers;

use App\Services\Bashrc;
use Illuminate\View\View;

/**
 * Le deploiement du `.bashrc` standardise — sous-lot B1.
 *
 * **Ce controleur ne fait AUCUNE ecriture, et n'ouvre aucune session SSH.**
 * B1 ne porte que la page : son inventaire de machines se lit en base, et les
 * sept routes qui joignent une machine partent par la passerelle (B2 pour les
 * lectures, B4 pour les ecritures — portees le 2026-09-07).
 *
 * ⚠ « six » etait faux : `backend/routes/bashrc.py` en declare SEPT
 * (`users`, `preview`, `template`, `deploy`, `restore`, `prerequisites`,
 * `backups`). Le portage en appelle cinq ; `prerequisites` n'est pas construit
 * (il installe un paquet en root, decision de l'exploitant) et `backups` reste
 * a porter.
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
            // ── B4 : les cles des deux ecritures.
            //
            // ⚠ UNE CLE PRESENTE DANS LES DEUX CATALOGUES NE VOYAGE PAS TOUTE
            //    SEULE. Ce blob est le seul chemin vers le JS : une cle oubliee
            //    ici rend du VIDE a l'ecran, et le vide ne ressemble pas a un
            //    defaut de traduction. Mesure du 2026-09-07 : les onze cles
            //    ci-dessous manquaient au premier jet, croisees par script.
            'deploy_confirme'   => __('bashrc.deploy_confirme'),
            'deploy_en_cours'   => __('bashrc.deploy_en_cours'),
            'deploy_fait'       => __('bashrc.deploy_fait'),
            'deploy_echec'      => __('bashrc.deploy_echec'),
            'deploy_sans_cible' => __('bashrc.deploy_sans_cible'),
            'restore'           => __('bashrc.restore'),
            'restore_aide'      => __('bashrc.restore_aide'),
            'restore_confirme'  => __('bashrc.restore_confirme'),
            'restore_en_cours'  => __('bashrc.restore_en_cours'),
            'restore_fait'      => __('bashrc.restore_fait'),
            'restore_echec'     => __('bashrc.restore_echec'),
            'restore_lecture'   => __('bashrc.restore_lecture'),
            'restore_aucune'    => __('bashrc.restore_aucune'),
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
