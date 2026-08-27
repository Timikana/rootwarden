<?php

namespace App\Http\Controllers;

use App\Services\Iptables;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Pare-feu iptables — sous-lot I1.
 *
 * **Ce controleur n'ouvre aucune session SSH.** Ouvrir la page ne joint aucune
 * machine : elle rend la liste des cibles et attend un geste explicite. Le
 * releve des regles actives part du navigateur, par la passerelle, machine par
 * machine.
 *
 * Garde : `role:1` + `perm:can_manage_iptables`, reprise telle quelle du legacy
 * — dont l'en-tete annonce pourtant « superadmin uniquement ». Voir
 * `App\Services\Iptables`.
 *
 * ══ CE QUE I1 NE FAIT PAS, ET POURQUOI C'EST ECRIT ═══════════════════════
 *
 * `POST /iptables` porte DEUX gestes sous une seule route : `action: "get"` lit
 * les regles, `action: "apply"` **les applique**. La passerelle ne peut donc
 * pas les distinguer — elle filtre sur le CHEMIN, jamais sur le corps.
 *
 * I1 n'emet que `action: "get"`, et l'ecran n'offre aucun moyen d'emettre
 * autre chose : il n'y a ni champ d'edition, ni bouton d'application. C'est une
 * fermeture **par l'absence**, la seule qu'une requete forgee ne contourne pas
 * — « ne pas offrir d'entree libre plutot que la valider ».
 */
class PareFeuController extends Controller
{
    public function __construct(private Iptables $iptables)
    {
    }

    public function __invoke(Request $requete): View
    {
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);
        $roleId = (int) $requete->session()->get('role_id', 0);

        $machines = $this->iptables->machines($idCompte, $roleId);

        $lignes = [];
        foreach ($machines as $m) {
            $lignes[] = [
                'machine'  => $m,
                'sensible' => $this->iptables->estSensible($m),
            ];
        }

        /*
         * `@json` avec un litteral inline casse le PHP compile par Blade : les
         * libelles se calculent ici (defaut paye en `bashrc/` B1 — page en 500).
         *
         * Et une chaine ecrite en dur dans le JS echapperait a la parite FR/EN :
         * tout ce que le script affiche passe par cette table.
         */
        $textes = [];
        foreach ([
            'choisir', 'chargement', 'echec', 'echec_reseau',
            'releve_le', 'sensible_avert',
            'bloc_actives_v4', 'bloc_actives_v6', 'bloc_fichier_v4', 'bloc_fichier_v6',
            'bloc_vide_titre', 'bloc_vide', 'fichier_absent_titre', 'fichier_absent',
            'releve_ok', 'aucune_machine_choisie',
            'port_ssh_annonce',
        ] as $cle) {
            $textes[$cle] = __('pare-feu.' . $cle);
        }

        return view('pare-feu', [
            'lignes'    => $lignes,
            'sensibles' => $this->iptables->compteSensibles($machines),
            'total'     => count($machines),
            /*
             * Le port SSH par machine voyage avec la page. I1 s'en sert pour
             * l'annoncer au moment du choix ; I4 et I5 s'en serviront pour
             * composer un gabarit qui ne suppose pas 22. Voir le service.
             */
            'portsSsh'  => $this->iptables->portsSsh($machines),
            'textes'    => $textes,
        ]);
    }
}
