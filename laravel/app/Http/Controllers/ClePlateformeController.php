<?php

namespace App\Http\Controllers;

use App\Services\ClePlateforme;
use Illuminate\View\View;

/**
 * La cle de plateforme — sous-lot P1.
 *
 * **Ce controleur n'ecrit rien et ne joint aucune machine**, et cela reste vrai
 * apres P3 : les gestes qui ecrivent partent du NAVIGATEUR vers la passerelle,
 * comme dans le legacy. Le controleur ne fait que lire `machines` et calculer
 * les PORTEES que les panneaux de decision annoncent. La rotation (P4) n'est
 * pas portee.
 *
 * Un commentaire qui affirmerait « aucune ecriture dans ce module » serait faux :
 * la page DECLENCHE quatre ecritures distantes. Ce qui est vrai est plus etroit,
 * et c'est ce qui est ecrit ici.
 *
 * Garde : `role:1` + `perm:can_manage_platform_key`, reprise telle quelle du
 * legacy — dont l'en-tete annonce pourtant « superadmin uniquement »
 * (`platform_keys.php:4`) alors que sa ligne 11 admet les TROIS roles.
 * Cinquieme occurrence du motif E-36, et la plus mal placee des cinq : elle
 * decrit la page qui manipule la cle de la flotte.
 */
class ClePlateformeController extends Controller
{
    public function __construct(private ClePlateforme $cles)
    {
    }

    public function __invoke(): View
    {
        $machines = $this->cles->machines();
        $compteurs = $this->cles->compteurs($machines);

        $lignes = [];
        foreach ($machines as $m) {
            $lignes[] = [
                'machine'  => $m,
                'auth'     => $this->cles->etatAuth($m),
                'sensible' => $this->cles->estSensible($m),
                // Le detail des mots de passe CONNUS, en quatre valeurs et non
                // en booleen : « root seul » et « utilisateur seul » ne se
                // reparent pas de la meme facon, et c'est `root_password` qui
                // n'a aucun chemin de reecriture depuis cette page.
                'mots_de_passe' => $this->etatMotsDePasse($m),
            ];
        }

        // `@json` avec un litteral inline casse le PHP compile par Blade : les
        // libelles du script se calculent ici.
        $textes = [];
        foreach ([
            'cle_chargement', 'cle_echec', 'cle_absente_titre', 'cle_absente',
            'cle_copier', 'cle_copiee',
            // P2
            'test_en_cours', 'test_ok', 'test_rien_a_tester', 'test_echec',
            'test_indecis',
            // P3 — les gestes qui ecrivent
            'geste_en_cours', 'geste_echec_reseau', 'geste_sans_verdict',
            'geste_ligne_ok', 'geste_ligne_echec', 'geste_bilan',
            'ressaisie_mdp_vide', 'effacement_bilan',
            'effacement_interrompu', 'confirmer_saisie_manquante',
        ] as $cle) {
            $textes[$cle] = __('plateforme.' . $cle);
        }

        $portees = [
            'deployer'       => $this->cles->porteeDeploiement($machines),
            'compte_service' => $this->cles->porteeCompteService($machines),
            'effacer'        => $this->cles->porteeEffacement($machines),
        ];

        // Les panneaux de decision sont des tableaux imbriques (titre, texte,
        // liste d'effets). `__()` les rend tels quels ; les aplatir ici ferait
        // deriver la structure du catalogue et celle du script.
        $textes['panneaux'] = __('plateforme.panneaux');
        foreach (['panneau_cible_une', 'panneau_cible_n', 'panneau_prod'] as $cle) {
            $textes[$cle] = __('plateforme.' . $cle);
        }

        return view('cle-plateforme', [
            'lignes'    => $lignes,
            'compteurs' => $compteurs,
            'textes'    => $textes,
            // ══ P3 — CHAQUE GESTE DE MASSE PORTE SA PROPRE PORTEE ═════════
            //
            // Le nombre annonce sur un bouton est `count(...['ids'])` de SA
            // portee, jamais une soustraction de deux compteurs calcules sur
            // des predicats differents — c'est le defaut mesure du legacy.
            //
            // LES PORTEES PARTENT EN JSON, PAS EN ATTRIBUTS. Un `data-noms`
            // separe par des virgules serait ambigu des qu'un nom de machine
            // contient une virgule — et les noms de ce parc admettent espaces
            // et « + ». Le separateur serait un piege silencieux : la liste
            // annoncee dans le panneau differerait de la liste envoyee.
            'portees'            => $portees,
            'effacementRefusees' => $this->cles->porteeEffacementRefusees($machines),
        ]);
    }

    /**
     * Quels mots de passe RootWarden connait encore, en QUATRE valeurs.
     *
     * `remove_ssh_password` efface les DEUX colonnes ; `reenter_ssh_password`
     * n'en restaure qu'UNE (`ssh.py:1152`, `root_password` n'y figure pas). Le
     * seul chemin qui reecrit `root_password` est la page Serveurs. Un booleen
     * « a un mot de passe » cacherait exactement l'asymetrie qui compte.
     */
    private function etatMotsDePasse(object $m): string
    {
        $u = (bool) ((int) $m->a_mot_de_passe);
        $r = (bool) ((int) $m->a_mot_de_passe_root);

        if ($u && $r) {
            return 'les_deux';
        }
        if ($u) {
            return 'utilisateur';
        }

        return $r ? 'root' : 'aucun';
    }
}
