<?php

namespace App\Http\Controllers;

use App\Services\ClePlateforme;
use Illuminate\View\View;

/**
 * La cle de plateforme — sous-lot P1.
 *
 * **Ce controleur n'ecrit rien et ne joint aucune machine.** Il lit `machines`
 * et rend la page ; la cle PUBLIQUE est lue par le script, a travers la
 * passerelle. Deployer, tester, relever les comptes, effacer un mot de passe et
 * faire tourner la cle sont P2, P3 et P4.
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
        ] as $cle) {
            $textes[$cle] = __('plateforme.' . $cle);
        }

        return view('cle-plateforme', [
            'lignes'    => $lignes,
            'compteurs' => $compteurs,
            'textes'    => $textes,
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
