<?php

namespace App\Http\Controllers;

use App\Services\ParcSsh;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Deploiement des cles SSH — sous-lot K1 : la page nue.
 *
 * La garde vit DANS LA ROUTE et nulle part ailleurs : `role:1` +
 * `perm:can_deploy_keys`, REPRISE TELLE QUELLE du legacy (`ssh/index.php:34-35`).
 *
 * ECART DECLARE, non tranche ici : l'en-tete du fichier legacy annonce depuis
 * toujours « Acces refuse pour les utilisateurs standards (role_id = 1) », ce que
 * son `checkAuth` n'applique pas. Meme nature que E-36, avec une consequence plus
 * lourde : un role 1 habilite pourrait declencher le deploiement (`POST /deploy`
 * n'a ni role ni permission) et ne pourrait pas en lire le resultat (`GET /logs`
 * est `@require_role(2)`). Restreindre serait un CHANGEMENT DE DROITS : c'est une
 * decision de l'exploitant, a prendre avec D-1 pour ne pas laisser deux pages en
 * desaccord. Voir `PARITE.md`.
 *
 * K1 n'appelle AUCUNE route du backend. Le declenchement du deploiement (K4) et
 * la lecture de son flux (K3) restent sur l'ancien portail, et la page le dit.
 */
class ClesSshController extends Controller
{
    public function __construct(private ParcSsh $parc)
    {
    }

    public function __invoke(Request $requete): View
    {
        // Le role vient de la SESSION, comme dans tout le portage — c'est le
        // middleware qui l'a valide. Les PERMISSIONS, elles, sont relues en base
        // par `App\Services\Droits` : le legacy porte lui-meme l'avertissement de
        // ne jamais decider d'un droit sur `$_SESSION['permissions']`.
        $idCompte = (int) $requete->session()->get('user_id', 0);
        $role     = (int) $requete->session()->get('role_id', 0);

        $machines = $this->parc->machinesVisibles($idCompte, $role);
        $tagsParMachine = $this->parc->tagsParMachine(array_map(
            static fn ($m) => (int) $m->id, $machines
        ));
        $vocabulaire = $this->parc->vocabulaire($machines, $tagsParMachine);

        return view('cles-ssh', [
            'machines' => $machines,
            'tagsParMachine' => $tagsParMachine,
            'tags' => $vocabulaire['tags'],
            'environnements' => $vocabulaire['environnements'],
            'libelles' => $this->libelles(),
        ]);
    }

    /**
     * Les libelles consommes par le script, POSES EN DONNEES.
     *
     * Une chaine ecrite en dur dans du JS echappe a la parite FR/EN.
     *
     * @return array<string,string>
     */
    private function libelles(): array
    {
        return [
            'aucune_selection' => __('ssh.aucune_selection'),
            'selection' => __('ssh.selection', ['nombre' => '{nombre}']),
            // ── Le constat avant deploiement (sous-lot K2) ────────────────
            'verif_en_cours' => __('ssh.verif_en_cours'),
            'verif_echec' => __('ssh.verif_echec', ['statut' => '{statut}']),
            'verif_pret' => __('ssh.verif_pret'),
            'verif_bloque' => __('ssh.verif_bloque', ['nombre' => '{nombre}']),
            'cles_aucune' => __('ssh.cles_aucune'),
            'cles_nombre' => __('ssh.cles_nombre', ['nombre' => '{nombre}']),
            'a_creer' => __('ssh.a_creer'),
            'a_revoquer' => __('ssh.a_revoquer'),
            'inventaire' => __('ssh.inventaire', ['nombre' => '{nombre}']),
            'url_preflight' => url('/api/gateway/preflight_check'),
            'url_comptes_distants' => config('app.url_legacy') . '/adm/server_users.php',
            'lien_comptes_distants' => __('ssh.lien_comptes_distants'),
        ];
    }
}
