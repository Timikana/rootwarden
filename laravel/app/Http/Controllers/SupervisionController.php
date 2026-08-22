<?php

namespace App\Http\Controllers;

use App\Services\Supervision;
use Illuminate\View\View;

/**
 * Supervision — module `supervision/`, sous-lot V1 : la page et ses quatre onglets.
 *
 * La garde vit DANS LA ROUTE et nulle part ailleurs : `role:2` +
 * `perm:can_manage_supervision`, REPRISE TELLE QUELLE du legacy
 * (`supervision/index.php:17-18`, `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` puis
 * `checkPermission('can_manage_supervision')`).
 *
 * AUCUN ECART A DECLARER SUR LA GARDE, et c'est assez rare pour etre dit :
 * contrairement a `ssh/` et a `security/`, l'en-tete de ce fichier legacy annonce
 * « Permissions : admin (2) + superadmin (3) + can_manage_supervision » et son
 * code applique exactement cela.
 *
 * V1 N'APPELLE AUCUNE ROUTE DU BACKEND. Le legacy, lui, en appelle deux des le
 * chargement et les rejoue a chaque bascule d'onglet : le catalogue de profils
 * arrive d'emblee. Ici tout est peint cote serveur, et le script ne fait que
 * montrer et cacher des panneaux deja rendus.
 */
class SupervisionController extends Controller
{
    public function __construct(private Supervision $supervision)
    {
    }

    public function __invoke(): View
    {
        return view('supervision', [
            'onglets' => $this->supervision->onglets(),
            'plateformes' => $this->supervision->plateformes(),
            'machines' => $this->supervision->machines(),
            'libelles' => $this->libelles(),
        ]);
    }

    /**
     * Les libelles consommes par le script, POSES EN DONNEES.
     *
     * C'EST ICI QUE V1 FERME LA DETTE i18n DU MODULE. Cote legacy, le JS lit ses
     * libelles dans `window._i18n`, alimente par `getJsTranslations('js.')` : onze
     * cles du module vivent dans `supervision.php` et pas dans `js.php`, et
     * `head.php` rend alors la CLE elle-meme. Comme une cle est une chaine non
     * vide, l'idiome `__('x') || 'repli'` ne replie jamais — la panne est
     * silencieuse et l'ecran affiche `editor_select_server`.
     *
     * Ici il n'y a pas deux catalogues : les libelles partent du MEME
     * `lang/<langue>/superv.php` que la page, en donnees, sur UNE ligne (`@json`
     * multiligne casse le PHP compile). Le defaut ne peut donc pas se reformer.
     *
     * @return array<string,string>
     */
    private function libelles(): array
    {
        return [
            'editeur_sans_serveur' => __('superv.editeur_sans_serveur'),
            'editeur_non_porte' => __('superv.a_venir_editeur'),
        ];
    }
}
