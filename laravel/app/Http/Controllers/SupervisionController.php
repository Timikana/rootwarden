<?php

namespace App\Http\Controllers;

use App\Services\Supervision;
use Illuminate\View\View;

/**
 * Supervision — module `supervision/`.
 *
 * Sous-lot V1 : la page et ses quatre onglets. Sous-lot V2 : le catalogue de
 * profils, en LECTURE — le CRUD et l'assignation restent a V5.
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
    /**
     * Ce que chaque plateforme affiche, dans l'ordre : cle de colonne => cle i18n.
     *
     * `hostname_pattern` et `extra_config` sont communs aux quatre. Les deux
     * secrets (`tls_psk_value`, `telegraf_output_token`) n'y figurent PAS : ils ne
     * sont meme pas lus en base, seule leur presence l'est.
     *
     * `updated_at` n'est volontairement pas affiche : il est ecrit par MySQL, donc
     * dans le fuseau du conteneur de base, et l'afficher ferait entrer dans cette
     * page le decalage declare en PARITE E-73. V3 montre la configuration, pas sa
     * piste d'audit.
     */
    private const CHAMPS_PAR_PLATEFORME = [
        'zabbix' => [
            'agent_type' => 'type_agent',
            'agent_version' => 'version_agent',
            'zabbix_server' => 'serveur',
            'zabbix_server_active' => 'serveur_actif',
            'listen_port' => 'port',
            'hostname_pattern' => 'motif_nom',
            'tls_connect' => 'tls_connexion',
            'tls_accept' => 'tls_acceptation',
            'tls_psk_identity' => 'psk_identite',
            'host_metadata_template' => 'metadonnees',
            'extra_config' => 'config_supplementaire',
        ],
        'centreon' => [
            'centreon_host' => 'centreon_hote',
            'centreon_port' => 'centreon_port',
            'hostname_pattern' => 'motif_nom',
            'extra_config' => 'config_supplementaire',
        ],
        'prometheus' => [
            'prometheus_listen' => 'prometheus_ecoute',
            'prometheus_collectors' => 'prometheus_collecteurs',
            'hostname_pattern' => 'motif_nom',
            'extra_config' => 'config_supplementaire',
        ],
        'telegraf' => [
            'telegraf_output_url' => 'telegraf_url',
            'telegraf_output_org' => 'telegraf_organisation',
            'telegraf_output_bucket' => 'telegraf_seau',
            'telegraf_inputs' => 'telegraf_entrees',
            'hostname_pattern' => 'motif_nom',
            'extra_config' => 'config_supplementaire',
        ],
    ];

    public function __construct(private Supervision $supervision)
    {
    }

    public function __invoke(): View
    {
        return view('supervision', [
            'onglets' => $this->supervision->onglets(),
            'plateformes' => $this->supervision->plateformes(),
            'machines' => $this->supervision->machines(),
            'profils' => $this->supervision->profilsParPlateforme(),
            'configuration' => $this->supervision->configurationParPlateforme(),
            /*
             * Les champs a rendre, PAR PLATEFORME. Une liste explicite plutot
             * qu'un parcours des colonnes : `supervision_config` porte les
             * colonnes des QUATRE plateformes sur la meme ligne, et les afficher
             * toutes ferait lire a un exploitant de Centreon des reglages Zabbix
             * qui ne s'appliquent pas a lui.
             */
            'champs' => self::CHAMPS_PAR_PLATEFORME,
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
