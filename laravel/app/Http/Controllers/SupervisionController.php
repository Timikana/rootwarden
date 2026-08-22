<?php

namespace App\Http\Controllers;

use App\Services\Supervision;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
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
    /**
     * Les colonnes a CHOIX FERME, et leurs valeurs admises.
     *
     * `tls_connect` et `tls_accept` sont des `enum` EN BASE
     * (`enum('unencrypted','psk','cert')`) : un champ de texte libre par-dessus
     * une colonne enumeree laisse taper une valeur que MySQL refusera — une
     * erreur d'ecriture la ou l'utilisateur attendait un enregistrement. Vu a
     * l'image sur la premiere version de ce formulaire.
     *
     * `agent_type` et `agent_version` sont des `varchar`, mais le legacy n'y offre
     * que deux valeurs chacun : les laisser libres inviterait a inventer un nom
     * d'agent que le deploiement ne saurait pas installer.
     */
    private const CHOIX_PAR_COLONNE = [
        'agent_type' => ['zabbix-agent', 'zabbix-agent2'],
        'agent_version' => ['7.0', '7.2'],
        'tls_connect' => ['unencrypted', 'psk', 'cert'],
        'tls_accept' => ['unencrypted', 'psk', 'cert'],
    ];

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
            'choix' => self::CHOIX_PAR_COLONNE,
            'libelles' => $this->libelles(),
        ]);
    }

    /**
     * Enregistre la configuration globale d'une plateforme — sous-lot V4.
     *
     * UNE SOUMISSION DE FORMULAIRE, PAS UN APPEL CLIENT. Le portage n'ouvre
     * aucune requete depuis le navigateur : le formulaire part en POST, le
     * controleur ecrit, et la page revient avec son message. Trois suites du
     * module assertent qu'aucun appel client ne partait de cette page — cette
     * propriete reste vraie.
     *
     * LES CHAMPS ECRITS SONT CEUX DE `CHAMPS_PAR_PLATEFORME`, et eux seuls. Le
     * legacy, lui, force `hostname_pattern` et `extra_config` pour les trois
     * plateformes non-Zabbix (`main.js:186`) : deux champs que l'utilisateur
     * remplit et que l'enregistrement jette. Ici ce qui est affiche est ce qui est
     * ecrit.
     */
    public function enregistrer(Request $requete): RedirectResponse
    {
        $plateforme = (string) $requete->input('plateforme', '');
        if (! array_key_exists($plateforme, self::CHAMPS_PAR_PLATEFORME)) {
            return redirect()->route('supervision')
                ->with('superv_erreur', __('superv.enregistrement_plateforme_inconnue'));
        }

        // LE CHAMP EXIGE, PAR PLATEFORME. Le legacy refuse un `zabbix_server`
        // vide ; le meme raisonnement vaut pour l'hote Centreon, qui sans valeur
        // produirait une configuration d'agent inerte.
        $exiges = ['zabbix' => 'zabbix_server', 'centreon' => 'centreon_host'];
        $exige = $exiges[$plateforme] ?? null;
        if ($exige !== null && trim((string) $requete->input($exige, '')) === '') {
            return redirect()->route('supervision')
                ->with('superv_erreur', __('superv.enregistrement_champ_exige', [
                    'champ' => __('superv.champ_' . self::CHAMPS_PAR_PLATEFORME[$plateforme][$exige]),
                ]));
        }

        $valeurs = [];
        foreach (array_keys(self::CHAMPS_PAR_PLATEFORME[$plateforme]) as $colonne) {
            $brut = $requete->input($colonne);
            $brut = is_string($brut) ? trim($brut) : $brut;
            // Une colonne nullable vide se stocke a NULL, pas a la chaine vide :
            // la lecture (V3) distingue « non renseigne » de « renseigne vide »,
            // et l'ecriture doit lui donner de quoi le faire.
            $valeurs[$colonne] = ($brut === '' || $brut === null) ? null : $brut;

            /*
             * UNE COLONNE A CHOIX FERME NE PREND QUE SES VALEURS. La liste est
             * cote serveur : un `<select>` empeche la faute a l'ecran, il
             * n'empeche rien du tout dans une requete forgee — et derriere il y a
             * un `enum` MySQL qui refuserait l'ecriture, donc une erreur au lieu
             * d'un refus lisible. Hors liste : on garde la valeur DEJA en base.
             */
            if (isset(self::CHOIX_PAR_COLONNE[$colonne])
                && ! in_array($valeurs[$colonne], self::CHOIX_PAR_COLONNE[$colonne], true)) {
                unset($valeurs[$colonne]);
            }
        }
        // `listen_port` et `centreon_port` sont des entiers en base : une chaine
        // vide y deviendrait 0, un port qui n'existe pas.
        foreach (['listen_port', 'centreon_port'] as $entier) {
            if (array_key_exists($entier, $valeurs)) {
                $valeurs[$entier] = $valeurs[$entier] === null ? null : (int) $valeurs[$entier];
            }
        }

        $this->supervision->enregistreConfiguration(
            $plateforme,
            $valeurs,
            // Un PSK vide veut dire « ne change rien », jamais « efface ».
            $plateforme === 'zabbix' ? (string) $requete->input('tls_psk_value', '') : null,
            (int) $requete->session()->get('user_id', 0),
        );

        return redirect()->route('supervision')
            ->with('superv_message', __('superv.enregistrement_fait', [
                'plateforme' => ucfirst($plateforme),
            ]));
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
