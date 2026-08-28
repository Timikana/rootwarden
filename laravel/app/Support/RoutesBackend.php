<?php

namespace App\Support;

/**
 * Ce que la passerelle accepte de transmettre au backend Python.
 *
 * SOURCE UNIQUE. Le legacy tient ces listes dans api_proxy.php ; elles sont
 * reprises ici a l'identique, avec UNE difference : la comparaison.
 *
 * ── Prefixe contre segment ───────────────────────────────────────────────────
 * Le legacy compare par debut de chaine : `strpos($path, $prefix) === 0`.
 * `/search` autorise donc `/searchall`, `/groups` autorise `/groupsecret`, et
 * toute route Python future dont le nom commence par un prefixe autorise
 * devient publique sans que personne ne l'ait decide.
 *
 * Ici, une entree se lit selon sa FORME :
 *   se terminant par '/'        espace de noms   '/fail2ban/' couvre tout ce
 *                                                qui commence par '/fail2ban/'
 *   se terminant par '_' ou '-' racine voulue    '/cve_' couvre '/cve_scan'
 *   sinon                       route exacte     '/search' couvre '/search' et
 *                                                '/search/xyz', PAS '/searchall'
 *
 * Verification faite avant de resserrer, sur les 201 routes REELLEMENT
 * declarees dans backend/ : les deux filtres rendent le MEME verdict, zero
 * difference. Le resserrement ne coute donc rien et refuse en plus des chemins
 * comme `/searchall`, `/command_logger` ou `/updateXYZ`.
 */
class RoutesBackend
{
    /** Releve fidele de ALLOWED_PROXY_PREFIXES (legacy/api_proxy.php). */
    public const LISTE_BLANCHE = [
        '/test', '/list_machines', '/filter_servers',
        '/server_status', '/linux_version', '/last_reboot', '/reboot_server',
        '/cve_', '/cron_preview',
        '/deploy', '/preflight_check',
        '/platform_key', '/deploy_platform_key', '/test_platform_key',
        '/deploy_service_account', '/revoke_service_account', '/regenerate_platform_key',
        '/remove_ssh_password', '/reenter_ssh_password',
        '/scan_server_users', '/sshd_allow_user',
        /*
         * `/server_users_inventory` (E-200) N'EST PAS DANS LE PROXY LEGACY, ET
         * CETTE LISTE CESSE DONC D'EN ETRE UN RELEVE FIDELE — c'est dit ici
         * plutot que laisse a la lecture suivante.
         *
         * La route est NEE pour le portage : elle rend l'inventaire des comptes
         * distants avec `nom_valide` et `motif_invalide`, que la page a besoin de
         * connaitre AU CHARGEMENT et qui n'existaient qu'au retour d'un scan.
         * Aucune page du legacy ne l'appelle, et l'ajouter a
         * `ALLOWED_PROXY_PREFIXES` elargirait la surface d'un proxy de PRODUCTION
         * pour une route sans appelant. On ne l'y ajoute donc pas.
         *
         * Sens de la divergence : le portage autorise UNE route de plus que le
         * legacy, et cette route ne fait que LIRE — elle ne joint aucune machine.
         */
        '/server_users_inventory',
        /*
         * `/machines/credential-status` (E-219) : MEME REGIME QUE CI-DESSUS, et
         * pour la meme raison — nee pour le portage, absente du proxy legacy, on
         * ne l'ajoute pas a `ALLOWED_PROXY_PREFIXES` d'un proxy de PRODUCTION.
         *
         * Elle repond a une question que le portage ne peut PAS calculer :
         * « ce secret dechiffre-t-il en vide ? ». Le test SQL `(password <> '')`
         * est faux, parce que PHP chiffre la chaine vide en `sodium:…` la ou
         * Python rend `''` — donc la colonne est NON VIDE pour un mot de passe
         * REELLEMENT vide. Seul le detenteur de la cle peut trancher, et
         * recopier le dechiffrement ici serait recopier une regle de securite.
         *
         * ELLE N'EST PAS DANS `ADMIN_SEULEMENT`, ET C'EST DELIBERE. Ce groupe
         * exige un role >= 2 a la passerelle ; or la page de la cle de
         * plateforme s'ouvre des le role 1 avec `can_manage_platform_key`. L'y
         * mettre rendrait la reponse inaccessible a des comptes que la page
         * admet, et l'ecran afficherait « indetermine » partout — un refus
         * d'acces deguise en incapacite de lecture. La borne juste est celle que
         * la route porte deja : `check_machine_access` DANS LE CORPS, machine
         * par machine, comme `/list_machines`. Elle ne joint aucune machine et
         * ne rend JAMAIS un secret, seulement un predicat sur lui.
         *
         * ET CETTE BOUCLE N'EST PAS UN CLOISONNEMENT DE FLOTTE — a ne pas
         * relire comme tel. `check_machine_access` rend `True` SANS CONDITION
         * des le role 2 (`helpers.py:299`) : le filtre ne mord donc qu'au
         * role 1. Un role 2 porteur de la permission voit tout le parc, ce qui
         * est coherent avec la garde de la page et avec le reste du depot. Ce
         * n'est pas un defaut ; le prendre pour une segmentation ferait
         * conclure de travers a la prochaine lecture.
         */
        '/machines/credential-status',
        /*
         * `/settings/announceable` : MEME REGIME, et pour P4. Elle rend la
         * valeur EFFECTIVE d'une liste fermee de reglages — dont
         * `platform_key_archive_days`, la duree pendant laquelle une cle de
         * plateforme detruite reste rejouable depuis son archive.
         *
         * POURQUOI LA LIRE PLUTOT QUE D'ECRIRE « 30 ». Cette duree est
         * configurable. Un nombre recopie dans un gabarit devient faux le jour
         * ou l'exploitant la change, et il devient faux EN SILENCE : l'ecran
         * continue d'annoncer une reversibilite de 30 jours sur un geste
         * irreversible. Un nombre affiche comme une garantie et fige dans un
         * autre fichier est un mensonge a retardement.
         *
         * PAS DANS `ADMIN_SEULEMENT` non plus : la route se garde par
         * `@require_api_key` SEULE, et le backend le DECLARE avec son motif —
         * aucune des douze valeurs ne distingue un utilisateur d'un autre, et ce
         * qui la borne est la liste fermee, pas un decorateur. Exiger un role
         * ici donnerait a croire qu'il y a la quelque chose a proteger.
         */
        '/settings/announceable',
        '/server_user_keys', '/server_user_remove_key',
        '/remove_user_keys', '/delete_remote_user',
        '/logs', '/update', '/update-logs', '/update_zabbix', '/update_security_exec',
        '/apt_check_lock', '/apt_update', '/security_updates',
        '/dpkg_repair', '/custom_update', '/dry_run_update', '/pending_packages',
        '/schedule_update', '/schedule_advanced_update', '/schedule_advanced_security_update',
        '/iptables', '/iptables-',
        '/fail2ban/', '/ssh-audit/', '/supervision/', '/graylog/', '/wazuh/',
        '/services/', '/admin/', '/bashrc/',
        '/exclude_user', '/server_lifecycle',
        '/policy/', '/drift/', '/tasks/',
        '/groups', '/maintenance/', '/approvals', '/command_log',
        '/chatops/users', '/tickets', '/search', '/docker/',
    ];

    /**
     * Releve fidele de ADMIN_ONLY_PREFIXES. Le backend protege deja ces routes
     * par ses propres decorateurs : c'est une defense en profondeur, on ne
     * depend jamais d'un seul rempart.
     */
    public const ADMIN_SEULEMENT = [
        '/deploy_service_account', '/revoke_service_account', '/regenerate_platform_key',
        '/deploy_platform_key', '/remove_ssh_password', '/reenter_ssh_password',
        '/scan_server_users', '/sshd_allow_user', '/remove_user_keys', '/delete_remote_user',
        /*
         * Meme famille que `/scan_server_users`, juste au-dessus : cette route
         * ENUMERE DES NOMS DE COMPTES. Le backend la garde par `@require_role(2)`
         * et la page l'exige aussi ; la citer ici est la defense en profondeur que
         * cette classe annonce. Absente du legacy pour la raison dite plus haut.
         */
        '/server_users_inventory',
        '/server_user_remove_key', '/admin/', '/policy/', '/exclude_user',
        '/server_lifecycle', '/update_security_exec', '/drift/', '/tasks/',
        '/groups', '/maintenance/windows', '/approvals', '/command_log',
        '/chatops/users', '/tickets', '/search',
        /*
         * `/supervision/` EST ABSENT DE `ADMIN_ONLY_PREFIXES` COTE LEGACY, et cette
         * liste en etait le releve fidele — elle recopiait donc le trou. Or la page
         * de supervision exige `role:2` des deux cotes : personne de legitime ne
         * perd un acces en l'ajoutant ici, et un role 1 porteur de
         * `can_manage_supervision` cesse de pouvoir appeler
         * `/api/gateway/supervision/profiles` — que le backend, lui, ne garde par
         * aucun `@require_role` (E-77). C'est exactement la defense en profondeur
         * que le commentaire de cette classe annonce : on ne depend jamais d'un
         * seul rempart. Le legacy garde son trou, et il est declare.
         */
        '/supervision/',
        /*
         * ══ E-235 : `/wazuh/` — MEME MOTIF, MEME REMEDE ═══════════════════
         *
         * `/wazuh/` est dans la liste blanche et ABSENT de la reserve a
         * l'administration : la passerelle le laisse donc passer pour un role 1
         * porteur de `can_manage_wazuh`.
         *
         * **Ce n'est PAS un trou** : les 15 routes du module portent
         * `@require_role(2)` cote backend — releve par analyse syntaxique, pas
         * par motif textuel, parce qu'un `grep` rend l'inverse sur ce fichier.
         * L'appel serait donc refuse. C'est **un rempart manquant sur deux**.
         *
         * Et la page exige `role:2` des DEUX cotes : le legacy fait
         * `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` (`wazuh/index.php:25`) et la
         * route portee `role:2`. **Personne de legitime ne perd un acces en
         * l'ajoutant ici** — c'est la meme demonstration que pour
         * `/supervision/` juste au-dessus.
         *
         * DIVERGENCE DECLAREE : `ADMIN_ONLY_PREFIXES` du legacy ne le porte pas.
         * Cette liste cesse donc d'en etre le releve fidele sur une entree de
         * plus — dit ici plutot que laisse a la lecture suivante, comme pour
         * `/server_users_inventory` et `/machines/credential-status`.
         *
         * On ne depend jamais d'un seul rempart.
         */
        '/wazuh/',
        /*
         * ══ E-235c : LES DEUX ROUTES DE PARC, ET ELLES SEULES ═════════════
         *
         * On m'a demande d'ajouter `/ssh-audit/` et `/cve_` en entier, au motif
         * que leurs routes de parc ne portent qu'un role. **Le motif est juste,
         * la portee demandee ne l'est pas** — et le test decisif est celui que
         * le precedent `/supervision/` impose lui-meme : *personne de legitime
         * ne doit perdre un acces.*
         *
         * MESURE. Les deux pages admettent le ROLE 1 avec leur permission, des
         * deux cotes :
         *   `security/index.php:37`  checkAuth([ROLE_USER, …]) + can_scan_cve
         *   `ssh-audit/index.php:12` checkAuth([ROLE_USER, …]) + can_audit_ssh
         *   portage : `/scan-cve` en `role:1` + `perm:can_scan_cve`
         *
         * Et un role 1 porteur de la permission atteint aujourd'hui `/cve_scan`,
         * `/cve_results`, `/cve_history`, `/cve_compare`, `/cve_reprioritize` —
         * TOUTES gardees par `@require_machine_access`, c'est-a-dire la garde
         * qui MORD au role 1 et le borne a SES machines.
         *
         * Fermer le prefixe entier remplacerait donc une borne PRECISE (vos
         * machines) par une borne AVEUGLE (personne sous le role 2), et
         * casserait la page pour les comptes auxquels elle est destinee. Ce
         * serait le contraire du precedent invoque.
         *
         * CE QUI SE FERME SANS RIEN COUTER : les deux routes de PARC, qui n'ont
         * aucune borne par machine et que le backend garde deja par
         * `@require_role(2)` seul. Un role 1 n'y a jamais eu acces.
         *
         *   /ssh-audit/scan-all   require_api_key + require_role(2)
         *   /cve_scan_all         require_api_key + require_role(2)
         *
         * Ce sont des entrees EXACTES : la comparaison par segment fait que
         * `/cve_scan_all` ne couvre pas `/cve_scan`, verifie.
         *
         * DIVERGENCE DECLAREE : le legacy ne les porte pas dans
         * `ADMIN_ONLY_PREFIXES`.
         *
         * ET DEUX ROUTES QUE LE RELEVE N'AVAIT PAS NOMMEES : `/cve_trends` et
         * `/cve_test_connection` portent `@require_api_key` SEUL — ni role, ni
         * permission, ni borne par machine. Ce sont des lectures, mais
         * `/cve_trends` rend des donnees de flotte. Signale, non ferme : elles
         * sont couvertes par le prefixe `/cve_` de la liste blanche, et les
         * fermer une par une sans arbitrage refait le defaut ci-dessus en petit.
         */
        '/ssh-audit/scan-all',
        '/cve_scan_all',
    ];

    /**
     * Routes exigeant une re-authentification ponctuelle. Changer une politique
     * sudoers ou un bloc Match User donne de fait root sur la machine cible.
     *
     * Le step-up est porte depuis A5 : la passerelle exige une marque fraiche
     * puis transmet, au lieu de refuser en bloc. Voir `App\Services\StepUp`.
     *
     * Le nom de l'action est DERIVE du chemin (`actionStepUp`) et non pris dans
     * une table : ajouter un motif suffit a doter la route de son propre nom.
     * Le legacy, lui, fusionne les trois routes root sous `policy_action`, si
     * bien qu'un step-up consenti pour ANNULER une politique autorise un
     * DEPLOIEMENT sudo pendant quinze minutes.
     */
    public const MOTIFS_STEP_UP = [
        '#^/policy/(sudo|sftp)/(deploy|remove)$#',
        '#^/policy/rollback$#',
    ];

    /** Le chemin est-il transmissible au backend ? */
    public static function autorisee(string $chemin): bool
    {
        return self::correspond($chemin, self::LISTE_BLANCHE);
    }

    /** Le chemin est-il reserve aux roles administrateur et au-dessus ? */
    public static function reserveeAdmin(string $chemin): bool
    {
        return self::correspond($chemin, self::ADMIN_SEULEMENT);
    }

    /**
     * Routes dont la reponse est un FLUX `text/plain`, tenu ouvert pendant que
     * la commande tourne sur la machine.
     *
     * La passerelle les relaie morceau par morceau au lieu de lire tout le
     * corps avant de repondre : une mise a jour de securite dure des minutes,
     * et un ecran qui ne bouge pas ne distingue pas un travail long d'un
     * blocage. Liste EXPLICITE et courte : le relais bufferise reste la regle,
     * et c'est lui que le reste du portage utilise.
     *
     * Le contenu de ces flux vient d'un pseudo-terminal. Il a porte le mot de
     * passe root jusqu'au 2026-08-19 — voir `filtre_echo_mot_de_passe()` cote
     * backend et PARITE.md, E-17.
     */
    public const EN_FLUX = [
        '/update',
        '/dry_run_update',
        '/security_updates',
        /*
         * SOUS-LOT V12 : LE DEPLOIEMENT INSTALLE, DONC IL TELECHARGE.
         *
         * Les autres gestes de `supervision/` restent bufferises, et c'est une
         * decision prise sur mesure : une reconfiguration d'une machine dure
         * 1,4 s. Le deploiement, lui, a ete remesure parce qu'il n'est pas de
         * la meme nature — il ajoute un depot, rafraichit les index apt et
         * installe des paquets.
         *
         * Mesure sur le banc d'essai : 9 270 ms. Cela passe dans les 120 s du
         * delai ordinaire. Mais ce chiffre est un PLANCHER, pas un plafond :
         * le banc n'a ni resolution DNS ni paquet a telecharger, donc chaque
         * etape reseau y echoue immediatement. Un deploiement reel tire un
         * `.deb` puis installe un agent et ses greffons — 120 s ne sont pas un
         * majorant credible, et un depassement rendrait une erreur de
         * passerelle alors que l'installation, elle, continuerait sur la
         * machine. Le pire des verdicts : « echec » sur un geste qui a reussi.
         *
         * Ces quatre chemins sont donc relayes morceau par morceau (delai 900 s).
         * `estUnFlux` est evaluee APRES les trois refus (liste blanche, reserve
         * a l'administration, re-authentification) : ce reglage ne change qu'un
         * delai et un mode de relais, aucune garde.
         */
        '/supervision/zabbix/deploy',
        '/supervision/centreon/deploy',
        '/supervision/prometheus/deploy',
        '/supervision/telegraf/deploy',
    ];

    /** Le chemin doit-il etre relaye morceau par morceau ? */
    public static function estUnFlux(string $chemin): bool
    {
        return in_array(rtrim($chemin, '/'), self::EN_FLUX, true);
    }

    /** Le chemin exige-t-il une re-authentification ponctuelle ? */
    public static function exigeStepUp(string $chemin): bool
    {
        return self::actionStepUp($chemin) !== null;
    }

    /**
     * Le nom de l'action exigee par ce chemin, ou `null` s'il n'en exige aucune.
     *
     * UN NOM PAR ROUTE : `/policy/sudo/deploy` -> `policy_sudo_deploy`. C'est ce
     * qui distingue ce portage du legacy, ou les trois routes root partagent
     * `policy_action`.
     */
    public static function actionStepUp(string $chemin): ?string
    {
        foreach (self::MOTIFS_STEP_UP as $motif) {
            if (preg_match($motif, $chemin) === 1) {
                return preg_replace('/[^a-z0-9]+/', '_', trim(strtolower($chemin), '/'));
            }
        }

        return null;
    }

    /**
     * Le chemin correspondant a un nom d'action, ou `null` si ce nom n'en
     * designe aucun. C'est la LISTE FERMEE des actions acceptables.
     *
     * La reciproque se calcule, puis elle est **verifiee par aller-retour** :
     * `policy_sudo_deploy` -> `/policy/sudo/deploy` -> `policy_sudo_deploy`. Si
     * un chemin garde portait un jour un blanc soulignement, l'aller-retour
     * echouerait et le nom serait REFUSE — fail-closed, plutot que d'ouvrir une
     * marque sur un chemin voisin.
     */
    public static function cheminStepUp(string $action): ?string
    {
        if ($action === '' || preg_match('/^[a-z0-9_]+$/', $action) !== 1) {
            return null;
        }

        $chemin = '/' . str_replace('_', '/', $action);

        return self::actionStepUp($chemin) === $action ? $chemin : null;
    }

    /**
     * Un chemin est-il couvert par l'une des entrees ? Voir l'en-tete de classe
     * pour la lecture des trois formes.
     *
     * @param  list<string>  $entrees
     */
    private static function correspond(string $chemin, array $entrees): bool
    {
        foreach ($entrees as $entree) {
            $derniere = substr($entree, -1);

            if ($derniere === '/' || $derniere === '_' || $derniere === '-') {
                if (str_starts_with($chemin, $entree)) {
                    return true;
                }
            } elseif ($chemin === $entree || str_starts_with($chemin, $entree . '/')) {
                return true;
            }
        }

        return false;
    }
}
