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
        '/server_user_remove_key', '/admin/', '/policy/', '/exclude_user',
        '/server_lifecycle', '/update_security_exec', '/drift/', '/tasks/',
        '/groups', '/maintenance/windows', '/approvals', '/command_log',
        '/chatops/users', '/tickets', '/search',
    ];

    /**
     * Routes exigeant une re-authentification ponctuelle. Changer une politique
     * sudoers ou un bloc Match User donne de fait root sur la machine cible.
     *
     * Le step-up n'est PAS encore porte : la passerelle refuse ces routes au
     * lieu de les transmettre. Un refus explicite vaut mieux qu'une action
     * root accordee sans le second controle que le legacy exige.
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
    ];

    /** Le chemin doit-il etre relaye morceau par morceau ? */
    public static function estUnFlux(string $chemin): bool
    {
        return in_array(rtrim($chemin, '/'), self::EN_FLUX, true);
    }

    /** Le chemin exige-t-il une re-authentification ponctuelle ? */
    public static function exigeStepUp(string $chemin): bool
    {
        foreach (self::MOTIFS_STEP_UP as $motif) {
            if (preg_match($motif, $chemin) === 1) {
                return true;
            }
        }

        return false;
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
