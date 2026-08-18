<?php

namespace App\Support;

/**
 * Le menu du portail — SOURCE UNIQUE.
 *
 * Le legacy decrit son menu DEUX FOIS : une fois en barre laterale, une fois en
 * tiroir mobile, avec la logique de droits recopiee dans les deux. Une decision
 * recopiee finit toujours par diverger. Ici, les deux rendus lisent ce tableau.
 *
 * Chaque entree porte :
 *   'cle'      cle i18n dans lang/{fr,en}/nav.php (sans prefixe)
 *   'garde'    'tous' | 'sa' | 'admin' | une permission ('can_*')
 *              Une permission vaut TOUJOURS « cette permission OU superadmin »,
 *              comme le legacy.
 *   'feature'  drapeau de fonctionnalite exige, facultatif
 *   'route'    nom de route Laravel si la page est PORTEE
 *   'legacy'   chemin sur l'ancien portail si elle ne l'est pas
 *
 * Une entree porte 'route' OU 'legacy', jamais les deux : c'est ce qui rend
 * l'etat du portage visible d'un coup d'oeil, et verifiable par un test.
 */
class Navigation
{
    /**
     * Releve fidele du menu de legacy/menu.php au 2026-08-18 : 32 entrees,
     * 3 sections. Les gardes sont celles du legacy, a l'identique.
     */
    public const SECTIONS = [
        'navigation' => [
            ['cle' => 'dashboard',      'garde' => 'tous',                    'route'  => 'accueil'],
            ['cle' => 'ssh_keys',       'garde' => 'can_deploy_keys',         'legacy' => '/ssh/'],
            ['cle' => 'updates',        'garde' => 'can_update_linux',        'legacy' => '/update/'],
            ['cle' => 'iptables',       'garde' => 'can_manage_iptables',     'legacy' => '/iptables/'],
            ['cle' => 'fail2ban',       'garde' => 'can_manage_fail2ban',     'legacy' => '/fail2ban/'],
            ['cle' => 'services',       'garde' => 'can_manage_services',     'legacy' => '/services/'],
            ['cle' => 'ssh_audit',      'garde' => 'can_audit_ssh',           'legacy' => '/ssh-audit/'],
            ['cle' => 'supervision',    'garde' => 'can_manage_supervision',  'legacy' => '/supervision/'],
            ['cle' => 'bashrc',         'garde' => 'can_manage_bashrc',       'legacy' => '/bashrc/'],
            ['cle' => 'graylog',        'garde' => 'can_manage_graylog',      'legacy' => '/graylog/'],
            ['cle' => 'wazuh',          'garde' => 'can_manage_wazuh',        'legacy' => '/wazuh/', 'feature' => 'wazuh'],
            ['cle' => 'cve_scan',       'garde' => 'can_scan_cve',            'legacy' => '/security/'],
            // Garde par ROLE et non par permission : releve tel quel du legacy.
            // L'ecart est signale dans INVENTAIRE.md — a arbitrer, pas a corriger
            // en silence pendant un portage de navigation.
            ['cle' => 'docker',         'garde' => 'admin',                   'legacy' => '/docker/index.php'],
        ],

        'admin' => [
            ['cle' => 'admin',          'garde' => 'can_admin_portal',        'legacy' => '/adm/admin_page.php'],
            ['cle' => 'tasks',          'garde' => 'can_admin_portal',        'legacy' => '/tasks/index.php'],
            ['cle' => 'groups',         'garde' => 'can_admin_portal',        'legacy' => '/groups/index.php'],
            ['cle' => 'maintenance',    'garde' => 'can_admin_portal',        'legacy' => '/maintenance/index.php'],
            ['cle' => 'approvals',      'garde' => 'can_admin_portal',        'legacy' => '/approvals/index.php'],
            ['cle' => 'commandlog',     'garde' => 'can_admin_portal',        'legacy' => '/commandlog/index.php'],
            ['cle' => 'chatops',        'garde' => 'can_admin_portal',        'legacy' => '/chatops/index.php'],
            ['cle' => 'tickets',        'garde' => 'can_admin_portal',        'legacy' => '/tickets/index.php'],
            ['cle' => 'search',         'garde' => 'can_admin_portal',        'legacy' => '/search/index.php'],
            ['cle' => 'audit_log',      'garde' => 'can_admin_portal',        'legacy' => '/adm/audit_log.php'],
            ['cle' => 'backups',        'garde' => 'can_admin_portal',        'legacy' => '/backups/index.php'],
            ['cle' => 'remote_users',   'garde' => 'can_manage_remote_users', 'legacy' => '/adm/server_users.php'],
            ['cle' => 'platform_key',   'garde' => 'can_manage_platform_key', 'legacy' => '/adm/platform_keys.php'],
            ['cle' => 'sudo_policies',  'garde' => 'sa',                      'legacy' => '/adm/server_user_sudo.php'],
            ['cle' => 'sftp_policies',  'garde' => 'sa',                      'legacy' => '/adm/server_user_sftp.php'],
            ['cle' => 'compliance',     'garde' => 'can_view_compliance',     'legacy' => '/security/compliance_report.php'],
            ['cle' => 'drift',          'garde' => 'can_view_compliance',     'legacy' => '/drift/index.php'],
        ],

        'other' => [
            ['cle' => 'profil',         'garde' => 'tous',                    'route'  => 'profil'],
            ['cle' => 'documentation',  'garde' => 'tous',                    'legacy' => '/documentation.php'],
            ['cle' => 'api_docs',       'garde' => 'sa',                      'legacy' => '/api/docs.php'],
        ],
    ];

    /**
     * Rend les sections visibles pour un jeu de droits donne, entrees filtrees.
     * Une section vide n'est pas rendue : un intitule de section sans rien
     * dessous laisse croire qu'un contenu a disparu.
     *
     * @param  array<string,bool>  $permissions
     * @return array<string, list<array<string,mixed>>>
     */
    public static function pour(int $roleId, array $permissions, array $fonctionnalites = []): array
    {
        $visibles = [];

        foreach (self::SECTIONS as $section => $entrees) {
            $retenues = [];
            foreach ($entrees as $entree) {
                if (isset($entree['feature']) && ! ($fonctionnalites[$entree['feature']] ?? true)) {
                    continue;
                }
                if (self::autorisee($entree['garde'], $roleId, $permissions)) {
                    $retenues[] = $entree;
                }
            }
            if ($retenues !== []) {
                $visibles[$section] = $retenues;
            }
        }

        return $visibles;
    }

    /**
     * Une permission vaut « cette permission OU superadmin », comme le legacy.
     * Le superadmin est le role 3.
     */
    private static function autorisee(string $garde, int $roleId, array $permissions): bool
    {
        return match ($garde) {
            'tous'  => true,
            'sa'    => $roleId >= 3,
            'admin' => $roleId >= 2,
            default => ($permissions[$garde] ?? false) || $roleId >= 3,
        };
    }
}
