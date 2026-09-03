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
     * L'ORDRE DU MENU SUIT LA SEQUENCE OPERATIONNELLE, PAS UNE IMPORTANCE.
     *
     * NAV-001, decide par l'exploitant. Sa formulation donne le principe mieux
     * que la consigne qu'il avait d'abord donnee : *quand on ajoute un serveur,
     * les menus ou il faut aller ensuite sont « Cle SSH plateforme » puis
     * « Utilisateurs distants » — et un nouvel utilisateur ne le sait pas.*
     *
     * La premiere section est donc LITTERALEMENT le parcours d'un serveur neuf.
     * `platform_key` et `remote_users` remontent de l'administration, ou ils
     * etaient enterres alors qu'ils sont les deux premiers gestes apres l'ajout
     * d'une machine ; `sudo_policies` et `sftp_policies` les suivent parce
     * qu'ils prolongent la meme question — qui accede, et avec quoi.
     *
     * Un ordre de menu AIDE, il ne GUIDE pas : le defaut « un nouvel
     * utilisateur ne le sait pas » reste ouvert, et il appelle un indicateur de
     * preparation par machine (FEAT-001), pas un ordre.
     *
     * 32 entrees, 5 sections. Les gardes sont INCHANGEES, a l'identique du
     * releve du legacy : reordonner un menu ne deplace aucun droit. `tickets`
     * est la seule entree retiree — sa route, sa vue et ses catalogues sont
     * CONSERVES, voir l'encadre ci-dessous.
     *
     * ══ POURQUOI LA ROUTE `tickets` RESTE, ALORS QUE SON ENTREE PART ═══════
     *
     * Mesure faite AVANT de retirer quoi que ce soit, et elle a trouve trois
     * consommateurs que le retrait de la seule entree n'aurait pas casses mais
     * que le retrait de la route aurait casses en silence :
     *
     *   — `POST /tickets` appelle un fournisseur ITSM EXTERNE, et il est appele
     *     depuis les pages CVE, pas depuis la page des tickets
     *     (`ScanCveController` passe `url_ticket` a l'ecran de scan). C'est
     *     l'exception de passerelle que le plan documente en §7 ;
     *   — `GET /search` ecrit `link: '/tickets/index.php'` pour CHAQUE ticket
     *     trouve (`backend/routes/search.py:82`), et `LiensLegacy` traduit ce
     *     chemin vers la route `tickets`. Retirer la route ferait pointer cette
     *     table sur une route inexistante — la recherche redeviendrait un menu
     *     qui mene ailleurs, le defaut meme que `LiensLegacy` existe pour
     *     empecher. Ce n'est PAS preventif : le backend l'emet vraiment ;
     *   — `recherche.js` porte une categorie `tickets` dans ses filtres.
     *
     * Retirer l'entree est REVERSIBLE et se voit ; casser une integration
     * sortante ne se voit pas. Les deux gestes sont donc separes, et le second
     * attend l'arbitrage de l'exploitant : consulter un ticket dans RootWarden
     * a-t-il encore un sens si le ticket vit dans l'ITSM ?
     */
    public const SECTIONS = [
        // ── Le parcours d'un serveur neuf, dans l'ordre ou on le suit ──────
        'parc' => [
            ['cle' => 'dashboard',      'garde' => 'tous',                    'route'  => 'accueil'],
            ['cle' => 'platform_key',   'garde' => 'can_manage_platform_key', 'route'  => 'cle-plateforme'],
            ['cle' => 'remote_users',   'garde' => 'can_manage_remote_users', 'route'  => 'comptes-distants'],
            ['cle' => 'ssh_keys',       'garde' => 'can_deploy_keys',         'route'  => 'cles-ssh'],
            ['cle' => 'sudo_policies',  'garde' => 'sa',                      'route'  => 'politiques'],
            ['cle' => 'sftp_policies',  'garde' => 'sa',                      'route'  => 'acces-sftp'],
        ],

        'exploitation' => [
            ['cle' => 'updates',        'garde' => 'can_update_linux',        'route'  => 'mises-a-jour'],
            ['cle' => 'services',       'garde' => 'can_manage_services',     'route'  => 'services'],
            ['cle' => 'supervision',    'garde' => 'can_manage_supervision',  'route'  => 'supervision'],
            ['cle' => 'bashrc',         'garde' => 'can_manage_bashrc',       'route'  => 'bashrc'],
            // Garde par ROLE et non par permission : releve tel quel du legacy.
            // L'ecart est signale dans INVENTAIRE.md — a arbitrer, pas a corriger
            // en silence pendant un reordonnancement de navigation.
            ['cle' => 'docker',         'garde' => 'admin',                   'route'  => 'docker'],
            ['cle' => 'graylog',        'garde' => 'can_manage_graylog',      'route'  => 'graylog'],
        ],

        'securite' => [
            ['cle' => 'cve_scan',       'garde' => 'can_scan_cve',            'route'  => 'scan-cve'],
            ['cle' => 'compliance',     'garde' => 'can_view_compliance',     'route'  => 'rapport-conformite'],
            ['cle' => 'drift',          'garde' => 'can_view_compliance',     'route'  => 'derive-config'],
            ['cle' => 'iptables',       'garde' => 'can_manage_iptables',     'route'  => 'pare-feu'],
            ['cle' => 'fail2ban',       'garde' => 'can_manage_fail2ban',     'route'  => 'fail2ban'],
            ['cle' => 'ssh_audit',      'garde' => 'can_audit_ssh',           'route'  => 'audit-ssh'],
            ['cle' => 'wazuh',          'garde' => 'can_manage_wazuh',        'route'  => 'wazuh', 'feature' => 'wazuh'],
        ],

        'admin' => [
            ['cle' => 'admin',          'garde' => 'can_admin_portal',        'route'  => 'comptes'],
            ['cle' => 'groups',         'garde' => 'can_admin_portal',        'route'  => 'groupes'],
            ['cle' => 'approvals',      'garde' => 'can_admin_portal',        'route'  => 'approbations'],
            ['cle' => 'maintenance',    'garde' => 'can_admin_portal',        'route'  => 'maintenance'],
            ['cle' => 'tasks',          'garde' => 'can_admin_portal',        'route'  => 'taches'],
            ['cle' => 'backups',        'garde' => 'can_admin_portal',        'route'  => 'sauvegardes'],
            ['cle' => 'audit_log',      'garde' => 'can_admin_portal',        'route'  => 'journal-audit'],
            ['cle' => 'commandlog',     'garde' => 'can_admin_portal',        'route'  => 'journal-commandes'],
            ['cle' => 'search',         'garde' => 'can_admin_portal',        'route'  => 'recherche'],
            ['cle' => 'chatops',        'garde' => 'can_admin_portal',        'route'  => 'chatops'],
        ],

        'autre' => [
            ['cle' => 'profil',         'garde' => 'tous',                    'route'  => 'profil'],
            ['cle' => 'documentation',  'garde' => 'tous',                    'route'  => 'documentation'],
            /*
             * `api_docs` BASCULE, et la garde reste `sa`.
             *
             * `legacy/api/docs.php:4` annonce « admins et superadmins » ; sa
             * ligne 9 fait `checkAuth([ROLE_SUPERADMIN])`. Le commentaire promet
             * un acces PLUS LARGE que le code (E-231) — la garde portee est
             * celle du code.
             *
             * La page portee ne sert PAS la description OpenAPI statique du
             * legacy : elle DERIVE ce que la passerelle autorise. Voir
             * `AutorisationsPasserelle`.
             */
            ['cle' => 'api_docs',       'garde' => 'sa',                      'route'  => 'autorisations-passerelle'],
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
