<?php

namespace Tests\Support;

/**
 * LES GARDES ATTENDUES, ROUTE PAR ROUTE. Relevé figé le 2026-08-27.
 *
 * ── POURQUOI CETTE TABLE EST ECRITE A LA MAIN ET NON DERIVEE ─────────────────
 *
 * Il serait plus court de lire les gardes dans le routeur et de les comparer a
 * elles-memes. Ce serait un test qui ne peut pas echouer : retirer `role:2`
 * d'une route changerait AUSSI l'attente, et le vert survivrait au defaut.
 *
 * Une attente n'a de valeur que si elle vient d'ailleurs que de la chose
 * mesuree. Celle-ci est donc un RELEVE FIGE, a confronter au legacy module par
 * module. Sa valeur n'est pas de dire quelle garde est juste — c'est le travail
 * de la parite — mais de rendre visible tout CHANGEMENT qui n'aurait pas ete
 * declare : une garde retiree, une garde affaiblie, une route neuve sans garde.
 *
 * Quand une garde change VOLONTAIREMENT, on modifie cette table dans le meme
 * commit que la route, et le message du commit dit pourquoi.
 */
class TableDesGardes
{
    /**
     * Les routes derriere `session.authentifiee`, avec les gardes qui S'AJOUTENT
     * a elle. Un tableau vide veut dire « aucune garde de role ni de
     * permission » — ce qui est une information, pas un oubli de relevé.
     *
     * @return list<array{0:string,1:string,2:list<string>}>
     */
    public static function authentifiees(): array
    {
        return [
            ['GET', 'acces-sftp', ['role:3']],
            ['GET', 'accueil', []],
            ['GET', 'api/gateway/{chemin?}', []],
            ['GET', 'approbations', ['role:2', 'perm:can_admin_portal']],
            ['GET', 'bashrc', ['role:2', 'perm:can_manage_bashrc']],
            ['GET', 'cgu', []],
            ['POST', 'cgu', []],
            ['GET', 'chatops', ['role:2', 'perm:can_admin_portal']],
            ['GET', 'cle-plateforme', ['role:1', 'perm:can_manage_platform_key']],
            ['GET', 'cles-api', ['role:3', 'perm:can_manage_api_keys']],
            ['POST', 'cles-api', ['role:3', 'perm:can_manage_api_keys']],
            ['POST', 'cles-api/{id}/revoquer', ['role:3', 'perm:can_manage_api_keys']],
            ['GET', 'cles-ssh', ['role:1', 'perm:can_deploy_keys']],
            ['GET', 'comptes', ['role:2', 'perm:can_admin_portal']],
            ['POST', 'comptes', ['role:2', 'perm:can_admin_portal']],
            ['GET', 'comptes-distants', ['role:2', 'perm:can_manage_remote_users']],
            ['POST', 'comptes-distants/{machine}/classer', ['role:2', 'perm:can_manage_remote_users']],
            ['POST', 'comptes-distants/{machine}/classer-en-attente', ['role:2', 'perm:can_manage_remote_users']],
            ['GET', 'comptes-distants/{machine}/cles/{username}', ['role:2', 'perm:can_manage_remote_users']],
            ['DELETE', 'comptes/{id}', ['role:3', 'perm:can_admin_portal']],
            ['POST', 'comptes/{id}/anonymiser', ['role:3', 'perm:can_admin_portal']],
            ['POST', 'comptes/{id}/cle-ssh', ['role:3', 'perm:can_admin_portal']],
            ['POST', 'comptes/{id}/deverrouiller', ['role:3', 'perm:can_admin_portal']],
            ['GET', 'comptes/{id}/etat-suppression', ['role:3', 'perm:can_admin_portal']],
            ['POST', 'comptes/{id}/mot-de-passe', ['role:2', 'perm:can_admin_portal']],
            ['POST', 'comptes/{id}/second-facteur', ['role:3', 'perm:can_admin_portal']],
            ['GET', 'derive-config', ['role:2', 'perm:can_view_compliance']],
            ['GET', 'docker', ['role:2']],
            ['GET', 'export-cve', ['role:1', 'perm:can_scan_cve']],
            ['GET', 'fail2ban', ['role:1', 'perm:can_manage_fail2ban']],
            ['GET', 'fail2ban/portee', ['role:1', 'perm:can_manage_fail2ban']],
            ['GET', 'graylog', ['role:2', 'perm:can_manage_graylog']],
            ['GET', 'journal-audit', ['role:2', 'perm:can_admin_portal']],
            ['GET', 'journal-audit/export', ['role:2', 'perm:can_admin_portal']],
            ['POST', 'journal-audit/sceller', ['role:3', 'perm:can_admin_portal']],
            ['GET', 'journal-audit/verifier', ['role:3', 'perm:can_admin_portal']],
            ['GET', 'journal-commandes', ['role:2', 'perm:can_admin_portal']],
            ['GET', 'maintenance', ['role:2', 'perm:can_admin_portal']],
            ['GET', 'mises-a-jour', ['role:1', 'perm:can_update_linux']],
            ['GET', 'notifications', ['role:1']],
            ['GET', 'notifications/compte', ['role:1']],
            ['GET', 'pare-feu', ['role:1', 'perm:can_manage_iptables']],
            ['POST', 'pare-feu/copie', ['role:1', 'perm:can_manage_iptables']],
            ['POST', 'pare-feu/copie/enregistrer', ['role:1', 'perm:can_manage_iptables']],
            ['GET', 'notifications/preferences', ['role:3', 'perm:can_admin_portal']],
            ['POST', 'notifications/preferences', ['role:3', 'perm:can_admin_portal']],
            ['POST', 'notifications/tout-lire', ['role:1']],
            ['DELETE', 'notifications/{id}', ['role:1']],
            ['POST', 'notifications/{id}/lire', ['role:1']],
            ['GET', 'permissions', ['role:3', 'perm:can_admin_portal']],
            ['POST', 'permissions/temporaires/{id}/revoquer', ['role:3', 'perm:can_admin_portal']],
            ['POST', 'permissions/{id}', ['role:3', 'perm:can_admin_portal']],
            ['POST', 'permissions/{id}/acces', ['role:3', 'perm:can_admin_portal']],
            ['GET', 'politiques', ['role:3']],
            ['GET', 'profil', []],
            ['POST', 'profil/mot-de-passe', []],
            ['POST', 'profil/step-up', []],
            ['POST', 'profil/step-up/revoquer', []],
            ['GET', 'rapport-conformite', ['role:2', 'perm:can_view_compliance']],
            ['GET', 'rapport-conformite/csv', ['role:2', 'perm:can_view_compliance']],
            ['GET', 'rapport-conformite/pdf', ['role:2', 'perm:can_view_compliance']],
            ['GET', 'recherche', ['role:2', 'perm:can_admin_portal']],
            ['GET', 'sauvegardes', ['role:2', 'perm:can_admin_portal']],
            ['GET', 'scan-cve', ['role:1', 'perm:can_scan_cve']],
            ['GET', 'scan-cve/apercu-cron', ['role:2', 'perm:can_scan_cve']],
            ['GET', 'scan-cve/comparaison', ['role:1', 'perm:can_scan_cve']],
            ['GET', 'scan-cve/planifications', ['role:2', 'perm:can_scan_cve']],
            ['POST', 'scan-cve/planifications', ['role:2', 'perm:can_scan_cve']],
            ['PUT', 'scan-cve/planifications/{id}', ['role:2', 'perm:can_scan_cve']],
            ['DELETE', 'scan-cve/planifications/{id}', ['role:2', 'perm:can_scan_cve']],
            ['GET', 'scan-cve/suivi', ['role:1', 'perm:can_scan_cve']],
            ['POST', 'scan-cve/suivi', ['role:1', 'perm:can_scan_cve']],
            ['GET', 'serveurs', ['role:2', 'perm:can_admin_portal']],
            ['POST', 'serveurs/ajouter', ['role:2', 'perm:can_admin_portal']],
            ['POST', 'serveurs/{id}/cycle', ['role:2', 'perm:can_admin_portal']],
            ['POST', 'serveurs/{id}/etiquettes', ['role:2', 'perm:can_admin_portal']],
            ['POST', 'serveurs/{id}/etiquettes/retirer', ['role:2', 'perm:can_admin_portal']],
            ['POST', 'serveurs/{id}/modifier', ['role:2', 'perm:can_admin_portal']],
            ['POST', 'serveurs/{id}/notes', ['role:2', 'perm:can_admin_portal']],
            ['POST', 'serveurs/{id}/notes/{note}/supprimer', ['role:2', 'perm:can_admin_portal']],
            ['POST', 'serveurs/{id}/supprimer', ['role:2', 'perm:can_admin_portal']],
            ['GET', 'services', ['role:1', 'perm:can_manage_services']],
            ['GET', 'supervision', ['role:2', 'perm:can_manage_supervision']],
            ['POST', 'supervision/configuration', ['role:2', 'perm:can_manage_supervision']],
            ['POST', 'supervision/profils', ['role:2', 'perm:can_manage_supervision']],
            ['POST', 'supervision/profils/supprimer', ['role:2', 'perm:can_manage_supervision']],
            ['POST', 'supervision/reglages', ['role:2', 'perm:can_manage_supervision']],
            ['GET', 'taches', ['role:2']],
            ['GET', 'tickets', ['role:2', 'perm:can_admin_portal']],
        ];
    }

    /**
     * Les routes SANS `session.authentifiee`, et la raison de chacune.
     *
     * C'est la liste qui compte le plus : elle est la seule chose qui empeche
     * une route neuve d'etre ajoutee HORS du groupe authentifie sans que
     * personne ne le remarque. « La garde est sur la PAGE, pas sur la REQUETE »
     * a deja coute trois trous a ce chantier.
     *
     * @return array<string,string>  "METHODE uri" => raison
     */
    public static function publiques(): array
    {
        return [
            // Ecrans d'authentification : ils EXISTENT pour qu'il n'y ait pas
            // encore de session.
            'GET connexion'                  => 'ecran de connexion',
            'POST connexion'                 => 'soumission du mot de passe',
            'GET second-facteur'             => 'ecran du second facteur',
            'POST second-facteur'            => 'soumission du code',
            'GET second-facteur/enrolement'  => 'enrolement initial du second facteur',
            'POST second-facteur/enrolement' => 'activation du second facteur',
            'POST deconnexion'               => 'fermer une session ne demande pas de session valide',
            'GET deconnexion'                => 'idem, par lien',

            // Redirections. Elles ne rendent aucun contenu : elles renvoient
            // vers une route qui, elle, est gardee.
            'GET /'                   => 'redirige vers /accueil',
            'GET auth/login.php'      => 'redirection depuis le legacy',
            'GET auth/verify_2fa.php' => 'redirection depuis le legacy',
            'GET index.php'           => 'redirection depuis le legacy',
            'GET profile.php'         => 'redirection depuis le legacy',
            'GET terms.php'           => 'redirection depuis le legacy',
            'GET adm/admin_page.php'  => 'redirection depuis le legacy',
            'GET commandlog'          => 'redirection d\'une partie archivee',
            'GET approvals'           => 'redirection d\'une partie archivee',
            'GET drift'               => 'redirection d\'une partie archivee',
            'GET backups'             => 'redirection d\'une partie archivee',
            'GET tasks'               => 'redirection d\'une partie archivee',
            'GET search'              => 'redirection d\'une partie archivee',

            // LE SEUL CHEMIN PUBLIC QUI ECRIT. Appele par Slack, qui ne peut
            // presenter ni session ni jeton. L'authentification est faite par le
            // backend, sur la signature Slack. Voir bootstrap/app.php.
            'POST chatops/webhook' => 'appele par Slack — authentifie par le backend',

            // Routes du cadre, pas du portage.
            'GET up'             => 'sonde de sante du cadre',
            'GET storage/{path}' => 'service de fichiers du cadre',
            'PUT storage/{path}' => 'service de fichiers du cadre',
        ];
    }

    /**
     * Valeurs a substituer aux parametres d'URI.
     *
     * Elles sont NUMERIQUES la ou la route porte `whereNumber` : une valeur qui
     * ne correspond pas a la contrainte rendrait 404, et un test de garde qui
     * mesure un 404 ne mesure rien.
     */
    public static function chemin(string $uri): string
    {
        return str_replace(
            ['{id}', '{machine}', '{note}', '{username}', '{chemin?}', '{path}'],
            ['1', '2', '1', 'compte-inexistant', 'test', 'x.txt'],
            $uri,
        );
    }
}
