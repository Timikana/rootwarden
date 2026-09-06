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
 *
 * ── ⚠ CE QUE CE RELEVE NE PEUT PAS EXPRIMER, PAR CONSTRUCTION ───────────────
 *
 * Il gele les gardes de ROUTE : intergiciels, role, permission. **Une garde qui
 * vit dans un CONTROLEUR lui est invisible**, et y forcer une ligne dirait qu'un
 * intergiciel la porte — une chose fausse, dans le fichier qui existe pour dire
 * le vrai.
 *
 * C'est le cas de TOUS les step-up du depot. Releve du 2026-09-06 :
 *
 *     ComptesController:514      compte_supprimer
 *     ComptesController:539      compte_anonymiser
 *     PermissionsController:165  permission_definir
 *     PortailController:196      profil_effacement      (E-449)
 *     PasserelleController:88    generique, action DERIVEE du chemin
 *
 * Cinq sites, quatre actions nommees du portage et une garde generique de
 * passerelle. **Une route de cette table peut donc etre plus gardee qu'elle n'y
 * parait** — jamais moins : un site de controleur AJOUTE une exigence, il n'en
 * retire aucune. Lire un tableau vide comme « rien ne garde ce geste » serait
 * l'erreur symetrique de celle qu'on evite en n'y inscrivant pas le step-up.
 *
 * `InventaireDesGardesTest::les_gardes_de_CONTROLEUR_sont_recensees` gele cette
 * liste : **cette limitation est mesuree, pas seulement declaree** — sans quoi
 * elle serait exactement le genre de propriete affirmee en commentaire que ce
 * depot passe son temps a demonter.
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
            // `role:3` SEUL, et c'est la garde du CODE legacy et non celle de son
            // commentaire — E-231. Pas de permission : le legacy n'en exige aucune,
            // et en inventer une resserrerait sans mandat.
            ['GET', 'autorisations-passerelle', ['role:3']],
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
            /*
             * `feaaaa2`. La colonne `password_expires_at` existait deja et le
             * portage la LIT en deux endroits ; son seul ecrivain vivant etait le
             * fichier qu'on eteint. Garde sur la ROUTE, pas dans le controleur.
             */
            ['POST', 'comptes/{id}/expiration', ['role:3', 'perm:can_admin_portal']],
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
            // Meme garde que la page et que ses deux voisines. `POST` malgre la
            // lecture : l'identifiant voyage dans le CORPS, pas dans l'URL ni dans
            // les journaux d'acces. Le controle porte sur l'objet RESOLU.
            ['POST', 'pare-feu/historique', ['role:1', 'perm:can_manage_iptables']],
            // Fermer une session ACTIVE : l'objet est une session de l'utilisateur
            // lui-meme, resolue depuis la sienne. Aucun role ni permission a
            // exiger — un compte quelconque doit pouvoir fermer les siennes.
            ['POST', 'profil/sessions/fermer', []],
            ['GET', 'groupes', ['role:2', 'perm:can_admin_portal']],
            ['GET', 'audit-ssh', ['role:1', 'perm:can_audit_ssh']],
            // La documentation ne porte aucun secret : elle decrit le produit.
            ['GET', 'documentation', []],
            ['GET', 'wazuh', ['role:2', 'perm:can_manage_wazuh']],
            ['POST', 'serveurs/importer', ['role:2', 'perm:can_admin_portal']],
            ['POST', 'comptes/importer', ['role:2', 'perm:can_admin_portal']],
            // Export RGPD art. 20. AUCUNE garde de role, et c'est FIDELE :
            // `legacy/profile/export.php:27` fait
            // `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` — tout compte
            // connecte, des le role 1. L'identifiant vient de la SESSION et aucun
            // parametre n'est offert : il n'y a pas d'objet a garder au-dela de
            // l'authentification.
            ['GET', 'profil/donnees-personnelles', []],
            // Masquer l'assistant d'accueil : le geste ne touche que la
            // preference d'affichage DU COMPTE LUI-MEME, resolue depuis la
            // session. Aucun objet a garder au-dela de l'authentification.
            ['POST', 'accueil/assistant/masquer', []],
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
            /*
             * LES TROIS GESTES DE LIBRE-SERVICE — `feaaaa2`, DOSSIER-30.
             *
             * Aucune garde de role ni de permission, et ce n'est PAS un oubli :
             * la cible EST le demandeur, l'identifiant venant de la SESSION et
             * jamais de la requete. Exiger un role ici interdirait a un role 1 de
             * poser la cle qui sert son propre acces. Le pendant administratif
             * (`POST comptes/{id}/cle-ssh`) reste `role:3` — deux routes, deux
             * arites, et c'est la difference d'arite qui fonde la difference de
             * garde.
             */
            ['POST', 'profil/courriel', []],
            ['POST', 'profil/cle-ssh', []],
            /*
             * ⚠ IRREVERSIBLE, ET SANS RE-AUTHENTIFICATION — a lire ensemble.
             *
             * Le geste est une ANONYMISATION (`user_logs` est une chaine de
             * hachage ; retirer une ligne romprait la verification de toutes les
             * suivantes). Le controleur porte trois protections reelles :
             * l'identifiant vient de la session, la confirmation exige la
             * RESSAISIE du nom du compte, et le dernier superadministrateur ne
             * peut pas se retirer.
             *
             * **Ce que la ressaisie couvre, et ce qu'elle ne couvre pas.** Le nom
             * a retaper est AFFICHE sur la page de profil elle-meme : la friction
             * protege contre le geste accidentel, pas contre une session
             * compromise. `POST profil/step-up` existe et n'est PAS exige ici.
             * *Ce n'est pas un defaut — c'est la portee du controle, et elle
             * merite d'etre ecrite plutot que supposee plus large.*
             *
             * NON PORTE DEPUIS LE LEGACY — c'est une capacite NEUVE. Mesure :
             * `legacy/profile.php` n'offre que l'EXPORT (16 formulaires, aucun
             * d'effacement ; ses `DELETE` visent `active_sessions` et
             * `remember_tokens`). Et pourtant `legacy/lang/fr/terms.php:78`
             * promet « Droit a l'effacement : demander la suppression de votre
             * compte et de vos donnees ». **Le legacy annoncait ce droit dans ses
             * CGU sans l'implementer ; le portage comble l'ecart.**
             */
            ['POST', 'profil/effacement', []],
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
            'GET groups'              => 'redirection depuis le legacy',
            'GET ssh-audit'           => 'redirection depuis le legacy',
            'GET documentation.php'   => 'redirection depuis le legacy',

            // ── LA REINITIALISATION DE MOT DE PASSE ─────────────────────
            // Publiques PAR NECESSITE : on ne peut pas exiger une session de
            // quelqu'un qui a perdu le moyen d'en ouvrir une. Ce qui les borne
            // n'est donc pas une garde de session mais une LIMITE DE DEBIT qui
            // echoue FERME et compte les demandes RECUES — un compteur qui ne
            // compte que les demandes REUSSIES ne limite pas l'enumeration, il
            // la finance — plus un jeton de 32 octets, hache, a usage unique et
            // valable une heure.
            'GET mot-de-passe-oublie'  => 'demander un lien : aucune session a exiger',
            'POST mot-de-passe-oublie' => 'soumettre l adresse : borne par la limite de debit',
            'GET reinitialiser'        => 'le lien recu par courriel porte le jeton',
            'POST reinitialiser'       => 'poser le nouveau mot de passe, jeton a usage unique',
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
