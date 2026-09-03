<?php

/*
 * Transfert des journaux vers Graylog. Cles PLATES : le fichier est charge d'un
 * bloc par `@json(__('graylog'))`. Jeu identique a `lang/en/graylog.php`,
 * verifie dans le meme commit.
 */
return [
    'title' => 'Transfert des journaux (Graylog)',
    'desc'  => 'Configure l\'envoi des journaux système des machines vers un serveur Graylog, via rsyslog.',

    'onglet_config'    => 'Configuration',
    'onglet_deploy'    => 'Machines',
    'onglet_templates' => 'Gabarits',
    'onglet_history'   => 'Historique',

    /*
     * L'ENCART QUE LE LEGACY N'A PAS. Trois gestes de cette page ouvrent une
     * session SSH reelle et installent ou retirent un paquet. Le dire avant.
     */
    'guide_titre'    => 'Ce que les boutons de l\'onglet Machines font vraiment',
    'guide_deploy'   => '« Déployer » ouvre une connexion SSH et installe rsyslog sur la machine si elle ne l\'a pas, puis y écrit les fichiers de configuration.',
    'guide_test'     => '« Tester » exécute une commande sur la machine pour y produire une entrée de journal. Le legacy le fait sans demander confirmation ; ici la confirmation est demandée.',
    'guide_retirer'  => '« Retirer » supprime les fichiers posés par RootWarden et redémarre rsyslog. Le paquet rsyslog lui-même est conservé.',
    'guide_prod'     => 'Le tableau liste toutes les machines non archivées, y compris celles de production. La confirmation nomme la machine visée.',

    'config_titre'   => 'Serveur de destination',
    'config_aide'    => 'Ces réglages valent pour la flotte entière : ils sont écrits dans la configuration rsyslog de chaque machine au prochain déploiement.',
    'hote'           => 'Hôte',
    'hote_aide'      => 'Nom ou adresse du serveur Graylog qui reçoit les journaux.',
    'port'           => 'Port',
    'protocole'      => 'Protocole',
    'tls_ca'         => 'Autorité de certification (TLS)',
    'tls_ca_aide'    => 'Chemin du fichier d\'autorité sur les machines. Requis seulement en TLS.',
    'rl_burst'       => 'Rafale maximale',
    'rl_interval'    => 'Intervalle de limitation (s)',
    'rl_aide'        => 'Zéro désactive la limitation de débit de rsyslog.',
    'enregistrer'    => 'Enregistrer',
    'enregistre'     => 'Configuration enregistrée.',
    'err_hote'       => 'L\'hôte est obligatoire : sans lui, aucun journal ne part.',
    'err_config'     => 'La configuration n\'a pas pu être enregistrée.',
    'err_charge'     => 'La configuration n\'a pas pu être lue.',
    'err_reseau'     => 'Le serveur n\'a pas répondu. Rien n\'a été modifié.',

    'err_retrait_actif' => '⚠ Le retrait a échoué : le transfert peut être ENCORE ACTIF sur cette machine. Vérifiez avant de considérer que les journaux ne partent plus.',

    'machines_titre' => 'Machines',
    'rafraichir'     => 'Rafraîchir',
    'chargement'     => 'Chargement…',
    'aucune_machine' => 'Aucune machine dans le parc.',
    'col_nom'        => 'Nom',
    'col_ip'         => 'Adresse',
    'col_etat'       => 'État',
    'col_version'    => 'Version rsyslog',
    'col_dernier'    => 'Dernier déploiement',
    'col_actions'    => 'Actions',
    'etat_transfere' => 'Transfert actif',
    'etat_absent'    => 'Non déployé',
    'btn_deploy'     => 'Déployer',
    'btn_test'       => 'Tester',
    'btn_retirer'    => 'Retirer',

    'confirm_titre_deploy'  => 'Installer rsyslog et déployer la configuration ?',
    'confirm_titre_test'    => 'Produire une entrée de journal sur cette machine ?',
    'confirm_titre_retirer' => 'Retirer la configuration RootWarden ?',
    'confirm_aide'          => 'Machine visée : :machine (:ip). Une connexion SSH sera ouverte et la commande exécutée en root.',
    'confirm_annuler'       => 'Annuler',
    'confirm_valider'       => 'Confirmer',

    'gabarits_titre' => 'Gabarits',
    'gabarit_nom'    => 'Nom',
    'gabarit_desc'   => 'Description',
    'gabarit_actif'  => 'Actif — poussé au prochain déploiement',
    'gabarit_contenu' => 'Contenu rsyslog',
    'gabarit_nouveau' => 'Nouveau',
    'gabarit_supprimer' => 'Supprimer',
    'gabarit_enregistre' => 'Gabarit enregistré.',
    'gabarit_supprime'   => 'Gabarit supprimé.',
    'gabarit_aucun'      => 'Aucun gabarit. Ceux qui sont actifs sont poussés sur les machines au déploiement.',
    'gabarit_actif_court' => 'actif',
    'gabarit_inactif'     => 'inactif',
    'err_gabarit_nom'  => 'Le nom du gabarit est obligatoire.',
    'err_gabarit'      => 'Le gabarit n\'a pas pu être enregistré.',
    'confirm_titre_gabarit' => 'Supprimer ce gabarit ?',
    'confirm_aide_gabarit'  => 'Gabarit : :nom. Il ne sera plus poussé lors des déploiements suivants.',

    'historique_titre' => 'Historique',
    'historique_vide'  => 'Aucune action enregistrée.',
];
