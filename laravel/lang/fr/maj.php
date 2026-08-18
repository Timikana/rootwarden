<?php

// lang/fr/maj.php - Mises a jour Linux, sous-lot U1 (parc et filtres).

return [
    'title' => 'Mises a jour Linux',
    'desc'  => 'Le parc Linux geré par RootWarden : version installee, disponibilite, planification '
             . 'des mises a jour de securite et dernier redemarrage.',

    // Portage partiel — dit a l'ecran plutot que masque.
    'partiel_titre' => 'Cette page est en cours de portage',
    'partiel_texte' => 'Le tableau, les filtres et les relevés par machine sont portes. Le lancement '
                     . 'des mises a jour, la planification et le redemarrage restent servis par '
                     . 'l\'ancien portail.',
    'partiel_lien'  => 'Ouvrir la page complete sur l\'ancien portail',

    // Filtres
    'filtres_titre'   => 'Filtrer le parc',
    'f_environment'   => 'Environnement',
    'f_criticality'   => 'Criticite',
    'f_network'       => 'Type de reseau',
    'tous'            => 'Tous',
    'btn_filter'      => 'Filtrer',
    'btn_refresh'     => 'Rafraichir la liste',
    'tip_refresh'     => 'Relit le parc. Aucune machine n\'est jointe.',

    // Colonnes
    'th_selection'     => 'Selection',
    'th_name'          => 'Serveur',
    'th_linux'         => 'Version Linux',
    'th_last_check'    => 'Dernier controle',
    'th_ip_port'       => 'Adresse',
    'th_status'        => 'Disponibilite',
    'th_secu_schedule' => 'MAJ securite planifiee',
    'th_last_exec'     => 'Derniere execution',
    'th_last_reboot'   => 'Dernier redemarrage',
    'th_env'           => 'Environnement',
    'th_criticality'   => 'Criticite',
    'th_network'       => 'Reseau',
    'th_actions'       => 'Relevés',

    // Relevés par machine
    'btn_version' => 'Version',
    'tip_version' => 'Interroge la machine pour lire sa version Linux. Sans effet sur elle.',
    'btn_statut'  => 'Disponibilite',
    'tip_statut'  => 'Teste la joignabilite du port SSH. Sans effet sur la machine.',
    'btn_reboot'  => 'Dernier redemarrage',
    'tip_reboot'  => 'Lit la date du dernier demarrage. Sans effet sur la machine.',

    // Etats
    'non_verifie' => 'Non verifie',
    'inconnu'     => 'Inconnu',
    'aucune'      => 'N/A',
    'en_cours'    => 'Releve en cours...',

    'vide'      => 'Aucune machine a afficher',
    'vide_aide' => 'Le parc est vide, ou aucune machine ne vous est attribuee.',
    'vide_filtre'      => 'Aucune machine ne correspond a ce filtre',
    'vide_filtre_aide' => 'Revenez a « Tous » sur les trois listes pour retrouver le parc complet.',

    'maj_ok'      => 'Parc relu a :heure — :nombre machine(s).',
    'filtre_ok'   => ':nombre machine(s) apres filtrage.',
    'err_load'    => 'Impossible de relire le parc.',
    'err_releve'  => 'Le releve a echoue.',
    'releve_ok'   => 'Releve termine.',
];
