<?php

// lang/fr/maj.php - Mises a jour Linux, sous-lot U1 (parc et filtres).

return [
    'title' => 'Mises a jour Linux',
    'desc'  => 'Le parc Linux geré par RootWarden : version installee, disponibilite, planification '
             . 'des mises a jour de securite et dernier redemarrage.',

    // Portage partiel — dit a l'ecran plutot que masque.
    'partiel_titre' => 'Cette page est en cours de portage',
    'partiel_texte' => 'Le tableau, les filtres, les releves par machine et le constat des '
                     . 'paquets en attente sont portes. La simulation, le lancement des mises '
                     . 'a jour, la planification et le redemarrage restent servis par '
                     . "l'ancien portail.",
    'partiel_lien'  => 'Ouvrir la page complete sur l\'ancien portail',

    // Filtres
    'filtres_titre'   => 'Filtrer le parc',
    'f_environment'   => 'Environnement',
    'f_criticality'   => 'Criticite',
    'f_network'       => 'Type de reseau',
    'f_tag' => 'Etiquette',
    'tip_tag' => 'Filtre sur les etiquettes posees par l\'administration du parc.',
    'tip_tag_vide' => 'Aucune etiquette n\'est posee sur le parc : rien a filtrer.',
    'tag_aucune' => 'Aucune etiquette au parc',
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

    // Journal d'execution (U2)
    'journal_titre' => 'Journal d\'execution',
    'journal_desc' => 'Ce que RootWarden a fait sur les serveurs pendant cette visite. Un panneau par machine, plus un journal general. Rien n\'est conserve d\'une visite a l\'autre — la tracabilite durable est dans le journal des commandes.',
    'journal_general' => 'Journal general',
    'journal_vide' => 'Aucune activite pour l\'instant.',
    'btn_vider' => 'Vider le journal',
    'tip_vider' => 'Efface l\'affichage. N\'efface aucune trace enregistree.',
    'suivre' => 'Suivre',
    'suivre_aide' => 'Descend automatiquement sur les nouvelles lignes. Se decoche si vous remontez lire.',

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

    // Sous-lot U3 — constat « paquets en attente »
    'btn_paquets' => 'Paquets en attente',
    'tip_paquets' => 'Interroge chaque machine retenue et liste ses paquets a mettre a jour. N\'installe rien.',
    'selection'      => ':nombre machine(s) retenue(s).',
    'selection_vide' => 'Aucune machine retenue — cochez au moins une ligne.',
    'aucune_selection' => 'Aucune machine retenue : cochez au moins une ligne avant de lancer le constat.',
    'paquets_en_cours' => 'Constat des paquets en attente...',
    'paquets_err'      => 'Le constat des paquets a echoue.',
    'paquets_aucun'    => 'Aucun paquet en attente.',
    'paquets_aucun_reserve' => 'Ce constat lit l\'index local de la machine. Il ne garantit pas que cet index a pu etre rafraichi : un depot injoignable donne le meme resultat qu\'un systeme a jour.',
    'paquets_nombre'   => ':nombre paquet(s) a mettre a jour :',
    'paquets_fin'      => 'Constat termine sur :nombre machine(s).',
    'paquets_fin_partielle' => 'Constat termine, mais :nombre machine(s) n\'ont pas repondu.',

    // Sous-lot U4 — planification
    'btn_planifier'      => 'Planifier',
    'tip_planifier'      => "Ecrit un cron sur la machine : mise a jour complete (apt-get upgrade) a l'heure choisie.",
    'btn_planifier_secu' => 'Planifier securite',
    'tip_planifier_secu' => "Ecrit un cron sur la machine : mises a jour de securite seules, et enregistre la date en base.",

    'f_date'   => 'Date',
    'f_time'   => 'Heure',
    'f_repeat' => 'Recurrence',

    'repeat_none'    => 'Ne pas repeter',
    'repeat_daily'   => 'Tous les jours',
    'repeat_weekly'  => 'Toutes les semaines',
    'repeat_monthly' => 'Tous les mois',

    'btn_cancel'     => 'Annuler',
    'btn_save_sched' => 'Enregistrer la planification',
    'tip_save_sched' => "Ecrit le fichier cron sur la machine distante, en root, et redemarre cron.",

    'titre_general' => 'Planifier une mise a jour',
    'titre_secu'    => 'Planifier une mise a jour de securite',
    'desc_general'  => 'Sur :machine — apt-get update puis apt-get upgrade, journalise dans /var/log/auto_update.log.',
    'desc_secu'     => 'Sur :machine — mises a jour de securite seules, journalisees dans /var/log/auto_security_update.log. La date planifiee est aussi enregistree en base.',

    'apercu_incomplet' => 'Choisissez une date et une heure pour voir ce qui sera ecrit sur la machine.',
    'apercu_daily'     => 'Tous les jours a :heure',
    'apercu_weekly'    => 'Tous les :jour a :heure',
    'apercu_monthly'   => 'Le :jour de chaque mois a :heure',
    'apercu_none'      => 'Le :jour/:mois a :heure',

    'reserve_annuel'  => "— et chaque annee ensuite : cron n'a pas de champ annee, « ne pas repeter » ne s'arrete jamais.",
    'reserve_lundi'   => "— la planification generale place toujours l'hebdomadaire le lundi, quelle que soit la date choisie.",
    'reserve_premier' => '— la planification generale place toujours le mensuel le premier du mois, quel que soit le jour choisi.',

    'j_lundi'    => 'lundis',
    'j_mardi'    => 'mardis',
    'j_mercredi' => 'mercredis',
    'j_jeudi'    => 'jeudis',
    'j_vendredi' => 'vendredis',
    'j_samedi'   => 'samedis',
    'j_dimanche' => 'dimanches',

    'sched_incomplet' => "Indiquez une date et une heure avant d'enregistrer.",
    'sched_en_cours'  => 'Ecriture du cron sur la machine...',
    'sched_pose'      => 'Cron pose : :cron',
    'sched_ok'        => 'Planification enregistree sur :machine.',
    'sched_err'       => "L'ecriture du cron a echoue.",
];
