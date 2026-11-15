<?php

// lang/fr/maj.php - Mises a jour Linux. Regles de redaction : docs/REDACTION-INTERFACE.md.

return [
    'title' => 'Mises à jour Linux',
    'desc'  => 'Version installée, disponibilité, planification des mises à jour et dernier redémarrage du parc Linux.',

    // Filtres
    'f_environment'   => 'Environnement',
    'f_criticality'   => 'Criticité',
    'f_network'       => 'Type de réseau',
    'f_tag' => 'Étiquette',
    'tip_tag' => 'Filtre sur les étiquettes des machines.',
    'tip_tag_vide' => "Aucune étiquette n'est posée sur le parc.",
    'tag_aucune' => 'Aucune étiquette au parc',
    'tous'            => 'Tous',
    'btn_filter'      => 'Filtrer',
    'btn_refresh'     => 'Rafraîchir la liste',
    'tip_refresh'     => "Relit le parc sans contacter les machines.",

    // Colonnes
    'th_selection'     => 'Sélection',
    'th_name'          => 'Serveur',
    'th_linux'         => 'Version Linux',
    'th_last_check'    => 'Dernier contrôle',
    'th_ip_port'       => 'Adresse',
    'th_status'        => 'Disponibilité',
    'th_secu_schedule' => "Mise à jour planifiée",
    'th_last_exec'     => 'Dernière exécution',
    'th_last_reboot'   => 'Dernier redémarrage',
    'th_env'           => 'Environnement',
    'th_criticality'   => 'Criticité',
    'th_network'       => 'Réseau',
    'th_actions'       => 'Relevés',

    // Releves par machine
    'btn_version' => 'Version',
    'tip_version' => 'Lit la version Linux de la machine, sans la modifier.',
    'btn_statut'  => 'Disponibilité',
    'tip_statut'  => 'Teste si le port SSH répond, sans modifier la machine.',
    'btn_reboot'  => 'Dernier redémarrage',
    'tip_reboot'  => 'Lit la date du dernier démarrage, sans modifier la machine.',

    // Journal d'execution
    'journal_titre' => "Journal d'exécution",
    'journal_desc' => "Ce qui a été fait sur les serveurs pendant cette visite. Rien n'est conservé : l'historique durable est dans le journal des commandes.",
    'journal_general' => 'Journal général',
    'journal_vide' => "Aucune activité pour l'instant.",
    'btn_vider' => 'Vider le journal',
    'tip_vider' => "Efface l'affichage, pas l'historique enregistré.",
    'suivre' => 'Suivre',
    'suivre_aide' => 'Descend sur les nouvelles lignes. Se décoche si vous remontez lire.',

    // Etats
    'non_verifie' => 'Non vérifié',
    'inconnu'     => 'Inconnu',
    'en_ligne'    => 'En ligne',
    'hors_ligne'  => 'Hors ligne',
    'aucune'      => 'N/A',
    'en_cours'    => 'Relevé en cours...',

    'vide'      => 'Aucune machine à afficher',
    'vide_aide' => "Le parc est vide, ou aucune machine ne vous est attribuée.",
    'vide_filtre'      => 'Aucune machine ne correspond à ce filtre',
    'vide_filtre_aide' => 'Remettez « Tous » sur les listes pour retrouver le parc complet.',

    'maj_ok'      => 'Parc relu à :heure — :nombre machine(s).',
    'filtre_ok'   => ':nombre machine(s) après filtrage.',
    'err_load'    => 'Impossible de relire le parc.',
    'err_releve'  => 'Le relevé a échoué.',
    'releve_ok'   => 'Relevé terminé.',

    // Paquets en attente
    'btn_paquets' => 'Paquets en attente',
    'tip_paquets' => "Liste les paquets à mettre à jour sur chaque machine cochée. N'installe rien.",
    'selection'      => ':nombre machine(s) retenue(s).',
    'selection_vide' => 'Aucune machine retenue — cochez au moins une ligne.',
    'aucune_selection' => "Aucune machine retenue : cochez au moins une ligne.",
    'paquets_en_cours' => 'Constat des paquets en attente...',
    'paquets_err'      => 'Le constat des paquets a échoué.',
    'paquets_aucun'    => 'Aucun paquet en attente.',
    'paquets_aucun_reserve' => "Constat fait sur l'index local de la machine : un dépôt injoignable donne le même résultat qu'un système à jour.",
    'paquets_nombre'   => ':nombre paquet(s) à mettre à jour :',
    'paquets_fin'      => 'Constat terminé sur :nombre machine(s).',
    'paquets_fin_partielle' => "Constat terminé, mais :nombre machine(s) n'ont pas répondu.",

    // Planification
    'btn_planifier'      => 'Planifier',
    'tip_planifier'      => "Écrit un cron sur la machine : apt-get upgrade à l'heure choisie.",
    'btn_planifier_secu' => "Planifier la mise à jour",
    'tip_planifier_secu' => "Écrit un cron sur la machine et affiche la date dans la colonne « Mise à jour planifiée ».",

    'f_date'   => 'Date',
    'f_time'   => 'Heure',
    'f_repeat' => 'Récurrence',

    'repeat_none'    => 'Ne pas répéter',
    'repeat_daily'   => 'Tous les jours',
    'repeat_weekly'  => 'Toutes les semaines',
    'repeat_monthly' => 'Tous les mois',

    'btn_cancel'     => 'Annuler',
    'btn_save_sched' => 'Enregistrer la planification',
    'tip_save_sched' => "Écrit le fichier cron sur la machine, en root, et redémarre cron.",

    'titre_general' => 'Planifier une mise à jour',
    'titre_secu'    => "Planifier une mise à jour des paquets",
    'desc_general'  => 'Sur :machine — apt-get update puis apt-get upgrade, journalisé dans /var/log/auto_update.log.',
    'desc_secu'     => "Sur :machine — apt-get update puis apt-get upgrade (tous les paquets installés, sans filtre de sécurité), journalisé dans /var/log/auto_security_update.log. La date apparaît dans la colonne « Mise à jour planifiée ».",

    'apercu_incomplet' => 'Choisissez une date et une heure pour voir ce qui sera écrit sur la machine.',
    'apercu_daily'     => 'Tous les jours à :heure',
    'apercu_weekly'    => 'Tous les :jour à :heure',
    'apercu_monthly'   => 'Le :jour de chaque mois à :heure',
    'apercu_none'      => 'Le :jour/:mois à :heure',

    'reserve_annuel'  => "— et chaque année ensuite : cron n'a pas de champ année, « ne pas répéter » ne s'arrête jamais.",
    'reserve_lundi'   => "— la planification générale place toujours l'hebdomadaire le lundi.",
    'reserve_premier' => '— la planification générale place toujours le mensuel le premier du mois.',

    'j_lundi'    => 'lundis',
    'j_mardi'    => 'mardis',
    'j_mercredi' => 'mercredis',
    'j_jeudi'    => 'jeudis',
    'j_vendredi' => 'vendredis',
    'j_samedi'   => 'samedis',
    'j_dimanche' => 'dimanches',

    'sched_incomplet' => "Indiquez une date et une heure avant d'enregistrer.",
    'sched_en_cours'  => 'Écriture du cron sur la machine...',
    'sched_pose'      => 'Cron posé : :cron',
    'sched_ok'        => 'Planification enregistrée sur :machine.',
    'sched_err'       => "L'écriture du cron a échoué.",

    // Redemarrage
    'btn_reboot_action' => 'Redémarrer',
    'tip_reboot_action' => "Coupe les sessions et interrompt les services des machines retenues.",

    'reboot_titre'        => 'Redémarrer les machines retenues',
    'reboot_machines'     => ':nombre machine(s) : :machines',
    'reboot_consequences' => 'Les sessions SSH ouvertes seront coupées et les services interrompus le temps du redémarrage.',
    'reboot_quatre_yeux'  => "Avec l'approbation activée, un redémarrage attend l'accord d'un second administrateur, sauf pour un superadministrateur.",

    'reboot_delai'    => 'Quand',
    'reboot_delai_0'  => 'Immédiatement',
    'reboot_delai_5'  => 'Dans 5 minutes',
    'reboot_delai_15' => 'Dans 15 minutes',
    'reboot_delai_60' => 'Dans 1 heure',

    'reboot_consigne'         => 'Recopiez le nombre de machines (:nombre) pour activer le bouton',
    'btn_reboot_confirmer'    => 'Redémarrer',
    'reboot_en_cours'         => 'Envoi de la demande de redémarrage...',
    'reboot_demande'          => 'Demande de redémarrage pour :machine',
    'reboot_attente'          => "Demande d'approbation n° :id créée : un second administrateur doit la valider avant tout redémarrage.",
    'reboot_envoye'           => 'Redémarrage envoyé à la machine.',
    'reboot_fenetre'          => 'Redémarrage refusé : hors fenêtre de maintenance autorisée.',
    'reboot_err'              => 'La demande de redémarrage a échoué.',
    'reboot_fin'              => 'Redémarrage envoyé à :nombre machine(s).',
    'reboot_fin_attente'      => ":nombre demande(s) d'approbation en attente. Rien n'a redémarré.",
    'reboot_fin_partielle'    => ':nombre machine(s) ont refusé la demande.',

    // Simulation et mises a jour de securite
    'btn_simulation' => 'Simuler',
    'tip_simulation' => "Montre ce qu'une mise à jour changerait, sans rien installer. Rafraîchit l'index des paquets.",
    'btn_secu_action' => "Mettre à jour les paquets",
    'tip_secu_action' => 'Met à jour les paquets installés (apt-get upgrade), sans en retirer.',

    'secu_titre'        => "Mettre à jour les paquets installés",
    'secu_machines'     => ':nombre machine(s) : :machines',
    'secu_consequences' => "Les paquets ayant une version plus récente sont mis à jour, sans en retirer aucun ni redémarrer la machine. Un service peut être relancé.",
    'secu_verrous'      => "Si apt ou dpkg tourne déjà, il est arrêté de force, ses verrous sont supprimés et la base dpkg réparée : une installation en cours sera interrompue.",
    'secu_consigne'     => "Recopiez PAQUETS pour activer le bouton",
    'secu_mot'          => "PAQUETS",
    'btn_secu_confirmer' => 'Appliquer',

    'flux_debut'         => 'Connexion à :machine...',
    'flux_fini'          => 'Terminé.',
    'flux_err'           => "La commande n'a pas pu être lancée.",
    'flux_fin_partielle' => ':nombre machine(s) ont échoué.',

    'simulation_en_cours' => 'Simulation en cours...',
    'simulation_fin'      => "Simulation terminée sur :nombre machine(s). Rien n'a été installé.",

    'secu_en_cours' => "Mise à jour des paquets en cours...",
    'secu_fin'      => "Paquets mis à jour sur :nombre machine(s).",

    // Mise a jour complete et reparation dpkg
    'btn_complete' => 'Mise à jour complète',
    'tip_complete' => 'Met à jour tous les paquets (apt full-upgrade), quitte à en installer ou en retirer.',
    'btn_dpkg'     => 'Réparation dpkg',
    'tip_dpkg'     => "Arrête de force apt et dpkg, supprime leurs verrous et répare la base des paquets.",

    'complete_titre'        => 'Mettre à jour tous les paquets',
    'complete_consequences' => "apt full-upgrade met à jour tous les paquets et peut en installer ou en retirer d'autres. Des services peuvent être relancés.",
    'complete_reserve'      => "Si apt ou dpkg tourne déjà, il est arrêté de force, ses verrous sont supprimés et la base dpkg réparée : une installation en cours sera interrompue.",
    'complete_mot'          => 'MISE A JOUR',
    'complete_consigne'     => 'Recopiez MISE A JOUR pour activer le bouton',
    'complete_bouton'       => 'Mettre à jour',
    'complete_en_cours'     => 'Mise à jour complète en cours...',
    'complete_fin'          => 'Mise à jour complète terminée sur :nombre machine(s).',

    'dpkg_titre'        => 'Réparer la base des paquets',
    'dpkg_consequences' => "Les processus apt, apt-get et dpkg sont tués (killall -9), leurs verrous supprimés, puis dpkg --configure -a termine les installations interrompues.",
    'dpkg_reserve'      => "À n'utiliser que si la machine refuse toute mise à jour à cause d'un verrou : une installation en cours sera perdue et devra être relancée.",
    'dpkg_mot'          => 'REPARER',
    'dpkg_consigne'     => 'Recopiez REPARER pour activer le bouton',
    'dpkg_bouton'       => 'Réparer',
    'dpkg_en_cours'     => 'Réparation dpkg en cours...',
    'dpkg_fin'          => 'Réparation terminée sur :nombre machine(s).',
    'dpkg_err'          => 'La réparation a échoué.',

    'err_reseau'      => "La passerelle est injoignable. Rien n'a été envoyé à la machine.",
    'action_machines' => ':nombre machine(s) : :machines',
];
