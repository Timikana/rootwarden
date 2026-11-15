<?php

// lang/en/maj.php - Linux updates. Writing rules: docs/REDACTION-INTERFACE.md.

return [
    'title' => 'Linux updates',
    'desc'  => 'Installed version, availability, update scheduling and last reboot of the Linux fleet.',

    // Filters
    'f_environment'   => 'Environment',
    'f_criticality'   => 'Criticality',
    'f_network'       => 'Network type',
    'f_tag' => 'Tag',
    'tip_tag' => 'Filters on machine tags.',
    'tip_tag_vide' => 'No tag is set on the fleet.',
    'tag_aucune' => 'No tag on the fleet',
    'tous'            => 'All',
    'btn_filter'      => 'Filter',
    'btn_refresh'     => 'Refresh the list',
    'tip_refresh'     => 'Re-reads the fleet without contacting the machines.',

    // Columns
    'th_selection'     => 'Selection',
    'th_name'          => 'Server',
    'th_linux'         => 'Linux version',
    'th_last_check'    => 'Last check',
    'th_status'        => 'Availability',
    'th_planification' => 'Scheduling',
    'planif_execution' => 'Last run:',
    'th_last_reboot'   => 'Last reboot',
    'th_actions'       => 'Actions',

    // Per-machine readings
    'btn_actions'  => 'Actions',
    'actions_pour' => 'Actions for :machine',
    'btn_version' => 'Version',
    'tip_version' => 'Reads the Linux version of the machine, without changing it.',
    'btn_statut'  => 'Availability',
    'tip_statut'  => 'Tests whether the SSH port answers, without changing the machine.',
    'btn_reboot'  => 'Last reboot',
    'tip_reboot'  => 'Reads the last boot time, without changing the machine.',

    // Execution log
    'journal_titre' => 'Execution log',
    'journal_desc' => 'What was done on the servers during this visit. Nothing is kept: the durable history is in the command log.',
    'journal_general' => 'General log',
    'journal_vide' => 'No activity yet.',
    'btn_vider' => 'Clear the log',
    'tip_vider' => 'Clears the display, not the recorded history.',
    'suivre' => 'Follow',
    'suivre_aide' => 'Scrolls to new lines. Unticks itself if you scroll up to read.',

    // States
    'non_verifie' => 'Not checked',
    'inconnu'     => 'Unknown',
    'en_ligne'    => 'Online',
    'hors_ligne'  => 'Offline',
    'aucune'      => 'N/A',
    'en_cours'    => 'Reading...',

    'vide'      => 'No machine to show',
    'vide_aide' => 'The fleet is empty, or no machine is assigned to you.',
    'vide_filtre'      => 'No machine matches this filter',
    'vide_filtre_aide' => 'Set the three lists back to "All" to see the whole fleet again.',

    'maj_ok'      => 'Fleet re-read at :heure — :nombre machine(s).',
    'filtre_ok'   => ':nombre machine(s) after filtering.',
    'err_load'    => 'Could not re-read the fleet.',
    'err_releve'  => 'The reading failed.',
    'releve_ok'   => 'Reading complete.',

    // Pending packages
    'btn_paquets' => 'Pending packages',
    'tip_paquets' => 'Lists the upgradable packages on each ticked machine. Installs nothing.',
    'selection'      => ':nombre machine(s) selected.',
    'selection_vide' => 'No machine selected — tick at least one row.',
    'aucune_selection' => 'No machine selected: tick at least one row before running the reading.',
    'paquets_en_cours' => 'Reading pending packages...',
    'paquets_err'      => 'The package reading failed.',
    'paquets_aucun'    => 'No pending package.',
    'paquets_aucun_reserve' => "Based on the machine's local index: an unreachable repository looks exactly like an up-to-date system.",
    'paquets_nombre'   => ':nombre package(s) to upgrade:',
    'paquets_fin'      => 'Reading complete on :nombre machine(s).',
    'paquets_fin_partielle' => 'Reading complete, but :nombre machine(s) did not answer.',

    // Scheduling
    'btn_planifier'      => 'Schedule',
    'tip_planifier'      => 'Writes a cron file on the machine: apt-get upgrade at the chosen time.',
    'btn_planifier_secu' => "Schedule the update",
    'tip_planifier_secu' => "Writes a cron file on the machine and shows the date in the \"Update scheduled\" column.",

    'f_date'   => 'Date',
    'f_time'   => 'Time',
    'f_repeat' => 'Recurrence',

    'repeat_none'    => 'Do not repeat',
    'repeat_daily'   => 'Every day',
    'repeat_weekly'  => 'Every week',
    'repeat_monthly' => 'Every month',

    'btn_cancel'     => 'Cancel',
    'btn_save_sched' => 'Save the schedule',
    'tip_save_sched' => 'Writes the cron file on the machine, as root, and restarts cron.',

    'titre_general' => 'Schedule an update',
    'titre_secu'    => "Schedule a package update",
    'desc_general'  => 'On :machine — apt-get update then apt-get upgrade, logged to /var/log/auto_update.log.',
    'desc_secu'     => "On :machine — apt-get update then apt-get upgrade (all installed packages, no security filter), logged to /var/log/auto_security_update.log. The date shows in the \"Update scheduled\" column.",

    'apercu_incomplet' => 'Pick a date and a time to see what will be written on the machine.',
    'apercu_daily'     => 'Every day at :heure',
    'apercu_weekly'    => 'Every :jour at :heure',
    'apercu_monthly'   => 'On day :jour of every month at :heure',
    'apercu_none'      => 'On :jour/:mois at :heure',

    'reserve_annuel'  => '— and every year after that: cron has no year field, so "do not repeat" never stops.',
    'reserve_lundi'   => '— general scheduling always puts the weekly job on Monday.',
    'reserve_premier' => '— general scheduling always puts the monthly job on the first of the month.',

    'j_lundi'    => 'Monday',
    'j_mardi'    => 'Tuesday',
    'j_mercredi' => 'Wednesday',
    'j_jeudi'    => 'Thursday',
    'j_vendredi' => 'Friday',
    'j_samedi'   => 'Saturday',
    'j_dimanche' => 'Sunday',

    'sched_incomplet' => 'Enter a date and a time before saving.',
    'sched_en_cours'  => 'Writing the cron file on the machine...',
    'sched_pose'      => 'Cron written: :cron',
    'sched_ok'        => 'Schedule saved on :machine.',
    'sched_err'       => 'Writing the cron file failed.',

    // Reboot
    'btn_reboot_action' => 'Reboot',
    'tip_reboot_action' => 'Cuts the sessions and interrupts the services of the selected machines.',

    'reboot_titre'        => 'Reboot the selected machines',
    'reboot_machines'     => ':nombre machine(s): :machines',
    'reboot_consequences' => 'Open SSH sessions will be cut and services interrupted for the duration of the reboot.',
    'reboot_quatre_yeux'  => 'With approval enabled, a reboot waits for a second administrator to agree, except for a superadministrator.',

    'reboot_delai'    => 'When',
    'reboot_delai_0'  => 'Immediately',
    'reboot_delai_5'  => 'In 5 minutes',
    'reboot_delai_15' => 'In 15 minutes',
    'reboot_delai_60' => 'In 1 hour',

    'reboot_consigne'         => 'Type the number of machines (:nombre) to enable the button',
    'btn_reboot_confirmer'    => 'Reboot',
    'reboot_en_cours'         => 'Sending the reboot request...',
    'reboot_demande'          => 'Reboot request for :machine',
    'reboot_attente'          => 'Approval request #:id created: a second administrator must approve it before anything reboots.',
    'reboot_envoye'           => 'Reboot sent to the machine.',
    'reboot_fenetre'          => 'Reboot refused: outside the allowed maintenance window.',
    'reboot_err'              => 'The reboot request failed.',
    'reboot_fin'              => 'Reboot sent to :nombre machine(s).',
    'reboot_fin_attente'      => ':nombre approval request(s) queued. Nothing has rebooted.',
    'reboot_fin_partielle'    => ':nombre machine(s) refused the request.',

    // Simulation and security updates
    'btn_simulation' => 'Dry run',
    'tip_simulation' => 'Shows what an update would change, without installing anything. Refreshes the package index.',
    'btn_secu_action' => "Update packages",
    'tip_secu_action' => 'Upgrades the installed packages (apt-get upgrade), without removing any.',

    'secu_titre'        => "Update installed packages",
    'secu_machines'     => ':nombre machine(s): :machines',
    'secu_consequences' => 'Packages with a newer version are upgraded, without removing any and without rebooting the machine. A service may be restarted.',
    'secu_verrous'      => 'If apt or dpkg is already running, it is force-stopped, its locks removed and the dpkg database repaired: an installation in progress will be interrupted.',
    'secu_consigne'     => "Type PACKAGES to enable the button",
    'secu_mot'          => "PACKAGES",
    'btn_secu_confirmer' => 'Apply',

    'flux_debut'         => 'Connecting to :machine...',
    'flux_fini'          => 'Done.',
    'flux_err'           => 'The command could not be started.',
    'flux_fin_partielle' => ':nombre machine(s) failed.',

    'simulation_en_cours' => 'Dry run in progress...',
    'simulation_fin'      => 'Simulation finished on :nombre machine(s). Nothing was installed.',

    'secu_en_cours' => "Package update in progress...",
    'secu_fin'      => "Packages updated on :nombre machine(s).",

    // Full upgrade and dpkg repair
    'btn_autres'   => 'More actions',
    'btn_complete' => 'Full upgrade',
    'tip_complete' => 'Upgrades every package (apt full-upgrade), installing or removing others if needed.',
    'btn_dpkg'     => 'Repair dpkg',
    'tip_dpkg'     => 'Force-stops apt and dpkg, removes their locks and repairs the package database.',

    'complete_titre'        => 'Upgrade every package',
    'complete_consequences' => 'apt full-upgrade upgrades every package and may install or remove others. Services may be restarted.',
    'complete_reserve'      => 'If apt or dpkg is already running, it is force-stopped, its locks removed and the dpkg database repaired: an installation in progress will be interrupted.',
    'complete_mot'          => 'UPGRADE',
    'complete_consigne'     => 'Type UPGRADE to enable the button',
    'complete_bouton'       => 'Upgrade',
    'complete_en_cours'     => 'Full upgrade in progress...',
    'complete_fin'          => 'Full upgrade complete on :nombre machine(s).',

    'dpkg_titre'        => 'Repair the package database',
    'dpkg_consequences' => 'The apt, apt-get and dpkg processes are killed (killall -9), their locks removed, then dpkg --configure -a finishes interrupted installations.',
    'dpkg_reserve'      => 'Use only when the machine refuses every update because of a lock: an installation in progress will be lost and must be started again.',
    'dpkg_mot'          => 'REPAIR',
    'dpkg_consigne'     => 'Type REPAIR to enable the button',
    'dpkg_bouton'       => 'Repair',
    'dpkg_en_cours'     => 'Repairing dpkg...',
    'dpkg_fin'          => 'Repair complete on :nombre machine(s).',
    'dpkg_err'          => 'The repair failed.',

    'err_reseau'      => 'The gateway cannot be reached. Nothing was sent to the machine.',
    'action_machines' => ':nombre machine(s): :machines',
];
