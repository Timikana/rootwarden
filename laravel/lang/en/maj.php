<?php

// lang/en/maj.php - Linux updates, sub-lot U1 (fleet and filters).

return [
    'title' => 'Linux updates',
    'desc'  => 'The Linux fleet managed by RootWarden: installed version, availability, scheduled '
             . 'security updates and last reboot.',

    // Partial port — said on screen rather than hidden.
    'partiel_titre' => 'What this page does not carry over',
    'partiel_texte' => 'Everything the old portal offered about updates now lives here. Two '
                     . 'server capabilities are deliberately left out: updating a chosen list '
                     . 'of packages, and excluding packages. The old page carried the code for '
                     . 'them, but no button ever reached it.',

    // Filters
    'filtres_titre'   => 'Filter the fleet',
    'f_environment'   => 'Environment',
    'f_criticality'   => 'Criticality',
    'f_network'       => 'Network type',
    'f_tag' => 'Tag',
    'tip_tag' => 'Filters on the tags set by fleet administration.',
    'tip_tag_vide' => 'No tag is set on the fleet: nothing to filter by.',
    'tag_aucune' => 'No tag on the fleet',
    'tous'            => 'All',
    'btn_filter'      => 'Filter',
    'btn_refresh'     => 'Refresh the list',
    'tip_refresh'     => 'Re-reads the fleet. No machine is contacted.',

    // Columns
    'th_selection'     => 'Selection',
    'th_name'          => 'Server',
    'th_linux'         => 'Linux version',
    'th_last_check'    => 'Last check',
    'th_ip_port'       => 'Address',
    'th_status'        => 'Availability',
    'th_secu_schedule' => 'Security update scheduled',
    'th_last_exec'     => 'Last run',
    'th_last_reboot'   => 'Last reboot',
    'th_env'           => 'Environment',
    'th_criticality'   => 'Criticality',
    'th_network'       => 'Network',
    'th_actions'       => 'Readings',

    // Per-machine readings
    'btn_version' => 'Version',
    'tip_version' => 'Asks the machine for its Linux version. No effect on it.',
    'btn_statut'  => 'Availability',
    'tip_statut'  => 'Tests whether the SSH port answers. No effect on the machine.',
    'btn_reboot'  => 'Last reboot',
    'tip_reboot'  => 'Reads the last boot time. No effect on the machine.',

    // Journal d'execution (U2)
    'journal_titre' => 'Execution log',
    'journal_desc' => 'What RootWarden did on the servers during this visit. One panel per machine, plus a general log. Nothing is kept between visits — durable traceability lives in the command log.',
    'journal_general' => 'General log',
    'journal_vide' => 'No activity yet.',
    'btn_vider' => 'Clear the log',
    'tip_vider' => 'Clears the display. It erases no recorded trace.',
    'suivre' => 'Follow',
    'suivre_aide' => 'Automatically scrolls to new lines. Unticks itself if you scroll up to read.',

    // States
    'non_verifie' => 'Not checked',
    'inconnu'     => 'Unknown',
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

    // Sub-lot U3 — pending packages reading
    'btn_paquets' => 'Pending packages',
    'tip_paquets' => 'Queries each selected machine and lists its upgradable packages. Installs nothing.',
    'selection'      => ':nombre machine(s) selected.',
    'selection_vide' => 'No machine selected — tick at least one row.',
    'aucune_selection' => 'No machine selected: tick at least one row before running the reading.',
    'paquets_en_cours' => 'Reading pending packages...',
    'paquets_err'      => 'The package reading failed.',
    'paquets_aucun'    => 'No pending package.',
    'paquets_aucun_reserve' => 'This reading uses the machine\'s local index. It does not guarantee that the index could be refreshed: an unreachable repository looks exactly like an up-to-date system.',
    'paquets_nombre'   => ':nombre package(s) to upgrade:',
    'paquets_fin'      => 'Reading complete on :nombre machine(s).',
    'paquets_fin_partielle' => 'Reading complete, but :nombre machine(s) did not answer.',

    // Sub-lot U4 — scheduling
    'btn_planifier'      => 'Schedule',
    'tip_planifier'      => 'Writes a cron file on the machine: full upgrade (apt-get upgrade) at the chosen time.',
    'btn_planifier_secu' => 'Schedule security',
    'tip_planifier_secu' => 'Writes a cron file on the machine: security updates only, and records the date in the database.',

    'f_date'   => 'Date',
    'f_time'   => 'Time',
    'f_repeat' => 'Recurrence',

    'repeat_none'    => 'Do not repeat',
    'repeat_daily'   => 'Every day',
    'repeat_weekly'  => 'Every week',
    'repeat_monthly' => 'Every month',

    'btn_cancel'     => 'Cancel',
    'btn_save_sched' => 'Save the schedule',
    'tip_save_sched' => 'Writes the cron file on the remote machine, as root, and restarts cron.',

    'titre_general' => 'Schedule an update',
    'titre_secu'    => 'Schedule a security update',
    'desc_general'  => 'On :machine — apt-get update then apt-get upgrade, logged to /var/log/auto_update.log.',
    'desc_secu'     => 'On :machine — security updates only, logged to /var/log/auto_security_update.log. The scheduled date is also recorded in the database.',

    'apercu_incomplet' => 'Pick a date and a time to see what will be written on the machine.',
    'apercu_daily'     => 'Every day at :heure',
    'apercu_weekly'    => 'Every :jour at :heure',
    'apercu_monthly'   => 'On day :jour of every month at :heure',
    'apercu_none'      => 'On :jour/:mois at :heure',

    'reserve_annuel'  => '— and every year after that: cron has no year field, so "do not repeat" never stops.',
    'reserve_lundi'   => '— general scheduling always puts the weekly job on Monday, whatever date you pick.',
    'reserve_premier' => '— general scheduling always puts the monthly job on the first of the month, whatever day you pick.',

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

    // Sub-lot U5 — reboot
    'btn_reboot_action' => 'Reboot',
    'tip_reboot_action' => 'Cuts the sessions and interrupts the services of the selected machines. Requires a second administrator to approve.',

    'reboot_titre'        => 'Reboot the selected machines',
    'reboot_machines'     => ':nombre machine(s): :machines',
    'reboot_consequences' => 'Every open SSH session will be cut, and the services (web, database) interrupted for the duration of the reboot.',
    'reboot_quatre_yeux'  => 'A reboot needs a second administrator to agree: your request will be queued, not executed. A request already queued for the same machine is not duplicated, and keeps the delay it carried.',

    'reboot_delai'    => 'When',
    'reboot_delai_0'  => 'Immediately',
    'reboot_delai_5'  => 'In 5 minutes',
    'reboot_delai_15' => 'In 15 minutes',
    'reboot_delai_60' => 'In 1 hour',

    'reboot_consigne'      => 'Type the number of machines (:nombre) to enable the button',
    'btn_reboot_confirmer' => 'Reboot',
    'reboot_en_cours'      => 'Sending the reboot request...',
    'reboot_demande'       => 'Reboot request for :machine',
    'reboot_attente'       => 'Approval request #:id created: a second administrator must approve it before anything reboots.',
    'reboot_envoye'        => 'Reboot sent to the machine.',
    'reboot_fenetre'       => 'Reboot refused: outside the allowed maintenance window.',
    'reboot_err'           => 'The reboot request failed.',
    'reboot_fin'           => 'Reboot sent to :nombre machine(s).',
    'reboot_fin_attente'   => ':nombre approval request(s) queued. Nothing has rebooted.',
    'reboot_fin_partielle' => ':nombre machine(s) refused the request.',

    // Sub-lot U6a — dry run and security updates
    'btn_simulation' => 'Dry run',
    'tip_simulation' => 'Shows what an update would change, without installing anything. Refreshes the package index on the machine.',
    'btn_secu_action' => 'Security updates',
    'tip_secu_action' => 'Installs the security updates. Destructive action: it changes the installed packages.',

    'secu_titre'        => 'Apply the security updates',
    'secu_machines'     => ':nombre machine(s): :machines',
    'secu_consequences' => 'The affected packages will be replaced by their fixed version, without a reboot. A service may be restarted during the operation.',
    'secu_verrous'      => 'If apt or dpkg is already running on the machine, this action KILLS them, removes their locks and repairs the dpkg database before carrying on. An installation running elsewhere will therefore be interrupted.',
    'secu_consigne'     => 'Type SECURITY to enable the button',
    'secu_mot'          => 'SECURITY',
    'btn_secu_confirmer' => 'Apply',

    'flux_debut'         => 'Connecting to :machine...',
    'flux_fini'          => 'Done.',
    'flux_err'           => 'The command could not be started.',
    'flux_fin_partielle' => ':nombre machine(s) failed.',

    'simulation_en_cours' => 'Dry run in progress...',
    'simulation_fin'      => 'Dry run complete on :nombre machine(s). Nothing was installed.',

    'secu_en_cours' => 'Security updates in progress...',
    'secu_fin'      => 'Security updates complete on :nombre machine(s).',

    // Sub-lot U6b — full upgrade and dpkg repair
    'btn_complete' => 'Full upgrade',
    'tip_complete' => 'Upgrades EVERY package, not only the security ones. Destructive action.',
    'btn_dpkg'     => 'Repair dpkg',
    'tip_dpkg'     => 'Force-stops the apt and dpkg processes, removes their locks, then repairs the package database.',

    'complete_titre'        => 'Upgrade every package',
    'complete_consequences' => 'apt full-upgrade replaces EVERY package that has a newer version, not only those fixing a flaw. Services may be restarted, and configuration files replaced.',
    'complete_reserve'      => 'If apt or dpkg is already running on the machine, this action KILLS them, removes their locks and repairs the dpkg database before carrying on. An installation running elsewhere will be interrupted.',
    'complete_mot'          => 'UPGRADE',
    'complete_consigne'     => 'Type UPGRADE to enable the button',
    'complete_bouton'       => 'Upgrade',
    'complete_en_cours'     => 'Full upgrade in progress...',
    'complete_fin'          => 'Full upgrade complete on :nombre machine(s).',

    'dpkg_titre'        => 'Repair the package database',
    'dpkg_consequences' => 'The running apt, apt-get and dpkg processes are KILLED (killall -9), their four lock files removed, then dpkg --configure -a finishes the half-done installations.',
    'dpkg_reserve'      => 'Use only when the machine refuses every update because of a lock. A legitimate installation in progress will be lost as it stands, and will have to be started again.',
    'dpkg_mot'          => 'REPAIR',
    'dpkg_consigne'     => 'Type REPAIR to enable the button',
    'dpkg_bouton'       => 'Repair',
    'dpkg_en_cours'     => 'Repairing dpkg...',
    'dpkg_fin'          => 'Repair complete on :nombre machine(s).',
    'dpkg_err'          => 'The repair failed.',

    'err_reseau'      => 'The gateway is unreachable. Nothing was sent to the machine.',
    'action_machines' => ':nombre machine(s): :machines',
];
