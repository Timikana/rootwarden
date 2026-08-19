<?php

// lang/en/maj.php - Linux updates, sub-lot U1 (fleet and filters).

return [
    'title' => 'Linux updates',
    'desc'  => 'The Linux fleet managed by RootWarden: installed version, availability, scheduled '
             . 'security updates and last reboot.',

    // Partial port — said on screen rather than hidden.
    'partiel_titre' => 'This page is being ported',
    'partiel_texte' => 'The table, the filters, the per-machine readings and the pending-package '
                     . 'reading are ported. The dry run, launching updates, scheduling and '
                     . 'rebooting are still served by the old portal.',
    'partiel_lien'  => 'Open the full page on the old portal',

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
];
