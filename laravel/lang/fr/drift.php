<?php

// lang/fr/drift.php - Detection de derive de configuration.

return [
    'title' => 'Detection de derive',
    'desc'  => 'Ecart entre l\'etat desire — celui que RootWarden gere — et l\'etat reel des serveurs. '
             . 'Le scan ne joint aucun serveur : il recalcule a partir des donnees deja collectees, '
             . 'il est donc immediat et sans effet sur la production.',

    'btn_scan_all' => 'Scanner tout le parc',
    'tip_scan_all' => 'Recalcule la derive de toutes les machines non archivees. Aucun serveur n\'est joint.',

    'col_server'   => 'Serveur',
    'col_sudo'     => 'sudo',
    'col_sshd'     => 'sshd',
    'col_fail2ban' => 'fail2ban',
    'col_checked'  => 'Dernier scan',
    'col_action'   => 'Action',
    'loading'      => 'Chargement...',

    // Resume
    'sum_servers'  => 'Serveurs suivis',
    'sum_clean'    => 'Conformes',
    'sum_drifted'  => 'En derive',
    'sum_findings' => 'Ecarts detectes',
    'sum_servers_aide'  => 'Machines non archivees du parc',
    'sum_clean_aide'    => 'Aucun ecart sur les trois categories',
    'sum_drifted_aide'  => 'Au moins un ecart a corriger',
    'sum_findings_aide' => 'Total des categories en ecart',

    // Etats de categorie
    'status_ok'      => 'Conforme',
    'status_drift'   => 'Derive',
    'status_unknown' => 'Jamais evalue',
    'status_absent'  => 'Non evalue',

    // Actions
    'btn_rescan' => 'Re-scanner',
    'tip_rescan' => 'Recalcule la derive de cette machine seule',
    'scanning'   => 'Scan en cours...',
    'scanned'    => 'Machine re-scannee.',
    'scan_done'  => 'Scan termine',

    // Etats vides et erreurs
    'empty'       => 'Aucune machine dans le parc',
    'empty_aide'  => 'La derive se calcule par machine : ajoutez un serveur au parc, puis lancez un scan.',
    'never'       => 'Jamais',
    'err_load'    => 'Impossible de charger les resultats de derive.',
    'err_scan'    => 'Le scan a echoue.',
];
