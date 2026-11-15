<?php

// lang/fr/drift.php - Detection de derive de configuration.

return [
    'title' => "Dérive de configuration",
    'desc'  => "Écart entre l'état voulu par RootWarden et l'état réel des serveurs. Calculé à partir des données déjà relevées : aucun serveur n'est joint.",

    'btn_scan_all' => 'Scanner tout le parc',
    'tip_scan_all' => "Recalcule la dérive de toutes les machines non archivées, sans joindre de serveur.",

    'col_server'   => 'Serveur',
    'col_sudo'     => 'sudo',
    'col_sshd'     => 'sshd',
    'col_fail2ban' => 'fail2ban',
    'col_checked'  => 'Dernier scan',
    'col_action'   => 'Action',
    'loading'      => "Chargement…",

    // Resume
    'sum_servers'  => 'Serveurs suivis',
    'sum_clean'    => 'Conformes',
    'sum_drifted'  => "En dérive",
    'sum_findings' => "Écarts détectés",
    'sum_servers_aide'  => "Machines non archivées",
    'sum_clean_aide'    => "Aucun écart",
    'sum_drifted_aide'  => "Au moins un écart",
    'sum_findings_aide' => "Total des écarts",

    // Etats de categorie
    'status_ok'      => 'Conforme',
    'status_drift'   => "Dérive",
    'status_unknown' => "Jamais évalué",
    'status_absent'  => "Non évalué",

    // Actions
    'btn_rescan' => "Recalculer",
    'tip_rescan' => "Recalcule la dérive de cette machine",
    'scanning'   => "Calcul en cours…",
    'scanned'    => "Machine recalculée.",
    'scan_done'  => "Calcul terminé",

    // Etats vides et erreurs
    'empty'       => 'Aucune machine dans le parc',
    'empty_aide'  => "Ajoutez un serveur, puis lancez un calcul.",
    'never'       => 'Jamais',
    'err_load'    => "Impossible de charger la dérive.",
    'err_scan'    => "Le calcul a échoué.",
];
