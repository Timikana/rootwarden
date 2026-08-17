<?php
// lang/fr/drift.php - Detection de derive de configuration (config drift)
return [
    // Navigation
    'nav.drift'      => 'Derive de config',
    'nav.tip_drift'  => 'Detecte les ecarts entre la config geree et l\'etat reel des serveurs',

    // Page (cote PHP)
    'drift.title'        => 'Detection de derive',
    'drift.desc'         => 'Ecarts entre l\'etat desire (gere par RootWarden) et l\'etat reel des serveurs.',
    'drift.btn_scan_all' => 'Scanner tout',
    'drift.col_server'   => 'Serveur',
    'drift.col_checked'  => 'Dernier scan',
    'drift.loading'      => 'Chargement...',

    // UI dynamique (cote JS - prefixe js.)
    'js.drift.status_drift' => 'Derive',
    'js.drift.sum_servers'  => 'Serveurs',
    'js.drift.sum_clean'    => 'Conformes',
    'js.drift.sum_drifted'  => 'En derive',
    'js.drift.sum_findings' => 'Ecarts detectes',
    'js.drift.empty'        => 'Aucun serveur. Lancez un scan.',
    'js.drift.btn_rescan'   => 'Re-scanner',
    'js.drift.err_load'     => 'Erreur de chargement des resultats.',
    'js.drift.err_scan'     => 'Erreur lors du scan.',
    'js.drift.scanned'      => 'Serveur re-scanne.',
    'js.drift.scanning'     => 'Scan en cours...',
    'js.drift.scan_done'    => 'Scan termine',
];
