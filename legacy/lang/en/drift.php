<?php
// lang/en/drift.php - Configuration drift detection
return [
    // Navigation
    'nav.drift'      => 'Config drift',
    'nav.tip_drift'  => 'Detects gaps between the managed config and the real state of servers',

    // Page (PHP side)
    'drift.title'        => 'Drift detection',
    'drift.desc'         => 'Gaps between the desired state (managed by RootWarden) and the real state of servers.',
    'drift.btn_scan_all' => 'Scan all',
    'drift.col_server'   => 'Server',
    'drift.col_checked'  => 'Last scan',
    'drift.loading'      => 'Loading...',

    // Dynamic UI (JS side - js. prefix)
    'js.drift.status_drift' => 'Drift',
    'js.drift.sum_servers'  => 'Servers',
    'js.drift.sum_clean'    => 'Compliant',
    'js.drift.sum_drifted'  => 'Drifted',
    'js.drift.sum_findings' => 'Gaps found',
    'js.drift.empty'        => 'No server. Run a scan.',
    'js.drift.btn_rescan'   => 'Re-scan',
    'js.drift.err_load'     => 'Failed to load results.',
    'js.drift.err_scan'     => 'Scan error.',
    'js.drift.scanned'      => 'Server re-scanned.',
    'js.drift.scanning'     => 'Scanning...',
    'js.drift.scan_done'    => 'Scan complete',
];
