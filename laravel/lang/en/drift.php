<?php

// lang/en/drift.php - Configuration drift detection.

return [
    'title' => 'Drift detection',
    'desc'  => 'Gap between the desired state — the one RootWarden manages — and the real state of the servers. '
             . 'The scan reaches no server: it recomputes from data already collected, so it is instant '
             . 'and has no effect on production.',

    'btn_scan_all' => 'Scan the whole fleet',
    'tip_scan_all' => 'Recomputes drift for every non-archived machine. No server is contacted.',

    'col_server'   => 'Server',
    'col_sudo'     => 'sudo',
    'col_sshd'     => 'sshd',
    'col_fail2ban' => 'fail2ban',
    'col_checked'  => 'Last scan',
    'col_action'   => 'Action',
    'loading'      => 'Loading...',

    // Summary
    'sum_servers'  => 'Servers tracked',
    'sum_clean'    => 'Compliant',
    'sum_drifted'  => 'Drifted',
    'sum_findings' => 'Gaps found',
    'sum_servers_aide'  => 'Non-archived machines in the fleet',
    'sum_clean_aide'    => 'No gap across the three categories',
    'sum_drifted_aide'  => 'At least one gap to fix',
    'sum_findings_aide' => 'Total categories in drift',

    // Category states
    'status_ok'      => 'Compliant',
    'status_drift'   => 'Drift',
    'status_unknown' => 'Never assessed',
    'status_absent'  => 'Not assessed',

    // Actions
    'btn_rescan' => 'Re-scan',
    'tip_rescan' => 'Recomputes drift for this machine only',
    'scanning'   => 'Scanning...',
    'scanned'    => 'Machine re-scanned.',
    'scan_done'  => 'Scan complete',

    // Empty states and errors
    'empty'       => 'No machine in the fleet',
    'empty_aide'  => 'Drift is computed per machine: add a server to the fleet, then run a scan.',
    'never'       => 'Never',
    'err_load'    => 'Could not load drift results.',
    'err_scan'    => 'The scan failed.',
];
