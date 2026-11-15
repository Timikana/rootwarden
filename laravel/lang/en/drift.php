<?php

// lang/en/drift.php - Configuration drift detection.

return [
    'title' => "Configuration drift",
    'desc'  => "Gap between the state RootWarden expects and the servers' actual state. Computed from data already collected: no server is contacted.",

    'btn_scan_all' => 'Scan the whole fleet',
    'tip_scan_all' => "Recomputes drift for all non-archived machines, without contacting any server.",

    'col_server'   => 'Server',
    'col_sudo'     => 'sudo',
    'col_sshd'     => 'sshd',
    'col_fail2ban' => 'fail2ban',
    'col_checked'  => 'Last scan',
    'col_action'   => 'Action',
    'loading'      => "Loading…",

    // Summary
    'sum_servers'  => 'Servers tracked',
    'sum_clean'    => 'Compliant',
    'sum_drifted'  => "Drifted",
    'sum_findings' => "Findings",
    'sum_servers_aide'  => "Non-archived machines",
    'sum_clean_aide'    => "No finding",
    'sum_drifted_aide'  => "At least one finding",
    'sum_findings_aide' => "Total findings",

    // Category states
    'status_ok'      => 'Compliant',
    'status_drift'   => "Drift",
    'status_unknown' => "Never evaluated",
    'status_absent'  => "Not evaluated",

    // Actions
    'btn_rescan' => "Recompute",
    'tip_rescan' => "Recomputes drift for this machine",
    'scanning'   => "Computing…",
    'scanned'    => "Machine recomputed.",
    'scan_done'  => "Computation done",

    // Empty states and errors
    'empty'       => 'No machine in the fleet',
    'empty_aide'  => "Add a server, then run a computation.",
    'never'       => 'Never',
    'err_load'    => "Could not load drift.",
    'err_scan'    => "The computation failed.",
];
