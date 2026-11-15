<?php

/*
 * Docker container inventory and update watch. Flat keys: the file is sent as
 * one block by `@json(__('docker'))`. Writing rules: docs/REDACTION-INTERFACE.md.
 */
return [
    'title' => 'Docker containers',
    'desc'  => 'Docker containers on each server and available updates: newer image on the registry, or git stack behind.',

    'machine_libelle' => 'Server to scan',
    'btn_scan_one'    => 'Scan this server',
    'btn_scan_all'    => 'Scan everything',
    'tip_scan_one'    => 'Lists the containers of the chosen server and compares image digests.',
    'tip_scan_all'    => 'Scans every non-archived server, one after another.',

    'guide_scan'      => 'A scan opens an SSH session and runs git fetch in every compose project. "Scan everything" covers every server, production included.',

    'col_machine'          => 'Server',
    'col_container'        => 'Container',
    'col_image'            => 'Image',
    'col_state'            => 'State',
    'col_image_update'     => 'Image update',
    'col_git'              => 'Git (stack)',
    'col_checked'          => 'Checked on',
    'tip_col_image_update' => '"Update available": a newer image exists on the registry.',
    'tip_col_git'          => 'Commits behind in the stack git repository. Click to see the changelog.',

    'loading'          => 'Loading…',
    'empty'            => 'No container known yet. Run a scan.',
    'up_to_date'       => 'Up to date',
    'update_available' => 'Update available',
    'update_hint'      => 'A newer version of this image exists on the registry.',
    'unknown'          => 'Unknown',
    'commits_behind'   => ':n commit(s) behind',

    'sum_containers'   => 'Containers',
    'sum_machines'     => 'Servers',
    'sum_img_updates'  => 'Image updates available',
    'sum_git_updates'  => 'Git stacks behind',

    'scanning'             => 'Docker scan running…',
    'scanning_all'         => 'Docker scan of every server…',
    'scan_done'            => 'Docker scan finished.',
    // ── THE SUMMARY IS COUNTED, AND IT NAMES THE FAILURES ────────────
    // `POST /docker/scan_all` returns a JSON-lines STREAM as `text/plain`: the
    // 200 leaves BEFORE the first scan runs. A verdict drawn from the HTTP
    // status therefore announces success even if every machine failed.
    'scan_all_done_simple' => 'Scan finished: :ok succeeded out of :total server(s) reported.',
    'scan_all_interrompu' => "The stream stopped: :ok succeeded and :echecs failed were reported, the following servers were not processed. Reload the page to read the real state.",
    'scan_all_sans_fin' => "This number counts the servers that answered, not the whole fleet: an interruption cannot be told from a normal end. Reload the page to read each server's state.",
    'scan_all_echecs'      => ':n server(s) failed: :noms',
    'scan_all_illisible'   => 'The scan was started, but its report could not be read. Reload the page to read the real state.',
    'scan_all_aucun'       => 'The scan returned no report: no server processed, or the stream stopped before the first answer.',
    'no_docker'            => 'Docker is not installed on this server.',
    'err_load'             => 'Could not load the inventory.',
    'err_scan'             => 'The Docker scan failed.',
    'err_reseau'           => 'The server did not respond. Try again in a moment.',
];
