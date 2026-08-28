<?php

/*
 * Docker container inventory and update watch. Flat keys — the file is loaded
 * as one block by `@json(__('docker'))`. The key set must stay identical to
 * `lang/fr/docker.php`.
 */
return [
    'title' => 'Docker containers',
    'desc'  => 'Detects the Docker containers on each server and reports available updates: image side (a newer version exists on the registry) and git side (the stack comes from a repository that is behind, with the commit changelog).',

    'machine_libelle' => 'Server to scan',
    'btn_scan_one'    => 'Scan this server',
    'btn_scan_all'    => 'Scan everything',
    'tip_scan_one'    => 'Opens an SSH session on the chosen server, lists its containers and compares image digests.',
    'tip_scan_all'    => 'Runs the scan on EVERY non-archived server, one after another — production included.',

    'guide_titre'     => 'What these buttons do',
    'guide_lecture'   => 'The page loads without scanning anything: it shows the last known inventory.',
    'guide_scan'      => '"Scan this server" opens an SSH session, runs `git fetch` in every compose project repository, and queries the image registry. It is not an inert read.',
    'guide_scan_tout' => '"Scan everything" does the same on EVERY non-archived server, production included.',

    'col_machine'          => 'Server',
    'col_container'        => 'Container',
    'col_image'            => 'Image',
    'col_state'            => 'State',
    'col_image_update'     => 'Image update',
    'col_git'              => 'Git (stack)',
    'col_checked'          => 'Checked on',
    'tip_col_image_update' => 'Compares the local image digest with the registry one: "Update available" means a newer version exists.',
    'tip_col_git'          => 'If the stack comes from a git repository: number of commits behind. Click to see the changelog.',

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
    'scan_all_done_simple' => 'Scan of every server finished: :ok succeeded out of :total.',
    'scan_all_echecs'      => ':n server(s) failed: :noms',
    'scan_all_illisible'   => "The scan was started, but its report could not be read: there is no way to say how many servers succeeded. Reload the page to read the real state.",
    'scan_all_aucun'       => "The scan returned no report at all — either no server was processed, or the stream stopped before the first answer.",
    'no_docker'            => 'Docker is not installed on this server.',
    'err_load'             => 'Could not load the inventory.',
    'err_scan'             => 'The Docker scan failed.',
    'err_reseau'           => 'The server did not respond. Try again in a moment.',
];
