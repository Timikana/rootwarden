<?php

/**
 * Module `security/` — vulnerabilities.
 *
 * Sub-batch S1: CSV export of a scan. The exported file's labels live here and
 * not in the controller: a hard-coded string escapes FR/EN parity, and an
 * exported report should read in the language of whoever exported it.
 */

return [
    // Refusals
    'export_parametre_requis'  => 'machine_id or scan_id required',
    'export_scan_introuvable'  => 'No scan found',

    // Metadata at the top of the file
    'export_titre'        => 'CVE report - :machine',
    'export_date'         => 'Scan date: :date',
    'export_paquets'      => 'Packages scanned: :nombre',
    'export_seuil'        => 'CVSS threshold: :seuil',
    'export_repartition'  => 'Critical: :critical | High: :high | Medium: :medium | Low: :low',

    // Table header
    'col_cve'       => 'CVE ID',
    'col_paquet'    => 'Package',
    'col_version'   => 'Version',
    'col_cvss'      => 'CVSS',
    'col_severite'  => 'Severity',
    'col_resume'    => 'Summary',

    // Empty state: it SAYS what it covers, rather than rendering a bare table.
    'export_aucune' => 'No vulnerability found above the configured threshold',
];
