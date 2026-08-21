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

    // Sous-lot S3 : la consultation des resultats CVE.
    'titre'                   => 'CVE vulnerability scan',
    'description'             => 'Results of the latest scan for each authorised server. This page is read-only.',
    'section_resume'          => 'Fleet summary',
    'section_serveurs'        => 'Servers',
    'serveurs_scannes'        => 'Servers scanned',
    'tuile_scannes_aide'      => 'among those accessible to you',
    'total_cve'               => 'Total vulnerabilities',
    'tuile_total_aide'        => 'sum of the latest scans',
    'critiques'               => 'Critical',
    'hautes'                  => 'High',
    'moyennes'                => 'Medium',
    'tuile_critiques_aide'   => 'fix these first',
    'tuile_hautes_aide'      => 'handle these next',
    'tuile_moyennes_aide'    => 'schedule these',
    'jamais_scanne'           => 'Never scanned',
    'jamais_scanne_aide'      => 'No completed scan for this server. The “Scan” button starts one.',
    'dernier_scan'            => 'Scan',
    'paquets_scannes'         => 'packages analysed',
    'seuil_du_scan'           => 'CVSS threshold',
    'voir_details'            => 'Click to see the detail',
    'replier'                 => 'Collapse the detail',
    'nb_cve'                  => ':nombre CVE',
    'col_suivi'               => 'Tracking',
    'filtre_severite'         => 'Severity:',
    'filtre_annee'            => 'Year:',
    'filtre_toutes'           => 'All',
    'filtre_tout'             => 'All',
    'recherche'               => 'Search a CVE or a package...',
    'affiche_sur'             => 'Showing :montre of :total',
    'voir_plus'               => 'Show more',
    'aucune_cve'              => 'No vulnerability above the configured threshold.',
    'aucun_resultat'          => 'No vulnerability matches this search.',
    'suivi_a_venir'           => 'Tracking a vulnerability is still on the legacy portal.',
    'comparer'                => 'Compare',
    'comparer_aide'           => 'Compare the two latest completed scans',
    'comparaison_titre'       => 'Comparison of the two latest scans',
    'comparaison_insuffisante' => 'Only one completed scan for this server: there is nothing to compare. A comparison needs two scans.',
    'comparaison_ajoutees'    => 'New',
    'comparaison_corrigees'   => 'Fixed',
    'comparaison_inchangees'  => 'Unchanged',
    'comparaison_identique'   => 'No difference between the two scans.',
    'fermer'                  => 'Close',
    'erreur_chargement'       => 'The vulnerability detail could not be displayed.',
    'erreur_comparaison'      => 'The comparison could not be retrieved.',
    'machine_invalide'        => 'Unknown or inaccessible server.',
    'aucun_serveur'           => 'No server is assigned to you.',
    'aucun_serveur_aide'      => 'An administrator must assign you at least one server for this page to have content.',
    'export_csv'              => 'Export as CSV',
    'scan_ancien_portail'     => 'Starting a scan is still on the legacy portal',
    // ── EPSS / KEV enrichment — sub-batch S6 ────────────────────────────────
    'tri_explication' => 'Vulnerabilities known to be exploited (KEV) are listed first, ahead of high severities that have never been exploited.',
    'kev_aide' => 'Actively exploited — CISA Known Exploited Vulnerabilities catalog',
    'kev_depuis' => 'in the catalog since :date',
    'epss_aide' => 'EPSS: probability of exploitation within 30 days',
    'priorite_aide' => ':libelle priority',
    'non_enrichi' => 'EPSS unknown',
    'reprio' => 'Refresh EPSS / KEV',
    'reprio_aide' => 'Queries FIRST.org and the CISA catalog again to recompute each vulnerability priority',
    'reprio_confirmer_titre' => 'Refresh EPSS / KEV enrichment?',
    'reprio_avertissement' => 'This rewrites the priority of all :nombre vulnerabilities from the latest scan, after querying two external services. There is no undo, and a network interruption can leave the enrichment incomplete.',
    'reprio_confirmer' => 'Refresh',
    'reprio_annuler' => 'Cancel',
    'reprio_encours' => 'Refreshing EPSS / KEV...',
    'reprio_ok' => 'Enrichment refreshed — :kev known exploited, :epss EPSS scores updated',
    'reprio_echec' => 'Refreshing the enrichment failed',
    // ── The scan (sub-batch S7a) ────────────────────────────────────────────
    'scan' => 'Scan',
    'scan_aide' => 'Looks for vulnerabilities in the packages installed on this server',
    'scan_en_cours' => 'Scanning...',
    'scan_confirmer_titre' => 'Run a vulnerability scan on :nom?',
    'scan_avertissement' => 'The server opens an SSH session to this machine and runs nine READ-ONLY commands — nothing on the target is modified. The scan may take several minutes, it records a new result that will replace the current one on screen, and it sends a report by email.',
    'scan_seuil' => 'CVSS threshold',
    'scan_source' => 'Data source',
    'scan_source_fast' => 'Fast',
    'scan_source_hybrid' => 'Hybrid — recommended',
    'scan_source_precise' => 'Precise',
    'scan_confirmer' => 'Start the scan',
    'scan_annuler' => 'Cancel',
    'scan_demarre' => 'Initializing...',
    'scan_paquet' => ':paquet (:courant/:total)',
    'scan_termine' => 'Scan finished: :paquets packages, :cve CVEs',
    'scan_erreur' => 'The scan failed: :message',
    'scan_refuse' => 'The scan was refused by the server (code :statut)',
    'scan_interrompu' => 'The scan stream ended without a conclusion: the result is uncertain',
];
