<?php

/**
 * Module `security/` — compliance report (sub-batch S2a).
 *
 * The 48 keys of the legacy `compliance.php` catalogue, prefix removed (here the
 * file name carries the module). Two of them were declared TWICE there —
 * `th_server` and `th_score` — and PHP silently kept the last one. The values
 * were identical, so it did no harm; the flaw is the same as a global
 * declaration overwriting another, and a catalogue reports it no better than
 * code does.
 *
 * The six `ecart_*` keys are NEW: the legacy built those labels in French, hard
 * coded, inside its posture computation. A UI string written in code escapes
 * FR/EN parity — the report's "Gaps" column stayed French whatever the language.
 */

return [
    'title'         => 'Compliance report',
    'desc'          => 'Compliance report for the fleet. The page is printable; the CSV and PDF exports each carry a SHA-256 digest of the report, computed when it is generated.',
    'generated_by'  => 'Generated on',
    'btn_print'     => 'Print',
    'btn_csv'       => 'Export as CSV',
    'btn_pdf'       => 'Export as PDF',

    // Executive summary
    'section_summary'     => 'Executive summary',
    'servers'             => 'Servers',
    'online'              => 'online',
    '2fa_active'          => '2FA enabled',
    'old_ssh_keys'        => 'SSH keys older than 90 days',
    'overdue_deadlines'   => 'Overdue deadlines',
    'ssh_audit_avg'       => 'Average SSH score',
    'supervision_coverage' => 'Monitoring coverage',

    // Consolidated posture
    'section_posture' => 'Compliance posture per server',
    'posture_desc'    => 'Consolidated score from 0 to 100, aggregating the sshd audit, critical and high CVEs, whether fail2ban is present, and configuration drift. The lowest reads first.',
    'posture_avg'     => 'Fleet average posture',
    'posture_empty'   => 'No server to assess.',

    // The gaps, which were hard coded in the legacy
    'ecart_sshd_non_audite' => 'sshd not audited',
    'ecart_cve_critiques'   => ':nombre critical CVE(s)',
    'ecart_cve_hautes'      => ':nombre high CVE(s)',
    'ecart_fail2ban'        => 'fail2ban missing',
    'ecart_derives'         => ':nombre configuration drift(s)',
    'ecart_aucun'           => 'compliant',

    // Sections
    'section_cve'         => 'CVE vulnerabilities',
    'section_remediation' => 'Remediation',
    'section_auth'        => 'Authentication',
    'section_firewall'    => 'Firewall — latest changes',
    'section_ssh_audit'   => 'SSH audit — security scores',
    'section_supervision' => 'Monitoring — deployed agents',

    // Column headers
    'th_server'    => 'Server',
    'th_ip'        => 'IP',
    'th_critical'  => 'Critical',
    'th_high'      => 'High',
    'th_total'     => 'Total',
    'th_last_scan' => 'Last scan',
    'th_score'     => 'Score',
    'th_grade'     => 'Grade',
    'th_gaps'      => 'Gaps',
    'th_user'      => 'User',
    'th_role'      => 'Role',
    'th_2fa'       => '2FA',
    'th_ssh_key'   => 'SSH key',
    'th_key_age'   => 'Key age',
    'th_last_pwd'  => 'Last password',
    'th_date'      => 'Date',
    'th_agents'    => 'Agents',

    // Remediation
    'rem_open'        => 'Open',
    'rem_in_progress' => 'In progress',
    'rem_resolved'    => 'Resolved',
    'rem_accepted'    => 'Accepted',
    'rem_wont_fix'    => 'Will not fix',

    // Legendes des tuiles : elles disent ce que le nombre MESURE.
    // Premier jet : des cles d'en-tete de colonne reutilisees comme legendes
    // (« Utilisateur » sous « 4 / 10 », « Age de la cle » sous « 0 »). Seule la
    // CAPTURE l'a montre — aucune assertion ne voit qu'un libelle ne veut rien dire.
    'tuile_serveurs_texte'    => 'in the fleet, archived included',
    'tuile_2fa_texte'         => 'of the active accounts',
    'tuile_cles_texte'        => 'keys to rotate',
    'tuile_echeances_texte'   => 'remediations past due',
    'tuile_ssh_texte'         => 'average of the latest audits',
    'tuile_supervision_texte' => 'servers carrying an agent',

    // Export CSV (sous-lot S2c). Les marqueurs de section sont TRADUITS, comme
    // le reste du fichier : un rapport se lit dans la langue de qui l'exporte.
    // Le test les repere par leur FORME (`=== … ===`) et non par leur texte,
    // sans quoi il rougirait en anglais.
    'csv_section_resume'     => 'SUMMARY',
    'csv_section_posture'    => 'POSTURE PER SERVER (sshd + CVE + fail2ban + drift)',
    'csv_section_serveurs'   => 'SERVERS',
    'csv_section_comptes'    => 'USERS',
    'csv_comptes_actifs'     => 'Active users',
    'csv_age_cle'            => 'Key age (days)',
    'th_statut'              => 'Status',
    'th_environnement'       => 'Environment',
    'th_derniere_maj'        => 'Last check',
    'th_actif'               => 'Active',
    'oui'                    => 'Yes',
    'non'                    => 'No',

    // Misc
    'never'            => 'Never',
    'by'               => 'by',
    'sans_config'      => 'no configuration',
    'footer_generated' => 'Report generated on',
    'empreinte'        => 'Report SHA-256 digest',
];
