<?php

/**
 * Module `security/` — rapport de conformite (sous-lot S2a).
 *
 * Les 48 cles du catalogue `compliance.php` du legacy, prefixe retire (ici le
 * nom du fichier porte le module). Deux d'entre elles y etaient declarees DEUX
 * FOIS — `th_server` et `th_score` — et PHP gardait silencieusement la derniere.
 * Les valeurs etaient identiques, donc sans consequence ; le defaut est le meme
 * qu'une declaration globale qui en ecrase une autre, et il n'est pas plus
 * signale dans un catalogue que dans du code.
 *
 * Les six cles `ecart_*` sont NOUVELLES : le legacy construisait ces libelles en
 * francais, en dur, dans son calcul de posture (`'sshd non audite'`,
 * `"$crit CVE critique(s)"`...). Une chaine d'interface ecrite dans du code
 * echappe a la parite FR/EN — la colonne « Ecarts » du rapport etait donc en
 * francais quelle que soit la langue choisie.
 */

return [
    'title'         => 'Rapport de conformite',
    'desc'          => 'Rapport de conformite du parc. La page est imprimable ; les exports CSV et PDF portent chacun une empreinte SHA-256 du rapport, calculee au moment de sa generation.',
    'generated_by'  => 'Genere le',
    'btn_print'     => 'Imprimer',
    'btn_csv'       => 'Exporter en CSV',
    'btn_pdf'       => 'Exporter en PDF',

    // Resume executif
    'section_summary'     => 'Resume executif',
    'servers'             => 'Serveurs',
    'online'              => 'en ligne',
    '2fa_active'          => '2FA activee',
    'old_ssh_keys'        => 'Cles SSH de plus de 90 jours',
    'overdue_deadlines'   => 'Echeances depassees',
    'ssh_audit_avg'       => 'Score SSH moyen',
    'supervision_coverage' => 'Couverture de supervision',

    // Posture consolidee
    'section_posture' => 'Posture de conformite par serveur',
    'posture_desc'    => 'Note consolidee de 0 a 100, agregeant l\'audit sshd, les CVE critiques et hautes, la presence de fail2ban et la derive de configuration. Le plus bas se lit en premier.',
    'posture_avg'     => 'Posture moyenne du parc',
    'posture_empty'   => 'Aucun serveur a evaluer.',

    // Les ecarts, qui etaient en dur dans le code du legacy
    'ecart_sshd_non_audite' => 'sshd non audite',
    'ecart_cve_critiques'   => ':nombre CVE critique(s)',
    'ecart_cve_hautes'      => ':nombre CVE haute(s)',
    'ecart_fail2ban'        => 'fail2ban absent',
    'ecart_derives'         => ':nombre derive(s) de configuration',
    'ecart_aucun'           => 'conforme',

    // Sections
    'section_cve'         => 'Vulnerabilites CVE',
    'section_remediation' => 'Remediation',
    'section_auth'        => 'Authentification',
    'section_firewall'    => 'Pare-feu — derniers changements',
    'section_ssh_audit'   => 'Audit SSH — scores de securite',
    'section_supervision' => 'Supervision — agents deployes',

    // En-tetes de colonnes
    'th_server'    => 'Serveur',
    'th_ip'        => 'IP',
    'th_critical'  => 'Critiques',
    'th_high'      => 'Elevees',
    'th_total'     => 'Total',
    'th_last_scan' => 'Dernier scan',
    'th_score'     => 'Score',
    'th_grade'     => 'Note',
    'th_gaps'      => 'Ecarts',
    'th_user'      => 'Utilisateur',
    'th_role'      => 'Role',
    'th_2fa'       => '2FA',
    'th_ssh_key'   => 'Cle SSH',
    'th_key_age'   => 'Age de la cle',
    'th_last_pwd'  => 'Dernier mot de passe',
    'th_date'      => 'Date',
    'th_agents'    => 'Agents',

    // Remediation
    'rem_open'        => 'Ouvertes',
    'rem_in_progress' => 'En cours',
    'rem_resolved'    => 'Resolues',
    'rem_accepted'    => 'Acceptees',
    'rem_wont_fix'    => 'Non corrigees',

    // Legendes des tuiles : elles disent ce que le nombre MESURE.
    // Premier jet : des cles d'en-tete de colonne reutilisees comme legendes
    // (« Utilisateur » sous « 4 / 10 », « Age de la cle » sous « 0 »). Seule la
    // CAPTURE l'a montre — aucune assertion ne voit qu'un libelle ne veut rien dire.
    'tuile_serveurs_texte'    => 'du parc, archivees comprises',
    'tuile_2fa_texte'         => 'des comptes actifs',
    'tuile_cles_texte'        => 'cles a renouveler',
    'tuile_echeances_texte'   => 'remediations en retard',
    'tuile_ssh_texte'         => 'moyenne des derniers audits',
    'tuile_supervision_texte' => 'serveurs portant un agent',

    // Export CSV (sous-lot S2c). Les marqueurs de section sont TRADUITS, comme
    // le reste du fichier : un rapport se lit dans la langue de qui l'exporte.
    // Le test les repere par leur FORME (`=== … ===`) et non par leur texte,
    // sans quoi il rougirait en anglais.
    'csv_section_resume'     => 'RESUME',
    'csv_section_posture'    => 'POSTURE PAR SERVEUR (sshd + CVE + fail2ban + derive)',
    'csv_section_serveurs'   => 'SERVEURS',
    'csv_section_comptes'    => 'UTILISATEURS',
    'csv_comptes_actifs'     => 'Utilisateurs actifs',
    'csv_age_cle'            => 'Age de la cle (jours)',
    'th_statut'              => 'Statut',
    'th_environnement'       => 'Environnement',
    'th_derniere_maj'        => 'Derniere verification',
    'th_actif'               => 'Actif',
    'oui'                    => 'Oui',
    'non'                    => 'Non',

    // Divers
    'never'            => 'Jamais',
    'by'               => 'par',
    'sans_config'      => 'sans configuration',
    'footer_generated' => 'Rapport genere le',
    'empreinte'        => 'Empreinte SHA-256 du rapport',
];
