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
    'title'         => "Rapport de conformité",
    'desc'          => "Imprimable ; les exports CSV et PDF portent l'empreinte SHA-256 du rapport, calculée à sa génération.",
    'generated_by'  => "Généré le",
    'btn_print'     => 'Imprimer',
    'btn_csv'       => 'Exporter en CSV',
    'btn_pdf'       => 'Exporter en PDF',

    // Resume executif
    'section_summary'     => "Résumé",
    'servers'             => 'Serveurs',
    'online'              => 'en ligne',
    '2fa_active'          => "2FA activée",
    'old_ssh_keys'        => "Clés SSH de plus de 90 jours",
    'overdue_deadlines'   => "Échéances dépassées",
    'ssh_audit_avg'       => 'Score SSH moyen',
    'supervision_coverage' => 'Couverture de supervision',

    // Posture consolidee
    'section_posture' => "Posture de conformité par serveur",
    'posture_desc'    => "Note de 0 à 100 : audit sshd, CVE critiques et hautes, fail2ban et dérive de configuration. Les plus basses en premier.",
    'posture_avg'     => 'Posture moyenne du parc',
    'posture_empty'   => "Aucun serveur à évaluer.",

    // Les ecarts, qui etaient en dur dans le code du legacy
    'ecart_sshd_non_audite' => "sshd non audité",
    'ecart_cve_critiques'   => ':nombre CVE critique(s)',
    'ecart_cve_hautes'      => ':nombre CVE haute(s)',
    'ecart_fail2ban'        => 'fail2ban absent',
    'ecart_derives'         => ":nombre dérive(s) de configuration",
    'ecart_aucun'           => 'conforme',

    // Sections
    'section_cve'         => "Vulnérabilités CVE",
    'section_remediation' => "Remédiation",
    'section_auth'        => 'Authentification',
    'section_firewall'    => "Pare-feu — derniers changements",
    'section_ssh_audit'   => "Audit SSH — scores de sécurité",
    'section_supervision' => "Supervision — agents déployés",

    // En-tetes de colonnes
    'th_server'    => 'Serveur',
    'th_ip'        => 'IP',
    'th_critical'  => 'Critiques',
    'th_high'      => "Élevées",
    'th_total'     => 'Total',
    'th_last_scan' => 'Dernier scan',
    'th_score'     => 'Score',
    'th_grade'     => 'Note',
    'th_gaps'      => "Écarts",
    'th_user'      => 'Utilisateur',
    'th_role'      => "Rôle",
    'th_2fa'       => '2FA',
    'th_ssh_key'   => "Clé SSH",
    'th_key_age'   => "Âge de la clé",
    'th_last_pwd'  => 'Dernier mot de passe',
    'th_date'      => 'Date',
    'th_agents'    => 'Agents',

    // Remediation
    'rem_open'        => 'Ouvertes',
    'rem_in_progress' => 'En cours',
    'rem_resolved'    => "Résolues",
    'rem_accepted'    => "Acceptées",
    'rem_wont_fix'    => "Non corrigées",

    // Legendes des tuiles : elles disent ce que le nombre MESURE.
    // Premier jet : des cles d'en-tete de colonne reutilisees comme legendes
    // (« Utilisateur » sous « 4 / 10 », « Age de la cle » sous « 0 »). Seule la
    // CAPTURE l'a montre — aucune assertion ne voit qu'un libelle ne veut rien dire.
    'tuile_serveurs_texte'    => "du parc, archivées comprises",
    'tuile_2fa_texte'         => 'des comptes actifs',
    'tuile_cles_texte'        => "clés à renouveler",
    'tuile_echeances_texte'   => "remédiations en retard",
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
    'th_derniere_maj'        => "Dernière vérification",
    'th_actif'               => 'Actif',
    'oui'                    => 'Oui',
    'non'                    => 'Non',

    // Divers
    'never'            => 'Jamais',
    'by'               => 'par',
    'sans_config'      => 'sans configuration',
    'footer_generated' => "Rapport généré le",
    'empreinte'        => 'Empreinte SHA-256 du rapport',
];
