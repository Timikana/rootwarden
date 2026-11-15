<?php

/*
 * SSH configuration audit.
 *
 * FLAT keys: the file is sent whole through `@json(__('ssh_audit'))`. The key
 * set must stay identical to `lang/fr/ssh_audit.php`. Writing rules:
 * docs/REDACTION-INTERFACE.md.
 */
return [
    'titre' => 'SSH configuration audit',
    'desc'  => 'Reads the SSH service configuration of your servers, scores it against a policy and tracks how it changes.',

    // ── Server selector, bounded to the perimeter ────────────────────────
    'chargement' => 'Loading…',
    'serveur_cible'   => 'Server',
    'serveur_choisir' => 'Choose a server…',
    'serveur_aucun'   => 'No server is assigned to you. Ask an administrator for access.',
    'serveur_borne'   => 'You only see the machines assigned to you here.',

    // ── History ──────────────────────────────────────────────────────────
    'historique_titre' => 'Previous readings',
    'historique_choisir' => 'Choose a server to see its previous readings.',
    'historique_vide'  => 'No reading has been taken on this server yet.',
    'historique_err'   => 'The readings for this server could not be read.',
    'note'   => 'Score',
    'lettre' => 'Grade',
    'le'     => 'on',

    'sev_critique' => 'critical',
    'sev_haute'    => 'high',
    'sev_moyenne'  => 'medium',
    'sev_basse'    => 'low',

    // ── Fleet (administration) ───────────────────────────────────────────
    'flotte_titre' => 'Latest reading for each server',
    'flotte_vide'  => 'No server has been read yet.',
    'flotte_err'   => 'The fleet state could not be read.',
    'reserve_admin' => 'The whole-fleet state and scheduled readings are reserved for administrators.',
    'th_serveur'   => 'Server',
    'th_ip'        => 'Address',
    'th_note'      => 'Score',
    'th_mention'   => 'Grade',
    'th_critiques' => 'Critical',
    'th_releve_le' => 'Read on',

    // ── Policy, read-only ────────────────────────────────────────────────
    // Writing is composed nowhere (SEC-013, see AuditSshController).
    'politique_titre' => 'Policy applied to this server',
    'politique_choisir' => 'Choose a server to see the policy applied to it.',
    'politique_vide'  => 'No rule is defined for this server: the default policy applies.',
    'politique_err'   => 'The policy for this server could not be read.',
    'politique_auditee' => 'audited',
    'politique_ignoree' => 'ignored',
    'politique_motif'   => 'Reason',
    'politique_lecture_seule' => 'Read-only: the policy cannot be changed from the portal.',

    // ── Schedules (administration) ───────────────────────────────────────
    'planifs_titre'   => 'Scheduled readings',
    'planifs_vide'    => 'No scheduled reading.',
    'planifs_err'     => 'The schedules could not be read.',
    'planif_active'   => 'active',
    'planif_suspendue' => 'paused',
    'planif_prochaine' => 'Next run',
    'planif_cible_parc' => 'the whole fleet',
    'planif_cible_tag'  => 'tag: :valeur',
    'planif_cible_env'  => 'environment: :valeur',
    'planif_cible_machines' => ':n named server(s)',
    // Narrow scope without a value: the scheduler skips it (scheduler.py,
    // `else` branch: WHERE 1=0).
    'planif_cible_inconnue' => 'incomplete target: skipped when due',

    // ── Buttons and decision panel ───────────────────────────────────────
    'btn_relever' => 'Read this server',
    'btn_config'  => 'View sshd_config',
    'btn_parc'    => 'Read the whole fleet',
    'btn_planif'  => 'Schedule a reading',
    'np_titre'  => 'Not available on this portal',
    'np_fermer' => 'Close',
    'np_sur_serveur' => 'Target server: :nom',

    'np_parc' => 'Reading the whole fleet is not available on this portal.',
    'np_parc_detail' => 'It would open an SSH session on every non-archived machine, production included, with no way to narrow it.',

    // ── Read a server ────────────────────────────────────────────────────
    'relever_titre' => 'Read this server?',
    'np_relever_detail' => 'Opens an SSH session on the server to read its configuration.',
    // Notifications are stored in the database (notify.py, inapp channel).
    'relever_ecrit' => 'The result is saved to the history and the audit log, and notified in the portal.',
    'relever_lancer' => 'Read now',
    'relever_en_cours' => 'Reading…',
    'relever_sans_serveur' => 'Choose a server before reading it.',
    'relever_fait' => 'Reading finished: grade :grade, score :score/100.',
    'relever_echec' => 'The reading did not complete. :message',
    'relever_refus' => 'The reading was refused. :message',

    // ── Read sshd_config ─────────────────────────────────────────────────
    'cfg_titre'    => 'Read sshd_config on this server?',
    'cfg_texte'    => 'Opens an SSH session on the server. Nothing is written, neither on the machine nor in the database.',
    'cfg_lire'     => 'Read the file',
    'cfg_en_cours' => 'Reading…',
    'cfg_titre_resultat' => 'sshd_config of :nom',
    'cfg_vide'     => 'The server answered, but the file is empty.',
    'cfg_echec'    => 'The file could not be read. :message',
    'cfg_refus'    => 'The read was refused. :message',
    'cfg_sans_serveur' => 'Choose a server before reading its configuration.',
    'cfg_lecture_seule' => 'Read-only: sshd_config cannot be changed from the portal.',

    // ── Schedule a reading ───────────────────────────────────────────────
    'planif_form_titre' => 'Schedule a reading',
    'planif_f_nom'      => 'Schedule name',
    'planif_f_nom_aide' => '100 characters at most.',
    'planif_f_freq'     => 'Periodicity',
    'planif_f_portee'   => 'What the reading covers',
    'planif_f_valeur'   => 'Scope value',
    'planif_freq_horaire'    => 'Every hour',
    'planif_freq_six_heures' => 'Every six hours',
    'planif_freq_quotidien'  => 'Every day at 02:00',
    'planif_freq_hebdo'      => 'Every Monday at 03:00',
    'planif_portee_environment' => 'One environment',
    'planif_portee_tag'         => 'One tag',
    'planif_portee_machines'    => 'Named servers',
    'planif_valider'    => 'Save the schedule',
    'planif_annuler'    => 'Cancel',

    'planif_valeur_requise' => 'Choose a value for this scope.',
    'planif_aucun_tag'      => 'No machine in the fleet carries a tag.',
    'planif_aucune_machine'  => 'No server is visible from this account.',
    'planif_nom_requis'      => 'A name is required.',
    'planif_creee'           => 'The schedule ":nom" is saved. Next run: :quand.',
    'planif_echec'           => 'The schedule could not be saved. :message',
    'planif_conf_titre'      => 'Save this schedule?',
    'np_planif_detail' => 'Each time it is due, the schedule opens SSH sessions on the machines in its scope, without confirmation.',

    // ── Suspend, resume, delete ──────────────────────────────────────────
    // `toggle` inverts the state without setting it, and `DELETE` does not
    // check `rowcount`: the RE-READ list is what counts, not the message.
    'planif_suppr_titre'   => 'Delete this schedule',
    'planif_suppr_texte'   => 'The schedule is deleted permanently. No machine is joined.',
    'planif_suppr_court'   => 'Delete',
    'planif_suppr_valider' => 'Delete the schedule',
    'planif_suppr_faite'   => 'Schedule deleted.',
    'planif_suppr_echec'   => 'Deletion failed: :message',

    'planif_suspendre'     => 'Suspend',
    'planif_reactiver'     => 'Resume',
    'planif_bascule_faite' => 'State changed. The list below shows the result.',
    'planif_bascule_echec' => 'The state change failed: :message',
    'planif_bascule_aveugle' => 'This button inverts the stored state. If someone changed it meanwhile, rely on the re-read list.',
    'planif_ce_qui_est_arme' => 'When due, this schedule reads the machines in its scope over SSH, without confirmation.',
    'planif_prochaine_le'    => 'Next run:',
    'planif_aucune_echeance' => 'no run time recorded',
];
