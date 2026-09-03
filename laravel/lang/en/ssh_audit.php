<?php

/*
 * SSH configuration audit — sub-lot A1. Flat keys, loaded as one block by
 * `@json(__('ssh_audit'))`. The key set must stay identical to
 * `lang/fr/ssh_audit.php`.
 */
return [
    'titre' => 'SSH configuration audit',
    'desc'  => 'Reads the SSH service configuration of your servers, scores it against a policy, and tracks how it changes.',

    'chargement' => 'Loading…',
    'serveur_cible'   => 'Server',
    'serveur_choisir' => 'Choose a server…',
    'serveur_aucun'   => 'No server is assigned to you. The SSH audit covers the machines in your perimeter, and it is empty.',
    'serveur_borne'   => 'You only see the machines assigned to you here.',

    'historique_titre' => 'Previous readings',
    'historique_vide'  => 'No reading has been taken on this server yet.',
    'historique_err'   => 'The readings for this server could not be read.',
    'note'   => 'Score',
    'lettre' => 'Grade',
    'le'     => 'on',

    'sev_critique' => 'critical',
    'sev_haute'    => 'high',
    'sev_moyenne'  => 'medium',
    'sev_basse'    => 'low',

    'flotte_titre' => 'Latest reading for each server',
    'flotte_vide'  => 'No server has been read yet.',
    'flotte_err'   => 'The fleet state could not be read.',
    'flotte_reserve' => 'This view covers the whole fleet and is not bounded to your perimeter: it is reserved for administration.',
    'th_serveur'   => 'Server',
    'th_ip'        => 'Address',
    'th_note'      => 'Score',
    'th_mention'   => 'Grade',
    'th_critiques' => 'Critical',
    'th_releve_le' => 'Read on',

    'politique_titre' => 'Policy applied to this server',
    'politique_desc'  => 'Each rule can be audited or ignored. This page displays them; it does not change them.',
    'politique_choisir' => 'Choose a server to see the policy applied to it.',
    'politique_vide'  => 'No rule is defined for this server: the default policy applies.',
    'politique_err'   => 'The policy for this server could not be read.',
    'politique_auditee' => 'audited',
    'politique_ignoree' => 'ignored',
    'politique_motif'   => 'Reason',
    // SEC-013: GET requires `can_audit_ssh`, POST requires `role(2)` ALONE —
    // writing is less guarded than reading, on the same URL, and the gateway
    // compares PATHS, never methods. Closure is by ABSENCE of any call.
    'politique_lecture_seule' => 'Changing the policy is not offered here, and that is not an oversight: on the old portal, writing a policy is less guarded than reading one. Until that is fixed server-side, this page composes no call that would write it.',

    'planifs_titre'   => 'Scheduled readings',
    'planifs_vide'    => 'No scheduled reading.',
    'planifs_err'     => 'The schedules could not be read.',
    'planifs_reserve' => 'Scheduled readings are reserved for administration.',
    'planif_active'   => 'active',
    'planif_suspendue' => 'paused',
    'planif_prochaine' => 'Next run',
    'planif_cible_parc' => 'the whole fleet',
    'planif_cible_tag'  => 'tag: :valeur',
    'planif_cible_env'  => 'environment: :valeur',
    'planif_cible_machines' => ':n named server(s)',
    // E-280: a malformed or unrecognised target falls back to THE WHOLE FLEET.
    // E-280, corrected: `target_type` IS a closed enum, so an invented value is
    // refused by the database. What remains reachable is an INCOMPLETE target.
    'planif_cible_inconnue' => 'incomplete target — will run on THE WHOLE FLEET',
    // E-280: "whole fleet" and "target not understood" are the SAME branch.
    'planif_cible_ambigue' => "'The whole fleet' is both a legitimate choice and what an incomplete target produces — a tag whose field was left blank. Both go through the same path, and nothing afterwards tells which one was used.",

    'portee_titre' => 'What this page can do today',
    'portee_texte' => 'It reads: the readings already taken, the policy applied, the fleet state and the scheduled readings. It joins no machine and writes nothing.',

    // A button label says what it DOES; the explanation lives in the panel.
    'btn_relever' => 'Read this server',
    'btn_config'  => 'View sshd_config',
    'btn_parc'    => 'Read the whole fleet',
    'btn_planif'  => 'Schedule a reading',
    'historique_choisir' => 'Choose a server to see its previous readings.',
    'np_titre'  => 'Not ported yet',
    'np_ouvrir' => 'Open in the old portal',
    'np_fermer' => 'Close',
    'np_sur_serveur' => 'Target server: :nom',

    'np_relever' => 'Reading a single server is not ported to this interface yet.',
    'np_relever_detail' => 'Reading a server opens a real SSH session on it and reads its configuration. It is a read, but it is a connection.',

    'np_parc' => 'Reading the whole fleet is not ported to this interface yet.',
    'np_parc_detail' => 'This action opens an SSH session on EVERY non-archived machine in the fleet, production included. It takes no parameter: there is nothing to restrict, and no way to aim it elsewhere.',
    // A3: the conjunction is SPLIT, not removed — see the note in
    // `lang/fr/ssh_audit.php`. `np_config_detail` does NOT move: its reserve
    // is about WRITING, which stays absent.
    'np_config' => 'Changing `sshd_config` is not ported to this interface yet.',

    // A3 — reading it IS ported. This action JOINS the machine: the backend
    // opens a real SSH session to read the file. Nothing is written.
    'cfg_titre'    => 'Read `sshd_config` on this server?',
    'cfg_texte'    => 'This read opens a real SSH session on the chosen server. It writes nothing, neither on the machine nor in the database, and the file is shown here read-only.',
    'cfg_lire'     => 'Read the file',
    'cfg_en_cours' => 'Reading…',
    'cfg_titre_resultat' => '`sshd_config` of :nom',
    'cfg_vide'     => 'The server answered, but the file is empty.',
    'cfg_echec'    => 'The file could not be read. :message',
    'cfg_refus'    => 'The read was refused. :message',
    'cfg_sans_serveur' => 'Choose a server before reading its configuration.',
    'cfg_lecture_seule' => 'This content is shown read-only: changing `sshd_config` is not ported here.',

    'np_config_detail' => 'Writing to `sshd_config` and reloading the service can cut SSH access to the server — and SSH is the only channel RootWarden has to get back in. A backup exists and restoring is possible.',
    // A2: creating a scheduled reading is PORTED — see the note in
    // `lang/fr/ssh_audit.php`. `np_planif_detail` does NOT move: it describes
    // the consequence, and it is the decision panel's text.
    //
    // DECLARED REDUCTION: only FOUR periodicities are offered. A free cron
    // expression cannot be typed here — a schedule triggers real SSH sessions
    // with nobody watching, and a closed list cannot be bypassed by a forged
    // request. The legacy portal stays open for another periodicity.
    'planif_freq_bornee' => "Four periodicities are offered. A free cron expression cannot be typed here: a schedule triggers real SSH sessions with nobody watching, and a closed list cannot be bypassed by a forged request. For another periodicity, the legacy portal stays open.",

    'planif_form_titre' => 'Schedule a reading',
    'planif_f_nom'      => 'Schedule name',
    'planif_f_nom_aide' => 'This name identifies the schedule in the list. 100 characters at most.',
    'planif_f_freq'     => 'Periodicity',
    'planif_f_portee'   => 'What the reading covers',
    'planif_f_valeur'   => 'Scope value',
    'planif_freq_horaire'    => 'Every hour',
    'planif_freq_six_heures' => 'Every six hours',
    'planif_freq_quotidien'  => 'Every day at 02:00',
    'planif_freq_hebdo'      => 'Every Monday at 03:00',
    'planif_portee_all'         => 'The whole fleet',
    'planif_portee_environment' => 'One environment',
    'planif_portee_tag'         => 'One tag',
    'planif_portee_machines'    => 'Named servers',
    'planif_valider'    => 'Save the schedule',
    'planif_annuler'    => 'Cancel',

    // Without a value, a restricted scope covers the WHOLE fleet — E-280.
    'planif_valeur_requise' => 'This scope needs a value. Without it, the schedule would cover the whole fleet — production included.',
    'planif_aucun_tag'      => 'No tag is carried by any machine in the fleet: this scope has nothing to target.',
    'planif_aucune_machine'  => 'No server is visible from this account: this scope has nothing to target.',
    'planif_nom_requis'      => 'A name is required.',
    'planif_creee'           => 'The schedule ":nom" is saved. Next run: :quand.',
    'planif_echec'           => 'The schedule could not be saved. :message',
    'planif_conf_titre'      => 'Save this schedule?',
    'np_planif_detail' => 'A schedule opens real SSH sessions, repeatedly, with nobody watching. It targets the whole fleet by default, production included — and a narrow target whose field was left blank comes to the same thing.',
];
