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

    'np_config' => 'Viewing and editing `sshd_config` are not ported to this interface yet.',
    'np_config_detail' => 'Writing to `sshd_config` and reloading the service can cut SSH access to the server — and SSH is the only channel RootWarden has to get back in. A backup exists and restoring is possible.',

    'np_planif_creer' => 'Creating a scheduled reading is not ported to this interface yet.',
    'np_planif_detail' => 'A schedule opens real SSH sessions, repeatedly, with nobody watching. It targets the whole fleet by default, production included — and a narrow target whose field was left blank comes to the same thing.',
];
