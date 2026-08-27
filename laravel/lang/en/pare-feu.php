<?php

/**
 * Firewall (iptables) — sub-lot I1.
 *
 * The legacy header claims "superadmin (role_id = 3) only — access denied to
 * all other roles", twice, while its guard admits role 1 (pattern E-36, fourth
 * occurrence). No text on this page may announce stricter access than the one
 * actually enforced.
 *
 * And none may suggest that `can_manage_iptables` protects the ACTIONS: of the
 * 23 routes across both filtering modules, only two checked it before the E-152
 * fix. It protects the screen.
 *
 * Key set MUST match `lang/fr/pare-feu.php` exactly — parity is verified.
 */

return [
    'titre' => 'Firewall',
    'intro' => 'The iptables firewall decides which connections a machine accepts. This page reads the rules currently in force, without changing anything.',

    // ── Choosing the machine ────────────────────────────────────────────
    'serveur' => 'Machine',
    'choisir' => 'Pick a machine, then read its rules.',
    'relever' => 'Read the rules',
    'aucune_machine_choisie' => 'Pick a machine first.',
    'machines_aucune_titre' => 'No machine is available to you',
    'machines_aucune' => 'This page only lists machines your account has access to. Ask an administrator for access.',

    // ── What the page says BEFORE the action ────────────────────────────
    'sensible' => 'Production',
    'sensible_avert' => 'This machine is in production or flagged critical. Reading its rules does not change them — but it is the machine the next actions will target.',
    'avert_titre' => 'A production machine is in this list',
    'avert_un' => 'One of the :total machines listed is in production or flagged critical.',
    'avert_plusieurs' => ':nb of the :total machines listed are in production or flagged critical.',

    /*
     * The SSH port is announced at the moment of choice, and it comes from the
     * DATABASE. The legacy rule templates assume 22; all three machines listen
     * on 22 today, so the defect is not armed — which is exactly what makes it
     * invisible. Announcing it now is refusing to reproduce it later.
     */
    'port_ssh_annonce' => 'SSH access for this machine: port :port. A ruleset that does not leave this port open would cut access, including RootWarden\'s own.',

    // ── The reading ─────────────────────────────────────────────────────
    'chargement' => 'Reading rules on the machine…',
    'releve_ok' => 'Rules read on :machine.',
    'releve_le' => 'Read on :date',
    'echec' => 'The rules could not be read. Is the machine reachable?',
    'echec_reseau' => 'The request did not complete. Neither success nor refusal: nothing was read.',

    // ── The four blocks ─────────────────────────────────────────────────
    'bloc_actives_v4' => 'Active rules (IPv4)',
    'bloc_actives_v6' => 'Active rules (IPv6)',
    'bloc_fichier_v4' => 'File rules.v4',
    'bloc_fichier_v6' => 'File rules.v6',

    /*
     * Three outcomes, not two: the read fails, the file is missing, the file
     * exists and is empty. The legacy distinguishes none of them — it drops the
     * response into a block and the marker the shell fabricates becomes the
     * file's contents (same defect as E-161 on fail2ban).
     */
    'bloc_vide_titre' => 'No rules',
    'bloc_vide' => 'The machine applies no rule on this stack. Everything is accepted by default.',
    'fichier_absent_titre' => 'File missing',
    'fichier_absent' => 'This file does not exist on the machine. The active rules will therefore not be restored on reboot.',

    // ── What I1 does not do, said on screen rather than silently absent ──
    'suite_titre' => 'This page changes nothing',
    'suite' => 'Reading is a read. Saving to the database, dry-run validation and applying rules are not ported yet: they remain on the old portal.',
    'suite_lien' => 'Open the firewall on the old portal',
];
