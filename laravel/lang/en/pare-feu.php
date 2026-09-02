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
    /* ⚠ Fixed 2026-09-02 (E-318) — see the FR catalogue for the full note.
     * Dry-run validation IS ported (`pare-feu.js:710` calls `/iptables-validate`);
     * only applying rules and its rollback remain on the old portal. The backend
     * reserve is kept and stated: `iptables.py` has not been reloaded by the
     * running process, so the call being wired does not mean it answers. */
    'suite' => 'Reading, storing a copy and dry-run validation touch no machine — validation is ported here. Only applying rules and its rollback remain on the old portal. Validation has not been exercised since the service restarted: if it does not answer, the old portal remains the proven path.',
    'suite_lien' => 'Open the firewall on the old portal',

    // ── I2: the database copy ───────────────────────────────────────────
    'copie_titre' => 'Copy stored in the database',
    'copie_intro' => 'The portal can keep a copy of a machine\'s rules, to find them again later. Storing a copy does NOT validate it and does NOT apply it.',
    'copie_charger' => 'Load the copy',
    'copie_enregistrer' => 'Store these rules',
    'copie_absente' => 'No copy stored for this machine.',
    'copie_le' => 'Copy stored on :date',
    'copie_enregistree' => 'Copy stored for :machine. It has been neither validated nor applied.',
    'copie_rien_a_enregistrer' => 'Read the rules first: there is nothing to store.',
    'copie_v4_vide' => 'The IPv4 rules are empty. An empty copy would be refused when restoring it, so it is not stored.',
    'copie_trop_grande' => 'The rules exceed what the column can hold (:max bytes). Nothing was stored.',
    'champs_manquants' => 'Incomplete request: both rule sets are expected, even when empty.',
    'machine_refusee' => 'Unknown machine, or outside your scope.',
    'copie_lignes_multiples' => 'Warning: :nb copies exist for this machine. The most recent one is shown.',
    'copie_bloc_v4' => 'IPv4 copy',
    'copie_bloc_v6' => 'IPv6 copy',

    // ── I3: the archived version history ────────────────────────────────
    'histo_titre' => 'Archived versions',
    'histo_intro' => 'Every rule application archives the rules it replaces. An empty version is never archived: every version listed here can be restored.',
    'histo_chargement' => 'Reading history…',
    'histo_vide_titre' => 'No archived version',
    'histo_vide' => 'No rule application has taken place on this machine from this portal yet. There is therefore nothing to restore.',
    'histo_echec_titre' => 'History unreadable',
    'histo_echec' => 'The history could not be read. That is not the same as an empty history: do not conclude there is nothing to restore.',
    'histo_tout' => ':nb archived version(s).',
    'histo_tronque' => 'The :affichees most recent, out of :total in total.',
    'histo_col_date' => 'Archived on',
    'histo_col_auteur' => 'By',
    'histo_col_motif' => 'Reason',
    'histo_auteur_inconnu' => 'Author not recorded',
    'histo_auteur_supprime' => 'Deleted account (no. :id)',
    'histo_sans_motif' => 'No reason given',

    // ── I4: dry-run validation ──────────────────────────────────────────
    'valid_titre' => 'Dry-run validation',
    'valid_intro' => 'The server can check that a ruleset is syntactically applicable, without applying it.',
    'valid_bouton' => 'Validate the stored copy',
    'valid_avant' => 'This check OPENS an SSH session on the machine and writes a temporary file there. It modifies no firewall table.',
    'valid_limite' => 'Validation covers IPv4 rules ONLY. A copy whose IPv6 is malformed would pass this check and fail on apply.',
    'valid_v4_vide' => 'This copy carries no IPv4 rules. There is nothing to validate: validation only knows IPv4, and refuses an empty copy.',
    'valid_sans_copie' => 'Load the stored copy first: it is what gets validated.',
    'valid_en_cours' => 'Validation running on the machine…',
    'valid_ok' => 'The server reports these rules as applicable.',
    'valid_invalide_court' => 'The server reports these rules as invalid — verdict to be re-read below.',
    'valid_invalide_titre' => 'Reported invalid — verdict to be re-read',
    'valid_invalide' => 'The server reports these rules as invalid. This verdict IS NOT RELIABLE on long output: the exit-code detection looks for its marker inside 4096-byte chunks, and a VALID ruleset can be reported invalid when the marker straddles a boundary. Read the output before concluding.',
    'valid_echec_titre' => 'Check did not complete',
    'valid_echec' => 'The check did not complete. This is neither "valid" nor "invalid": nothing was verified.',
    'valid_sortie' => 'Server output',

    // A non-measurement announced in advance is a reserve; announced
    // afterwards, an excuse. Said above the button — see fr.
    'copie_jamais_exercee' => "Saving a rule copy has never yet been performed from this interface: the action is wired and confirmed, but its completion has not been observed on a machine. The old portal remains the only proven route.",
];
