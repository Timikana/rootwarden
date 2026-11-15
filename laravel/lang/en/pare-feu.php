<?php

/**
 * iptables firewall. Writing rules: docs/REDACTION-INTERFACE.md.
 *
 * No text may announce stricter access than the one actually enforced.
 */

return [
    'titre' => 'Firewall',
    'intro' => 'Read, validate, apply and restore the iptables rules of a machine.',

    // ── Choosing the machine ────────────────────────────────────────────
    'serveur' => 'Machine',
    'choisir' => 'Pick a machine, then read its rules.',
    'relever' => 'Read the rules',
    'aucune_machine_choisie' => 'Pick a machine first.',
    'machines_aucune_titre' => 'No machine is available to you',
    'machines_aucune' => 'Ask an administrator for access.',

    // ── What the page says BEFORE the action ────────────────────────────
    'sensible' => 'Production',
    'sensible_avert' => 'Machine in production or critical: reading its rules changes nothing, the next actions do.',
    'avert_titre' => 'A production machine is in this list',
    'avert_un' => 'One of the :total machines is in production or critical.',
    'avert_plusieurs' => ':nb of the :total machines are in production or critical.',

    /*
     * The SSH port is announced at the moment of choice, and it comes from the
     * DATABASE. The legacy rule templates assume 22; all three machines listen
     * on 22 today, so the defect is not armed — which is exactly what makes it
     * invisible. Announcing it now is refusing to reproduce it later.
     */
    'port_ssh_annonce' => 'SSH access for this machine: port :port. A rule set that closes this port would cut access, including RootWarden\'s.',

    // ── The reading ─────────────────────────────────────────────────────
    'chargement' => 'Reading rules on the machine…',
    'releve_ok' => 'Rules read on :machine.',
    'releve_le' => 'Read on :date',
    'echec' => 'The rules could not be read. Is the machine reachable?',
    'echec_reseau' => 'The request did not complete: nothing was read.',

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
    'fichier_absent' => 'This file does not exist on the machine: the active rules will not be restored at reboot.',

    // ── What I1 does not do, said on screen rather than silently absent ──
    /* ⚠ Fixed 2026-09-02 (E-318) — see the FR catalogue for the full note.
     * Dry-run validation IS ported (`pare-feu.js:710` calls `/iptables-validate`);
     * only applying rules and its rollback remain on the old portal. The backend
     * reserve is kept and stated: `iptables.py` has not been reloaded by the
     * running process, so the call being wired does not mean it answers. */

    // ── I2: the database copy ───────────────────────────────────────────
    'copie_titre' => 'Saved copy',
    'copie_intro' => 'The portal can keep a copy of a machine\'s rules. Saving it neither validates nor applies it.',
    'copie_charger' => 'Load the copy',
    'copie_enregistrer' => 'Store these rules',
    'copie_absente' => 'No copy stored for this machine.',
    'copie_le' => 'Copy stored on :date',
    'copie_enregistree' => 'Copy stored for :machine. It has been neither validated nor applied.',
    'copie_rien_a_enregistrer' => 'Read the rules first: there is nothing to store.',
    'copie_v4_vide' => 'The IPv4 rules are empty: an empty copy could not be restored, so it is not saved.',
    'copie_trop_grande' => 'The rules exceed the maximum size (:max bytes). Nothing was saved.',
    'champs_manquants' => 'Incomplete request: both rule sets are expected, even when empty.',
    'machine_refusee' => 'Unknown machine, or outside your scope.',
    'copie_lignes_multiples' => 'Warning: :nb copies exist for this machine. The most recent one is shown.',
    'copie_bloc_v4' => 'IPv4 copy',
    'copie_bloc_v6' => 'IPv6 copy',

    // ── I3: the archived version history ────────────────────────────────
    'histo_titre' => 'Archived versions',
    'histo_intro' => 'Each apply archives the rules it replaces, unless they were empty. Every version listed can be restored.',
    'histo_chargement' => 'Reading history…',
    'histo_vide_titre' => 'No archived version',
    'histo_vide' => 'No rules have been applied on this machine from this portal yet: nothing to restore.',
    'histo_echec_titre' => 'History unreadable',
    'histo_echec' => 'The history could not be read: do not conclude there is nothing to restore.',
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
    'valid_intro' => 'Checks that a rule set can be applied, without applying it.',
    'valid_bouton' => 'Validate the stored copy',
    'valid_avant' => 'This check opens an SSH session and writes a temporary file on the machine; it does not change the firewall.',
    'valid_limite' => 'Only the IPv4 rules are checked: an IPv6 error would pass this check and fail when applied.',
    'valid_v4_vide' => 'This copy has no IPv4 rule: nothing to validate.',
    'valid_sans_copie' => 'Load the stored copy first: it is what gets validated.',
    'valid_en_cours' => 'Validation running on the machine…',
    'valid_ok' => 'The server reports these rules as applicable.',
    'valid_invalide_court' => 'The server reports these rules as invalid: read the output below.',
    'valid_invalide_titre' => 'Rules reported as invalid',
    'valid_invalide' => 'The server reports these rules as invalid. Read the output before fixing them.',
    'valid_echec_titre' => 'Check did not complete',
    'valid_echec' => 'The check did not complete: nothing was verified.',
    'valid_sortie' => 'Server output',

    // A non-measurement announced in advance is a reserve; announced
    // afterwards, an excuse. Said above the button — see fr.

    /* Q3 — the eight titles `rwRetourPareFeu()` returns. They were cited by the
     * module and existed nowhere: a title that designates nothing satisfies every
     * shape assertion while rendering bare. The four `sur: false` cases say
     * "I don't know", never "it failed". */
    'ipt_retour_succes'           => 'The rules were applied.',
    'ipt_retour_regles_invalides' => 'The server rejected these rules: nothing was applied, and the machine is unchanged.',
    'ipt_retour_refus'            => 'The request was refused before any check of the rules. Nothing was applied.',
    'ipt_retour_erreur_serveur'   => 'The server failed before answering. Nothing tells us whether the rules were applied: read the machine state before retrying.',
    'ipt_retour_corps_illisible'  => 'The server answered, but its answer is unreadable. The change may have gone through: read the machine state before retrying.',
    'ipt_retour_inabouti'         => 'The request never left. Nothing was applied.',
    'ipt_retour_doute_marqueur'   => 'The server reports that its verdict is not sound. Read it as neither success nor failure: read the machine state.',
    'ipt_retour_contrat_inconnu'  => 'The answer matches no expected case. Read the machine state rather than assume.',

    /* I5 — the apply screen. */
    'appl_titre'      => 'Apply a rule set',
    'appl_intro'      => 'The chosen set replaces every rule on the machine (iptables-restore). The previous version is archived before writing.',
    'appl_gabarit'    => 'Rule set',
    'appl_gabarit_aide' => 'The SSH port comes from the chosen machine; it is never assumed to be 22.',
    'appl_apercu'     => 'What will be applied',
    'appl_ssh_ouvert' => 'SSH port :port stays reachable with this set.',
    'appl_ssh_ferme'  => '⛔ This set closes SSH port :port: once applied, it would cut your access, and only a physical console could bring it back.',
    'appl_ssh_doute'  => '⛔ Cannot tell whether SSH port :port stays open with this set: applying is refused.',
    'appl_bouton'     => 'Apply to the machine',
    'appl_en_cours'   => 'Applying…',
    'appl_conf_titre' => 'Replace the rules on :machine?',
    'appl_conf_texte' => 'Every current rule on :machine will be replaced by the ":gabarit" set. The previous version is archived and can be restored from the history.',
    'appl_conf_ok'    => 'Replace the rules',
    'appl_conf_non'   => 'Cancel',
    'appl_annule'     => 'Cancelled — no request was sent.',

    /* I6 — rollback. It is MORE dangerous than applying, not less: applying, the
     * operator WRITES the rules and can read them; rolling back, they pick a DATE.
     * `iptables_history` carries no port, and an archived version was valid ON THE
     * DAY IT WAS ARCHIVED — if the SSH port changed since, restoring it closes
     * access. Q2 therefore uses TODAY's port, never the archive's.
     * The first two keys are rendered by the SERVER and need not travel. */
    'rb_version_absente'     => 'No version selected.',
    'rb_version_introuvable' => 'That version cannot be found for this machine.',
    'rb_titre'      => 'Rollback',
    'rb_bouton'     => 'Return to this version',
    'rb_lecture'    => 'Reading the archived version…',
    'rb_lecture_echec' => 'The version could not be read. Nothing was restored.',
    'rb_apercu'     => 'What will be restored',
    'rb_archive_le' => 'Version archived on :date',
    'rb_ssh_ouvert' => 'SSH port :port, the machine\'s port today, stays reachable with this version.',
    'rb_ssh_ferme'  => '⛔ This version closes the current SSH port :port: restored now, it would cut your access.',
    'rb_ssh_doute'  => '⛔ Cannot tell whether this version leaves SSH port :port open: restoring is refused.',
    'rb_conf_titre' => 'Restore the version from :date on :machine?',
    'rb_conf_texte' => 'The current rules on :machine will be replaced by this version. The current state is archived before writing: this rollback can be undone.',
    'rb_conf_ok'    => 'Restore this version',
    'rb_conf_non'   => 'Cancel',
    /*
     * VALIDATION BEFORE ROLLBACK — TWO REFUSALS, TWO SENTENCES.
     *
     * « invalid » is an ACCUSATION: it is about the rules, and it must be true.
     * « undecided » is an ADMISSION: nothing was verified. Both refuse; merging
     * them would wear the guard down, because an operator who knows his ruleset
     * is sound would learn that the guard is wrong.
     */
    'rb_valid_en_cours'   => 'Checking this version against the machine…',
    'rb_valid_invalide'   => '⛔ Version refused: the machine cannot load it. Restored, it would overwrite the rules file and the machine would reboot without a firewall. Nothing was applied.',
    'rb_valid_indecidable' => '⚠ Restore refused: the check did not complete (:motif). Nothing was applied.',
    'rb_en_cours'   => 'Restoring…',
    'rb_annule'     => 'Cancelled — no request was sent.',
];
