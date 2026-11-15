<?php

/**
 * Sudo rights per remote account.
 *
 * READ THIS BEFORE CHANGING ANY PRESET HELP TEXT. These strings describe a
 * privilege scope. `tests/e2e/go-adm-politiques.mjs` re-reads
 * `backend/sudo_manager.py` inside the container on every run and refuses to
 * let the screen contradict it: help for a preset classed 'root' must say root.
 * Writing rules: docs/REDACTION-INTERFACE.md.
 */

return [
    'titre'          => 'Sudo rights per remote account',
    'intro'          => 'Choose what a remote account may run as root on a machine. Nothing is written before you confirm.',
    'machine'        => 'Machine',
    'compte'         => 'Remote account',
    'aucun_compte'   => 'No managed account on this machine',
    'vide_titre'     => 'No account to grant rights to',
    'vide_texte'     => 'This machine has no "managed" or "to review" account. Run an inventory from the remote accounts page, then classify the accounts.',
    'vide_action'    => 'Open remote accounts',

    'choix'          => 'What the account will be able to do',
    'prereglage'     => 'Preset',
    'regles_libres'  => 'Typed rules',
    'regles_aide'    => 'One rule per line, in sudoers format. Only the syntax is checked, not the scope.',
    'services'       => 'Allowed services',
    'services_aide'  => 'Comma-separated.',
    'nopasswd'       => 'Without asking for a password (NOPASSWD)',
    'nopasswd_aide'  => 'No password will be asked for these commands.',
    'runas'          => 'Run as',

    // ── Scope, as sudo_manager.py documents it ─────────────────────────────
    'portee_root'         => 'Grants root access',
    'portee_root_detail'  => 'This preset can give full control of the machine.',
    'portee_borne'        => 'Bounded scope',
    'portee_borne_detail' => 'Closed list of commands.',
    'portee_inconnu'         => 'Scope not analysed',
    'portee_inconnu_detail'  => 'You write the rule; only its syntax is checked.',

    'aide_all_nopasswd'       => 'Every command as root. Reserve it for service accounts.',
    'aide_apt_only'           => 'Allows apt to install and upgrade software. Equivalent to root access: a crafted package can open a root shell.',
    'aide_restart_services'   => 'Restart, reload and check the status of any systemd service.',
    'aide_read_logs'          => 'Log reading: tail and cat under /var/log, journalctl without a pager.',
    'aide_systemctl_specific' => 'Restart, reload and check the status of only the services named below.',
    'aide_custom'             => 'Hand-written rules. Their scope is not analysed: they can grant root with nothing flagging it.',

    'preset_all_nopasswd'       => 'Full root access',
    'preset_restart_services'   => 'Service restarts',
    'preset_apt_only'           => 'APT updates',
    'preset_read_logs'          => 'Log reading',
    'preset_systemctl_specific' => 'Named services',
    'preset_custom'             => 'Free-form rules',

    // ── Actions ────────────────────────────────────────────────────────────
    'deployer'       => 'Deploy…',
    'auditer'        => 'Audit',
    'retirer'        => 'Remove…',
    'aide_deployer'  => 'Writes the configuration to the machine, after validating its syntax.',
    'aide_auditer'   => 'Reads the file present on the machine. Changes nothing.',
    'aide_retirer'   => 'Deletes this configuration from the machine; the account loses these rights.',

    // ── Confirmations ──────────────────────────────────────────────────────
    'confirmer_titre'   => 'Confirm deployment',
    'confirmer_intro'   => 'A sudoers file will be written to the machine.',
    'confirmer_machine' => 'Machine',
    'confirmer_compte'  => 'Account',
    'confirmer_portee'  => 'What this grants',
    'confirmer_root'    => 'This preset grants root access to this account.',
    'confirmer_valider' => 'Deploy to the machine',
    'confirmer_annuler' => 'Cancel',
    'retirer_titre'     => 'Confirm removal',
    'retirer_intro'     => 'This account\'s sudoers file will be deleted from the machine. The account will lose these rights.',
    'retirer_valider'   => 'Remove from the machine',
    'reauth'            => 'You will be asked to re-authenticate before this is sent.',

    // ── History ────────────────────────────────────────────────────────────
    'historique'        => 'History and rollback',
    'hist_date'         => 'Date',
    'hist_auteur'       => 'By',
    'hist_etat'         => 'Status',
    'hist_regle'        => 'Rule written',
    'hist_vide'         => 'No deployment recorded for this account.',
    'etat_applied'      => 'Applied',
    'etat_rolled_back'  => 'Rolled back',
    'etat_failed'       => 'Failed',
    'etat_superseded'   => 'Superseded',
    'derniere'          => 'Last write',
    'jamais'            => 'never deployed',
    'rollback_titre' => 'Restore an earlier version',
    'rollback_texte' => 'Rewrites on the machine the exact sudoers from before this deployment. Re-authentication required.',
    'resultat'          => 'Result',
    'rollback' => 'Roll back',
    'rollback_confirme' => 'Roll this deployment back and rewrite the previous sudoers on the machine? Re-authentication will be requested.',
];
