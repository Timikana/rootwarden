<?php

/**
 * SFTP/SSH access per remote account.
 *
 * CAUTION BEFORE CHANGING A HELP TEXT. `tests/e2e/go-adm-sftp.mjs` pairs each
 * checkbox with ITS help in the DOM and rejects a help text recommending to
 * untick next to a ticked box. Writing rules: docs/REDACTION-INTERFACE.md.
 */

return [
    'titre'        => 'SFTP access per remote account',
    'intro'        => 'Set what a remote account may do over SSH: file transfer or terminal, password, tunnels.',
    'machine'      => 'Machine',
    'compte'       => 'Remote account',
    'aucun_compte' => 'No managed account on this machine',
    'vide_titre'   => 'No account to set access for',
    'vide_texte'   => 'This machine has no "managed" or "to review" account. Run an inventory from the remote accounts page, then classify the accounts.',
    'vide_action'  => 'Open remote accounts',

    'options'      => 'What the account will be able to do when connecting',

    // ── What each setting produces ─────────────────────────────────────────
    'f_sftp_only'  => 'File transfer only (no terminal)',
    'h_sftp_only'  => 'The account can only upload and download files.',
    'f_chroot'     => 'Cage (root directory)',
    'h_chroot'     => 'The account only sees this directory. Absolute path, no ".."; empty: no cage.',
    'f_working'    => 'Landing directory',
    // sftp_manager.py: in terminal mode the directory is only written as a comment.
    'h_working'    => 'Applied only with file transfer only.',
    'f_password'   => 'Allow password login',
    'h_password'   => 'When off, an SSH key is required.',
    'f_tcp'        => 'Allow network tunnels (port forwarding)',
    'h_tcp'        => 'Lets other network connections pass through SSH.',
    'f_agent'      => 'Allow key bouncing (agent forwarding)',
    'h_agent'      => 'Lets the account reuse its SSH key to bounce to another machine.',
    'f_x11'        => 'Allow remote graphical display (X11)',
    'h_x11'        => 'Lets the account open graphical windows through SSH.',

    // ── Starting state (AccesSftp::initial) ────────────────────────────────
    'neuve_titre'  => 'No access is set for this account yet',
    'neuve_texte'  => 'The settings start from the most closed position: file transfer only, SSH key required, no tunnels.',
    'ouvre'        => 'Widens access',
    'restreint'    => 'Restricts access',

    // ── Actions ────────────────────────────────────────────────────────────
    'deployer'      => 'Deploy…',
    'auditer'       => 'Audit',
    'retirer'       => 'Remove…',
    'aide_deployer' => 'Writes the block to the machine, after validating the configuration.',
    'aide_auditer'  => 'Reads the block present on the machine. Changes nothing.',
    'aide_retirer'  => 'Deletes this block from the machine.',

    // ── Confirmations ──────────────────────────────────────────────────────
    'confirmer_titre'   => 'Confirm deployment',
    'confirmer_intro'   => 'An SSH configuration block will be written to the machine. For this account, it replaces the server\'s general configuration.',
    'confirmer_machine' => 'Machine',
    'confirmer_compte'  => 'Account',
    'confirmer_effet'   => 'What this opens',
    'confirmer_ouvre'   => 'These settings widen this account\'s access',
    'aucun_reglage_ouvert' => 'no setting widens access',
    'confirmer_valider' => 'Deploy to the machine',
    'confirmer_annuler' => 'Cancel',
    'retirer_titre'     => 'Confirm removal',
    'retirer_intro'     => 'This account\'s block will be deleted from the machine. The account will fall back to the server\'s general configuration, which may be more permissive.',
    'retirer_valider'   => 'Remove from the machine',
    'reauth'            => 'You will be asked to re-authenticate before this is sent.',

    // ── History ────────────────────────────────────────────────────────────
    'historique'       => 'History and rollback',
    'hist_date'        => 'Date',
    'hist_auteur'      => 'By',
    'hist_etat'        => 'Status',
    'hist_bloc'        => 'Block written',
    'hist_vide'        => 'No deployment recorded for this account.',
    'etat_applied'     => 'Applied',
    'etat_rolled_back' => 'Rolled back',
    'etat_failed'      => 'Failed',
    'etat_superseded'  => 'Superseded',
    'derniere'         => 'Last write',
    'jamais'           => 'never deployed',
    'resultat'         => 'Result',
    'rollback_titre'   => 'Restore an earlier version',
    'rollback_texte'   => 'Rewrites on the machine the exact SSH block from before this deployment. Re-authentication required.',
    'rollback' => 'Roll back',
    'rollback_confirme' => 'Roll this deployment back and rewrite the previous SSH block on the machine? Re-authentication will be requested.',
];
