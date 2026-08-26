<?php

/**
 * SFTP/SSH access per remote account — sub-batch D9b.
 *
 * READ THIS BEFORE CHANGING ANY HELP TEXT. The legacy carried help here that was
 * CORRECT — "If not needed, untick: it is safer" — and shipped the three matching
 * boxes TICKED. The screen advised the opposite of what it delivered.
 *
 * `tests/e2e/go-adm-sftp.mjs` pairs each box with ITS OWN help in the DOM and
 * refuses to let help recommending unticking sit beside a ticked box. Rewording
 * a help string without the initial state following therefore FAILS the batch —
 * by design.
 */

return [
    'titre'        => 'SFTP access per remote account',
    'intro_titre'  => 'What is this page for?',
    'intro'        => 'Here you set what a remote account may do when it connects over SSH: transfer '
                      . 'files only, or open a terminal; with or without a password; with or without '
                      . 'network tunnels. The setting is written to the machine in a block dedicated '
                      . 'to that account.',
    'machine'      => 'Machine',
    'compte'       => 'Remote account',
    'aucun_compte' => 'No managed account on this machine',
    'vide_titre'   => 'No account to set access for',
    'vide_texte'   => 'This machine has no account with status "managed" or "to review". Run an '
                      . 'inventory from the remote accounts page, then classify the accounts '
                      . 'concerned.',
    'vide_action'  => 'Open remote accounts',

    'options'      => 'What the account will be able to do when connecting',

    // ── WHAT EACH SETTING PRODUCES ─────────────────────────────────────────
    'f_sftp_only'  => 'File transfer only (no terminal)',
    'h_sftp_only'  => 'When on, the account can ONLY upload and download files. It cannot open a '
                      . 'terminal to type commands. That is what "SFTP access" means, and that is why '
                      . 'this setting starts on.',
    'f_chroot'     => 'Cage (root directory)',
    'h_chroot'     => 'The account sees ONLY this directory and what it contains, as if it were alone '
                      . 'on the machine. Absolute path, no "..". Leave empty for no cage.',
    'f_working'    => 'Landing directory',
    'h_working'    => 'The directory the account lands in on arrival. It only takes effect with file '
                      . 'transfer only: in terminal mode the module does not apply it and merely '
                      . 'records it as a comment.',
    'f_password'   => 'Allow password login',
    'h_password'   => 'When on, the account can log in with a password. When off, it MUST use an SSH '
                      . 'key — considerably safer, and that is the starting state.',
    'f_tcp'        => 'Allow network tunnels (port forwarding)',
    'h_tcp'        => 'When on, the account can route other network connections through SSH, for '
                      . 'instance to reach an internal database from outside. Off to begin with: it '
                      . 'is safer.',
    'f_agent'      => 'Allow key bouncing (agent forwarding)',
    'h_agent'      => 'When on, the account can reuse its SSH key to bounce from this machine to '
                      . 'another. Off to begin with.',
    'f_x11'        => 'Allow remote graphical display (X11)',
    'h_x11'        => 'When on, the account can open graphical windows through SSH. Rarely useful on a '
                      . 'server. Off to begin with.',

    // ── THE STARTING STATE, AND WHY IT IS THAT ONE ─────────────────────────
    'neuve_titre'  => 'No access is set for this account yet',
    'neuve_texte'  => 'The settings below start from the most closed position: file transfer only, '
                      . 'SSH key required, no tunnels. Open what you need, rather than closing what '
                      . 'you do not.',
    'ouvre'        => 'Widens access',
    'restreint'    => 'Restricts access',

    // ── THE GESTURES ───────────────────────────────────────────────────────
    'deployer'      => 'Deploy…',
    'auditer'       => 'Audit',
    'retirer'       => 'Remove…',
    'aide_deployer' => 'Writes the block to the machine, after validating the complete configuration.',
    'aide_auditer'  => 'Reads the block actually present on the machine. Changes nothing.',
    'aide_retirer'  => 'Deletes this block from the machine; the account falls back to the server\'s '
                       . 'general configuration.',

    // ── THE CONFIRMATION THAT WAS MISSING ──────────────────────────────────
    'confirmer_titre'   => 'Confirm deployment',
    'confirmer_intro'   => 'This will write an SSH configuration block to the machine. For this '
                           . 'account, that block REPLACES whatever the server\'s general '
                           . 'configuration would have given. Check before confirming:',
    'confirmer_machine' => 'Machine',
    'confirmer_compte'  => 'Account',
    'confirmer_effet'   => 'What this opens',
    'confirmer_ouvre'   => 'These settings WIDEN this account\'s access',
    'aucun_reglage_ouvert' => 'no setting widens access',
    'confirmer_valider' => 'Deploy to the machine',
    'confirmer_annuler' => 'Cancel',
    'retirer_titre'     => 'Confirm removal',
    'retirer_intro'     => 'This account\'s block will be deleted from the machine. The account will '
                           . 'fall back to the server\'s general configuration, which may be more '
                           . 'permissive.',
    'retirer_valider'   => 'Remove from the machine',
    'reauth'            => 'You will be asked to re-authenticate before this is sent.',

    // ── HISTORY ────────────────────────────────────────────────────────────
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
    'rollback_texte'   => 'Rolling a deployment back is not ported yet. It rewrites an SSH block on '
                          . 'the machine, and is done from the legacy portal for now.',
    'rollback_lien'    => 'Roll this deployment back in the legacy portal',
];
