<?php

/**
 * Sudo rights per remote account — sub-batch D9a.
 *
 * READ THIS BEFORE CHANGING ANY PRESET HELP TEXT. These strings describe a
 * privilege scope. The legacy claimed, under `apt_only`, "They cannot touch the
 * rest of the system", while `backend/sudo_manager.py:80-84` documents the
 * opposite — "this preset is ROOT-EQUIVALENT".
 *
 * `tests/e2e/go-adm-politiques.mjs` re-reads that module inside the container on
 * every run and refuses to let the screen contradict it. Help text that softens
 * the scope of a preset classed 'root' therefore FAILS the batch — by design.
 */

return [
    'titre'          => 'Sudo rights per remote account',
    'intro_titre'    => 'What is this page for?',
    'intro'          => '"sudo" lets an ordinary account run certain commands as the administrator '
                        . '(root). Here you choose, for ONE account on ONE machine, what it will be '
                        . 'allowed to do — then you confirm before anything is written to the machine.',
    'machine'        => 'Machine',
    'compte'         => 'Remote account',
    'aucun_compte'   => 'No managed account on this machine',
    'vide_titre'     => 'No account to grant rights to',
    'vide_texte'     => 'This machine has no account with status "managed" or "to review". '
                        . 'Run an inventory from the remote accounts page, then classify the '
                        . 'accounts concerned.',
    'vide_action'    => 'Open remote accounts',

    'choix'          => 'What the account will be able to do',
    'prereglage'     => 'Preset',
    'regles_libres'  => 'Rules entered',
    'regles_aide'    => 'One rule per line, in sudoers format. Only the SYNTAX will be checked '
                        . '(`visudo -cf`): the actual scope of what you write is not analysed.',
    'services'       => 'Allowed services',
    'services_aide'  => 'Comma-separated. Example: nginx, php8.2-fpm, redis-server',
    'nopasswd'       => 'Without asking for a password (NOPASSWD)',
    'nopasswd_aide'  => 'When ticked, the account will have no password to enter for these commands.',
    'runas'          => 'Run as',

    // ── SCOPE, as the module itself documents it ───────────────────────────
    'portee_root'         => 'Grants root access',
    'portee_root_detail'  => 'This preset ultimately allows full control of the machine.',
    'portee_borne'        => 'Bounded scope',
    'portee_borne_detail' => 'Closed command list, hardened by the module that produces it.',
    'portee_inconnu'         => 'Scope not analysed',
    'portee_inconnu_detail'  => 'You write the rule yourself; only its syntax will be checked.',

    'aide_all_nopasswd'       => 'Full root access, without a password: the rule written is literally '
                                 . '"everything, as root". Reserve this for service accounts.',
    'aide_apt_only'           => 'Allows "apt" to install and upgrade software. '
                                 . 'THIS AMOUNTS TO ROOT ACCESS: installing a package runs its '
                                 . 'maintainer scripts as root, which allows obtaining a root shell '
                                 . 'through a package built for that purpose. There is no safe way to '
                                 . '"limit this to apt". Grant it only to operators you would already '
                                 . 'trust with root.',
    'aide_restart_services'   => 'Allows restarting, reloading and checking the status of systemd '
                                 . 'services, with no restriction on which ones.',
    'aide_read_logs'          => 'Reading logs only: "tail" and "cat" under /var/log, and "journalctl" '
                                 . 'without paging. The module removed "less", which allowed opening a '
                                 . 'root shell.',
    'aide_systemctl_specific' => 'Restart, reload and check the status of ONLY the services you name '
                                 . 'below.',
    'aide_custom'             => 'Hand-written rules. Their scope is not analysed: they may grant root '
                                 . 'without anything saying so.',

    'preset_all_nopasswd'       => 'Full root access',
    'preset_restart_services'   => 'Service restarts',
    'preset_apt_only'           => 'APT updates',
    'preset_read_logs'          => 'Log reading',
    'preset_systemctl_specific' => 'Named services',
    'preset_custom'             => 'Free-form rules',

    // ── THE GESTURES ───────────────────────────────────────────────────────
    'deployer'       => 'Deploy…',
    'auditer'        => 'Audit',
    'retirer'        => 'Remove…',
    'aide_deployer'  => 'Writes the configuration to the machine, after validating its syntax.',
    'aide_auditer'   => 'Reads the file actually present on the machine. Changes nothing.',
    'aide_retirer'   => 'Deletes this configuration from the machine; the account loses these rights.',

    // ── THE CONFIRMATION THAT WAS MISSING ──────────────────────────────────
    'confirmer_titre'   => 'Confirm deployment',
    'confirmer_intro'   => 'This will write a sudoers file to the machine. Check before confirming:',
    'confirmer_machine' => 'Machine',
    'confirmer_compte'  => 'Account',
    'confirmer_portee'  => 'What this grants',
    'confirmer_root'    => 'This preset grants root access to that account.',
    'confirmer_valider' => 'Deploy to the machine',
    'confirmer_annuler' => 'Cancel',
    'retirer_titre'     => 'Confirm removal',
    'retirer_intro'     => 'This account\'s sudoers file will be deleted from the machine. '
                           . 'The account will lose the rights it granted.',
    'retirer_valider'   => 'Remove from the machine',
    'reauth'            => 'You will be asked to re-authenticate before this is sent.',

    // ── HISTORY ────────────────────────────────────────────────────────────
    'historique'        => 'History and rollback',
    'hist_date'         => 'Date',
    'hist_auteur'       => 'By',
    'hist_etat'         => 'Status',
    'hist_fichier'      => 'File',
    'hist_regle'        => 'Rule written',
    'hist_vide'         => 'No deployment recorded for this account.',
    'etat_applied'      => 'Applied',
    'etat_rolled_back'  => 'Rolled back',
    'etat_failed'       => 'Failed',
    'etat_superseded'   => 'Superseded',
    'derniere'          => 'Last write',
    'jamais'            => 'never deployed',
    'rollback_titre' => 'Restore an earlier version',
    'rollback_texte' => 'Rolling a deployment back is not ported yet. It rewrites a sudoers file on the machine, and is done from the legacy portal for now.',
    'rollback_lien' => 'Roll this deployment back in the legacy portal',
    'resultat'          => 'Result',
];
