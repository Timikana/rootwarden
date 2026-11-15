<?php

/**
 * Standardised `.bashrc` deployment — English.
 *
 * Same key set as lang/fr/bashrc.php. Writing rules: docs/REDACTION-INTERFACE.md.
 * Texts read by the JS travel through the controller's `$textes` block.
 */

return [
    'titre'       => '.bashrc deployment',
    'intro'       => 'Installs a standardised `.bashrc` on the chosen accounts; it runs on every login.',
    'onglet_deploiement' => 'Deployment',
    'onglet_historique'  => 'History',
    'onglet_gabarit'     => 'Template',

    // ── THE ESTATE ─────────────────────────────────────────────────────────
    'machines'        => 'Target machines',
    'col_nom'         => 'Machine',
    'col_ip'          => 'Address',
    'col_etat'        => 'Last deployment',
    'jamais'          => 'never deployed',
    'simule_le'       => 'simulated on :date by :auteur, nothing was written',
    'deploye_le'      => 'deployed on :date by :auteur',

    // ── THE SENSITIVE MACHINE ──────────────────────────────────────────────
    'sensible'        => 'Production',
    'sensible_aide'   => 'A deployment replaces the `.bashrc` of the chosen accounts, including `root`\'s if ticked.',
    'avert_titre'     => 'This list includes production',
    'avert_un'        => 'One of the :total machines is in production or critical; it is flagged in the table.',
    'avert_plusieurs' => ':nb of the :total machines are in production or critical; they are flagged in the table.',

    // ── THE COUNTER, WHICH IS STATED ───────────────────────────────────────
    'aucune_selection' => 'No machine selected.',
    'selection_une'    => '1 machine selected.',
    'selection_n'      => ':nb machines selected.',
    'selection_prod'   => ':nb machines selected, :prod of them in production.',

    'vide_titre'  => 'No machine in the estate',
    'vide_texte'  => 'Add a machine from the Servers page.',
    'vide_action' => 'Open servers',

    'comptes_titre' => 'Machine accounts',
    'comptes_choisir' => 'Tick a machine to read its accounts.',
    'comptes_plusieurs' => 'Tick a single machine to read its accounts.',
    'comptes_chargement' => 'Reading accounts…',
    'comptes_echec' => 'Could not read the accounts. Check that the machine is reachable.',
    'comptes_aucun' => 'No eligible account (UID 0 or ≥ 1000, with a shell).',
    'col_compte' => 'Account',
    'col_uid' => 'UID',
    'col_home' => 'Home directory',
    'col_bashrc' => 'Current file',
    'bashrc_absent' => 'absent',
    'tout' => 'Tick all',
    'tout_avec_root' => '(root included)',
    'compte_root' => 'administrator',
    'compte_root_aide' => 'Administrator account: its .bashrc runs on every root login.',
    'apercu' => 'Preview (diff)',
    'apercu_aide' => 'Shows what would change, without writing anything.',
    'apercu_titre' => 'What would change',
    'apercu_chargement' => 'Reading the remote file…',
    'apercu_echec' => 'Could not build the preview.',
    'apercu_vide' => 'Tick at least one account to see what would change.',
    'apercu_taille' => ':avant o → :apres o',

    'perso' => 'customised',
    'perso_aide' => 'Only the "USER CUSTOM" blocks are kept (in ~/.bashrc.local); the rest of the file is replaced.',

    'gabarit_titre' => 'The deployed template',
    'gabarit_intro' => 'Every machine will receive this file at the next deployment.',
    'gabarit_lignes' => 'Lines',
    'gabarit_octets' => 'Bytes',
    'gabarit_sha' => 'Fingerprint',
    'gabarit_chargement' => 'Reading the template…',
    'gabarit_echec' => 'Could not read the template.',
    'gabarit_modifie' => 'Unsaved changes.',
    'gabarit_enregistrer' => 'Save',
    'gabarit_annuler' => 'Discard changes',
    'gabarit_enregistre' => 'Template saved.',
    'gabarit_erreur' => 'Saving failed.',
    'gabarit_encours' => 'Saving…',
    'gabarit_confirmer' => 'Save this template? Every machine will receive it at the next deployment.',
    'danger_titre' => 'Forms recognised as destructive',
    'danger_reconnu' => 'Recognised:',
    'danger_portee' => 'Only eight known forms are detected; on saving, only the syntax is checked.',
    'danger_confirmer' => 'This template contains forms recognised as destructive. Save it anyway?',

    // ── THE WRITES ─────────────────────────────────────────────────────────
    'col_action' => 'Action',
    'deploy' => 'Deploy',
    'deploy_aide' => 'Writes the standardised .bashrc to the ticked accounts, after a timestamped backup of the old one.',
    'deploy_confirme' => "Deploy the standardised .bashrc to :nombre account(s): :comptes?\n\nThe old file is backed up; \"USER CUSTOM\" blocks are moved to ~/.bashrc.local.",
    'deploy_en_cours' => 'Deploying…',
    'deploy_fait' => 'Deployment complete.',
    'deploy_echec' => 'Deployment failed. The remote .bashrc was not replaced.',
    'deploy_sans_cible' => 'Choose a machine and at least one account.',
    'restore' => 'Restore',
    'restore_aide' => 'Restores the most recent backup of this account.',
    // The JS replaces only the FIRST occurrence of each placeholder.
    'restore_confirme' => "Restore :sauvegarde for :compte?\n\nDated :date, :taille bytes; the most recent of :nombre backup(s).\n\nThe current .bashrc will be replaced.",
    'restore_en_cours' => 'Restoring :compte…',
    'restore_fait' => 'Backup restored for :compte.',
    'restore_echec' => 'Restoring :compte failed.',
    'figlet_absent' => 'figlet is not installed: the .bashrc banner will not render. The rest works.',

    'restore_lecture' => 'Reading backups for :compte…',
    'restore_aucune' => 'No backup for :compte: nothing to restore.',

    // ── INSTALLING figlet ──────────────────────────────────────────────────
    'figlet_installer' => "Install figlet",
    'figlet_confirme' => "Install figlet on this machine?\n\nThe package will be installed by the package manager. This page cannot uninstall it.",
    'figlet_en_cours' => "Installing figlet…",
    'figlet_fait' => "figlet is installed.",
    'figlet_echec' => "Installing figlet failed.",

];
