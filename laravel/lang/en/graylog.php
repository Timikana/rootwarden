<?php

/*
 * Log forwarding to Graylog. FLAT keys: the file is loaded in one block by
 * `@json(__('graylog'))`. Identical key set to `lang/fr/graylog.php`, checked in
 * the same commit.
 */
return [
    'title' => 'Log forwarding (Graylog)',
    'desc'  => 'Configures how machines ship their system logs to a Graylog server, through rsyslog.',

    'onglet_config'    => 'Configuration',
    'onglet_deploy'    => 'Machines',
    'onglet_templates' => 'Templates',
    'onglet_history'   => 'History',

    'guide_titre'    => 'What the buttons on the Machines tab actually do',
    'guide_deploy'   => '"Deploy" opens an SSH connection and installs rsyslog on the machine if missing, then writes the configuration files there.',
    'guide_test'     => '"Test" runs a command on the machine to produce a log entry. The old portal did this without asking; here confirmation is required.',
    'guide_retirer'  => '"Remove" deletes the files RootWarden placed and restarts rsyslog. The rsyslog package itself is kept.',
    'guide_prod'     => 'The table lists every non-archived machine, production ones included. The confirmation names the target machine.',

    'config_titre'   => 'Destination server',
    'config_aide'    => 'These settings apply to the whole fleet: they are written into each machine\'s rsyslog configuration on the next deployment.',
    'hote'           => 'Host',
    'hote_aide'      => 'Name or address of the Graylog server receiving the logs.',
    'port'           => 'Port',
    'protocole'      => 'Protocol',
    'tls_ca'         => 'Certificate authority (TLS)',
    'tls_ca_aide'    => 'Path to the authority file on the machines. Required for TLS only.',
    'rl_burst'       => 'Maximum burst',
    'rl_interval'    => 'Rate limit interval (s)',
    'rl_aide'        => 'Zero disables rsyslog rate limiting.',
    'enregistrer'    => 'Save',
    'enregistre'     => 'Configuration saved.',
    'err_hote'       => 'The host is required: without it, no log is shipped.',
    'err_config'     => 'The configuration could not be saved.',
    'err_charge'     => 'The configuration could not be read.',
    'err_reseau'     => 'The server did not answer. Nothing was changed.',

    'err_retrait_actif' => '⚠ Removal failed: forwarding may STILL BE ACTIVE on this machine. Check before assuming logs are no longer shipped.',

    'machines_titre' => 'Machines',
    'rafraichir'     => 'Refresh',
    'chargement'     => 'Loading…',
    'aucune_machine' => 'No machine in the fleet.',
    'col_nom'        => 'Name',
    'col_ip'         => 'Address',
    'col_etat'       => 'State',
    'col_version'    => 'rsyslog version',
    'col_dernier'    => 'Last deployment',
    'col_actions'    => 'Actions',
    'etat_transfere' => 'Forwarding',
    'etat_absent'    => 'Not deployed',
    'btn_deploy'     => 'Deploy',
    'btn_test'       => 'Test',
    'btn_retirer'    => 'Remove',

    'confirm_titre_deploy'  => 'Install rsyslog and deploy the configuration?',
    'confirm_titre_test'    => 'Produce a log entry on this machine?',
    'confirm_titre_retirer' => 'Remove the RootWarden configuration?',
    'confirm_aide'          => 'Target machine: :machine (:ip). An SSH connection will be opened and the command run as root.',
    'confirm_annuler'       => 'Cancel',
    'confirm_valider'       => 'Confirm',

    'gabarits_titre' => 'Templates',
    'gabarit_nom'    => 'Name',
    'gabarit_desc'   => 'Description',
    'gabarit_actif'  => 'Enabled — pushed on the next deployment',
    'gabarit_contenu' => 'rsyslog content',
    'gabarit_nouveau' => 'New',
    'gabarit_supprimer' => 'Delete',
    'gabarit_enregistre' => 'Template saved.',
    'gabarit_supprime'   => 'Template deleted.',
    'gabarit_aucun'      => 'No template. Enabled ones are pushed to the machines on deployment.',
    'gabarit_actif_court' => 'enabled',
    'gabarit_inactif'     => 'disabled',
    'err_gabarit_nom'  => 'The template name is required.',
    'err_gabarit'      => 'The template could not be saved.',
    'confirm_titre_gabarit' => 'Delete this template?',
    'confirm_aide_gabarit'  => 'Template: :nom. It will no longer be pushed on later deployments.',

    'historique_titre' => 'History',
    'historique_vide'  => 'No recorded action.',
];
