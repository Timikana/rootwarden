<?php

/*
 * Log forwarding to Graylog. FLAT keys: the file is sent in one block by
 * `@json(__('graylog'))`. Writing rules: docs/REDACTION-INTERFACE.md.
 */
return [
    'title' => 'Log forwarding (Graylog)',
    'desc'  => 'Ships the system logs of the machines to a Graylog server, through rsyslog.',

    'onglet_config'    => 'Configuration',
    'onglet_deploy'    => 'Machines',
    'onglet_templates' => 'Templates',
    'onglet_history'   => 'History',

    'guide_titre'    => 'What the buttons do',
    'guide_deploy'   => '"Deploy" installs rsyslog if needed, then writes its configuration on the machine.',
    'guide_test'     => '"Test" writes a test entry to the machine log.',
    'guide_retirer'  => '"Remove" deletes the files RootWarden placed and restarts rsyslog; the package stays installed.',
    'guide_prod'     => 'The table includes production machines; the confirmation names the target machine.',

    'config_titre'   => 'Destination server',
    'config_aide'    => 'These settings apply to the whole fleet; they take effect on the next deployment.',
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
    'err_hote'       => 'The host is required.',
    'err_config'     => 'The configuration could not be saved.',
    'err_charge'     => 'The configuration could not be read.',
    'err_reseau'     => 'The server did not answer. Nothing was changed.',

    'err_retrait_actif' => 'Removal failed: forwarding may still be active on this machine. Check it.',

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
    'gabarit_aucun'      => 'No template. Create one with "New".',
    'gabarit_actif_court' => 'enabled',
    'gabarit_inactif'     => 'disabled',
    'err_gabarit_nom'  => 'The template name is required.',
    'err_gabarit'      => 'The template could not be saved.',
    'confirm_titre_gabarit' => 'Delete this template?',
    'confirm_aide_gabarit'  => 'Template: :nom. It will no longer be pushed on later deployments.',

    'historique_titre' => 'History',
    'historique_vide'  => 'No recorded action.',
];
