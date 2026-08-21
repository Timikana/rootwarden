<?php

/*
 * Module `ssh/` — "SSH keys". Sub-batch K1: the bare page.
 *
 * `serveurs_disponibles` carries a `:nombre` token that is ACTUALLY substituted.
 * The legacy writes `count($machines)` then `t('ssh.servers_available')`, whose
 * value is ":count serveur(s) disponible(s)" — the token stays on screen.
 */

return [
    'titre' => 'SSH key deployment',
    'description' => 'Select the servers to deploy the public keys of entitled accounts to. The deployment itself is still on the legacy portal.',
    'serveurs_disponibles' => ':nombre server(s) available',

    'aucun_serveur' => 'No reachable server',
    'aucun_serveur_aide' => 'No machine is assigned to you, or every machine in the fleet is archived.',

    'filtre_tag' => 'Tag',
    'filtre_env' => 'Environment',
    'tous_tags' => 'All tags',
    'tous_envs' => 'All environments',
    'cocher_filtre' => 'Select filtered',
    'cocher_tout' => 'Select all',
    'decocher_tout' => 'Clear selection',

    'aucune_selection' => 'No server selected',
    'selection' => ':nombre server(s) selected',

    'deployer' => 'Deploy the keys',
    'annuler' => 'Cancel',
    'confirmer_titre' => 'Deploy SSH keys to these servers?',
    'confirmer_avertissement' => 'On every checked server, as root: the sudo package is installed if missing, entitled accounts are created, their authorized_keys file is REWRITTEN, and a sudoers policy is installed. Keys belonging to any account that lost its entitlement are REVOKED. None of this can be undone from this page.',
    'non_porte' => 'Starting the deployment and reading its log are not ported yet.',
    'non_porte_lien' => 'Run them from the legacy portal',
];
