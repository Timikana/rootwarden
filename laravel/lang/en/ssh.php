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
    // ── The pre-deployment check (sub-batch K2) ─────────────────────────────
    'verifier' => 'Check prerequisites',
    'verifier_aide' => 'Queries the checked servers READ-ONLY and reports back. Deploys nothing.',
    'verif_en_cours' => 'Checking...',
    'verif_echec' => 'The check failed (code :statut)',
    'verif_pret' => 'No missing prerequisite',
    'verif_bloque' => ':nombre server(s) blocked: fix below or uncheck them',
    'cles_aucune' => 'WARNING: no active account carries an SSH key — a deployment would deploy nothing',
    'cles_nombre' => ':nombre active account(s) with an SSH key',
    'inventaire' => ':nombre account(s) inventoried on this server',
    'a_creer' => 'Accounts that will be created:',
    'a_revoquer' => 'Access that will be REVOKED (key removed, account kept):',
    'lien_comptes_distants' => 'Open Remote users',
    // ── The deployment log (sub-batch K3) ───────────────────────────────────
    'journal' => 'View the last deployment log',
    'journal_aide' => 'Reads the log already written. Contacts no server and triggers nothing.',
    'journal_ouverture' => 'Reading the log...',
    'journal_vide' => 'The log is empty: no deployment has been started yet.',
    'journal_fin' => '— end of log —',
    'journal_refus' => 'The log was refused by the server (code :statut)',
    'journal_interrompu' => 'The stream ended before the log did: what precedes is incomplete',
];
