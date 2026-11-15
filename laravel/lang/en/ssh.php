<?php

/*
 * SSH keys: deploying public keys across the fleet.
 *
 * `serveurs_disponibles` carries a `:nombre` token that IS substituted.
 * Writing rules: docs/REDACTION-INTERFACE.md.
 */

return [
    'titre' => 'SSH key deployment',
    'description' => 'Select the servers, check the prerequisites, then deploy the public keys of entitled accounts.',
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
    'confirmer_avertissement' => 'On every checked server, as root: sudo is installed if missing, entitled accounts are created, their authorized_keys is rewritten and a sudoers policy is installed. Keys of accounts that lost their entitlement are revoked, with no way back from this page.',

    // ── Pre-deployment check ────────────────────────────────────────────────
    'verifier' => 'Check prerequisites',
    'verifier_aide' => 'Queries the checked servers read-only. Deploys nothing.',
    'verif_en_cours' => 'Checking…',
    'verif_echec' => 'The check failed (code :statut)',
    'verif_non_concluante' => 'The check is not conclusive: the server returned no verdict.',
    'verif_pret' => 'No missing prerequisite',
    'verif_bloque' => ':nombre server(s) blocked: fix below or uncheck them',
    // DeploiementCles refuses the deployment when `users_with_keys` is zero.
    'cles_aucune' => 'No active account carries an SSH key: the deployment will be refused. Add a key to at least one account.',
    'cles_nombre' => ':nombre active account(s) with an SSH key',
    'inventaire' => ':nombre account(s) inventoried on this server',
    'revoques_synthese' => 'Access that will be revoked on the checked servers — :nombre in total: :noms',
    'inventaire_non_lu' => 'The account inventory could not be read on this machine: the access that would be revoked is unknown.',
    'machines_sans_resultat' => 'Selected machines with no result: :nombre. They are counted neither blocking nor ready.',
    'badge_ok' => 'OK',
    'badge_echec' => 'FAIL',
    'badge_partiel' => 'PARTIAL',
    'a_creer' => 'Accounts that will be created:',
    'a_revoquer' => 'Access that will be revoked (key removed, account kept):',
    'sans_cle' => 'Authorised accounts with no key for this machine — their keys will be removed there:',
    'lien_comptes_distants' => 'Open remote accounts',

    // ── Deployment log ──────────────────────────────────────────────────────
    'journal' => 'View the last deployment log',
    'journal_aide' => 'Reads the log already written. Contacts no server.',
    'journal_ouverture' => 'Reading the log…',
    'journal_vide' => 'The log is empty: no deployment has been started yet.',
    'journal_fin' => '— end of log —',
    'journal_refus' => 'The log was refused by the server (code :statut)',
    'journal_interrompu' => 'The stream ended before the log did: what precedes is incomplete.',

    // ── Deployment refusals ─────────────────────────────────────────────────
    // Each message says what was NOT done: retrying blindly can revoke access.
    'err_aucune_machine' => 'No machine selected.',
    'err_backend_injoignable' => 'The deployment service is unreachable. Nothing was deployed.',
    'err_preflight_refuse' => 'The pre-deployment check was refused. Nothing was deployed.',
    'err_preflight_sans_resultat' => 'The pre-deployment check returned no result. Nothing was deployed.',
    'err_preflight_echoue' => 'Check failed for: :machines. Nothing was deployed: fix those machines or unselect them.',
    'err_aucun_compte_avec_cle' => 'No active account holds an SSH key on this fleet: the deployment would remove every access. Nothing was deployed; add a key to at least one account.',
];
