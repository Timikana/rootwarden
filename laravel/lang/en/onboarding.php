<?php

/*
 * The first-run assistant. The key set must stay identical to
 * `lang/fr/onboarding.php`. See fr for why the wording is uniform: the legacy
 * mixes two registers eleven lines apart.
 */
return [
    'titre'      => 'Welcome to RootWarden',
    'sous_titre' => "Each step is detected automatically.",
    'masquer'    => 'Hide the assistant',
    'avancement' => ':faites of :total',

    'termine_titre' => 'RootWarden is ready',
    'termine_desc'  => "All steps are done. You can hide the assistant.",
    'termine_cta'   => 'Hide for good',

    'fait'   => 'Step done',
    'a_faire' => 'Step to do',

    'etape_serveurs_titre' => 'Add your first server',
    'etape_serveurs_desc'  => "RootWarden acts on your servers over SSH only.",
    'etape_serveurs_cta'   => 'Add a server',

    'etape_comptes_titre' => 'Create at least one dedicated administrator',
    'etape_comptes_desc'  => "One account per person: a shared account cannot be revoked.",
    'etape_comptes_cta'   => 'Manage accounts',

    'etape_second_facteur_titre' => 'Enable the second factor on your account',
    'etape_second_facteur_desc'  => "Without a second factor, the account relies on its password alone.",
    'etape_second_facteur_cta'   => 'Enable the second factor',

    'etape_cle_ssh_titre' => 'Add your public SSH key',
    'etape_cle_ssh_desc'  => "Your public key (ed25519 or RSA) is deployed to the servers you have access to.",
    'etape_cle_ssh_cta'   => 'Add the key',

    'etape_cle_plateforme_titre' => 'Deploy the platform key',
    'etape_cle_plateforme_desc'  => "RootWarden's own key, which replaces stored passwords.",
    'etape_cle_plateforme_cta'   => 'Deploy the key',

    'etape_sans_mot_de_passe_titre' => 'Remove the SSH passwords from the database',
    'etape_sans_mot_de_passe_desc'  => "Once the platform key is in place, erase the stored passwords.",
    'etape_sans_mot_de_passe_cta'   => 'Open the platform key page',

    'etape_cle_api_titre' => 'Create a dedicated API key',
    'etape_cle_api_desc'  => "Replace the auto-generated key with a key limited to the routes it needs.",
    'etape_cle_api_cta'   => 'Manage API keys',

    'etape_premier_releve_titre' => 'Run a first audit',
    'etape_premier_releve_desc'  => "An SSH audit or a vulnerability scan checks the whole chain.",
    'etape_premier_releve_cta'   => 'Open the SSH audit',

    /* The warning states the CONSEQUENCE, not the order of moves — see fr. */
    'avert_sans_cle' => "Not before deploying the platform key: you would lose all access to the affected servers.",

    'cle_plateforme_source' => 'Detected from the servers carrying the platform key.',
];
