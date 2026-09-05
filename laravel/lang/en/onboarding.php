<?php

/*
 * The first-run assistant. The key set must stay identical to
 * `lang/fr/onboarding.php`. See fr for why the wording is uniform: the legacy
 * mixes two registers eleven lines apart.
 */
return [
    'titre'      => 'Welcome to RootWarden',
    'sous_titre' => 'A few steps to secure and prepare your platform. Each one is detected automatically: there is nothing to tick.',
    'masquer'    => 'Hide the assistant',
    'avancement' => ':faites of :total',

    'termine_titre' => 'RootWarden is ready',
    'termine_desc'  => 'Every step is done. You can hide this assistant: it will not come back for this account.',
    'termine_cta'   => 'Hide for good',

    'fait'   => 'Step done',
    'a_faire' => 'Step to do',

    'etape_serveurs_titre' => 'Add your first server',
    'etape_serveurs_desc'  => 'Register at least one Linux server to manage. RootWarden never acts locally: everything goes through SSH.',
    'etape_serveurs_cta'   => 'Add a server',

    'etape_comptes_titre' => 'Create at least one dedicated administrator',
    'etape_comptes_desc'  => 'Do not leave the initial superadmin account on its own. Create one account per person who runs the platform — a shared account cannot be revoked.',
    'etape_comptes_cta'   => 'Manage accounts',

    'etape_second_facteur_titre' => 'Enable the second factor on your account',
    'etape_second_facteur_desc'  => 'An administration account without a second factor rests on the strength of its password alone.',
    'etape_second_facteur_cta'   => 'Enable the second factor',

    'etape_cle_ssh_titre' => 'Add your public SSH key',
    'etape_cle_ssh_desc'  => 'Put your public key (ed25519 or RSA) in your profile. It will be deployed on the servers you have access to, and you will sign in to them without a password.',
    'etape_cle_ssh_cta'   => 'Add the key',

    'etape_cle_plateforme_titre' => 'Deploy the platform key',
    'etape_cle_plateforme_desc'  => "An Ed25519 key of RootWarden's own, pushed to your servers. It is what replaces the stored passwords, and it can be replaced in a single move.",
    'etape_cle_plateforme_cta'   => 'Deploy the key',

    'etape_sans_mot_de_passe_titre' => 'Remove the SSH passwords from the database',
    'etape_sans_mot_de_passe_desc'  => 'Once the platform key is in place, erase the stored passwords. What is not stored cannot leak.',
    'etape_sans_mot_de_passe_cta'   => 'Open the platform key page',

    'etape_cle_api_titre' => 'Create a dedicated API key',
    'etape_cle_api_desc'  => 'Replace the automatically generated key with a dedicated one, limited to the routes it needs. A key with no scope opens everything.',
    'etape_cle_api_cta'   => 'Manage API keys',

    'etape_premier_releve_titre' => 'Run a first audit',
    'etape_premier_releve_desc'  => 'SSH audit or vulnerability scan: this is what proves the whole chain works, from SSH through to the display.',
    'etape_premier_releve_cta'   => 'Open the SSH audit',

    /* The warning states the CONSEQUENCE, not the order of moves — see fr. */
    'avert_sans_cle' => 'Not to be done before the platform key is deployed: without it, erasing the passwords removes the last access to the servers concerned.',

    'cle_plateforme_source' => 'Detected from the servers carrying the platform key.',
];
