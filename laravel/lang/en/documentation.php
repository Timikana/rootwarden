<?php

/*
 * Portal documentation. The 22 `guide.*` keys are the only translated part of
 * the legacy's 1 756 lines; the rest is hand-written French prose and is not
 * ported. Inline `<strong>` markup is stripped, not rendered — see fr.
 */
return [
    'title' => 'Getting Started',
    'intro' => 'Follow these steps to configure RootWarden after installation.',
    'step1_title' => 'Login and secure your account',
    'step1_text' => 'Log in with the credentials generated at first startup (shown in Docker logs). Change your password and configure mandatory 2FA.',
    'step2_title' => 'Add your servers',
    'step2_text' => 'In Admin > Servers, add each Linux server with its IP, SSH port, username and password. Credentials are AES-256 encrypted in the database.',
    'step3_title' => 'Scan remote users',
    'step3_text' => 'In Remote Users, scan each server to discover existing accounts. Classify each account (managed / excluded / unmanaged). This step is mandatory before any deployment.',
    'step4_title' => 'Configure your SSH key',
    'step4_text' => 'In My Profile, paste your SSH public key (ed25519 or RSA). It will be deployed on assigned servers.',
    'step5_title' => 'Assign access',
    'step5_text' => 'In Admin > Access & Permissions, assign servers to each user and configure functional permissions (deployment, updates, iptables, etc.).',
    'step6_title' => 'Deploy SSH keys',
    'step6_text' => 'In SSH Keys, check the servers and click "Deploy". The preflight checks connectivity and shows the account inventory. No account is ever deleted automatically.',
    'step7_title' => 'Configure notifications',
    'step7_text' => 'In Admin > Access & Permissions > Email notifications, configure who receives alerts for each event type (CVE scan, SSH audit, etc.).',
    'security_title' => 'Security principles',
    'sec_1' => 'No password is stored in plain text - AES-256 + libsodium encryption.',
    'sec_2' => 'Deployment never automatically deletes accounts.',
    'sec_3' => 'Every action is logged in the audit trail.',
    'sec_4' => '2FA authentication (TOTP) is mandatory for all accounts.',
    'sec_5' => 'Server accounts must be classified before any deployment.',

    'titre' => 'Documentation',
    'desc'  => 'Getting started with the portal, and where to find the rest.',

    // The guard on this page is a ROLE THRESHOLD, not a permission — see fr.
    'seuil_titre' => 'What your role opens',
    'seuil_role1' => "Your role gives access to the functional documentation. Five sections describing infrastructure and the API surface are reserved for administration — that is a decision, not an oversight.",
    'seuil_admin' => 'Your role gives access to the whole documentation, including the infrastructure and API sections.',

    'reste_titre' => 'The reference documentation',
    'reste_texte' => "The rest of the documentation — architecture, encryption, sessions, procedures — still lives on the old portal and is not copied here.",
    'reste_perime' => "It carries references measured as stale: twelve page paths that no longer answer, and two cited routes that do not exist. Eleven of its sections describe parts already removed from the product.",
    'reste_cache'  => "This page does not copy it: reproducing a text that nothing regenerates would amount to freezing a cache. What can be derived is derived elsewhere, from the source.",
    'reste_ouvrir' => 'Open the reference documentation',

    'derive_titre' => 'Routes and rights, derived',
    'derive_texte' => "The list of reachable routes and the rights they require is not written by hand: it is derived from the gateway's real configuration. That is the only form that cannot go stale in silence.",
    'derive_lien'  => 'View the gateway authorisations',
    'derive_reserve' => 'An authorisation claim cannot be derived from a single layer: the product has three, and they do not always agree.',

    'console_titre' => 'The API console is not carried over',
    'console_texte' => "The old portal offers a free-text field that composes a request to any route in the product. It elevates no privilege — the guards still apply — but it bypasses the interface: no decision panel, no machine named, for actions that carry one on their own pages.",

];
