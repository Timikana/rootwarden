<?php

/**
 * Portal home — English.
 *
 * Strict parity with lang/fr/accueil.php: same key set, same commit.
 */
return [

    'bienvenue'   => 'Hello :nom',
    'orientation' => "You are on the new interface. The shortcuts below lead to the modules your rights open for you; those not yet ported open the legacy portal in a new tab.",

    // Roles
    'role_lecteur'    => 'Reader',
    'role_admin'      => 'Administrator',
    'role_superadmin' => 'Super administrator',

    // Tiles
    'acces_titre' => 'Modules available',
    'acces_texte' => '{0}No module is open to you with the :role role.|{1}A single module is open to you with the :role role.|[2,*]Modules opened by your rights, :role role.',

    'portes_titre' => 'Already ported',
    'portes_texte' => 'How many of your modules the new interface serves. The others open the previous portal in a new tab.',

    'securite_titre'  => 'Second factor',
    'securite_valeur' => 'Active',
    'securite_texte'  => 'Your session was opened with a single-use code. A code already used is refused, even from another browser.',

    'ancien_titre' => 'Previous portal',
    'ancien_texte' => 'Still running, with the same credentials. Menu entries marked with an arrow link straight to it.',

    // Explicit empty state
    // ── THE TWELVE SHORTCUTS, PORTED FROM `legacy/index.php:363-385` ──────
    // Each tile's LABEL comes from `nav.<key>`: the legacy has two sets saying
    // the same thing, and two sets diverge. Only the DESCRIPTION belongs to the
    // tiles, and it is taken from the legacy.
    'raccourcis_titre' => 'Go straight to',
    'raccourcis_aide' => "These shortcuts follow your rights: you only see what your role and permissions open for you. An arrow marks a page still served by the legacy portal.",
    'raccourcis_aucun' => "No module is open to your account at the moment. This is not a display error: ask an administrator for the matching permissions.",

    'desc_ssh_keys' => 'Deploy the public keys',
    'desc_updates' => 'APT updates and reboots',
    'desc_iptables' => 'Firewall rules',
    'desc_cve_scan' => 'Known vulnerabilities in the fleet',
    'desc_admin' => 'Accounts, servers, rights',
    'desc_supervision' => 'Deploy and manage the monitoring agents',
    'desc_bashrc' => 'Deploy a standardised .bashrc',
    'desc_graylog' => 'Sidecar, centralisation and collectors',
    'desc_wazuh' => 'SIEM agent and editable rules',
    'desc_ssh_audit' => 'Scan the SSH configuration',
    'desc_compliance' => 'Compliance report',
    'desc_documentation' => 'Technical guide',

    // ── THE SEQUENCE, STATED WHERE PEOPLE ARRIVE ─────────────────────────
    // Operator request: « when you add a server, which menus to go to next is
    // not obvious, and a new user does not know ». A NUMBERED list: the order
    // is the substance, not the presentation.
    'sequence_titre' => 'Just added a server? The order matters',
    'sequence_1' => "Deploy the platform key on the server. The same action also creates the administration account with passwordless root rights.",
    'sequence_2' => "Survey the server's remote accounts, and classify those RootWarden should manage or ignore.",
    'sequence_3' => "Check that key-based login works before removing anything — the « Test » button does that without writing.",
    'sequence_4' => "Only then does erasing the password from the database make sense. Done earlier, it deprives you of the only fallback if the key does not work.",
    'sequence_aide' => "This order is not a preference: erasing the password before checking the key removes RootWarden's only way back onto the server.",

    // ── THE FLEET, BOUNDED TO THE ACCOUNT'S SCOPE ────────────────────────
    'parc_compteur_titre' => 'Your machines',
    'parc_perimetre' => '{0}none of your machines|{1}1 of your machines|[2,*]:count of your machines',
    'parc_total' => '{1}1 in the fleet|[2,*]:count in the fleet',
    'parc_borne_aide' => "You only see the machines assigned to you here. The second number is the real size of the fleet: it is shown so the boundary is visible rather than guessed.",
    'parc_illisible' => "The fleet could not be read. This is not « no machines »: the database did not answer, and no number shown here would be reliable.",
    // ══ THE LEGACY'S NINE INDICATORS, BOUNDED ════════════════════════════
    'ind_parc_titre' => 'Your fleet',
    'ind_machines' => 'machines',
    'ind_en_ligne' => 'online',
    'ind_hors_ligne' => 'offline',
    // THREE STATES, NOT TWO. The legacy counts « != ONLINE » and therefore files
    // machines of UNKNOWN state among the offline ones. Both counters add up to
    // the total, which makes them look consistent — and that is what kept the
    // defect invisible.
    'ind_inconnu' => 'state unknown',
    'ind_inconnu_aide' => "These machines are neither online nor offline: the product has no up-to-date information about them. The legacy portal counted them as offline, which asserted a state the data does not carry.",
    'ind_cle' => 'with the platform key',

    'ind_cve_titre' => 'Known vulnerabilities',
    'ind_cve_date' => 'last scan',
    'ind_cve_nombre' => 'CVE at the last scan',
    'ind_cve_critiques' => 'critical, all scans',
    'ind_cve_aucun_scan' => "No vulnerability scan has been run on the machines in your scope. This is not « zero CVE »: it is the absence of measurement.",
    'ind_cve_illisible' => "The scan history could not be read. This is not « no CVE » — no number shown here would be reliable.",

    'ind_comptes_titre' => 'Portal accounts',
    'ind_actifs' => 'active accounts',
    'ind_sans_cle' => 'with no SSH key stored',
    'ind_sans_cle_sature' => "This indicator is at 100% today: no account has an SSH key stored. It is ported anyway — a saturated indicator is the only way to see it stop being saturated.",
    'ind_sans_2fa' => 'with no second factor',
    'ind_sans_2fa_aide' => "This number is restricted to role 3. It says what share of the portal's accounts opens with a password alone — useful information for acting on it, and a map of targets for anyone who has no acting to do. Your own second-factor state is shown above.",
    'ind_comptes_reserve' => "Account counters are not shown to your role. They do not concern your machines: a scope of machines does not bound a population of users, so they are bounded by role instead.",

    'ind_illisible' => "These values could not be read. This is not « zero »: the database did not answer.",
    'ind_borne' => "These numbers only cover the machines assigned to you.",
];
