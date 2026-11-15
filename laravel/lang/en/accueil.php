<?php

/**
 * Portal home — English.
 *
 * Strict parity with lang/fr/accueil.php: same key set, same commit.
 */
return [

    'bienvenue'   => 'Hello :nom',
    'orientation' => "Your modules, the state of your fleet and what needs your attention.",

    // Roles
    'role_lecteur'    => 'Reader',
    'role_admin'      => 'Administrator',
    'role_superadmin' => 'Super administrator',

    // Tiles
    'acces_titre' => 'Modules available',
    'acces_texte' => "{0}No module open to the :role role.|{1}One module open to the :role role.|[2,*]Modules open to the :role role.",


    'securite_titre'  => 'Second factor',
    'securite_valeur' => 'Active',
    'securite_texte'  => "Session opened with a one-time code.",


    // Explicit empty state
    // ── THE TWELVE SHORTCUTS, PORTED FROM `legacy/index.php:363-385` ──────
    // Each tile's LABEL comes from `nav.<key>`: the legacy has two sets saying
    // the same thing, and two sets diverge. Only the DESCRIPTION belongs to the
    // tiles, and it is taken from the legacy.
    'raccourcis_titre' => 'Go straight to',
    'raccourcis_aide' => "Based on your role and permissions.",
    'raccourcis_aucun' => "No module is open to your account. Ask an administrator for the permissions.",

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
    'sequence_titre' => "After adding a server, in this order",
    'sequence_1' => "Deploy the platform key (it also creates the administration account).",
    'sequence_2' => "Survey the remote accounts and classify them.",
    'sequence_3' => "Test key-based login.",
    'sequence_4' => "Only then erase the stored passwords: earlier, you would lose the only fallback if the key does not work.",

    // ── THE FLEET, BOUNDED TO THE ACCOUNT'S SCOPE ────────────────────────
    'parc_compteur_titre' => 'Your machines',
    // E-263: the TITLE too — see fr.
    'parc_compteur_titre_neutre' => 'The fleet',
    'parc_perimetre' => '{0}none of your machines|{1}1 of your machines|[2,*]:count of your machines',
    'parc_total' => '{1}1 in the fleet|[2,*]:count in the fleet',
    // E-263: the NEUTRAL variant. Rendered when the boundary does not BITE.
    // Carries a {0} case that `parc_total` deliberately lacks — see fr.
    'parc_neutre' => '{0}no machine in the fleet|{1}1 machine in the fleet|[2,*]:count machines in the fleet',
    'parc_borne_aide' => "Only your machines are counted; the second number is the fleet size.",
    'parc_illisible' => "The fleet could not be read: no number here is reliable.",
    // ══ THE LEGACY'S NINE INDICATORS, BOUNDED ════════════════════════════
    'ind_parc_titre' => 'Your fleet',
    // E-263, third occurrence of the same possessive — see fr.
    'ind_parc_titre_neutre' => 'Fleet state',
    'ind_machines' => 'machines',
    'ind_en_ligne' => 'online',
    'ind_hors_ligne' => 'offline',
    // THREE STATES, NOT TWO. The legacy counts « != ONLINE » and therefore files
    // machines of UNKNOWN state among the offline ones. Both counters add up to
    // the total, which makes them look consistent — and that is what kept the
    // defect invisible.
    'ind_inconnu' => 'state unknown',
    'ind_inconnu_aide' => "No recent information on these machines.",
    'ind_cle' => 'with the platform key',

    'ind_cve_titre' => 'Known vulnerabilities',
    'ind_cve_date' => 'last scan',
    // E-269: see fr — both come from ONE machine.
    'ind_cve_date_machine' => 'last scan of :machine',
    'ind_cve_nombre' => 'CVE at the last scan',
    'ind_cve_nombre_machine' => 'CVE at the last scan of :machine',
    'ind_cve_critiques' => 'critical, latest scan per machine',
    'ind_cve_aucun_scan' => "No vulnerability scan on your machines (this is not “zero CVEs”).",
    'ind_cve_illisible' => "The scan history could not be read.",

    'ind_comptes_titre' => 'Portal accounts',
    'ind_actifs' => 'active accounts',
    'ind_sans_cle' => 'with no SSH key stored',
    'ind_sans_cle_sature' => "No account has a stored SSH key yet.",
    'ind_sans_2fa' => 'with no second factor',
    'ind_sans_2fa_aide' => "Visible to superadmins only.",
    'ind_comptes_reserve' => "Account counters are not shown for your role.",

    'ind_illisible' => "Unreadable values: the database did not respond.",
    'ind_borne' => "Your machines only.",

    // ══ E-264: THE ALERT REGION ══════════════════════════════════════════
    'alertes_titre' => "What needs your attention",
    // "Nothing" is said ONLY if everything was read — see fr for why.
    'alertes_aucune' => "Nothing needs your attention right now.",
    'alertes_aucune_aide' => "On your machines, within what your role can read.",
    'alertes_illisible' => "Some checks failed: their silence does not mean everything is fine.",
    'alertes_illisible_familles' => "Not read: :familles.",
    'alertes_voir' => "View",

    'alerte_hors_ligne' => '{1}machine offline|[2,*]machines offline',
    'alerte_sans_cle_parc' => '{1}machine without the platform key|[2,*]machines without the platform key',
    'alerte_cve_critiques' => '{1}critical vulnerability reported|[2,*]critical vulnerabilities reported',
    'alerte_sans_2fa' => '{1}active account without a second factor|[2,*]active accounts without a second factor',
    'alerte_sans_cle_compte' => '{1}active account without an SSH key|[2,*]active accounts without an SSH key',
    'alerte_maj_ancienne' => '{1}machine not checked for over 30 days|[2,*]machines not checked for over 30 days',
    'alerte_ssh_faible' => '{1}machine with an SSH score below 50|[2,*]machines with an SSH score below 50',
    'alerte_cles_anciennes' => '{1}account whose SSH key is over 90 days old|[2,*]accounts whose SSH key is over 90 days old',

    'alertes_famille_parc' => "fleet state",
    'alertes_famille_cve' => "vulnerabilities",
    'alertes_famille_comptes' => "accounts",
    'alertes_famille_parc_suivi' => "machine follow-up",
    'alertes_famille_cles_comptes' => "account key age",
];
