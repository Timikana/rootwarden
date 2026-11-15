<?php

/**
 * Fail2ban — sub-batch F1.
 *
 * The legacy header claims "admin (2), superadmin (3)" while its guard admits
 * role 1 (pattern E-36). No text on this page may claim an access stricter than
 * the one actually enforced.
 *
 * And none may suggest that `can_manage_fail2ban` protects the GESTURES: of the
 * 23 routes across both filtering modules, only two check it (E-152). It
 * protects the screen.
 */

return [
    'titre' => 'Fail2ban',
    'intro' => 'Fail2ban bans addresses that fail to authenticate too often.',
    'serveur' => 'Machine',
    'choisir' => 'Choose a machine, then read its state.',
    'relever' => 'Read the state',
    'sensible' => 'Production',
    'sensible_avert' => 'Production machine: disabling Fail2ban or emptying its jails would leave it exposed.',
    'avert_titre' => 'A production machine is in this list',
    'avert_un' => 'One of the :total machines offered is in production or marked critical.',
    'avert_plusieurs' => ':nb of the :total machines offered are in production or marked critical.',
    'chargement' => 'Reading the state on the machine…',
    'echec' => 'The state could not be read. Is the machine reachable?',
    'etat' => 'State',
    'etat_absent' => 'Fail2ban is not installed',
    'etat_absent_aide' => 'Nothing bans failed authentication attempts on this machine.',
    'etat_arrete' => 'Installed, but stopped',
    'etat_arrete_aide' => 'No address is banned while it stays stopped.',
    'etat_actif' => 'Running',
    'jails' => 'Watched jails',
    'jails_aucune' => 'No active jail: Fail2ban watches nothing.',
    // Plurals are composed, not parenthesised: « 1 bannies » reached the
    // screen — visible in a capture, invisible to every assertion.
    // The count is always substituted, even in the singular form: it also
    // serves zero, and a hard-coded "1" showed "1 banned address" for none.
    'jails_une' => ':nb jail',
    'jails_plusieurs' => ':nb jails',
    'adresses_une' => ':nb banned address',
    'adresses_plusieurs' => ':nb banned addresses',
    'bannies' => 'banned',
    'compte_bannies_une' => ':nb banned',
    'compte_bannies_plusieurs' => ':nb banned',
    'cache_maintenant' => 'checked just now',
    'cache_titre' => 'Last known reading',
    'cache_jamais' => 'never read',
    'cache_le' => 'read on :date',
    'cache_aide' => 'State from the last stored reading. Read it again to refresh it.',
    'vide_titre' => 'No machine in the estate',
    'vide_texte' => 'Add a machine from the Servers page.',
    'vide_action' => 'Open servers',
    // The count is REMOVED, not reduced — see fr. The three remaining are
    // appaired one by one against the backend's 19 routes.
    // F8 removes ONE item from the enumeration and only that one — see the
    // note in `lang/fr/fail2ban.php`.

    // F8 — geolocating a banned address. THIS IS AN OUTGOING CALL TO A THIRD
    // PARTY, IN CLEAR. The panel names the third party AND the absence of
    // encryption; it also carries the reassuring fact that private, loopback
    // and reserved addresses never leave. The backend's own reserve is NOT
    // copied: "the IP is already public" measures the sensitivity of the DATA,
    // not that of the RELATION — what is not public is that our infrastructure
    // banned it.
    'geo_bouton'     => 'Geolocate',
    'geo_conf_titre' => 'Query a third party about :ip?',
    'geo_conf_texte' => "The address :ip will be sent in clear text (HTTP) to ip-api.com, a third-party service. Private and reserved addresses are never sent.",
    'geo_en_cours'   => 'Querying…',
    // The in-row result does NOT repeat the address: `go-fail2ban-f4.mjs:566`
    // asserts that a banned address APPEARS in the list, via `includes()` on
    // its innerText. Repeating it here would make that assertion satisfiable
    // by my rendering instead of by the ban — a false green, which never
    // signals itself. The journal carries the address; the row already does.
    'geo_resultat'   => ':pays (:code)',
    'geo_locale'     => 'local address, no request was sent.',
    'geo_inconnu'    => 'the service could not answer.',
    /* See the French catalogue: `OFF` means DISABLED, never `??` (which already
     * means "the service could not answer"). Naming the variable is deliberate. */
    'geo_desactivee' => "geolocation disabled (GEOIP_ENABLED): no request sent.",
    /* Disabled, there is no consent to ask for — there is a state to state.
     * `geo_conf_texte` would otherwise promise a transmission that will not
     * happen, and a warning that cries wolf spends the credibility of every
     * other warning, not just its own. */
    'geo_off_titre' => 'Geolocation disabled',
    'geo_off_texte' => "No address will be sent to ip-api.com. To enable it, set GEOIP_ENABLED=true on the server.",
    'geo_journal'    => ':ip — :detail',
    'geo_echec'      => 'Geolocation failed. :message',

    // ── Sub-lot F2: history and timeline ─────────────────────────────────
    'histo_titre' => 'Ban history',
    'histo_aide' => 'Bans and unbans recorded for this machine, available even if it is unreachable.',
    'histo_choisir' => 'Pick a machine to see its history.',
    'histo_vide_titre' => 'No ban recorded',
    'histo_vide' => 'No ban or unban recorded for this machine.',
    'histo_echec_titre' => 'The history could not be read',
    'histo_echec' => 'Try again; if the error persists, check the portal log.',
    'histo_tout' => ':nb row(s), the full history for this machine',
    'histo_tronque' => 'The :montre most recent of :total.',
    'histo_th_date' => 'Date',
    'histo_th_jail' => 'Jail',
    'histo_th_ip' => 'Address',
    'histo_th_action' => 'Action',
    'histo_th_par' => 'By',
    'action_ban' => 'banned',
    'action_unban' => 'unbanned',
    'par_inconnu' => 'account #:id (deleted?)',
    'par_repli' => 'unattributed',
    'par_repli_aide' => 'Action recorded without an account identifier: "admin" does not necessarily mean the account of that name.',
    'frise_titre' => 'Activity over the last 30 days',
    'frise_aide' => 'One bar per day: its height counts bans and unbans, its colour shows which dominate.',
    'frise_vide_titre' => 'No activity over 30 days',
    'frise_vide' => 'No ban or unban over the last 30 days.',
    'frise_jour' => ':date — :bans banned, :unbans unbanned',
    'frise_legende_ban' => 'bans',
    'frise_legende_unban' => 'unbans',

    // ── Sub-lot F3: configuration, logs, services ────────────────────────
    'voir_config' => 'View jail.local',
    'voir_logs' => 'View logs',
    'config_titre' => 'Configuration — /etc/fail2ban/jail.local',
    'logs_titre' => 'Log — /var/log/fail2ban.log',
    'lu_a_l_instant' => 'Read just now on :machine.',
    'fichier_absent_titre' => 'This file does not exist on the machine',
    'fichier_absent' => 'No configuration file on the machine.',
    'journal_absent_titre' => 'This log does not exist on the machine',
    'journal_absent' => 'Fail2ban has not written anything there yet, or is not running.',
    'lecture_echec_titre' => 'The read failed',
    'lecture_echec' => 'The machine did not respond or refused the read.',
    'services_titre' => 'Detected services and available jails',
    'services_aide' => 'A service that is not installed cannot be watched.',
    'services_installe' => 'Installed',
    'services_absent' => 'Not installed',
    'services_jails' => 'Jails:',
    'services_jail_active' => 'active',
    'services_vide_titre' => 'No service detected',
    'services_vide' => 'Fail2ban has nothing to watch on this machine.',

    // ── Sub-lot F4: ban and unban ────────────────────────────────────────
    'jail_detail_titre' => 'Jail :jail',
    'jail_fermer' => 'Close',
    'jail_maxretry' => 'Attempts before ban',
    'jail_bantime' => 'Ban duration',
    'jail_findtime' => 'Observation window',
    'jail_secondes' => ':nb s',
    'jail_inconnu' => 'not read',
    'bannies_titre' => 'Currently banned addresses',
    'bannies_vide_titre' => 'No banned address',
    'bannies_vide' => 'This jail bans nobody right now.',
    'bannies_th_ip' => 'Address',
    'bannies_th_action' => 'Action',
    'ban_etiquette' => 'Address to ban',
    'ban_placeholder' => '198.51.100.42',
    'ban_aide' => 'IPv4 or IPv6. The ban applies to this machine only.',
    'bannir' => 'Ban',
    'debannir' => 'Unban',
    'tout_debannir' => 'Unban all',
    'conf_titre_ban' => 'Ban :ip on :machine?',
    'conf_texte_ban' => 'The address :ip will be banned in the :jail jail, on :machine only, until the ban expires.',
    'conf_titre_debannir' => 'Unban :ip on :machine?',
    'conf_texte_debannir' => 'The address :ip will be able to connect to :machine again. Other machines are not affected.',
    'conf_titre_tout' => 'Unban ALL addresses from :jail on :machine?',
    'conf_texte_tout' => 'The :nb address(es) banned in this jail will be able to connect to :machine again. Irreversible: the ban list will be lost.',
    'conf_confirmer' => 'Confirm',
    'conf_annuler' => 'Cancel',
    'geste_journal' => 'Action log',
    'geste_vide' => 'No action performed.',
    'geste_reussi' => ':message',
    'geste_echoue' => 'Failed — :message',
    'ban_invalide' => 'Invalid IP address: nothing was sent.',

    // ── Sub-lot F5: jails and whitelist ──────────────────────────────────
    'blanche_titre' => 'Never-banned addresses (whitelist)',
    'blanche_aide' => 'Fail2ban will never ban these addresses, whatever the jail.',
    'blanche_lue' => 'Read from /etc/fail2ban/jail.local on :machine.',
    'blanche_supposee_titre' => 'Default values, absent from the configuration',
    'blanche_supposee' => 'jail.local has no ignoreip line on :machine: these entries are Fail2ban default values, nothing to remove.',
    'blanche_vide_titre' => 'No exempt address',
    'blanche_vide' => 'No address is exempt on this machine.',
    'blanche_etiquette' => 'Address to exempt',
    'blanche_ajouter' => 'Exempt this address',
    'blanche_retirer' => 'Remove',
    'blanche_non_retirable' => 'Cannot be removed',
    'blanche_non_retirable_aide' => ':ip is a network: only addresses can be removed.',
    'conf_titre_blanche_ajout' => 'Exempt :ip on :machine?',
    'conf_texte_blanche_ajout' => ':ip will never be banned on :machine again. ⚠ Fail2ban restarts: current bans on this machine will be lost.',
    'conf_titre_blanche_retrait' => 'Remove the exemption for :ip on :machine?',
    'conf_texte_blanche_retrait' => ':ip can be banned on :machine again. ⚠ Fail2ban restarts: current bans on this machine will be lost.',
    'jail_reglages_titre' => 'Enable jail :jail on :machine',
    'jail_reglages_avert' => '⚠ Enabling a jail rewrites /etc/fail2ban/jail.local and restarts the service: current bans on this machine will be lost.',
    'jail_activer' => 'Enable jail',
    'jail_desactiver' => 'Disable',
    'jail_maxretry_aide' => 'Number of failures before banning.',
    'jail_bantime_aide' => 'In seconds, at least 60.',
    'jail_findtime_aide' => 'Period over which failures are counted, in seconds, at least 60.',
    'conf_titre_jail' => 'Enable :jail on :machine?',
    'conf_texte_jail' => 'The :jail jail will be written to /etc/fail2ban/jail.local on :machine: :maxretry attempt(s), :bantime s ban, :findtime s window. ⚠ The service restarts: current bans on this machine will be lost.',

    // ── Sub-lot F6: the two whole-fleet actions ──────────────────────────
    //
    // Neither action takes ANY machine parameter: the backend picks its
    // targets in the database. No text here may suggest the operator chooses
    // the scope — they can only READ it. And none says « all servers »
    // without giving the number: the legacy did, and that is E-173.
    'parc_titre' => "Fleet-wide actions",
    'parc_aide' => "They do not target the chosen machine: their targets come from the last stored reading.",
    'parc_installer' => "Install Fail2ban across the fleet",
    'parc_bannir' => "Ban across the fleet",
    'parc_ban_titre' => "Ban across the fleet",
    'parc_ban_aide' => "The address entered above would be banned on the :nb machine(s) the last reading reports as active: :machines.",
    'parc_ban_aide_aucune' => "The last reading reports no active machine: this ban would reach nothing. Read the machines' state.",
    'parc_role_titre' => "These two actions require the Administrator role",
    'parc_role' => "With your role, they would be refused. Per-machine actions remain available.",
    'portee_titre' => "What these actions would touch today",
    'portee_cache' => "Scope derived from each machine's last reading, not from its current state.",
    'portee_installer' => "Installing Fail2ban across the fleet would touch :nb machine(s), out of a fleet of :parc:",
    'portee_installer_aucune' => "Installing Fail2ban across the fleet would touch no machine: the recorded reading says the whole fleet (:parc) already has it.",
    'portee_bannir' => "Banning an address across the fleet would touch :nb machine(s), out of a fleet of :parc:",
    'portee_bannir_aucune' => "Banning an address across the fleet would touch NO machine: the recorded reading calls none of the fleet's machines (:parc) active.",
    'portee_jamais' => "never read",
    'portee_jamais_aide' => "A machine never read is included in the installations.",
    'portee_archivee' => "retired from the fleet",
    'portee_archivee_aide' => "Archived machine: missing from the selector, but still targeted by fleet actions.",
    'portee_releve_le' => "read on :date",
    'portee_inconnue_titre' => "The scope could not be read",
    'portee_inconnue' => "The machines that would be affected are unknown: both actions are refused. Reload the page.",
    'parc_ban_inconnue' => "Unreadable scope: this ban is refused.",
    'conf_titre_parc_inconnue' => "Scope unknown — nothing will be sent",
    'conf_texte_parc_inconnue' => "The scope could not be read: nothing will be sent.",
    'portee_relire' => "Re-read the scope",
    'portee_relue' => "Scope re-read just now.",
    'portee_echec' => "Could not read again: the lists shown date from page load.",
    'conf_titre_parc_ban' => "Ban :ip on :nb fleet machine(s)?",
    'conf_texte_parc_ban' => ":ip will be banned in the :jail jail on the :nb machine(s) the last reading reports as active: :machines. Machines where Fail2ban is missing or stopped are not affected.",
    'conf_titre_parc_ban_vide' => "No machine would be banned",
    'conf_texte_parc_ban_vide' => "The last reading reports no active machine: :ip would be banned nowhere. Nothing will be sent.",
    'conf_titre_parc_install' => "Install Fail2ban on :nb fleet machine(s)?",
    'conf_texte_parc_install' => "Fail2ban will be installed by apt-get on :nb machine(s): :machines. Production or critical: :prod. Never read: :jamais. Cannot be undone from this page.",
    'conf_titre_parc_install_vide' => "No machine to install",
    'conf_texte_parc_install_vide' => "The reading says the whole fleet (:parc) already has Fail2ban. Nothing will be sent.",
    'recopie_etiquette' => "To confirm, retype the number of machines affected",
    'recopie_aide' => "This action affects several machines at once.",
    'recopie_faux' => "The number retyped does not match.",
    'parc_envoi' => "Fleet action sent to :nb machine(s)…",
    'parc_resultat_machine' => ":machine: :etat",
    'parc_ok' => "succeeded",
    'parc_echec' => "failed — :message",
    'parc_echec_muet' => "failed, no reason reported",
    'parc_apres_install' => "This action does not update the reading: read each machine to refresh the scope.",
    'parc_rien' => "No machine in the response.",

    // TWO KEYS WITH NO READER TODAY, SAID RATHER THAN FIXED.
    // `histo_choisir` and `jail_desactiver` are read neither by the view nor by
    // the script (measured 2026-08-27: zero occurrences outside these
    // catalogues). `jail_desactiver` will be read by F7 —
    // `/fail2ban/disable_jail` is one of its four capabilities. Removing them
    // to put them back two sub-lots later costs an FR/EN divergence for
    // nothing: decided 2026-08-27.

    // F7 — disabling a jail. It LOWERS a guard: nothing is deleted and
    // « Activer » restores it, but the machine stops being protected against
    // brute force, and an SSH session is opened to do it. The panel names the
    // consequence, not the mechanism. See fr.
    'conf_titre_desact' => "Disable :jail on :machine?",
    'conf_texte_desact' => "The :jail jail will stop watching :machine. ⚠ The service restarts: current bans on this machine will be lost. \"Enable\" restores the jail.",

    /*
     * ══ LES DEUX GESTES PAR MACHINE — ISO-PERIMETRE ══════════════════
     *
     * Le legacy les offrait ; ils avaient ete perdus par un arbitrage que
     * l'exploitant a annule (« portage a iso-perimetre »). `install_all`
     * etait deja porte : le geste le plus LARGE existait, le plus ETROIT
     * manquait — l'inverse de l'ordre de risque.
     */
    'installer' => "Install Fail2ban",
    'redemarrer' => "Restart the service",
    'conf_titre_install' => "Install Fail2ban on :machine?",
    'conf_texte_install' => "The package will be installed on :machine only, by its package manager. It may take a minute and cannot be undone from this page.",
    'conf_titre_restart' => "Restart Fail2ban on :machine?",
    'conf_texte_restart' => "The service will be restarted on :machine only and will reload its configuration. ⚠ Current bans on this machine will be lost.",

];
