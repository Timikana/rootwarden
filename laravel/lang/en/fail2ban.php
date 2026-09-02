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
    'intro' => 'Fail2ban bans addresses that fail authentication too often. This page shows its state on your machines, and the jails it watches.',
    'serveur' => 'Machine',
    'choisir' => 'Choose a machine, then read its state.',
    'relever' => 'Read the state',
    'sensible' => 'Production',
    'sensible_avert' => 'Fail2ban PROTECTS this production machine. Disabling it or emptying its jails would leave it exposed.',
    'avert_titre' => 'A production machine is in this list',
    'avert_un' => 'One of the :total machines offered is in production or marked critical.',
    'avert_plusieurs' => ':nb of the :total machines offered are in production or marked critical.',
    'chargement' => 'Reading the state on the machine…',
    'echec' => 'The state could not be read. Is the machine reachable?',
    'etat' => 'State',
    'etat_absent' => 'Fail2ban is not installed',
    'etat_absent_aide' => 'Nothing bans authentication attempts on this machine. Installation is done from the legacy portal.',
    'etat_arrete' => 'Installed, but stopped',
    'etat_arrete_aide' => 'Fail2ban is present and not running: no address is banned while it stays stopped.',
    'etat_actif' => 'Running',
    'jails' => 'Watched jails',
    'jails_aucune' => 'No active jail. Fail2ban is running, but watching nothing.',
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
    'cache_aide' => 'This state comes from the last recorded reading, not from the machine right now. Read it again to refresh.',
    'vide_titre' => 'No machine in the estate',
    'vide_texte' => 'No active machine is registered. Add one from server administration.',
    'vide_action' => 'Open servers',
    // The count is REMOVED, not reduced — see fr. The three remaining are
    // appaired one by one against the backend's 19 routes.
    'non_porte_titre' => "What this tab cannot do yet",
    'non_porte_texte' => "Installing Fail2ban on ONE machine, restarting the service and looking up an address's geolocation are still done from the legacy portal. Everything else is here: state, jails and disabling them, history, configuration, logs, bans, the allowlist and the two fleet actions.",
    'non_porte_lien' => 'Open Fail2ban in the legacy portal',

    // ── Sub-lot F2: history and timeline ─────────────────────────────────
    'histo_titre' => 'Ban history',
    'histo_aide' => 'Bans and unbans recorded for this machine. This list is read from the database: it stays available even when the machine is unreachable.',
    'histo_choisir' => 'Pick a machine to see its history.',
    'histo_vide_titre' => 'No ban recorded',
    'histo_vide' => 'No ban or unban has ever been recorded for this machine. This is not a read error: the list is empty.',
    'histo_echec_titre' => 'The history could not be read',
    'histo_echec' => 'The database read failed. That is not the same as an empty history — try again, then check the portal log.',
    'histo_tout' => ':nb row(s), the full history for this machine',
    'histo_tronque' => 'The :montre most recent out of :total. Older ones are not shown.',
    'histo_th_date' => 'Date',
    'histo_th_jail' => 'Jail',
    'histo_th_ip' => 'Address',
    'histo_th_action' => 'Action',
    'histo_th_par' => 'By',
    'action_ban' => 'banned',
    'action_unban' => 'unbanned',
    'par_inconnu' => 'account #:id (deleted?)',
    'par_repli' => 'unattributed',
    'par_repli_aide' => 'The backend writes "admin" when it receives no user id: this is not necessarily the account named "admin".',
    'frise_titre' => 'Activity over the last 30 days',
    'frise_aide' => 'One bar per day. Its height counts ALL events for that day — bans and unbans — and its colour says which dominate.',
    'frise_vide_titre' => 'No activity over 30 days',
    'frise_vide' => 'No ban or unban has been recorded for this machine over the last 30 days.',
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
    'fichier_absent' => 'The machine replied that no configuration file is present. This is not an empty configuration: there is none.',
    'journal_absent_titre' => 'This log does not exist on the machine',
    'journal_absent' => 'The machine replied that no log file is present. Fail2ban has therefore written nothing there yet — or is not running.',
    'lecture_echec_titre' => 'The read failed',
    'lecture_echec' => 'The machine did not answer, or refused the read. That is not the same as a missing file.',
    'services_titre' => 'Detected services and available jails',
    'services_aide' => 'What the machine replied to the detection. A service that is not installed cannot be watched: its jail would have nothing to read.',
    'services_installe' => 'Installed',
    'services_absent' => 'Not installed',
    'services_jails' => 'Jails:',
    'services_jail_active' => 'active',
    'services_vide_titre' => 'No service detected',
    'services_vide' => 'The detection reported no service. Fail2ban therefore has nothing to watch on this machine.',

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
    'bannies_vide' => 'This jail is banning nobody right now. This is not a read error: the list is empty.',
    'bannies_th_ip' => 'Address',
    'bannies_th_action' => 'Action',
    'ban_etiquette' => 'Address to ban',
    'ban_placeholder' => '198.51.100.42',
    'ban_aide' => 'An IPv4 or IPv6 address. The ban applies only to the machine shown above.',
    'bannir' => 'Ban',
    'debannir' => 'Unban',
    'tout_debannir' => 'Unban all',
    'conf_titre_ban' => 'Ban :ip on :machine?',
    'conf_texte_ban' => 'Address :ip will be banned in jail :jail, on :machine and on it alone. Any connection from that address will be refused until the ban expires.',
    'conf_titre_debannir' => 'Unban :ip on :machine?',
    'conf_texte_debannir' => 'Address :ip will be able to connect to :machine again. If it is banned on other machines, those are not affected.',
    'conf_titre_tout' => 'Unban ALL addresses from :jail on :machine?',
    'conf_texte_tout' => 'The :nb address(es) currently banned in this jail will be able to connect to :machine again. This cannot be undone: the list of banned addresses will be lost.',
    'conf_confirmer' => 'Confirm',
    'conf_annuler' => 'Cancel',
    'geste_journal' => 'Action log',
    'geste_vide' => 'No action has been performed on this page yet.',
    'geste_reussi' => ':message',
    'geste_echoue' => 'Failed — :message',
    'ban_invalide' => 'This is not a valid IP address. Nothing was sent.',

    // ── Sub-lot F5: jails and whitelist ──────────────────────────────────
    'blanche_titre' => 'Never-banned addresses (whitelist)',
    'blanche_aide' => 'These addresses are exempt: fail2ban will never ban them, in any jail.',
    'blanche_lue' => 'Read from /etc/fail2ban/jail.local on :machine.',
    'blanche_supposee_titre' => 'This list is ASSUMED, not read',
    'blanche_supposee' => 'The /etc/fail2ban/jail.local file on :machine has no ignoreip line. The entries below are the ones fail2ban applies by default — they appear nowhere in this machine\'s configuration, so there is nothing to remove.',
    'blanche_vide_titre' => 'No exempt address',
    'blanche_vide' => 'No address is exempt on this machine.',
    'blanche_etiquette' => 'Address to exempt',
    'blanche_ajouter' => 'Exempt this address',
    'blanche_retirer' => 'Remove',
    'blanche_non_retirable' => 'Cannot be removed',
    'blanche_non_retirable_aide' => ':ip is a network, not an address, and the backend only accepts addresses. A removal would always fail.',
    'conf_titre_blanche_ajout' => 'Exempt :ip on :machine?',
    'conf_texte_blanche_ajout' => ':ip will never be banned on :machine again, in any jail. ⚠ This RESTARTS fail2ban: every ban currently in force on this machine will be lost.',
    'conf_titre_blanche_retrait' => 'Remove the exemption for :ip on :machine?',
    'conf_texte_blanche_retrait' => ':ip will be bannable again on :machine. ⚠ This RESTARTS fail2ban: every ban currently in force on this machine will be lost.',
    'jail_reglages_titre' => 'Enable jail :jail on :machine',
    'jail_reglages_avert' => '⚠ Enabling a jail REWRITES /etc/fail2ban/jail.local and RESTARTS the service: every ban currently in force on this machine will be lost.',
    'jail_activer' => 'Enable jail',
    'jail_desactiver' => 'Disable',
    'jail_maxretry_aide' => 'Number of failures before banning.',
    'jail_bantime_aide' => 'Ban duration, in seconds. Minimum 60.',
    'jail_findtime_aide' => 'Window over which failures are counted, in seconds. Minimum 60.',
    'conf_titre_jail' => 'Enable :jail on :machine?',
    'conf_texte_jail' => 'Jail :jail will be written to /etc/fail2ban/jail.local on :machine, with :maxretry attempt(s), a :bantime s ban and a :findtime s window. ⚠ The service RESTARTS: every ban currently in force on this machine will be lost.',

    // ── Sub-lot F6: the two whole-fleet actions ──────────────────────────
    //
    // Neither action takes ANY machine parameter: the backend picks its
    // targets in the database. No text here may suggest the operator chooses
    // the scope — they can only READ it. And none says « all servers »
    // without giving the number: the legacy did, and that is E-173.
    'parc_titre' => "Whole-fleet actions",
    'parc_aide' => "These two actions do not target the machine selected above: they take none. The backend picks its own targets, in the database, from the last recorded reading. What this section announces is the result of ITS queries, read from the same database.",
    'parc_installer' => "Install Fail2ban across the fleet",
    'parc_bannir' => "Ban across the fleet",
    'parc_ban_titre' => "Ban across the fleet",
    'parc_ban_aide' => "The address entered above would be banned on the machines the last reading calls active, and on those alone — :nb in total: :machines.",
    'parc_ban_aide_aucune' => "The last reading calls NO machine active: this action would touch nothing. Read the machines' state so the scope becomes known.",
    'parc_role_titre' => "These two actions require the administrator role",
    'parc_role' => "The backend's two fleet routes require role 2 — the only ones in this module. With your role they would refuse. The machine-by-machine actions remain available.",
    'portee_titre' => "What these actions would touch today",
    'portee_cache' => "This scope is decided by the last recorded reading, machine by machine — not by the machines' state right now. A machine whose Fail2ban has died since its reading is absent from the installations even though it no longer protects anything; a machine installed since is still listed.",
    'portee_installer' => "Installing Fail2ban across the fleet would touch :nb machine(s), out of a fleet of :parc:",
    'portee_installer_aucune' => "Installing Fail2ban across the fleet would touch no machine: the recorded reading says the whole fleet (:parc) already has it.",
    'portee_bannir' => "Banning an address across the fleet would touch :nb machine(s), out of a fleet of :parc:",
    'portee_bannir_aucune' => "Banning an address across the fleet would touch NO machine: the recorded reading calls none of the fleet's machines (:parc) active.",
    'portee_jamais' => "never read",
    'portee_jamais_aide' => "A machine marked « never read » has no reading row at all. The installation query keeps the machines whose reading does not say « installed » — and a machine with no reading is one of them: never having looked at it is enough to have it installed.",
    'portee_archivee' => "retired from the fleet",
    'portee_archivee_aide' => "This machine is archived: it is absent from the selector above. The two fleet queries, however, do not filter on lifecycle — so it remains a target.",
    'portee_releve_le' => "read on :date",
    'portee_inconnue_titre' => "The scope could not be read",
    'portee_inconnue' => "Neither the page load nor the re-read returned the scope of these two actions. This is NOT « no machine »: we do not know which ones would be touched, so both actions are refused here. Reload the page.",
    'parc_ban_inconnue' => "The scope could not be read: this action is refused as long as we do not know which machines it would touch.",
    'conf_titre_parc_inconnue' => "Scope unknown — nothing will be sent",
    'conf_texte_parc_inconnue' => "The scope of this action could not be read. A fleet action is not sent without knowing how many machines it covers: nothing will be sent.",
    'portee_relire' => "Re-read the scope",
    'portee_relue' => "Scope re-read just now.",
    'portee_echec' => "The scope could not be re-read. The lists shown are those from page load.",
    'conf_titre_parc_ban' => "Ban :ip on :nb fleet machine(s)?",
    'conf_texte_parc_ban' => ":ip will be banned in jail :jail on the machines the last reading calls active — :nb in total: :machines. Machines whose Fail2ban is absent or stopped are not touched, exposed as they may be. This action goes out to several machines at once.",
    'conf_titre_parc_ban_vide' => "No machine would be banned",
    'conf_texte_parc_ban_vide' => "The last reading calls no machine active: the scope of this action is 0 machines, and :ip would be banned nowhere. Nothing will be sent.",
    'conf_titre_parc_install' => "Install Fail2ban on :nb fleet machine(s)?",
    'conf_texte_parc_install' => "Fail2ban will be installed with apt-get on the machines whose reading does not say they have it — :nb in total: :machines. Machines in production or marked critical within this scope: :prod. Machines never read: :jamais — never having looked at one is enough to have it installed. This action installs a package on several machines at once, and it cannot be undone from this page.",
    'conf_titre_parc_install_vide' => "No machine to install",
    'conf_texte_parc_install_vide' => "The recorded reading says the whole fleet (:parc) already has Fail2ban: the scope of this action is 0 machines. Nothing will be sent.",
    'recopie_etiquette' => "To confirm, retype the number of machines affected",
    'recopie_aide' => "This action covers several machines at once. Confirming it means retyping their number: two « yes » in a row are a reflex, not two decisions.",
    'recopie_faux' => "The number retyped does not match.",
    'parc_envoi' => "Fleet action sent to :nb machine(s)…",
    'parc_resultat_machine' => ":machine: :etat",
    'parc_ok' => "succeeded",
    'parc_echec' => "failed — :message",
    'parc_echec_muet' => "failed — the backend does not say why",
    'parc_apres_install' => "This action does not update the reading: the scope above will stay the same until each machine is read.",
    'parc_rien' => "The backend reported no machine.",

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
    'conf_texte_desact' => "The :jail jail will stop watching :machine: failed authentication attempts will no longer be banned. The action opens an SSH session on the machine. It is restored by « Activer », and no already-banned address is released.",
    'desact_jamais_exercee' => "This action has never yet been performed from this interface.",
];
