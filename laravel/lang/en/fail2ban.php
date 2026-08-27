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
    'jails_une' => '1 jail',
    'jails_plusieurs' => ':nb jails',
    'adresses_une' => '1 banned address',
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
    'non_porte_titre' => 'The Fail2ban gestures are not ported yet',
    'non_porte_texte' => 'Banning, unbanning, editing a jail or the allowlist are done from the legacy portal for now. This page carries the state and the access guards; the gestures follow.',
    'non_porte_lien' => 'Open Fail2ban in the legacy portal',
];
