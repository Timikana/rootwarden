<?php

/**
 * systemd service management — sub-batch S1.
 *
 * NOTE. This module carries E-149: the eight backend routes have neither role
 * nor permission, and `can_manage_services` only protects the screen. The port
 * cannot close that on its own — see `App\Services\ServicesSystemd`.
 *
 * No text on this page should suggest a gesture is checked anywhere other than
 * where it actually is.
 */

return [
    'titre' => 'Service management',
    'intro' => 'Start, stop and monitor the systemd services of your machines. Each gesture applies to one machine at a time, and is confirmed before it is sent.',
    'serveur' => 'Target machine',
    'choisir_serveur' => 'Choose a machine, then load its services.',
    'charger' => 'Load services',
    'sensible' => 'Production',
    'sensible_aide' => 'Stopping a service on this machine interrupts a service in production.',
    'avert_titre' => 'A production machine is in this list',
    'avert_un' => 'One of the :total machines offered is in production or marked critical. It is flagged in the selector.',
    'avert_plusieurs' => ':nb of the :total machines offered are in production or marked critical.',
    'sensible_confirmer' => 'This machine is in production. Loading its services changes nothing — but the gestures that follow do.',
    'filtres' => 'Filter',
    'filtre_etat' => 'State',
    'filtre_categorie' => 'Category',
    'recherche' => 'Search for a service',
    'filtres_inactifs' => 'Filters become active once the services are loaded.',
    'chargement' => 'Reading services on the machine…',
    'echec' => 'The services could not be read. Is the machine reachable?',
    'aucun_service' => 'This machine exposes no readable systemd service.',
    'journaux' => 'Gesture log',
    'journaux_vides' => 'No gesture performed since this page was opened.',
    'vide_titre' => 'No machine in the estate',
    'vide_texte' => 'No active machine is registered. Add one from server administration.',
    'vide_action' => 'Open servers',
    'non_porte_titre' => 'The service gestures are not ported yet',
    'non_porte_texte' => 'Listing, starting, stopping and restarting a service are done from the legacy portal for now. This page carries the inventory and the access guards; the gestures follow.',
    'non_porte_lien' => 'Open service management in the legacy portal',
];
