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
    'col_service' => 'Service',
    'col_etat' => 'State',
    'col_active' => 'Enabled at boot',
    'col_categorie' => 'Category',
    'col_description' => 'Description',
    'etat_actif' => 'running',
    'etat_arrete' => 'stopped',
    'etat_echoue' => 'failed',
    'active_oui' => 'yes',
    'active_non' => 'no',
    'protege' => 'protected',
    'protege_aide' => 'This service can be neither stopped nor restarted from this page: the backend refuses the gesture, it is not merely hidden here.',
    'charges' => ':nb services read on :machine.',
    'aucun_systemd' => 'This machine returned no service. It may not expose systemd — which is not the same as a failed enumeration, which would have said so.',
    'filtres_actifs' => 'Filter the list below.',
    'filtre_tous' => 'All',
    'aucun_resultat' => 'No service matches this filter.',
    'resultat_compte' => ':visibles services shown out of :total.',

    'journal_lu' => 'Read of :machine: :nb service(s).',

    'boot_enabled' => 'enabled',
    'boot_disabled' => 'disabled',
    'boot_static' => 'static',
    'boot_masked' => 'masked',
    'boot_unknown' => 'unknown',
    'boot_static_aide' => 'This service has no boot switch: systemd starts it when another unit needs it.',
    'boot_masked_aide' => 'This service is masked: systemd will refuse to start it while it is.',
    'act_demarrer' => 'Start',
    'act_arreter' => 'Stop',
    'act_redemarrer' => 'Restart',
    'act_activer' => 'Enable at boot',
    'act_desactiver' => 'Disable at boot',
    'col_actions' => 'Actions',
    'confirmer_arreter' => 'Stop :service on :machine? The service will stop responding immediately.',
    'confirmer_redemarrer' => 'Restart :service on :machine? The service will be briefly unavailable.',
    'confirmer_demarrer' => 'Start :service on :machine?',
    'confirmer_activer' => 'Enable :service at boot on :machine?',
    'confirmer_desactiver' => 'Disable :service at boot on :machine? It will no longer come back after a reboot.',
    'geste_fait' => ':service: :message',
    'geste_echec' => 'The gesture on :service failed: :message',

    'non_porte_titre' => 'The service gestures are not ported yet',
    'non_porte_texte' => 'Listing, starting, stopping and restarting a service are done from the legacy portal for now. This page carries the inventory and the access guards; the gestures follow.',
    'non_porte_lien' => 'Open service management in the legacy portal',
];
