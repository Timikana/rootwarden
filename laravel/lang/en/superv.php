<?php

/*
 * Module `supervision/` — sub-lot V1: the page and its four tabs.
 *
 * EVERYTHING THE SCRIPT DISPLAYS LIVES HERE, in the same file as what the page
 * displays. That is the answer to the legacy debt: over there the JS reads its
 * labels from a second catalogue (`js.php`) where eleven of the module's keys are
 * missing, and `head.php` then renders the KEY itself on screen —
 * `editor_select_server`. Since a key is a non-empty string, `__('x') || 'default'`
 * never falls back: the failure is silent. One catalogue, and it cannot come back.
 */

return [
    'titre' => 'Monitoring',
    'sous_titre' => 'Monitoring agent deployment and configuration',
    'description' => 'This page gathers the agent configuration, the profile catalogue, deployment across the fleet and editing of the remote configuration file.',

    'plateforme' => 'Platform',

    'onglet_config' => 'Global configuration',
    'onglet_profiles' => 'Profiles',
    'onglet_deploy' => 'Agent deployment',
    'onglet_editor' => 'Config editor',

    'config_titre' => 'Agent template configuration',
    'config_description' => 'These settings act as a template for every deployment. Each server may carry its own values.',

    'profils_titre' => 'Monitoring profiles',
    'profils_description' => 'Reusable presets (host metadata, server, proxy). The catalogue is written once, then each server is attached to a profile.',

    'deploiement_titre' => 'Agent deployment',
    'deploiement_description' => 'Install, reconfigure and uninstall the agent on the fleet servers.',

    'editeur_titre' => 'Remote configuration editor',
    'editeur_description' => 'Read, edit and save the agent configuration file on a server.',
    'editeur_serveur' => 'Server',
    'editeur_choisir_serveur' => 'Select a server',
    'editeur_lire' => 'Read configuration',
    // THE GUARD V1 CLOSES. On the legacy portal this message is the key
    // `editor_select_server`, rendered verbatim, in a native dialog.
    'editeur_sans_serveur' => 'Select a server first: with no server there is no configuration to read.',

    'aucune_machine' => 'No server in the fleet',
    'aucune_machine_aide' => 'Every machine is archived, or the fleet is empty.',

    // What V1 does not port yet SAYS SO, rather than leaving a bare panel.
    // The empty state's heading does NOT repeat the panel's own: seen in the
    // capture, the same wording twice in a row reads as a rendering defect.
    'pas_encore_porte' => 'Not ported to this portal yet',
    'a_venir_config' => 'Reading and saving this configuration arrive with the following sub-lots. Until then they stay on the previous portal.',
    'a_venir_profils' => 'The profile catalogue and its assignment arrive with the following sub-lots. Until then they stay on the previous portal.',
    'a_venir_deploiement' => 'The fleet table and the deployment actions arrive with the following sub-lots: they reach the servers over SSH and change their configuration, they are not ported lightly. Until then they stay on the previous portal.',
    'a_venir_editeur' => 'Reading and writing the remote file arrive with the following sub-lots. Until then they stay on the previous portal.',
    'vers_legacy' => 'Open on the previous portal',
];
