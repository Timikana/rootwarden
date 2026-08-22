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

    // ── The global configuration, sub-lot V3 (read-only) ─────────────────
    'config_aucune' => 'No global configuration recorded',
    'config_aucune_aide' => 'No global configuration is recorded for :plateforme. The agent template defaults will apply on the next deployment.',
    // THERE IS NO SUCH THING AS "THE" GLOBAL CONFIGURATION: the table carries no
    // uniqueness constraint on the platform, and both portals read the row with
    // the highest id. Say it, rather than implying a single record.
    'config_plus_recente' => 'Several configurations may coexist for one platform: the most recently recorded one applies, and that is the one shown here.',
    'champ_vide' => 'Not set',
    'champ_type_agent' => 'Agent type',
    'champ_version_agent' => 'Agent version',
    'champ_serveur' => 'Server',
    'champ_serveur_actif' => 'Active server',
    'champ_port' => 'Listen port',
    'champ_motif_nom' => 'Hostname pattern',
    'champ_tls_connexion' => 'TLS connect',
    'champ_tls_acceptation' => 'TLS accept',
    'champ_psk_identite' => 'PSK identity',
    'champ_psk_valeur' => 'PSK key',
    'champ_metadonnees' => 'Host metadata template',
    'champ_config_supplementaire' => 'Extra lines',
    'champ_centreon_hote' => 'Centreon host',
    'champ_centreon_port' => 'Centreon port',
    'champ_prometheus_ecoute' => 'Listen address',
    'champ_prometheus_collecteurs' => 'Collectors',
    'champ_telegraf_url' => 'Output URL',
    'champ_telegraf_organisation' => 'Organisation',
    'champ_telegraf_seau' => 'Bucket',
    'champ_telegraf_entrees' => 'Inputs',
    'champ_telegraf_jeton' => 'Output token',
    'secret_pose' => 'Set',
    'secret_absent' => 'Not set',
    'secret_jamais_affiche' => 'The value stays in the database: this portal does not read it.',
    // ── Saving, sub-lot V4 ────────────────────────────────────────────────
    'secret_conserve' => 'Leaving this empty keeps the key already recorded. This portal never reads it.',
    'secret_jeton_non_porte' => 'Editing this token is not ported yet: it stays on the previous portal.',
    'enregistrer' => 'Save',
    // THE SCOPE OF A SAVE IS STATED. The legacy portal writes to the most recent
    // row with NO platform filter: saving Zabbix overwrites a Centreon row there.
    // Here the write is scoped, and the screen says so.
    'enregistrement_portee' => 'This save only changes the :plateforme configuration.',
    'enregistrement_fait' => ':plateforme configuration saved.',
    'enregistrement_champ_exige' => 'The ":champ" field is required: without it the deployed configuration would be inert.',
    'enregistrement_plateforme_inconnue' => 'Unknown platform: nothing was saved.',

    'profils_titre' => 'Monitoring profiles',
    // ── The catalogue, sub-lot V2 (read-only) ─────────────────────────────
    'profil_nom' => 'Name',
    'profil_actions' => 'Actions',
    // ── The CRUD, sub-lot V5 ──────────────────────────────────────────────
    'champ_profil_nom' => 'Name',
    'champ_profil_description' => 'Description',
    'champ_profil_metadonnees' => 'HostMetadata',
    'champ_profil_serveur' => 'Server',
    'champ_profil_serveur_actif' => 'Active server',
    'champ_profil_mandataire' => 'Proxy',
    'champ_profil_port' => 'Listen port',
    'champ_profil_notes' => 'Notes',
    'profil_modifier' => 'Edit',
    'profil_supprimer' => 'Delete',
    'profil_nouveau' => 'New profile',
    'profil_titre_nouveau' => 'New profile',
    'profil_titre_modifier' => 'Edit profile :nom',
    'profil_nom_exige' => 'The name is required: it is what links the profile to an auto-registration rule.',
    // THE CONSTRAINT IS IN THE DATABASE (`uk_platform_name`), verified against the
    // schema: the refusal is a property of the data, not a courtesy of the UI.
    'profil_doublon' => 'A profile named ":nom" already exists for :plateforme. Names are unique per platform.',
    'profil_introuvable' => 'This profile does not exist, or no longer does.',
    'profil_cree' => 'Profile ":nom" created.',
    'profil_modifie' => 'Profile ":nom" updated.',
    'profil_supprime' => 'Profile ":nom" deleted. :machines server(s) fall back to the global configuration.',
    'profil_supprimer_titre' => 'Delete profile ":nom"?',
    // THE COST IS STATED BEFORE THE ACT, not observed after it.
    'profil_supprimer_cout' => ':machines server(s) will lose this profile and fall back to the global configuration on the next deployment. This deletion cannot be undone.',
    'profil_supprimer_confirmer' => 'Delete permanently',
    'annuler' => 'Cancel',
    // ASSIGNMENT IS NOT PORTED, and that is a decision: its entry point is the
    // deployment table, and inverting it (picking machines for a profile) would be
    // designing, not migrating.
    'profils_assignation_ailleurs' => 'Attaching a server to a profile is done from the deployment table, which is not ported yet.',
    'profil_metadonnees' => 'HostMetadata',
    'profil_serveur' => 'Server',
    'profil_mandataire' => 'Proxy',
    'profil_machines' => 'Machines',
    // AN ABSENT VALUE SAYS WHAT IT MEANS. The legacy portal writes "-", which
    // teaches nothing: here the absence means the global configuration applies,
    // and that is what is written.
    'profil_herite' => 'Global configuration',
    'profils_aucun' => 'No profile for this platform',
    'profils_aucun_aide' => 'No monitoring profile is defined for :plateforme. Profiles belong to one platform each.',
    'profils_interpolation' => 'Values may contain {machine.name} or {machine.ip}: they are substituted at deployment time.',
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
    // ── The fleet and version detection, sub-lot V6 ───────────────────────
    'machine_nom' => 'Server',
    'machine_adresse' => 'Address',
    'machine_environnement' => 'Environment',
    'machine_agents' => 'Recorded agents',
    // NO AGENT IS A FINDING, not a silence: a detection that finds nothing
    // deletes the recorded row.
    'agent_aucun' => 'Nothing recorded',
    'version_detecter' => 'Detect version',
    'version_en_cours' => 'Reading the version on :nom...',
    'version_trouvee' => 'Version detected on :nom: :version.',
    'version_absente' => 'No agent installed on :nom. The previous record was cleared.',
    // A REFUSAL IS NOT "NO AGENT": a client that does not read the status would
    // conclude "nothing installed" without having measured anything.
    'version_refus' => 'The read was refused (status :statut). No conclusion can be drawn from it.',
    'version_echec' => 'The read did not complete: the server may be unreachable.',
    'aucune_machine_aide' => 'Every machine is archived, or the fleet is empty.',

    // What V1 does not port yet SAYS SO, rather than leaving a bare panel.
    // The empty state's heading does NOT repeat the panel's own: seen in the
    // capture, the same wording twice in a row reads as a rendering defect.
    'pas_encore_porte' => 'Not ported to this portal yet',
    'a_venir_config' => 'Reading and saving this configuration arrive with the following sub-lots. Until then they stay on the previous portal.',
    'a_venir_profils' => 'The profile catalogue and its assignment arrive with the following sub-lots. Until then they stay on the previous portal.',
    // A TEXT CAN BECOME FALSE WITHOUT ANY TEST SEEING IT: the fleet table is
    // ported as of V6, so the sentence announcing it "for later" no longer was.
    'a_venir_deploiement' => 'Installing, reconfiguring and uninstalling an agent, along with surveying the whole fleet at once, arrive with the following sub-lots: those acts CHANGE the servers, and surveying the whole fleet needs redesigning as a background task. Until then they stay on the previous portal.',
    'a_venir_editeur' => 'Reading and writing the remote file arrive with the following sub-lots. Until then they stay on the previous portal.',
    'vers_legacy' => 'Open on the previous portal',
];
