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
    // ── The remote editor, sub-lot V7 (read-only) ─────────────────────────
    // THE ANNOUNCED PATH COMES FROM THE SAME SOURCE AS THE ONE THAT WILL BE READ.
    // The legacy portal shows a path hardcoded in the client: see PARITE E-79.
    // BEFORE THE READ, THE PAGE CANNOT SAY "READ": nothing has been. Two labels,
    // and the script switches from the first to the second once the read lands.
    'editeur_chemin' => 'Target file:',
    'editeur_chemin_lu' => 'File read:',
    'editeur_contenu' => 'File content',
    'editeur_vide' => 'Pick a server then read its configuration to display it here.',
    'editeur_lecture_en_cours' => 'Reading the file on :nom...',
    'editeur_lu' => 'File :chemin read on :nom.',
    // THREE DISTINCT CASES: a missing file is an ANSWER, not a failure.
    'editeur_absent' => 'The file :chemin does not exist on :nom. No agent is likely installed there.',
    'editeur_refus' => 'The read was refused (status :statut). No conclusion can be drawn from it.',
    'editeur_echec' => 'The read did not complete: the server may be unreachable.',
    'sauvegardes_titre' => 'Backups of the file on the server.',
    'sauvegardes_lister' => 'List backups',
    'sauvegardes_aucune' => 'No backup on this server.',
    'sauvegardes_nombre' => ':nombre backup(s):',
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
    'version_non_concluante' => "The probe could not read anything on :nom: we do not know whether an agent is installed there. The recorded reading was NOT modified.",
    'version_refus' => 'The read was refused (status :statut). No conclusion can be drawn from it.',
    'version_echec' => 'The read did not complete: the server may be unreachable.',
    'aucune_machine_aide' => 'Every machine is archived, or the fleet is empty.',

    // What V1 does not port yet SAYS SO, rather than leaving a bare panel.
    // The empty state's heading does NOT repeat the panel's own: seen in the
    // capture, the same wording twice in a row reads as a rendering defect.
    // A TEXT CAN BECOME FALSE WITHOUT ANY TEST SEEING IT: the fleet table is
    // ported as of V6, so the sentence announcing it "for later" no longer was.

    // ── Sub-lot V8: surveying the fleet as a background task ──────────────
    'releve_titre' => 'Survey monitoring agents across the fleet',
    'releve_description' => 'Asks every server which monitoring agents are installed on it, and at which version. This is a READ: nothing is installed, reconfigured or restarted. The survey runs as a background task and its progress is followed in the task centre.',
    'releve_bouton' => 'Survey the fleet',
    'releve_cout' => ':machines machine(s), :plateformes platform(s), :sessions SSH session(s) — one per machine, not one per platform.',
    'releve_production' => 'PRODUCTION machines involved: :machines.',
    'releve_aide_fond' => 'The survey does not block this page: the response is immediate and the sweep carries on in the background, one server after another.',
    'releve_annuler' => 'Cancel',
    'releve_confirmer' => 'Start the survey',
    'releve_en_cours' => 'Queueing the survey...',
    'releve_lance' => 'Survey started on :machines machine(s) — task #:tache.',
    'releve_aucune' => 'No machine to survey.',
    'releve_refus' => 'Survey refused (status :statut).',
    'releve_echec' => 'The survey could not be started.',
    'releve_voir_taches' => 'Follow in the task centre',

    // ── Sub-lot V9: writing the remote file and restoring a backup ─────────
    'editeur_sauver' => 'Write to the server',
    'editeur_sauver_vide' => 'The content is empty: nothing would be written. Read the file first, or type a configuration.',
    'editeur_sauver_cout' => 'This acts on :chemin, on the selected server.',
    'editeur_effet_sauvegarde' => 'a timestamped copy of the current file is created on the server, before anything is written',
    'editeur_effet_ecriture' => 'the file is replaced by the content shown above',
    'editeur_effet_redemarrage' => 'the monitoring agent is restarted so it picks up the new configuration',
    'editeur_sauver_annuler' => 'Cancel',
    'editeur_sauver_confirmer' => 'Write and restart',
    'editeur_sauver_en_cours' => 'Writing...',
    'editeur_sauve_et_redemarre' => 'File written and agent restarted.',
    'editeur_sauve_sans_redemarrage' => 'File written, but the agent did NOT restart. The configuration is in place and the service is not running: check it before relying on this server being monitored.',
    'editeur_sauver_refus' => 'Write refused (status :statut).',
    'editeur_sauver_echec' => 'The file was not written.',
    'restaurer_bouton' => 'Restore',
    'restaurer_cout' => 'Restoring :nom will overwrite :chemin on the selected server.',
    'restaurer_aide' => 'The current file is copied first as well: a restore can therefore be undone. The agent is restarted afterwards.',
    'restaurer_annuler' => 'Cancel',
    'restaurer_confirmer' => 'Restore and restart',
    'restaurer_en_cours' => 'Restoring :nom...',
    'restaure_et_redemarre' => ':nom restored and agent restarted.',
    'restaure_sans_redemarrage' => ':nom restored, but the agent did NOT restart. The file is in place and the service is not running.',
    'restaurer_refus' => 'Restore refused (status :statut).',
    'restaurer_echec' => 'The restore did not go through.',
    'editeur_change_serveur' => 'Server changed: the editing area was cleared. Anything typed there was not saved.',

    // ── Sub-lot V10a: per-machine settings ────────────────────────────────
    'reglages_lien' => 'Settings',
    'reglages_titre' => 'Per-machine settings',
    'reglages_description' => 'These settings apply to ONE server only and take precedence over its profile and over the global configuration. A field left empty means "inherited": the server then takes the value from its profile, or from the global configuration.',
    'reglages_aucune_machine' => 'No server selected',
    'reglages_aucune_machine_aide' => 'Use the "Settings" button on a row of the table above to open its settings.',
    'reglages_pour' => 'Settings for server :nom.',
    'reglages_effet_differe' => 'Saving reaches NO server: these values live in the database and will only be sent to the machine at the next reconfiguration.',
    'reglages_herite' => 'inherited',
    'reglages_fermer' => 'Close',
    'reglages_enregistrer' => 'Save the settings',
    'reglages_vide_efface' => 'Clearing a field DELETES the setting: the server falls back to its profile or to the global configuration. A setting saved empty would produce a valueless line in the configuration file.',
    'reglages_hors_liste' => 'This server also carries settings outside this list, set by other means: :champs. They take effect, and this screen cannot change them.',
    'reglages_enregistres' => 'Settings for :nom saved.',
    'reglages_refuses' => 'Settings refused because their value is invalid: :champs. The others were saved.',
    'reglages_machine_inconnue' => 'Unknown or archived server: nothing was saved.',
    'override_hostname' => 'Declared host name',
    'override_hostname_aide' => 'The name the agent presents itself with to the monitoring server.',
    'override_serveur' => 'Monitoring server',
    'override_serveur_aide' => 'The address the agent accepts requests from.',
    'override_serveur_actif' => 'Server in active mode',
    'override_serveur_actif_aide' => 'The address the agent sends its measurements to on its own.',
    'override_metadonnees' => 'Host metadata',
    'override_metadonnees_aide' => 'Used by the server to file this host automatically.',
    'override_port' => 'Listening port',
    'override_port_aide' => 'Between 1 and 65535. Defaults to 10050.',
    'override_tls_connect' => 'Encryption of outgoing connections',
    'override_tls_connect_aide' => 'How the agent encrypts what it sends.',
    'override_tls_accept' => 'Encryption of incoming connections',
    'override_tls_accept_aide' => 'What the agent accepts receiving.',
    'override_psk_identite' => 'PSK identity',
    'override_psk_identite_aide' => 'The name of the shared key. The key itself stays in the global configuration and is never shown here.',

    // ── Sub-lot V10: reconfiguration ──────────────────────────────────────
    'reconf_bouton' => 'Reconfigure',
    'reconf_titre' => "Reconfigure a server's agent",
    'reconf_description' => 'Pushes the configuration computed by the portal again — global configuration, server profile and per-machine settings — without reinstalling the agent. The action applies to ONE server, the one on the chosen row.',
    'reconf_sans_config' => 'No global configuration saved',
    'reconf_sans_config_aide' => 'Reconfiguration is refused as long as no global configuration exists: there would be nothing to push. Fill it in under the "Global configuration" tab, then come back here.',
    'reconf_cout' => 'Reconfiguring :nom will replace the known settings in :chemin on that server.',
    'reconf_effet_sauvegarde' => 'a timestamped copy of the current file is created on the server, before anything is written',
    'reconf_effet_fusion' => 'known keys are replaced one by one in :chemin — lines the portal does not manage SURVIVE, unlike the editor which rewrites the whole file',
    'reconf_effet_psk' => 'the shared key is rewritten on the server, in a separate file',
    'reconf_effet_redemarrage' => 'the monitoring agent is restarted so it picks up the new configuration',
    'reconf_annuler' => 'Cancel',
    'reconf_confirmer' => 'Reconfigure and restart',
    'reconf_en_cours' => 'Reconfiguring :nom...',
    'reconf_reussie' => 'Configuration pushed to :nom and agent restarted.',
    'reconf_partielle' => 'Configuration pushed to :nom, but a remote command FAILED (code :codes). The file is in place and the service may not be running: read the log below before relying on this server being monitored.',
    'reconf_echouee' => 'Reconfiguring :nom failed.',
    'reconf_inachevee' => 'Reconfiguring :nom did not complete: the log is truncated.',
    'reconf_avertissements' => ':nombre warning(s) in the log.',
    'reconf_refus' => 'Reconfiguration refused (status :statut).',
    'reconf_echec' => 'The reconfiguration could not be started.',

    // ── Sub-lot V11: uninstalling ─────────────────────────────────────────
    'desinst_bouton' => 'Uninstall',
    'desinst_titre' => "Uninstall a server's agent",
    'desinst_description' => 'Removes the monitoring agent from ONE server: the service is stopped, the package and its configuration are purged. This action DESTROYS and cannot be undone — reinstalling the agent requires a deployment.',
    'desinst_cout' => "Uninstalling the agent from :nom will remove the package and its configuration, including :chemin.",
    'desinst_effet_service' => "the agent's service is stopped if it is running",
    'desinst_effet_purge' => 'the package is purged: the program AND its configuration files go. Other packages on the server are left alone.',
    'desinst_effet_inventaire' => "this agent's inventory row is removed, but ONLY if the command succeeded",
    'desinst_aide_verif' => 'After the action, the portal reads the installed version back from the server to VERIFY the agent is really gone, rather than trusting what the command claims.',
    'desinst_annuler' => 'Cancel',
    'desinst_confirmer' => 'Uninstall the agent',
    'desinst_en_cours' => 'Uninstalling on :nom...',
    'desinst_purge' => 'Agent uninstalled from :nom. Packages purged: :paquets.',
    'desinst_rien' => 'No agent was installed on :nom: there was nothing to uninstall. The inventory has been updated accordingly.',
    'desinst_echouee' => 'Uninstalling on :nom FAILED (code :codes). The inventory was not changed: read the log below to find out what is left on the server.',
    'desinst_inachevee' => 'Uninstalling on :nom did not complete: the log is truncated.',
    'desinst_refus' => 'Uninstall refused (status :statut).',
    'desinst_echec' => 'The uninstall could not be started.',
    'desinst_verif_en_cours' => 'Verifying on the server...',
    'desinst_verif_absent' => 'Verified: no agent is detected on this server any more.',
    'desinst_verif_present' => 'WARNING: an agent is STILL detected on this server (version :version). The command returned a success, yet the agent is still there.',
    'desinst_verif_impossible' => 'The verification could not complete: the real state of the server was not established.',
    'desinst_production' => ':nom is a PRODUCTION server. Monitoring of it stops as soon as the agent is gone.',
    /*
     * ── SUB-LOT V12: DEPLOYMENT ──────────────────────────────────────────
     *
     * STEPS ARE NAMED, NOT COUNTED, and they are rendered PER PLATFORM.
     * Measured: `zabbix_deploy` and `generic_deploy` do not do the same work.
     * Zabbix starts by PURGING the agent in place, renames the configuration to
     * `.old` and downloads a `.deb` from repo.zabbix.com; Prometheus adds no
     * external repository; Centreon and Telegraf lay down a GPG key and a
     * `sources.list`. Listing the Zabbix steps while the selector is on
     * Telegraf would be defect E-79 through another door.
     */
    'depl_bouton' => 'Deploy',
    'depl_titre' => 'Agent deployment',
    'depl_description' => 'Installs the agent on one server, then writes the configuration built from the global configuration, the machine settings and its profile. The gesture applies to ONE machine: the one on the chosen row.',
    'depl_sans_config' => 'No global configuration: deployment would be refused.',
    'depl_sans_config_aide' => 'For Zabbix, the backend returns a 400 error until the Configuration tab has been saved. Fill it in first: deployment takes the agent version, the server to reach and the hostname pattern from it.',
    'depl_sans_config_generique' => 'No global configuration for this platform: the agent will be installed, but NO configuration will be written on the machine. Unlike Zabbix, the backend does not refuse this case.',
    'depl_cout' => 'Deploy the :plateforme agent on :nom. The following steps will run on the machine:',
    'depl_production' => ':nom is a PRODUCTION server. Check the steps below before deciding: some of them interrupt monitoring while they run.',
    'depl_effet_purge' => 'Zabbix agents already installed are PURGED: deploying starts by uninstalling.',
    'depl_effet_ancienne' => 'The current configuration :chemin is renamed to .old — a second deployment will overwrite that copy.',
    'depl_effet_greffons' => 'Three plugins already in place (postgresql, mssql, mongodb) are removed.',
    'depl_effet_depot_externe' => 'The :hote repository is added to the machine, which must be able to reach it over the Internet.',
    'depl_effet_index' => 'The machine apt indexes are refreshed.',
    'depl_effet_installation' => 'The :paquet package is installed.',
    'depl_effet_psk' => 'A PSK key is written on the machine, in /etc/zabbix/zabbix_agent2.d/server.key.',
    'depl_effet_sauvegarde' => 'The existing configuration :chemin is backed up, timestamped.',
    'depl_effet_configuration' => 'The :chemin file is written.',
    'depl_effet_extra' => 'The extra configuration is appended at the end of the file.',
    'depl_effet_service' => 'The :service service is restarted, then enabled at boot.',
    'depl_effet_inventaire' => 'The inventory records the agent as deployed — even if the previous steps failed.',
    'depl_annuler' => 'Cancel',
    'depl_confirmer' => 'Deploy now',
    'depl_en_cours' => 'Deployment running on :nom...',
    'depl_reussi' => 'Deployment finished on :nom: every step returned a success.',
    'depl_echouee' => 'Deployment on :nom FAILED (code :codes). The portal recorded the agent in its inventory anyway.',
    'depl_inachevee' => 'Deployment on :nom did not complete: no step concludes.',
    'depl_refus' => 'Deployment was refused (status :statut). Nothing was sent to the machine.',
    'depl_echec' => 'Deployment could not be started.',
    'depl_verif_en_cours' => 'Checking what is actually installed...',
    'depl_verif_conforme' => 'Checked: agent detected in version :version.',
    'depl_verif_divergente' => 'WARNING: the detected version is :trouvee, whereas :attendue was requested.',
    'depl_verif_absente' => "WARNING: NO agent is detected on :nom. The portal has just recorded this agent in its inventory — the inventory is the one that is wrong.",
    'depl_verif_impossible' => 'The check could not complete: what is actually installed was not established.',
];
