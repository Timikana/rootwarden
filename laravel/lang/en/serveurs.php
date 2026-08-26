<?php

/**
 * The machine estate — `adm/` module, sub-lot D6a.
 *
 * STRICT PARITY with `lang/fr/serveurs.php`: same keys, same order.
 */
return [
    'title' => 'Servers',
    'desc' => 'The machines RootWarden administers: their address, the SSH account used to reach them, their environment and their criticality.',
    'compte' => ':n machine(s) in the estate',

    // Environment legend
    'legende' => 'Environments',

    // Search
    'filtre_label' => 'Filter the estate',
    'filtre_placeholder' => 'name, address, user…',
    'filtre_resultat' => ':n machine(s) shown',

    // Add
    'ajouter_titre' => 'Add a machine',
    'champ_nom' => 'Name',
    'champ_ip' => 'IP address',
    'champ_port' => 'SSH port',
    'champ_utilisateur' => 'SSH account',
    'champ_mdp' => 'Password',
    'champ_mdp_root' => 'Root password',
    'champ_environnement' => 'Environment',
    'champ_criticite' => 'Criticality',
    'champ_reseau' => 'Network',
    'env_autre' => 'Other',
    'crit_critique' => 'Critical',
    'crit_non_critique' => 'Not critical',
    'res_interne' => 'Internal',
    'res_externe' => 'External',
    'aide_nom' => 'Letters, digits, spaces, dots, hyphens, underscores, plus signs and parentheses.',
    'aide_ip' => 'Private addresses are accepted. Loopback, link-local and multicast are refused: they do not designate a reachable machine.',
    'btn_ajouter' => 'Add the machine',
    'champs_requis' => 'Fields marked with a star are required.',

    // Edit
    'inchange' => 'Leave empty to keep unchanged',
    'options_deploiement' => 'Deployment options',
    'opt_nettoyage' => 'Clean up stale accounts',
    'opt_nettoyage_aide' => 'On the next deployment, machine accounts that no longer match any access will be removed.',
    'btn_enregistrer' => 'Save',
    'btn_supprimer' => 'Remove from estate',

    // Deletion
    'suppr_titre' => 'Remove :nom from the estate?',
    'suppr_texte' => 'The machine disappears from vulnerability scans, from supervision and from key deployments. The machine itself is not touched: nothing is changed on it, no access is revoked.',
    'suppr_confirmer' => 'Remove from estate',
    'suppr_annuler' => 'Cancel',

    // States
    'en_ligne' => 'online',
    'hors_ligne' => 'offline',
    'statut_inconnu' => 'unknown state',
    'auth_cle' => 'Key authentication',
    'auth_mdp' => 'Password authentication',
    'cycle_retrait' => 'Being retired',
    'cycle_archive' => 'Archived',
    'cycle_date' => 'retirement planned for :date',

    // Empty state
    'vide' => 'No machine in the estate.',
    'vide_aide' => 'Until a machine is declared, neither vulnerability scans nor key deployments have a target.',

    // What D6a does not carry yet
    'reste_titre' => "Three capabilities of this tab are not ported yet.",
    'reste_texte' => "Lifecycle, connection test and CSV file import go through separate entry points on the legacy portal. They still work there.",
    'reste_lien' => 'Open the legacy portal',

    // Outcomes
    'ajoutee' => 'Machine :nom has been added to the estate.',
    'modifiee' => 'Machine :nom has been updated.',
    'supprimee' => 'Machine :nom has been removed from the estate.',

    // Errors
    'err_champs' => 'Refused fields: :champs.',
    'err_doublon' => 'A machine already carries this name or this address.',
    'err_ajout' => 'The machine could not be added.',
    'err_modification' => 'The machine could not be updated.',
    'err_suppression' => 'The machine could not be removed.',
    'err_introuvable' => 'This machine does not exist.',
    'err_secret' => 'Both passwords are required on creation, and the encryption service must be available.',

    // Tags and notes — sub-lot D6b
    'etiquettes_titre' => 'Tags',
    'etiquettes_vide' => 'No tag.',
    'etiquette_champ' => 'New tag',
    'etiquette_placeholder' => 'production, web…',
    'etiquette_aide' => 'Lowercase letters, digits, hyphen and underscore. Anything else is removed.',
    'etiquette_ajouter' => 'Add',
    'etiquette_retirer' => 'Remove tag :tag',
    'etiquette_posee' => 'The tag has been added.',
    'etiquette_retiree' => 'The tag has been removed.',
    'notes_titre' => 'Notes',
    'notes_vide' => 'No note on this machine.',
    'notes_borne' => 'Only the last :n notes are shown.',
    'note_champ' => 'New note',
    'note_placeholder' => 'what the next person needs to know…',
    'note_ajouter' => 'Add',
    'note_supprimer' => 'Delete this note',
    'note_posee' => 'The note has been added.',
    'note_supprimee' => 'The note has been deleted.',
    'err_etiquette_vide' => 'A tag must contain at least one lowercase letter, digit, hyphen or underscore.',
    'err_etiquette_longue' => 'A tag cannot exceed 50 characters.',
    'err_note_vide' => 'A note cannot be empty.',
    'err_note_introuvable' => 'This note does not exist on this machine.',

    // Lifecycle and connection — sub-lot D6d
    'exploitation_titre' => 'Lifecycle and connection',
    'cycle_active' => 'Reactivate',
    'cycle_retiring' => 'Retire',
    'cycle_archived' => 'Archive',
    'cycle_active_fait' => 'The machine has been reactivated.',
    'cycle_retiring_fait' => 'The machine has been retired.',
    'cycle_archived_fait' => 'The machine has been archived.',
    'cycle_inchange' => 'The machine was already in that state: nothing changed.',
    'btn_tester' => 'Test connection',
    'test_en_cours' => 'Testing…',
    'test_en_ligne' => 'The machine answers on :ip.',
    'test_hors_ligne' => 'The machine does not answer on :ip.',
    'test_echec' => 'The test could not be run.',
];
