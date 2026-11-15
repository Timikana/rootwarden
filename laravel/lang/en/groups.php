<?php

/*
 * Machine groups and bulk actions. Flat keys — the file is loaded as one block
 * by `@json(__('groups'))`. The key set must stay identical to
 * `lang/fr/groups.php`.
 */
return [
    'titre' => 'Groups and bulk actions',
    'desc'  => "Group servers by criteria or by list, then run actions on the whole group.",

    'chargement' => 'Loading…',
    'vide_titre'  => 'No group',
    'vide_texte'  => "Create one with « New group ».",
    'err_charge'  => 'The list of groups could not be read.',

    'membres'       => 'Members',
    'type_dynamique' => 'Dynamic',
    'type_statique'  => 'Static',
    'cree_par'      => 'Created by',
    'cree_le'       => 'Created on',
    // The legacy renders an EMPTY line for this case, while the backend
    // resolves it to `1=1` — the whole fleet, production included.
    'sans_filtre'   => 'no filter — every machine in the fleet',
    'membres_aucun' => 'No server matches this group.',
    'membres_err'   => 'The members of this group could not be read.',

    'act_membres'  => 'Show members',
    'act_masquer'  => 'Hide members',
    'act_derive'   => 'Drift scan',
    'act_cve'      => 'CVE scan',
    'act_supprimer' => 'Delete',
    'act_nouveau'  => 'New group',

    'aide_membres' => 'Shows the servers this group resolves to right now.',

    // A SHARED PANEL MUST NAME ITS TARGET — see fr.
    'np_sur_groupe' => 'Target group: :nom',
    'np_titre'      => "Not available here",
    'np_fermer'     => 'Close',
    // R4: deleting a group IS ported. `np_supprimer_detail` does NOT move — it
    // carries the REASSURING fact, and that is the one that matters most: the
    // fear is "am I destroying my machines", the answer is no, and the panel
    // must give it. Same principle as F8.
    //
    // And the verdict is NOT `success`: the route answers
    // {'success': True, 'deleted': rowcount > 0} even when nothing was
    // deleted. `supprimer_introuvable` exists for that case.
    'supprimer_titre'      => 'Delete this group?',
    'supprimer_membres'    => 'This group gathers :n server(s) today.',
    'supprimer_definitif'  => "Permanent deletion: the group will have to be recreated.",
    'supprimer_valider'    => 'Delete the group',
    'supprimer_fait'       => 'Group ":nom" is deleted. The servers it gathered were not modified.',
    'supprimer_introuvable' => 'No group was deleted: ":nom" no longer existed. The list is reloaded.',
    'supprimer_echec'      => 'The group could not be deleted. :message',
    'np_supprimer_detail' => 'Deletion only affects the group: the servers it gathers are not modified.',

    // R3: the bulk drift scan is PORTED — see the note in `lang/fr/groups.php`.
    // `np_cve` and its satellites do NOT move: the CVE scan opens one SSH
    // session per machine and sends one email per machine with results.
    'der_titre'  => 'Run a drift scan',
    'der_texte'  => "Opens no SSH session: re-reads the data in the database and updates each member's drift record. The scheduler already does this every hour.",
    'der_lancer' => 'Run the drift scan',

    // The number shown is the RESOLVED one, never the expected one: a group
    // whose filters were all rejected stores as `{}` — the same object as a
    // group with no criteria, hence `1=1`, hence the whole fleet.
    'resolu_nombre'   => 'This group resolves to :n server(s) today.',
    'resolu_prod'     => '⚠ Production is among them: :noms.',
    'resolu_reresolu' => "Number computed now: a dynamic group is recomputed at launch and may include a machine added in between.",

    // No announced scope, no confirmation offered.
    'der_illisible' => "Unable to read this group's scope: running the scan is not offered.",
    'der_vide'      => 'This group resolves to no server today: a scan would record nothing.',
    'der_lance'     => ':n server(s) queued. Follow them in the task centre.',
    'der_echoue'    => 'The drift scan could not be started. :message',

    'np_cve'        => "The bulk CVE scan is not available on this page.",
    'np_cve_detail' => "It would open an SSH session on every group member and send an email report for each scanned machine.",
    'np_cve_membres' => 'This group resolves to :n server(s) today.',
    'np_cve_prod'   => '⚠ Production is among them: :noms.',
    'np_cve_derive' => "Number computed now: a dynamic group is recomputed at launch and may include a machine added in between.",

    // Any role >= 2 passes check_machine_access — see fr.
    'parc_entier'  => "Bulk actions can target the whole fleet: per-machine access does not limit them.",

    // R2 — creating a group. E-274 closed by construction: saving goes through
    // the decision panel, which announces the resolved scope. See fr.
    'form_titre' => 'New group',
    'f_nom' => 'Name',
    'f_desc' => 'Description',
    'f_type' => 'How members are chosen',
    'type_dyn_aide' => 'By rule: machines matching the criteria join and leave on their own.',
    'type_stat_aide' => 'By list: you name the machines one by one.',
    'f_env' => 'Environment',
    'f_crit' => 'Criticality',
    'f_reseau' => 'Network',
    'f_cycle' => 'Lifecycle',
    'f_membres' => 'Machines in the group',
    'btn_enregistrer' => 'Save',
    'btn_annuler' => 'Cancel',
    'portee_aucun_filtre' => "No criterion ticked: this group will contain every machine in the fleet, production included.",
    'portee_filtres' => 'Criteria kept: :liste',
    'portee_statique' => ':n machine(s) named.',
    'portee_statique_vide' => 'No machine named: the group will be empty.',
    'portee_archivees' => "A group with no criterion also includes archived machines.",
    'err_nom' => 'A name is required.',
    'err_creation' => 'The group could not be created.',
];
