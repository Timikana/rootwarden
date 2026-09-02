<?php

/*
 * Machine groups and bulk actions. Flat keys — the file is loaded as one block
 * by `@json(__('groups'))`. The key set must stay identical to
 * `lang/fr/groups.php`.
 */
return [
    'titre' => 'Groups and bulk actions',
    'desc'  => 'Group your servers by a dynamic rule (environment, criticality, network, lifecycle, tags) or by a static list, then run bulk operations tracked in the task centre.',

    'chargement' => 'Loading…',
    'vide_titre'  => 'No group',
    'vide_texte'  => 'No group exists yet. A group gathers servers, then serves as the target of a bulk action.',
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
    'np_titre'      => 'Not ported yet',
    'np_ouvrir'     => 'Open in the old portal',
    'np_fermer'     => 'Close',

    'np_supprimer'  => 'Deleting a group is not ported to this interface yet.',
    'np_supprimer_detail' => 'Deletion only affects the group: the servers it gathers are not modified.',

    'np_derive'     => 'The bulk drift scan is not ported to this interface yet.',
    'np_derive_detail' => 'This action opens NO SSH session: it re-reads data already in the database and updates each member\'s drift record. The scheduler already does the same work every hour across the whole fleet.',

    'np_cve'        => 'The bulk CVE scan is not ported to this interface yet.',
    'np_cve_detail' => 'This action opens a real SSH session on EVERY member of the group, and each machine whose scan completes triggers a report sent by email. This is not a read: it is as many connections and as many sends as the group has servers.',
    'np_cve_membres' => 'This group resolves to :n server(s) today.',
    'np_cve_prod'   => '⚠ Production is among them: :noms.',
    'np_cve_derive' => 'The number shown is today\'s. A dynamic group is re-resolved when the action starts: a machine added to the fleet in between would enter the action without ever having been shown here.',

    'portee_titre' => 'What this page can do today',
    // R2: creation IS ported now — see fr.
    'portee_texte' => 'Reading groups, their members and creation are ported. Deletion and the two bulk actions still go through the old portal — each button explains what it engages before sending you there.',
    'parc_entier'  => 'An administrator role can target the whole fleet: no machine assignment bounds bulk actions.',

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
    'portee_aucun_filtre' => 'No criterion is ticked: this group will contain EVERY machine in the fleet, production included.',
    'portee_filtres' => 'Criteria kept: :liste',
    'portee_statique' => ':n machine(s) named.',
    'portee_statique_vide' => 'No machine named: the group will be empty.',
    'portee_archivees' => "The server-side fleet computation does not exclude archived machines: a group with no criterion may contain some.",
    'err_nom' => 'A name is required.',
    'cree' => 'Group created.',
    'err_creation' => 'The group could not be created.',
];
