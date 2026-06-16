<?php
// lang/fr/groups.php - Groupes de machines + actions de masse
return [
    // Navigation
    'nav.groups' => 'Groupes & masse',
    'nav.tip_groups' => 'Groupes de machines dynamiques/statiques et operations de masse',

    // Page (PHP)
    'groups.title' => 'Groupes & actions de masse',
    'groups.desc' => 'Regroupez vos serveurs par regle dynamique (environnement, criticite, reseau, cycle de vie, tags) ou liste statique, puis lancez des operations groupees suivies dans le centre de taches.',
    'groups.btn_new' => 'Nouveau groupe',
    'groups.f_name' => 'Nom',
    'groups.f_desc' => 'Description',
    'groups.type_dynamic' => 'Dynamique (regle)',
    'groups.type_static' => 'Statique (liste)',
    'groups.dynamic_hint' => 'Les serveurs correspondant a TOUS les criteres coches sont inclus automatiquement (OR a l\'interieur d\'une categorie, AND entre categories).',
    'groups.f_environment' => 'Environnement',
    'groups.f_criticality' => 'Criticite',
    'groups.f_network' => 'Reseau',
    'groups.f_lifecycle' => 'Cycle de vie',
    'groups.f_tags' => 'Tags',
    'groups.tags_placeholder' => 'web, db, frontal (separes par des virgules)',
    'groups.tags_known' => 'Tags connus',
    'groups.f_members' => 'Membres',
    'groups.btn_save' => 'Enregistrer',
    'groups.btn_cancel' => 'Annuler',
    'groups.loading' => 'Chargement...',

    // JS (prefixe js. -> charge via getJsTranslations)
    'js.groups.empty' => 'Aucun groupe. Cree ton premier groupe.',
    'js.groups.members' => 'Membres',
    'js.groups.type_static' => 'Statique',
    'js.groups.type_dynamic' => 'Dynamique',
    'js.groups.act_members' => 'Voir membres',
    'js.groups.act_drift' => 'Scan derive',
    'js.groups.act_cve' => 'Scan CVE',
    'js.groups.act_delete' => 'Supprimer',
    'js.groups.err_load' => 'Erreur de chargement.',
    'js.groups.empty_members' => 'Aucun serveur ne correspond.',
    'js.groups.confirm_run' => 'Lancer ":action" sur tous les membres du groupe ?',
    'js.groups.queued' => ':n serveur(s) en file - suivi dans le centre de taches.',
    'js.groups.err_run' => 'Echec du lancement de l\'action.',
    'js.groups.confirm_delete' => 'Supprimer le groupe ":name" ?',
    'js.groups.deleted' => 'Groupe supprime.',
    'js.groups.err_name' => 'Le nom est requis.',
    'js.groups.saved' => 'Groupe enregistre.',
    'js.groups.err_save' => 'Echec de l\'enregistrement.',
];
