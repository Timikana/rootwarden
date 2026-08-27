<?php

/**
 * Gestion des services systemd — sous-lot S1.
 *
 * ATTENTION. Ce module porte E-149 : les huit routes backend n'ont ni role ni
 * permission, et `can_manage_services` ne protege que l'ecran. Le portage ne
 * peut pas le refermer seul — voir `App\Services\ServicesSystemd`.
 *
 * Aucun texte de cette page ne doit laisser croire qu'un geste est verifie
 * ailleurs qu'ou il l'est reellement.
 */

return [
    'titre' => 'Gestion des services',
    'intro' => 'Démarrer, arrêter et surveiller les services systemd de vos machines. Chaque geste porte sur une machine à la fois, et se confirme avant de partir.',
    'serveur' => 'Machine cible',
    'choisir_serveur' => 'Choisissez une machine, puis chargez ses services.',
    'charger' => 'Charger les services',
    'sensible' => 'Production',
    'sensible_aide' => 'Arrêter un service sur cette machine interrompt un service en production.',
    'avert_titre' => 'Une machine de production figure dans cette liste',
    'avert_un' => 'Une des :total machines proposées est en production ou marquée critique. Elle est signalée dans le choix.',
    'avert_plusieurs' => ':nb des :total machines proposées sont en production ou marquées critiques.',
    'sensible_confirmer' => 'Cette machine est en production. Charger ses services ne modifie rien — mais les gestes suivants, si.',
    'filtres' => 'Filtrer',
    'filtre_etat' => 'État',
    'filtre_categorie' => 'Catégorie',
    'recherche' => 'Rechercher un service',
    'filtres_inactifs' => 'Les filtres s\'activeront une fois les services chargés.',
    'chargement' => 'Lecture des services sur la machine…',
    'echec' => 'Les services n\'ont pas pu être lus. La machine est-elle joignable ?',
    'aucun_service' => 'Cette machine n\'expose aucun service systemd lisible.',
    'journaux' => 'Journal des gestes',
    'journaux_vides' => 'Aucun geste effectué depuis l\'ouverture de cette page.',
    'vide_titre' => 'Aucune machine au parc',
    'vide_texte' => 'Aucune machine active n\'est enregistrée. Ajoutez-en depuis l\'administration des serveurs.',
    'vide_action' => 'Ouvrir les serveurs',
    'col_service' => 'Service',
    'col_etat' => 'État',
    'col_active' => 'Activé au démarrage',
    'col_categorie' => 'Catégorie',
    'col_description' => 'Description',
    'etat_actif' => 'en marche',
    'etat_arrete' => 'arrêté',
    'etat_echoue' => 'en échec',
    'active_oui' => 'oui',
    'active_non' => 'non',
    'protege' => 'protégé',
    'protege_aide' => 'Ce service ne peut être ni arrêté ni redémarré depuis cette page : le backend refuse le geste, il n\'est pas seulement masqué ici.',
    'charges' => ':nb services lus sur :machine.',
    'aucun_systemd' => 'Cette machine n\'a rendu aucun service. Elle n\'expose peut-être pas systemd — ce n\'est pas la même chose qu\'une énumération en échec, qui l\'aurait dit.',
    'filtres_actifs' => 'Filtrez la liste ci-dessous.',
    'filtre_tous' => 'Tous',
    'aucun_resultat' => 'Aucun service ne correspond à ce filtre.',
    'resultat_compte' => ':visibles services affichés sur :total.',

    'journal_lu' => 'Lecture de :machine : :nb service(s).',

    'non_porte_titre' => 'Les gestes sur les services ne sont pas encore portés',
    'non_porte_texte' => 'Lister, démarrer, arrêter et redémarrer un service se font pour l\'instant depuis l\'ancien portail. Cette page porte l\'inventaire et les accès ; les gestes suivent.',
    'non_porte_lien' => 'Ouvrir la gestion des services dans l\'ancien portail',
];
