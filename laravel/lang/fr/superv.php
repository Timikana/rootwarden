<?php

/*
 * Module `supervision/` — sous-lot V1 : la page et ses quatre onglets.
 *
 * TOUT CE QUE LE SCRIPT AFFICHE EST ICI, dans le meme fichier que ce que la page
 * affiche. C'est la reponse a la dette du legacy : la-bas, le JS lit ses libelles
 * dans un second catalogue (`js.php`) ou onze cles du module manquent, et
 * `head.php` rend alors la CLE elle-meme a l'ecran — `editor_select_server`.
 * Comme une cle est une chaine non vide, `__('x') || 'repli'` ne replie jamais :
 * la panne est silencieuse. Un seul catalogue, et elle ne peut plus se reformer.
 */

return [
    'titre' => 'Supervision',
    'sous_titre' => 'Deploiement et configuration des agents de supervision',
    'description' => "Cette page rassemble la configuration des agents, le catalogue de profils, le deploiement sur le parc et l'edition du fichier de configuration distant.",

    'plateforme' => 'Plateforme',

    'onglet_config' => 'Configuration globale',
    'onglet_profiles' => 'Profils',
    'onglet_deploy' => 'Deploiement agents',
    'onglet_editor' => 'Editeur de configuration',

    'config_titre' => 'Configuration du modele d\'agent',
    'config_description' => 'Ces parametres servent de modele a tous les deploiements. Chaque serveur peut porter ses propres valeurs.',

    'profils_titre' => 'Profils de supervision',
    'profils_description' => "Reglages reutilisables (metadonnees d'hote, serveur, mandataire). Le catalogue est ecrit une fois, puis chaque serveur est rattache a un profil.",

    'deploiement_titre' => 'Deploiement des agents',
    'deploiement_description' => 'Installation, reconfiguration et desinstallation de l\'agent sur les serveurs du parc.',

    'editeur_titre' => 'Editeur de configuration distante',
    'editeur_description' => "Lire, modifier et enregistrer le fichier de configuration de l'agent sur un serveur.",
    'editeur_serveur' => 'Serveur',
    'editeur_choisir_serveur' => 'Choisir un serveur',
    'editeur_lire' => 'Lire la configuration',
    // LE GARDE QUE V1 FERME. Cote legacy, ce message est la cle
    // `editor_select_server` affichee telle quelle, en clair, dans une boite.
    'editeur_sans_serveur' => 'Choisissez d\'abord un serveur : sans serveur, il n\'y a aucune configuration a lire.',

    'aucune_machine' => 'Aucun serveur dans le parc',
    'aucune_machine_aide' => 'Toutes les machines sont archivees, ou le parc est vide.',

    // Ce que V1 ne porte pas encore le DIT, plutot que de laisser un panneau nu.
    // Le titre de l'etat vide ne REPETE pas celui du panneau : vu a l'image, le
    // meme intitule deux fois de suite se lit comme un defaut d'affichage.
    'pas_encore_porte' => 'Pas encore porte sur ce portail',
    'a_venir_config' => 'La lecture et l\'enregistrement de cette configuration arrivent avec les sous-lots suivants. En attendant, ils restent sur l\'ancien portail.',
    'a_venir_profils' => 'Le catalogue de profils et son assignation arrivent avec les sous-lots suivants. En attendant, ils restent sur l\'ancien portail.',
    'a_venir_deploiement' => "Le tableau du parc et les actions de deploiement arrivent avec les sous-lots suivants : elles joignent les serveurs en SSH et modifient leur configuration, elles ne se portent pas a la legere. En attendant, elles restent sur l'ancien portail.",
    'a_venir_editeur' => 'La lecture et l\'ecriture du fichier distant arrivent avec les sous-lots suivants. En attendant, elles restent sur l\'ancien portail.',
    'vers_legacy' => 'Ouvrir sur l\'ancien portail',
];
