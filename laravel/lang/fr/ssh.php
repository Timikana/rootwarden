<?php

/*
 * Module `ssh/` — « Cles SSH ». Sous-lot K1 : la page nue.
 *
 * `serveurs_disponibles` porte un jeton `:nombre` REELLEMENT substitue. Le legacy
 * ecrit `count($machines)` puis `t('ssh.servers_available')`, dont la valeur est
 * « :count serveur(s) disponible(s) » : le jeton reste en clair a l'ecran.
 */

return [
    'titre' => 'Deploiement des cles SSH',
    'description' => "Selectionnez les serveurs sur lesquels deployer les cles publiques des comptes habilites. Le deploiement lui-meme reste sur l'ancien portail.",
    'serveurs_disponibles' => ':nombre serveur(s) disponible(s)',

    'aucun_serveur' => 'Aucun serveur accessible',
    'aucun_serveur_aide' => "Aucune machine ne vous est attribuee, ou toutes celles du parc sont archivees.",

    'filtre_tag' => 'Etiquette',
    'filtre_env' => 'Environnement',
    'tous_tags' => 'Toutes les etiquettes',
    'tous_envs' => 'Tous les environnements',
    'cocher_filtre' => 'Cocher le filtre',
    'cocher_tout' => 'Cocher tout',
    'decocher_tout' => 'Tout decocher',

    'aucune_selection' => 'Aucun serveur selectionne',
    'selection' => ':nombre serveur(s) selectionne(s)',

    'deployer' => 'Deployer les cles',
    'annuler' => 'Annuler',
    'confirmer_titre' => 'Deployer les cles SSH sur ces serveurs ?',
    'confirmer_avertissement' => "Sur chaque serveur coche, et en tant que root : le paquet sudo est installe s'il manque, les comptes habilites sont crees, leur fichier authorized_keys est REECRIT, et une politique sudoers est posee. Les cles de tout compte ayant perdu son habilitation sont REVOQUEES. Rien de tout cela n'est reversible depuis cette page.",
    'non_porte' => "Le declenchement du deploiement et la lecture de son journal ne sont pas encore portes.",
    'non_porte_lien' => "Les lancer depuis l'ancien portail",
];
