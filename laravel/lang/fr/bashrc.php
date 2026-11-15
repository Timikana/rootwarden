<?php

/**
 * Deploiement du `.bashrc` standardise.
 *
 * Regles de redaction : docs/REDACTION-INTERFACE.md. La machine de production
 * reste signalee, et un compteur a zero s'enonce plutot que de s'afficher comme
 * un chiffre.
 *
 * Les textes lus par le JS voyagent par le bloc `$textes` du controleur : une
 * cle ajoutee ici pour le JS doit y etre ajoutee aussi.
 */

return [
    'titre'       => 'Déploiement du .bashrc',
    'intro'       => 'Installe un `.bashrc` standardisé sur les comptes choisis ; il s\'exécute à chaque connexion.',
    'onglet_deploiement' => 'Déploiement',
    'onglet_historique'  => 'Historique',
    'onglet_gabarit'     => 'Gabarit',

    // ── LE PARC ────────────────────────────────────────────────────────────
    'machines'        => 'Machines cibles',
    'col_nom'         => 'Machine',
    'col_ip'          => 'Adresse',
    'col_etat'        => 'Dernier déploiement',
    'jamais'          => 'jamais déployé',
    'simule_le'       => 'simulé le :date par :auteur, rien n\'a été écrit',
    'deploye_le'      => 'déployé le :date par :auteur',

    // ── LA MACHINE SENSIBLE ────────────────────────────────────────────────
    'sensible'        => 'Production',
    'sensible_aide'   => 'Un déploiement remplace le `.bashrc` des comptes choisis, y compris celui de `root` s\'il est coché.',
    'avert_titre'     => 'Cette liste contient de la production',
    'avert_un'        => 'Une des :total machines est en production ou critique ; elle est signalée dans le tableau.',
    'avert_plusieurs' => ':nb des :total machines sont en production ou critiques ; elles sont signalées dans le tableau.',

    // ── LE COMPTEUR, QUI S'ENONCE ──────────────────────────────────────────
    'aucune_selection' => 'Aucune machine sélectionnée.',
    'selection_une'    => '1 machine sélectionnée.',
    'selection_n'      => ':nb machines sélectionnées.',
    'selection_prod'   => ':nb machines sélectionnées, dont :prod en production.',

    'vide_titre'  => 'Aucune machine au parc',
    'vide_texte'  => 'Ajoutez une machine depuis la page Serveurs.',
    'vide_action' => 'Ouvrir les serveurs',

    'comptes_titre' => 'Comptes de la machine',
    'comptes_choisir' => 'Cochez une machine pour lire ses comptes.',
    'comptes_plusieurs' => 'Cochez une seule machine pour lire ses comptes.',
    'comptes_chargement' => 'Lecture des comptes…',
    'comptes_echec' => 'Impossible de lire les comptes. Vérifiez que la machine est joignable.',
    'comptes_aucun' => 'Aucun compte éligible (UID 0 ou ≥ 1000, avec un interpréteur).',
    'col_compte' => 'Compte',
    'col_uid' => 'UID',
    'col_home' => 'Dossier personnel',
    'col_bashrc' => 'Fichier actuel',
    'bashrc_absent' => 'absent',
    'tout' => 'Tout cocher',
    'tout_avec_root' => '(root compris)',
    'compte_root' => 'administrateur',
    'compte_root_aide' => 'Compte administrateur : son .bashrc s\'exécute à chaque connexion root.',
    'apercu' => 'Aperçu (diff)',
    'apercu_aide' => 'Montre ce qui changerait, sans rien écrire.',
    'apercu_titre' => 'Ce qui changerait',
    'apercu_chargement' => 'Lecture du fichier distant…',
    'apercu_echec' => 'Impossible de construire l\'aperçu.',
    'apercu_vide' => 'Cochez au moins un compte pour voir ce qui changerait.',
    'apercu_taille' => ':avant o → :apres o',

    'perso' => 'personnalisé',
    'perso_aide' => 'Seuls les blocs « USER CUSTOM » sont conservés (dans ~/.bashrc.local) ; le reste du fichier est remplacé.',

    'gabarit_titre' => 'Le gabarit déployé',
    'gabarit_intro' => 'Toutes les machines recevront ce fichier au prochain déploiement.',
    'gabarit_lignes' => 'Lignes',
    'gabarit_octets' => 'Octets',
    'gabarit_sha' => 'Empreinte',
    'gabarit_chargement' => 'Lecture du gabarit…',
    'gabarit_echec' => 'Impossible de lire le gabarit.',
    'gabarit_modifie' => 'Modifications non enregistrées.',
    'gabarit_enregistrer' => 'Enregistrer',
    'gabarit_annuler' => 'Annuler les modifications',
    'gabarit_enregistre' => 'Gabarit enregistré.',
    'gabarit_erreur' => 'L\'enregistrement a échoué.',
    'gabarit_encours' => 'Enregistrement…',
    'gabarit_confirmer' => 'Enregistrer ce gabarit ? Toutes les machines le recevront au prochain déploiement.',
    'danger_titre' => 'Formes reconnues comme destructrices',
    'danger_reconnu' => 'Reconnu :',
    'danger_portee' => 'Seules huit formes connues sont détectées ; à l\'enregistrement, seule la syntaxe est vérifiée.',
    'danger_confirmer' => 'Ce gabarit contient des formes reconnues comme destructrices. L\'enregistrer quand même ?',

    // ── LES ECRITURES ──────────────────────────────────────────────────────
    'col_action' => 'Action',
    'deploy' => 'Déployer',
    'deploy_aide' => 'Écrit le .bashrc standardisé sur les comptes cochés, après une sauvegarde horodatée de l\'ancien.',
    'deploy_confirme' => "Déployer le .bashrc standardisé sur :nombre compte(s) : :comptes ?\n\nL'ancien fichier est sauvegardé ; les blocs « USER CUSTOM » sont déplacés dans ~/.bashrc.local.",
    'deploy_en_cours' => 'Déploiement en cours…',
    'deploy_fait' => 'Déploiement terminé.',
    'deploy_echec' => 'Le déploiement a échoué. Le .bashrc distant n\'a pas été remplacé.',
    'deploy_sans_cible' => 'Choisissez une machine et au moins un compte.',
    'restore' => 'Restaurer',
    'restore_aide' => 'Restaure la sauvegarde la plus récente de ce compte.',
    // Le JS ne remplace que la PREMIERE occurrence de chaque marqueur.
    'restore_confirme' => "Restaurer :sauvegarde pour :compte ?\n\nDatée du :date, :taille octets ; la plus récente des :nombre sauvegarde(s).\n\nLe .bashrc actuel sera remplacé.",
    'restore_en_cours' => 'Restauration de :compte…',
    'restore_fait' => 'Sauvegarde restaurée pour :compte.',
    'restore_echec' => 'La restauration de :compte a échoué.',
    'figlet_absent' => 'figlet n\'est pas installé : la bannière du .bashrc ne s\'affichera pas. Le reste fonctionne.',

    'restore_lecture' => 'Lecture des sauvegardes de :compte…',
    'restore_aucune' => 'Aucune sauvegarde pour :compte : rien à restaurer.',

    // ── L'INSTALLATION DE figlet ───────────────────────────────────────────
    'figlet_installer' => "Installer figlet",
    'figlet_confirme' => "Installer figlet sur cette machine ?\n\nLe paquet sera installé par le gestionnaire de paquets. Cette page ne permet pas de le désinstaller.",
    'figlet_en_cours' => "Installation de figlet…",
    'figlet_fait' => "figlet est installé.",
    'figlet_echec' => "L'installation de figlet a échoué.",

];
