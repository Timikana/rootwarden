<?php

/**
 * Deploiement du `.bashrc` standardise — sous-lot B1.
 *
 * Ce module n'a AUCUN defaut de securite (voir `MODULE-BASHRC.md` §3). Les trois
 * corrections du portage sont de PRESENTATION, et ces textes en portent deux :
 * distinguer la machine de production, et enoncer un compteur a zero plutot que
 * de l'afficher comme un chiffre.
 */

return [
    'titre'       => 'Deploiement du .bashrc',
    'intro'       => 'Cette page installe un fichier `.bashrc` standardise sur les comptes des '
                     . 'machines que vous choisissez. Ce fichier s\'execute a CHAQUE connexion de '
                     . 'ces comptes.',
    'onglet_deploiement' => 'Deploiement',
    'onglet_historique'  => 'Historique',
    'onglet_gabarit'     => 'Gabarit',

    // ── LE PARC ────────────────────────────────────────────────────────────
    'machines'        => 'Machines cibles',
    'col_nom'         => 'Machine',
    'col_ip'          => 'Adresse',
    'col_etat'        => 'Dernier deploiement',
    'jamais'          => 'jamais deploye',
    'simule_le'       => 'simule le :date par :auteur — rien n\'a ete ecrit',
    'deploye_le'      => 'deploye le :date par :auteur',

    // ── LA MACHINE SENSIBLE, QUI NE DOIT PAS SE FONDRE DANS LA LISTE ──────
    'sensible'        => 'Production',
    'sensible_titre'  => 'Machine de production ou critique',
    'sensible_aide'   => 'Un deploiement sur cette machine remplace le `.bashrc` des comptes '
                         . 'choisis, y compris celui de `root` s\'il est retenu.',
    'avert_titre'     => 'Une machine de production figure dans cette liste',
    'avert_un'        => 'Une des :total machines proposees est en production ou marquee critique. '
                         . 'Elle est signalee dans le tableau.',
    'avert_plusieurs' => ':nb des :total machines proposees sont en production ou marquees '
                         . 'critiques. Elles sont signalees dans le tableau.',

    // ── LE COMPTEUR, QUI S'ENONCE ──────────────────────────────────────────
    'aucune_selection' => 'Aucune machine selectionnee — un deploiement ne deploierait rien.',
    'selection_une'    => '1 machine selectionnee.',
    'selection_n'      => ':nb machines selectionnees.',
    'selection_prod'   => ':nb machines selectionnees, dont :prod en production.',

    'vide_titre'  => 'Aucune machine au parc',
    'vide_texte'  => 'Aucune machine active n\'est enregistree. Ajoutez-en depuis '
                     . 'l\'administration des serveurs avant de deployer quoi que ce soit.',
    'vide_action' => 'Ouvrir les serveurs',

    'comptes_titre' => 'Comptes de la machine',
    'comptes_choisir' => 'Cochez une machine ci-dessus pour lire ses comptes.',
    'comptes_plusieurs' => 'Plusieurs machines sont cochees. Les comptes se lisent machine par machine : n\'en cochez qu\'une.',
    'comptes_chargement' => 'Lecture des comptes sur la machine…',
    'comptes_echec' => 'Les comptes n\'ont pas pu etre lus. La machine est-elle joignable ?',
    'comptes_aucun' => 'Cette machine n\'expose aucun compte eligible (UID 0 ou >= 1000, avec un interpreteur).',
    'col_compte' => 'Compte',
    'col_uid' => 'UID',
    'col_home' => 'Dossier personnel',
    'col_bashrc' => 'Fichier actuel',
    'bashrc_absent' => 'absent',
    'tout' => 'Tout cocher',
    'tout_avec_root' => '« Tout cocher » retient aussi root.',
    'compte_root' => 'administrateur',
    'compte_root_aide' => 'Le compte administrateur de la machine. Deployer sur root remplace le fichier qui s\'execute a chaque connexion administrateur.',
    'apercu' => 'Apercu (diff)',
    'apercu_aide' => 'Lit le fichier present sur la machine et montre ce qui changerait. N\'ecrit rien.',
    'apercu_titre' => 'Ce qui changerait',
    'apercu_chargement' => 'Lecture du fichier distant…',
    'apercu_echec' => 'L\'apercu n\'a pas pu etre construit.',
    'apercu_vide' => 'Cochez au moins un compte pour voir ce qui changerait.',
    'apercu_taille' => ':avant o → :apres o',

    'perso' => 'personnalise',
    'perso_aide' => 'Ce compte a des blocs marques « USER CUSTOM » dans son fichier. En mode « fusionner », ce sont les SEULS qui seront conserves ; tout le reste sera remplace.',

    'gabarit_titre' => 'Le gabarit deploye',
    'gabarit_intro' => 'Ce fichier est celui que toutes les machines recevront au prochain deploiement. Il s\'execute a chaque connexion des comptes concernes.',
    'gabarit_lignes' => 'Lignes',
    'gabarit_octets' => 'Octets',
    'gabarit_sha' => 'Empreinte',
    'gabarit_chargement' => 'Lecture du gabarit…',
    'gabarit_echec' => 'Le gabarit n\'a pas pu etre lu.',
    'gabarit_modifie' => 'Modifications non enregistrees.',
    'gabarit_enregistrer' => 'Enregistrer',
    'gabarit_annuler' => 'Annuler les modifications',
    'gabarit_enregistre' => 'Gabarit enregistre.',
    'gabarit_erreur' => 'L\'enregistrement a echoue.',
    'gabarit_encours' => 'Enregistrement…',
    'gabarit_confirmer' => 'Enregistrer ce gabarit ? Toutes les machines le recevront au prochain deploiement.',
    'danger_titre' => 'Formes reconnues comme destructrices',
    'danger_reconnu' => 'Reconnu :',
    'danger_portee' => 'Cette reconnaissance porte sur huit formes connues. Elle ne verifie ni ce que fait le reste du fichier, ni ce que fera celui-ci une fois deploye — seule sa syntaxe sera controlee a l\'enregistrement.',
    'danger_confirmer' => 'Ce gabarit contient des formes reconnues comme destructrices. L\'enregistrer quand meme ?',

    'non_porte_titre' => 'Les gestes de deploiement ne sont pas encore portes',
    'non_porte_texte' => 'Choisir les comptes, previsualiser le fichier et le deployer se font pour '
                         . 'l\'instant depuis l\'ancien portail. Cette page porte l\'inventaire et '
                         . 'les acces ; les gestes suivent.',
    'non_porte_lien'  => 'Ouvrir le deploiement dans l\'ancien portail',
];
