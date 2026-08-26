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

    'non_porte_titre' => 'Les gestes de deploiement ne sont pas encore portes',
    'non_porte_texte' => 'Choisir les comptes, previsualiser le fichier et le deployer se font pour '
                         . 'l\'instant depuis l\'ancien portail. Cette page porte l\'inventaire et '
                         . 'les acces ; les gestes suivent.',
    'non_porte_lien'  => 'Ouvrir le deploiement dans l\'ancien portail',
];
