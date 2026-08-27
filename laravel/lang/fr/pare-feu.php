<?php

/**
 * Pare-feu iptables — sous-lot I1.
 *
 * L'en-tete du legacy annonce « superadmin (role_id = 3) uniquement — accès
 * refusé à tous les autres rôles », deux fois, alors que sa garde admet le
 * rôle 1 (motif E-36, quatrième occurrence). Aucun texte de cette page ne doit
 * annoncer un accès plus strict que celui qui est appliqué.
 *
 * Et aucun ne doit laisser croire que `can_manage_iptables` protège les GESTES :
 * sur les 23 routes des deux modules de filtrage, deux seulement la vérifiaient
 * avant le correctif d'E-152. Elle protège l'écran.
 */

return [
    'titre' => 'Pare-feu',
    'intro' => 'Le pare-feu iptables décide quelles connexions une machine accepte. Cette page relève les règles actuellement en vigueur, sans rien modifier.',

    // ── Le choix de la machine ──────────────────────────────────────────
    'serveur' => 'Machine',
    'choisir' => 'Choisissez une machine, puis relevez ses règles.',
    'relever' => 'Relever les règles',
    'aucune_machine_choisie' => 'Choisissez d\'abord une machine.',
    'machines_aucune_titre' => 'Aucune machine ne vous est accessible',
    'machines_aucune' => 'Cette page ne propose que les machines auxquelles votre compte a accès. Demandez un accès à un administrateur.',

    // ── Ce que la page annonce AVANT le geste ───────────────────────────
    'sensible' => 'Production',
    'sensible_avert' => 'Cette machine est en production ou marquée critique. Relever ses règles ne les modifie pas — mais c\'est sur elle que porteront les gestes suivants.',
    'avert_titre' => 'Une machine de production figure dans cette liste',
    'avert_un' => 'Une des :total machines proposées est en production ou marquée critique.',
    'avert_plusieurs' => ':nb des :total machines proposées sont en production ou marquées critiques.',

    /*
     * Le port SSH est annoncé au moment du choix, et il vient de la BASE.
     * Les gabarits de règles du legacy supposent 22 ; les trois machines du parc
     * écoutent sur 22, donc le défaut n'est pas armé — et c'est ce qui le rend
     * invisible. L'annoncer maintenant, c'est refuser de le reproduire plus tard.
     */
    'port_ssh_annonce' => 'Accès SSH de cette machine : port :port. Un jeu de règles qui ne laisse pas ce port ouvert couperait l\'accès, y compris celui de RootWarden.',

    // ── Le relevé ───────────────────────────────────────────────────────
    'chargement' => 'Lecture des règles sur la machine…',
    'releve_ok' => 'Règles relevées sur :machine.',
    'releve_le' => 'Relevé le :date',
    'echec' => 'Les règles n\'ont pas pu être lues. La machine est-elle joignable ?',
    'echec_reseau' => 'La requête n\'a pas abouti. Ni succès, ni refus : rien n\'a été lu.',

    // ── Les quatre blocs ────────────────────────────────────────────────
    'bloc_actives_v4' => 'Règles actives (IPv4)',
    'bloc_actives_v6' => 'Règles actives (IPv6)',
    'bloc_fichier_v4' => 'Fichier rules.v4',
    'bloc_fichier_v6' => 'Fichier rules.v6',

    /*
     * Trois issues, pas deux : la lecture échoue, le fichier est absent, le
     * fichier existe et il est vide. Le legacy n'en distingue aucune — il pose
     * la réponse dans un bloc et le marqueur fabriqué par le shell y devient le
     * contenu du fichier (même défaut qu'E-161 sur fail2ban).
     */
    'bloc_vide_titre' => 'Aucune règle',
    'bloc_vide' => 'La machine n\'applique aucune règle sur cette pile. Tout est accepté par défaut.',
    'fichier_absent_titre' => 'Fichier absent',
    'fichier_absent' => 'Ce fichier n\'existe pas sur la machine. Les règles actives ne seront donc pas rétablies au redémarrage.',

    // ── Ce que I1 ne fait pas, dit à l'écran plutôt qu'absent en silence ──
    'suite_titre' => 'Cette page ne modifie rien',
    'suite' => 'Le relevé est une lecture. La copie en base, la validation à blanc et l\'application des règles ne sont pas encore portées : elles restent sur l\'ancien portail.',
    'suite_lien' => 'Ouvrir le pare-feu sur l\'ancien portail',
];
