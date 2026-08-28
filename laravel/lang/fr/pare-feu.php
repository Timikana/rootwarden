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
    'suite' => 'Le relevé et la copie en base ne touchent aucune machine. La validation à blanc et l\'application des règles ne sont pas encore portées : elles restent sur l\'ancien portail.',
    'suite_lien' => 'Ouvrir le pare-feu sur l\'ancien portail',

    // ── I2 : la copie en base ───────────────────────────────────────────
    'copie_titre' => 'Copie enregistrée en base',
    'copie_intro' => 'Le portail peut garder une copie des règles d\'une machine, pour les retrouver plus tard. Enregistrer une copie NE la valide pas et NE l\'applique pas.',
    'copie_charger' => 'Charger la copie',
    'copie_enregistrer' => 'Enregistrer ces règles',
    'copie_absente' => 'Aucune copie enregistrée pour cette machine.',
    'copie_le' => 'Copie enregistrée le :date',
    'copie_enregistree' => 'Copie enregistrée pour :machine. Elle n\'a été ni validée, ni appliquée.',
    'copie_rien_a_enregistrer' => 'Relevez d\'abord les règles : il n\'y a rien à enregistrer.',
    'copie_v4_vide' => 'Les règles IPv4 sont vides. Une copie vide serait refusée au moment de la restaurer : elle n\'est donc pas enregistrée.',
    'copie_trop_grande' => 'Les règles dépassent la taille que la colonne peut contenir (:max octets). Rien n\'a été enregistré.',
    'champs_manquants' => 'Requête incomplète : les deux jeux de règles sont attendus, même vides.',
    'machine_refusee' => 'Machine inconnue ou hors de votre périmètre.',
    'copie_lignes_multiples' => 'Attention : :nb copies existent pour cette machine. La plus récente est affichée.',
    'copie_bloc_v4' => 'Copie IPv4',
    'copie_bloc_v6' => 'Copie IPv6',

    // ── I3 : l'historique des versions archivées ────────────────────────
    'histo_titre' => 'Versions archivées',
    'histo_intro' => 'Chaque application de règles archive celles qu\'elle remplace. Une version vide n\'est jamais archivée : toutes celles listées ici sont restaurables.',
    'histo_chargement' => 'Lecture de l\'historique…',
    'histo_vide_titre' => 'Aucune version archivée',
    'histo_vide' => 'Aucune application de règles n\'a encore eu lieu sur cette machine depuis ce portail. Il n\'y a donc rien à restaurer.',
    'histo_echec_titre' => 'Historique illisible',
    'histo_echec' => 'L\'historique n\'a pas pu être lu. Ce n\'est pas la même chose qu\'un historique vide : ne concluez pas qu\'il n\'y a rien à restaurer.',
    'histo_tout' => ':nb version(s) archivée(s).',
    'histo_tronque' => 'Les :affichees plus récentes, sur :total au total.',
    'histo_col_date' => 'Archivée le',
    'histo_col_auteur' => 'Par',
    'histo_col_motif' => 'Motif',
    'histo_auteur_inconnu' => 'Auteur non enregistré',
    'histo_auteur_supprime' => 'Compte supprimé (n° :id)',
    'histo_sans_motif' => 'Aucun motif indiqué',

    // ── I4 : la validation à blanc ──────────────────────────────────────
    'valid_titre' => 'Validation à blanc',
    'valid_intro' => 'Le serveur peut vérifier qu\'un jeu de règles est syntaxiquement applicable, sans l\'appliquer.',
    'valid_bouton' => 'Valider la copie à blanc',
    'valid_avant' => 'Ce contrôle OUVRE une session SSH sur la machine et y écrit un fichier temporaire. Il ne modifie aucune table du pare-feu.',
    'valid_limite' => 'La validation ne porte QUE sur les règles IPv4. Une copie dont l\'IPv6 est mal formé passerait ce contrôle et échouerait à l\'application.',
    'valid_v4_vide' => 'Cette copie ne porte aucune règle IPv4. Il n\'y a rien à valider : la validation ne connaît que l\'IPv4, et refuse une copie vide.',
    'valid_sans_copie' => 'Chargez d\'abord la copie en base : c\'est elle qui est validée.',
    'valid_en_cours' => 'Validation en cours sur la machine…',
    'valid_ok' => 'Le serveur déclare ces règles applicables.',
    'valid_invalide_court' => 'Le serveur declare ces regles invalides — verdict a relire ci-dessous.',
    'valid_invalide_titre' => 'Déclarées invalides — verdict à relire',
    'valid_invalide' => 'Le serveur déclare ces règles invalides. Ce verdict N\'EST PAS FIABLE sur une sortie longue : la détection du code de sortie le cherche dans des fragments de 4096 octets, et un jeu de règles VALIDE peut être déclaré invalide lorsque le marqueur tombe à cheval. Lisez la sortie avant de conclure.',
    'valid_echec_titre' => 'Contrôle non abouti',
    'valid_echec' => 'Le contrôle n\'a pas abouti. Ce n\'est ni « valide » ni « invalide » : rien n\'a été vérifié.',
    'valid_sortie' => 'Sortie du serveur',
];
