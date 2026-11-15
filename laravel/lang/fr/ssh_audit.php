<?php

/*
 * Audit de configuration SSH.
 *
 * Cles PLATES : le fichier part d'un bloc par `@json(__('ssh_audit'))`, et
 * Laravel espace deja par fichier. Le jeu de cles doit rester identique a
 * `lang/en/ssh_audit.php`. Redaction : docs/REDACTION-INTERFACE.md.
 */
return [
    'titre' => 'Audit de configuration SSH',
    'desc'  => "Relève la configuration du service SSH de vos serveurs, la note selon une politique et suit son évolution.",

    // ── Le selecteur, borne au perimetre ─────────────────────────────────
    'chargement' => 'Chargement…',
    'serveur_cible'   => 'Serveur',
    'serveur_choisir' => 'Choisissez un serveur…',
    'serveur_aucun'   => "Aucun serveur ne vous est attribué. Demandez l'accès à un administrateur.",
    'serveur_borne'   => "Vous ne voyez ici que les machines qui vous sont attribuées.",

    // ── L'historique ─────────────────────────────────────────────────────
    'historique_titre' => 'Relevés précédents',
    'historique_choisir' => 'Choisissez un serveur pour voir ses relevés précédents.',
    'historique_vide'  => "Aucun relevé n'a encore été fait sur ce serveur.",
    'historique_err'   => "Les relevés de ce serveur n'ont pas pu être lus.",
    'note'   => 'Note',
    'lettre' => 'Mention',
    'le'     => 'le',

    'sev_critique' => 'critiques',
    'sev_haute'    => 'hautes',
    'sev_moyenne'  => 'moyennes',
    'sev_basse'    => 'basses',

    // ── La flotte (administration) ───────────────────────────────────────
    'flotte_titre' => 'Dernier relevé de chaque serveur',
    'flotte_vide'  => "Aucun serveur n'a encore été relevé.",
    'flotte_err'   => "L'état de la flotte n'a pas pu être lu.",
    'reserve_admin' => "L'état de tout le parc et les relevés planifiés sont réservés aux administrateurs.",
    'th_serveur'   => 'Serveur',
    'th_ip'        => 'Adresse',
    'th_note'      => 'Note',
    'th_mention'   => 'Mention',
    'th_critiques' => 'Critiques',
    'th_releve_le' => 'Relevé le',

    // ── La politique, en lecture seule ───────────────────────────────────
    // L'ecriture n'est composee nulle part (SEC-013, voir AuditSshController).
    'politique_titre' => 'Politique appliquée à ce serveur',
    'politique_choisir' => 'Choisissez un serveur pour voir la politique qui lui est appliquée.',
    'politique_vide'  => "Aucune règle n'est définie pour ce serveur : la politique par défaut s'applique.",
    'politique_err'   => "La politique de ce serveur n'a pas pu être lue.",
    'politique_auditee' => 'auditée',
    'politique_ignoree' => 'ignorée',
    'politique_motif'   => 'Motif',
    'politique_lecture_seule' => "Lecture seule : la politique ne se modifie pas depuis le portail.",

    // ── Les planifications (administration) ──────────────────────────────
    'planifs_titre'   => 'Relevés planifiés',
    'planifs_vide'    => 'Aucun relevé planifié.',
    'planifs_err'     => "Les planifications n'ont pas pu être lues.",
    'planif_active'   => 'active',
    'planif_suspendue' => 'suspendue',
    'planif_prochaine' => 'Prochaine exécution',
    'planif_cible_parc' => 'tout le parc',
    'planif_cible_tag'  => 'tag : :valeur',
    'planif_cible_env'  => 'environnement : :valeur',
    'planif_cible_machines' => ':n serveur(s) désigné(s)',
    // Portee restreinte sans valeur : le planificateur l'ignore (scheduler.py,
    // branche `else` : WHERE 1=0).
    'planif_cible_inconnue' => "cible incomplète : ignorée à l'échéance",

    // ── Les boutons et le panneau de decision ────────────────────────────
    'btn_relever' => 'Relever ce serveur',
    'btn_config'  => 'Voir sshd_config',
    'btn_parc'    => 'Relever tout le parc',
    'btn_planif'  => 'Planifier un relevé',
    'np_titre'  => 'Non disponible sur ce portail',
    'np_fermer' => 'Fermer',
    'np_sur_serveur' => 'Serveur visé : :nom',

    'np_parc' => "Le relevé de tout le parc n'est pas disponible sur ce portail.",
    'np_parc_detail' => "Il ouvrirait une session SSH sur chaque machine non archivée, production comprise, sans possibilité de restreindre.",

    // ── Relever un serveur ───────────────────────────────────────────────
    'relever_titre' => 'Relever ce serveur ?',
    'np_relever_detail' => "Ouvre une session SSH sur le serveur pour lire sa configuration.",
    // Les notifications sont en base (notify.py, canal inapp) : rien ne sort.
    'relever_ecrit' => "Le résultat est enregistré dans l'historique et le journal d'audit, et notifié dans le portail.",
    'relever_lancer' => 'Relever maintenant',
    'relever_en_cours' => 'Relevé en cours…',
    'relever_sans_serveur' => 'Choisissez un serveur avant de le relever.',
    'relever_fait' => 'Relevé terminé : note :grade, score :score/100.',
    'relever_echec' => "Le relevé n'a pas abouti. :message",
    'relever_refus' => 'Le relevé a été refusé. :message',

    // ── Lire sshd_config ─────────────────────────────────────────────────
    'cfg_titre'    => 'Lire sshd_config sur ce serveur ?',
    'cfg_texte'    => "Ouvre une session SSH sur le serveur. Rien n'est écrit, ni sur la machine ni en base.",
    'cfg_lire'     => 'Lire le fichier',
    'cfg_en_cours' => 'Lecture en cours…',
    'cfg_titre_resultat' => 'sshd_config de :nom',
    'cfg_vide'     => 'Le serveur a répondu, mais le fichier est vide.',
    'cfg_echec'    => "Le fichier n'a pas pu être lu. :message",
    'cfg_refus'    => "La lecture a été refusée. :message",
    'cfg_sans_serveur' => 'Choisissez un serveur avant de lire sa configuration.',
    'cfg_lecture_seule' => "Lecture seule : sshd_config ne se modifie pas depuis le portail.",

    // ── Planifier un releve ──────────────────────────────────────────────
    'planif_form_titre' => 'Planifier un relevé',
    'planif_f_nom'      => 'Nom de la planification',
    'planif_f_nom_aide' => '100 caractères au plus.',
    'planif_f_freq'     => 'Périodicité',
    'planif_f_portee'   => 'Sur quoi le relevé porte',
    'planif_f_valeur'   => 'Valeur de la portée',
    'planif_freq_horaire'    => 'Toutes les heures',
    'planif_freq_six_heures' => 'Toutes les six heures',
    'planif_freq_quotidien'  => 'Chaque jour à 02:00',
    'planif_freq_hebdo'      => 'Chaque lundi à 03:00',
    'planif_portee_environment' => 'Un environnement',
    'planif_portee_tag'         => 'Un tag',
    'planif_portee_machines'    => 'Des serveurs désignés',
    'planif_valider'    => 'Enregistrer la planification',
    'planif_annuler'    => 'Annuler',

    'planif_valeur_requise' => "Choisissez une valeur pour cette portée.",
    'planif_aucun_tag'      => "Aucune machine du parc ne porte de tag.",
    'planif_aucune_machine'  => "Aucun serveur n'est visible depuis ce compte.",
    'planif_nom_requis'      => 'Un nom est nécessaire.',
    'planif_creee'           => 'La planification « :nom » est enregistrée. Prochaine exécution : :quand.',
    'planif_echec'           => "La planification n'a pas pu être enregistrée. :message",
    'planif_conf_titre'      => 'Enregistrer cette planification ?',
    'np_planif_detail' => "À chaque échéance, la planification ouvre des sessions SSH sur les machines de sa portée, sans confirmation.",

    // ── Suspendre, reactiver, supprimer ──────────────────────────────────
    // `toggle` inverse l'etat sans le poser, et `DELETE` ne verifie pas
    // `rowcount` : la liste RELUE fait foi, pas le message.
    'planif_suppr_titre'   => 'Supprimer cette planification',
    'planif_suppr_texte'   => "La planification est supprimée définitivement. Aucune machine n'est jointe.",
    'planif_suppr_court'   => 'Supprimer',
    'planif_suppr_valider' => 'Supprimer la planification',
    'planif_suppr_faite'   => 'Planification supprimée.',
    'planif_suppr_echec'   => 'La suppression a échoué : :message',

    'planif_suspendre'     => 'Suspendre',
    'planif_reactiver'     => 'Réactiver',
    'planif_bascule_faite' => "État modifié. La liste ci-dessous montre l'état obtenu.",
    'planif_bascule_echec' => "Le changement d'état a échoué : :message",
    'planif_bascule_aveugle' => "Ce bouton inverse l'état enregistré. Si quelqu'un l'a changé entre-temps, fiez-vous à la liste relue.",
    'planif_ce_qui_est_arme' => "À son échéance, cette planification relève en SSH les machines de sa portée, sans confirmation.",
    'planif_prochaine_le'    => 'Prochaine échéance :',
    'planif_aucune_echeance' => 'aucune échéance enregistrée',
];
