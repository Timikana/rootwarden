<?php

/*
 * Audit de configuration SSH — sous-lot A1.
 *
 * Cles PLATES : le fichier part d'un bloc par `@json(__('ssh_audit'))`, et
 * Laravel espace deja par fichier. Le jeu de cles doit rester identique a
 * `lang/en/ssh_audit.php`.
 *
 * A1 ne porte que la LECTURE en base : la politique, l'historique, la flotte,
 * les planifications. Les cles des gestes distants (`fix`, editeur,
 * sauvegardes) ne sont PAS portees ici — elles viendront avec A2 et A3.
 */
return [
    'titre' => 'Audit de configuration SSH',
    'desc'  => "Relève la configuration du service SSH de vos serveurs, la note contre une politique, et suit son évolution.",

    // ── LE SELECTEUR, BORNE COMME LE LEGACY ──────────────────────────────
    'chargement' => 'Chargement…',
    'serveur_cible'   => 'Serveur',
    'serveur_choisir' => 'Choisissez un serveur…',
    'serveur_aucun'   => "Aucun serveur ne vous est attribué. L'audit SSH porte sur les machines de votre périmètre, et il est vide.",
    'serveur_borne'   => "Vous ne voyez ici que les machines qui vous sont attribuées.",

    // ── L'HISTORIQUE — `GET /results`, borne au perimetre ────────────────
    'historique_titre' => 'Relevés précédents',
    'historique_vide'  => "Aucun relevé n'a encore été fait sur ce serveur.",
    'historique_err'   => "Les relevés de ce serveur n'ont pas pu être lus.",
    'note'   => 'Note',
    'lettre' => 'Mention',
    'le'     => 'le',

    'sev_critique' => 'critiques',
    'sev_haute'    => 'hautes',
    'sev_moyenne'  => 'moyennes',
    'sev_basse'    => 'basses',

    // ── LA FLOTTE — `GET /fleet`, reserve a l'administration ─────────────
    'flotte_titre' => 'Dernier relevé de chaque serveur',
    'flotte_vide'  => "Aucun serveur n'a encore été relevé.",
    'flotte_err'   => "L'état de la flotte n'a pas pu être lu.",
    'flotte_reserve' => "Cette vue porte sur tout le parc et n'est pas bornée à votre périmètre : elle est réservée à l'administration.",
    'th_serveur'   => 'Serveur',
    'th_ip'        => 'Adresse',
    'th_note'      => 'Note',
    'th_mention'   => 'Mention',
    'th_critiques' => 'Critiques',
    'th_releve_le' => 'Relevé le',

    // ── LA POLITIQUE — `GET /policies` SEUL ──────────────────────────────
    'politique_titre' => 'Politique appliquée à ce serveur',
    'politique_desc'  => "Chaque règle peut être auditée ou ignorée. Cette page les affiche ; elle ne les modifie pas.",
    'politique_choisir' => 'Choisissez un serveur pour voir la politique qui lui est appliquée.',
    'politique_vide'  => "Aucune règle n'est définie pour ce serveur : la politique par défaut s'applique.",
    'politique_err'   => "La politique de ce serveur n'a pas pu être lue.",
    'politique_auditee' => 'auditée',
    'politique_ignoree' => 'ignorée',
    'politique_motif'   => 'Motif',
    /*
     * ⚠ POURQUOI L'ECRITURE DE POLITIQUE N'EXISTE PAS SUR CETTE PAGE.
     * SEC-013 : `GET /ssh-audit/policies` exige `can_audit_ssh`, `POST` exige
     * `role(2)` SEUL. Un role 2 sans la permission ne peut donc pas LIRE une
     * politique et peut en ECRIRE une, sur n'importe quelle machine. Et la
     * passerelle ne peut pas separer les deux : elle compare des CHEMINS,
     * jamais des methodes. La fermeture se fait donc par l'ABSENCE d'appel.
     */
    'politique_lecture_seule' => "La modification de la politique n'est pas offerte ici, et ce n'est pas un oubli : sur l'ancien portail, l'écriture de politique est moins gardée que sa lecture. Tant que ce n'est pas corrigé côté serveur, cette page ne compose aucun appel qui l'écrirait.",

    // ── LES PLANIFICATIONS — reserve a l'administration ──────────────────
    'planifs_titre'   => 'Relevés planifiés',
    'planifs_vide'    => 'Aucun relevé planifié.',
    'planifs_err'     => "Les planifications n'ont pas pu être lues.",
    'planifs_reserve' => "Les relevés planifiés sont réservés à l'administration.",
    'planif_active'   => 'active',
    'planif_suspendue' => 'suspendue',
    'planif_prochaine' => 'Prochaine exécution',
    'planif_cible_parc' => 'tout le parc',
    'planif_cible_tag'  => 'tag : :valeur',
    'planif_cible_env'  => 'environnement : :valeur',
    'planif_cible_machines' => ':n serveur(s) désigné(s)',
    // ⚠ E-280 : une cible mal formee ou non reconnue tombe sur TOUT LE PARC.
    // E-280, corrige : `target_type` EST une liste fermee
    // (`enum('all','tag','environment','machines') NOT NULL`), donc une valeur
    // inventee est refusee par la base. Ce qui reste atteignable est une cible
    // INCOMPLETE : « par tag » dont le champ est reste blanc.
    'planif_cible_inconnue' => "cible incomplète — s'exécutera sur TOUT le parc",
    // E-280 : « tout le parc » et « je n'ai pas compris la cible » sont la MEME
    // branche du planificateur. Rien, ni a l'execution ni ensuite en base, ne
    // dit laquelle des deux a produit un relevé du parc entier.
    'planif_cible_ambigue' => "« Tout le parc » est à la fois un choix légitime et ce que produit une cible laissée incomplète — un tag dont le champ est resté blanc. Les deux passent par le même chemin, et rien, même après coup, ne permet de savoir laquelle a été employée.",

    // ── CE QUE LA PAGE DIT D'ELLE-MEME ───────────────────────────────────
    'portee_titre' => 'Ce que cette page peut faire aujourd’hui',
    'portee_texte' => "Elle lit : les relevés déjà faits, la politique appliquée, l'état de la flotte et les relevés planifiés. Elle ne joint aucune machine et n'écrit rien.",

    // ── LES CAPACITES NON PORTEES ────────────────────────────────────────
    /*
     * ── UN LIBELLE DE BOUTON N'EST PAS UNE PHRASE ────────────────────────
     * Le premier jet employait le message du panneau comme etiquette : le
     * bouton portait « Le releve de tout le parc n'est pas encore porte sur
     * cette interface. ». Un bouton dit ce qu'il FAIT ; l'explication vit
     * dans le panneau qu'il ouvre. Vu a l'image.
     */
    'btn_relever' => 'Relever ce serveur',
    'btn_config'  => 'Voir sshd_config',
    'btn_parc'    => 'Relever tout le parc',
    'btn_planif'  => 'Planifier un relevé',
    // Chaque section dit ce qui lui manque, avec SES mots : le premier jet
    // rendait le message de la politique sous le titre de l'historique.
    'historique_choisir' => 'Choisissez un serveur pour voir ses relevés précédents.',
    'np_titre'  => 'Pas encore porté',
    'np_ouvrir' => "Ouvrir dans l'ancien portail",
    'np_fermer' => 'Fermer',
    'np_sur_serveur' => 'Serveur visé : :nom',

    'np_relever' => "Le relevé d'un serveur n'est pas encore porté sur cette interface.",
    'np_relever_detail' => "Relever un serveur ouvre une session SSH réelle sur lui et lit sa configuration. C'est une lecture, mais c'est une connexion.",

    'np_parc' => "Le relevé de tout le parc n'est pas encore porté sur cette interface.",
    // ⚠ LE PANNEAU LE PLUS IMPORTANT DE LA PAGE.
    'np_parc_detail' => "Ce geste ouvre une session SSH sur CHAQUE machine non archivée du parc, production comprise. Il ne prend aucun paramètre : il n'y a rien à restreindre, et aucune façon de le viser ailleurs.",

    'np_config' => "L'affichage et la modification de `sshd_config` ne sont pas encore portés sur cette interface.",
    'np_config_detail' => "Écrire dans `sshd_config` et recharger le service peut couper l'accès SSH au serveur — et SSH est le seul canal dont RootWarden dispose pour y revenir. Une sauvegarde existe et la restauration est possible.",

    'np_planif_creer' => "La création d'un relevé planifié n'est pas encore portée sur cette interface.",
    // ⚠ E-280 : ce que l'ancien portail ne dit pas au moment de planifier.
    'np_planif_detail' => "Une planification ouvre des sessions SSH réelles, à répétition, sans personne devant l'écran. Elle vise par défaut tout le parc, production comprise — et une cible restreinte dont le champ est resté blanc revient au même.",
];
