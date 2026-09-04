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

    /*
     * ══ A4 — LE RELEVE D'UN SERVEUR EST PORTE ═════════════════════════════
     *
     * `np_relever` est RETIREE. `np_relever_detail` NE BOUGE PAS : sa reserve
     * porte sur la CONNEXION, et elle reste vraie une fois l'ecran porte —
     * meme raison que `np_config_detail`, gardee parce qu'elle portait sur
     * l'ecriture.
     *
     * ⚠ MAIS ELLE EST INCOMPLETE, ET LA MESURE L'A MONTRE.
     *
     * « C'est une lecture, mais c'est une connexion » decrit ce que le geste
     * fait A LA MACHINE. Il fait aussi trois choses EN BASE
     * (`ssh_audit.py:143-165`) : `_save_audit_result` persiste un releve,
     * `_log_audit_action` ecrit au journal d'audit, et `notify_subscribed`
     * leve des notifications.
     *
     * ⚠ ET J'AI FAILLI ECRIRE QUE CE GESTE ENVOYAIT DES COURRIELS. Le mot
     * « notification » m'a fait supposer un canal sortant. Mesure :
     * `notify.py:122` filtre `np.channel IN ('inapp', 'both')`, et `notify.py`
     * ne contient AUCUNE occurrence de smtp, webhook, telegram ni slack.
     * **Ce sont des notifications EN BASE, rien ne sort.** Le dire faux aurait
     * fait renoncer a un geste sur — l'inverse exact du defaut qu'on corrige
     * d'habitude.
     *
     * `relever_ecrit` complete la reserve SANS la modifier : ce qui est garde
     * doit rester tel quel pour rester comparable.
     */
    'relever_ecrit' => "Le relevé est enregistré : il apparaît dans « Relevés précédents », il est inscrit au journal d'audit, et il lève des notifications dans le portail. Rien n'est envoyé à l'extérieur.",
    'relever_titre' => 'Relever ce serveur ?',
    'relever_lancer' => 'Relever maintenant',
    'relever_en_cours' => 'Relevé en cours…',
    'relever_sans_serveur' => 'Choisissez un serveur avant de le relever.',
    'relever_fait' => 'Relevé terminé : note :grade, score :score/100.',
    'relever_echec' => "Le relevé n'a pas abouti. :message",
    'relever_refus' => 'Le relevé a été refusé. :message',
    'np_relever_detail' => "Relever un serveur ouvre une session SSH réelle sur lui et lit sa configuration. C'est une lecture, mais c'est une connexion.",

    'np_parc' => "Le relevé de tout le parc n'est pas encore porté sur cette interface.",
    // ⚠ LE PANNEAU LE PLUS IMPORTANT DE LA PAGE.
    'np_parc_detail' => "Ce geste ouvre une session SSH sur CHAQUE machine non archivée du parc, production comprise. Il ne prend aucun paramètre : il n'y a rien à restreindre, et aucune façon de le viser ailleurs.",

    /*
     * ══ A3 — LA CONJONCTION EST SCINDEE, PAS RETIREE ══════════════════════
     *
     * Elle disait « l'affichage ET la modification ». A3 porte l'affichage :
     * la phrase devient donc a MOITIE fausse, et une moitie fausse se lit
     * comme entierement vraie. C'est la septieme forme du motif de la semaine
     * — apres `serveurs` (trois capacites, une portee) et `bashrc` (deux
     * portees declarees absentes), la conjonction est la plus discrete.
     *
     * `np_config_detail` NE BOUGE PAS : sa reserve porte sur l'ECRITURE, qui
     * reste absente, et elle reste vraie mot pour mot.
     */
    'np_config' => "La modification de `sshd_config` n'est pas encore portée sur cette interface.",

    // ══ A3 — L'AFFICHAGE, PORTE ═══════════════════════════════════════════
    //
    // ⚠ CE GESTE JOINT LA MACHINE. `POST /ssh-audit/config` ouvre une vraie
    // session SSH (`ssh_audit.py:372`) pour lire le fichier. C'est une
    // LECTURE — rien n'est ecrit, ni sur la machine ni en base — mais ce
    // n'est pas une lecture locale, et le panneau doit le dire AVANT le clic.
    'cfg_titre'    => 'Lire `sshd_config` sur ce serveur ?',
    'cfg_texte'    => "Cette lecture ouvre une session SSH réelle sur le serveur choisi. Elle n'écrit rien, ni sur la machine ni en base, et le fichier s'affiche ici en lecture seule.",
    'cfg_lire'     => 'Lire le fichier',
    'cfg_en_cours' => 'Lecture en cours…',
    'cfg_titre_resultat' => '`sshd_config` de :nom',
    'cfg_vide'     => 'Le serveur a répondu, mais le fichier est vide.',
    'cfg_echec'    => "Le fichier n'a pas pu être lu. :message",
    'cfg_refus'    => "La lecture a été refusée. :message",
    'cfg_sans_serveur' => 'Choisissez un serveur avant de lire sa configuration.',
    // La lecture seule se DIT, elle ne se devine pas d'une absence de bouton.
    'cfg_lecture_seule' => "Ce contenu est affiché en lecture seule : la modification de `sshd_config` n'est pas portée ici.",

    'np_config_detail' => "Écrire dans `sshd_config` et recharger le service peut couper l'accès SSH au serveur — et SSH est le seul canal dont RootWarden dispose pour y revenir. Une sauvegarde existe et la restauration est possible.",

    // ══ A2 — LA CREATION D'UN RELEVE PLANIFIE EST PORTEE ═══════════════════
    //
    // `np_planif_creer` est RETIREE : elle declarait une absence qui n'existe
    // plus. `np_planif_detail`, en revanche, NE BOUGE PAS — elle decrit la
    // consequence du geste, et c'est le texte du panneau de decision. Une
    // reserve qui dit ce qu'un geste engage sert autant quand le geste est
    // porte que quand il ne l'est pas.
    //
    // ⚠ CE QUI EST REDUIT, ET QUI EST DECLARE : le formulaire n'offre que
    // QUATRE frequences. Une expression cron arbitraire n'est pas saisissable
    // ici. Le legacy en offrait une, et la borne serveur (intervalle minimum
    // de dix minutes) la validait. Le choix est deliberé : une entree libre
    // validee se contourne par une requete forgee, une entree libre absente
    // non — et une cron est ce qui declenche des sessions SSH reelles sans
    // personne devant l'ecran. Qui a besoin d'une autre periodicite passe par
    // l'ancien portail, et la phrase ci-dessous le dit.
    'planif_freq_bornee' => "Quatre périodicités sont proposées. Une expression cron libre n'est pas saisissable ici : une planification déclenche des sessions SSH réelles sans personne devant l'écran, et une liste fermée ne se contourne pas par une requête forgée. Pour une autre périodicité, l'ancien portail reste ouvert.",

    'planif_form_titre' => 'Planifier un relevé',
    'planif_f_nom'      => 'Nom de la planification',
    'planif_f_nom_aide' => 'Ce nom identifie la planification dans la liste. 100 caractères au plus.',
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

    // ⚠ SANS VALEUR, UNE PORTEE RESTREINTE VISE TOUT LE PARC — E-280. La
    // garde serveur refuse desormais ce cas (400), et le formulaire ne le
    // propose pas : le bouton reste inerte tant que la portee n'est pas
    // complete. Le rempart est cote serveur ; ici c'est l'ergonomie.
    'planif_valeur_requise' => "Cette portée demande une valeur. Sans elle, la planification viserait tout le parc — y compris la production.",
    'planif_aucun_tag'      => "Aucun tag n'est porté par une machine du parc : cette portée n'a rien à viser.",
    'planif_aucune_machine'  => "Aucun serveur n'est visible depuis ce compte : cette portée n'a rien à viser.",
    'planif_nom_requis'      => 'Un nom est nécessaire.',
    'planif_creee'           => 'La planification « :nom » est enregistrée. Prochaine exécution : :quand.',
    'planif_echec'           => "La planification n'a pas pu être enregistrée. :message",
    'planif_conf_titre'      => 'Enregistrer cette planification ?',
    // ⚠ E-280 : ce que l'ancien portail ne dit pas au moment de planifier.
    'np_planif_detail' => "Une planification ouvre des sessions SSH réelles, à répétition, sans personne devant l'écran. Elle vise par défaut tout le parc, production comprise — et une cible restreinte dont le champ est resté blanc revient au même.",
];
