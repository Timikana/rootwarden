<?php

/**
 * Les comptes distants — module `adm/`, sous-lot D8.
 *
 * PARITE STRICTE avec `lang/en/distants.php` : memes cles, dans le meme ordre.
 */
return [
    'title' => 'Comptes distants',
    'desc' => 'Les comptes système présents sur une machine du parc, tels que le dernier scan les a relevés. Cette page lit la base : elle ne joint la machine que si vous le lui demandez.',
    'champ_machine' => 'Machine',
    'btn_choisir' => 'Afficher',
    'scan_aide' => "Le scan ouvre une session SSH vers la machine, énumère ses comptes et met l'inventaire à jour. Il n'est jamais lancé au chargement de la page.",
    'btn_scanner' => 'Scanner la machine',
    'scan_en_cours' => 'Scan en cours…',
    'scan_fait' => "Scan terminé. Rechargez pour voir l'inventaire à jour.",
    'illisible_ligne' => "nom illisible : :motif",
    'illisible_classable' => "Le classer reste possible et c'est le seul geste qui debloque : classer est un changement de statut en base, il ne joint pas la machine.",
    'illisible_hors_gestes' => "Ces comptes sont retires du choix des gestes distants : le backend les refuse, et proposer un geste qui ne peut pas aboutir n'est pas une offre.",
    'illisible_divergence' => "⚠ :nombre compte(s) rendu(s) par l'inventaire n'ont pas de ligne dans le tableau ci-dessous — les deux lectures ne concordent pas. Rechargez la page.",
    'illisibles_titre' => "Comptes au nom illisible relevés sur cette machine",
    'illisibles_texte' => "Aucun geste distant ne peut viser ces comptes : leur nom est interpolé dans des chemins exécutés en root, et le backend les refuse. Le nom vient du /etc/passwd de la machine — c'est un indice à regarder, pas une erreur de RootWarden. Comptes concernés — :nombre au total : :liste.",
    'illisibles_bloquant' => "⚠ Tant qu'un de ces comptes reste « en attente d'examen », il BLOQUE le déploiement de clés — la vérification préalable les compte, elle, et c'est délibéré : en exclure une ligne aurait desserré un garde. Les classer est le seul moyen de débloquer.",
    'motif_vide' => "nom vide",
    'motif_trop_long' => "nom de plus de 32 caractères",
    'motif_composant_de_chemin' => "n'est pas un nom mais un composant de chemin",
    'motif_caracteres_interdits' => "caractères interdits dans un nom de compte",
    'motif_inconnu' => "motif non reconnu par cet écran",
    'scan_non_concluant' => "Scan non concluant. Lectures qui ont échoué : :sources. L'inventaire affiché est celui du dernier scan abouti — il n'a PAS été modifié.",
    'scan_comptes_lus' => "Les comptes, eux, ont bien été lus : ce sont les compteurs de clés qui sont périmés.",
    'scan_source_comptes' => "la liste des comptes",
    'scan_source_cles_root' => "les clés lues en root",
    'scan_source_cles_utilisateur' => "les clés lues par le compte de service",
    'scan_echec' => "Le scan n'a pas abouti.",
    'en_attente_titre' => ':n compte(s) attendent un examen.',
    'en_attente_aide' => "Le scan les a trouvés sans savoir quoi en penser. Les classer est SANS RETOUR : « en attente d'examen » ne se repose jamais.",
    'btn_classer_masse' => 'Classer les :n comme « :statut »',
    'rien_en_attente' => "Aucun compte n'attend d'examen sur cette machine.",
    'liste_titre' => ':n compte(s) sur :machine',
    'col_compte' => 'Compte',
    'col_uid' => 'UID',
    'col_shell' => 'Interpréteur',
    'col_cles' => 'Clés',
    'col_statut' => 'Statut',
    'col_action' => 'Classer',
    'cle_plateforme' => 'clé RootWarden',
    'cle_tierce' => 'clé tierce',
    'n_cles' => ':n clé(s)',
    'aucune_cle' => 'aucune clé',
    'statut_managed' => 'géré',
    'statut_excluded' => 'exclu',
    'statut_unmanaged' => 'non géré',
    'statut_pending_review' => "en attente d'examen",
    'btn_classer' => 'Classer',
    'vide' => 'Aucun compte relevé sur cette machine.',
    'vide_aide' => "Lancez un scan : tant qu'il n'a pas eu lieu, l'inventaire est vide et rien ne dit ce que la machine héberge.",
    'gestes_titre' => 'Gestes sur la machine',
    'gestes_aide' => 'Ces trois gestes MODIFIENT la machine distante. Désignez le compte, puis confirmez dans le panneau : il nomme ce que le geste engage.',
    'geste_compte' => 'Compte visé',
    'geste_choisir' => '— choisir un compte —',
    'btn_retirer_cles' => 'Effacer ses clés',
    'btn_sshd' => 'Autoriser dans sshd',
    'btn_supprimer' => 'Supprimer le compte',
    'annuler' => 'Annuler',
    'confirmer' => 'Confirmer',
    'geste_sans_compte' => "Choisissez d'abord un compte.",
    'geste_en_cours' => 'Geste en cours…',
    'geste_fait' => "La demande est partie et le serveur l'a acceptée. Ce n'est pas la preuve que le geste a abouti sur la machine : pour « Effacer ses clés », le backend ne vérifie pas son propre effet et répond « réussi » sans regarder. Relance un scan pour lire l'état réel.",
    'geste_echec' => "Le geste n'a pas abouti.",
    'cles_titre' => 'Clés de :nom',
    'cles_desc' => 'Seules les empreintes sont conservées : la base ne stocke pas les clés elles-mêmes.',
    'col_type' => 'Type',
    'col_empreinte' => 'Empreinte SHA-256',
    'col_commentaire' => 'Commentaire',
    'col_origine' => 'Origine',
    'classe' => 'Le compte :nom est classé « :statut ».',
    'classes_en_masse' => ':n compte(s) classés « :statut ».',
    'err_introuvable' => "Le compte :nom n'est pas dans l'inventaire de cette machine.",
    'err_statut' => "Ce statut n'est pas proposé.",
    'err_aucun_en_attente' => "Aucun compte n'attendait d'examen.",

    // Panneaux de decision — les trois gestes qui MODIFIENT la machine
    'panneau_cles_titre' => 'Effacer toutes les clés de :nom ?',
    'panneau_cles_texte' => "Le fichier `authorized_keys` de :nom sera vidé sur :machine. Tout accès par clé à ce compte cesse immédiatement, y compris celui de RootWarden s'il en dépendait.",
    'panneau_sshd_titre' => 'Autoriser :nom dans sshd ?',
    'panneau_sshd_texte' => "La directive `AllowUsers` de :machine sera modifiée et sshd rechargé. Une erreur à cette étape peut couper l'accès SSH à la machine.",
    'panneau_suppr_titre' => 'Supprimer le compte :nom ?',
    'panneau_suppr_texte' => '`userdel` sera exécuté sur :machine, ET SON RÉPERTOIRE PERSONNEL SERA SUPPRIMÉ AVEC LUI. Ce geste ne se défait pas : ni le compte, ni ses fichiers, ni ses clés ne peuvent être restaurés depuis RootWarden.',

    /*
     * ══ UNE NON-MESURE ANNONCEE A L'AVANCE ══════════════════════════════
     *
     * Les trois gestes ci-dessus atteignent une machine reelle : ils
     * reecrivent des cles d'acces, modifient `sshd_config`, ou suppriment un
     * compte systeme. **Aucun n'a jamais ete exerce depuis cette interface**
     * — ni sur le banc, ni ailleurs.
     *
     * Le dire sur la PAGE, et pas seulement dans un registre : c'est la
     * personne qui va cliquer qui a besoin de l'information, et elle ne lit
     * pas le CHANGELOG. Une non-mesure annoncee a l'avance est un fait ;
     * annoncee apres coup, c'est une excuse.
     */
    'gestes_jamais_exerces' => "Ces trois gestes n'ont encore jamais été exercés depuis cette interface. Ils sont câblés et confirmés par un panneau, mais leur bon fonctionnement n'a pas été observé sur une machine — l'ancien portail reste la seule voie éprouvée.",
];
