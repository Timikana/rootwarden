<?php

/**
 * Accueil du portail — francais.
 *
 * Parite stricte avec lang/en/accueil.php : meme jeu de cles, meme commit.
 */
return [

    'bienvenue'   => 'Bonjour :nom',
    'orientation' => "Vous êtes sur la nouvelle interface. Les raccourcis ci-dessous mènent aux modules que vos droits vous ouvrent ; ceux qui ne sont pas encore portés ouvrent l'ancien portail dans un nouvel onglet.",

    // Roles
    'role_lecteur'    => 'Lecteur',
    'role_admin'      => 'Administrateur',
    'role_superadmin' => 'Superadministrateur',

    // Tuiles
    'acces_titre' => 'Modules accessibles',
    'acces_texte' => '{0}Aucun module ne vous est ouvert avec le rôle :role.|{1}Un seul module vous est ouvert avec le rôle :role.|[2,*]Modules ouverts par vos droits, rôle :role.',

    'portes_titre' => 'Déjà portés',
    'portes_texte' => "Nombre de vos modules servis par la nouvelle interface. Les autres ouvrent l'ancien portail dans un nouvel onglet.",

    'securite_titre'  => 'Second facteur',
    'securite_valeur' => 'Actif',
    'securite_texte'  => "Votre session a été ouverte avec un code à usage unique. Un code déjà utilisé est refusé, même depuis un autre navigateur.",

    'ancien_titre' => 'Ancien portail',
    'ancien_texte' => "Toujours en service, avec les mêmes identifiants. Les entrées de menu marquées d'une flèche y renvoient directement.",

    // Etat vide, explicite
    // ── LES DOUZE RACCOURCIS, PORTES DE `legacy/index.php:363-385` ────────
    // Le LIBELLE de chaque tuile vient de `nav.<cle>` : le legacy en a deux
    // jeux qui disent la meme chose, et deux jeux divergent. Seule la
    // DESCRIPTION est propre aux tuiles, et elle est reprise du legacy.
    'raccourcis_titre' => 'Aller directement à',
    'raccourcis_aide' => "Ces raccourcis suivent vos droits : vous ne voyez que ce que votre rôle et vos permissions vous ouvrent. Une flèche signale une page encore servie par l'ancien portail.",
    'raccourcis_aucun' => "Aucun module n'est ouvert à votre compte pour l'instant. Ce n'est pas une erreur d'affichage : demandez les permissions correspondantes à un administrateur.",

    'desc_ssh_keys' => 'Déployer les clés publiques',
    'desc_updates' => 'Mises à jour APT et redémarrages',
    'desc_iptables' => 'Règles de pare-feu',
    'desc_cve_scan' => 'Vulnérabilités connues du parc',
    'desc_admin' => 'Comptes, serveurs, droits',
    'desc_supervision' => 'Déployer et gérer les agents de supervision',
    'desc_bashrc' => 'Déployer un .bashrc standardisé',
    'desc_graylog' => 'Sidecar, centralisation et collecteurs',
    'desc_wazuh' => 'Agent SIEM et règles éditables',
    'desc_ssh_audit' => 'Scanner la configuration SSH',
    'desc_compliance' => 'Rapport de conformité',
    'desc_documentation' => 'Guide technique',

    // ── LA SEQUENCE, DITE A L'ENDROIT OU L'ON ARRIVE ──────────────────────
    // Demande de l'exploitant : « quand on ajoute un serveur, les menus ou
    // aller ensuite ne sont pas evidents, et un nouvel utilisateur ne le sait
    // pas ». Une liste NUMEROTEE : l'ordre est l'acquis, pas la presentation.
    'sequence_titre' => "Vous venez d'ajouter un serveur ? L'ordre compte",
    'sequence_1' => "Déployez la clé de plateforme sur le serveur. Le même geste crée aussi le compte d'administration avec les droits root sans mot de passe.",
    'sequence_2' => "Relevez les comptes distants du serveur, et classez ceux que RootWarden doit gérer ou ignorer.",
    'sequence_3' => "Vérifiez que la connexion par clé fonctionne avant de retirer quoi que ce soit — le bouton « Tester » le fait sans rien écrire.",
    'sequence_4' => "Alors seulement, effacer le mot de passe de la base a un sens. Fait avant, il vous prive du seul recours si la clé ne fonctionne pas.",
    'sequence_aide' => "Cet ordre n'est pas une préférence : effacer le mot de passe avant d'avoir vérifié la clé retire à RootWarden son unique moyen de revenir sur le serveur.",

    // ── LE PARC, BORNE AU PERIMETRE DU COMPTE ─────────────────────────────
    'parc_compteur_titre' => 'Vos machines',
    'parc_perimetre' => '{0}aucune de vos machines|{1}1 de vos machines|[2,*]:count de vos machines',
    'parc_total' => '{1}1 au parc|[2,*]:count au parc',
    'parc_borne_aide' => "Vous ne voyez ici que les machines qui vous sont attribuées. Le second nombre est la taille réelle du parc : il est affiché pour que la borne soit visible, et non devinée.",
    'parc_illisible' => "Le parc n'a pas pu être lu. Ce n'est pas « aucune machine » : la base n'a pas répondu, et aucun nombre affiché ici ne serait fiable.",
];
