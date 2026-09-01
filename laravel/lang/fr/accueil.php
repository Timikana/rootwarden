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
    // ══ LES NEUF INDICATEURS DU LEGACY, BORNES ═══════════════════════════
    'ind_parc_titre' => 'Votre parc',
    'ind_machines' => 'machines',
    'ind_en_ligne' => 'en ligne',
    'ind_hors_ligne' => 'hors ligne',
    // TROIS ETATS, PAS DEUX. Le legacy compte « != ONLINE » et range donc les
    // machines d'etat INCONNU parmi les hors ligne. Les deux compteurs somment
    // au total, ce qui les fait paraitre coherents — et c'est ce qui rendait le
    // defaut invisible.
    'ind_inconnu' => 'état inconnu',
    'ind_inconnu_aide' => "Ces machines ne sont ni en ligne ni hors ligne : le produit n'a pas d'information à jour sur elles. L'ancien portail les comptait comme hors ligne, ce qui affirmait un état que la donnée ne porte pas.",
    'ind_cle' => 'avec la clé de plateforme',

    'ind_cve_titre' => 'Vulnérabilités connues',
    'ind_cve_date' => 'dernier scan',
    'ind_cve_nombre' => 'CVE au dernier scan',
    'ind_cve_critiques' => 'critiques, tous scans',
    'ind_cve_aucun_scan' => "Aucun scan de vulnérabilités n'a été fait sur les machines de votre périmètre. Ce n'est pas « zéro CVE » : c'est l'absence de mesure.",
    'ind_cve_illisible' => "L'historique des scans n'a pas pu être lu. Ce n'est pas « aucune CVE » — aucun nombre affiché ici ne serait fiable.",

    'ind_comptes_titre' => 'Comptes du portail',
    'ind_actifs' => 'comptes actifs',
    'ind_sans_cle' => 'sans clé SSH enregistrée',
    'ind_sans_cle_sature' => "Cet indicateur vaut aujourd'hui 100 % : aucun compte n'a de clé SSH enregistrée. Il est porté quand même — un indicateur saturé est le seul moyen de voir qu'il cesse de l'être.",
    'ind_sans_2fa' => 'sans second facteur',
    'ind_sans_2fa_aide' => "Ce nombre est réservé au rôle 3. Il dit quelle part des comptes du portail s'ouvre avec un mot de passe seul — une information utile pour agir, et une carte de cibles pour qui n'a pas à agir. Votre propre état de second facteur est affiché plus haut.",
    'ind_comptes_reserve' => "Les compteurs de comptes ne sont pas affichés à votre rôle. Ils ne portent pas sur vos machines : un périmètre de machines ne borne pas une population d'utilisateurs, donc ils se bornent par rôle.",

    'ind_illisible' => "Ces valeurs n'ont pas pu être lues. Ce n'est pas « zéro » : la base n'a pas répondu.",
    'ind_borne' => "Ces nombres ne portent que sur les machines qui vous sont attribuées.",
];
