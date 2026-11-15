<?php

/**
 * Le parc de machines — module `adm/`, sous-lot D6a.
 *
 * PARITE STRICTE avec `lang/en/serveurs.php` : memes cles, dans le meme ordre.
 */
return [
    'title' => 'Serveurs',
    'desc' => "Les machines administrées par RootWarden et le compte SSH qui sert à s'y connecter.",
    'compte' => ':n machine(s) au parc',

    // Recherche
    'filtre_label' => 'Filtrer le parc',
    'filtre_placeholder' => 'nom, adresse, compte…',
    'filtre_resultat' => ':n machine(s) affichée(s)',

    // Ajout
    'ajouter_titre' => 'Ajouter une machine',
    'champ_nom' => 'Nom',
    'champ_ip' => 'Adresse IP',
    'champ_port' => 'Port SSH',
    'champ_utilisateur' => 'Compte SSH',
    'champ_mdp' => 'Mot de passe',
    'champ_mdp_root' => 'Mot de passe root',
    'champ_environnement' => 'Environnement',
    'champ_criticite' => 'Criticité',
    'champ_reseau' => 'Réseau',
    'env_autre' => 'Autre',
    'crit_critique' => 'Critique',
    'crit_non_critique' => 'Non critique',
    'res_interne' => 'Interne',
    'res_externe' => 'Externe',
    'aide_nom' => 'Lettres, chiffres, espaces, points, tirets, souligné, plus et parenthèses.',
    'aide_ip' => "Adresses privées acceptées. Bouclage, lien-local, multicast et plages réservées refusés.",
    'btn_ajouter' => 'Ajouter la machine',
    'champs_requis' => 'Les champs marqués d\'une étoile sont obligatoires.',

    // Modification
    'inchange' => 'Laisser vide pour ne pas changer',
    'options_deploiement' => 'Options de déploiement',
    'opt_nettoyage' => 'Nettoyer les comptes obsolètes',
    'opt_nettoyage_aide' => "Sans effet aujourd'hui : aucun déploiement ne supprime de compte. Un compte qui a perdu l'accès perd sa clé et ses droits sudo, mais reste sur la machine.",
    'btn_enregistrer' => 'Enregistrer',
    'btn_supprimer' => 'Retirer du parc',

    // Suppression
    'suppr_titre' => 'Retirer :nom du parc ?',
    'suppr_texte' => "La machine sort des scans, de la supervision et des déploiements de clés. Rien n'est modifié sur la machine : les comptes et les clés posés restent en place.",
    'suppr_confirmer' => 'Retirer du parc',
    'suppr_annuler' => 'Annuler',

    // Etats
    'en_ligne' => 'en ligne',
    'hors_ligne' => 'hors ligne',
    'statut_inconnu' => 'état inconnu',
    'auth_cle' => 'Authentification par clé',
    'auth_mdp' => 'Authentification par mot de passe',
    'cycle_retrait' => 'En cours de retrait',
    'cycle_archive' => 'Archivée',
    'cycle_date' => 'retrait prévu le :date',

    // Etat vide
    'vide' => 'Aucune machine au parc.',
    'vide_aide' => "Ajoutez-en une avec « Ajouter une machine », ou importez un fichier CSV.",


    // Retours
    'ajoutee' => 'La machine :nom est ajoutée au parc.',
    'modifiee' => 'La machine :nom est modifiée.',
    'supprimee' => 'La machine :nom est retirée du parc.',

    // Erreurs
    'err_champs' => 'Champs refusés : :champs.',
    'err_doublon' => 'Une machine porte déjà ce nom ou cette adresse.',
    'err_ajout' => "La machine n'a pas pu être ajoutée.",
    'err_modification' => "La machine n'a pas pu être modifiée.",
    'err_suppression' => "La machine n'a pas pu être retirée.",
    'err_introuvable' => 'Cette machine n\'existe pas.',
    'err_secret' => "Les deux mots de passe sont obligatoires à la création, et le service de chiffrement doit être disponible.",

    // Étiquettes et notes — sous-lot D6b
    'etiquettes_titre' => 'Étiquettes',
    'etiquettes_vide' => 'Aucune étiquette.',
    'etiquette_champ' => 'Nouvelle étiquette',
    'etiquette_placeholder' => 'production, web…',
    'etiquette_aide' => 'Minuscules, chiffres, tiret et souligné. Le reste est retiré.',
    'etiquette_ajouter' => 'Ajouter',
    'etiquette_retirer' => "Retirer l'étiquette :tag",
    'etiquette_posee' => "L'étiquette est posée.",
    'etiquette_retiree' => "L'étiquette est retirée.",
    'notes_titre' => 'Notes',
    'notes_vide' => 'Aucune note sur cette machine.',
    'notes_borne' => 'Seules les :n dernières notes sont affichées.',
    'note_champ' => 'Nouvelle note',
    'note_placeholder' => 'ce que la prochaine personne doit savoir…',
    'note_ajouter' => 'Ajouter',
    'note_supprimer' => 'Supprimer cette note',
    'note_posee' => 'La note est ajoutée.',
    'note_supprimee' => 'La note est supprimée.',
    'err_etiquette_vide' => 'Une étiquette doit contenir au moins un caractère parmi les minuscules, les chiffres, le tiret et le souligné.',
    'err_etiquette_longue' => 'Une étiquette ne peut pas dépasser 50 caractères.',
    'err_note_vide' => 'Une note ne peut pas être vide.',
    'err_note_introuvable' => "Cette note n'existe pas sur cette machine.",

    // Cycle de vie et connexion — sous-lot D6d
    'exploitation_titre' => 'Cycle de vie et connexion',
    'cycle_active' => 'Réactiver',
    'cycle_retiring' => 'Mettre en retrait',
    'cycle_archived' => 'Archiver',
    'cycle_active_fait' => 'La machine est réactivée.',
    'cycle_retiring_fait' => 'La machine est mise en retrait.',
    'cycle_archived_fait' => 'La machine est archivée.',
    'cycle_inchange' => "La machine était déjà dans cet état : rien n'a changé.",
    'btn_tester' => 'Tester la connexion',
    'test_en_cours' => 'Test en cours…',
    'test_en_ligne' => 'La machine répond sur :ip.',
    'test_hors_ligne' => 'La machine ne répond pas sur :ip.',
    'test_echec' => "Le test n'a pas pu être mené.",

    /* ═══ Import CSV — D6e ═══════════════════════════════════════════════ */
    'imp_titre' => 'Importer des serveurs depuis un fichier CSV',
    'imp_aide' => "Une ligne d'en-tête est exigée. Colonnes obligatoires : name, ip, user, password, root_password. Facultatives : port, environment, criticality, network_type, tags (séparées par « ; »).",
    'imp_champ' => 'fichier CSV',
    'imp_fichier' => 'Fichier CSV',
    'imp_fichier_aide' => 'Au plus :ko kio et :lignes lignes de données.',
    'imp_doublons' => 'Ignorer les serveurs déjà présents plutôt que de les signaler en erreur',
    'imp_valider' => 'Importer',

    // ⚠ CE QUE LE FICHIER CONTIENT, DIT AVANT DE LE CHOISIR. Les colonnes
    // `password` et `root_password` sont des secrets EN CLAIR dans le fichier :
    // ils sont chiffres a l'enregistrement, mais le fichier lui-meme ne l'est
    // pas.
    'imp_secrets' => "Ce fichier contient des mots de passe en clair, dont ceux de root, et il n'est pas chiffré. Supprimez-le après l'import.",

    'imp_bilan_titre' => "Résultat de l'import",
    'imp_crees' => ':n serveur(s) créé(s).',
    'imp_aucun' => "Aucun serveur créé.",
    'imp_lues' => ':n ligne(s) de données lue(s).',
    'imp_erreurs_titre' => ':n ligne(s) refusée(s)',
    'imp_ligne' => 'Ligne :n',
    'imp_doublon' => 'déjà présent (nom ou adresse), ignoré',

    // Le PLAFOND est DIT, jamais une troncature muette.
    'imp_tronque' => "Le fichier dépasse :lignes lignes de données : les suivantes n'ont pas été traitées. Découpez-le et importez le reste.",
    'imp_manquantes' => 'Colonnes obligatoires absentes de la ligne d\'en-tête : :noms. Aucune ligne n\'a été traitée.',
    'imp_err_illisible' => "Le fichier n'a pas pu être ouvert. Aucune ligne n'a été traitée.",
    'imp_err_vide' => "Le fichier est vide ou n'a pas de ligne d'en-tête. Aucune ligne n'a été traitée.",
    'imp_refus' => "Une ligne est refusée si un mot de passe est vide, ou si environment (PROD, DEV, TEST, OTHER), criticality (CRITIQUE, NON CRITIQUE) ou network_type (INTERNE, EXTERNE) a une autre valeur.",


    // Audit 2026-10-13, H-3 : cle d'hote SSH memorisee (TOFU).
    "cle_hote_titre" => "Clé d'hôte SSH",
    "cle_hote_inconnue" => "Aucune clé mémorisée : elle sera enregistrée à la prochaine connexion.",
    "cle_hote_memorisee" => "Mémorisée depuis le :depuis — :type, empreinte SHA-256 :empreinte",
    "cle_hote_aide" => "RootWarden refuse de se connecter si la machine présente une autre clé. Si elle a été réinstallée, oubliez sa clé : la suivante sera acceptée.",
    "cle_hote_confirme" => "Je confirme que cette machine a été réinstallée (sinon, une usurpation est possible)",
    "cle_hote_oublier" => "Oublier la clé d'hôte",
    "cle_hote_oubliee" => "Clé d'hôte oubliée pour :nom : la prochaine connexion l'enregistrera à nouveau.",
    "cle_hote_confirmation_requise" => "Confirmez que la machine a été réinstallée avant d'oublier sa clé.",
];
