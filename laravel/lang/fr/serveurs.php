<?php

/**
 * Le parc de machines — module `adm/`, sous-lot D6a.
 *
 * PARITE STRICTE avec `lang/en/serveurs.php` : memes cles, dans le meme ordre.
 */
return [
    'title' => 'Serveurs',
    'desc' => "Le parc de machines administrées par RootWarden : leur adresse, le compte SSH utilisé pour s'y connecter, leur environnement et leur criticité.",
    'compte' => ':n machine(s) au parc',

    // Legende des environnements
    'legende' => 'Environnements',

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
    'aide_ip' => "Les adresses privées sont acceptées. Le bouclage, le lien-local et le multicast sont refusés : ils ne désignent pas une machine joignable.",
    'btn_ajouter' => 'Ajouter la machine',
    'champs_requis' => 'Les champs marqués d\'une étoile sont obligatoires.',

    // Modification
    'inchange' => 'Laisser vide pour ne pas changer',
    'options_deploiement' => 'Options de déploiement',
    'opt_nettoyage' => 'Nettoyer les comptes obsolètes',
    'opt_nettoyage_aide' => 'Au prochain déploiement, les comptes de la machine qui ne correspondent plus à aucun accès seront supprimés.',
    'btn_enregistrer' => 'Enregistrer',
    'btn_supprimer' => 'Retirer du parc',

    // Suppression
    'suppr_titre' => 'Retirer :nom du parc ?',
    'suppr_texte' => "La machine disparaît des scans de vulnérabilités, de la supervision et des déploiements de clés. La machine elle-même n'est pas touchée : rien n'est modifié dessus, aucun accès n'est révoqué.",
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
    'vide_aide' => "Tant qu'aucune machine n'est déclarée, ni les scans de vulnérabilités ni les déploiements de clés n'ont de cible.",


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
    'imp_aide' => "Le fichier doit porter une ligne d'en-tête. Colonnes obligatoires : name, ip, user, password, root_password. Colonnes optionnelles : port, environment, criticality, network_type, tags.",
    'imp_champ' => 'fichier CSV',
    'imp_fichier' => 'Fichier CSV',
    'imp_fichier_aide' => 'Au plus :ko kio et :lignes lignes de données.',
    'imp_doublons' => 'Ignorer les serveurs déjà présents plutôt que de les signaler en erreur',
    'imp_valider' => 'Importer',

    // ⚠ CE QUE LE FICHIER CONTIENT, DIT AVANT DE LE CHOISIR. Les colonnes
    // `password` et `root_password` sont des secrets EN CLAIR dans le fichier :
    // ils sont chiffres a l'enregistrement, mais le fichier lui-meme ne l'est
    // pas. Le legacy ne le disait nulle part.
    'imp_secrets' => "Ce fichier contient des mots de passe en clair, dont ceux de root. Ils sont chiffrés à l'enregistrement, mais le fichier ne l'est pas : supprimez-le après l'import et ne le laissez pas dans un dossier partagé.",

    'imp_bilan_titre' => "Résultat de l'import",
    'imp_crees' => ':n serveur(s) créé(s).',
    'imp_aucun' => "Aucun serveur créé.",
    'imp_lues' => ':n ligne(s) de données lue(s).',
    'imp_erreurs_titre' => ':n ligne(s) refusée(s)',
    'imp_ligne' => 'Ligne :n',
    'imp_doublon' => 'déjà présent (nom ou adresse), ignoré',

    // Le PLAFOND est DIT, jamais une troncature muette.
    'imp_tronque' => "Le fichier dépasse :lignes lignes de données : les lignes suivantes n'ont PAS été traitées. Découpez-le et relancez — ce n'est ni un succès complet ni un échec.",
    'imp_manquantes' => 'Colonnes obligatoires absentes de la ligne d\'en-tête : :noms. Aucune ligne n\'a été traitée.',
    'imp_err_illisible' => "Le fichier n'a pas pu être ouvert. Aucune ligne n'a été traitée.",
    'imp_err_vide' => "Le fichier est vide ou n'a pas de ligne d'en-tête. Aucune ligne n'a été traitée.",

    // ⚠ CES DEUX TEXTES DISENT UNE DIVERGENCE ASSUMEE avec l'ancien portail.
    'imp_diverge_titre' => "Deux différences avec l'ancien portail",
    'imp_diverge_secret' => "Une ligne dont le mot de passe ou celui de root est vide est REFUSÉE. L'ancien portail la créait, et la machine paraissait alors porter un mot de passe alors qu'elle n'en avait pas.",
    'imp_diverge_env' => "Une valeur d'environnement, de criticité ou de type de réseau non reconnue REFUSE la ligne. L'ancien portail la remplaçait en silence par « OTHER » : une faute de frappe sur « PROD » retirait la machine de la population des machines de production, sans que rien ne le signale.",

];
