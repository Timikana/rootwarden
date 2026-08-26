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

    // Ce que D6a ne porte pas encore
    'reste_titre' => "Trois capacités de cet onglet ne sont pas encore portées.",
    'reste_texte' => "Cycle de vie, test de connexion et import par fichier CSV passent par des points d'entrée distincts de l'ancien portail. Ils y fonctionnent toujours.",
    'reste_lien' => "Ouvrir l'ancien portail",

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
];
