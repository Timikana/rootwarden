<?php

/**
 * Profil — francais. Parite stricte avec lang/en/profil.php.
 *
 * Regles de redaction : docs/REDACTION-INTERFACE.md. L'avertissement de
 * l'effacement reste visible ; le detail du fichier RGPD se replie.
 */
return [

    'compte_titre' => 'Compte',
    'compte_texte' => 'Connecté sous :nom, avec le rôle :role.',

    'second_facteur_titre'  => 'Second facteur',
    'second_facteur_valeur' => 'Actif',
    'second_facteur_texte'  => "Un code à usage unique est exigé à chaque connexion.",

    /*
     * La politique est celle du legacy, a l'identique. Une seule cle pour les
     * cinq regles de complexite : dire QUELLE regle a echoue renseigne autant
     * l'attaquant que la personne. `mdp_politique` sert aussi a la page de
     * reinitialisation.
     */
    'mdp_titre' => 'Changer le mot de passe',
    'mdp_politique' => 'Au moins :longueur caractères, avec une minuscule, une majuscule, un chiffre et un caractère spécial. Les :historique derniers mots de passe sont refusés, ainsi que celui en cours.',
    'mdp_actuel' => 'Mot de passe actuel',
    'mdp_nouveau' => 'Nouveau mot de passe',
    'mdp_confirmation' => 'Confirmer le nouveau mot de passe',
    'mdp_enregistrer' => 'Changer le mot de passe',
    'mdp_effet_sessions' => "Vos autres sessions et connexions mémorisées seront fermées.",
    'mdp_ok' => 'Mot de passe modifié.',
    'mdp_erreur_actuel' => 'Mot de passe actuel incorrect.',
    'mdp_erreur_correspondance' => 'Les mots de passe ne correspondent pas.',
    'mdp_erreur_politique' => 'Le mot de passe doit contenir au moins 15 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial.',
    'mdp_erreur_historique' => 'Ce mot de passe a déjà été utilisé. Choisissez-en un autre.',
    'mdp_erreur_fuite' => 'Ce mot de passe apparaît dans une fuite de données publique. Choisissez-en un autre.',
    'mdp_erreur_compte' => 'Compte introuvable.',

    // ── Donnees personnelles (RGPD) ──────────────────────────────────────
    'rgpd_titre' => 'Vos données personnelles',
    'rgpd_aide' => 'Téléchargez, au format JSON, toutes les données que ce portail détient sur vous (RGPD, articles 15 et 20).',
    'rgpd_bouton' => 'Télécharger mes données',
    'rgpd_details' => 'Contenu du fichier',
    'rgpd_contenu' => 'Votre profil, vos droits, vos accès machines, vos historiques d\'actions et de connexions, vos sessions, vos préférences de notification et les dates de changement de mot de passe.',
    'rgpd_protege' => 'N\'y figurent pas : les empreintes de vos anciens mots de passe, ni vos identifiants de session en entier (coupés à huit caractères).',
    'rgpd_borne' => 'Les historiques d\'actions et de connexions sont bornés ; au-delà, le fichier indique le nombre total de lignes.',
    'rgpd_trace' => 'Chaque téléchargement est inscrit au journal d\'audit.',

    // ── Sessions ouvertes ────────────────────────────────────────────────
    'sessions_titre' => 'Vos sessions ouvertes',
    'sessions_aide'  => "Fermer une session la déconnecte immédiatement.",
    'sessions_vide'  => "Aucune session enregistrée, pas même celle-ci : ce n'est pas normal.",
    'sessions_err'   => "Impossible de lire vos sessions.",
    'sessions_actuelle' => 'session actuelle',
    'sessions_vue'    => 'vue le :date',
    // La liste est bornee, et la borne est dite.
    'sessions_bornee' => 'Les :n plus récentes, sur :total enregistrées.',
    // Une session expiree sans deconnexion garde sa ligne : le planificateur ne
    // purge qu'apres sept jours d'inactivite (backend/scheduler.py).
    'sessions_vestiges' => "Une session expirée sans déconnexion reste listée jusqu'à sept jours.",
    'sessions_revoquer' => 'Fermer',
    // L'identifiant complet ne sort pas du serveur — voir SessionsActives.
    'sessions_empreinte' => 'empreinte :valeur',
    'sessions_revoquee'  => 'Session fermée.',
    'sessions_introuvable' => "Cette session n'existe plus : elle a peut-être déjà été fermée.",
    'sessions_pas_la_sienne' => "Pour fermer la session courante, utilisez « Déconnexion ».",

    // ── Adresse, cles SSH, effacement ────────────────────────────────────
    'courriel_titre' => 'Adresse de courriel',
    'courriel_aide' => 'Elle reçoit le lien de réinitialisation du mot de passe.',
    'courriel_label' => 'Nouvelle adresse',
    'courriel_enregistrer' => 'Enregistrer l\'adresse',
    'courriel_ok' => 'Adresse de courriel enregistrée.',
    'err_courriel_vide' => 'Une adresse est nécessaire pour réinitialiser votre mot de passe. Pour l\'effacer, effacez votre compte.',
    'err_courriel_long' => 'Adresse trop longue (255 caractères au plus).',
    'err_courriel_forme' => 'Cette adresse n\'a pas une forme valide.',
    'err_courriel_pris' => 'Cette adresse sert déjà à un autre compte.',
    'cle_label' => 'Clé publique',
    'cle_retiree' => 'Clé SSH retirée.',
    'eff_titre' => 'Effacer mon compte',
    'eff_aide' => 'Efface vos données personnelles (nom, adresse, société, clés SSH, second facteur) et désactive le compte.',
    'eff_prevenu' => 'Irréversible : vous serez déconnecté immédiatement. Le journal d\'audit est conservé, sans votre identité.',
    'eff_confirmation_label' => 'Pour confirmer, saisissez le nom de votre compte : :nom',
    'eff_code_label' => 'Code de votre application d\'authentification (six chiffres)',
    // Les deux controles n'ont pas le meme objet (EffacementLibreServiceTest C6).
    'eff_code_aide'  => "Le nom protège d'une erreur de manipulation ; le code, d'une session volée.",
    'eff_bouton' => 'Effacer définitivement mon compte',
    'eff_err_confirmation' => 'Le nom saisi ne correspond pas à celui du compte. Rien n\'a été effacé.',
    'eff_fait' => 'Votre compte a été effacé. Le journal d\'audit est conservé sans votre identité.',

    // Plusieurs cles SSH par compte (migration 067)
    'cles_titre' => 'Vos clés SSH',
    'cles_aide' => 'Format « algorithme base64 [commentaire] ». Chaque clé est posée au prochain déploiement, sur toutes vos machines ou sur celles que vous cochez.',
    'cles_aucune' => 'Aucune clé enregistrée : rien ne sera posé pour vous. Ajoutez-en une ci-dessous.',
    'cles_th_nom' => 'Nom',
    'cles_th_empreinte' => 'Empreinte',
    'cles_th_portee' => 'Portée',
    'cles_th_ajoutee' => 'Ajoutée le',
    'cles_portee_toutes' => 'Toutes mes machines',
    'cles_portee_machines' => 'Seulement les machines cochées',
    'cles_portee_aide' => 'Seules les machines auxquelles vous avez accès sont proposées.',
    'cles_sans_acces' => 'Vous n\'avez accès à aucune machine : vos clés ne seront posées nulle part tant qu\'un administrateur ne vous en donne pas l\'accès.',
    'cles_retirer' => 'Retirer',
    'cles_ajout_titre' => 'Ajouter une clé',
    'cles_nom' => 'Nom de la clé',
    'cles_nom_exemple' => 'portable, poste fixe, automate-srv-web01…',
    'cles_ajouter' => 'Ajouter la clé',
    'cle_ajoutee' => 'Clé SSH ajoutée. Elle sera posée au prochain déploiement.',
    'err_cle_vide' => 'Collez une clé publique.',
    'err_cle_libelle' => 'Donnez un nom à la clé (100 caractères au plus).',
    'err_cle_doublon' => 'Cette clé est déjà enregistrée sur votre compte.',
    'err_cle_portee_vide' => 'Cochez au moins une machine, ou choisissez « Toutes mes machines ».',
    'err_cle_portee_hors_acces' => 'Une des machines cochées n\'est pas accessible à votre compte : rien n\'a été enregistré.',
    'err_cle_introuvable' => 'Cette clé n\'existe pas sur votre compte.',
];
