<?php

/**
 * Profil — francais. Parite stricte avec lang/en/profil.php.
 */
return [

    'compte_titre' => 'Compte',
    'compte_texte' => 'Connecté sous :nom, avec le rôle :role.',

    'second_facteur_titre'  => 'Second facteur',
    'second_facteur_valeur' => 'Actif',
    'second_facteur_texte'  => "Un code à usage unique est exigé à chaque connexion. Il n'existe aucun accès sans second facteur.",
    // E-203 : les sessions SONT listees desormais. La chaine decrivait un
    // manque qui vient d'etre comble — un libelle qui survit au defaut
    // qu'il decrit devient faux sans que rien ne le signale.
    /*
     * ── SOUS-LOT A2 : LE CHANGEMENT DE MOT DE PASSE ──────────────────────
     *
     * La politique est celle du legacy, a l'identique : les deux portails
     * partagent la base, donc une regle plus laxiste d'un cote serait un
     * contournement de l'autre. Le legacy rend UNE seule cle pour les cinq
     * regles de complexite — on garde ce choix : dire QUELLE regle a echoue
     * renseigne autant l'attaquant que la personne.
     */
    'mdp_titre' => 'Changer le mot de passe',
    'mdp_politique' => 'Au moins :longueur caracteres, avec une minuscule, une majuscule, un chiffre et un caractere special. Les :historique derniers mots de passe sont refuses, ainsi que celui en cours.',
    'mdp_actuel' => 'Mot de passe actuel',
    'mdp_nouveau' => 'Nouveau mot de passe',
    'mdp_confirmation' => 'Confirmer le nouveau mot de passe',
    'mdp_enregistrer' => 'Changer le mot de passe',
    // E-203 : la reserve « il ne consulte pas encore » n'a plus d'objet.
    'mdp_effet_sessions' => "Vos autres sessions seront fermées, sur ce portail comme sur l'ancien — les deux vérifient à chaque requête — et les connexions mémorisées oubliées.",
    'mdp_ok' => 'Mot de passe modifie avec succes.',
    'mdp_erreur_actuel' => 'Mot de passe actuel incorrect.',
    'mdp_erreur_correspondance' => 'Les mots de passe ne correspondent pas.',
    'mdp_erreur_politique' => 'Le mot de passe doit contenir au moins 15 caracteres, une majuscule, une minuscule, un chiffre et un caractere special.',
    'mdp_erreur_historique' => 'Ce mot de passe a deja ete utilise. Choisissez-en un autre.',
    'mdp_erreur_fuite' => 'Ce mot de passe apparait dans une fuite de donnees publique. Choisissez-en un autre.',
    'mdp_erreur_compte' => 'Compte introuvable.',

    // ══ E-203 : LES SESSIONS OUVERTES ════════════════════════════════════
    'rgpd_titre' => 'Vos données personnelles',
    'rgpd_aide' => 'Téléchargez la copie de toutes les données que ce portail détient sur vous (RGPD, articles 15 et 20). Le fichier est un JSON, lisible et réutilisable ailleurs.',
    'rgpd_bouton' => 'Télécharger mes données',
    'rgpd_contenu' => 'Le fichier contient votre profil, vos droits, vos accès machines, votre historique d\'actions et de connexions, vos sessions ouvertes, vos préférences de notification et les dates de vos changements de mot de passe.',
    'rgpd_protege' => 'Deux choses n\'y figurent pas, volontairement : les empreintes de vos anciens mots de passe, et vos identifiants de session en entier — ils sont coupés à huit caractères, parce qu\'un fichier que vous archivez ou transférez ne doit pas contenir de quoi rejouer une session.',
    'rgpd_borne' => 'Les deux historiques les plus longs sont bornés. Si le vôtre dépasse la borne, le fichier le DIT : il porte le nombre total de lignes à côté du nombre exporté.',
    'rgpd_trace' => 'Votre demande est enregistrée dans le journal d\'audit, comme l\'exige la tenue du registre.',
    'sessions_titre' => 'Vos sessions ouvertes',
    'sessions_aide'  => "Chaque connexion à ce portail ou à l'ancien ouvre une session. Fermer une session la déconnecte immédiatement, des deux côtés.",
    'sessions_vide'  => "Aucune session enregistrée — pas même celle-ci, ce qui n'est pas normal.",
    'sessions_err'   => "Vos sessions n'ont pas pu être lues. Ce n'est pas « aucune session » : la liste n'a pas répondu.",
    'sessions_actuelle' => 'session actuelle',
    'sessions_depuis' => 'ouverte le :date',
    'sessions_vue'    => 'vue le :date',
    // La liste est bornee, et la borne est DITE : montrer 20 lignes sur 2 584
    // sans le dire serait le compteur qui ment qu'on corrige partout ailleurs.
    'sessions_bornee' => 'Les :n plus récentes, sur :total enregistrées.',
    // Une ligne de trois semaines n'est PAS une session ouverte : le fichier
    // de session a expiré depuis longtemps. Le dire évite de présenter un
    // vestige comme un accès vivant.
    'sessions_vestiges' => "L'ancien portail enregistre une ligne par connexion et n'en retire jamais : les plus anciennes ne correspondent plus à un accès ouvert.",
    'sessions_revoquer' => 'Fermer',
    // L'identifiant complet ne sort pas du serveur — voir SessionsActives.
    'sessions_empreinte' => 'empreinte :valeur',
    'sessions_revoquee'  => 'Session fermée.',
    'sessions_introuvable' => "Cette session n'existe plus — elle a peut-être déjà été fermée.",
    'sessions_pas_la_sienne' => "Pour fermer la session courante, utilisez « Déconnexion ».",

    /* Libre-service du sujet : adresse, cle SSH, effacement (2026-09-05). */
    'courriel_titre' => 'Adresse de courriel',
    'courriel_aide' => 'C\'est l\'adresse qui reçoit le lien de réinitialisation. La changer ici ne change rien d\'autre.',
    'courriel_label' => 'Nouvelle adresse',
    'courriel_enregistrer' => 'Enregistrer l\'adresse',
    'courriel_ok' => 'Adresse de courriel enregistrée.',
    'err_courriel_vide' => 'Une adresse est nécessaire : c\'est votre chemin de retour si vous perdez votre mot de passe. Pour l\'effacer, utilisez l\'effacement du compte.',
    'err_courriel_long' => 'Adresse trop longue (255 caractères au plus).',
    'err_courriel_forme' => 'Cette adresse n\'a pas une forme valide.',
    'err_courriel_pris' => 'Cette adresse sert déjà à un autre compte.',
    'cle_label' => 'Clé publique',
    'cle_retiree' => 'Clé SSH retirée.',
    'eff_titre' => 'Effacer mon compte',
    'eff_aide' => 'Vos données personnelles sont effacées : nom, adresse, société, clé SSH, second facteur. Le compte est désactivé et aucun mot de passe ne permet plus d\'y entrer.',
    'eff_prevenu' => 'Le journal d\'audit est conservé, sans votre identité. Il est scellé par une chaîne de vérification : en retirer des lignes rendrait invérifiables toutes les suivantes. Ce geste est irréversible et vous déconnecte immédiatement.',
    'eff_confirmation_label' => 'Pour confirmer, saisissez le nom de votre compte : :nom',
    /*
     * ⚠ DEUX CONTROLES, DEUX PORTEES — et le libelle le DIT, parce que la page
     * en montre deux et que rien ne distingue leur objet a l'oeil.
     *
     *   retaper le nom     protege du geste ACCIDENTEL, et rien de plus : le
     *                      nom est AFFICHE juste au-dessus du champ.
     *   le second facteur  protege d'une session VOLEE — le seul des deux qui
     *                      exige quelque chose que le voleur n'a pas.
     */
    'eff_code_label' => 'Code de votre application d\'authentification (six chiffres)',
    'eff_code_aide'  => "Le nom retapé protège d'un geste accidentel — il est écrit juste au-dessus. Ce code-ci protège d'une session volée : c'est le seul des deux qu'un intrus ne peut pas fournir. Le même geste sur le compte de quelqu'un d'autre l'exige déjà.",
    'eff_bouton' => 'Effacer définitivement mon compte',
    'eff_err_confirmation' => 'Le nom saisi ne correspond pas à celui du compte. Rien n\'a été effacé.',
    'eff_fait' => 'Votre compte a été effacé. Les données personnelles ont été retirées et le journal d\'audit conservé sans votre identité.',
    // Plusieurs cles SSH par compte (migration 067)
    'cles_titre' => 'Vos clés SSH',
    'cles_aide' => 'Une clé publique par ajout, au format « algorithme base64 [commentaire] ». Chaque clé est posée sur toutes vos machines, ou seulement sur celles que vous choisissez — et uniquement là où votre compte a accès, au prochain déploiement des clés.',
    'cles_aucune' => 'Aucune clé enregistrée : rien ne sera posé pour vous au prochain déploiement.',
    'cles_th_nom' => 'Nom',
    'cles_th_empreinte' => 'Empreinte',
    'cles_th_portee' => 'Portée',
    'cles_th_ajoutee' => 'Ajoutée le',
    'cles_portee_toutes' => 'Toutes mes machines',
    'cles_portee_machines' => 'Seulement les machines cochées',
    'cles_portee_aide' => 'La liste ne montre que les machines auxquelles vous avez accès : une clé ne peut pas ouvrir une machine que votre compte n\'atteint pas.',
    'cles_sans_acces' => 'Vous n\'avez accès à aucune machine : une clé ajoutée ne sera posée nulle part tant qu\'un administrateur ne vous en a pas donné l\'accès.',
    'cles_retirer' => 'Retirer',
    'cles_ajout_titre' => 'Ajouter une clé',
    'cles_nom' => 'Nom de la clé',
    'cles_nom_exemple' => 'portable, poste fixe, automate-srv-web01…',
    'cles_ajouter' => 'Ajouter la clé',
    'cle_ajoutee' => 'Clé SSH ajoutée. Elle sera posée au prochain déploiement des clés.',
    'err_cle_vide' => 'Collez une clé publique.',
    'err_cle_libelle' => 'Donnez un nom à la clé (100 caractères au plus).',
    'err_cle_doublon' => 'Cette clé est déjà enregistrée sur votre compte.',
    'err_cle_portee_vide' => 'Cochez au moins une machine, ou choisissez « Toutes mes machines ».',
    'err_cle_portee_hors_acces' => 'Une des machines cochées n\'est pas accessible à votre compte : rien n\'a été enregistré.',
    'err_cle_introuvable' => 'Cette clé n\'existe pas sur votre compte.',
];
